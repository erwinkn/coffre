// Checkpoints under load (W209): load.ts appends at `--rate` a second in a
// process of its own while this one checkpoints every `--every` ms (0: never),
// sealing, signing, writing tiles, and handing each head to the witnesses.
// Prints what a checkpoint costs (statements, database time, this process's
// CPU, Postgres's CPU from its container's cgroup) and the window achieved:
// for each checkpoint, from its oldest entry's commit to the checkpoint's
// commit, and to every witness holding it.
//
//   node experiments/merkle/bench.ts --url postgresql://… --rate 1000 --seconds 30 --every 500 \
//     [--cgroup /sys/fs/cgroup/…/cpu.stat] [--witness local|<url>] [--archive <url>] [--fresh] [--label x]
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { Checkpointer, createLog, keysFrom, type Tick, type Witness } from './src/log.ts';
import { verifierFrom } from './src/note.ts';
import { fileMemory } from './src/memory.ts';
import { httpArchive, httpWitness, localWitness } from './src/witness.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, rate: { type: 'string', default: '1000' }, seconds: { type: 'string', default: '30' }, every: { type: 'string', default: '1000' },
  pool: { type: 'string', default: '40' }, cgroup: { type: 'string' }, witness: { type: 'string' }, archive: { type: 'string' },
  'witness-token': { type: 'string' }, fresh: { type: 'boolean', default: false }, label: { type: 'string', default: '' },
} });
const url = values.url!;
const keys = await keysFrom('w209-synthetic');
const db = new pg.Client({ connectionString: url });
await db.connect();
if (values.fresh) {
  await createLog(db);
}
await db.query('SELECT pg_stat_statements_reset()').catch(() => {});
const scratch = mkdtempSync(join(homedir(), 'scratch', 'w209', 'bench-'));
const headers: Record<string, string> = values['witness-token'] === undefined ? {} : { authorization: `Bearer ${values['witness-token']}` };
const witnesses: Witness[] = [];
if (values.witness === 'local') witnesses.push(localWitness('witness.example', await verifierFrom(keys.signer.verifierKey), keys.witness));
else if (values.witness !== undefined) witnesses.push(httpWitness('do-witness', values.witness, headers));
if (values.archive !== undefined) witnesses.push(httpArchive('r2-archive', values.archive, headers));
const cp = await Checkpointer.open(db, keys, { memory: fileMemory(join(scratch, 'memory')), witnesses });

const cpu = () => (values.cgroup === undefined ? NaN : Number(/usage_usec (\d+)/.exec(readFileSync(values.cgroup, 'utf8'))![1]) / 1000);
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)] ?? NaN;
};

const load = spawn(process.execPath, [new URL('./load.ts', import.meta.url).pathname, '--url', url, '--rate', values.rate, '--seconds', values.seconds, '--pool', values.pool], { stdio: ['ignore', 'pipe', 'inherit'] });
let out = '';
load.stdout.on('data', (d) => { out += d; });
const loaded = new Promise<void>((resolve) => load.on('exit', () => resolve()));
await new Promise((r) => setTimeout(r, 1500)); // its pool connects

const every = Number(values.every);
const ticks: Tick[] = [];
const pg0 = cpu();
const self0 = process.cpuUsage();
const t0 = performance.now();
let running = true;
void loaded.then(() => { running = false; });
while (running) {
  const due = t0 + (ticks.length + 1) * (every || 1000);
  await new Promise((r) => setTimeout(r, Math.max(0, due - performance.now())));
  if (every > 0 && running) ticks.push(await cp.tick());
}
const seconds = (performance.now() - t0) / 1000;
const pgMs = cpu() - pg0;
const self = process.cpuUsage(self0);
const final = every > 0 ? await cp.tick() : null;
const loadResult = JSON.parse(out.trim().split('\n').at(-1)!);

// The first tick seals what the load wrote while it connected: left out of the window and cost figures.
const signed = ticks.slice(1).filter((t) => t.signed);
const stmts = await db.query(`SELECT calls, round(mean_exec_time::numeric, 3) AS ms, left(regexp_replace(query, '\\s+', ' ', 'g'), 40) AS q
  FROM pg_stat_statements WHERE query LIKE '%seal_window%' OR query LIKE '%audit_tiles (level%' ORDER BY calls DESC LIMIT 2`).catch(() => ({ rows: [] }));
console.log([
  values.label.padEnd(10), `rate ${values.rate}/s`, `every ${every} ms`,
  `served ${loadResult.perSecond.toFixed(0)}/s p50 ${loadResult.p50.toFixed(2)} p99 ${loadResult.p99.toFixed(2)} p99.9 ${loadResult.p999.toFixed(1)} max ${loadResult.max.toFixed(0)} ms`,
  Object.keys(loadResult.errors).length === 0 ? 'no errors' : `errors ${JSON.stringify(loadResult.errors)}`,
  `pg ${(pgMs / seconds / 10).toFixed(1)}% of a core`,
].join('  '));
if (signed.length > 0) {
  const failures = ticks.flatMap((t) => t.failures);
  console.log(`  checkpoints: ${signed.length} of ${ticks.length} ticks signed, ${(signed.length * 2 / seconds).toFixed(1)} statements/s, ${(signed.reduce((s, t) => s + t.entries, 0) / signed.length).toFixed(0)} entries each, ${pct(signed.map((t) => t.tilesWritten), 50)} tiles written each`);
  console.log(`    database: seal p50/p99 ${pct(signed.map((t) => t.sealMs), 50).toFixed(2)}/${pct(signed.map((t) => t.sealMs), 99).toFixed(2)} ms, write ${pct(signed.map((t) => t.writeMs), 50).toFixed(2)}/${pct(signed.map((t) => t.writeMs), 99).toFixed(2)} ms  ${stmts.rows.map((r) => `[${r.calls} × ${r.ms} ms server: ${r.q}]`).join(' ')}`);
  console.log(`    checkpointer CPU: ${((self.user + self.system) / 1000 / (signed.length + 1)).toFixed(2)} ms per checkpoint all in (verify ${'MACs'}, hash, tree, sign, pg client), of which MAC+tree+sign p50/p99 ${pct(signed.map((t) => t.cpuMs), 50).toFixed(2)}/${pct(signed.map((t) => t.cpuMs), 99).toFixed(2)} ms`);
  console.log(`    window (oldest entry's commit → sealed): p50 ${pct(signed.map((t) => t.oldestToSealMs), 50).toFixed(0)} p99 ${pct(signed.map((t) => t.oldestToSealMs), 99).toFixed(0)} max ${Math.max(...signed.map((t) => t.oldestToSealMs)).toFixed(0)} ms` +
    (witnesses.length === 0 ? '' : `; → witnessed: p50 ${pct(signed.map((t) => t.oldestToWitnessedMs), 50).toFixed(0)} p99 ${pct(signed.map((t) => t.oldestToWitnessedMs), 99).toFixed(0)} max ${Math.max(...signed.map((t) => t.oldestToWitnessedMs)).toFixed(0)} ms (witness round trip p50 ${pct(signed.map((t) => t.witnessMs), 50).toFixed(0)} ms)`));
  console.log(`    tree: ${final!.size} leaves; ${failures.length === 0 ? 'no failures' : `FAILURES ${failures.slice(0, 3).join('; ')}`}`);
}
rmSync(scratch, { recursive: true, force: true });
await db.end();

// What a tick costs on Postgres at R44's rate (docs/design/audit-tree.md,
// "Numbers"): a loader in a process of its own appends `rate` entries a
// second, one in a hundred a change, each under the fence's lock shared as
// use_credential takes it, so that close_one waits for the appends in
// flight; the checkpointer ticks every 500 ms through the vault's login,
// its memory an fsynced file, and reports each tick's barrier, window read,
// write and CPU. On a Postgres of your own, never the shared one: it empties
// the log's tables of the database the URLs name.
//
//   node --conditions=coffre:source packages/vault/scripts/checkpoint-bench.ts <owner url> <vault url> [rate] [seconds] [dir]
import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { fileMemory } from '../src/checkpointer-node.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';

const [ownerUrl, vaultUrl, rateArg, secondsArg, dirArg] = process.argv.slice(2);
if (ownerUrl === undefined || vaultUrl === undefined) throw new Error('usage: checkpoint-bench.ts <owner url> <vault url> [rate] [seconds] [dir]');
const rate = Number(rateArg ?? 1000);
const seconds = Number(secondsArg ?? 60);

if (process.env.BENCH_LOADER === '1') {
  // The loader: `rate` appends a second for `seconds`, over 16 connections.
  const key = logMacKey(Buffer.from(process.env.BENCH_SEED!, 'hex'));
  const pool = postgresClient(ownerUrl, { max: 16 });
  const end = Date.now() + seconds * 1000;
  let sent = 0;
  const start = Date.now();
  const inflight = new Set<Promise<unknown>>();
  while (Date.now() < end) {
    const due = Math.floor(((Date.now() - start) / 1000) * rate);
    while (sent < due) {
      sent += 1;
      const at = Date.now();
      const p = sent % 100 === 0
        ? (() => {
          const row = { at, requestId: `c-${randomUUID()}`, object: randomUUID(), actor: 'vault', payload: '{"op":"genesis"}', seal: randomBytes(16) };
          return pool.unsafe(`WITH l AS (SELECT pg_advisory_xact_lock_shared(1668244070, 0))
            INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) SELECT nextval('log_number'), $1, $2, $3, $4, $5, $6, $7 FROM l`,
          [row.at, row.requestId, row.object, row.actor, row.payload, row.seal, entryMac(key, { tree: 'changes', row })]);
        })()
        : (() => {
          const row = { at, requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
          return pool.unsafe(`WITH l AS (SELECT pg_advisory_xact_lock_shared(1668244070, 0))
            INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) SELECT nextval('log_number'), $1, $2, $3, $4, $5, $6, $7 FROM l`,
          [row.at, String(row.requestId), row.credential, row.secret, row.purpose, entryMac(key, { tree: 'uses', row }), row.place]);
        })();
      // Sent now: postgres.js sends a query only once it is executed or awaited.
      inflight.add(p.execute());
      void p.finally(() => inflight.delete(p));
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  await Promise.all(inflight);
  await pool.end();
  process.send?.({ sent });
  process.exit(0);
}

const seed = randomBytes(32);
const owner = postgresClient(ownerUrl, { max: 2 });
for (const table of ['log_checkpoints', 'log_tiles', 'log_changes', 'log_uses']) await owner.unsafe(`DELETE FROM ${table}`);
await owner.unsafe(`UPDATE log_fence SET at_floor = $1`, [Date.now() - 3000]);
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
await owner.unsafe('SELECT make_day($1::date), make_day($2::date)', [day(Date.now()), day(Date.now() + 86_400_000)]);
await owner.unsafe('CHECKPOINT');

const dir = dirArg ?? mkdtempSync(join(tmpdir(), 'coffre-checkpoint-bench-'));
const memoryFile = join(dir, `memory-${process.pid}`);
const vaultPool = postgresClient(vaultUrl, { max: 1 });
const database = createDatabase(vaultPool);
const cp = await openLogCheckpointer({ store: logStore(database), signingKeys: [seed], memory: fileMemory(memoryFile) });

const loader = fork(new URL(import.meta.url), [ownerUrl, vaultUrl, String(rate), String(seconds)], {
  env: { ...process.env, BENCH_LOADER: '1', BENCH_SEED: seed.toString('hex') },
  execArgv: ['--conditions=coffre:source'],
});
const done = new Promise<{ sent: number }>((resolve) => loader.on('message', (m) => resolve(m as { sent: number })));

type Sample = { entries: number; closeMs: number; writeMs: number; cpuMs: number; wallMs: number };
const samples: Sample[] = [];
const stop = Date.now() + seconds * 1000;
while (Date.now() < stop) {
  const t0 = performance.now();
  const c0 = process.cpuUsage();
  const t = await cp.tick();
  const c = process.cpuUsage(c0);
  if (t.failures.length > 0) throw new Error(`tick refused: ${t.failures.join('; ')}`);
  if (t.signed) samples.push({ entries: t.entries, closeMs: t.closeMs, writeMs: t.writeMs, cpuMs: (c.user + c.system) / 1000, wallMs: performance.now() - t0 });
  await new Promise((resolve) => setTimeout(resolve, Math.max(0, 500 - (performance.now() - t0))));
}
const { sent } = await done;
const [tiles] = await owner.unsafe<[{ n: number; bytes: string }]>(`SELECT count(*)::int AS n, pg_size_pretty(sum(pg_column_size(hashes))) AS bytes FROM log_tiles`);
const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
const kept = samples.slice(Math.floor(samples.length / 10));
const line = (name: string, xs: number[]) => `${name} p50 ${q(xs, 0.5).toFixed(2)} / p99 ${q(xs, 0.99).toFixed(2)} ms`;
console.log(`${sent} entries in ${seconds} s (${(sent / seconds).toFixed(0)}/s), ${samples.length} ticks, ${q(kept.map((s) => s.entries), 0.5)} entries a tick p50; trees ${cp.pair.pair.changes.size} changes, ${cp.pair.pair.uses.size} uses; ${tiles.n} tiles, ${tiles.bytes}`);
console.log([line('barrier + window', kept.map((s) => s.closeMs)), line('write', kept.map((s) => s.writeMs)), line('tick wall', kept.map((s) => s.wallMs)), line('checkpointer CPU', kept.map((s) => s.cpuMs))].join('; '));
await vaultPool.end();
await owner.end();
if (dirArg === undefined) rmSync(dir, { recursive: true, force: true });

// What a tick costs in the checkpointer's Durable Object (docs/design/
// audit-tree.md, "Numbers"): workerd, as `wrangler dev` runs it, with the
// object ticking on its alarm through Hyperdrive's local connection, while
// checkpoint-bench.ts's loader appends `rate` entries a second. Reports each
// tick's barrier and window, write and wall time inside the object. On a
// Postgres of your own: it empties the log's tables.
//
//   node --conditions=coffre:source packages/vault/scripts/checkpoint-bench-workers.ts <owner url> <vault url> [rate] [seconds]
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { pairSigners } from '@coffre/core/merkle';
import pg from 'pg';
import { unstable_dev } from 'wrangler';

import { logOrigin } from '../src/checkpointer.ts';

const [ownerUrl, vaultUrl, rateArg, secondsArg] = process.argv.slice(2);
if (ownerUrl === undefined || vaultUrl === undefined) throw new Error('usage: checkpoint-bench-workers.ts <owner url> <vault url> [rate] [seconds]');
const rate = Number(rateArg ?? 1000);
const seconds = Number(secondsArg ?? 60);

const seed = randomBytes(32);
const owner = new pg.Pool({ connectionString: ownerUrl, max: 2 });
for (const table of ['log_checkpoints', 'log_tiles', 'log_changes', 'log_uses']) await owner.query(`DELETE FROM ${table}`);
await owner.query(`UPDATE log_fence SET at_floor = $1`, [Date.now() - 3000]);
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
await owner.query('SELECT make_day($1::date), make_day($2::date)', [day(Date.now()), day(Date.now() + 86_400_000)]);

const signers = await pairSigners(await logOrigin(seed), seed);
const dir = mkdtempSync(join(tmpdir(), 'coffre-checkpoint-bench-workers-'));
writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
  name: 'coffre-checkpoint-bench',
  compatibility_date: '2026-08-06',
  compatibility_flags: ['nodejs_compat'],
  vars: {
    VAULT_KEY: randomBytes(32).toString('base64'), SIGNING_KEY: seed.toString('base64'), WITNESS_KEY: randomBytes(32).toString('base64'),
    LOG_KEYS: JSON.stringify({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }),
  },
  hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'checkpoint-bench', localConnectionString: vaultUrl }],
  durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }, { name: 'WITNESS', class_name: 'CoffreWitness' }] },
  migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer', 'CoffreWitness'] }],
  r2_buckets: [{ binding: 'ARCHIVE', bucket_name: 'checkpoint-bench' }],
}));
process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
const worker = await unstable_dev(fileURLToPath(new URL('../test/workers/checkpointer-worker.ts', import.meta.url)), {
  config: join(dir, 'wrangler.json'),
  local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
  experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
});
const ask = async <T>(op: string): Promise<T> => (await (await worker.fetch('/', { method: 'POST', body: JSON.stringify({ op }) })).json()) as T;
await ask('start');

const loader = fork(new URL('./checkpoint-bench.ts', import.meta.url), [ownerUrl, vaultUrl, String(rate), String(seconds)], {
  env: { ...process.env, BENCH_LOADER: '1', BENCH_SEED: seed.toString('hex') },
  execArgv: ['--conditions=coffre:source'],
});
type T = { at: number; entries: number; signed: boolean; closeMs: number; writeMs: number; wallMs: number };
const ticks = new Map<number, T>();
const end = Date.now() + seconds * 1000;
while (Date.now() < end) {
  await new Promise((resolve) => setTimeout(resolve, 10_000));
  for (const t of (await ask<{ ticks: T[] }>('status')).ticks) ticks.set(t.at, t);
}
await new Promise((resolve) => loader.on('exit', resolve));
const signed = [...ticks.values()].filter((t) => t.signed && t.entries > 100);
const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
const line = (name: string, xs: number[]) => `${name} p50 ${q(xs, 0.5).toFixed(2)} / p99 ${q(xs, 0.99).toFixed(2)} ms`;
console.log(`${signed.length} ticks sampled, ${q(signed.map((t) => t.entries), 0.5)} entries a tick p50, witnessed by the object's witness and archived in R2 each tick`);
console.log([line('barrier + window', signed.map((t) => t.closeMs)), line('write', signed.map((t) => t.writeMs)), line('tick wall', signed.map((t) => t.wallMs))].join('; '));
await worker.stop();
await owner.end();
rmSync(dir, { recursive: true, force: true });

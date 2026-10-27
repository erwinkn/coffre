// What R51's wait costs a change (docs/design/0.15-plan.md, "As built: PR
// 4b"): changes, `concurrency` at a time, each one transaction that takes
// the fence exclusive, inserts its entry and commits, as change_input does;
// then `sealThrough` of its number, timed from the commit. The checkpointer
// also ticks every 500 ms, as it runs, and a loader appends `rate` uses a
// second under the fence shared, as use_credential does. No witness. On a
// Postgres of your own, never the shared one: it empties the log's tables of
// the database the URLs name.
//
//   node --conditions=coffre:source packages/vault/scripts/seal-wait-bench.ts <owner url> <vault url> [changes] [concurrency] [rate]
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createDatabase } from '@coffre/db';
import pg from 'pg';

import { fileMemory } from '../src/checkpointer-node.ts';
import { openLogCheckpointer, TICK_MS } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';

const [ownerUrl, vaultUrl, changesArg, concurrencyArg, rateArg] = process.argv.slice(2);
if (ownerUrl === undefined || vaultUrl === undefined) throw new Error('usage: seal-wait-bench.ts <owner url> <vault url> [changes] [concurrency] [rate]');
const changes = Number(changesArg ?? 200);
const concurrency = Number(concurrencyArg ?? 1);
const rate = Number(rateArg ?? 0);

const seed = randomBytes(32);
const key = logMacKey(seed);
const owner = new pg.Pool({ connectionString: ownerUrl, max: 16 + concurrency });
for (const table of ['log_checkpoints', 'log_tiles', 'log_changes', 'log_uses']) await owner.query(`DELETE FROM ${table}`);
await owner.query(`UPDATE log_fence SET at_floor = $1`, [Date.now() - 3000]);
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
await owner.query('SELECT make_day($1::date), make_day($2::date)', [day(Date.now()), day(Date.now() + 86_400_000)]);

const dir = mkdtempSync(join(tmpdir(), 'coffre-seal-wait-'));
const vaultPool = new pg.Pool({ connectionString: vaultUrl, max: Number(process.env.BENCH_VAULT_POOL ?? 1) });
const cp = await openLogCheckpointer({ store: logStore(createDatabase(vaultPool)), seed, memory: fileMemory(join(dir, 'memory')) });

let running = true;
// The checkpointer's own beat, as runCheckpointer keeps it.
const beat = (async () => {
  while (running) {
    await cp.tick().catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, TICK_MS));
  }
})();
// Uses, `rate` a second, under the fence shared.
let used = 0;
const load = (async () => {
  if (rate === 0) return;
  const start = Date.now();
  const inflight = new Set<Promise<unknown>>();
  while (running) {
    const due = Math.floor(((Date.now() - start) / 1000) * rate);
    while (used < due) {
      used += 1;
      const row = { at: Date.now(), requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
      const p = owner.query(`WITH l AS (SELECT pg_advisory_xact_lock_shared(1668244070, 0))
        INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) SELECT nextval('log_number'), $1, $2, $3, $4, $5, $6, $7 FROM l`,
      [row.at, String(row.requestId), row.credential, row.secret, row.purpose, entryMac(key, { tree: 'uses', row }), row.place]);
      inflight.add(p);
      void p.finally(() => inflight.delete(p));
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  await Promise.all(inflight);
})();

async function change(): Promise<{ commitMs: number; sealMs: number }> {
  const client = await owner.connect();
  const t0 = performance.now();
  let number: bigint;
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(1668244070, 0)');
    const row = { at: Date.now(), requestId: `c-${randomUUID()}`, object: randomUUID(), actor: 'bench', payload: '{"op":"credential.issue"}', seal: randomBytes(16) };
    const { rows } = await client.query<{ number: string }>(
      `INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (nextval('log_number'), $1, $2, $3, $4, $5, $6, $7) RETURNING number`,
      [row.at, row.requestId, row.object, row.actor, row.payload, row.seal, entryMac(key, { tree: 'changes', row })],
    );
    await client.query('COMMIT');
    number = BigInt(rows[0]!.number);
  } finally {
    client.release();
  }
  const t1 = performance.now();
  await cp.sealThrough(number);
  return { commitMs: t1 - t0, sealMs: performance.now() - t1 };
}

await new Promise((resolve) => setTimeout(resolve, 1000));
const samples: { commitMs: number; sealMs: number }[] = [];
let next = 0;
const t0 = performance.now();
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (next < changes) {
    next += 1;
    samples.push(await change());
  }
}));
const wall = performance.now() - t0;
running = false;
await Promise.all([beat, load]);

const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
const line = (name: string, xs: number[]) => `${name} p50 ${q(xs, 0.5).toFixed(1)} / p90 ${q(xs, 0.9).toFixed(1)} / p99 ${q(xs, 0.99).toFixed(1)} ms`;
console.log(`${changes} changes, ${concurrency} at a time, ${rate} uses/s beside (${used} sent): ${(changes / (wall / 1000)).toFixed(0)} changes/s`);
console.log(`${line('commit', samples.map((s) => s.commitMs))}; ${line('seal wait', samples.map((s) => s.sealMs))}`);
await vaultPool.end();
await owner.end();
rmSync(dir, { recursive: true, force: true });

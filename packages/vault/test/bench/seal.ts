// What a change waits for its seal (R51) on Workers, with every round trip of the checkpointer's connection to Postgres
// held `SEAL_BENCH_RTT_MS` (20 by default, what each costs through Hyperdrive on Cloudflare, T112): the checkpointer's
// Durable Object in workerd, its alarm ticking, its Hyperdrive behind the proxy that holds each Sync (postgres-proxy.ts).
//
// Not part of the suite. On the suite's Postgres, as a test file:
//
//   scripts/test-suite.sh --files packages/vault/test/bench/seal.ts
//
// Prints the ticks' wall time and statements, and each change's seal, asked as the app asks it once its change has
// committed: a change every `SEAL_BENCH_GAP_MS` (700 by default, so that it lands anywhere in a tick), with uses landing
// beside at `SEAL_BENCH_USES` a second (0 by default).
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { postgresProxy } from '../../../../scripts/postgres-proxy.ts';
import { logMacKey } from '../../src/log-entry.ts';
import { openTestDatabase, VAULT_URL, type TestDatabase } from '../database.ts';
import { logWriter } from '../log-entries.ts';

const RTT = Number(process.env.SEAL_BENCH_RTT_MS ?? 20);
const GAP = Number(process.env.SEAL_BENCH_GAP_MS ?? 700);
const CHANGES = Number(process.env.SEAL_BENCH_CHANGES ?? 40);
const USES = Number(process.env.SEAL_BENCH_USES ?? 0);

let db: TestDatabase;
let worker: Unstable_DevWorker;
let proxy: Awaited<ReturnType<typeof postgresProxy>>;
let dir: string;
const seed = randomBytes(32);
const token = randomBytes(16).toString('hex');

before(async () => {
  db = await openTestDatabase();
  proxy = await postgresProxy(VAULT_URL, { delayMs: RTT });
  dir = mkdtempSync(join(tmpdir(), 'coffre-seal-bench-'));
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name: 'coffre-seal-bench',
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { VAULT_KEY: randomBytes(32).toString('base64'), SIGNING_KEY: seed.toString('base64'), TOKEN: token },
    hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'seal-bench', localConnectionString: proxy.url }],
    durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer'] }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('../workers/seal-bench-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  await worker?.stop();
  await proxy?.close();
  await db?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const ask = async <T>(op: string, number?: bigint): Promise<T> => {
  const response = await worker.fetch('/', { method: 'POST', headers: { 'x-token': token }, body: JSON.stringify({ op, number: number === undefined ? undefined : String(number) }), signal: AbortSignal.timeout(20_000) });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? String(response.status));
  return body;
};

const pct = (values: number[], p: number) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * p))]!;
const said = (values: number[]) => `p50 ${pct(values, 0.5).toFixed(0)}, p90 ${pct(values, 0.9).toFixed(0)}, max ${Math.max(...values).toFixed(0)} ms (n ${values.length})`;

test(`a change's seal, each round trip ${RTT} ms`, { timeout: 600_000 }, async () => {
  const log = logWriter(db.owner, logMacKey(seed));
  await log.empty();
  await log.days();
  await ask('start');
  // The first ticks open the checkpointer and make the days; then idle ticks alone.
  await sleep(3000);
  const s0 = proxy.syncs;
  const t0 = performance.now();
  await sleep(5000);
  const idle = (await ask<{ ticks: { wallMs: number; closeMs: number; writeMs: number; at: number }[] }>('status')).ticks.filter((t) => t.at >= Date.now() - 5000);
  const idleSyncs = proxy.syncs - s0;
  console.log(`idle: ${idle.length} ticks in ${((performance.now() - t0) / 1000).toFixed(1)} s, ${(idleSyncs / Math.max(1, idle.length)).toFixed(1)} Syncs a tick; tick wall ${said(idle.map((t) => t.wallMs))}; barrier+window ${said(idle.map((t) => t.closeMs))}`);

  let using = USES > 0;
  const uses = (async () => {
    while (using) {
      await log.use();
      await sleep(1000 / USES);
    }
  })();
  const seals: number[] = [];
  const s1 = proxy.syncs;
  for (let i = 0; i < CHANGES; i += 1) {
    await sleep(GAP * (0.5 + Math.random()));
    const number = await log.change();
    const t = performance.now();
    await ask<{ ms: number }>('seal', number);
    seals.push(performance.now() - t);
  }
  using = false;
  await uses;
  const ticks = (await ask<{ ticks: { wallMs: number; closeMs: number; writeMs: number }[] }>('status')).ticks;
  console.log(`changes: seal ${said(seals)}; ${((proxy.syncs - s1) / CHANGES).toFixed(1)} Syncs a change, ticks included; last ticks' wall ${said(ticks.map((t) => t.wallMs))}, barrier+window ${said(ticks.map((t) => t.closeMs))}, write ${said(ticks.map((t) => t.writeMs))}`);
});

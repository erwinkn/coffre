// T169 on Workers, in workerd: the vault's entrypoint and its checkpointer's
// object (test/workers/stall-worker.ts), the object's connection through a
// proxy that stops answering (stall-proxy.ts), as W278's bench met on
// Cloudflare. Meanwhile a use answers through the entrypoint as ever, a
// change committed answers unsealed within its bound, and `sealing` says
// the checkpointer does not seal; answered again, it seals by itself.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { UNSEALED, type Sealing, type UseOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { emptyDatabase, ENGINE, HOT_URL, openTestDatabase, run, VAULT_URL, type TestDatabase } from './database.ts';
import { stallProxy, type StallProxy } from './stall-proxy.ts';
import { ask, change, emptyLog, KEK, SIGNING_KEY, useDatabases, world } from './use-world.ts';

const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
let worker: Unstable_DevWorker;
let proxy: StallProxy;
let dir: string;

before(async () => {
  if (skip) return;
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyDatabase(db.owner);
  await emptyLog();
  for (const table of ['log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  proxy = await stallProxy(VAULT_URL);
  dir = mkdtempSync(join(tmpdir(), 'coffre-stall-worker-'));
  const name = 'coffre-stall-workers-test';
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name,
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { KEK: JSON.stringify(KEK), SIGNING_KEY: SIGNING_KEY.toString('base64'), TICK_BOUND_MS: '1000' },
    hyperdrive: [
      { binding: 'VAULT_HYPERDRIVE', id: 'stall-workers-test', localConnectionString: proxy.url },
      { binding: 'HOT_HYPERDRIVE', id: 'stall-workers-hot', localConnectionString: HOT_URL },
    ],
    durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer'] }],
    services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/stall-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'none',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  proxy?.release();
  await worker?.stop();
  await proxy?.close();
  if (db !== undefined) await emptyDatabase(db.owner);
  await db?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

async function call<T>(method: string, ...args: unknown[]): Promise<{ ok: true; result: T } | { ok: false; error: string }> {
  const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify({ method, args }), signal: AbortSignal.timeout(30_000) });
  return (await response.json()) as { ok: true; result: T } | { ok: false; error: string };
}

async function answered<T>(method: string, ...args: unknown[]): Promise<T> {
  const answer = await call<T>(method, ...args);
  assert.ok(answer.ok, answer.ok ? '' : answer.error);
  return answer.result;
}

/** Asks `sealing` until it says `ok`, or past `ms` throws with its last answer. */
const untilSealing = async (ok: boolean, ms: number, what: string) => {
  const end = Date.now() + ms;
  for (;;) {
    const said = await answered<Sealing>('sealing');
    if (said.ok === ok) return;
    if (Date.now() > end) throw new Error(`${what}: not within ${ms} ms; it said ${JSON.stringify(said)}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
};

test("T169, Workers: the checkpointer's connection stops answering: a use answers through the entrypoint, a change answers unsealed within its bound, sealing goes red; answered again, it seals by itself", { skip, timeout: 120_000 }, async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  // The first call starts the object; it seals within a tick or two.
  assert.equal((await answered<{ log?: string }>('about')).log, '0.15');
  await untilSealing(true, 20_000, 'sealing at first');
  assert.ok((await answered<UseOutcome>('use', ask(w, id))).ok);

  proxy.hold();
  let t0 = Date.now();
  await untilSealing(false, 8000, 'red');
  assert.ok(Date.now() - t0 < 8000);
  // A use waits on no checkpointer: its own connection, the hot path's.
  t0 = Date.now();
  const outcome = await answered<UseOutcome>('use', ask(w, id));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.ok(Date.now() - t0 < 2000, `the use took ${Date.now() - t0} ms`);
  // A change committed meanwhile: its seal answers unsealed within its bound, in core's words, the app's 503.
  const number = await change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, w.objects.principal, async () => {});
  t0 = Date.now();
  const unsealed = await call('waitSealed', { number: String(number) });
  assert.ok(!unsealed.ok && unsealed.error.includes(UNSEALED), JSON.stringify(unsealed));
  assert.ok(Date.now() - t0 < 12_000, `unsealed after ${Date.now() - t0} ms`);

  // Answered again: the object's next alarms open another checkpointer, which seals, the change among it.
  proxy.release();
  await untilSealing(true, 45_000, 'sealing again');
  assert.ok((await answered<{ ok: boolean }>('waitSealed', { number: String(number) })).ok);
  const status = await answered<{ ticks: { failures: string[] }[] }>('checkpointerStatus');
  assert.ok(status.ticks.every((t) => t.failures.length === 0), JSON.stringify(status.ticks.flatMap((t) => t.failures)));
});

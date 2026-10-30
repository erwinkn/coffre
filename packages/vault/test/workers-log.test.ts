// 0.15's log on Workers (T136): the vault's entrypoint configured with its
// hot path's Hyperdrive and its checkpointer's Durable Object
// (test/workers/log-worker.ts), as a deployment is. Its first call starts
// the object; it says it answers uses, and answers one, through the
// entrypoint; its first call waits for the cutover's seal, which the object
// makes.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { decrypt } from '@coffre/core/envelope';
import type { UseOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { emptyDatabase, ENGINE, HOT_URL, openTestDatabase, rows, VAULT_URL, type TestDatabase } from './database.ts';
import { ask, emptyLog, KEK, SIGNING_KEY, useDatabases, world } from './use-world.ts';

const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
let worker: Unstable_DevWorker;
let dir: string;

before(async () => {
  if (skip) return;
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyDatabase(db.owner);
  await emptyLog();
  dir = mkdtempSync(join(tmpdir(), 'coffre-log-worker-'));
  const name = 'coffre-log-workers-test';
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name,
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { KEK: JSON.stringify(KEK), SIGNING_KEY: SIGNING_KEY.toString('base64') },
    hyperdrive: [
      { binding: 'VAULT_HYPERDRIVE', id: 'log-workers-test', localConnectionString: VAULT_URL },
      { binding: 'HOT_HYPERDRIVE', id: 'log-workers-hot', localConnectionString: HOT_URL },
    ],
    durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer'] }],
    services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/log-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  await worker?.stop();
  if (db !== undefined) await emptyDatabase(db.owner);
  await db?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

async function call<T>(method: string, ...args: unknown[]): Promise<T> {
  const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify({ method, args }), signal: AbortSignal.timeout(30_000) });
  const body = (await response.json()) as { ok: boolean; result?: T; error?: string };
  assert.ok(body.ok, body.error ?? 'the call failed');
  return body.result as T;
}

test("on Workers, the vault starts its checkpointer from its first call, says it answers uses, and a use through the entrypoint opens its value, its entry the log's", { skip, timeout: 120_000 }, async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  assert.equal((await call<{ open: boolean }>('checkpointerStatus')).open, false, 'nothing started it yet');
  const about = await call<{ log?: string; uses?: boolean }>('about');
  assert.equal(about.log, '0.15');
  assert.equal(about.uses, true);
  // Started, and open, before the first call answered: no call meets a log with no checkpoint.
  assert.equal((await call<{ open: boolean }>('checkpointerStatus')).open, true);
  const outcome = await call<UseOutcome>('use', ask(w, id));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const { value } = outcome;
  const plain = decrypt({ envelopeVersion: value.envelope.version, ciphertext: Buffer.from(value.envelope.ciphertext, 'base64'), iv: Buffer.from(value.envelope.iv, 'base64'), authTag: Buffer.from(value.envelope.authTag, 'base64') },
    value.context, Buffer.from(value.key, 'base64'));
  assert.equal(plain.toString(), 'postgres://prod');
  assert.deepEqual(await rows<{ secret: string }>(db.owner, sql`SELECT secret::text FROM log_uses`), [{ secret: id }]);
});

test('on Workers, a vault with no checkpointer bound is refused at its first call, by name', { skip, timeout: 120_000 }, async () => {
  const bare = mkdtempSync(join(tmpdir(), 'coffre-log-worker-bare-'));
  const name = 'coffre-log-workers-bare';
  writeFileSync(join(bare, 'wrangler.json'), JSON.stringify({
    name,
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { KEK: JSON.stringify(KEK), SIGNING_KEY: SIGNING_KEY.toString('base64') },
    hyperdrive: [
      { binding: 'VAULT_HYPERDRIVE', id: 'log-workers-test', localConnectionString: VAULT_URL },
      { binding: 'HOT_HYPERDRIVE', id: 'log-workers-hot', localConnectionString: HOT_URL },
    ],
    services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
  }));
  const unbound = await unstable_dev(fileURLToPath(new URL('./workers/log-worker.ts', import.meta.url)), {
    config: join(bare, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'none',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
  try {
    const response = await unbound.fetch('/', { method: 'POST', body: JSON.stringify({ method: 'about', args: [] }), signal: AbortSignal.timeout(30_000) });
    const body = (await response.json()) as { ok: boolean; error?: string };
    assert.equal(body.ok, false);
    assert.match(body.error ?? '', /set checkpointer in vault\(…\), env\.CHECKPOINTER/);
  } finally {
    await unbound.stop();
    rmSync(bare, { recursive: true, force: true });
  }
});

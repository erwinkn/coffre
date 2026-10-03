// The vault in workerd, as it runs on Cloudflare: a page load fires a
// handful of calls at once, and on a fresh isolate they are its first. On
// Cloudflare, a call that waits on a promise only another call's I/O can
// settle is cancelled as hung when that call goes; local workerd lets it
// finish, so isolate.test.ts holds the vault to that rule, and this runs the
// same bursts through the entrypoint, over a database as slow as Hyperdrive
// from far away.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { emptyDatabase, ENGINE, openTestDatabase, places, VAULT_URL, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
before(async () => {
  if (!skip) db = await openTestDatabase();
});
after(() => db?.close());
beforeEach(async () => {
  if (!skip) await emptyDatabase(db.owner);
});

/**
 * Postgres as Hyperdrive serves it from far away: each chunk either way
 * delayed by `ms`. Locally a query answers in well under a millisecond,
 * which hides calls waiting on each other's I/O.
 */
async function slowPostgres(ms: number): Promise<{ url: string; close(): Promise<void> }> {
  const target = new URL(VAULT_URL);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) =>
      from.on('data', (chunk) => setTimeout(() => to.write(chunk), ms));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  const url = new URL(VAULT_URL);
  url.port = String(address.port);
  return { url: url.href, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

/** A fresh isolate of the vault Worker, over the suite's database through the vault's login. */
async function freshVault(database: string): Promise<{
  call(method: string, ...args: unknown[]): Promise<{ ok: boolean; error?: string }>;
  stop(): Promise<void>;
}> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-worker-'));
  const name = 'coffre-vault-workers-test';
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { VAULT_KEY: randomBytes(32).toString('base64') },
      hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'vault-workers-test', localConnectionString: database }],
      services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  let worker: Unstable_DevWorker;
  try {
    worker = await unstable_dev(fileURLToPath(new URL('./workers/vault-worker.ts', import.meta.url)), {
      config: join(dir, 'wrangler.json'),
      local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
    });
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  return {
    async call(method, ...args) {
      const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify({ method, args }), signal: AbortSignal.timeout(20_000) });
      const text = await response.text();
      try {
        return JSON.parse(text) as { ok: boolean; error?: string };
      } catch {
        return { ok: false, error: `${response.status}: ${text}` };
      }
    },
    async stop() {
      await worker.stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function assertAllAnswered(results: { ok: boolean; error?: string }[]): void {
  const failed = results.filter((result) => !result.ok).map((result) => result.error);
  assert.deepEqual(failed, [], 'every call answered, none cancelled as hung');
}

test('a fresh isolate answers a page load of concurrent first calls', { skip, timeout: 120_000 }, async () => {
  const database = await slowPostgres(20);
  const vault = await freshVault(database.url);
  try {
    const results = await Promise.all([
      vault.call('access', ROOT),
      vault.call('access', ROOT),
      vault.call('access', 'user:ada@acme.example'),
      vault.call('access', 'user:bob@acme.example'),
      vault.call('about'),
      vault.call('about'),
      vault.call('verifyLog', {}),
      vault.call('verifyLog', {}),
    ]);
    assertAllAnswered(results);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('a fresh isolate answers concurrent first key operations', { skip, timeout: 120_000 }, async () => {
  const placed = await places(db.owner);
  const secrets = await Promise.all(Array.from({ length: 6 }, () => placed.secret(placed.dev)));
  const database = await slowPostgres(20);
  const vault = await freshVault(database.url);
  try {
    // Settled by one call first, so that what is tested here is the key check before the first key operation.
    assert.ok((await vault.call('access', ROOT)).ok);
    const results = await Promise.all(
      secrets.map((secret) => vault.call('wrap', { principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] })),
    );
    assertAllAnswered(results);
  } finally {
    await vault.stop();
    await database.close();
  }
});


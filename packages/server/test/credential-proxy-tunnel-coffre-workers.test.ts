// The tunnel through coffre's own Durable Object, `createCoffre(…).Sockets`,
// in workerd, as a Workers deployment runs it (test/workers/coffre-worker.ts):
// the object's coffre, its database client over Hyperdrive opened and closed
// with its queries, the migration door, the vault over its service binding,
// and the plugin's admission, log entries and rechecks. The data is the
// suite's, seeded from Node with the vault's and the log's keys, which the
// Worker is given too. Postgres only.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { clientFor } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { deps, DEV, entries, ROOT, route, sessionFor, useMcp } from './mcp-fixture.ts';
import { tunnelListener } from './tunnel-listener.ts';

const skip = TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database, over Hyperdrive' : false;
const NAME = 'coffre-tunnel-coffre-workers-test';

let dir: string;
let worker: Unstable_DevWorker;
let handle: string;

useMcp(async () => {
  if (skip) return;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { DATABASE_URL: { value: `${TEST_RUNTIME_DATABASE_URL}?sslmode=disable`, sensitivity: 'sensitive' } });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  handle = (await (await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) })).json() as { token: string }).token;
});

/** The Worker, once the suite's instance exists: it is given the instance's keys. */
async function boot(): Promise<void> {
  dir = mkdtempSync(join(tmpdir(), 'coffre-tunnel-coffre-worker-'));
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name: NAME,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      // The keys the suite's instance seeds with: the vault opens what it wrote, and the log goes on from its head.
      vars: { APP_KEY: deps.chainKey.toString('base64'), VAULT_KEY: (deps.vault as unknown as { kek: Buffer }).kek.toString('base64') },
      hyperdrive: [
        { binding: 'HYPERDRIVE', id: 'coffre-app', localConnectionString: TEST_RUNTIME_DATABASE_URL },
        { binding: 'VAULT_HYPERDRIVE', id: 'coffre-vault', localConnectionString: TEST_VAULT_DATABASE_URL },
      ],
      services: [{ binding: 'VAULT', service: NAME, entrypoint: 'Vault' }],
      durable_objects: { bindings: [{ name: 'SOCKETS', class_name: 'CoffreSockets' }] },
      migrations: [{ tag: 'sockets', new_sqlite_classes: ['CoffreSockets'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/coffre-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
}

after(async () => {
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

test("a run's session in coffre's object: admitted and logged as on Node, rechecked a second, and ended once its handle is revoked", { skip, timeout: 180_000 }, async () => {
  await boot();
  const listener = await tunnelListener(`ws://${worker.address}:${worker.port}/use/market/dev/db`, handle);
  try {
    const client = new pg.Client({ connectionString: `postgres://app:${handle}@127.0.0.1:${listener.port}/app` });
    client.on('error', () => undefined);
    const ended = new Promise((resolve) => client.once('end', resolve));
    await client.connect();
    assert.deepEqual((await client.query('SELECT current_user AS who')).rows, [{ who: 'coffre_runtime' }]);
    // One use at admission, as on Node; then the object's check, a use too, each second.
    const admitted = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'db');
    assert.equal(admitted.length, 1);
    assert.equal(admitted[0]!.metadata.tunnel, true);
    for (let waited = 0; waited < 5000; waited += 100) {
      if ((await entries('credential.use')).some((entry) => entry.metadata.recheck === true)) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.ok((await entries('credential.use')).some((entry) => entry.metadata.recheck === true), 'the object rechecked the handle');
    assert.deepEqual((await client.query('SELECT 1 AS one')).rows, [{ one: 1 }]);

    // Revoked from Node, as `coffre tokens revoke` does: the object's next check ends the session.
    const session = await sessionFor(DEV);
    const listed = (await (await route(`/api/members/user:${DEV}/tokens`, { headers: { authorization: `Bearer ${session}` } })).json()) as { tokens: { id: string; hint: string }[] };
    const id = listed.tokens.find((token) => token.hint.endsWith(handle.slice(-4)))!.id;
    await route(`/api/members/user:${DEV}/tokens/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
    const revoked = Date.now();
    await ended;
    assert.ok(Date.now() - revoked < 5000, `the session outlived its handle by ${Date.now() - revoked} ms`);
    // And a new connection is refused at admission.
    const refused = new pg.Client({ connectionString: `postgres://app:${handle}@127.0.0.1:${listener.port}/app` });
    refused.on('error', () => undefined);
    await assert.rejects(refused.connect());
  } finally {
    listener.close();
  }
});

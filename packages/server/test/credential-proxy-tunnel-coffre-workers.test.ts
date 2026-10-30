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

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';


import { clientFor, usesLogged } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { db, deps, DEV, ROOT, route, sessionFor, useMcp } from './mcp-fixture.ts';
import { appClient, tunnelListener } from './tunnel-listener.ts';

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
        { binding: 'HOT_HYPERDRIVE', id: 'coffre-vault-hot', localConnectionString: TEST_HOT_DATABASE_URL },
      ],
      services: [{ binding: 'VAULT', service: NAME, entrypoint: 'Vault' }],
      durable_objects: { bindings: [{ name: 'SOCKETS', class_name: 'CoffreSockets' }, { name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }] },
      migrations: [{ tag: 'sockets', new_sqlite_classes: ['CoffreSockets'] }, { tag: 'checkpointer', new_sqlite_classes: ['CoffreCheckpointer'] }],
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
    const client = appClient(listener.port, handle);
    assert.deepEqual([...await client.unsafe('SELECT current_user AS who')], [{ who: 'coffre_runtime' }]);
    // One use at admission, 0.15's, as on Node (the Worker's vault keeps 0.15's log, cut over by its app's door if
    // the suite's instance was not); then the object's check each second, a use its isolate's cover may leave
    // unlogged: the revoke below, which a check finds, is what shows them.
    assert.equal((await usesLogged(db.owner)).filter((use) => use.purpose === 4).length, 1);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);

    // Revoked from Node, as `coffre tokens revoke` does: the object's next check ends the session.
    const session = await sessionFor(DEV);
    const listed = (await (await route(`/api/members/user:${DEV}/tokens`, { headers: { authorization: `Bearer ${session}` } })).json()) as { tokens: { id: string; hint: string }[] };
    const id = listed.tokens.find((token) => token.hint.endsWith(handle.slice(-4)))!.id;
    await route(`/api/members/user:${DEV}/tokens/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
    const revoked = Date.now();
    await client.ended;
    assert.ok(Date.now() - revoked < 5000, `the session outlived its handle by ${Date.now() - revoked} ms`);
    // And a new connection is refused at admission.
    const refused = appClient(listener.port, handle);
    await assert.rejects(refused.unsafe('SELECT 1'));
    await refused.end();
    await client.end();
  } finally {
    listener.close();
  }
});

// The door below this version's migrations (src/app.ts, `respond`): a
// database an earlier release migrated lacks this one's ledger rows, and
// until `coffre migrate` adds them every path but health answers 503
// `migrating`, sign-in, MCP and a CI run's exchange included, with the vault
// asked nothing. Once the app has seen its database migrated, it asks no
// more. A database that cannot be reached is let through, to meet the outage
// as any request would; any other failure of the question fails the request,
// a pool with no connection to give with 503 (D238).
// app.test.ts holds a database never migrated, which has no ledger at all.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { migrationLedger } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { coffreRoute, respond, schemaReady } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';

const ORIGIN = 'https://secrets.acme.example';
const [app, owner] = await Promise.all([openDatabase(TEST_RUNTIME_DATABASE_URL), openDatabase(TEST_OWNER_DATABASE_URL)]);
after(() => Promise.all([app.close(), owner.close()]));

/** Every vault call any runtime here made, by name: the door asks none. */
const asked: string[] = [];
const vault = new Proxy({} as Vault, {
  get: (_target, name) => () => {
    asked.push(String(name));
    return Promise.reject(new Error(`the vault was asked ${String(name)}`));
  },
});

/** A runtime that has not seen its database migrated yet, as a fresh isolate's or process's. `db`: another than the app's. */
function freshRuntime(db: Database = app.db): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault,
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
    auditChainKey: Buffer.alloc(32, 3).toString('base64'),
  });
  return createRuntime(config, db, vault, { transport: { json: (url) => Promise.reject(new Error(`fetched ${url}`)) }, gates: null });
}

/** One request as Start answers it: coffre's middleware, then coffre's route, or else a page. */
async function ask(runtime: CoffreRuntime, path: string, init: RequestInit & { accept?: string } = {}) {
  let rendered = false;
  const { accept = 'application/json', ...rest } = init;
  const request = new Request(`${ORIGIN}${path}`, { ...rest, headers: { accept, ...rest.headers } });
  const response = await respond(request, runtime, null, async () => {
    rendered = true;
    return (await coffreRoute(request, runtime, null)) ?? new Response('<p>a page</p>', { headers: { 'content-type': 'text/html' } });
  });
  return { status: response.status, type: response.headers.get('content-type') ?? '', retry: response.headers.get('retry-after'), body: await response.text(), rendered };
}

/** The ledger's rows forgotten while `work` runs, as on a database an earlier release migrated: this release's are not there. */
async function migratedBefore(work: () => Promise<void>): Promise<void> {
  const ledger = migrationLedger(owner.db);
  const entries = [...(await owner.db.execute<Record<string, unknown>>(sql`SELECT * FROM ${ledger}`))];
  assert.ok(entries.length > 0, 'the suite database is migrated');
  // The earlier release's: all but this one's last.
  await owner.db.execute(sql`DELETE FROM ${ledger} WHERE id = (SELECT max(id) FROM ${ledger})`);
  try {
    await work();
  } finally {
    await owner.db.execute(sql`DELETE FROM ${ledger}`);
    for (const entry of entries) {
      const columns = Object.keys(entry);
      await owner.db.execute(sql`INSERT INTO ${ledger} (${sql.join(columns.map((column) => sql.identifier(column)), sql`, `)})
        VALUES (${sql.join(columns.map((column) => sql`${entry[column]}`), sql`, `)})`);
    }
  }
}

test("on a database an earlier release migrated, the app serves nothing but its health: sign-in, MCP and a CI run's exchange answer 503 migrating, and the vault is asked nothing", async () => {
  asked.length = 0;
  const runtime = freshRuntime();
  await migratedBefore(async () => {
    const api = await ask(runtime, '/api/me', { headers: { authorization: 'Bearer coffre_cli_x' } });
    assert.deepEqual([api.status, api.rendered, (JSON.parse(api.body) as { error: string }).error, api.retry], [503, false, 'migrating', '30']);
    assert.match(api.body, /an owner runs `coffre migrate`, as every deploy does first/);
    for (const [path, method] of [['/auth/signin/github', 'GET'], ['/mcp', 'POST'], ['/api/auth/oidc', 'POST'], ['/api/auth', 'GET'], ['/api/auth/device', 'POST'], ['/api/oauth/token', 'POST'], ['/.well-known/oauth-authorization-server', 'GET']] as const) {
      const answer = await ask(runtime, path, { method });
      assert.deepEqual([answer.status, answer.rendered, answer.retry], [503, false, '30'], path);
    }
    const page = await ask(runtime, '/projects', { accept: 'text/html,application/xhtml+xml' });
    assert.deepEqual([page.status, page.rendered, page.type], [503, false, 'text/html; charset=utf-8']);
    assert.match(page.body, /coffre's database lacks this version's migrations/);
    // Health answers: alive, and not ready.
    assert.equal((await ask(runtime, '/livez')).status, 200);
    const ready = await ask(runtime, '/readyz');
    assert.deepEqual([ready.status, JSON.parse(ready.body)], [503, { ok: false }]);
    assert.equal(runtime.schema.migrated, false);
  });
  assert.deepEqual(asked, []);
});

test('once the app has seen its database migrated, it asks no more', async () => {
  const runtime = freshRuntime();
  const page = await ask(runtime, '/projects', { accept: 'text/html' });
  assert.deepEqual([page.status, page.rendered], [200, true]);
  assert.equal(runtime.schema.migrated, true);
  await migratedBefore(async () => {
    // Known for as long as its configuration lives: the isolate's, or the process's.
    assert.equal((await ask(runtime, '/projects', { accept: 'text/html' })).rendered, true);
    // A fresh one asks, and is below the door.
    assert.equal((await ask(freshRuntime(), '/projects', { accept: 'text/html' })).status, 503);
  });
});

test('a database that cannot be reached is let through the door, to meet its outage; any other failure of the question fails the request', async (t) => {
  t.mock.method(console, 'error', () => undefined);
  const failing = (error: unknown) => ({ execute: () => Promise.reject(error), select: () => { throw error; } }) as unknown as Database;
  const coded = (message: string, code: string) => Object.assign(new Error(message), { code });
  for (const error of [coded('connect ECONNREFUSED 127.0.0.1:1', 'ECONNREFUSED'), new Error('Server connection attempt failed: destination_unavailable')]) {
    const runtime = freshRuntime(failing(error));
    assert.equal(await schemaReady(runtime), true, error.message);
    // Not known as migrated: the next request asks again.
    assert.equal(runtime.schema.migrated, false);
  }
  // A pool with no connection to give is the database busy, no outage (D238): it fails the request, with 503.
  for (const error of [coded('permission denied for schema drizzle', '42501'), coded('canceling statement due to lock timeout', '55P03'), new Error('Failed to acquire a connection from the pool.')]) {
    await assert.rejects(schemaReady(freshRuntime(failing(error))), error, error.message);
  }
  // As a request meets it: the page renders, to show its own error state, for the outage; a 500 for the rest.
  const unreachable = await ask(freshRuntime(failing(coded('connect ECONNREFUSED 127.0.0.1:1', 'ECONNREFUSED'))), '/projects', { accept: 'text/html' });
  assert.deepEqual([unreachable.status, unreachable.rendered], [200, true]);
  const denied = await ask(freshRuntime(failing(coded('permission denied for schema drizzle', '42501'))), '/projects', { accept: 'text/html' });
  assert.deepEqual([denied.status, denied.rendered], [500, false]);
  const busy = await ask(freshRuntime(failing(new Error('Failed to acquire a connection from the pool.'))), '/api/projects');
  assert.deepEqual([busy.status, busy.rendered], [503, false]);
});

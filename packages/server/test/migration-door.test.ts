import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { github, signin, type Principal } from '@coffre/core/identity';
import { isUnreachable, migrationLedger } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import { coffreRoute, respond, runScheduled } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { openTestDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://coffre.test';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, ['admin@acme.example']);
});

after(async () => {
  await db.close();
});

/** A runtime that has not yet seen its database migrated, as a fresh isolate or process. */
function freshRuntime(): CoffreRuntime {
  return {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    signin: null,
    workloads: null,
    mcp: null,
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }).resolve(ORIGIN),
    publicUrl: ORIGIN,
    verifier: { verify: async (token: string): Promise<Principal> => ({ type: 'user', id: token, email: token, subject: token }) },
    waitUntil,
    schema: { migrated: false },
  };
}

/** One request as Start answers it: coffre's middleware, then coffre's routes, or a page. */
async function ask(runtime: CoffreRuntime, path: string, accept = 'application/json'): Promise<{ status: number; type: string; body: string; rendered: boolean }> {
  let rendered = false;
  const request = new Request(`${ORIGIN}${path}`, { headers: { accept } });
  const response = await respond(request, runtime, null, async () => {
    rendered = true;
    return (await coffreRoute(request, runtime, null)) ?? new Response('<p>a page</p>', { headers: { 'content-type': 'text/html' } });
  });
  return { status: response.status, type: response.headers.get('content-type') ?? '', body: await response.text(), rendered };
}

/** No ledger at all while `work` runs, as on a database never migrated: the table moved aside, its grants with it. */
async function neverMigrated(work: () => Promise<void>): Promise<void> {
  const [away, back] = TEST_ENGINE === 'sqlite'
    ? [sql`ALTER TABLE __drizzle_migrations RENAME TO __drizzle_migrations_away`, sql`ALTER TABLE __drizzle_migrations_away RENAME TO __drizzle_migrations`]
    : [sql`ALTER TABLE drizzle.__drizzle_migrations RENAME TO __drizzle_migrations_away`, sql`ALTER TABLE drizzle.__drizzle_migrations_away RENAME TO __drizzle_migrations`];
  await run(away);
  try {
    await work();
  } finally {
    await run(back);
  }
}

/** The ledger's rows forgotten while `work` runs, as on a database migrated by an earlier release. */
async function unmigrated(work: () => Promise<void>): Promise<void> {
  const ledger = migrationLedger(db.owner);
  const entries = await rows(sql`SELECT * FROM ${ledger}`);
  await run(sql`DELETE FROM ${ledger}`);
  try {
    await work();
  } finally {
    for (const entry of entries) {
      const columns = Object.keys(entry);
      await run(sql`INSERT INTO ${ledger} (${sql.join(columns.map((column) => sql.identifier(column)), sql`, `)})
        VALUES (${sql.join(columns.map((column) => sql`${entry[column]}`), sql`, `)})`);
    }
  }
}

test('below its migrations, the app serves nothing but its health: the API and the pages answer 503 migrating, readiness is red', async () => {
  const runtime = freshRuntime();
  await unmigrated(async () => {
    const api = await ask(runtime, '/api/me');
    assert.deepEqual([api.status, api.rendered, (JSON.parse(api.body) as { error: string }).error], [503, false, 'migrating']);
    assert.match(api.body, /an owner runs `coffre migrate`, as every deploy does first/);
    for (const path of ['/auth/signin/github', '/mcp', '/api/auth/oidc']) assert.equal((await ask(runtime, path)).status, 503, path);
    const page = await ask(runtime, '/projects', 'text/html,application/xhtml+xml');
    assert.deepEqual([page.status, page.rendered, page.type], [503, false, 'text/html; charset=utf-8']);
    assert.match(page.body, /coffre's database lacks this version's migrations/);
    // Health answers: alive, and not ready.
    assert.deepEqual([(await ask(runtime, '/livez')).status, (await ask(runtime, '/readyz')).status], [200, 503]);
    assert.equal((JSON.parse((await ask(runtime, '/readyz')).body) as { ok: boolean }).ok, false);
    await assert.rejects(runScheduled(runtime), /lacks this version's migrations/);
  });
  // A database never migrated has no ledger: below the migrations too, not an outage.
  await neverMigrated(async () => {
    const api = await ask(freshRuntime(), '/api/me');
    assert.deepEqual([api.status, api.rendered, (JSON.parse(api.body) as { error: string }).error], [503, false, 'migrating']);
    const page = await ask(freshRuntime(), '/auth/signin/github', 'text/html');
    assert.deepEqual([page.status, page.rendered], [503, false]);
  });
  // Migrated, it serves; and once it has seen so, it stays so, asking no more.
  const page = await ask(runtime, '/projects', 'text/html');
  assert.deepEqual([page.status, page.rendered], [200, true]);
  assert.equal(runtime.schema.migrated, true);
  await unmigrated(async () => {
    assert.equal((await ask(runtime, '/projects', 'text/html')).rendered, true);
  });
});

/** Raw SQL as the owner, on either engine. */
async function rows(query: SQL): Promise<Record<string, unknown>[]> {
  if (TEST_ENGINE === 'sqlite') return (db.owner as unknown as { all: (q: SQL) => Promise<Record<string, unknown>[]> }).all(query);
  return (await (db.owner as unknown as { execute: (q: SQL) => Promise<{ rows: Record<string, unknown>[] }> }).execute(query)).rows;
}

async function run(query: SQL): Promise<void> {
  if (TEST_ENGINE === 'sqlite') await (db.owner as unknown as { run: (q: SQL) => Promise<unknown> }).run(query);
  else await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}

test('only a database that cannot be reached is an outage the door lets through; any other failure is not', () => {
  assert.equal(isUnreachable(Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' })), true);
  assert.equal(isUnreachable(new Error('query failed', { cause: Object.assign(new Error('the database system is shutting down'), { code: '57P03' }) })), true);
  assert.equal(isUnreachable(Object.assign(new Error('connection failure'), { code: '08006' })), true);
  assert.equal(isUnreachable(new Error('Connection terminated unexpectedly')), true);
  assert.equal(isUnreachable(Object.assign(new Error('relation "drizzle.__drizzle_migrations" does not exist'), { code: '42P01' })), false);
  assert.equal(isUnreachable(Object.assign(new Error('permission denied for schema drizzle'), { code: '42501' })), false);
  assert.equal(isUnreachable(new Error('no such table: __drizzle_migrations')), false);
});

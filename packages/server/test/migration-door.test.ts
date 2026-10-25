import test, { mock, after, before } from 'node:test';
import assert from 'node:assert/strict';

import { github, signin, type Principal } from '@coffre/core/identity';
import { isUnreachable, migrationLedger } from '@coffre/db/dialect';
import { asc, sql, type SQL } from 'drizzle-orm';

import { coffreRoute, respond, runScheduled } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { admitSocket } from '../src/socket-admission.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { appendAudit } from '../src/db/audit.ts';
import { auditLog } from './db/tables.ts';

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
    previousChainKeys: [],
    signin: null,
    workloads: null,
    mcp: null,
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }).resolve(ORIGIN),
    publicUrl: ORIGIN,
    verifier: { verify: async (token: string): Promise<Principal> => ({ type: 'user', id: token, email: token, subject: token }) },
    waitUntil,
    schema: { migrated: false }, appKey: { settled: false },
    rotateAfterDays: 365,
    plugins: [],
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

test("below its migrations, a plugin's WebSocket is refused at the same door, on Node and in a Durable Object alike, and its plugin never asked", async () => {
  let asked = false;
  const runtime = { ...freshRuntime(), plugins: [{ name: 'sockets', routes: { prefix: '/sockets', fetch: async () => new Response(), socket: async () => ((asked = true), new Response('admitted')) } }] };
  await unmigrated(async () => {
    const answer = await admitSocket(new Request(`${ORIGIN}/sockets/x`), runtime, null);
    assert.ok(answer instanceof Response);
    assert.equal(answer.status, 503);
    assert.match(await answer.text(), /lacks this version's migrations/);
  });
  assert.equal(asked, false);
});

test('a plugin that takes 20 s to admit a WebSocket, as under a burst of runs at once, is let in; past 45 s, refused', async () => {
  let decide!: (answer: Response) => void;
  const runtime = { ...freshRuntime(), plugins: [{ name: 'sockets', routes: { prefix: '/sockets', fetch: async () => new Response(), socket: () => new Promise<Response>((resolve) => (decide = resolve)) } }] };
  runtime.schema.migrated = true;
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const slow = admitSocket(new Request(`${ORIGIN}/sockets/x`), runtime, null);
    while (decide === undefined) await new Promise((resolve) => setImmediate(resolve));
    mock.timers.tick(20_000);
    decide(new Response('admitted'));
    assert.equal(await ((await slow) as Response).text(), 'admitted');
    const stuck = admitSocket(new Request(`${ORIGIN}/sockets/x`), runtime, null);
    await new Promise((resolve) => setImmediate(resolve));
    mock.timers.tick(45_000);
    const refused = (await stuck) as Response;
    assert.deepEqual([refused.status, await refused.text()], [503, 'coffre took too long to decide']);
  } finally {
    mock.timers.reset();
  }
});

test('only a database that cannot be reached is an outage the door lets through; any other failure is not', () => {
  assert.equal(isUnreachable(Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' })), true);
  assert.equal(isUnreachable(new Error('query failed', { cause: Object.assign(new Error('the database system is shutting down'), { code: '57P03' }) })), true);
  assert.equal(isUnreachable(Object.assign(new Error('connection failure'), { code: '08006' })), true);
  assert.equal(isUnreachable(new Error('Connection terminated unexpectedly')), true);
  assert.equal(isUnreachable(Object.assign(new Error('relation "drizzle.__drizzle_migrations" does not exist'), { code: '42P01' })), false);
  assert.equal(isUnreachable(Object.assign(new Error('permission denied for schema drizzle'), { code: '42501' })), false);
  assert.equal(isUnreachable(new Error('no such table: __drizzle_migrations')), false);
  // Hyperdrive, with every connection of its pool to the database busy, or none to be made.
  const pool = Object.assign(new Error('Timed out while waiting for an open slot in the pool.'), { code: '58000', severity: 'FATAL' });
  assert.equal(isUnreachable(new Error('Failed query: select 1', { cause: pool })), true);
  assert.equal(isUnreachable(new Error('Failed to acquire a connection from the pool.')), true);
  assert.equal(isUnreachable(new Error('Server connection attempt failed: destination_unavailable')), true);
  assert.equal(isUnreachable(Object.assign(new Error('sorry, too many clients already'), { code: '53300' })), true);
  // A statement that gave up waiting had its connection: the door is no place to let it through.
  assert.equal(isUnreachable(Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' })), false);
});

test('without an audit watch, the scheduled run asks the vault to checkpoint and writes no beat, and readiness is the database migrated', async () => {
  await resetDatabase(db.owner);
  const runtime = { ...freshRuntime(), schema: { migrated: true }, appKey: { settled: true } };
  const written = () => db.owner.select({ action: auditLog.action }).from(auditLog).orderBy(asc(auditLog.seq));
  await runScheduled(runtime);
  await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [{ actorType: 'system', actorId: 'test', action: 'secret.read', decision: 'allow' }]));
  await runScheduled(runtime);
  const actions = (await written()).map((row) => row.action);
  assert.deepEqual([actions.includes('audit.heartbeat'), actions.at(-1)], [false, 'audit.checkpoint']);
  const ready = await ask(runtime, '/readyz');
  assert.deepEqual([ready.status, JSON.parse(ready.body)], [200, { ok: true, watched: false }]);
});

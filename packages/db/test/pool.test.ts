// Node's pool: which connection a statement takes. postgres.js took the one
// idle the longest, so a steady load cycled every connection of the pool,
// each backend's caches cold, and Postgres spent ~8% more CPU per use at a
// pool of 16 than node-postgres, which takes the one idle the shortest.
// Coffre's own, in src/postgres-js, takes that one too.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type AddressInfo } from 'node:net';

import { sql } from 'drizzle-orm';

import { createDatabase } from '../src/database.ts';
import { isUnavailable } from '../src/dialect.ts';
import { HyperdrivePool } from '../src/hyperdrive.ts';
import postgres from '../src/postgres-js/index.ts';
import { postgresClient, postgresOptions, postgresSession, SessionLost } from '../src/postgres.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only' : false;
const DATABASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

test('a statement takes the connection idle the shortest: one after another, they keep to one backend', { skip }, async () => {
  const client = postgresClient(DATABASE, { max: 4 });
  try {
    // Four connections open at once, then idle.
    const opened = await Promise.all(Array.from({ length: 4 }, () => client.unsafe('select pg_backend_pid() as pid, pg_sleep(0.05)')));
    assert.equal(new Set(opened.map(([row]) => row!.pid)).size, 4);
    const pids = new Set<number>();
    for (let i = 0; i < 20; i += 1) pids.add((await client.unsafe('select pg_backend_pid() as pid'))[0]!.pid as number);
    assert.equal(pids.size, 1, `20 statements, one after another, on ${pids.size} backends`);
  } finally {
    await client.end();
  }
});

test("a transaction's BEGIN queued behind as many statements as a connection pipelines still learns its connection, and ends its transaction", { skip }, async () => {
  // Two at most in flight on the connection: the BEGIN goes behind two.
  const client = postgres({ ...postgresOptions(DATABASE), max: 1, max_pipeline: 2, onnotice: () => {} });
  try {
    await client.unsafe('select 1');
    const before = [client.unsafe('select pg_sleep(0.05)').execute(), client.unsafe('select 1').execute()];
    const inside = await client.begin(async (tx) => (await tx.unsafe('select 2 as n'))[0]!.n);
    await Promise.all(before);
    assert.equal(inside, 2);
    // The transaction ended: each statement's clock is its own again, never one transaction's.
    const [first] = await client.unsafe('select now() as at');
    await new Promise((resolve) => setTimeout(resolve, 20));
    const [second] = await client.unsafe('select now() as at');
    assert.notDeepEqual(first!.at, second!.at, 'the connection was left inside the transaction');
  } finally {
    await client.end();
  }
});

test('a session lost between statements refuses the next, rather than dial a connection that holds none of what it set', { skip }, async () => {
  const owner = postgresClient(DATABASE, { max: 1 });
  const session = postgresSession(DATABASE, { application_name: 'coffre-session-test' });
  try {
    await session.unsafe("SET lock_timeout = '5s'");
    await session.unsafe('BEGIN');
    const [{ pid }] = (await session.unsafe('select pg_backend_pid() as pid')) as unknown as [{ pid: number }];
    await owner.unsafe('select pg_terminate_backend($1)', [pid]);
    // The connection's close reaches the session: then every statement, a transaction's too, is refused.
    for (let tries = 0; ; tries += 1) {
      const answer = await session.unsafe('select 1').then(() => 'answered', (error: Error) => error);
      if (answer instanceof SessionLost) break;
      assert.ok(tries < 50 && answer !== 'answered', `a statement after the session was lost: ${String(answer)}`);
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await assert.rejects(session.unsafe('COMMIT'), SessionLost);
    await assert.rejects(session.begin(async (tx) => tx.unsafe('select 1')), SessionLost);
    // And no other connection was made for it.
    const [{ n }] = (await owner.unsafe("select count(*)::int as n from pg_stat_activity where application_name = 'coffre-session-test'")) as unknown as [{ n: number }];
    assert.equal(n, 0);
  } finally {
    await session.end();
    await owner.end();
  }
});

test('a connection lost under a query: the query fails, and the client closes without another query to open it again', { skip, timeout: 10_000 }, async () => {
  const owner = postgresClient(DATABASE, { max: 1 });
  try {
    for (const client of [postgresClient(DATABASE, { max: 2, application_name: 'coffre-lost-test' }), new HyperdrivePool(DATABASE)]) {
      const db = createDatabase(client);
      const running = db.execute(sql`select pg_sleep(5)`).then(() => 'answered', (error: Error) => error);
      for (let tries = 0; ; tries += 1) {
        const [{ n }] = (await owner.unsafe("select count(*)::int as n from pg_stat_activity where query = 'select pg_sleep(5)' and state = 'active'")) as unknown as [{ n: number }];
        if (n > 0) break;
        assert.ok(tries < 100, 'the query never ran');
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      await owner.unsafe("select pg_terminate_backend(pid) from pg_stat_activity where query = 'select pg_sleep(5)'");
      assert.ok((await running) instanceof Error);
      // Upstream kept the failed query as the connection's, and end() waited for it to answer.
      await client.end();
    }
  } finally {
    await owner.end();
  }
});

test('a connection closed while it opens, with no error said, fails its query at once, as an outage, and is not dialled again', { timeout: 10_000 }, async () => {
  // A server that takes the connection, reads the startup, and hangs up: as a proxy or a pooler with no room may.
  let dials = 0;
  const server = createServer((socket) => {
    dials += 1;
    socket.once('data', () => socket.end());
    socket.on('error', () => {});
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `postgresql://u:p@127.0.0.1:${(server.address() as AddressInfo).port}/coffre`;
  try {
    for (const client of [postgresClient(url, { max: 1 }), new HyperdrivePool(url)]) {
      dials = 0;
      const failed = await createDatabase(client).execute(sql`select 1`).then(() => null, (error: unknown) => error);
      assert.ok(isUnavailable(failed), `answered as an outage: ${String(failed)}`);
      assert.equal(dials, 1, 'dialled again');
      await client.end();
    }
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('a client closed while its connection opens, then hung up on, closes', { timeout: 10_000 }, async () => {
  // The hang-up comes once the client has asked to close.
  const server = createServer((socket) => {
    socket.once('data', () => setTimeout(() => socket.end(), 50));
    socket.on('error', () => {});
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const client = postgresClient(`postgresql://u:p@127.0.0.1:${(server.address() as AddressInfo).port}/coffre`, { max: 1 });
    const asked = client.unsafe('select 1').execute().then(() => null, (error: unknown) => error);
    await new Promise((resolve) => setTimeout(resolve, 10));
    const closing = client.end();
    assert.ok(isUnavailable(await asked));
    // Upstream left the end asked meanwhile waiting for a terminate that never came.
    assert.equal(await Promise.race([closing.then(() => 'closed'), new Promise((resolve) => setTimeout(resolve, 2000, 'waiting'))]), 'closed');
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test("a URL's bounds reach the server as the connection starts, as node-postgres sent them", { skip }, async () => {
  const client = postgresClient(`${DATABASE}?statement_timeout=1234&lock_timeout=567&idle_in_transaction_session_timeout=89000`, { max: 1 });
  try {
    const [row] = await client.unsafe("select current_setting('statement_timeout') as statement, current_setting('lock_timeout') as lock, current_setting('idle_in_transaction_session_timeout') as idle");
    assert.deepEqual({ ...row }, { statement: '1234ms', lock: '567ms', idle: '89s' });
  } finally {
    await client.end();
  }
});

test('a client ending when its connection is cut opens no other for what waited: those fail, and the client closes', { skip, timeout: 10_000 }, async () => {
  const owner = postgresClient(DATABASE, { max: 1 });
  // One connection, one statement on it at a time: the second waits on the connection, the third for one.
  const client = postgres({ ...postgresOptions(DATABASE), max: 1, max_pipeline: 1, onnotice: () => {}, connection: { application_name: 'coffre-ending-test' } });
  try {
    const asked = ['select pg_sleep(5)', 'select 2', 'select 3'].map((text) => client.unsafe(text).execute().then(() => 'answered', (error: { code?: string }) => error.code));
    for (let tries = 0; ; tries += 1) {
      const [{ n }] = (await owner.unsafe("select count(*)::int as n from pg_stat_activity where application_name = 'coffre-ending-test' and state = 'active'")) as unknown as [{ n: number }];
      if (n > 0) break;
      assert.ok(tries < 100, 'the first statement never ran');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const closing = client.end();
    await owner.unsafe("select pg_terminate_backend(pid) from pg_stat_activity where application_name = 'coffre-ending-test'");
    await closing;
    // The one running is cut short; what waited is refused, the client ending.
    const answers = await Promise.all(asked);
    assert.equal(answers[0], 'CONNECTION_CLOSED');
    assert.ok(answers.slice(1).every((answer) => answer === 'CONNECTION_CLOSED' || answer === 'CONNECTION_ENDED'), answers.join());
    // Upstream opened the connection again for the third, after end() had answered.
    await new Promise((resolve) => setTimeout(resolve, 200));
    const [{ n }] = (await owner.unsafe("select count(*)::int as n from pg_stat_activity where application_name = 'coffre-ending-test'")) as unknown as [{ n: number }];
    assert.equal(n, 0);
  } finally {
    await owner.end();
  }
});

test('an ending client reserves no connection; one reserved before, released after, ends with it', { skip, timeout: 10_000 }, async () => {
  const owner = postgresClient(DATABASE, { max: 1 });
  const backends = async () => ((await owner.unsafe("select count(*)::int as n from pg_stat_activity where application_name = 'coffre-reserve-test'")) as unknown as [{ n: number }])[0].n;
  try {
    const client = postgresClient(DATABASE, { max: 2, application_name: 'coffre-reserve-test' });
    await client.unsafe('select 1');
    // What is asked in end()'s own tick is served, as a statement is, and end() waits for it: what is asked after is refused.
    const closing = client.end();
    await new Promise((resolve) => setImmediate(resolve));
    await assert.rejects(client.reserve(), { code: 'CONNECTION_ENDED' });
    await closing;
    // Reserved before the end: the end waits for its release, then the connection closes.
    const other = postgresClient(DATABASE, { max: 2, application_name: 'coffre-reserve-test' });
    const reserved = await other.reserve();
    await reserved.unsafe('select 1');
    const ending = other.end();
    // Asked in end()'s tick: served, and released after.
    const late = other.reserve();
    reserved.release();
    (await late).release();
    assert.equal(await Promise.race([ending.then(() => 'ended'), new Promise((resolve) => setTimeout(resolve, 2000, 'waiting'))]), 'ended');
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(await backends(), 0);
  } finally {
    await owner.end();
  }
});

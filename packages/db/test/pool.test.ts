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

test("a connection cut while it answers leaves nothing of that answer to the next query: its error, its rows", { skip, timeout: 15_000 }, async () => {
  const owner = postgresClient(DATABASE, { max: 1 });
  const client = postgresClient(DATABASE, { max: 1, application_name: 'coffre-cut-test' });
  try {
    // Two rows answered, then a wait, during which the backend is ended.
    const cut = client.unsafe('select n, pg_sleep(case when n = 3 then 5 else 0 end) from generate_series(1, 3) n').execute().then(() => null, (error: unknown) => error);
    for (let tries = 0; ; tries += 1) {
      const [{ n }] = (await owner.unsafe("select count(*)::int as n from pg_stat_activity where application_name = 'coffre-cut-test' and wait_event = 'PgSleep'")) as unknown as [{ n: number }];
      if (n > 0) break;
      assert.ok(tries < 200, 'the statement never waited');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    await owner.unsafe("select pg_terminate_backend(pid) from pg_stat_activity where application_name = 'coffre-cut-test'");
    assert.ok(await cut);
    // Upstream failed the first with the dead connection's error, and answered the second after two holes.
    assert.deepEqual([...await client.unsafe('select 7 as seven')], [{ seven: 7 }]);
    assert.deepEqual([...await client.unsafe('select 8 as eight')], [{ eight: 8 }]);
  } finally {
    await client.end();
    await owner.end();
  }
});

/** A server on 127.0.0.1 that answers each connection's first message with `answer`, and what follows with `then`; its URL. */
async function fakeServer(answer: (socket: import('node:net').Socket) => void, then?: (socket: import('node:net').Socket, data: Buffer) => void) {
  const server = createServer((socket) => {
    socket.on('error', () => {});
    socket.once('data', () => {
      answer(socket);
      if (then) socket.on('data', (data: Buffer) => then(socket, data));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { url: `postgresql://u:p@127.0.0.1:${(server.address() as AddressInfo).port}/coffre`, close: async () => { server.close(); await once(server, 'close'); } };
}

/** A message from the server: its type, a length, the body. */
const message = (type: string, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts);
  const header = Buffer.alloc(5);
  header.write(type, 0);
  header.writeInt32BE(body.length + 4, 1);
  return Buffer.concat([header, body]);
};
const int32 = (n: number) => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };

/** Whether `work` left a promise rejected with no one to catch it. */
async function leavesNothingUnhandled(work: () => Promise<void>): Promise<unknown[]> {
  const unhandled: unknown[] = [];
  const hear = (reason: unknown) => void unhandled.push(reason);
  process.on('unhandledRejection', hear);
  try {
    await work();
    await new Promise((resolve) => setTimeout(resolve, 50));
  } finally {
    process.off('unhandledRejection', hear);
  }
  return unhandled;
}

test('an opening the client cannot finish fails its query and closes, with nothing left unhandled: a TLS key it cannot read, a SCRAM message it cannot, a sign-in it has not, a socket it cannot make', { timeout: 10_000 }, async () => {
  // TLS: the server says yes to it, and the client's own key is no key.
  const tls = await fakeServer((socket) => socket.write('S'));
  // SCRAM: the server asks for it, then answers the client's first message without its salt.
  const scram = await fakeServer(
    (socket) => socket.write(message('R', int32(10), Buffer.from('SCRAM-SHA-256\0\0'))),
    (socket) => socket.write(message('R', int32(11), Buffer.from('r=nonce,i=4096'))),
  );
  // GSSAPI, which the client has not.
  const gss = await fakeServer((socket) => socket.write(message('R', int32(7))));
  try {
    const unhandled = await leavesNothingUnhandled(async () => {
      // Each fails the query that opened it, closes, and opens again for the next, which fails as well; then the client ends.
      const keyless = postgres({ ...postgresOptions(tls.url), ssl: { key: 'not a key', cert: 'not a cert' }, max: 1, connect_timeout: 5 });
      await assert.rejects(keyless.unsafe('select 1'), { code: 'ERR_OSSL_PEM_NO_START_LINE' });
      await assert.rejects(keyless.unsafe('select 1'), { code: 'ERR_OSSL_PEM_NO_START_LINE' });
      await keyless.end();
      const saltless = postgres({ ...postgresOptions(scram.url), max: 1, connect_timeout: 5 });
      await assert.rejects(saltless.unsafe('select 1'));
      await assert.rejects(saltless.unsafe('select 1'));
      await saltless.end();
      const kerberos = postgres({ ...postgresOptions(gss.url), max: 1, connect_timeout: 0 });
      await assert.rejects(kerberos.unsafe('select 1'), { code: 'AUTH_TYPE_NOT_SUPPORTED' });
      await assert.rejects(kerberos.unsafe('select 1'), { code: 'AUTH_TYPE_NOT_SUPPORTED' });
      await kerberos.end();
      const socketless = postgres({ ...postgresOptions(DATABASE), socket: () => Promise.reject(new Error('no socket')), max: 1 });
      await assert.rejects(socketless.unsafe('select 1'), { message: 'no socket' });
      await assert.rejects(socketless.unsafe('select 1'), { message: 'no socket' });
      await socketless.end();
    });
    assert.deepEqual(unhandled, []);
  } finally {
    await tls.close();
    await scram.close();
    await gss.close();
  }
});

test('a COPY reaching the client fails, and leaves the connection to the next statement', { skip }, async () => {
  const client = postgresClient(DATABASE, { max: 1 });
  try {
    await assert.rejects(client.unsafe('copy (select 1) to stdout'), { code: 'COPY_NOT_SUPPORTED' });
    await client.unsafe('create temporary table copied (n int)');
    await assert.rejects(client.unsafe('copy copied from stdin'));
    assert.deepEqual([...await client.unsafe('select count(*)::int as n from copied')], [{ n: 0 }]);
  } finally {
    await client.end();
  }
});

test('a BEGIN that fails runs none of its transaction outside it: not its first statement, sent with it, nor any after', { skip }, async () => {
  const sent: string[] = [];
  const client = postgres({ ...postgresOptions(DATABASE), max: 1, onnotice: () => {}, debug: (_: number, text: string, values: unknown[]) => void sent.push([text, ...values].join(' ')) });
  try {
    await client.unsafe('create temporary table kept (n int)');
    // 'bogus' is no isolation level: Postgres refuses the BEGIN, and skips what came under its Sync.
    const refused = { code: '42601' };
    // The first statement with parameters (the extended protocol), without (the simple one), and several at once.
    await assert.rejects(client.begin('isolation level bogus', (tx) => tx.unsafe('insert into kept values ($1)', [1])), refused);
    await assert.rejects(client.begin('isolation level bogus', (tx) => tx.unsafe('insert into kept values (2)')), refused);
    await assert.rejects(client.begin('isolation level bogus', (tx) => [tx.unsafe('insert into kept values ($1)', [3]), tx.unsafe('insert into kept values ($1)', [4])]), refused);
    // Caught, and another asked: refused, never sent.
    let after: unknown;
    await assert.rejects(client.begin('isolation level bogus', async (tx) => {
      await tx.unsafe('insert into kept values ($1)', [5]).catch(() => {});
      after = await tx.unsafe('insert into kept values ($1)', [6]).catch((e: unknown) => e);
    }), refused);
    assert.equal((after as { code?: string }).code, 'TRANSACTION_NOT_BEGUN');
    // Each first statement went with its BEGIN, and nothing else: not 4, behind it, nor 6, after it, nor a rollback.
    const begin = 'begin isolation level bogus';
    assert.deepEqual(sent.slice(1), [begin, 'insert into kept values ($1) 1', begin, 'insert into kept values (2)', begin, 'insert into kept values ($1) 3', begin, 'insert into kept values ($1) 5']);
    // Nothing ran; the connection is the pool's again, and a transaction on it begins.
    assert.deepEqual([...await client.unsafe('select count(*)::int as n from kept')], [{ n: 0 }]);
    await client.begin((tx) => tx.unsafe('insert into kept values ($1)', [7]));
    assert.deepEqual([...await client.unsafe('select n from kept')], [{ n: 7 }]);
  } finally {
    await client.end();
  }
});

test('a transaction that asks nothing sends nothing, and one that asks sends BEGIN with its first statement', { skip }, async () => {
  const sent: string[] = [];
  const client = postgres({ ...postgresOptions(DATABASE), max: 1, onnotice: () => {}, debug: (_: number, text: string) => void sent.push(text) });
  try {
    await client.unsafe('select 1');
    sent.length = 0;
    assert.equal(await client.begin(() => 'nothing'), 'nothing');
    await assert.rejects(client.begin(() => Promise.reject(new Error('before any statement'))), { message: 'before any statement' });
    assert.deepEqual(sent, []);
    await client.begin('read only', async (tx) => {
      await tx.unsafe('select $1::int', [1]);
      await tx.unsafe('select 2');
    });
    assert.deepEqual(sent, ['begin read only', 'select $1::int', 'select 2', 'commit']);
  } finally {
    await client.end();
  }
});

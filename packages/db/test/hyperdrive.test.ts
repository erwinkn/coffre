// A Worker's database through Hyperdrive: one connection for the whole
// call, which its queries and transactions take turns on, and each query
// one round trip. On Cloudflare, a
// call that opened several connections at once was now and then cancelled
// as hung, so the count of connections is what these hold it to, through a
// proxy that sees each one, in front of the suite's Postgres.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { connect, createServer, type Socket } from 'node:net';

import { sql } from 'drizzle-orm';

import { openDatabase } from '../src/connect.ts';
import { createDatabase, QueryOutsideTransaction } from '../src/database.ts';
import { HyperdrivePool } from '../src/hyperdrive.ts';

import { postgresClient } from '../src/postgres.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only: Hyperdrive' : false;
const DATABASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

/**
 * Postgres behind a proxy that counts the connections made to it and the
 * round trips on them (each time the client speaks again after an answer),
 * can cut them, and can hold a COMMIT on its way, as a slow network would.
 */
async function counted() {
  const target = new URL(DATABASE);
  const open = new Set<Socket>();
  let opened = 0;
  let peak = 0;
  let trips = 0;
  let commits: Promise<void> | null = null;
  const server = createServer((client) => {
    opened += 1;
    open.add(client);
    peak = Math.max(peak, open.size);
    const upstream = connect(Number(target.port), target.hostname);
    let answered = true;
    let sending = Promise.resolve();
    client.on('data', (chunk: Buffer) => {
      if (answered) trips += 1;
      answered = false;
      const held = commits !== null && /commit/i.test(chunk.toString('latin1')) ? commits : null;
      sending = sending.then(async () => {
        await held;
        upstream.write(chunk);
      });
    });
    upstream.on('data', (chunk: Buffer) => {
      answered = true;
      client.write(chunk);
    });
    const end = () => {
      open.delete(client);
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = new URL(DATABASE);
  url.port = String((server.address() as { port: number }).port);
  after(() => {
    // Whatever a failed test left open goes, so that the file ends.
    for (const socket of open) socket.destroy();
    return new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return {
    url: url.href,
    get opened() {
      return opened;
    },
    get peak() {
      return peak;
    },
    get open() {
      return open.size;
    },
    get trips() {
      return trips;
    },
    /** Hold every COMMIT until `until` settles. */
    holdCommits(until: Promise<void>) {
      commits = until;
    },
    cut: () => {
      for (const socket of open) socket.destroy();
    },
  };
}

const n = (rows: Record<string, unknown>[]) => Number(rows[0]!.n);

test('a call opens one connection, and its queries and transactions take turns on it', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  // As a vault call does: reads at once, one after another, and a transaction among them.
  const [a, b, c] = await Promise.all([1, 2, 3].map((value) => db.execute(sql`select ${value}::int as n`)));
  assert.deepEqual([n(a), n(b), n(c)], [1, 2, 3]);
  const [inside, beside] = await Promise.all([
    db.transaction(async (tx) => n(await tx.execute(sql`select 4 as n`)) + n(await tx.execute(sql`select 5 as n`))),
    db.execute(sql`select 6 as n`),
  ]);
  assert.deepEqual([inside, n(beside)], [9, 6]);
  assert.deepEqual([proxy.opened, proxy.peak], [1, 1]);
  await pool.end();
  for (let tries = 0; proxy.open > 0; tries += 1) {
    assert.ok(tries < 100, 'the connection was left open');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
});

test('a query asked while a transaction holds the connection waits for it, and is not part of it', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  // A table of the session's own: the one connection is the session.
  await db.execute(sql`create temporary table turns (v text)`);
  const order: string[] = [];
  let begun!: () => void;
  const inTransaction = new Promise<void>((resolve) => (begun = resolve));
  let finish!: () => void;
  const finished = new Promise<void>((resolve) => (finish = resolve));
  const rolledBack = db
    .transaction(async (tx) => {
      await tx.execute(sql`insert into turns values ('in the transaction')`);
      begun();
      await finished;
      order.push('transaction');
      throw new Error('rolled back');
    })
    .catch((error: Error) => error.message);
  await inTransaction;
  // Asked while the transaction is open: it waits, and the rollback does not take it.
  const beside = db.execute(sql`insert into turns values ('beside it')`).then(() => order.push('beside'));
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(order, [], 'the query ran inside the open transaction');
  finish();
  assert.equal(await rolledBack, 'rolled back');
  await beside;
  assert.deepEqual(order, ['transaction', 'beside']);
  assert.deepEqual([...await db.execute(sql`select v from turns`)], [{ v: 'beside it' }]);
  assert.equal(proxy.opened, 1);
  await pool.end();
});

test('closing waits for what is under way; a connection lost or closed is opened again for the next query', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  // Drizzle runs a query when it is awaited: `then` starts it now.
  const slow = db.execute(sql`select pg_sleep(0.1), 7 as n`).then(n);
  const closed = pool.end();
  assert.equal(await slow, 7, 'end cut a query short');
  await closed;
  // Closed, then asked again, as a Worker's background work may: a new connection.
  assert.equal(n(await db.execute(sql`select 8 as n`)), 8);
  assert.equal(proxy.opened, 2);
  // Lost under a query: that query fails, and the next connects again.
  const cutShort = db.execute(sql`select pg_sleep(1), 9 as n`).then(n);
  await new Promise((resolve) => setTimeout(resolve, 50));
  proxy.cut();
  await assert.rejects(cutShort);
  assert.equal(n(await db.execute(sql`select 10 as n`)), 10);
  assert.equal(proxy.opened, 3);
  await pool.end();
});

test('a query on the database from inside its own transaction is refused at once, not left to wait for itself', { skip, timeout: 10_000 }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  await db.execute(sql`create temporary table turns (v text)`);
  // On the database, not on tx: refused, and the transaction rolls back.
  await assert.rejects(
    db.transaction(async (tx) => {
      await tx.execute(sql`insert into turns values ('rolled back')`);
      await db.execute(sql`select 1`);
    }),
    (error: Error) => error instanceof QueryOutsideTransaction && /^query outside its transaction: use tx/.test(error.message),
  );
  // A transaction opened inside one would wait for it just the same.
  await assert.rejects(db.transaction(async () => db.transaction(async (inner) => inner.execute(sql`select 1`))), QueryOutsideTransaction);

  // Another flow's query waits its turn, as before; and what a transaction left running queries freely
  // once its work is done, even before its COMMIT has come back: held here, as a slow network would.
  let commit!: () => void;
  proxy.holdCommits(new Promise<void>((resolve) => (commit = resolve)));
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let left: Promise<unknown> = Promise.resolve();
  const transaction = db.transaction(async (tx) => {
    await tx.execute(sql`insert into turns values ('committed')`);
    left = held.then(() => new Promise((resolve) => setTimeout(resolve, 20))).then(() => db.execute(sql`select count(*)::int as n from turns`));
    // Awaited below, after the transaction: a refusal meanwhile is this test's failure, not an unhandled rejection.
    left.catch(() => {});
    await held;
  });
  const elsewhere = db.execute(sql`select 1 as n`).then(n);
  await new Promise((resolve) => setTimeout(resolve, 30));
  release();
  // The work is done, the COMMIT held, and what it left running asks for its query at 20 ms.
  await new Promise((resolve) => setTimeout(resolve, 40));
  commit();
  await transaction;
  assert.equal(await elsewhere, 1);
  assert.equal(n((await left) as Record<string, unknown>[]), 1);
  assert.equal(proxy.opened, 1);
  await pool.end();
});

test("Node's pool refuses the same query, so that the suites catch it before a Worker would hang on it", { skip, timeout: 10_000 }, async () => {
  const { db, close } = await openDatabase(DATABASE);
  try {
    await assert.rejects(db.transaction(async () => db.execute(sql`select 1`)), QueryOutsideTransaction);
    assert.equal(n(await db.transaction((tx) => tx.execute(sql`select 2 as n`))), 2);
  } finally {
    await close();
  }
});

test("with closeIdleMs, what outlives a call closes its connection once idle, and the next query connects again", { skip }, async () => {
  const proxy = await counted();
  // As a Durable Object's coffre does: a check now and then, none of them a call that ends the pool.
  const pool = new HyperdrivePool(proxy.url, { closeIdleMs: 50 });
  const db = createDatabase(pool);
  const closed = async () => {
    for (let tries = 0; proxy.open > 0; tries += 1) {
      assert.ok(tries < 100, 'the idle connection was left open');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  };
  // One check's queries, each after the last, share one connection: the gap between them is shorter than the idle time.
  assert.equal(n(await db.execute(sql`select 1 as n`)), 1);
  assert.equal(n(await db.transaction(async (tx) => tx.execute(sql`select 2 as n`))), 2);
  assert.equal(proxy.opened, 1);
  await closed();
  // The next check connects again, and lets go again.
  assert.equal(n(await db.execute(sql`select 3 as n`)), 3);
  assert.equal(proxy.opened, 2);
  await closed();
  await pool.end();
});

/**
 * Each kind of value coffre sends, as a statement's parameter, and what
 * comes back: the same value, in one round trip. postgres.js asks the server
 * for a statement's types before it sends its values, a round trip more,
 * unless every value goes as text the server types, as node-postgres sends
 * them; coffre's copy asks only for an array or an object (src/postgres-js).
 */
const KINDS: { kind: string; query: ReturnType<typeof sql>; back: unknown; trips?: number }[] = [
  { kind: 'text', query: sql`select ${'héllo, "wörld"'}::text as v`, back: 'héllo, "wörld"' },
  { kind: 'int', query: sql`select ${-42}::int as v`, back: -42 },
  { kind: 'bigint above 2^53', query: sql`select ${2n ** 60n + 1n}::int8 as v`, back: '1152921504606846977' },
  { kind: 'bigint above 2^53, as text', query: sql`select ${'9007199254740993'}::int8 as v`, back: '9007199254740993' },
  { kind: 'numeric', query: sql`select ${'12345678901234567890.0123456789'}::numeric as v`, back: '12345678901234567890.0123456789' },
  { kind: 'bool', query: sql`select ${true}::bool as v`, back: true },
  { kind: 'bool, as text', query: sql`select ${'false'}::bool as v`, back: false },
  { kind: 'bytea', query: sql`select ${Buffer.from([0, 1, 254, 255])}::bytea as v`, back: Buffer.from([0, 1, 254, 255]) },
  { kind: 'timestamptz', query: sql`select ${'2026-10-27T10:00:00.123Z'}::timestamptz = '2026-10-27T10:00:00.123Z' as v`, back: true },
  { kind: 'timestamptz, as text', query: sql`select ${'2026-10-27T10:00:00.123Z'}::timestamptz at time zone 'UTC' as v`, back: '2026-10-27 10:00:00.123' },
  { kind: 'json', query: sql`select ${JSON.stringify({ a: [1, 'two', null], b: { c: true } })}::json as v`, back: { a: [1, 'two', null], b: { c: true } } },
  { kind: 'jsonb', query: sql`select ${JSON.stringify({ n: 2 ** 53 + 2, s: 'x' })}::jsonb as v`, back: { n: 2 ** 53 + 2, s: 'x' } },
  { kind: 'uuid', query: sql`select ${'0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f'}::uuid as v`, back: '0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f' },
  { kind: 'null', query: sql`select ${null}::text as v`, back: null },
  { kind: 'text[], answered', query: sql`select array[${'a'}, ${'b,c'}, ${'"q"'}]::text[] as v`, back: ['a', 'b,c', '"q"'] },
  { kind: 'uuid[], answered', query: sql`select array[${'0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f'}]::uuid[] as v`, back: ['0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f'] },
  { kind: 'int8[], answered', query: sql`select array[${'9007199254740993'}::int8, 1] as v`, back: ['9007199254740993', '1'] },
];

async function eachKindIn(db: ReturnType<typeof createDatabase>, proxy: { readonly trips: number }) {
  // The connection made first: what is counted is each statement's own.
  await db.execute(sql`select 1`);
  const seen: Record<string, { back: unknown; trips: number }> = {};
  for (const { kind, query } of KINDS) {
    const before = proxy.trips;
    const [row] = await db.execute(query);
    seen[kind] = { back: row!.v, trips: proxy.trips - before };
  }
  assert.deepEqual(seen, Object.fromEntries(KINDS.map(({ kind, back, trips }) => [kind, { back, trips: trips ?? 1 }])));
}

test('on Workers, each kind of value comes back as it was sent, each statement in one round trip', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  try {
    await eachKindIn(createDatabase(pool), proxy);
    // A transaction: its statements, the first with BEGIN, then COMMIT, each one round trip.
    const before = proxy.trips;
    await createDatabase(pool).transaction(async (tx) => {
      await tx.execute(sql`select ${1}::int`);
      await tx.execute(sql`select ${'two'}::text`);
    });
    assert.equal(proxy.trips - before, 3);
  } finally {
    await pool.end();
  }
});

test("on Node's pool too", { skip }, async () => {
  const proxy = await counted();
  const { db, close } = await openDatabase(proxy.url);
  try {
    await eachKindIn(db, proxy);
  } finally {
    await close();
  }
});

test('an array or a date sent as a parameter goes as node-postgres sends one: as text the server types, in one round trip', { skip }, async () => {
  const proxy = await counted();
  const client = postgresClient(proxy.url, { max: 1 });
  try {
    await client.unsafe('select 1');
    const before = proxy.trips;
    const [row] = await client.unsafe(
      'select $1::text[] as texts, $2::uuid[] as ids, $3::int8[] as big, $4::bytea[] as bytes, $5::smallint[] as small, $6::int[] as nested, $7::timestamptz = $8::timestamptz as same',
      [
        ['a', 'b,c', '"q"', 'back\\slash', null, '{}', 'NULL'],
        ['0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f'],
        ['9007199254740993', 2n ** 60n],
        [Buffer.from([0, 255]), Buffer.alloc(0)],
        [1, 2],
        [[1, 2], [3, 4]],
        new Date('2026-10-27T10:00:00.123Z'),
        '2026-10-27T10:00:00.123Z',
      ] as never[],
    );
    assert.deepEqual({ ...row }, {
      texts: ['a', 'b,c', '"q"', 'back\\slash', null, '{}', 'NULL'],
      ids: ['0f9c2a4e-5b7d-4c1e-9a3f-2d6b8e0c1a5f'],
      big: ['9007199254740993', '1152921504606846976'],
      bytes: [Buffer.from([0, 255]), Buffer.alloc(0)],
      small: [1, 2],
      nested: [[1, 2], [3, 4]],
      same: true,
    });
    assert.equal(proxy.trips - before, 1);
    // In a transaction, and a savepoint in it, the same.
    const [inside] = await client.begin(async (tx) => tx.savepoint(async (sp) => sp.unsafe('select $1::bytea[] as bytes', [[Buffer.from([7])]])));
    assert.deepEqual(inside!.bytes, [Buffer.from([7])]);
    // Arrays the driver would bind as their first element's type, a boolean's included, in a savepoint too.
    let trips = proxy.trips;
    const firsts = [[1, 2], [true, false], [Buffer.from([1]), Buffer.from([2])], ['x', 'y']] as never[];
    const typed = 'select $1::int[] as ints, $2::bool[] as bools, $3::bytea[] as bytes, $4::text[] as texts';
    const back = { ints: [1, 2], bools: [true, false], bytes: [Buffer.from([1]), Buffer.from([2])], texts: ['x', 'y'] };
    assert.deepEqual({ ...(await client.unsafe(typed, firsts))[0] }, back);
    assert.equal(proxy.trips - trips, 1);
    assert.deepEqual({ ...(await client.begin(async (tx) => tx.savepoint(async (sp) => sp.unsafe(typed, firsts))))[0] }, back);
    // Bytes of any view, and undefined, as node-postgres sends them.
    trips = proxy.trips;
    const view = new Uint8Array([9, 8, 7, 6]);
    const [bytes] = await client.unsafe('select $1::bytea as buffer, $2::bytea as view, $3::bytea as data, $4::text as none', [
      view.buffer, new DataView(view.buffer, 1, 2), new Uint16Array([0x0102]), undefined,
    ] as never[]);
    assert.deepEqual({ ...bytes }, { buffer: Buffer.from([9, 8, 7, 6]), view: Buffer.from([8, 7]), data: Buffer.from(new Uint16Array([0x0102]).buffer), none: null });
    assert.equal(proxy.trips - trips, 1);
  } finally {
    await client.end();
  }
});

test("a statement asked of the pool is a statement as postgres.js's is: started by execute(), and a promise", { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  try {
    // Started now, without an await, as a caller holding it for later starts it.
    const started = pool.unsafe('select 1 as n').execute();
    for (let tries = 0; proxy.trips === 0; tries += 1) {
      assert.ok(tries < 100, 'execute() sent nothing');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(n((await started) as Record<string, unknown>[]), 1);
    let finished = false;
    assert.match(String(await pool.unsafe('select nonsense').catch((error: Error) => error.message)), /nonsense/);
    await pool.unsafe('select 2').finally(() => (finished = true));
    assert.equal(finished, true);
  } finally {
    await pool.end();
  }
});

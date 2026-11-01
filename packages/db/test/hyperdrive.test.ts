// A Worker's database through Hyperdrive: one connection for the whole
// call, which its queries and transactions take turns on, and each query
// one round trip. On Cloudflare, a
// call that opened several connections at once was now and then cancelled
// as hung, so the count of connections is what these hold it to, through a
// proxy that sees each one, in front of the suite's Postgres.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { sql } from 'drizzle-orm';

import { openDatabase } from '../src/connect.ts';
import { createDatabase, QueryOutsideTransaction, tablesOf } from '../src/database.ts';
import { forUpdate } from '../src/dialect.ts';
import { prepared } from '../src/prepared.ts';
import { HyperdrivePool } from '../src/hyperdrive.ts';
import { later } from '../src/later.ts';

import { postgresClient } from '../src/postgres.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only: Hyperdrive' : false;
const DATABASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

/** The proxy in front of the suite's Postgres (`postgresProxy`), closed once the file's tests are done. */
async function counted() {
  const proxy = await postgresProxy(DATABASE);
  // Whatever a failed test left open goes, so that the file ends.
  after(() => proxy.close());
  return proxy;
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

test('with groupReads, the reads asked together go under one Sync, each answered with its own rows', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url, { groupReads: true });
  const db = createDatabase(pool);
  const { projects } = tablesOf(db);
  await db.execute(sql`select 1`);
  const syncs = proxy.syncs;
  // With values and without, as rows and as arrays (Drizzle's selects), a hundred of them: one round trip.
  const [listed, ...answers] = await Promise.all([
    db.select({ id: projects.id }).from(projects).where(sql`false`),
    db.execute(sql`select 'none' as n`),
    ...Array.from({ length: 100 }, (_, i) => db.execute(sql`select ${i}::int as n, ${`v${i}`}::text as v`)),
  ]);
  assert.deepEqual(listed, []);
  assert.equal(answers[0]![0]!.n, 'none');
  assert.deepEqual(answers.slice(1).map((rows) => [Number(rows[0]!.n), rows[0]!.v]), Array.from({ length: 100 }, (_, i) => [i, `v${i}`]));
  assert.equal(proxy.syncs - syncs, 1);
  // One after another, each is a round trip of its own.
  for (const value of [1, 2]) assert.equal(n(await db.execute(sql`select ${value}::int as n`)), value);
  assert.equal(proxy.syncs - syncs, 3);
  await pool.end();
});

test('with groupReads, a write or a transaction asked among reads goes alone, and every statement in the order asked', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url, { groupReads: true });
  const db = createDatabase(pool);
  await db.execute(sql`create temporary table grouped (v int)`);
  const syncs = proxy.syncs;
  // Asked of the pool in this order, each at once: a transaction starts when it is asked, a Drizzle query when awaited.
  const count = () => pool.unsafe('select count(*)::int as n from grouped').then(n);
  const [before, , after, , inside, last] = await Promise.all([
    count(),
    pool.unsafe('insert into grouped values (1)').then(() => null),
    count(),
    pool.begin((tx) => tx.unsafe('insert into grouped values (2)')),
    pool.begin(async (tx) => n(await tx.unsafe('select count(*)::int as n from grouped'))),
    count(),
  ]);
  assert.deepEqual([before, after, inside, last], [0, 1, 2, 2]);
  // The reads, the insert, the reads after it, the two transactions (their BEGIN with their statement, then COMMIT), the last read.
  assert.equal(proxy.syncs - syncs, 1 + 1 + 1 + 2 + 2 + 1);
  await pool.end();
});

test('with groupReads, a read that fails fails its group, each read with its error, once; the connection goes on', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url, { groupReads: true });
  const db = createDatabase(pool);
  await db.execute(sql`select 1`);
  const syncs = proxy.syncs;
  const settled = await Promise.allSettled([
    db.execute(sql`select 1 as n`),
    db.execute(sql`select 1 / ${0}::int as n`),
    db.execute(sql`select 3 as n`),
  ]);
  for (const outcome of settled) {
    assert.equal(outcome.status, 'rejected');
    // Drizzle's error, around Postgres's: the division's, for each.
    assert.equal(((outcome as PromiseRejectedResult).reason as { cause?: { code?: string } }).cause?.code, '22012');
  }
  // Sent once, not again: a group that fails is not asked a second time.
  assert.equal(proxy.syncs - syncs, 1);
  assert.equal(n(await db.execute(sql`select 4 as n`)), 4);
  await pool.end();
});

test('with groupReads, a select marked as a write goes alone, and a group with a value only the server can type goes each alone', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url, { groupReads: true });
  const db = createDatabase(pool);
  await db.execute(sql`select 1`);
  let syncs = proxy.syncs;
  // A function that writes, called by a select: said so, it takes its own turn.
  await Promise.all([db.execute(sql`/* writes */ select ${1}::int as n`), db.execute(sql`select ${2}::int as n`)]);
  assert.equal(proxy.syncs - syncs, 2);
  // An object of a class of its own, which the server types, alone: nothing of the group went, then each went alone.
  const typed = new (class Five { toString() { return '5'; } })();
  syncs = proxy.syncs;
  const [five, six] = await Promise.all([db.execute(sql`select ${typed}::int as n`), db.execute(sql`select ${6}::int as n`)]);
  assert.deepEqual([n(five), n(six)], [5, 6]);
  assert.ok(proxy.syncs - syncs >= 2, 'each went alone');
  await pool.end();
});

test('with groupReads, a connection cut while a group is out fails each of its reads once, and the next read connects again', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url, { groupReads: true });
  const db = createDatabase(pool);
  await db.execute(sql`select 1`);
  const asked = Promise.allSettled([
    db.execute(sql`select ${1}::int as n, pg_sleep(1)`),
    db.execute(sql`select ${2}::int as n`),
    db.execute(sql`select ${3}::int as n`),
  ]);
  // Once the group is out, as its first read sleeps.
  const syncs = proxy.syncs;
  for (let tries = 0; proxy.syncs === syncs; tries += 1) {
    assert.ok(tries < 200, 'the group never went');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  proxy.cut();
  const settled = await asked;
  assert.deepEqual(settled.map((outcome) => outcome.status), ['rejected', 'rejected', 'rejected']);
  assert.equal(n(await db.execute(sql`select ${4}::int as n`)), 4);
  await pool.end();
});

test('without groupReads, reads asked together each take a turn, as before', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  await db.execute(sql`select 1`);
  const syncs = proxy.syncs;
  await Promise.all([1, 2, 3].map((value) => db.execute(sql`select ${value}::int as n`)));
  assert.equal(proxy.syncs - syncs, 3);
  await pool.end();
});

test("postgres.js's group holds plain reads alone, and never none", { skip }, async () => {
  const client = postgresClient(DATABASE, { max: 1 });
  try {
    assert.throws(() => client.group([{ query: 'select 1' }, { query: 'insert into nowhere values (1)' }]), { code: 'GROUP_NOT_READ' });
    assert.throws(() => client.group([{ query: 'with x as (delete from nowhere) select 1' }]), { code: 'GROUP_NOT_READ' });
    assert.throws(() => client.group([]), { code: 'EMPTY_GROUP' });
    const [a, b] = await client.group([{ query: 'select $1::int as n', parameters: [5] }, { query: 'select 6 as n', arrays: true }]);
    assert.deepEqual([a![0], b![0]], [{ n: 5 }, [6]]);
  } finally {
    await client.end();
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

test("a transaction's statements asked together go under one Sync, its BEGIN with the first, and what it left to `later` with its COMMIT", { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  await db.execute(sql`create temporary table gathered (n int)`);
  const syncs = proxy.syncs;
  const counted_ = await db.transaction(async (tx) => {
    const [a, b, c] = await Promise.all([tx.execute(sql`select 1 as n`), tx.execute(sql`select ${2}::int as n`), tx.execute(sql`select count(*)::int as n from gathered`)]);
    later(tx, sql`insert into gathered values (${n(a) + n(b)})`);
    later(tx, sql`insert into gathered values (4)`);
    return n(c);
  });
  assert.equal(counted_, 0);
  assert.equal(proxy.syncs - syncs, 2, 'BEGIN and the reads, then the inserts and COMMIT');
  assert.deepEqual([...await db.execute(sql`select n from gathered order by n`)], [{ n: 3 }, { n: 4 }]);
  // One after another, each still its own; a savepoint goes alone, after what was gathered before it.
  const before = proxy.syncs;
  await db.transaction(async (tx) => {
    await tx.execute(sql`insert into gathered values (5)`);
    await tx.transaction(async (inner) => inner.execute(sql`insert into gathered values (6)`));
  });
  // The insert with BEGIN; the savepoint; its insert; COMMIT.
  assert.equal(proxy.syncs - before, 4);
  assert.deepEqual([...await db.execute(sql`select n from gathered order by n`)].map((row) => row.n), [3, 4, 5, 6]);
  await pool.end();
});

test("a write left to `later` as a work's first statement goes behind what was asked before it: the head's lock first (Fable's review of #452)", { skip }, async () => {
  const sent: string[] = [];
  const client = postgresClient(DATABASE, { max: 1, debug: (_: number, text: string) => void sent.push(text) });
  try {
    const db = createDatabase(client);
    await db.execute(sql`create temporary table ordered (n int)`);
    // As `audited` asks it: the head's lock, a lazy prepared select, then the work, whose first statement is a `later`.
    const lock = prepared((on) => forUpdate(on, on.select({ next: tablesOf(on).auditChainHead.nextSeq }).from(tablesOf(on).auditChainHead)));
    await db.transaction(async (tx) => {
      // Awaited at once inside an async function, as `lockLogHead` awaits it, not yet answered when the work starts.
      const locking = (async () => await lock(tx))();
      later(tx, sql`insert into ordered values (1)`);
      await locking;
    });
    const at = (part: string) => sent.findIndex((text) => text.includes(part));
    assert.ok(at('audit_chain_head') >= 0 && at('audit_chain_head') < at('insert into ordered'), `sent ${JSON.stringify(sent)}`);
    assert.deepEqual([...await db.execute(sql`select n from ordered`)], [{ n: 1 }]);
  } finally {
    await client.end();
  }
});

test('a statement of a group that fails: those before it answer, it fails with its error, those after as an aborted transaction, and the transaction rolls back with its error', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  await db.execute(sql`create temporary table failing (n int)`);
  let settled: PromiseSettledResult<unknown>[] = [];
  const syncs = proxy.syncs;
  await assert.rejects(db.transaction(async (tx) => {
    settled = await Promise.allSettled([
      tx.execute(sql`insert into failing values (1) returning n`),
      tx.execute(sql`insert into failing values (${'two'}::int)`),
      tx.execute(sql`select 3 as n`),
    ]);
  }), { code: '22P02' });
  assert.equal(settled[0]!.status, 'fulfilled');
  assert.deepEqual([...(settled[0] as PromiseFulfilledResult<Record<string, unknown>[]>).value], [{ n: 1 }]);
  const causes = settled.slice(1).map((outcome) => ((outcome as PromiseRejectedResult).reason as { cause?: { code?: string } }).cause?.code);
  assert.deepEqual(causes, ['22P02', '25P02']);
  // The group, then its ROLLBACK; nothing kept, and the connection goes on.
  assert.equal(proxy.syncs - syncs, 2);
  assert.deepEqual([...await db.execute(sql`select count(*)::int as n from failing`)], [{ n: 0 }]);
  await pool.end();
});

test('a write left to `later` that fails has Postgres skip the COMMIT: nothing is kept, and the transaction fails with its error', { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  await db.execute(sql`create temporary table skipped (n int)`);
  await assert.rejects(db.transaction(async (tx) => {
    await tx.execute(sql`insert into skipped values (1)`);
    later(tx, sql`insert into skipped values (2)`);
    later(tx, sql`insert into skipped values (${'three'}::int)`);
  }), { code: '22P02' });
  assert.deepEqual([...await db.execute(sql`select count(*)::int as n from skipped`)], [{ n: 0 }]);
  await pool.end();
});

test('a COMMIT that Postgres runs and refuses ends the transaction: it fails with why, and no ROLLBACK follows', { skip }, async () => {
  const proxy = await counted();
  const sent: string[] = [];
  const client = postgresClient(proxy.url, { max: 1, debug: (_: number, text: string) => void sent.push(text) });
  try {
    const db = createDatabase(client);
    await db.execute(sql`create temporary table deferred (n int unique deferrable initially deferred)`);
    const syncs = proxy.syncs;
    await assert.rejects(db.transaction(async (tx) => {
      later(tx, sql`insert into deferred values (1)`);
      later(tx, sql`insert into deferred values (1)`);
    }), { code: '23505' });
    assert.equal(proxy.syncs - syncs, 1, 'BEGIN, both inserts and the COMMIT, under one Sync');
    assert.ok(!sent.includes('rollback'), `sent ${JSON.stringify(sent)}`);
    assert.deepEqual([...await db.execute(sql`select count(*)::int as n from deferred`)], [{ n: 0 }]);
  } finally {
    await client.end();
  }
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

test("closing by a time: what is under way then fails, what waits for its turn is never sent, and nothing opens the connection again (T170)", { skip }, async () => {
  const proxy = await counted();
  const pool = new HyperdrivePool(proxy.url);
  const db = createDatabase(pool);
  // A use's call past its deadline: its statement still running, another asked behind it.
  const slow = db.execute(sql`select pg_sleep(5), 1 as n`).then(n);
  const behind = db.execute(sql`select 2 as n`).then(n);
  const started = Date.now();
  const closed = pool.end(Date.now() + 100);
  await assert.rejects(slow);
  await assert.rejects(behind);
  await closed;
  assert.ok(Date.now() - started < 2_000, `closed after ${Date.now() - started} ms`);
  // Asked again after, as the call's work left behind may: refused, never a connection again.
  await assert.rejects(db.execute(sql`select 3 as n`), (error: Error) => /closed at the time it was given/.test(String((error.cause as Error | undefined)?.message)));
  assert.equal(proxy.opened, 1);
  for (let tries = 0; proxy.open > 0; tries += 1) {
    assert.ok(tries < 100, 'the connection was left open');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  // Done before its time, a call closes as ever: its statements answered, and none failed.
  const next = new HyperdrivePool(proxy.url);
  const answered = createDatabase(next).execute(sql`select 4 as n`).then(n);
  await next.end(Date.now() + 5_000);
  assert.equal(await answered, 4);
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
    // A transaction: its statements, the first with BEGIN, then COMMIT, each one round trip and one Sync, whichever
    // shape the first goes in: with parameters, BEGIN's Parse, Bind and Execute ahead of its own; without, one Query
    // of both, as the vault's SET LOCAL goes.
    for (const first of [sql`select ${1}::int`, sql`select 1`, sql.raw('SET LOCAL lock_timeout = 1000')]) {
      const before = { trips: proxy.trips, syncs: proxy.syncs };
      await createDatabase(pool).transaction(async (tx) => {
        await tx.execute(first);
        await tx.execute(sql`select ${'two'}::text`);
      });
      assert.deepEqual({ trips: proxy.trips - before.trips, syncs: proxy.syncs - before.syncs }, { trips: 3, syncs: 3 });
    }
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

// A Worker's database through Hyperdrive: one connection for the whole
// call, which its queries and transactions take turns on. On Cloudflare, a
// call that opened several connections at once was now and then cancelled
// as hung, so the count of connections is what these hold it to, through a
// proxy that sees each one, in front of the suite's Postgres.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { connect, createServer, type Socket } from 'node:net';

import { sql } from 'drizzle-orm';

import { createDatabase } from '../src/database.ts';
import { HyperdrivePool } from '../src/hyperdrive.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only: Hyperdrive' : false;
const DATABASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

/** Postgres behind a proxy that counts the connections made to it, and can cut them. */
async function counted() {
  const target = new URL(DATABASE);
  const open = new Set<Socket>();
  let opened = 0;
  let peak = 0;
  const server = createServer((client) => {
    opened += 1;
    open.add(client);
    peak = Math.max(peak, open.size);
    const upstream = connect(Number(target.port), target.hostname);
    client.pipe(upstream).pipe(client);
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
    cut: () => {
      for (const socket of open) socket.destroy();
    },
  };
}

const n = (rows: { rows: Record<string, unknown>[] }) => Number(rows.rows[0]!.n);

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
  const { rows } = await db.execute(sql`select v from turns`);
  assert.deepEqual(rows, [{ v: 'beside it' }]);
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

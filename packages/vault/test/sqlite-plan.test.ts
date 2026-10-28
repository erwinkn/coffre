// A query plan read on SQLite (T146). libsql leaves an `EXPLAIN`'s statement active on its connection, so the reads that
// connection makes afterwards keep a snapshot open, and its next `BEGIN IMMEDIATE`, once another connection has
// committed, fails with SQLITE_BUSY_SNAPSHOT, now and then for as long as the statement lives. `sqlitePlan` reads a plan on
// a connection of its own so no pooled connection carries one; the product never runs an EXPLAIN.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { openDatabase } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { ENGINE, openTestDatabase, rows, run, sqlitePlan, type TestDatabase } from './database.ts';

const sqliteOnly = { skip: ENGINE === 'sqlite' ? false : 'SQLite only: libsql' };

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** The step a write of another connection takes between `reader`'s read and its own transaction. */
async function writeThenBegin(reader: TestDatabase['owner']): Promise<void> {
  await rows(reader, sql`SELECT max(number) FROM log_changes`);
  await run(db.vault, sql`UPDATE log_fence SET at_floor = at_floor + 1`);
  await reader.transaction(async (tx) => {
    await run(tx, sql`UPDATE log_fence SET at_floor = at_floor + 1`);
  });
}

test("libsql keeps a connection's snapshot open after an EXPLAIN: its next transaction, after another's write, fails (why `sqlitePlan` has a connection of its own)", sqliteOnly, async () => {
  const { db: reader, close } = await openDatabase(process.env.COFFRE_TEST_DATABASE_URL!);
  try {
    await rows(reader, sql`EXPLAIN QUERY PLAN SELECT max(number) FROM log_changes`);
    await assert.rejects(writeThenBegin(reader), (error: unknown) => {
      const { extendedCode, cause } = error as { extendedCode?: string; cause?: { extendedCode?: string } };
      assert.equal(extendedCode ?? cause?.extendedCode, 'SQLITE_BUSY_SNAPSHOT');
      return true;
    });
  } finally {
    await close();
  }
});

test('a plan read by `sqlitePlan` leaves the suite\'s connections able to write after another connection did', sqliteOnly, async () => {
  const plan = await sqlitePlan(sql`SELECT max(number) FROM log_changes`);
  assert.ok(plan.length > 0, 'a plan');
  await writeThenBegin(db.owner);
  await writeThenBegin(db.vault);
});

// T143: a use on a database just migrated, before the checkpointer has made any day of uses. The suite's template is
// only migrated (setup-test-database.sh), so this file's database is a new instance's.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { sql } from 'drizzle-orm';

import { daysAround } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { ENGINE, openTestDatabase, rows, type TestDatabase } from './database.ts';
import { ask, isolate, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());

test('a new database holds the days the checkpointer would make around now', { skip: ENGINE === 'postgres' ? false : 'SQLite does not partition' }, async () => {
  const made = await logStore(db.vault).days();
  // The template was migrated some time ago, perhaps before a midnight: of daysAround's five, the middle three are the
  // days it holds whenever in the last day it was.
  for (const day of daysAround(Date.now()).slice(1, 4)) assert.ok(made.includes(day), `${day} is made by the migrations: ${made.join()}`);
});

test('a use on a freshly migrated database, before any checkpointer tick', async () => {
  // No emptyLog: it makes the days around today, which is what this is about.
  const w = await world();
  const id = await w.key('postgres://prod');
  const { use } = await isolate();
  const outcome = await use(ask(w, id));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1);
});

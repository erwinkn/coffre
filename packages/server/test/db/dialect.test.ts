import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { Database } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { projects } from '@coffre/db/schema';
import { asc, like } from 'drizzle-orm';

import { insert, insertIfAbsent, update, upsert } from '../../src/db/queries.ts';
import { openTestDatabase } from './engine.ts';

// The named operations of dialect.ts.

let db: Database;
let close: () => Promise<void>;

before(async () => {
  ({ runtime: db, close } = await openTestDatabase());
});

after(() => close());

/** Slugs of a test's own, so that no reset is needed. */
function place() {
  const prefix = `t${randomUUID().slice(0, 8)}`;
  return {
    row: (name: string) => ({ id: randomUUID(), slug: `${prefix}-${name}`, name }),
    names: async () =>
      (await db.select({ name: projects.name }).from(projects).where(like(projects.slug, `${prefix}-%`)).orderBy(asc(projects.slug)))
        .map((row) => row.name),
  };
}

test('insertIfAbsent inserts the rows whose keys are free and counts them', async () => {
  const { row, names } = place();
  await insert(db, projects, row('alpha'));
  assert.equal(await insertIfAbsent(db, projects, [row('alpha'), row('beta'), row('gamma')]), 2);
  assert.equal(await insertIfAbsent(db, projects, row('beta')), 0);
  assert.deepEqual(await names(), ['alpha', 'beta', 'gamma']);
});

test('a duplicate skipped inside a transaction leaves the transaction going', async () => {
  const { row, names } = place();
  await insert(db, projects, row('alpha'));
  await db.transaction(async (tx) => {
    assert.equal(await insertIfAbsent(tx, projects, row('alpha')), 0);
    await insert(tx, projects, row('beta'));
  });
  assert.deepEqual(await names(), ['alpha', 'beta']);
});

test('insertIfAbsent skips duplicates only: a failed check still fails', async () => {
  const { row, names } = place();
  const bad = { ...row('bad'), slug: 'Not a slug' };
  await assert.rejects(insertIfAbsent(db, projects, [row('alpha'), bad]));
  assert.deepEqual(await names(), []);
});

test('a duplicate key is recognised as one, and nothing else is', async () => {
  const { row } = place();
  const alpha = row('alpha');
  await insert(db, projects, alpha);
  const duplicate = await insert(db, projects, { ...alpha, id: randomUUID() }).catch((error: unknown) => error);
  assert.equal(isUniqueViolation(duplicate), true);
  const failedCheck = await insert(db, projects, { ...row('x'), slug: '-' }).catch((error: unknown) => error);
  assert.ok(failedCheck instanceof Error);
  assert.equal(isUniqueViolation(failedCheck), false);
});

test('upsert overwrites the named columns of the row whose key repeats', async () => {
  const { row, names } = place();
  const alpha = row('alpha');
  await insert(db, projects, alpha);
  await upsert(db, projects, [{ ...alpha, id: randomUUID(), name: 'renamed' }, row('beta')], {
    target: ['slug'],
    columns: ['name'],
  });
  assert.deepEqual(await names(), ['renamed', 'beta']);
});

test('update counts the rows it matched, changed or not', async () => {
  const { row } = place();
  const alpha = row('alpha');
  await insert(db, projects, alpha);
  assert.equal(await update(db, projects, { id: alpha.id }, { name: 'alpha' }), 1);
  assert.equal(await update(db, projects, { id: randomUUID() }, { name: 'nobody' }), 0);
});

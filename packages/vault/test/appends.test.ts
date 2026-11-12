// The log's appends, past what one statement binds: the mark of an entry 0.15 wrote, and a chain kept whole across
// statements.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { appendEntries } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { emptyDatabase, openTestDatabase, rows, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

test("an append of 3,000 entries, the most one statement takes, fits its parameters with the mark, which is a literal, and each says whether 0.15 wrote it (review r5 of PR 9b)", async () => {
  const key = deriveLogKey('vault', randomBytes(32));
  const entries = Array.from({ length: 3000 }, () => ({ actor: ROOT, action: 'secret.read', decision: 'allow' as const, metadata: '{}' }));
  await db.owner.transaction((tx) => appendEntries(tx, key, entries, undefined, undefined, [], true));
  await db.owner.transaction((tx) => appendEntries(tx, key, entries.slice(0, 2)));
  const marks = await rows<{ log015: boolean | null; n: string | number }>(db.owner, sql`SELECT log015, count(*) AS n FROM audit_log GROUP BY log015 ORDER BY log015`);
  assert.deepEqual(marks.map((row) => [row.log015, Number(row.n)]), [[true, 3000], [null, 2]]);
});

test('an append of more entries than one statement binds goes in several, in the one transaction, its chain whole: a rotation closing thousands of open intents (review r3 of #538)', async () => {
  const key = deriveLogKey('vault', randomBytes(32));
  // Past 3,000 a statement, more than twice.
  const entries = Array.from({ length: 6_500 }, (_, i) => ({ actor: ROOT, action: 'secret.read', decision: 'deny' as const, code: 'wrong_kek', metadata: JSON.stringify({ item: i }) }));
  const appended = await db.owner.transaction((tx) => appendEntries(tx, key, entries));
  assert.equal(appended.nextSeq - appended.seqStart, 6_500n);
  const [{ n, first, last }] = await rows<{ n: string | number; first: string | number; last: string | number }>(db.owner,
    sql`SELECT count(*) AS n, min(seq) AS first, max(seq) AS last FROM audit_log`);
  assert.deepEqual([Number(n), BigInt(first), BigInt(last)], [6_500, appended.seqStart, appended.nextSeq - 1n]);
  // And the next append goes on from its head.
  const next = await db.owner.transaction((tx) => appendEntries(tx, key, entries.slice(0, 1)));
  assert.equal(next.seqStart, appended.nextSeq);
});

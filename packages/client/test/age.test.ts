import test from 'node:test';
import assert from 'node:assert/strict';

import { ageInDays, olderThan } from '@coffre/client';

const NOW = Date.parse('2026-10-16T12:00:00.000Z');
const key = (updatedAt: string | null, archived = false) => ({ updatedAt, archived });

test("a value's age is in whole days, and it is older than N days from day N + 1", () => {
  assert.equal(ageInDays(key('2026-10-16T01:00:00.000Z'), NOW), 0);
  assert.equal(ageInDays(key('2026-10-15T12:00:00.000Z'), NOW), 1);
  assert.equal(ageInDays(key(null), NOW), null);
  // A clock behind the database's never makes a value younger than new.
  assert.equal(ageInDays(key('2026-10-16T12:00:01.000Z'), NOW), 0);

  const year = key('2025-10-16T12:00:00.000Z');
  assert.equal(ageInDays(year, NOW), 365);
  assert.equal(olderThan(year, 365, NOW), false);
  assert.equal(olderThan(key('2025-10-15T12:00:00.000Z'), 365, NOW), true);
});

test('an archived key, which nothing reads, and a key with no value are never due', () => {
  assert.equal(olderThan(key('2020-01-01T00:00:00.000Z', true), 365, NOW), false);
  assert.equal(olderThan(key(null), 0, NOW), false);
});

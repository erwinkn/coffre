// Where each count of the log's prefix goes (T245): the whole prefix while it is short, else a window a checkpoint,
// round the log; a verification's, the newest window.
import test from 'node:test';
import assert from 'node:assert/strict';

import { COUNTED_AT_ONCE, countWindow, newestWindow } from '../src/log.ts';

test('a prefix no longer than a count is counted whole, every time', () => {
  assert.deepEqual(countWindow(-1n, null), { from: 0n, to: -1n, next: null });
  assert.deepEqual(countWindow(9n, null), { from: 0n, to: 9n, next: null });
  assert.deepEqual(countWindow(COUNTED_AT_ONCE - 1n, null), { from: 0n, to: COUNTED_AT_ONCE - 1n, next: null });
  assert.equal(newestWindow(9n), 0n);
});

test('a longer prefix is counted a window at a time, round to the first entry again past its end', () => {
  // A prefix through 9, four a count: [0, 3], [4, 7], [8, 9], then [0, 3] again.
  const laps: [bigint, bigint][] = [];
  let at: bigint | null = null;
  for (let i = 0; i < 4; i += 1) {
    const window = countWindow(9n, at, 4n);
    laps.push([window.from, window.to]);
    at = window.next;
  }
  assert.deepEqual(laps, [[0n, 3n], [4n, 7n], [8n, 9n], [0n, 3n]]);
  // The prefix grown since: a window goes on where the last stopped, and covers what came after.
  assert.deepEqual(countWindow(13n, 8n, 4n), { from: 8n, to: 11n, next: 12n });
  // A cursor past the prefix (a checkpoint's, before a restore cut the log short): from the first entry.
  assert.deepEqual(countWindow(5n, 8n, 4n), { from: 0n, to: 3n, next: 4n });
  assert.equal(newestWindow(9n, 4n), 6n);
});

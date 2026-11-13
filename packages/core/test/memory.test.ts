import test from 'node:test';
import assert from 'node:assert/strict';

import { BODIES_BYTES, BODY_READ_WHOLE_BYTES, CACHE_SLICE_BYTES, CACHES_BYTES, ISOLATE_BYTES, Lru, RUNTIME_BYTES, USE_IN_FLIGHT_BYTES, USES_BYTES, USES_IN_FLIGHT, weight } from '../src/memory.ts';

test("the shares split an isolate's 128 MB, and leave the runtime more than an idle app's isolate holds", () => {
  assert.equal(USES_BYTES + BODIES_BYTES + CACHES_BYTES + RUNTIME_BYTES, ISOLATE_BYTES);
  // 8,602,928 bytes: the app's Worker idle, once collected.
  assert.ok(RUNTIME_BYTES > 3 * 8_602_928, `${RUNTIME_BYTES}`);
  assert.equal(Math.floor(USES_BYTES / USE_IN_FLIGHT_BYTES), 2083);
  // The CPU bound, 3 s ÷ 2.4 ms, is the smaller, while a key in flight holds at most 51,200 bytes (config.md, Q1).
  assert.equal(USES_IN_FLIGHT, 1250);
  assert.ok(USE_IN_FLIGHT_BYTES <= USES_BYTES / USES_IN_FLIGHT);
  assert.equal(BODIES_BYTES / (2 * BODY_READ_WHOLE_BYTES), 8);
  assert.ok(7 * CACHE_SLICE_BYTES <= CACHES_BYTES);
});

/** Entries of one weight each: a one-letter key and a small number, 170 bytes with the entry's own. */
const each = 128 + weight('a') + weight(1);

test('past its bytes, the least recently used goes first, one at a time; a read makes an entry the most recent', () => {
  const lru = new Lru<string, number>(3 * each);
  lru.set('a', 1).set('b', 2).set('c', 3);
  assert.equal(lru.held, 3 * each);
  assert.equal(lru.get('a'), 1);
  lru.set('d', 4);
  // b was the least recently used: a was read since, c and d set after.
  assert.deepEqual([...lru], [['c', 3], ['a', 1], ['d', 4]]);
  lru.set('e', 5);
  assert.deepEqual([...lru].map(([key]) => key), ['a', 'd', 'e']);
  // Set again, an entry is the most recent, and takes no other's room.
  lru.set('a', 6);
  assert.deepEqual([...lru], [['d', 4], ['e', 5], ['a', 6]]);
  assert.equal(lru.held, 3 * each);
});

test('an entry goes by its weight: a heavy one makes room by as many as it needs, and one heavier than all is not kept', () => {
  const lru = new Lru<string, string>(1000);
  for (const key of ['a', 'b', 'c', 'd']) lru.set(key, key);
  assert.equal(lru.size, 4);
  const heavy = 'x'.repeat(250);
  lru.set('h', heavy);
  // 128 + 26 + 524 bytes, beside four of 180: three of them made room, the least recently used first.
  assert.deepEqual([...lru].map(([key]) => key), ['d', 'h']);
  lru.set('huge', 'x'.repeat(1000));
  assert.equal(lru.has('huge'), false);
  assert.deepEqual([...lru].map(([key]) => key), ['d', 'h'], 'and nothing went for it');
  assert.equal(lru.delete('h'), true);
  assert.equal(lru.held, 128 + weight('d') + weight('d'));
  lru.clear();
  assert.deepEqual([lru.size, lru.held], [0, 0]);
});

test('a cache weighs its entries as it is told: by a given rule, or `weight`, an upper bound on what V8 holds for plain data', () => {
  const lru = new Lru<string, { definition: string }>(10_000, (key, item) => weight(key) + 3 * weight(item.definition));
  lru.set('k', { definition: 'abc' });
  assert.equal(lru.held, 128 + weight('k') + 3 * weight('abc'));
  assert.equal(weight('abc'), 30);
  assert.equal(weight({ a: 'abc', b: [1, null] }), 56 + 32 + 30 + 48 + 16 + 16);
});

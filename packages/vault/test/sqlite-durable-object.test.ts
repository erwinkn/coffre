import test from 'node:test';
import assert from 'node:assert/strict';

import { durableObjectSqlite } from '../src/sqlite-durable-object.ts';

test("a Durable Object's cursors run to their end, even when a loop over one stops early", () => {
  // As workerd's: its own iterator, with no return() to close it.
  const cursors: { read: number; rows: number }[] = [];
  const storage = {
    sql: {
      exec() {
        const cursor = { read: 0, rows: 3 };
        cursors.push(cursor);
        const next = () => (cursor.read < cursor.rows ? { value: { n: ++cursor.read } } : { done: true as const });
        const iterator = { next, [Symbol.iterator]: () => iterator };
        return Object.assign(iterator, { toArray: () => [...iterator] });
      },
    },
  } as unknown as DurableObjectStorage;
  const db = durableObjectSqlite(storage);

  assert.deepEqual(db.get('SELECT n FROM t LIMIT 1'), { n: 1 });
  for (const row of db.iterate<{ n: number }>('SELECT n FROM t')) {
    if (row.n === 1) break;
  }
  assert.deepEqual(cursors, [
    { read: 3, rows: 3 },
    { read: 3, rows: 3 },
  ]);
});

import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import test, { after, before } from 'node:test';
import { openTestDatabase, resetDatabase, waitUntil } from './api-fixture.ts';
import { environments } from './db/tables.ts';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => { db = await openTestDatabase(); });
after(async () => { await db.close(); });

test('reset still drains tracked background work before deleting any table', async () => {
  await resetDatabase(db.owner);
  let release!: () => void;
  const task = new Promise<void>((resolve) => { release = resolve; });
  waitUntil(task);
  let deleting = false;
  const owner = new Proxy(db.owner, {
    get(target, property) {
      if (property !== 'delete') return Reflect.get(target, property);
      return (table: unknown) => {
        deleting = true;
        return Reflect.apply(target.delete, target, [table]);
      };
    },
  });
  const resetting = resetDatabase(owner);
  try {
    await setImmediate();
    assert.equal(deleting, false);
  } finally {
    release();
    await resetting;
  }
  assert.deepEqual(await db.owner.select().from(environments), []);
});

// A matrix's batch, one of its cells failing while the others still run (matrix-cells.test.ts): a test file of its
// own, shaped as a matrix is, run as a process that must exit by itself once its test fails. node:test reports a failed
// test and leaves the process to exit when nothing is left open, as the matrices' processes do: a pool still open keeps
// it running. Each cell opens its isolate's pool and its connection, as a cell's measured isolate does; the others are
// made but never asked, and keep theirs open until the file's `endSlowed`.
import test, { after, before } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

import { openTestDatabase, type TestDatabase } from './database.ts';
import { each, endSlowed, namedWorld, slowed } from './named-world.ts';
import { emptyLog, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase({ connections: 1 });
  await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

test('a batch, one of its cells failing', async () => {
  await namedWorld(db);
  try {
    await each([0, 1, 2, 3], async (i) => {
      // The failing cell fails as the others are still opening theirs; the last of them opens it after the failure.
      if (i === 3) await sleep(500);
      const measured = await slowed(db, { connections: 1 });
      await measured.connect();
      if (i === 0) throw new Error('a cell failed');
      await sleep(1000);
      return measured;
    });
  } finally {
    await endSlowed();
  }
});

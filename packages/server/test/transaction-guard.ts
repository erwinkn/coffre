import { AsyncLocalStorage } from 'node:async_hooks';
import assert from 'node:assert/strict';
import { afterEach } from 'node:test';

import type { Database } from '@coffre/db';
import { drainBackgroundTasks } from './background-tasks.ts';

const transaction = new AsyncLocalStorage<{ open: boolean }>();
const violations: string[] = [];

/** Track the calling request, not unrelated transactions running alongside it. */
export function guardTransactions<T extends Database>(db: T): T {
  const run = db.transaction.bind(db);
  db.transaction = ((work, options) => {
    const state = { open: true };
    return run((tx) => transaction.run(state, () => work(guardTransactions(tx as unknown as Database) as never)), options)
      .finally(() => { state.open = false; });
  }) as Database['transaction'];
  return db;
}

export function assertOutsideTransaction(method: string): void {
  if (!transaction.getStore()?.open) return;
  const message = `vault.${method} called with an app transaction open`;
  violations.push(message);
  throw new Error(message);
}

// An API error or failed background sync must not hide a violation.
afterEach(async () => {
  await drainBackgroundTasks();
  const found = violations.splice(0);
  assert.deepEqual(found, [], 'vault calls must happen outside app transactions');
});

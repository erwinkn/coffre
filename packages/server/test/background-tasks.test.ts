import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';

import { drainBackgroundTasks, trackBackgroundTask } from './background-tasks.ts';

test('draining follows child tasks and waits for siblings even after a rejection', async () => {
  let release!: () => void;
  const child = new Promise<void>((resolve) => { release = resolve; });
  trackBackgroundTask(Promise.resolve().then(() => { trackBackgroundTask(child); }));
  const failure = new Error('expected background failure');
  const rejected = Promise.reject(failure);
  const observed = rejected.catch((error: unknown) => assert.equal(error, failure));
  trackBackgroundTask(rejected);

  let drained = false;
  const draining = drainBackgroundTasks().then(() => { drained = true; });
  try {
    await setImmediate();
    assert.equal(drained, false, 'a rejection must not abandon another task or its child');
  } finally {
    release();
    await draining;
    await observed;
  }
  assert.equal(drained, true);
});

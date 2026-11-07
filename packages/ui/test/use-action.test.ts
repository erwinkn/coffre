import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';
import { QueryObserver } from '@tanstack/react-query';

import { act } from '../src/lib/use-action.ts';
import { createQueryClient } from '../src/lib/queries.ts';

/** A query on screen, counting its reads. */
async function watched(queryKey: string[]) {
  const queryClient = createQueryClient();
  let reads = 0;
  const options = { queryKey, queryFn: async () => ++reads };
  await queryClient.fetchQuery(options);
  const stop = new QueryObserver(queryClient, options).subscribe(() => {});
  return { queryClient, reads: () => reads, stop };
}

const cutOff = () => new CoffreError(200, 'unreadable', 'coffre answered 200, but its answer did not arrive whole');

test('a change whose 200 was cut off reads again what it touched, and says its answer was lost', async () => {
  const { queryClient, reads, stop } = await watched(['settings']);
  const said: (string | null)[] = [];
  let succeeded = false;
  await act(queryClient, () => Promise.reject(cutOff()), { affects: [['settings']], onSuccess: () => { succeeded = true; } }, (error) => said.push(error));
  assert.equal(reads(), 2, 'read again');
  assert.equal(succeeded, false, 'onSuccess needs the answer it never got');
  assert.deepEqual(said, ['coffre’s answer was cut off on the way. Reload to see where things stand.']);
  stop();
});

test('one whose touches are named from its answer reads everything again', async () => {
  const { queryClient, reads, stop } = await watched(['anything']);
  await act(queryClient, () => Promise.reject(cutOff()), { affects: () => [['named']] }, () => {});
  assert.equal(reads(), 2);
  stop();
});

test('a refusal reads nothing again', async () => {
  const { queryClient, reads, stop } = await watched(['settings']);
  const said: (string | null)[] = [];
  await act(queryClient, () => Promise.reject(new CoffreError(409, 'conflict', 'taken')), { affects: [['settings']] }, (error) => said.push(error));
  assert.equal(reads(), 1);
  assert.deepEqual(said, ['taken']);
  stop();
});

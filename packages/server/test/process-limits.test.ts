// `processLimits`, Node's limit per source (W331, D177): 10,000 requests per
// 10-second window by default, each key counted apart, at most 10,000 keys.
import test from 'node:test';
import assert from 'node:assert/strict';

import { processLimits, SOURCE_RETRY_AFTER } from '../src/workloads/limits.ts';

const passes = async (limiter: ReturnType<typeof processLimits>['perSource'], key: string, n: number): Promise<number> => {
  let passed = 0;
  for (let i = 0; i < n; i++) if ((await limiter.limit({ key })).success) passed++;
  return passed;
};

test('10,000 a window by default: the 10,001st from one address is refused, another address and another entry point counted apart', async () => {
  const { perSource } = processLimits();
  assert.equal(await passes(perSource, 'exchange:198.51.100.1', 10_001), 10_000);
  assert.equal(await passes(perSource, 'exchange:198.51.100.2', 1), 1);
  assert.equal(await passes(perSource, 'oauth:token:198.51.100.1', 1), 1);
});

test('the window is 10 seconds: refused until it has moved on, which is when a refusal says to come back', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { perSource } = processLimits({ perSource: 2 });
  assert.equal(await passes(perSource, 'k', 3), 2);
  t.mock.timers.tick(9_999);
  assert.equal(await passes(perSource, 'k', 1), 0);
  t.mock.timers.tick(1);
  assert.equal(await passes(perSource, 'k', 3), 2);
  assert.equal(SOURCE_RETRY_AFTER, '10');
});

test('at most 10,000 keys: past them, the oldest window goes and counts from nothing again', async () => {
  const { perSource } = processLimits({ perSource: 1 });
  assert.equal(await passes(perSource, 'first', 2), 1);
  for (let i = 0; i < 9_999; i++) await perSource.limit({ key: `other:${i}` });
  // 10,000 keys, the first among them: still counted.
  assert.equal(await passes(perSource, 'first', 1), 0);
  await perSource.limit({ key: 'one more' });
  assert.equal(await passes(perSource, 'first', 1), 1);
});

test("0.15's options are taken and read no more, and its limiters still returned let everything through (W331, D177)", async () => {
  const limits = processLimits({ perSource: 3, total: 1, perConnection: 1 });
  assert.equal(await passes(limits.perSource, 'a', 3) + (await passes(limits.perSource, 'b', 3)), 6);
  // A deployment that picks them out still builds and starts; neither counts.
  assert.equal(await passes(limits.total, 'total', 20_000), 20_000);
  assert.equal(await passes(limits.perConnection, 'connection:c', 20_000), 20_000);
  assert.throws(() => processLimits({ perSource: 0 }), /a whole number of requests a window/);
});

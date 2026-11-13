// Adaptive throttling (docs/design/limits.md, "Refusing fast on overload: adaptive throttling"):
// the share of uses an isolate refuses at once, from what it
// answered, in time or not, over the last two use deadlines. No database.
import test from 'node:test';
import assert from 'node:assert/strict';

import { USE_DEADLINE_MS } from '@coffre/core/vault';

import { Throttle, THROTTLE_K, THROTTLE_WINDOW_MS } from '../src/throttle.ts';

const T0 = 1_800_000_000_000;

/** `uses` answered at `at`, the first `inTime` of them in time, none asked of the throttle first. */
function answered(throttle: Throttle, at: number, uses: number, inTime: number): void {
  for (let i = 0; i < uses; i += 1) throttle.answered(at, i < inTime);
}

/** How many of `uses` asked at `at` it refuses, each one it lets through answered as `inTime` says. */
function asked(throttle: Throttle, at: number, uses: number, inTime: boolean): number {
  let refused = 0;
  for (let i = 0; i < uses; i += 1) {
    if (throttle.refuses(at)) refused += 1;
    else throttle.answered(at, inTime);
  }
  return refused;
}

test('nothing is refused while at least two in three uses are answered in time', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 1_500, 1_000);
  assert.equal(throttle.rate(T0), 0);
  assert.equal(asked(throttle, T0, 1_000, true), 0);
});

test('2,500 a second offered, 1,040 answered in time, for a window: p about 38%, K times the accepts let through', () => {
  const throttle = new Throttle();
  for (let s = 0; s < THROTTLE_WINDOW_MS / 1_000; s += 1) answered(throttle, T0 + s * 1_000, 2_500, 1_040);
  const p = throttle.rate(T0 + THROTTLE_WINDOW_MS - 1);
  assert.ok(Math.abs(p - (15_000 - THROTTLE_K * 6_240) / 15_001) < 1e-12);
  assert.ok(Math.abs(2_500 * (1 - p) - THROTTLE_K * 1_040) < 1, 'about 1,560 a second let through');
});

test('refusals are spread at the rate, not drawn: at p = 1/5, one use in five', () => {
  const throttle = new Throttle();
  // 60,000 answered, 31,990 in time: p = 12,015 ÷ 60,001, just over 1/5, which ten more uses barely move.
  answered(throttle, T0, 60_000, 31_990);
  assert.ok(Math.abs(throttle.rate(T0) - 0.2) < 1e-3);
  const pattern = Array.from({ length: 10 }, () => throttle.refuses(T0));
  assert.deepEqual(pattern, [false, false, false, false, true, false, false, false, false, true]);
});

test("a cold isolate's burst refuses nothing until a use has failed: the uses in flight are not counted", () => {
  const throttle = new Throttle();
  for (let i = 0; i < 200; i += 1) assert.equal(throttle.refuses(T0), false, `use ${i + 1}, the earlier ones in flight`);
});

test('a cold isolate whose first use was late refuses one of the next two, and never shuts', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 1, 0);
  assert.equal(throttle.rate(T0), 1 / 2);
  assert.equal(throttle.refuses(T0), false);
  assert.equal(throttle.refuses(T0), true);
  assert.ok(asked(throttle, T0, 10_000, false) < 10_000, 'some still let through, however many fail');
  assert.ok(throttle.rate(T0) < 1);
});

test('uses answered in time bring refusals back to 0 while the failures are still in the window', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 1_000, 0);
  assert.ok(throttle.rate(T0) > 0.99);
  // 2,000 more, all in time: 3,000 answered, 2,000 in time, exactly two in three.
  answered(throttle, T0 + 3_000, 2_000, 2_000);
  assert.equal(throttle.rate(T0 + 3_000), 0);
  assert.equal(throttle.refuses(T0 + 3_000), false);
});

test('what the window has left counts for nothing: second by second, and after a gap of more than the window', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 100, 0);
  answered(throttle, T0 + 3_000, 10, 10);
  assert.equal(throttle.rate(T0 + THROTTLE_WINDOW_MS - 1), (110 - 15) / 111, 'the first second still in the window');
  // The first second leaves it: 10 answered, 10 in time.
  assert.equal(throttle.rate(T0 + THROTTLE_WINDOW_MS), 0);
  // Every bucket after a long gap is empty, the failures with it.
  answered(throttle, T0 + 10 * THROTTLE_WINDOW_MS, 10, 0);
  assert.equal(throttle.rate(T0 + 10 * THROTTLE_WINDOW_MS), 10 / 11);
  assert.equal(throttle.rate(T0 + 11 * THROTTLE_WINDOW_MS), 0);
});

/**
 * One isolate against a vault that answers `capacity` uses a second in time, each `ANSWER_MS` after it is asked; any
 * more it lets through wait their whole deadline and answer `late`. `offered` uses a second, for each second, oldest
 * first, asked evenly through the second; returns what each second's asks did. Outcomes reach the throttle when they
 * settle, in order with the asks, as on an isolate.
 */
function overload(offered: readonly number[], capacity: number) {
  const ANSWER_MS = 100;
  const throttle = new Throttle();
  // Both queues settle in the order their uses were asked, so each stays sorted by time.
  const inTimes: number[] = [];
  const lates: number[] = [];
  const settle = (until: number) => {
    while (true) {
      const next = Math.min(inTimes[0] ?? Infinity, lates[0] ?? Infinity);
      if (next > until) return;
      if (next === inTimes[0]) throttle.answered(inTimes.shift()!, true);
      else throttle.answered(lates.shift()!, false);
    }
  };
  return offered.map((uses, s) => {
    let inTime = 0;
    let late = 0;
    let refused = 0;
    for (let i = 0; i < uses; i += 1) {
      const now = T0 + s * 1_000 + (i * 1_000) / uses;
      settle(now);
      if (throttle.refuses(now)) refused += 1;
      else if (inTime < capacity) {
        inTime += 1;
        inTimes.push(now + ANSWER_MS);
      } else {
        late += 1;
        lates.push(now + USE_DEADLINE_MS);
      }
    }
    return { inTime, late, refused };
  });
}

test('after an overload, a load under capacity is let through in full within two windows; during it, most of the excess is refused, not late', () => {
  // A load measured on Cloudflare, scaled to one isolate: 2.5 times what it answers, for two minutes, then half of it.
  const burst = 120;
  const seconds = overload([...Array(burst).fill(250), ...Array(60).fill(50)], 100);
  const during = seconds.slice(10, burst);
  const sum = (key: 'inTime' | 'late' | 'refused') => during.reduce((n, second) => n + second[key], 0);
  assert.ok(sum('inTime') >= 0.95 * 100 * during.length, `answered in time ${sum('inTime')}, about all it can`);
  // At K = 1.5 the steady state refuses 2 for every late one; spread asks and settled outcomes land
  // under that, so the check is the run's own: most of the excess refused.
  assert.ok(sum('refused') > sum('late'), `refused ${sum('refused')}, late ${sum('late')}`);
  // The last second anything is refused, or late, after the burst: about 9 s in this model, held to two windows.
  const after = seconds.slice(burst);
  const last = after.findLastIndex((second) => second.refused > 0 || second.late > 0);
  assert.ok(last + 1 <= (2 * THROTTLE_WINDOW_MS) / 1_000, `all let through ${last + 1} s after the burst`);
  assert.ok(after.slice(last + 1).every((second) => second.inTime === 50));
});

// Adaptive throttling (docs/design/config.md, Q1, step 2): the share of uses an isolate refuses at once, from what it
// answered, in time or not, over the last two minutes. No database.
import test from 'node:test';
import assert from 'node:assert/strict';

import { Throttle, THROTTLE_WINDOW_MS } from '../src/throttle.ts';

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

test('nothing is refused while at least half the uses are answered in time', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 1_000, 500);
  assert.equal(throttle.rate(T0), 0);
  assert.equal(asked(throttle, T0, 1_000, true), 0);
});

test("the book's example: 2,500 a second offered, 1,040 answered in time, for two minutes: p about 17%", () => {
  const throttle = new Throttle();
  for (let s = 0; s < 120; s += 1) answered(throttle, T0 + s * 1_000, 2_500, 1_040);
  assert.ok(Math.abs(throttle.rate(T0 + 119_000) - (300_000 - 2 * 124_800) / 300_001) < 1e-12);
});

test('refusals are spread at the rate, not drawn: at p = 1/5, one use in five', () => {
  const throttle = new Throttle();
  // 60,000 answered, 23,990 in time: p = 12,020 ÷ 60,001, just over 1/5, which ten more uses barely move.
  answered(throttle, T0, 60_000, 23_990);
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
  // 1,000 more, all in time: 2,000 answered, 1,000 in time, exactly half.
  answered(throttle, T0 + 30_000, 1_000, 1_000);
  assert.equal(throttle.rate(T0 + 30_000), 0);
  assert.equal(throttle.refuses(T0 + 30_000), false);
});

test('what the window has left counts for nothing: second by second, and after a gap of more than the window', () => {
  const throttle = new Throttle();
  answered(throttle, T0, 100, 0);
  answered(throttle, T0 + 60_000, 10, 10);
  assert.equal(throttle.rate(T0 + THROTTLE_WINDOW_MS - 1), (110 - 20) / 111, 'the first second still in the window');
  // The first second leaves it: 10 answered, 10 in time.
  assert.equal(throttle.rate(T0 + THROTTLE_WINDOW_MS), 0);
  // Every bucket after a long gap is empty, the failures with it.
  answered(throttle, T0 + 10 * THROTTLE_WINDOW_MS, 10, 0);
  assert.equal(throttle.rate(T0 + 10 * THROTTLE_WINDOW_MS), 10 / 11);
  assert.equal(throttle.rate(T0 + 11 * THROTTLE_WINDOW_MS), 0);
});

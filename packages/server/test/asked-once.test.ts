// A value an isolate asks for once (asked-once.ts, T201): its concurrent first requests make one call and take its
// answer, or its failure; no request ever waits on another's pending call, so a call that never settles (its request
// cancelled, on Workers) holds the others back only until one of them takes the call over.
import test from 'node:test';
import assert from 'node:assert/strict';

import type { Vault } from '@coffre/core/vault';

import { ApiError } from '../src/api/errors.ts';
import { keeps015 } from '../src/api/changes.ts';
import { askedOnce, askOnce, WAIT_MS } from '../src/asked-once.ts';
import type { ProxyCode } from '../src/proxy-code.ts';
import { gateProxy } from '../src/proxy-gate.ts';

const settles = <T>(ms: number, value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** A call settled when the test says. */
function call<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => ((resolve = yes), (reject = no)));
  return { promise, resolve, reject };
}
const unasked = (): Promise<never> => assert.fail('a request that joined a call under way made one');
/** How `answer` settles, without leaving its rejection unhandled while the test goes on. */
const outcome = <T>(answer: Promise<T>) => answer.then((value) => ({ value }), (error: unknown) => ({ error }));
/** Within `ms`, or the request waits still: on another call's pending work, or for ever. */
const within = <T>(ms: number, answer: Promise<T>) =>
  Promise.race([answer, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`still waiting after ${ms} ms`)), ms).unref())]);

test("an isolate's concurrent first requests make one call and each takes its answer; every request after makes none", async () => {
  const kept = askedOnce<string>();
  let calls = 0;
  const ask = () => ((calls += 1), settles(30, 'about'));
  const answers = await Promise.all(Array.from({ length: 50 }, () => askOnce(kept, ask)));
  assert.deepEqual(new Set(answers), new Set(['about']));
  assert.equal(calls, 1);
  assert.equal(await askOnce(kept, ask), 'about');
  assert.equal(calls, 1);
});

test('a call that fails: the requests that waited on it answer with its failure, and the next request asks again', async () => {
  const kept = askedOnce<string>();
  let calls = 0;
  const down = new Error('the vault is down');
  const failing = () => ((calls += 1), settles(30, null).then(() => Promise.reject(down)));
  const answers = await Promise.allSettled(Array.from({ length: 20 }, () => askOnce(kept, failing)));
  assert.ok(answers.every((answer) => answer.status === 'rejected' && answer.reason === down));
  assert.equal(calls, 1, 'one call: the others took its failure');
  assert.equal(await askOnce(kept, () => ((calls += 1), settles(5, 'up'))), 'up');
  assert.equal(calls, 2, 'a failure is kept only for the requests that waited on it');
});

test("a call that never settles holds the others back only so long: one takes the call over, and the rest take its answer (AGENTS.md, \"What an isolate keeps\")", async () => {
  const kept = askedOnce<string>();
  let calls = 0;
  // The first request's call never settles, as one whose request Workers cancelled.
  void askOnce(kept, () => ((calls += 1), new Promise<string>(() => {})), { takeOverMs: 100 });
  const started = Date.now();
  const answers = await Promise.race([
    Promise.all(Array.from({ length: 20 }, () => askOnce(kept, () => ((calls += 1), settles(10, 'settled')), { takeOverMs: 100 }))),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("still waiting after 2 s: on another call's pending work")), 2_000).unref()),
  ]);
  assert.deepEqual(new Set(answers), new Set(['settled']));
  assert.equal(calls, 2, 'one request took the call over; the others waited on it');
  const waited = Date.now() - started;
  assert.ok(waited >= 90 && waited < 1_000, `waited ${waited} ms`);
});

// Review r1 of T201: an outcome is its attempt's, given to the requests that joined that attempt, never told apart by
// the clock. Each of the next three answered otherwise when outcomes were kept by time (`failed.at >= began`).

test("a retry in the millisecond its predecessor failed: the retry's followers take the retry's answer, not that failure", async (t) => {
  t.mock.method(Date, 'now', () => 1_000);
  const kept = askedOnce<string>();
  const first = call<string>();
  const second = call<string>();
  const leader = askOnce(kept, () => first.promise);
  const follower = outcome(askOnce(kept, unasked));
  await pause(5);
  const down = new Error('the vault is down');
  first.reject(down);
  await assert.rejects(leader, (error) => error === down);
  // The same millisecond: the next request asks again, and another joins its call.
  const retry = askOnce(kept, () => second.promise);
  const retryFollower = askOnce(kept, unasked);
  await pause(30);
  assert.deepEqual(await follower, { error: down }, "the first call's follower takes its failure");
  second.resolve('up');
  assert.equal(await within(1_000, retryFollower), 'up');
  assert.equal(await retry, 'up');
});

test("a superseded call's late failure reaches no request that joined the call that took it over", async () => {
  const kept = askedOnce<string>();
  const stale = call<string>();
  const fresh = call<string>();
  // The first call hangs: its request is cancelled, as Workers does, and only fails long after.
  const cancelled = outcome(askOnce(kept, () => stale.promise));
  const taker = askOnce(kept, () => fresh.promise, { takeOverMs: 50 });
  await pause(100);
  assert.notEqual(kept.under, null);
  const joiner = askOnce(kept, unasked);
  await pause(5);
  const late = new Error('the cancelled call failed at last');
  stale.reject(late);
  assert.deepEqual(await cancelled, { error: late });
  await pause(30);
  fresh.resolve('up');
  assert.equal(await within(1_000, joiner), 'up', "the take-over's follower takes the take-over's answer");
  assert.equal(await taker, 'up');
});

test("a retry that succeeds before the failed call's followers wake: they take their own call's failure, and every request after the answer", async () => {
  const kept = askedOnce<string>();
  const first = call<string>();
  const leader = askOnce(kept, () => first.promise);
  const followers = Array.from({ length: 10 }, () => outcome(askOnce(kept, unasked)));
  await pause(30);
  const down = new Error('the vault is down');
  first.reject(down);
  await assert.rejects(leader, (error) => error === down);
  // The followers poll on timers: the retry starts and settles before any wakes.
  assert.equal(await askOnce(kept, () => Promise.resolve('up')), 'up');
  const answers = await within(1_000, Promise.all(followers));
  assert.ok(
    answers.every((answer) => 'error' in answer && answer.error === down),
    `each follower takes the outcome of the call it joined: ${JSON.stringify(answers.map((answer) => ('value' in answer ? answer.value : 'failed')))}`,
  );
  assert.equal(await askOnce(kept, unasked), 'up');
});

/** Mocked time (timers and the clock) moved on `ms` in steps of `step`, each step's settled work run before the next. */
type Clock = { tick: (ms: number) => void };
async function advance(clock: Clock, ms: number, step = 1) {
  for (let moved = 0; moved < ms; moved += step) {
    clock.tick(step);
    await new Promise((resolve) => setImmediate(resolve));
  }
}
/**
 * The polls' jitter held at its middle, so mocked time alone says when each poll comes (1, 3, 7, 15, 31 ms, then every
 * 20 ms); past `budget` jitters drawn, a poll throws, so a request that loops without waiting fails rather than hangs
 * the event loop (review r3 of T201).
 */
function steadyJitter(t: { mock: { method: (object: object, name: string, impl: () => number) => unknown } }, budget = 10_000) {
  const drawn = { count: 0 };
  t.mock.method(Math, 'random', () => {
    drawn.count += 1;
    if (drawn.count > budget) throw new Error(`${drawn.count} polls: a request polls without waiting`);
    return 0.5;
  });
  return drawn;
}
/** `answer`, and whether it has settled yet. */
function watched<T>(answer: Promise<T>) {
  const seen = { settled: null as { value: T } | { error: unknown } | null };
  void answer.then((value) => (seen.settled = { value }), (error: unknown) => (seen.settled = { error }));
  return seen;
}
/** Settled with asked-once's refusal: 503 `starting`, Retry-After 1. */
function refusedStarting(seen: { settled: { value: unknown } | { error: unknown } | null }) {
  const error = seen.settled !== null && 'error' in seen.settled ? seen.settled.error : null;
  assert.ok(error instanceof ApiError, `refused: ${JSON.stringify(seen.settled)}`);
  assert.deepEqual([error.status, error.reason, error.retryAfter], [503, 'starting', '1']);
}

test('a request waits WAIT_MS in all, however many calls are taken over meanwhile: then 503, Retry-After 1, and it never makes the call', async (t) => {
  // Mocked time, moved a millisecond at a time: each take-over comes before the waiting request's poll would see its
  // call 100 ms old, however slow the machine (review r2 of T201).
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 0 });
  const kept = askedOnce<string>();
  const never = () => new Promise<string>(() => {});
  void askOnce(kept, never);
  // Other requests keep taking the call over, each just before this one would, each cancelled in turn: every 15 ms one
  // joins and takes over within 5 ms of its call's start, so no call this request joins reaches its 100 ms.
  const takers = setInterval(() => void askOnce(kept, never, { takeOverMs: 5, waitMs: 2_000 }).catch(() => {}), 15);
  try {
    let asked = false;
    const waiting = watched(askOnce(kept, () => ((asked = true), Promise.resolve('mine')), { takeOverMs: 100, waitMs: 300 }));
    await advance(t.mock.timers, 299);
    assert.equal(waiting.settled, null, 'within its 300 ms it waits');
    await advance(t.mock.timers, 2);
    refusedStarting(waiting);
    assert.equal(asked, false, 'every call it joined was taken over before it would');
  } finally {
    clearInterval(takers);
  }
});

test("a request that took a call over keeps its deadline: its own call hanging, it answers 503 at WAIT_MS all the same (review r2 of T201)", async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const kept = askedOnce<string>();
  const never = () => new Promise<string>(() => {});
  void askOnce(kept, never);
  let asked = 0;
  const waiting = watched(askOnce(kept, () => ((asked += 1), new Promise<string>(() => {})), { takeOverMs: 100, waitMs: 300 }));
  await advance(t.mock.timers, 150);
  assert.equal(asked, 1, 'it took the call over at 100 ms');
  await advance(t.mock.timers, 149);
  assert.equal(waiting.settled, null);
  await advance(t.mock.timers, 2);
  refusedStarting(waiting);
  assert.equal(asked, 1, 'it made one call: its own, never taken over by itself');
});

test("a request that took a call over takes another's answer meanwhile: its own call hanging, another request's take-over answers it", async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const kept = askedOnce<string>();
  void askOnce(kept, () => new Promise<string>(() => {}));
  const waiting = watched(askOnce(kept, () => new Promise<string>(() => {}), { takeOverMs: 100, waitMs: 300 }));
  await advance(t.mock.timers, 150);
  // Its call (since 100 ms) hangs; another request, trusting a call only 20 ms, takes it over, its call answering 10 ms
  // later.
  const other = watched(askOnce(kept, () => settles(10, 'up'), { takeOverMs: 20, waitMs: 300 }));
  await advance(t.mock.timers, 60);
  assert.deepEqual(other.settled, { value: 'up' });
  assert.deepEqual(waiting.settled, { value: 'up' }, 'it took the answer its take-over never gave');
});

test("a request that took a call over answers as soon as its own call does, not on its next poll", async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  steadyJitter(t);
  const kept = askedOnce<string>();
  void askOnce(kept, () => new Promise<string>(() => {}));
  const mine = call<string>();
  let asked = false;
  const waiting = watched(askOnce(kept, () => ((asked = true), mine.promise), { takeOverMs: 100, waitMs: 300 }));
  // Its poll at 111 ms finds the call 100 ms old and takes it over (review r3 of T201: the jitter drawn, it might not
  // have by 120 ms).
  await advance(t.mock.timers, 120);
  assert.equal(asked, true, 'it took the call over');
  assert.equal(waiting.settled, null);
  mine.resolve('mine');
  // No time passes: its own call settled, it answers.
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(waiting.settled, { value: 'mine' });
});

test("a request whose own call fails after it joined a newer attempt waits on that one, polling on its timers: its call's settling wakes it once (review r3 of T201)", async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const drawn = steadyJitter(t);
  const kept = askedOnce<string>();
  void askOnce(kept, () => new Promise<string>(() => {}));
  const mine = call<string>();
  let asked = 0;
  const ask = () => ((asked += 1), asked === 1 ? mine.promise : new Promise<string>(() => {}));
  // It polls at 1, 3, 7, ... 91, 111 ms, and takes the first call over at 111 ms.
  const waiting = watched(askOnce(kept, ask, { takeOverMs: 100, waitMs: 300 }));
  await advance(t.mock.timers, 120);
  assert.equal(asked, 1, 'it took the first call over');
  // Another request, trusting a call 20 ms, takes its call over at 135 ms; it joins that one on its poll at 151 ms.
  let taken = false;
  void askOnce(kept, () => ((taken = true), new Promise<string>(() => {})), { takeOverMs: 20, waitMs: 1_000 }).catch(() => {});
  await advance(t.mock.timers, 50);
  assert.equal(taken, true, 'its call was taken over');
  // Its own call fails now: not the outcome of the attempt it waits on.
  mine.reject(new Error('its own call, superseded'));
  const before = drawn.count;
  await advance(t.mock.timers, 60);
  assert.equal(waiting.settled, null, 'it waits on the attempt it joined');
  assert.ok(drawn.count - before <= 10, `it polled ${drawn.count - before} times in 60 ms: about one every 20 ms for each request`);
  // At 235 ms, the newer call 100 ms old, it takes that one over too, a call of its own that hangs; at 300 ms, 503.
  await advance(t.mock.timers, 300 - 230 + 1);
  refusedStarting(waiting);
  assert.equal(asked, 2, 'its second call: the newer attempt taken over, never its own failure taken for an answer');
});

test("the gate's reservation, waiting its deadline on the vault's about() another request asks: 503 `starting`, as asked-once answers it, not the gate's own reason (review r2 of T201)", async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  let asked = 0;
  let reserved = 0;
  // A vault whose about() never answers: its request cancelled, as Workers does, and each take-over's in turn.
  const vault = {
    about: () => ((asked += 1), new Promise(() => {})),
    reserveProxy: async () => ((reserved += 1), { ok: true, cleared: [] }),
  } as unknown as Vault;
  // Another route's request asks about() first; the gate's then joins its call.
  void keeps015(vault).catch(() => {});
  const gate = watched(gateProxy(vault, { names: ['maps'] } as unknown as ProxyCode));
  await advance(t.mock.timers, WAIT_MS - 10, 10);
  assert.equal(gate.settled, null);
  await advance(t.mock.timers, 20, 10);
  refusedStarting(gate);
  assert.deepEqual([asked, reserved], [2, 0], 'the first call, then its take-over; nothing reserved');
});

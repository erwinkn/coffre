// A value an isolate asks for once (asked-once.ts, T201): its concurrent first requests make one call and take its
// answer, or its failure; no request ever waits on another's pending call, so a call that never settles (its request
// cancelled, on Workers) holds the others back only until one of them takes the call over.
import test from 'node:test';
import assert from 'node:assert/strict';

import { askedOnce, askOnce } from '../src/asked-once.ts';

const settles = <T>(ms: number, value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));

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
  void askOnce(kept, () => ((calls += 1), new Promise<string>(() => {})), 100);
  const started = Date.now();
  const answers = await Promise.race([
    Promise.all(Array.from({ length: 20 }, () => askOnce(kept, () => ((calls += 1), settles(10, 'settled')), 100))),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("still waiting after 2 s: on another call's pending work")), 2_000).unref()),
  ]);
  assert.deepEqual(new Set(answers), new Set(['settled']));
  assert.equal(calls, 2, 'one request took the call over; the others waited on it');
  const waited = Date.now() - started;
  assert.ok(waited >= 90 && waited < 1_000, `waited ${waited} ms`);
});

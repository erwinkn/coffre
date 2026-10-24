// The workload gate (docs/design/workload-access.md, section 5.2), through
// PR 0's `Gate` and the state behind it: a proof is taken once, across a
// restart too; a stale nonce is answered with the current one, under which
// the proof then passes; past the ceiling, `overloaded`; past a limit, a
// refusal whose first says so. And the Durable Object around the same
// state, with a storage in memory: its counts over a day outlive an
// eviction, its epochs never do.
import test from 'node:test';
import assert from 'node:assert/strict';

import type { Gate } from '@coffre/core/identity';

import { CoffreGates, workersGates, type GatesNamespace } from '../src/cloudflare-gates.ts';
import { DURABLE_WINDOW_MS, EPOCH_MS, FLUSH_MS, GATE_CEILING, GateState, processGates, SKEW_MS } from '../src/gate.ts';

const T0 = 1_792_805_400_000;
const SESSION = '0e7a4c1e-5b0c-4f53-9f43-8f5f1c2b9a10';
const jti = (n: number) => `jti-${String(n).padStart(18, '0')}`;
const proof = (n: number, nonce: string) => ({ replay: { session: SESSION, jti: jti(n), nonce } });

test('a proof is taken once: the same jti again is replayed, its signature twin included', () => {
  const gate = new GateState(T0);
  const nonce = gate.nonce(T0);
  assert.deepEqual(gate.admit(proof(1, nonce), T0), { ok: true, nonce });
  assert.deepEqual(gate.admit(proof(1, nonce), T0 + 1), { ok: false, reason: 'replayed' });
  assert.deepEqual(gate.admit(proof(2, nonce), T0 + 2), { ok: true, nonce });
});

test('a gate that restarts has a new epoch: a proof it took before is refused for its nonce, never taken again', () => {
  const before = new GateState(T0);
  const nonce = before.nonce(T0);
  assert.equal(before.admit(proof(1, nonce), T0).ok, true);
  const after = new GateState(T0 + 5);
  const fresh = after.nonce(T0 + 5);
  assert.notEqual(fresh, nonce);
  assert.deepEqual(after.admit(proof(1, nonce), T0 + 6), { ok: false, reason: 'use_dpop_nonce', nonce: fresh });
});

test('use_dpop_nonce carries the current nonce, under which the same request then passes', () => {
  const gate = new GateState(T0);
  const answer = gate.admit(proof(1, 'g0.not-this-gates'), T0);
  assert.equal(answer.ok, false);
  assert.ok(!answer.ok && answer.reason === 'use_dpop_nonce');
  assert.deepEqual(gate.admit(proof(2, answer.nonce), T0 + 1), { ok: true, nonce: answer.nonce });
});

test('a nonce is taken for its epoch and the next, and refused from the one after, however few requests came', () => {
  const gate = new GateState(T0);
  const first = gate.nonce(T0);
  assert.match(first, /^g0\.[A-Za-z0-9_-]{22}$/);
  const second = gate.nonce(T0 + EPOCH_MS);
  assert.match(second, /^g1\./);
  assert.notEqual(second, first);
  assert.deepEqual(gate.admit(proof(1, first), T0 + EPOCH_MS + 1), { ok: true, nonce: second });
  assert.deepEqual(gate.admit(proof(1, first), T0 + EPOCH_MS + 2), { ok: false, reason: 'replayed' });
  const third = gate.nonce(T0 + 2 * EPOCH_MS);
  assert.deepEqual(gate.admit(proof(2, first), T0 + 2 * EPOCH_MS), { ok: false, reason: 'use_dpop_nonce', nonce: third });
  assert.equal(gate.admit(proof(3, second), T0 + 2 * EPOCH_MS).ok, true);
  // Idle for two epochs: both nonces it had are gone at once.
  const later = T0 + 4 * EPOCH_MS + 10;
  assert.deepEqual(gate.admit(proof(4, third), later), { ok: false, reason: 'use_dpop_nonce', nonce: gate.nonce(later) });
  assert.match(gate.nonce(later), /^g4\./);
});

test('a clock stepped back a little keeps the epoch; further, the gate starts over: nothing is taken twice either way', () => {
  const gate = new GateState(T0);
  const nonce = gate.nonce(T0 + EPOCH_MS);
  assert.equal(gate.admit(proof(1, nonce), T0 + EPOCH_MS).ok, true);
  assert.equal(gate.nonce(T0 + EPOCH_MS - SKEW_MS), nonce);
  assert.deepEqual(gate.admit(proof(1, nonce), T0 + EPOCH_MS - SKEW_MS), { ok: false, reason: 'replayed' });
  const fresh = gate.nonce(T0);
  assert.notEqual(fresh, nonce);
  assert.deepEqual(gate.admit(proof(1, nonce), T0), { ok: false, reason: 'use_dpop_nonce', nonce: fresh });
});

test('a clock that jumped a day ahead and came back holds the gate there for no longer than a nonce retry', () => {
  const second = T0 - (T0 % 1000);
  const gate = new GateState(second);
  const minute = [{ key: 'stripe', windowMs: 60_000, most: 120 }];
  assert.equal(gate.admit({ counts: minute }, second + 86_400_000).ok, true);
  // Back to the real time: two requests a second for an hour pass as they would have.
  for (let n = 0; n < 7200; n++) {
    const answer = gate.admit({ counts: minute }, second + 1 + n * 500);
    assert.ok(answer.ok, `${n}: ${JSON.stringify(answer)}`);
  }
});

test('a jti taken under the previous nonce is refused under the current one too, while the gate remembers it', () => {
  const gate = new GateState(T0);
  const first = gate.nonce(T0);
  assert.equal(gate.admit(proof(1, first), T0).ok, true);
  const second = gate.nonce(T0 + EPOCH_MS);
  assert.deepEqual(gate.admit(proof(1, second), T0 + EPOCH_MS), { ok: false, reason: 'replayed' });
  // And the other way: taken under the current nonce, refused under the previous one.
  assert.equal(gate.admit(proof(2, second), T0 + EPOCH_MS).ok, true);
  assert.deepEqual(gate.admit(proof(2, first), T0 + EPOCH_MS), { ok: false, reason: 'replayed' });
});

test("a clock stepped back across a window's start counts in the window it had: a day's limit is not given again", () => {
  const midnight = Math.ceil(T0 / 86_400_000) * 86_400_000;
  const gate = new GateState(midnight - 10);
  const perDay = [{ key: 'stripe', windowMs: 86_400_000, most: 1 }];
  assert.equal(gate.admit({ counts: perDay }, midnight + 5).ok, true);
  assert.equal(gate.admit({ counts: perDay }, midnight - 1).ok, false);
  assert.deepEqual(gate.admit({ counts: perDay }, midnight + 7), { ok: false, reason: 'limit', key: 'stripe', retryAfterMs: 86_400_000 - 7, first: false });
});

test('a request that names a count twice is an error, before it spends anything', () => {
  const gate = new GateState(T0);
  const nonce = gate.nonce(T0);
  const twice = [{ key: 'stripe', windowMs: 60_000, most: 2 }, { key: 'stripe', windowMs: 60_000, most: 2 }];
  assert.throws(() => gate.admit({ ...proof(1, nonce), counts: twice }, T0), /names a count twice: 60000:stripe, 60000:stripe/);
  assert.equal(gate.admit({ ...proof(1, nonce), counts: [twice[0]!] }, T0).ok, true);
});

test('past several counts, the one whose window ends last says when to retry', () => {
  const gate = new GateState(T0);
  const day = Math.floor(T0 / 86_400_000) * 86_400_000;
  const counts = [{ key: 'per-minute', windowMs: 60_000, most: 0 }, { key: 'per-day', windowMs: 86_400_000, most: 0 }];
  assert.deepEqual(gate.admit({ counts }, T0), { ok: false, reason: 'limit', key: 'per-day', retryAfterMs: day + 86_400_000 - T0, first: true });
});

test('a count asked again after a clock came back from far ahead counts in the real window, and what it writes says so', () => {
  const hour = Math.ceil(T0 / 3_600_000) * 3_600_000;
  const gate = new GateState(hour - 60_000, { durable: true });
  const perHour = [{ key: 'stripe', windowMs: 3_600_000, most: 1 }];
  // At 13:00 for one request, then back at 12:59.
  assert.equal(gate.admit({ counts: perHour }, hour + 5000).ok, true);
  const stored = new Map(gate.flush());
  assert.equal(gate.admit({ counts: perHour }, hour - 59_000).ok, true);
  for (const [id, held] of gate.flush()) stored.set(id, held);
  // Evicted, and made again at the real 13:00: 12:00's window has ended, and 13:00's counts from zero, as in memory.
  const again = new GateState(hour + 1, { durable: true });
  again.restore(stored);
  assert.equal(again.admit({ counts: perHour }, hour + 1).ok, true);
  assert.equal(gate.admit({ counts: perHour }, hour + 1).ok, true);
});

test('a window a count starts again in is written even when another count refuses the request: an eviction brings back what memory holds', () => {
  const hour = Math.ceil(T0 / 3_600_000) * 3_600_000;
  const gate = new GateState(hour - 60_000, { durable: true });
  const perHour = { key: 'stripe', windowMs: 3_600_000, most: 1 };
  const closed = { key: 'openai', windowMs: 3_600_000, most: 0 };
  assert.equal(gate.admit({ counts: [perHour] }, hour + 5000).ok, true);
  const stored = new Map(gate.flush());
  // Back at 12:59: refused by the other count, the first starts again in 12:00's window all the same.
  assert.equal(gate.admit({ counts: [perHour, closed] }, hour - 59_000).ok, false);
  for (const [id, held] of gate.flush()) stored.set(id, held);
  const again = new GateState(hour + 1, { durable: true });
  again.restore(stored);
  assert.equal(gate.admit({ counts: [perHour] }, hour + 1).ok, true);
  assert.equal(again.admit({ counts: [perHour] }, hour + 1).ok, true);
});

test("counts read back by an object whose clock is a little behind the window they were written in count on in it", () => {
  const day = Math.ceil(T0 / 86_400_000) * 86_400_000;
  const perDay = [{ key: 'stripe', windowMs: 86_400_000, most: 2 }];
  const before = new GateState(day - 1000, { durable: true });
  assert.equal(before.admit({ counts: perDay }, day + 300).ok, true);
  assert.equal(before.admit({ counts: perDay }, day + 301).ok, true);
  const written = before.flush();
  const after = new GateState(day - 100, { durable: true });
  after.restore(written);
  assert.deepEqual(after.admit({ counts: perDay }, day - 50), { ok: false, reason: 'limit', key: 'stripe', retryAfterMs: 86_400_050, first: true });
  assert.equal(after.admit({ counts: perDay }, day + 1000).ok, false);
  // Written by a clock far ahead: more than a skew away, so the count starts again in its own window.
  const far = new GateState(day - 3_600_000, { durable: true });
  far.restore(written);
  assert.equal(far.admit({ counts: perDay }, day - 3_600_000).ok, true);
});

test("a Node process's gate keeps no count for a write: only a Durable Object writes them", () => {
  const counts = [{ key: 'stripe', windowMs: 86_400_000, most: 5 }];
  const node = new GateState(T0);
  node.admit({ counts }, T0);
  assert.equal(node.dirty, false);
  assert.deepEqual(node.flush(), []);
  const object = new GateState(T0, { durable: true });
  object.admit({ counts }, T0);
  assert.equal(object.dirty, true);
  assert.deepEqual(object.flush(), [['86400000:stripe', { start: Math.floor(T0 / 86_400_000) * 86_400_000, taken: 1, refused: false }]]);
});

test(`past ${GATE_CEILING} requests in a second, overloaded; the next second takes them again`, () => {
  const start = T0 - (T0 % 1000);
  const gate = new GateState(start);
  const nonce = gate.nonce(start);
  for (let n = 0; n < GATE_CEILING; n++) assert.equal(gate.admit(proof(n, nonce), start + (n % 1000)).ok, true);
  assert.deepEqual(gate.admit(proof(GATE_CEILING, nonce), start + 999), { ok: false, reason: 'overloaded' });
  assert.deepEqual(gate.admit({}, start + 999), { ok: false, reason: 'overloaded' });
  // The overloaded proof was never looked at: the next second takes it.
  assert.equal(gate.admit(proof(GATE_CEILING, nonce), start + 1000).ok, true);
});

test('past a limit, refused with when to retry; first only for the first refusal in its window; refusals count nothing', () => {
  const gate = new GateState(T0);
  const minute = Math.floor(T0 / 60_000) * 60_000;
  const counts = [{ key: 'stripe', windowMs: 60_000, most: 2 }];
  assert.equal(gate.admit({ counts }, minute).ok, true);
  assert.equal(gate.admit({ counts }, minute + 1).ok, true);
  assert.deepEqual(gate.admit({ counts }, minute + 10_000), { ok: false, reason: 'limit', key: 'stripe', retryAfterMs: 50_000, first: true });
  assert.deepEqual(gate.admit({ counts }, minute + 20_000), { ok: false, reason: 'limit', key: 'stripe', retryAfterMs: 40_000, first: false });
  // The next window starts over, its first refusal first again.
  assert.equal(gate.admit({ counts }, minute + 60_000).ok, true);
  assert.equal(gate.admit({ counts }, minute + 60_001).ok, true);
  assert.equal((gate.admit({ counts }, minute + 60_002) as { first: boolean }).first, true);
});

test('a request past one of its counts counts in none, and its proof is spent all the same', () => {
  const gate = new GateState(T0);
  const nonce = gate.nonce(T0);
  const day = Math.floor(T0 / 86_400_000) * 86_400_000;
  const minute = { key: 'stripe', windowMs: 60_000, most: 5 };
  const perDay = { key: 'stripe', windowMs: 86_400_000, most: 1 };
  assert.equal(gate.admit({ ...proof(1, nonce), counts: [minute, perDay] }, T0).ok, true);
  assert.deepEqual(gate.admit({ ...proof(2, nonce), counts: [minute, perDay] }, T0), { ok: false, reason: 'limit', key: 'stripe', retryAfterMs: day + 86_400_000 - T0, first: true });
  assert.deepEqual(gate.admit(proof(2, nonce), T0), { ok: false, reason: 'replayed' });
  // The minute counted one request, not two: four more pass.
  for (let n = 0; n < 4; n++) assert.equal(gate.admit({ counts: [minute] }, T0).ok, true);
  assert.equal(gate.admit({ counts: [minute] }, T0).ok, false);
});

test("a Node process holds one gate per workload: one workload's nonce is not another's", async () => {
  const gates = processGates();
  const api: Gate = gates('token:api');
  const batch: Gate = gates('token:batch');
  const nonce = await api.nonce();
  assert.equal(await gates('token:api').nonce(), nonce);
  assert.notEqual(await batch.nonce(), nonce);
  assert.equal((await api.admit(proof(1, nonce))).ok, true);
  assert.deepEqual(await gates('token:api').admit(proof(1, nonce)), { ok: false, reason: 'replayed' });
  assert.equal((await batch.admit(proof(1, nonce))).ok, false);
});

/** A Durable Object's storage, in memory, and its alarm, run by hand. */
function objectState(stored = new Map<string, unknown>()) {
  let alarm: number | null = null;
  const starting: Promise<unknown>[] = [];
  /** The storage operations that fail next, once each. */
  const failing = new Set<'put' | 'setAlarm'>();
  const fail = (operation: 'put' | 'setAlarm') => {
    if (failing.delete(operation)) throw new Error(`${operation} failed`);
  };
  const state = {
    storage: {
      list: async <T>({ prefix }: { prefix: string }) => new Map([...stored].filter(([key]) => key.startsWith(prefix)) as [string, T][]),
      put: async <T>(entries: Record<string, T>) => {
        fail('put');
        for (const [key, value] of Object.entries(entries)) stored.set(key, structuredClone(value));
      },
      setAlarm: async (time: number) => {
        fail('setAlarm');
        alarm = time;
      },
    },
    blockConcurrencyWhile: <T>(callback: () => Promise<T>) => {
      const done = callback();
      starting.push(done);
      return done;
    },
  };
  return { state, stored, failing, alarm: () => alarm, started: () => Promise.all(starting) };
}

/** The namespace a Worker binds: an object per name, made by its first call, and again by the first after an eviction, as Cloudflare does. */
function namespace(make: () => CoffreGates) {
  const objects = new Map<string, CoffreGates>();
  const gates: GatesNamespace = {
    idFromName: (name) => name,
    get: (id) => ({
      fetch: (request) => {
        const name = id as string;
        if (!objects.has(name)) objects.set(name, make());
        return objects.get(name)!.fetch(request);
      },
    }),
  };
  return { gates, objects };
}

test("on Workers, each workload's object: a replayed proof refused, and after an eviction its nonce", async () => {
  const held = objectState();
  const { gates, objects } = namespace(() => new CoffreGates(held.state, {}));
  const gate = workersGates(gates)('token:api');
  assert.equal(objects.size, 0);
  const nonce = await gate.nonce();
  assert.deepEqual([...objects.keys()], ['gate:token:api']);
  assert.deepEqual(await gate.admit(proof(1, nonce)), { ok: true, nonce });
  assert.deepEqual(await gate.admit(proof(1, nonce)), { ok: false, reason: 'replayed' });
  objects.clear();
  const answer = await gate.admit(proof(1, nonce));
  assert.ok(!answer.ok && answer.reason === 'use_dpop_nonce' && answer.nonce !== nonce);
});

test("on Workers, a day's counts are written within a flush and read back after an eviction; a minute's are not", async () => {
  const held = objectState();
  const first = new CoffreGates(held.state, {});
  await held.started();
  const { gates } = namespace(() => first);
  const gate = workersGates(gates)('token:api');
  const perDay = { key: 'stripe', windowMs: DURABLE_WINDOW_MS * 24, most: 2 };
  const perMinute = { key: 'stripe', windowMs: 60_000, most: 1 };
  const before = Date.now();
  assert.equal((await gate.admit({ counts: [perDay, perMinute] })).ok, true);
  const alarm = held.alarm();
  assert.ok(alarm !== null && alarm >= before + FLUSH_MS && alarm <= Date.now() + FLUSH_MS, 'no flush was scheduled');
  await first.alarm();
  assert.deepEqual([...held.stored.keys()], [`count:${perDay.windowMs}:stripe`]);

  const evicted = objectState(held.stored);
  const second = new CoffreGates(evicted.state, {});
  await evicted.started();
  const again = workersGates(namespace(() => second).gates)('token:api');
  // The minute starts over; the day has one request left.
  assert.equal((await again.admit({ counts: [perDay, perMinute] })).ok, true);
  const refused = await again.admit({ counts: [perDay] });
  assert.ok(!refused.ok && refused.reason === 'limit' && refused.first);
  await second.alarm();
  assert.equal((held.stored.get(`count:${perDay.windowMs}:stripe`) as { refused: boolean }).refused, true);
});

test('on Workers, a write that fails is written by the retried alarm, and an alarm that could not be set is set by the next request', async () => {
  const held = objectState();
  const object = new CoffreGates(held.state, {});
  await held.started();
  const gate = workersGates(namespace(() => object).gates)('token:api');
  const perDay = { key: 'stripe', windowMs: 86_400_000, most: 5 };
  held.failing.add('setAlarm');
  await assert.rejects(gate.admit({ counts: [perDay] }), /the workload gate failed|setAlarm failed/);
  assert.equal(held.alarm(), null);
  assert.equal((await gate.admit({ counts: [perDay] })).ok, true);
  assert.notEqual(held.alarm(), null, 'no request set the alarm again');
  held.failing.add('put');
  await assert.rejects(object.alarm(), /put failed/);
  assert.equal(held.stored.size, 0);
  await object.alarm();
  assert.equal((held.stored.get('count:86400000:stripe') as { taken: number }).taken, 2);
});

test('on Workers, an alarm set by a clock that has since stepped back is brought forward', async (t) => {
  const real = Date.now;
  t.after(() => {
    Date.now = real;
  });
  const now = real();
  const held = objectState();
  const object = new CoffreGates(held.state, {});
  await held.started();
  const gate = workersGates(namespace(() => object).gates)('token:api');
  const perDay = { key: 'stripe', windowMs: 86_400_000, most: 5 };
  Date.now = () => now + 86_400_000;
  await gate.admit({ counts: [perDay] });
  assert.equal(held.alarm(), now + 86_400_000 + FLUSH_MS);
  Date.now = () => now;
  await gate.admit({ counts: [perDay] });
  assert.equal(held.alarm(), now + FLUSH_MS);
  // Within a flush of the last, no new alarm.
  Date.now = () => now + 1;
  await gate.admit({ counts: [perDay] });
  assert.equal(held.alarm(), now + FLUSH_MS);
});

test('a gate that fails is an error, never an answer', async () => {
  const broken: GatesNamespace = { idFromName: (name) => name, get: () => ({ fetch: async () => new Response('exceeded its memory', { status: 500 }) }) };
  await assert.rejects(workersGates(broken)('token:api').admit(proof(1, 'g0.x')), /the workload gate failed: 500/);
});

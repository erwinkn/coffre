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
import { DURABLE_WINDOW_MS, EPOCH_MS, FLUSH_MS, GATE_CEILING, GateState, processGates } from '../src/gate.ts';

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

test('a clock that goes back keeps the epoch: nothing is taken twice', () => {
  const gate = new GateState(T0);
  const nonce = gate.nonce(T0 + EPOCH_MS);
  assert.equal(gate.admit(proof(1, nonce), T0 + EPOCH_MS).ok, true);
  assert.equal(gate.nonce(T0), nonce);
  assert.deepEqual(gate.admit(proof(1, nonce), T0), { ok: false, reason: 'replayed' });
});

test(`past ${GATE_CEILING} requests in a second, overloaded; the next second takes them again`, () => {
  const gate = new GateState(T0 - (T0 % 1000));
  const start = T0 - (T0 % 1000);
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
  const state = {
    storage: {
      list: async <T>({ prefix }: { prefix: string }) => new Map([...stored].filter(([key]) => key.startsWith(prefix)) as [string, T][]),
      put: async <T>(entries: Record<string, T>) => {
        for (const [key, value] of Object.entries(entries)) stored.set(key, structuredClone(value));
      },
      setAlarm: async (time: number) => {
        alarm = time;
      },
    },
    blockConcurrencyWhile: <T>(callback: () => Promise<T>) => {
      const done = callback();
      starting.push(done);
      return done;
    },
  };
  return { state, stored, alarm: () => alarm, started: () => Promise.all(starting) };
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

test('a gate that fails is an error, never an answer', async () => {
  const broken: GatesNamespace = { idFromName: (name) => name, get: () => ({ fetch: async () => new Response('exceeded its memory', { status: 500 }) }) };
  await assert.rejects(workersGates(broken)('token:api').admit(proof(1, 'g0.x')), /the workload gate failed: 500/);
});

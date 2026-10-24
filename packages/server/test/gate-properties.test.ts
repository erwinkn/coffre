import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { DURABLE_WINDOW_MS, EPOCH_MS, GateState } from '../src/gate.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';

// The gate of docs/design/workload-access.md (section 5.2, PR 1b), against
// a reference written from the design rather than from the code: random
// sequences of requests, waits and restarts, and every answer must be the
// reference's. The reference keeps every proof ever taken, across restarts,
// so a gate that took one twice disagrees with it.

const T0 = 1_792_805_400_000;
/** Small, so that sequences reach it. */
const CEILING = 4;
const WINDOWS = [1000, 60_000, DURABLE_WINDOW_MS] as const;

type Count = { key: 'stripe' | 'openai'; windowMs: number; most: number };
type Operation =
  /** A clock's step, back too. */
  | { kind: 'wait'; ms: number }
  | { kind: 'restart' }
  | { kind: 'nonce' }
  /** `nonce`: which nonce seen so far the proof carries, counting back from the newest; past them all, one no gate gave. */
  | { kind: 'admit'; jti: number | null; nonce: number; counts: Count[] };

const count = gs.record({ key: gs.sampledFrom(['stripe', 'openai'] as const), windowMs: gs.sampledFrom(WINDOWS), most: gs.integers({ minValue: 0, maxValue: 3 }) });
const admit = gs.record({
  kind: gs.just('admit' as const),
  jti: gs.oneOf(gs.integers({ minValue: 0, maxValue: 1 }), gs.integers({ minValue: 0, maxValue: 1 }), gs.just(null)),
  nonce: gs.oneOf(gs.just(0), gs.integers({ minValue: 0, maxValue: 3 })),
  counts: gs.arrays(count, { maxSize: 3 }),
});
// Requests most often, so that sequences replay proofs and fill windows; time mostly in small steps, now and then back.
const operation = gs.oneOf<Operation>(
  admit,
  admit,
  admit,
  admit,
  gs.record({
    kind: gs.just('wait' as const),
    ms: gs.oneOf(gs.sampledFrom([0, 1, 999, 1000, EPOCH_MS - 1, EPOCH_MS, 2 * EPOCH_MS, -1, -1000]), gs.integers({ minValue: -2000, maxValue: 3 * EPOCH_MS })),
  }),
  gs.record({ kind: gs.just('wait' as const), ms: gs.sampledFrom([EPOCH_MS, 2 * EPOCH_MS]) }),
  gs.record({ kind: gs.just('nonce' as const) }),
  gs.record({ kind: gs.just('restart' as const) }),
);

type Answer = { ok: true } | { ok: false; reason: string; key?: string; retryAfterMs?: number; first?: boolean } | 'throws';

/** The reference: what the design says each answer is. */
class Reference {
  /** The clock the gate is given, which may go back; and the time it runs at, the latest it was given, which never does. */
  clock = T0;
  now = T0;
  life = 0;
  started = T0;
  /** Each nonce a gate gave, with the life and epoch it named. */
  readonly nonces: { nonce: string; life: number; epoch: number }[] = [];
  /** Every proof taken, with the life and epoch of its nonce. */
  readonly taken: { life: number; epoch: number; jti: number; nonce: string }[] = [];
  second = -1;
  inSecond = 0;
  /** This life's counted requests and refusals, by count: their times. */
  counted = new Map<string, number[]>();
  refused = new Map<string, number[]>();

  step(ms: number) {
    this.clock += ms;
  }

  /** A call: the gate is given the clock. */
  called() {
    this.now = Math.max(this.now, this.clock);
  }

  epoch() {
    return Math.floor((this.now - this.started) / EPOCH_MS);
  }

  /** The gate's current nonce, as it said it: the same for one epoch of one life, and never one it gave before. */
  current(nonce: string) {
    const known = this.nonces.find((seen) => seen.life === this.life && seen.epoch === this.epoch());
    if (known !== undefined) {
      assert.equal(nonce, known.nonce, 'the nonce changed within an epoch');
      return;
    }
    assert.ok(!this.nonces.some((seen) => seen.nonce === nonce), 'a nonce came back from another epoch or life');
    this.nonces.push({ nonce, life: this.life, epoch: this.epoch() });
  }

  restart() {
    this.life += 1;
    this.started = this.clock;
    this.now = this.clock;
    this.second = -1;
    this.counted = new Map();
    this.refused = new Map();
  }

  /** The answer the design gives, its nonce left to `current`. */
  admit(jti: number | null, nonce: string, counts: Count[]): Answer {
    const ids = counts.map((count) => `${count.key}/${count.windowMs}`);
    if (new Set(ids).size !== ids.length) return 'throws';
    this.called();
    const second = Math.floor(this.now / 1000);
    if (second !== this.second) {
      this.second = second;
      this.inSecond = 0;
    }
    if (this.inSecond >= CEILING) return { ok: false, reason: 'overloaded' };
    this.inSecond += 1;
    if (jti !== null) {
      const named = this.nonces.find((seen) => seen.nonce === nonce);
      const live = (epoch: number) => this.epoch() - epoch <= 1;
      if (named === undefined || named.life !== this.life || !live(named.epoch)) return { ok: false, reason: 'use_dpop_nonce' };
      // A jti is spent for as long as the gate remembers it, under either live nonce.
      if (this.taken.some((proof) => proof.life === this.life && proof.jti === jti && live(proof.epoch))) return { ok: false, reason: 'replayed' };
      assert.ok(!this.taken.some((proof) => proof.nonce === nonce && proof.jti === jti), 'a proof was taken twice');
      this.taken.push({ life: this.life, epoch: named.epoch, jti, nonce });
    }
    let past: { id: string; count: Count; start: number } | undefined;
    for (const [i, count] of counts.entries()) {
      const start = Math.floor(this.now / count.windowMs) * count.windowMs;
      const inWindow = (this.counted.get(ids[i]!) ?? []).filter((time) => time >= start).length;
      if (inWindow >= count.most && (past === undefined || start + count.windowMs > past.start + past.count.windowMs)) past = { id: ids[i]!, count, start };
    }
    if (past !== undefined) {
      const first = (this.refused.get(past.id) ?? []).every((time) => time < past.start);
      this.refused.set(past.id, [...(this.refused.get(past.id) ?? []), this.now]);
      return { ok: false, reason: 'limit', key: past.count.key, retryAfterMs: past.start + past.count.windowMs - this.now, first };
    }
    for (const id of ids) this.counted.set(id, [...(this.counted.get(id) ?? []), this.now]);
    return { ok: true };
  }
}

const settings = propertySettings(500);

test(`the gate answers as the reference over any requests, clock steps and restarts, and takes no proof twice, seed ${settings.seed}`, () => hegel.test((tc) => {
  const operations: Operation[] = tc.draw(gs.arrays(operation, { minSize: 1, maxSize: 60 }));
  const reference = new Reference();
  let gate = new GateState(T0, { ceiling: CEILING });
  for (const op of operations) {
    switch (op.kind) {
      case 'wait':
        reference.step(op.ms);
        break;
      case 'restart':
        reference.restart();
        gate = new GateState(reference.clock, { ceiling: CEILING });
        break;
      case 'nonce':
        reference.called();
        reference.current(gate.nonce(reference.clock));
        break;
      case 'admit': {
        const seen = reference.nonces;
        const nonce = op.nonce < seen.length ? seen[seen.length - 1 - op.nonce]!.nonce : 'g0.AAAAAAAAAAAAAAAAAAAAAA';
        const replay = op.jti === null ? undefined : { session: 's', jti: `jti-${op.jti}`, nonce };
        const expected = reference.admit(op.jti, nonce, op.counts);
        const context = JSON.stringify({ op, nonce });
        if (expected === 'throws') {
          assert.throws(() => gate.admit({ replay, counts: op.counts }, reference.clock), /names a count twice/, context);
          break;
        }
        const answer = gate.admit({ replay, counts: op.counts }, reference.clock);
        if (answer.ok || answer.reason === 'use_dpop_nonce') {
          reference.current(answer.nonce);
          const { nonce: _, ...rest } = answer;
          assert.deepEqual(rest, expected, context);
        } else {
          assert.deepEqual(answer, expected, context);
        }
        break;
      }
    }
  }
}, settings));

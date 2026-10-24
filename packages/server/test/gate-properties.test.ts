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
  | { kind: 'wait'; ms: number }
  | { kind: 'restart' }
  | { kind: 'nonce' }
  /** `nonce`: which nonce seen so far the proof carries, counting back from the newest; past them all, one no gate gave. */
  | { kind: 'admit'; jti: number | null; nonce: number; count: Count | null };

const admit = gs.record({
  kind: gs.just('admit' as const),
  jti: gs.optional(gs.integers({ minValue: 0, maxValue: 2 })),
  nonce: gs.oneOf(gs.just(0), gs.integers({ minValue: 0, maxValue: 3 })),
  count: gs.optional(gs.record({ key: gs.sampledFrom(['stripe', 'openai'] as const), windowMs: gs.sampledFrom(WINDOWS), most: gs.integers({ minValue: 0, maxValue: 3 }) })),
});
// Requests most often, so that sequences replay proofs and fill windows; time mostly in small steps.
const operation = gs.oneOf<Operation>(
  admit,
  admit,
  admit,
  gs.record({ kind: gs.just('wait' as const), ms: gs.oneOf(gs.sampledFrom([0, 1, 999, 1000, EPOCH_MS - 1, EPOCH_MS, 2 * EPOCH_MS]), gs.integers({ minValue: 0, maxValue: 3 * EPOCH_MS })) }),
  gs.record({ kind: gs.just('nonce' as const) }),
  gs.record({ kind: gs.just('restart' as const) }),
);

/** The reference: what the design says each answer is. */
class Reference {
  now = T0;
  life = 0;
  started = T0;
  /** Each nonce a gate gave, with the life and epoch it named. */
  readonly nonces: { nonce: string; life: number; epoch: number }[] = [];
  /** Every proof taken, in any life: `<nonce> <jti>`. */
  readonly taken = new Set<string>();
  second = -1;
  inSecond = 0;
  /** This life's counted requests and refusals, by count: their times. */
  counted = new Map<string, number[]>();
  refused = new Map<string, number[]>();

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
    this.started = this.now;
    this.second = -1;
    this.counted = new Map();
    this.refused = new Map();
  }

  /** The answer the design gives, its nonce left to `current`. */
  admit(jti: number | null, nonce: string, count: Count | null): { ok: true } | { ok: false; reason: string; key?: string; retryAfterMs?: number; first?: boolean } {
    const second = Math.floor(this.now / 1000);
    if (second !== this.second) {
      this.second = second;
      this.inSecond = 0;
    }
    if (this.inSecond >= CEILING) return { ok: false, reason: 'overloaded' };
    this.inSecond += 1;
    if (jti !== null) {
      const named = this.nonces.find((seen) => seen.nonce === nonce);
      const live = named !== undefined && named.life === this.life && this.epoch() - named.epoch <= 1;
      if (!live) return { ok: false, reason: 'use_dpop_nonce' };
      if (this.taken.has(`${nonce} ${jti}`)) return { ok: false, reason: 'replayed' };
      this.taken.add(`${nonce} ${jti}`);
    }
    if (count !== null) {
      const id = `${count.key}/${count.windowMs}`;
      const start = Math.floor(this.now / count.windowMs) * count.windowMs;
      const inWindow = (times: number[] | undefined) => (times ?? []).filter((time) => time >= start);
      if (inWindow(this.counted.get(id)).length >= count.most) {
        const first = inWindow(this.refused.get(id)).length === 0;
        this.refused.set(id, [...(this.refused.get(id) ?? []), this.now]);
        return { ok: false, reason: 'limit', key: count.key, retryAfterMs: start + count.windowMs - this.now, first };
      }
      this.counted.set(id, [...(this.counted.get(id) ?? []), this.now]);
    }
    return { ok: true };
  }
}

const settings = propertySettings(200);

test(`the gate answers as the reference over any requests, waits and restarts, and takes no proof twice, seed ${settings.seed}`, () => hegel.test((tc) => {
  const operations: Operation[] = tc.draw(gs.arrays(operation, { minSize: 1, maxSize: 60 }));
  const reference = new Reference();
  let gate = new GateState(T0, CEILING);
  for (const op of operations) {
    switch (op.kind) {
      case 'wait':
        reference.now += op.ms;
        break;
      case 'restart':
        reference.restart();
        gate = new GateState(reference.now, CEILING);
        break;
      case 'nonce':
        reference.current(gate.nonce(reference.now));
        break;
      case 'admit': {
        const seen = reference.nonces;
        const nonce = op.nonce < seen.length ? seen[seen.length - 1 - op.nonce]!.nonce : 'g0.AAAAAAAAAAAAAAAAAAAAAA';
        const replay = op.jti === null ? undefined : { session: 's', jti: `jti-${op.jti}`, nonce };
        const answer = gate.admit({ replay, counts: op.count === null ? [] : [op.count] }, reference.now);
        const expected = reference.admit(op.jti, nonce, op.count);
        if (answer.ok || answer.reason === 'use_dpop_nonce') {
          reference.current(answer.nonce);
          const { nonce: _, ...rest } = answer;
          assert.deepEqual(rest, expected, JSON.stringify({ op, nonce }));
        } else {
          assert.deepEqual(answer, expected, JSON.stringify({ op, nonce }));
        }
        break;
      }
    }
  }
}, settings));

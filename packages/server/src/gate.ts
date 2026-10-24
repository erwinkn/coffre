// A workload's gate (docs/design/workload-access.md, section 5.2): what
// must be both shared by every request of one service and fast. Its nonces
// make each proof single-use, and its counts hold the limits. On Node it is
// an object in the process (`processGates`); on Workers, a Durable Object
// per workload around the same state (cloudflare-gates.ts).
//
// Nonces are epochs. A gate draws a random nonce when it starts and a new
// one every `EPOCH_MS`, and takes a proof only under the current or the
// previous one, remembering every `jti` it took under each. So a proof is
// taken once, for at most two epochs, and a gate that restarts, whose old
// nonces nobody holds any more, forgets nothing that matters: no `jti` is
// stored, and no clock is trusted across a restart.
//
// The gate decides no one's access. Freezes, revocations and grants are the
// database's, read on each request; losing a gate costs a nonce retry and
// resets its counts, and lets nothing through.
import { base64url } from '@coffre/client/dpop';
import type { Gate, GateAdmission, GateCount } from '@coffre/core/identity';

/** How long a nonce is current; it is taken for one epoch more, as the previous. */
export const EPOCH_MS = 120_000;
/**
 * The requests a gate takes in one second, a Durable Object's documented
 * soft limit; past it, `overloaded`. It bounds what a gate remembers: two
 * epochs at the ceiling, 240,000 `jti`s of 22 characters, about 20 MB.
 */
export const GATE_CEILING = 1000;
/** Counts over a window this long or longer survive a Durable Object's eviction, written every `FLUSH_MS`: a day's limit. Shorter ones live in memory. */
export const DURABLE_WINDOW_MS = 3_600_000;
/** How often a Durable Object writes its durable counts: an eviction loses at most this much of them. */
export const FLUSH_MS = 10_000;

/** Where a runtime finds a workload's gate, by its service's principal (`token:api-prod`). */
export type Gates = (principal: string) => Gate;

/** A count's window: when it started, the requests it took, and whether it has refused one yet. */
export type Count = { start: number; taken: number; refused: boolean };

/** One epoch: its nonce, and every `jti` taken under it. */
type Epoch = { nonce: string; seen: Set<string> };

/**
 * One workload's gate, in memory: what `Gate` asks of it, with the time
 * given on each call. Every method runs to its end without waiting, so no
 * two requests interleave inside one.
 */
export class GateState {
  readonly #started: number;
  readonly #ceiling: number;
  #n = 0;
  #current: Epoch;
  #previous: Epoch | null = null;
  /** The second the ceiling counts, and what it took in it. */
  #second = -1;
  #inSecond = 0;
  /** By `countId`. */
  readonly #counts = new Map<string, Count>();
  /** The durable counts changed since `flush` last took them. */
  readonly #dirty = new Set<string>();

  constructor(now: number, ceiling = GATE_CEILING) {
    this.#started = now;
    this.#ceiling = ceiling;
    this.#current = epoch(0);
  }

  nonce(now: number): string {
    this.#rotate(now);
    return this.#current.nonce;
  }

  /**
   * Replay first, when there is a proof: its nonce must be the current or
   * the previous one, and its `jti` new under it, which it then is no
   * longer, whatever follows. Then every count: past any one, the request
   * is refused and none counts it.
   */
  admit(request: { replay?: { jti: string; nonce: string }; counts?: readonly GateCount[] }, now: number): GateAdmission {
    this.#rotate(now);
    const second = Math.floor(now / 1000);
    if (second !== this.#second) {
      this.#second = second;
      this.#inSecond = 0;
    }
    if (this.#inSecond >= this.#ceiling) return { ok: false, reason: 'overloaded' };
    this.#inSecond += 1;

    const { replay, counts = [] } = request;
    if (replay !== undefined) {
      const under = replay.nonce === this.#current.nonce ? this.#current : replay.nonce === this.#previous?.nonce ? this.#previous : null;
      if (under === null) return { ok: false, reason: 'use_dpop_nonce', nonce: this.#current.nonce };
      if (under.seen.has(replay.jti)) return { ok: false, reason: 'replayed' };
      under.seen.add(replay.jti);
    }

    const windows = counts.map((count) => {
      const id = countId(count);
      const start = Math.floor(now / count.windowMs) * count.windowMs;
      let held = this.#counts.get(id);
      if (held === undefined || held.start !== start) {
        held = { start, taken: 0, refused: false };
        this.#counts.set(id, held);
      }
      return { id, count, held };
    });
    const past = windows.find(({ count, held }) => held.taken >= count.most);
    if (past !== undefined) {
      const first = !past.held.refused;
      past.held.refused = true;
      this.#touched(past.id, past.count.windowMs);
      return { ok: false, reason: 'limit', key: past.count.key, retryAfterMs: past.held.start + past.count.windowMs - now, first };
    }
    for (const { id, count, held } of windows) {
      held.taken += 1;
      this.#touched(id, count.windowMs);
    }
    return { ok: true, nonce: this.#current.nonce };
  }

  /** The durable counts changed since the last call, by `countId`, to write. */
  flush(): [string, Count][] {
    const changed = [...this.#dirty].flatMap((id): [string, Count][] => {
      const held = this.#counts.get(id);
      return held === undefined ? [] : [[id, { ...held }]];
    });
    this.#dirty.clear();
    return changed;
  }

  /** Whether a durable count waits to be written. */
  get dirty(): boolean {
    return this.#dirty.size > 0;
  }

  /** Durable counts as `flush` gave them, read back when a Durable Object starts again: those whose window has ended are left out. */
  restore(counts: Iterable<[string, Count]>, now: number) {
    for (const [id, held] of counts) {
      if (held.start + windowOf(id) > now) this.#counts.set(id, { ...held });
    }
  }

  #touched(id: string, windowMs: number) {
    if (windowMs >= DURABLE_WINDOW_MS) this.#dirty.add(id);
  }

  /**
   * The epoch `now` falls in, counted from the start: epoch `n`'s nonce is
   * taken from `n × EPOCH_MS` until `(n + 2) × EPOCH_MS`, however few
   * requests came. A clock that goes back keeps the epoch it has.
   */
  #rotate(now: number) {
    const n = Math.floor((now - this.#started) / EPOCH_MS);
    if (n <= this.#n) return;
    this.#previous = n === this.#n + 1 ? this.#current : null;
    this.#n = n;
    this.#current = epoch(n);
    for (const [id, held] of this.#counts) {
      if (held.start + windowOf(id) <= now && !this.#dirty.has(id)) this.#counts.delete(id);
    }
  }
}

/** Epoch `n`: a nonce of 16 random bytes after its number, which says nothing secret, and nothing taken yet. */
function epoch(n: number): Epoch {
  return { nonce: `g${n}.${base64url(crypto.getRandomValues(new Uint8Array(16)))}`, seen: new Set() };
}

/** A count's name in the gate and in a Durable Object's storage: its window, then its key. */
function countId(count: GateCount): string {
  return `${count.windowMs}:${count.key}`;
}

function windowOf(id: string): number {
  return Number(id.slice(0, id.indexOf(':')));
}

/**
 * The gates of a Node process, one per workload, made with its first
 * request. A Node deployment runs one app process: several, Coffre on
 * Kubernetes with more than one replica included, would each hold gates of
 * their own, whose nonces differ, and a client bouncing between them would
 * be asked for a new nonce at every bounce. That fails loudly, never
 * unsafely: a proof is taken only by the gate whose nonce it carries.
 */
export function processGates(): Gates {
  const gates = new Map<string, GateState>();
  return (principal) => {
    const gate = gates.get(principal) ?? new GateState(Date.now());
    gates.set(principal, gate);
    return {
      nonce: async () => gate.nonce(Date.now()),
      admit: async (request) => gate.admit(request, Date.now()),
    };
  };
}

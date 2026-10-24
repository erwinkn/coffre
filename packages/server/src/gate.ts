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
/** Counts over a window this long or longer, an hour's or a day's, survive a Durable Object's eviction, written every `FLUSH_MS`. Shorter ones live in memory. */
export const DURABLE_WINDOW_MS = 3_600_000;
/** How often a Durable Object writes its durable counts: an eviction loses at most this much of them. */
export const FLUSH_MS = 10_000;
/**
 * How far a clock may step back and the gate take it as skew, two
 * machines' or a Durable Object's made again elsewhere: its epoch and its
 * counts' windows stay. Past it, a new epoch.
 */
export const SKEW_MS = 10_000;

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
 *
 * Clocks step, both ways. Its epochs run on the latest time it was given,
 * so a step back of `SKEW_MS` at most revives none; a step back further
 * starts a new epoch, as a restart does, so a clock that jumped ahead and
 * came back costs a nonce retry. Each count holds one window, the one it
 * was last asked in, or a later one up to `SKEW_MS` ahead, which a clock a
 * little behind still counts in; asked in any other, it starts again at
 * zero. Neither depends on the other, and a count never waits for the
 * clock to come back to it.
 */
export class GateState {
  #started: number;
  readonly #ceiling: number;
  /** Whether its counts over `DURABLE_WINDOW_MS` or more are kept for `flush`: a Durable Object's, which writes them. */
  readonly #durable: boolean;
  /** The latest time it was given, which its epochs run on. */
  #latest: number;
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

  constructor(now: number, options: { ceiling?: number; durable?: boolean } = {}) {
    this.#started = now;
    this.#latest = now;
    this.#ceiling = options.ceiling ?? GATE_CEILING;
    this.#durable = options.durable ?? false;
    this.#current = epoch(0);
  }

  nonce(now: number): string {
    this.#rotate(now);
    return this.#current.nonce;
  }

  /**
   * Replay first, when there is a proof: its nonce must be the current or
   * the previous one, and its `jti` taken under neither, which it then is,
   * whatever follows. Then every count, each named once: past any, the
   * request is refused and none counts it.
   */
  admit(request: { replay?: { jti: string; nonce: string }; counts?: readonly GateCount[] }, now: number): GateAdmission {
    const { replay, counts = [] } = request;
    const ids = counts.map(countId);
    if (new Set(ids).size !== ids.length) throw new Error(`a request names a count twice: ${ids.join(', ')}`);
    this.#rotate(now);
    const second = Math.floor(now / 1000);
    if (second !== this.#second) {
      this.#second = second;
      this.#inSecond = 0;
    }
    if (this.#inSecond >= this.#ceiling) return { ok: false, reason: 'overloaded' };
    this.#inSecond += 1;

    if (replay !== undefined) {
      const under = replay.nonce === this.#current.nonce ? this.#current : replay.nonce === this.#previous?.nonce ? this.#previous : null;
      if (under === null) return { ok: false, reason: 'use_dpop_nonce', nonce: this.#current.nonce };
      if (this.#current.seen.has(replay.jti) || this.#previous?.seen.has(replay.jti)) return { ok: false, reason: 'replayed' };
      under.seen.add(replay.jti);
    }

    const windows = counts.map((count, i) => {
      const id = ids[i]!;
      const start = Math.floor(now / count.windowMs) * count.windowMs;
      let held = this.#counts.get(id);
      const ahead = held !== undefined && held.start > start && held.start - now <= SKEW_MS;
      if (held === undefined || (held.start !== start && !ahead)) {
        held = { start, taken: 0, refused: false };
        this.#counts.set(id, held);
        this.#touched(id, count.windowMs);
      }
      return { id, count, held, end: held.start + count.windowMs };
    });
    // Past several, the one that ends last says when to retry.
    const past = windows.filter(({ count, held }) => held.taken >= count.most).sort((a, b) => b.end - a.end)[0];
    if (past !== undefined) {
      const first = !past.held.refused;
      past.held.refused = true;
      this.#touched(past.id, past.count.windowMs);
      return { ok: false, reason: 'limit', key: past.count.key, retryAfterMs: past.end - now, first };
    }
    for (const { id, count, held } of windows) {
      held.taken += 1;
      this.#touched(id, count.windowMs);
    }
    return { ok: true, nonce: this.#current.nonce };
  }

  /** The durable counts changed since the last call, by `countId`, to write; `unwritten` gives them back if the write fails. */
  flush(): [string, Count][] {
    const changed = [...this.#dirty].flatMap((id): [string, Count][] => {
      const held = this.#counts.get(id);
      return held === undefined ? [] : [[id, { ...held }]];
    });
    this.#dirty.clear();
    return changed;
  }

  /** Counts `flush` gave whose write failed: they wait to be written again. */
  unwritten(ids: Iterable<string>) {
    for (const id of ids) if (this.#counts.has(id)) this.#dirty.add(id);
  }

  /** Whether a durable count waits to be written. */
  get dirty(): boolean {
    return this.#dirty.size > 0;
  }

  /** Durable counts as `flush` gave them, read back when a Durable Object starts again: one whose window has ended starts again when asked, as in memory. */
  restore(counts: Iterable<[string, Count]>) {
    for (const [id, held] of counts) this.#counts.set(id, { ...held });
  }

  #touched(id: string, windowMs: number) {
    if (this.#durable && windowMs >= DURABLE_WINDOW_MS) this.#dirty.add(id);
  }

  /**
   * The epoch the latest time falls in, counted from the start: epoch
   * `n`'s nonce is taken from `n × EPOCH_MS` until `(n + 2) × EPOCH_MS`,
   * however few requests came. Given a time further back than `SKEW_MS`,
   * it starts again from it with a new epoch.
   */
  #rotate(now: number) {
    if (now < this.#latest - SKEW_MS) {
      this.#started = now;
      this.#latest = now;
      this.#n = 0;
      this.#current = epoch(0);
      this.#previous = null;
      return;
    }
    if (now > this.#latest) this.#latest = now;
    const n = Math.floor((this.#latest - this.#started) / EPOCH_MS);
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

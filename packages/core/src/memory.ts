// What a Worker's isolate may hold, split into named shares, and the one cache every kept answer is held in.
//
// Cloudflare gives each isolate 128 MB, "per-isolate, not per-invocation. A single isolate can handle many concurrent
// requests" (https://developers.cloudflare.com/workers/platform/limits/#memory). Past it the isolate is ended, with
// every request it serves. So what an isolate holds for its requests at once, and what it keeps between them, is
// bounded by shares of that number, each with its source:
//
//   share            bytes        holds                                               source
//   uses in flight   64,000,000   the `/use` calls an isolate holds open              half, a policy choice
//   proxy bodies     16 MiB       request bodies the credential proxy reads whole     the 16 MiB one body took before
//   caches           16 MiB       answers kept between requests                       as much as the bodies
//   runtime          the rest     code, the runtime's own, a request's objects        measured: 8.6 MB of it idle
//
// The vault's Worker is an isolate of its own, split the same way: it reads no proxy body, and its caches
// (`UseCache`, `@coffre/vault`) are still counted by `useLimits`, its keys in flight by `USES_IN_FLIGHT`. On Node,
// nothing ends a process at 128 MB: each process holds to the same numbers, as defensive bounds, so a deployment
// behaves alike on either runtime.

import { USE_DEADLINE_MS } from './vault.ts';

const MiB = 1024 * 1024;

/**
 * An isolate's memory: "128 MB", read as decimal megabytes, the smaller of the two readings, so that the shares fit
 * whichever Cloudflare means.
 */
export const ISOLATE_BYTES = 128_000_000;

/** The `/use` calls an isolate holds open at once: half the isolate (docs/design/limits.md, "Memory, per isolate"). */
export const USES_BYTES = 64_000_000;

/**
 * What one key in flight holds in the vault's isolate, from its admission to its answer, its wait on the key service
 * included: 30 KiB, the largest of the measurements, so that `USES_IN_FLIGHT` holds whichever is nearest workerd's.
 *
 *   a use held in its statement, local workerd, its RPC from the app included     30 KiB (36 by heap snapshot), flat
 *                                                                                  from 100 to 500
 *   a lone use held at its key service, Node, in process                          13 to 15 KiB, 250 to 1,000 held
 *   a batch's key held there, batches of 100, Node, in process                    6 to 9 KiB, 500 and 1,000 held
 *
 * Node's V8 does not compress pointers, as workerd's does, so its figures bound workerd's for the same objects from
 * above; they leave out the transport, which the workerd figure has. A key service's requests take turns, eight at
 * once (`@coffre/core/kek`'s aws-kms.ts), so the keys waiting there hold their place in its queue, not a request each.
 * `USES_IN_FLIGHT` is 1,250 while this is at most 51,200 bytes (64,000,000 ÷ 1,250): past it, memory binds.
 */
export const USE_IN_FLIGHT_BYTES = 30 * 1024;

/** The CPU one use takes in the vault's isolate, warm: 2.4 ms, local workerd (`pnpm bench:workers`'s use). */
export const USE_CPU_MS = 2.4;

/**
 * How many keys an isolate or process has in flight at once, each a place in the vault's admission (`UseCache`,
 * `@coffre/vault`): past it, a use is refused at once, `overloaded`. The smaller of what its memory holds and
 * what its CPU can serve within one use's deadline, since a use admitted past that could only be answered `late`:
 *
 *   min(USES_BYTES ÷ USE_IN_FLIGHT_BYTES, USE_DEADLINE_MS ÷ USE_CPU_MS)
 *     = min(64,000,000 ÷ 30,720, 3,000 ms ÷ 2.4 ms) = min(2,083, 1,250) = 1,250
 *
 * Derived, never set (docs/design/limits.md, "Admission: places in flight, from memory and CPU"). On Node, the same
 * two bounds for the process, as for the other shares. To re-measure the bytes: `packages/vault/test/bench/held.ts`
 * (its header says how to run it), and a heap snapshot of the vault's Worker under `pnpm bench:workers`; the CPU:
 * `pnpm bench:workers`, its use's warm CPU.
 */
export const USES_IN_FLIGHT = Math.min(Math.floor(USES_BYTES / USE_IN_FLIGHT_BYTES), Math.floor(USE_DEADLINE_MS / USE_CPU_MS));

/**
 * Request bodies the credential proxy reads whole, all of an isolate's at once: the 16 MiB one body could take before,
 * now shared, so that a burst of large bodies is refused fast (503 with `Retry-After`) rather than ending the isolate.
 */
export const BODIES_BYTES = 16 * MiB;

/**
 * The most of one request's body held whole: an API call's, not an upload's, which streams. Eight at once fill
 * `BODIES_BYTES`, since each byte is charged twice (the bytes, and a copy's or its chunks'). A WebSocket's message on
 * Node is held to it too.
 */
export const BODY_READ_WHOLE_BYTES = 1 * MiB;

/** Answers kept between requests, all of an isolate's caches together: as much as the bodies take. */
export const CACHES_BYTES = 16 * MiB;

/**
 * What is left for the runtime: the code, the runtime's own state, and what no share counts (a request's objects, a
 * response on its way, the collector's slack). 30.4 MB, of which the app's Worker of `examples/workers` holds 8.6 MB
 * idle, warmed by a sign-in and a few pages (8,602,928 bytes of heap once collected: local workerd, the inspector's
 * `Runtime.getHeapUsage` after `HeapProfiler.collectGarbage`). The vault's Worker, the smaller bundle,
 * was not measured.
 */
export const RUNTIME_BYTES = ISOLATE_BYTES - USES_BYTES - BODIES_BYTES - CACHES_BYTES;

/**
 * The caches an isolate of the app keeps, each an equal slice of `CACHES_BYTES`, as none is known to need more than
 * another: the credential proxy's values and handles, its UI definitions' items, readings, values and places, and the
 * vault's answers about each principal (`Accesses`, `@coffre/server`).
 */
const APP_CACHES = 7;
export const CACHE_SLICE_BYTES = Math.floor(CACHES_BYTES / APP_CACHES);

/**
 * What a cache entry costs beyond its key and value: its slot in the map and the entry `Lru` keeps of it, 77 bytes
 * measured (Node 24, whose V8 does not compress pointers, as workerd's does), up to three words more while the map's
 * table is half empty after it doubles.
 */
const ENTRY_BYTES = 128;

/**
 * An upper bound on what V8 holds for `value`, settled data as the caches keep it: strings at two bytes a character
 * (one-byte strings take one), each with its header; numbers boxed; arrays and objects their slots, a key's name
 * shared by every object of its shape. Measured against the heap on Node 24, every entry of the caches as they keep
 * it, its slot in the map included, holds less than `weight` gives its key and value alone: a handle's environments
 * 232 bytes against 350, a cached value 310 against 576, an access 1,256 against 2,926.
 */
export function weight(value: unknown): number {
  switch (typeof value) {
    case 'string':
      return 24 + 2 * value.length;
    case 'number':
    case 'bigint':
      return 16;
    case 'object': {
      if (value === null) return 0;
      if (Array.isArray(value)) return value.reduce((sum: number, item) => sum + weight(item), 48 + 8 * value.length);
      if (value instanceof Set || value instanceof Map) return [...value].reduce((sum: number, item) => sum + weight(item), 64 + 24 * value.size);
      const entries = Object.entries(value);
      return entries.reduce((sum, [, item]) => sum + weight(item), 56 + 16 * entries.length);
    }
    default:
      return 0;
  }
}

/**
 * A map that keeps its most recently used entries within `bytes`: each weighed as it is set (`weight` of its key and
 * value, unless `weigh` says otherwise), and past `bytes` the least recently used go first, one at a time, never all
 * at once. An entry heavier than `bytes` alone is not kept. Settled values only, never a pending promise: a request
 * that awaits another's work is cancelled with it on Workers (AGENTS.md, "What an isolate keeps").
 *
 *   new Lru<string, number>(400)   each entry 170 bytes: set a, set b, get a, set c   holds a and c, b gone first
 */
export class Lru<K, V> {
  readonly bytes: number;
  readonly #weigh: (key: K, value: V) => number;
  readonly #entries = new Map<K, { value: V; bytes: number }>();
  #held = 0;

  constructor(bytes: number, weigh: (key: K, value: V) => number = (key, value) => weight(key) + weight(value)) {
    this.bytes = bytes;
    this.#weigh = weigh;
  }

  get size(): number {
    return this.#entries.size;
  }

  /** The bytes its entries are weighed at, together. */
  get held(): number {
    return this.#held;
  }

  /** The value at `key`, made the most recently used. */
  get(key: K): V | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry.value;
  }

  has(key: K): boolean {
    return this.#entries.has(key);
  }

  /** `value` at `key`, the most recently used, the least recently used others gone as far as it needs room. */
  set(key: K, value: V): this {
    this.delete(key);
    const bytes = ENTRY_BYTES + this.#weigh(key, value);
    if (bytes > this.bytes) return this;
    for (const [old, entry] of this.#entries) {
      if (this.#held + bytes <= this.bytes) break;
      this.#entries.delete(old);
      this.#held -= entry.bytes;
    }
    this.#entries.set(key, { value, bytes });
    this.#held += bytes;
    return this;
  }

  delete(key: K): boolean {
    const entry = this.#entries.get(key);
    if (entry === undefined) return false;
    this.#entries.delete(key);
    this.#held -= entry.bytes;
    return true;
  }

  clear(): void {
    this.#entries.clear();
    this.#held = 0;
  }

  /** Each key and value, the least recently used first, none made more recent. */
  *[Symbol.iterator](): IterableIterator<[K, V]> {
    for (const [key, { value }] of this.#entries) yield [key, value];
  }
}

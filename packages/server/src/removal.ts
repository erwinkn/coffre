import { AsyncLocalStorage } from 'node:async_hooks';

import type { VaultEntry } from '@coffre/core/vault';

/**
 * What one request, or one scheduled run, may spend removing bindings in batches (W331; formal/Unbinding.tla;
 * `#bindingsByVault` in api/workloads.ts): how many credentials one vault call revokes, and whether it may make one
 * more such call. Past it, the removal answers that it is under way (`RemovalUnderWay`, a 202), its binding closed, for
 * the person's next request, or the next scheduled run, to go on with. Null on Node, where nothing bounds a request's
 * calls or CPU: its batches are the fence's (`UNBIND_BATCH`), and a removal ends in one request.
 */
export type RemovalBudget = {
  /** The most credentials one vault call of a removal revokes. */
  readonly batch: number;
  /** Whether the request may make one more of a removal's vault calls, `after` of its own still to make once it ends; spent if so. */
  take(after: number): boolean;
};

/**
 * A Worker request's: Cloudflare's own limits, and the CPU each call was measured to cost.
 *
 * - Invocations: "A single request has a maximum of 32 Worker invocations, and each call to a Service binding counts
 *   towards this limit. Subsequent calls will throw an exception." (developers.cloudflare.com/workers/runtime-apis/
 *   bindings/service-bindings/#limits, 2026-11-06). Counted, not guessed: every call the request made to its vault so
 *   far (`countedVault`), and `after`, those it makes once the removal ends.
 * - CPU, a policy: R27 holds a request to 10 ms at the median, 20 at p99; a removal's call is held to 10, Workers
 *   Free's hard limit an invocation, because one over it is killed (1102) on every try, and its binding could never be
 *   removed. A vault call costs `VAULT_CALL_FIXED_MS` and `VAULT_MS_PER_CREDENTIAL` a credential; the app's request
 *   `APP_REQUEST_FIXED_MS`, and `APP_MS_PER_CREDENTIAL` a credential it names.
 *
 * Measured on 2026-11-06, Postgres 16.14 on Debian, an AMD EPYC 9454P shared with other work (load about 20), warm:
 * a sweep call of the vault's in process (Node) 0.55 ms for 1 credential, 5.0 for 100, 18.7 for 400; an unbind
 * request's own CPU, the vault's apart, 0.75 ms with no credential, 2.5 with 100. On Workers each also opens a
 * connection of its own and logs in, which the verifier measured on local workerd the same day: 4.3 ms with three
 * statements (packages/vault/src/verifier.ts, `ABOVE_NEWEST`). No assertion holds these in CI: they would flake.
 */
export function workersRemovalBudget(calls: () => number): RemovalBudget {
  let made = 0;
  return {
    batch: WORKERS_BATCH,
    take(after) {
      if (made >= WORKERS_BATCHES || calls() + 1 + after > WORKERS_INVOCATIONS) return false;
      made += 1;
      return true;
    },
  };
}

const WORKERS_INVOCATIONS = 32;
const CPU_MS = 10;
const VAULT_CALL_FIXED_MS = 4.3 + 0.55;
const VAULT_MS_PER_CREDENTIAL = 0.045;
const APP_REQUEST_FIXED_MS = 4.3 + 0.75;
const APP_MS_PER_CREDENTIAL = 0.0175;
/** A Worker's batch: as many as a vault call's CPU allows (114), below the fence's (`UNBIND_BATCH`, 125). */
export const WORKERS_BATCH = Math.floor((CPU_MS - VAULT_CALL_FIXED_MS) / VAULT_MS_PER_CREDENTIAL);
/** And as many of them as the app's request's CPU allows (2). */
const WORKERS_BATCHES = Math.floor((CPU_MS - APP_REQUEST_FIXED_MS) / (WORKERS_BATCH * APP_MS_PER_CREDENTIAL));

/**
 * The vault's entry, every call to it counted for the Worker invocation it is made in, of which one makes 32 at most:
 * one counted entry for each entry, so that the vault `versioned` makes of it is the isolate's one, which the isolate's
 * caches key on (`keeping`, the proxy's `GATES`; review r8), while each invocation counts its own calls, the
 * isolate's requests running interleaved (`countingCalls`).
 */
export function countedEntry(entry: VaultEntry): VaultEntry {
  let counted = COUNTED.get(entry);
  if (counted === undefined) {
    counted = {
      call: (release, method, args) => {
        const made = INVOCATION.getStore();
        if (made !== undefined) made.calls += 1;
        return entry.call(release, method, args);
      },
    };
    COUNTED.set(entry, counted);
  }
  return counted;
}

/**
 * One invocation's count of its vault calls (`countedEntry`): `run` its work, a request's or a scheduled run's, and every
 * call made in it, and in what it leaves to `waitUntil`, counts here, as `calls` says.
 */
export function countingCalls(): { calls: () => number; run<T>(work: () => T): T } {
  const made = { calls: 0 };
  return { calls: () => made.calls, run: (work) => INVOCATION.run(made, work) };
}

const COUNTED = new WeakMap<VaultEntry, VaultEntry>();
const INVOCATION = new AsyncLocalStorage<{ calls: number }>();

/**
 * A removal not yet finished in this request, its binding closed: `left`, what its request has still to do, the
 * credentials to revoke and the bindings to end, of every binding it ends (a replacement of keys, several), so that it
 * falls with each request asked again that does any of it (the client holds it to falling, review r8).
 */
export class RemovalUnderWay extends Error {
  readonly left: number;
  /**
   * Whether this request made any of the removal's calls: one made inside another, whose calls are spent, made none,
   * and asking it again would not either, however `left` falls as credentials end on their own (Fable on #520).
   */
  readonly progressed: boolean;
  constructor(left: number, progressed: boolean) {
    super(`the removal is under way: ${left} left to do (credentials to revoke, bindings to end); ask again to go on`);
    this.name = 'RemovalUnderWay';
    this.left = left;
    this.progressed = progressed;
  }
}

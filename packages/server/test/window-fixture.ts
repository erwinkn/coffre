// Fixed 60 s windows in tests (T217, T202). Two things count by the wall clock's minute: a workload gate's
// limits (`gate.ts`: a count's window starts at `floor(now / windowMs) * windowMs`), and the vault's bulk cap, whose
// refresh period a use writes its key's row in (`bulk.ts`). A minute turning over between a test's calls resets the
// first and makes the second's next use write its row again, a statement and a round it did not take before.
// A test whose assertion depends on all its calls sharing one window uses what is here, rather than hope it does.
import { setTimeout as sleep } from 'node:timers/promises';

import { GateState, type Gates } from '../src/gate.ts';

const MINUTE_MS = 60_000;

/**
 * `processGates()` on a clock stopped one second into the current minute (so into its hour and day, too): every
 * call of a test falls in one window of each length, whenever the test runs. `GateState` is `processGates`' own
 * state, given the time on each call. The gate's one-second ceiling counts the stopped second, so a test may make
 * `GATE_CEILING` requests through one set of gates, which none comes near.
 */
export function pinnedGates(now: number = Date.now()): Gates {
  const at = Math.floor(now / MINUTE_MS) * MINUTE_MS + 1000;
  const gates = new Map<string, GateState>();
  return (principal) => {
    const gate = gates.get(principal) ?? new GateState(at);
    gates.set(principal, gate);
    return {
      nonce: async () => gate.nonce(at),
      admit: async (request) => gate.admit(request, at),
    };
  };
}

/**
 * Waits for the next minute if fewer than `ms` of this one are left, so that calls taking less than `ms` share a
 * refresh period of the bulk cap (a minute, `refreshMs` of the default 15-minute window). The same wait as the
 * vault's matrices make (`inPeriod`); the database's clock and this one are the machine's.
 */
export async function inBulkPeriod(ms: number, now: () => number = Date.now): Promise<void> {
  const left = MINUTE_MS - (now() % MINUTE_MS);
  if (left < ms) await sleep(left + 50);
}

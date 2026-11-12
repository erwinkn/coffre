// Fixed windows in tests (T217, T202, T218, T204). Two things count by the clock: a workload gate's limits (`gate.ts`:
// a count's window starts at `floor(now / windowMs) * windowMs`), the wall clock's minute; and the vault's bulk cap,
// whose refresh period a use writes its key's row in (`bulk.ts`), a minute that starts for each principal's key at a
// phase of its own (`phaseOf`, 0074's `bulk_period`). A window turning over between a test's calls resets the first and makes
// the second's next use write its row again, a statement and a round it did not take before.
// A test whose assertion depends on all its calls sharing one window uses what is here, rather than hope it does.
// A gate's day count is the same, by the UTC day: a test in this process stops the clock (`t.mock.timers`), one in
// another (workerd) waits for a day with room (`inUtcDay`).
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

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
 * Where `principal`'s `key` starts its refresh periods, in [0, `refresh`): the vault's `phaseOf` (`bulk.ts`), which
 * 0074's `bulk_period` computes too (`sql-copies.test.ts` holds it to `phaseOf`). A copy, since a
 * package's tests import another's exports only, and the vault exports no cap internals; a copy that drifted would
 * only wait at the wrong times again, as the minute did (T204).
 */
function phaseOf(principal: string, key: string, refresh: number): number {
  return createHash('sha256').update(`${principal}/${key.toLowerCase()}`, 'utf8').digest().readUIntBE(0, 6) % refresh;
}

/** The phases of every key with a value in `place` (`project/environment`), for each of `principals`. Reads the keys from `db`. */
async function bulkPhases(db: Queryable, principals: readonly string[], place: string): Promise<number[]> {
  const [project, environment] = place.split('/');
  const keys = await rowsOf<{ id: string }>(db, sql`
    SELECT s.id FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects q ON q.id = e.project_id
     WHERE q.slug = ${project} AND e.slug = ${environment} AND s.current_version_id IS NOT NULL`);
  if (keys.length === 0) throw new Error(`no key with a value in ${place}`);
  return principals.flatMap((principal) => keys.map(({ id }) => phaseOf(principal, id, MINUTE_MS)));
}

/** How long from `at` until the first of `phases` turns its period. */
function untilTurn(phases: readonly number[], at: number): number {
  return Math.min(...phases.map((phase) => MINUTE_MS - ((((at - phase) % MINUTE_MS) + MINUTE_MS) % MINUTE_MS)));
}

/**
 * Waits until no key with a value in `place` (`project/environment`) turns its bulk-cap period within `ms` for any of
 * `principals`, so that calls taking less than `ms` share each key's period (a minute, `refreshMs` of the default
 * 15-minute window). Reads the keys from `db`. Waits less than a minute, or throws if no time in the
 * next one leaves `ms` for every key. The database's clock and this one are the machine's.
 */
export async function inBulkPeriod(ms: number, db: Queryable, principals: readonly string[], place: string, now: () => number = Date.now): Promise<void> {
  const phases = await bulkPhases(db, principals, place);
  const start = now();
  for (let at = start; at < start + MINUTE_MS; at += untilTurn(phases, at) + 50) {
    if (untilTurn(phases, at) >= ms) {
      if (at > start) await sleep(at - now());
      return;
    }
  }
  throw new Error(`no time in the next minute leaves ${ms} ms in every one of ${phases.length} keys' periods`);
}

/**
 * Waits until just after a key with a value in `place` turned its bulk-cap period for one of `principals`, at a turn
 * the next of which is at least `ms` away: a use made before the wait wrote that key's row in its last period, and
 * calls after it taking less than `ms` share every key's period. Waits at most a minute and `ms`, or throws if no turn
 * in the next minute leaves `ms`.
 */
export async function pastBulkTurn(ms: number, db: Queryable, principals: readonly string[], place: string, now: () => number = Date.now): Promise<void> {
  const phases = await bulkPhases(db, principals, place);
  const start = now();
  for (let turn = start + untilTurn(phases, start); turn < start + MINUTE_MS + ms; turn += untilTurn(phases, turn + 1) + 1) {
    if (untilTurn(phases, turn + 1) + 1 >= ms + 100) {
      await sleep(turn + 50 - now());
      return;
    }
  }
  throw new Error(`no turn in the next minute of ${phases.length} keys' periods leaves ${ms} ms before the next`);
}

const DAY_MS = 86_400_000;

/**
 * Waits for the next UTC day if fewer than `ms` of this one are left, so that a test of a Durable Object in workerd,
 * whose clock a test cannot stop, keeps its day's counts in one window (T218). Waits at most `ms`.
 */
export async function inUtcDay(ms: number, now: () => number = Date.now): Promise<void> {
  const left = DAY_MS - (now() % DAY_MS);
  if (left < ms) await sleep(left + 50);
}

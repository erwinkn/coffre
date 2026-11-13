// A bulk-cap period in tests. A use writes its key's row in the cap's current refresh period
// (`bulk.ts`), and one the key already has in its period writes nothing. A period turning over between a test's calls
// makes the next use write its row again: a statement and a round it did not take before. Each principal's key has
// periods of its own (`phaseOf`), so a test that counts the statements of several uses, the first of which enters the
// key, either makes its keys as their periods start (`freshKeyId`, which the worlds' keys are) or waits here for a
// time when none of its keys' periods turns (`inBulkPeriod`), rather than hope its calls share one.
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { phaseOf, REFRESH_MAX_MS } from '../src/bulk.ts';

/** The refresh of the default window, 15 minutes, which the test vaults keep: a minute. */
const REFRESH = REFRESH_MAX_MS;

/** How long `principal`'s `key` has been in its current period at `now`. */
const into = (principal: string, key: string, now: number) => (((now - phaseOf(principal, key, REFRESH)) % REFRESH) + REFRESH) % REFRESH;

/**
 * A new key's id whose period, for `principal`, began less than `FRESH_MS` ago: a key made with it can be used for a
 * minute less that before its period turns, as a key whose periods all started together could at the start of a
 * minute. A shorter window's periods (a tenth of it) divide the minute, so one of theirs starts then too.
 */
export function freshKeyId(principal: string, now: number = Date.now()): string {
  for (;;) {
    const id = randomUUID();
    if (into(principal, id, now) < FRESH_MS) return id;
  }
}
const FRESH_MS = 2000;

/**
 * Waits until none of `pairs`' periods turns within `ms` (each a principal's key), so that calls taking less than `ms`
 * share each key's period. Waits less than a period, or throws if no time in the next one leaves `ms` for every pair.
 * The database's clock and this one are the machine's.
 */
export async function inBulkPeriod(ms: number, pairs: readonly { principal: string; key: string }[], now: () => number = Date.now): Promise<void> {
  const start = now();
  let at = start;
  while (at < start + REFRESH) {
    // The pair whose period turns first after `at`; past its turn, the next try.
    const left = Math.min(...pairs.map(({ principal, key }) => REFRESH - into(principal, key, at)));
    if (left >= ms) {
      if (at > start) await sleep(at - now());
      return;
    }
    at += left + 50;
  }
  throw new Error(`no time in the next ${REFRESH} ms leaves ${ms} ms in every one of ${pairs.length} keys' periods`);
}

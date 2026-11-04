// A bulk-cap period in tests (T218, after T202). A use writes its key's row in the cap's current refresh period
// (`bulk.ts`), and one the key already has in its period writes nothing. A minute turning over between a test's
// calls makes the next use write its row again: a statement and a round it did not take before. A test that counts
// the statements of several uses, the first of which enters the key, waits here for a period with room, rather than
// hope its calls share one.
import { setTimeout as sleep } from 'node:timers/promises';

import { refreshMs } from '../src/bulk.ts';
import { CONFIG } from './use-world.ts';

/**
 * Waits for the next refresh period if fewer than `ms` of this one are left, so that calls taking less than `ms` share
 * it (a minute at the default window). The same wait as the matrices' `inPeriod`; the database's clock and this one
 * are the machine's.
 */
export async function inBulkPeriod(ms: number, now: () => number = Date.now): Promise<void> {
  const period = refreshMs(CONFIG.bulkLimit);
  const left = period - (now() % period);
  if (left < ms) await sleep(left + 50);
}

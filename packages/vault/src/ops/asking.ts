import { sql } from 'drizzle-orm';

import { callerFrom, type Asking, type callerParts, type Shown } from '../caller.ts';
import type { Refusal, Seen } from '../change.ts';
import type { Deciding } from '../vault.ts';

/** A change about no project, for `callerParts`: the caller's instance role and its scope decide, and none of their grants. */
export const NOWHERE = sql`(SELECT NULL::uuid WHERE false)`;

/**
 * Who asks a change, or why they are refused: one whose credential stands.
 * A workload's session that stands and is stopped is told why; a narrowed
 * one uses values and changes nothing.
 */
export function asking(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, vault: Deciding, at: number): Asking | Refusal {
  const caller = callerFrom(seen, shown, vault.workloads, at);
  if (caller === null) return { refused: 'unauthenticated' };
  if (caller.workload?.stop != null) return { refused: caller.workload.stop };
  if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
  return caller;
}

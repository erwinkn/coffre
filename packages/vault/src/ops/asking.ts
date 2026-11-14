import { ownsInstance } from '@coffre/core/access';
import type { LogAction } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { callerFrom, type Asking, type callerParts, type Shown } from '../caller.ts';
import type { Refusal, Seen } from '../change.ts';
import type { Said } from '../entry.ts';
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

/** Whether the caller is an Owner of the whole instance, on a credential no scope narrows. */
export const ownsAllAsking = (caller: Asking) => caller.holds.credentialScope == null && ownsInstance(caller.holds);

/** Who asks, or why they are refused (`asking`), and any workload's session, which changes no one's access. */
export function managing(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, vault: Deciding, at: number): Asking | Refusal {
  const caller = asking(seen, shown, vault, at);
  // A workload's session changes no one's access, whatever its scope holds, as 0.14's router refused it (docs/design/workload-access.md, D15).
  if (!('refused' in caller) && caller.workload !== null) return { refused: 'workload_cannot_issue' };
  return caller;
}

/** An entry of a change a caller asks: who asked, on what, and what it mentions. */
export function said(action: LogAction, caller: Asking, shown: { request: string | null; ip: string | null }, objects: string[], detail: Record<string, unknown>): Said {
  return {
    kept: true,
    action,
    actor: caller.principal,
    credential: caller.credential.id,
    request: shown.request,
    ip: shown.ip,
    objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, ...objects],
    detail,
  };
}

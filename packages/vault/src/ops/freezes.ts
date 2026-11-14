import { freezeTarget } from '@coffre/core/identity';
import type { Answers, FreezeChanges, Presented, WorkloadFreeze, WorkloadUnfreeze } from '@coffre/core/vault';
import { bindings, credentials, policy, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerParts, refusedTo } from '../caller.ts';
import { amended, part, type Operation, type Parts, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Deciding } from '../vault.ts';
import { managing, ownsAllAsking, said } from './asking.ts';
import type { Operations } from './index.ts';
import { presented } from './input.ts';
import { managesSealed, projectsOf, runs, serviceParts, type ServiceIn } from './services.ts';

/** The longest reason a freeze keeps, as the route takes it. */
const MOST_REASON = 400;

/** Text as Postgres keeps it, of 1 to `most` characters, with nothing around it: no NUL, no half of a surrogate pair. */
const reasonAsked = (value: unknown, most: number): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= most && value.trim() === value && !value.includes('\0') && Buffer.from(value).toString() === value;

/**
 * A workload's use frozen, or the freeze lifted (`workload.freeze`,
 * `workload.unfreeze`; docs/design/workload-access.md, 8.2): a field of the
 * row it stops, which keeps every session, code and binding under it, so
 * that lifting it restores service with no new sign-in. The instance's is
 * the policy row's, which an Owner of the whole instance sets on a
 * session; a service account's, one of its bindings' or one of its
 * workloads' sessions' is that row's, which whoever manages the service
 * account sets (`managesService`), freezing as lifting. A freeze asked of
 * what is frozen keeps its time, and changes nothing; so does a lift of
 * what is not.
 *
 * Its decision reads what says who manages the service account: its row,
 * its grants, their places and roles, the environments of its projects
 * and the instance's setting, and the caller's holdings there. It is made
 * on the rows the vault wrote (`managesSealed`), and only then is a row
 * written behind the vault refused, `tampered`, so that nobody who may not
 * is told of one.
 */
function freezing(frozen: boolean) {
  return (input: Presented & (WorkloadFreeze | WorkloadUnfreeze), vault: Deciding): Operation<Parts, Answers['workload.freeze']> => {
    const shown = presented(input);
    const { target } = input;
    const reason = frozen ? (input as WorkloadFreeze).reason : null;
    if (typeof target !== 'string' || target.length > MOST_REASON || freezeTarget(target) !== target || target.startsWith('credential:') || (frozen && !reasonAsked(reason, MOST_REASON))) {
      throw new TypeError("a freeze names its target as freezeTarget spells it, the instance, a service account, a binding or a session (an upstream credential's is upstream.freeze), and a freeze says why in 1 to 400 characters");
    }
    const action = frozen ? 'workload.freeze' : 'workload.unfreeze';
    const kind = target === 'instance' ? 'instance' : (target.slice(0, target.indexOf(':')) as 'token' | 'binding' | 'session');
    const id = target.slice(target.indexOf(':') + 1);
    // The service account it is of: by its id, or the member of the binding or the workload's session it names.
    const service: ServiceIn = kind === 'token' ? target
      : kind === 'binding' ? sql`(SELECT b.principal FROM bindings b WHERE b.id = ${id}::uuid)`
      : kind === 'session' ? sql`(SELECT c.principal FROM credentials c WHERE c.id = ${id}::uuid)`
      : null;
    const read = {
      // What the caller holds where the service account holds something, and what says who manages it.
      ...callerParts(shown.token, projectsOf(service)),
      ...serviceParts(service),
      instanceRow: part(policy, kind === 'instance' ? sql`${policy.onlyRow}` : sql`false`),
      bindingRow: part(bindings, kind === 'binding' ? sql`${bindings.id} = ${id}::uuid` : sql`false`),
      sessionRow: part(credentials, kind === 'session' ? sql`${credentials.id} = ${id}::uuid` : sql`false`),
    };
    type Read = Seen<typeof read>;
    /** What it names, as far as the rows read have it. */
    const objects = (seen: Read) => [
      ...seen.account.map((row) => `principal:${row.id}`),
      ...seen.bindingRow.map((row) => `binding:${row.id}`),
      ...seen.sessionRow.map((row) => `credential:${row.id}`),
    ];
    return {
      read,
      denied: refusedTo(action, shown, vault.workloads, { objects }),
      decide(seen: Read, at: number, unsealed: Unsealed<typeof read>) {
        const caller = managing(seen, shown, vault, at);
        if ('refused' in caller) return caller;
        const now = new Date(at);
        /** The change: the field written, or, as it is already, nothing but the entry that says so. */
        const made = (was: Date | null, write: (frozenAt: Date | null) => Write) => {
          const detail = { target, ...(frozen ? { reason } : {}) };
          if ((was !== null) === frozen) {
            return { writes: [], entry: said(action, caller, shown, objects(seen), { ...detail, unchanged: true }), answer: { target, frozenAt: was?.toISOString() ?? null } };
          }
          return { writes: [write(frozen ? now : null)], entry: said(action, caller, shown, objects(seen), detail), answer: { target, frozenAt: frozen ? now.toISOString() : null } };
        };

        if (kind === 'instance') {
          if (!runs(caller) || !ownsAllAsking(caller)) return { refused: 'no_access' };
          // The row is always there: without it every workload is frozen, and a lift would have nothing to write.
          const [row] = seen.instanceRow;
          if (row === undefined) return { refused: 'tampered' };
          return made(row.workloadsFrozenAt, (frozenAt) => amended(policy, row, { workloadsFrozenAt: frozenAt, changedAt: now, changedBy: caller.principal }));
        }

        const [account] = seen.account;
        const [bound] = seen.bindingRow;
        const [session] = seen.sessionRow;
        // A binding or a session of the service account, in its generation, not revoked: the account was read as the row's
        // member, and is held to it all the same.
        const ofIt = (row: { principal: string; generation: number; revokedAt: Date | null } | undefined) =>
          row !== undefined && row.principal === account!.id && row.generation === account!.generation && row.revokedAt === null;
        // What it names, live: an active service account, or one of its bindings, or one of its workloads' sessions.
        const live = account !== undefined && account.status === 'active' && account.id.startsWith('token:')
          && (kind === 'token' || (kind === 'binding' ? ofIt(bound) : ofIt(session) && session!.kind === 'workload'));
        if (!live || !managesSealed(caller, seen, account.id, at)) {
          // Whoever runs the instance manages every service account: one whose row is written behind the vault is theirs to be told of.
          return runs(caller) && Object.values(unsealed).some((count) => count > 0) ? { refused: 'tampered' } : { refused: 'no_access' };
        }
        // A row written behind the vault is not a row that is absent: a grant of the service's hidden, a place's protection edited.
        if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
        if (kind === 'token') return made(account.frozenAt, (frozenAt) => amended(principals, account, { frozenAt }));
        if (kind === 'binding') return made(bound!.frozenAt, (frozenAt) => amended(bindings, bound!, { frozenAt }));
        return made(session!.frozenAt, (frozenAt) => amended(credentials, session!, { frozenAt }));
      },
    };
  };
}

export const freezeOperations: Operations<FreezeChanges> = {
  'workload.freeze': freezing(true),
  'workload.unfreeze': freezing(false),
};

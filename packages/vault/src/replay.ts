import { EVERYWHERE, isInstanceRole, isScope, normalScope, type InstanceRole, type Scope } from '@coffre/core/access';
import type { StoredEntry } from '@coffre/core/audit';
import type { AccessFault, FaultGrant } from '@coffre/core/vault';

import { ACCESS_ACTIONS, type GrantRow, type Member, type Place } from './store.ts';

export { ACCESS_ACTIONS };

/**
 * Why the members and grants in the database do not follow from the
 * vault's entries, or null when they do; `describeAccessFault` words it.
 * Every change to either is logged in the transaction that makes it, with
 * the row's times taken from its entry, so replaying the allowed ones from
 * the first gives the tables back, and a row the log does not explain was
 * written around the vault: a grant inserted with the database's own login,
 * a removal undone.
 *
 * `state` is the allowed access entries replayed (`apply`), each after its
 * MAC was checked, in the snapshot `rows` and `stored` were read in.
 *
 * Grants are compared as they are live at `at`. Clearing one that has
 * lapsed changes nothing anyone holds, so it is not logged.
 */
export function replayFault(state: Replayed, rows: readonly Member[], storedGrants: readonly GrantRow[], at: number): AccessFault | null {
  const { members, held } = state;
  const stored = new Map(rows.map((member) => [member.principal, member]));
  for (const principal of [...new Set([...stored.keys(), ...members.keys()])].sort()) {
    const [inStore, inLog] = [stored.get(principal), members.get(principal)];
    if (inLog === undefined) return { kind: 'unlogged-member', principal };
    if (inStore === undefined) return { kind: 'missing-member', principal };
    const same = (field: keyof LoggedMember) => (field === 'scope' ? JSON.stringify(inStore.scope) === JSON.stringify(inLog.scope) : inStore[field] === inLog[field]);
    const fields = MEMBER_FIELDS.filter(([field]) => !same(field)).map(([, column]) => column);
    if (fields.length > 0) return { kind: 'member-differs', principal, fields };
  }

  const live = (grant: GrantRow) => grant.expiresAt === null || grant.expiresAt > at;
  const logged = new Set([...held.values()].flatMap((grantsOf) => [...grantsOf.values()]).filter(live).map(grantKey));
  const inStore = new Set(storedGrants.filter(live).map(grantKey));
  const extra = [...inStore].sort().find((grant) => !logged.has(grant));
  if (extra !== undefined) return { kind: 'unlogged-grant', grant: faultGrant(extra) };
  const missing = [...logged].sort().find((grant) => !inStore.has(grant));
  if (missing !== undefined) return { kind: 'missing-grant', grant: faultGrant(missing) };
  return null;
}

/** A member as the log says they are: their row, but for the MAC, which only the store has. */
export type LoggedMember = Omit<Member, 'mac'>;

/** Who the log says is a member, and what each holds, as far as it has been replayed. */
export type Replayed = { members: Map<string, LoggedMember>; held: Map<string, Map<string, GrantRow>> };

/** One access entry, authenticated, applied to `state`; a fault when it changes someone never admitted. */
export function apply(state: Replayed, row: StoredEntry): AccessFault | null {
  const principal = row.subjectPrincipal!;
  const detail = JSON.parse(row.metadata) as Record<string, unknown>;
  const place = placeOf(row, detail);
  const grantsOf = state.held.get(principal) ?? new Map<string, GrantRow>();
  state.held.set(principal, grantsOf);
  const before = state.members.get(principal);
  const changed = { statusChangedAt: row.occurredAt, statusChangedBy: row.actor };
  switch (row.action) {
    case 'member.add':
    case 'member.restore':
      state.members.set(principal, {
        principal,
        status: 'active',
        ...standingIn(detail),
        generation: before?.generation ?? 0,
        createdAt: before?.createdAt ?? row.occurredAt,
        createdBy: before?.createdBy ?? row.actor,
        accessSeq: row.seq,
        ...changed,
      });
      return null;
    case 'member.owner':
    case 'member.role':
      if (before === undefined) return { kind: 'unadmitted-change', seq: Number(row.seq), principal };
      state.members.set(principal, { ...before, ...standingIn(detail), accessSeq: row.seq });
      return null;
    case 'member.remove': {
      if (before === undefined) return { kind: 'unadmitted-change', seq: Number(row.seq), principal };
      // A removal names the generation it moved to; one before this format
      // was always the next.
      const generation = typeof detail.generation === 'number' ? detail.generation : before.generation + 1;
      state.members.set(principal, { ...before, status: 'removed', role: 'member', scope: EVERYWHERE, generation, accessSeq: row.seq, ...changed });
      grantsOf.clear();
      return null;
    }
    case 'access.grant':
      grantsOf.set(placeKey(place), {
        principal,
        ...place,
        role: detail.role as string,
        expiresAt: detail.expiresAt === null ? null : Date.parse(detail.expiresAt as string),
        grantedAt: row.occurredAt,
        grantedBy: row.actor,
      });
      if (before !== undefined) state.members.set(principal, { ...before, accessSeq: row.seq });
      return null;
    case 'access.revoke':
      grantsOf.delete(placeKey(place));
      if (before !== undefined) state.members.set(principal, { ...before, accessSeq: row.seq });
      return null;
  }
  return null;
}

/**
 * The instance role an entry gives: its `role` and `scope`, or, in one
 * 0.4 wrote, whether it made them an owner, an Admin everywhere.
 */
function standingIn(detail: Record<string, unknown>): { role: InstanceRole; scope: Scope } {
  if (typeof detail.role !== 'string') return { role: detail.owner === true ? 'admin' : 'member', scope: EVERYWHERE };
  const role = isInstanceRole(detail.role) ? detail.role : 'member';
  return { role, scope: role !== 'member' && isScope(detail.scope) ? normalScope(detail.scope) : EVERYWHERE };
}

/** A member's fields, and the columns a fault names them by. */
const MEMBER_FIELDS = [
  ['status', 'status'],
  ['role', 'role'],
  ['scope', 'scope'],
  ['generation', 'generation'],
  ['createdAt', 'created_at'],
  ['createdBy', 'created_by'],
  ['statusChangedAt', 'status_changed_at'],
  ['statusChangedBy', 'status_changed_by'],
  ['accessSeq', 'access_seq'],
] as const satisfies readonly (readonly [keyof LoggedMember, string])[];

/**
 * The place an access entry is about: its project and environment, or, with
 * neither, every project, which it names as a path (`*`, or `*` and a slug).
 */
function placeOf(row: StoredEntry, detail: Record<string, unknown>): Place {
  if (row.projectId !== null || row.environmentId !== null) {
    return { projectId: row.projectId, environmentId: row.environmentId, environmentSlug: null };
  }
  const slug = typeof detail.place === 'string' ? detail.place.split('/')[1] : undefined;
  return { projectId: null, environmentId: null, environmentSlug: slug ?? null };
}

/** A grant's place: its environment, or its project when it has none, or every project's path. */
function placeKey(place: Place): string {
  return place.environmentId ?? place.projectId ?? (place.environmentSlug === null ? '*' : `*/${place.environmentSlug}`);
}

function grantKey(grant: GrantRow): string {
  return JSON.stringify([
    grant.principal,
    grant.projectId,
    grant.environmentId,
    grant.environmentSlug,
    grant.role,
    grant.expiresAt,
    grant.grantedAt,
    grant.grantedBy,
  ]);
}

function faultGrant(key: string): FaultGrant {
  const [principal, projectId, environmentId, environmentSlug, role] = JSON.parse(key) as [string, string | null, string | null, string | null, string];
  return { principal, projectId, environmentId, environmentSlug, role };
}

import type { GrantRow, Member, Store } from './store.ts';

/** Every entry that changes who is a member or what they hold. */
export const ACCESS_ACTIONS = [
  'principal.admit',
  'principal.restore',
  'principal.owner',
  'principal.remove',
  'grant.create',
  'grant.update',
  'grant.revoke',
] as const;

/**
 * Why the members and grants in the store do not follow from the log, or
 * null when they do. Every change to either is logged in the transaction
 * that makes it, so replaying the allowed ones from the first entry gives
 * the tables back, and a row the log does not explain was written around
 * the vault: a grant inserted into its SQLite, a removal undone.
 *
 * Grants are compared as they are live at `at`. Clearing one that has
 * lapsed changes nothing anyone holds, so it is not logged.
 */
export function replay(store: Store, at: number): string | null {
  const members = new Map<string, Member>();
  const grants = new Map<string, Map<string, GrantRow>>();
  for (const row of store.logOf(ACCESS_ACTIONS)) {
    const principal = row.subject!;
    const detail = JSON.parse(row.detail) as Record<string, unknown>;
    const place = { projectId: detail.projectId as string, environmentId: detail.environmentId as string | null };
    const held = grants.get(principal) ?? new Map<string, GrantRow>();
    grants.set(principal, held);
    switch (row.action) {
      case 'principal.admit':
      case 'principal.restore':
        members.set(principal, { principal, status: 'active', owner: detail.owner === true, since: row.at, by: row.actor });
        break;
      case 'principal.owner': {
        const member = members.get(principal);
        if (member === undefined) return `entry ${row.seq} changes ${principal}, whom the log never admitted`;
        member.owner = detail.owner === true;
        break;
      }
      case 'principal.remove':
        members.set(principal, { principal, status: 'removed', owner: false, since: row.at, by: row.actor });
        held.clear();
        break;
      case 'grant.create':
      case 'grant.update':
        held.set(placeKey(place), {
          principal,
          ...place,
          role: detail.role as string,
          expiresAt: detail.expiresAt === null ? null : Date.parse(detail.expiresAt as string),
          grantedAt: row.at,
          grantedBy: row.actor,
        });
        break;
      case 'grant.revoke':
        held.delete(placeKey(place));
        break;
    }
  }

  const stored = new Map(store.allMembers().map((member) => [member.principal, member]));
  for (const principal of [...new Set([...stored.keys(), ...members.keys()])].sort()) {
    const [inStore, inLog] = [stored.get(principal), members.get(principal)];
    if (inLog === undefined) return `the store has ${principal} as a member, whom the log never admitted`;
    if (inStore === undefined) return `the log admits ${principal}, whom the store does not have`;
    const fields = (['status', 'owner', 'since', 'by'] as const).filter((field) => inStore[field] !== inLog[field]);
    if (fields.length > 0) return `the store's ${principal} differs from the log's in ${fields.join(', ')}`;
  }

  const live = (grant: GrantRow) => grant.expiresAt === null || grant.expiresAt > at;
  const logged = new Set([...grants.values()].flatMap((held) => [...held.values()]).filter(live).map(grantKey));
  const inStore = new Set(store.allGrants().filter(live).map(grantKey));
  const extra = [...inStore].sort().find((grant) => !logged.has(grant));
  if (extra !== undefined) return `the store holds a grant the log never gave: ${describe(extra)}`;
  const missing = [...logged].sort().find((grant) => !inStore.has(grant));
  if (missing !== undefined) return `the log gives a grant the store does not hold: ${describe(missing)}`;
  return null;
}

function placeKey(place: { projectId: string; environmentId: string | null }): string {
  return JSON.stringify([place.projectId, place.environmentId]);
}

function grantKey(grant: GrantRow): string {
  return JSON.stringify([
    grant.principal,
    grant.projectId,
    grant.environmentId,
    grant.role,
    grant.expiresAt,
    grant.grantedAt,
    grant.grantedBy,
  ]);
}

function describe(key: string): string {
  const [principal, projectId, environmentId, role] = JSON.parse(key) as [string, string, string | null, string];
  return `${principal} as ${role} on ${projectId}${environmentId === null ? '' : `/${environmentId}`}`;
}

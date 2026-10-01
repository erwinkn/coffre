import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import type { GrantRow, Member } from './store.ts';

/**
 * The MAC over each member's row and grants: what makes a row written
 * around the vault, by anyone who can write the database but does not hold
 * its signing key, one the vault refuses rather than trusts.
 *
 * One MAC per member, over the row and the member's grants as a sorted set,
 * lapsed ones included, rather than one per row: a grant deleted fails it as
 * surely as one added or edited. `access_seq` is in it too, so a genuine row
 * put back from before a later change still names the older entry, which the
 * log has moved past (vault.ts, `#integrity`).
 *
 * A change to what is covered is a new version of the tuple, never an edit.
 */

/** The key member rows are sealed under, derived from the signing key: one more secret to hold, not one more to keep. */
export function rowKey(signingKey: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', signingKey, new Uint8Array(0), 'coffre.vault.rows.v1', 32));
}

export function memberMac(key: Buffer, member: Omit<Member, 'mac'>, grants: readonly GrantRow[]): Buffer {
  const held = grants
    .map((grant) => [
      grant.environmentId === null ? 'project' : 'environment',
      grant.environmentId ?? grant.projectId,
      grant.role,
      grant.expiresAt,
      grant.grantedAt,
      grant.grantedBy,
    ])
    .map((tuple) => JSON.stringify(tuple))
    .sort();
  const tuple = [
    'coffre.vault.member.v1',
    member.principal,
    member.status,
    member.owner,
    member.generation,
    member.accessSeq.toString(),
    member.createdAt,
    member.createdBy,
    member.statusChangedAt,
    member.statusChangedBy,
    held,
  ];
  return createHmac('sha256', key).update(JSON.stringify(tuple)).digest();
}

/** Whether `member`'s MAC is the vault's, over this row and these grants. */
export function sealed(key: Buffer, member: Member, grants: readonly GrantRow[]): boolean {
  const expected = memberMac(key, member, grants);
  return member.mac.length === expected.length && timingSafeEqual(member.mac, expected);
}

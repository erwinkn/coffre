import { createHash } from 'node:crypto';

import { isCredentialScope, type CallerKind, type CredentialScope, type InstanceRole, type Scope } from '@coffre/core/access';
import { TOMBSTONE } from '@coffre/core/schemas';
import type { CredentialColumns, EnvironmentColumns, SecretColumns, VersionColumns } from '@coffre/core/vault';
import { storedRole } from '@coffre/db/grants';

import type { CredentialInput, EnvironmentInput, Input, InputGrant, Nature, PrincipalInput, SecretInput } from './inputs.ts';

/**
 * The tables' rows as the objects of the 0.15 log (inputs.ts): what a seal
 * covers, made from a row's columns alone. One mapping for every reader and
 * writer of a row, the use path's statement (use.ts) and the change path
 * (plan, PR 4) alike, so that what one seals the other checks. A row's other
 * columns, bookkeeping the app updates outside any change (a credential's
 * `last_used_at`), are no part of its object (docs/design/sealed-inputs.md).
 *
 * Each function takes the columns as plain values, whichever query read
 * them: times in ms since the epoch, uuids as text. Each object is made
 * from its own rows: an environment is deleted when its own slug is a
 * tombstone, not its project's (a project's deletion writes its
 * environments' changes, plan PR 4b). The one column of another row an
 * object holds is an environment's project's archival, which 0.14 decides
 * on, kept apart from its own; a project's archive changes each of its
 * environments. A key's source is its newest reference row's while that
 * row has not ended.
 */

/** A credential's columns: `credentials` (a session, a token, a workload's session), as the app sends them too (`prepare`). */
export type { CredentialColumns };

/**
 * A credential: a person's on a `user:` principal, a workload's session, or
 * a bearer's token. A scope that does not parse as one reaches nothing.
 */
export function credentialObject(row: CredentialColumns): CredentialInput {
  const caller: CallerKind = row.principal.startsWith('user:') ? 'person' : row.kind === 'workload' ? 'workload' : 'bearer';
  return { kind: 'credential', id: row.id, principal: row.principal, caller, scope: scopeOf(row.scope), expiresAt: row.expiresAt, revoked: row.revoked, generation: row.generation };
}

function scopeOf(stored: string | null): CredentialScope | null {
  if (stored === null) return null;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(stored);
  } catch {}
  return isCredentialScope(parsed) ? parsed : [];
}

/** A member's grant as its object holds it, from its row (`vault_grants`): an environment's with that environment's project. */
type GrantColumns = Pick<InputGrant, 'projectId' | 'environmentId' | 'environmentSlug' | 'role' | 'expiresAt'>;

/** A member's object, from their row (its role and scope as `storedRole` reads them) and their grants, lapsed ones too. */
export function principalObject(member: { principal: string; status: string; generation: number; role: InstanceRole; scope: Scope }, grants: readonly GrantColumns[]): PrincipalInput {
  return {
    kind: 'principal',
    principal: member.principal,
    status: member.status === 'active' ? 'active' : 'removed',
    generation: member.generation,
    role: member.role,
    scope: member.scope,
    grants: grants.map(({ projectId, environmentId, environmentSlug, role, expiresAt }) => ({ projectId, environmentId, environmentSlug, role, expiresAt })),
  };
}

/** A member's role and scope as stored (`owner`, `role`, `scope`), as their object holds them. */
export function memberStanding(row: { owner: boolean; role: string | null; scope: string | null }): { role: InstanceRole; scope: Scope } {
  return storedRole(row);
}

/**
 * A key's columns (`secrets`, its version's in `secret_versions`),
 * unarchived: an archived key is no object (`VersionColumns`,
 * `SecretColumns`: @coffre/core/vault, the app sends them too).
 */
export type { SecretColumns, VersionColumns };

/**
 * A key: its current version, nature and wrapped data key, or a plain
 * one's digest; or, for a reference, its source, whose value and nature
 * are its own (R23): a reference holds no version, and is a secret by
 * itself. A reference that has ended holds neither (`ended`).
 */
export function secretObject(row: SecretColumns): SecretInput {
  const { id, projectId, environmentId, source, version } = row;
  if (source !== null || version === null) {
    return { kind: 'secret', id, projectId, environmentId, version: '', nature: 'secret', key: null, digest: null, source, reference: source === null ? null : row.reference };
  }
  const nature: Nature = version.sensitive ? 'sensitive' : version.plaintext !== null ? 'plain' : 'secret';
  const key = nature === 'plain' ? null : { kekProvider: version.kekProvider, kekId: version.kekId, kekVersion: version.kekVersion, bytes: version.wrappedDek };
  const digest = nature === 'plain' ? plainDigest(version.plaintext!) : null;
  return { kind: 'secret', id, projectId, environmentId, version: version.id, nature, key, digest, source: null, reference: null };
}

/** A plain value's digest, as its object holds it: SHA-256 of its UTF-8 text, base64. */
export function plainDigest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('base64');
}

/** An environment's columns (`environments`), as the app sends them too (@coffre/core/vault). */
export type { EnvironmentColumns };

/**
 * An environment: its slug, as it was before any tombstone, whether it was
 * deleted, and its own archival and its project's, apart. A deleted one
 * holds no project's archival: it reads nothing, and its project archived
 * or restored after changes nothing of it.
 */
export function environmentObject(row: EnvironmentColumns): EnvironmentInput {
  const tomb = row.slug.indexOf(TOMBSTONE);
  return {
    kind: 'environment', id: row.id, projectId: row.projectId, slug: tomb < 0 ? row.slug : row.slug.slice(0, tomb),
    owner: row.owner, parentId: row.parentId, protected: row.protected === true, deleted: tomb >= 0, archived: row.archived, projectArchived: tomb < 0 && row.projectArchived,
  };
}

/**
 * The roles and the policy: each one `log_config` row whose value is the
 * object as the change that made it wrote it (0022's `change_input`:
 * genesis's `value`), read whole. A value that is not that object fails
 * its seal.
 */
export function configObject(value: string): Input {
  return JSON.parse(value) as Input;
}

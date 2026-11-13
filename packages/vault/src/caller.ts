import { EVERYWHERE, isCredentialScope, isInstanceRole, isScope, type CredentialScope, type Holdings, type Permission, type Policy, type RoleDefinition } from '@coffre/core/access';
import type { credentials, environments, grants, identities, principals, roles } from '@coffre/db/schema';

import type { Row } from './rows.ts';

/**
 * Who is asking (docs/design/0.16.md, "A use"): from a credential's rows,
 * each under the vault's MAC, to what its holder may do now. One function
 * of the rows and the time, for a use and for a change alike.
 */

/** A caller's rows, as one read found them. A row whose MAC is not the vault's is not among them. */
export type CallerRows = {
  credential: readonly Row<typeof credentials>[];
  principal: readonly Row<typeof principals>[];
  identity: readonly Row<typeof identities>[];
  grants: readonly Row<typeof grants>[];
  roles: readonly Row<typeof roles>[];
  /** The environments the request is about: a grant on one names it alone, and a protected one says so in its row. */
  environments: readonly Row<typeof environments>[];
};

export type Caller = {
  /** `user:<email>` or `token:<name>`. */
  principal: string;
  credential: Row<typeof credentials>;
  /** What they hold, as `@coffre/core/access` decides on it. */
  holds: Holdings;
};

/** The credential kinds decided here. A workload's session and an MCP connection come with their own rows, bindings and ancestors, not built yet. */
const KINDS: ReadonlySet<string> = new Set(['browser', 'cli', 'service', 'personal', 'handle']);

function parsed(json: string | null): unknown {
  if (json === null) return null;
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

/**
 * The caller, or null: no such credential, one expired, revoked or frozen,
 * one of a member removed since it was issued, or of an account since
 * unlinked. One answer for all of these, so that none says which.
 */
export function callerOf(rows: CallerRows, at: number): Caller | null {
  const [credential] = rows.credential;
  const [principal] = rows.principal;
  if (credential === undefined || principal === undefined || !KINDS.has(credential.kind)) return null;
  // What a trust binding issued stands while its binding does: with the workloads.
  if (credential.createdBy.startsWith('binding:')) return null;
  if (credential.revokedAt !== null || credential.frozenAt !== null || credential.expiresAt.getTime() <= at) return null;
  // A removal moves the generation on: everything issued before it is dead, whatever its own row says.
  if (principal.id !== credential.principal || principal.status !== 'active' || principal.generation !== credential.generation) return null;
  // A browser's session is an account's, always; any credential that names an account goes with it.
  if (credential.identityId === null ? credential.kind === 'browser' : !rows.identity.some((identity) => identity.id === credential.identityId && identity.revokedAt === null)) return null;

  const service = principal.id.startsWith('token:');
  const scope = principal.scope === null ? EVERYWHERE : parsed(principal.scope);
  if (!isScope(scope)) return null;
  // A session carries no scope. A token's is its cap, and one that does not read as a scope reaches nothing.
  const session = credential.kind === 'browser' || credential.kind === 'cli';
  const cap = parsed(credential.scope);
  const credentialScope: CredentialScope | null = session ? null : isCredentialScope(cap) ? cap : [];

  const projectOf = new Map(rows.environments.map((environment) => [environment.id, environment.projectId]));
  const definitions = (instance: boolean) =>
    Object.fromEntries(rows.roles.filter((role) => role.instance === instance).map((role): [string, RoleDefinition] => [role.id, { name: role.name, description: role.description, permissions: role.permissions as Permission[], protected: role.protected as Permission[] }]));
  return {
    principal: principal.id,
    credential,
    holds: {
      role: !service && isInstanceRole(principal.role) ? principal.role : 'member',
      scope,
      // A grant on an environment names only it: its project is the environment's row's. One on a place this request is not about decides nothing here.
      grants: rows.grants
        .filter((grant) => grant.principal === principal.id && (grant.expiresAt === null || grant.expiresAt.getTime() > at))
        .map((grant) => ({ projectId: grant.projectId ?? projectOf.get(grant.environmentId!) ?? null, environmentId: grant.environmentId, role: grant.role })),
      credentialScope,
      // A role with no row is no role: the roles are the rows read, never the ones that ship.
      policy: { roles: definitions(false), instanceRoles: definitions(true) as Policy['instanceRoles'], protected: rows.environments.filter((environment) => environment.protected).map((environment) => environment.id), protectedIn: {} },
      service,
      kind: service ? 'bearer' : 'person',
    },
  };
}

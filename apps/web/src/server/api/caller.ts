import {
  PERMISSIONS,
  PROJECT_ONLY_PERMISSIONS,
  roleGrants,
  type Permission,
  type Role,
} from '../../../../../packages/core/src/access.ts';
import type { Queryable } from '../../../../../packages/db/src/database.ts';
import { callerGrants } from '../../../../../packages/db/src/queries.ts';

export type PrincipalRef = { type: 'user' | 'service'; id: string };

export type CallerGrant = {
  id: string;
  /** The project the grant is in, also for a grant on one of its environments. */
  projectId: string;
  /** Null for a grant on the whole project. */
  environmentId: string | null;
  role: Role;
  expiresAt: Date | null;
};

/**
 * Who is asking, and everything they hold. Loaded once per request; every
 * permission check after that is a plain function of this value.
 */
export type Caller = {
  principal: PrincipalRef;
  /** An active member, or a root admin. Everyone else only reaches sign-in. */
  registered: boolean;
  /** Named in COFFRE_ROOT_ADMINS: everything, everywhere. */
  isRootAdmin: boolean;
  /** Root admins and active users with the instance `owner` role. */
  isOwner: boolean;
  instanceRole: 'user' | 'owner' | 'root-admin';
  /** Live grants only. */
  grants: CallerGrant[];
};

/** A place a permission applies to: a project, or one of its environments. */
export type Place = { projectId: string; environmentId?: string | null };

export function isConfiguredRootAdmin(
  principal: PrincipalRef,
  rootAdmins: readonly string[],
): boolean {
  return principal.type === 'user' && rootAdmins.includes(principal.id);
}

/** The principal and their live grants, in one query. */
export async function loadCaller(
  db: Queryable,
  principal: PrincipalRef,
  rootAdmins: readonly string[],
  now = new Date(),
): Promise<Caller> {
  const ref = { type: principal.type, id: principal.id };
  // A root admin may do everything, so there is nothing to load.
  if (isConfiguredRootAdmin(principal, rootAdmins)) {
    return { principal: ref, registered: true, isRootAdmin: true, isOwner: true, instanceRole: 'root-admin', grants: [] };
  }
  const row = await callerGrants(db, principal, now);
  const active = row?.active === true;
  const isOwner = active && principal.type === 'user' && row?.instanceRole === 'owner';
  const held = active ? row!.grants.map((grant) => ({ ...grant, role: grant.role as Role })) : [];

  return {
    principal: ref,
    registered: active,
    isRootAdmin: false,
    isOwner,
    instanceRole: isOwner ? 'owner' : 'user',
    grants: held,
  };
}

/**
 * Whether the caller may do `permission` at `place`.
 *
 *   on a project       its project grant; owners also manage every project
 *   on an environment  its environment grant or its project's grant
 *
 * An environment grant never reaches up to the project: `developer` on
 * `market/prod` does not let anyone rename `market`.
 */
export function can(caller: Caller, permission: Permission, place: Place): boolean {
  if (caller.isRootAdmin) return true;
  const environmentId = place.environmentId ?? null;
  if (environmentId === null && caller.isOwner && PROJECT_ONLY_PERMISSIONS.includes(permission)) {
    return true;
  }
  return caller.grants.some(
    (grant) =>
      grant.projectId === place.projectId &&
      (grant.environmentId === null || grant.environmentId === environmentId) &&
      roleGrants(grant.role, permission),
  );
}

/** Everything the caller may do at `place`, in catalogue order. */
export function permissionsAt(caller: Caller, place: Place): Permission[] {
  return PERMISSIONS.filter((permission) => can(caller, permission, place));
}

/** Whether the caller holds anything anywhere in a project, which is what lets them see it. */
export function seesProject(caller: Caller, projectId: string): boolean {
  return caller.isOwner || caller.grants.some((grant) => grant.projectId === projectId);
}

/** Whether the caller holds `permission` anywhere at all. */
export function canAnywhere(caller: Caller, permission: Permission): boolean {
  return caller.isRootAdmin || caller.grants.some((grant) => roleGrants(grant.role, permission));
}

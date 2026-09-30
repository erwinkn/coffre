import {
  allows,
  PERMISSIONS,
  roleGrants,
  type Permission,
  type Place,
  type Role,
} from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';

import { formatMember } from './paths.ts';

export type { Place };

export type PrincipalRef = { type: 'user' | 'service'; id: string };

export type CallerGrant = {
  /** The project the grant is in, also for a grant on one of its environments. */
  projectId: string;
  /** Null for a grant on the whole project. */
  environmentId: string | null;
  role: Role;
  expiresAt: Date | null;
};

/**
 * Who is asking, and everything they hold. Loaded from the vault once per
 * request; every permission check after that is a plain function of this
 * value. The vault checks again whatever touches a key or a grant.
 */
export type Caller = {
  principal: PrincipalRef;
  /** An active member, or a root admin. Everyone else only reaches sign-in. */
  registered: boolean;
  /** Named in the vault's COFFRE_ROOT_ADMINS: everything, everywhere. */
  isRootAdmin: boolean;
  /** Root admins and active users with the instance `owner` role. */
  isOwner: boolean;
  instanceRole: 'user' | 'owner' | 'root-admin';
  /** Live grants only. */
  grants: CallerGrant[];
};

/** The principal and their live grants, in one vault call. */
export async function loadCaller(vault: Vault, principal: PrincipalRef): Promise<Caller> {
  return callerFrom({ type: principal.type, id: principal.id }, await vault.access(formatMember(principal)));
}

export function callerFrom(principal: PrincipalRef, access: Access): Caller {
  return {
    principal,
    registered: access.status === 'active',
    isRootAdmin: access.isRootAdmin,
    isOwner: access.isOwner,
    instanceRole: access.isRootAdmin ? 'root-admin' : access.isOwner ? 'owner' : 'user',
    grants: access.grants.map((grant) => ({
      projectId: grant.projectId,
      environmentId: grant.environmentId,
      role: grant.role,
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt),
    })),
  };
}

/**
 * Whether the caller may do `permission` at `place`: the rule the vault
 * applies too, from core.
 *
 *   on a project       its project grant; owners also manage every project
 *   on an environment  its environment grant or its project's grant
 */
export function can(caller: Caller, permission: Permission, place: Place): boolean {
  return allows(caller, permission, place);
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

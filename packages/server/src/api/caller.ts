import {
  allows,
  instanceRoleGrants,
  PERMISSIONS,
  roleGrants,
  type GrantPlace,
  type InstanceRole,
  type Permission,
  type Place,
  type Role,
  type Scope,
} from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';

import { formatMember } from './paths.ts';

export type { Place };

export type PrincipalRef = { type: 'user' | 'service'; id: string };

/** A grant: `projectId` is the project it is in, also for a grant on one of its environments (`GrantPlace`). */
export type CallerGrant = GrantPlace & {
  role: Role;
  expiresAt: Date | null;
};

/**
 * Who is asking, and everything they hold. Loaded from the vault once per
 * request; every permission check after that is a plain function of this
 * value, `Holdings` in @coffre/core/access. The vault checks again
 * whatever touches a key or a grant.
 */
export type Caller = {
  principal: PrincipalRef;
  /** An active member, or a root admin. Everyone else only reaches sign-in. */
  registered: boolean;
  /** A member the vault refuses because their record failed its integrity check. */
  tampered: boolean;
  /** The membership this request authenticated, checked again before linking accounts. */
  generation: number;
  /** Named in the vault's COFFRE_ROOT_ADMINS: everything, everywhere. */
  isRootAdmin: boolean;
  /** Their instance role and where it applies, projects by id; `member` everywhere for services and strangers. */
  role: InstanceRole;
  scope: Scope;
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
    tampered: access.status === 'tampered',
    generation: access.generation,
    isRootAdmin: access.isRootAdmin,
    role: access.role,
    scope: access.scope,
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
 *   on a project       its project grant, or their instance role, when its scope takes in all of the project
 *   on an environment  its environment grant, its project's grant, or their instance role, when its scope takes it in
 */
export function can(caller: Caller, permission: Permission, place: Place): boolean {
  return allows(caller, permission, place);
}

/** Everything the caller may do at `place`, in catalogue order. */
export function permissionsAt(caller: Caller, place: Place): Permission[] {
  return PERMISSIONS.filter((permission) => can(caller, permission, place));
}

/** A project, or one of its environments, as a permission check names it. */
export function placeOf(project: { id: string }, environment: { id: string; slug: string } | null): Place {
  return environment === null
    ? { projectId: project.id }
    : { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug };
}

/**
 * Whether the caller holds anything anywhere in a project, which is what
 * lets them see it: a grant on it or in it, or an instance role whose
 * scope takes in it or one of its environments.
 */
export function seesProject(caller: Caller, project: { id: string; environments: { id: string; slug: string }[] }): boolean {
  const places = [placeOf(project, null), ...project.environments.map((environment) => placeOf(project, environment))];
  return places.some((place) => PERMISSIONS.some((permission) => can(caller, permission, place)));
}

/** Whether the caller holds `permission` anywhere at all: by a grant, or by their instance role. */
export function canAnywhere(caller: Caller, permission: Permission): boolean {
  return caller.isRootAdmin || instanceRoleGrants(caller.role, permission) || caller.grants.some((grant) => roleGrants(grant.role, permission));
}

/** How the API names someone's instance role: theirs, or `root-admin` for a root admin. */
export function instanceRoleOf(holder: { isRootAdmin: boolean; role: InstanceRole }): InstanceRole | 'root-admin' {
  return holder.isRootAdmin ? 'root-admin' : holder.role;
}

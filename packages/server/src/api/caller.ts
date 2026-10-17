import {
  allows,
  instanceRoleGrants,
  PERMISSIONS,
  roleGrants,
  type GrantPlace,
  type InstanceRole,
  type Permission,
  type Place as CorePlace,
  type CredentialScope,
  type Role,
  type Scope,
} from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';

import { formatMember } from './paths.ts';

/**
 * A place a permission is checked at. A personal config's names its owner
 * and the environment it is a config of: `can` decides it on them, never
 * on grants or roles at the personal config itself.
 */
export type Place = CorePlace | (Extract<CorePlace, { environmentSlug: string | null }> & {
  personal: { owner: string; parent: { environmentId: string; environmentSlug: string | null } };
});

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
  /** An active member. Everyone else only reaches sign-in. */
  registered: boolean;
  /** A member the vault refuses because their record failed its integrity check. */
  tampered: boolean;
  /** The membership this request authenticated, checked again before linking accounts. */
  generation: number;
  /** Their instance role and where it applies, projects by id; `member` everywhere for services and strangers. */
  role: InstanceRole;
  scope: Scope;
  /** Live grants only. */
  grants: CallerGrant[];
  /** The scope of the service token or binding the request came in on, past which nothing reaches; null for a session. */
  credentialScope: CredentialScope | null;
};

/** The principal and their live grants, in one vault call. */
export async function loadCaller(vault: Vault, principal: PrincipalRef): Promise<Caller> {
  return callerFrom({ type: principal.type, id: principal.id }, await vault.access(formatMember(principal)));
}

export function callerFrom(principal: PrincipalRef, access: Access, credentialScope: CredentialScope | null = null): Caller {
  return {
    principal,
    registered: access.status === 'active',
    tampered: access.status === 'tampered',
    generation: access.generation,
    role: access.role,
    scope: access.scope,
    grants: access.grants.map((grant) => ({
      projectId: grant.projectId,
      environmentId: grant.environmentId,
      role: grant.role,
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt),
    })),
    credentialScope,
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
  if (!('personal' in place)) return allows(caller, permission, place);
  const parent = { projectId: place.projectId, ...place.personal.parent };
  // A personal config's values: its owner's alone, while they read its parent; no grant or role reaches them,
  // an Owner's included (docs/design/forking.md, section 3). The vault decides the same.
  if (SECRET_PERMISSIONS.includes(permission)) {
    return caller.principal.type === 'user' && formatMember(caller.principal) === place.personal.owner && allows(caller, 'secret.read', parent);
  }
  // Anything else, as at its parent: its log, to whoever reads the parent's.
  return allows(caller, permission, parent);
}

const SECRET_PERMISSIONS: readonly Permission[] = ['secret.read', 'secret.write', 'secret.archive'];

/** Everything the caller may do at `place`, in catalogue order. */
export function permissionsAt(caller: Caller, place: Place): Permission[] {
  return PERMISSIONS.filter((permission) => can(caller, permission, place));
}

/** A project, or one of its environments, as a permission check names it: a personal config with its owner and parent. */
export function placeOf(
  project: { id: string },
  environment: { id: string; slug: string; owner?: string | null; parentId?: string | null; parentSlug?: string | null } | null,
): Place {
  if (environment === null) return { projectId: project.id };
  const place = { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug };
  if (environment.owner == null) return place;
  // A parent unknown here matches no grant: the owner's read of it is not assumed.
  return { ...place, personal: { owner: environment.owner, parent: { environmentId: environment.parentId ?? '', environmentSlug: environment.parentSlug ?? null } } };
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

/** Whether the caller holds `permission` anywhere at all: by a grant, or by their instance role; within their credential's scope. */
export function canAnywhere(caller: Caller, permission: Permission): boolean {
  if (caller.credentialScope !== null && !caller.credentialScope.some((grant) => roleGrants(grant.role, permission))) return false;
  return instanceRoleGrants(caller.role, permission) || caller.grants.some((grant) => roleGrants(grant.role, permission));
}

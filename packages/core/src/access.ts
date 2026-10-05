/**
 * Who may do what: seven permissions and the six roles that bundle them.
 *
 * Deliberately constants and not tables or a policy language. A grant names
 * one role for one member on one place, and a check is a lookup in this file,
 * so authorisation stays something you can read end to end.
 */

export const PERMISSIONS = [
  'secret.read',
  'secret.write',
  'secret.archive',
  'audit.read',
  'environment.manage',
  'grant.manage',
  'project.manage',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/**
 * Permissions that only make sense on a project. Granting
 * `environment.manage` on one environment would be incoherent: what it
 * authorises is creating that environment's siblings.
 */
export const PROJECT_ONLY_PERMISSIONS: readonly Permission[] = [
  'environment.manage',
  'grant.manage',
  'project.manage',
];

export const ROLES = {
  viewer: {
    name: 'Viewer',
    description: 'Read secret values.',
    permissions: ['secret.read'],
  },
  developer: {
    name: 'Developer',
    description: 'Read and write secrets.',
    permissions: ['secret.read', 'secret.write'],
  },
  maintainer: {
    name: 'Maintainer',
    description: 'Read, write and retire secrets, and manage environments.',
    permissions: ['secret.read', 'secret.write', 'secret.archive', 'environment.manage'],
  },
  'access-manager': {
    name: 'Access manager',
    description: 'Manage who has access. Cannot read secret values.',
    permissions: ['grant.manage'],
  },
  auditor: {
    name: 'Auditor',
    description: 'Read the audit log. Cannot read secret values.',
    permissions: ['audit.read'],
  },
  owner: {
    name: 'Owner',
    description: 'Everything, including reading secret values.',
    permissions: [...PERMISSIONS],
  },
} as const satisfies Record<string, {
  name: string;
  description: string;
  permissions: readonly Permission[];
}>;

export type Role = keyof typeof ROLES;

export const ROLE_NAMES = Object.keys(ROLES) as Role[];

export function isRole(value: string): value is Role {
  return Object.hasOwn(ROLES, value);
}

export function roleGrants(role: Role, permission: Permission): boolean {
  return (ROLES[role].permissions as readonly Permission[]).includes(permission);
}

/** Roles that hold a project-only permission can only be granted on a project. */
export function assignableToEnvironment(role: Role): boolean {
  return !ROLES[role].permissions.some((permission) =>
    PROJECT_ONLY_PERMISSIONS.includes(permission),
  );
}

/**
 * A place a permission applies to: a project, or one of its environments,
 * named by its slug too, which grants on every project match by. A slug
 * not read (null) matches no grant on a slug.
 */
export type Place =
  | { projectId: string; environmentId?: null }
  | { projectId: string; environmentId: string; environmentSlug: string | null };

/**
 * Where a grant applies, by the fields it fills (`grantKind`):
 *
 *   market        projectId
 *   market/dev    projectId and environmentId
 *   *             neither: every project, the ones created later too
 *   *, on dev     environmentSlug only: the environment of that slug in every project
 */
export type GrantPlace = {
  /** The project, also of an environment's grant; null only on every project. */
  projectId: string | null;
  environmentId: string | null;
  /** On every project, the one environment slug it covers; null for all of them, and on a project's grant. */
  environmentSlug: string | null;
};

/**
 * What a grant's fields say it is on, or null when they say nothing
 * coherent: an environment without its project, as a grant whose
 * environment row is gone reads, or a slug beside an id. A grant is on
 * every project only when it names no place at all; anything else that
 * lacks a field covers nothing.
 */
export function grantKind(grant: GrantPlace): 'project' | 'environment' | 'every-project' | null {
  if (grant.environmentId !== null) return grant.projectId !== null && grant.environmentSlug === null ? 'environment' : null;
  if (grant.projectId !== null) return grant.environmentSlug === null ? 'project' : null;
  return 'every-project';
}

/** Every project, as a path names it. */
export const EVERY_PROJECT = '*';

/** A grant on every project as a path: `*`, or `*` and the environment slug it covers in each. */
export function everyProjectPath(environmentSlug: string | null): string {
  return environmentSlug === null ? EVERY_PROJECT : `${EVERY_PROJECT}/${environmentSlug}`;
}

/**
 * What someone holds: everything a permission check reads. The app builds
 * it from what the vault says once per request; the vault builds it from
 * its own store. Both then ask the same functions below, so the rules
 * cannot drift apart.
 */
export type Holdings = {
  /** Named in the vault's configuration: everything, everywhere. */
  isRootAdmin: boolean;
  /** Root admins and active users with the instance `owner` role. */
  isOwner: boolean;
  /** Live grants only. */
  grants: readonly (GrantPlace & { role: Role })[];
};

/**
 * Whether a grant at `grant` reaches `place`:
 *
 *   market        market and each of its environments
 *   market/dev    market/dev
 *   *             every project and every environment
 *   *, on dev     each environment whose slug is dev, in every project
 *
 * An environment's grant never reaches up to its project, whether it names
 * the environment or its slug.
 */
export function covers(grant: GrantPlace, place: Place): boolean {
  switch (grantKind(grant)) {
    case 'environment':
      return grant.projectId === place.projectId && grant.environmentId === (place.environmentId ?? null);
    case 'project':
      return grant.projectId === place.projectId;
    case 'every-project':
      return grant.environmentSlug === null || (place.environmentId != null && place.environmentSlug !== null && place.environmentSlug === grant.environmentSlug);
    case null:
      return false;
  }
}

/**
 * Whether `holder` may do `permission` at `place`: a grant that covers it
 * gives the role's permissions there, and grants add up. Owners also manage
 * every project. `developer` on `market/prod` does not let anyone rename
 * `market`.
 */
export function allows(holder: Holdings, permission: Permission, place: Place): boolean {
  if (holder.isRootAdmin) return true;
  if (place.environmentId == null && holder.isOwner && PROJECT_ONLY_PERMISSIONS.includes(permission)) {
    return true;
  }
  return holder.grants.some((grant) => covers(grant, place) && roleGrants(grant.role, permission));
}

/**
 * Whether the actor may manage grants at this place: on a project or its
 * environments, with `grant.manage` on the project; on every project, as an
 * instance owner or a root admin only.
 */
export function mayManageAccess(actor: Holdings, place: GrantPlace): boolean {
  const kind = grantKind(place);
  if (kind === 'every-project') return actor.isOwner || actor.isRootAdmin;
  return kind !== null && place.projectId !== null && allows(actor, 'grant.manage', { projectId: place.projectId });
}

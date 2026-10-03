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

/** A place a permission applies to: a project, or one of its environments. */
export type Place = { projectId: string; environmentId?: string | null };

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
  grants: readonly { projectId: string; environmentId: string | null; role: Role }[];
};

/**
 * Whether `holder` may do `permission` at `place`.
 *
 *   on a project       its project grant; owners also manage every project
 *   on an environment  its environment grant or its project's grant
 *
 * An environment grant never reaches up to the project: `developer` on
 * `market/prod` does not let anyone rename `market`.
 */
export function allows(holder: Holdings, permission: Permission, place: Place): boolean {
  if (holder.isRootAdmin) return true;
  const environmentId = place.environmentId ?? null;
  if (environmentId === null && holder.isOwner && PROJECT_ONLY_PERMISSIONS.includes(permission)) {
    return true;
  }
  return holder.grants.some(
    (grant) =>
      grant.projectId === place.projectId &&
      (grant.environmentId === null || grant.environmentId === environmentId) &&
      roleGrants(grant.role, permission),
  );
}

/** Whether the actor may manage grants on this project. */
export function mayManageAccess(actor: Holdings, place: Place): boolean {
  return allows(actor, 'grant.manage', { projectId: place.projectId });
}

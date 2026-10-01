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

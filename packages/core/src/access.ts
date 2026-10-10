/**
 * Who may do what: seven permissions, the six project roles a grant names,
 * and the five instance roles a person holds across every project.
 *
 * Deliberately constants and not tables or a policy language. A grant names
 * one role for one member on one place, a person's instance role names one
 * role and its scope, and a check is a lookup in this file, so authorisation
 * stays something you can read end to end.
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
 * A person's role on the whole instance: what they hold in every project
 * their scope covers, before any grant. Service accounts are always
 * members, and hold only what their grants give. Admins and owners also
 * run the instance (`runsInstance`) when nothing narrows their scope.
 */
export const INSTANCE_ROLES = {
  member: {
    name: 'Member',
    description: 'Only what projects grant.',
    permissions: [],
  },
  auditor: {
    name: 'Auditor',
    description: 'Read the audit log. No secret values.',
    permissions: ['audit.read'],
  },
  developer: {
    name: 'Developer',
    description: 'Read and write secrets.',
    permissions: ['secret.read', 'secret.write'],
  },
  admin: {
    name: 'Admin',
    description: 'Manage people, service accounts, projects and access. No secret values.',
    permissions: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'],
  },
  owner: {
    name: 'Owner',
    description: 'Everything an admin does, and read every secret.',
    permissions: [...PERMISSIONS],
  },
} as const satisfies Record<string, {
  name: string;
  description: string;
  permissions: readonly Permission[];
}>;

export type InstanceRole = keyof typeof INSTANCE_ROLES;

export const INSTANCE_ROLE_NAMES = Object.keys(INSTANCE_ROLES) as InstanceRole[];

export function isInstanceRole(value: string): value is InstanceRole {
  return Object.hasOwn(INSTANCE_ROLES, value);
}

export function instanceRoleGrants(role: InstanceRole, permission: Permission): boolean {
  return (INSTANCE_ROLES[role].permissions as readonly Permission[]).includes(permission);
}

/** The roles that manage people and access: Admin, and Owner, which adds every secret. */
export function administers(role: InstanceRole): boolean {
  return role === 'admin' || role === 'owner';
}

/**
 * Which projects, or environments, a scope takes in: all of them, only
 * those listed, or all but those listed. Projects are listed by id, so a
 * rename keeps them; environments by slug, so `dev` is the `dev` of every
 * project, the ones made later too.
 */
export type Filter = 'all' | { only: string[] } | { except: string[] };

/**
 * Where a person's instance role applies: the projects it reaches, and the
 * environments in them, by slug. A grant reaches past it; nothing else does.
 *
 *   { projects: 'all', environments: { only: ['dev'] } }       every project's dev
 *   { projects: { except: [billing] }, environments: 'all' }   all but billing
 */
export type Scope = { projects: Filter; environments: Filter };

/** Every project and every environment. */
export const EVERYWHERE: Scope = { projects: 'all', environments: 'all' };

/** Whether a scope narrows nothing. */
export function unscoped(scope: Scope): boolean {
  return scope.projects === 'all' && scope.environments === 'all';
}

/** Whether a filter takes in a project's id or an environment's slug; one not read (null) is in none that lists. */
export function admits(filter: Filter, value: string | null | undefined): boolean {
  if (filter === 'all') return true;
  if (value == null) return false;
  return 'only' in filter ? filter.only.includes(value) : !filter.except.includes(value);
}

/**
 * One way to write each scope, which the vault seals and the log replays:
 * lists sorted, without repeats; an empty `except` is `all`. An empty
 * `only` stays: it takes in nothing.
 */
export function normalScope(scope: Scope): Scope {
  const normal = (filter: Filter): Filter => {
    if (filter === 'all') return 'all';
    if ('only' in filter) return { only: [...new Set(filter.only)].sort() };
    return filter.except.length === 0 ? 'all' : { except: [...new Set(filter.except)].sort() };
  };
  return { projects: normal(scope.projects), environments: normal(scope.environments) };
}

/** Whether `value` is a scope as `normalScope` writes it, and as the vault stores it. */
export function isScope(value: unknown): value is Scope {
  const isFilter = (filter: unknown): filter is Filter => {
    if (filter === 'all') return true;
    if (typeof filter !== 'object' || filter === null || Array.isArray(filter)) return false;
    const keys = Object.keys(filter);
    if (keys.length !== 1 || (keys[0] !== 'only' && keys[0] !== 'except')) return false;
    const list = (filter as Record<string, unknown>)[keys[0]];
    return Array.isArray(list) && list.every((item) => typeof item === 'string' && item.length > 0);
  };
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const { projects, environments, ...rest } = value as Record<string, unknown>;
  return Object.keys(rest).length === 0 && isFilter(projects) && isFilter(environments);
}

/**
 * A scope in words, its projects named as the caller has them (slugs, at
 * the API's edges): `All projects`, `All projects · dev only`,
 * `web, api`, `All projects but billing · all but prod`.
 */
export function scopeInWords(scope: Scope): string {
  const list = (names: string[]) => names.join(', ');
  const { projects, environments } = scope;
  const where = projects === 'all'
    ? 'All projects'
    : 'only' in projects
      ? (projects.only.length === 0 ? 'No projects' : list(projects.only))
      : `All projects but ${list(projects.except)}`;
  if (environments === 'all') return where;
  if ('only' in environments) return `${where} · ${environments.only.length === 0 ? 'no environments' : `${list(environments.only)} only`}`;
  return `${where} · all but ${list(environments.except)}`;
}

/**
 * A place a permission applies to: a project, or one of its environments,
 * named by its slug too, which a scope matches environments by. A slug not
 * read (null) is in no scope that names environments.
 */
export type Place =
  | { projectId: string; environmentId?: null }
  | { projectId: string; environmentId: string; environmentSlug: string | null };

/**
 * Whether a scope takes in a place. A project as a whole is in it only when
 * the scope keeps all of its environments: a role scoped to `dev` reaches
 * every `dev`, never a project around one.
 */
export function inScope(scope: Scope, place: Place): boolean {
  if (!admits(scope.projects, place.projectId)) return false;
  if (place.environmentId == null) return scope.environments === 'all';
  return admits(scope.environments, place.environmentSlug);
}

/**
 * Where a grant applies: a project (`environmentId` null), or one of its
 * environments, which names its project too.
 */
export type GrantPlace = {
  projectId: string | null;
  environmentId: string | null;
};

/**
 * What a grant's fields say it is on, or null when they say nothing
 * coherent: an environment without its project, as a grant whose
 * environment row is gone reads, or neither, as the grants on every project
 * of 0.4 read until the vault replaces them. Null covers nothing.
 */
export function grantKind(grant: GrantPlace): 'project' | 'environment' | null {
  if (grant.projectId === null) return null;
  return grant.environmentId === null ? 'project' : 'environment';
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
  /** `member` for service accounts, and for anyone not active. */
  role: InstanceRole;
  scope: Scope;
  /** Live grants only. */
  grants: readonly (GrantPlace & { role: Role })[];
};

/** Someone who holds nothing: a stranger, a removed member, a tampered row. */
export const NOTHING: Holdings = { isRootAdmin: false, role: 'member', scope: EVERYWHERE, grants: [] };

/**
 * Whether a grant at `grant` reaches `place`:
 *
 *   market        market and each of its environments
 *   market/dev    market/dev
 *
 * An environment's grant never reaches up to its project.
 */
export function covers(grant: GrantPlace, place: Place): boolean {
  switch (grantKind(grant)) {
    case 'environment':
      return grant.projectId === place.projectId && grant.environmentId === (place.environmentId ?? null);
    case 'project':
      return grant.projectId === place.projectId;
    case null:
      return false;
  }
}

/**
 * Whether `holder` may do `permission` at `place`: their instance role
 * gives its permissions inside its scope, a grant that covers the place
 * gives its role's there, and they add up. A Developer scoped to `dev` with
 * `viewer` on `billing` reads and writes every `dev`, and reads all of
 * `billing`.
 */
export function allows(holder: Holdings, permission: Permission, place: Place): boolean {
  if (holder.isRootAdmin) return true;
  if (instanceRoleGrants(holder.role, permission) && inScope(holder.scope, place)) return true;
  return holder.grants.some((grant) => covers(grant, place) && roleGrants(grant.role, permission));
}

/**
 * Whether the actor may give or take grants at this place: with
 * `grant.manage` there, from a project grant or an instance role whose
 * scope takes it in. A grant on a project reaches all its environments, so
 * an admin scoped to `dev` manages `market/dev`'s grants, not `market`'s.
 */
export function mayManageAccess(actor: Holdings, place: Place): boolean {
  return allows(actor, 'grant.manage', place);
}

/**
 * Whether the holder runs the instance: a root admin, or an Admin or Owner
 * whose scope narrows nothing. They add and remove people and service
 * accounts, set instance roles, read the instance's own log entries
 * (sign-ins, people), and change its settings. A scoped Admin manages only
 * inside its scope, so it does none of these.
 */
export function runsInstance(holder: Holdings): boolean {
  return holder.isRootAdmin || (administers(holder.role) && unscoped(holder.scope));
}

/**
 * Whether the holder may make a project: an Admin or Owner whose scope
 * takes the new one in as a whole. A scope listing only some projects does
 * not list the new one; one that keeps only some environments does not
 * hold the project around them.
 */
export function makesProjects(holder: Holdings): boolean {
  if (holder.isRootAdmin) return true;
  const { projects, environments } = holder.scope;
  return administers(holder.role) && environments === 'all' && (projects === 'all' || 'except' in projects);
}

export {
  convertEveryProjectGrants,
  type Conversion,
  type ConversionInput,
  type ConvertedGrant,
  type EveryProjectGrant,
  type Narrowed,
} from './access-conversion.ts';

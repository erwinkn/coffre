/**
 * Who may do what: eight permissions, the seven project roles a grant names,
 * and the five instance roles a person holds across every project.
 *
 * Deliberately constants and not tables or a policy language. A grant names
 * one role for one member on one place, a person's instance role names one
 * role and its scope, and a check is a lookup in this file, so authorisation
 * stays something you can read end to end.
 */

/**
 * `secret.read` hands a value back: a reveal, `coffre get`, `coffre run`'s
 * values. `secret.use` uses it without handing it back: a placeholder in a
 * person's app, the credential proxy filling it in (docs/design/credential-proxy.md).
 * Every role that reads uses too. What a person gets is the narrower of the
 * two and the key's sensitivity: a sensitive key is only ever used.
 */
export const PERMISSIONS = [
  'secret.read',
  'secret.use',
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

/**
 * What a role holds: `permissions` in an environment that is not
 * protected, and on its project; `protected`, what a person holds of it in
 * a protected environment (docs/design/roles.md). Project-wide permissions
 * are in `permissions` alone: a project is never protected. A service
 * account holds `permissions` everywhere.
 */
export type RoleDefinition = {
  name: string;
  description: string;
  permissions: readonly Permission[];
  protected: readonly Permission[];
};

export const ROLES = {
  viewer: {
    name: 'Viewer',
    description: 'Read and use secret values.',
    permissions: ['secret.read', 'secret.use'],
    protected: ['secret.use'],
  },
  contributor: {
    name: 'Contributor',
    description: 'Use and write secrets, never read them: apps get placeholders through the credential proxy.',
    permissions: ['secret.use', 'secret.write'],
    protected: ['secret.use', 'secret.write'],
  },
  developer: {
    name: 'Developer',
    description: 'Read, use and write secrets.',
    permissions: ['secret.read', 'secret.use', 'secret.write'],
    protected: ['secret.use', 'secret.write'],
  },
  maintainer: {
    name: 'Maintainer',
    description: 'Read, use, write and retire secrets, and manage environments.',
    permissions: ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage'],
    protected: ['secret.use', 'secret.write', 'secret.archive'],
  },
  'access-manager': {
    name: 'Access manager',
    description: 'Manage who has access. Cannot read secret values.',
    permissions: ['grant.manage'],
    protected: [],
  },
  auditor: {
    name: 'Auditor',
    description: 'Read the audit log. Cannot read secret values.',
    permissions: ['audit.read'],
    protected: ['audit.read'],
  },
  owner: {
    name: 'Owner',
    description: 'Everything, including reading secret values.',
    permissions: [...PERMISSIONS],
    protected: [...PERMISSIONS].filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission)),
  },
} as const satisfies Record<string, RoleDefinition>;

/** A role coffre ships, as its default says (`ROLES`); an Owner may edit any but Owner. */
export type BuiltinRole = keyof typeof ROLES;

/** A project role by id: one coffre ships, or one an Owner made (`ROLE_ID`), as the instance's policy defines it. */
export type Role = string;

export const ROLE_NAMES = Object.keys(ROLES) as BuiltinRole[];

/** A custom role's id: lowercase, as a slug, and no built-in one's. */
export const ROLE_ID = /^[a-z][a-z0-9-]{1,31}$/;

/** Whether `value` names a role of `policy`'s: a built-in one, as it ships, unless told. */
export function isRole(value: string, policy: Policy = DEFAULT_POLICY): value is Role {
  return Object.hasOwn(policy.roles, value);
}

/** Whether `value` is one of the roles coffre ships. */
export function isBuiltinRole(value: string): value is BuiltinRole {
  return Object.hasOwn(ROLES, value);
}

/** Whether `role` holds `permission` where nothing is protected, as `policy` defines it: as it ships, unless told. */
export function roleGrants(role: Role, permission: Permission, policy: Policy = DEFAULT_POLICY): boolean {
  return definitionOf(policy, role)?.permissions.includes(permission) ?? false;
}

/** Roles that hold a project-only permission can only be granted on a project. */
export function assignableToEnvironment(role: Role, policy: Policy = DEFAULT_POLICY): boolean {
  const definition = definitionOf(policy, role);
  return definition !== undefined && !definition.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission));
}

/** A project role's definition in `policy`, or undefined for none. */
export function definitionOf(policy: Policy, role: Role): RoleDefinition | undefined {
  return Object.hasOwn(policy.roles, role) ? policy.roles[role] : undefined;
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
    description: 'None.',
    permissions: [],
    protected: [],
  },
  auditor: {
    name: 'Auditor',
    description: 'Read the audit log. No secret values.',
    permissions: ['audit.read'],
    protected: ['audit.read'],
  },
  developer: {
    name: 'Developer',
    description: 'Read, use and write secrets.',
    permissions: ['secret.read', 'secret.use', 'secret.write'],
    protected: ['secret.use', 'secret.write'],
  },
  admin: {
    name: 'Admin',
    description: 'Manage people, service accounts, projects and access. No secret values.',
    permissions: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'],
    protected: ['audit.read'],
  },
  owner: {
    name: 'Owner',
    description: 'Everything, every secret included.',
    permissions: [...PERMISSIONS],
    protected: [...PERMISSIONS].filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission)),
  },
} as const satisfies Record<string, RoleDefinition>;

export type InstanceRole = keyof typeof INSTANCE_ROLES;

export const INSTANCE_ROLE_NAMES = Object.keys(INSTANCE_ROLES) as InstanceRole[];

export function isInstanceRole(value: string): value is InstanceRole {
  return Object.hasOwn(INSTANCE_ROLES, value);
}

/** Whether an instance role holds `permission` where nothing is protected, as `policy` defines it: as it ships, unless told. */
export function instanceRoleGrants(role: InstanceRole, permission: Permission, policy: Policy = DEFAULT_POLICY): boolean {
  return (policy.instanceRoles[role]?.permissions ?? []).includes(permission);
}

/**
 * The instance's access policy, which the vault keeps (docs/design/roles.md):
 * its project roles, the built-ins as an Owner edited them and the ones an
 * Owner made, its instance roles as edited, and which environments are
 * protected, by id. The vault decides on it, and tells the app it with
 * every member's access.
 */
export type Policy = {
  roles: Readonly<Record<Role, RoleDefinition>>;
  instanceRoles: Readonly<Record<InstanceRole, RoleDefinition>>;
  protected: readonly string[];
  /**
   * The protected environments by their project's id, each with its slug,
   * which a scoped role's filters read: what a grant on a whole project
   * reaches of them. A fork's slug is null until its row is written.
   */
  protectedIn: Readonly<Record<string, readonly { environmentId: string; slug: string | null }[]>>;
};

/** The policy before any Owner edits it: every role as it ships, and no environment protected. */
export const DEFAULT_POLICY: Policy = { roles: ROLES, instanceRoles: INSTANCE_ROLES, protected: [], protectedIn: {} };

/**
 * How long the policy keeps an environment's id protected before its row
 * is written, a fork's in flight, which writes it one call later; one with
 * no row after that is a fork refused or abandoned. Until then it is a
 * place a check on its project weighs (`protectedWithin`), which no scoped
 * instance role's filters take in, so short. A fork writes its row only
 * well within it, so no row ever brings back an id the policy dropped.
 */
export const UNWRITTEN_FORK_MS = 10 * 60 * 1000;

/** The roles an Owner may not edit: Owner, which holds everything, and the instance's Member, which holds nothing. */
export const FIXED_ROLES = { roles: ['owner'] as readonly string[], instanceRoles: ['owner', 'member'] as readonly InstanceRole[] };

/**
 * What is wrong with a role's definition, or null: a name and a
 * description; known permissions, each once; reading implies using, in
 * each column; and the protected column holds no more than the other, and
 * nothing project-wide.
 */
export function definitionProblem(definition: RoleDefinition): string | null {
  const { name, description, permissions } = definition;
  if (typeof name !== 'string' || name.trim() === '' || name.length > 40 || /[\u0000-\u001f\u007f]/.test(name)) return 'a role needs a name of 1 to 40 characters';
  if (typeof description !== 'string' || description.length > 200 || /[\u0000-\u001f\u007f]/.test(description)) return 'a description is 200 characters at most';
  for (const column of [permissions, definition.protected]) {
    if (!Array.isArray(column) || column.some((permission) => !PERMISSIONS.includes(permission)) || new Set(column).size !== column.length) {
      return `a role holds permissions from ${PERMISSIONS.join(', ')}, each once`;
    }
    if (column.includes('secret.read') && !column.includes('secret.use')) return 'a role that reads values uses them too: add secret.use';
  }
  if (definition.protected.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission))) return 'a project-wide permission has one column: a project is never protected';
  if (definition.protected.some((permission) => !permissions.includes(permission))) return 'a role holds no more in a protected environment than in one that is not';
  return null;
}

/** A definition as the vault stores and compares it: each column in catalogue order. */
export function normalDefinition(definition: RoleDefinition): RoleDefinition {
  const ordered = (column: readonly Permission[]) => PERMISSIONS.filter((permission) => column.includes(permission));
  return { name: definition.name.trim(), description: definition.description, permissions: ordered(definition.permissions), protected: ordered(definition.protected) };
}

/**
 * Whether `definition` gives `holder` `permission` at `place`: its
 * protected column for a person in a protected environment, its other
 * column anywhere else, and project-wide permissions from that one always.
 */
export function holds(definition: RoleDefinition | undefined, permission: Permission, place: Place, holder: Pick<Holdings, 'policy' | 'service'>): boolean {
  if (definition === undefined) return false;
  if (PROJECT_ONLY_PERMISSIONS.includes(permission)) return definition.permissions.includes(permission);
  return (guarded(holder, place) ? definition.protected : definition.permissions).includes(permission);
}

/** In a policy's `protected`, every environment: the policy the vault falls back on when it cannot read its own (`CLOSED_POLICY`). */
export const EVERY_ENVIRONMENT = '*';

/** Whether `holder` holds the protected column at `place`: a person, in an environment the policy protects. */
export function guarded(holder: Pick<Holdings, 'policy' | 'service'>, place: Place): boolean {
  if (holder.service === true || place.environmentId == null) return false;
  return protects(holder.policy ?? DEFAULT_POLICY, place.environmentId);
}

/** Whether `policy` protects the environment of this id: by name, or every one (`EVERY_ENVIRONMENT`). */
export function protects(policy: Policy, environmentId: string): boolean {
  return policy.protected.includes(environmentId) || policy.protected.includes(EVERY_ENVIRONMENT);
}

/** The roles that manage people and access: Admin, and Owner, which adds every secret. */
export function administers(role: InstanceRole): boolean {
  return role === 'admin' || role === 'owner';
}

/**
 * Whether a role and its scope make someone an Owner of the whole
 * instance: the one standing the instance always keeps at least one of,
 * and the one its bootstrap gives while it has none. An Owner scoped to
 * `market` owns market, not the instance.
 */
export function ownsInstance(standing: { role: InstanceRole; scope: Scope }): boolean {
  return standing.role === 'owner' && unscoped(standing.scope);
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
 * What a service account's token or trust binding carries, its scope:
 * grants as the account's are, a role on a project or an environment, each
 * one the account held and its issuer could give when it was issued.
 * Nothing changes it after. A request made with it holds what both it and
 * the account hold now (`allows`), so narrowing the account narrows it, and
 * a grant the account gets later reaches no credential issued before:
 *
 *   account   developer on market/dev, then viewer on market/prod too
 *   token     developer on market/dev, issued before market/prod
 *   request   reads and writes market/dev, never market/prod
 *
 * A person's personal token carries one too, each grant one they held when
 * they made it (`delegable` roles only), and is weighed the same way
 * against what they hold now, by their instance role or their grants.
 *
 * Each grant keeps what its role held when the credential was issued, both
 * columns (`permissions`), and no more than its issuer held, so neither a
 * role an Owner widens later nor its issuer widens the credential
 * (docs/design/roles.md, section 8, rule 3).
 */
export type CredentialScope = readonly ScopeGrant[];

/** What a role holds, or a credential's grant held when it was issued: where nothing is protected, and in a protected environment. */
export type Columns = { normal: readonly Permission[]; protected: readonly Permission[] };

/**
 * One place of a credential's scope: a role there, and what it held when
 * the credential was issued (`issuedGrant`). One kept by a release before
 * 0.10, its role's name alone, holds that role as it ships, a constant no
 * edit changes, so it never widens either: a built-in role's, or nothing
 * for any other name.
 */
export type ScopeGrant = GrantPlace & { role: Role; permissions?: Columns };

/**
 * A grant of a scope with what its role holds now in `policy`, kept: what a
 * credential issued now carries. Given what its issuer holds at its place
 * (`heldColumns`), no more than that either, column by column, so that
 * neither the role nor the issuer, widened later, widens the credential:
 *
 *   viewer edited to read in prod; Ada, a Developer, uses there
 *   Ada's token, viewer on market      read, use / use
 *   Developer widened to read in prod  the token still only uses prod
 */
export function issuedGrant(grant: GrantPlace & { role: Role }, policy: Policy = DEFAULT_POLICY, held?: Columns): ScopeGrant {
  const definition = definitionOf(policy, grant.role);
  const within = (column: readonly Permission[] = [], cap?: readonly Permission[]) => (cap === undefined ? [...column] : column.filter((permission) => cap.includes(permission)));
  return {
    projectId: grant.projectId,
    environmentId: grant.environmentId,
    role: grant.role,
    permissions: { normal: within(definition?.permissions, held?.normal), protected: within(definition?.protected, held?.protected) },
  };
}

/**
 * What `holder` holds at `place` in each column a credential's grant there
 * keeps (`issuedGrant`): `normal`, as if nothing were protected; `protected`,
 * as a person in a protected environment. At an environment, as if it were
 * protected; at a project, in an environment of it that no grant names,
 * the least they hold in any of its environments, those it protects later
 * included: only what covers the whole project reaches one.
 *
 *   Ada, a Developer of market, at market    read, use, write / use, write
 */
export function heldColumns(holder: Holdings, place: Place): Columns {
  const policy = holder.policy ?? DEFAULT_POLICY;
  const held = (protect: readonly string[], at: Place) => PERMISSIONS.filter((permission) => allows({ ...holder, policy: { ...policy, protected: protect } }, permission, at));
  const anyOf: Place = place.environmentId != null ? place : { projectId: place.projectId, environmentId: '', environmentSlug: null };
  return { normal: held([], place), protected: held([EVERY_ENVIRONMENT], anyOf) };
}

/**
 * The protected environments a grant at `place` reaches beyond it: for a
 * grant on a project, each of its environments `policy` protects, where a
 * person holds the protected column and a service account the other one;
 * none for a grant on an environment. Whoever checks a grant on a project
 * against what someone holds checks it there too (`givesService`,
 * `personalScope`): it reaches them.
 */
export function protectedWithin(policy: Policy, place: Place): Place[] {
  if (place.environmentId != null) return [];
  return (policy.protectedIn[place.projectId] ?? []).map(({ environmentId, slug }) => ({ projectId: place.projectId, environmentId, environmentSlug: slug }));
}

/** What a scope's grant holds, as it was issued, as a role holds it: whatever the role is now, which no edit changes. */
export function scopeDefinition(grant: ScopeGrant): RoleDefinition {
  if (grant.permissions !== undefined) return { name: grant.role, description: '', permissions: grant.permissions.normal, protected: grant.permissions.protected };
  // Kept before 0.10: the role as it ships, whatever an Owner made of it since.
  return isBuiltinRole(grant.role) ? ROLES[grant.role] : { name: grant.role, description: '', permissions: [], protected: [] };
}

/** The most places a scope asked for names: far more than any credential needs, and a bound on what a request makes the app check. */
export const MAX_SCOPE_PLACES = 1000;

/**
 * Whether a personal token's scope may name `role`: one that manages no
 * access. A token acting as its person reaches their secrets and places,
 * never who holds them, so it cannot hand anyone, itself included, more
 * than it was given. A project's Owner who wants a token for all of it
 * names `maintainer`.
 */
export function delegable(role: Role, policy: Policy = DEFAULT_POLICY): boolean {
  return isRole(role, policy) && !roleGrants(role, 'grant.manage', policy);
}

/** The roles a personal token's scope may name, in catalogue order. */
export function delegableRoles(policy: Policy = DEFAULT_POLICY): Role[] {
  return Object.keys(policy.roles).filter((role) => delegable(role, policy));
}

/** The roles a personal token's scope may name, as they ship. */
export const DELEGABLE_ROLES: readonly Role[] = delegableRoles();

/**
 * The longest a personal token lasts: a week. It is for an afternoon's
 * script or agent, and whoever needs it longer makes another, as a person,
 * rather than keep one around.
 */
export const MAX_PERSONAL_TOKEN_MINUTES = 7 * 24 * 60;

/**
 * A credential's scope, by path as the API names it, in words, each role
 * with its places: `developer on market/dev, api/dev; viewer on market/prod`.
 */
export function credentialScopeInWords(scope: Readonly<Record<string, string>>): string {
  const byRole = new Map<string, string[]>();
  for (const [path, role] of Object.entries(scope)) byRole.set(role, [...(byRole.get(role) ?? []), path]);
  return [...byRole].map(([role, paths]) => `${role} on ${paths.join(', ')}`).join('; ') || 'nothing';
}

/** Whether `value` is a credential's scope as the app stores it and the vault reads it: one grant a place, each role one that place takes. */
export function isCredentialScope(value: unknown): value is CredentialScope {
  if (!Array.isArray(value)) return false;
  const places = new Set<string>();
  const column = (list: unknown) => Array.isArray(list) && list.every((permission) => PERMISSIONS.includes(permission as Permission)) && new Set(list).size === list.length;
  return value.every((grant: unknown) => {
    if (typeof grant !== 'object' || grant === null || Array.isArray(grant)) return false;
    const { projectId, environmentId, role, permissions, ...rest } = grant as Record<string, unknown>;
    if (Object.keys(rest).length > 0 || typeof projectId !== 'string' || typeof role !== 'string') return false;
    // As issued, both columns; or, kept before 0.10, a built-in role's name alone, which holds it as it ships.
    if (!ROLE_ID.test(role)) return false;
    if (permissions === undefined) {
      if (!isBuiltinRole(role)) return false;
    } else {
      if (typeof permissions !== 'object' || permissions === null || Array.isArray(permissions)) return false;
      const { normal, protected: guarded, ...more } = permissions as Record<string, unknown>;
      if (Object.keys(more).length > 0 || !column(normal) || !column(guarded)) return false;
    }
    const definition = scopeDefinition(grant as ScopeGrant);
    if (environmentId !== null && (typeof environmentId !== 'string' || definition.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission)))) return false;
    const place = `${projectId}/${environmentId ?? ''}`;
    if (places.has(place)) return false;
    places.add(place);
    return true;
  });
}

/**
 * What someone holds: everything a permission check reads. The app builds
 * it from what the vault says once per request; the vault builds it from
 * its own store. Both then ask the same functions below, so the rules
 * cannot drift apart.
 */
export type Holdings = {
  /** `member` for service accounts, and for anyone not active. */
  role: InstanceRole;
  scope: Scope;
  /** Live grants only. */
  grants: readonly (GrantPlace & { role: Role })[];
  /**
   * The scope of the credential a request came in on, past which nothing
   * reaches; absent or null for a session's. A scope names places, so a
   * request made with one holds nothing of the instance's own: it does not
   * run the instance, read its whole log or make projects, whatever its
   * holder's instance role.
   */
  credentialScope?: CredentialScope | null;
  /** The instance's policy, its roles and protected environments, as the vault said it: as it ships, absent. */
  policy?: Policy;
  /** A service account's, which holds each role's normal column everywhere; a person's holds a protected environment's column there. */
  service?: boolean;
};

/** Someone who holds nothing: a stranger, a removed member, a tampered row. */
export const NOTHING: Holdings = { role: 'member', scope: EVERYWHERE, grants: [] };

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
  if (holder.credentialScope != null && !scopeHolds(holder, permission, place)) return false;
  const policy = holder.policy ?? DEFAULT_POLICY;
  if (inScope(holder.scope, place) && holds(policy.instanceRoles[holder.role], permission, place, holder)) return true;
  return holder.grants.some((grant) => covers(grant, place) && holds(definitionOf(policy, grant.role), permission, place, holder));
}

/**
 * Whether the credential a request came in on, a scoped token or binding,
 * leaves `permission` at `place` to its holder: always, for a session. A
 * personal config's owner holds its every permission by reading its parent
 * (docs/design/forking.md), and a token of theirs is still held to the
 * role its scope names there: a viewer's token reads it, and writes nothing.
 */
export function withinCredential(holder: Holdings, permission: Permission, place: Place): boolean {
  return holder.credentialScope == null || scopeHolds(holder, permission, place);
}

/** Whether the credential's scope covers `place` with a grant that held `permission` there when it was issued. */
function scopeHolds(holder: Holdings, permission: Permission, place: Place): boolean {
  return (holder.credentialScope ?? []).some((grant) => covers(grant, place) && holds(scopeDefinition(grant), permission, place, holder));
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
 * Whether the holder runs the instance: an Admin or Owner whose scope
 * narrows nothing. They add and remove people, set instance
 * roles, and change the instance's settings; they read its whole log too
 * (`readsWholeLog`). A scoped Admin manages only inside its scope, so it
 * does none of these.
 */
export function runsInstance(holder: Holdings): boolean {
  return holder.credentialScope == null && administers(holder.role) && unscoped(holder.scope);
}

/**
 * Who may set up service accounts themselves, the instance's setting: a
 * scope as a role's is, projects by id and environments by slug, which
 * only those who run the instance change. Inside it, any person gives a
 * service account what they hold, never more (`givesService`). Everywhere,
 * unless it says otherwise:
 *
 *   { projects: 'all', environments: { except: ['prod'] } }   CI for dev and staging; prod's takes an Admin
 */
export type ServiceSetting = Scope;

/**
 * Whether `holder` may give a service account `role` at `place`: where
 * they manage access, as anyone may; or inside the setting, where they hold
 * everything `role` does. A Developer on `market/dev` gives viewer or
 * developer there, never maintainer; a grant on `market` takes holding it
 * on all of `market`. `setting` is null for a service account, which sets
 * up none; a request on a credential with a scope sets none up either,
 * since what it set up would outlive it. A service account holds a role's
 * normal column even in a protected environment, so a person there, who
 * holds its protected column, gives none what they do not hold themselves:
 * a Developer of a protected prod, who only uses it, gives no viewer there.
 */
export function givesService(holder: Holdings, setting: ServiceSetting | null, role: Role, place: Place, kept?: RoleDefinition): boolean {
  if (mayManageAccess(holder, place)) return true;
  const policy = holder.policy ?? DEFAULT_POLICY;
  // What the grant holds: its role as the policy defines it, or what a credential kept of it (`issuesCredential`).
  const definition = kept ?? definitionOf(policy, role);
  // A role that holds nothing is given by whoever manages access there alone: by anyone else, it would be a grant an
  // Owner could fill in later, and under a policy the vault cannot read, every role but Owner's holds nothing.
  if (definition === undefined || definition.permissions.length === 0) return false;
  if (setting === null || holder.credentialScope != null || !inScope(setting, place)) return false;
  if (!definition.permissions.every((permission) => allows(holder, permission, place))) return false;
  // A grant on a whole project reaches its protected environments too, where the service holds the role's normal column:
  // the person giving it holds that there as well, or gives none.
  const inEnvironments = definition.permissions.filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission));
  return protectedWithin(policy, place).every((there) => inEnvironments.every((permission) => allows(holder, permission, there)));
}

/** Whether `holder` gives a service account anything anywhere among `places`: whether they set any up. */
export function setsUpServices(holder: Holdings, setting: ServiceSetting | null, places: readonly Place[]): boolean {
  if (runsInstance(holder)) return true;
  const roles = Object.keys((holder.policy ?? DEFAULT_POLICY).roles);
  return places.some((place) => roles.some((role) => givesService(holder, setting, role, place)));
}

/** A service account as `managesService` weighs it: its live grants, where they are, and who admitted it. */
export type ServiceAccount = {
  grants: readonly { role: Role; place: Place }[];
  /** The member who admitted it last (`user:…`), as its row says. */
  admittedBy: string | null;
};

/**
 * Whether `holder`, the member `actor`, manages a service account: issues
 * and revokes its tokens, adds and removes its trust bindings, changes its
 * grants and removes it. A credential for it reads everything it holds, so
 * they must reach every grant it holds, as if giving it (`givesService`):
 * a Developer on `dev` manages an account on `market/dev`, and not one that
 * holds `market/prod` too. One that holds nothing, only the person who
 * admitted it: anyone else's token for it would read whatever it is given
 * next. Those who run the instance manage every one.
 */
export function managesService(holder: Holdings, setting: ServiceSetting | null, actor: string, account: ServiceAccount): boolean {
  if (runsInstance(holder)) return true;
  if (account.grants.length === 0) return setting !== null && account.admittedBy === actor;
  return account.grants.every((grant) => givesService(holder, setting, grant.role, grant.place));
}

/**
 * Whether `holder`, the member `actor`, may issue a token or a trust
 * binding of `account` whose scope is `scope`: they manage the account
 * (`managesService`), and each grant of the scope is one they could give it
 * (`givesService`) and one it holds, every permission of its role there;
 * of a grant that keeps less than its role, every permission it `kept`, as
 * a binding replacing others keeps what they held.
 * For an account that holds `developer` on `market/dev`, a Developer of
 * `dev` issues `developer` or `viewer` there; nobody issues `market/prod`
 * for it, or `maintainer` on `market/dev`, until the account holds them.
 */
export function issuesCredential(
  holder: Holdings,
  setting: ServiceSetting | null,
  actor: string,
  account: ServiceAccount,
  scope: readonly { role: Role; place: Place; kept?: RoleDefinition }[],
): boolean {
  if (!managesService(holder, setting, actor, account)) return false;
  const policy = holder.policy ?? DEFAULT_POLICY;
  const held: Holdings = { ...NOTHING, policy, service: true, grants: account.grants.map(({ role, place }) => ({ projectId: place.projectId, environmentId: place.environmentId ?? null, role })) };
  return scope.every(({ role, place, kept }) => givesService(holder, setting, role, place, kept)
    && ((kept ?? definitionOf(policy, role))?.permissions.every((permission) => allows(held, permission, place)) ?? false));
}

/**
 * Whether the holder reads the whole log, the instance's own entries
 * (sign-ins, people, service accounts, settings) with every project's, and
 * verifies it: whoever holds `audit.read` by an instance role whose scope
 * narrows nothing, in both its columns, an Auditor's included: an Auditor
 * edited to read no protected environment's log reads every other place's,
 * and not the whole. Reading, not running: an Auditor of the whole
 * instance changes nothing it reads about. Anyone else reads the places
 * they hold `audit.read` in.
 */
export function readsWholeLog(holder: Holdings): boolean {
  const role = (holder.policy ?? DEFAULT_POLICY).instanceRoles[holder.role];
  return holder.credentialScope == null && unscoped(holder.scope)
    && role !== undefined && role.permissions.includes('audit.read') && role.protected.includes('audit.read');
}

/**
 * Whether the holder may make a project: an Admin or Owner whose scope
 * takes the new one in as a whole. A scope listing only some projects does
 * not list the new one; one that keeps only some environments does not
 * hold the project around them.
 */
export function makesProjects(holder: Holdings): boolean {
  const { projects, environments } = holder.scope;
  return holder.credentialScope == null && administers(holder.role) && environments === 'all' && (projects === 'all' || 'except' in projects);
}

export {
  convertEveryProjectGrants,
  type Conversion,
  type ConversionInput,
  type ConvertedGrant,
  type EveryProjectGrant,
  type Narrowed,
} from './access-conversion.ts';

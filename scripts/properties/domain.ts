/**
 * Coffre's domain as Hegel generators, for the property tests of every
 * package: instances, projects, environments, forks and `@me` overlays,
 * keys and their natures, references, roles and the policy an Owner edits,
 * grants, personal tokens, service tokens and trust bindings.
 *
 * An independent model: transcribed from the README's role tables and the
 * standing rules (docs/design/roles.md, docs/design/forking.md), never
 * imported from the code it checks, so a test that compares the two
 * compares two readings of the rules. Plain data only, no `@coffre/*`
 * import: each test maps it onto the types it calls.
 */
import type { TestCase } from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

export const PERMISSIONS = [
  'secret.read', 'secret.use', 'secret.write', 'secret.archive',
  'audit.read', 'environment.manage', 'grant.manage', 'project.manage',
] as const;
export type Permission = (typeof PERMISSIONS)[number];
/** Held on a project alone: a project is never protected, and an environment grant holds none. */
export const PROJECT_ONLY: readonly Permission[] = ['environment.manage', 'grant.manage', 'project.manage'];
const IN_ENVIRONMENTS = PERMISSIONS.filter((permission) => !PROJECT_ONLY.includes(permission));

/** What a role holds: where nothing is protected, and what a person holds of it in a protected environment. */
export type Columns = { permissions: readonly Permission[]; protected: readonly Permission[] };

/** The project roles as they ship (README, "Roles"). */
export const ROLES: Readonly<Record<string, Columns>> = {
  viewer: { permissions: ['secret.read', 'secret.use'], protected: ['secret.use'] },
  contributor: { permissions: ['secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] },
  developer: { permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] },
  maintainer: {
    permissions: ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage'],
    protected: ['secret.use', 'secret.write', 'secret.archive'],
  },
  'access-manager': { permissions: ['grant.manage'], protected: [] },
  auditor: { permissions: ['audit.read'], protected: ['audit.read'] },
  owner: { permissions: PERMISSIONS, protected: IN_ENVIRONMENTS },
};
export const ROLE_NAMES = Object.keys(ROLES);

/** The instance roles as they ship: what a person holds in every project their scope takes in. */
export const INSTANCE_ROLES = {
  member: { permissions: [], protected: [] },
  auditor: { permissions: ['audit.read'], protected: ['audit.read'] },
  developer: { permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] },
  admin: { permissions: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'], protected: ['audit.read'] },
  owner: { permissions: PERMISSIONS, protected: IN_ENVIRONMENTS },
} as const satisfies Record<string, Columns>;
export type InstanceRole = keyof typeof INSTANCE_ROLES;
export const INSTANCE_ROLE_NAMES = Object.keys(INSTANCE_ROLES) as InstanceRole[];

/** A key's nature (R16): `plain` is shown, `secret` read by whoever may, `sensitive` never handed to a person. */
export const NATURES = ['plain', 'secret', 'sensitive'] as const;
export type Nature = (typeof NATURES)[number];

/** Projects by id, environments by slug, as a scope filters them. */
export type Filter = 'all' | { only: string[] } | { except: string[] };
export type Scope = { projects: Filter; environments: Filter };

/** A project (`environmentId` null) or one of its environments. */
export type Grant = { projectId: string; environmentId: string | null; role: string };

export type Environment = {
  id: string;
  projectId: string;
  slug: string;
  /** A fork's parent, in the same project; null for a root environment. */
  parentId: string | null;
  /** An `@me` overlay's owner (`user:…`): a fork only they read and write (R8, R18, R20). */
  owner: string | null;
};
export type Project = { id: string; slug: string; environments: Environment[] };
export type Secret = {
  id: string;
  environmentId: string;
  key: string;
  nature: Nature;
  /** A reference's source secret, whose value and nature it takes (R20, R23); null for a value of its own. */
  reference: string | null;
  archived: boolean;
};
/** A key a fork removed from what it inherits. */
export type Dismissal = { environmentId: string; key: string };

export type Person = { principal: string; role: InstanceRole; scope: Scope; grants: Grant[] };
export type ServiceAccount = { principal: string; grants: Grant[] };
/**
 * A credential: a person's personal token, a service account's token, or a
 * trust binding (OIDC) that mints its sessions. Each carries its scope, the
 * grants it names, issued by `issuer`.
 */
export type Credential =
  | { kind: 'personal'; issuer: string; scope: Grant[] }
  | { kind: 'service'; account: string; issuer: string; scope: Grant[] }
  | { kind: 'binding'; account: string; issuer: string; scope: Grant[]; provider: 'github' | 'kubernetes' | 'oidc'; subject: string };

export type World = {
  projects: Project[];
  secrets: Secret[];
  dismissals: Dismissal[];
  people: Person[];
  services: ServiceAccount[];
  credentials: Credential[];
};

/** The deepest fork chain coffre makes: a fork of a fork of a fork. */
export const MAX_PARENTS = 3;

/** A lowercase UUID, as coffre's ids and the AAD require. Hegel shrinks it towards zeros. */
export const uuid = gs.binary({ minSize: 16, maxSize: 16 }).map((bytes) => {
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
});

/**
 * A UUID none of `used` has, which it joins. Hegel shrinks every id towards
 * zeros, and two places with one id would be one place to the code and two
 * to the model: a repeat takes a counter as its last group instead.
 */
export function freshUuid(tc: TestCase, used: Set<string>): string {
  let id = tc.draw(uuid);
  for (let n = used.size; used.has(id); n++) id = `${id.slice(0, 24)}${n.toString(16).padStart(12, '0')}`;
  used.add(id);
  return id;
}

/** A key name coffre accepts: `^[A-Za-z_][A-Za-z0-9_]{0,127}$`. */
export const keyName = gs.fromRegex('[A-Za-z_][A-Za-z0-9_]{0,127}', { fullmatch: true });
/**
 * Strings near a key name: one character off, the length limit's edges,
 * look-alikes, separators and line breaks. Most are not key names; a
 * validator is held to the pattern above on each.
 */
export const nearKeyName = gs.oneOf(
  keyName,
  gs.fromRegex('[A-Za-z0-9_]{127,130}', { fullmatch: true }),
  gs.composite((tc) => {
    const base = tc.draw(keyName);
    const at = tc.draw(gs.integers({ minValue: 0, maxValue: base.length }));
    const odd = tc.draw(gs.sampledFrom(['-', '.', ' ', '=', '$', '\n', '\r', '\0', 'é', 'İ', 'K', ' ', '﻿', '0', 'K', '/']));
    return base.slice(0, at) + odd + base.slice(at);
  }),
  gs.text({ maxSize: 6 }),
);

/** Any unicode value but NUL, which no environment variable can carry. */
export const value = gs.text({ maxSize: 40 }).map((text) => text.replaceAll('\0', ''));
/** Values a shell or a parser trips on: quotes, `$`, backslashes, line breaks, `#`, `=`, spaces, and their mixes. */
export const awkwardValue = gs.oneOf(
  value,
  gs.arrays(gs.sampledFrom(['\'', '"', '$', '`', '\\', '\n', '\r', '\r\n', '#', ' #', '=', ' ', '\t', '!', '${X}', '$(id)', 'a', 'é', ' ', '\\n', '\'\\\'\'', 'EOF', 'ghadelimiter']), { maxSize: 8 }).map((parts) => parts.join('')),
);

/** A project's environment slugs, few, so that places and scopes collide. */
const PROJECT_SLUGS = ['market', 'ops', 'billing'] as const;
const ENVIRONMENT_SLUGS = ['dev', 'prod', 'staging', 'qa'] as const;
export const PEOPLE = ['user:ada@acme.example', 'user:bo@acme.example', 'user:cy@acme.example'] as const;
export const SERVICES = ['token:ci', 'token:deploy'] as const;

/** Every place of a world: each project, and each of its environments. */
export function placesOf(projects: readonly Project[]): { projectId: string; environmentId: string | null; slug: string | null }[] {
  return projects.flatMap((project) => [
    { projectId: project.id, environmentId: null, slug: null },
    ...project.environments.map((environment) => ({ projectId: project.id, environmentId: environment.id, slug: environment.slug })),
  ]);
}

/** A fork's chain, nearest parent first, as coffre walks it. */
export function parentsOf(environments: readonly Environment[], environmentId: string): Environment[] {
  const byId = new Map(environments.map((environment) => [environment.id, environment]));
  const chain: Environment[] = [];
  for (let at = byId.get(environmentId)?.parentId ?? null; at !== null && chain.length < MAX_PARENTS; at = byId.get(at)?.parentId ?? null) {
    chain.push(byId.get(at)!);
  }
  return chain;
}

function filter(values: readonly string[]) {
  return gs.oneOf(
    gs.just('all' as Filter),
    gs.arrays(gs.sampledFrom(values), { maxSize: 2 }).map((only): Filter => ({ only: [...new Set(only)] })),
    gs.arrays(gs.sampledFrom(values), { minSize: 1, maxSize: 2 }).map((except): Filter => ({ except: [...new Set(except)] })),
  );
}

/** A scope over these projects' ids and these environment slugs, a stranger's included, which narrows nothing that exists. */
export function scope(projectIds: readonly string[], slugs: readonly string[] = ENVIRONMENT_SLUGS) {
  return gs.record({ projects: filter([...projectIds, 'gone']), environments: filter([...slugs, 'gone']) });
}

/**
 * Projects with their environments: a root `dev` and `prod` maybe, forks of
 * them to `MAX_PARENTS` deep, and `@me` overlays of any of them. Ids are
 * drawn, so two runs share none, and slugs repeat across projects.
 */
export const projects = (options: { maxProjects?: number; maxEnvironments?: number } = {}) => gs.composite((tc): Project[] => {
  const count = tc.draw(gs.integers({ minValue: 1, maxValue: options.maxProjects ?? 2 }));
  const used = new Set<string>();
  return PROJECT_SLUGS.slice(0, count).map((slug) => {
    const id = freshUuid(tc, used);
    const environments: Environment[] = [];
    const total = tc.draw(gs.integers({ minValue: 1, maxValue: options.maxEnvironments ?? 5 }));
    for (let n = 0; n < total; n++) {
      // A fork's chain stays within `MAX_PARENTS`, and nothing forks an overlay.
      const parents = environments.filter((environment) => environment.owner === null && parentsOf(environments, environment.id).length < MAX_PARENTS);
      const parent = parents.length === 0 ? null : tc.draw(gs.optional(gs.sampledFrom(parents)));
      // One overlay per person per environment, as `environments_parent_id_owner_key` keeps it.
      const owners = parent === null ? [] : PEOPLE.filter((person) => !environments.some((environment) => environment.parentId === parent.id && environment.owner === person));
      const owner = owners.length === 0 ? null : tc.draw(gs.optional(gs.sampledFrom(owners)));
      const taken = new Set(environments.map((environment) => environment.slug));
      const free = ENVIRONMENT_SLUGS.filter((name) => !taken.has(name));
      // An overlay's stored slug, as coffre makes it: its parent's, `-p-` and eight hex digits; a path names it `<parent>@me`.
      const environmentSlug = owner !== null ? `${parent!.slug}-p-${n.toString(16).padStart(8, '0')}` : free.length > 0 ? tc.draw(gs.sampledFrom(free)) : `fork-${n}`;
      if (taken.has(environmentSlug)) continue;
      environments.push({ id: freshUuid(tc, used), projectId: id, slug: environmentSlug, parentId: parent?.id ?? null, owner });
    }
    return { id, slug, environments };
  });
});

/** A role's two columns as an Owner may write them: reading implies using, and the protected column within the other, with nothing project-wide. */
export const columns = gs.composite((tc): Columns => {
  const permissions = PERMISSIONS.filter(() => tc.draw(gs.booleans()));
  if (permissions.includes('secret.read') && !permissions.includes('secret.use')) permissions.splice(1, 0, 'secret.use');
  const guarded = permissions.filter((permission) => !PROJECT_ONLY.includes(permission) && tc.draw(gs.booleans()));
  if (guarded.includes('secret.read') && !guarded.includes('secret.use')) guarded.push('secret.use');
  return { permissions: PERMISSIONS.filter((permission) => permissions.includes(permission)), protected: PERMISSIONS.filter((permission) => guarded.includes(permission)) };
});

/** The instance's policy: built-in roles as an Owner edited them (Owner fixed), custom ones, instance roles (Owner and Member fixed), and protected environments. */
export type Policy = { roles: Record<string, Columns>; instanceRoles: Record<InstanceRole, Columns>; protected: string[] };
export const policy = (environmentIds: readonly string[]) => gs.composite((tc): Policy => {
  const roles: Record<string, Columns> = {};
  for (const name of ROLE_NAMES) roles[name] = name === 'owner' || !tc.draw(gs.booleans()) ? ROLES[name]! : tc.draw(columns);
  for (const name of tc.draw(gs.arrays(gs.sampledFrom(['release-manager', 'reader', 'on-call']), { maxSize: 2 }))) roles[name] = tc.draw(columns);
  const instanceRoles = { ...INSTANCE_ROLES } as Record<InstanceRole, Columns>;
  for (const name of ['auditor', 'developer', 'admin'] as const) if (tc.draw(gs.booleans())) instanceRoles[name] = tc.draw(columns);
  const guarded = environmentIds.filter(() => tc.draw(gs.booleans()));
  return { roles, instanceRoles, protected: guarded };
});

/** A grant somewhere in these projects: on a project, or on an environment with a role that holds nothing project-wide there. */
export const grant = (projects: readonly Project[], roles: Readonly<Record<string, Columns>> = ROLES) => gs.composite((tc): Grant => {
  const project = tc.draw(gs.sampledFrom(projects));
  const role = tc.draw(gs.sampledFrom(Object.keys(roles)));
  const onProject = roles[role]!.permissions.some((permission) => PROJECT_ONLY.includes(permission)) || tc.draw(gs.booleans());
  return { projectId: project.id, environmentId: onProject ? null : tc.draw(gs.sampledFrom(project.environments)).id, role };
});

/** Grants with at most one per place, as the vault keeps them. */
export const grants = (projects: readonly Project[], roles?: Readonly<Record<string, Columns>>, maxSize = 4) =>
  gs.arrays(grant(projects, roles), { maxSize }).map((held) => [...new Map(held.map((item) => [`${item.projectId}/${item.environmentId ?? ''}`, item])).values()]);

/**
 * A world: projects, their keys of every nature, references between them,
 * a fork's removals, people with instance roles, scopes and grants,
 * service accounts with grants, and the credentials issued for them.
 */
export const world = (options: { maxProjects?: number; maxEnvironments?: number; maxSecrets?: number } = {}) => gs.composite((tc): World => {
  const drawn = tc.draw(projects(options));
  const environments = drawn.flatMap((project) => project.environments);
  const used = new Set([...drawn.map((project) => project.id), ...environments.map((environment) => environment.id)]);
  const secrets: Secret[] = [];
  for (let n = tc.draw(gs.integers({ minValue: 0, maxValue: options.maxSecrets ?? 8 })); n > 0; n--) {
    const environment = tc.draw(gs.sampledFrom(environments));
    const key = tc.draw(gs.sampledFrom(['DATABASE_URL', 'STRIPE_KEY', 'API_TOKEN', 'REGION']));
    if (secrets.some((secret) => secret.environmentId === environment.id && secret.key === key)) continue;
    // A reference points at a value of its own elsewhere, never at itself or another reference, and never into an overlay.
    const sources = secrets.filter((secret) => secret.reference === null && secret.environmentId !== environment.id && environments.find((each) => each.id === secret.environmentId)!.owner === null);
    const reference = environment.owner === null && sources.length > 0 && tc.draw(gs.booleans()) ? tc.draw(gs.sampledFrom(sources)) : null;
    secrets.push({
      id: freshUuid(tc, used), environmentId: environment.id, key,
      nature: reference?.nature ?? tc.draw(gs.sampledFrom(NATURES)),
      reference: reference?.id ?? null,
      archived: tc.draw(gs.integers({ minValue: 0, maxValue: 5 })) === 0,
    });
  }
  const forks = environments.filter((environment) => environment.parentId !== null);
  const dismissals = forks.length === 0 ? [] : tc.draw(gs.arrays(gs.record({
    environmentId: gs.sampledFrom(forks.map((environment) => environment.id)),
    key: gs.sampledFrom(['DATABASE_URL', 'STRIPE_KEY', 'API_TOKEN', 'REGION']),
  }), { maxSize: 3 })).filter((item, i, all) => all.findIndex((other) => other.environmentId === item.environmentId && other.key === item.key) === i);
  const ids = drawn.map((project) => project.id);
  const people = PEOPLE.map((principal): Person => ({
    principal,
    role: tc.draw(gs.sampledFrom(INSTANCE_ROLE_NAMES)),
    scope: tc.draw(scope(ids)),
    grants: tc.draw(grants(drawn)),
  }));
  const services = SERVICES.map((principal): ServiceAccount => ({ principal, grants: tc.draw(grants(drawn)) }));
  const credentials: Credential[] = [];
  for (let n = tc.draw(gs.integers({ minValue: 0, maxValue: 3 })); n > 0; n--) {
    const issuer = tc.draw(gs.sampledFrom(PEOPLE));
    const kind = tc.draw(gs.sampledFrom(['personal', 'service', 'binding'] as const));
    if (kind === 'personal') {
      // A personal token names delegable roles alone: none that manages access.
      const delegable = Object.fromEntries(Object.entries(ROLES).filter(([, held]) => !held.permissions.includes('grant.manage')));
      credentials.push({ kind, issuer, scope: tc.draw(grants(drawn, delegable)) });
      continue;
    }
    const account = tc.draw(gs.sampledFrom(services));
    const scope = account.grants.filter(() => tc.draw(gs.booleans()));
    credentials.push(kind === 'service'
      ? { kind, account: account.principal, issuer, scope }
      : { kind, account: account.principal, issuer, scope, provider: tc.draw(gs.sampledFrom(['github', 'kubernetes', 'oidc'] as const)), subject: tc.draw(gs.sampledFrom(['repo:acme/app:ref:refs/heads/main', 'system:serviceaccount:prod:app', 'pipeline-7'])) });
  }
  return { projects: drawn, secrets, dismissals, people, services, credentials };
});

import {
  admits,
  allows,
  EVERYWHERE,
  INSTANCE_ROLES,
  instanceRoleGrants,
  normalScope,
  roleGrants,
  ROLES,
  type GrantPlace,
  type InstanceRole,
  type Place,
  type Role,
  type Scope,
} from './access.ts';

/**
 * How the vault replaces the grants on every project of 0.4 (`*`, and `*`
 * on one environment slug) with what 0.5 has instead: a person's instance
 * role and its scope, and project grants. Pure, so the vault converts with
 * it and anyone can read what it does to each case.
 *
 * Nobody ends up holding more than before, anywhere, at any time. Where the
 * new model cannot say exactly what a grant said, it says less:
 *
 *   developer on *            Developer, everywhere
 *   developer on dev in each  Developer, environments only dev
 *   auditor on *              Auditor, everywhere
 *   viewer on *               viewer on each project there is now
 *   maintainer on *           Developer, everywhere, and maintainer on each project there is now
 *   owner on *, as an owner   Owner (an owner of 0.4 is an Admin)
 *   any, for a service        the same role on each project, or each environment of the slug, there is now
 *
 * What a grant leaves to project grants reaches the projects there are
 * now, not those made later (`narrowed`, `later-projects`). A project grant
 * the member holds already stays when the new one would not hold all it
 * does for as long (`kept`).
 */

/** A grant on every project of 0.4: on all of each (`environmentSlug` null), or on the environment of one slug in each. */
export type EveryProjectGrant = { environmentSlug: string | null; role: Role; expiresAt: number | null };

export type ConversionInput = {
  /** A person may hold an instance role; a service account holds grants only. */
  person: boolean;
  /** Their instance role before: `admin` for an owner of 0.4, `member` for anyone else. */
  role: InstanceRole;
  /** Their live grants on every project. */
  everyProject: readonly EveryProjectGrant[];
  /** Their live grants on projects and environments. */
  grants: readonly (GrantPlace & { role: Role; expiresAt: number | null })[];
  /** The projects there are now, deleted ones left out, with their environments. */
  projects: readonly { id: string; environments: readonly { id: string; slug: string }[] }[];
};

/** A project grant the conversion gives: new, or in place of the one they held there (`replaces`). */
export type ConvertedGrant = { projectId: string; environmentId: string | null; role: Role; expiresAt: number | null; replaces: Role | null };

/** Where the conversion gives less than a grant on every project did. */
export type Narrowed =
  /** It reaches the projects there are now as project grants, and none made later. */
  | { kind: 'later-projects'; grant: EveryProjectGrant }
  /** They held `kept` at this place already, which the grant's role would not have held all of, or for as long: it stays. */
  | { kind: 'kept'; grant: EveryProjectGrant; projectId: string; environmentId: string | null; kept: Role };

export type Conversion = { role: InstanceRole; scope: Scope; grants: ConvertedGrant[]; narrowed: Narrowed[] };

export function convertEveryProjectGrants(input: ConversionInput): Conversion {
  const { role, scope } = input.person ? instanceRoleFor(input.role, input.everyProject) : { role: input.role, scope: EVERYWHERE };
  const held = new Map(input.grants.map((grant) => [placeKey(grant), grant]));
  const grants: ConvertedGrant[] = [];
  const narrowed: Narrowed[] = [];

  for (const grant of input.everyProject) {
    if (byRole(role, scope, grant)) continue;
    narrowed.push({ kind: 'later-projects', grant });
    for (const place of reached(grant, input.projects)) {
      const at: Place = place.environmentId === null
        ? { projectId: place.projectId }
        : { projectId: place.projectId, environmentId: place.environmentId, environmentSlug: grant.environmentSlug };
      if (holdsAlready(role, scope, [...held.values()], grant, at)) continue;
      const existing = held.get(placeKey(place));
      if (existing !== undefined && !(within(existing.role, grant.role) && outlasts(grant.expiresAt, existing.expiresAt))) {
        narrowed.push({ kind: 'kept', grant, ...place, kept: existing.role });
        continue;
      }
      const given = { ...place, role: grant.role, expiresAt: grant.expiresAt };
      held.set(placeKey(place), given);
      grants.push({ ...given, replaces: existing?.role ?? null });
    }
  }
  return { role, scope, grants, narrowed };
}

/**
 * The strongest instance role a person's lasting grants on every project
 * add up to, never more than they held: an owner of 0.4 (an Admin) who
 * read, wrote and retired secrets everywhere is an Owner; anyone else is a
 * Developer or an Auditor where those grants were on all of every project,
 * or on some environment slugs (Developer first), or stays as they were.
 */
function instanceRoleFor(previous: InstanceRole, everyProject: readonly EveryProjectGrant[]): { role: InstanceRole; scope: Scope } {
  const lasting = everyProject.filter((grant) => grant.expiresAt === null);
  const all = lasting.find((grant) => grant.environmentSlug === null)?.role;
  if (previous === 'admin') {
    const adds = all === undefined ? [] : ROLES[all].permissions;
    const owner = INSTANCE_ROLES.owner.permissions.every((permission) => instanceRoleGrants('admin', permission) || (adds as readonly string[]).includes(permission));
    return { role: owner ? 'owner' : 'admin', scope: EVERYWHERE };
  }
  if (previous !== 'member') return { role: previous, scope: EVERYWHERE };
  const fits = (role: InstanceRole, held: Role) => INSTANCE_ROLES[role].permissions.every((permission) => roleGrants(held, permission));
  const candidates = ['developer', 'auditor'] as const;
  for (const role of candidates) if (all !== undefined && fits(role, all)) return { role, scope: EVERYWHERE };
  for (const role of candidates) {
    const only = lasting.filter((grant) => grant.environmentSlug !== null && fits(role, grant.role)).map((grant) => grant.environmentSlug!);
    if (only.length > 0) return { role, scope: normalScope({ projects: 'all', environments: { only } }) };
  }
  return { role: 'member', scope: EVERYWHERE };
}

/** Whether the instance role, in its scope, holds all a grant on every project did, wherever it did, for good. */
function byRole(role: InstanceRole, scope: Scope, grant: EveryProjectGrant): boolean {
  const covered = scope.projects === 'all' && (grant.environmentSlug === null ? scope.environments === 'all' : admits(scope.environments, grant.environmentSlug));
  return covered && ROLES[grant.role].permissions.every((permission) => instanceRoleGrants(role, permission));
}

/** Whether every permission of the grant's role is held at `at` already, by the role or by grants lasting as long. */
function holdsAlready(
  role: InstanceRole,
  scope: Scope,
  held: readonly (GrantPlace & { role: Role; expiresAt: number | null })[],
  grant: EveryProjectGrant,
  at: Place,
): boolean {
  const lasting = held.filter((other) => outlasts(other.expiresAt, grant.expiresAt));
  return ROLES[grant.role].permissions.every((permission) => allows({ isRootAdmin: false, role, scope, grants: lasting }, permission, at));
}

/** The places a grant on every project reached: each project, or each environment of its slug. */
function reached(grant: EveryProjectGrant, projects: ConversionInput['projects']): { projectId: string; environmentId: string | null }[] {
  return projects.flatMap((project): { projectId: string; environmentId: string | null }[] =>
    grant.environmentSlug === null
      ? [{ projectId: project.id, environmentId: null }]
      : project.environments.filter((environment) => environment.slug === grant.environmentSlug).map((environment) => ({ projectId: project.id, environmentId: environment.id })),
  );
}

/** Whether `role` holds nothing `wider` does not. */
function within(role: Role, wider: Role): boolean {
  return ROLES[role].permissions.every((permission) => roleGrants(wider, permission));
}

/** Whether an end of `a` comes no sooner than one of `b`; null is never. */
function outlasts(a: number | null, b: number | null): boolean {
  return a === null || (b !== null && a >= b);
}

function placeKey(place: GrantPlace): string {
  return place.environmentId ?? place.projectId!;
}

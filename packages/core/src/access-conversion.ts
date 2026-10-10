import {
  admits,
  allows,
  assignableToEnvironment,
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
 * now, not those made later (`narrowed`, `later-projects`). A place holds
 * one grant: where they hold one already that neither it nor the new one
 * holds all of, for as long, a project's goes on to each of its
 * environments instead, the one that does not read the log first
 * (`environments`: not environments made later, nor, for an auditor, the
 * project's own entries). Only where neither can, or on an environment, is
 * something lost, the one that reads kept (`lost`):
 *
 *   viewer on *, auditor on billing      auditor on billing, viewer on each of billing's environments
 *   viewer on *, developer on billing    developer on billing
 *   maintainer on *, access-manager on billing, as a service
 *                                        maintainer on billing: access-manager there is lost
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

/** Where the conversion gives less than a grant on every project did, each naming the grant it comes of. */
export type Narrowed =
  /** It reaches the projects there are now as project grants, and none made later. */
  | { kind: 'later-projects'; grant: EveryProjectGrant }
  /**
   * `role` on this project, the grant's or the one they held there, is on
   * each of its environments instead: not on environments made later, nor
   * on the project's own log entries.
   */
  | { kind: 'environments'; grant: EveryProjectGrant; projectId: string; role: Role }
  /** No grant here holds both: `kept` stays (until `keptUntil`), and what `lost` held beyond it is gone. */
  | { kind: 'lost'; grant: EveryProjectGrant; projectId: string; environmentId: string | null; lost: Role; kept: Role; keptUntil: number | null };

export type Conversion = { role: InstanceRole; scope: Scope; grants: ConvertedGrant[]; narrowed: Narrowed[] };

type Held = GrantPlace & { role: Role; expiresAt: number | null };
type Wanted = { role: Role; expiresAt: number | null };
type At = { project: ConversionInput['projects'][number]; environment: { id: string; slug: string } | null };

export function convertEveryProjectGrants(input: ConversionInput): Conversion {
  const { role, scope } = input.person ? instanceRoleFor(input.role, input.everyProject) : { role: input.role, scope: EVERYWHERE };
  const before = new Map(input.grants.map((grant) => [placeKey(grant), grant]));
  const held = new Map<string, Held>(before);
  const given = new Map<string, ConvertedGrant>();
  const narrowed: Narrowed[] = [];

  const give = (at: At, wanted: Wanted) => {
    const place = { projectId: at.project.id, environmentId: at.environment?.id ?? null, role: wanted.role, expiresAt: wanted.expiresAt };
    held.set(placeKey(place), place);
    given.set(placeKey(place), { ...place, replaces: before.get(placeKey(place))?.role ?? null });
  };
  // What `grant` held at `at`, as `wanted`, added to what they hold there already.
  const settle = (grant: EveryProjectGrant, at: At, wanted: Wanted) => {
    const place: Place = at.environment === null
      ? { projectId: at.project.id }
      : { projectId: at.project.id, environmentId: at.environment.id, environmentSlug: at.environment.slug };
    if (holdsAlready(role, scope, [...held.values()], wanted, place)) return;
    const existing = held.get(at.environment?.id ?? at.project.id);
    if (existing === undefined || (within(existing.role, wanted.role) && outlasts(wanted.expiresAt, existing.expiresAt))) {
      give(at, wanted);
      return;
    }
    // One place, one grant, and neither holds the other for as long: on a
    // project, one of them goes on to its environments, as far as it reached
    // but for environments made later; the one that reads no log first, as
    // an environment's grant reads none of its project's entries.
    if (at.environment === null) {
      const down = [wanted, existing]
        .filter((candidate) => assignableToEnvironment(candidate.role))
        .sort((a, b) => Number(roleGrants(a.role, 'audit.read')) - Number(roleGrants(b.role, 'audit.read')))[0];
      if (down !== undefined) {
        if (down === existing) give(at, wanted);
        narrowed.push({ kind: 'environments', grant, projectId: at.project.id, role: down.role });
        for (const environment of at.project.environments) settle(grant, { project: at.project, environment }, { role: down.role, expiresAt: down.expiresAt });
        return;
      }
    }
    // Nothing holds both: the one that reads stays, else the one they had.
    const keep = !roleGrants(wanted.role, 'secret.read') || roleGrants(existing.role, 'secret.read') ? existing : wanted;
    const lose = keep === existing ? wanted : existing;
    if (keep === wanted) give(at, wanted);
    narrowed.push({ kind: 'lost', grant, projectId: at.project.id, environmentId: at.environment?.id ?? null, lost: lose.role, kept: keep.role, keptUntil: keep.expiresAt });
  };

  for (const grant of input.everyProject) {
    if (byRole(role, scope, grant)) continue;
    narrowed.push({ kind: 'later-projects', grant });
    for (const project of input.projects) {
      const reached = grant.environmentSlug === null
        ? [null]
        : project.environments.filter((environment) => environment.slug === grant.environmentSlug);
      for (const environment of reached) settle(grant, { project, environment }, grant);
    }
  }
  return { role, scope, grants: [...given.values()], narrowed };
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
  held: readonly Held[],
  grant: Wanted,
  at: Place,
): boolean {
  const lasting = held.filter((other) => outlasts(other.expiresAt, grant.expiresAt));
  return ROLES[grant.role].permissions.every((permission) => allows({ isRootAdmin: false, role, scope, grants: lasting }, permission, at));
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

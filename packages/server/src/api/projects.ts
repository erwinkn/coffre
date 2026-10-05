import { randomUUID } from 'node:crypto';

import { covers, everyProjectPath, ROLES, type Permission, type Role } from '@coffre/core/access';
import { isUniqueViolation } from '@coffre/db/dialect';
import { environments, projects } from '@coffre/db/schema';

import { knownMigrations } from '@coffre/db/schema-version';

import { appliedMigrations, distinctSecretCounts, everyProjectGrants, insert, places, update, type EveryProjectGrant, type ResolvedPath } from '../db/queries.ts';
import { everyProjectReaches, seesGrantsIn } from './members.ts';
import { COFFRE_VERSION } from '../version.ts';
import { can, canAnywhere, permissionsAt, placeOf, seesProject } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, type ApiContext } from './context.ts';
import { conflict, notFound } from './errors.ts';

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  /**
   * False for someone signed in but not a member: `/me` is the one call that
   * answers them, so the UI can say who they are and that the door is shut.
   */
  registered: boolean;
  /** Refused by the vault: their record failed its integrity check. */
  tampered: boolean;
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
  canReadAudit: boolean;
  /** Every live environment the caller holds something in, and what. */
  environments: { project: string; environment: string; permissions: Permission[] }[];
  /**
   * The deployment, for owners and root admins only, who upgrade it: the
   * version of coffre it runs, and its database's migrations, the first
   * `applied` of `known`, which are this version's. Null for anyone else:
   * versions tell an attacker what to try.
   */
  instance: InstanceState | null;
};

export type InstanceState = { version: string; migrations: { applied: number; known: string[] } };

export type ProjectEnvironmentSummary = {
  slug: string;
  name: string;
  /** True when the caller may open the environment's secret metadata page. */
  accessible: boolean;
  /** Omitted for environments that the caller may only know by name. */
  details: { archivedAt: string | null; secretCount: number | null } | null;
};

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  /** What the caller may do at project scope. */
  permissions: Permission[];
  environments: ProjectEnvironmentSummary[];
  /**
   * Distinct live secret names across the live environments the caller can
   * open: the same key in dev and prod is one secret. Null when they can open
   * none, or the project is archived.
   */
  secretCount: number | null;
};

const iso = (value: Date | null) => value?.toISOString() ?? null;

/**
 * Someone who reaches a place through a grant on every project, the ones
 * made later too: the member, where the grant is (`*`, or `*` and the
 * environment slug it covers in each), and its role.
 */
export type InheritedGrant = { member: string; place: string; role: Role; roleName: string; expiresAt: string | null };

/**
 * The live grants on every project that reach a place, for a caller who sees
 * that project's grants (`seesGrantsIn`), and nothing for anyone else: a
 * project as a whole (`environment` null), which only grants on all of every
 * project reach, or an environment by its slug.
 */
async function inheritedGrants(ctx: ApiContext, projectId: string, environment: string | null): Promise<InheritedGrant[]> {
  if (!seesGrantsIn(ctx.caller, projectId)) return [];
  const grants = await everyProjectGrants(ctx.db, new Date());
  return grants
    .filter((grant) => grant.environmentSlug === null || grant.environmentSlug === environment)
    .map(inherited);
}

function inherited(grant: EveryProjectGrant): InheritedGrant {
  return {
      member: grant.principal,
      place: everyProjectPath(grant.environmentSlug),
      role: grant.role as Role,
      roleName: ROLES[grant.role as Role].name,
    expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
  };
}

export async function me(ctx: ApiContext): Promise<Me> {
  const { caller } = ctx;
  const reachable: Me['environments'] = [];
  for (const project of await places(ctx.db)) {
    if (project.archivedAt !== null) continue;
    for (const environment of project.environments) {
      if (environment.archivedAt !== null) continue;
      const place = placeOf(project, environment);
      const holds = caller.isRootAdmin || caller.grants.some((grant) => covers(grant, place));
      if (!holds) continue;
      reachable.push({
        project: project.slug,
        environment: environment.slug,
        permissions: permissionsAt(caller, place),
      });
    }
  }
  return {
    principal: caller.principal,
    registered: caller.registered,
    tampered: caller.tampered,
    instanceRole: caller.instanceRole,
    isRootAdmin: caller.isRootAdmin,
    canReadAudit: caller.isOwner || canAnywhere(caller, 'audit.read'),
    environments: reachable,
    instance: caller.isOwner || caller.isRootAdmin ? await instanceState(ctx) : null,
  };
}

/** The version this server runs, and how far its database's migrations are (`appliedMigrations`, as readiness counts them). */
async function instanceState(ctx: ApiContext): Promise<InstanceState> {
  return {
    version: COFFRE_VERSION,
    migrations: { applied: await appliedMigrations(ctx.db), known: [...knownMigrations(ctx.db)] },
  };
}

/**
 * The projects the caller can see: any grant anywhere in one makes it
 * visible. An environment grant shows the project without conferring
 * authority over it, so `permissions` are the project-scope ones, and the
 * caller learns the names of environments they hold nothing in, not their
 * contents.
 *
 * `everyProject` is the grants on every project, for those who make
 * projects or environments, which a new one is reached by at once, and
 * for those who manage access.
 */
export async function listProjects(ctx: ApiContext): Promise<{ projects: ProjectSummary[]; everyProject: InheritedGrant[] }> {
  const { caller } = ctx;
  const summaries: ProjectSummary[] = [];
  // The projects whose secrets the caller may count, and where they may.
  const counted: { summary: ProjectSummary; projectId: string; environmentIds: string[] }[] = [];
  const known = await places(ctx.db);
  for (const project of known) {
    if (!seesProject(caller, project)) continue;
    const scope = { projectId: project.id };
    if (project.archivedAt !== null && !caller.isOwner && !can(caller, 'project.manage', scope)) {
      continue;
    }
    const manages =
      can(caller, 'environment.manage', scope) || can(caller, 'grant.manage', scope);

    const summary: ProjectSummary = {
      slug: project.slug,
      name: project.name,
      archivedAt: iso(project.archivedAt),
      permissions: permissionsAt(caller, scope),
      environments: project.environments.map((environment) => {
        // Every role that writes or archives also reads, so read is the test.
        const secretAccess = can(caller, 'secret.read', placeOf(project, environment));
        if (!manages && !secretAccess) {
          return { slug: environment.slug, name: environment.name, accessible: false, details: null };
        }
        return {
          slug: environment.slug,
          name: environment.name,
          accessible: secretAccess,
          details: {
            archivedAt: iso(environment.archivedAt),
            secretCount: secretAccess ? environment.secretCount : null,
          },
        };
      }),
      secretCount: null,
    };
    summaries.push(summary);

    const environmentIds = project.environments
      .filter(
        (environment) =>
          environment.archivedAt === null &&
          can(caller, 'secret.read', placeOf(project, environment)),
      )
      .map((environment) => environment.id);
    if (project.archivedAt === null && environmentIds.length > 0) {
      counted.push({ summary, projectId: project.id, environmentIds });
    }
  }

  // One query counts every project, rather than one list per environment.
  const counts = await distinctSecretCounts(ctx.db, counted.flatMap((entry) => entry.environmentIds));
  for (const { summary, projectId } of counted) summary.secretCount = counts.get(projectId) ?? 0;
  // Each grant on every project, to whoever sees the grants of a project it reaches: as `listMembers` shows them.
  const everyProject = !caller.isOwner && !canAnywhere(caller, 'grant.manage')
    ? []
    : (await everyProjectGrants(ctx.db, new Date()))
        .filter((grant) => caller.isOwner || known.some((project) => everyProjectReaches(grant.environmentSlug, project) && seesGrantsIn(caller, project.id)))
        .map(inherited);
  return { projects: summaries, everyProject };
}

export type PlaceView = { slug: string; name: string; archivedAt: string | null };

function slugTaken(what: 'project' | 'environment', slug: string): Error {
  return conflict(`a ${what} named "${slug}" already exists`);
}

/**
 * Create a project, or leave it as it is if it already exists: `PUT` names
 * the thing it creates, so sending it twice is harmless. Instance owners only.
 */
export async function putProject(
  ctx: ApiContext,
  place: ResolvedPath | null,
  slug: string,
  input: { name: string },
): Promise<{ project: PlaceView; created: boolean; inherited: InheritedGrant[] }> {
  const put = await audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'project.create', { metadata: { slug } });
    if (place !== null) {
      const { project } = place;
      return { id: project.id, project: { slug, name: project.name, archivedAt: iso(project.archivedAt) }, created: false };
    }
    const id = randomUUID();
    try {
      await insert(tx, projects, { id, slug, name: input.name });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('project', slug);
      throw error;
    }
    log.push(allowed(ctx, 'project.create', { projectId: id, metadata: { slug, name: input.name } }));
    return { id, project: { slug, name: input.name, archivedAt: null }, created: true };
  });
  // Grants on every project reach it as a whole; one on a slug, only an environment of it, which it has none of yet.
  const { id, ...made } = put;
  return { ...made, inherited: await inheritedGrants(ctx, id, null) };
}

type PlacePatch = { name?: string; slug?: string; archived?: boolean };

/**
 * What a patch changes on a project or environment: its name and slug, and
 * its archivedAt, left undefined when the patch does not move it.
 */
function placeChanges(
  current: { slug: string; name: string; archivedAt: Date | null },
  patch: PlacePatch,
): { renames: { name?: string; slug?: string }; archivedAt: Date | null | undefined } {
  const renames: { name?: string; slug?: string } = {};
  if (patch.name !== undefined && patch.name !== current.name) renames.name = patch.name;
  if (patch.slug !== undefined && patch.slug !== current.slug) renames.slug = patch.slug;
  let archivedAt: Date | null | undefined;
  if (patch.archived === true && current.archivedAt === null) archivedAt = new Date();
  if (patch.archived === false && current.archivedAt !== null) archivedAt = null;
  return { renames, archivedAt };
}

/** Rename, re-slug, archive or restore a project. */
export async function patchProject(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: PlacePatch,
): Promise<{ project: PlaceView }> {
  const { project } = place;
  const { renames, archivedAt } = placeChanges(project, patch);
  const renamed = Object.keys(renames).length > 0;
  return audited(ctx, async (tx, log) => {
    if (renamed || archivedAt !== undefined) {
      try {
        await update(tx, projects, { id: project.id }, { ...renames, archivedAt });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        throw new Refusal(
          slugTaken('project', renames.slug!),
          denied(ctx, 'project.update', 'slug_taken', { projectId: project.id, metadata: { slug: renames.slug } }),
        );
      }
    }
    if (renamed) {
      log.push(allowed(ctx, 'project.update', {
        projectId: project.id,
        metadata: { from: project.slug, ...renames },
      }));
    }
    if (archivedAt !== undefined) {
      log.push(allowed(ctx, archivedAt === null ? 'project.restore' : 'project.archive', {
        projectId: project.id,
        metadata: { slug: renames.slug ?? project.slug },
      }));
    }
    return {
      project: {
        slug: renames.slug ?? project.slug,
        name: renames.name ?? project.name,
        archivedAt: iso(archivedAt === undefined ? project.archivedAt : archivedAt),
      },
    };
  });
}

/** Create an environment unless it exists. Needs `environment.manage` on the project. */
export async function putEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  slug: string,
  input: { name: string },
): Promise<{ environment: PlaceView; created: boolean; inherited: InheritedGrant[] }> {
  const { project, environment } = place;
  if (environment !== null) {
    const existing = { slug, name: environment.name, archivedAt: iso(environment.archivedAt) };
    return { environment: existing, created: false, inherited: await inheritedGrants(ctx, project.id, slug) };
  }
  const put = await audited(ctx, async (tx, log) => {
    if (project.archivedAt !== null) {
      throw new Refusal(
        conflict(`${project.slug} is archived; restore it before adding environments`),
        denied(ctx, 'environment.create', 'project_archived', {
          projectId: project.id,
          metadata: { environmentSlug: slug },
        }),
      );
    }
    const id = randomUUID();
    try {
      await insert(tx, environments, { id, projectId: project.id, slug, name: input.name });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('environment', slug);
      throw error;
    }
    log.push(allowed(ctx, 'environment.create', {
      projectId: project.id,
      environmentId: id,
      metadata: { slug, name: input.name },
    }));
    return { environment: { slug, name: input.name, archivedAt: null }, created: true };
  });
  return { ...put, inherited: await inheritedGrants(ctx, project.id, slug) };
}

/**
 * Rename, re-slug, archive or restore an environment. `inherited` is who
 * reaches it through grants on every project under its slug now: a new
 * slug can bring in those who hold it in every project.
 */
export async function patchEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: PlacePatch,
): Promise<{ environment: PlaceView; inherited: InheritedGrant[] }> {
  const { project, environment } = place;
  if (environment === null) throw notFound('no such environment');
  const { renames, archivedAt } = placeChanges(environment, patch);
  const renamed = Object.keys(renames).length > 0;
  const scope = { projectId: project.id, environmentId: environment.id };
  const patched = await audited(ctx, async (tx, log) => {
    if (renamed || archivedAt !== undefined) {
      try {
        await update(tx, environments, { id: environment.id }, { ...renames, archivedAt });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        throw new Refusal(
          slugTaken('environment', renames.slug!),
          denied(ctx, 'environment.update', 'slug_taken', { ...scope, metadata: { slug: renames.slug } }),
        );
      }
    }
    if (renamed) {
      log.push(allowed(ctx, 'environment.update', {
        ...scope,
        metadata: { from: environment.slug, ...renames },
      }));
    }
    if (archivedAt !== undefined) {
      log.push(allowed(ctx, archivedAt === null ? 'environment.restore' : 'environment.archive', {
        ...scope,
        metadata: { environmentSlug: renames.slug ?? environment.slug },
      }));
    }
    return {
      environment: {
        slug: renames.slug ?? environment.slug,
        name: renames.name ?? environment.name,
        archivedAt: iso(archivedAt === undefined ? environment.archivedAt : archivedAt),
      },
    };
  });
  return { ...patched, inherited: await inheritedGrants(ctx, project.id, patched.environment.slug) };
}

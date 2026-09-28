import { randomUUID } from 'node:crypto';

import { and, asc, count, eq, isNull } from 'drizzle-orm';

import type { Permission } from '../../../../../packages/core/src/access.ts';
import type { Queryable } from '../../../../../packages/db/src/database.ts';
import { isUniqueViolation } from '../../../../../packages/db/src/dialect.ts';
import { environments, projects, secrets } from '../../../../../packages/db/src/schema.ts';
import { can, canAnywhere, permissionsAt, seesProject } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, type ApiContext } from './context.ts';
import { conflict, notFound } from './errors.ts';
import type { ResolvedPath } from './paths.ts';

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
  canReadAudit: boolean;
  /** Every live environment the caller holds something in, and what. */
  environments: { project: string; environment: string; permissions: Permission[] }[];
};

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
};

type PlaceRow = {
  id: string;
  slug: string;
  name: string;
  archivedAt: Date | null;
  environments: {
    id: string;
    slug: string;
    name: string;
    archivedAt: Date | null;
    secretCount: number;
  }[];
};

/** Every project with its environments and their live secret counts, in one query. */
async function loadPlaces(db: Queryable): Promise<PlaceRow[]> {
  const rows = await db
    .select({
      id: projects.id,
      slug: projects.slug,
      name: projects.name,
      archivedAt: projects.archivedAt,
      environmentId: environments.id,
      environmentSlug: environments.slug,
      environmentName: environments.name,
      environmentArchivedAt: environments.archivedAt,
      secretCount: count(secrets.id),
    })
    .from(projects)
    .leftJoin(environments, eq(environments.projectId, projects.id))
    .leftJoin(
      secrets,
      and(eq(secrets.environmentId, environments.id), isNull(secrets.archivedAt)),
    )
    .groupBy(
      projects.id,
      projects.slug,
      projects.name,
      projects.archivedAt,
      environments.id,
      environments.slug,
      environments.name,
      environments.archivedAt,
    )
    .orderBy(asc(projects.slug), asc(environments.slug));

  const places: PlaceRow[] = [];
  for (const row of rows) {
    let place = places.at(-1);
    if (place?.id !== row.id) {
      place = { id: row.id, slug: row.slug, name: row.name, archivedAt: row.archivedAt, environments: [] };
      places.push(place);
    }
    if (row.environmentId === null) continue;
    place.environments.push({
      id: row.environmentId,
      slug: row.environmentSlug!,
      name: row.environmentName!,
      archivedAt: row.environmentArchivedAt,
      secretCount: Number(row.secretCount),
    });
  }
  return places;
}

const iso = (value: Date | null) => value?.toISOString() ?? null;

export async function me(ctx: ApiContext): Promise<Me> {
  const { caller } = ctx;
  const reachable: Me['environments'] = [];
  for (const project of await loadPlaces(ctx.db)) {
    if (project.archivedAt !== null) continue;
    for (const environment of project.environments) {
      if (environment.archivedAt !== null) continue;
      const place = { projectId: project.id, environmentId: environment.id };
      const holds = caller.isRootAdmin || caller.grants.some(
        (grant) =>
          grant.projectId === project.id &&
          (grant.environmentId === null || grant.environmentId === environment.id),
      );
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
    instanceRole: caller.instanceRole,
    isRootAdmin: caller.isRootAdmin,
    canReadAudit: caller.isOwner || canAnywhere(caller, 'audit.read'),
    environments: reachable,
  };
}

/**
 * The projects the caller can see: any grant anywhere in one makes it
 * visible. An environment grant shows the project without conferring
 * authority over it, so `permissions` are the project-scope ones, and the
 * caller learns the names of environments they hold nothing in, not their
 * contents.
 */
export async function listProjects(ctx: ApiContext): Promise<{ projects: ProjectSummary[] }> {
  const { caller } = ctx;
  const summaries: ProjectSummary[] = [];
  for (const project of await loadPlaces(ctx.db)) {
    if (!seesProject(caller, project.id)) continue;
    const scope = { projectId: project.id };
    if (project.archivedAt !== null && !caller.isOwner && !can(caller, 'project.manage', scope)) {
      continue;
    }
    const manages =
      can(caller, 'environment.manage', scope) || can(caller, 'grant.manage', scope);

    summaries.push({
      slug: project.slug,
      name: project.name,
      archivedAt: iso(project.archivedAt),
      permissions: permissionsAt(caller, scope),
      environments: project.environments.map((environment) => {
        // Every role that writes or archives also reads, so read is the test.
        const secretAccess = can(caller, 'secret.read', {
          projectId: project.id,
          environmentId: environment.id,
        });
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
    });
  }
  return { projects: summaries };
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
  slug: string,
  input: { name: string },
): Promise<{ project: PlaceView; created: boolean }> {
  return audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'project.create', { metadata: { slug } });
    const [existing] = await tx
      .select({ name: projects.name, archivedAt: projects.archivedAt })
      .from(projects)
      .where(eq(projects.slug, slug));
    if (existing !== undefined) {
      return { project: { slug, name: existing.name, archivedAt: iso(existing.archivedAt) }, created: false };
    }
    const id = randomUUID();
    try {
      await tx.insert(projects).values({ id, slug, name: input.name });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('project', slug);
      throw error;
    }
    log.push(allowed(ctx, 'project.create', { projectId: id, metadata: { slug, name: input.name } }));
    return { project: { slug, name: input.name, archivedAt: null }, created: true };
  });
}

/** Rename, re-slug, archive or restore a project. */
export async function patchProject(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: { name?: string; slug?: string; archived?: boolean },
): Promise<{ project: PlaceView }> {
  const { project } = place;
  return audited(ctx, async (tx, log) => {
    const changes: { name?: string; slug?: string } = {};
    if (patch.name !== undefined && patch.name !== project.name) changes.name = patch.name;
    if (patch.slug !== undefined && patch.slug !== project.slug) changes.slug = patch.slug;
    const now = new Date();
    let archivedAt: Date | null | undefined;
    if (patch.archived === true && !project.archived) archivedAt = now;
    if (patch.archived === false && project.archived) archivedAt = null;

    if (Object.keys(changes).length > 0) {
      if (changes.slug !== undefined) {
        const [taken] = await tx.select({ id: projects.id }).from(projects).where(eq(projects.slug, changes.slug));
        if (taken !== undefined) throw slugTaken('project', changes.slug);
      }
      try {
        await tx.update(projects).set(changes).where(eq(projects.id, project.id));
      } catch (error) {
        if (isUniqueViolation(error)) throw slugTaken('project', changes.slug ?? project.slug);
        throw error;
      }
      log.push(allowed(ctx, 'project.update', {
        projectId: project.id,
        metadata: { from: project.slug, ...changes },
      }));
    }
    if (archivedAt !== undefined) {
      await tx.update(projects).set({ archivedAt }).where(eq(projects.id, project.id));
      log.push(allowed(ctx, archivedAt === null ? 'project.restore' : 'project.archive', {
        projectId: project.id,
        metadata: { slug: changes.slug ?? project.slug },
      }));
    }

    const archived = archivedAt === undefined ? project.archived : archivedAt !== null;
    const [current] = await tx
      .select({ archivedAt: projects.archivedAt })
      .from(projects)
      .where(eq(projects.id, project.id));
    return {
      project: {
        slug: changes.slug ?? project.slug,
        name: changes.name ?? project.name,
        archivedAt: archived ? iso(current?.archivedAt ?? now) : null,
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
): Promise<{ environment: PlaceView; created: boolean }> {
  const { project } = place;
  if (place.environment !== null) {
    const { environment } = place;
    const [row] = await ctx.db
      .select({ archivedAt: environments.archivedAt })
      .from(environments)
      .where(eq(environments.id, environment.id));
    return {
      environment: { slug, name: environment.name, archivedAt: iso(row?.archivedAt ?? null) },
      created: false,
    };
  }
  return audited(ctx, async (tx, log) => {
    if (project.archived) {
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
      await tx.insert(environments).values({ id, projectId: project.id, slug, name: input.name });
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
}

export async function patchEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: { name?: string; slug?: string; archived?: boolean },
): Promise<{ environment: PlaceView }> {
  const { project } = place;
  const environment = place.environment;
  if (environment === null) throw notFound('no such environment');
  return audited(ctx, async (tx, log) => {
    const changes: { name?: string; slug?: string } = {};
    if (patch.name !== undefined && patch.name !== environment.name) changes.name = patch.name;
    if (patch.slug !== undefined && patch.slug !== environment.slug) changes.slug = patch.slug;
    const now = new Date();
    let archivedAt: Date | null | undefined;
    if (patch.archived === true && !environment.archived) archivedAt = now;
    if (patch.archived === false && environment.archived) archivedAt = null;
    const scope = { projectId: project.id, environmentId: environment.id };

    if (Object.keys(changes).length > 0) {
      if (changes.slug !== undefined) {
        const [taken] = await tx
          .select({ id: environments.id })
          .from(environments)
          .where(and(eq(environments.projectId, project.id), eq(environments.slug, changes.slug)));
        if (taken !== undefined) throw slugTaken('environment', changes.slug);
      }
      try {
        await tx.update(environments).set(changes).where(eq(environments.id, environment.id));
      } catch (error) {
        if (isUniqueViolation(error)) throw slugTaken('environment', changes.slug ?? environment.slug);
        throw error;
      }
      log.push(allowed(ctx, 'environment.update', {
        ...scope,
        metadata: { from: environment.slug, ...changes },
      }));
    }
    if (archivedAt !== undefined) {
      await tx.update(environments).set({ archivedAt }).where(eq(environments.id, environment.id));
      log.push(allowed(ctx, archivedAt === null ? 'environment.restore' : 'environment.archive', {
        ...scope,
        metadata: { environmentSlug: changes.slug ?? environment.slug },
      }));
    }

    const archived = archivedAt === undefined ? environment.archived : archivedAt !== null;
    const [current] = await tx
      .select({ archivedAt: environments.archivedAt })
      .from(environments)
      .where(eq(environments.id, environment.id));
    return {
      environment: {
        slug: changes.slug ?? environment.slug,
        name: changes.name ?? environment.name,
        archivedAt: archived ? iso(current?.archivedAt ?? now) : null,
      },
    };
  });
}

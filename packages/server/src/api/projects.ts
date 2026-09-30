import { randomUUID } from 'node:crypto';

import type { Permission } from '@coffre/core/access';

import { isUniqueViolation } from '../db/dialect.ts';
import { insert, places, update, type ResolvedPath } from '../db/queries.ts';
import { environments, projects } from '../db/schema.ts';
import { can, canAnywhere, permissionsAt, seesProject } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, type ApiContext } from './context.ts';
import { conflict, notFound } from './errors.ts';

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  /**
   * False for someone signed in but not a member: `/me` is the one call that
   * answers them, so the UI can say who they are and that the door is shut.
   */
  registered: boolean;
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

const iso = (value: Date | null) => value?.toISOString() ?? null;

export async function me(ctx: ApiContext): Promise<Me> {
  const { caller } = ctx;
  const reachable: Me['environments'] = [];
  for (const project of await places(ctx.db)) {
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
    registered: caller.registered,
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
  for (const project of await places(ctx.db)) {
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
  place: ResolvedPath | null,
  slug: string,
  input: { name: string },
): Promise<{ project: PlaceView; created: boolean }> {
  return audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'project.create', { metadata: { slug } });
    if (place !== null) {
      const { project } = place;
      return { project: { slug, name: project.name, archivedAt: iso(project.archivedAt) }, created: false };
    }
    const id = randomUUID();
    try {
      await insert(tx, projects, { id, slug, name: input.name });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('project', slug);
      throw error;
    }
    log.push(allowed(ctx, 'project.create', { projectId: id, metadata: { slug, name: input.name } }));
    return { project: { slug, name: input.name, archivedAt: null }, created: true };
  });
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
): Promise<{ environment: PlaceView; created: boolean }> {
  const { project, environment } = place;
  if (environment !== null) {
    return { environment: { slug, name: environment.name, archivedAt: iso(environment.archivedAt) }, created: false };
  }
  return audited(ctx, async (tx, log) => {
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
}

export async function patchEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: PlacePatch,
): Promise<{ environment: PlaceView }> {
  const { project, environment } = place;
  if (environment === null) throw notFound('no such environment');
  const { renames, archivedAt } = placeChanges(environment, patch);
  const renamed = Object.keys(renames).length > 0;
  const scope = { projectId: project.id, environmentId: environment.id };
  return audited(ctx, async (tx, log) => {
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
}

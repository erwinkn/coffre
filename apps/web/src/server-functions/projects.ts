import { z } from 'zod';

import { deriveUiCapabilities } from '../lib/capabilities.ts';
import { getMe } from '../server/queries/me.ts';
import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import { displayName, slug } from '../shared/schemas.ts';
import { currentRequestContext } from './session.ts';
import { uiFailure, uiMutation, uiResult } from './result.ts';

export const listProjects = registeredServerFn({ method: 'GET' }).handler(async () => {
  const runtime = getRuntime();
  const ctx = currentRequestContext();
  return uiResult(async () => {
    const [me, projects] = await Promise.all([
      getMe(runtime, ctx),
      runtime.admin.listProjects(ctx),
    ]);
    return { projects, capabilities: deriveUiCapabilities(me, projects) };
  });
});

/** One project and, when permitted, its grants. */
export const getProject = registeredServerFn({ method: 'GET' })
  .validator(z.object({ project: slug }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    try {
      const projects = await runtime.admin.listProjects(ctx);
      const project = projects.find((entry) => entry.slug === data.project);
      if (!project) return { ok: false as const, error: null };

      if (!project.permissions.includes('grant.manage')) {
        return { ok: true as const, project, grants: [], grantsError: null };
      }

      try {
        const grants = await runtime.admin.listGrants(ctx, data.project);
        return { ok: true as const, project, grants, grantsError: null };
      } catch (error) {
        return {
          ok: true as const,
          project,
          grants: [],
          grantsError: uiFailure(error).error,
        };
      }
    } catch (error) {
      return uiFailure(error);
    }
  });

export const createProject = registeredServerFn({ method: 'POST' })
  .validator(z.object({ slug, name: displayName }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() => runtime.admin.createProject(ctx, data.slug, data.name));
  });

export const updateProject = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, slug, name: displayName }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.updateProject(ctx, data.project, { slug: data.slug, name: data.name }),
    );
  });

export const setProjectArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, archived: z.boolean() }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.setProjectArchived(ctx, data.project, data.archived),
    );
  });

export const createEnvironment = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, slug, name: displayName }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.createEnvironment(ctx, data.project, data.slug, data.name),
    );
  });

export const updateEnvironment = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, environment: slug, slug, name: displayName }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.updateEnvironment(ctx, data.project, data.environment, {
        slug: data.slug,
        name: data.name,
      }),
    );
  });

export const setEnvironmentArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    environment: slug,
    archived: z.boolean(),
  }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.setEnvironmentArchived(
        ctx,
        data.project,
        data.environment,
        data.archived,
      ),
    );
  });

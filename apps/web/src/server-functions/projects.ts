import { z } from 'zod';

import { deriveUiCapabilities } from '../lib/capabilities.ts';
import { conflict } from '../server/api/errors.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import type { GrantRow } from '../shared/models.ts';
import { displayName, slug } from '../shared/schemas.ts';
import { api } from './session.ts';
import { uiFailure, uiMutation, uiResult } from './result.ts';

export const listProjects = registeredServerFn({ method: 'GET' }).handler(async () =>
  uiResult(async () => {
    const coffre = api();
    const [me, { projects }] = await Promise.all([coffre.me(), coffre.projects.list()]);
    return { projects, capabilities: deriveUiCapabilities(me, projects) };
  }),
);

/** One project and, when permitted, its grants. */
export const getProject = registeredServerFn({ method: 'GET' })
  .validator(z.object({ project: slug }))
  .handler(async ({ data }) => {
    try {
      const coffre = api();
      const { projects } = await coffre.projects.list();
      const project = projects.find((entry) => entry.slug === data.project);
      if (!project) return { ok: false as const, error: null };

      if (!project.permissions.includes('grant.manage')) {
        return { ok: true as const, project, grants: [], grantsError: null };
      }

      try {
        const { members } = await coffre.members.list(data.project);
        const grants: GrantRow[] = members.flatMap((member) =>
          member.grants.map((grant) => ({
            id: grant.id,
            principalType: member.principalType,
            principalId: member.principalId,
            role: grant.role,
            roleName: grant.roleName,
            permissions: grant.permissions,
            scope: grant.environment === null ? ('project' as const) : ('environment' as const),
            environmentSlug: grant.environment,
            expiresAt: grant.expiresAt,
          })),
        );
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

/** Creating is an idempotent PUT; the form reports a slug that is taken. */
export const createProject = registeredServerFn({ method: 'POST' })
  .validator(z.object({ slug, name: displayName }))
  .handler(async ({ data }) =>
    uiMutation(async () => {
      const { created } = await api().projects.create(data.slug, { name: data.name });
      if (!created) throw conflict(`a project named "${data.slug}" already exists`);
    }),
  );

export const updateProject = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, slug, name: displayName }))
  .handler(async ({ data }) =>
    uiMutation(() => api().projects.update(data.project, { slug: data.slug, name: data.name })),
  );

export const setProjectArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, archived: z.boolean() }))
  .handler(async ({ data }) =>
    uiMutation(() => api().projects.update(data.project, { archived: data.archived })),
  );

export const createEnvironment = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, slug, name: displayName }))
  .handler(async ({ data }) =>
    uiMutation(async () => {
      const { created } = await api().environments.create(`${data.project}/${data.slug}`, { name: data.name });
      if (!created) throw conflict(`an environment named "${data.slug}" already exists`);
    }),
  );

export const updateEnvironment = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, environment: slug, slug, name: displayName }))
  .handler(async ({ data }) =>
    uiMutation(() =>
      api().environments.update(`${data.project}/${data.environment}`, { slug: data.slug, name: data.name }),
    ),
  );

export const setEnvironmentArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    environment: slug,
    archived: z.boolean(),
  }))
  .handler(async ({ data }) =>
    uiMutation(() =>
      api().environments.update(`${data.project}/${data.environment}`, { archived: data.archived }),
    ),
  );

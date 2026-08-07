import { z } from 'zod';

import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import {
  grantId,
  instanceRole,
  isoDateTime,
  principalId,
  principalType,
  slug,
} from '../shared/schemas.ts';
import { currentRequestContext } from './session.ts';
import { uiFailure, uiMutation } from './result.ts';

export const listDirectoryPrincipals = registeredServerFn({ method: 'GET' }).handler(async () => {
  const runtime = getRuntime();
  const ctx = currentRequestContext();
  try {
    return { ok: true as const, principals: await runtime.admin.listDirectory(ctx) };
  } catch (error) {
    const status =
      typeof error === 'object' && error !== null && 'statusCode' in error
        ? (error as { statusCode?: number }).statusCode
        : undefined;
    if (status === 403) {
      return { ok: false as const, error: 'Only owners can manage users and service accounts.' };
    }
    return uiFailure(error);
  }
});

export const createGrant = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    principalType,
    principalId,
    role: slug,
    environmentSlug: slug.nullable(),
    expiresAt: isoDateTime.nullable(),
  }))
  .handler(async ({ data }) => {
    const { project, ...input } = data;
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() => runtime.admin.createGrant(ctx, project, input));
  });

export const revokeGrant = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, grantId }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() => runtime.admin.revokeGrant(ctx, data.project, data.grantId));
  });

export const updateGrant = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, grantId, role: slug }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.updateGrant(ctx, data.project, data.grantId, data.role),
    );
  });

export const createDirectoryPrincipal = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    principalType,
    principalId,
    instanceRole,
  }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() => runtime.admin.addDirectoryPrincipal(ctx, data));
  });

export const updateDirectoryPrincipalRole = registeredServerFn({ method: 'POST' })
  .validator(z.object({ principalId, instanceRole }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.updateDirectoryPrincipalRole(ctx, data.principalId, data.instanceRole),
    );
  });

export const removeDirectoryPrincipal = registeredServerFn({ method: 'POST' })
  .validator(z.object({ principalType, principalId }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.admin.removeDirectoryPrincipal(ctx, data.principalType, data.principalId),
    );
  });

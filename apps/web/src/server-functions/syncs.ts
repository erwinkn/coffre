import { z } from 'zod';

import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import { slug, syncId } from '../shared/schemas.ts';
import { currentRequestContext } from './session.ts';
import { uiResult } from './result.ts';

export const listSyncs = registeredServerFn({ method: 'GET' })
  .validator(z.object({ project: slug, environment: slug }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(() => runtime.syncs.list(ctx, data.project, data.environment));
  });

export const createSync = registeredServerFn({ method: 'POST' })
  .validator(
    z.object({
      project: slug,
      environment: slug,
      provider: z.string().min(1).max(64),
      config: z.record(z.string(), z.unknown()),
      credential: z.string().min(1).max(400),
    }),
  )
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => ({
      sync: await runtime.syncs.create(ctx, data.project, data.environment, {
        provider: data.provider,
        config: data.config,
        credential: data.credential,
      }),
    }));
  });

/** Runs in the request, so the toast can say what left. */
export const runSync = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: syncId }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(() => runtime.syncs.runNow(ctx, data.id));
  });

export const setSyncPaused = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: syncId, paused: z.boolean() }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => ({ sync: await runtime.syncs.setPaused(ctx, data.id, data.paused) }));
  });

export const archiveSync = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: syncId }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => ({ sync: await runtime.syncs.archive(ctx, data.id) }));
  });

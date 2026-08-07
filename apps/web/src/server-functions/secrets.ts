import { z } from 'zod';

import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import { parseDotenv } from '../server/services/dotenv.ts';
import { secretKey, slug } from '../shared/schemas.ts';
import { currentRequestContext } from './session.ts';
import { uiMutation, uiResult } from './result.ts';

const secretRef = {
  project: slug,
  environment: slug,
  key: secretKey,
};

export const listKeys = registeredServerFn({ method: 'GET' })
  .validator(z.object({ project: slug, environment: slug }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(() => runtime.secrets.listKeys(ctx, data.project, data.environment));
  });

/** Reveals are POST server functions so they cannot be prefetched or cached as navigation. */
export const revealSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object(secretRef))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => {
      const secret = await runtime.secrets.readSecret(
        ctx,
        data.project,
        data.environment,
        data.key,
      );
      return { value: secret.value };
    });
  });

export const saveSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, value: z.string().max(64 * 1024) }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => {
      const written = await runtime.secrets.writeSecret(
        ctx,
        data.project,
        data.environment,
        data.key,
        data.value,
      );
      return { version: written.version };
    });
  });

export const renameSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, nextKey: secretKey }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.secrets.renameSecret(
        ctx,
        data.project,
        data.environment,
        data.key,
        data.nextKey,
      ),
    );
  });

export const setSecretArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, archived: z.boolean() }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.secrets.setSecretArchived(
        ctx,
        data.project,
        data.environment,
        data.key,
        data.archived,
      ),
    );
  });

export const listVersions = registeredServerFn({ method: 'POST' })
  .validator(z.object(secretRef))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => {
      const result = await runtime.secrets.listVersions(
        ctx,
        data.project,
        data.environment,
        data.key,
      );
      return { versions: result.versions };
    });
  });

export const rollbackSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, version: z.number().int().positive() }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiMutation(() =>
      runtime.secrets.rollback(
        ctx,
        data.project,
        data.environment,
        data.key,
        data.version,
      ),
    );
  });

export const importEnv = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    environment: slug,
    content: z.string().max(1024 * 1024),
    dryRun: z.boolean(),
  }))
  .handler(async ({ data }) => {
    const parsed = parseDotenv(data.content);
    if (parsed.entries.length === 0 && parsed.problems.length > 0) {
      return { ok: true as const, plan: [], problems: parsed.problems };
    }

    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => {
      const result = await runtime.secrets.importSecrets(
        ctx,
        data.project,
        data.environment,
        parsed.entries,
        data.dryRun,
      );
      return { plan: result.plan, problems: parsed.problems };
    });
  });

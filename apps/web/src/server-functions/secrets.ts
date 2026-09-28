import { z } from 'zod';

import { planImport } from '../../../../packages/client/src/index.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import { parseDotenv } from '../../../../packages/core/src/dotenv.ts';
import { secretKey, slug } from '../shared/schemas.ts';
import { api } from './session.ts';
import { uiMutation, uiResult } from './result.ts';

const secretRef = {
  project: slug,
  environment: slug,
  key: secretKey,
};

type SecretRef = { project: string; environment: string; key: string };
const pathOf = (ref: SecretRef) => `${ref.project}/${ref.environment}/${ref.key}`;

export const listKeys = registeredServerFn({ method: 'GET' })
  .validator(z.object({ project: slug, environment: slug }))
  .handler(async ({ data }) =>
    uiResult(() => api().secrets.list(`${data.project}/${data.environment}`)),
  );

/** Reveals are POST server functions so they cannot be prefetched or cached as navigation. */
export const revealSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object(secretRef))
  .handler(async ({ data }) =>
    uiResult(async () => {
      const { values } = await api().secrets.reveal(pathOf(data));
      return { value: values[data.key] };
    }),
  );

export const saveSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, value: z.string().max(64 * 1024) }))
  .handler(async ({ data }) =>
    uiResult(async () => {
      const { keys } = await api().secrets.set(`${data.project}/${data.environment}`, {
        [data.key]: data.value,
      });
      const outcome = keys[data.key];
      return { version: 'version' in outcome ? outcome.version : 0 };
    }),
  );

export const renameSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, nextKey: secretKey }))
  .handler(async ({ data }) => uiMutation(() => api().secrets.rename(pathOf(data), data.nextKey)));

export const setSecretArchived = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, archived: z.boolean() }))
  .handler(async ({ data }) =>
    uiMutation(() => api().secrets.update(pathOf(data), { archived: data.archived })),
  );

export const listVersions = registeredServerFn({ method: 'POST' })
  .validator(z.object(secretRef))
  .handler(async ({ data }) =>
    uiResult(async () => ({ versions: (await api().secrets.history(pathOf(data))).versions })),
  );

export const rollbackSecret = registeredServerFn({ method: 'POST' })
  .validator(z.object({ ...secretRef, version: z.number().int().positive() }))
  .handler(async ({ data }) => uiMutation(() => api().secrets.restore(pathOf(data), data.version)));

export const importEnv = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    environment: slug,
    content: z.string().max(1024 * 1024),
    dryRun: z.boolean(),
  }))
  .handler(async ({ data }) => {
    const parsed = parseDotenv(data.content);
    if (parsed.entries.length === 0) {
      return { ok: true as const, plan: [], problems: parsed.problems };
    }

    return uiResult(async () => {
      const coffre = api();
      const path = `${data.project}/${data.environment}`;
      const { plan, changes } = await planImport(coffre, path, parsed.entries);
      if (!data.dryRun && Object.keys(changes).length > 0) await coffre.secrets.set(path, changes);
      return { plan, problems: parsed.problems };
    });
  });

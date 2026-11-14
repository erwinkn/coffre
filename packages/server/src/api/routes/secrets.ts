import { createHash } from 'node:crypto';

import { environmentPath, personalOf, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { changed } from '../change.ts';
import { ApiError, badRequest, refusal } from '../errors.ts';
import { stopOf } from '../given.ts';
import { parsePath } from '../paths.ts';
import { route } from '../route.ts';

/** The most keys one read names, as the vault takes them. */
const MOST_READ = 1000;
/** A value's length, in UTF-16 units, as the vault takes one (`secret.write`). */
const VALUE_LENGTH = 64 * 1024;

/** A value as text Postgres stores and a reader gets back as written: no NUL, no half of a surrogate pair. The vault's own rule, told here as a 400. */
const secretValue = z.string().max(VALUE_LENGTH).refine((value) => !value.includes('\0') && Buffer.from(value).toString() === value, 'a value is well-formed text, with no NUL');

/** An environment as a path names it: its slug, and whether it is the caller's personal config of it (`dev@me`). */
export function environmentOf(named: string): { environment: string; mine: boolean } {
  const of = personalOf(named);
  return of === null ? { environment: named, mine: false } : { environment: of, mine: true };
}

/**
 * A read's version: each key with the secret and version it resolved to,
 * in the order read. What a watch compares the next one with (`coffre
 * export --watch`): it changes whenever what a read opens does.
 */
export function versionOf(read: readonly { key: string; secret: string; version: number }[]): string {
  // Key names hold no NUL or newline (`secretKey`).
  const hash = createHash('sha256');
  for (const item of read) hash.update(`${item.key}\0${item.secret}:${item.version}\n`);
  return hash.digest('base64url');
}

/**
 * `market/prod` or `market/prod/KEY`, each part as a path's segment is
 * (`PARAMS`): the vault takes a name as given, and one it cannot store is
 * its fault, not a refusal.
 */
const readPath = z.string().max(400).transform((text, issue) => {
  const path = parsePath(text, [2, 3]);
  if (!slug.safeParse(path.project).success || !environmentPath.safeParse(path.environment).success || (path.key !== undefined && !secretKey.safeParse(path.key).success)) {
    issue.addIssue({ code: 'custom', message: `"${text.slice(0, 80)}" names no environment or secret` });
    return z.NEVER;
  }
  return { project: path.project, environment: path.environment!, key: path.key };
});

export const secretRoutes = {
  /**
   * The only way to open a value, and a POST so nothing can trigger it by
   * prefetching: one call to the vault, which finds the caller, decides,
   * opens and logs.
   *
   * `market/prod/KEY` is one key, refused whole with why. `market/prod` is
   * the environment, or with `keys` those of its keys: it answers what the
   * caller is given and names what it left out, a person's sensitive
   * values in `sensitive` and a workload's use-only ones in `useOnly`; a
   * key it does not hold, or one with no value, is left out unnamed. Any
   * other key that cannot be read refuses the whole read, rather than run
   * without it.
   */
  ...route('POST /reveals', {
    input: z.object({ path: readPath, keys: z.array(secretKey).min(1).max(MOST_READ).optional() }).strict(),
    run: async (ctx, { input }) => {
      const { path } = input;
      const named = `${path.project}/${path.environment}`;
      if (input.keys !== undefined && path.key !== undefined) throw badRequest('keys names keys of an environment: give its path, <project>/<environment>');
      const one = path.key;
      const answer = await ctx.vault.use({
        ...ctx.shown,
        project: path.project,
        ...environmentOf(path.environment),
        keys: one === undefined ? (input.keys ?? null) : [one],
        purpose: one === undefined ? 'run' : 'reveal',
        upstream: null,
      });
      if ('refused' in answer) throw refusal(answer.refused, one === undefined ? named : `${named}/${one}`);
      // A null-prototype record: a key named __proto__ is a key like any other.
      const values: Record<string, string> = Object.create(null);
      const read: { key: string; secret: string; version: number }[] = [];
      const left: Record<string, string[]> = { sensitive: [], use_only: [] };
      // One key is refused whole with why; a whole environment, as `stopOf` says.
      const stop = one === undefined ? stopOf(answer.values) : answer.values.find((item) => 'refused' in item);
      if (stop !== undefined && 'refused' in stop) throw refusal(stop.refused, `${named}/${stop.key}`);
      for (const item of answer.values) {
        if ('refused' in item) left[item.refused]?.push(item.key);
        else {
          values[item.key] = item.value;
          read.push(item);
        }
      }
      return { operationId: ctx.shown.request, values: { ...values }, sensitive: left.sensitive!, useOnly: left.use_only!, version: one === undefined ? versionOf(read) : null };
    },
  }),

  /**
   * Write values in one environment: `{ "KEY": "value" }`, or
   * `{ "KEY": { "value", "sensitivity": "sensitive" } }` to say who sees
   * it. One call to the vault, which decides and writes all of them or
   * none, and says each one's sensitivity as written: a bare value is
   * sensitive over a sensitive one, and a secret otherwise (`secret.write`).
   *
   * Not served yet, each refused as a 400 by the input's shape or below:
   * archiving a key (`null`), a generated value, a reference, a nature
   * changed in place, a dry run, and `dev@me`.
   */
  ...route('PATCH /secrets/:project/:environment', {
    input: z.record(secretKey, z.union([secretValue, z.object({ value: secretValue, sensitivity: z.enum(['plain', 'secret', 'sensitive']) }).strict()])).refine((patch) => Object.keys(patch).length > 0, 'name at least one key'),
    query: z.object({}).strict(),
    run: async (ctx, { params, input }) => {
      const { environment, mine } = environmentOf(params.environment);
      if (mine) throw new ApiError('not_implemented', `a write to ${params.project}/${params.environment}, your personal config, is not served yet`);
      const values = Object.entries(input).map(([key, written]) => (typeof written === 'string' ? { key, value: written } : { key, value: written.value, nature: written.sensitivity }));
      const answer = await changed(ctx, { op: 'secret.write', project: params.project, environment, keys: values }, `${params.project}/${params.environment}`);
      // As entries: a key named __proto__ is a key like any other.
      return { operationId: ctx.shown.request, keys: Object.fromEntries(Object.entries(answer.keys).map(([key, { version, nature }]) => [key, { version, sensitivity: nature }])) };
    },
  }),
};

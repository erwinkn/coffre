import { createHash } from 'node:crypto';

import { environmentPath, personalOf, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { changed } from '../change.ts';
import { ApiError, badRequest, refusal } from '../errors.ts';
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

/** What a whole environment's read leaves out and names, and what it leaves out as not there: any other refusal of a key refuses the read. */
const LEFT_OUT = new Set(['sensitive', 'use_only', 'unknown_key', 'no_value']);

/**
 * The key that refuses a whole environment's read, or none: past a key's
 * name, a fork says nothing of what its reader cannot read, so a parent
 * the caller does not read is told first. The reveal's rule, and the
 * version's (`GET …/version`).
 */
export function stopOf(items: readonly ({ key: string } | { key: string; refused: string })[]): { key: string; refused: string } | undefined {
  const stops = items.filter((item): item is { key: string; refused: string } => 'refused' in item && !LEFT_OUT.has(item.refused));
  return stops.find((item) => item.refused === 'parent_unreadable') ?? stops[0];
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

/** A reference's source, `market/prod/KEY`: a key of an environment, never of a personal config. */
const sourcePath = readPath.refine((path) => path.key !== undefined && personalOf(path.environment) === null, 'a reference names its source as <project>/<environment>/<KEY>, never in a personal config');

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
   * it; `{ "KEY": { "ref": "billing/prod/STRIPE_KEY" } }` makes the key a
   * reference to that one, which whoever reads here reads through it. One
   * call to the vault, which decides and writes all of them or none, and
   * says each value's sensitivity as written: a bare value is sensitive over
   * a sensitive one, and a secret otherwise (`secret.write`). A reference
   * is answered with its source, as asked.
   *
   * Not served yet, each refused as a 400 by the input's shape or below:
   * archiving a key (`null`), a generated value, a nature changed in place,
   * a dry run, and `dev@me`.
   */
  ...route('PATCH /secrets/:project/:environment', {
    input: z.record(secretKey, z.union([secretValue, z.object({ value: secretValue, sensitivity: z.enum(['plain', 'secret', 'sensitive']) }).strict(), z.object({ ref: sourcePath }).strict()]))
      .refine((patch) => Object.keys(patch).length > 0, 'name at least one key'),
    query: z.object({}).strict(),
    run: async (ctx, { params, input }) => {
      const { environment, mine } = environmentOf(params.environment);
      if (mine) throw new ApiError('not_implemented', `a write to ${params.project}/${params.environment}, your personal config, is not served yet`);
      const keys = Object.entries(input).map(([key, written]) => (typeof written === 'string' ? { key, value: written }
        : 'ref' in written ? { key, ref: { project: written.ref.project, environment: written.ref.environment, key: written.ref.key! } }
          : { key, value: written.value, nature: written.sensitivity }));
      const answer = await changed(ctx, { op: 'secret.write', project: params.project, environment, keys }, `${params.project}/${params.environment}`);
      const references = keys.flatMap((item) => (item.ref === undefined ? [] : [[item.key, { reference: `${item.ref.project}/${item.ref.environment}/${item.ref.key}` }] as const]));
      // As entries: a key named __proto__ is a key like any other.
      return { operationId: ctx.shown.request, keys: Object.fromEntries([...Object.entries(answer.keys).map(([key, { version, nature }]) => [key, { version, sensitivity: nature }] as const), ...references]) };
    },
  }),

  /**
   * Break the reference a key is: whoever read through it reads nothing
   * there until the key is given a value. Whoever writes the key may, and
   * whoever manages access in its source's project; one call to the vault,
   * which decides (`reference.break`). Answered with what it read, by the
   * source's rows: `(gone)` where the vault does not see them. Who made the
   * reference, and when, is the log's, read with the references' list.
   */
  ...route('DELETE /secrets/:project/:environment/:key/reference', {
    run: async (ctx, { params }) => {
      const holder = `${params.project}/${params.environment}/${params.key}`;
      // A personal config holds values only.
      if (environmentOf(params.environment).mine) throw refusal('no_reference', holder);
      const { source } = await changed(ctx, { op: 'reference.break', project: params.project, environment: params.environment, key: params.key }, holder);
      return { operationId: ctx.shown.request, reference: { holder, source: source === null ? '(gone)' : `${source.project}/${source.environment}/${source.key}`, state: 'broken' as const } };
    },
  }),
};

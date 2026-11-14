import { createHash, timingSafeEqual } from 'node:crypto';

import { formatRecipe, parseRecipe, recipeProblem, type Generation } from '@coffre/core/recipe';
import { environmentPath, folderName, personalOf, rowId, secretKey, slug } from '@coffre/core/schemas';
import type { KeyWrite, SecretWrite } from '@coffre/core/vault';
import { z } from 'zod';

import type { Nature } from '../../db/queries/secrets.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { badRequest, refusal } from '../errors.ts';
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

/** How a client made a value (`@coffre/core/recipe`): its recipe, and for a key pair the two keys it writes. */
const generation = z.object({ recipe: z.string().max(64), pair: z.object({ private: secretKey, public: secretKey }).strict().optional() }).strict();

/**
 * What is wrong with a patch's generated values, or null, as 0.14.7 said
 * it. A key pair's recipe writes its two keys at once, each naming both,
 * `{ private, public }`, the same on both, with the same recipe. Any other
 * recipe names no pair.
 */
function generationProblem(patch: Readonly<Record<string, unknown>>): string | null {
  const generationOf = (value: unknown): Generation | null =>
    value !== null && typeof value === 'object' && 'generated' in value ? (value as { generated: Generation }).generated : null;
  for (const [key, value] of Object.entries(patch)) {
    const generated = generationOf(value);
    if (generated === null) continue;
    const problem = recipeProblem(generated.recipe);
    if (problem !== null) return `${key}: ${problem}`;
    const recipe = formatRecipe(parseRecipe(generated.recipe));
    const { pair } = generated;
    if (parseRecipe(recipe).kind !== 'pair') {
      if (pair !== undefined) return `${key}: ${recipe} makes one value, not a key pair`;
      continue;
    }
    if (pair === undefined) return `${key}: ${recipe} makes a key pair: name its private and public keys`;
    if (pair.private === pair.public) return `${key}: a key pair's two keys need different names`;
    if (key !== pair.private && key !== pair.public) return `${key}: it is neither key of the pair it names, ${pair.private} and ${pair.public}`;
    const other = key === pair.private ? pair.public : pair.private;
    const theirs = Object.hasOwn(patch, other) ? generationOf(patch[other]) : null;
    if (theirs === null || recipeProblem(theirs.recipe) !== null || formatRecipe(parseRecipe(theirs.recipe)) !== recipe
      || theirs.pair?.private !== pair.private || theirs.pair.public !== pair.public) {
      return `${key}: a key pair is written whole: ${other} needs the same recipe and pair in the same patch`;
    }
  }
  return null;
}

/** A recipe as the vault keeps it, `bytes:32:base62` for `BYTES:32`: what Regenerate reads back. */
const canonical = ({ recipe, pair }: Generation): Generation => ({ recipe: formatRecipe(parseRecipe(recipe)), ...(pair === undefined ? {} : { pair: { private: pair.private, public: pair.public } }) });

/** What a merge patch would do to a key: the answer to `?dryRun=1`, as 0.14's. */
export type DryRunOutcome = 'added' | 'changed' | 'unchanged' | 'archived';
export type DryRunResult = { dryRun: true; keys: Record<string, DryRunOutcome> };

/** A merge patch written, as 0.14 answered it: each key's version and sensitivity as written, a reference's source, or archived. */
export type SetResult = {
  operationId: string | null;
  keys: Record<string, { version: number; sensitivity: Nature } | { archived: true } | { reference: string }>;
};

/** Whether two values are the same, in a time that says nothing of where they differ. */
const same = (a: string, b: string) => timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());

/**
 * A write weighed (`vault.weigh`), and nothing written: what it would do to
 * each key, never a value. A value typed over the key's own, as it is kept,
 * is `unchanged` only if it is that value, which takes opening it: the vault
 * names the version (`compare`), and one use opens those keys for the
 * caller, purpose `compare`, logged as a read and counted toward the cap,
 * as 0.14's dry run did. Each is `unchanged` only if the use handed back
 * the very version weighed, so neither a version written in between nor a
 * value read through a reference or a parent is ever compared, and it is
 * the value written. A key the use refuses, sensitive to a person or used
 * only, or a use refused whole, is `changed`: nobody is told their guess
 * is right unless they read the value. 0.14 refused the whole dry run
 * without `secret.read`; a writer who does not read is told what the
 * write's own answer would tell them, every value `changed`.
 */
async function dryRun(ctx: ApiContext, change: SecretWrite, values: ReadonlyMap<string, string>, at: string): Promise<DryRunResult> {
  const weighed = await ctx.vault.weigh<'secret.write'>({ ...ctx.shown, ...change });
  if ('refused' in weighed) throw refusal(weighed.refused, at);
  const { outcomes } = weighed.answer;
  const asked = Object.entries(outcomes).flatMap(([key, outcome]) => (typeof outcome === 'object' ? [{ key, ...outcome.compare }] : []));
  // A null-prototype record: a key named __proto__ is a key like any other.
  const keys: Record<string, DryRunOutcome> = Object.create(null);
  for (const [key, outcome] of Object.entries(outcomes)) keys[key] = typeof outcome === 'object' ? 'changed' : outcome;
  // A use reads 1,000 keys at most, and a write names 2,000.
  for (let from = 0; from < asked.length; from += MOST_READ) {
    const batch = asked.slice(from, from + MOST_READ);
    const used = await ctx.vault.use({ ...ctx.shown, project: change.project, environment: change.environment, mine: change.mine ?? false, keys: batch.map((item) => item.key), purpose: 'compare', upstream: null });
    if ('refused' in used) continue;
    const given = new Map(used.values.map((item) => [item.key, item]));
    for (const { key, secret, version } of batch) {
      const got = given.get(key);
      if (got !== undefined && !('refused' in got) && got.secret === secret && got.version === version && same(got.value, values.get(key)!)) keys[key] = 'unchanged';
    }
  }
  return { dryRun: true, keys: { ...keys } };
}

/** The keys a folder of one environment, or of the caller's personal config of it, held, re-filed under `to`, or in none. */
async function refiled(ctx: ApiContext, params: { project: string; environment: string; folder: string }, to: string | null): Promise<string[]> {
  const at = `${params.project}/${params.environment}`;
  return (await changed(ctx, { op: 'secret.refile', project: params.project, ...environmentOf(params.environment), folder: params.folder, to }, `${at}, folder ${params.folder}`)).moved;
}

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
   * it; `{ "KEY": { "value", "generated": { "recipe": "bytes:32:hex" } } }`
   * for a value a client made by a recipe, which Regenerate makes the next
   * one by, never plain, and for a key pair both keys at once, each naming
   * the pair, `"pair": { "private", "public" }` (a 400 otherwise); with
   * `"replaces"`, the version id a listing gave (`versionId`), a value is
   * written only over that version, and is a 409 `stale` if the key holds
   * another now (a regenerate's); `{ "KEY": { "ref": "billing/prod/STRIPE_KEY" } }` makes the key a
   * reference to that one, which whoever reads here reads through it;
   * `{ "KEY": null }` archives the key, which takes `secret.archive`. One
   * call to the vault, which decides and writes all of them or none, and
   * says each value's sensitivity as written: a bare value is sensitive over
   * a sensitive one, and a secret otherwise (`secret.write`). A reference
   * is answered with its source, as asked, and a key archived as archived.
   *
   * In `dev@me`, the caller's personal config of dev, made by a write that
   * gives a key a value where they have none, as 0.14's: its owner's alone,
   * while they read or use dev, and it holds no reference (a 400).
   *
   * With `?dryRun=1`, what the write would do to each key, and nothing
   * written (`dryRun`): `added`, `changed`, `unchanged` or `archived`.
   *
   * Not served yet, refused as a 400 by the input's shape: a nature
   * changed in place, `{ "sensitivity" }` alone.
   */
  ...route('PATCH /secrets/:project/:environment', {
    input: z.record(secretKey, z.union([
      secretValue,
      z.object({ value: secretValue, generated: generation, replaces: rowId.optional(), sensitivity: z.enum(['secret', 'sensitive']).optional() }).strict(),
      z.object({ value: secretValue, sensitivity: z.enum(['plain', 'secret', 'sensitive']), replaces: rowId.optional() }).strict(),
      z.object({ ref: sourcePath }).strict(),
    ]).nullable())
      .refine((patch) => Object.keys(patch).length > 0, 'name at least one key'),
    // `?dryRun=1` weighs the write and makes none. Any other query is refused, not ignored: a mistyped flag must not write.
    query: z.object({ dryRun: z.enum(['1', 'true']).optional() }).strict(),
    run: async (ctx, { params, input, query }): Promise<SetResult | DryRunResult> => {
      const { environment, mine } = environmentOf(params.environment);
      if (mine && Object.values(input).some((written) => typeof written === 'object' && written !== null && 'ref' in written)) {
        throw badRequest(`${params.project}/${params.environment} is your personal config, which holds values only: make the reference in ${params.project}/${environment}`);
      }
      const problem = generationProblem(input);
      if (problem !== null) throw badRequest(problem);
      const keys = Object.entries(input).map(([key, written]): KeyWrite => (written === null ? { key, archived: true } : typeof written === 'string' ? { key, value: written }
        : 'ref' in written ? { key, ref: { project: written.ref.project, environment: written.ref.environment, key: written.ref.key! } }
          : { key, value: written.value, nature: written.sensitivity, replaces: written.replaces, ...('generated' in written ? { generated: canonical(written.generated) } : {}) }));
      const change = { op: 'secret.write', project: params.project, environment, mine, keys } as const;
      const at = `${params.project}/${params.environment}`;
      if (query.dryRun !== undefined) return dryRun(ctx, change, new Map(keys.flatMap((item) => (item.value === undefined ? [] : [[item.key, item.value]]))), at);
      const answer = await changed(ctx, change, at);
      const told = keys.flatMap((item): [string, { reference: string } | { archived: true }][] => (item.ref !== undefined ? [[item.key, { reference: `${item.ref.project}/${item.ref.environment}/${item.ref.key}` }]]
        : item.archived === true ? [[item.key, { archived: true }]] : []));
      // As entries: a key named __proto__ is a key like any other.
      return { operationId: ctx.shown.request, keys: Object.fromEntries([...Object.entries(answer.keys).map(([key, { version, nature }]) => [key, { version, sensitivity: nature }] as const), ...told]) };
    },
  }),

  /**
   * Archive one key, or bring it back (`archived`), and file it in a
   * folder, or in none (`folder`): one call to the vault, which decides
   * both or neither (`secret.write`). Archiving takes `secret.archive`, a
   * return `secret.read` too, since the value serves again; filing takes
   * `secret.write`, archived or not. Or, alone, in a fork, reset it to what
   * a parent passes down (`inherit: true`), its own value archived, or
   * undo that (`false`): `secret.write`, as writing over a parent's does,
   * and `secret.read` to undo, since its value serves again. Answered with
   * the key and what was asked of it, which is what it now is; 0.14 also
   * answered a reset with the parent it reads and the key's folder.
   *
   * Or, alone, rename it (`key`), with its history, as `secret.write`
   * takes: one change of the vault's (`secret.rename`), which carries the
   * name down to every fork below. 0.14 took a rename beside an archiving
   * or a folder, in one transaction; asked together here, it is a 400. Its
   * own name beside the rest is no rename, as in 0.14.
   */
  ...route('PATCH /secrets/:project/:environment/:key', {
    input: z.object({ key: secretKey, archived: z.boolean(), folder: folderName.nullable(), inherit: z.boolean() }).partial().strict()
      .refine((patch) => patch.key !== undefined || patch.archived !== undefined || patch.folder !== undefined || patch.inherit !== undefined, 'provide a key, an archived flag, a folder or inherit')
      .refine((patch) => patch.inherit === undefined || Object.keys(patch).length === 1, 'inherit goes alone'),
    run: async (ctx, { params, input }) => {
      const at = `${params.project}/${params.environment}/${params.key}`;
      const { archived, folder, inherit } = input;
      // Alone, a name is a rename, onto its own name included, which the vault logs as asked; beside the rest, its own is none.
      if (input.key !== undefined && archived === undefined && folder === undefined) {
        await changed(ctx, { op: 'secret.rename', project: params.project, ...environmentOf(params.environment), key: params.key, to: input.key }, at);
        return { operationId: ctx.shown.request, key: input.key };
      }
      if (input.key !== undefined && input.key !== params.key) throw badRequest('rename a key on its own, not with an archiving or a folder');
      const write: KeyWrite = inherit === undefined ? { key: params.key, archived, folder } : { key: params.key, inherit };
      await changed(ctx, { op: 'secret.write', project: params.project, ...environmentOf(params.environment), keys: [write] }, at);
      return { operationId: ctx.shown.request, key: params.key, ...(archived === undefined ? {} : { archived }), ...(folder === undefined ? {} : { folder }), ...(inherit === undefined ? {} : { inherit }) };
    },
  }),

  /**
   * Restore a version of a key: its value becomes the key's next version,
   * opened and sealed again by the vault, which hands it to nobody. It
   * comes back as it was kept, and sensitive while the key is or its
   * newest value was; made by a recipe or in a pair, it comes back as
   * typed. One call to the vault (`secret.write`), which takes
   * `secret.write` and `secret.read`: the old value serves again. An
   * archived key is brought back first. Answered with the version it is
   * now, and its sensitivity.
   */
  ...route('POST /secrets/:project/:environment/:key/restore', {
    input: z.object({ version: z.number().int().min(1).max(2 ** 31 - 1) }).strict(),
    run: async (ctx, { params, input }) => {
      const at = `${params.project}/${params.environment}/${params.key}`;
      const answer = await changed(ctx, { op: 'secret.write', project: params.project, ...environmentOf(params.environment), keys: [{ key: params.key, restore: input.version }] }, at);
      const { version, nature } = Object.entries(answer.keys).find(([key]) => key === params.key)![1];
      return { operationId: ctx.shown.request, key: params.key, version, sensitivity: nature };
    },
  }),

  /**
   * Rename a folder of an environment's keys: every key filed there,
   * archived ones too, at once, by whoever writes keys there
   * (`secret.refile`). A folder is a label, so renaming onto one that is
   * there merges them.
   */
  ...route('PATCH /folders/:project/:environment/:folder', {
    input: z.object({ name: folderName }).strict(),
    run: async (ctx, { params, input }) => ({ operationId: ctx.shown.request, folder: input.name, moved: await refiled(ctx, params, input.name) }),
  }),

  /** Empty a folder of an environment's keys: each stays where it is, in no folder. */
  ...route('DELETE /folders/:project/:environment/:folder', {
    run: async (ctx, { params }) => ({ operationId: ctx.shown.request, folder: null, moved: await refiled(ctx, params, null) }),
  }),

  /**
   * Dismiss keys an environment is missing (`true`), or restore them
   * (`null`), as a merge patch: "Dismiss all" is one call, and one entry
   * in the log. The team's decision, which its missing keys list shows
   * apart until someone restores it. In a fork, or `dev@me`, a dismissal is
   * also a removal: the key is no longer inherited there. Whoever writes
   * keys there may; one call to the vault, which decides and writes them
   * all or none (`missing.dismiss`), 2,000 keys at most.
   */
  ...route('PATCH /projects/:project/:environment/dismissals', {
    input: z.record(secretKey, z.literal(true).nullable()).refine((patch) => Object.keys(patch).length > 0, 'name at least one key'),
    run: async (ctx, { params, input }) => {
      const keys = Object.entries(input).map(([key, dismissed]) => ({ key, dismissed: dismissed === true }));
      const answer = await changed(ctx, { op: 'missing.dismiss', project: params.project, ...environmentOf(params.environment), keys }, `${params.project}/${params.environment}`);
      return { operationId: ctx.shown.request, keys: answer.keys };
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

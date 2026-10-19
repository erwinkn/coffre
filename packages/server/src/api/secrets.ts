import { createHash, randomUUID } from 'node:crypto';

import type { Permission } from '@coffre/core/access';
import type { Envelope } from '@coffre/core/envelope';
import { formatRecipe, parseRecipe, recipeProblem, type Generation } from '@coffre/core/recipe';
import { isTombstone } from '@coffre/core/schemas';
import type { HolderRef, SecretRef } from '@coffre/core/vault';
import type { Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation, SNAPSHOT } from '@coffre/db/dialect';
import { dismissedKeys, secretReferences, secrets, secretVersions } from '@coffre/db/schema';

import {
  dismissalsIn,
  environmentSecrets,
  insert,
  insertIfAbsent,
  lock,
  recipeRow,
  referenceRows,
  resolvePath,
  secretHeads,
  secretPlaces,
  sensitiveVersions,
  secretsInFolder,
  secretHistory,
  update,
  MAX_PARENTS,
  type ParentRow,
  type ResolvedPath,
  type SecretPlaceRow,
  type SecretRow,
  type VersionRecipe,
  upsert,
  fileSecrets,
  secretFolderOf,
} from '../db/queries.ts';
import { can, lists, permissionsAt, placeOf } from './caller.ts';
import { allowed, asking, audited, denied, need, recorded, refuse, Refusal, vaultRefusal, withRefusals, type ApiContext } from './context.ts';
import type { AuditEntry } from '../db/audit.ts';
import { ApiError, badRequest, conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import { descendantsOf, inheritedRows, type InheritedRow } from './inheritance.ts';
import { personalName, resolveRead } from './personal.ts';
import { openValues, plain, rewrapValue, rewrapValues, sealValues } from './keys.ts';
import { formatMember, formatPath, type Path } from './paths.ts';
import { currentReferences, placeOfRow, readableValues, readersOf, refuseIfRead, unreadParents, type Readable, type ReferenceView, type Resolved, type Unreadable } from './references.ts';

export type SecretKey = {
  key: string;
  /**
   * The reference it is, when it has no value of its own: what it reads,
   * whether it does, and whether you could open its source where it is.
   */
  reference: (ReferenceView & { canOpenSource: boolean }) | null;
  /** The folder it is listed in within this environment, or null for none. */
  folder: string | null;
  archived: boolean;
  /** Its own current version; a reference has none, and reads its source's. */
  version: number | null;
  /**
   * When the value it reads was written: its current version, or a live
   * reference's source's current version. A rename or a move is no write.
   * Null while it reads no value.
   */
  updatedAt: string | null;
  /** Who wrote its own current version; null for a reference. */
  updatedBy: string | null;
  /**
   * The id of the version it resolves to, its own or, in a fork, the one
   * it inherits: what a regenerate says it `replaces`. Unique, unlike a
   * version number, which each row counts from one. Null where `version` is.
   */
  versionId: string | null;
  /**
   * How its current value was made, when a client generated it: what
   * Regenerate makes the next one by. A key pair's half has it only while
   * the other half's current value is from the same pair.
   */
  generated: Generation | null;
  /**
   * The value itself, for a plain key: no secret, an account's id, shown to
   * whoever lists the environment and, inherited, to whoever reads the
   * parent that holds it. Null for a secret, and for a reference.
   */
  value: string | null;
  /**
   * Who sees its current value (`Sensitivity`): `plain`, whoever lists the
   * environment; `secret`, those whose role reads it; `sensitive`, nobody,
   * Owners included, its apps using it through the credential proxy and
   * service accounts reading it. A live reference's is its source's
   * current value's, a plain one read as a secret. Null where there is no
   * value to read.
   */
  sensitivity: Sensitivity | null;
  /**
   * Whether you may see its current value: a plain one listed here, or a
   * secret where it is held, here or, inherited, on the parent that holds
   * it. A Contributor's personal config reads their own values, and none of
   * its parent's. False for a sensitive value, which nobody sees, and where
   * there is no value to read.
   */
  readable: boolean;
  /**
   * In a fork, the key its parents hold under this name
   * (docs/design/forking.md): `inherited`, no row here, the parent's value
   * read live; `overridden`, a value or reference of its own over the
   * parent's; `removed`, the parent's key this fork does without. `from`
   * is the environment that holds it, the parent or one above; `changed`
   * says its value is newer than the override; `reset`, that the fork's
   * own value was reset to it and is kept, archived, for `inherit: false`
   * to serve again; `held`, false for a removal of a key no parent passes
   * down now, `from` naming the nearest that archived or removed it. Each key is listed once. Null for a key only this
   * environment holds, and outside forks.
   */
  parent: { from: string; state: 'inherited' | 'overridden' | 'removed'; changed: boolean; reset: boolean; held: boolean } | null;
};

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
  /** The recipe that made it, when it was generated. */
  recipe: string | null;
  /** Whether it was written plain, its value no secret. */
  plain: boolean;
  /** Who sees it (`Sensitivity`): `plain` exactly when `plain` is. */
  sensitivity: Sensitivity;
};

/**
 * Who sees a key's value, loosest first: `plain`, anyone who lists its
 * environment; `secret`, the default, people whose role reads secrets;
 * `sensitive`, no person, Owners included, which their apps use through the
 * credential proxy and service accounts read. A key is made stricter at
 * any time, its value kept; looser only by writing a value again, so a
 * value nobody could read is never shown by flipping it.
 */
export type Sensitivity = 'plain' | 'secret' | 'sensitive';

export const SENSITIVITIES: readonly Sensitivity[] = ['plain', 'secret', 'sensitive'];

/** How a version is held, from its columns. */
export function sensitivityOf(version: { plaintext?: string | null; plain?: boolean; sensitive: boolean }): Sensitivity {
  if (version.sensitive) return 'sensitive';
  return version.plain === true || (version.plaintext ?? null) !== null ? 'plain' : 'secret';
}

/** Whether `a` lets fewer people see a value than `b`. */
export function stricter(a: Sensitivity, b: Sensitivity): boolean {
  return SENSITIVITIES.indexOf(a) > SENSITIVITIES.indexOf(b);
}

/**
 * A value, a value a client generated, with how (`@coffre/core/recipe`), a
 * value with who sees it, the key's value as it is made stricter, or a
 * reference to another secret by path. A value written without a recipe
 * has none: writing one by hand ends what Regenerate can do. A value that
 * says no `sensitivity` is a secret, or sensitive where the key is now:
 * writing over a plain one makes the key secret again, and writing over a
 * sensitive one keeps it sensitive. `{ plain: true }` is 0.9's way to say
 * `sensitivity: 'plain'`. `{ sensitivity }` with no value makes the key's
 * current value stricter, as a new version of it, and never looser: that
 * takes the value written again. A regenerate, or a plain value written
 * over the one its writer revealed, says the version each key's value
 * `replaces`, by its id, and is refused if that is not its current version.
 */
export type SecretValue =
  | string
  | { value: string; generated: Generation; replaces?: string; sensitivity?: 'secret' | 'sensitive' }
  | { value: string; plain: true; replaces?: string }
  | { value: string; sensitivity: Sensitivity; replaces?: string }
  | { sensitivity: Sensitivity }
  | { ref: string };

/** What a write says of who sees each key's value, where it says it. */
function askedSensitivity(value: SecretValue | null): Sensitivity | undefined {
  if (value === null || typeof value !== 'object' || 'ref' in value) return undefined;
  if ('plain' in value) return 'plain';
  return 'sensitivity' in value ? value.sensitivity : undefined;
}

/** Whether a patch's value only makes the key's current value stricter, writing no value. */
function isMark(value: SecretValue | null): value is { sensitivity: Sensitivity } {
  return value !== null && typeof value === 'object' && !('value' in value) && 'sensitivity' in value;
}

/** What `PATCH /secrets/:project/:environment` did to each key it named. */

/**
 * For `market/dev@me`: the environment it is a personal config of, and
 * `fallback` while you have none, the list then being dev's own.
 */
export type PersonalView = { of: string; fallback: boolean };

/** A reset in a fork, or its undoing: the key as it is now, and the environment that holds the parent's. */
export type InheritResult = { key: string; archived: boolean; folder: string | null; from: string };

export type SetOutcome = { version: number } | { archived: true } | { reference: string };
export type SetResult = { operationId: string; keys: Record<string, SetOutcome> };

type Environment = { projectId: string; environmentId: string };

/**
 * The environment a secrets call works in. An archived project or
 * environment serves nothing, exactly as if it did not exist.
 */
function liveEnvironment(place: ResolvedPath): Environment | null {
  if (place.project.archivedAt !== null || place.environment === null || place.environment.archivedAt !== null) {
    return null;
  }
  return { projectId: place.project.id, environmentId: place.environment.id };
}

function requireLive(place: ResolvedPath): Environment {
  const environment = liveEnvironment(place);
  if (environment === null) throw notFound('unknown project or environment');
  return environment;
}

/** One version of a secret, as the vault names it: bound to its ids, labelled with its path. */
export function secretRef(
  place: { project: { slug: string }; environment: { slug: string } | null },
  environment: Environment,
  secret: { id: string; key: string },
  version: number,
): SecretRef {
  return {
    ...environment,
    secretId: secret.id,
    version,
    path: `${place.project.slug}/${place.environment!.slug}/${secret.key}`,
  };
}

/**
 * The current value of every live secret in an environment, or of one
 * secret. What reveals decrypt.
 */
export async function currentEnvelopes(
  db: Queryable,
  environmentId: string,
  secretId?: string,
): Promise<{ secretId: string; secretVersionId: string; key: string; version: number; envelope: Envelope }[]> {
  return (await environmentSecrets(db, environmentId, secretId === undefined ? undefined : { secretId })).flatMap((secret) =>
    secret.archivedAt === null && secret.current !== null
      ? [{
          secretId: secret.id,
          secretVersionId: secret.current.id,
          key: secret.key,
          version: secret.current.version,
          envelope: secret.current.envelope,
        }]
      : [],
  );
}

/**
 * Secret names, who last changed them and when, never values; and the days
 * a value may go unchanged before it is flagged (`rotateAfterDays`). A
 * fork lists what it inherits too, each key under `parent`, and `parents`
 * names the environments it inherits from, nearest first. An inherited
 * key's name, folder and standing are any reader's (key names are not
 * secret within a project); its version and age only those of a reader of
 * the parent that holds it. A fork's own rows and its parents' are read in
 * one snapshot, so a write meanwhile is seen whole or not at all.
 */
export async function listSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
): Promise<{ permissions: Permission[]; keys: SecretKey[]; parents: string[]; personal: PersonalView | null; rotateAfterDays: number | null }> {
  const environment = requireLive(place);
  const fork = place.environment!.parentId !== null;
  const read = async (db: Queryable) => {
    const rows = await environmentSecrets(db, environment.environmentId);
    const inherited = fork
      ? await inheritedRows(db, environment.environmentId)
      : { parents: [], held: new Map<string, InheritedRow>(), removed: new Set<string>(), cut: new Map<string, ParentRow>() };
    if (inherited === null) throw conflict(`${place.project.slug}/${place.environment!.slug}'s parents loop or run past ${MAX_PARENTS}: it was made around coffre`);
    const references = await currentReferences(db, [...rows, ...[...inherited.held.values()].map((held) => held.row)].filter((row) => row.current === null).map((row) => row.id));
    // A reference reads as its source's current value does: sensitive, or a secret, a plain one's included.
    const sensitiveSources = await sensitiveVersions(db, [...references.values()].flatMap((reference) => (reference.state === 'live' ? [reference.source!.currentVersionId!] : [])));
    return { rows, inherited, references, sensitiveSources };
  };
  const { rows, inherited, references, sensitiveSources } = fork ? await ctx.db.transaction(read, SNAPSHOT) : await read(ctx.db);
  const levelOfRow = (row: SecretRow): Sensitivity | null => {
    if (row.current !== null) return sensitivityOf(row.current);
    const reference = references.get(row.id);
    if (reference?.state !== 'live') return null;
    return sensitiveSources.has(reference.source!.currentVersionId!) ? 'sensitive' : 'secret';
  };
  const referenceOf = (secretId: string): SecretKey['reference'] => {
    const reference = references.get(secretId);
    if (reference === undefined) return null;
    const { source } = reference;
    const canOpenSource = source !== null && lists(ctx.caller, placeOfRow(source));
    return { ...reference.view, canOpenSource };
  };
  // A reference's value is its source's: as old as the version it reads.
  const writtenAt = (row: SecretRow): Date | null => {
    if (row.current !== null) return row.current.createdAt;
    const reference = references.get(row.id);
    return reference?.state === 'live' ? reference.source!.currentVersionAt : null;
  };
  const own = new Set(rows.filter((row) => row.archivedAt === null).map((row) => row.key));
  // How each value was made, over the rows the environment resolves to: its own live ones, and in a fork
  // those it inherits and holds none of, so a key pair reads as one only while both halves resolve to it.
  const generated = generations([
    ...rows,
    ...[...inherited.held].filter(([key]) => !own.has(key) && !inherited.removed.has(key)).map(([, held]) => held.row),
  ]);
  const view = (row: SecretRow): Omit<SecretKey, 'parent' | 'readable'> => ({
    key: row.key,
    reference: referenceOf(row.id),
    folder: row.folder,
    archived: row.archivedAt !== null,
    version: row.current?.version ?? null,
    versionId: row.current?.id ?? null,
    updatedAt: writtenAt(row)?.toISOString() ?? null,
    updatedBy: row.current?.createdBy ?? null,
    generated: generated.get(row.id) ?? null,
    value: row.current?.plaintext ?? null,
    sensitivity: levelOfRow(row),
  });
  // Told of a parent's key, its version, age and plain value, as a lister of the parent is: a reader, or a Contributor who uses it.
  const told = (from: { id: string; slug: string }) =>
    lists(ctx.caller, { projectId: environment.projectId, environmentId: from.id, environmentSlug: from.slug });
  // Whether the caller reads a value where it is held: a Contributor only uses dev, and reads their own values in dev@me.
  const readsHere = can(ctx.caller, 'secret.read', placeOf(place.project, place.environment));
  const readsAt = (from: { id: string; slug: string }) =>
    can(ctx.caller, 'secret.read', { projectId: environment.projectId, environmentId: from.id, environmentSlug: from.slug });
  const readable = (key: Pick<SecretKey, 'value' | 'sensitivity'>, reader: boolean) =>
    key.sensitivity !== null && key.sensitivity !== 'sensitive' && (key.value !== null || reader);

  // An override reset to the parent's: its key is listed once, as inherited or removed, saying its own value is kept.
  const removedSince = (key: string) => inherited.removed.has(key) && inherited.cut.has(key);
  const reset = new Set(rows.filter((row) => row.archivedAt !== null && (inherited.held.has(row.key) || removedSince(row.key))).map((row) => row.key));
  const keys: SecretKey[] = rows.filter((row) => !reset.has(row.key)).map((row) => {
    const held = row.archivedAt === null ? inherited.held.get(row.key) : undefined;
    // An archived key has no value to read: a read of it is refused.
    const listed = view(row);
    const here = { ...listed, readable: row.archivedAt === null && readable(listed, readsHere) };
    if (held === undefined) return { ...here, parent: null };
    // Flagged while the parent's value is newer than the override, to whoever may know when it was written.
    const [mine, theirs] = [writtenAt(row), writtenAt(held.row)];
    const changed = told(held.from) && mine !== null && theirs !== null && theirs > mine;
    return { ...here, parent: { from: held.from.slug, state: 'overridden', changed, reset: false, held: true } };
  });
  // A parent archived or deleted, which only a write around coffre leaves in a chain, cuts it: a read refuses there, and no
  // plain value is listed from it or past it.
  const cut = inherited.parents.findIndex((parent) => parent.archivedAt !== null || parent.deleted);
  const live = (from: { slug: string }) => cut === -1 || inherited.parents.findIndex((parent) => parent.slug === from.slug) < cut;
  for (const [key, held] of inherited.held) {
    if (own.has(key)) continue;
    const removed = inherited.removed.has(key);
    const shown = !removed && told(held.from);
    const listed = {
      ...view(held.row),
      ...(shown ? {} : { reference: null, version: null, versionId: null, updatedAt: null, updatedBy: null, generated: null, value: null, sensitivity: null }),
      ...(shown && live(held.from) ? {} : { value: null }),
      // A removed key resolves to nothing here, and has nothing to regenerate.
      ...(removed ? { generated: null, value: null, sensitivity: null } : {}),
    };
    keys.push({
      ...listed,
      // Read through here, so by a reader of here and of the parent that holds it, while the chain to it is whole.
      readable: readable(listed, live(held.from) && readsHere && readsAt(held.from)),
      archived: false,
      parent: { from: held.from.slug, state: removed ? 'removed' : 'inherited', changed: false, reset: reset.has(key), held: true },
    });
  }
  // A removal of a key a parent archived or removed since: doing nothing, until that parent brings it back. Listed, to be restored.
  for (const key of inherited.removed) {
    const from = inherited.cut.get(key);
    if (from === undefined || own.has(key)) continue;
    keys.push({
      key, reference: null, folder: null, archived: false, version: null, versionId: null, updatedAt: null, updatedBy: null, generated: null, value: null, sensitivity: null, readable: false,
      parent: { from: from.slug, state: 'removed', changed: false, reset: reset.has(key), held: false },
    });
  }
  keys.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return {
    permissions: permissionsAt(ctx.caller, placeOf(place.project, place.environment)),
    keys,
    parents: inherited.parents.map((parent) => parent.slug),
    personal: place.personal === undefined ? null : { of: place.personal.of.slug, fallback: place.personal.fallback === true },
    rotateAfterDays: ctx.rotateAfterDays,
  };
}

/**
 * How each live key's current value was made, by secret id, for those a
 * client generated. A key pair's half is one only beside the other: a live
 * key whose current version shares its pair id and holds the other half.
 * Typed over, archived, or restored to another pair's version, either half
 * breaks the pair, and neither has a recipe until the pair is made again.
 */
export function generations(rows: readonly SecretRow[]): Map<string, Generation> {
  const live = rows.filter((row) => row.archivedAt === null && row.current?.recipe != null);
  const halves = new Map<string, { private?: SecretRow; public?: SecretRow }>();
  for (const row of live) {
    const pair = row.current!.recipe!.pair;
    if (pair === null) continue;
    const both = halves.get(pair.id) ?? {};
    both[pair.half] = row;
    halves.set(pair.id, both);
  }
  // What the database holds is checked as a write's would be: a recipe that does not parse makes nothing.
  const kindOf = (recipe: string) => (recipeProblem(recipe) === null ? parseRecipe(recipe).kind : null);
  const out = new Map<string, Generation>();
  for (const row of live) {
    const { recipe, pair } = row.current!.recipe!;
    const kind = kindOf(recipe);
    if (pair === null) {
      if (kind !== null && kind !== 'pair') out.set(row.id, { recipe });
      continue;
    }
    const both = halves.get(pair.id)!;
    if (kind !== 'pair' || both.private === undefined || both.public === undefined) continue;
    if (both.private.current!.recipe!.recipe !== recipe || both.public.current!.recipe!.recipe !== recipe) continue;
    out.set(row.id, { recipe, pair: { private: both.private.key, public: both.public.key } });
  }
  return out;
}

/**
 * What is wrong with a patch's generated values, or null. A key pair's
 * recipe writes its two keys at once, each naming both: `{ private, public }`,
 * the same on both, with the same recipe. Any other recipe names no pair.
 */
export function generationProblem(patch: Readonly<Record<string, unknown>>): string | null {
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

/**
 * The recipe each generated key's new version stores: canonical, and for a
 * key pair a fresh id its two halves share. Checked by `generationProblem`.
 */
function recipesOf(patch: Readonly<Record<string, SecretValue | null>>): Map<string, VersionRecipe> {
  const pairIds = new Map<string, string>();
  const out = new Map<string, VersionRecipe>();
  for (const [key, value] of Object.entries(patch)) {
    if (value === null || typeof value !== 'object' || !('generated' in value)) continue;
    const { recipe, pair } = value.generated;
    const canonical = formatRecipe(parseRecipe(recipe));
    if (pair === undefined) {
      out.set(key, { recipe: canonical, pair: null });
      continue;
    }
    const names = `${pair.private}/${pair.public}`;
    if (!pairIds.has(names)) pairIds.set(names, randomUUID());
    out.set(key, { recipe: canonical, pair: { id: pairIds.get(names)!, half: key === pair.private ? 'private' : 'public' } });
  }
  return out;
}

/**
 * Append a version and make it current. Versions are never rewritten. The
 * caller holds the secret's row lock, which is what makes `version` its own.
 */
async function appendVersion(
  tx: Transaction,
  secretId: string,
  version: number,
  envelope: Envelope,
  createdBy: string,
  recipe: VersionRecipe | null,
  plaintext: string | null,
  sensitive: boolean,
): Promise<void> {
  const id = randomUUID();
  await insert(tx, secretVersions, { id, secretId, version, ...envelope, createdBy, ...recipeRow(recipe), plaintext, sensitive });
  await update(tx, secrets, { id: secretId }, { currentVersionId: id, currentVersion: version, updatedAt: new Date() });
}

/**
 * A fork's keys that got a value or a reference of their own, which are
 * no longer removed: reset later, each inherits again (docs/design/forking.md).
 * A row becomes live in five places, each of which ends its key's removal
 * here, under the head: a write (`setSecrets`), a restored version
 * (`restoreVersion`), an unarchive and a rename onto the key (`patchSecret`),
 * and an override undoing a reset (`inheritSecret`). A rename in a parent
 * carries removals down itself (`renameBelow`), and ends the removal of the
 * name a personal config's key is moved aside to.
 */
async function endRemovals(
  ctx: ApiContext,
  tx: Transaction,
  log: AuditEntry[],
  place: ResolvedPath,
  environment: Environment,
  keys: readonly string[],
  operationId: string | null,
): Promise<void> {
  if (place.environment!.parentId === null || keys.length === 0) return;
  const removed = new Set((await dismissalsIn(tx, environment.environmentId)).map((row) => row.key));
  for (const key of keys.filter((key) => removed.has(key))) {
    await update(tx, dismissedKeys, { environmentId: environment.environmentId, key }, { restoredAt: new Date(), restoredBy: ctx.caller.principal.id });
    log.push(allowed(ctx, 'missing.restore', { ...environment, operationId, metadata: { key } }));
  }
}

/**
 * The keys a write in this environment may bring back from archived: in a
 * fork, those its parents hold, whose own row is an override reset to
 * theirs (`inheritSecret`). None elsewhere.
 */
async function resetKeys(db: Queryable, place: ResolvedPath): Promise<ReadonlySet<string>> {
  return new Set((await inheritedOf(db, place))?.held.keys());
}

/**
 * Why a regenerate in the patch is stale, or null: each value that says the
 * version it `replaces` must name the version its key resolves to now, by
 * id, as the listing gave it: its own live row's current version, or in a
 * fork, while it holds none live and did not remove it, the one it inherits.
 */
function regenerated(
  patch: Readonly<Record<string, SecretValue | null>>,
  own: ReadonlyMap<string, { archivedAt: Date | null; currentVersionId: string | null }>,
  inherited: Awaited<ReturnType<typeof inheritedRows>>,
): string | null {
  for (const [key, value] of Object.entries(patch)) {
    if (value === null || typeof value !== 'object' || !('replaces' in value) || value.replaces === undefined) continue;
    const row = own.get(key);
    const live = row !== undefined && row.archivedAt === null;
    const passedDown = live || inherited?.removed.has(key) ? undefined : inherited?.held.get(key)?.row;
    const resolved = live ? row.currentVersionId : passedDown?.current?.id ?? null;
    if (resolved === value.replaces) continue;
    return resolved === null
      ? `${key} has no value to ${'generated' in value ? 'regenerate' : 'replace'} now: it was renamed, archived or made a reference since it was listed. Nothing was written`
      : `${key} changed since it was listed: it was written, rolled back or regenerated meanwhile. Nothing was written`;
  }
  return null;
}

/** What a fork inherits, or null outside forks: what its reset overrides are, and what a regenerate replaces there. */
async function inheritedOf(db: Queryable, place: ResolvedPath): Promise<Awaited<ReturnType<typeof inheritedRows>>> {
  if (place.environment!.parentId === null) return null;
  return inheritedRows(db, place.environment!.id);
}

/** A competing write invalidated the keys prepared outside the transaction. */
class PrepareAgain extends Error {}

async function optimistic<T>(ctx: ApiContext, work: () => Promise<T>): Promise<T> {
  return withRefusals(ctx, async () => {
    // Bound the work under sustained contention; an ordinary burst can retry.
    for (let attempt = 0; attempt < 16; attempt++) {
      try {
        return await work();
      } catch (error) {
        if (!(error instanceof PrepareAgain)) throw error;
      }
    }
    throw conflict('the secrets kept changing; try again');
  });
}

/**
 * The place as it is under the log's head, which every write to a place
 * takes first: archived or deleted since the router found it, it takes no
 * write. The head is held, so an archive or a deletion cannot commit until we do.
 */
export async function checkEnvironment(tx: Transaction, place: ResolvedPath, expected: Environment): Promise<void> {
  const current = await resolvePath(tx, { project: place.project.slug, environment: place.environment!.slug });
  if (current === null) throw notFound('unknown project or environment');
  const live = requireLive(current);
  if (live.projectId !== expected.projectId || live.environmentId !== expected.environmentId) throw notFound('unknown project or environment');
}

/**
 * The only way to write. A string sets a key, adding it if it is new;
 * `{ ref }` makes it a reference to another secret, by path; `null`
 * archives it. One transaction, one version or reference and one audit
 * entry per key, so fifty keys from an `.env` file land together or not at
 * all.
 *
 * A key that is a reference stops being one when it gets a value or
 * another reference: the vault ends it first, `replaced`, before anything
 * is written, so a write that then fails leaves a key with no value, never
 * one still reading the source it was moved off.
 *
 * The operation id is drawn inside the retried preparation: an attempt that
 * prepares again leaves the vault's `key.wrap` entries for keys nothing
 * stored, and a fresh id keeps them out of the write that did land.
 */
export async function setSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, SecretValue | null>,
  /** Run under the log's head, before anything is written, by a caller whose patch holds what it read elsewhere: a fork's copy. */
  stillSo?: (tx: Transaction) => Promise<void>,
): Promise<SetResult> {
  const environment = requireLive(place);
  const keysIn = Object.keys(patch);
  const problem = generationProblem(patch);
  if (problem !== null) throw badRequest(problem);
  const recipes = recipesOf(patch);
  const asked = new Map(Object.entries(patch).flatMap(([key, value]) => {
    const sensitivity = askedSensitivity(value);
    return sensitivity === undefined ? [] : [[key, sensitivity] as const];
  }));
  // A personal config's values are bound to its owner by the vault (R8), which a plain value, read without it, is not: none
  // is plain there. Only its owner lists one, so a secret serves them the same.
  if (place.environment!.owner !== null && [...asked.values()].includes('plain')) {
    throw badRequest(`${place.project.slug}/${personalName(place)} is a personal config: the vault binds its values to their owner, so none is plain; write it as a secret, which only they read`);
  }
  const writes = Object.entries(patch).flatMap(([key, value]): [string, string][] =>
    typeof value === 'string' ? [[key, value]] : value !== null && 'value' in value ? [[key, value.value]] : []);
  const marks = Object.entries(patch).flatMap(([key, value]) => (isMark(value) ? [{ key, to: value.sensitivity }] : []));
  const refs = Object.entries(patch).flatMap(([key, value]) => (value !== null && typeof value === 'object' && 'ref' in value ? [{ key, ref: value.ref }] : []));
  const archives = keysIn.filter((key) => patch[key] === null);
  // The keys found sensitive by any attempt of this write, which a write that says nothing keeps sensitive: a
  // reference's source written again as a secret, or a reference retargeted, between attempts makes it no looser.
  const sticky = new Set<string>();
  const result = await optimistic(ctx, async () => {
    const operationId = randomUUID();
    const heads = await secretHeads(ctx.db, environment.environmentId, { keys: keysIn });
    const prepared = new Map(heads.map((row) => [row.key, row]));
    const currently = await currentReferences(ctx.db, heads.filter((row) => row.currentVersionId === null).map((row) => row.id));
    // Each key's newest reference, which the transaction checks no write replaced meanwhile.
    const newestBefore = newestReferences(await referenceRows(ctx.db, { holderSecretIds: heads.map((row) => row.id) }));
    // In a fork, an archived key its parent holds is an override reset to the parent's: writing it overrides
    // again. One the parent lacks is archived as anywhere, and unarchiving it takes more than a write.
    const inherited = await inheritedOf(ctx.db, place);
    const resettable = new Set(inherited?.held.keys());
    // Who sees each key's value now (`levelsAt`), which the transaction resolves again under the head.
    const levels = await levelsAt(ctx.db, place, environment.environmentId, keysIn);
    const levelNow = (key: string): Sensitivity | null => levels.get(key) ?? null;
    for (const [key, level] of await stickyLevels(ctx.db, place, environment.environmentId, keysIn, levels)) if (level === 'sensitive') sticky.add(key);
    // A write that says nothing is a secret, and sensitive where the key is: never looser than it was, but for plain, said each time.
    const levelOf = (key: string): Sensitivity => asked.get(key) ?? (sticky.has(key) ? 'sensitive' : 'secret');
    const refuseArchived = (key: string, row: { id: string }) => new Refusal(
      conflict(`${key} is archived; unarchive it before writing a new version`),
      denied(ctx, 'secret.write', 'secret_archived', { ...environment, secretId: row.id, operationId, metadata: { key } }),
    );
    // A regenerate replaces the versions it was listed with, by their ids, or nothing: a key
    // renamed, archived or written meanwhile, here or in a parent, is not the one it regenerates.
    // Checked again under the head, below, where nothing can move.
    const stale = regenerated(patch, prepared, inherited);
    // Its own reason, `stale`, for a client that read the version it replaces to tell from any other conflict.
    if (stale !== null) throw new ApiError('conflict', stale, 'stale');
    const archived = (key: string) => {
      const row = prepared.get(key);
      if (row?.archivedAt == null || resettable.has(key)) return;
      throw refuseArchived(key, row);
    };
    const items = writes.map(([key, value]) => {
      archived(key);
      const row = prepared.get(key);
      const secret = { id: row?.id ?? randomUUID(), key };
      return { key, secret: { ...secretRef(place, environment, secret, (row?.currentVersion ?? 0) + 1), sensitive: levelOf(key) === 'sensitive' }, value };
    });
    const tightened = await tightening(ctx, place, environment, marks, prepared, levelNow, operationId);
    const references = (await referenceTargets(ctx, place, environment, refs, prepared, currently, operationId)).filter((item) => {
      archived(item.key);
      return !item.unchanged;
    });
    // What gets a value or another reference stops being the reference it is.
    const replaced = [...items.map((item) => item.secret.secretId), ...references.map((item) => item.holder.secretId)]
      .flatMap((secretId) => {
        const reference = currently.get(secretId);
        return reference === undefined || reference.row.ended !== null ? [] : [reference.row];
      });

    // IDs and versions are provisional until the transaction checks them.
    const sealed = await sealValues(ctx.vault, asking(ctx, operationId), items);
    if (!sealed.ok) throw vaultRefusal(ctx, sealed.refusal, 'secret.write', { ...environment, operationId });
    const rewrapped = await rewrapValues(ctx.vault, asking(ctx, operationId), tightened.map(({ secret, from }) => ({ secret, from })));
    if (!rewrapped.ok) throw vaultRefusal(ctx, rewrapped.refusal, 'secret.write', { ...environment, operationId });
    // Vault calls only for what there is: most writes make and end no reference.
    const made = references.length === 0 ? { ok: true as const, seqs: [] } : await ctx.vault.reference({
      ...asking(ctx, operationId),
      items: references.map(({ id, holder, source }) => ({ id, holder, source: { secretId: source.id } })),
    });
    if (!made.ok) throw vaultRefusal(ctx, made.refusal, 'secret.reference', { ...environment, operationId });
    if (replaced.length > 0) {
      const ended = await ctx.vault.endReferences({
        ...asking(ctx, operationId),
        reason: 'replaced',
        items: replaced.map((row) => ({ reference: row.id, seq: Number(row.createdSeq) })),
      }).catch(async (error: unknown) => {
        await abandon(ctx, operationId, references, made.seqs);
        throw error;
      });
      if (!ended.ok) {
        await abandon(ctx, operationId, references, made.seqs);
        throw vaultRefusal(ctx, ended.refusal, 'secret.write', { ...environment, operationId });
      }
    }

    return audited(ctx, async (tx, log) => {
      await checkEnvironment(tx, place, environment);
      await stillSo?.(tx);
      // Each source again under the head: archived or deleted since it was checked, it is no source (D41).
      if (references.length > 0) {
        const sources = await secretPlaces(tx, references.map((item) => item.source.id));
        for (const { key, source } of references) {
          const now = sources.get(source.id);
          if (now !== undefined && now.archivedAt === null && now.environmentArchivedAt === null && now.projectArchivedAt === null
            && !isTombstone(now.project) && !isTombstone(now.environment)) continue;
          throw new Refusal(
            notFound(`${sourcePath(source)} was archived or deleted meanwhile: it is no live secret to refer to`),
            denied(ctx, 'secret.reference', 'source_archived', { ...environment, operationId, metadata: { key, source: sourcePath(source) } }),
          );
        }
      }
      await insertIfAbsent(tx, secrets, [
        ...items.map(({ key, secret }) => ({ key, id: secret.secretId })),
        ...references.map(({ key, holder }) => ({ key, id: holder.secretId })),
      ].filter(({ key }) => !prepared.has(key)).map(({ key, id }) => ({ id, ...environment, key })));
      const rows = await lock(tx, secrets, { environmentId: environment.environmentId, key: keysIn });
      const byKey = new Map(rows.map((row) => [row.key, row]));
      const created = new Map([
        ...items.map((item) => [item.key, item.secret.secretId] as const),
        ...references.map((item) => [item.key, item.holder.secretId] as const),
        ...tightened.map((item) => [item.key, item.secret.secretId] as const),
      ]);
      for (const key of keysIn) {
        const before = prepared.get(key);
        const current = byKey.get(key);
        if (before === undefined) {
          if (current?.id !== created.get(key) || (current !== undefined && (current.currentVersion !== 0 || current.archivedAt !== null))) {
            throw new PrepareAgain();
          }
        } else if (current === undefined || current.id !== before.id
          || current.currentVersion !== before.currentVersion
          || current.currentVersionId !== before.currentVersionId
          || current.archivedAt?.getTime() !== before.archivedAt?.getTime()) {
          throw new PrepareAgain();
        }
      }
      // A reference made meanwhile, to a key this write prepared without it.
      const newest = newestReferences(await referenceRows(tx, { holderSecretIds: rows.map((row) => row.id) }));
      if (rows.some((row) => newest.get(row.id) !== newestBefore.get(row.id))) throw new PrepareAgain();
      // What a regenerate replaces, resolved again under the head, its parents' rows included: one that
      // moved since it was prepared is prepared again, and refused there.
      if (Object.values(patch).some((value) => value !== null && typeof value === 'object' && 'replaces' in value)) {
        // The rows that were there when it was prepared: one this write just made for an override is not yet one.
        const before = new Map([...byKey].filter(([key]) => prepared.has(key)));
        if (regenerated(patch, before, await inheritedOf(tx, place)) !== null) throw new PrepareAgain();
      }
      // Each written key's level again under the head, what its entry says it was. A write that says nothing takes it: a
      // value written or marked, a reference made, retargeted or ended, here or in a parent, since it was prepared, is prepared again.
      const previous = items.length === 0 ? new Map<string, Sensitivity | null>() : await levelsAt(tx, place, environment.environmentId, items.map(({ key }) => key));
      const holds = await stickyLevels(tx, place, environment.environmentId, items.map(({ key }) => key), previous);
      const loosened = items.filter(({ key, secret }) => !asked.has(key) && holds.get(key) === 'sensitive' && secret.sensitive !== true);
      // Found so, it stays so: the attempt that prepares again keeps it sensitive, whatever its source is by then.
      for (const { key } of loosened) sticky.add(key);
      if (loosened.length > 0) throw new PrepareAgain();
      const keys: Record<string, SetOutcome> = {};
      // A reset override written again serves again, a reference written again unchanged too; still one the parent holds.
      const revived = keysIn.filter((key) => patch[key] !== null && byKey.get(key)?.archivedAt != null);
      const stillResettable = revived.length === 0 ? resettable : await resetKeys(tx, place);
      for (const key of revived) {
        const row = byKey.get(key)!;
        if (!stillResettable.has(key)) throw refuseArchived(key, row);
        await update(tx, secrets, { id: row.id }, { archivedAt: null });
        log.push(allowed(ctx, 'secret.unarchive', { ...environment, secretId: row.id, operationId, metadata: { key } }));
      }
      const versions = [
        ...items.map(({ key, secret, value }, i) => {
          const recipe = recipes.get(key) ?? null;
          const level = levelOf(key);
          log.push(allowed(ctx, 'secret.write', {
            ...environment, secretId: secret.secretId, operationId, relatedSeq: sealed.seqs[i],
            metadata: { key, version: secret.version, ...(recipe === null ? {} : { recipe: recipe.recipe }), ...sensitivityDetail(level, previous.get(key) ?? null) },
          }));
          keys[key] = { version: secret.version };
          return {
            id: randomUUID(), secretId: secret.secretId, version: secret.version, ...sealed.values[i],
            createdBy: ctx.caller.principal.id, ...recipeRow(recipe), plaintext: level === 'plain' ? value : null, sensitive: level === 'sensitive',
          };
        }),
        // The value as it is, made stricter: its ciphertext and how it was made, its key wrapped again as the new level.
        ...tightened.map(({ key, secret, from, to, was, recipe }, i) => {
          log.push(allowed(ctx, 'secret.write', {
            ...environment, secretId: secret.secretId, operationId, relatedSeq: rewrapped.seqs[i],
            metadata: { key, version: secret.version, ...(recipe === null ? {} : { recipe: recipe.recipe }), ...sensitivityDetail(to, was), kept: from.version },
          }));
          keys[key] = { version: secret.version };
          return {
            id: randomUUID(), secretId: secret.secretId, version: secret.version, ...rewrapped.values[i],
            createdBy: ctx.caller.principal.id, ...recipeRow(recipe), plaintext: null, sensitive: to === 'sensitive',
          };
        }),
      ];
      for (const { key, version } of unchangedMarks(marks, prepared, levelNow)) keys[key] = { version };
      await insert(tx, secretVersions, versions);
      const now = new Date();
      for (const { id, secretId, version } of versions) {
        await update(tx, secrets, { id: secretId }, { currentVersionId: id, currentVersion: version, updatedAt: now });
      }
      for (const [i, { key, id, holder, source }] of references.entries()) {
        await update(tx, secrets, { id: holder.secretId }, { currentVersionId: null, updatedAt: now });
        await insert(tx, secretReferences, {
          id,
          projectId: holder.projectId,
          environmentId: holder.environmentId,
          secretId: holder.secretId,
          sourceProjectId: source.projectId,
          sourceEnvironmentId: source.environmentId,
          sourceSecretId: source.id,
          createdSeq: BigInt(made.seqs[i]!),
          // The member, as the vault's entry names them. Provenance only: lists and the offboarding report read the maker from the entry.
          createdBy: formatMember(ctx.caller.principal),
        });
        log.push(allowed(ctx, 'secret.reference', {
          ...environment, secretId: holder.secretId, operationId, relatedSeq: made.seqs[i], metadata: {
            key, source: sourcePath(source), also: { projectId: source.projectId, environmentId: source.environmentId, secretId: source.id },
          },
        }));
        keys[key] = { reference: sourcePath(source) };
      }
      for (const { key, source } of refs.map((ref) => ({ key: ref.key, source: ref.ref }))) keys[key] ??= { reference: source };
      await endRemovals(ctx, tx, log, place, environment, keysIn.filter((key) => patch[key] !== null), operationId);
      const archiving = archives.map((key) => byKey.get(key)).filter((secret) => secret !== undefined && secret.archivedAt === null);
      if (archiving.length > 0) {
        await refuseIfRead(ctx, tx, `${place.project.slug}/${place.environment!.slug}`, { ...environment, secretIds: archiving.map((secret) => secret!.id) }, 'secret.archive', { ...environment, operationId });
      }
      for (const key of archives) {
        const secret = byKey.get(key);
        keys[key] = { archived: true };
        if (secret === undefined || secret.archivedAt !== null) continue;
        await update(tx, secrets, { id: secret.id }, { archivedAt: now });
        log.push(allowed(ctx, 'secret.archive', { ...environment, secretId: secret.id, operationId, metadata: { key } }));
      }
      return { operationId, keys };
    }).catch(async (error: unknown) => {
      await abandon(ctx, operationId, references, made.seqs);
      throw error;
    });
  });
  return result;
}

/**
 * Who sees each key's value now: its own live value's level; a reference's,
 * live or ended, its source's current value's, sensitive or a secret; or, in
 * a fork, the level of what it inherits, a parent's reference resolved the
 * same way. Null for a key with nothing to read, a reference's with no
 * source value. Read in `db`: a transaction's resolves it as the write
 * commits. Not `inheriting`, a key's own level alone, null for one it
 * only inherits.
 */
async function levelsAt(
  db: Queryable,
  place: ResolvedPath,
  environmentId: string,
  keys: readonly string[],
  { inheriting = true }: { inheriting?: boolean } = {},
): Promise<Map<string, Sensitivity | null>> {
  const heads = new Map((await secretHeads(db, environmentId, { keys: [...keys] })).map((row) => [row.key, row]));
  const inherited = inheriting ? await inheritedOf(db, place) : null;
  const passedDown = (key: string) => (inherited?.removed.has(key) ? undefined : inherited?.held.get(key)?.row);
  const own = (key: string) => {
    const row = heads.get(key);
    return row !== undefined && row.archivedAt === null ? row : undefined;
  };
  const references = await currentReferences(db, keys.flatMap((key) => {
    const mine = own(key);
    const held = passedDown(key);
    return [...(mine !== undefined && mine.current === null ? [mine.id] : []), ...(held !== undefined && held.current === null ? [held.id] : [])];
  }));
  // Live or not: a write ends the reference it replaces before it commits, and the value it writes is still the one that
  // reference read. A reference ended otherwise, or to a source archived meanwhile, is held as its source is too.
  const sourceOf = (holder: string) => references.get(holder)?.source?.currentVersionId ?? undefined;
  const sensitive = await sensitiveVersions(db, [...references.keys()].flatMap((holder) => sourceOf(holder) ?? []));
  const throughReference = (holder: string): Sensitivity | null | undefined => {
    if (!references.has(holder)) return undefined;
    const source = sourceOf(holder);
    return source === undefined ? null : sensitive.has(source) ? 'sensitive' : 'secret';
  };
  return new Map(keys.map((key): [string, Sensitivity | null] => {
    const mine = own(key);
    if (mine?.current != null) return [key, sensitivityOf(mine.current)];
    const mineThrough = mine === undefined ? undefined : throughReference(mine.id);
    if (mineThrough !== undefined) return [key, mineThrough];
    // A row of its own with no value and no reference reads what it inherits, as a read does.
    const held = passedDown(key);
    if (held === undefined) return [key, null];
    if (held.current !== null) return [key, sensitivityOf(held.current)];
    return [key, throughReference(held.id) ?? null];
  }));
}

/**
 * The level a write that says nothing keeps: the key's (`levels`, as
 * `levelsAt` read them). In a personal config, only its owner's own
 * value's: over a key it inherits, theirs is a secret they read, which
 * their app is given, a sensitive key's included (R18).
 */
async function stickyLevels(
  db: Queryable,
  place: ResolvedPath,
  environmentId: string,
  keys: readonly string[],
  levels: Map<string, Sensitivity | null>,
): Promise<Map<string, Sensitivity | null>> {
  return place.environment!.owner === null ? levels : levelsAt(db, place, environmentId, keys, { inheriting: false });
}

/** What a `secret.write` entry says of who sees the value: as 0.9 said plain, and what it was when that changed. */
function sensitivityDetail(level: Sensitivity, was: Sensitivity | null): Record<string, unknown> {
  return {
    ...(level === 'plain' ? { plain: true } : level === 'sensitive' ? { sensitive: true } : {}),
    ...(was !== null && was !== level ? { was } : {}),
  };
}

/** A key's current value made stricter, as a new version: its key wrapped again as `to`, the rest of it kept. */
type Tightened = {
  key: string;
  secret: SecretRef;
  from: { id: string; version: number; envelope: Envelope };
  to: Sensitivity;
  was: Sensitivity;
  recipe: VersionRecipe | null;
};

/**
 * The marks of a patch that make a key stricter, each its current value's
 * version and the new one it becomes. One already as strict is left as it
 * is. One looser is refused: that takes the value written again, so nobody
 * ever shows a value by flipping it. A key with no value of its own here,
 * a reference or one a fork inherits, has nothing to make stricter.
 */
async function tightening(
  ctx: ApiContext,
  place: ResolvedPath,
  environment: Environment,
  marks: readonly { key: string; to: Sensitivity }[],
  prepared: ReadonlyMap<string, { id: string; key: string; currentVersion: number; currentVersionId: string | null; archivedAt: Date | null }>,
  levelNow: (key: string) => Sensitivity | null,
  operationId: string,
): Promise<Tightened[]> {
  const refused = (key: string, message: string, reason: string, metadata: Record<string, unknown> = {}) =>
    new Refusal(conflict(message), denied(ctx, 'secret.write', reason, { ...environment, operationId, metadata: { key, ...metadata } }));
  const stricterOnes = marks.filter(({ key, to }) => {
    const row = prepared.get(key);
    if (row?.archivedAt != null) throw refused(key, `${key} is archived; unarchive it before marking it`, 'secret_archived');
    const was = levelNow(key);
    if (row === undefined || row.currentVersionId === null) {
      throw was === null
        ? refused(key, `${key} has no value of its own to mark ${to}: write one`, 'no_value')
        : row !== undefined
          ? refused(key, `${key} is a reference: mark its source, which it reads`, 'reference')
          : refused(key, `${key} is inherited: mark it where it is held, or write a value of ${place.project.slug}/${place.environment!.slug}'s own`, 'inherited');
    }
    if (was === to) return false;
    if (stricter(was!, to)) {
      throw refused(key, `${key} is ${was}: making it ${to} takes its value written again, never a flip of the one stored`, 'looser', { sensitivity: to, was });
    }
    return true;
  });
  if (stricterOnes.length === 0) return [];
  const rows = new Map((await environmentSecrets(ctx.db, environment.environmentId)).map((row) => [row.key, row]));
  return stricterOnes.map(({ key, to }) => {
    const head = prepared.get(key)!;
    const current = rows.get(key)?.current;
    // Written meanwhile: the version the write prepared is no longer the one it would keep.
    if (current == null || current.id !== head.currentVersionId) throw new PrepareAgain();
    return {
      key,
      secret: { ...secretRef(place, environment, head, head.currentVersion + 1), sensitive: to === 'sensitive' },
      from: { id: current.id, version: current.version, envelope: current.envelope },
      to,
      was: levelNow(key)!,
      recipe: current.recipe,
    };
  });
}

/** The marks that leave a key as it is, already that strict: each answers its current version. */
function unchangedMarks(
  marks: readonly { key: string; to: Sensitivity }[],
  prepared: ReadonlyMap<string, { currentVersion: number }>,
  levelNow: (key: string) => Sensitivity | null,
): { key: string; version: number }[] {
  return marks.filter(({ key, to }) => levelNow(key) === to).map(({ key }) => ({ key, version: prepared.get(key)!.currentVersion }));
}

/**
 * End, `abandoned`, the references the vault sealed for a write that stored
 * none of them: refused, failed, or prepared again under fresh ids. Then a
 * row written later around the app, naming one, reads nothing. Best effort,
 * and after the write's own answer: meanwhile a seal no row names is no
 * reference, and the write's error is the one to answer with.
 */
async function abandon(ctx: ApiContext, operationId: string, references: readonly { id: string }[], seqs: readonly number[]): Promise<void> {
  if (seqs.length === 0) return;
  await ctx.vault.endReferences({
    ...asking(ctx, operationId),
    reason: 'abandoned',
    items: references.map(({ id }, i) => ({ reference: id, seq: seqs[i]! })),
  }).catch(() => undefined);
}

/** Each holder's newest reference's id, from rows oldest first. */
function newestReferences(rows: readonly { id: string; holder: { secretId: string } }[]): Map<string, string> {
  return new Map(rows.map((row) => [row.holder.secretId, row.id]));
}

const sourcePath = (source: SecretPlaceRow) => `${source.project}/${source.environment}/${source.key}`;

/** A reference a write makes: its id, holder and source; `unchanged` when the key already reads that source. */
type ReferenceTarget = { key: string; id: string; holder: HolderRef; source: SecretPlaceRow; unchanged: boolean };

/**
 * The references a patch makes, checked: each source a live secret the
 * caller reads by their own grants, not the holder, and not itself a
 * reference (one hop); and no holder a source others read through, since
 * they would then read through two. The vault checks the grants again, and
 * reads only the source its entry names, whatever the app decided.
 */
async function referenceTargets(
  ctx: ApiContext,
  place: ResolvedPath,
  environment: Environment,
  refs: { key: string; ref: string }[],
  prepared: Map<string, { id: string; key: string }>,
  currently: Map<string, Resolved>,
  operationId: string,
): Promise<ReferenceTarget[]> {
  if (refs.length === 0) return [];
  const refused = (key: string, message: string, reason: string) =>
    new Refusal(conflict(message), denied(ctx, 'secret.reference', reason, { ...environment, operationId, metadata: { key } }));
  // A personal config's values are bound to its owner: no reference holds one there, nor reads one from there (the vault refuses both too).
  if (place.environment!.owner !== null) {
    throw refused(refs[0]!.key, `a personal config holds values only, no reference: copy the value of ${refs[0]!.ref} instead`, 'personal');
  }
  const resolved = await Promise.all(refs.map(async ({ key, ref }) => {
    const parts = ref.split('/');
    const found = parts.length === 3 ? await resolvePath(ctx.db, { project: parts[0]!, environment: parts[1]!, key: parts[2]! }) : null;
    if (found?.environment == null || found.secret === null || found.project.archivedAt !== null || found.environment.archivedAt !== null || found.secret.archivedAt !== null) {
      // A key a fork only inherits is its parent's: the reference goes to where the value is held. Said only to
      // a reader of the fork, who may know its project's key names; to anyone else, it is no secret at all.
      const tells = found?.environment != null && found.environment.parentId !== null && found.environment.archivedAt === null
        && can(ctx.caller, 'secret.read', placeOf(found.project, found.environment));
      const inherited = tells ? await inheritedRows(ctx.db, found!.environment!.id) : null;
      const held = inherited?.removed.has(parts[2]!) === false ? inherited.held.get(parts[2]!) : undefined;
      const why = held === undefined ? `${ref} is no live secret to refer to` : `${ref} is inherited from ${parts[0]}/${held.from.slug}: refer to ${parts[0]}/${held.from.slug}/${parts[2]} instead`;
      throw new Refusal(notFound(why), denied(ctx, 'secret.reference', 'unknown_source', { ...environment, operationId, metadata: { key, source: ref } }));
    }
    if (found.environment.owner !== null) throw refused(key, `${ref} is in a personal config, which no reference reads`, 'personal');
    need(ctx, 'secret.read', placeOf(found.project, found.environment), 'secret.reference', { operationId, metadata: { key, source: ref } });
    return { key, secretId: found.secret.id };
  }));
  const holders = refs.map(({ key }) => prepared.get(key)?.id ?? randomUUID());
  const [sources, sourceReferences, readers] = await Promise.all([
    secretPlaces(ctx.db, resolved.map((source) => source.secretId)),
    currentReferences(ctx.db, resolved.map((source) => source.secretId)),
    readersOf(ctx.db, holders),
  ]);
  return refs.map(({ key }, i) => {
    const source = sources.get(resolved[i]!.secretId)!;
    const holderId = holders[i]!;
    if (source.id === holderId) throw refused(key, `${key} cannot be a reference to itself`, 'reference_to_itself');
    if (sourceReferences.has(source.id)) {
      const via = sourceReferences.get(source.id);
      throw refused(key, `${sourcePath(source)} is itself a reference${via === undefined ? '' : ` to ${via.view.source}`}: point ${key} at its source instead`, 'reference_to_reference');
    }
    const pointing = readers.filter((reader) => reader.row.source.secretId === holderId);
    if (pointing.length > 0) {
      throw refused(key, `${pointing.length} reference${pointing.length === 1 ? '' : 's'} read ${key} (${pointing.map((reader) => reader.view.holder).join(', ')}): a reference cannot point at a reference, so break ${pointing.length === 1 ? 'it' : 'them'} first`, 'referenced_holder');
    }
    const now = currently.get(holderId);
    return {
      key,
      id: randomUUID(),
      holder: { ...environment, secretId: holderId, path: `${place.project.slug}/${place.environment!.slug}/${key}` },
      source,
      unchanged: now !== undefined && now.row.ended === null && now.row.source.secretId === source.id,
    };
  });
}

/** What a merge patch would do to a key: the answer to `?dryRun=1`. */
export type DryRunOutcome = 'added' | 'changed' | 'unchanged' | 'archived';
export type DryRunResult = { dryRun: true; keys: Record<string, DryRunOutcome> };

/**
 * `setSecrets` without the write: what each key in the patch would become,
 * as an outcome, never a value. Nothing is written but the audit entries.
 *
 * Telling `changed` from `unchanged` decrypts the current value, and the
 * answer tells whoever sent the patch whether their guess was right: a read.
 * So a dry run needs secret.read, and the vault logs every value it opens as
 * a `secret.read` for the purpose `compare`, one operation per call, the way
 * it logs a reveal's. Keys that are new or being archived open nothing.
 */
export async function dryRunSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, SecretValue | null>,
): Promise<DryRunResult> {
  const environment = requireLive(place);
  const operationId = randomUUID();
  return withRefusals(ctx, async () => {
    need(ctx, 'secret.read', placeOf(place.project, place.environment), 'secret.read', { operationId, metadata: { dryRun: true } });
    const rows = new Map((await environmentSecrets(ctx.db, environment.environmentId)).map((row) => [row.key, row]));
    // In a fork, an archived key its parent holds is an override reset to the parent's: writing it overrides again, a change.
    const resettable = await resetKeys(ctx.db, place);
    // Refuse what the write would refuse before opening anything.
    for (const [key, value] of Object.entries(patch)) {
      if (value !== null && rows.get(key)?.archivedAt != null && !resettable.has(key)) {
        throw conflict(`${key} is archived; unarchive it before writing a new version`);
      }
    }

    // A null-prototype record: a key named __proto__ is a key like any other.
    const keys: Record<string, DryRunOutcome> = Object.create(null);
    const comparing: { key: string; value: string; secretVersionId: string; secret: SecretRef; envelope: Envelope }[] = [];
    for (const [key, value] of Object.entries(patch)) {
      const secret = rows.get(key);
      // A mark keeps a value, and one with none of its own here, as the write would refuse it, is refused before anything else.
      if (isMark(value) && (secret === undefined || secret.archivedAt !== null || secret.current === null)) {
        throw conflict(`${key} has no value of its own to mark ${value.sensitivity}: write one`);
      }
      if (value === null) {
        // Archiving what is already gone changes nothing, as in setSecrets.
        keys[key] = secret === undefined || secret.archivedAt !== null ? 'unchanged' : 'archived';
        continue;
      }
      if (secret === undefined) {
        keys[key] = 'added';
        continue;
      }
      if (secret.archivedAt !== null) {
        keys[key] = 'changed';
        continue;
      }
      // A reference, or a value over a reference: what it is now is not a value to compare.
      // A generated value is new by making, and opens nothing to say so. A value is unchanged
      // only as it was held, plain, secret or sensitive: a plain one compares with no read, being no
      // secret, and a sensitive one never with a person's guess, which nobody is told is right.
      const { current } = secret;
      const now = current === null ? null : sensitivityOf(current);
      if (isMark(value)) {
        if (now === null) throw conflict(`${key} has no value of its own to mark ${value.sensitivity}: write one`);
        if (stricter(now, value.sensitivity)) throw conflict(`${key} is ${now}: making it ${value.sensitivity} takes its value written again, never a flip of the one stored`);
        keys[key] = now === value.sensitivity ? 'unchanged' : 'changed';
        continue;
      }
      const level = askedSensitivity(value) ?? (now === 'sensitive' ? 'sensitive' : 'secret');
      if (current === null || level !== now || (typeof value === 'object' && ('generated' in value || 'ref' in value))
        || (now === 'sensitive' && ctx.caller.principal.type === 'user')) {
        keys[key] = 'changed';
        continue;
      }
      const written = typeof value === 'string' ? value : value.value;
      if (now === 'plain') {
        keys[key] = current.plaintext === written ? 'unchanged' : 'changed';
        continue;
      }
      comparing.push({ key, value: written, secretVersionId: current.id, secret: secretRef(place, environment, secret, current.version), envelope: current.envelope });
    }
    const opened = await openValues(ctx.vault, { ...asking(ctx, operationId), purpose: 'compare' }, comparing);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    comparing.forEach(({ key, value }, i) => {
      keys[key] = opened.values[i] === value ? 'unchanged' : 'changed';
    });
    return { dryRun: true as const, keys: { ...keys } };
  });
}

/** Rename a secret, archive or unarchive it, or move it to a folder. Its versions are untouched. */
export async function patchSecret(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: { key?: string; archived?: boolean; folder?: string | null },
): Promise<{ key: string; archived: boolean; folder: string | null }> {
  const environment = requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');
  const wasArchived = secret.archivedAt !== null;
  const renaming = patch.key !== undefined && patch.key !== secret.key;
  const archiving = patch.archived !== undefined && patch.archived !== wasArchived;
  const archived = patch.archived ?? wasArchived;
  const where = { ...environment, secretId: secret.id };
  if (renaming && archived) {
    throw conflict(`${secret.key} is archived; unarchive it before renaming it`);
  }
  const before = (await secretFolderOf(ctx.db, environment.environmentId)).get(secret.id) ?? null;
  const moving = patch.folder !== undefined && patch.folder !== before;
  const folder = moving ? patch.folder! : before;
  if (!renaming && !archiving && !moving) return { key: secret.key, archived, folder };

  const nextKey = patch.key!;
  const result = await audited(ctx, async (tx, log) => {
    // Under the head, as every write to a place: one deleted since the router found it is not written to, nor filed.
    await checkEnvironment(tx, place, environment);
    // A rename names the key it found: renamed meanwhile, the forks below would be searched for a name gone.
    if (renaming) {
      const [now] = await lock(tx, secrets, { id: secret.id });
      if (now?.key !== secret.key) {
        throw new Refusal(
          conflict(`${secret.key} was renamed meanwhile${now === undefined ? '' : ` to ${now.key}`}: nothing changed`),
          denied(ctx, 'secret.rename', 'renamed_meanwhile', { ...where, metadata: { key: secret.key, nextKey } }),
        );
      }
    }
    if (archiving && archived) {
      await refuseIfRead(ctx, tx, `${place.project.slug}/${place.environment!.slug}`, { ...environment, secretIds: [secret.id] }, 'secret.archive', where);
    }
    if (renaming || archiving) {
      try {
        await update(tx, secrets, { id: secret.id }, {
          ...(archiving ? { archivedAt: archived ? new Date() : null } : {}),
          ...(renaming ? { key: nextKey, updatedAt: new Date() } : {}),
        });
      } catch (error) {
        if (!renaming || !isUniqueViolation(error)) throw error;
        throw new Refusal(
          conflict(`a secret named "${nextKey}" already exists`),
          denied(ctx, 'secret.rename', 'duplicate_key', { ...where, metadata: { key: secret.key, nextKey } }),
        );
      }
    }
    if (archiving) {
      log.push(allowed(ctx, archived ? 'secret.archive' : 'secret.unarchive', {
        ...where,
        metadata: { key: secret.key },
      }));
    }
    if (renaming) {
      log.push(allowed(ctx, 'secret.rename', { ...where, metadata: { key: secret.key, nextKey } }));
      await renameBelow(ctx, tx, log, place, secret.key, nextKey);
    }
    // Live under its key again, or under a new one: in a fork, no longer removed. The row as it is now, under the head, names the key.
    if (!archived && (archiving || renaming)) {
      const [now] = await lock(tx, secrets, { id: secret.id });
      if (now !== undefined && now.archivedAt === null) await endRemovals(ctx, tx, log, place, environment, [now.key], null);
    }
    if (moving) {
      await fileSecrets(tx, [{ secretId: secret.id, folder }]);
      log.push(allowed(ctx, 'secret.move', { ...where, metadata: { key: renaming ? nextKey : secret.key, from: before, to: folder } }));
    }
    return { key: renaming ? nextKey : secret.key, archived, folder };
  });
  return result;
}

/**
 * A rename carries down to every fork below, forks of forks and archived
 * ones included (docs/design/forking.md): each one's own row of the key,
 * its override, takes the new name, and so does its removal, so a fork
 * goes on overriding or doing without the key it did. Left alone, it would
 * export its old override beside the parent's renamed key. A fork that
 * holds the new name already refuses the rename, named. No value moves, so
 * the forks take nothing of the renamer.
 */
async function renameBelow(
  ctx: ApiContext,
  tx: Transaction,
  log: AuditEntry[],
  place: ResolvedPath,
  key: string,
  nextKey: string,
): Promise<void> {
  const parent = place.environment!.slug;
  for (const fork of await descendantsOf(tx, place.environment!.id)) {
    const at = { projectId: place.project.id, environmentId: fork.id };
    const rows = await lock(tx, secrets, { environmentId: fork.id, key: [key, nextKey] });
    const taken = rows.find((row) => row.key === nextKey);
    // A personal config is named to nobody but its owner: its own key of the new name moves aside, `NEXT_KEY_2`, rather than stop the rename.
    if (taken !== undefined && fork.owner !== null) {
      const aside = await asideKey(tx, fork.id, nextKey);
      await update(tx, secrets, { id: taken.id }, { key: aside, updatedAt: new Date() });
      log.push(allowed(ctx, 'secret.rename', { ...at, secretId: taken.id, metadata: { key: nextKey, nextKey: aside, parent, aside: true } }));
      // Live under its new name, it is no longer removed there, as any row made live (`endRemovals`). An archived one serves nothing: the removal stands.
      if (taken.archivedAt === null && (await dismissalsIn(tx, fork.id)).some((row) => row.key === aside)) {
        await update(tx, dismissedKeys, { environmentId: fork.id, key: aside }, { restoredAt: new Date(), restoredBy: ctx.caller.principal.id });
        log.push(allowed(ctx, 'missing.restore', { ...at, metadata: { key: aside, renamed: nextKey, parent } }));
      }
    } else if (taken !== undefined) {
      throw new Refusal(
        conflict(`${place.project.slug}/${fork.slug} inherits ${key} and holds a ${nextKey} of its own: rename or archive that one first`),
        denied(ctx, 'secret.rename', 'duplicate_key_below', { ...at, secretId: taken.id, metadata: { key, nextKey, parent } }),
      );
    }
    const own = rows.find((row) => row.key === key);
    if (own !== undefined) {
      await update(tx, secrets, { id: own.id }, { key: nextKey, updatedAt: new Date() });
      log.push(allowed(ctx, 'secret.rename', { ...at, secretId: own.id, metadata: { key, nextKey, parent } }));
    }
    // Its removal follows the key: removed under the old name, removed under the new; not, not.
    const removed = new Set((await dismissalsIn(tx, fork.id)).map((row) => row.key));
    const now = new Date();
    const by = ctx.caller.principal.id;
    if (removed.has(key)) {
      await update(tx, dismissedKeys, { environmentId: fork.id, key }, { restoredAt: now, restoredBy: by });
      await upsert(tx, dismissedKeys, [{ environmentId: fork.id, key: nextKey, dismissedAt: now, dismissedBy: by, restoredAt: null, restoredBy: null }], {
        target: ['environmentId', 'key'],
        columns: ['dismissedAt', 'dismissedBy', 'restoredAt', 'restoredBy'],
      });
      log.push(allowed(ctx, 'missing.restore', { ...at, metadata: { key, renamed: nextKey, parent } }));
      log.push(allowed(ctx, 'missing.dismiss', { ...at, metadata: { key: nextKey, renamed: key, parent } }));
    } else if (removed.has(nextKey)) {
      await update(tx, dismissedKeys, { environmentId: fork.id, key: nextKey }, { restoredAt: now, restoredBy: by });
      log.push(allowed(ctx, 'missing.restore', { ...at, metadata: { key: nextKey, renamed: key, parent } }));
    }
  }
}

/**
 * A name for a personal config's key moved out of a rename's way:
 * `NEXT_KEY_2`, `_3` and on, held by nothing the config reads, its own
 * keys or those it inherits, and within the 128 characters a key takes.
 */
async function asideKey(tx: Transaction, environmentId: string, key: string): Promise<string> {
  const inherited = await inheritedRows(tx, environmentId);
  const taken = new Set([...(await environmentSecrets(tx, environmentId)).map((row) => row.key), ...(inherited?.held.keys() ?? [])]);
  for (let n = 2; ; n++) {
    const suffix = `_${n}`;
    const name = `${key.slice(0, 128 - suffix.length)}${suffix}`;
    if (!taken.has(name)) return name;
  }
}

/**
 * In a fork, reset a key to its parent's value (`inherit`): its own row is
 * archived, with its history, and the parent's value shows through again.
 * `false` undoes that: the row serves again, overriding the parent with the
 * value it had. Either takes `secret.write`, as overriding does, since
 * neither loses a value; so either needs a parent that holds the key, or
 * it would be archiving, which takes more.
 */
export async function inheritSecret(ctx: ApiContext, place: ResolvedPath, inherit: boolean): Promise<InheritResult> {
  const environment = requireLive(place);
  const secret = place.secret!;
  const here = `${place.project.slug}/${place.environment!.slug}`;
  const where = { ...environment, secretId: secret.id };
  if (place.environment!.parentId === null) {
    throw conflict(`${here} inherits from no environment: ${inherit ? 'archive' : 'unarchive'} ${secret.key} instead`);
  }
  return audited(ctx, async (tx, log) => {
    await checkEnvironment(tx, place, environment);
    const [row] = await lock(tx, secrets, { id: secret.id });
    if (row === undefined) throw notFound('unknown secret');
    const folder = (await secretFolderOf(tx, environment.environmentId)).get(secret.id) ?? null;
    const inherited = await inheritedRows(tx, environment.environmentId);
    const held = inherited?.held.get(row.key);
    if (held === undefined) {
      throw new Refusal(
        conflict(`no environment ${here} inherits from holds ${row.key}: ${inherit ? 'archive' : 'unarchive'} it instead`),
        denied(ctx, 'secret.update', 'not_inherited', { ...where, metadata: { key: row.key } }),
      );
    }
    const result = { key: row.key, archived: inherit, folder, from: held.from.slug };
    if ((row.archivedAt !== null) === inherit) return result;
    if (inherit) {
      await refuseIfRead(ctx, tx, here, { ...environment, secretIds: [row.id] }, 'secret.reset', where);
      await update(tx, secrets, { id: row.id }, { archivedAt: new Date() });
      log.push(allowed(ctx, 'secret.reset', { ...where, metadata: { key: row.key, from: held.from.slug } }));
    } else {
      await update(tx, secrets, { id: row.id }, { archivedAt: null });
      log.push(allowed(ctx, 'secret.unarchive', { ...where, metadata: { key: row.key } }));
      await endRemovals(ctx, tx, log, place, environment, [row.key], null);
    }
    return result;
  });
}

/**
 * Rename one of an environment's key folders, or take every key out of it
 * (`to` null): one transaction under the log's head, one `secret.move` per
 * key, archived keys too. Renaming onto a folder that exists merges the
 * two: a folder is only a label. The router checked `secret.write` here.
 */
export async function refileSecrets(ctx: ApiContext, place: ResolvedPath, folder: string, to: string | null): Promise<{ folder: string | null; moved: string[] }> {
  const environment = requireLive(place);
  const operationId = randomUUID();
  return audited(ctx, async (tx, log) => {
    // Under the head, as every write to a place: one archived or deleted since the router found it takes none.
    await checkEnvironment(tx, place, environment);
    const filed = await secretsInFolder(tx, environment.environmentId, folder);
    if (filed.length === 0) throw notFound(`no folder "${folder}" in ${place.project.slug}/${place.environment!.slug}`);
    if (to !== folder) {
      await fileSecrets(tx, filed.map((secret) => ({ secretId: secret.id, folder: to })));
      for (const secret of filed) {
        log.push(allowed(ctx, 'secret.move', { ...environment, secretId: secret.id, operationId, metadata: { key: secret.key, from: folder, to } }));
      }
    }
    return { folder: to, moved: filed.map((secret) => secret.key) };
  });
}

/**
 * Who wrote each version and when, never values. Needs `secret.read`: the
 * shape of a history says something about the secret too.
 */
export async function listVersions(
  ctx: ApiContext,
  place: ResolvedPath,
): Promise<{ key: string; archived: boolean; versions: SecretVersion[] }> {
  requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');
  const versions = await secretHistory(ctx.db, secret.id);
  return {
    key: secret.key,
    archived: secret.archivedAt !== null,
    versions: versions.map((row) => ({
      version: row.version,
      createdAt: row.createdAt.toISOString(),
      createdBy: row.createdBy,
      current: row.id === secret.currentVersionId,
      kek: `${row.envelope.kekProvider}:${row.envelope.kekId}`,
      recipe: row.recipe?.recipe ?? null,
      plain: row.plaintext !== null,
      sensitivity: sensitivityOf(row),
    })),
  };
}

/**
 * Bring back an old value as a new version. The old ciphertext is copied as
 * it is: it is bound to the secret, not to a version number, so it still
 * opens. The vault wraps its data key again under the current key, which
 * takes a write grant and never opens the value.
 */
export async function restoreVersion(
  ctx: ApiContext,
  place: ResolvedPath,
  toVersion: number,
): Promise<{ key: string; version: number }> {
  const environment = requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');
  const where = { ...environment, secretId: secret.id };

  let foundSensitive = false;
  const result = await optimistic(ctx, async () => {
    // Inside the retried preparation, as in setSecrets: a rewrap the retry discards keeps its own id.
    const operationId = randomUUID();
    const [prepared] = await secretHeads(ctx.db, environment.environmentId, { id: secret.id });
    if (prepared === undefined) throw notFound('unknown secret');
    if (prepared.archivedAt !== null) throw conflict(`${secret.key} is archived; unarchive it before restoring a version`);
    const versions = await secretHistory(ctx.db, secret.id);
    const target = versions.find((row) => row.version === toVersion);
    if (target === undefined) {
      throw new Refusal(
        notFound(`${secret.key} has no version ${toVersion}`),
        denied(ctx, 'secret.restore', 'unknown_version', { ...where, operationId, metadata: { key: secret.key, from: toVersion } }),
      );
    }
    const fromVersion = prepared.currentVersion;
    const version = fromVersion + 1;
    // The old value comes back as it was held, plain or a secret, and sensitive while the key is, a reference's source
    // included, or while its newest stored version is, which a key made a reference keeps: the vault rewraps none looser.
    // Resolved again under the head.
    const floor = async (db: Queryable, newest: { sensitive: boolean } | undefined) => {
      const was = (await levelsAt(db, place, environment.environmentId, [prepared.key])).get(prepared.key) ?? null;
      return { was, sensitive: was === 'sensitive' || newest?.sensitive === true };
    };
    // Sensitive once found so, by any attempt: a reference's source written again as a secret between attempts makes it no looser.
    if ((await floor(ctx.db, versions[0])).sensitive) foundSensitive = true;
    const level = foundSensitive ? 'sensitive' : sensitivityOf(target);
    const rewrapped = await rewrapValue(ctx.vault, asking(ctx, operationId), { ...secretRef(place, environment, prepared, version), sensitive: level === 'sensitive' }, target);
    if (!rewrapped.ok) {
      throw vaultRefusal(ctx, rewrapped.refusal, 'secret.restore', { ...where, operationId, metadata: { key: prepared.key, from: toVersion } });
    }
    // An old value brought back ends the reference the key is now.
    const reference = prepared.currentVersionId === null ? (await currentReferences(ctx.db, [secret.id])).get(secret.id) : undefined;
    if (reference !== undefined && reference.row.ended === null) {
      const ended = await ctx.vault.endReferences({
        ...asking(ctx, operationId), reason: 'replaced', items: [{ reference: reference.row.id, seq: Number(reference.row.createdSeq) }],
      });
      if (!ended.ok) throw vaultRefusal(ctx, ended.refusal, 'secret.restore', { ...where, operationId, metadata: { key: prepared.key, from: toVersion } });
    }
    return audited(ctx, async (tx, log) => {
      await checkEnvironment(tx, place, environment);
      const [current] = await lock(tx, secrets, { id: secret.id });
      if (current === undefined || current.currentVersion !== fromVersion || current.currentVersionId !== prepared.currentVersionId
        || current.archivedAt !== null || current.key !== prepared.key) throw new PrepareAgain();
      const { was, sensitive } = await floor(tx, (await secretHistory(tx, secret.id))[0]);
      if (level !== 'sensitive' && sensitive) {
        // Found so, it stays so, as above.
        foundSensitive = true;
        throw new PrepareAgain();
      }
      // The old value comes back with how it was made, and plain if it was. A key pair's half comes
      // back with its pair's id, which pairs it again only beside the other half of the same pair.
      await appendVersion(tx, secret.id, version, rewrapped.values[0], ctx.caller.principal.id, target.recipe, level === 'plain' ? target.plaintext : null, level === 'sensitive');
      log.push(allowed(ctx, 'secret.restore', {
        ...where, operationId, relatedSeq: rewrapped.seqs[0], metadata: { key: prepared.key, version, from: toVersion, ...sensitivityDetail(level, was) },
      }));
      await endRemovals(ctx, tx, log, place, environment, [prepared.key], operationId);
      return { key: prepared.key, version };
    });
  });
  return result;
}

/**
 * The keys the credential proxy opens, chosen from what the read resolved:
 * the environment it resolved to, and each key it holds, whether a
 * parent's and which (`from`, its slug), whether plain, no secret, or
 * sensitive, and whether the caller reads where it is held; and, to
 * whoever reads where it is held, the version it resolves to and the
 * recipe that made it, when a client generated one value by one (a key
 * pair's half has none here). Chosen once, from the rows that are then
 * opened.
 */
export type PickKeys = (
  environment: { path: string; personal: boolean },
  held: { key: string; inherited: boolean; from: string | null; plain: boolean; sensitive: boolean; reads: boolean; versionId: string | null; recipe: string | null }[],
) => readonly string[];

/**
 * The only way to decrypt, and a POST so nothing can trigger it by
 * prefetching. The vault logs one `secret.read` per secret it releases,
 * sharing the operation id: "they read the whole environment" is true but
 * useless, "they read these nine keys at these versions" is what an
 * investigation needs. Refusals are logged too, by whichever of the app and
 * the vault refused.
 *
 * A person's read of a whole environment leaves its sensitive values out,
 * naming them in `sensitive`: nobody is handed one, and the vault refuses
 * any read that asks it to. A read of one sensitive key is refused whole,
 * as the vault's own refusal. A service account reads them all.
 */
export async function reveal(
  ctx: ApiContext,
  path: Path,
  /**
   * For the credential proxy, in process and never over HTTP: some keys
   * only, opened to `use` them for the caller or to `expose` them to their
   * app (docs/design/credential-proxy.md), with `logged` in the app's own
   * entry of it, `credential.use`. A key the environment does not hold is
   * left out, not refused: the proxy says which it needs.
   */
  use?: { purpose: 'use' | 'expose'; keys: readonly string[] | PickKeys; logged: Record<string, unknown> },
): Promise<{ operationId: string; values: Record<string, string>; plain: string[]; sensitive: string[]; version: string | null; environment: { path: string; personal: boolean }; keys: string[] }> {
  const operationId = randomUUID();
  return recorded(ctx, async (log) => {
    // `market/dev@me`: your personal config of dev, or dev while you have none.
    const place = await resolveRead(ctx, path);
    const environment = place === null ? null : liveEnvironment(place);
    if (place === null || environment === null) {
      throw new Refusal(
        notFound('unknown project or environment'),
        denied(ctx, 'secret.read', 'unknown_environment', {
          projectId: place?.project.id ?? null,
          operationId,
          metadata: { path: formatPath(path) },
        }),
      );
    }
    // The proxy uses values for its reader, and hands back only those they read: it needs use, and each value it gives, read.
    need(ctx, use === undefined ? 'secret.read' : 'secret.use', placeOf(place.project, place.environment), 'secret.read', {
      operationId,
      metadata: path.key === undefined ? {} : { key: path.key },
    });
    const read = await readableValues(ctx.db, place, environment, path.key);
    const named = { path: `${place.project.slug}/${personalName(place) ?? place.environment!.slug}`, personal: place.environment!.owner !== null };
    // The proxy's keys, chosen from these very rows, and what stops them: a parent or a reference one of them reads through, or the chain.
    // A parent's plain value, version and recipe are told only to its readers, as the listing tells them (R8): to anyone
    // else, its key is a key like any other.
    const parentOf = (item: Readable) => ({ projectId: environment.projectId, environmentId: item.parent!.environmentId, environmentSlug: item.parent!.slug });
    const told = (item: Readable) => item.parent === undefined || lists(ctx.caller, parentOf(item));
    // Whether the caller reads a value where it is held, which the proxy hands back only then: a Contributor only uses.
    const readsHere = can(ctx.caller, 'secret.read', placeOf(place.project, place.environment));
    const readsAt = (item: Readable) => (item.parent === undefined ? readsHere : can(ctx.caller, 'secret.read', parentOf(item)));
    const chosen = use === undefined ? null : typeof use.keys === 'function' ? use.keys(named, read.items.map((item) => ({
      key: item.key,
      inherited: item.parent !== undefined,
      from: item.parent?.slug ?? null,
      plain: plain(item) && told(item),
      sensitive: item.secret.sensitive === true,
      reads: readsAt(item),
      versionId: told(item) ? item.secretVersionId : null,
      recipe: told(item) && item.via === undefined && item.recipe?.pair === null ? item.recipe.recipe : null,
    }))) : use.keys;
    const wanted = (item: { key?: string }) => chosen === null || item.key === undefined || chosen.includes(item.key);
    // What a person's read of a whole environment leaves out: its sensitive values, which nobody is handed.
    const withheld = (item: Readable) => use === undefined && path.key === undefined && ctx.caller.principal.type === 'user' && item.secret.sensitive === true;
    const rows = read.items.filter((item) => wanted(item) && !withheld(item));
    const sensitive = read.items.filter(withheld).map((item) => item.key);
    const unreadable = read.unreadable.filter(wanted);
    // A key neither here nor inherited. A fork's key may have no row of its own: its parent's is read.
    if (path.key !== undefined && rows.length === 0 && unreadable.length === 0 && (place.secret === null || place.secret.archivedAt !== null)) {
      throw new Refusal(
        notFound('unknown secret'),
        denied(ctx, 'secret.read', 'unknown_secret', { ...environment, operationId, metadata: { key: path.key } }),
      );
    }
    // Before any other refusal: past a key's name, a fork says nothing of what its reader cannot read.
    // The proxy's: what it uses takes use on each parent, and what it hands back was chosen only where its reader reads.
    const unread = unreadParents(ctx, environment.projectId, { items: rows, unreadable }, use === undefined ? ['secret.read'] : ['secret.read', 'secret.use']);
    if (unread.size > 0) {
      const which = [...unread].map(([slug, keys]) => `${keys.join(', ')} from ${place.project.slug}/${slug}`);
      throw new Refusal(
        forbidden(`${formatPath(path)} inherits ${which.join('; ')}, which you cannot read`),
        denied(ctx, 'secret.read', 'parent_unreadable', { ...environment, operationId, metadata: { parents: [...unread.keys()] } }),
      );
    }
    // A reference or a parent that cannot be read stops the whole read, saying why, rather than run without it.
    if (unreadable.length > 0) {
      throw new Refusal(
        conflict(unreadable.map((unread) => unread.reason).join('; ')),
        denied(ctx, 'secret.read', 'reference_unreadable', { ...environment, operationId, metadata: { references: unreadable.length } }),
      );
    }
    // A key with nothing to read, no version of its own and no reference the vault sealed, as a row written around it: no value.
    if (path.key !== undefined && rows.length === 0) {
      throw new Refusal(
        notFound(`${formatPath(path)} holds no value`),
        denied(ctx, 'secret.read', 'no_value', { ...environment, operationId, metadata: { key: path.key } }),
      );
    }
    const opened = await openValues(ctx.vault, { ...asking(ctx, operationId), purpose: use?.purpose ?? (path.key === undefined ? 'run' : 'reveal') }, rows);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const values: Record<string, string> = Object.create(null);
    for (const [i, row] of rows.entries()) values[row.key] = opened.values[i];
    // The keys whose values are plain: no secret, for the proxy to hand on as they are and leave unredacted.
    const plainKeys = rows.filter(plain).map((row) => row.key);
    if (use !== undefined) {
      // Which credential the values went into, and where: the vault's entry names the keys, this one what they were for.
      log.push(allowed(ctx, 'credential.use', { ...environment, operationId, metadata: { purpose: use.purpose, keys: rows.map((row) => row.key), ...use.logged } }));
      return { operationId, values: { ...values }, plain: plainKeys, sensitive, version: null, environment: named, keys: read.items.map((item) => item.key) };
    }
    if (rows.length === 0) {
      // An empty environment still produced a read. Log the attempt rather than nothing.
      log.push(allowed(ctx, 'secret.read', { ...environment, operationId, metadata: { reason: 'empty_environment' } }));
    }
    // An environment's version, of exactly what was read: what a watch compares the next one with.
    return { operationId, values: { ...values }, plain: plainKeys, sensitive, version: path.key === undefined ? versionOf({ items: rows, unreadable }) : null, environment: named, keys: rows.map((row) => row.key) };
  });
}

/**
 * A version of what a read of the environment would open, for whoever
 * polls it before reading (`coffre export --watch`): it changes whenever
 * that does, and opens nothing, so it is not logged. Each key counts with
 * the version it resolves to, its own, its reference's source's or a
 * parent's, and each key that cannot be read with why; never a value or
 * its ciphertext. It hashes the read's own resolution (`readableValues`),
 * so whatever a read comes to resolve through changes it too. Inherited
 * keys it counts need read on their parent, as a read does: their version
 * would say when the parent's value changed, which the listing tells only
 * that parent's readers. A person's leaves the sensitive keys out first,
 * as their read does: one inherited from a parent they do not read is
 * never theirs to read, and refuses neither.
 */
export async function environmentVersion(ctx: ApiContext, place: ResolvedPath): Promise<{ version: string }> {
  const environment = requireLive(place);
  const read = await readableValues(ctx.db, place, environment);
  // Of what a read by the caller would open, filtered as `reveal` filters it, before asking what they read.
  const person = ctx.caller.principal.type === 'user';
  const opened = { ...read, items: read.items.filter((item) => !(person && item.secret.sensitive === true)) };
  const unread = unreadParents(ctx, environment.projectId, opened, ['secret.read', 'secret.use']);
  if (unread.size > 0) {
    const which = [...unread].map(([slug, keys]) => `${keys.join(', ')} from ${place.project.slug}/${slug}`);
    await refuse(ctx, new Refusal(
      forbidden(`${place.project.slug}/${place.environment!.slug} inherits ${which.join('; ')}, which you cannot read`),
      denied(ctx, 'secret.version', 'parent_unreadable', { ...environment, metadata: { parents: [...unread.keys()] } }),
    ));
  }
  return { version: versionOf(opened) };
}

/**
 * A read's version: each key with the version it resolves to, and each key
 * that cannot be read with why. A whole environment's read answers it too
 * (`reveal`), of what it opened.
 */
function versionOf(read: { items: readonly Readable[]; unreadable: readonly Unreadable[] }): string {
  // Key names hold no NUL or newline (`secretKey`), and every reason comes last on its line.
  const hash = createHash('sha256');
  for (const item of read.items) hash.update(`${item.key}\0${item.secretVersionId}\n`);
  for (const unreadable of read.unreadable) hash.update(`!${unreadable.key ?? ''}\0${unreadable.reason}\n`);
  return hash.digest('base64url');
}

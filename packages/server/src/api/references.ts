import { randomUUID } from 'node:crypto';

import { allows, guarded, type Holdings, type Permission, type Place } from '@coffre/core/access';
import type { Envelope } from '@coffre/core/envelope';
import { isTombstone } from '@coffre/core/schemas';
import type { SecretRef, Via } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import {
  dismissalsIn,
  environmentSecrets,
  MAX_PARENTS,
  parentsOf,
  referenceRows,
  secretPlaces,
  secretPlacesOfEnds,
  versionEnvelopes,
  type ReferenceRow,
  type ResolvedPath,
  type SecretPlaceRow,
  type SecretRow,
  type VersionRecipe,
} from '../db/queries.ts';
import { can, lists } from './caller.ts';
import { asking, denied, Refusal, type ApiContext } from './context.ts';
import { ApiError, conflict, notFound, vaultRefused } from './errors.ts';
import { formatMember, type Path } from './paths.ts';
import { placeAt } from './render.ts';
import type { ReadPlace } from './members.ts';

/**
 * References: a secret whose value is another's, read live through it by
 * whoever reads the holder's environment (docs/design/environments.md). The
 * vault makes each one, as its `reference.create` entry, and checks that
 * entry at every read; `secret_references` only points at it.
 */

/**
 * Whether a holder reads through its reference now, and if not, why:
 * ended by the source's side (`broken`) or by a value of its own
 * (`replaced`), or a source that is gone, archived, itself a reference
 * now, or without a value yet. Only `live` reads.
 */
export type ReferenceState = 'live' | 'broken' | 'replaced' | 'source_archived' | 'source_deleted' | 'source_is_reference' | 'source_empty';

/** A reference as the API shows it: where it is held, what it reads, and whether it does. */
export type ReferenceView = {
  id: string;
  holder: string;
  source: string;
  state: ReferenceState;
  /** The source's current version, while it reads. */
  version: number | null;
  createdBy: string;
  createdAt: string;
  endedBy: string | null;
  endedAt: string | null;
};

/** A reference, resolved: its row, both ends' places, and its state. */
export type Resolved = { row: ReferenceRow; holder: SecretPlaceRow; source: SecretPlaceRow | null; state: ReferenceState; view: ReferenceView };

/** A member as a sentence names them: a person by their email, a service account as `service:<name>`. */
const shown = (member: string) => member.replace(/^user:/, '').replace(/^token:/, 'service:');

const path = (place: SecretPlaceRow) => `${place.project}/${place.environment}/${place.key}`;

/** A place deleted for good, alone or with its project: a tombstone's slug (`@coffre/core/schemas`). */
const deleted = (place: SecretPlaceRow) => isTombstone(place.project) || isTombstone(place.environment);

/** Whether a secret is archived, itself or with its environment or project: nothing reads it. */
const archived = (place: SecretPlaceRow) => place.archivedAt !== null || place.environmentArchivedAt !== null || place.projectArchivedAt !== null;

/** Where a secret is, as grants match it: its environment by id and by slug. */
export function placeOfRow(place: SecretPlaceRow): Place {
  return { projectId: place.projectId, environmentId: place.environmentId, environmentSlug: place.environment };
}

/** Both ends of some references: where each secret is now, and the reference each is now, if any (`currentRows`). */
type Ends = { places: Map<string, SecretPlaceRow>; current: Map<string, ReferenceRow> };

/** Both ends of each row, read at once: two statements, side by side. */
async function endsOf(db: Queryable, rows: readonly ReferenceRow[]): Promise<Ends> {
  const ids = [...new Set(rows.flatMap((row) => [row.holder.secretId, row.source.secretId]))];
  if (ids.length === 0) return { places: new Map(), current: new Map() };
  const [held, places] = await Promise.all([referenceRows(db, { holderSecretIds: ids }), secretPlaces(db, ids)]);
  return { places, current: newestHeld(held, places) };
}

/**
 * Both ends of the references sealed in or into a project, as their rows
 * name them: read beside the list of them, needing nothing of it.
 */
async function endsAround(db: Queryable, projectId: string): Promise<Ends> {
  const [held, places] = await Promise.all([referenceRows(db, { endsOf: projectId }), secretPlacesOfEnds(db, projectId)]);
  return { places, current: newestHeld(held, places) };
}

/** Each row, with both ends read (`ends`, when its caller read them already) and its state decided. */
export async function resolveReferences(db: Queryable, rows: readonly ReferenceRow[], ends?: Ends): Promise<Resolved[]> {
  if (rows.length === 0) return [];
  const { places, current } = ends ?? await endsOf(db, rows);
  return rows.map((row) => {
    const holder = places.get(row.holder.secretId)!;
    const source = places.get(row.source.secretId) ?? null;
    const state = stateOf(row, source, current.has(row.source.secretId));
    return {
      row,
      holder,
      source,
      state,
      view: {
        id: row.id,
        holder: path(holder),
        source: source === null ? '(gone)' : path(source),
        state,
        version: state === 'live' ? source!.currentVersion : null,
        createdBy: row.createdBy,
        createdAt: row.createdAt.toISOString(),
        endedBy: row.ended?.by ?? null,
        endedAt: row.ended === null ? null : new Date(row.ended.at).toISOString(),
      },
    };
  });
}

function stateOf(row: ReferenceRow, source: SecretPlaceRow | null, sourceIsReference: boolean): ReferenceState {
  if (row.ended !== null) return row.ended.reason === 'replaced' ? 'replaced' : 'broken';
  if (source === null || deleted(source)) return 'source_deleted';
  if (archived(source)) return 'source_archived';
  if (sourceIsReference) return 'source_is_reference';
  if (source.currentVersionId === null) return 'source_empty';
  return 'live';
}

/**
 * The reference each of these secrets is now, ended or not: its newest,
 * while it has no value of its own. A secret given a value after one ended
 * it is a value, and the reference is its history.
 */
async function currentRows(db: Queryable, secretIds: readonly string[]): Promise<Map<string, ReferenceRow>> {
  if (secretIds.length === 0) return new Map();
  const [rows, places] = await Promise.all([referenceRows(db, { holderSecretIds: [...new Set(secretIds)] }), secretPlaces(db, secretIds)]);
  return newestHeld(rows, places);
}

/** Of the references these secrets held, each one's newest, while it has no value of its own: the reference it is now. */
function newestHeld(rows: readonly ReferenceRow[], places: ReadonlyMap<string, SecretPlaceRow>): Map<string, ReferenceRow> {
  const newest = new Map<string, ReferenceRow>();
  for (const row of rows) newest.set(row.holder.secretId, row);
  for (const secretId of [...newest.keys()]) {
    if (places.get(secretId)?.currentVersionId != null) newest.delete(secretId);
  }
  return newest;
}

/** The reference each of these holders is now, resolved, keyed by holder. */
export async function currentReferences(db: Queryable, secretIds: readonly string[]): Promise<Map<string, Resolved>> {
  if (secretIds.length === 0) return new Map();
  const resolved = await resolveReferences(db, [...(await currentRows(db, secretIds)).values()]);
  return new Map(resolved.map((reference) => [reference.row.holder.secretId, reference]));
}

/** The references `member` made, `user:ada@acme.example`, each resolved. */
export async function referencesBy(db: Queryable, member: string): Promise<Resolved[]> {
  return resolveReferences(db, await referenceRows(db, { createdBy: member }));
}

/** Live references whose source is one of these secrets: what reads them from elsewhere. */
export async function readersOf(db: Queryable, secretIds: readonly string[]): Promise<Resolved[]> {
  if (secretIds.length === 0) return [];
  return currentOf(db, (await referenceRows(db, { sourceSecretIds: [...secretIds] })).filter((row) => row.ended === null));
}

/**
 * Of these rows, those their holder reads through now, resolved; `keep`
 * narrows them further. Their ends as read beside them (`endsAround`),
 * unless a row's seal names an end those did not find.
 */
async function currentOf(db: Queryable, rows: readonly ReferenceRow[], keep: (row: ReferenceRow) => boolean = () => true, around?: Ends): Promise<Resolved[]> {
  const found = around !== undefined && rows.every((row) => around.places.has(row.holder.secretId) && around.places.has(row.source.secretId));
  const ends = found ? around : await endsOf(db, rows);
  return resolveReferences(db, rows.filter((row) => ends.current.get(row.holder.secretId)?.id === row.id && keep(row)), ends);
}

/** What an archive takes: a project, one of its environments, or keys in one. */
export type ArchivedPlace = { projectId: string; environmentId?: string; secretIds?: readonly string[] };

/**
 * The live references that read a secret in `place` from outside it: what
 * archiving it would break, which it is refused while any read (D41). Live
 * as the lists decide, by the vault's seal and its `reference.end`: a row
 * without a seal is no reference, and blocks nothing. One held inside the
 * place is archived with it, and breaks nobody's run; nor does one held in
 * a key, environment or project archived already (D58): if its holder is
 * restored later, it shows its source archived, and reads refuse saying so.
 * Asked under the log's head, with the archive's own write, so that none is
 * made, and no holder restored, meanwhile.
 */
export async function archiveBlockers(db: Queryable, place: ArchivedPlace): Promise<Resolved[]> {
  const within = (end: ReferenceRow['holder']) =>
    end.projectId === place.projectId
    && (place.environmentId === undefined || end.environmentId === place.environmentId)
    && (place.secretIds === undefined || place.secretIds.includes(end.secretId));
  const rows = (await referenceRows(db, place.secretIds === undefined ? { projectId: place.projectId } : { sourceSecretIds: [...place.secretIds] }))
    .filter((row) => row.ended === null && within(row.source) && !within(row.holder));
  const resolved = await currentOf(db, rows);
  return resolved.filter((reference) => reference.state === 'live' && !archived(reference.holder));
}


/** How many references an archive's refusal names, before "and N more". */
const NAMED = 10;

/**
 * Why `what` cannot be archived: the references that read it, and who can
 * break each, as the refusal to make a reference into a held key says it.
 */
export function archiveRefused(what: string, readers: readonly Resolved[]): string {
  const n = readers.length;
  const named = readers.slice(0, NAMED).map((reference) => `${reference.view.holder} reads ${reference.view.source}`);
  const more = n > NAMED ? `, and ${n - NAMED} more` : '';
  const projects = [...new Set(readers.map((reference) => reference.source!.project))];
  return `${n === 1 ? '1 reference reads' : `${n} references read`} ${what}: ${named.join('; ')}${more}. Archiving would stop ${n === 1 ? 'that read' : 'those reads'}, so break ${n === 1 ? 'it' : 'them'} first: ${projects.join(' and ')}'s owners and access managers can, or whoever writes the environment that holds ${n === 1 ? 'it' : 'each'} (\`coffre references break ${n === 1 ? readers[0]!.view.holder : '<holder>'} --apply\`)`;
}

/**
 * Refuse to archive what live references read from elsewhere (D41): under
 * the log's head, in the archive's own transaction, so that none is made
 * meanwhile. Restoring is never refused. `what` is the project's or the
 * environment's path; archiving keys, the refusal names those read, as its
 * message and its entry: `market/prod/DATABASE_URL`, or `2 keys of market/prod`.
 */
export async function refuseIfRead(
  ctx: ApiContext,
  tx: Queryable,
  what: string,
  place: ArchivedPlace,
  action: string,
  fields: Omit<NonNullable<Parameters<typeof denied>[3]>, 'metadata'>,
): Promise<void> {
  const readers = await archiveBlockers(tx, place);
  if (readers.length === 0) return;
  const read = place.secretIds === undefined ? [] : [...new Map(readers.map(({ source }) => [source!.id, source!])).values()]
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const [one] = read.length === 1 ? read : [];
  const named = one !== undefined ? path(one) : read.length > 1 ? `${read.length} keys of ${what}` : what;
  // One key's refusal is in that key's own log; several are listed.
  const about = one !== undefined ? { key: one.key } : read.length > 1 ? { keys: read.map((secret) => secret.key) } : {};
  throw new Refusal(
    conflict(archiveRefused(named, readers)),
    denied(ctx, action, 'referenced', {
      ...fields,
      ...(one === undefined ? {} : { secretId: one.id }),
      metadata: { path: named, ...about, references: readers.map((reference) => reference.row.id) },
    }),
  );
}

/**
 * Why a read through `reference` cannot happen, and who can fix it: said
 * whole, since a run or an export stops at it rather than go without.
 */
export function unreadable({ view, holder, source, row, state }: Resolved): string {
  const at = (iso: string | null) => (iso ?? '').slice(0, 10);
  const lead = `${view.holder} is a reference to ${view.source}`;
  const where = source === null ? 'its project' : `${source.project}/${source.environment}`;
  switch (state) {
    case 'broken':
      return `${lead}, which ${shown(view.endedBy ?? 'someone')} broke on ${at(view.endedAt)}: set a value for ${holder.key}, or ask someone who reads ${where} to make the reference again`;
    case 'replaced':
      return `${view.holder} stopped following ${view.source} on ${at(view.endedAt)}, and has no value of its own yet: set one`;
    case 'source_archived':
      return `${lead}, which is archived: ${where}'s maintainers can unarchive it, or set a value for ${holder.key}`;
    case 'source_deleted':
      return `${lead}, which was deleted: set a value for ${holder.key}`;
    case 'source_is_reference':
      return `${lead}, which is itself a reference now: point ${holder.key} at its source, or set a value`;
    case 'source_empty':
      return `${lead}, which has no value yet: set one there, or here`;
    case 'live':
      return `${lead} (${row.id})`;
  }
}

/**
 * A value to open: its own version, or a source's through a reference
 * (`via`). An inherited one names the parent it comes from, and `through`,
 * the fork it was read in, which the vault logs it in too.
 */
export type Readable = {
  key: string;
  /** The folder it is listed in, where it is held. */
  folder: string | null;
  secretVersionId: string;
  secret: SecretRef;
  envelope: Envelope;
  /** Its value, when it is a plain one: read without the vault (`openValues`). A reference's is always opened through it. */
  plaintext?: string | null;
  /** How its value was made, when a client generated it; a reference's is its source's business, and has none here. */
  recipe?: VersionRecipe | null;
  via?: Via;
  /** A reference's own key, where it is held: what a use names (keys.ts, `OpenItem`). */
  holder?: string;
  /** Where a reference's source is, as grants match it. */
  source?: Place;
  through?: string;
  parent?: { environmentId: string; slug: string };
};

/** What a read cannot open, and why; and the parent it would be inherited from, which the reader must read to be told. */
export type Unreadable = { reason: string; key?: string; parent?: { environmentId: string; slug: string } };
/**
 * A live key held with neither a value nor a reference the vault sealed,
 * written around the app: it settles its name, as the list and the missing
 * keys count it, so a fork serves no parent's value for it, and reads as no
 * value, as it does anywhere.
 */
export type Hollow = { key: string; parent?: { environmentId: string; slug: string } };

/**
 * What a read of an environment, or of one key in it, opens: each live
 * key's current value, and for a key that is a reference, its source's
 * current value through it. A fork's keys come first, then each parent's
 * in turn for the keys no nearer environment holds or removed (a dismissal,
 * docs/design/forking.md), all read in one snapshot, so a write meanwhile
 * is seen whole or not at all; the snapshot is closed before anything is
 * opened. An environment with no parent needs none: a read of it opens no
 * transaction. A key that cannot be read is named in `unreadable`, and its
 * reader decides: a read refuses whole rather than go without it.
 */
export async function readableValues(
  db: Database,
  place: ResolvedPath,
  environment: { projectId: string; environmentId: string },
  key?: string,
  /**
   * The environment's own rows as `app_read` read them already (db/read-ahead.ts): of an environment with no parent
   * only, whose read is that one statement. A fork's layers are read together, in one snapshot.
   */
  ahead?: readonly SecretRow[],
): Promise<{ items: Readable[]; unreadable: Unreadable[]; hollow: Hollow[] }> {
  if (place.environment!.parentId === null) return resolveValues(db, place, environment, key, ahead);
  return db.transaction((tx) => resolveValues(tx, place, environment, key), SNAPSHOT);
}

/** `readableValues` in a transaction of the caller's, as it is under that transaction: a fork's copy, under the log's head. */
export async function resolveValues(
  tx: Queryable,
  place: ResolvedPath,
  environment: { projectId: string; environmentId: string },
  key?: string,
  /** The environment's own rows, read ahead (`readableValues`). */
  ahead?: readonly SecretRow[],
): Promise<{ items: Readable[]; unreadable: Unreadable[]; hollow: Hollow[] }> {
  const here = `${place.project.slug}/${place.environment!.slug}`;
  // An environment that names no parent has none: nothing to read.
  const parents = place.environment!.parentId === null ? [] : await parentsOf(tx, environment.environmentId);
  if (parents === null) return { items: [], unreadable: [{ reason: `${here}'s parents loop or run past ${MAX_PARENTS}: it was made around coffre` }], hollow: [] };
  const layers = [{ id: environment.environmentId, slug: place.environment!.slug, archived: false, deleted: false }, ...parents];
  const items: Readable[] = [];
  const refused: Unreadable[] = [];
  const hollow: Hollow[] = [];
  // The keys a nearer environment settled: holds, or removed.
  const settled = new Set<string>();
  for (const [depth, layer] of layers.entries()) {
    const parent = depth === 0 ? undefined : { environmentId: layer.id, slug: layer.slug };
    if (layer.deleted || layer.archived) {
      refused.push({ reason: `${here} inherits from ${place.project.slug}/${layer.slug}, which is ${layer.deleted ? 'deleted' : 'archived'}` });
      break;
    }
    const own = await valuesIn(tx, place.project.slug, { projectId: environment.projectId, environmentId: layer.id, slug: layer.slug }, key, depth === 0 ? ahead : undefined);
    for (const item of own.items) {
      if (settled.has(item.key)) continue;
      items.push(parent === undefined ? item : { ...item, through: environment.environmentId, parent });
    }
    for (const unread of own.unreadable) if (!settled.has(unread.key)) refused.push({ ...unread, ...(parent === undefined ? {} : { parent }) });
    for (const empty of own.hollow) if (!settled.has(empty)) hollow.push({ key: empty, ...(parent === undefined ? {} : { parent }) });
    for (const settles of [...own.items, ...own.unreadable, ...own.hollow.map((empty) => ({ key: empty }))]) settled.add(settles.key);
    if (depth < layers.length - 1) for (const dismissed of await dismissalsIn(tx, layer.id)) settled.add(dismissed.key);
  }
  items.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { items, unreadable: refused, hollow };
}

/**
 * The inherited keys a caller cannot be told of, by the parent each comes
 * from: values, and unreadable keys alike, since why a key cannot be read
 * (a broken reference's source, who broke it) is the parent's to tell.
 * Reading what a fork inherits takes read on that parent, by the caller's
 * own grants: a fork lends nothing. Using it, as the credential proxy
 * does, takes use there, which read implies (`anyOf`).
 */
export function unreadParents(
  ctx: ApiContext,
  projectId: string,
  read: { items: readonly Readable[]; unreadable: readonly Unreadable[] },
  anyOf: readonly Permission[] = ['secret.read'],
): Map<string, string[]> {
  const unread = new Map<string, string[]>();
  for (const row of [...read.items, ...read.unreadable]) {
    if (row.parent === undefined || row.key === undefined) continue;
    const parent = { projectId, environmentId: row.parent.environmentId, environmentSlug: row.parent.slug };
    if (!anyOf.some((permission) => can(ctx.caller, permission, parent))) unread.set(row.parent.slug, [...(unread.get(row.parent.slug) ?? []), row.key].sort());
  }
  return unread;
}

/** One environment's own values, without what it inherits: `readableValues`, a layer at a time. */
async function valuesIn(
  db: Queryable,
  project: string,
  environment: { projectId: string; environmentId: string; slug: string },
  key?: string,
  ahead?: readonly SecretRow[],
): Promise<{ items: Readable[]; unreadable: { key: string; reason: string }[]; hollow: string[] }> {
  const rows = (ahead ?? (await environmentSecrets(db, environment.environmentId, key === undefined ? undefined : { key }))).filter((row) => row.archivedAt === null);
  const references = await currentReferences(db, rows.filter((row) => row.current === null).map((row) => row.id));
  const live = [...references.values()].filter((reference) => reference.state === 'live');
  const envelopes = await versionEnvelopes(db, live.map((reference) => reference.source!.currentVersionId!));
  const items: Readable[] = [];
  const refused: { key: string; reason: string }[] = [];
  const hollow: string[] = [];
  for (const row of rows) {
    if (row.current !== null) {
      items.push({
        key: row.key,
        folder: row.folder,
        secretVersionId: row.current.id,
        secret: {
          projectId: environment.projectId,
          environmentId: environment.environmentId,
          secretId: row.id,
          version: row.current.version,
          path: `${project}/${environment.slug}/${row.key}`,
          sensitive: row.current.sensitive,
        },
        envelope: row.current.envelope,
        plaintext: row.current.plaintext,
        recipe: row.current.recipe,
      });
      continue;
    }
    const reference = references.get(row.id);
    if (reference === undefined) {
      hollow.push(row.key);
      continue;
    }
    const source = reference.source!;
    const opened = reference.state === 'live' ? envelopes.get(source.currentVersionId!) : undefined;
    if (opened === undefined) {
      refused.push({ key: row.key, reason: unreadable(reference) });
      continue;
    }
    items.push({
      key: row.key,
      folder: row.folder,
      secretVersionId: source.currentVersionId!,
      // Opened as the source it is: its value is bound to the source's ids.
      secret: { projectId: source.projectId, environmentId: source.environmentId, secretId: source.id, version: opened.version, path: path(source), sensitive: opened.sensitive },
      envelope: opened.envelope,
      // A plain source's value is plain here too: a reference takes its nature from its source.
      plaintext: opened.plaintext,
      via: { reference: reference.row.id, seq: Number(reference.row.createdSeq) },
      holder: row.id,
      source: placeOfRow(source),
    });
  }
  return { items, unreadable: refused, hollow };
}

// --- the API -----------------------------------------------------------------------

/** A reference as `GET /api/references` lists it, for whoever may see it. */
export type ListedReference = ReferenceView & {
  /** Who reads its holder's environment, so its source, by a grant: for those who manage either project's access. */
  readers: string[] | null;
  /** Whether the caller may break it: writing its holder, or managing its source's project's access. */
  canBreak: boolean;
  /** Whether its holder is archived, itself or with its environment or project: it reads nothing, and blocks no archive of its source (D58). */
  holderArchived: boolean;
};

/**
 * The live references into and out of a place, `market`, `market/prod` or
 * `market/prod/KEY`: those it lends and those it holds. Each is listed to
 * whoever reads or manages either end; its readers, to whoever manages
 * either project's access. "Who can read this secret" includes them.
 */
export async function listReferences(
  ctx: ApiContext,
  path: Path,
  readersAt: () => Promise<(places: ReadPlace[]) => string[][]>,
): Promise<{ references: ListedReference[] }> {
  const place = await placeAt(ctx, path);
  if (place === null || (path.environment !== undefined && place.environment === null) || (path.key !== undefined && place.secret === null)) {
    throw notFound('no such project, environment or secret');
  }
  const [all, around] = await Promise.all([referenceRows(ctx.db, { projectId: place.project.id }), endsAround(ctx.db, place.project.id)]);
  const rows = all.filter((row) => row.ended === null);
  const at = (end: ReferenceRow['holder']) =>
    (path.environment === undefined || end.environmentId === place.environment!.id) && (path.key === undefined || end.secretId === place.secret!.id);
  const { caller } = ctx;
  const sees = (row: ReferenceRow) => [row.holder, row.source].some((end) =>
    lists(caller, end) || can(caller, 'grant.manage', { projectId: end.projectId }));
  const manages = (row: ReferenceRow) => [row.holder, row.source].some((end) => can(caller, 'grant.manage', { projectId: end.projectId }));
  // Who reads through them, for whoever manages access at either end: read beside both ends, once one may be shown.
  const [resolved, readersOf] = await Promise.all([
    currentOf(ctx.db, rows, (row) => (at(row.holder) || at(row.source)) && sees(row), around),
    rows.some((row) => (at(row.holder) || at(row.source)) && manages(row)) ? readersAt() : null,
  ]);
  const shown = resolved.filter((reference) => manages(reference.row));
  const readers = readersOf?.(shown.map((reference) => ({ ...reference.row.holder, ...(reference.source === null ? {} : { source: placeOfRow(reference.source) }) }))) ?? [];
  return {
    references: resolved.map((reference) => ({
      ...reference.view,
      readers: shown.includes(reference) ? readers[shown.indexOf(reference)]! : null,
      canBreak: can(caller, 'secret.write', reference.row.holder) || can(caller, 'grant.manage', { projectId: reference.row.source.projectId }),
      holderArchived: archived(reference.holder),
    })),
  };
}

/**
 * The live references into or out of a place being deleted: what reads it
 * from elsewhere, and what it reads. Deleting the place ends them.
 */
export async function referencesAt(db: Queryable, place: { projectId: string; environmentId: string | null }): Promise<Resolved[]> {
  const within = (end: ReferenceRow['holder']) =>
    end.projectId === place.projectId && (place.environmentId === null || end.environmentId === place.environmentId);
  const rows = (await referenceRows(db, { projectId: place.projectId }))
    .filter((row) => row.ended === null && (within(row.holder) || within(row.source)));
  return resolveReferences(db, rows);
}

/** End these references as broken, in one vault call: nothing reads through them any more. */
export async function endReferences(ctx: ApiContext, references: readonly Resolved[], operationId: string): Promise<void> {
  if (references.length === 0) return;
  const ended = await ctx.vault.endReferences({
    ...asking(ctx, operationId),
    reason: 'broken',
    items: references.map((reference) => ({ reference: reference.row.id, seq: Number(reference.row.createdSeq) })),
  });
  if (!ended.ok) throw vaultRefused(ended.refusal);
}

/**
 * Break the reference a secret is: its readers stop reading the source
 * through it. Whoever writes the holder may, and whoever manages the
 * source's project's access; the vault decides, and logs `reference.end`.
 * To anyone else, there is no such reference.
 */
export async function breakReference(ctx: ApiContext, place: ResolvedPath): Promise<{ reference: ReferenceView }> {
  const secret = place.secret;
  const reference = secret === null || place.environment === null ? undefined : (await currentReferences(ctx.db, [secret.id])).get(secret.id);
  const { caller } = ctx;
  const may = reference !== undefined && (can(caller, 'secret.write', reference.row.holder) || can(caller, 'grant.manage', { projectId: reference.row.source.projectId }));
  if (reference === undefined || !may) throw notFound('no such reference');
  if (reference.row.ended !== null) throw conflict(`${reference.view.holder} stopped following ${reference.view.source} already`);
  const operationId = randomUUID();
  const ended = await ctx.vault.endReferences({
    ...asking(ctx, operationId),
    reason: 'broken',
    items: [{ reference: reference.row.id, seq: Number(reference.row.createdSeq) }],
  });
  if (!ended.ok) throw vaultRefused(ended.refusal);
  return { reference: { ...reference.view, state: 'broken', endedBy: formatMember(caller.principal), endedAt: new Date().toISOString() } };
}

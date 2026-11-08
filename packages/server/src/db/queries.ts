import { EVERYWHERE, type GrantPlace, type InstanceRole, type Scope } from '@coffre/core/access';
import { BEARER_PROFILES } from '@coffre/core/identity';
import { verifyEntries, type Author, type LogKey } from '@coffre/core/audit';
import { ACCESS_ACTIONS, MAX_PARENTS, settingsFrom, type Checkpoint, type EnvironmentColumns, type LoggedChange, type SecretColumns } from '@coffre/core/vault';
import type { Envelope } from '@coffre/core/envelope';
import { deletedWithProject, isTombstone, personalOf, tombstoneOf } from '@coffre/core/schemas';
import { later, own, prepared, tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { accessAllowed, logObject, newestSeqQuery, newestVaultSeq, recordField, recorded, withinBytes, type ChangeRecord } from '@coffre/db/log';
import { findingsOf, findingStands, readGrants, storedRole, tamperedMembers } from '@coffre/db/grants';
import * as dialect from '@coffre/db/dialect';
import { ahead, canonicalTimestamp, changedRows, clock, clockMillis, forUpdate, migrationLedger, tombstone, truth, type Table } from '@coffre/db/dialect';
import type * as schema from '@coffre/db/schema';
import { alias } from 'drizzle-orm/pg-core';
import { and, asc, count, countDistinct, desc, eq, exists, getTableColumns, getTableName, gt, gte, inArray, isNotNull, isNull, like, lt, lte, not, notInArray, or, sql, type AnyColumn, type SQL } from 'drizzle-orm';

import { answerQuery, settingsQuery } from './answers.ts';
import { readsBy } from './reads.ts';
import { authMac, AuthRowTampered, checkAuthRow, issuedBy, issuingBinding, signedAs, verifyAuthRow, type AuthRow, type AuthTable } from '../auth-rows.ts';

/**
 * Every query coffre runs, and nowhere else: named reads returning all
 * that their callers need, generic writes, and a lock.
 * The server works on what these return and never writes SQL; lint keeps
 * drizzle out of the server and the pages.
 *
 * Each query builds on the tables of the database it is given (`tablesOf`),
 * so the one text runs on Postgres and SQLite; see portable.ts. The
 * server names a table for the generic writes by importing schema.ts, and
 * `own` swaps in the database's twin.
 *
 * Ordinary writes do not check first and do not read back. A unique constraint
 * answers "is it taken", and a conditional update's row count answers "was
 * it still there"; the response is built from what was written. Signed rows
 * authenticate their old contents before a state change is signed.
 */

// --- generic writes -----------------------------------------------------------

type Tables = typeof schema;
type Row<T extends Table> = T['$inferSelect'];
type NewRow<T extends Table> = T['$inferInsert'];

/**
 * Which rows: each named column equals its value, is null, or is one of a
 * list. `{ environmentId, key: ['A', 'B'], archivedAt: null }`.
 */
export type Match<T extends Table> = {
  [K in keyof Row<T>]?: Row<T>[K] | NonNullable<Row<T>[K]>[];
};

function matching<T extends Table>(table: T, match: Match<T>): SQL | undefined {
  const columns = getTableColumns(table) as Record<string, ReturnType<typeof getTableColumns>[string]>;
  return and(
    ...Object.entries(match)
      .filter(([, value]) => value !== undefined)
      .map(([name, value]) => {
        const column = columns[name];
        if (value === null) return isNull(column);
        return Array.isArray(value) ? inArray(column, value) : eq(column, value);
      }),
  );
}

export async function insert<T extends Table>(db: Queryable, table: T, rows: NewRow<T> | NewRow<T>[]): Promise<void> {
  if (Array.isArray(rows) && rows.length === 0) return;
  await db.insert(own(db, table)).values(rows as never);
}

/** Insert the rows whose unique keys are free; returns how many that was. */
export async function insertIfAbsent<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T> | NewRow<T>[],
): Promise<number> {
  const all = Array.isArray(rows) ? rows : [rows];
  if (all.length === 0) return 0;
  return dialect.insertIfAbsent(db, own(db, table), all);
}

/** Insert the rows, or where one repeats the unique key `target`, overwrite its `columns`. */
export async function upsert<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T>[],
  { target, columns }: { target: (keyof Row<T>)[]; columns: (keyof Row<T>)[] },
): Promise<void> {
  if (rows.length === 0) return;
  await dialect.upsert(db, own(db, table), rows, target, columns);
}

/**
 * Set columns on the matching rows; returns how many matched. Matching on
 * the old value (`{ id, revokedAt: null }`) makes it a compare-and-set.
 */
export async function update<T extends Table>(
  db: Queryable,
  table: T,
  match: Match<T>,
  set: Partial<NewRow<T>>,
): Promise<number> {
  const mine = own(db, table);
  return changedRows(await db.update(mine).set(set as never).where(matching(mine, match)));
}

/**
 * A credential's last use, on its own and outside any transaction, as sign-in writes it when nothing carries it: a touch
 * handed to a held write (`heldWrites`) whose write then went down today's path instead. Losing it never costs the request.
 */
export async function touchCredential(db: Queryable, touch: { credential: string; at: Date; ip: string | null }): Promise<void> {
  await update(db, tablesOf(db).credentials, { id: touch.credential }, { lastUsedAt: touch.at, lastUsedIp: touch.ip }).catch(() => 0);
}

/** State changes authenticate the old row first and cannot overwrite a concurrent change. */
export async function updateAuth<
  T extends Tables['identities'] | Tables['credentials'] | Tables['deviceLogins'] | Tables['serviceBindings'] | Tables['oauthClients'] | Tables['mcpConnections'],
>(
  db: Queryable,
  chainKey: Buffer,
  table: T,
  match: Match<T>,
  changes: Partial<NewRow<T>>,
): Promise<number> {
  const mine = own(db, table);
  const kind = signedAs(getTableName(table));
  const rows = await db.select().from(mine as Table).where(matching(mine, match));
  let changed = 0;
  for (const raw of rows) {
    const row = raw as AuthRow;
    // An unauthenticated row is dead; never sign its claimed contents again.
    if (!checkAuthRow(chainKey, kind, row)) continue;
    const next = { ...row, ...changes } as AuthRow;
    changed += await update(db, table, { ...match, id: row.id, authMac: row.authMac } as Match<T>, {
      ...changes, authMac: authMac(chainKey, kind, next),
    } as Partial<NewRow<T>>);
  }
  return changed;
}

/**
 * Lock the matching rows until the transaction ends, and read them as they
 * are once the lock is ours. Only for real races; each caller says which.
 */
export async function lock<T extends Table>(tx: Transaction, table: T, match: Match<T>): Promise<Row<T>[]> {
  const mine = own(tx, table);
  return (await forUpdate(tx, tx.select().from(mine as Table).where(matching(mine, match)))) as Row<T>[];
}

/**
 * An environment's rows of `secrets`, archived ones included. The table is
 * indexed by project first (`secrets_lookup_idx`), which a read by
 * environment alone does not name: it would walk that index end to end, or the
 * table, every project's keys and every archived one in it (T152). So the
 * project is read off the environment, once for the statement (an init plan),
 * and the rows are a range of that environment's own.
 */
function inEnvironment(db: Queryable, environmentId: string): SQL {
  const { secrets, environments } = tablesOf(db);
  return and(
    eq(secrets.environmentId, environmentId),
    eq(secrets.projectId, sql`(SELECT ${environments.projectId} FROM ${environments} WHERE ${environments.id} = ${environmentId})`),
  )!;
}

// --- places -----------------------------------------------------------------

export type ResolvedPath = {
  project: { id: string; slug: string; name: string; archivedAt: Date | null };
  environment: {
    id: string;
    slug: string;
    name: string;
    archivedAt: Date | null;
    /** The environment it inherits from, a fork's, and its slug. */
    parentId: string | null;
    parentSlug: string | null;
    /** A personal config's owner, `user:<email>`: an environment whose values are theirs alone. */
    owner: string | null;
  } | null;
  /**
   * For a path that asks for your personal config, `market/dev@me`: the
   * environment it is a config of, whether you have one (`environment`) or
   * not (null). Only a read falls back to it: then `environment` is it,
   * and `fallback` says so.
   */
  personal?: { of: { id: string; slug: string; archivedAt: Date | null }; fallback?: true };
  secret: {
    id: string;
    key: string;
    archivedAt: Date | null;
    currentVersionId: string | null;
    /** 0 before the first version. */
    currentVersion: number;
  } | null;
};

const none = sql`1 = 0`;

/** A place that is not deleted: its slug is no tombstone's (`@coffre/core/schemas`). */
function standing(slug: AnyColumn): SQL {
  return not(tombstone(slug));
}

/**
 * A path's project, environment and secret. Null when the project does not
 * exist; a missing environment or secret comes back as null in its place.
 * A deleted place is missing too, unless asked for its `tombstones`, by
 * which the log is still read: `market~deleted-2026-10-05`. Then a deleted
 * project's environment is named by its slug as it was, `…/dev`, as well as
 * by its own tombstone: 0.14 leaves it `dev`, 0.15's log makes it
 * `dev~deleted` (`deletedWithProject`). Never both: no live slug holds a
 * `~`, and only a project's deletion, once, writes `dev~deleted`.
 */
export async function resolvePath(
  db: Queryable,
  path: { project: string; environment?: string; key?: string },
  { tombstones = false, owner = null }: { tombstones?: boolean; owner?: string | null } = {},
): Promise<ResolvedPath | null> {
  const { projects, environments, secrets } = tablesOf(db);
  const alive = (slug: AnyColumn) => (tombstones ? undefined : standing(slug));
  // `dev@me`: dev first, then its personal config owned by whoever asks, and the key in that.
  const personalSlug = path.environment === undefined ? null : personalOf(path.environment);
  const slug = personalSlug ?? path.environment;
  // A deleted project's environment by its slug as it was: `dev` or `dev~deleted`, the exact one first should both ever be there.
  const either = tombstones && slug !== undefined && !isTombstone(slug);
  const [row] = await db
    .select({ project: projects, environment: environments, secret: secrets })
    .from(projects)
    .leftJoin(
      environments,
      slug === undefined
        ? none
        : and(
          eq(environments.projectId, projects.id),
          either ? inArray(environments.slug, [slug, deletedWithProject(slug)]) : eq(environments.slug, slug),
          alive(environments.slug),
        ),
    )
    .leftJoin(
      secrets,
      path.key === undefined || personalSlug !== null ? none : and(eq(secrets.projectId, projects.id), eq(secrets.environmentId, environments.id), eq(secrets.key, path.key)),
    )
    .where(and(eq(projects.slug, path.project), alive(projects.slug)))
    .orderBy(...(either ? [sql`CASE WHEN ${environments.slug} = ${slug} THEN 0 ELSE 1 END`] : []))
    .limit(1);
  if (row === undefined) return null;
  const { project } = row;
  let { environment, secret } = row;
  let personal: ResolvedPath['personal'];
  if (personalSlug !== null) {
    // A personal config is never anyone's parent: `dev@me@me` names nothing.
    if (environment === null || environment.owner !== null) {
      environment = null;
    } else {
      personal = { of: { id: environment.id, slug: environment.slug, archivedAt: environment.archivedAt } };
      const mine = owner === null ? undefined : await personalConfig(db, environment.id, owner);
      environment = mine ?? null;
      secret = null;
      if (mine !== undefined && path.key !== undefined) {
        [secret = null] = await db.select().from(secrets).where(and(eq(secrets.projectId, project.id), eq(secrets.environmentId, mine.id), eq(secrets.key, path.key)));
      }
    }
  }
  const parentSlug = environment?.parentId == null
    ? null
    : personal?.of.id === environment.parentId
      ? personal.of.slug
      : ((await db.select({ slug: environments.slug }).from(environments).where(eq(environments.id, environment.parentId)))[0]?.slug ?? null);
  return {
    ...resolvedPlace(project, environment, parentSlug),
    ...(personal === undefined ? {} : { personal }),
    secret:
      secret === null
        ? null
        : {
            id: secret.id,
            key: secret.key,
            archivedAt: secret.archivedAt,
            currentVersionId: secret.currentVersionId,
            currentVersion: secret.currentVersion,
          },
  };
}

/**
 * A project and an environment as a resolved path names them, from their
 * rows and the parent's slug: what `resolvePath` answers, and what a read
 * that found them otherwise answers in its place.
 */
export function resolvedPlace(
  project: { id: string; slug: string; name: string; archivedAt: Date | null },
  environment: { id: string; slug: string; name: string; archivedAt: Date | null; parentId: string | null; owner: string | null } | null,
  parentSlug: string | null,
): Pick<ResolvedPath, 'project' | 'environment'> {
  return {
    project: { id: project.id, slug: project.slug, name: project.name, archivedAt: project.archivedAt },
    environment: environment === null
      ? null
      : { id: environment.id, slug: environment.slug, name: environment.name, archivedAt: environment.archivedAt, parentId: environment.parentId, parentSlug, owner: environment.owner },
  };
}

/** When each environment was made, by id. */
export async function environmentsCreatedAt(db: Queryable, ids: readonly string[]): Promise<Map<string, Date>> {
  if (ids.length === 0) return new Map();
  const { environments } = tablesOf(db);
  const rows = await db.select({ id: environments.id, createdAt: environments.createdAt }).from(environments).where(inArray(environments.id, [...ids]));
  return new Map(rows.map((row) => [row.id, row.createdAt]));
}

/** `owner`'s personal config of an environment, deleted ones apart: one at most (`environments_parent_id_owner_key`). */
export async function personalConfig(db: Queryable, parentId: string, owner: string) {
  const { environments } = tablesOf(db);
  const [row] = await db
    .select()
    .from(environments)
    .where(and(eq(environments.parentId, parentId), eq(environments.owner, owner), standing(environments.slug)));
  return row;
}

/** Live environments' paths by id, `market/dev`, as they are named now: one deleted, or of a project deleted, is left out. */
export async function environmentPaths(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const { projects, environments } = tablesOf(db);
  const rows = await db
    .select({ id: environments.id, environment: environments.slug, project: projects.slug })
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(and(inArray(environments.id, [...ids]), standing(environments.slug), standing(projects.slug)));
  return new Map(rows.map((row) => [row.id, `${row.project}/${row.environment}`]));
}

/**
 * What a decision made from the policy holds to (`policyStill`), in one
 * statement: the newest `policy.change`, by its number, as
 * `newestPolicySeq` reads it, and the live slug of each environment `ids`
 * names, as the vault reads them into the policy (`livePolicy`). One
 * deleted, or of a project deleted, is left out, as one whose row is not
 * written yet.
 */
export function policyNow(db: Queryable, ids: readonly string[]): Promise<{ seq: bigint | null; slugs: Map<string, string> }> {
  // Started now (`.then`), not once awaited: under `audited`, ahead of what the work asks next, a first `later` write
  // included, which could otherwise rename a protected environment before this reads it (postgres-js's `flush`).
  // Nothing protected, the newest change alone: a join on nothing still scans every environment on SQLite.
  if (ids.length === 0) return newestVaultSeq(db, 'policy.change').then((seq) => ({ seq, slugs: new Map<string, string>() }));
  const { projects, environments } = tablesOf(db);
  const live = sql`${and(inArray(environments.id, [...ids]), standing(environments.slug))}
    AND EXISTS (SELECT 1 FROM ${projects} WHERE ${projects.id} = ${environments.projectId} AND ${standing(projects.slug)})`;
  // One row for the newest change, whatever the environments: one more per live environment, each beside it.
  return dialect.rowsNow<{ seq: string | number | null; id: string | null; slug: string | null }>(db, sql`
    SELECT (${newestSeqQuery(db, 'policy.change')}) AS seq, ${environments.id} AS id, ${environments.slug} AS slug
    FROM (SELECT 1 AS one) AS here LEFT JOIN ${environments} ON ${live}`).then((rows) => {
    const seq = rows[0]?.seq ?? null;
    return {
      seq: seq === null ? null : BigInt(seq),
      slugs: new Map(rows.flatMap((row) => (row.id === null || row.slug === null ? [] : [[row.id, row.slug] as const]))),
    };
  });
}

export type PlaceRow = {
  id: string;
  slug: string;
  name: string;
  archivedAt: Date | null;
  /** The folder it is listed in, or null for none. */
  folder: string | null;
  /**
   * Distinct live keys across its live environments but personal configs,
   * the team's: the project list's count for whoever lists every one of
   * them. Null unless counted (`counts`).
   */
  teamKeys: number | null;
  /** Each with its live secret count, its own rows (a fork's inherited keys are its parent's), null unless counted. */
  environments: {
    id: string;
    slug: string;
    name: string;
    archivedAt: Date | null;
    parentId: string | null;
    parentSlug: string | null;
    /** A personal config's owner: listed to them and to the project's maintainers alone. */
    owner: string | null;
    secretCount: number | null;
  }[];
};

/**
 * Every project with its environments, by slug. Deleted ones are left out,
 * unless asked for their `tombstones`, to name an id the log holds. `within`
 * reads only the projects of these ids, for a request whose caller reaches no
 * others: it reads as many rows however many projects there are beside them.
 *
 * `counts` counts each environment's live secrets and each project's team keys,
 * in the same statement: what the project list shows, and a render's shell. A
 * count reads the keys of the places it reads (`countedPlaceRows`), so unasked
 * the statement reads no `secrets` at all (T221): a member's report, `me` and
 * the rest read as many pages however many keys the instance holds, and by one
 * plan, where a count's plan followed the statistics of `secrets` (T166's
 * flake, 48 pages one run and 1,183 the next).
 */
export async function places(
  db: Queryable,
  { tombstones = false, within, counts: counted = false }: { tombstones?: boolean; within?: readonly string[]; counts?: boolean } = {},
): Promise<PlaceRow[]> {
  if (within?.length === 0) return [];
  if (counted && tombstones) throw new Error('places: only live places are counted');
  const rows: (Awaited<ReturnType<typeof placeRows>>[number] & { secretCount?: number; teamKeys?: number | null })[] = counted
    ? (within !== undefined ? await countedPlaceRows(db, within) : await liveCountedPlaces(db))
    : within !== undefined ? await placeRows(db, tombstones, within) : tombstones ? await everyPlace(db) : await livePlaces(db);
  const found: PlaceRow[] = [];
  for (const { project, environment, secretCount, teamKeys } of rows) {
    let place = found.at(-1);
    if (place?.id !== project.id) {
      place = { id: project.id, slug: project.slug, name: project.name, archivedAt: project.archivedAt, folder: project.folder, teamKeys: counted ? 0 : null, environments: [] };
      found.push(place);
    }
    // The project's team keys come with each of its environments that holds keys.
    if (counted && teamKeys != null) place.teamKeys = Number(teamKeys);
    if (environment === null) continue;
    place.environments.push({
      id: environment.id,
      slug: environment.slug,
      name: environment.name,
      archivedAt: environment.archivedAt,
      parentId: environment.parentId,
      parentSlug: null,
      owner: environment.owner,
      secretCount: counted ? Number(secretCount) : null,
    });
  }
  for (const place of found) {
    const slugOf = new Map(place.environments.map((environment) => [environment.id, environment.slug]));
    for (const environment of place.environments) environment.parentSlug = environment.parentId === null ? null : (slugOf.get(environment.parentId) ?? null);
  }
  return found;
}

/**
 * The ids of these projects' environments, deleted ones among them: where a page of the log reads what was written
 * (`writtenAt`). The environments alone, by `environments_project_id_slug_key`, a thousand projects a statement: as
 * many rows as environments, however many keys they hold, where `places` counts each one's (review r7 of #490).
 */
export async function environmentIdsOf(db: Queryable, projectIds: readonly string[]): Promise<Map<string, string[]>> {
  const { environments } = tablesOf(db);
  const unique = [...new Set(projectIds)];
  const found = new Map<string, string[]>(unique.map((id) => [id, []]));
  for (let start = 0; start < unique.length; start += 1000) {
    const rows = await db.select({ id: environments.id, projectId: environments.projectId }).from(environments)
      .where(inArray(environments.projectId, unique.slice(start, start + 1000)));
    for (const { id, projectId } of rows) found.get(projectId)!.push(id);
  }
  return found;
}

/** The projects and their environments, a row each (a project with none, a row of its own), and nothing of their keys. */
function placeRows(db: Queryable, tombstones: boolean, within?: readonly string[]) {
  const { projects, environments } = tablesOf(db);
  const alive = (slug: AnyColumn) => (tombstones ? undefined : standing(slug));
  return db
    .select({ project: projects, environment: environments })
    .from(projects)
    .leftJoin(environments, and(eq(environments.projectId, projects.id), alive(environments.slug)))
    .where(and(alive(projects.slug), within === undefined ? undefined : inArray(projects.id, [...within])))
    .orderBy(asc(projects.slug), asc(environments.slug));
}

/**
 * The live places' rows, each with its environment's live keys counted and its project's team keys (`PlaceRow.teamKeys`).
 * Both counts come from one read of the keys (`live`, a CTE named twice, so Postgres reads it once), and that read
 * names the standing environments it counts by id, `= ANY(ARRAY(…))`, so Postgres can scan `secrets_live_idx` over
 * those ids alone, past the keys of deleted environments (0.14's log leaves them unarchived). Grouped over all of
 * `secrets_live_idx`, the count read every deleted environment's keys: with 40,000 keys in 100 deleted environments,
 * the project list's count went from 308 pages to 945, where this one went from 166 to 169 (`request-cost.alone.ts`,
 * review r1 of T221). That is a plan, not a promise: Postgres may scan the whole table and filter the deleted
 * environments' keys out, as with one standing environment of 4,000 keys beside two deleted ones of 4,000 each
 * (67 pages, then 191, review r2).
 *
 * This bounds what it reads to the keys it counts, not their pages: Postgres picks between a bitmap scan, each table
 * page once, and an index scan, a table page for each key, by `secrets.environment_id`'s correlation, computed over the
 * archived keys too. With 600,000 archived keys in environment order and 41,200 live ones among them, this count reads
 * 19,861 pages, as every shape of it that reads the table does; a covering index reads 514 there, and 61,491 once
 * scattered updates have cleared the visibility map. Only counts kept as the keys change would bound it (T226).
 */
function countedPlaceRows(db: Queryable, within?: readonly string[]) {
  const { projects, environments, secrets } = tablesOf(db);
  const counted = db
    .select({ id: environments.id })
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(and(standing(environments.slug), standing(projects.slug), within === undefined ? undefined : inArray(environments.projectId, [...within])));
  const live = db.$with('live').as(db
    .select({ environmentId: secrets.environmentId, projectId: secrets.projectId, key: secrets.key })
    .from(secrets)
    .where(and(
      isNull(secrets.archivedAt),
      dialect.engineOf(db) === 'postgres' ? sql`${secrets.environmentId} = ANY(ARRAY(${counted}))` : inArray(secrets.environmentId, counted),
    )));
  const keys = db
    .select({ environmentId: live.environmentId, projectId: live.projectId, keys: count().as('keys') })
    .from(live)
    .groupBy(live.environmentId, live.projectId)
    .as('keys');
  const team = db
    .select({ projectId: live.projectId, keys: countDistinct(live.key).as('team_keys') })
    .from(live)
    .innerJoin(environments, and(eq(environments.id, live.environmentId), isNull(environments.archivedAt), isNull(environments.owner)))
    .groupBy(live.projectId)
    .as('team');
  // An environment's count and its project's team keys, a row for each environment with keys: a subquery, so that the
  // statement starts `select`, a read the others of a request ride with (`plainRead` in @coffre/db).
  const counts = db
    .with(live)
    .select({ environmentId: keys.environmentId, keys: keys.keys, teamKeys: team.keys })
    .from(keys)
    .leftJoin(team, eq(team.projectId, keys.projectId))
    .as('counts');
  return db
    .select({
      project: projects,
      environment: environments,
      secretCount: sql<number>`coalesce(${counts.keys}, 0)`,
      teamKeys: counts.teamKeys,
    })
    .from(projects)
    .leftJoin(environments, and(eq(environments.projectId, projects.id), standing(environments.slug)))
    .leftJoin(counts, eq(counts.environmentId, environments.id))
    .where(and(standing(projects.slug), within === undefined ? undefined : inArray(projects.id, [...within])))
    .orderBy(asc(projects.slug), asc(environments.slug));
}

// What most requests read of the instance, every project and environment: built once (`prepared`).
const livePlaces = prepared((db) => placeRows(db, false));
const liveCountedPlaces = prepared((db) => countedPlaceRows(db));
const everyPlace = prepared((db) => placeRows(db, true));

// --- folders --------------------------------------------------------------------
// One level, for projects and for an environment's secrets, which arrange
// lists and do nothing else (docs/design/environments.md): a column on each.

/** The folder each project is listed in, for those in one. */
export async function projectFolderOf(db: Queryable): Promise<Map<string, string>> {
  const { projects } = tablesOf(db);
  const rows = await db.select({ id: projects.id, folder: projects.folder }).from(projects).where(isNotNull(projects.folder));
  return new Map(rows.map((row) => [row.id, row.folder!]));
}

/**
 * The projects filed in `folder`, deleted ones left out, each with its
 * environments, as seeing a project is decided: what renaming or removing
 * the folder moves.
 */
export async function projectsInFolder(db: Queryable, folder: string): Promise<{ id: string; slug: string; environments: { id: string; slug: string }[] }[]> {
  const { projects, environments } = tablesOf(db);
  const rows = (await db
    .select({ id: projects.id, slug: projects.slug })
    .from(projects)
    .where(eq(projects.folder, folder))
    .orderBy(asc(projects.slug))).filter((row) => !isTombstone(row.slug));
  if (rows.length === 0) return [];
  const places = await db
    .select({ id: environments.id, slug: environments.slug, projectId: environments.projectId })
    .from(environments)
    .where(inArray(environments.projectId, rows.map((row) => row.id)));
  return rows.map((row) => ({ ...row, environments: places.filter((place) => place.projectId === row.id && !isTombstone(place.slug)) }));
}

/** An environment's secrets filed in `folder`, archived ones too, by key. */
export async function secretsInFolder(db: Queryable, environmentId: string, folder: string): Promise<{ id: string; key: string }[]> {
  const { secrets } = tablesOf(db);
  return db
    .select({ id: secrets.id, key: secrets.key })
    .from(secrets)
    .where(and(inEnvironment(db, environmentId), eq(secrets.folder, folder)))
    .orderBy(asc(secrets.key));
}

/** The folder each of an environment's secrets is listed in, for those in one. */
export async function secretFolderOf(db: Queryable, environmentId: string): Promise<Map<string, string>> {
  const { secrets } = tablesOf(db);
  const rows = await db
    .select({ id: secrets.id, folder: secrets.folder })
    .from(secrets)
    .where(and(inEnvironment(db, environmentId), isNotNull(secrets.folder)));
  return new Map(rows.map((row) => [row.id, row.folder!]));
}

/** File a project in `folder`, or in none. */
export async function fileProject(tx: Transaction, projectId: string, folder: string | null): Promise<void> {
  const { projects } = tablesOf(tx);
  await tx.update(projects).set({ folder }).where(eq(projects.id, projectId));
}

/** File secrets in folders, or in none: one update per folder. */
export async function fileSecrets(tx: Transaction, rows: { secretId: string; folder: string | null }[]): Promise<void> {
  const { secrets } = tablesOf(tx);
  for (const folder of new Set(rows.map((row) => row.folder))) {
    const ids = rows.filter((row) => row.folder === folder).map((row) => row.secretId);
    await tx.update(secrets).set({ folder }).where(inArray(secrets.id, ids));
  }
}

/**
 * How many distinct live secret names each project holds across the given
 * environments: the same key in dev and prod is one secret.
 */
export async function distinctSecretCounts(db: Queryable, environmentIds: string[]): Promise<Map<string, number>> {
  if (environmentIds.length === 0) return new Map();
  const { secrets } = tablesOf(db);
  const rows = await db
    .select({ projectId: secrets.projectId, count: countDistinct(secrets.key) })
    .from(secrets)
    .where(and(inArray(secrets.environmentId, environmentIds), isNull(secrets.archivedAt)))
    .groupBy(secrets.projectId);
  return new Map(rows.map((row) => [row.projectId, Number(row.count)]));
}

// --- deleting a place ----------------------------------------------------------

/** A project, or one of its environments: what a deletion takes. */
export type Doomed = { projectId: string; environmentId: string | null };

/** A grant, lapsed or live, on a place being deleted: an environment's names its project too, as the vault's changes do. */
export type DoomedGrant = { principal: string; projectId: string; environmentId: string | null; role: string; expiresAt: number | null };

/**
 * What deleting a place would take: how many keys it names, how many of
 * their versions still hold a value, and every grant on it, lapsed ones
 * too, with who would hold nothing else afterwards. The grants are the
 * vault's to revoke; a list of them is a read (`members` reads them too).
 */
export async function deletionScope(db: Queryable, place: Doomed): Promise<{
  /** The environments it takes, by slug: a project's every live one, or the one. */
  environments: { id: string; slug: string }[];
  keys: number;
  versions: number;
  grants: DoomedGrant[];
  /** Members with no instance role, whose every live grant is among `grants`. */
  stranded: string[];
}> {
  const { secrets, secretVersions, grants, principals, environments } = tablesOf(db);
  const under = secretsUnder(secrets, place);
  // Every grant on the instance, the place's and all others: few rows, and what tells who is left holding nothing.
  const [going, [keys], [versions], held] = await Promise.all([
    db.select({ id: environments.id, slug: environments.slug }).from(environments).where(and(
      eq(environments.projectId, place.projectId),
      place.environmentId === null ? standing(environments.slug) : eq(environments.id, place.environmentId),
    )).orderBy(asc(environments.slug)),
    db.select({ n: count() }).from(secrets).where(under),
    db.select({ n: count() }).from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
      .where(and(under, holdsValue(secretVersions))),
    db.select({
      principal: grants.principal,
      projectId: sql<string>`coalesce(${grants.projectId}, ${environments.projectId})`,
      environmentId: grants.environmentId,
      role: grants.role,
      expiresAt: grants.expiresAt,
      owner: principals.owner,
      instanceRole: principals.role,
      scope: principals.scope,
    })
      .from(grants)
      .innerJoin(principals, eq(principals.principal, grants.principal))
      .leftJoin(environments, eq(environments.id, grants.environmentId))
      .orderBy(asc(grants.principal)),
  ]);
  const doomed = (grant: (typeof held)[number]) =>
    place.environmentId === null ? grant.projectId === place.projectId : grant.environmentId === place.environmentId;
  const lost = held.filter(doomed).map(({ owner: _, instanceRole: _role, scope: _scope, ...grant }) => grant);
  const now = Date.now();
  // An instance role that reaches anything keeps them in, wherever its scope does.
  const roleless = (grant: (typeof held)[number]) => storedRole({ owner: grant.owner, role: grant.instanceRole, scope: grant.scope }).role === 'member';
  const stranded = [...new Set(lost.map((grant) => grant.principal))].filter((principal) =>
    held.every((grant) => grant.principal !== principal
      || (roleless(grant) && (doomed(grant) || (grant.expiresAt !== null && grant.expiresAt <= now)))));
  return { environments: going, keys: Number(keys.n), versions: Number(versions.n), grants: lost, stranded };
}

function secretsUnder(secrets: Tables['secrets'], place: Doomed): SQL {
  return and(
    eq(secrets.projectId, place.projectId),
    place.environmentId === null ? undefined : eq(secrets.environmentId, place.environmentId),
  )!;
}

/** A version that still holds its value: an erased one has an empty ciphertext and wrapped key, and no plaintext. */
function holdsValue(secretVersions: Tables['secretVersions']): SQL {
  return or(sql`length(${secretVersions.ciphertext}) > 0`, sql`length(${secretVersions.wrappedDek}) > 0`, isNotNull(secretVersions.plaintext))!;
}

/**
 * Empty the ciphertext and wrapped data key of every version under a place,
 * and clear a plain one's plaintext: the one change a version takes
 * (`secret_versions_erase_only`). Its row stays, which the log names.
 * Returns how many still held a value.
 */
export async function eraseVersions(tx: Transaction, place: Doomed): Promise<number> {
  const { secrets, secretVersions } = tablesOf(tx);
  const under = tx.select({ id: secrets.id }).from(secrets).where(secretsUnder(secrets, place));
  const empty = Buffer.alloc(0);
  return changedRows(await tx.update(secretVersions)
    .set({ ciphertext: empty, wrappedDek: empty, plaintext: null })
    .where(and(inArray(secretVersions.secretId, under), holdsValue(secretVersions))));
}

/** The ids of the live keys under a place, archived ones apart: those its deletion erases with 0.15's log. */
export async function liveSecretsUnder(db: Queryable, place: Doomed): Promise<string[]> {
  const { secrets } = tablesOf(db);
  return (await db.select({ id: secrets.id }).from(secrets).where(and(secretsUnder(secrets, place), isNull(secrets.archivedAt)))).map((row) => row.id);
}

/**
 * Each of a deleted project's environments its tombstone, `dev~deleted`
 * (`deletedWithProject`), in one write under the log's head, which every
 * change of a slug takes first. No read: the project is deleted once, so
 * none of its environments holds such a slug yet.
 */
export async function tombstoneEnvironments(tx: Transaction, going: readonly string[]): Promise<void> {
  if (going.length === 0) return;
  const { environments } = tablesOf(tx);
  await tx.update(environments).set({ slug: sql`${environments.slug} || ${deletedWithProject('')}` }).where(inArray(environments.id, [...going]));
}

/**
 * The slug a deleted place keeps, `market~deleted-2026-10-05`, or
 * `market~deleted-2026-10-05-2` for the second that day: one that no
 * tombstone beside it holds yet. A deletion reads it under the log's
 * head, which every change of a slug takes first, so no other can claim it
 * before it commits.
 */
export async function tombstoneSlug(db: Queryable, slug: string, day: Date, within: { projectId: string } | null): Promise<string> {
  const { projects, environments } = tablesOf(db);
  const base = tombstoneOf(slug, day);
  const rows = within === null
    ? await db.select({ slug: projects.slug }).from(projects).where(like(projects.slug, `${base}%`))
    : await db.select({ slug: environments.slug }).from(environments)
      .where(and(eq(environments.projectId, within.projectId), like(environments.slug, `${base}%`)));
  const taken = new Set(rows.map((row) => row.slug));
  let n = 1;
  while (taken.has(tombstoneOf(slug, day, n))) n += 1;
  return tombstoneOf(slug, day, n);
}

// --- 0.15's objects -----------------------------------------------------------

/**
 * `value`, of a key's newest reference row, null for a key with none: a seek
 * on `secret_references_holder_idx`, (secret_id, created_seq), to the last
 * row at or before the key's newest, taken only if that row is the key's.
 * `holder` names the key's id in the outer query. As `secret_id = holder
 * ORDER BY created_seq DESC LIMIT 1`, the equality makes `secret_id` a
 * constant of the order, which `secret_references_created_seq_key` then
 * serves too: where few keys hold many rows, Postgres walks it backwards,
 * through every newer row of every other key's (T220: a key's object read
 * 288 pages once another key had 5,000 newer rows, 4 before;
 * `request-cost.alone.ts`). Only the holder index serves this order.
 */
function ofNewestReference(db: Queryable, holder: AnyColumn | SQL, value: SQL): SQL<string | null> {
  const { secretReferences } = tablesOf(db);
  return sql<string | null>`(SELECT CASE WHEN ${secretReferences.secretId} = ${holder} THEN ${value} END FROM ${secretReferences}
    WHERE ${secretReferences.secretId} <= ${holder} ORDER BY ${secretReferences.secretId} DESC, ${secretReferences.createdSeq} DESC LIMIT 1)`;
}

/** A row as an object of 0.15's log takes it (@coffre/core/vault's columns), with the seal on it. */
export type ObjectRead<C> = { columns: C; seal: Buffer | null };

/** A key's columns and seal; `archived`: no object while it is, and these columns what it serves unarchived. */
export type SecretRead = ObjectRead<SecretColumns> & { archived: boolean };

/**
 * Keys as 0.15's objects take them (`secretObject`, packages/vault): each
 * one's place, its current version's nature and wrapped data key, never its
 * ciphertext, a plain one's text (which the vault hashes: its object, and
 * the log, hold only the digest; these columns are never logged), and, with
 * no version of its own, the source its newest reference names while that
 * reference has not ended, as `use_credential` reads them. By id, or every
 * key under a place, archived ones included.
 */
export async function secretObjects(db: Queryable, by: { ids: readonly string[] } | { under: Doomed }): Promise<Map<string, SecretRead>> {
  const { secrets, secretVersions, secretReferences } = tablesOf(db);
  // Its newest reference row's source, unless that row has ended (`ended_at`): the vault's end of it, logged.
  const source = ofNewestReference(db, secrets.id, sql`CASE WHEN ${secretReferences.endedAt} IS NULL THEN ${secretReferences.sourceSecretId} END`);
  // And that row's id, which the object holds beside its source.
  const reference = ofNewestReference(db, secrets.id, sql`CASE WHEN ${secretReferences.endedAt} IS NULL THEN ${secretReferences.id} END`);
  const read = (where: SQL) => db
    .select({
      id: secrets.id,
      projectId: secrets.projectId,
      environmentId: secrets.environmentId,
      archivedAt: secrets.archivedAt,
      seal: secrets.seal,
      versionId: secrets.currentVersionId,
      sensitive: secretVersions.sensitive,
      plaintext: secretVersions.plaintext,
      kekProvider: secretVersions.kekProvider,
      kekId: secretVersions.kekId,
      kekVersion: secretVersions.kekVersion,
      wrappedDek: secretVersions.wrappedDek,
      source,
      reference,
    })
    .from(secrets)
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(where);
  const rows = [];
  if ('under' in by) rows.push(...await read(secretsUnder(secrets, by.under)));
  else {
    const unique = [...new Set(by.ids)];
    for (let start = 0; start < unique.length; start += 1000) rows.push(...await read(inArray(secrets.id, unique.slice(start, start + 1000))));
  }
  return new Map(rows.map((row) => [row.id, {
    columns: {
      id: row.id,
      projectId: row.projectId,
      environmentId: row.environmentId,
      source: row.versionId === null ? row.source : null,
      reference: row.versionId === null ? row.reference : null,
      version: row.versionId === null || row.wrappedDek === null ? null : {
        id: row.versionId,
        sensitive: row.sensitive === true,
        plaintext: row.plaintext ?? null,
        kekProvider: row.kekProvider!,
        kekId: row.kekId!,
        kekVersion: row.kekVersion!,
        wrappedDek: Buffer.from(row.wrappedDek).toString('base64'),
      },
    },
    seal: row.seal ?? null,
    archived: row.archivedAt !== null,
  }]));
}

/**
 * Environments as 0.15's objects take them (`environmentObject`), by id, or a
 * project's every one, deleted ones included: each with its project's
 * archival, apart from its own.
 */
export async function environmentObjects(db: Queryable, by: { ids: readonly string[] } | { projectId: string }): Promise<Map<string, ObjectRead<EnvironmentColumns>>> {
  const { environments, projects } = tablesOf(db);
  if ('ids' in by && by.ids.length === 0) return new Map();
  const rows = await db
    .select({
      id: environments.id,
      projectId: environments.projectId,
      slug: environments.slug,
      owner: environments.owner,
      parentId: environments.parentId,
      protected: environments.protected,
      archivedAt: environments.archivedAt,
      projectArchived: truth(isNotNull(projects.archivedAt)),
      seal: environments.seal,
    })
    .from(environments)
    .leftJoin(projects, eq(projects.id, environments.projectId))
    .where('ids' in by ? inArray(environments.id, [...new Set(by.ids)]) : eq(environments.projectId, by.projectId));
  return new Map(rows.map(({ archivedAt, projectArchived, seal, ...row }) => [row.id, {
    columns: { ...row, protected: row.protected ?? null, archived: archivedAt !== null, projectArchived: Boolean(projectArchived) },
    seal: seal ?? null,
  }]));
}

// --- members and sign-in ------------------------------------------------------

/**
 * A member as the database names it, the vault's way: `user:<email>` for a
 * person, `token:<id>` for a service. The API's `service` stays out of storage.
 */
export function principalOf(member: { type: string; id: string }): string {
  return `${member.type === 'service' ? 'token' : 'user'}:${member.id}`;
}

/** `principalOf` undone. */
export function memberOf(principal: string): { type: 'user' | 'service'; id: string } {
  const colon = principal.indexOf(':');
  return { type: principal.slice(0, colon) === 'token' ? 'service' : 'user', id: principal.slice(colon + 1) };
}

/**
 * A member's status and generation as the vault last committed them, or
 * null for no member: `user:…` or `token:…`. Read without a lock:
 * a member's row is the vault's to lock. Inside a transaction that holds
 * the log's head, any change the vault is making waits for it, so what this
 * reads holds until it commits.
 */
export async function memberStanding(db: Queryable, principal: string): Promise<{ status: string; generation: number; accessSeq: bigint } | null> {
  const { principals } = tablesOf(db);
  const [row] = await db
    .select({ status: principals.status, generation: principals.generation, accessSeq: principals.accessSeq })
    .from(principals)
    .where(eq(principals.principal, principal));
  return row ?? null;
}

/**
 * The vault's newest entry about `principal`'s access, their role, grants
 * or membership, by its seq, as their row names it (`access_seq`); null for
 * no row. Read before the vault is asked about them, and again under the
 * head, it says whether its answer is still theirs (`issuerStill`): the
 * vault writes the row with each such entry, under the same head. With the
 * database clock, as `findCredential` reads, so that Hyperdrive never
 * answers it from its cache.
 */
export async function newestAccessSeq(db: Queryable, principal: string): Promise<bigint | null> {
  const { principals } = tablesOf(db);
  const [row] = await db.select({ seq: principals.accessSeq, now: clock(db) }).from(principals).where(eq(principals.principal, principal));
  return row?.seq ?? null;
}

/**
 * Whether a request's way in still stands: its member active at the
 * generation it was checked at, the credential it came in on not revoked,
 * and the MCP connection or Cloudflare binding it came through neither, the
 * binding with no tombstone either; one statement, with the
 * database clock, so that Hyperdrive never answers it from its cache: a
 * cached yes from an earlier request would let a revoked one through. Rows
 * read only to refuse, so no MAC to check: a row changed around the app can
 * only turn a request away (`credentialStill`).
 */
export async function wayInStands(
  db: Queryable,
  way: { principal: string; generation: number; credentialId: string | null; bindingId?: string | null; connectionId: string | null },
): Promise<boolean> {
  const { principals, credentials, mcpConnections, serviceBindings } = tablesOf(db);
  const credential = way.credentialId === null ? sql`1 = 1` : sql`EXISTS (SELECT 1 FROM ${credentials} WHERE ${credentials.id} = ${way.credentialId}
    AND ${credentials.revokedAt} IS NULL AND ${credentials.generation} = ${way.generation})`;
  const connection = way.connectionId === null ? sql`1 = 1` : sql`EXISTS (SELECT 1 FROM ${mcpConnections} WHERE ${mcpConnections.id} = ${way.connectionId}
    AND ${mcpConnections.revokedAt} IS NULL AND ${mcpConnections.generation} = ${way.generation})`;
  const binding = way.bindingId == null ? sql`1 = 1` : sql`EXISTS (SELECT 1 FROM ${serviceBindings} WHERE ${serviceBindings.id} = ${way.bindingId}
    AND ${serviceBindings.revokedAt} IS NULL AND ${serviceBindings.generation} = ${way.generation}) AND NOT ${hasTombstone(db, way.bindingId)}`;
  const [row] = await db
    .select({ status: principals.status, generation: principals.generation, stands: truth(sql`${credential} AND ${connection} AND ${binding}`), now: clock(db) })
    .from(principals)
    .where(eq(principals.principal, way.principal));
  return row !== undefined && row.status === 'active' && row.generation === way.generation && row.stands;
}

/**
 * Who holds each role, as stored: how many grants name each project role,
 * lapsed ones too, as the vault counts them before deleting a role; and how
 * many active people hold each instance role.
 */
export async function roleHolders(db: Queryable): Promise<{ roles: Map<string, number>; instanceRoles: Map<InstanceRole, number> }> {
  const { grants, principals } = tablesOf(db);
  const [granted, people] = await Promise.all([
    db.select({ role: grants.role, count: count() }).from(grants).groupBy(grants.role),
    db.select({ owner: principals.owner, role: principals.role, scope: principals.scope })
      .from(principals)
      .where(and(eq(principals.status, 'active'), like(principals.principal, 'user:%'))),
  ]);
  const instanceRoles = new Map<InstanceRole, number>();
  for (const row of people) {
    const { role } = storedRole(row);
    instanceRoles.set(role, (instanceRoles.get(role) ?? 0) + 1);
  }
  return { roles: new Map(granted.map((row) => [row.role, Number(row.count)])), instanceRoles };
}

/**
 * Every active member, person or service account, with their instance
 * role, its scope and their live grants, as stored: what weighing a change
 * to the roles reads (`roleImpact`). A service account is a Member of
 * everything, whatever its row says, as the vault reads it. The vault
 * checks these rows whenever they are used; a display reads them as the
 * database has them.
 */
export async function memberHoldings(db: Queryable, now: Date): Promise<{ principal: string; service: boolean; role: InstanceRole; scope: Scope; grants: StoredGrant[] }[]> {
  const { principals } = tablesOf(db);
  const [rows, granted] = await Promise.all([
    db.select({ principal: principals.principal, owner: principals.owner, role: principals.role, scope: principals.scope })
      .from(principals)
      .where(eq(principals.status, 'active'))
      .orderBy(asc(principals.principal)),
    readGrants(db, { liveAt: now.getTime() }),
  ]);
  const byPrincipal = new Map<string, StoredGrant[]>();
  for (const { principal, projectId, environmentId, role, expiresAt } of granted) {
    byPrincipal.set(principal, [...(byPrincipal.get(principal) ?? []), { projectId, environmentId, role, expiresAt }]);
  }
  return rows.map((row) => {
    const service = !row.principal.startsWith('user:');
    const standing = service ? { role: 'member' as const, scope: EVERYWHERE } : storedRole(row);
    return { principal: row.principal, service, ...standing, grants: byPrincipal.get(row.principal) ?? [] };
  });
}

/**
 * A grant as `grants` holds it: on a project, or one of its
 * environments (with its project). A grant on every project of 0.4, which
 * names neither until the vault replaces it, reaches nothing (`grantKind`).
 */
export type StoredGrant = GrantPlace & { role: string; expiresAt: number | null };

const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export type MemberRow = {
  type: 'user' | 'service';
  id: string;
  createdAt: Date;
  /** As the vault last wrote their row. */
  status: 'active' | 'removed';
  /** Their instance role and its scope, projects by id (`storedRole`). */
  role: InstanceRole;
  scope: Scope;
  generation: number;
  statusChangedAt: Date;
  statusChangedBy: string;
  /**
   * Their live grants, as stored. The vault checks a member's row and
   * grants against its MAC whenever they are used, which the app cannot:
   * a list shows them as the database has them.
   */
  grants: StoredGrant[];
  /**
   * Whether the vault has found their row or grants changed around it
   * since it last changed what they hold (`tamperedMembers`): a finding of
   * 0.15's log names their newest change, or, for a finding of 0.14's, its
   * newest is newer than its newest access entry. The vault refuses them while their row fails its check.
   */
  tampered: boolean;
  /** Live credentials: neither revoked nor expired. */
  credentials: {
    id: string;
    kind: string;
    generation: number;
    label: string | null;
    tokenHint: string;
    identityId: string | null;
    /** The provider of the account that opened a session. */
    provider: string | null;
    createdAt: Date;
    createdBy: string;
    expiresAt: Date;
    lastUsedAt: Date | null;
    lastUsedIp: string | null;
    /** A service token's scope, as stored (`readScope`). */
    scope: string | null;
  }[];
  /** Sign-in accounts still bound. */
  identities: {
    id: string;
    provider: string;
    subject: string;
    issuerHash: string;
    generation: number;
    email: string | null;
    createdAt: Date;
    lastSignInAt: Date | null;
  }[];
};

/** What one member holds, as stored: their row, their live grants by place, and the projects' slugs a scope names by id. */
export type MemberAccessRows = {
  /** Null when they have no row. */
  /** `admittedBy`: who admitted them last, or removed them, as their row says (`status_changed_by`). */
  member: { status: 'active' | 'removed'; role: InstanceRole; scope: Scope; tampered: boolean; admittedBy: string } | null;
  grants: { projectId: string; projectSlug: string; environmentId: string | null; environmentSlug: string | null; role: string; expiresAt: number | null }[];
  /** Every project's slug, by id, when their scope names projects; empty otherwise. */
  projectSlugs: Map<string, string>;
};

/**
 * One member's access in one query, whatever they hold: their row (and
 * whether the vault's findings about it stand, as `tamperedMembers` says:
 * whether a finding names their newest change, the newest of 0.14's
 * against their newest access entry), each live grant with the slugs of
 * its place, and, when their scope names projects, every project's slug,
 * to name them by. A member page reads this once, not one list per project.
 *
 *   SELECT m.status, m.owner, m.role, m.scope, m.status_changed_by, <finding>, <change>, x.*
 *   FROM principals m LEFT JOIN (
 *     SELECT 'grant', g.principal, project, slugs, role, end FROM grants g … WHERE g.principal = $1 AND live
 *     UNION ALL
 *     SELECT 'project', $1, p.id, p.slug, … FROM projects p WHERE m's scope is set
 *   ) x ON x.principal = m.principal
 *   WHERE m.principal = $1
 */
export async function memberAccess(db: Queryable, principal: string, now: Date): Promise<MemberAccessRows> {
  const { principals: m, grants: g, environments: e, projects: p, auditLog: log } = tablesOf(db);
  const actions = sql.join(ACCESS_ACTIONS.map((action) => sql`${action}`), sql`, `);
  const place = sql`coalesce(${g.projectId}, ${e.projectId})`;
  const found = findingsOf(db, principal);
  const query = sql`
    SELECT ${m.status} AS status, ${m.owner} AS owner, ${m.role} AS member_role, ${m.scope} AS scope, ${m.statusChangedBy} AS status_changed_by,
      ${found.legacy} AS found_seq, ${found.named} AS found_named,
      (SELECT CAST(max(${log.seq}) AS text) FROM ${log} WHERE ${log.author} = 'vault' AND ${log.decision} = 'allow'
        AND ${log.action} IN (${actions}) AND ${log.subjectPrincipal} = ${m.principal}) AS changed_seq,
      x.kind, x.project_id, x.project_slug, x.environment_id, x.environment_slug, x.role, x.expires_at
    FROM ${m}
    LEFT JOIN (
      SELECT 'grant' AS kind, ${g.principal} AS principal, ${place} AS project_id, ${p.slug} AS project_slug,
        ${g.environmentId} AS environment_id, ${e.slug} AS environment_slug, ${g.role} AS role, ${g.expiresAt} AS expires_at
      FROM ${g}
      LEFT JOIN ${e} ON ${e.id} = ${g.environmentId}
      JOIN ${p} ON ${p.id} = ${place}
      WHERE ${g.principal} = ${principal} AND (${g.expiresAt} IS NULL OR ${g.expiresAt} > ${now.getTime()})
      UNION ALL
      SELECT 'project', CAST(${principal} AS text), ${p.id}, ${p.slug}, NULL, NULL, NULL, NULL
      FROM ${p}
      WHERE EXISTS (SELECT 1 FROM ${m} WHERE ${m.principal} = ${principal} AND ${m.scope} IS NOT NULL)
    ) x ON x.principal = ${m.principal}
    WHERE ${m.principal} = ${principal}`;
  type Row = {
    status: string; owner: boolean | number; member_role: string | null; scope: string | null; status_changed_by: string;
    found_seq: string | null; found_named: number | string; changed_seq: string | null;
    kind: 'grant' | 'project' | null; project_id: string | null; project_slug: string | null;
    environment_id: string | null; environment_slug: string | null; role: string | null; expires_at: string | number | null;
  };
  const rows = await dialect.rowsOf<Row>(db, query);
  const [first] = rows;
  if (first === undefined) return { member: null, grants: [], projectSlugs: new Map() };
  const big = (value: string | null) => (value === null ? null : BigInt(value));
  return {
    member: {
      status: first.status as 'active' | 'removed',
      ...storedRole({ owner: first.owner === true || first.owner === 1, role: first.member_role, scope: first.scope }),
      tampered: findingStands({ legacy: big(first.found_seq), access: big(first.changed_seq), named: Number(first.found_named) === 1 }),
      admittedBy: first.status_changed_by,
    },
    grants: rows.flatMap((row) =>
      row.kind === 'grant'
        ? [{
            projectId: row.project_id!,
            projectSlug: row.project_slug!,
            environmentId: row.environment_id,
            environmentSlug: row.environment_slug,
            role: row.role!,
            expiresAt: row.expires_at === null ? null : Number(row.expires_at),
          }]
        : [],
    ),
    projectSlugs: new Map(rows.flatMap((row) => (row.kind === 'project' ? [[row.project_id!, row.project_slug!] as const] : []))),
  };
}

/**
 * The vault retains removed members too: a member the log has changed
 * with no row means tampering. Of one member, a change of theirs in 0.15's
 * log (one probe of its object's index) or an allowed access entry of
 * 0.14's (one probe of `audit_log_access_idx`), as the vault's check weighs
 * both (`#onLog`): the adds of 0.16 write no access entry (T179 PR 4a). Of
 * everyone, the principals the vault's allowed access entries name, each
 * found by one step down that index (a skip scan), those with a row passed
 * over: as many steps as there are principals, however many entries, its
 * refusals included, the log holds about them (R48, T239). A change's
 * object names its member by a hash alone, which a scan cannot turn back
 * into a principal; but a first add down the two-trip path, which since
 * 0.16.0 writes no access entry, names them in its payload: those too, one
 * entry each of `log_changes_admitted_idx`, as many as were added so (a
 * principal's first add is its only one, made where no row names them).
 */
export async function missingMembers(db: Queryable, member?: { type: string; id: string }): Promise<string[]> {
  if (member !== undefined) {
    const principal = principalOf(member);
    const rows = await dialect.rowsOf<{ principal: string }>(db, sql`SELECT CAST(${principal} AS text) AS principal
      WHERE NOT EXISTS (SELECT 1 FROM principals WHERE principals.principal = ${principal})
        AND (EXISTS (SELECT 1 FROM log_changes WHERE log_changes.object = ${logObject('principal', principal)})
          OR EXISTS (SELECT 1 FROM audit_log WHERE ${accessAllowed()} AND subject_principal = ${principal}))`);
    return rows.map((row) => row.principal);
  }
  const next = (after: SQL | null) => sql`(SELECT subject_principal FROM audit_log WHERE ${accessAllowed()} AND subject_principal ${after === null ? sql`IS NOT NULL` : sql`> ${after}`} ORDER BY subject_principal LIMIT 1)`;
  const engine = dialect.engineOf(db);
  // Whom a first add down the two-trip path added: its payload's `ref`, `{"id": principal, "kind": "principal"}`.
  const added = engine === 'postgres' ? sql.raw(`(log_changes.payload::jsonb -> 'ref' ->> 'id')`) : sql.raw(`json_extract(log_changes.payload, '$.ref.id')`);
  // A plain read, `select …`, which a page's other reads may go with (`groupReads`, @coffre/db/hyperdrive).
  const rows = await dialect.rowsOf<{ principal: string }>(db, sql`SELECT principal FROM (
    WITH RECURSIVE named (principal) AS (
      SELECT ${next(null)}
      UNION ALL
      SELECT ${next(sql`named.principal`)} FROM named WHERE named.principal IS NOT NULL
    )
    SELECT principal FROM named
    WHERE (principal LIKE 'user:%' OR principal LIKE 'token:%')
      AND NOT EXISTS (SELECT 1 FROM principals WHERE principals.principal = named.principal)
    UNION
    SELECT a.principal FROM (SELECT ${added} AS principal FROM log_changes WHERE ${recorded(engine, sql.raw('log_changes.payload'), 'admitted')}) AS a
    WHERE NOT EXISTS (SELECT 1 FROM principals WHERE principals.principal = a.principal)
  ) AS missing ORDER BY principal`);
  return rows.map((row) => row.principal);
}

/**
 * People and services in the vault's directory, with their live sessions,
 * tokens and sign-in accounts: one of them, or everyone. What they may
 * reach is the vault's to say; offboarding and the account page read this.
 * `sessions: false` reads who they are and what they hold alone, their
 * credentials and identities left empty: what a list of grants shows;
 * `standing: false` their sessions alone, their grants and the vault's
 * findings about them left empty: what their sessions' lists show.
 */
export async function members(
  db: Queryable,
  chainKey: Buffer,
  filter: { member?: { type: string; id: string }; sessions?: false; standing?: false },
  now: Date,
): Promise<MemberRow[]> {
  const { principals, credentials, identities } = tablesOf(db);
  const principal = filter.member === undefined ? undefined : principalOf(filter.member);
  const of = (column: typeof principals.principal | typeof credentials.principal | typeof identities.principal) =>
    principal === undefined ? undefined : eq(column, principal);
  // Read binary columns directly. Relational JSON encodes bytea on Postgres
  // and cannot hold blobs on SQLite, so it cannot carry these MACs unchanged.
  const [rows, held, bound, granted, tampered] = await Promise.all([
    db
      .select({
        principal: principals.principal,
        createdAt: principals.createdAt,
        status: principals.status,
        owner: principals.owner,
        role: principals.role,
        scope: principals.scope,
        generation: principals.generation,
        statusChangedAt: principals.statusChangedAt,
        statusChangedBy: principals.statusChangedBy,
      })
      .from(principals)
      .where(of(principals.principal))
      .orderBy(asc(principals.principal)),
    // Live ones only, through `credentials_live_idx`: a CI service leaves an expired one behind each run.
    filter.sessions === false ? [] : db.select().from(credentials).where(and(of(credentials.principal), isNull(credentials.revokedAt), gt(credentials.expiresAt, now))),
    filter.sessions === false ? [] : db.select().from(identities).where(of(identities.principal)),
    filter.standing === false ? [] : readGrants(db, { ...(principal === undefined ? {} : { principal }), liveAt: now.getTime() }),
    filter.standing === false ? new Set<string>() : tamperedMembers(db, principal),
  ]);
  const validIdentities = bound.filter((row) => checkAuthRow(chainKey, 'identities', row));
  const providers = new Map(validIdentities.filter((row) => row.revokedAt === null).map((row) => [row.id, row.provider]));
  // A session is dead too when the account it depends on cannot authenticate.
  const validCredentials = held.filter((row) => checkAuthRow(chainKey, 'credentials', row)
    && (row.identityId === null || providers.has(row.identityId)));
  return rows.map((row) => ({
    ...memberOf(row.principal),
    createdAt: new Date(row.createdAt),
    status: row.status as MemberRow['status'],
    ...storedRole(row),
    generation: row.generation,
    statusChangedAt: new Date(row.statusChangedAt),
    statusChangedBy: row.statusChangedBy,
    grants: granted
      .filter((grant) => grant.principal === row.principal)
      .map(({ projectId, environmentId, role, expiresAt }) => ({ projectId, environmentId, role, expiresAt })),
    tampered: tampered.has(row.principal),
    credentials: validCredentials.filter((credential) => credential.principal === row.principal
      && credential.revokedAt === null && credential.expiresAt > now)
      .map(({ tokenHash: _hash, authMac: _mac, principal: _principal, revokedAt: _at, revokedBy: _by, ...credential }) => ({
        ...credential,
        provider: credential.identityId === null ? null : providers.get(credential.identityId) ?? null,
      })),
    identities: validIdentities.filter((identity) => identity.principal === row.principal
      && identity.revokedAt === null).map((identity) => ({
      id: identity.id,
      provider: identity.provider,
      subject: identity.subject,
      issuerHash: identity.issuerHash,
      generation: identity.generation,
      email: identity.email,
      createdAt: identity.createdAt,
      lastSignInAt: identity.lastSignInAt,
    })),
  }));
}

/**
 * Every allowed read, write and import of a secret by these actors, a read
 * of several once per secret it lists, then every restore, oldest first.
 * Each row that names a secret carries it as it is now: its key, current
 * version, and whether it or its place is archived. Several reads, so the
 * caller runs them in one snapshot (`SNAPSHOT`): a restore committed between
 * two would show its version without the one it restored.
 *
 * With 0.15's log a read is a use (T166), whose version the vault's
 * projection of it says (`readsBy`): each version of each key they read,
 * through a reference its source's, as 0.14's entry named it. A caller that
 * read them already, beside its other reads, passes them: one round trip
 * fewer.
 */
export async function memberActivity(db: Queryable, actorIds: string[], readAlready?: Awaited<ReturnType<typeof readsBy>>) {
  const { auditLog, secrets, environments, projects } = tablesOf(db);
  const allowed = eq(auditLog.decision, 'allow');
  const entries = (where: SQL | undefined) => db
    .select({
      actor: auditLog.actor,
      action: auditLog.action,
      secretId: auditLog.secretId,
      metadata: auditLog.metadata,
      occurredAt: auditLog.occurredAt,
      key: secrets.key,
      currentVersion: secrets.currentVersion,
      archived: truth(sql`${secrets.archivedAt} IS NOT NULL OR ${environments.archivedAt} IS NOT NULL OR ${projects.archivedAt} IS NOT NULL`),
      project: projects.slug,
      environment: environments.slug,
    })
    .from(auditLog)
    .leftJoin(secrets, eq(secrets.id, auditLog.secretId))
    .leftJoin(environments, eq(environments.id, secrets.environmentId))
    .leftJoin(projects, eq(projects.id, secrets.projectId))
    .where(where)
    .orderBy(asc(auditLog.seq));
  // Their reads and writes, and every restore, few, each someone's choice, for whichever secrets were seen: one statement.
  // Beside it, their uses, under 0.15's log.
  const members = actorIds.flatMap((id) => [`user:${id}`, `token:${id}`]);
  // And their key writes 0.15's log records alone (T179, 0.16.0), each a change naming its key and version by id.
  const [logged, used, wrote] = await Promise.all([
    entries(and(allowed, or(and(inArray(auditLog.actor, members), inArray(auditLog.action, ['secret.read', 'secret.write'])), eq(auditLog.action, 'secret.restore')))),
    readAlready ?? readsBy(db, members),
    writtenBy(db, members),
  ]);
  const restores = logged.filter((row) => row.action === 'secret.restore');
  const seen = logged.filter((row) => row.action !== 'secret.restore');
  const listedOf = (row: (typeof seen)[number]) => {
    const { secrets: listed } = JSON.parse(row.metadata) as { secrets?: unknown };
    return row.action !== 'secret.read' || row.secretId !== null || !Array.isArray(listed) ? null : listed as { secretId?: unknown }[];
  };
  const ids = seen.flatMap((row) => (listedOf(row) ?? []).flatMap(({ secretId }) => (typeof secretId === 'string' ? [secretId] : [])));
  const [now, usedRows, wroteRows] = await Promise.all([secretPlaces(db, ids), readsOf(db, used), writesOf(db, wrote)]);
  const rows = seen.flatMap((row) => {
    const listed = listedOf(row);
    if (listed === null) return [row];
    return listed.flatMap((secret) => {
      const found = typeof secret.secretId === 'string' ? now.get(secret.secretId) : undefined;
      if (found === undefined) return [];
      return [{
        ...row,
        secretId: found.id,
        metadata: JSON.stringify(secret),
        key: found.key,
        currentVersion: found.currentVersion,
        archived: found.archivedAt !== null || found.environmentArchivedAt !== null || found.projectArchivedAt !== null,
        project: found.project,
        environment: found.environment,
      }];
    });
  });
  return [...rows, ...usedRows, ...wroteRows, ...restores].map(shown);
}

/**
 * The key writes by these members that 0.15's log records alone (T179, 0.16.0): each change's actor, time, key and
 * version, by id, from its payload. One read of `log_changes_written_actor_idx`, each member's entries.
 */
async function writtenBy(db: Queryable, members: readonly string[]): Promise<{ actor: string; at: number; secret: string; version: string }[]> {
  if (members.length === 0) return [];
  const { logChanges } = tablesOf(db);
  const rows = await db.select({ actor: logChanges.actor, at: logChanges.at, payload: logChanges.payload }).from(logChanges)
    .where(and(recorded(dialect.engineOf(db), logChanges.payload, 'written'), inArray(logChanges.actor, [...members])));
  // Ids of a payload's own, which a database writer may have written anything into: looked up only as ids.
  const id = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
  return rows.flatMap(({ actor, at, payload }) => {
    let parsed: { ref?: { id?: unknown }; version?: unknown };
    try {
      parsed = JSON.parse(payload) as typeof parsed;
    } catch {
      return [];
    }
    const { ref, version } = parsed;
    return id(ref?.id) && id(version) ? [{ actor, at: Number(at), secret: ref.id, version }] : [];
  });
}

/** Their key writes from 0.15's log (`writtenBy`), as `memberActivity` lists writes: each version they wrote, by its number. */
async function writesOf(db: Queryable, wrote: Awaited<ReturnType<typeof writtenBy>>) {
  if (wrote.length === 0) return [];
  const [now, versions] = await Promise.all([secretPlaces(db, wrote.map(({ secret }) => secret)), versionsOf(db, wrote.map(({ version }) => version))]);
  return wrote.flatMap(({ actor, at, secret, version }) => {
    const found = now.get(secret);
    const number = versions.get(version)?.version;
    if (found === undefined || number === undefined) return [];
    return [{
      actor,
      action: 'secret.write',
      secretId: secret,
      metadata: JSON.stringify({ version: number }),
      occurredAt: at,
      key: found.key,
      currentVersion: found.currentVersion,
      archived: found.archivedAt !== null || found.environmentArchivedAt !== null || found.projectArchivedAt !== null,
      project: found.project,
      environment: found.environment,
    }];
  });
}

/** Their reads under 0.15's log (`readsBy`), as `memberActivity` lists reads (above): each version they read. */
async function readsOf(db: Queryable, seen: Awaited<ReturnType<typeof readsBy>>) {
  if (seen.length === 0) return [];
  const now = await secretPlaces(db, seen.map((one) => one.secret));
  return seen.map(({ secret, ...one }) => ({ ...one, secretId: secret })).flatMap(({ actor, at, secretId, version }) => {
    const found = now.get(secretId);
    if (found === undefined) return [];
    return [{
      actor,
      action: 'secret.read',
      secretId,
      metadata: JSON.stringify({ version }),
      occurredAt: at,
      key: found.key,
      currentVersion: found.currentVersion,
      archived: found.archivedAt !== null || found.environmentArchivedAt !== null || found.projectArchivedAt !== null,
      project: found.project,
      environment: found.environment,
    }];
  });
}

/** The person an account at a provider is bound to, if it is. */
export async function findIdentity(
  db: Queryable,
  chainKey: Buffer,
  account: { provider: string; issuerHash: string; subject: string },
) {
  const { identities } = tablesOf(db);
  const rows = await db
    .select()
    .from(identities)
    .where(
      and(eq(identities.provider, account.provider), eq(identities.issuerHash, account.issuerHash), eq(identities.subject, account.subject)),
    );
  for (const row of rows) verifyAuthRow(chainKey, 'identities', row);
  return rows.find((row) => row.revokedAt === null) ?? null;
}

/**
 * A credential by its token's hash or by id, with whether its sign-in
 * account is still bound. Revoked and expired ones too: the caller decides
 * what is live, and the vault whether its principal is still a member.
 *
 * It reads the database clock as well, which keeps it out of Hyperdrive's
 * query cache: Hyperdrive caches no query that calls a stable or volatile
 * function, CURRENT_TIMESTAMP among them. Every request looks its
 * credential up outside a transaction, so on a Hyperdrive config created
 * without `--caching-disabled`, a token revoked or a session signed out
 * would otherwise keep working for up to a minute.
 */
export async function findCredential(
  db: Queryable,
  chainKey: Buffer,
  by: { tokenHash: Buffer } | { id: string },
  /**
   * The row by the token's hash as `app_read` read it already (read-ahead.ts), null for none: checked here as this read's.
   * `'answer'`: read by the token's hash, with what the vault's rows say of its principal, in the same statement (`answerQuery`);
   * `'settings'`, with the instance's settings alone, as they say them.
   */
  ahead?: CredentialRead | null | 'answer' | 'settings',
  /**
   * Whether a check will decide on what stands behind it: false when none will (the policy `off`; a later try's check
   * that it is still the same credential), and then nothing more is read for it (`passkeyOf`'s history) and
   * `passkeyRead` is undefined, as for a row read without it (review r1 of #528).
   */
  checked = true,
) {
  let row: CredentialRead | undefined;
  if ('id' in by) {
    [row] = await credentialById(db, { id: by.id });
  } else if (ahead === 'answer') {
    [row] = await credentialAnswerByHash(db, { tokenHash: by.tokenHash });
  } else if (ahead === 'settings') {
    [row] = await credentialSettingsByHash(db, { tokenHash: by.tokenHash });
  } else if (ahead === undefined) {
    [row] = await credentialByHash(db, { tokenHash: by.tokenHash });
  } else {
    if (ahead !== null && !ahead.credential.tokenHash.equals(by.tokenHash)) throw new Error('the credential read ahead is of another token');
    row = ahead ?? undefined;
  }
  if (row === undefined) return null;
  verifyAuthRow(chainKey, 'credentials', row.credential);
  if (row.identity !== null) verifyAuthRow(chainKey, 'identities', row.identity);
  if (row.credential.identityId !== null && row.identity === null) throw new Error('credential identity is missing');
  const binding = issuingBinding(row.credential.createdBy);
  const stands = binding === null ? null : await standingBinding(db, chainKey, binding, row.credential.principal, row.credential.generation);
  return {
    ...row.credential,
    /** What stands behind it, read with it (`passkeyOf`): undefined when no check asked (`checked`) or the row came from a read that did not (`app_read`, the vault's). */
    passkeyRead: checked ? await passkeyOf(db, chainKey, row.credential, row) : undefined,
    /** For a credential a trust binding issued: whether that binding still stands. Null for any other. */
    bindingStands: binding === null ? null : stands !== null,
    /** Its scope, as stored: its own, or for one a binding issued, the binding's. */
    scope: binding === null ? row.credential.scope : stands?.scope ?? null,
    identityRevokedAt: row.identity?.revokedAt ?? null,
    identityProvider: row.identity?.provider ?? null,
    identityIssuerHash: row.identity?.issuerHash ?? null,
    subject: row.identity?.subject ?? null,
    now: row.now,
    /** The newest `policy.change` there was as the credential was read, by its number: before the vault is asked (`policyStill`). */
    policySeq: row.policySeq === null ? null : BigInt(row.policySeq),
    /** What the vault's rows say of its principal, as `answerQuery` read them, when asked for (`answerOf`). */
    answer: row.answer,
    /** The instance's settings as the vault's rows say them, when asked for alone. */
    settings: row.settings === undefined ? undefined : settingsFrom(row.settings),
  };
}

function credentialRow(db: Queryable, by: (credentials: Tables['credentials']) => SQL, shown: 'answer' | 'settings' | null = null) {
  const { credentials, identities, passkeys } = tablesOf(db);
  // The newest policy change, as `newestPolicySeq` reads it on its own.
  const newestPolicy = sql<string | number | null>`(${newestSeqQuery(db, 'policy.change')})`;
  return db
    .select({
      credential: credentials, identity: identities, now: clock(db), policySeq: newestPolicy,
      // The passkey it names, by its primary key, and whether its person holds a live one (section 6.2 of passkeys.md).
      passkey: passkeys, passkeyHeld: heldSql(sql`${credentials.principal}`, sql`${credentials.generation}`),
      ...(shown === 'answer' ? { answer: sql<unknown>`(${answerQuery(db, sql`${credentials.principal}`)})` } : {}),
      ...(shown === 'settings' ? { settings: sql<string | null>`(${settingsQuery()})` } : {}),
    })
    .from(credentials)
    .leftJoin(identities, eq(identities.id, credentials.identityId))
    .leftJoin(passkeys, eq(passkeys.id, credentials.passkeyId))
    .where(by(credentials));
}

/** What `heldSql` answers: a live passkey at the generation, or only rows that are not (removed, or of another generation); null for none ever. */
const HELD = { live: 2, removed: 1 } as const;

/**
 * Whether a person holds a live passkey at a generation (`HELD.live`), has rows but none live at it (`HELD.removed`:
 * removed, or of another generation), or never had one (null): one probe of `passkeys_live_idx`, which most often finds
 * none, and, finding none, one of `passkeys_principal_idx`, at any generation. Those rows apart, because what reads them
 * as not live holds them to their MACs first (`passkeyOf`): a row whose `removed_at` or `generation` was changed in the
 * database, the MAC left as it was, fails there (review r5 of #500). Written out, not through drizzle's table, so that a
 * statement that also joins `passkeys` (`credentialRow`) keeps the two apart.
 */
function heldSql(principal: SQL, generation: SQL): SQL<number | null> {
  return sql<number | null>`(CASE
    WHEN EXISTS (SELECT 1 FROM passkeys held WHERE held.principal = ${principal} AND held.generation = ${generation} AND held.removed_at IS NULL) THEN ${sql.raw(String(HELD.live))}
    WHEN EXISTS (SELECT 1 FROM passkeys held WHERE held.principal = ${principal}) THEN ${sql.raw(String(HELD.removed))}
  END)`.mapWith(Number);
}

/**
 * What would stand behind a credential an issue makes (passkeys.md, section 6.1), read under the log's head as the
 * request's check reads its own (`credentialRow`): the passkey it would name, by id (its MAC the check's), and whether
 * `principal` holds a live passkey at `generation`. One statement.
 */
export async function passkeyBehind(db: Queryable, chainKey: Buffer, holder: { principal: string; generation: number; passkeyId: string | null }): Promise<PasskeyRead> {
  const { passkeys } = tablesOf(db);
  const [row] = await db
    .select({ passkey: passkeys, passkeyHeld: heldSql(sql`${holder.principal}`, sql`${holder.generation}`), now: clock(db) })
    .from(sql`(SELECT 1) one`)
    .leftJoin(passkeys, holder.passkeyId === null ? sql`1 = 0` : eq(passkeys.id, holder.passkeyId));
  return (await passkeyOf(db, chainKey, holder, row!))!;
}

export type PasskeyRow = Tables['passkeys']['$inferSelect'];

/**
 * What a credential or MCP connection needs behind it (docs/design/passkeys.md, section 6.2), read in the statement that
 * reads it: the passkey it names, null for none; and whether its person holds a live passkey, `'tampered'` when that
 * rests on a removal whose row fails its MAC. Neither is checked against its MAC here but by the check, where its answer
 * depends on it (`passkeyStands`): a credential the check passes over (a service's, a handle, any under `off`) never
 * fails on a passkey it does not need (review r1 of #497).
 */
export type PasskeyRead = { passkey: PasskeyRow | null; held: boolean | 'tampered' };

/**
 * The passkey read with a row (`credentialRow`, `findConnection`), unchecked (`PasskeyRead`); undefined for a row read
 * without it. For what names no passkey, of a person who has passkey rows but none live at its generation: those rows,
 * each held to its MAC, one statement more (`passkeyHistory`), since a removal or a generation forged in the database
 * (`removed_at` set or `generation` moved, the MAC left as it was) would otherwise read as a person holding none, and pass
 * a session made while one was live, under `off` or by the previous release (R64; reviews r3 and r5 of #500). Only then:
 * anyone else's read is the one statement.
 */
async function passkeyOf(
  db: Queryable,
  chainKey: Buffer,
  holder: { principal: string; generation: number; passkeyId: string | null },
  row: { passkey?: PasskeyRow | null; passkeyHeld?: number | null },
): Promise<PasskeyRead | undefined> {
  if (row.passkeyHeld === undefined) return undefined;
  const read = { passkey: row.passkey ?? null, held: row.passkeyHeld === HELD.live };
  if (row.passkeyHeld !== HELD.removed || holder.passkeyId !== null) return read;
  try {
    const { live } = await passkeyHistory(db, chainKey, holder.principal, holder.generation);
    return { ...read, held: live > 0 };
  } catch (error) {
    if (error instanceof AuthRowTampered) return { ...read, held: 'tampered' };
    throw error;
  }
}

// --- passkeys: the ceremonies' reads and writes (docs/design/passkeys.md, sections 3 and 7) --------------------------

/**
 * A person's live passkeys at a generation, oldest first, each its MAC the app's (a row that fails it is reported and
 * passed over, as no passkey): what a ceremony offers (`allowCredentials`) and an add excludes.
 */
export async function livePasskeys(db: Queryable, chainKey: Buffer, principal: string, generation: number): Promise<PasskeyRow[]> {
  const { passkeys } = tablesOf(db);
  const rows = await db.select().from(passkeys)
    .where(and(eq(passkeys.principal, principal), eq(passkeys.generation, generation), isNull(passkeys.removedAt)))
    .orderBy(asc(passkeys.createdAt));
  return rows.filter((row) => checkAuthRow(chainKey, 'passkeys', row));
}

/**
 * Every passkey row a person has had, at any generation, removed ones included, each held to its MAC (a row that fails
 * it throws, `verifyAuthRow`): how many there are, an enrollment's `passkeysEver` (section 3.2; rows are never deleted,
 * so every add moves it for good, and a sealed state that names the old count enrolls nothing again), and how many are
 * live at `generation`. Read under the head by what decides on a person holding none: their first passkey, and a sign-in
 * the provider alone answers. It reads the rows rather than count them for their MACs: a removal forged in the database
 * (`removed_at` set, the MAC left as it was) refuses, where a count read it as no passkey and let another be the first
 * (R64; review r2 of #500). By `passkeys_principal_idx`.
 */
export async function passkeyHistory(db: Queryable, chainKey: Buffer, principal: string, generation: number): Promise<{ ever: number; live: number }> {
  const { passkeys } = tablesOf(db);
  const rows = await db.select().from(passkeys).where(eq(passkeys.principal, principal));
  for (const row of rows) verifyAuthRow(chainKey, 'passkeys', row);
  return { ever: rows.length, live: rows.filter((row) => row.generation === generation && row.removedAt === null).length };
}

/** A member as a sign-in's callback weighs them (`signinMembers`). */
export type SigninMember = { principal: string; status: string; generation: number; accessSeq: bigint; ever: number; live: number };

/**
 * What a sign-in's callback decides on (passkeys.md, section 3.1), beside the identity it reads in the same round trip
 * (`findIdentity`): the members its account may be, the one its live identity names and one per verified email, each
 * with its status and generation, the vault's newest entry about its access (`access_seq`, which the sign-in's
 * transaction holds it to under the head, as `issuerStill` does), and its passkeys, ever and live at that generation.
 * One statement, with the database clock, so that Hyperdrive never answers it from its cache: a cached sequence
 * would read as moved under the head on every try. Rows of the vault's, unchecked: what they decide is only whether to
 * ask for a passkey first, and the sign-in checks the vault's own answer before it issues anything.
 */
export async function signinMembers(
  db: Queryable,
  account: { provider: string; issuerHash: string; subject: string },
  emails: readonly string[],
): Promise<Map<string, SigninMember>> {
  const { principals, identities } = tablesOf(db);
  const bound = db
    .select({ principal: identities.principal })
    .from(identities)
    .where(and(eq(identities.provider, account.provider), eq(identities.issuerHash, account.issuerHash), eq(identities.subject, account.subject), isNull(identities.revokedAt)));
  const candidates = emails.map((email) => `user:${email}`);
  const rows = await db
    .select({
      principal: principals.principal,
      status: principals.status,
      generation: principals.generation,
      accessSeq: principals.accessSeq,
      // Named in full: drizzle writes a column of the one table it selects from unqualified, which the subquery would read as its own.
      ever: sql<number>`(SELECT count(*) FROM passkeys ever WHERE ever.principal = principals.principal)`,
      live: sql<number>`(SELECT count(*) FROM passkeys live WHERE live.principal = principals.principal AND live.generation = principals.generation AND live.removed_at IS NULL)`,
      now: clock(db),
    })
    .from(principals)
    .where(candidates.length === 0 ? inArray(principals.principal, bound) : or(inArray(principals.principal, candidates), inArray(principals.principal, bound)));
  return new Map(rows.map(({ now: _, ever, live, ...row }) => [row.principal, { ...row, ever: Number(ever), live: Number(live) }]));
}

/** Whether a passkey row, anyone's, live or not, has this credential ID: what a first passkey's unique violation was. */
export async function passkeyCredentialTaken(db: Queryable, credentialId: Buffer): Promise<boolean> {
  const { passkeys } = tablesOf(db);
  const rows = await db.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.credentialId, credentialId)).limit(1);
  return rows.length > 0;
}

/** The passkey a response's credential ID names, whoever's, live or not; null for none. Its MAC is checked: a row that fails it throws (`verifyAuthRow`). */
export async function passkeyByCredentialId(db: Queryable, chainKey: Buffer, credentialId: Buffer): Promise<PasskeyRow | null> {
  const { passkeys } = tablesOf(db);
  const [row] = await db.select().from(passkeys).where(eq(passkeys.credentialId, credentialId)).limit(1);
  if (row === undefined) return null;
  verifyAuthRow(chainKey, 'passkeys', row);
  return row;
}

/**
 * An assertion taken (section 7.3): its passkey's replay mark and counter moved forward, in one statement, inside the
 * transaction that makes what the touch is for. 0 when it did not move: replayed, overtaken by a newer challenge, a
 * counter that did not move, or a passkey removed, or no longer the person's at that generation, meanwhile.
 */
export async function touchPasskey(
  tx: Queryable,
  touch: { id: string; principal: string; generation: number; issuedAt: Date; signCount: number },
): Promise<number> {
  const { passkeys } = tablesOf(tx);
  return changedRows(
    await tx
      .update(passkeys)
      .set({ lastChallengeAt: touch.issuedAt, signCount: touch.signCount, lastUsedAt: new Date() })
      .where(and(
        eq(passkeys.id, touch.id),
        eq(passkeys.principal, touch.principal),
        eq(passkeys.generation, touch.generation),
        isNull(passkeys.removedAt),
        or(isNull(passkeys.lastChallengeAt), lt(passkeys.lastChallengeAt, touch.issuedAt)),
        // A counter that moves, or one that never does: synced passkeys keep 0.
        touch.signCount === 0 ? eq(passkeys.signCount, 0) : lt(passkeys.signCount, touch.signCount),
      )),
  );
}

/** A passkey added, signed as the app signs one (section 5.1). */
export async function insertPasskey(
  tx: Queryable,
  chainKey: Buffer,
  row: Omit<NewRow<Tables['passkeys']>, 'authMac'> & {
    id: string; principal: string; generation: number; userHandle: Buffer; credentialId: Buffer; publicKey: Buffer; algorithm: number;
  },
): Promise<void> {
  const signed = { ...row, removedAt: null };
  await insert(tx, tablesOf(tx).passkeys, { ...signed, authMac: authMac(chainKey, 'passkeys', signed) });
}

/**
 * The person's factor lock (section 6.1), which every change to their passkeys takes first, before the log's head, and
 * the vault's issue of their tokens takes too (migration 0064): `pg_advisory_xact_lock(1717658484, hashtext(<principal>))`,
 * started now, not once awaited, so that it goes ahead of the head in the transaction's first Sync. SQLite's one writer
 * is the lock.
 */
export function lockFactor(tx: Transaction, principal: string): Promise<unknown> {
  if (dialect.engineOf(tx) !== 'postgres') return Promise.resolve();
  return dialect.rowsNow(tx, sql`SELECT pg_advisory_xact_lock(1717658484, hashtext(${principal}))::text AS locked`);
}

/**
 * A person's approved device codes that no CLI has redeemed yet: what a change to their passkeys denies (section 6.1),
 * each a compare-and-set on its MAC, and a denial names nobody and no passkey (`device_logins_approval_names_principal`,
 * `device_logins_passkey_check`).
 * `unbacked`: only those that name no passkey, a first passkey's; otherwise all of them, a removal's and a reset's.
 * The ids it denied.
 */
export async function denyApprovals(tx: Queryable, chainKey: Buffer, principal: string, at: Date, which: { unbacked: boolean }): Promise<string[]> {
  const { deviceLogins } = tablesOf(tx);
  const rows = await tx.select().from(deviceLogins).where(and(
    eq(deviceLogins.principal, principal),
    eq(deviceLogins.decision, 'approved'),
    isNull(deviceLogins.consumedAt),
    which.unbacked ? isNull(deviceLogins.passkeyId) : undefined,
    gt(deviceLogins.expiresAt, at),
  ));
  // A denial names no passkey either (`device_logins_passkey_check`; review r1 of #529): the touch that approved
  // it no longer stands. Each its own compare-and-set, asked together: one round trip for them all.
  const decided = await Promise.all(rows.filter((row) => checkAuthRow(chainKey, 'device_authorizations', row)).map(async (row) => {
    const moved = await updateAuth(tx, chainKey, deviceLogins, { id: row.id, authMac: row.authMac }, { decision: 'denied', decidedAt: at, principal: null, generation: 0, passkeyId: null });
    return moved > 0 ? row.id : null;
  }));
  return decided.filter((id) => id !== null);
}

/**
 * A live passkey removed (sections 3.6 and 3.7): its removal and who made it, signed again, since the MAC covers
 * `removed_at`; a compare-and-set on the MAC read, so a row changed since is no row to remove. 1 if it moved, 0 if not.
 */
export async function removePasskeyRow(tx: Queryable, chainKey: Buffer, row: PasskeyRow, by: { removedAt: Date; removedBy: string }): Promise<number> {
  const { passkeys } = tablesOf(tx);
  const signed = { ...row, removedAt: by.removedAt };
  return changedRows(
    await tx
      .update(passkeys)
      .set({ ...by, authMac: authMac(chainKey, 'passkeys', signed) })
      .where(and(eq(passkeys.id, row.id), eq(passkeys.authMac, row.authMac), isNull(passkeys.removedAt))),
  );
}

/** A live passkey of the person's renamed (section 3.6): its name is outside the MAC, so nothing is signed again. 1 if it moved, 0 if not. */
export async function renamePasskeyRow(tx: Queryable, passkey: { id: string; principal: string; generation: number }, name: string): Promise<number> {
  const { passkeys } = tablesOf(tx);
  return changedRows(
    await tx
      .update(passkeys)
      .set({ name })
      .where(and(eq(passkeys.id, passkey.id), eq(passkeys.principal, passkey.principal), eq(passkeys.generation, passkey.generation), isNull(passkeys.removedAt))),
  );
}

/**
 * Every passkey row a person has had, at any generation, removed ones included, oldest first, each held to its MAC (a
 * row that fails it throws, `verifyAuthRow`): what a removal, a reset or another passkey's add decides on, read under
 * the person's factor lock, and what their Passkeys tab lists. By `passkeys_principal_idx`.
 */
export async function passkeysOf(db: Queryable, chainKey: Buffer, principal: string): Promise<PasskeyRow[]> {
  const { passkeys } = tablesOf(db);
  const rows = await db.select().from(passkeys).where(eq(passkeys.principal, principal)).orderBy(asc(passkeys.createdAt));
  for (const row of rows) verifyAuthRow(chainKey, 'passkeys', row);
  return rows;
}

/** A credential as `findCredential` reads it: its row, its sign-in account's, the database's clock, and the newest policy change. */
export type CredentialRead = {
  credential: Tables['credentials']['$inferSelect'];
  identity: Tables['identities']['$inferSelect'] | null;
  now: string;
  policySeq: string | number | null;
  answer?: unknown;
  settings?: string | null;
  /**
   * The passkey it names and whether its person holds one (`HELD`), when the read had them: `credentialRow`'s, and the
   * vault's named call's, key write's and add's (T216, migration 0073); not `app_read`'s.
   */
  passkey?: PasskeyRow | null;
  passkeyHeld?: number | null;
};

// Every request's credential, by its token's hash: built once (`prepared`).
const credentialByHash = prepared((db) => credentialRow(db, (credentials) => eq(credentials.tokenHash, sql.placeholder('tokenHash'))));
const credentialById = prepared((db) => credentialRow(db, (credentials) => eq(credentials.id, sql.placeholder('id'))));
// A request's that only shows its caller, with what the vault's rows say of them (`answerShown`).
const credentialAnswerByHash = prepared((db) => credentialRow(db, (credentials) => eq(credentials.tokenHash, sql.placeholder('tokenHash')), 'answer'));
// A page render's, whose `me` shows the instance's settings beside the vault's answer.
const credentialSettingsByHash = prepared((db) => credentialRow(db, (credentials) => eq(credentials.tokenHash, sql.placeholder('tokenHash')), 'settings'));

// --- trust bindings -----------------------------------------------------------

export type BindingRow = Tables['serviceBindings']['$inferSelect'];

/**
 * A service's live bindings, oldest first: made in its current generation,
 * its row not revoked, its MAC the app's, and no tombstone. A row that fails
 * its MAC is reported and passed over; a row put back after its binding was
 * removed is passed over by its tombstone, whatever the row says. A removal
 * moves the generation past every binding at once.
 */
export async function liveBindings(db: Queryable, chainKey: Buffer, principal: string, generation: number): Promise<BindingRow[]> {
  return (await bindingsNow(db, chainKey, principal, generation)).live;
}

/**
 * A service's bindings at a generation, from one read: every row not
 * revoked (`unrevoked`), and those of them live (`liveBindings`: its MAC
 * the app's, no tombstone). With 0.15's log the vault's change of them
 * holds the first set to the rows (PR 3a): the MAC and the tombstone are
 * the app's concerns, and a row that fails them is still a row there,
 * which would otherwise refuse every change of the account's bindings.
 */
export async function bindingsNow(db: Queryable, chainKey: Buffer, principal: string, generation: number): Promise<{ live: BindingRow[]; unrevoked: BindingRow[] }> {
  const { serviceBindings } = tablesOf(db);
  const rows = await db
    .select()
    .from(serviceBindings)
    .where(and(eq(serviceBindings.principal, principal), eq(serviceBindings.generation, generation), isNull(serviceBindings.revokedAt)))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id));
  const genuine = rows.filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
  const dead = await tombstoned(db, genuine.map((row) => row.id));
  return { live: genuine.filter((row) => !dead.has(row.id)), unrevoked: rows };
}

/** A binding of `principal`'s by id, as its row is, MAC or not: what the vault ends, whose seal it checks itself (PR 3a). */
export async function bindingRow(db: Queryable, principal: string, id: string): Promise<BindingRow | null> {
  const { serviceBindings } = tablesOf(db);
  const [row] = await db.select().from(serviceBindings).where(and(eq(serviceBindings.id, id), eq(serviceBindings.principal, principal)));
  return row ?? null;
}

/**
 * Every credential these bindings issued that is neither revoked nor past
 * its end at `at`, as the rows are, MAC or not: what the vault's end of the
 * bindings must name, every one, to end them (PR 3a). A row whose MAC fails
 * is dead to the app's checks, and still one the statement counts. For a
 * vault older than the batches (`about().sweeps`), which ends a binding in
 * one call; the batches read `issuedSoonest`, then `credentialRows`.
 */
/**
 * Live at `at`: on Postgres, at the database's own clock as this statement starts (`now()`, stable, so that it still bounds
 * the index's range), never the app's: the end's check names every credential live on that clock a moment later
 * (`change_bindings`' `clock_timestamp()`), and an app clock ahead of it would leave some out, each end `moved` (Fable on
 * #520). On SQLite the app and the vault share the process's clock.
 */
function liveAt(db: Queryable, at: Date): SQL | Date {
  return dialect.engineOf(db) === 'postgres' ? sql`now()` : at;
}

export async function issuedCredentials(db: Queryable, principal: string, bindingIds: readonly string[], at: Date): Promise<CredentialRow[]> {
  const { credentials } = tablesOf(db);
  if (bindingIds.length === 0) return [];
  return db.select().from(credentials)
    .where(and(eq(credentials.principal, principal), inArray(credentials.createdBy, bindingIds.map((id) => `binding:${id}`)), isNull(credentials.revokedAt), gt(credentials.expiresAt, liveAt(db, at))));
}

/**
 * The first `atMost` of those (`issuedCredentials`), soonest to end first,
 * by id and the bytes of what they carry of any length (their scope and
 * places), not the rows (W331, review r5): a removal's batch is chosen from
 * this, and only its rows are read whole, so what an isolate holds is one
 * batch's, however wide their scopes. Through `credentials_live_idx`, in its
 * order: a credential a sweep revoked leaves that partial index, so the next
 * batch's read starts past the last's, and none walks the binding's history.
 */
export async function issuedSoonest(
  db: Queryable, principal: string, bindingIds: readonly string[], at: Date, atMost: number, after: Date | null,
): Promise<{ id: string; bytes: number; expiresAt: Date }[]> {
  const { credentials } = tablesOf(db);
  if (bindingIds.length === 0) return [];
  const length = (column: AnyColumn) => (dialect.engineOf(db) === 'postgres' ? sql`coalesce(octet_length(${column}), 0)` : sql`coalesce(length(CAST(${column} AS BLOB)), 0)`);
  return db.select({ id: credentials.id, bytes: sql<number | string>`${length(credentials.scope)} + ${length(credentials.places)}`.mapWith(Number), expiresAt: credentials.expiresAt })
    .from(credentials)
    .where(and(
      eq(credentials.principal, principal), inArray(credentials.createdBy, bindingIds.map((id) => `binding:${id}`)), isNull(credentials.revokedAt), gt(credentials.expiresAt, liveAt(db, at)),
      // From the last batch's end (review r6): the index's range starts there, so another binding's credentials that
      // end sooner are walked once a removal, not once a batch. The batch itself, revoked, has left the index; an `id`
      // tie-break here would cost the ordered scan its limit (a bitmap scan of all that follow, sorted). One of these
      // bindings' ending sooner, made since, is the end's: it reads from the start.
      ...(after === null ? [] : [gte(credentials.expiresAt, after)]),
    ))
    .orderBy(asc(credentials.expiresAt), asc(credentials.id))
    .limit(atMost);
}

/** How many credentials these bindings issued are still live at `at` (`issuedCredentials`): what a removal under way has left. */
export async function liveIssued(db: Queryable, principal: string, bindingIds: readonly string[], at: Date): Promise<number> {
  const { credentials } = tablesOf(db);
  if (bindingIds.length === 0) return 0;
  const [row] = await db.select({ n: count() }).from(credentials)
    .where(and(eq(credentials.principal, principal), inArray(credentials.createdBy, bindingIds.map((id) => `binding:${id}`)), isNull(credentials.revokedAt), gt(credentials.expiresAt, liveAt(db, at))));
  return Number(row?.n ?? 0);
}

/**
 * Whether the app's log holds a binding's tombstone, its `token.unbind`: what the app trusts of an end, as it does when
 * it reads a binding (`standingBinding`). Written once the vault's end was answered, which waits for its seal.
 */
export async function bindingTombstoned(db: Queryable, bindingId: string): Promise<boolean> {
  const [row] = await db.select({ tombstoned: truth(hasTombstone(db, bindingId)) }).from(sql`(SELECT 1) AS one`);
  return row?.tombstoned === true;
}

/**
 * Every binding a removal closed and did not end (W331): what the scheduled run goes on with (`resumeRemovals`). Its
 * row as it is, MAC or not, as a removal's end names the rows it ends whatever their MAC (Fable on PR 3a).
 */
export async function closedBindings(db: Queryable, _chainKey: Buffer): Promise<BindingRow[]> {
  const { serviceBindings } = tablesOf(db);
  return db.select().from(serviceBindings).where(and(isNotNull(serviceBindings.closedAt), isNull(serviceBindings.revokedAt))).orderBy(asc(serviceBindings.closedAt));
}

/** These credentials' rows, as they are, MAC or not: a removal's batch, read whole once chosen (`issuedSoonest`). */
export async function credentialRows(db: Queryable, ids: readonly string[]): Promise<CredentialRow[]> {
  const { credentials } = tablesOf(db);
  return ids.length === 0 ? [] : db.select().from(credentials).where(inArray(credentials.id, [...ids]));
}

/**
 * One binding of `principal`'s, by ID: revoked or not, tombstoned or not.
 * Null for none, or for a row that fails its MAC, which is reported.
 */
export async function findBinding(db: Queryable, chainKey: Buffer, principal: string, id: string): Promise<BindingRow | null> {
  const { serviceBindings } = tablesOf(db);
  const [row] = await db
    .select()
    .from(serviceBindings)
    .where(and(eq(serviceBindings.id, id), eq(serviceBindings.principal, principal)));
  return row !== undefined && checkAuthRow(chainKey, 'service_bindings', row) ? row : null;
}

/**
 * Which of these bindings have a tombstone: an app entry `token.unbind`,
 * allowed, naming the binding's ID. A denied attempt is logged under the
 * same action and never counts. Every such entry counts, never only the
 * latest; their MACs are not checked, since a forged tombstone can only
 * refuse. One read through `audit_log_unbind_idx`, whose expression this
 * repeats.
 */
export async function tombstoned(db: Queryable, ids: readonly string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const { auditLog } = tablesOf(db);
  const bindingId = dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'bindingId')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.bindingId')`;
  const rows = await db
    .select({ id: bindingId })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, 'token.unbind'), eq(auditLog.decision, 'allow'), inArray(bindingId, [...ids])));
  return new Set(rows.map((row) => row.id));
}

/** The expression `audit_log_unbind_idx` indexes: the binding an entry names. */
function namedBinding(db: Queryable): SQL<string> {
  const { auditLog } = tablesOf(db);
  return dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'bindingId')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.bindingId')`;
}

/** Whether the binding `id` (a column or a value) has a tombstone: an allowed app `token.unbind` naming it. */
export function hasTombstone(db: Queryable, id: SQL | string): SQL {
  const { auditLog } = tablesOf(db);
  return sql`EXISTS (SELECT 1 FROM ${auditLog} WHERE ${auditLog.author} = 'app' AND ${auditLog.action} = 'token.unbind'
    AND ${auditLog.decision} = 'allow' AND ${namedBinding(db)} = ${id})`;
}

/**
 * What an exchange may match, in one read: the service's live bindings on
 * this issuer, in its current generation as its member row says, with no
 * tombstone, each MAC-checked. Only those it may issue a bearer credential
 * for, too: of `BEARER_PROFILES`, with no policy. A binding made for a
 * key-bound session never buys one here, whatever token is presented
 * (docs/design/workload-access.md, section 4.1). A service holds at most
 * `MAX_BINDINGS`, made so under the log's head; more than that here is a
 * database changed around the app, and matches nothing.
 *
 * With them, so that a token one may take costs no read of its own: whether
 * the token, by its signing input's hash, was exchanged already, and the
 * newest `policy.change`, read before the vault is asked about the
 * service; and the account's and each binding's newest change, which the
 * vault checks and pins in its one statement (T192, `NewestChanges`).
 * Uncached, as `tokenConsumed` is. With no candidate, none is read: the
 * token is refused.
 */
export async function exchangeCandidates(
  db: Queryable,
  chainKey: Buffer,
  principal: string,
  issuer: string,
  max: number,
  token: Buffer,
): Promise<{ bindings: BindingRow[]; spent: boolean | null; policySeq: bigint | null; newest: NewestChanges }> {
  const { spentIdTokens, serviceBindings, principals } = tablesOf(db);
  const id = dialect.engineOf(db) === 'postgres' ? sql`${serviceBindings.id}::text` : sql`${serviceBindings.id}`;
  const spent = db.select({ hash: spentIdTokens.hash }).from(spentIdTokens).where(eq(spentIdTokens.hash, token));
  const rows = await db
    .select({
      binding: serviceBindings,
      spent: truth(exists(spent)),
      policySeq: sql<string | number | null>`(${newestSeqQuery(db, 'policy.change')})`,
      ...newestChangeColumns(db, principal, serviceBindings.id),
      now: clock(db),
    })
    .from(serviceBindings)
    .innerJoin(principals, and(eq(principals.principal, serviceBindings.principal), eq(principals.generation, serviceBindings.generation)))
    .where(and(
      eq(serviceBindings.principal, principal),
      eq(serviceBindings.issuer, issuer),
      isNull(serviceBindings.revokedAt),
      // Closed by a removal under way (W331): it signs nobody in, so it shadows no binding that would (review r6).
      isNull(serviceBindings.closedAt),
      isNull(serviceBindings.policy),
      inArray(serviceBindings.profile, [...BEARER_PROFILES]),
      sql`NOT ${hasTombstone(db, id)}`,
    ))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id))
    .limit(max + 1);
  if (rows.length > max) {
    console.error({ event: 'bindings_over_limit', principal, issuer }, 'a service holds more bindings than any can');
    return { bindings: [], spent: null, policySeq: null, newest: NO_CHANGES };
  }
  const seq = rows[0]?.policySeq ?? null;
  const bindings = rows.map((row) => row.binding).filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
  return {
    bindings,
    // Null where nothing was read: no binding, so no row to read it with.
    spent: rows[0]?.spent ?? null,
    policySeq: seq === null ? null : BigInt(seq),
    newest: await newestChanges(db, principal, rows),
  };
}

/**
 * The account's newest change in 0.15's log and each read binding's, by the
 * binding's id, for the vault to check and pin (T192, `SignInInput.newest`):
 * every column their MAC covers but their object, which the vault derives.
 * None where the log holds no change of it.
 */
export type NewestChanges = { member: LoggedChange | null; bindings: ReadonlyMap<string, LoggedChange | null> };

const NO_CHANGES: NewestChanges = { member: null, bindings: new Map() };

/**
 * `newestChanges`' columns, on Postgres: in the statement that reads the
 * bindings, one probe of `log_changes_object_idx` each, the account's an
 * uncorrelated subquery, read once. As text, a JSON array in `loggedChange`'s
 * order. SQLite has no `log_object`: none here, read after (`newestChanges`).
 */
export function newestChangeColumns(db: Queryable, principal: string, binding: AnyColumn): { memberChange?: SQL<string | null>; bindingChange?: SQL<string | null> } {
  if (dialect.engineOf(db) !== 'postgres') return {};
  const newest = (object: SQL) => sql<string | null>`(SELECT json_build_array(c.number::text, c.at, c.request_id, c.actor, c.payload, encode(c.seal, 'base64'), encode(c.mac, 'base64'))::text
    FROM log_changes c WHERE c.object = ${object} ORDER BY c.number DESC LIMIT 1)`;
  return { memberChange: newest(sql`${logObject('principal', principal)}::uuid`), bindingChange: newest(sql`log_object('binding', ${binding}::text)`) };
}

/**
 * `NewestChanges` of the rows a bindings read answered with
 * `newestChangeColumns`; on SQLite, read now by their objects' keys, a
 * statement of their own (SQLite deploys no app: its cost is no sign-in's).
 */
export async function newestChanges(db: Queryable, principal: string, rows: readonly { binding: { id: string }; memberChange?: string | null; bindingChange?: string | null }[]): Promise<NewestChanges> {
  if (rows.length === 0) return NO_CHANGES;
  if (dialect.engineOf(db) === 'postgres') {
    return { member: loggedChange(rows[0]!.memberChange ?? null), bindings: new Map(rows.map((row) => [row.binding.id, loggedChange(row.bindingChange ?? null)])) };
  }
  const { logChanges } = tablesOf(db);
  const read = async (object: string): Promise<LoggedChange | null> => {
    const [row] = await db.select().from(logChanges).where(eq(logChanges.object, object)).orderBy(desc(logChanges.number)).limit(1);
    if (row === undefined) return null;
    const base64 = (bytes: Uint8Array | null) => (bytes === null ? null : Buffer.from(bytes).toString('base64'));
    return { number: String(row.number), at: Number(row.at), requestId: row.requestId, actor: row.actor, payload: row.payload, seal: base64(row.seal ?? null), mac: base64(row.mac)! };
  };
  const [member, ...bindings] = await Promise.all([read(logObject('principal', principal)), ...rows.map((row) => read(logObject('binding', row.binding.id)))]);
  return { member: member!, bindings: new Map(rows.map((row, i) => [row.binding.id, bindings[i]!])) };
}

/** A change as `newestChangeColumns` renders it, or none. */
function loggedChange(text: string | null): LoggedChange | null {
  if (text === null) return null;
  const [number, at, requestId, actor, payload, seal, mac] = JSON.parse(text) as [string, number, string, string, string, string | null, string];
  return { number, at, requestId, actor, payload, seal, mac };
}

/**
 * A credential's binding, if it still stands: its row the app's, not
 * revoked, no tombstone, of the same member and generation; null if not. It reads the
 * database clock, as `findCredential` does, so that Hyperdrive never
 * answers it from its cache: a cached "no tombstone" would let a credential
 * whose rows were put back after its binding was removed sign in again. A
 * query of its own, not a join in `findCredential`: only a credential a
 * binding issued asks it, and the exchange asks it under its transaction.
 */
export async function standingBinding(db: Queryable, chainKey: Buffer, bindingId: string, principal: string, generation: number): Promise<BindingRow | null> {
  const { serviceBindings } = tablesOf(db);
  const [row] = await db
    .select({ binding: serviceBindings, tombstoned: truth(hasTombstone(db, bindingId)), now: clock(db) })
    .from(serviceBindings)
    .where(eq(serviceBindings.id, bindingId));
  return row !== undefined && bindingStands(chainKey, row, principal, generation) ? row.binding : null;
}

/**
 * Whether a binding's row, read with its tombstone, still stands for `principal` in `generation` (`standingBinding`).
 * One a removal closed still does, for the credentials it exchanged (W331): a use by name asks the vault before this is
 * read, and the vault refuses first whatever the app would (named-use.ts), so a check here alone would tell a caller
 * what the vault looked up (review r8). They end at their batch, or at their own end, five minutes after their sign-in
 * at most (`EXCHANGED_CREDENTIAL_MS`), whichever comes first. A session of it, which lives hours, the app refuses first
 * (`sessionRowsFor`).
 */
function bindingStands(chainKey: Buffer, row: { binding: BindingRow; tombstoned: boolean }, principal: string, generation: number): boolean {
  return !row.tombstoned && row.binding.revokedAt === null
    && row.binding.principal === principal && row.binding.generation === generation
    && checkAuthRow(chainKey, 'service_bindings', row.binding);
}

/**
 * What an exchange checks again under the log's head, in one read: that
 * its member is still active in `generation` (`memberStanding`), and that
 * its binding still stands (`standingBinding`).
 */
export async function exchangeStill(
  db: Queryable,
  chainKey: Buffer,
  binding: { id: string; principal: string; generation: number },
): Promise<{ stands: boolean; scope: string | null }> {
  const { serviceBindings, principals } = tablesOf(db);
  const [row] = await db
    .select({
      binding: serviceBindings,
      tombstoned: truth(hasTombstone(db, binding.id)),
      status: principals.status,
      generation: principals.generation,
      now: clock(db),
    })
    .from(serviceBindings)
    .leftJoin(principals, eq(principals.principal, binding.principal))
    .where(eq(serviceBindings.id, binding.id));
  if (row === undefined) return { stands: false, scope: null };
  const member = row.status === 'active' && row.generation === binding.generation;
  return { stands: member && bindingStands(chainKey, row, binding.principal, binding.generation), scope: row.binding.scope };
}

/**
 * How a credential came to be, for the entries written on it: through a
 * trust binding, the sign-in, its place in its log and the run its issuer
 * asserted; or, a personal token, its label, as its issue recorded it.
 * Each with the account it acts as, as that record names it: what a use
 * through it is shown by when its row says nothing (T166).
 */
export type CredentialOrigin =
  | { kind: 'signIn'; seq: bigint; log: '0.14' | '0.15'; run: Record<string, unknown>; principal: string }
  | { kind: 'personal'; label: string; principal: string | null };

/**
 * How these credentials came to be, by credential ID (`CredentialOrigin`),
 * where the log says. 0.14's `token.exchange` and `token.create` entries,
 * through `audit_log_exchange_idx` and `audit_log_token_create_idx`, whose
 * expressions this repeats; or, with 0.15's log, the credential's sign-in
 * or issue change (D147). Either makes its credential, so it is the
 * object's first change: one probe of `log_changes_object_idx` each,
 * however many renewals and revokes came after (R48). One statement.
 */
export async function originsOf(db: Queryable, credentialIds: readonly string[]): Promise<Map<string, CredentialOrigin>> {
  if (credentialIds.length === 0) return new Map();
  const { auditLog, logChanges } = tablesOf(db);
  const engine = dialect.engineOf(db);
  const metadata = (field: string) => engine === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> ${sql.raw(`'${field}'`)})`
    : sql<string>`json_extract(${auditLog.metadata}, ${sql.raw(`'$.${field}'`)})`;
  const entries = (action: 'token.exchange' | 'token.create', id: SQL<string>) => sql`
    SELECT ${id} AS credential, ${auditLog.seq} AS seq, ${auditLog.metadata} AS record, '0.14' AS log, ${sql.raw(`'${action}'`)} AS action, ${auditLog.actor} AS actor FROM ${auditLog}
     WHERE ${and(eq(auditLog.author, 'app'), eq(auditLog.action, action), eq(auditLog.decision, 'allow'), inArray(id, [...credentialIds]))}`;
  const objects = new Map(credentialIds.map((id) => [logObject('credential', id), id]));
  // A plain read, `SELECT …`, which a page's other reads may go with (`groupReads`).
  const rows = await dialect.rowsOf<{ credential: string; seq: string | number | bigint; record: string; log: '0.14' | '0.15'; action: string | null; actor: string }>(db, sql`
    ${entries('token.exchange', metadata('credentialId'))}
    UNION ALL
    ${entries('token.create', metadata('targetCredentialId'))}
    UNION ALL
    SELECT ${engine === 'postgres' ? sql`CAST(${logChanges.object} AS text)` : logChanges.object}, ${logChanges.number}, ${logChanges.payload}, '0.15', NULL, ${logChanges.actor} FROM ${logChanges}
     WHERE ${logChanges.number} IN (${sql.join([...objects.keys()].map((object) => sql`(SELECT min(${logChanges.number}) FROM ${logChanges} WHERE ${logChanges.object} = ${object})`), sql`, `)})
       AND ${recorded(engine, logChanges.payload, 'signIn', 'issue')}`);
  return new Map(rows.flatMap((row): [string, CredentialOrigin][] => {
    const id = row.log === '0.14' ? row.credential : objects.get(row.credential);
    if (id === undefined) return [];
    const record = JSON.parse(row.record) as { run?: unknown; kind?: unknown; label?: unknown; principal?: unknown; signIn?: { run?: unknown }; issue?: { kind?: unknown; label?: unknown } };
    const signIn = row.log === '0.14' ? (row.action === 'token.exchange' ? record : undefined) : record.signIn;
    if (signIn !== undefined) {
      const { run } = signIn;
      // A sign-in is its service's: 0.14's entry and 0.15's change both name it as their actor.
      return [[id, { kind: 'signIn', seq: BigInt(row.seq), log: row.log, run: typeof run === 'object' && run !== null ? (run as Record<string, unknown>) : {}, principal: row.actor }]];
    }
    const { kind, label } = (row.log === '0.14' ? record : record.issue) ?? {};
    // A personal token is its person's, who made it: 0.15's issue names the account, 0.14's entry its actor.
    const principal = row.log === '0.15' ? (typeof record.principal === 'string' ? record.principal : null) : row.actor;
    return kind === 'personal' && typeof label === 'string' ? [[id, { kind: 'personal', label, principal }]] : [];
  }));
}

/**
 * A change of 0.15's log that records what 0.14 logged as an entry, which
 * 0.15 writes none of (D147): a sign-in through a trust binding (T156); a
 * token the vault issued; a credential it revoked by request, or that signed
 * itself out (T164). Its row: the payload names the object, and holds its
 * record (`RECORDS`).
 */
export type RecordedChange = {
  number: bigint;
  /** Milliseconds since the epoch, the vault's clock. */
  at: number;
  actor: string;
  payload: string;
  /** The rest of what its MAC covers, for the vault to vouch for it (T166). */
  requestId: string;
  object: string;
  seal: Buffer | null;
  mac: Buffer;
};

/**
 * Where a page of those changes goes on from, below: a change, by its `at`,
 * then its number, as they are listed; or a time alone, without a number,
 * every change asked at it or before.
 */
export type ChangePoint = { at: number; number?: bigint };

/** The changes below `point`, as `ChangePoint` says. */
function below(db: Queryable, point: ChangePoint): SQL {
  const { logChanges } = tablesOf(db);
  return point.number === undefined
    ? sql`${logChanges.at} <= ${point.at}`
    : sql`(${logChanges.at}, ${logChanges.number}) < (${point.at}, ${point.number})`;
}

/** The changes at `point` or above it: none of those below it. */
function notBelow(db: Queryable, point: ChangePoint): SQL {
  const { logChanges } = tablesOf(db);
  return point.number === undefined
    ? sql`${logChanges.at} > ${point.at}`
    : sql`(${logChanges.at}, ${logChanges.number}) >= (${point.at}, ${point.number})`;
}

/** Whether an actor's name is a member's, a person's (`user:`) or a service's (`token:`), whom 0.15's records name. */
export function isMember(name: string): boolean {
  return name.startsWith('user:') || name.startsWith('token:');
}

/** Whether an actor's name is a service's, whom a sign-in names. */
function isService(name: string): boolean {
  return name.startsWith('token:');
}

/** The actors a list of 0.15's records is held to, of those asked: those `kind` takes; undefined for every one. */
function recordActors(actors: readonly string[] | undefined, kind: (name: string) => boolean): (string | undefined)[] {
  return actors === undefined ? [undefined] : actors.filter(kind);
}

/**
 * Where a page lists the key writes 0.15's log records alone (T179, 0.16.0): every one, on a page of the whole log;
 * those at these environments, on a place's page or a reader's of some places; those of one key.
 */
export type WrittenAt = { all: true } | { environmentIds: readonly string[] } | { secretId: string };

/**
 * The changes 0.15's log records in place of 0.14's entries, newest first by
 * when the vault asked, `at`, then by number: one that waited for a lock
 * takes its number after one that asked later. On a page of the instance's
 * (`instance`): the sign-ins; with `detail`, the token issues, revokes and
 * sign-outs, which 0.14 shows only when asked; and the first adds down the
 * two-trip path. Wherever `written` says: the key writes down that path.
 * Since 0.16.0 neither writes a 0.14 entry (T179): their change is the
 * record. And with `refusals`, their refusals, which the vault records in
 * place of 0.14's deny entries since PR 6: an add's on a page of the
 * instance's, a key write's wherever `at` says, but on a key's page, where
 * 0.14's never stood (the route's refusal names no key). Up to `limit`, below `before`, of the members `actors` names if
 * it does: a sign-in's is a service, the rest's anyone's. One round trip
 * (`newest`: a statement a few hundred reads, a few statements at a
 * time past that), of each index's entries,
 * each member's, each environment's, as many as it returns at most,
 * however many other changes the log holds (R48); at a place, of some
 * members, each member's there.
 */
export async function sealedPage(
  db: Queryable,
  filter: {
    actors?: readonly string[]; detail: boolean; before?: ChangePoint; limit: number; instance: boolean; written: WrittenAt | null;
    refusals?: { instance: boolean; at: WrittenAt | null } | null;
  },
  stop?: AbortController,
): Promise<{ rows: RecordedChange[]; more: boolean }> {
  const { logChanges } = tablesOf(db);
  const engine = dialect.engineOf(db);
  const of = (records: ChangeRecord[], actor: string | undefined) => and(recorded(engine, logChanges.payload, ...records), actor === undefined ? undefined : eq(logChanges.actor, actor))!;
  // The reads one at a time, as `newest` takes them: a project's page of tens of thousands of environments, of a
  // member's two forms, is more reads than a call takes arguments (review r4 of #490), and more than an isolate
  // holds at once, made together (review r5).
  const { written } = filter;
  const refusals = filter.refusals ?? null;
  // A key write's records wherever `at` says: every one, each member's; else at a key, or at each environment.
  function* writes(record: 'written' | 'refusedWrite', at: WrittenAt): Generator<SQL> {
    if ('all' in at) {
      for (const actor of recordActors(filter.actors, isMember)) yield of([record], actor);
      return;
    }
    // Of some members at a place: a read of each member's there (`log_changes_written_actor_environment_idx`,
    // `…_actor_object_idx`), never the place's read with the others' passed over, which grows with their writes.
    for (const actor of recordActors(filter.actors, isMember)) {
      if ('secretId' in at) {
        // A refusal names no key, as 0.14's entry of it named none.
        if (record === 'written') yield and(of([record], actor), eq(logChanges.object, logObject('secret', at.secretId)))!;
      } else for (const id of at.environmentIds) yield and(of([record], actor), eq(recordField(engine, logChanges.payload, 'environmentId'), id))!;
    }
  }
  function* reads(): Generator<SQL> {
    if (filter.instance) {
      for (const actor of recordActors(filter.actors, isService)) yield of(SIGN_INS, actor);
      if (filter.detail) for (const actor of recordActors(filter.actors, isMember)) yield of(HIDDEN, actor);
      for (const actor of recordActors(filter.actors, isMember)) yield of(['admitted'], actor);
    }
    if (refusals?.instance === true) for (const actor of recordActors(filter.actors, isMember)) yield of(['refusedAdd'], actor);
    if (written !== null) yield* writes('written', written);
    if (refusals?.at != null) yield* writes('refusedWrite', refusals.at);
  }
  const object = engine === 'postgres' ? sql`CAST(${logChanges.object} AS text)` : logChanges.object;
  const columns = sql`${logChanges.number} AS "number", ${logChanges.at} AS "at", ${logChanges.actor} AS "actor", ${logChanges.payload} AS "payload",
    ${logChanges.requestId} AS "request_id", ${object} AS "object", ${logChanges.seal} AS "seal", ${logChanges.mac} AS "mac"`;
  const rows = await newest<{ number: string | number | bigint; at: string | number; actor: string; payload: string; request_id: string; object: string; seal: Uint8Array | null; mac: Uint8Array }>(
    db, reads(), columns, filter.before, filter.limit + 1, 0, stop,
  );
  return {
    rows: rows.slice(0, filter.limit).map((row) => ({
      number: BigInt(row.number), at: Number(row.at), actor: row.actor, payload: row.payload,
      requestId: row.request_id, object: row.object, seal: row.seal === null ? null : Buffer.from(row.seal), mac: Buffer.from(row.mac),
    })),
    more: rows.length > filter.limit,
  };
}

/** The records a page shows, the sign-ins; and those it leaves out unless asked for its detail, the token issues, revokes and sign-outs. */
const SIGN_INS: ChangeRecord[] = ['signIn'];
const HIDDEN: ChangeRecord[] = ['issue', 'revoke', 'signOut'];

/**
 * The most reads one statement of `newest` takes: SQLite's default limit on
 * a compound SELECT's terms is 500, and each read's few parameters keep
 * Postgres's 65,535 far off (review r3 of #490).
 */
export const READS_PER_STATEMENT = 250;

/**
 * The most statements of `newest` made and asked at once: with more reads,
 * the next is made once one has answered, so that an isolate holds no more
 * than these, and the newest rows so far, however many reads a page takes
 * (review r5 of #490: 130,000 reads made at once held 617 MiB, past
 * Workers' 128 MB).
 */
export const STATEMENTS_AT_ONCE = 4;

/**
 * The newest of the changes each of `reads` holds (a condition its index's
 * repeats), below `before`, `take` of them past the first `skip`: each read
 * on its own and newest first, no further than that, then the newest of
 * them all. A statement of `READS_PER_STATEMENT` reads at most, each of as
 * many index entries as it reads, each read's at most: up to that many
 * reads, one statement, one round trip. With more, a statement of each
 * `READS_PER_STATEMENT`, `STATEMENTS_AT_ONCE` asked together, each made
 * from `reads` as it is asked; their rows merge by `at`, then number, as
 * one statement's would, keeping the newest `skip + take`. The first of
 * them to fail aborts `stop` with its error, at once, and so does a read
 * beside them that shares it: no statement is asked after that, and once
 * those asked have answered, `newest` fails with the first error.
 */
async function newest<Row extends { number: string | number | bigint; at: string | number }>(
  db: Queryable, reads: Iterable<SQL>, columns: SQL, before: ChangePoint | undefined, take: number, skip = 0, stop = new AbortController(),
): Promise<Row[]> {
  const { logChanges } = tablesOf(db);
  const statement = (part: readonly SQL[], take: number, skip: number) => {
    const each = part.map((where, i) => sql`SELECT * FROM (
      SELECT ${columns} FROM ${logChanges}
       WHERE ${and(where, before === undefined ? undefined : below(db, before))}
       ORDER BY ${logChanges.at} DESC, ${logChanges.number} DESC LIMIT ${skip + take}) AS ${sql.raw(`r${i}`)}`);
    return sql`${sql.join(each, sql` UNION ALL `)} ORDER BY "at" DESC, "number" DESC LIMIT ${take} OFFSET ${skip}`;
  };
  const left = reads[Symbol.iterator]();
  const nextPart = (): SQL[] => {
    const part: SQL[] = [];
    while (part.length < READS_PER_STATEMENT) {
      const next = left.next();
      if (next.done === true) break;
      part.push(next.value);
    }
    return part;
  };
  stop.signal.throwIfAborted();
  const first = nextPart();
  if (first.length === 0) return [];
  const second = nextPart();
  if (second.length === 0) return dialect.rowsOf<Row>(db, statement(first, take, skip));
  // Each statement's newest `skip + take`: the overall ones are among them.
  const keep = skip + take;
  const at = (row: Row) => Number(row.at);
  const byNewest = (a: Row, b: Row) => at(b) - at(a) || (BigInt(b.number) > BigInt(a.number) ? 1 : BigInt(b.number) < BigInt(a.number) ? -1 : 0);
  let kept: Row[] = [];
  const made = [first, second];
  // The first statement to fail fails the page: no other is asked after it, and those already asked are
  // waited for, so that a failed page leaves none running behind it (review r6 of #490). It says so at once, as a
  // read beside it that fails does (review r7), so that the page fails with the first error, not one met while
  // waiting (review r8): `stop`'s reason, which a later abort leaves as it is.
  const asking = async () => {
    while (!stop.signal.aborted) {
      try {
        const part = made.pop() ?? nextPart();
        if (part.length === 0) return;
        const rows = await dialect.rowsOf<Row>(db, statement(part, keep, 0));
        kept = kept.concat(rows).sort(byNewest).slice(0, keep);
      } catch (error) {
        stop.abort(error);
      }
    }
  };
  await Promise.all(Array.from({ length: STATEMENTS_AT_ONCE }, asking));
  stop.signal.throwIfAborted();
  return kept.slice(skip, skip + take);
}

/**
 * The most token issues, revokes and sign-outs a page that hides them
 * counts past where it stopped showing entries: a page whose stretch holds
 * more ends its stretch there, and the pages after count the rest
 * (`sealedReach`). However much of a member's history is nothing but
 * those (a person who only ever made handles), a page counts no more than
 * this beyond what it shows (R48).
 */
export const HIDDEN_COUNTED = 1000;

/**
 * How far below `before` a page may count the token issues, revokes and
 * sign-outs of the members `actors` names: the `HIDDEN_COUNTED`-th newest,
 * which the count takes in; null when fewer are left. One read of as many
 * index entries, each member's, from the indexes alone.
 */
export async function sealedReach(db: Queryable, filter: { actors?: readonly string[]; before?: ChangePoint }): Promise<ChangePoint | null> {
  const { logChanges } = tablesOf(db);
  const engine = dialect.engineOf(db);
  const reads = recordActors(filter.actors, isMember).map((actor) => and(recorded(engine, logChanges.payload, ...HIDDEN), actor === undefined ? undefined : eq(logChanges.actor, actor))!);
  if (reads.length === 0) return null;
  const [row] = await newest<{ number: string | number | bigint; at: string | number }>(
    db, reads, sql`${logChanges.number} AS "number", ${logChanges.at} AS "at"`, filter.before, 1, HIDDEN_COUNTED - 1,
  );
  return row === undefined ? null : { at: Number(row.at), number: BigInt(row.number) };
}

/**
 * The token issues, revokes and sign-outs 0.15's log records, of the
 * members `actors` names if it does, at `from` or above it and below
 * `before`, by the action 0.14 logged each as: what a page that hides them
 * counts over its stretch. One grouped count, of as many index entries as
 * the stretch holds.
 */
export async function sealedHidden(
  db: Queryable,
  filter: { actors?: readonly string[]; from?: ChangePoint; before?: ChangePoint },
): Promise<{ action: string; count: number }[]> {
  const { logChanges } = tablesOf(db);
  const engine = dialect.engineOf(db);
  const actors = filter.actors?.filter(isMember);
  if (actors?.length === 0) return [];
  const action = sql<string>`CASE WHEN ${recorded(engine, logChanges.payload, 'issue')} THEN 'token.create' WHEN ${recorded(engine, logChanges.payload, 'signOut')} THEN 'sign_out' ELSE 'token.revoke' END`;
  return db
    .select({ action, count: count() })
    .from(logChanges)
    .where(and(
      recorded(engine, logChanges.payload, ...HIDDEN),
      actors === undefined ? undefined : inArray(logChanges.actor, actors),
      filter.from === undefined ? undefined : notBelow(db, filter.from),
      filter.before === undefined ? undefined : below(db, filter.before),
    ))
    .groupBy(action);
}

/**
 * Whether this token, by its signing input's hash, was exchanged already.
 * Uncached, as `standingBinding` is: a cached "not yet" would send a replay
 * on to the vault and the commit, which refuses it only there.
 */
export async function tokenConsumed(db: Queryable, hash: Buffer): Promise<boolean> {
  const { spentIdTokens } = tablesOf(db);
  const [row] = await db.select({ hash: spentIdTokens.hash, now: clock(db) }).from(spentIdTokens).where(eq(spentIdTokens.hash, hash));
  return row !== undefined;
}

/** Spend a token: false when it was spent already, which the primary key decides. */
export async function consumeToken(db: Queryable, hash: Buffer): Promise<boolean> {
  return (await insertIfAbsent(db, tablesOf(db).spentIdTokens, { hash })) === 1;
}

/**
 * Forget up to `atMost` spent tokens, those spent over two hours ago: an
 * exchange refuses a token issued over an hour ago (`MAX_TOKEN_AGE_SECONDS`),
 * so their records guard nothing. On Postgres the runtime login deletes no
 * row itself, and asks `prune_consumed_tokens`, which deletes only those
 * (migration 0016). How many went.
 */
export async function pruneSpentTokens(db: Queryable, atMost: number): Promise<number> {
  if (dialect.engineOf(db) === 'postgres') {
    // A write, through its function: marked so, it never goes with the reads asked beside it (`groupReads`, @coffre/db/hyperdrive).
    const [{ pruned }] = await db.execute<{ pruned: number }>(sql`/* writes */ SELECT prune_consumed_tokens(${atMost}) AS pruned`) as unknown as [{ pruned: number }];
    return pruned;
  }
  const { spentIdTokens } = tablesOf(db);
  const old = db.select({ hash: spentIdTokens.hash }).from(spentIdTokens).where(lt(spentIdTokens.consumedAt, sql`${clockMillis(db)} - ${SPENT_TOKENS_KEPT_MS}`)).limit(atMost);
  return changedRows(await db.delete(spentIdTokens).where(inArray(spentIdTokens.hash, old)));
}

/** How long a spent token's record is kept: prune_consumed_tokens's two hours, which SQLite applies here. */
export const SPENT_TOKENS_KEPT_MS = 2 * 60 * 60 * 1000;

/**
 * Spend a token and, only if this spent it, insert the credential its
 * exchange issues and stamp the binding's last use: false, and nothing
 * written, when it was spent already, which the primary key decides. One
 * statement on Postgres, under the log's head; SQLite, with no
 * data-modifying CTE, runs them in turn.
 */
export async function exchangeToken(db: Queryable, token: Buffer, credential: NewRow<Tables['credentials']>, bindingId: string, at: Date): Promise<boolean> {
  const { spentIdTokens, credentials, serviceBindings } = tablesOf(db);
  if (dialect.engineOf(db) === 'sqlite') {
    if (!(await consumeToken(db, token))) return false;
    await insert(db, credentials, credential);
    await update(db, serviceBindings, { id: bindingId }, { lastUsedAt: at });
    return true;
  }
  const spend = db.insert(spentIdTokens).values({ hash: token }).onConflictDoNothing().returning({ hash: spentIdTokens.hash });
  // The credential's row once for each token spent: none, or one. Its other columns take the database's defaults: a column
  // added later with a default of Drizzle's own (`$defaultFn`) gets it from `insert` on SQLite, not here.
  const columns = Object.entries(getTableColumns(credentials)).filter(([name]) => credential[name as keyof typeof credential] !== undefined);
  const names = sql.join(columns.map(([, column]) => sql.identifier(column.name)), sql`, `);
  const values = sql.join(columns.map(([name, column]) => sql.param(credential[name as keyof typeof credential], column)), sql`, `);
  const stamp = db.update(serviceBindings).set({ lastUsedAt: at }).where(and(eq(serviceBindings.id, bindingId), sql`EXISTS (SELECT 1 FROM spent)`));
  const [row] = await dialect.rowsOf<{ spent: boolean }>(db, sql`WITH spent AS (${spend.getSQL()}),
    issued AS (INSERT INTO ${credentials} (${names}) SELECT ${values} FROM spent),
    stamped AS (${stamp.getSQL()})
    SELECT EXISTS (SELECT 1 FROM spent) AS spent`);
  return row!.spent;
}

export async function insertBinding(db: Queryable, chainKey: Buffer, row: Omit<NewRow<Tables['serviceBindings']>, 'authMac'> & {
  id: string; principal: string; generation: number; profile: string; issuer: string; jwksUri: string; claims: string;
}): Promise<void> {
  const signed = { ...row, revokedAt: null };
  await insert(db, tablesOf(db).serviceBindings, { ...signed, authMac: authMac(chainKey, 'service_bindings', signed) });
}

/**
 * Retire directory records from older memberships, including a sweep that
 * rolled back: the credentials' ids it revoked (`priorCredentials`).
 */
export async function revokePriorMembership(
  db: Queryable,
  chainKey: Buffer,
  principal: { type: string; id: string },
  generation: number,
  revokedBy: string,
): Promise<{ credentials: string[]; connections: string[] }> {
  const { identities } = tablesOf(db);
  const revokedAt = new Date();
  for (const row of await db.select().from(identities).where(and(eq(identities.principal, principalOf(principal)), lt(identities.generation, generation), isNull(identities.revokedAt)))) {
    if (!checkAuthRow(chainKey, 'identities', row)) continue;
    await updateAuth(db, chainKey, identities, { id: row.id, authMac: row.authMac }, { revokedAt, revokedBy });
  }
  // Each connection it ends is a change of 0.15's log, as each credential is (T147): the caller prepared them from the same read.
  const connections: string[] = [];
  for (const row of await priorConnections(db, chainKey, principal, generation, revokedAt)) {
    if ((await updateAuth(db, chainKey, tablesOf(db).mcpConnections, { id: row.id, authMac: row.authMac }, { revokedAt, revokedBy })) > 0) connections.push(row.id);
  }
  return { credentials: await revokeCredentialsWhere(db, chainKey, priorCredentials(principal, generation, revokedAt), { revokedAt, revokedBy }), connections };
}

/** A member's live MCP connections of a membership before `generation`, their MACs the app's: what `revokePriorMembership` ends. */
export async function priorConnections(db: Queryable, chainKey: Buffer, principal: { type: string; id: string }, generation: number, at: Date): Promise<ConnectionRow[]> {
  const { mcpConnections } = tablesOf(db);
  const rows = await db.select().from(mcpConnections).where(and(eq(mcpConnections.principal, principalOf(principal)), lt(mcpConnections.generation, generation),
    isNull(mcpConnections.revokedAt), gt(mcpConnections.expiresAt, at)));
  return rows.filter((row) => checkAuthRow(chainKey, 'mcp_connections', row));
}

/** A person's credentials of this membership, live at `at`, that name no passkey: what a first passkey ends (passkeys.md, section 6.1). */
export function unbackedCredentials(principal: { type: string; id: string }, generation: number, at: Date): CredentialsWhere {
  return (credentials) => and(eq(credentials.principal, principalOf(principal)), eq(credentials.generation, generation), isNull(credentials.passkeyId), gt(credentials.expiresAt, at));
}

/** Every credential of a person's live at `at`, whatever names it: what removing one of their passkeys, or a reset, ends (passkeys.md, section 6.1). */
export function personCredentials(principal: { type: string; id: string }, at: Date): CredentialsWhere {
  return (credentials) => and(eq(credentials.principal, principalOf(principal)), gt(credentials.expiresAt, at));
}

/** A member's credentials of a membership before `generation`, live at `at`: expired ones are dead already, and a CI service leaves one behind each run. */
export function priorCredentials(principal: { type: string; id: string }, generation: number, at: Date): CredentialsWhere {
  return (credentials) => and(eq(credentials.principal, principalOf(principal)), lt(credentials.generation, generation), gt(credentials.expiresAt, at));
}

// --- credentials revoked, and 0.15's log ------------------------------------

export type CredentialRow = Tables['credentials']['$inferSelect'];

/** Which credentials: a condition on the engine's own table. */
export type CredentialsWhere = (credentials: Tables['credentials']) => SQL | undefined;

/** One credential, by its id or its token's hash; a sign-in account's sessions. */
export const credentialsBy = {
  id: (id: string): CredentialsWhere => (credentials) => eq(credentials.id, id),
  tokenHash: (tokenHash: Buffer): CredentialsWhere => (credentials) => eq(credentials.tokenHash, tokenHash),
  identity: (identityId: string): CredentialsWhere => (credentials) => eq(credentials.identityId, identityId),
  ids: (ids: readonly string[]): CredentialsWhere => (credentials) => inArray(credentials.id, [...ids]),
  /** The browser session a cookie's token is, if it is this principal's: what a touch replaces (passkeys.md, section 6.5). */
  session: (tokenHash: Buffer, principal: string): CredentialsWhere => (credentials) =>
    and(eq(credentials.tokenHash, tokenHash), eq(credentials.principal, principal), eq(credentials.kind, 'browser')),
};

/**
 * The live credentials `where` names: not revoked, and their MAC the app's
 * (a row that fails it is dead, and never signed again, as `updateAuth`
 * leaves it), with their seals. What a revoke of them changes: with 0.15's
 * log, its changes are prepared from this read before the transaction, in
 * which `revokeCredentialsWhere` reads them again (`AppChanges.expect`).
 */
export async function liveCredentialsWhere(db: Queryable, chainKey: Buffer, where: CredentialsWhere): Promise<CredentialRow[]> {
  const { credentials } = tablesOf(db);
  const rows = await db.select().from(credentials).where(and(where(credentials as Tables['credentials']), isNull(credentials.revokedAt)));
  return rows.filter((row) => checkAuthRow(chainKey, 'credentials', row));
}

/** Revoke the live credentials `where` names, each a compare-and-set on its MAC, as `updateAuth` does: the ids it revoked. */
export async function revokeCredentialsWhere(db: Queryable, chainKey: Buffer, where: CredentialsWhere, by: { revokedAt: Date; revokedBy: string }): Promise<string[]> {
  const { credentials } = tablesOf(db);
  // Each its own compare-and-set, asked together: one round trip for them all, however many (review r1 of #529).
  const rows = await liveCredentialsWhere(db, chainKey, where);
  const done = await Promise.all(rows.map((row) => update(db, credentials as Tables['credentials'], { id: row.id, authMac: row.authMac, revokedAt: null }, { ...by, authMac: authMac(chainKey, 'credentials', { ...row, ...by }) })));
  return rows.filter((_, i) => done[i]! > 0).map((row) => row.id);
}

/**
 * Revoke a member's credentials still live at `at`, or only those
 * `createdBy` issued: not revoked, not expired. Expired ones are dead
 * already, and a CI service's run to thousands; through
 * `credentials_live_idx`, the work is what is live, whatever the history.
 */
export async function revokeLiveCredentials(
  db: Queryable,
  chainKey: Buffer,
  live: { principal: string; createdBy?: string; at: Date },
  changes: { revokedAt: Date; revokedBy: string },
): Promise<string[]> {
  return revokeCredentialsWhere(db, chainKey, liveCredentialsOf(live), changes);
}

/** A member's credentials live at `at`, or only those `createdBy` issued (`revokeLiveCredentials`). */
export function liveCredentialsOf(live: { principal: string; createdBy?: string; at: Date }): CredentialsWhere {
  return (credentials) => and(
    eq(credentials.principal, live.principal),
    gt(credentials.expiresAt, live.at),
    live.createdBy === undefined ? undefined : eq(credentials.createdBy, live.createdBy),
  );
}

// --- MCP clients and connections -------------------------------------------

export type OauthClientRow = Tables['oauthClients']['$inferSelect'];
export type ConnectionRow = Tables['mcpConnections']['$inferSelect'];

export async function insertOauthClient(db: Queryable, chainKey: Buffer, row: Omit<NewRow<Tables['oauthClients']>, 'authMac'> & {
  id: string; name: string; redirectUris: string;
}): Promise<void> {
  const signed = { ...row, revokedAt: null };
  await insert(db, tablesOf(db).oauthClients, { ...signed, authMac: authMac(chainKey, 'oauth_clients', signed) });
}

/** A registered client, by its ID: null for none, a revoked one, or one that fails its MAC, which is reported. */
export async function findOauthClient(db: Queryable, chainKey: Buffer, id: string): Promise<OauthClientRow | null> {
  const { oauthClients } = tablesOf(db);
  const [row] = await db.select().from(oauthClients).where(eq(oauthClients.id, id));
  return row !== undefined && row.revokedAt === null && checkAuthRow(chainKey, 'oauth_clients', row) ? row : null;
}

/**
 * Revoke up to `limit` registrations made before `before` that no
 * connection names: a client that registered and never connected. Nothing
 * is deleted, as nowhere in coffre; a revoked registration connects no more.
 * Returns how many were revoked.
 */
export async function sweepOauthClients(db: Queryable, chainKey: Buffer, before: Date, limit: number): Promise<number> {
  const { oauthClients, mcpConnections } = tablesOf(db);
  const unused = await db
    .select({ id: oauthClients.id })
    .from(oauthClients)
    .where(and(
      isNull(oauthClients.revokedAt),
      lt(oauthClients.createdAt, before),
      sql`NOT EXISTS (SELECT 1 FROM ${mcpConnections} WHERE ${mcpConnections.clientId} = CAST(${oauthClients.id} AS TEXT))`,
    ))
    .limit(limit);
  if (unused.length === 0) return 0;
  return updateAuth(db, chainKey, oauthClients, { id: unused.map((row) => row.id), revokedAt: null }, { revokedAt: new Date() });
}

export async function insertConnection(db: Queryable, chainKey: Buffer, row: Omit<NewRow<Tables['mcpConnections']>, 'authMac'> & {
  id: string; principal: string; generation: number; clientId: string; clientName: string; clientHost: string | null; registration: string;
  scopes: string; redirectUri: string; codeHash: Buffer; codeChallenge: string; codeExpiresAt: Date; expiresAt: Date; passkeyId: string | null;
}): Promise<void> {
  const signed = { ...row, refreshHash: null, refreshPreviousHash: null, revokedAt: null };
  await insert(db, tablesOf(db).mcpConnections, { ...signed, authMac: authMac(chainKey, 'mcp_connections', signed) });
}

/**
 * The connection a code, a refresh token or an ID names, its MAC checked:
 * revoked, expired or not, for the caller to judge. A refresh token found
 * as the one before the current one says so: `previous`, a reuse. Null for
 * none; a row that fails its MAC refuses (`AuthRowTampered`).
 */
export async function findConnection(
  db: Queryable,
  chainKey: Buffer,
  by: { id: string } | { codeHash: Buffer } | { refreshHash: Buffer },
): Promise<(ConnectionRow & { previous: boolean; now: Date; passkeyRead: PasskeyRead }) | null> {
  const { mcpConnections } = tablesOf(db);
  const where =
    'id' in by
      ? eq(mcpConnections.id, by.id)
      : 'codeHash' in by
        ? eq(mcpConnections.codeHash, by.codeHash)
        : or(eq(mcpConnections.refreshHash, by.refreshHash), eq(mcpConnections.refreshPreviousHash, by.refreshHash));
  const { passkeys } = tablesOf(db);
  const [row] = await db
    .select({
      connection: mcpConnections, now: clockMillis(db),
      // What stands behind it, as for a credential (`credentialRow`): every use through it holds it (section 6.2).
      passkey: passkeys, passkeyHeld: heldSql(sql`${mcpConnections.principal}`, sql`${mcpConnections.generation}`),
    })
    .from(mcpConnections)
    .leftJoin(passkeys, eq(passkeys.id, mcpConnections.passkeyId))
    .where(where)
    .limit(1);
  if (row === undefined) return null;
  verifyAuthRow(chainKey, 'mcp_connections', row.connection);
  const previous = 'refreshHash' in by && row.connection.refreshHash?.equals(by.refreshHash) !== true;
  return { ...row.connection, previous, now: new Date(row.now), passkeyRead: (await passkeyOf(db, chainKey, row.connection, row))! };
}

/**
 * A person's connections that have not ended, codes not yet redeemed among
 * them, newest first: rows that fail their MAC are reported and passed over.
 */
export async function liveConnections(db: Queryable, chainKey: Buffer, principal: string, at: Date): Promise<ConnectionRow[]> {
  const { mcpConnections } = tablesOf(db);
  const rows = await db
    .select()
    .from(mcpConnections)
    .where(and(eq(mcpConnections.principal, principal), isNull(mcpConnections.revokedAt), gt(mcpConnections.expiresAt, at)))
    .orderBy(desc(mcpConnections.createdAt));
  return rows.filter((row) => checkAuthRow(chainKey, 'mcp_connections', row));
}

export type ApprovalRow = Tables['mcpApprovals']['$inferSelect'];

export async function insertApproval(db: Queryable, row: NewRow<Tables['mcpApprovals']> & { id: string; expiresAt: Date }): Promise<void> {
  await insert(db, tablesOf(db).mcpApprovals, row);
}

/** An approval by its ID, with the database's clock, which its expiry is read against. */
export async function findApproval(db: Queryable, id: string): Promise<(ApprovalRow & { now: Date }) | null> {
  const { mcpApprovals } = tablesOf(db);
  const [row] = await db.select({ approval: mcpApprovals, now: clockMillis(db) }).from(mcpApprovals).where(eq(mcpApprovals.id, id)).limit(1);
  return row === undefined ? null : { ...row.approval, now: new Date(row.now) };
}

/** Decide a pending approval that has not expired, by the database's clock as the write runs: 1 if it moved, 0 if not. */
export async function decideApproval(db: Queryable, id: string, status: 'approved' | 'denied'): Promise<number> {
  const { mcpApprovals } = tablesOf(db);
  return changedRows(
    await db
      .update(mcpApprovals)
      .set({ status, decidedAt: new Date() })
      .where(and(eq(mcpApprovals.id, id), eq(mcpApprovals.status, 'pending'), ahead(db, mcpApprovals.expiresAt))),
  );
}

/**
 * A connection's approvals whose end its client has not heard yet, asked
 * since `since`, newest first, with the database's clock: older ones can
 * no longer be rejoined, and no longer wait.
 */
export async function openApprovals(db: Queryable, connectionId: string, since: Date): Promise<{ rows: ApprovalRow[]; now: Date }> {
  const { mcpApprovals } = tablesOf(db);
  const rows = await db
    .select({ approval: mcpApprovals, now: clockMillis(db) })
    .from(mcpApprovals)
    .where(and(eq(mcpApprovals.connectionId, connectionId), isNull(mcpApprovals.reportedAt), gt(mcpApprovals.createdAt, since)))
    .orderBy(desc(mcpApprovals.createdAt));
  return { rows: rows.map((row) => row.approval), now: new Date(rows[0]?.now ?? Date.now()) };
}

/**
 * The same call's earlier approvals, approved and never answered: their
 * change may or may not have been made. Their client is never told they
 * ended, so they stay in the open approvals' index.
 */
export async function unansweredApprovals(db: Queryable, connectionId: string, digest: Buffer): Promise<ApprovalRow[]> {
  const { mcpApprovals } = tablesOf(db);
  return db
    .select()
    .from(mcpApprovals)
    .where(and(eq(mcpApprovals.connectionId, connectionId), eq(mcpApprovals.digest, digest), isNull(mcpApprovals.reportedAt), eq(mcpApprovals.status, 'approved'), isNull(mcpApprovals.outcome)));
}

/** Device authorizations: one by either of its codes, or every one still waiting for a decision. */
export async function findDeviceAuthorizations(
  db: Queryable,
  chainKey: Buffer,
  by: { userCode: string } | { deviceCodeHash: Buffer },
) {
  const { deviceLogins } = tablesOf(db);
  const rows = await db
    .select()
    .from(deviceLogins)
    .where('userCode' in by ? eq(deviceLogins.userCode, by.userCode) : eq(deviceLogins.deviceCodeHash, by.deviceCodeHash));
  for (const row of rows) verifyAuthRow(chainKey, 'device_authorizations', row);
  return rows;
}

/**
 * The address each open device login came from, for the next one's
 * admission: the rows' every column but the label, which the MAC does not
 * cover and anyone may make as long as a body is, so that the hundreds of
 * open logins admission reads hold a few hundred bytes each, never a body's
 * size each. Each row's MAC is checked all the same.
 */
export async function openDeviceSources(db: Queryable, chainKey: Buffer, at: Date): Promise<(string | null)[]> {
  const { deviceLogins } = tablesOf(db);
  const { clientLabel: _label, ...columns } = getTableColumns(deviceLogins);
  const rows = await db.select(columns).from(deviceLogins).where(and(isNull(deviceLogins.decidedAt), gt(deviceLogins.expiresAt, at)));
  for (const row of rows) verifyAuthRow(chainKey, 'device_authorizations', row);
  return rows.map((row) => row.clientIp);
}

// --- secrets ------------------------------------------------------------------

/** The committed state to compare after the vault prepares a write or restore. */
export async function secretHeads(db: Queryable, environmentId: string, by: { keys: string[] } | { id: string }) {
  const { secrets, secretVersions } = tablesOf(db);
  const rows = await db.select({
    id: secrets.id,
    key: secrets.key,
    currentVersion: secrets.currentVersion,
    currentVersionId: secrets.currentVersionId,
    archivedAt: secrets.archivedAt,
    // How its current value is held, which a write that says nothing keeps the strictness of (`Sensitivity`).
    plain: sql<boolean | number | null>`${secretVersions.plaintext} IS NOT NULL`,
    sensitive: secretVersions.sensitive,
  }).from(secrets).leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId)).where(and(
    inEnvironment(db, environmentId),
    'id' in by ? eq(secrets.id, by.id) : inArray(secrets.key, by.keys),
  ));
  return rows.map(({ plain, sensitive, ...row }) => ({ ...row, current: row.currentVersionId === null ? null : { plain: Boolean(plain), sensitive: sensitive === true } }));
}

const envelopeColumns = (secretVersions: Tables['secretVersions']) => ({
  envelopeVersion: secretVersions.envelopeVersion,
  kekProvider: secretVersions.kekProvider,
  kekId: secretVersions.kekId,
  kekVersion: secretVersions.kekVersion,
  wrappedDek: secretVersions.wrappedDek,
  iv: secretVersions.iv,
  authTag: secretVersions.authTag,
  ciphertext: secretVersions.ciphertext,
});

/**
 * How a version's value was made, when a client generated it: its recipe
 * (`@coffre/core/recipe`), and for a key pair the id its two halves share
 * and which half this is. Null for a typed value.
 */
export type VersionRecipe = { recipe: string; pair: { id: string; half: PairHalf } | null };
export type PairHalf = 'private' | 'public';

const recipeColumns = (secretVersions: Tables['secretVersions']) => ({
  recipe: secretVersions.recipe,
  pairId: secretVersions.pairId,
  pairHalf: secretVersions.pairHalf,
});

/** The columns a version stores its recipe in, from what a write made. */
export function recipeRow(made: VersionRecipe | null): { recipe: string | null; pairId: string | null; pairHalf: PairHalf | null } {
  return { recipe: made?.recipe ?? null, pairId: made?.pair?.id ?? null, pairHalf: made?.pair?.half ?? null };
}

function recipeOf(row: { recipe: string | null; pairId: string | null; pairHalf: string | null }): VersionRecipe | null {
  if (row.recipe === null) return null;
  const half = row.pairHalf === 'private' || row.pairHalf === 'public' ? row.pairHalf : null;
  return { recipe: row.recipe, pair: row.pairId === null || half === null ? null : { id: row.pairId, half } };
}

function envelopeOf(row: Envelope): Envelope {
  return {
    envelopeVersion: row.envelopeVersion,
    kekProvider: row.kekProvider,
    kekId: row.kekId,
    kekVersion: row.kekVersion,
    wrappedDek: row.wrappedDek,
    iv: row.iv,
    authTag: row.authTag,
    ciphertext: row.ciphertext,
  };
}

export type SecretRow = {
  id: string;
  key: string;
  /** The folder it is listed in, if any. */
  folder: string | null;
  archivedAt: Date | null;
  /** Null before the first version. */
  current: {
    id: string;
    version: number;
    createdAt: Date;
    createdBy: string;
    envelope: Envelope;
    recipe: VersionRecipe | null;
    /** The value itself, for a plain one: no secret, and opened without the vault. Null for a secret. */
    plaintext: string | null;
    /** Whether it is sensitive: never handed back to a person, which the vault's wrap of its key binds. */
    sensitive: boolean;
  } | null;
};

/**
 * An environment's secrets, archived ones included, each with its current
 * version and ciphertext; or just one of them, by id or by key. Listing,
 * revealing, running and exporting all read this.
 */
export async function environmentSecrets(
  db: Queryable,
  environmentId: string,
  only?: { secretId: string } | { key: string },
): Promise<SecretRow[]> {
  const { secrets, secretVersions, projects, environments } = tablesOf(db);
  const rows = await db
    .select({
      id: secrets.id,
      key: secrets.key,
      folder: secrets.folder,
      archivedAt: secrets.archivedAt,
      versionId: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns(secretVersions),
      ...recipeColumns(secretVersions),
      plaintext: secretVersions.plaintext,
      sensitive: secretVersions.sensitive,
    })
    .from(secrets)
    .innerJoin(projects, eq(projects.id, secrets.projectId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(and(
      eq(secrets.environmentId, environmentId),
      eq(secrets.projectId, environments.projectId),
      isNull(projects.archivedAt),
      isNull(environments.archivedAt),
      only === undefined ? undefined : 'secretId' in only ? eq(secrets.id, only.secretId) : eq(secrets.key, only.key),
    ))
    .orderBy(asc(secrets.key));
  return rows.map(secretRowOf);
}

/** A key's row and its current version's columns, as `environmentSecrets` selects them, null for a key with no version. */
type SecretColumnsRead = { id: string; key: string; folder: string | null; archivedAt: Date | null; versionId: string | null; version: number | null; createdAt: Date | null; createdBy: string | null; plaintext: string | null; sensitive: boolean | null }
  & { [K in keyof Envelope]: Envelope[K] | null } & { recipe: string | null; pairId: string | null; pairHalf: string | null };

/** A key's row as `environmentSecrets` answers it, from its columns: the same from `app_read` (read-ahead.ts). */
export function secretRowOf(row: SecretColumnsRead): SecretRow {
  return {
    id: row.id,
    key: row.key,
    folder: row.folder,
    archivedAt: row.archivedAt,
    current:
      row.versionId === null
        ? null
        : {
            id: row.versionId,
            version: row.version!,
            createdAt: row.createdAt!,
            createdBy: row.createdBy!,
            envelope: envelopeOf(row as Envelope),
            recipe: recipeOf(row),
            plaintext: row.plaintext,
            sensitive: row.sensitive === true,
          },
  };
}

/** Every version of a secret, newest first. */
export async function secretHistory(
  db: Queryable,
  secretId: string,
): Promise<{ id: string; version: number; createdAt: Date; createdBy: string; envelope: Envelope; recipe: VersionRecipe | null; plaintext: string | null; sensitive: boolean }[]> {
  const { secretVersions } = tablesOf(db);
  const rows = await db
    .select({
      id: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns(secretVersions),
      ...recipeColumns(secretVersions),
      plaintext: secretVersions.plaintext,
      sensitive: secretVersions.sensitive,
    })
    .from(secretVersions)
    .where(eq(secretVersions.secretId, secretId))
    .orderBy(desc(secretVersions.version));
  return rows.map((row) => ({
    id: row.id,
    version: row.version,
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    envelope: envelopeOf(row),
    recipe: recipeOf(row),
    plaintext: row.plaintext,
    sensitive: row.sensitive,
  }));
}


// --- missing keys ---------------------------------------------------------------

export { MAX_PARENTS };

/** An environment a fork inherits from, as a read needs it. */
export type ParentRow = { id: string; slug: string; archived: boolean; deleted: boolean };

/**
 * The environments `environmentId` inherits from, nearest first: its
 * parent, that one's, and so on, in one statement. The app makes a parent
 * before its child and never changes it, so its chains neither loop nor run
 * past `MAX_PARENTS`. Null for one that does, written around it.
 */
export async function parentsOf(db: Queryable, environmentId: string): Promise<ParentRow[] | null> {
  // One level past the most there may be, so that a chain too long, or a loop, shows.
  const chain = await dialect.rowsOf<{ id: string; slug: string; archived: boolean | number; parent_id: string | null }>(db, sql`
    WITH RECURSIVE chain (id, slug, archived, parent_id, depth) AS (
      SELECT id, slug, archived_at IS NOT NULL, parent_id, 0 FROM environments WHERE id = ${environmentId}
      UNION ALL
      SELECT parent.id, parent.slug, parent.archived_at IS NOT NULL, parent.parent_id, chain.depth + 1
      FROM chain JOIN environments parent ON parent.id = chain.parent_id
      WHERE chain.depth <= ${MAX_PARENTS}
    )
    SELECT id, slug, archived, parent_id FROM chain ORDER BY depth`);
  const [self, ...above] = chain;
  if (self === undefined) return [];
  const parents: ParentRow[] = [];
  const seen = new Set([environmentId]);
  for (const row of above) {
    if (seen.has(row.id) || parents.length === MAX_PARENTS) return null;
    seen.add(row.id);
    parents.push({ id: row.id, slug: row.slug, archived: Boolean(row.archived), deleted: isTombstone(row.slug) });
  }
  // A parent named and not found: the chain was cut around the app.
  const last = chain.at(-1)!;
  return last.parent_id === null ? parents : null;
}

/** Whether an environment, and its project, are neither archived nor deleted. */
export async function liveEnvironment(db: Queryable, environmentId: string): Promise<boolean> {
  const { environments, projects } = tablesOf(db);
  const [row] = await db
    .select({ id: environments.id })
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(and(
      eq(environments.id, environmentId),
      isNull(environments.archivedAt),
      isNull(projects.archivedAt),
      standing(environments.slug),
      standing(projects.slug),
    ));
  return row !== undefined;
}

/**
 * The environments that inherit from `environmentId` directly: the live
 * ones, or with `archived`, those archived too. Each with its owner, a
 * personal config's, which follows its parent where a shared fork stops it.
 */
export async function forksOf(db: Queryable, environmentId: string, { archived = false }: { archived?: boolean } = {}): Promise<{ id: string; slug: string; owner: string | null; archivedAt: Date | null }[]> {
  const { environments } = tablesOf(db);
  return db
    .select({ id: environments.id, slug: environments.slug, owner: environments.owner, archivedAt: environments.archivedAt })
    .from(environments)
    .where(and(eq(environments.parentId, environmentId), archived ? undefined : isNull(environments.archivedAt), standing(environments.slug)))
    .orderBy(asc(environments.slug));
}

/** An environment's dismissed keys, those not restored since. */
export async function dismissalsIn(db: Queryable, environmentId: string) {
  const { dismissedKeys } = tablesOf(db);
  return db
    .select({ key: dismissedKeys.key, dismissedAt: dismissedKeys.dismissedAt, dismissedBy: dismissedKeys.dismissedBy })
    .from(dismissedKeys)
    .where(and(eq(dismissedKeys.environmentId, environmentId), isNull(dismissedKeys.restoredAt)));
}

/** The keys these environments dismissed, those not restored since, and who and when: in a fork, what it removed. */
export async function dismissalsAcross(db: Queryable, environmentIds: readonly string[]) {
  if (environmentIds.length === 0) return [];
  const { dismissedKeys } = tablesOf(db);
  return db
    .select({ environmentId: dismissedKeys.environmentId, key: dismissedKeys.key, dismissedAt: dismissedKeys.dismissedAt, dismissedBy: dismissedKeys.dismissedBy })
    .from(dismissedKeys)
    .where(and(inArray(dismissedKeys.environmentId, [...environmentIds]), isNull(dismissedKeys.restoredAt)));
}

/** The live keys of these environments, each with its folder. */
export async function liveKeysIn(db: Queryable, environmentIds: readonly string[]) {
  if (environmentIds.length === 0) return [];
  const { secrets } = tablesOf(db);
  return db
    .select({ environmentId: secrets.environmentId, key: secrets.key, folder: secrets.folder })
    .from(secrets)
    .where(and(inArray(secrets.environmentId, [...environmentIds]), isNull(secrets.archivedAt)));
}

/**
 * The live keys, each with its folder, and the dismissals of every
 * environment of the projects with a fork among `within` (any, without):
 * what each of their environments resolves to (`resolveKeys`). Neither
 * needs another statement's answer first, so they go with the read of the
 * places (`groupReads`, @coffre/db/hyperdrive).
 */
export async function forkedKeys(db: Queryable, within?: readonly string[]) {
  const { environments, secrets, dismissedKeys } = tablesOf(db);
  const forked = db.select({ id: environments.projectId }).from(environments)
    .where(and(isNotNull(environments.parentId), standing(environments.slug), within === undefined ? undefined : inArray(environments.projectId, [...within])));
  const theirs = db.select({ id: environments.id }).from(environments).where(and(inArray(environments.projectId, forked), standing(environments.slug)));
  return Promise.all([
    db.select({ environmentId: secrets.environmentId, key: secrets.key, folder: secrets.folder }).from(secrets)
      .where(and(inArray(secrets.environmentId, theirs), isNull(secrets.archivedAt))),
    db.select({ environmentId: dismissedKeys.environmentId, key: dismissedKeys.key }).from(dismissedKeys)
      .where(and(inArray(dismissedKeys.environmentId, theirs), isNull(dismissedKeys.restoredAt))),
  ]);
}

/** The live keys of these environments, each with its folder, and those `archivedIn` archived: whether it holds a key at all. */
export async function keysAcross(db: Queryable, environmentIds: readonly string[], archivedIn: string) {
  const { secrets } = tablesOf(db);
  return db
    .select({ environmentId: secrets.environmentId, key: secrets.key, folder: secrets.folder, archivedAt: secrets.archivedAt })
    .from(secrets)
    .where(and(inArray(secrets.environmentId, [...environmentIds]), or(isNull(secrets.archivedAt), eq(secrets.environmentId, archivedIn))));
}

// --- references -----------------------------------------------------------------

/**
 * A reference as the app's row points at it, and the vault's end of it if
 * one names its creation: whether a reference is live comes from the log
 * (`audit_log_reference_end_idx`), never from the row, which only grows.
 */
export type ReferenceRow = {
  id: string;
  createdSeq: bigint;
  createdAt: Date;
  createdBy: string;
  /** Each end with its environment's slug, which grants on one environment in every project match. */
  holder: { projectId: string; environmentId: string; environmentSlug: string; secretId: string };
  source: { projectId: string; environmentId: string; environmentSlug: string; secretId: string };
  ended: { by: string; at: number; reason: string } | null;
};

/** Each of these environments' slug, by id. */
async function environmentSlugs(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const { environments } = tablesOf(db);
  const rows = await db.select({ id: environments.id, slug: environments.slug }).from(environments).where(inArray(environments.id, [...new Set(ids)]));
  return new Map(rows.map((row) => [row.id, row.slug]));
}

/**
 * References by holder, by source, by project on either side, or by who made
 * them; oldest first. Each is what the vault sealed: its holder, source and
 * maker come from its `reference.create` entry, never from the app's row,
 * which only points at the entry and which the app's login can write. A row
 * with no such entry, or one about another reference, is no reference.
 * Looked up by project or source, the seals are found first, through the
 * log's `also` indexes, so that a row edited to name other places still
 * shows where its seal says; by maker, through its actor index
 * (`audit_log_actor_idx`), since the maker is the seal's actor (D46).
 */
export async function referenceRows(
  db: Queryable,
  where: { holderSecretIds?: string[]; sourceSecretIds?: string[]; projectId?: string; createdBy?: string },
): Promise<ReferenceRow[]> {
  const { secretReferences, auditLog, environments } = tablesOf(db);
  if (where.holderSecretIds?.length === 0 || where.sourceSecretIds?.length === 0) return [];
  const bySeal = where.projectId !== undefined || where.sourceSecretIds !== undefined || where.createdBy !== undefined;
  // One statement: each row with its seal, its end if any, and its two environments' slugs, as its own columns name
  // them; looked up by seal, the seals first, by the subquery's indexes.
  const [seal, ended, holderAt, sourceAt] = [alias(auditLog, 'seal'), alias(auditLog, 'ended'), alias(environments, 'holder_at'), alias(environments, 'source_at')];
  const rows = await db
    .select({
      reference: secretReferences,
      endedBy: ended.actor,
      endedAt: ended.occurredAt,
      endMetadata: ended.metadata,
      seal: { seq: seal.seq, actor: seal.actor, occurredAt: seal.occurredAt, projectId: seal.projectId, environmentId: seal.environmentId, metadata: seal.metadata },
      holderSlug: holderAt.slug,
      sourceSlug: sourceAt.slug,
    })
    .from(secretReferences)
    .leftJoin(ended, and(
      eq(ended.relatedSeq, secretReferences.createdSeq),
      eq(ended.author, 'vault'),
      eq(ended.action, 'reference.end'),
      eq(ended.decision, 'allow'),
    ))
    .leftJoin(seal, and(eq(seal.seq, secretReferences.createdSeq), sealing(seal)))
    .leftJoin(holderAt, eq(holderAt.id, secretReferences.environmentId))
    .leftJoin(sourceAt, eq(sourceAt.id, secretReferences.sourceEnvironmentId))
    .where(and(
      bySeal ? inArray(secretReferences.createdSeq, sealedBy(db, where)) : undefined,
      where.holderSecretIds === undefined ? undefined : inArray(secretReferences.secretId, where.holderSecretIds),
    ))
    .orderBy(asc(secretReferences.createdSeq));
  type Sealed = { reference?: unknown; secretId?: unknown; also?: { projectId?: unknown; environmentId?: unknown; secretId?: unknown } };
  const text = (value: unknown): value is string => typeof value === 'string' && value !== '';
  const slugs = new Map<string, string>();
  const sealed = rows.flatMap(({ reference: row, endedBy, endedAt, endMetadata, seal, holderSlug, sourceSlug }) => {
    if (seal === null || seal.projectId === null || seal.environmentId === null) return [];
    const detail = JSON.parse(seal.metadata) as Sealed;
    const source = detail.also ?? {};
    if (detail.reference !== row.id || !text(detail.secretId) || !text(source.projectId) || !text(source.environmentId) || !text(source.secretId)) return [];
    const holder = { projectId: seal.projectId, environmentId: seal.environmentId, secretId: detail.secretId };
    if (where.holderSecretIds !== undefined && !where.holderSecretIds.includes(holder.secretId)) return [];
    if (holderSlug !== null) slugs.set(row.environmentId, holderSlug);
    if (sourceSlug !== null) slugs.set(row.sourceEnvironmentId, sourceSlug);
    return [{
      id: row.id,
      createdSeq: row.createdSeq,
      createdAt: new Date(seal.occurredAt),
      createdBy: seal.actor,
      holder,
      source: { projectId: source.projectId, environmentId: source.environmentId, secretId: source.secretId },
      ended: endedBy === null ? null : { by: endedBy, at: endedAt!, reason: String((JSON.parse(endMetadata!) as { reason?: unknown }).reason ?? 'broken') },
    }];
  });
  // A row edited to name other environments than its seal: those its seal names, looked up.
  const unknown = sealed.flatMap((row) => [row.holder.environmentId, row.source.environmentId]).filter((id) => !slugs.has(id));
  for (const [id, slug] of await environmentSlugs(db, unknown)) slugs.set(id, slug);
  return sealed.map((row) => ({
    ...row,
    holder: { ...row.holder, environmentSlug: slugs.get(row.holder.environmentId)! },
    source: { ...row.source, environmentSlug: slugs.get(row.source.environmentId)! },
  }));
}

/** A `reference.create` the vault wrote: what makes a reference one. */
function sealing(entry: { author: AnyColumn; action: AnyColumn; decision: AnyColumn }): SQL {
  return and(eq(entry.author, 'vault'), eq(entry.action, 'reference.create'), eq(entry.decision, 'allow'))!;
}

/** The seals of the references made in or into a project, of a source, or by someone: through the log's indexes, `also` among them. */
function sealedBy(db: Queryable, where: { sourceSecretIds?: string[]; projectId?: string; createdBy?: string }) {
  const { auditLog } = tablesOf(db);
  return db.select({ seq: auditLog.seq }).from(auditLog).where(and(
    sealing(auditLog),
    where.projectId === undefined ? undefined : or(eq(auditLog.projectId, where.projectId), also(db, 'projectId', [where.projectId])),
    where.sourceSecretIds === undefined ? undefined : also(db, 'secretId', where.sourceSecretIds),
    where.createdBy === undefined ? undefined : eq(auditLog.actor, where.createdBy),
  ));
}

/** Where each secret is, by path, and whether anything of it is archived; with its current version's id and when it was written. */
export type SecretPlaceRow = {
  id: string;
  key: string;
  projectId: string;
  project: string;
  environmentId: string;
  environment: string;
  archivedAt: Date | null;
  projectArchivedAt: Date | null;
  environmentArchivedAt: Date | null;
  currentVersionId: string | null;
  currentVersion: number;
  currentVersionAt: Date | null;
};

/**
 * These secrets, where they are now, by id: any number of them, a thousand
 * a query, within every engine's bound on a statement's parameters (an
 * offboarding report asks for each secret a member's reads listed).
 */
export async function secretPlaces(db: Queryable, ids: readonly string[]): Promise<Map<string, SecretPlaceRow>> {
  const { secrets } = tablesOf(db);
  const unique = [...new Set(ids)];
  const found = new Map<string, SecretPlaceRow>();
  for (let start = 0; start < unique.length; start += 1000) {
    for (const row of await secretPlaceRows(db, inArray(secrets.id, unique.slice(start, start + 1000)))) found.set(row.id, row);
  }
  return found;
}

/**
 * These versions' numbers and recipes, by id: what a key write recorded in 0.15's log alone names by id (T179). A
 * thousand ids a statement, as `secretPlaces` reads keys: an offboarding report names every version a member ever
 * wrote, and one statement takes no more than 65,534 parameters (review r2 of #490).
 */
export async function versionsOf(db: Queryable, ids: readonly string[]): Promise<Map<string, { version: number; recipe: string | null }>> {
  const { secretVersions } = tablesOf(db);
  const unique = [...new Set(ids)];
  const found = new Map<string, { version: number; recipe: string | null }>();
  for (let start = 0; start < unique.length; start += 1000) {
    const rows = await db.select({ id: secretVersions.id, version: secretVersions.version, recipe: secretVersions.recipe }).from(secretVersions)
      .where(inArray(secretVersions.id, unique.slice(start, start + 1000)));
    for (const { id, version, recipe } of rows) found.set(id, { version, recipe });
  }
  return found;
}

function secretPlaceRows(db: Queryable, where: SQL): Promise<SecretPlaceRow[]> {
  const { secrets, secretVersions, environments, projects } = tablesOf(db);
  return db
    .select({
      id: secrets.id,
      key: secrets.key,
      projectId: secrets.projectId,
      project: projects.slug,
      environmentId: secrets.environmentId,
      environment: environments.slug,
      archivedAt: secrets.archivedAt,
      projectArchivedAt: projects.archivedAt,
      environmentArchivedAt: environments.archivedAt,
      currentVersionId: secrets.currentVersionId,
      currentVersion: secrets.currentVersion,
      currentVersionAt: secretVersions.createdAt,
    })
    .from(secrets)
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .innerJoin(projects, eq(projects.id, secrets.projectId))
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(where);
}

/** Which of these versions are sensitive: what a reference to one reads as. */
export async function sensitiveVersions(db: Queryable, ids: readonly string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const { secretVersions } = tablesOf(db);
  const rows = await db
    .select({ id: secretVersions.id })
    .from(secretVersions)
    .where(and(inArray(secretVersions.id, [...new Set(ids)]), eq(secretVersions.sensitive, true)));
  return new Set(rows.map((row) => row.id));
}

/**
 * Which of these environments hold a sensitive value now: a live key's own
 * current version; or, a live key with no version of its own, the source its
 * newest reference names, whose current version it reads as (R23): so not
 * the source of a reference repointed, given a value of its own or archived
 * since. Each is the environment's own project's to give a service, a
 * reference's as any key held there (R71). A hint for whoever issues a
 * service's credential that will not read them, so a reference broken since
 * still counts: 0.14's log keeps its end in the vault's entry alone
 * (`referenceRows`), 0.15's in `ended_at` too, and the hint reads alike on
 * both.
 *
 * Each goes from the environments' live keys (`secrets_live_idx`) and looks
 * up the rest of a key by id, one subquery a step, which Postgres runs per
 * key and never turns into a join: so as many pages however many keys,
 * versions or references the instance holds elsewhere or archives. As joins
 * (T214), the planner weighed a scan of `secret_references` (no index by
 * the holder's environment), of `secrets` or of `secret_versions` against
 * the lookups, and picked by the statistics of the day.
 */
export async function holdingSensitive(db: Queryable, environmentIds: readonly string[]): Promise<Set<string>> {
  if (environmentIds.length === 0) return new Set();
  const { secrets, secretVersions, secretReferences } = tablesOf(db);
  const ids = [...new Set(environmentIds)];
  const live = and(inArray(secrets.environmentId, ids), isNull(secrets.archivedAt));
  const sensitive = (versionId: SQL | AnyColumn) => sql`(SELECT ${secretVersions.sensitive} FROM ${secretVersions} WHERE ${secretVersions.id} = ${versionId})`;
  // The holder's newest reference's source, ended or not (above).
  const newest = ofNewestReference(db, secrets.id, sql`${secretReferences.sourceSecretId}`);
  // Whether that source's current version is sensitive. `source` names the source's row, so `secrets` in `newest` is
  // still the holder's.
  const sourceSensitive = sql`EXISTS (SELECT 1 FROM ${secrets} source WHERE source.id = ${newest} AND ${sensitive(sql`source.current_version_id`)})`;
  const [own, referred] = await Promise.all([
    db.selectDistinct({ environmentId: secrets.environmentId }).from(secrets).where(and(live, sensitive(secrets.currentVersionId))),
    db.selectDistinct({ environmentId: secrets.environmentId }).from(secrets).where(and(live, isNull(secrets.currentVersionId), sourceSensitive)),
  ]);
  return new Set([...own, ...referred].map((row) => row.environmentId));
}

/** These versions' numbers and envelopes, by id: what a read through a reference opens. */
export async function versionEnvelopes(db: Queryable, ids: readonly string[]): Promise<Map<string, { version: number; envelope: Envelope; sensitive: boolean; plaintext: string | null }>> {
  if (ids.length === 0) return new Map();
  const { secretVersions } = tablesOf(db);
  const rows = await db
    .select({ id: secretVersions.id, version: secretVersions.version, sensitive: secretVersions.sensitive, plaintext: secretVersions.plaintext, ...envelopeColumns(secretVersions) })
    .from(secretVersions)
    .where(inArray(secretVersions.id, [...new Set(ids)]));
  return new Map(rows.map((row) => [row.id, { version: row.version, envelope: envelopeOf(row), sensitive: row.sensitive === true, plaintext: row.plaintext ?? null }]));
}

/** These versions' plain values, by id, for those that are plain: a reference to one is plain too. */
export async function plainVersions(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const { secretVersions } = tablesOf(db);
  const rows = await db
    .select({ id: secretVersions.id, plaintext: secretVersions.plaintext })
    .from(secretVersions)
    .where(and(inArray(secretVersions.id, [...new Set(ids)]), isNotNull(secretVersions.plaintext)));
  return new Map(rows.map((row) => [row.id, row.plaintext!]));
}

// --- the audit log ------------------------------------------------------------

/**
 * The chain head and the database clock, in one statement. Locked, it is
 * where every appender queues, which is what keeps the chain a chain. The
 * clock is the database's, not an application server's, so entries from
 * several servers still order by time (CDR 2024/1774 Art 12(2)(f)).
 */
export async function auditHead(db: Queryable): Promise<{ nextSeq: bigint; headHash: Buffer } | null> {
  const { auditChainHead } = tablesOf(db);
  const [head] = await db
    .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash })
    .from(auditChainHead)
    .limit(1);
  return head ?? null;
}

const auditColumns = (auditLog: Tables['auditLog']) => ({
  seq: auditLog.seq,
  author: auditLog.author,
  keyId: auditLog.keyId,
  occurredAt: auditLog.occurredAt,
  actor: auditLog.actor,
  action: auditLog.action,
  decision: auditLog.decision,
  code: auditLog.code,
  subjectPrincipal: auditLog.subjectPrincipal,
  projectId: auditLog.projectId,
  environmentId: auditLog.environmentId,
  secretId: auditLog.secretId,
  secretVersionId: auditLog.secretVersionId,
  operationId: auditLog.operationId,
  requestId: auditLog.requestId,
  sourceIp: auditLog.sourceIp,
  relatedSeq: auditLog.relatedSeq,
  metadata: auditLog.metadata,
});

/** When an entry happened, as the API shows it. */
function shown<Row extends { occurredAt: number }>(row: Row): Omit<Row, 'occurredAt'> & { occurredAt: string } {
  return { ...row, occurredAt: new Date(row.occurredAt).toISOString() };
}

/** Rows in chain order from `fromSeq`, with every field as it was hashed: a batch of a full check, at most `limit` and `BATCH_BYTES` of metadata. */
export async function auditRange(db: Queryable, fromSeq = 0n, limit = 1000) {
  const { auditLog } = tablesOf(db);
  const batch = await withinBytes(db, gte(auditLog.seq, fromSeq), limit);
  if (batch === null) return [];
  const rows = await db
    .select({ ...auditColumns(auditLog), prevHash: auditLog.prevHash, mac: auditLog.mac, hash: auditLog.hash })
    .from(auditLog)
    .where(and(gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, author: row.author as Author, decision: row.decision as 'allow' | 'deny' }));
}

export type AuditFilter = {
  /**
   * Entries in any of these projects or environments, for a caller who reads
   * only those; in a project, none about the environments of it they do not
   * read (`except`), a protected one whose log their role leaves out.
   */
  within?: { projectIds: string[]; environmentIds: string[]; except?: string[] };
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  /** Entries by any of these actors, as the log stores them: `user:ada@acme.example`. */
  actors?: string[];
  decision?: string;
  /** Entries with none of these actions, filtered here so a page stays full. */
  excludeActions?: readonly string[];
  /** Entries older than this, for paging backwards. */
  beforeSeq?: bigint;
  limit: number;
};

/**
 * The place on the other side of an entry about a reference, `also` in its
 * metadata: the holder for a read of its source, the source for the
 * reference's making and end. Repeats the `audit_log_also_*_idx`
 * expressions and their condition, so that each is read by its index.
 */
function also(db: Queryable, field: 'projectId' | 'environmentId' | 'secretId', ids: readonly string[]): SQL {
  const { auditLog } = tablesOf(db);
  const postgres = dialect.engineOf(db) === 'postgres';
  const present = postgres ? sql`((${auditLog.metadata})::jsonb -> 'also') IS NOT NULL` : sql`json_extract(${auditLog.metadata}, '$.also') IS NOT NULL`;
  const value = postgres
    ? sql`(((${auditLog.metadata})::jsonb -> 'also') ->> ${sql.raw(`'${field}'`)})`
    : sql`json_extract(${auditLog.metadata}, ${sql.raw(`'$.also.${field}'`)})`;
  return and(present, inArray(value, [...ids]))!;
}

/**
 * A read of several secrets at one place that lists one of these among its
 * `secrets`, read there or through it, as a holder (`readsByPlace` in the
 * vault). Its entry names no secret of its own; its place's filters narrow
 * the entries this reads.
 */
function listed(db: Queryable, ids: readonly string[]): SQL {
  const { auditLog } = tablesOf(db);
  const named = (secret: SQL) => or(...ids.map((id) => sql`${secret} = ${id}`))!;
  const among = dialect.engineOf(db) === 'postgres'
    ? sql`EXISTS (SELECT 1 FROM jsonb_array_elements(((${auditLog.metadata})::jsonb -> 'secrets')) AS listed(secret)
        WHERE ${named(sql`(listed.secret ->> 'secretId')`)} OR ${named(sql`((listed.secret -> 'also') ->> 'secretId')`)})`
    : sql`EXISTS (SELECT 1 FROM json_each(${auditLog.metadata}, '$.secrets') AS listed
        WHERE ${named(sql`json_extract(listed.value, '$.secretId')`)} OR ${named(sql`json_extract(listed.value, '$.also.secretId')`)})`;
  return and(eq(auditLog.action, 'secret.read'), isNull(auditLog.secretId), among)!;
}

/**
 * The conditions of `filter`, as a WHERE clause on the log. A place matches
 * the entries about it, and those about a reference into or out of it; a
 * secret, too, the reads of several that list it.
 */
function auditWhere(db: Queryable, filter: Omit<AuditFilter, 'limit'>): SQL | undefined {
  const { auditLog } = tablesOf(db);
  const { within } = filter;
  const columns = { projectId: auditLog.projectId, environmentId: auditLog.environmentId, secretId: auditLog.secretId };
  const at = (field: keyof typeof columns, ids: readonly string[]) =>
    ids.length === 0 ? sql`false` : or(inArray(columns[field], [...ids]), also(db, field, ids));
  return and(
    within === undefined
      ? undefined
      : or(at('projectId', within.projectIds), at('environmentId', within.environmentIds)),
    // An entry about a place left out, as its main place or one it names besides (`also`), is left out with it.
    within?.except === undefined || within.except.length === 0
      ? undefined
      : and(or(isNull(auditLog.environmentId), notInArray(auditLog.environmentId, within.except)), sql`NOT COALESCE(${also(db, 'environmentId', within.except)}, false)`),
    filter.projectId === undefined ? undefined : at('projectId', [filter.projectId]),
    filter.environmentId === undefined ? undefined : at('environmentId', [filter.environmentId]),
    filter.secretId === undefined ? undefined : or(at('secretId', [filter.secretId]), listed(db, [filter.secretId])),
    filter.actors === undefined ? undefined : inArray(auditLog.actor, filter.actors),
    filter.decision === undefined ? undefined : eq(auditLog.decision, filter.decision),
    filter.excludeActions === undefined || filter.excludeActions.length === 0
      ? undefined
      : notInArray(auditLog.action, [...filter.excludeActions]),
    filter.beforeSeq === undefined ? undefined : lt(auditLog.seq, filter.beforeSeq),
  );
}

/**
 * A page of the log, both authors, newest first, with the slugs of the
 * places each entry names and the key of its secret: up to `limit` entries,
 * fewer where they list more than a page holds (`withinBytes`). `more`
 * when older entries may match: the page was full, or cut short.
 */
export async function auditPage(db: Queryable, filter: AuditFilter) {
  const { auditLog, projects, environments, secrets } = tablesOf(db);
  const where = auditWhere(db, filter);
  const page = await withinBytes(db, where, filter.limit, 'desc');
  if (page === null) return { rows: [], more: false };
  const rows = await db
    .select({ ...auditColumns(auditLog), project: projects.slug, environment: environments.slug, key: secrets.key })
    .from(auditLog)
    .leftJoin(projects, eq(projects.id, auditLog.projectId))
    .leftJoin(environments, eq(environments.id, auditLog.environmentId))
    .leftJoin(secrets, eq(secrets.id, auditLog.secretId))
    .where(and(where, lte(auditLog.seq, page.from), gte(auditLog.seq, page.to)))
    .orderBy(desc(auditLog.seq));
  return { rows: rows.map(shown), more: page.cut || page.count === filter.limit };
}

/** The newest of one author's allowed entries of `action`, with the database's clock beside it. */
function newestEntry(db: Queryable, author: 'app' | 'vault', action: string) {
  const { auditLog } = tablesOf(db);
  return db
    .select({ seq: auditLog.seq, occurredAt: auditLog.occurredAt, metadata: auditLog.metadata, now: clockMillis(db) })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), eq(auditLog.decision, 'allow')))
    .orderBy(desc(auditLog.seq))
    .limit(1);
}

/**
 * The newest checkpoint the vault signed: its newest `audit.checkpoint`,
 * whose signature whoever shows it checks with the vault's public key.
 */
export async function latestCheckpoint(db: Queryable): Promise<Checkpoint | null> {
  const [row] = await newestEntry(db, 'vault', 'audit.checkpoint');
  return row === undefined ? null : (JSON.parse(row.metadata) as Checkpoint);
}

/** The hash of entry `seq`, hex, or null when there is none. */
export async function auditHashAt(db: Queryable, seq: bigint): Promise<string | null> {
  const { auditLog } = tablesOf(db);
  const [row] = await db.select({ hash: auditLog.hash }).from(auditLog).where(eq(auditLog.seq, seq));
  return row?.hash.toString('hex') ?? null;
}

/**
 * The vault's newest checkpoint that keeps a tally, and its entry: one
 * written since 0.10.1, which names the last entry of the prefix it signs
 * as related. A verification goes on from it.
 */
export async function latestTallied(db: Queryable): Promise<{ entry: bigint; checkpoint: Signed | null } | null> {
  const [row] = await talliedCheckpoints(db).orderBy(desc(tablesOf(db).auditLog.seq)).limit(1);
  return row === undefined ? null : { entry: row.seq, checkpoint: signedIn(row.metadata) };
}

/**
 * The vault's checkpoint at entry `seq`, if one that keeps a tally is
 * there, with its entry's hash: null for its prefix if it names none.
 */
export async function talliedAt(db: Queryable, seq: bigint): Promise<{ checkpoint: Signed | null; hash: string } | null> {
  const [row] = await talliedCheckpoints(db, eq(tablesOf(db).auditLog.seq, seq));
  return row === undefined ? null : { checkpoint: signedIn(row.metadata), hash: row.hash.toString('hex') };
}

/** The prefix a checkpoint names: its last entry and that entry's hash. */
export type Signed = { seq: number; hash: string };

/**
 * What a checkpoint's entry says it signed, or null when it says nothing
 * that could be: the app reads it before the vault checks the entry by its
 * MAC, and the vault names what is wrong with it.
 */
function signedIn(metadata: string): Signed | null {
  const read = JSON.parse(metadata) as unknown;
  if (typeof read !== 'object' || read === null) return null;
  const { seq, hash } = read as { seq?: unknown; hash?: unknown };
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0 || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) return null;
  return { seq, hash };
}

/** Up to `limit` of the vault's checkpoints that keep a tally after entry `after`, oldest first: each one's entry, and the last entry it signs. */
export async function talliedAfter(db: Queryable, after: bigint, limit: number): Promise<{ entry: bigint; signs: bigint }[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ entry: auditLog.seq, signs: auditLog.relatedSeq })
    .from(auditLog)
    .where(and(...talliedWhere(db), gt(auditLog.seq, after)))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return rows.map(({ entry, signs }) => ({ entry, signs: signs! }));
}

function talliedWhere(db: Queryable) {
  const { auditLog } = tablesOf(db);
  return [eq(auditLog.author, 'vault'), eq(auditLog.action, 'audit.checkpoint'), eq(auditLog.decision, 'allow'), isNotNull(auditLog.relatedSeq)];
}

function talliedCheckpoints(db: Queryable, where?: SQL) {
  const { auditLog } = tablesOf(db);
  return db.select({ seq: auditLog.seq, metadata: auditLog.metadata, hash: auditLog.hash }).from(auditLog).where(and(...talliedWhere(db), where));
}

/**
 * How many entries of each of `actions` match `filter`, but for its
 * exclusions and limit, from `fromSeq` on: one grouped count. Both authors
 * are named so that the log's (author, action, seq) index serves it, a
 * range per action, without reading the entries themselves when nothing
 * else is filtered on.
 */
export async function auditActionCounts(
  db: Queryable,
  filter: AuditFilter,
  actions: readonly string[],
  fromSeq?: bigint,
): Promise<{ action: string; count: number }[]> {
  const { auditLog } = tablesOf(db);
  return db
    .select({ action: auditLog.action, count: count() })
    .from(auditLog)
    .where(
      and(
        inArray(auditLog.author, ['app', 'vault']),
        inArray(auditLog.action, [...actions]),
        fromSeq === undefined ? undefined : gte(auditLog.seq, fromSeq),
        auditWhere(db, { ...filter, excludeActions: undefined }),
      ),
    )
    .groupBy(auditLog.action);
}

/**
 * A key write's writes, held to the vault's read (T179 PR 3; `heldWrite` in api/secrets.ts), each left to `later`, so
 * that they go with what its transaction asks next, its COMMIT at the latest, under one Sync: its credential's last
 * use first, when `verify` left it to the request; then the hold (`hold_inputs`, migration 0061: the issue lock and the
 * fence, then the vault's read again, `coffre_moved` unless it reads as decided); then each new key's row, the
 * versions and each key's current version. Postgres only, as the vault's read is.
 *
 * The credential's row before the issue lock and the fence, as `issue_token` and `revoke_credential` take it
 * (formal/WriteLocks.tla, TouchFirst): after them, the write would hold the issue lock and wait for an issue's shared
 * hold on the row, that issue queued for the issue lock behind the checkpointer's barrier, which waits for the
 * write's: a cycle Postgres breaks only after `deadlock_timeout`, the fence held exclusive and every use waiting.
 */
export function heldWrites(
  tx: Transaction,
  write: {
    hold: { tokenHash: Buffer; project: string; environment: string; keys: readonly string[]; digest: Buffer };
    made: readonly { id: string; projectId: string; environmentId: string; key: string }[];
    versions: readonly NewRow<typeof schema.secretVersions>[];
    touched: { credential: string; at: Date; ip: string | null } | null;
  },
): void {
  const { secrets, secretVersions, credentials } = tablesOf(tx);
  const { hold } = write;
  if (write.touched !== null) later(tx, tx.update(credentials).set({ lastUsedAt: write.touched.at, lastUsedIp: write.touched.ip }).where(eq(credentials.id, write.touched.credential)));
  later(tx, sql`SELECT hold_inputs(${hold.tokenHash}::bytea, ${hold.project}::text, ${hold.environment}::text, ${sql.param([...hold.keys])}::text[], ${hold.digest}::bytea)`);
  if (write.made.length > 0) later(tx, tx.insert(secrets).values([...write.made]));
  if (write.versions.length > 0) later(tx, tx.insert(secretVersions).values([...write.versions]));
  const now = new Date();
  for (const version of write.versions) {
    later(tx, tx.update(secrets).set({ currentVersionId: version.id!, currentVersion: version.version, updatedAt: now }).where(eq(secrets.id, version.secretId)));
  }
}


import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

/**
 * The audit page's statements (docs/design/0.16.md, "Pages"): the places a
 * page is about, a stretch of the log, and the tiles that prove what it
 * shows. Read as they are: the page proves each entry it shows against the
 * head the vault vouched for, and the places only scope and name what it
 * lists.
 */

/** An entry of `log` as stored: its place in the log's order, its tree and its place there, and its body, which its hash covers. */
export type LogRow = { seq: number; kept: boolean; leaf: number; body: string };

/** An environment as a permission check names it, with the one it is a config of or inherits from. */
export type LogEnvironment = { id: string; projectId: string; slug: string; protected: boolean; owner: string | null; parent: { id: string; slug: string; protected: boolean } | null };

/** A project's places, deletions' tombstones included: an entry about one stays as readable as the place was. */
export type LogPlaces = { projects: Map<string, string>; environments: Map<string, LogEnvironment> };

/**
 * The places a page is about, in one statement: the project `slug` names,
 * and those `within` names by id (every one for null), each with every
 * environment. With `key`,
 * the ids of every secret of that key in the named project, archived and
 * deleted ones too, by environment: a path to a key reads the log of each.
 */
export async function logPlaces(db: Queryable, at: { slug: string; key?: string; within?: readonly string[] | null } | { within: readonly string[] | null }): Promise<LogPlaces & { secrets: { id: string; environmentId: string }[] }> {
  const within = at.within === undefined ? null : at.within === null ? sql`true` : sql`p.id = ANY(${sql.param([...at.within])}::uuid[])`;
  const named = 'slug' in at ? sql`p.slug = ${at.slug}` : null;
  const where = named === null ? within! : within === null ? named : sql`(${named} OR ${within})`;
  const keyed = 'slug' in at && at.key !== undefined
    ? sql`UNION ALL SELECT s.project_id::text, NULL, s.environment_id::text, NULL, NULL, NULL, NULL, NULL, NULL, s.id::text FROM secrets s WHERE s.project_id IN (SELECT id FROM projects WHERE slug = ${at.slug}) AND s.key = ${at.key}`
    : sql``;
  const rows = await rowsOf<{ project_id: string; project: string | null; id: string | null; slug: string | null; protected: boolean | null; owner: string | null; parent_id: string | null; parent_slug: string | null; parent_protected: boolean | null; secret: string | null }>(
    db,
    sql`
      SELECT p.id::text AS project_id, p.slug AS project, e.id::text AS id, e.slug, e.protected, e.owner,
        parent.id::text AS parent_id, parent.slug AS parent_slug, parent.protected AS parent_protected, NULL AS secret
      FROM projects p
      LEFT JOIN environments e ON e.project_id = p.id
      LEFT JOIN environments parent ON parent.id = e.parent_id
      WHERE ${where}
      ${keyed}`,
  );
  const found: LogPlaces & { secrets: { id: string; environmentId: string }[] } = { projects: new Map(), environments: new Map(), secrets: [] };
  for (const row of rows) {
    if (row.secret !== null) {
      found.secrets.push({ id: row.secret, environmentId: row.id! });
      continue;
    }
    found.projects.set(row.project_id, row.project!);
    if (row.id === null) continue;
    const parent = row.parent_id === null ? null : { id: row.parent_id, slug: row.parent_slug!, protected: row.parent_protected! };
    found.environments.set(row.id, { id: row.id, projectId: row.project_id, slug: row.slug!, protected: row.protected!, owner: row.owner, parent });
  }
  return found;
}

/**
 * The most objects a page reads `log_index` by. Each is one index probe and
 * one subquery of the statement, which Postgres nests: at ten thousand it
 * runs out of stack. A page about more reads the log itself.
 */
export const MOST_OBJECTS = 1000;

/**
 * How many index rows the merge reads for each entry it keeps: an entry is
 * in the index under every object it mentions, and a page's objects are a
 * project's and its environments', which an entry about an environment
 * both mentions.
 */
const COPIES = 2;

/** A stretch of the log, newest first, and whether it stopped before the end of what it reads. */
export type Stretch = { rows: LogRow[]; more: boolean };

/**
 * A stretch of the log, newest first: up to `rows` entries at or below
 * `below`. From `log` itself, by its key; or, for `objects`, from
 * `log_index` (`stretchOf`). An entry that mentions two of them comes once.
 */
export async function logStretch(db: Queryable, at: { objects: readonly string[] | null; below: number | null; rows: number }): Promise<Stretch> {
  const { objects, rows } = at;
  if (objects !== null && objects.length === 0) return { rows: [], more: false };
  const read = await rowsOf<LogRow & { merged: number }>(db, stretchOf(at));
  const more = read.length === rows || (objects !== null && read[0]?.merged === rows * COPIES);
  return { rows: read.map(({ merged: _, ...row }) => row), more };
}

/**
 * `logStretch`'s statement. For `objects`, each one's newest `rows`, merged
 * newest first under a `LIMIT` of `COPIES` × `rows`: what it returns is
 * bounded whatever the plan, what it reads is the plan Postgres picks. Where
 * the objects hold more than the merge takes, it streams each one's from its
 * index and stops with the merge: `COPIES` × `rows` index rows and one more
 * per object, however long the log. Where its statistics say they hold about
 * what the merge takes, it may sort each one's instead, which reads all the
 * object holds below `below`: ten environments of 300 entries each read
 * 3,000 for a merge of 2,000. It reads more than that only as far as its
 * statistics are wrong: a table grown seventeenfold since its last `ANALYZE`
 * still streamed, Postgres scaling its counts by the table's size
 * (audit.test.ts holds both plans). Only then does it drop an entry two
 * objects share, from those it read. A `DISTINCT` over the merge would read
 * the same, but Postgres plans it as a hash of every object's `rows` once
 * the objects are a few dozen: 210 objects at a thousand rows, 210,000 index
 * rows in 175 ms, where this reads 2,210 in 16 ms; and without each object's
 * `LIMIT`, it sorts them all, 60,000 rows where this reads 2,199 (drive:
 * W419-plans/audit-stretch-explain.txt). `merged` says how many the merge
 * read, for `more`: fewer than it may, and it reached the end.
 */
export function stretchOf(at: { objects: readonly string[] | null; below: number | null; rows: number }): SQL {
  const { objects, below, rows } = at;
  if (objects === null) {
    const where = below === null ? sql`` : sql`WHERE l.seq <= ${below}`;
    // By the column, not the number it is read as: the key's order, read backwards.
    return sql`SELECT l.seq::float8 AS seq, l.kept, l.leaf::float8 AS leaf, l.body, 0 AS merged FROM log l ${where} ORDER BY l.seq DESC LIMIT ${rows}`;
  }
  const where = below === null ? sql`` : sql`AND seq <= ${below}`;
  const each: SQL[] = objects.map((object) => sql`(SELECT seq FROM log_index WHERE object = ${object} ${where} ORDER BY seq DESC LIMIT ${rows})`);
  return sql`
    WITH merged AS MATERIALIZED (SELECT seq FROM (${sql.join(each, sql` UNION ALL `)}) each ORDER BY seq DESC LIMIT ${rows * COPIES})
    SELECT l.seq::float8 AS seq, l.kept, l.leaf::float8 AS leaf, l.body, (SELECT count(*) FROM merged)::int AS merged
    FROM (SELECT DISTINCT seq FROM merged ORDER BY seq DESC LIMIT ${rows}) found
    JOIN log l ON l.seq = found.seq
    ORDER BY l.seq DESC`;
}

/** A tile of a tree's hashes, by its level and its number (`@coffre/core/log`). */
export type TileAt = { kept: boolean; level: number; index: number };

/**
 * What proves and names a page's entries, in one statement: the tiles, as
 * stored, and the names of the projects, environments, secrets and
 * credentials its entries mention, by id; and for each credential in
 * `runs`, the first entry that names it, which for a CI run's is its
 * exchange, whose claims say the run once the tree proves it. Ids are
 * checked as UUIDs before: a body names what it likes.
 */
export async function logProofs(
  db: Queryable,
  tiles: readonly TileAt[],
  ids: { projects: readonly string[]; environments: readonly string[]; secrets: readonly string[]; credentials: readonly string[]; runs: readonly string[] },
): Promise<{ tiles: { kept: Map<string, Buffer>; aging: Map<string, Buffer> }; projects: Map<string, string>; environments: Map<string, { slug: string; projectId: string }>; secrets: Map<string, string>; credentials: Map<string, { kind: string; label: string | null }>; firsts: Map<string, LogRow> }> {
  const list = (values: readonly string[]) => sql`ANY(${sql.param([...values])}::uuid[])`;
  const rows = await rowsOf<{ kind: 'tile' | 'project' | 'environment' | 'secret' | 'credential' | 'first'; kept: boolean | null; level: number | null; number: number | null; hashes: Buffer | null; id: string | null; name: string | null; more: string | null; leaf: number | null }>(
    db,
    sql`
      SELECT 'tile' AS kind, t.kept, t.level::int AS level, t.number::float8 AS number, t.hashes, NULL AS id, NULL AS name, NULL AS more, NULL::float8 AS leaf FROM log_tiles t WHERE ${tiled(tiles)}
      UNION ALL SELECT 'project', NULL, NULL, NULL, NULL, p.id::text, p.slug, NULL, NULL FROM projects p WHERE p.id = ${list(ids.projects)}
      UNION ALL SELECT 'environment', NULL, NULL, NULL, NULL, e.id::text, e.slug, e.project_id::text, NULL FROM environments e WHERE e.id = ${list(ids.environments)}
      UNION ALL SELECT 'secret', NULL, NULL, NULL, NULL, s.id::text, s.key, NULL, NULL FROM secrets s WHERE s.id = ${list(ids.secrets)}
      UNION ALL SELECT 'credential', NULL, NULL, NULL, NULL, c.id::text, c.label, c.kind, NULL FROM credentials c WHERE c.id = ${list(ids.credentials)}
      UNION ALL SELECT 'first', l.kept, NULL, l.seq::float8, NULL, r.id::text, NULL, l.body, l.leaf::float8
        FROM unnest(${sql.param([...ids.runs])}::uuid[]) AS r(id)
        JOIN log l ON l.seq = (SELECT min(x.seq) FROM log_index x WHERE x.object = 'credential:' || r.id::text)`,
  );
  const found = { tiles: { kept: new Map<string, Buffer>(), aging: new Map<string, Buffer>() }, projects: new Map<string, string>(), environments: new Map<string, { slug: string; projectId: string }>(), secrets: new Map<string, string>(), credentials: new Map<string, { kind: string; label: string | null }>(), firsts: new Map<string, LogRow>() };
  for (const row of rows) {
    if (row.kind === 'tile') found.tiles[row.kept! ? 'kept' : 'aging'].set(`${row.level}/${row.number}`, Buffer.from(row.hashes!));
    else if (row.kind === 'project') found.projects.set(row.id!, row.name!);
    else if (row.kind === 'environment') found.environments.set(row.id!, { slug: row.name!, projectId: row.more! });
    else if (row.kind === 'secret') found.secrets.set(row.id!, row.name!);
    else if (row.kind === 'first') found.firsts.set(row.id!, { seq: row.number!, kept: row.kept!, leaf: row.leaf!, body: row.more! });
    else found.credentials.set(row.id!, { kind: row.more!, label: row.name });
  }
  return found;
}

/** Tiles the page's own read lacked: a run's exchange, far below the page, proves up paths of its own. */
export async function logTiles(db: Queryable, tiles: readonly TileAt[]): Promise<{ kept: Map<string, Buffer>; aging: Map<string, Buffer> }> {
  const rows = await rowsOf<{ kept: boolean; level: number; number: number; hashes: Buffer }>(db, sql`SELECT t.kept, t.level::int AS level, t.number::float8 AS number, t.hashes FROM log_tiles t WHERE ${tiled(tiles)}`);
  const found = { kept: new Map<string, Buffer>(), aging: new Map<string, Buffer>() };
  for (const row of rows) found[row.kept ? 'kept' : 'aging'].set(`${row.level}/${row.number}`, Buffer.from(row.hashes));
  return found;
}

function tiled(tiles: readonly TileAt[]): SQL {
  return tiles.length === 0 ? sql`false` : sql`(t.kept, t.level, t.number) IN (${sql.join(tiles.map(({ kept, level, index }) => sql`(${kept}, ${level}, ${index})`), sql`, `)})`;
}

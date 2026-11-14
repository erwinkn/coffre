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
 * or those `within` names by id (every one for null), each with every
 * environment. With `key`,
 * the ids of every secret of that key in the named project, archived and
 * deleted ones too, by environment: a path to a key reads the log of each.
 */
export async function logPlaces(db: Queryable, at: { slug: string; key?: string } | { within: readonly string[] | null }): Promise<LogPlaces & { secrets: { id: string; environmentId: string }[] }> {
  const where = 'slug' in at ? sql`p.slug = ${at.slug}` : at.within === null ? sql`true` : sql`p.id = ANY(${sql.param([...at.within])}::uuid[])`;
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
 * A stretch of the log, newest first: up to `rows` entries at or below
 * `before`, the entry at `before` included when it is there (the page
 * above's last, for its holes to meet this page's). From `log` itself, by
 * its key; or, for `objects`, from `log_index`, the newest `rows` of each
 * object merged, each one index probe and a walk back, so the statement
 * reads about `rows` index rows and one per object, however long the log.
 * An entry that mentions two of them comes once.
 */
export async function logStretch(db: Queryable, at: { objects: readonly string[] | null; before: number | null; rows: number }): Promise<LogRow[]> {
  const { objects, before, rows } = at;
  if (objects === null) {
    const below = before === null ? sql`` : sql`WHERE l.seq <= ${before}`;
    // By the column, not the number it is read as: the key's order, read backwards.
    return rowsOf<LogRow>(db, sql`SELECT l.seq::float8 AS seq, l.kept, l.leaf::float8 AS leaf, l.body FROM log l ${below} ORDER BY l.seq DESC LIMIT ${rows}`);
  }
  if (objects.length === 0) return [];
  const below = before === null ? sql`` : sql`AND seq < ${before}`;
  // Each object's newest, merged: Postgres reads them as one Merge Append and stops at `rows`.
  const each: SQL[] = objects.map((object) => sql`(SELECT seq FROM log_index WHERE object = ${object} ${below} ORDER BY seq DESC LIMIT ${rows})`);
  return rowsOf<LogRow>(
    db,
    sql`
      SELECT l.seq::float8 AS seq, l.kept, l.leaf::float8 AS leaf, l.body
      FROM (SELECT DISTINCT seq FROM (SELECT seq FROM (${sql.join(each, sql` UNION ALL `)}) each ORDER BY seq DESC LIMIT ${rows}) newest) found
      JOIN log l ON l.seq = found.seq
      ORDER BY l.seq DESC`,
  );
}

/** A tile of a tree's hashes, by its level and its number (`@coffre/core/log`). */
export type TileAt = { kept: boolean; level: number; index: number };

/**
 * What proves and names a page's entries, in one statement: the tiles, as
 * stored, and the names of the projects, environments, secrets and
 * credentials its entries mention, by id. Ids are checked as UUIDs before:
 * a body names what it likes.
 */
export async function logProofs(
  db: Queryable,
  tiles: readonly TileAt[],
  ids: { projects: readonly string[]; environments: readonly string[]; secrets: readonly string[]; credentials: readonly string[] },
): Promise<{ tiles: { kept: Map<string, Buffer>; aging: Map<string, Buffer> }; projects: Map<string, string>; environments: Map<string, { slug: string; projectId: string }>; secrets: Map<string, string>; credentials: Map<string, { kind: string; label: string | null }> }> {
  const tiled = tiles.length === 0 ? sql`false` : sql`(t.kept, t.level, t.number) IN (${sql.join(tiles.map(({ kept, level, index }) => sql`(${kept}, ${level}, ${index})`), sql`, `)})`;
  const list = (values: readonly string[]) => sql`ANY(${sql.param([...values])}::uuid[])`;
  const rows = await rowsOf<{ kind: 'tile' | 'project' | 'environment' | 'secret' | 'credential'; kept: boolean | null; level: number | null; number: number | null; hashes: Buffer | null; id: string | null; name: string | null; more: string | null }>(
    db,
    sql`
      SELECT 'tile' AS kind, t.kept, t.level::int AS level, t.number::float8 AS number, t.hashes, NULL AS id, NULL AS name, NULL AS more FROM log_tiles t WHERE ${tiled}
      UNION ALL SELECT 'project', NULL, NULL, NULL, NULL, p.id::text, p.slug, NULL FROM projects p WHERE p.id = ${list(ids.projects)}
      UNION ALL SELECT 'environment', NULL, NULL, NULL, NULL, e.id::text, e.slug, e.project_id::text FROM environments e WHERE e.id = ${list(ids.environments)}
      UNION ALL SELECT 'secret', NULL, NULL, NULL, NULL, s.id::text, s.key, NULL FROM secrets s WHERE s.id = ${list(ids.secrets)}
      UNION ALL SELECT 'credential', NULL, NULL, NULL, NULL, c.id::text, c.label, c.kind FROM credentials c WHERE c.id = ${list(ids.credentials)}`,
  );
  const found = { tiles: { kept: new Map<string, Buffer>(), aging: new Map<string, Buffer>() }, projects: new Map<string, string>(), environments: new Map<string, { slug: string; projectId: string }>(), secrets: new Map<string, string>(), credentials: new Map<string, { kind: string; label: string | null }>() };
  for (const row of rows) {
    if (row.kind === 'tile') found.tiles[row.kept! ? 'kept' : 'aging'].set(`${row.level}/${row.number}`, Buffer.from(row.hashes!));
    else if (row.kind === 'project') found.projects.set(row.id!, row.name!);
    else if (row.kind === 'environment') found.environments.set(row.id!, { slug: row.name!, projectId: row.more! });
    else if (row.kind === 'secret') found.secrets.set(row.id!, row.name!);
    else found.credentials.set(row.id!, { kind: row.more!, label: row.name });
  }
  return found;
}

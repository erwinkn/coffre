import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/** A project with its environments, as a page lists them: no key, no value. `archivedAt` is ISO 8601. */
export type PlaceRow = {
  id: string;
  slug: string;
  archived: boolean;
  archivedAt: string | null;
  /** The folder it is listed in, or null for none. */
  folder: string | null;
  /** `parent`: the environment it inherits from, a personal config's the one it is a config of. */
  environments: { id: string; slug: string; archived: boolean; archivedAt: string | null; protected: boolean; owner: string | null; parent: { id: string; slug: string; archived: boolean; protected: boolean } | null }[];
};

/** A time as the API says it: ISO 8601, whichever way the driver hands it back. */
const iso = (value: Date | string | null): string | null => (value === null ? null : new Date(value).toISOString());

/**
 * The projects `within` names, by id, or every project for null, each with
 * its environments: one statement. A deletion's tombstone is no place. The
 * rows are read as they are, their MACs unchecked: they say what a page
 * lists, and decide no use and no change.
 *
 *   granting  only the projects a grant naming this project role is on,
 *             lapsed or of a membership before a removal too
 *   most      at most one environment past this many, to see there are more
 *             (a project with none is one): the caller refuses past it
 */
export async function places(db: Queryable, within: readonly string[] | null, only: { granting?: string; most?: number } = {}): Promise<PlaceRow[]> {
  const scoped = within === null ? sql`true` : sql`p.id = ANY(${sql.param([...within])}::uuid[])`;
  const granting = only.granting === undefined ? sql`true` : sql`p.id IN (SELECT COALESCE(g.project_id, ge.project_id) FROM grants g LEFT JOIN environments ge ON ge.id = g.environment_id WHERE g.role = ${only.granting})`;
  const most = only.most === undefined ? sql`` : sql` LIMIT ${only.most + 1}`;
  const rows = await rowsOf<{ project_id: string; project: string; project_archived_at: Date | string | null; folder: string | null; id: string | null; slug: string; archived_at: Date | string | null; protected: boolean; owner: string | null; parent_id: string | null; parent_slug: string | null; parent_archived: boolean | null; parent_protected: boolean | null }>(
    db,
    sql`
      SELECT p.id AS project_id, p.slug AS project, p.archived_at AS project_archived_at, p.folder,
        e.id, e.slug, e.archived_at, e.protected, e.owner,
        parent.id AS parent_id, parent.slug AS parent_slug, parent.archived_at IS NOT NULL AS parent_archived, parent.protected AS parent_protected
      FROM projects p
      LEFT JOIN environments e ON e.project_id = p.id AND strpos(e.slug, '~') = 0
      LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
      WHERE ${scoped} AND ${granting} AND strpos(p.slug, '~') = 0
      ORDER BY p.slug, e.slug${most}`,
  );
  const found = new Map<string, PlaceRow>();
  for (const row of rows) {
    let project = found.get(row.project_id);
    if (project === undefined) {
      const archivedAt = iso(row.project_archived_at);
      found.set(row.project_id, (project = { id: row.project_id, slug: row.project, archived: archivedAt !== null, archivedAt, folder: row.folder, environments: [] }));
    }
    if (row.id === null) continue;
    const parent = row.parent_id === null ? null : { id: row.parent_id, slug: row.parent_slug!, archived: row.parent_archived!, protected: row.parent_protected! };
    const archivedAt = iso(row.archived_at);
    project.environments.push({ id: row.id, slug: row.slug, archived: archivedAt !== null, archivedAt, protected: row.protected, owner: row.owner, parent });
  }
  return [...found.values()];
}

/** Environments may inherit through three above them, and a personal config sits one below: as a use reads a chain (`@coffre/vault`'s use.ts). */
const CHAIN = 4;

/**
 * How many keys each of `environments` holds, as a read of it resolves
 * them: its own, and for a fork those it inherits, the nearest live row
 * deciding (an archived one, an override reset, is passed over, as a use
 * passes it), and none past a key the fork dismissed. With, for each of their projects, how many names those
 * of `environments` that are also in `counted` hold between them: the same
 * key in dev and prod is one. One statement, whatever the instance holds;
 * the rows it reads are the keys of those environments and their chains.
 */
export async function keyCounts(db: Queryable, environments: readonly string[], counted: readonly string[]): Promise<{ environments: Map<string, number>; projects: Map<string, number> }> {
  const rows = await rowsOf<{ project_id: string; environment_id: string | null; keys: number; names: number }>(
    db,
    sql`
      WITH RECURSIVE chain (environment_id, project_id, layer, depth) AS (
        SELECT e.id, e.project_id, e.id, 0 FROM environments e WHERE e.id = ANY(${sql.param([...environments])}::uuid[])
        UNION ALL
        SELECT chain.environment_id, chain.project_id, e.parent_id, chain.depth + 1
        FROM chain JOIN environments e ON e.id = chain.layer
        WHERE e.parent_id IS NOT NULL AND chain.depth < ${CHAIN}
      ),
      resolved AS (
        SELECT DISTINCT ON (chain.environment_id, held.key) chain.environment_id, chain.project_id, held.key, held.kind = 0 AS live
        FROM chain CROSS JOIN LATERAL (
          SELECT s.key, 0 AS kind FROM secrets s WHERE s.project_id = chain.project_id AND s.environment_id = chain.layer AND s.archived_at IS NULL
          UNION ALL
          SELECT d.key, 1 FROM dismissed_keys d WHERE d.environment_id = chain.layer AND d.restored_at IS NULL
        ) held
        ORDER BY chain.environment_id, held.key, chain.depth, held.kind
      )
      SELECT project_id, environment_id, count(*) FILTER (WHERE live)::int AS keys,
        count(DISTINCT key) FILTER (WHERE live AND environment_id = ANY(${sql.param([...counted])}::uuid[]))::int AS names
      FROM resolved
      GROUP BY GROUPING SETS ((project_id, environment_id), (project_id))`,
  );
  const counts = { environments: new Map<string, number>(), projects: new Map<string, number>() };
  for (const row of rows) {
    if (row.environment_id === null) counts.projects.set(row.project_id, row.names);
    else counts.environments.set(row.environment_id, row.keys);
  }
  return counts;
}

/** A personal config, as its project's maintainers list it: whose, of what, and its keys by name. */
export type PersonalRow = { owner: string; of: string | null; slug: string; keys: string[]; archived: boolean; createdAt: string };

/**
 * The project of `slug` among `within` (by id, or every one for null), and
 * its personal configs, archived ones too, each with its live keys' names:
 * one statement. Null when there is no such project among them.
 */
export async function personalConfigs(db: Queryable, slug: string, within: readonly string[] | null): Promise<{ id: string; configs: PersonalRow[] } | null> {
  const scoped = within === null ? sql`true` : sql`p.id = ANY(${sql.param([...within])}::uuid[])`;
  const rows = await rowsOf<{ project_id: string; slug: string | null; owner: string | null; of: string | null; archived: boolean | null; created_at: Date | string | null; keys: string[] | null }>(
    db,
    sql`
      SELECT p.id AS project_id, e.slug, e.owner, parent.slug AS of, e.archived_at IS NOT NULL AS archived, e.created_at,
        (SELECT array_agg(s.key ORDER BY s.key) FROM secrets s WHERE s.project_id = p.id AND s.environment_id = e.id AND s.archived_at IS NULL) AS keys
      FROM projects p
      LEFT JOIN environments e ON e.project_id = p.id AND e.owner IS NOT NULL AND strpos(e.slug, '~') = 0
      LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
      WHERE p.slug = ${slug} AND ${scoped}
      ORDER BY parent.slug, e.owner`,
  );
  if (rows.length === 0) return null;
  return {
    id: rows[0]!.project_id,
    configs: rows.flatMap((row) => (row.slug === null ? [] : [{ owner: row.owner!, of: row.of, slug: row.slug, keys: row.keys ?? [], archived: row.archived!, createdAt: iso(row.created_at)! }])),
  };
}

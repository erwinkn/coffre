import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/** A project with its environments, as a page lists them: no key, no value. */
export type PlaceRow = {
  id: string;
  slug: string;
  archived: boolean;
  /** `parent`: the environment it inherits from, a personal config's the one it is a config of. */
  environments: { id: string; slug: string; archived: boolean; protected: boolean; owner: string | null; parent: { id: string; slug: string; archived: boolean; protected: boolean } | null }[];
};

/**
 * The projects `within` names, by id, or every project for null, each with
 * its environments: one statement. A deletion's tombstone is no place. The
 * rows are read as they are, their MACs unchecked: they say what a page
 * lists, and decide no use and no change.
 */
export async function places(db: Queryable, within: readonly string[] | null): Promise<PlaceRow[]> {
  const scoped = within === null ? sql`true` : sql`p.id = ANY(${sql.param([...within])}::uuid[])`;
  const rows = await rowsOf<{ project_id: string; project: string; project_archived: boolean; id: string | null; slug: string; archived: boolean; protected: boolean; owner: string | null; parent_id: string | null; parent_slug: string | null; parent_archived: boolean | null; parent_protected: boolean | null }>(
    db,
    sql`
      SELECT p.id AS project_id, p.slug AS project, p.archived_at IS NOT NULL AS project_archived,
        e.id, e.slug, e.archived_at IS NOT NULL AS archived, e.protected, e.owner,
        parent.id AS parent_id, parent.slug AS parent_slug, parent.archived_at IS NOT NULL AS parent_archived, parent.protected AS parent_protected
      FROM projects p
      LEFT JOIN environments e ON e.project_id = p.id AND strpos(e.slug, '~') = 0
      LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
      WHERE ${scoped} AND strpos(p.slug, '~') = 0
      ORDER BY p.slug, e.slug`,
  );
  const found = new Map<string, PlaceRow>();
  for (const row of rows) {
    let project = found.get(row.project_id);
    if (project === undefined) found.set(row.project_id, (project = { id: row.project_id, slug: row.project, archived: row.project_archived, environments: [] }));
    if (row.id === null) continue;
    const parent = row.parent_id === null ? null : { id: row.parent_id, slug: row.parent_slug!, archived: row.parent_archived!, protected: row.parent_protected! };
    project.environments.push({ id: row.id, slug: row.slug, archived: row.archived, protected: row.protected, owner: row.owner, parent });
  }
  return [...found.values()];
}

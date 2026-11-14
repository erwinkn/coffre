import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * The instance's roles and settings as its pages show them. The rows are
 * read as they are, their MACs unchecked: they say what a page lists, and
 * decide no use and no change.
 */

/** A role as its row defines it. `instance` tells an instance role from a project role, whose ids overlap. */
export type RoleRow = { instance: boolean; id: string; name: string; description: string; permissions: string[]; protected: string[] };

/**
 * Every role's row, with how many grants name each project role, lapsed,
 * of a membership before a removal, or on a place gone, since any of them
 * refuses deleting it; and how many active people hold each instance role.
 * One statement: the roles, and the grants and members counted by role.
 */
export async function roleRows(db: Queryable): Promise<{ roles: RoleRow[]; granted: Record<string, number>; people: Record<string, number> }> {
  const [row] = await rowsOf<{ roles: RoleRow[] | null; granted: Record<string, number> | null; people: Record<string, number> | null }>(
    db,
    sql`
      SELECT
        (SELECT json_agg(json_build_object('instance', r.instance, 'id', r.id, 'name', r.name, 'description', r.description, 'permissions', r.permissions, 'protected', r.protected)
          ORDER BY r.instance, r.id) FROM roles r) AS roles,
        (SELECT json_object_agg(g.role, g.n) FROM (SELECT role, count(*) AS n FROM grants GROUP BY role) g) AS granted,
        (SELECT json_object_agg(m.role, m.n) FROM (SELECT role, count(*) AS n FROM principals WHERE status = 'active' AND id LIKE 'user:%' GROUP BY role) m) AS people`,
  );
  return { roles: row?.roles ?? [], granted: row?.granted ?? {}, people: row?.people ?? {} };
}

/**
 * What weighing a change to one role reads of the roles: every role's row,
 * at most one past `most`, and how many grants name `role`, a project role,
 * counted as `roleRows` counts them, to one past `most`. One statement.
 */
export async function rolesWeighed(db: Queryable, role: { instance: boolean; id: string }, most: number): Promise<{ roles: RoleRow[]; granted: number }> {
  const [row] = await rowsOf<{ roles: RoleRow[] | null; granted: number | string }>(
    db,
    sql`
      SELECT
        (SELECT json_agg(json_build_object('instance', r.instance, 'id', r.id, 'name', r.name, 'description', r.description, 'permissions', r.permissions, 'protected', r.protected)
          ORDER BY r.instance, r.id) FROM (SELECT * FROM roles ORDER BY instance, id LIMIT ${most + 1}) r) AS roles,
        (SELECT count(*) FROM (SELECT 1 FROM grants WHERE ${!role.instance} AND role = ${role.id} LIMIT ${most + 1}) g) AS granted`,
  );
  return { roles: row?.roles ?? [], granted: Number(row?.granted ?? 0) };
}

/**
 * Where people set up service accounts themselves, as the policy row keeps
 * it (JSON, projects by id), with the slug of each project its text names,
 * by id: a superset of those it lists, which the route picks from. Null
 * when the instance has no policy row. One statement.
 */
export async function settingsRow(db: Queryable): Promise<{ serviceAccounts: string; slugs: Record<string, string> } | null> {
  const [row] = await rowsOf<{ service_accounts: string; slugs: Record<string, string> | null }>(
    db,
    sql`
      SELECT p.service_accounts,
        (SELECT json_object_agg(sp.id, sp.slug) FROM projects sp WHERE strpos(sp.slug, '~') = 0 AND strpos(p.service_accounts, sp.id::text) > 0) AS slugs
      FROM policy p`,
  );
  return row === undefined ? null : { serviceAccounts: row.service_accounts, slugs: row.slugs ?? {} };
}

/**
 * Where people set up service accounts themselves, as the policy row keeps
 * it (JSON, projects by id); null when the instance has no policy row. One
 * statement, of one row.
 */
export async function serviceAccountsSetting(db: Queryable): Promise<string | null> {
  const [row] = await rowsOf<{ service_accounts: string }>(db, sql`SELECT service_accounts FROM policy WHERE only_row`);
  return row?.service_accounts ?? null;
}

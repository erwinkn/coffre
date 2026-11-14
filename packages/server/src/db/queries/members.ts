import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { PlaceRow } from './places.ts';

/**
 * A member as the members' pages list them: their row, and the grants of
 * theirs the read took in. The rows are read as they are, their MACs
 * unchecked: they say what a page lists, and decide no use and no change.
 */
export type MemberRow = {
  /** `user:<email>` or `token:<name>`. */
  id: string;
  status: 'active' | 'removed';
  role: string;
  /** As the row keeps it, JSON (`Scope`, projects by id); null is everywhere. */
  scope: string | null;
  /** Whether their instance role holds anything where nothing is protected, as the instance's `roles` row defines it. */
  roleHolds: boolean;
  /** The slug of each project the scope's text names, by id: the scope is parsed by the route, which reads only those it names. */
  scopeSlugs: Record<string, string>;
  statusChangedAt: string;
  statusChangedBy: string;
  grants: GrantRow[];
};

/** A live grant, at its place, with its role as the instance defines it: no definition, a role it no longer has. */
export type GrantRow = {
  project: { id: string; slug: string };
  /** Null for a grant on the whole project. */
  environment: PlaceRow['environments'][number] | null;
  role: string;
  definition: { name: string; permissions: string[] } | null;
  expiresAt: string | null;
};

type Raw = {
  id: string;
  status: 'active' | 'removed';
  role: string;
  scope: string | null;
  role_holds: boolean | null;
  scope_slugs: Record<string, string> | null;
  status_changed_at: Date | string;
  status_changed_by: string;
  grants: {
    project_id: string; project: string; role: string; expires_at: string | null; role_name: string | null; permissions: string[] | null;
    environment_id: string | null; environment: string | null; archived_at: string | null; protected: boolean | null; owner: string | null;
    parent_id: string | null; parent: string | null; parent_archived: boolean | null; parent_protected: boolean | null;
  }[] | null;
};

const iso = (value: Date | string): string => new Date(value).toISOString();

/**
 * Members and their live grants, one statement. A live grant is of its
 * member's generation, not ended at `now`, on a place that is there (a
 * deletion's tombstone is none); an archived one is listed. Only an active
 * member's.
 *
 *   member     one member by principal, or anyone
 *   within     the projects whose grants are read, by id; null, every one
 *   project    only grants on this project, by id, and its environments
 *   listed     `all`, every member the rest lets through, with or without
 *              a grant read; `held`, those holding one, and, with `roles`,
 *              anyone whose instance role is not `member`
 *   removed    removed members too, with no grant
 *   scopes     the slugs of the projects each scope names, for whoever
 *              is shown scopes
 */
export async function members(
  db: Queryable,
  query: { member?: string; within: readonly string[] | null; project?: string; listed: 'all' | 'held'; roles?: boolean; removed: boolean; scopes: boolean; now: Date },
): Promise<MemberRow[]> {
  const within = query.within === null ? sql`true` : sql`gp.id = ANY(${sql.param([...query.within])}::uuid[])`;
  const onProject = query.project === undefined ? sql`true` : sql`gp.id = ${query.project}::uuid`;
  const member = query.member === undefined ? sql`true` : sql`m.id = ${query.member}`;
  const status = query.removed ? sql`true` : sql`m.status = 'active'`;
  const listed = query.listed === 'all' ? sql`true` : query.roles === true ? sql`(held.grants IS NOT NULL OR m.role <> 'member')` : sql`held.grants IS NOT NULL`;
  const rows = await rowsOf<Raw>(
    db,
    sql`
      SELECT m.id, m.status, m.role, m.scope, m.status_changed_at, m.status_changed_by,
        cardinality(ir.permissions) > 0 AS role_holds, scoped.slugs AS scope_slugs, held.grants
      FROM principals m
      LEFT JOIN roles ir ON ir.instance AND ir.id = m.role
      LEFT JOIN LATERAL (
        SELECT json_agg(json_build_object(
          'project_id', gp.id, 'project', gp.slug, 'role', g.role, 'expires_at', g.expires_at, 'role_name', r.name, 'permissions', r.permissions,
          'environment_id', e.id, 'environment', e.slug, 'archived_at', e.archived_at, 'protected', e.protected, 'owner', e.owner,
          'parent_id', parent.id, 'parent', parent.slug, 'parent_archived', parent.archived_at IS NOT NULL, 'parent_protected', parent.protected
        ) ORDER BY gp.slug, e.slug NULLS LAST) AS grants
        FROM grants g
        LEFT JOIN environments e ON e.id = g.environment_id
        LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
        JOIN projects gp ON gp.id = COALESCE(g.project_id, e.project_id)
        LEFT JOIN roles r ON NOT r.instance AND r.id = g.role
        WHERE m.status = 'active' AND g.principal = m.id AND g.generation = m.generation
          AND (g.expires_at IS NULL OR g.expires_at > ${query.now.toISOString()}::timestamptz)
          AND (g.environment_id IS NULL OR (e.id IS NOT NULL AND strpos(e.slug, '~') = 0)) AND strpos(gp.slug, '~') = 0
          AND ${within} AND ${onProject}
      ) held ON true
      LEFT JOIN LATERAL (
        -- A scope names its projects by id inside its JSON: the projects whose id it holds, a superset of those it lists, which the route picks from.
        SELECT json_object_agg(sp.id, sp.slug) AS slugs FROM projects sp
        WHERE ${query.scopes ? sql`true` : sql`false`} AND m.scope IS NOT NULL AND strpos(sp.slug, '~') = 0 AND strpos(m.scope, sp.id::text) > 0
      ) scoped ON true
      WHERE ${member} AND ${status} AND ${listed}
      ORDER BY m.id`,
  );
  return rows.map((row) => ({
    id: row.id,
    status: row.status,
    role: row.role,
    scope: row.scope,
    roleHolds: row.role_holds === true,
    scopeSlugs: row.scope_slugs ?? {},
    statusChangedAt: iso(row.status_changed_at),
    statusChangedBy: row.status_changed_by,
    grants: (row.grants ?? []).map((grant) => ({
      project: { id: grant.project_id, slug: grant.project },
      environment: grant.environment_id === null ? null : {
        id: grant.environment_id,
        slug: grant.environment!,
        archived: grant.archived_at !== null,
        archivedAt: grant.archived_at === null ? null : iso(grant.archived_at),
        protected: grant.protected === true,
        owner: grant.owner,
        parent: grant.parent_id === null ? null : { id: grant.parent_id, slug: grant.parent!, archived: grant.parent_archived === true, protected: grant.parent_protected === true },
      },
      role: grant.role,
      definition: grant.role_name === null ? null : { name: grant.role_name, permissions: grant.permissions ?? [] },
      expiresAt: grant.expires_at === null ? null : iso(grant.expires_at),
    })),
  }));
}

/** The project of `slug`, with its environments, as `places` lists one: one statement; null when it is not there, a deletion's tombstone included. */
export async function projectNamed(db: Queryable, slug: string): Promise<PlaceRow | null> {
  const rows = await rowsOf<{ project_id: string; project_archived_at: Date | string | null; folder: string | null; id: string | null; slug: string; archived_at: Date | string | null; protected: boolean; owner: string | null; parent_id: string | null; parent_slug: string | null; parent_archived: boolean | null; parent_protected: boolean | null }>(
    db,
    sql`
      SELECT p.id AS project_id, p.archived_at AS project_archived_at, p.folder,
        e.id, e.slug, e.archived_at, e.protected, e.owner,
        parent.id AS parent_id, parent.slug AS parent_slug, parent.archived_at IS NOT NULL AS parent_archived, parent.protected AS parent_protected
      FROM projects p
      LEFT JOIN environments e ON e.project_id = p.id AND strpos(e.slug, '~') = 0
      LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
      WHERE p.slug = ${slug} AND strpos(p.slug, '~') = 0
      ORDER BY e.slug`,
  );
  const [first] = rows;
  if (first === undefined) return null;
  const at = (value: Date | string | null) => (value === null ? null : iso(value));
  return {
    id: first.project_id,
    slug,
    archived: first.project_archived_at !== null,
    archivedAt: at(first.project_archived_at),
    folder: first.folder,
    environments: rows.flatMap((row) => (row.id === null ? [] : [{
      id: row.id,
      slug: row.slug,
      archived: row.archived_at !== null,
      archivedAt: at(row.archived_at),
      protected: row.protected,
      owner: row.owner,
      parent: row.parent_id === null ? null : { id: row.parent_id, slug: row.parent_slug!, archived: row.parent_archived!, protected: row.parent_protected! },
    }])),
  };
}

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

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
  /** Their instance role as the instance's `roles` row defines it: none, a role it no longer has. */
  roleDefinition: Definition | null;
  /** The slug of each project the scope's text names, by id: the scope is parsed by the route, which reads only those it names. */
  scopeSlugs: Record<string, string>;
  statusChangedAt: string;
  statusChangedBy: string;
  grants: GrantRow[];
  /** A removed member's keys to rotate, counted when the read asked (`removed`); null for anyone active. */
  toRotate: number | null;
};

/** A live grant, at its place, with its role as the instance defines it: no definition, a role it no longer has. */
export type GrantRow = {
  project: { id: string; slug: string };
  /** Null for a grant on the whole project. */
  environment: PlaceRow['environments'][number] | null;
  role: string;
  definition: Definition | null;
  expiresAt: string | null;
};

/** A role as its row defines it: what it holds, and what of that it holds in a protected environment. */
export type Definition = { name: string; permissions: string[]; protected: string[] };

type Raw = {
  id: string;
  status: 'active' | 'removed';
  role: string;
  scope: string | null;
  role_holds: boolean | null;
  role_name: string | null;
  role_permissions: string[] | null;
  role_protected: string[] | null;
  scope_slugs: Record<string, string> | null;
  status_changed_at: Date | string;
  status_changed_by: string;
  to_rotate: number | string | null;
  grants: {
    project_id: string; project: string; role: string; expires_at: string | null; role_name: string | null; permissions: string[] | null; guarded: string[] | null;
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
 *   removed    removed members too, with no grant, and how many keys each
 *              has to rotate (`seenBy`)
 *   scopes     the slugs of the projects each scope names, for whoever
 *              is shown scopes
 *   reaching   only those a role reaches: holding a live grant naming the
 *              project role, or holding the instance role
 *   most       at most one member past this many, and one grant past this
 *              many of each, to see there are more: the caller refuses past it
 */
export async function members(
  db: Queryable,
  query: { member?: string; within: readonly string[] | null; project?: string; listed: 'all' | 'held'; roles?: boolean; removed: boolean; scopes: boolean; reaching?: { instance: boolean; role: string }; most?: number; now: Date },
): Promise<MemberRow[]> {
  const now = sql`${query.now.toISOString()}::timestamptz`;
  const reaching = query.reaching === undefined ? sql`true` : query.reaching.instance ? sql`m.role = ${query.reaching.role}`
    : sql`EXISTS (SELECT 1 FROM grants rg WHERE rg.principal = m.id AND rg.generation = m.generation AND rg.role = ${query.reaching.role} AND (rg.expires_at IS NULL OR rg.expires_at > ${now}))`;
  // Unordered, so the database stops at the limit rather than sorting every grant first; `json_agg` orders what it took.
  const most = query.most === undefined ? sql`` : sql` LIMIT ${query.most + 1}`;
  const members = query.most === undefined ? sql`` : sql` LIMIT ${query.most + 1}`;
  const within = query.within === null ? sql`true` : sql`gp.id = ANY(${sql.param([...query.within])}::uuid[])`;
  const onProject = query.project === undefined ? sql`true` : sql`gp.id = ${query.project}::uuid`;
  const member = query.member === undefined ? sql`true` : sql`m.id = ${query.member}`;
  const status = query.removed ? sql`true` : sql`m.status = 'active'`;
  const listed = query.listed === 'all' ? sql`true` : query.roles === true ? sql`(held.grants IS NOT NULL OR m.role <> 'member')` : sql`held.grants IS NOT NULL`;
  const rows = await rowsOf<Raw>(
    db,
    sql`
      SELECT m.id, m.status, m.role, m.scope, m.status_changed_at, m.status_changed_by,
        cardinality(ir.permissions) > 0 AS role_holds, ir.name AS role_name, ir.permissions AS role_permissions, ir.protected AS role_protected, scoped.slugs AS scope_slugs, held.grants,
        ${query.removed ? sql`CASE WHEN m.status = 'removed' THEN coalesce(rotating.keys, 0) END` : sql`NULL`} AS to_rotate
      FROM principals m
      LEFT JOIN roles ir ON ir.instance AND ir.id = m.role
      LEFT JOIN LATERAL (
        SELECT json_agg(one.grant ORDER BY one.project, one.environment NULLS LAST) AS grants FROM (
          SELECT gp.slug AS project, e.slug AS environment, json_build_object(
            'project_id', gp.id, 'project', gp.slug, 'role', g.role, 'expires_at', g.expires_at, 'role_name', r.name, 'permissions', r.permissions, 'guarded', r.protected,
            'environment_id', e.id, 'environment', e.slug, 'archived_at', e.archived_at, 'protected', e.protected, 'owner', e.owner,
            'parent_id', parent.id, 'parent', parent.slug, 'parent_archived', parent.archived_at IS NOT NULL, 'parent_protected', parent.protected
          ) AS grant
          FROM grants g
          LEFT JOIN environments e ON e.id = g.environment_id
          LEFT JOIN environments parent ON parent.id = e.parent_id AND strpos(parent.slug, '~') = 0
          JOIN projects gp ON gp.id = COALESCE(g.project_id, e.project_id)
          LEFT JOIN roles r ON NOT r.instance AND r.id = g.role
          WHERE m.status = 'active' AND g.principal = m.id AND g.generation = m.generation
            AND (g.expires_at IS NULL OR g.expires_at > ${now})
            AND (g.environment_id IS NULL OR (e.id IS NOT NULL AND strpos(e.slug, '~') = 0)) AND strpos(gp.slug, '~') = 0
            AND ${within} AND ${onProject}${most}
        ) one
      ) held ON true
      LEFT JOIN LATERAL (
        -- A scope names its projects by id inside its JSON: the projects whose id it holds, a superset of those it lists, which the route picks from.
        SELECT json_object_agg(sp.id, sp.slug) AS slugs FROM projects sp
        WHERE ${query.scopes ? sql`true` : sql`false`} AND m.scope IS NOT NULL AND strpos(sp.slug, '~') = 0 AND strpos(m.scope, sp.id::text) > 0
      ) scoped ON true
      ${query.removed ? sql`LEFT JOIN (
        -- The removed members asked about, all at once: one pass over their rows, not one statement a member.
        SELECT seen.principal, count(*) FILTER (WHERE seen.rotate) AS keys FROM (${seenBy(sql`SELECT m.id FROM principals m WHERE m.status = 'removed' AND ${member}`)}) seen GROUP BY seen.principal
      ) rotating ON rotating.principal = m.id` : sql``}
      WHERE ${member} AND ${status} AND ${listed} AND ${reaching}
      ORDER BY m.id${members}`,
  );
  return rows.map((row) => ({
    id: row.id,
    status: row.status,
    role: row.role,
    scope: row.scope,
    roleHolds: row.role_holds === true,
    roleDefinition: row.role_name === null ? null : { name: row.role_name, permissions: row.role_permissions ?? [], protected: row.role_protected ?? [] },
    scopeSlugs: row.scope_slugs ?? {},
    statusChangedAt: iso(row.status_changed_at),
    statusChangedBy: row.status_changed_by,
    toRotate: row.to_rotate === null ? null : Number(row.to_rotate),
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
      definition: grant.role_name === null ? null : { name: grant.role_name, permissions: grant.permissions ?? [], protected: grant.guarded ?? [] },
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

/** The slugs of projects by id, those still there: what a scope the vault answered with names. One statement. */
export async function projectSlugs(db: Queryable, ids: readonly string[]): Promise<Record<string, string>> {
  const rows = await rowsOf<{ id: string; slug: string }>(db, sql`SELECT id, slug FROM projects WHERE id = ANY(${sql.param([...ids])}::uuid[]) AND strpos(slug, '~') = 0`);
  return Object.fromEntries(rows.map((row) => [row.id, row.slug]));
}

/**
 * The live keys some members read or wrote a value of, a row for each
 * member and key, from their own rows alone: their `exposures`, by its
 * key's prefix, and the versions they wrote, by
 * `secret_versions_created_by_idx`. `who` is SQL for the members: one id
 * (a parameter, or a column outside), or a statement listing them, which
 * this reads once for all of them, never a statement each.
 *
 * A key is to rotate (`rotate`) when they know its current value: they
 * last saw the key on or after the date its value was first written to it
 * (`first_written_at`, which a restore copies from its source), or they
 * wrote that value themselves: a version of theirs, not a restore
 * (`created_at = first_written_at`), first wrote it, so on the current
 * value's date. Example: Bo wrote `STRIPE_KEY` v1 on day 1, Ada v2 on day
 * 5, and v4 restores v1 on day 9: Bo knows v4, `wrote`. Had Bo only
 * restored Ada's value, he would not. `at` is the later of the two dates
 * that hold. A key whose value is no longer one they knew is counted as
 * rotated.
 *
 * Both dates are the vault's clock, and a version's date precedes its
 * commit, so a read of it is dated after it: a read's `seen_at`, a minute
 * behind at most, never crosses a value, since the first read of a new
 * version is always marked. Two machines' clocks a few milliseconds apart
 * are the one imprecision.
 *
 * A key archived, or in an environment or project archived or deleted, is
 * none: what reads it comes back with it, and is listed then. A read
 * through a reference records the key it reads, its source. A deleted
 * place's slug holds a `~`, tested with `NOT LIKE`, whose share Postgres
 * reads from the column's statistics: it takes `strpos(…) = 0` to keep one
 * row in 200, and walks every key from projects and environments.
 */
export function seenBy(who: SQL): SQL {
  return sql`
    SELECT t.principal, sp.slug AS project, se.slug AS environment, s.key, s.current_version AS version,
      coalesce(bool_or(t.wrote = c.first_written_at), false) AS wrote,
      coalesce(bool_or(t.seen_at >= c.first_written_at OR t.wrote = c.first_written_at), false) AS rotate,
      max(greatest(CASE WHEN t.seen_at >= c.first_written_at THEN t.seen_at END, CASE WHEN t.wrote = c.first_written_at THEN t.wrote END)) AS at
    FROM (
      SELECT principal, secret_id, seen_at, NULL::timestamptz AS wrote FROM exposures WHERE principal IN (${who})
      UNION ALL
      SELECT created_by, secret_id, NULL, first_written_at FROM secret_versions WHERE created_by IN (${who}) AND created_at = first_written_at
    ) t
    JOIN secrets s ON s.id = t.secret_id
    JOIN secret_versions c ON c.secret_id = s.id AND c.version = s.current_version
    JOIN environments se ON se.id = s.environment_id
    JOIN projects sp ON sp.id = s.project_id
    WHERE s.archived_at IS NULL AND se.archived_at IS NULL AND sp.archived_at IS NULL AND se.slug NOT LIKE '%~%' AND sp.slug NOT LIKE '%~%'
    GROUP BY t.principal, s.id, sp.slug, se.slug, c.first_written_at`;
}

/** A key someone read or wrote a value of, as `seenBy` finds it. */
export type SeenKey = { project: string; environment: string; key: string; version: number; wrote: boolean; rotate: boolean; at: string | null };

/** One member's report, as its one statement reads it. */
export type ReportRow = Omit<MemberRow, 'grants' | 'roleHolds' | 'roleDefinition' | 'toRotate'> & {
  /** What still lets them in, at their generation: live grants, sign-in accounts, and credentials by kind. */
  live: { grants: number; sessions: number; tokens: number; identities: number; apps: number };
  keys: SeenKey[];
  /** Their personal configs: each one's project, the environment it is a config of, and its own slug. */
  personal: { project: string; of: string; slug: string }[];
};

/**
 * What one member holds and has seen: their row, what still lets them in,
 * the live keys they read or wrote (`seenBy`), and their personal configs.
 * One statement, driven from their own rows; null for no such member.
 */
export async function reportOf(db: Queryable, principal: string, now: Date): Promise<ReportRow | null> {
  const at = now.toISOString();
  const [row] = await rowsOf<{
    id: string; status: 'active' | 'removed'; role: string; scope: string | null; scope_slugs: Record<string, string> | null;
    status_changed_at: Date | string; status_changed_by: string;
    grants: number | string; sessions: number | string; tokens: number | string; apps: number | string; identities: number | string;
    keys: (SeenKey & { principal: string })[] | null;
    personal: { project: string; of: string; slug: string }[] | null;
  }>(
    db,
    sql`
      SELECT m.id, m.status, m.role, m.scope, m.status_changed_at, m.status_changed_by, scoped.slugs AS scope_slugs,
        (SELECT count(*) FROM grants g
          LEFT JOIN environments e ON e.id = g.environment_id
          JOIN projects gp ON gp.id = COALESCE(g.project_id, e.project_id)
          WHERE m.status = 'active' AND g.principal = m.id AND g.generation = m.generation
            AND (g.expires_at IS NULL OR g.expires_at > ${at}::timestamptz)
            AND (g.environment_id IS NULL OR (e.id IS NOT NULL AND strpos(e.slug, '~') = 0)) AND strpos(gp.slug, '~') = 0) AS grants,
        held.sessions, held.tokens, held.apps,
        (SELECT count(*) FROM identities i WHERE i.principal = m.id AND i.generation = m.generation AND i.revoked_at IS NULL) AS identities,
        (SELECT json_agg(seen) FROM (${seenBy(sql`m.id`)}) seen) AS keys,
        (SELECT json_agg(json_build_object('project', pp.slug, 'of', parent.slug, 'slug', pe.slug) ORDER BY pp.slug, pe.slug)
          FROM environments pe
          JOIN projects pp ON pp.id = pe.project_id
          JOIN environments parent ON parent.id = pe.parent_id
          WHERE pe.owner = m.id AND strpos(pe.slug, '~') = 0 AND strpos(pp.slug, '~') = 0) AS personal
      FROM principals m
      LEFT JOIN LATERAL (
        SELECT count(*) FILTER (WHERE c.kind IN ('browser', 'cli')) AS sessions,
          count(*) FILTER (WHERE c.kind = 'mcp') AS apps,
          count(*) FILTER (WHERE c.kind NOT IN ('browser', 'cli', 'mcp')) AS tokens
        FROM credentials c
        WHERE c.principal = m.id AND c.generation = m.generation AND c.revoked_at IS NULL AND c.expires_at > ${at}::timestamptz
      ) held ON true
      LEFT JOIN LATERAL (
        SELECT json_object_agg(sp.id, sp.slug) AS slugs FROM projects sp
        WHERE m.scope IS NOT NULL AND strpos(sp.slug, '~') = 0 AND strpos(m.scope, sp.id::text) > 0
      ) scoped ON true
      WHERE m.id = ${principal}`,
  );
  if (row === undefined) return null;
  return {
    id: row.id,
    status: row.status,
    role: row.role,
    scope: row.scope,
    scopeSlugs: row.scope_slugs ?? {},
    statusChangedAt: iso(row.status_changed_at),
    statusChangedBy: row.status_changed_by,
    live: { grants: Number(row.grants), sessions: Number(row.sessions), tokens: Number(row.tokens), identities: Number(row.identities), apps: Number(row.apps) },
    keys: (row.keys ?? []).map(({ principal: _, ...key }) => ({ ...key, at: key.at === null ? null : iso(key.at) })),
    personal: row.personal ?? [],
  };
}

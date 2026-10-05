import { sql, type SQL } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { engineOf } from './dialect.ts';
import { applied } from './schema-version.ts';

/**
 * Grants as `vault_grants` holds them, read and written on the schema of
 * any release since the baseline. The column `environment_slug` came with
 * `0005_instance_grants`, and a release runs on the schema before its own
 * migration until that runs (AGENTS.md, "expand, then contract"). Drizzle
 * names every column it knows in a select or an insert, so these do not use
 * it: a read takes every column the table has, `*`, and an insert names the
 * slug only for a grant that has one, which no database holds before the
 * migration.
 *
 * Only the vault writes grants; the app reads them for its lists.
 */

/**
 * One grant: on a project (`environmentId` null), one of its environments
 * (`projectId` is the environment's project), every project (both ids
 * null), or one environment slug in every project (`environmentSlug`).
 */
export type GrantRow = {
  principal: string;
  projectId: string | null;
  environmentId: string | null;
  environmentSlug: string | null;
  role: string;
  /** Milliseconds since the epoch, or null for no end. */
  expiresAt: number | null;
  grantedAt: number;
  grantedBy: string;
};

/** A row as the driver returns it: Postgres's bigints are strings. */
type Raw = {
  principal: string;
  project_id: string | null;
  environment_id: string | null;
  environment_slug?: string | null;
  environment_project_id: string | null;
  role: string;
  expires_at: number | string | null;
  granted_at: number | string;
  granted_by: string;
};

/**
 * Grants, lapsed ones too unless `liveAt` says when to judge them: one
 * member's, or everyone's; `everyProject`, only those on every project.
 */
export async function readGrants(
  db: Queryable,
  filter: { principal?: string; liveAt?: number; everyProject?: boolean } = {},
): Promise<GrantRow[]> {
  const where: SQL[] = [];
  if (filter.principal !== undefined) where.push(sql`g.principal = ${filter.principal}`);
  if (filter.liveAt !== undefined) where.push(sql`(g.expires_at IS NULL OR g.expires_at > ${filter.liveAt})`);
  if (filter.everyProject === true) where.push(sql`g.project_id IS NULL AND g.environment_id IS NULL`);
  const rows = await rawRows<Raw>(db, sql`
    SELECT g.*, e.project_id AS environment_project_id
    FROM vault_grants g LEFT JOIN environments e ON e.id = g.environment_id
    ${where.length === 0 ? sql`` : sql`WHERE ${sql.join(where, sql` AND `)}`}`);
  return rows.map((row) => ({
    principal: row.principal,
    projectId: row.project_id ?? row.environment_project_id,
    environmentId: row.environment_id,
    environmentSlug: row.environment_slug ?? null,
    role: row.role,
    expiresAt: row.expires_at === null ? null : Number(row.expires_at),
    grantedAt: Number(row.granted_at),
    grantedBy: row.granted_by,
  }));
}

/** Whether the database can hold grants on every project: the migration that lets it has run. */
export function canGrantEveryProject(db: Queryable): Promise<boolean> {
  return applied(db, '0005_instance_grants');
}

/** Add a grant; an environment's row names only the environment. */
export async function insertGrant(db: Queryable, grant: GrantRow): Promise<void> {
  const columns: [string, unknown][] = [
    ['principal', grant.principal],
    ['project_id', grant.environmentId === null ? grant.projectId : null],
    ['environment_id', grant.environmentId],
    ...(grant.environmentSlug === null ? [] : [['environment_slug', grant.environmentSlug] as [string, unknown]]),
    ['role', grant.role],
    ['expires_at', grant.expiresAt],
    ['granted_at', grant.grantedAt],
    ['granted_by', grant.grantedBy],
  ];
  await rawRows(db, sql`
    INSERT INTO vault_grants (${sql.join(columns.map(([name]) => sql.identifier(name)), sql`, `)})
    VALUES (${sql.join(columns.map(([, value]) => sql`${value}`), sql`, `)})`);
}

/** The rows of a statement written out, as the driver returns them, on either engine. */
async function rawRows<Row>(db: Queryable, query: SQL): Promise<Row[]> {
  if (engineOf(db) === 'postgres') return (await db.execute(query)).rows as Row[];
  return (db as unknown as { all<R>(query: SQL): Promise<R[]> }).all<Row>(query);
}

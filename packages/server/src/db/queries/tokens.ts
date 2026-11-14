import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { Definition } from './members.ts';

/**
 * A member's tokens as their list reads them (`GET /members/:member/tokens`),
 * with what says who may read it: the rows as they are, their MACs
 * unchecked. What they show decides nothing; the vault decides each change
 * of a token on its own read.
 */

/** A live token of the member's, its row as stored: `scope` is its JSON, by place id. */
export type TokenRow = {
  id: string;
  kind: string;
  label: string | null;
  hint: string | null;
  scope: string | null;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
};

/**
 * A live grant of a service account's, at its place: `found` when the read
 * found its place's row, `tombstone` when that row is a deletion's.
 */
export type HeldGrant = { projectId: string; environmentId: string | null; environmentSlug: string | null; role: string; definition: Definition | null; found: boolean; tombstone: boolean };

export type MemberTokens = {
  /** Null when no active member has that id. */
  member: null | {
    /** Who admitted them last (`status_changed_by`). */
    admittedBy: string;
    /** A service account's live grants; none read for a person. */
    grants: HeldGrant[];
  };
  /** The instance's setting of where people set service accounts up, JSON, as its row says; null for a person, or with no row. */
  setting: string | null;
  /** Newest first. */
  tokens: TokenRow[];
  /** The slug of each project and environment the tokens' scopes name, by id, those still there. */
  slugs: Record<string, string>;
};

/** A place's id in a scope's JSON, as `JSON.stringify` writes it: one only a UUID matches, so the cast never fails, whatever a row holds. */
const SCOPE_ID = '"(?:projectId|environmentId)":"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"';

/**
 * A member's live tokens, one statement on the credentials' live index: a
 * person's personal tokens and handles; a service account's tokens and its
 * workloads' sessions, but not what a trust binding issued a CI run (it
 * comes and goes with the run). For a service account, what
 * `managesService` weighs: its live grants, with their roles' rows, and the
 * instance's setting. A token is live while its member is active, of its
 * generation, not revoked and not past `at`.
 */
export async function memberTokens(db: Queryable, member: string, at: Date): Promise<MemberTokens> {
  const service = member.startsWith('token:');
  const now = sql`${at.toISOString()}::timestamptz`;
  const rows = await rowsOf<{
    status_changed_by: string | null;
    found: boolean;
    setting: string | null;
    grants: { project_id: string; environment_id: string | null; environment: string | null; found: boolean; tombstone: boolean; role: string; role_name: string | null; permissions: string[] | null; guarded: string[] | null }[] | null;
    tokens: { id: string; kind: string; label: string | null; hint: string | null; scope: string | null; created_at: string; created_by: string; expires_at: string; last_used_at: string | null; last_used_ip: string | null }[] | null;
    slugs: Record<string, string> | null;
  }>(
    db,
    sql`
      WITH m AS (SELECT id, generation, status_changed_by FROM principals WHERE id = ${member} AND status = 'active'),
      live AS (
        SELECT c.* FROM credentials c JOIN m ON c.principal = m.id AND c.generation = m.generation
        WHERE c.revoked_at IS NULL AND c.expires_at > ${now}
          AND (c.kind IN ('personal', 'handle') OR (c.kind = 'service' AND c.created_by NOT LIKE 'binding:%') OR c.kind = 'workload')
      ),
      named AS (SELECT DISTINCT (regexp_matches(scope, ${SCOPE_ID}, 'g'))[1]::uuid AS id FROM live WHERE scope IS NOT NULL)
      SELECT
        (SELECT status_changed_by FROM m) AS status_changed_by,
        EXISTS (SELECT 1 FROM m) AS found,
        (SELECT service_accounts FROM policy WHERE ${service} AND only_row) AS setting,
        (SELECT json_agg(json_build_object(
            'project_id', coalesce(g.project_id, e.project_id), 'environment_id', g.environment_id, 'environment', e.slug,
            'found', CASE WHEN g.environment_id IS NULL THEN p.id IS NOT NULL ELSE e.id IS NOT NULL END,
            'tombstone', strpos(CASE WHEN g.environment_id IS NULL THEN coalesce(p.slug, '') ELSE coalesce(e.slug, '') END, '~') > 0,
            'role', g.role, 'role_name', r.name, 'permissions', r.permissions, 'guarded', r.protected))
          FROM m JOIN grants g ON g.principal = m.id AND g.generation = m.generation
          LEFT JOIN environments e ON e.id = g.environment_id
          LEFT JOIN projects p ON p.id = coalesce(g.project_id, e.project_id)
          LEFT JOIN roles r ON NOT r.instance AND r.id = g.role
          WHERE ${service} AND (g.expires_at IS NULL OR g.expires_at > ${now})) AS grants,
        (SELECT json_agg(json_build_object(
            'id', id, 'kind', kind, 'label', label, 'hint', token_hint, 'scope', scope, 'created_at', created_at, 'created_by', created_by,
            'expires_at', expires_at, 'last_used_at', last_used_at, 'last_used_ip', last_used_ip) ORDER BY created_at DESC, id)
          FROM live) AS tokens,
        (SELECT json_object_agg(id, slug) FROM (
          SELECT p.id, p.slug FROM projects p WHERE p.id IN (SELECT id FROM named) AND strpos(p.slug, '~') = 0
          UNION ALL SELECT e.id, e.slug FROM environments e WHERE e.id IN (SELECT id FROM named) AND strpos(e.slug, '~') = 0
        ) places) AS slugs`,
  );
  const row = rows[0]!;
  const iso = (value: string | null) => (value === null ? null : new Date(value).toISOString());
  return {
    member: !row.found ? null : {
      admittedBy: row.status_changed_by ?? '',
      grants: (row.grants ?? []).map((grant) => ({
        projectId: grant.project_id,
        environmentId: grant.environment_id,
        environmentSlug: grant.environment,
        role: grant.role,
        definition: grant.role_name === null ? null : { name: grant.role_name, permissions: grant.permissions ?? [], protected: grant.guarded ?? [] },
        found: grant.found,
        tombstone: grant.tombstone,
      })),
    },
    setting: row.setting,
    tokens: (row.tokens ?? []).map((token) => ({
      id: token.id,
      kind: token.kind,
      label: token.label,
      hint: token.hint,
      scope: token.scope,
      createdAt: iso(token.created_at)!,
      createdBy: token.created_by,
      expiresAt: iso(token.expires_at)!,
      lastUsedAt: iso(token.last_used_at),
      lastUsedIp: token.last_used_ip,
    })),
    slugs: row.slugs ?? {},
  };
}

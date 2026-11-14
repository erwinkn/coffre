import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * A service account's trust bindings, as its page lists them. The rows are
 * read as they are, their MACs unchecked: they say what a page lists, and
 * decide nothing. Whether the caller may see them is weighed on the same
 * rows, the way the vault weighs who manages a service (`managesService`),
 * and decides nothing either: a change asks the vault again.
 */

/** A live binding of the service's generation, as stored. */
export type BindingRow = {
  id: string;
  profile: string;
  issuer: string;
  jwksUri: string;
  /** The keys it carries, JSON; null when they are fetched from `jwksUri`. */
  jwks: string | null;
  /** JSON, as sealed. */
  claims: string;
  scope: string | null;
  policy: string | null;
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

/** A live grant of the service's, at its place, with its role as the instance defines it: no definition, an instance role or one it no longer has. */
export type ServiceGrantRow = {
  projectId: string;
  environmentId: string | null;
  /** Null for a place that is gone. */
  project: string | null;
  environment: string | null;
  role: string;
  definition: { name: string; permissions: string[]; protected: string[] } | null;
};

export type ServiceBindings = {
  status: string;
  /** Who admitted it, or last changed its status: who manages it while it holds nothing. */
  admittedBy: string;
  /** The instance's setting of where people set service accounts up, as its row keeps it; null without the row. */
  setting: string | null;
  grants: ServiceGrantRow[];
  bindings: BindingRow[];
  /** The path of each project and environment the bindings' scopes and reads name, by id: `market`, `market/prod`. */
  paths: Record<string, string>;
  /** The name of each key the bindings' reads list, by id. */
  keys: Record<string, string>;
};

type Raw = {
  status: string;
  status_changed_by: string;
  setting: string | null;
  grants: RawGrant[];
  bindings: { id: string; profile: string; issuer: string; jwks_uri: string; jwks: string | null; claims: string; scope: string | null; policy: string | null; label: string | null; created_at: string; created_by: string; last_used_at: string | null }[];
  paths: Record<string, string>;
  keys: Record<string, string>;
};

/** A grant as `liveGrants` reads it. */
export type RawGrant = { project_id: string; environment_id: string | null; project: string | null; environment: string | null; role: string; name: string | null; permissions: string[] | null; protected: string[] | null };

/**
 * The live grants of the principal row aliased `m`, of its generation, with
 * their places' slugs and their project roles' rows, as JSON: what
 * `managesService` weighs a service account by.
 */
export const liveGrants = (now: Date) => sql`(SELECT coalesce(json_agg(json_build_object(
    'project_id', coalesce(g.project_id, e.project_id), 'environment_id', g.environment_id,
    'project', pr.slug, 'environment', e.slug, 'role', g.role,
    'name', r.name, 'permissions', r.permissions, 'protected', r.protected)), '[]')
  FROM grants g
  LEFT JOIN environments e ON e.id = g.environment_id
  LEFT JOIN projects pr ON pr.id = coalesce(g.project_id, e.project_id)
  LEFT JOIN roles r ON r.id = g.role AND NOT r.instance
  WHERE g.principal = m.id AND g.generation = m.generation AND (g.expires_at IS NULL OR g.expires_at > ${now}))`;

/** A grant `liveGrants` read, as the app weighs it. */
export const grantRow = (grant: RawGrant): ServiceGrantRow => ({
  projectId: grant.project_id,
  environmentId: grant.environment_id,
  project: grant.project,
  environment: grant.environment,
  role: grant.role,
  definition: grant.name === null ? null : { name: grant.name, permissions: grant.permissions ?? [], protected: grant.protected ?? [] },
});

/** Any id a binding's scope or policy names: the places and keys looked up for its listing, whatever the text around them. */
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

/**
 * The service `member` (`token:<name>`), its live grants and the instance's
 * setting, by which the caller is weighed, and its live bindings of its
 * generation, oldest first, with the names of the places and keys they
 * name: one statement. Null for a principal that has no row.
 */
export async function serviceBindings(db: Queryable, member: string, now: Date): Promise<ServiceBindings | null> {
  const [row] = await rowsOf<Raw>(db, sql`
    WITH member AS (SELECT id, status, generation, status_changed_by FROM principals WHERE id = ${member}),
    live AS (
      SELECT b.* FROM bindings b JOIN member m ON b.principal = m.id AND b.generation = m.generation
      WHERE b.revoked_at IS NULL
    ),
    named AS (
      SELECT DISTINCT (found[1])::uuid AS id
      FROM live, regexp_matches(coalesce(live.scope, '') || ' ' || coalesce(live.policy, ''), ${UUID}, 'g') AS found
    )
    SELECT m.status, m.status_changed_by,
      (SELECT service_accounts FROM policy WHERE only_row) AS setting,
      ${liveGrants(now)} AS grants,
      (SELECT coalesce(json_agg(json_build_object(
          'id', b.id, 'profile', b.profile, 'issuer', b.issuer, 'jwks_uri', b.jwks_uri, 'jwks', b.jwks, 'claims', b.claims,
          'scope', b.scope, 'policy', b.policy, 'label', b.label, 'created_at', b.created_at, 'created_by', b.created_by,
          'last_used_at', b.last_used_at) ORDER BY b.created_at, b.id), '[]')
        FROM live b) AS bindings,
      (SELECT coalesce(json_object_agg(place.id, place.path), '{}') FROM (
        SELECT pr.id::text AS id, pr.slug AS path FROM projects pr WHERE pr.id IN (SELECT id FROM named) AND strpos(pr.slug, '~') = 0
        UNION ALL
        SELECT e.id::text, pr.slug || '/' || e.slug FROM environments e JOIN projects pr ON pr.id = e.project_id
          WHERE e.id IN (SELECT id FROM named) AND strpos(pr.slug, '~') = 0 AND strpos(e.slug, '~') = 0
      ) place) AS paths,
      (SELECT coalesce(json_object_agg(s.id, s.key), '{}') FROM secrets s WHERE s.id IN (SELECT id FROM named)) AS keys
    FROM member m
  `);
  if (row === undefined) return null;
  return {
    status: row.status,
    admittedBy: row.status_changed_by,
    setting: row.setting,
    grants: row.grants.map(grantRow),
    bindings: row.bindings.map((binding) => ({
      id: binding.id,
      profile: binding.profile,
      issuer: binding.issuer,
      jwksUri: binding.jwks_uri,
      jwks: binding.jwks,
      claims: binding.claims,
      scope: binding.scope,
      policy: binding.policy,
      label: binding.label,
      createdAt: new Date(binding.created_at).toISOString(),
      createdBy: binding.created_by,
      lastUsedAt: binding.last_used_at === null ? null : new Date(binding.last_used_at).toISOString(),
    })),
    paths: row.paths,
    keys: row.keys,
  };
}

/** A live binding on an issuer: what the app reads to know which keys to verify a CI run's token under. */
export type IssuerBinding = { id: string; profile: string; jwksUri: string; jwks: string | null; claims: string; bearer: boolean };

/**
 * The live bindings of `member` (`token:<name>`) on `issuer`, of the
 * service's generation, oldest first, `most` at most: the rows the vault's
 * exchange reads, in its order, one statement on the index it reads by
 * (`bindings_live_idx`). `bearer`: one with no policy, which a CI run's
 * exchange takes. Unchecked: they choose which keys the app verifies
 * under, and the vault decides on its own read of them.
 */
export async function issuerBindings(db: Queryable, member: string, issuer: string, most: number): Promise<IssuerBinding[]> {
  const rows = await rowsOf<{ id: string; profile: string; jwks_uri: string; jwks: string | null; claims: string; bearer: boolean }>(db, sql`
    SELECT b.id, b.profile, b.jwks_uri, b.jwks, b.claims, b.policy IS NULL AS bearer
    FROM principals p
    JOIN bindings b ON b.principal = p.id AND b.issuer = ${issuer} AND b.generation = p.generation AND b.revoked_at IS NULL
    WHERE p.id = ${member} AND p.status = 'active'
    ORDER BY b.created_at, b.id
    LIMIT ${most}
  `);
  return rows.map((row) => ({ id: row.id, profile: row.profile, jwksUri: row.jwks_uri, jwks: row.jwks, claims: row.claims, bearer: row.bearer }));
}

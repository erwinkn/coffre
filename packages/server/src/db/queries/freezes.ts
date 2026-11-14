import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { GRANT_JSON, GRANT_PLACES, grantRow, liveFor, type RawGrant, type ServiceGrantRow } from './bindings.ts';

/**
 * The freezes standing (docs/design/workload-access.md, section 8.2), as
 * the rows keep them: the policy row's for every workload, and a service
 * account's, one of its bindings' or one of its workloads' sessions'. The
 * rows are read as they are, their MACs unchecked: a listing decides
 * nothing, and the vault decides each use and each change on its own read.
 */

/** A freeze standing, in `freezeTarget`'s one spelling, with the service account it is of; null for the instance's. */
export type FreezeRow = { target: string; service: string | null; frozenAt: string };

/** A service account a freeze is of, with what says who manages it, as `serviceBindings` reads it. */
export type FrozenService = { status: string; admittedBy: string; grants: ServiceGrantRow[] };

export type Freezes = {
  /** The instance's first, then by service account and target; at most one past `most`. */
  freezes: FreezeRow[];
  /** The instance's setting of where people set service accounts up, as its row keeps it; null without the row. */
  setting: string | null;
  /** Each service account a freeze listed is of, by id, with its live grants; empty when `weighed` is false. */
  services: Record<string, FrozenService>;
  /** How many grants were read for them, at most one past `most`: past it, `services` holds some of them, and weighs nothing. */
  held: number;
};

type Raw = {
  freezes: { target: string; service: string | null; frozen_at: string }[];
  setting: string | null;
  services: Record<string, { status: string; status_changed_by: string; grants: RawGrant[] }>;
  held: number | string;
};

/**
 * Every freeze standing, at most one past `most`, of what is still there to
 * stop: an active service account, a live binding of its generation, a
 * workload's session of its generation neither revoked nor past its end.
 * With `weighed`, each service account they are of, with its live grants
 * and their roles, by which the app weighs whether the caller manages it:
 * at most one past `most` grants in all. One statement. Sessions are found
 * from the active service accounts, each's by its id on an index the
 * credentials' member leads, never among a person's, whatever the
 * database's collation.
 */
export async function freezes(db: Queryable, opts: { weighed: boolean; most: number; now: Date }): Promise<Freezes> {
  const { weighed, most, now } = opts;
  const [row] = await rowsOf<Raw>(db, sql`
    WITH frozen AS (
      SELECT 'instance' AS target, NULL::text AS service, workloads_frozen_at AS frozen_at FROM policy WHERE only_row AND workloads_frozen_at IS NOT NULL
      UNION ALL
      SELECT p.id, p.id, p.frozen_at FROM principals p WHERE p.frozen_at IS NOT NULL AND p.status = 'active'
      UNION ALL
      SELECT 'binding:' || b.id, p.id, b.frozen_at
        FROM bindings b JOIN principals p ON p.id = b.principal AND p.generation = b.generation AND p.status = 'active'
        WHERE b.frozen_at IS NOT NULL AND b.revoked_at IS NULL
      UNION ALL
      -- Each active service account's sessions, by its id: OFFSET 0 keeps the planner from reading every credential to find them.
      SELECT 'session:' || c.id, p.id, c.frozen_at
        FROM principals p CROSS JOIN LATERAL (
          SELECT c.id, c.frozen_at FROM credentials c
          WHERE c.principal = p.id AND c.generation = p.generation AND c.revoked_at IS NULL AND c.expires_at > ${now}
            AND c.frozen_at IS NOT NULL AND c.kind = 'workload' AND c.not_after > ${now}
          OFFSET 0) c
        WHERE p.id LIKE 'token:%' AND p.status = 'active'
    ),
    listed AS (SELECT * FROM frozen ORDER BY service NULLS FIRST, target LIMIT ${most + 1}),
    weighed AS (SELECT m.id, m.status, m.status_changed_by, m.generation FROM principals m WHERE ${weighed} AND m.id IN (SELECT service FROM listed)),
    held AS (
      SELECT g.principal, ${GRANT_JSON} AS one
      FROM weighed m JOIN grants g ON ${liveFor(now)} ${GRANT_PLACES}
      LIMIT ${most + 1}
    )
    SELECT
      (SELECT coalesce(json_agg(json_build_object('target', l.target, 'service', l.service, 'frozen_at', l.frozen_at) ORDER BY l.service NULLS FIRST, l.target), '[]') FROM listed l) AS freezes,
      (SELECT service_accounts FROM policy WHERE only_row) AS setting,
      (SELECT coalesce(json_object_agg(m.id, json_build_object('status', m.status, 'status_changed_by', m.status_changed_by,
          'grants', (SELECT coalesce(json_agg(h.one), '[]') FROM held h WHERE h.principal = m.id))), '{}')
        FROM weighed m) AS services,
      (SELECT count(*) FROM held) AS held
  `);
  return {
    freezes: (row?.freezes ?? []).map((freeze) => ({ target: freeze.target, service: freeze.service, frozenAt: new Date(freeze.frozen_at).toISOString() })),
    setting: row?.setting ?? null,
    services: Object.fromEntries(Object.entries(row?.services ?? {}).map(([id, service]) => [id, {
      status: service.status,
      admittedBy: service.status_changed_by,
      grants: service.grants.map(grantRow),
    }])),
    held: Number(row?.held ?? 0),
  };
}

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { grantRow, liveGrants, type RawGrant, type ServiceGrantRow } from './bindings.ts';

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
  /** Each service account a freeze listed is of, by id; empty when `weighed` is false. */
  services: Record<string, FrozenService>;
};

type Raw = {
  freezes: { target: string; service: string | null; frozen_at: string }[];
  setting: string | null;
  services: Record<string, { status: string; status_changed_by: string; grants: RawGrant[] }>;
};

/**
 * Every freeze standing, at most one past `most`, of what is still there to
 * stop: an active service account, a live binding of its generation, a
 * workload's session of its generation neither revoked nor past its end.
 * With `weighed`, each service account they are of, with its live grants
 * and their roles, by which the app weighs whether the caller manages it.
 * One statement. Sessions are found by the range of service accounts' ids,
 * on an index the credentials' member leads, never among a person's.
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
      SELECT 'session:' || c.id, p.id, c.frozen_at
        FROM credentials c JOIN principals p ON p.id = c.principal AND p.generation = c.generation AND p.status = 'active'
        WHERE c.principal >= 'token:' AND c.principal < 'token;' AND c.revoked_at IS NULL AND c.expires_at > ${now}
          AND c.frozen_at IS NOT NULL AND c.kind = 'workload' AND c.not_after > ${now}
    ),
    listed AS (SELECT * FROM frozen ORDER BY service NULLS FIRST, target LIMIT ${most + 1})
    SELECT
      (SELECT coalesce(json_agg(json_build_object('target', l.target, 'service', l.service, 'frozen_at', l.frozen_at) ORDER BY l.service NULLS FIRST, l.target), '[]') FROM listed l) AS freezes,
      (SELECT service_accounts FROM policy WHERE only_row) AS setting,
      (SELECT coalesce(json_object_agg(m.id, json_build_object('status', m.status, 'status_changed_by', m.status_changed_by, 'grants', ${liveGrants(now)})), '{}')
        FROM principals m WHERE ${weighed} AND m.id IN (SELECT service FROM listed)) AS services
  `);
  return {
    freezes: (row?.freezes ?? []).map((freeze) => ({ target: freeze.target, service: freeze.service, frozenAt: new Date(freeze.frozen_at).toISOString() })),
    setting: row?.setting ?? null,
    services: Object.fromEntries(Object.entries(row?.services ?? {}).map(([id, service]) => [id, {
      status: service.status,
      admittedBy: service.status_changed_by,
      grants: service.grants.map(grantRow),
    }])),
  };
}

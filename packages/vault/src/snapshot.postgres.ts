import { TOMBSTONE } from '@coffre/core/schemas';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { sql, type SQL } from 'drizzle-orm';

import type { Asked } from './snapshot.ts';

/** An entry of `audit_log` aliased `e`, as JSON (`RawEntry`): whole numbers past 2^53 as text, bytes as hex. */
const ENTRY = sql.raw(`json_build_object(
  'seq', e.seq::text, 'author', e.author, 'keyId', e.key_id, 'occurredAt', e.occurred_at, 'actor', e.actor, 'action', e.action,
  'decision', e.decision, 'code', e.code, 'subjectPrincipal', e.subject_principal, 'projectId', e.project_id,
  'environmentId', e.environment_id, 'secretId', e.secret_id, 'secretVersionId', e.secret_version_id,
  'operationId', e.operation_id, 'requestId', e.request_id, 'sourceIp', e.source_ip, 'relatedSeq', e.related_seq::text,
  'metadata', e.metadata, 'prevHash', encode(e.prev_hash, 'hex'), 'mac', encode(e.mac, 'hex'), 'hash', encode(e.hash, 'hex'))`);

const NOW = sql.raw('(extract(epoch from clock_timestamp()) * 1000)::bigint');

/**
 * `snapshot`'s statement on Postgres: one row, `snapshot`, JSON, and
 * `stable`, the part of it what the decision depends on, as text. Each part
 * reads one index range.
 */
export function snapshotQuery(asked: Asked): SQL {
  // The head, waiting for it, no longer than `waitMs` when set, which the row's condition sets before it waits: the clock
  // is read once it is held, the rest as of when the statement began.
  const bound = asked.waitMs === undefined ? sql`` : sql` AND set_config('lock_timeout', ${String(Math.trunc(asked.waitMs))}, true) IS NOT NULL`;
  const head = asked.head === true
    ? sql`, head AS (SELECT next_seq, head_hash, ${NOW} AS at FROM (SELECT next_seq, head_hash FROM audit_chain_head WHERE only_row${bound} FOR UPDATE) locked)`
    : sql``;
  const clock = asked.head === true ? sql`(SELECT at FROM head)` : NOW;
  return sql`
    WITH ${POLICY}${head}
    SELECT json_build_object(
      'at', ${clock},
      'head', ${asked.head === true ? sql`(SELECT json_build_object('nextSeq', next_seq::text, 'hash', encode(head_hash, 'hex')) FROM head)` : sql`NULL`},
      'last', ${asked.head === true ? sql`(SELECT json_build_object('seq', seq::text, 'hash', encode(hash, 'hex')) FROM audit_log ORDER BY seq DESC LIMIT 1)` : sql`NULL`},
      'released', ${released(asked, clock)}
    ) AS snapshot, (${stable(asked)})::text AS stable`;
}

/**
 * Whether what `asked` read, `read`, is what the database holds now, and
 * the keys its principal holds released as of `at`, the clock its entries
 * are stamped with, still within `cap`: true or false, in a statement that
 * holds the head (`appendEntries`, `unchanged`).
 */
export function stillQuery(asked: Asked, read: string, at: number, cap: number): SQL {
  const count = asked.released === undefined ? sql`true` : sql`${released(asked, sql`${at}::bigint`)} <= ${cap}`;
  return sql`(WITH ${POLICY} SELECT (${stable(asked)})::text = ${read} AND ${count})`;
}

/** The newest allowed `policy.change` in the vault's name, as a CTE. */
const POLICY = sql`policy AS (
  SELECT * FROM audit_log WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow' ORDER BY seq DESC LIMIT 1
)`;

/**
 * Everything a decision reads but the clock, the head and the count of
 * releases: what nothing but a change, with its entry, changes. Each list in
 * one order, so that two reads of the same rows are the same text.
 */
function stable(asked: Asked): SQL {
  const principals = sql`${sql.param([...asked.principals])}::text[]`;
  const environments = sql`${sql.param([...(asked.environments ?? [])])}::uuid[]`;
  const references = sql`${sql.param((asked.references ?? []).map(String))}::bigint[]`;
  const actions = sql`${sql.param([...ACCESS_ACTIONS])}::text[]`;
  const tomb = `%${TOMBSTONE}%`;
  return sql`json_build_object(
      'rotation', ${asked.head === true
        ? sql`(SELECT ${ENTRY} FROM audit_log e WHERE author = 'vault' AND action = 'key.rotate' AND decision = 'allow' ORDER BY seq DESC LIMIT 1)`
        : sql`NULL`},
      'members', ${asked.members === true
        ? sql`(SELECT coalesce(json_agg(json_build_object(
            'principal', principal, 'status', status, 'owner', owner, 'role', role, 'scope', scope, 'generation', generation,
            'createdAt', created_at, 'createdBy', created_by, 'statusChangedAt', status_changed_at, 'statusChangedBy', status_changed_by,
            'accessSeq', access_seq::text, 'mac', encode(mac, 'hex')) ORDER BY principal), '[]') FROM vault_members WHERE principal = ANY(${principals}))`
        : sql`'[]'::json`},
      'grants', (
        SELECT coalesce(json_agg(json_build_object(
          'principal', g.principal, 'projectId', coalesce(g.project_id, env.project_id), 'environmentId', g.environment_id,
          'environmentSlug', g.environment_slug, 'role', g.role, 'expiresAt', g.expires_at, 'grantedAt', g.granted_at, 'grantedBy', g.granted_by)
          ORDER BY g.principal, g.project_id NULLS FIRST, g.environment_id NULLS FIRST, g.environment_slug NULLS FIRST), '[]')
        FROM vault_grants g LEFT JOIN environments env ON env.id = g.environment_id
        WHERE g.principal = ANY(${principals})
      ),
      'access', (
        SELECT coalesce(json_agg(${ENTRY} ORDER BY asked.principal), '[]')
        FROM unnest(${principals}) AS asked (principal)
        CROSS JOIN LATERAL (
          SELECT * FROM audit_log
          WHERE author = 'vault' AND subject_principal = asked.principal AND action = ANY(${actions}) AND decision = 'allow'
          ORDER BY seq DESC LIMIT 1
        ) e
      ),
      'policy', (SELECT ${ENTRY} FROM policy e),
      'environments', (
        SELECT coalesce(json_agg(json_build_object(
          'id', env.id, 'projectId', env.project_id, 'slug', env.slug, 'owner', env.owner, 'parentId', env.parent_id,
          'deleted', env.slug LIKE ${tomb} OR project.slug LIKE ${tomb},
          'archived', env.archived_at IS NOT NULL OR project.archived_at IS NOT NULL) ORDER BY env.id), '[]')
        FROM environments env JOIN projects project ON project.id = env.project_id
        -- One list of ids, each found by the primary key.
        WHERE env.id = ANY(ARRAY(
          SELECT unnest(${environments})
          UNION SELECT parent_id FROM environments WHERE id = ANY(${environments}) AND owner IS NOT NULL
          -- What the newest policy protects, by the ids its JSON names; one that is no UUID names nothing.
          UNION SELECT (place #>> '{}')::uuid FROM policy, jsonb_path_query(policy.metadata::jsonb, '$.policy.protected[*].environmentId') AS place
          WHERE (place #>> '{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ))
      ),
      'ended', (
        SELECT coalesce(json_agg(related_seq::text ORDER BY related_seq), '[]') FROM audit_log
        WHERE author = 'vault' AND action = 'reference.end' AND decision = 'allow' AND related_seq = ANY(${references})
      )
    )`;
}

/** How many distinct keys `asked.released.principal` holds released as of `clock`, the asked keys among them; 0 unless asked. */
function released(asked: Asked, clock: SQL): SQL {
  const released = asked.released;
  if (released === undefined) return sql`0`;
  return sql`(
    SELECT count(DISTINCT key) FROM (
      -- A read of one key names it; of several at one place, lists them (readsByPlace, vault.ts). An entry, or an
      -- item of its list, that names no key, which only a forged entry is, counts as one key of its own.
      SELECT coalesce(e.secret_id::text, CASE jsonb_typeof(one -> 'secretId') WHEN 'string' THEN one ->> 'secretId' END, 'entry:' || e.seq) FROM audit_log e
      -- Each item of a list, never what lax paths would make of an object; silent, as strict paths fail on what is missing.
      LEFT JOIN LATERAL jsonb_path_query(CASE WHEN e.secret_id IS NULL THEN e.metadata::jsonb END, 'strict $.secrets ? (@.type() == "array")[*]', '{}', true) AS one ON true
      WHERE e.author = 'vault' AND e.actor = ${released.principal} AND e.action = 'secret.read' AND e.decision = 'allow'
        AND e.occurred_at > ${clock} + ${released.clockOffsetMs} - ${released.windowMs}
      UNION ALL SELECT unnest(${sql.param([...released.keys])}::text[])
    ) AS released (key)
  )`;
}

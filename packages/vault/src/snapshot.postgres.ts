import { TOMBSTONE } from '@coffre/core/schemas';
import { accessAllowed, changesOf } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';

import type { Asked } from './snapshot.ts';
import { newestChangeJson } from './store.ts';

/** An asked member's newest change, and a place's, each by its object's index (`changesOf`). */
const MEMBER_CHANGE = changesOf('x', sql`log_object('principal', asked.principal)`);
const PLACE_CHANGE = changesOf('l', sql`log_object('environment', g.id::text)`);

/** An entry of `audit_log` aliased `e`, as JSON (`RawEntry`): whole numbers past 2^53 as text, bytes as hex. */
const ENTRY = sql.raw(`json_build_object(
  'seq', e.seq::text, 'author', e.author, 'keyId', e.key_id, 'occurredAt', e.occurred_at, 'actor', e.actor, 'action', e.action,
  'decision', e.decision, 'code', e.code, 'subjectPrincipal', e.subject_principal, 'projectId', e.project_id,
  'environmentId', e.environment_id, 'secretId', e.secret_id, 'secretVersionId', e.secret_version_id,
  'operationId', e.operation_id, 'requestId', e.request_id, 'sourceIp', e.source_ip, 'relatedSeq', e.related_seq::text,
  'metadata', e.metadata, 'prevHash', encode(e.prev_hash, 'hex'), 'mac', encode(e.mac, 'hex'), 'hash', encode(e.hash, 'hex'))`);

const NOW = sql.raw('(extract(epoch from clock_timestamp()) * 1000)::bigint');

/** `snapshot`'s statement on Postgres: one row, one JSON column. Each part reads one index range. */
export function snapshotQuery(asked: Asked): SQL {
  const principals = sql`${sql.param([...asked.principals])}::text[]`;
  const environments = sql`${sql.param([...(asked.environments ?? [])])}::uuid[]`;
  const references = sql`${sql.param((asked.references ?? []).map(String))}::bigint[]`;
  const tomb = `%${TOMBSTONE}%`;
  const released = asked.released;
  // The places read: those asked, the environments each personal config among them is a config of, those the asked
  // principals' grants are on (whose projects their grants are read with), and what the newest policy
  // protects, by the ids its JSON names (one that is no UUID names nothing).
  const placeIds = sql`ARRAY(
          SELECT unnest(${environments})
          UNION SELECT parent_id FROM environments WHERE id = ANY(${environments}) AND owner IS NOT NULL
          UNION SELECT environment_id FROM grants WHERE principal = ANY(${principals}) AND environment_id IS NOT NULL
          UNION SELECT (place #>> '{}')::uuid FROM policy, jsonb_path_query(policy.metadata::jsonb, '$.policy.protected[*].environmentId') AS place
          WHERE (place #>> '{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )`;
  // The head only if nobody holds it: a statement never waits for it, so all it reads is as of when it took it (`snapshot`).
  const head = asked.head === true
    ? sql`, head AS (SELECT next_seq, head_hash FROM audit_chain_head WHERE only_row FOR UPDATE SKIP LOCKED)`
    : sql``;
  return sql`
    WITH policy AS (
      SELECT * FROM audit_log WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow' ORDER BY seq DESC LIMIT 1
    )${head}
    SELECT json_build_object(
      'at', ${NOW},
      'head', ${asked.head === true ? sql`(SELECT json_build_object('nextSeq', next_seq::text, 'hash', encode(head_hash, 'hex')) FROM head)` : sql`NULL`},
      'last', ${asked.head === true ? sql`(SELECT json_build_object('seq', seq::text, 'hash', encode(hash, 'hex')) FROM audit_log ORDER BY seq DESC LIMIT 1)` : sql`NULL`},
      'rotation', ${asked.head === true
        ? sql`(SELECT ${ENTRY} FROM audit_log e WHERE author = 'vault' AND action = 'key.rotate' AND decision = 'allow' ORDER BY seq DESC LIMIT 1)`
        : sql`NULL`},
      'members', ${asked.members === true
        ? sql`(SELECT coalesce(json_agg(json_build_object(
            'principal', principal, 'status', status, 'owner', owner, 'role', role, 'scope', scope, 'generation', generation,
            'createdAt', created_at, 'createdBy', created_by, 'statusChangedAt', status_changed_at, 'statusChangedBy', status_changed_by,
            'accessSeq', access_seq::text, 'mac', encode(mac, 'hex'))), '[]') FROM principals WHERE principal = ANY(${principals}))`
        : sql`'[]'::json`},
      'grants', (
        SELECT coalesce(json_agg(json_build_object(
          'principal', g.principal, 'projectId', coalesce(g.project_id, env.project_id), 'environmentId', g.environment_id,
          'environmentSlug', g.environment_slug, 'role', g.role, 'expiresAt', g.expires_at, 'grantedAt', g.granted_at, 'grantedBy', g.granted_by)), '[]')
        FROM grants g LEFT JOIN environments env ON env.id = g.environment_id
        WHERE g.principal = ANY(${principals})
      ),
      'access', (
        SELECT coalesce(json_agg(${ENTRY}), '[]')
        FROM unnest(${principals}) AS asked (principal)
        CROSS JOIN LATERAL (
          -- One step of audit_log_access_idx, its condition as constants (\`accessAllowed\`), the principal \`= ANY\` and
          -- first in the order so that only that index yields it (\`keyedBy\`; T245, R48).
          SELECT * FROM audit_log
          WHERE ${accessAllowed()} AND subject_principal = ANY(ARRAY[asked.principal])
          ORDER BY subject_principal DESC, seq DESC LIMIT 1
        ) e
      ),
      'policy', (SELECT ${ENTRY} FROM policy e),
      -- What 0.15's log holds each asked member's row to (T179 PR 2, \`memberLogs\`): the row's seal, and its object's newest
      -- change, whole, whose MAC the vault checks and whose payload names the 0.14 entry it accounts for. One probe each.
      'memberLogs', (
        SELECT coalesce(json_agg(json_build_object(
          'principal', asked.principal, 'seal', encode(m.seal, 'hex'), 'number', l.number::text, 'at', l.at::text, 'requestId', l.request_id,
          'object', l.object, 'actor', l.actor, 'payload', l.payload, 'newest', encode(l.seal, 'hex'), 'mac', encode(l.mac, 'hex'))), '[]')
        FROM unnest(${principals}) AS asked (principal)
        LEFT JOIN principals m ON m.principal = asked.principal
        LEFT JOIN LATERAL (
          SELECT x.* FROM log_changes x WHERE ${MEMBER_CHANGE.where} ORDER BY ${MEMBER_CHANGE.order} LIMIT 1
        ) l ON true
      ),
      'settings', ${asked.settings === true
        ? sql`(SELECT ${ENTRY} FROM audit_log e WHERE author = 'vault' AND action = 'settings.change' AND decision = 'allow' ORDER BY seq DESC LIMIT 1)`
        : sql`NULL`},
      'environments', (
        SELECT coalesce(json_agg(json_build_object(
          'id', env.id, 'projectId', env.project_id, 'slug', env.slug, 'owner', env.owner, 'parentId', env.parent_id,
          'deleted', env.slug LIKE ${tomb} OR project.slug LIKE ${tomb},
          'archived', env.archived_at IS NOT NULL OR project.archived_at IS NOT NULL,
          -- What 0.15's log holds the row to (T159): its object's own columns, its seal, and its newest change, whole, its
          -- MAC to check (T190, review r3), one probe of its object's changes, newest first (log_changes_object_idx).
          'protected', env.protected, 'ownArchived', env.archived_at IS NOT NULL, 'projectArchived', project.archived_at IS NOT NULL,
          'seal', encode(env.seal, 'hex'),
          'newest', ${newestChangeJson(sql`log_object('environment', env.id::text)`)})), '[]')
        FROM environments env JOIN projects project ON project.id = env.project_id
        -- One list of ids, each found by the primary key.
        WHERE env.id = ANY(${placeIds})
      ),
      -- Of those ids, each the log holds a change of but no row (or no project's) answers to: deleted outright around it,
      -- with its newest change's seal (T159, review r5). One probe of its object's changes each.
      'gone', (
        SELECT coalesce(json_agg(json_build_object('id', g.id, 'newest', encode(l.seal, 'hex'))), '[]')
        FROM (
          SELECT a.id FROM unnest(${placeIds}) AS a (id)
          WHERE NOT EXISTS (SELECT 1 FROM environments env JOIN projects project ON project.id = env.project_id WHERE env.id = a.id)
          OFFSET 0
        ) g
        CROSS JOIN LATERAL (SELECT l.seal FROM log_changes l WHERE ${PLACE_CHANGE.where} ORDER BY ${PLACE_CHANGE.order} LIMIT 1) l
      ),
      'ended', (
        SELECT coalesce(json_agg(related_seq::text), '[]') FROM audit_log
        WHERE author = 'vault' AND action = 'reference.end' AND decision = 'allow' AND related_seq = ANY(${references})
      ),
      'released', ${released === undefined
        ? sql`0`
        : sql`(
          -- The keys released within the window, but those asked for, up to one past the cap: a row for each key the
          -- principal was ever released, however many reads of them the log holds (vault_releases, which the database
          -- keeps from it). The bound is a subquery, evaluated once: clock_timestamp() alone is volatile, and runs a row.
          SELECT count(*) FROM (
            SELECT 1 FROM vault_releases
            WHERE principal = ${released.principal} AND released_at > (SELECT ${NOW} + ${released.clockOffsetMs} - ${released.windowMs})
              AND key <> ALL(${sql.param([...released.keys])}::text[])
            LIMIT ${released.cap + 1}
          ) AS before
        ) + (SELECT count(DISTINCT key) FROM unnest(${sql.param([...released.keys])}::text[]) AS asked (key))`}
    ) AS snapshot`;
}

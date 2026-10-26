import { TOMBSTONE } from '@coffre/core/schemas';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { sql, type SQL } from 'drizzle-orm';

import type { Asked } from './snapshot.ts';

/**
 * An entry of `audit_log` aliased `e`, as JSON (`RawEntry`), bytes as hex.
 * A JSON value loses its type leaving a subquery, so whoever takes one
 * from a subquery wraps it in `json(…)`.
 */
const ENTRY = sql.raw(`json_object(
  'seq', e.seq, 'author', e.author, 'keyId', e.key_id, 'occurredAt', e.occurred_at, 'actor', e.actor, 'action', e.action,
  'decision', e.decision, 'code', e.code, 'subjectPrincipal', e.subject_principal, 'projectId', e.project_id,
  'environmentId', e.environment_id, 'secretId', e.secret_id, 'secretVersionId', e.secret_version_id,
  'operationId', e.operation_id, 'requestId', e.request_id, 'sourceIp', e.source_ip, 'relatedSeq', e.related_seq,
  'metadata', e.metadata, 'prevHash', hex(e.prev_hash), 'mac', hex(e.mac), 'hash', hex(e.hash))`);

const NOW = sql.raw(`CAST(unixepoch('subsec') * 1000 AS INTEGER)`);

/**
 * `snapshot`'s statement on SQLite, the same as on Postgres. Nothing is
 * locked: one transaction runs at a time (connect.ts), so the head is the
 * last entry's.
 */
export function snapshotQuery(asked: Asked): SQL {
  const principals = JSON.stringify(asked.principals);
  const environments = JSON.stringify(asked.environments ?? []);
  const references = JSON.stringify((asked.references ?? []).map(Number));
  const actions = JSON.stringify(ACCESS_ACTIONS);
  const tomb = `%${TOMBSTONE}%`;
  const released = asked.released;
  const head = asked.head === true;
  return sql`
    WITH policy AS (
      SELECT * FROM audit_log WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow' ORDER BY seq DESC LIMIT 1
    )
    SELECT json_object(
      'at', ${NOW},
      'head', ${head ? sql`json((SELECT json_object('nextSeq', next_seq, 'hash', hex(head_hash)) FROM audit_chain_head WHERE only_row))` : sql`NULL`},
      'last', ${head ? sql`json((SELECT json_object('seq', seq, 'hash', hex(hash)) FROM audit_log ORDER BY seq DESC LIMIT 1))` : sql`NULL`},
      'rotation', ${head
        ? sql`json((SELECT ${ENTRY} FROM audit_log e WHERE author = 'vault' AND action = 'key.rotate' AND decision = 'allow' ORDER BY seq DESC LIMIT 1))`
        : sql`NULL`},
      'members', json(${asked.members === true
        ? sql`(SELECT json_group_array(json_object(
            'principal', principal, 'status', status, 'owner', owner, 'role', role, 'scope', scope, 'generation', generation,
            'createdAt', created_at, 'createdBy', created_by, 'statusChangedAt', status_changed_at, 'statusChangedBy', status_changed_by,
            'accessSeq', access_seq, 'mac', hex(mac))) FROM vault_members WHERE principal IN (SELECT value FROM json_each(${principals})))`
        : sql`'[]'`}),
      'grants', json((
        SELECT json_group_array(json_object(
          'principal', g.principal, 'projectId', coalesce(g.project_id, env.project_id), 'environmentId', g.environment_id,
          'environmentSlug', g.environment_slug, 'role', g.role, 'expiresAt', g.expires_at, 'grantedAt', g.granted_at, 'grantedBy', g.granted_by))
        FROM vault_grants g LEFT JOIN environments env ON env.id = g.environment_id
        WHERE g.principal IN (SELECT value FROM json_each(${principals}))
      )),
      'access', json((
        SELECT json_group_array(json(newest)) FROM (
          SELECT (
            SELECT ${ENTRY} FROM audit_log e
            WHERE author = 'vault' AND subject_principal = asked.value AND action IN (SELECT value FROM json_each(${actions})) AND decision = 'allow'
            ORDER BY seq DESC LIMIT 1
          ) AS newest
          FROM json_each(${principals}) AS asked
        ) WHERE newest IS NOT NULL
      )),
      'policy', json((SELECT ${ENTRY} FROM policy e)),
      'environments', json((
        SELECT json_group_array(json_object(
          'id', env.id, 'projectId', env.project_id, 'slug', env.slug, 'owner', env.owner, 'parentId', env.parent_id,
          'deleted', env.slug LIKE ${tomb} OR project.slug LIKE ${tomb},
          'archived', env.archived_at IS NOT NULL OR project.archived_at IS NOT NULL))
        FROM environments env JOIN projects project ON project.id = env.project_id
        WHERE env.id IN (SELECT value FROM json_each(${environments}))
          OR env.id IN (SELECT parent_id FROM environments WHERE id IN (SELECT value FROM json_each(${environments})) AND owner IS NOT NULL)
          OR env.id IN (
            SELECT json_extract(place.value, '$.environmentId')
            FROM policy, json_each(policy.metadata, '$.policy.protected') AS place
            -- Of a forged entry's, an element that is no object names nothing: json_extract would fail on a string.
            WHERE json_valid(policy.metadata) AND json_type(policy.metadata, '$.policy.protected') = 'array' AND place.type = 'object'
          )
      )),
      'ended', json((
        SELECT json_group_array(related_seq) FROM audit_log
        WHERE author = 'vault' AND action = 'reference.end' AND decision = 'allow' AND related_seq IN (SELECT value FROM json_each(${references}))
      )),
      'released', ${released === undefined
        ? sql`0`
        : sql`(
          -- The keys released within the window, but those asked for, up to one past the cap (snapshot.postgres.ts).
          SELECT count(*) FROM (
            SELECT 1 FROM vault_releases
            WHERE principal = ${released.principal} AND released_at > ${NOW} + ${released.clockOffsetMs} - ${released.windowMs}
              AND key NOT IN (SELECT value FROM json_each(${JSON.stringify(released.keys)}))
            LIMIT ${released.cap + 1}
          )
        ) + (SELECT count(DISTINCT value) FROM json_each(${JSON.stringify(released.keys)}))`}
    ) AS snapshot`;
}

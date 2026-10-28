import { TOMBSTONE } from '@coffre/core/schemas';
import { answerFrom, policyFrom, settingsFrom, type Access, type Settings } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import { engineOf, rowsOf } from '@coffre/db/dialect';
import { storedRole } from '@coffre/db/grants';
import { sql, type SQL } from 'drizzle-orm';

/**
 * What the vault would answer about `principal`, and its settings, as the
 * rows the vault keeps say it, in one statement: their member row, their
 * grants, the newest `policy.change` in the vault's name with the rows of
 * the environments it protects, and the newest `settings.change`. The same
 * rule as the vault's (`answerFrom`, `policyFrom`, `settingsFrom` in
 * @coffre/core/vault), but unchecked: the app holds none of the vault's
 * keys, so a row changed around the vault reads as it says, where the vault
 * would refuse its member as `tampered`, and an entry forged in its name as
 * the vault's own. So what it answers is only ever shown (`GET /api/me`),
 * never decided on (`Caller.unchecked`); everything the caller then asks
 * for, the vault decides.
 *
 *   Ada, a Viewer of market/dev, at `GET /api/me`   her row, her grant, the policy   no vault call
 *   her row changed around the vault                 shown as it says                  her next reveal: refused, tampered
 */
export async function answerShown(db: Queryable, principal: string): Promise<Shown> {
  const [row] = await rowsOf<{ answer: unknown }>(db, sql`SELECT (${answerQuery(db, sql`${principal}`)}) AS answer`);
  return answerOf(principal, row!.answer);
}

/**
 * Whether a request that only shows its caller may show what the rows say
 * (`answerShown`), or asks the vault, as any request does: only an active
 * member's. Anyone else is refused, or admitted, by the vault's answer, and
 * the rows would say neither: a person the deployment names an Owner
 * (`owners`) with no row yet, as behind Cloudflare Access, where nothing
 * signs them in first, is admitted by the vault's first answer about them,
 * and the rows hold no member until it has.
 */
export function shownActive(access: Access): boolean {
  return access.status === 'active';
}

/** What `answerShown` answers: the access, the settings, and the newest `policy.change`'s number, read with them. */
export type Shown = { access: Access; settings: Settings; policySeq: bigint | null };

/**
 * `answerShown`'s query, for the principal `principal` names, to run or to
 * read inside another: as a credential's read takes it with the credential,
 * by its row's principal (`findCredential`). One JSON value.
 */
export function answerQuery(db: Queryable, principal: SQL): SQL {
  return (engineOf(db) === 'postgres' ? postgres : sqlite)(principal);
}

/** The answer about `principal`, from what `answerQuery` read. */
export function answerOf(principal: string, answer: unknown): Shown {
  const raw = (typeof answer === 'string' ? JSON.parse(answer) : answer) as Raw;
  const at = Number(raw.at);
  const member = raw.member === null ? undefined : {
    status: raw.member.status,
    ...storedRole({ owner: raw.member.owner === true || raw.member.owner === 1, role: raw.member.role, scope: raw.member.scope }),
    generation: Number(raw.member.generation),
    statusChangedAt: Number(raw.member.statusChangedAt),
    statusChangedBy: raw.member.statusChangedBy,
  };
  const grants = raw.grants.map((grant) => ({ ...grant, expiresAt: grant.expiresAt === null ? null : Number(grant.expiresAt), grantedAt: Number(grant.grantedAt) }));
  const environments = new Map(raw.environments.map(({ id, slug, deleted }) => [id, { slug, deleted: Boolean(deleted) }]));
  const { policy } = policyFrom(raw.policy, environments, at);
  return {
    access: answerFrom(principal, member, grants, at, false, policy),
    settings: settingsFrom(raw.settings),
    policySeq: raw.policySeq === null ? null : BigInt(raw.policySeq),
  };
}

/**
 * What a request shows of its caller, read by the app from the vault's
 * rows, unchecked, with what it reads first: `'caller'`, all of it, and
 * nothing asked of the vault (`answerShown`), for `GET /api/me`, whose
 * caller is then `unchecked`; `'settings'`, the instance's settings alone,
 * beside the vault's answer, for a page's render, whose `me` shows them.
 */
export type Shows = 'caller' | 'settings';

/** The instance's settings as the vault's newest `settings.change` says them, unchecked, as `answerShown` reads them. */
export async function settingsShown(db: Queryable): Promise<Settings> {
  const [row] = await rowsOf<{ settings: string | null }>(db, sql`SELECT (${settingsQuery()}) AS settings`);
  return settingsFrom(row?.settings ?? null);
}

/** The same, with the newest `policy.change`'s number, which a request reads before it asks the vault (`newestPolicySeq`): one statement. */
export async function policySeqAndSettings(db: Queryable): Promise<{ policySeq: bigint | null; settings: Settings }> {
  const [row] = await rowsOf<{ seq: Int | null; settings: string | null }>(db, sql`SELECT (SELECT seq FROM (${newest('policy.change')}) AS policy) AS seq, (${settingsQuery()}) AS settings`);
  return { policySeq: row?.seq == null ? null : BigInt(row.seq), settings: settingsFrom(row?.settings ?? null) };
}

/** The newest `settings.change`'s metadata, to read inside another statement. */
export function settingsQuery(): SQL {
  return sql`SELECT metadata FROM (${newest('settings.change')}) AS settings`;
}

/** Whole numbers come as JSON numbers or text, as each dialect's query writes them. */
type Int = number | string;

type Raw = {
  at: Int;
  member: { status: 'active' | 'removed'; owner: boolean | number; role: string | null; scope: string | null; generation: Int; statusChangedAt: Int; statusChangedBy: string } | null;
  grants: { projectId: string | null; environmentId: string | null; role: string; expiresAt: Int | null; grantedAt: Int; grantedBy: string }[];
  policySeq: Int | null;
  policy: string | null;
  environments: { id: string; slug: string; deleted: boolean | number }[];
  settings: string | null;
};

const TOMB = `%${TOMBSTONE}%`;

/** The newest allowed entry of `action` in the vault's name, as the vault reads its newest (`newestVaultEntries`). */
const newest = (action: string) => sql`SELECT seq, metadata FROM audit_log WHERE author = 'vault' AND action = ${action} AND decision = 'allow' ORDER BY seq DESC LIMIT 1`;

/** On Postgres: one JSON value, each part one index range, as the vault's own read (vault snapshot.postgres.ts). */
function postgres(principal: SQL): SQL {
  return sql`
    WITH policy AS (${newest('policy.change')})
    SELECT json_build_object(
      'at', (extract(epoch from clock_timestamp()) * 1000)::bigint,
      'member', (
        SELECT json_build_object('status', status, 'owner', owner, 'role', role, 'scope', scope, 'generation', generation,
          'statusChangedAt', status_changed_at, 'statusChangedBy', status_changed_by)
        FROM vault_members WHERE principal = ${principal}
      ),
      'grants', (
        SELECT coalesce(json_agg(json_build_object(
          'projectId', coalesce(g.project_id, env.project_id), 'environmentId', g.environment_id, 'role', g.role,
          'expiresAt', g.expires_at, 'grantedAt', g.granted_at, 'grantedBy', g.granted_by)), '[]')
        FROM vault_grants g LEFT JOIN environments env ON env.id = g.environment_id
        WHERE g.principal = ${principal}
      ),
      'policySeq', (SELECT seq::text FROM policy),
      'policy', (SELECT metadata FROM policy),
      'environments', (
        SELECT coalesce(json_agg(json_build_object('id', env.id, 'slug', env.slug, 'deleted', env.slug LIKE ${TOMB} OR project.slug LIKE ${TOMB})), '[]')
        FROM environments env JOIN projects project ON project.id = env.project_id
        -- What the newest policy protects, by the ids its JSON names; one that is no UUID names nothing.
        WHERE env.id = ANY(ARRAY(
          SELECT (place #>> '{}')::uuid FROM policy, jsonb_path_query(policy.metadata::jsonb, '$.policy.protected[*].environmentId') AS place
          WHERE (place #>> '{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ))
      ),
      'settings', (${settingsQuery()})
    ) AS answer`;
}

/** On SQLite, the same (vault snapshot.sqlite.ts): a JSON value leaving a subquery is wrapped in `json(…)`. */
function sqlite(principal: SQL): SQL {
  return sql`
    WITH policy AS (${newest('policy.change')})
    SELECT json_object(
      'at', CAST(unixepoch('subsec') * 1000 AS INTEGER),
      'member', json((
        SELECT json_object('status', status, 'owner', owner, 'role', role, 'scope', scope, 'generation', generation,
          'statusChangedAt', status_changed_at, 'statusChangedBy', status_changed_by)
        FROM vault_members WHERE principal = ${principal}
      )),
      'grants', json((
        SELECT json_group_array(json_object(
          'projectId', coalesce(g.project_id, env.project_id), 'environmentId', g.environment_id, 'role', g.role,
          'expiresAt', g.expires_at, 'grantedAt', g.granted_at, 'grantedBy', g.granted_by))
        FROM vault_grants g LEFT JOIN environments env ON env.id = g.environment_id
        WHERE g.principal = ${principal}
      )),
      'policySeq', (SELECT seq FROM policy),
      'policy', (SELECT metadata FROM policy),
      'environments', json((
        SELECT json_group_array(json_object('id', env.id, 'slug', env.slug, 'deleted', env.slug LIKE ${TOMB} OR project.slug LIKE ${TOMB}))
        FROM environments env JOIN projects project ON project.id = env.project_id
        WHERE env.id IN (
          SELECT json_extract(place.value, '$.environmentId')
          FROM policy, json_each(policy.metadata, '$.policy.protected') AS place
          -- Of a forged entry's, an element that is no object names nothing: json_extract would fail on a string.
          WHERE json_valid(policy.metadata) AND json_type(policy.metadata, '$.policy.protected') = 'array' AND place.type = 'object'
        )
      )),
      'settings', (${settingsQuery()})
    ) AS answer`;
}

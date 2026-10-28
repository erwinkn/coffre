import type { WorkloadProfile } from '@coffre/core/identity';
import { prepared, tablesOf, type Queryable } from '@coffre/db';
import { newestSeqQuery } from '@coffre/db/log';
import * as dialect from '@coffre/db/dialect';
import { changedRows, clockMillis, truth } from '@coffre/db/dialect';
import type * as schema from '@coffre/db/schema';
import { and, asc, eq, inArray, isNotNull, isNull, lt, or, sql, type AnyColumn, type SQL } from 'drizzle-orm';

import { authMac, checkAuthRow } from '../auth-rows.ts';
import { hasTombstone, insert, type BindingRow } from './queries.ts';

// A workload's key-bound sessions (docs/design/workload-access.md, section
// 5): the one statement every request runs, the bindings an exchange reads,
// the freezes, and the conditional renewal. Queries of their own, beside
// queries.ts's, as every query of the server's lives under src/db.

type Tables = typeof schema;
export type SessionRow = Tables['credentials']['$inferSelect'];

/** The freeze kinds the log holds (section 8.2): a target is frozen while its newest allowed one of these is a freeze. */
const FREEZE_ACTIONS = ['workload.freeze', 'workload.unfreeze'] as const;

/** The expression `audit_log_freeze_idx` indexes: the target an entry names. */
function namedTarget(db: Queryable): SQL<string> {
  const { auditLog } = tablesOf(db);
  return dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'target')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.target')`;
}

/**
 * Whether `target` (a value, a column or an expression) is frozen now: its
 * newest allowed freeze or lift is a freeze. One index lookup each, through
 * `audit_log_freeze_idx`; a null target is never frozen. Their MACs are not
 * checked: a forged freeze can only refuse, and a deleted one breaks the
 * chain, which the next verification finds.
 */
function frozen(db: Queryable, target: SQL | string): SQL<boolean> {
  const { auditLog } = tablesOf(db);
  const newest = sql`(SELECT ${auditLog.action} FROM ${auditLog} WHERE ${auditLog.author} = 'app'
    AND ${auditLog.action} IN (${sql.join(FREEZE_ACTIONS.map((action) => sql`${action}`), sql`, `)}) AND ${auditLog.decision} = 'allow'
    AND ${namedTarget(db)} = ${target} ORDER BY ${auditLog.seq} DESC LIMIT 1)`;
  return truth(sql`COALESCE(${newest} = 'workload.freeze', ${dialect.engineOf(db) === 'postgres' ? sql`false` : sql`0`})`);
}

/** Whether binding `id` (a column, as text) has a tombstone, as a boolean (`hasTombstone`). */
function tombstoned(db: Queryable, id: SQL): SQL<boolean> {
  return truth(hasTombstone(db, id));
}

/** A binding's ID as text, to compare with what an entry or a target names. */
function idText(db: Queryable, id: SQL | AnyColumn): SQL {
  return dialect.engineOf(db) === 'postgres' ? sql`${id}::text` : sql`${id}`;
}

/** A place as a request names it: an environment's ID, or its path's slugs. */
export type NamedPlace = string | { project: string; environment: string } | null;

/** The placeholders a named place fills: by ID, or by its slugs. */
function placeParams(place: NamedPlace) {
  const byPath = typeof place === 'object' && place !== null ? place : null;
  return { place: typeof place === 'string' ? place : null, placeProject: byPath?.project ?? null, placeEnvironment: byPath?.environment ?? null };
}

/**
 * The place a request uses, as text: named by ID, or by path through the
 * slugs' unique indexes (never a personal config, nor a deleted one, whose
 * slug a `~` marks), or else `otherwise`; and its path as named now, null
 * for none or one deleted.
 */
function placeColumns(db: Queryable, otherwise: SQL) {
  const { environments, projects } = tablesOf(db);
  const byId = sql`CAST(${sql.placeholder('place')} AS text)`;
  const project = sql`CAST(${sql.placeholder('placeProject')} AS text)`;
  const byPath = sql`(SELECT ${idText(db, environments.id)} FROM ${environments} INNER JOIN ${projects} ON ${projects.id} = ${environments.projectId}
    WHERE ${projects.slug} = ${project} AND ${environments.slug} = CAST(${sql.placeholder('placeEnvironment')} AS text) AND ${environments.owner} IS NULL)`;
  const place = sql<string | null>`CASE WHEN ${byId} IS NOT NULL THEN ${byId} WHEN ${project} IS NOT NULL THEN ${byPath} ELSE ${otherwise} END`;
  const placePath = sql<string | null>`(SELECT ${projects.slug} || '/' || ${environments.slug} FROM ${environments} INNER JOIN ${projects} ON ${projects.id} = ${environments.projectId}
    WHERE ${environments.id} = ${dialect.engineOf(db) === 'postgres' ? sql`CAST(${place} AS uuid)` : place} AND ${environments.slug} NOT LIKE '%~%' AND ${projects.slug} NOT LIKE '%~%')`;
  return { place, placePath };
}

/** A one-row source, for a statement that reads only expressions. */
const single = sql`(SELECT 1 AS ${sql.identifier('one')}) AS ${sql.identifier('single')}`;

/** Text joined: `||` on both engines. */
const joined = (...parts: (SQL | string)[]) => sql.join(parts.map((part) => (typeof part === 'string' ? sql`${part}` : part)), sql` || `);

/**
 * Section 5.3's one statement, by the session token's hash: the session's
 * row and its ancestors' (a `narrow` child's, root first, at most four),
 * each with its member's standing as `vault_members` holds it (read
 * without the vault's MAC: removal only moves the generation on, so a
 * stale read can only refuse), its binding and whether a tombstone names
 * it, and the freezes of the instance, the service, the binding, the
 * session and, when the request names one, the credential it uses
 * (`credential:<environment id>/<name>`): in the place the request names,
 * by ID or by path (`market/prod`, found by its slugs), or when it names
 * none, in the one environment the session's row was made for. Each row
 * also says that place, its ID and its path as named now (null when a path
 * names no environment). With the database clock, which
 * keeps it out of Hyperdrive's cache and is what renewal decides on, and
 * the newest policy change, as `findCredential` reads it.
 *
 * One row per credential; the session's is the one with `tokenHash`, and
 * none at all for a token nobody holds. Nothing is checked here: the
 * caller holds every row to its MAC and every clause (`standingSession`).
 */
export async function workloadSession(db: Queryable, tokenHash: Buffer, uses: { place: NamedPlace; credential: string | null }) {
  const rows = await sessionRows(db, { tokenHash, ...placeParams(uses.place), credential: uses.credential });
  return rows.map((row) => ({
    ...row,
    policySeq: row.policySeq === null ? null : BigInt(row.policySeq),
  }));
}

const sessionRows = prepared((db) => sessionStatement(db));

/** Section 5.3's statement as built, before it is prepared: for a test that holds its plan to its indexes. */
export function sessionStatement(db: Queryable) {
  const { credentials, serviceBindings, vaultMembers } = tablesOf(db);
  const postgres = dialect.engineOf(db) === 'postgres';
  const tokenHash = sql.placeholder('tokenHash');
  // The binding a workload's row names, `binding:<id>`: every workload row has one, a child its root's.
  const bindingId = postgres
    ? sql`CASE WHEN ${credentials.kind} = 'workload' AND ${credentials.createdBy} LIKE 'binding:%' THEN CAST(substr(${credentials.createdBy}, 9) AS uuid) END`
    : sql`CASE WHEN ${credentials.kind} = 'workload' AND ${credentials.createdBy} LIKE 'binding:%' THEN substr(${credentials.createdBy}, 9) END`;
  // The session's ancestors, by the IDs its row lists (under its MAC): the IDs as uuids, an array, so each is a primary-key lookup.
  const ancestors = postgres
    ? sql`${credentials.id} = ANY(ARRAY(SELECT CAST(jsonb_array_elements_text(${sql.identifier('own')}.${sql.identifier('ancestors')}::jsonb) AS uuid) FROM ${credentials} AS ${sql.identifier('own')} WHERE ${sql.identifier('own')}.${sql.identifier('token_hash')} = ${tokenHash}))`
    : sql`${credentials.id} IN (SELECT ${sql.identifier('listed')}.${sql.identifier('value')} FROM ${credentials} AS ${sql.identifier('own')}, json_each(${sql.identifier('own')}.${sql.identifier('ancestors')}) AS ${sql.identifier('listed')} WHERE ${sql.identifier('own')}.${sql.identifier('token_hash')} = ${tokenHash})`;
  // The credential it uses, in the environment named or else the row's one place: null when it names none, or the row several.
  const name = sql`CAST(${sql.placeholder('credential')} AS text)`;
  const onlyPlace = postgres
    ? sql`CASE WHEN jsonb_array_length(${credentials.places}::jsonb) = 1 THEN ${credentials.places}::jsonb -> 0 ->> 'environmentId' END`
    : sql`CASE WHEN json_array_length(${credentials.places}) = 1 THEN json_extract(${credentials.places}, '$[0].environmentId') END`;
  // The place it uses: named, or else the row's one.
  const { place, placePath } = placeColumns(db, onlyPlace);
  const used = sql`CASE WHEN ${name} IS NULL THEN NULL ELSE 'credential:' || ${place} || '/' || ${name} END`;
  return db
    .select({
      credential: credentials,
      binding: serviceBindings,
      bindingTombstoned: tombstoned(db, idText(db, serviceBindings.id)),
      memberStatus: vaultMembers.status,
      memberGeneration: vaultMembers.generation,
      frozen: {
        instance: frozen(db, 'instance'),
        service: frozen(db, sql`${credentials.principal}`),
        binding: frozen(db, joined('binding:', idText(db, serviceBindings.id))),
        session: frozen(db, joined('session:', idText(db, credentials.id))),
        credential: frozen(db, used),
      },
      place,
      placePath,
      now: clockMillis(db),
      policySeq: sql<string | number | null>`(${newestSeqQuery(db, 'policy.change')})`,
    })
    .from(credentials)
    .leftJoin(vaultMembers, eq(vaultMembers.principal, credentials.principal))
    .leftJoin(serviceBindings, sql`${serviceBindings.id} = ${bindingId}`)
    .where(or(eq(credentials.tokenHash, tokenHash), ancestors));
}

/**
 * A Cloudflare call's binding (section 9.2), in one statement: the
 * service's live bindings of profile `cloudflare`, each with whether a
 * tombstone names it, its member's standing, the place the call names, by
 * ID or path, with its path as named now, and the freezes of the instance,
 * the service, the binding and, in that place, the credential the call
 * uses. A service holds at most a few; the caller takes the oldest that
 * stands.
 */
export async function callBindings(db: Queryable, principal: string, uses: { place: NamedPlace; credential: string | null }) {
  return bindingCalls(db, { principal, ...placeParams(uses.place), credential: uses.credential });
}

const bindingCalls = prepared((db) => {
  const { serviceBindings, vaultMembers } = tablesOf(db);
  const { place, placePath } = placeColumns(db, sql`NULL`);
  const name = sql`CAST(${sql.placeholder('credential')} AS text)`;
  return db
    .select({
      binding: serviceBindings,
      tombstoned: tombstoned(db, idText(db, serviceBindings.id)),
      memberStatus: vaultMembers.status,
      memberGeneration: vaultMembers.generation,
      frozen: {
        instance: frozen(db, 'instance'),
        service: frozen(db, sql`${serviceBindings.principal}`),
        binding: frozen(db, joined('binding:', idText(db, serviceBindings.id))),
        credential: frozen(db, sql`CASE WHEN ${name} IS NULL THEN NULL ELSE 'credential:' || ${place} || '/' || ${name} END`),
      },
      place,
      placePath,
      now: clockMillis(db),
      policySeq: sql<string | number | null>`(${newestSeqQuery(db, 'policy.change')})`,
    })
    .from(serviceBindings)
    .leftJoin(vaultMembers, eq(vaultMembers.principal, serviceBindings.principal))
    .where(and(
      eq(serviceBindings.principal, sql.placeholder('principal')),
      eq(serviceBindings.profile, 'cloudflare'),
      isNull(serviceBindings.revokedAt),
      isNotNull(serviceBindings.policy),
    ))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id));
});

/**
 * What `/api/auth/workload` may match for a proof, in one read: the
 * service's live bindings of `profiles` on `issuer`, in its current
 * generation, with no tombstone, each MAC-checked; only those with a
 * policy, so a bearer binding of before never makes a key-bound session,
 * and an explicit profile list, so a binding of another proof's (its
 * claims none) never matches a token (section 11, "Filtered by profile").
 * More than `max` is a database changed around the app, and matches nothing.
 */
export async function workloadCandidates(
  db: Queryable,
  chainKey: Buffer,
  principal: string,
  issuer: string,
  profiles: readonly WorkloadProfile[],
  max: number,
): Promise<BindingRow[]> {
  const { serviceBindings, vaultMembers } = tablesOf(db);
  if (profiles.length === 0) return [];
  const rows = await db
    .select({ binding: serviceBindings, tombstoned: tombstoned(db, idText(db, serviceBindings.id)), now: clockMillis(db) })
    .from(serviceBindings)
    .innerJoin(vaultMembers, and(eq(vaultMembers.principal, serviceBindings.principal), eq(vaultMembers.generation, serviceBindings.generation)))
    .where(and(
      eq(serviceBindings.principal, principal),
      eq(serviceBindings.issuer, issuer),
      isNull(serviceBindings.revokedAt),
      isNotNull(serviceBindings.policy),
      inArray(serviceBindings.profile, [...profiles]),
    ))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id))
    .limit(max + 1);
  if (rows.length > max) {
    console.error({ event: 'bindings_over_limit', principal, issuer }, 'a service holds more bindings than any can');
    return [];
  }
  return rows.filter((row) => !row.tombstoned).map((row) => row.binding).filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
}

/** Which of these freeze targets are frozen now, in one statement: the exchange's check, under the log's head. */
export async function frozenTargets(db: Queryable, targets: readonly string[]): Promise<string[]> {
  if (targets.length === 0) return [];
  // One row of booleans: `frozen` is a scalar subquery each.
  const columns = Object.fromEntries(targets.map((target, i) => [`t${i}`, frozen(db, target)]));
  const [row] = (await db.select({ ...columns, now: clockMillis(db) }).from(single)) as unknown as Record<string, boolean>[];
  return targets.filter((_, i) => row?.[`t${i}`] === true);
}

/** Insert a workload's session, its MAC over everything that binds it (`workload_credentials`). */
export async function insertSession(db: Queryable, chainKey: Buffer, row: SessionFields): Promise<void> {
  await insert(db, tablesOf(db).credentials, signedSession(chainKey, row));
}

/** A workload's session's columns, as it is made. */
export type SessionFields = Omit<Tables['credentials']['$inferInsert'], 'authMac'> & {
  id: string; kind: 'workload'; tokenHash: Buffer; tokenHint: string; generation: number; principal: string; identityId: null; createdBy: string; expiresAt: Date;
  revokedAt: null; scope: string | null; places: string | null; jkt: string; notAfter: Date; ancestors: string | null; constraints: string | null;
  enrollmentId: string | null; approvedAt: Date | null; approvedBy: string | null;
};

/** A workload's session's row with its MAC: what `insertSession` writes, and what the vault writes for 0.15's sign-in (T149). */
export function signedSession(chainKey: Buffer, row: SessionFields): SessionFields & { authMac: Buffer } {
  return { ...row, authMac: authMac(chainKey, 'credentials', row) };
}

/** The database's clock, in milliseconds, as this statement runs: renewal's first step. */
export async function databaseNow(db: Queryable): Promise<number> {
  const [row] = await db.select({ now: clockMillis(db) }).from(single);
  return row!.now;
}

/** How close to its expiry a session may still be renewed: a renewal that arrives later revives nothing. */
export const RENEW_MARGIN_MS = 5_000;

/**
 * Renewal's second step (section 4.4, 5.4): move a session's expiry to
 * `expiresAt`, its MAC with it, only while it is still exactly as it was
 * read (`old`: its expiry and MAC), not revoked, and more than
 * `RENEW_MARGIN_MS` from expiring on the database's clock as this
 * statement runs. A renewal that lost a race, or came late, updates
 * nothing, so it never revives a session a count on the same clock already
 * saw as dead. True if it moved.
 */
export async function renewSession(db: Queryable, chainKey: Buffer, old: SessionRow, expiresAt: Date): Promise<boolean> {
  const { credentials } = tablesOf(db);
  const margin = dialect.engineOf(db) === 'postgres'
    ? sql`${credentials.expiresAt} > clock_timestamp() + interval '${sql.raw(String(RENEW_MARGIN_MS))} milliseconds'`
    : sql`${credentials.expiresAt} > CAST(unixepoch('subsec') * 1000 AS INTEGER) + ${RENEW_MARGIN_MS}`;
  const next = { ...old, expiresAt };
  const changed = await db.update(credentials)
    .set({ expiresAt, authMac: authMac(chainKey, 'credentials', next) })
    .where(and(
      eq(credentials.id, old.id),
      eq(credentials.expiresAt, old.expiresAt),
      eq(credentials.authMac, old.authMac),
      isNull(credentials.revokedAt),
      margin,
    ));
  return changedRows(changed) === 1;
}

/** These keys' names, by ID: a binding's `reads`, shown by name. */
export async function keyNames(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const { secrets } = tablesOf(db);
  const rows = await db.select({ id: secrets.id, key: secrets.key }).from(secrets).where(inArray(secrets.id, [...new Set(ids)]));
  return new Map(rows.map((row) => [row.id, row.key]));
}


/**
 * Whether this caller raises `service`'s `kind` alert now: the first to
 * ask since `everyMs` before `now`, as one conditional write decides, so
 * that two isolates or processes at once raise it once. A read first, so
 * that one capped out, as nearly all are, writes and locks nothing; each
 * a statement of its own, outside any transaction, so none waits for, or
 * holds, the log's head.
 */
export async function claimAlert(db: Queryable, service: string, kind: string, now: Date, everyMs: number): Promise<boolean> {
  const { cappedAlerts } = tablesOf(db);
  const since = new Date(now.getTime() - everyMs);
  const [last] = await db.select({ raisedAt: cappedAlerts.raisedAt }).from(cappedAlerts).where(and(eq(cappedAlerts.service, service), eq(cappedAlerts.kind, kind)));
  if (last !== undefined && last.raisedAt >= since) return false;
  const claimed = await db.insert(cappedAlerts)
    .values({ service, kind, raisedAt: now })
    .onConflictDoUpdate({
      target: [cappedAlerts.service, cappedAlerts.kind],
      set: { raisedAt: now },
      setWhere: lt(cappedAlerts.raisedAt, since),
    });
  return changedRows(claimed) === 1;
}

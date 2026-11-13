import type { WorkloadProfile } from '@coffre/core/identity';
import { prepared, type Queryable } from '@coffre/db';
import { newestSeqQuery } from '@coffre/db/log';
import { changedRows, clockMillis, truth } from '@coffre/db/dialect';
import type * as schema from '@coffre/db/schema';
import { and, asc, eq, inArray, isNotNull, isNull, lt, or, sql, type AnyColumn, type SQL } from 'drizzle-orm';

import { authMac, checkAuthRow } from '../auth-rows.ts';
import { bindingLive, insert, newestChangeColumns, newestChanges, type BindingRow, type NewestChanges } from './queries.ts';
import { cappedAlerts, credentials, environments, principals, projects, secrets, serviceBindings } from '@coffre/db/schema';

// A workload's key-bound sessions (docs/design/workload-access.md, section
// 5): the one statement every request runs, the bindings an exchange reads,
// and the conditional renewal. Queries of their own, beside
// queries.ts's, as every query of the server's lives under src/db.

type Tables = typeof schema;
export type SessionRow = Tables['credentials']['$inferSelect'];

/** Whether a binding's row is dead to the app: not standing as the log has it (`bindingLive`), as a boolean. */
function tombstoned(binding: typeof serviceBindings): SQL<boolean> {
  return truth(sql`NOT ${bindingLive(binding.id, binding.seal)}`);
}

/** An ID as text. */
function idText(id: SQL | AnyColumn): SQL {
  return sql`${id}::text`;
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
function placeColumns(otherwise: SQL) {
  const byId = sql`CAST(${sql.placeholder('place')} AS text)`;
  const project = sql`CAST(${sql.placeholder('placeProject')} AS text)`;
  const byPath = sql`(SELECT ${idText(environments.id)} FROM ${environments} INNER JOIN ${projects} ON ${projects.id} = ${environments.projectId}
    WHERE ${projects.slug} = ${project} AND ${environments.slug} = CAST(${sql.placeholder('placeEnvironment')} AS text) AND ${environments.owner} IS NULL)`;
  const place = sql<string | null>`CASE WHEN ${byId} IS NOT NULL THEN ${byId} WHEN ${project} IS NOT NULL THEN ${byPath} ELSE ${otherwise} END`;
  const placePath = sql<string | null>`(SELECT ${projects.slug} || '/' || ${environments.slug} FROM ${environments} INNER JOIN ${projects} ON ${projects.id} = ${environments.projectId}
    WHERE ${environments.id} = CAST(${place} AS uuid) AND ${environments.slug} NOT LIKE '%~%' AND ${projects.slug} NOT LIKE '%~%')`;
  return { place, placePath };
}

/** A one-row source, for a statement that reads only expressions. */
const single = sql`(SELECT 1 AS ${sql.identifier('one')}) AS ${sql.identifier('single')}`;

/**
 * Section 5.3's one statement, by the session token's hash: the session's
 * row and its ancestors' (a `narrow` child's, root first, at most four),
 * each with its member's standing as `principals` holds it (read
 * without the vault's MAC: removal only moves the generation on, so a
 * stale read can only refuse), its binding and whether a tombstone names
 * it, and the place the request uses: the one it names, by ID or by
 * path (`market/prod`, found by its slugs), or when it names none, the one
 * environment the session's row was made for, its ID and its path as
 * named now (null when a path names no environment). With the database
 * clock, which keeps it out of Hyperdrive's cache and is what renewal
 * decides on, and the newest policy change, as `findCredential` reads it.
 *
 * One row per credential; the session's is the one with `tokenHash`, and
 * none at all for a token nobody holds. Nothing is checked here: the
 * caller holds every row to its MAC and every clause (`standingSession`).
 */
export async function workloadSession(db: Queryable, tokenHash: Buffer, place: NamedPlace) {
  const rows = await sessionRows(db, { tokenHash, ...placeParams(place) });
  return rows.map((row) => ({
    ...row,
    policySeq: row.policySeq === null ? null : BigInt(row.policySeq),
  }));
}

const sessionRows = prepared((db) => sessionStatement(db));

/** Section 5.3's statement as built, before it is prepared: for a test that holds its plan to its indexes. */
export function sessionStatement(db: Queryable) {
  const tokenHash = sql.placeholder('tokenHash');
  // The binding a workload's row names, `binding:<id>`: every workload row has one, a child its root's.
  const bindingId = sql`CASE WHEN ${credentials.kind} = 'workload' AND ${credentials.createdBy} LIKE 'binding:%' THEN CAST(substr(${credentials.createdBy}, 9) AS uuid) END`;
  // The session's ancestors, by the IDs its row lists (under its MAC): the IDs as uuids, an array, so each is a primary-key lookup.
  const ancestors = sql`${credentials.id} = ANY(ARRAY(SELECT CAST(jsonb_array_elements_text(${sql.identifier('own')}.${sql.identifier('ancestors')}::jsonb) AS uuid) FROM ${credentials} AS ${sql.identifier('own')} WHERE ${sql.identifier('own')}.${sql.identifier('token_hash')} = ${tokenHash}))`;
  // The row's one place: null when it lists none, or several.
  const onlyPlace = sql`CASE WHEN jsonb_array_length(${credentials.places}::jsonb) = 1 THEN ${credentials.places}::jsonb -> 0 ->> 'environmentId' END`;
  // The place it uses: named, or else the row's one.
  const { place, placePath } = placeColumns(onlyPlace);
  return db
    .select({
      credential: credentials,
      binding: serviceBindings,
      bindingTombstoned: tombstoned(serviceBindings),
      memberStatus: principals.status,
      memberGeneration: principals.generation,
      place,
      placePath,
      now: clockMillis(),
      policySeq: sql<string | number | null>`(${newestSeqQuery(db, 'policy')})`,
    })
    .from(credentials)
    .leftJoin(principals, eq(principals.principal, credentials.principal))
    .leftJoin(serviceBindings, sql`${serviceBindings.id} = ${bindingId}`)
    .where(or(eq(credentials.tokenHash, tokenHash), ancestors));
}

/**
 * A Cloudflare call's binding (section 9.2), in one statement: the
 * service's live bindings of profile `cloudflare`, each with whether a
 * tombstone names it, its member's standing, and the place the call
 * names, by ID or path, with its path as named now. A service holds at
 * most a few; the caller takes the oldest that stands.
 */
export async function callBindings(db: Queryable, principal: string, place: NamedPlace) {
  return bindingCalls(db, { principal, ...placeParams(place) });
}

const bindingCalls = prepared((db) => {
  const { place, placePath } = placeColumns(sql`NULL`);
  return db
    .select({
      binding: serviceBindings,
      tombstoned: tombstoned(serviceBindings),
      memberStatus: principals.status,
      memberGeneration: principals.generation,
      place,
      placePath,
      now: clockMillis(),
      policySeq: sql<string | number | null>`(${newestSeqQuery(db, 'policy')})`,
    })
    .from(serviceBindings)
    .leftJoin(principals, eq(principals.principal, serviceBindings.principal))
    .where(and(
      eq(serviceBindings.principal, sql.placeholder('principal')),
      eq(serviceBindings.profile, 'cloudflare'),
      isNull(serviceBindings.revokedAt),
      // Closed by a removal under way (W331): it takes no call from then on, as it signs nobody in.
      isNull(serviceBindings.closedAt),
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
 * With them, the account's and each binding's newest change, which the
 * vault checks and pins in its one statement (T192, `NewestChanges`).
 * Each is read whole, its label included, and its MAC checked over its
 * claims and issuer, whatever their size: an Owner's, and accepted
 * (docs/design/workload-access.md, section 3, "What an Owner's bindings
 * cost").
 */
export async function workloadCandidates(
  db: Queryable,
  chainKey: Buffer,
  principal: string,
  issuer: string,
  profiles: readonly WorkloadProfile[],
  max: number,
): Promise<{ bindings: BindingRow[]; newest: NewestChanges }> {
  if (profiles.length === 0) return { bindings: [], newest: newestChanges([]) };
  const rows = await db
    .select({ binding: serviceBindings, ...newestChangeColumns(principal, serviceBindings.id), now: clockMillis() })
    .from(serviceBindings)
    .innerJoin(principals, and(eq(principals.principal, serviceBindings.principal), eq(principals.generation, serviceBindings.generation)))
    .where(and(
      eq(serviceBindings.principal, principal),
      eq(serviceBindings.issuer, issuer),
      isNull(serviceBindings.revokedAt),
      // Closed by a removal under way (W331): it signs nobody in, so it shadows no binding that would (review r6).
      isNull(serviceBindings.closedAt),
      isNotNull(serviceBindings.policy),
      inArray(serviceBindings.profile, [...profiles]),
      // Standing as the log has it, as the vault holds it to after: a row put back over its end matches nothing here.
      bindingLive(serviceBindings.id, serviceBindings.seal),
    ))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id))
    .limit(max + 1);
  if (rows.length > max) {
    console.error({ event: 'bindings_over_limit', principal, issuer }, 'a service holds more bindings than any can');
    return { bindings: [], newest: newestChanges([]) };
  }
  const bindings = rows.map((row) => row.binding).filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
  return { bindings, newest: newestChanges(rows) };
}

/** Insert a workload's session, its MAC over everything that binds it (`workload_credentials`). */
export async function insertSession(db: Queryable, chainKey: Buffer, row: SessionFields): Promise<void> {
  await insert(db, credentials, signedSession(chainKey, row));
}

/** A workload's session's columns, as it is made. */
export type SessionFields = Omit<Tables['credentials']['$inferInsert'], 'authMac'> & {
  id: string; kind: 'workload'; tokenHash: Buffer; tokenHint: string; generation: number; principal: string; identityId: null; createdBy: string; expiresAt: Date;
  revokedAt: null; scope: string | null; places: string | null; jkt: string; notAfter: Date; ancestors: string | null; constraints: string | null;
  enrollmentId: string | null; approvedAt: Date | null; approvedBy: string | null;
  /** A workload's session stands on its token, never on a person's passkey. */
  passkeyId?: null; confirmedAt?: null;
};

/** A workload's session's row with its MAC: what `insertSession` writes, and what the vault writes for 0.15's sign-in (T149). */
export function signedSession(chainKey: Buffer, row: SessionFields): SessionFields & { authMac: Buffer } {
  const fields = { ...row, passkeyId: null, confirmedAt: null };
  return { ...fields, authMac: authMac(chainKey, 'credentials', fields) };
}

/** The database's clock, in milliseconds, as this statement runs: renewal's first step. */
export async function databaseNow(db: Queryable): Promise<number> {
  const [row] = await db.select({ now: clockMillis() }).from(single);
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
  const margin = sql`${credentials.expiresAt} > clock_timestamp() + interval '${sql.raw(String(RENEW_MARGIN_MS))} milliseconds'`;
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

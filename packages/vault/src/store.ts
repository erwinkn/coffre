import { EVERYWHERE, ownsInstance, type InstanceRole, type Scope } from '@coffre/core/access';
import type { StoredEntry } from '@coffre/core/audit';
import { ACCESS_ACTIONS, type BindingColumns, type ConnectionColumns, type CredentialColumns, type EnvironmentColumns, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { later, laterRows, prepared, type Queryable, type Transaction } from '@coffre/db';
import { clockMillis, rowsOf, tombstone, truth } from '@coffre/db/dialect';
import { readGrants, roleColumns, storedRole, type GrantRow } from '@coffre/db/grants';
import { accessAllowed, authoredBy, changesOf, entriesOf, entryColumns, firstEntryUnder, newestVaultEntries, numbersIn, recorded, strictly, withinBytes, type ChangeNumbers } from '@coffre/db/log';

import { MAX_BULK_WINDOW_MINUTES } from './config.ts';
import { indexBytes, objectKey, type EnvironmentInput, type Input, type Kind, type ProxyItem, type Ref, type RoleInput } from './inputs.ts';
import { changeHolds, CUTOVER_OBJECT, type ChangeRow, type LogMacKey } from './log-entry.ts';
import type { StoredRole } from './role-rows.ts';
import { configObject, environmentObject, memberStanding, policyObject, principalObject, secretObject } from './objects.ts';
import { and, asc, count, desc, eq, gt, gte, inArray, isNotNull, isNull, like, lt, lte, or, sql, type SQL, type SQLWrapper } from 'drizzle-orm';
import { auditChainHead, auditLog, environments, grants as grantsTable, logChanges, logConfig, policy, principals, projects, proxyDefinitions, proxyReserved, roles, secrets, secretVersions } from '@coffre/db/schema';

/**
 * Every query the vault makes, and the only code in it that holds them.
 * Each reads or writes one thing; what they add up to, a decision, is in
 * `vault.ts`. The tables are the shared database's: `principals` and
 * `grants`, which only the vault writes, the places it decides on,
 * and the audit log, where its entries are the ones `author = 'vault'`.
 *
 * Times are milliseconds since the epoch, from the database's clock.
 */

/** A member's row; schema.ts in @coffre/db says what each column means. */
export type Member = {
  principal: string;
  status: 'active' | 'removed';
  /** A person's instance role and its scope; `member` everywhere for anyone else (`memberOf`). */
  role: InstanceRole;
  scope: Scope;
  generation: number;
  createdAt: number;
  createdBy: string;
  statusChangedAt: number;
  statusChangedBy: string;
  /** The vault's last access entry about the member. */
  accessSeq: bigint;
  /** The vault's MAC over this row and the member's grants; rows.ts. */
  mac: Buffer;
};

/** Every entry that changes who is a member or what they hold. */
export { ACCESS_ACTIONS };

/**
 * Where a grant applies: a project, or one of its environments (with its
 * project, which its row finds through `environments`); or, for a grant on
 * every project of 0.4, until the vault replaces it, neither, with the one
 * environment slug it covers in each, if any.
 */
export type Place = Pick<GrantRow, 'projectId' | 'environmentId' | 'environmentSlug'>;

/** A grant as stored, which `@coffre/db/grants` reads and writes. */
export type { GrantRow };
export { accessEntriesAbout, insertGrant, liveProjects } from '@coffre/db/grants';
export { newestVaultEntries } from '@coffre/db/log';

/**
 * Fail each lock wait in this transaction after `lockMs`,
 * rather than wait for ever behind a transaction that never ends; with
 * `statementMs`, any statement that takes longer, too. A queue for a row each
 * holder updates, as the log's head, is no one wait: a waiter follows each
 * update to the row's new version and waits again, its lock's clock started
 * over, so only the statement's own bound ends it.
 */
export async function boundLockWaits(tx: Transaction, lockMs: number, statementMs?: number, { final = false }: { final?: boolean } = {}): Promise<void> {
  const lock = String(Math.trunc(lockMs));
  const statement = statementMs === undefined
    ? sql`SELECT set_config('lock_timeout', ${lock}, true)`
    : sql`SELECT set_config('lock_timeout', ${lock}, true), set_config('statement_timeout', ${String(Math.trunc(Math.min(statementMs, MAX_STATEMENT_MS)))}, true)`;
  // `final`: nothing awaits it, it goes first in what the transaction asks next (`later`).
  if (final) later(tx, statement);
  else await tx.execute(statement);
}

/** Postgres's `statement_timeout` takes an int of milliseconds: a bound past it is none. */
const MAX_STATEMENT_MS = 2_147_483_647;

/**
 * How long a release is kept: the longest bulk limit window
 * (`MAX_BULK_WINDOW_MINUTES`, a day), and an hour, a margin for the
 * database's clock stepping back between a prune and a later count, which
 * is seconds. Migration 0021's `prune_vault_releases` holds the same, a day
 * and an hour, in its own SQL: a longer window takes a migration too.
 */
export const RELEASES_KEPT_MS = MAX_BULK_WINDOW_MINUTES * 60_000 + 3_600_000;

/**
 * Delete up to `atMost` rows of `vault_releases` released over
 * `RELEASES_KEPT_MS` before the database's clock: what no bulk count can
 * read again. The vault's login deletes no row itself, and asks
 * `prune_vault_releases`, which deletes only those (migration 0021). How
 * many went.
 */
export async function pruneReleases(db: Queryable, atMost: number): Promise<number> {
  const [row] = await rowsOf<{ pruned: number }>(db, sql`SELECT prune_vault_releases(${atMost}::int) AS pruned`);
  return row!.pruned;
}

/** The database's clock, now. */
export async function now(db: Queryable): Promise<number> {
  const [{ at }] = await clock(db);
  return at;
}

const clock = prepared((db) => db.select({ at: clockMillis() }).from(auditChainHead));

// --- members --------------------------------------------------------------------

function memberColumns() {
  return {
    principal: principals.principal,
    status: principals.status,
    owner: principals.owner,
    role: principals.role,
    scope: principals.scope,
    generation: principals.generation,
    createdAt: principals.createdAt,
    createdBy: principals.createdBy,
    statusChangedAt: principals.statusChangedAt,
    statusChangedBy: principals.statusChangedBy,
    accessSeq: principals.accessSeq,
    mac: principals.mac,
  };
}

/** A row as stored: `role` and `scope` as their columns hold them. */
export type StoredMember = Omit<Member, 'role' | 'scope'> & { owner: boolean; role: string | null; scope: string | null };

/** A member as their row says (`storedRole`). */
export function memberOf({ owner, role, scope, ...row }: StoredMember): Member {
  return { ...row, ...storedRole({ owner, role, scope }) };
}

function storedChange(change: Partial<Omit<Member, 'principal'>>): Record<string, unknown> {
  const { role, scope, ...rest } = change;
  if (role === undefined) return rest;
  return { ...rest, ...roleColumns(role, scope ?? EVERYWHERE) };
}

export async function member(db: Queryable, principal: string): Promise<Member | undefined> {
  const [row] = await memberRow(db, { principal });
  return row === undefined ? undefined : memberOf(row as StoredMember);
}

const memberRow = prepared((db) => {
  return db.select(memberColumns()).from(principals).where(eq(principals.principal, sql.placeholder('principal')));
});

export async function allMembers(db: Queryable): Promise<Member[]> {
  return ((await db.select(memberColumns()).from(principals).orderBy(asc(principals.principal))) as StoredMember[]).map(memberOf);
}

/**
 * The rows that say their member is an active Owner of the whole instance
 * (`ownsInstance` in @coffre/core/access), as stored: a row changed around
 * the vault says so too, which the caller checks. The scope is read as the
 * row's MAC reads it, parsed: any way of writing everywhere is everywhere.
 */
export async function instanceOwners(db: Queryable): Promise<Member[]> {
  const rows = await db
    .select(memberColumns())
    .from(principals)
    .where(and(eq(principals.status, 'active'), eq(principals.role, 'owner')))
    .orderBy(asc(principals.principal));
  return (rows as StoredMember[]).map(memberOf).filter(ownsInstance);
}

/**
 * Lock these members' rows for the rest of the transaction, in one order
 * everywhere, and read them: those that have none are not in the map. Every
 * decision about a member takes its row first, so two of them, from any
 * process, never interleave; but `shared`, for a decision that writes no
 * member's row, as a read, takes them as other such decisions do, side by
 * side, and only what changes the member waits for it, and it for that.
 *
 * Postgres lets a share lock join those already held even while a writer
 * waits for them, so a steady stream of one member's reads would hold a
 * removal off for ever. So each row comes with an advisory lock on its
 * principal, which the lock manager queues in order: a read asked after a
 * writer waits behind it. The same statement takes it, then the row, one
 * principal after another. 0.15's `change_input` (0022_log_015) takes the
 * same two in one statement, before the log's head, and
 * scripts/test-schema.sh holds the pair to that order: keep them together.
 */
export async function lockMembers(tx: Transaction, principals: readonly string[], shared = false): Promise<Map<string, Member>> {
  const rows = await membersLocked(tx, principals, shared);
  return new Map((rows as (StoredMember & { queued?: unknown })[]).map(({ queued: _, ...row }) => [row.principal, memberOf(row)]));
}

/**
 * `lockMembers` for a write that needs none of the rows, only their locks: not waited for (`later`), it goes in its
 * place in what the transaction asks next, its COMMIT at the latest.
 */
export function laterLockMembers(tx: Transaction, principals: readonly string[]): void {
  later(tx, membersLocked(tx, principals, false));
}

/** The members' queues and rows, locked in principal order (`lockMembers`). */
function membersLocked(tx: Transaction, names: readonly string[], shared: boolean) {
  const queued = sql`${sql.raw(shared ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock')}(${MEMBER_QUEUE}, hashtext(${principals.principal}))`;
  return tx
    .select({ ...memberColumns(), queued })
    .from(principals)
    .where(inArray(principals.principal, [...new Set(names)]))
    .orderBy(asc(principals.principal))
    .for(shared ? 'share' : 'no key update');
}

/**
 * The first key of the members' queues, Postgres's advisory locks: the
 * second is the principal's hash, and the pair is in a space of its own,
 * apart from the migrator's single key. A hash two principals share queues
 * one behind the other's writer; and two changes that each lock two
 * members, where one's first and the other's second share it, can wait on
 * each other, which Postgres ends after a second by failing one of them
 * (40P01): about n² / 2³³ for an instance of n members.
 */
const MEMBER_QUEUE = 0x636f666d;

/**
 * Add `row`. A principal has one row: when two decisions admit the same
 * one at once, the second fails here, and rolls back with its entries.
 */
export async function insertMember(
  tx: Transaction,
  row: Member,
  /** `final`: nothing awaits it, it goes with what the transaction asks next, its COMMIT at the latest (`later`). */
  { final = false }: { final?: boolean } = {},
): Promise<void> {
  const statement = tx.insert(principals).values(storedChange(row) as typeof principals.$inferInsert);
  if (final) later(tx, statement);
  else await statement;
}

export async function updateMember(
  tx: Transaction,
  principal: string,
  change: Partial<Omit<Member, 'principal'>>,
  /** `final`: nothing awaits it, it goes with what the transaction asks next, its COMMIT at the latest (`later`). */
  { final = false }: { final?: boolean } = {},
): Promise<void> {
  const statement = tx.update(principals).set(storedChange(change)).where(eq(principals.principal, principal));
  if (final) later(tx, statement);
  else await statement;
}

// --- grants ---------------------------------------------------------------------

/** Grants, lapsed ones too, each with its project, which an environment's grant finds through `environments`. */
export function grants(db: Queryable, principal?: string): Promise<GrantRow[]> {
  return readGrants(db, principal === undefined ? {} : { principal });
}

/**
 * A grant's row names its environment, or its project when it has none, or
 * neither on every project, with the slug it covers there, if any.
 */
function at(place: Place) {
  if (place.environmentId !== null) return eq(grantsTable.environmentId, place.environmentId);
  if (place.projectId !== null) return and(eq(grantsTable.projectId, place.projectId), isNull(grantsTable.environmentId));
  return and(
    isNull(grantsTable.projectId),
    isNull(grantsTable.environmentId),
    place.environmentSlug === null ? isNull(grantsTable.environmentSlug) : eq(grantsTable.environmentSlug, place.environmentSlug),
  );
}

/** An environment as a decision reads it. */
export type EnvironmentRow = {
  projectId: string;
  slug: string;
  owner: string | null;
  parentId: string | null;
  deleted: boolean;
  archived: boolean;
  /** Read when asked (`seals`): what 0.15's log holds the row to. */
  sealed?: EnvironmentSeal;
};

/**
 * What 0.15's log holds an environment's row to (T159): the row's object
 * (`environmentObject`), its seal, and its object's newest change's seal,
 * null for none, with that change whole (`change`), its MAC to check
 * (T190, review r3): the seal column alone is a writer's to edit. The vault
 * checks them before it decides on the row.
 */
export type EnvironmentSeal = { object: EnvironmentInput; seal: Buffer | null; newest: Buffer | null; change: Omit<ChangeRow, 'number'> | null };

/**
 * Each of these environments that exists, by id, with its project, its
 * slug, what grants on one slug in every project match, and whether it was
 * deleted, alone or with its project: then no key under it opens, or is
 * wrapped, whatever grant would cover it; `all`, every one. With `seals`,
 * what 0.15's log holds each to as well, in the same statement.
 */
export async function environmentsById(
  db: Queryable,
  ids: readonly string[] | 'all',
  { seals = false }: { seals?: boolean } = {},
): Promise<Map<string, EnvironmentRow>> {
  if (ids !== 'all' && ids.length === 0) return new Map();
  return environmentRows(db, ids, seals);
}

async function environmentRows(db: Queryable, ids: readonly string[] | 'all', seals: boolean): Promise<Map<string, EnvironmentRow>> {
  const columns = {
    id: environments.id,
    projectId: environments.projectId,
    slug: environments.slug,
    // A personal config's owner, and the environment it is a config of, whose read it takes.
    owner: environments.owner,
    parentId: environments.parentId,
    deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!),
    // Only what names a fork asks it: nothing is decided on it.
    archived: truth(or(isNotNull(environments.archivedAt), isNotNull(projects.archivedAt))!),
  };
  const sealColumns = {
    protected: environments.protected,
    ownArchived: truth(isNotNull(environments.archivedAt)),
    projectArchived: truth(isNotNull(projects.archivedAt)),
    seal: environments.seal,
    // One probe of its object's changes, newest first (`log_changes_object_idx`): that change whole, its MAC to check.
    newest: sql<NewestColumns | string | null>`${newestChangeJson(sql`log_object('environment', ${environments.id}::text)`)}`,
  };
  const rows = (await db
    .select(seals ? { ...columns, ...sealColumns } : columns)
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(ids === 'all' ? undefined : inArray(environments.id, [...new Set(ids)]))) as (Omit<EnvironmentRow, 'sealed'> & { id: string } & Partial<SealedColumns>)[];
  // An id asked with no row, which the log holds a change of: deleted outright around it (review r5). A statement more,
  // only when a row is missing.
  const rowless = seals && ids !== 'all' ? [...new Set(ids)].filter((id) => !rows.some((row) => row.id === id)) : [];
  const gone = await loggedEnvironments(db, rowless);
  return new Map<string, EnvironmentRow>([...[...gone].map(([id, last]) => [id, goneEnvironment(id, last)] as const), ...rows.map(({ id, protected: guarded, ownArchived, projectArchived, seal, newest: last, ...environment }) => [id, {
    ...environment,
    ...(seals ? {
      sealed: environmentSeal(
        { id, projectId: environment.projectId, slug: environment.slug, owner: environment.owner, parentId: environment.parentId, protected: guarded ?? null, archived: Boolean(ownArchived), projectArchived: Boolean(projectArchived) },
        seal ?? null,
        last ?? null,
      ),
    } : {}),
  }] as const)]);
}

/**
 * A place the log holds a change of, which no row answers to (deleted outright around the log, or its project's): read
 * as a row whose seal is none, which no check passes (`#placeFault`), so that every decision on it fails closed as on
 * any other row the log does not hold, a protection on it kept (review r5). Its other columns name nothing.
 */
export function goneEnvironment(id: string, newest: Buffer | null): EnvironmentRow {
  const columns = { id, projectId: '', slug: '', owner: null, parentId: null, protected: null, archived: false, projectArchived: false };
  return { projectId: '', slug: '', owner: null, parentId: null, deleted: false, archived: false, sealed: { object: environmentObject(columns), seal: null, newest, change: null } };
}

/**
 * Of these environment ids, those the log holds a change of: by its newest seal, null for one that left none. One probe
 * of each object's changes.
 */
async function loggedEnvironments(db: Queryable, ids: readonly string[]): Promise<Map<string, Buffer | null>> {
  if (ids.length === 0) return new Map();
  // Still no row as of this statement: one made since the read before is no place deleted (review r6).
  const environment = changesOf('l', sql`log_object('environment', g.id::text)`);
  const rows = await rowsOf<{ id: string; seal: Buffer | Uint8Array | null }>(db, sql`SELECT g.id::text AS id, l.seal FROM unnest(${sql.param([...ids])}::uuid[]) AS g (id)
    CROSS JOIN LATERAL (SELECT l.seal FROM log_changes l WHERE ${environment.where} ORDER BY ${environment.order} LIMIT 1) l
    WHERE NOT EXISTS (SELECT 1 FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = g.id)`);
  return new Map(rows.map((row) => [row.id, bytes(row.seal)]));
}

/** The columns `environmentsById` reads with `seals`, as the drivers answer them. */
type SealedColumns = { protected: boolean | null; ownArchived: boolean; projectArchived: boolean; seal: Buffer | Uint8Array | null; newest: NewestColumns | string | null };

/** An environment's row as 0.15's log holds it to (`EnvironmentSeal`), from its columns, its seal and its newest change as read. */
export function environmentSeal(columns: EnvironmentColumns, seal: Buffer | Uint8Array | null, newest: NewestColumns | string | null): EnvironmentSeal {
  const change = newestRowOf(newest);
  return { object: environmentObject(columns), seal: bytes(seal), newest: change?.seal ?? null, change };
}

/**
 * An object's newest change, as a statement reads it beside the object's row: one JSON object
 * (`newestChangeJson`), its bytes in hex. Null for none.
 */
export type NewestColumns = {
  at: string | number | bigint; request_id: string; object: string; actor: string; payload: string;
  newest: Buffer | Uint8Array | string | null; mac: Buffer | Uint8Array | string | null;
};

/** `newestChangeJson`: the newest change of the object `key` names, whole, one probe of `log_changes_object_idx`. */
export function newestChangeJson(key: SQL): SQL {
  const newest = changesOf('l', key);
  return sql`(SELECT json_build_object('at', l.at::text, 'request_id', l.request_id::text, 'object', l.object::text, 'actor', l.actor, 'payload', l.payload,
      'newest', encode(l.seal, 'hex'), 'mac', encode(l.mac, 'hex'))
    FROM log_changes l WHERE ${newest.where} ORDER BY ${newest.order} LIMIT 1)`;
}

/** The change `NewestColumns` reads, as its MAC covers it (`changeHolds`); null for none. */
export function newestRowOf(read: NewestColumns | string | null | undefined): Omit<ChangeRow, 'number'> | null {
  if (read == null) return null;
  const row = typeof read === 'string' ? (JSON.parse(read) as NewestColumns) : read;
  const raw = (value: Buffer | Uint8Array | string | null) => (typeof value === 'string' ? Buffer.from(value, 'hex') : bytes(value));
  return {
    at: Number(row.at), requestId: String(row.request_id).toLowerCase(), object: String(row.object).toLowerCase(), actor: String(row.actor), payload: String(row.payload),
    seal: raw(row.newest), mac: raw(row.mac) ?? Buffer.alloc(0),
  };
}

/**
 * A member's row as 0.15's log holds it to (T179 PR 2): the row's own
 * seal, and its object's newest change, whole, its MAC to check (`row`),
 * with the 0.14 access entry that change accounts for (`old`,
 * `Changes.cite`), or null for none. `seal` is null for a member with no
 * row, or a row the log never sealed.
 */
export type MemberLog = {
  seal: Buffer | null;
  newest: { seal: Buffer | null; old: bigint | null; row: Omit<ChangeRow, 'number'> } | null;
  /** Read by `memberLogs` alone (a snapshot has its own, `newestAccess`): the vault's newest allowed access entry about the member, unchecked. */
  access?: bigint | null;
};

/** The columns `memberLogs` reads, as the drivers answer them: the newest change's as `log_changes` names them. */
export type MemberLogColumns = {
  seal: Buffer | Uint8Array | null; number: string | number | bigint | null;
  at: string | number | bigint | null; request_id: string | null; object: string | null; actor: string | null; payload: string | null;
  newest: Buffer | Uint8Array | null; mac: Buffer | Uint8Array | null;
};

/** A member's `MemberLog` from its columns: `newest` from the change's number, which only a change has; its `old` from its payload. */
export function memberLogOf(row: MemberLogColumns): MemberLog {
  if (row.number === null) return { seal: bytes(row.seal), newest: null };
  const payload = row.payload ?? '';
  let old: bigint | null = null;
  try {
    const named = (JSON.parse(payload) as { old?: unknown }).old;
    if (typeof named === 'string' || typeof named === 'number') old = BigInt(named);
  } catch {
    // A payload no change of the vault's writes: its MAC fails it (`#onLog`).
  }
  return {
    seal: bytes(row.seal),
    newest: {
      seal: bytes(row.newest),
      old,
      row: {
        at: Number(row.at), requestId: String(row.request_id).toLowerCase(), object: String(row.object).toLowerCase(), actor: String(row.actor), payload,
        seal: bytes(row.newest), mac: bytes(row.mac) ?? Buffer.alloc(0),
      },
    },
  };
}

/**
 * Each of `principals`' `MemberLog`, in one statement: the row by its key,
 * its newest change by one probe of `log_changes_object_idx`, newest first,
 * and its newest access entry by one probe, whatever the logs' length
 * (R48). A principal asked has an entry whether or not it has a row.
 */
export async function memberLogs(db: Queryable, principals: readonly string[]): Promise<Map<string, MemberLog>> {
  if (principals.length === 0) return new Map();
  const rows = await rowsOf<MemberLogColumns & { principal: string; access: string | number | bigint | null }>(db, memberLogsPostgres(principals));
  return new Map(rows.map((row) => [row.principal, { ...memberLogOf(row), access: row.access == null ? null : BigInt(String(row.access)) }]));
}

/**
 * Whom a first add down the two-trip path added (T179, since 0.16.0): the
 * principals its change in 0.15's log names, `{"id": principal, …}` its
 * `ref`, which 0.14's log holds no entry of. Unchecked: a change written
 * around the vault only adds to whom `verifyLog` holds to 0.15's log, which
 * checks each one's newest change. One read of `log_changes_admitted_idx`,
 * as many rows as were added so.
 */
export async function fastAdded(db: Queryable): Promise<Set<string>> {
  const principal = sql.raw(`(payload::jsonb -> 'ref' ->> 'id')`);
  const rows = await rowsOf<{ principal: string | null }>(db, sql`SELECT DISTINCT ${principal} AS principal FROM log_changes WHERE ${recorded(sql.raw('payload'), 'admitted')}`);
  return new Set(rows.flatMap(({ principal }) => (principal === null ? [] : [principal])));
}

/** The vault's newest allowed access entry about principal `p`, unchecked: one probe, as a use's (`m_access`, 0053). */
function newestAccessSeq(p: SQL): SQL {
  return sql`(SELECT a.seq FROM audit_log a WHERE ${accessAllowed('a')} AND a.subject_principal = ${p} ORDER BY a.seq DESC LIMIT 1)`;
}

function memberLogsPostgres(principals: readonly string[]): SQL {
  const newest = changesOf('x', sql`log_object('principal', p.principal)`);
  const asked = sql`unnest(${sql.param([...principals])}::text[])`;
  return sql`SELECT p.principal, m.seal, l.number, l.at, l.request_id::text AS request_id, l.object::text AS object, l.actor, l.payload, l.seal AS newest, l.mac,
      ${newestAccessSeq(sql`p.principal`)} AS access
    FROM ${asked} AS p (principal)
    LEFT JOIN principals m ON m.principal = p.principal
    LEFT JOIN LATERAL (
      SELECT x.* FROM log_changes x WHERE ${newest.where} ORDER BY ${newest.order} LIMIT 1
    ) l ON true`;
}

export async function deleteGrant(tx: Transaction, principal: string, place: Place): Promise<void> {
  await tx.delete(grantsTable).where(and(eq(grantsTable.principal, principal), at(place)));
}

export async function deleteGrants(tx: Transaction, principal: string): Promise<void> {
  await tx.delete(grantsTable).where(eq(grantsTable.principal, principal));
}

/**
 * Up to `limit` of the newest stored data keys wrapped under one KEK, each
 * with the secret it opens for: what proves a KEK is the one the data was
 * wrapped with, before the vault records a check value for it.
 */
export async function wrappedUnder(db: Queryable, provider: string, keyId: string, limit: number) {
  const rows = await db
    .select({
      projectId: secrets.projectId,
      environmentId: secrets.environmentId,
      secretId: secretVersions.secretId,
      version: secretVersions.version,
      kekProvider: secretVersions.kekProvider,
      kekId: secretVersions.kekId,
      kekVersion: secretVersions.kekVersion,
      bytes: secretVersions.wrappedDek,
    })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(and(eq(secretVersions.kekProvider, provider), eq(secretVersions.kekId, keyId), sealed(secretVersions.wrappedDek)))
    .orderBy(desc(secretVersions.createdAt))
    .limit(limit);
  return rows.map((row) => ({ ...row, bytes: Buffer.from(row.bytes) }));
}

/** Of these projects and environments, the ones that exist, each environment with its project and slug. */
export async function places(
  db: Queryable,
  projectIds: readonly string[],
  environmentIds: readonly string[],
  { seals = false }: { seals?: boolean } = {},
): Promise<{ projects: Set<string>; environments: Map<string, EnvironmentRow>; deleted: Set<string> }> {
  const [foundProjects, foundEnvironments] = await Promise.all([
    projectIds.length === 0
      ? []
      : db.select({ id: projects.id, deleted: truth(tombstone(projects.slug)) }).from(projects).where(inArray(projects.id, [...projectIds])),
    environmentsById(db, environmentIds, { seals }),
  ]);
  return {
    projects: new Set(foundProjects.map((row) => row.id)),
    environments: foundEnvironments,
    // The projects and environments among them that were deleted, alone or with their project.
    deleted: new Set([...foundProjects.filter((row) => row.deleted).map((row) => row.id), ...[...foundEnvironments].filter(([, row]) => row.deleted).map(([id]) => id)]),
  };
}

/** Who holds a grant on every project of 0.4, lapsed or not, which the vault replaces (`#convert`). */
export async function everyProjectHolders(db: Queryable): Promise<string[]> {
  const rows = await db
    .selectDistinct({ principal: grantsTable.principal })
    .from(grantsTable)
    .where(and(isNull(grantsTable.projectId), isNull(grantsTable.environmentId)))
    .orderBy(asc(grantsTable.principal));
  return rows.map((row) => row.principal);
}

// --- the log --------------------------------------------------------------------

/** Rows of the log as the chain's codec reads them: `author` and `decision` are checked by the table. */
function stored(rows: object[]): StoredEntry[] {
  return rows as StoredEntry[];
}

/** Up to `limit` entries of either author from `fromSeq`, oldest first: the chain as it runs. */
export async function entriesFrom(db: Queryable, fromSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const batch = await withinBytes(db, gte(auditLog.seq, fromSeq), limit);
  if (batch === null) return [];
  const rows = await db
    .select(entryColumns())
    .from(auditLog)
    .where(and(gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to)))
    .orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** Up to `limit` of the vault's entries after `afterSeq`, oldest first: every one, whatever its action or decision. */
export async function vaultEntriesAfter(db: Queryable, afterSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const vault = authoredBy('vault');
  const batch = await withinBytes(db, and(vault, gt(auditLog.seq, afterSeq)), limit);
  if (batch === null) return [];
  const rows = await db
    .select(entryColumns())
    .from(auditLog)
    .where(and(vault, gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to)))
    .orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** The hash of the entry at each of `seqs` the log holds, by seq. */
export async function hashesAt(db: Queryable, seqs: readonly bigint[]): Promise<Map<bigint, Buffer>> {
  const hashes = new Map<bigint, Buffer>();
  for (let from = 0; from < seqs.length; from += HASHES_AT_ONCE) {
    const rows = await db
      .select({ seq: auditLog.seq, hash: auditLog.hash })
      .from(auditLog)
      .where(inArray(auditLog.seq, seqs.slice(from, from + HASHES_AT_ONCE)));
    for (const { seq, hash } of rows) hashes.set(seq, hash);
  }
  return hashes;
}

/** How many entries' hashes one query asks for: a checkpoint every five minutes is tens of thousands of a year. */
const HASHES_AT_ONCE = 5000;

/** The entry at `seq`'s hash, or undefined when there is none. */
export async function hashAt(db: Queryable, seq: bigint): Promise<Buffer | undefined> {
  const [row] = await db.select({ hash: auditLog.hash }).from(auditLog).where(eq(auditLog.seq, seq));
  return row?.hash;
}

/** Up to `limit` of the vault's entries before `before` (the newest when undefined), newest first. */
export async function vaultPage(db: Queryable, before: bigint | undefined, limit: number): Promise<StoredEntry[]> {
  const rows = await db
    .select(entryColumns())
    .from(auditLog)
    .where(and(authoredBy('vault'), before === undefined ? undefined : lt(auditLog.seq, before)))
    .orderBy(desc(auditLog.seq))
    .limit(limit);
  return stored(rows);
}

/**
 * The seq of the vault's first entry under `keyId`, or undefined: one step
 * of `audit_log_vault_key_idx` (`firstEntryUnder`; T245, R48), whether or not the key ever wrote.
 * Until 0.16 no index served it, and a key that never wrote, a new KEK's
 * before its rotation lands, read the whole log; a fresh isolate's start
 * (`#start` in vault.ts, T206) skipped it once a rotation to the key was
 * logged, by a `NOT EXISTS` over the rotations that grew with them (4,741
 * pages past 40,000). One step now, it asks it plainly.
 */
export async function firstVaultEntryUnder(db: Queryable, keyId: string): Promise<bigint | undefined> {
  return firstEntryUnder(db, 'vault', keyId);
}

/** The entries at these seqs, any author, by seq: what a reference names as its seal. */
export async function entriesAt(db: Queryable, seqs: readonly bigint[]): Promise<Map<bigint, StoredEntry>> {
  if (seqs.length === 0) return new Map();
  const rows = stored(await db.select(entryColumns()).from(auditLog).where(inArray(auditLog.seq, [...new Set(seqs)])));
  return new Map(rows.map((row) => [row.seq, row]));
}

/**
 * The vault's allowed `reference.end` entries naming these `reference.create`
 * entries, whole, for a caller to hold to their MACs: a break weighs only
 * authentic ends (a forged one must not stop a genuine break), where a read
 * takes any (the snapshot's `ended`, `snapshotQuery`).
 */
export async function referenceEnds(db: Queryable, seqs: readonly bigint[]): Promise<StoredEntry[]> {
  if (seqs.length === 0) return [];
  return stored(await db.select(entryColumns()).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'reference.end'), eq(auditLog.decision, 'allow'), inArray(auditLog.relatedSeq, [...new Set(seqs)]))));
}

/** The project each environment is in: a holder's ids, checked against each other. */
/** Whether a project of this id is there, and not deleted. */
export async function projectLive(db: Queryable, id: string): Promise<boolean> {
  const rows = await db.select({ deleted: truth(tombstone(projects.slug)) }).from(projects).where(eq(projects.id, id));
  return rows.length > 0 && !rows[0]!.deleted;
}

export async function projectsOfEnvironments(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const rows = await db.select({ id: environments.id, projectId: environments.projectId }).from(environments).where(inArray(environments.id, [...new Set(ids)]));
  return new Map(rows.map((row) => [row.id, row.projectId]));
}

/** A secret as the vault reads it to make a reference to it: where it is, its path, and its current version. */
export type SecretPlace = { secretId: string; projectId: string; environmentId: string; path: string; currentVersionId: string | null };

/** The live keys of these names in these environments, by id: what a proxy definition's save resolves its keys among (a fork chain's). */
export async function secretsNamed(db: Queryable, environmentIds: readonly string[], names: readonly string[]): Promise<{ id: string; environmentId: string; key: string }[]> {
  if (environmentIds.length === 0 || names.length === 0) return [];
  return db.select({ id: secrets.id, environmentId: secrets.environmentId, key: secrets.key }).from(secrets)
    .where(and(inArray(secrets.environmentId, [...environmentIds]), inArray(secrets.key, [...names]), isNull(secrets.archivedAt)));
}

export async function secretsByIds(db: Queryable, ids: readonly string[]): Promise<Map<string, SecretPlace>> {
  if (ids.length === 0) return new Map();
  const rows = await db
    .select({
      secretId: secrets.id,
      projectId: secrets.projectId,
      environmentId: secrets.environmentId,
      project: projects.slug,
      environment: environments.slug,
      key: secrets.key,
      currentVersionId: secrets.currentVersionId,
    })
    .from(secrets)
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .innerJoin(projects, eq(projects.id, secrets.projectId))
    .where(inArray(secrets.id, [...new Set(ids)]));
  return new Map(rows.map(({ project, environment, key, ...row }) => [row.secretId, { ...row, path: `${project}/${environment}/${key}` }]));
}

/**
 * Each secret's nature, as its current version has it: plain where its
 * value is stored as it is, sensitive where it is bound so, and otherwise
 * secret, as is one with no value of its own.
 */
export async function natures(db: Queryable, secretIds: readonly string[]): Promise<Map<string, 'plain' | 'secret' | 'sensitive'>> {
  if (secretIds.length === 0) return new Map();
  const rows = await db
    .select({ id: secrets.id, sensitive: secretVersions.sensitive, plain: truth(isNotNull(secretVersions.plaintext)) })
    .from(secrets)
    .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(inArray(secrets.id, [...new Set(secretIds)]));
  return new Map(rows.map((row) => [row.id, Boolean(row.sensitive) ? 'sensitive' : Boolean(row.plain) ? 'plain' : 'secret']));
}

/**
 * For each version a rewrap would bring back into its secret, its nature
 * when it is an old value, no looser than it was stored nor than its value
 * was made since (the newest version of its very ciphertext), not the
 * secret's current one; null for the current one, which a mark wraps again
 * with no value changing.
 */
export async function restoredNatures(
  db: Queryable,
  items: readonly { secretId: string; from: string }[],
): Promise<('plain' | 'secret' | 'sensitive' | null)[]> {
  if (items.length === 0) return [];
  const [current, versions] = await Promise.all([
    db.select({ id: secrets.id, version: secrets.currentVersionId }).from(secrets).where(inArray(secrets.id, [...new Set(items.map((item) => item.secretId))])),
    db.select({
      id: secretVersions.id,
      sensitive: sql<boolean>`(${secretVersions.sensitive} OR (${heldAs(secretVersions, sql`same.sensitive`)}))`,
      plain: sql<boolean>`(${secretVersions.plaintext} IS NOT NULL AND (${heldAs(secretVersions, sql`same.plaintext IS NOT NULL`)}))`,
    }).from(secretVersions)
      .where(inArray(secretVersions.id, [...new Set(items.map((item) => item.from))])),
  ]);
  const currentOf = new Map(current.map((row) => [row.id, row.version]));
  const natureOf = new Map(versions.map((row) => [row.id, Boolean(row.sensitive) ? 'sensitive' as const : Boolean(row.plain) ? 'plain' as const : 'secret' as const]));
  return items.map(({ secretId, from }) => (currentOf.get(secretId) === from ? null : natureOf.get(from) ?? 'secret'));
}

/** The vault's newest rotation of the KEK, or undefined: one step of `audit_log_rotation_idx` (`KINDS`; T245, R48). */
export async function latestRotation(db: Queryable): Promise<StoredEntry | undefined> {
  return newestOf(db, entriesOf('rotation'));
}

/** The newest entry `where` holds, or undefined. */
async function newestOf(db: Queryable, where: SQL): Promise<StoredEntry | undefined> {
  const [row] = await db.select(entryColumns()).from(auditLog).where(where).orderBy(desc(auditLog.seq)).limit(1);
  return row === undefined ? undefined : stored([row])[0];
}

/** The vault's newest signed checkpoint, or undefined: one step of `audit_log_signed_idx` (`KINDS`; T245, R48), however many refusals came since. */
export async function latestSigned(db: Queryable): Promise<StoredEntry | undefined> {
  return newestOf(db, entriesOf('signed'));
}

/**
 * The vault's newest checkpoint that keeps a tally, allowed, or undefined:
 * one written since 0.10.1, which names the last entry of the prefix it
 * signs as related (`related_seq`); those before name none.
 */
export async function latestTallied(db: Queryable): Promise<StoredEntry | undefined> {
  return newestOf(db, and(entriesOf('signed'), isNotNull(auditLog.relatedSeq))!);
}

/** The vault's newest `audit.checkpoint` entry, signed or refused, or undefined: one step of `audit_log_checkpoint_idx` (`KINDS`). */
export async function newestCheckpointEntry(db: Queryable): Promise<StoredEntry | undefined> {
  return newestOf(db, entriesOf('checkpoint'));
}

/**
 * The vault's checkpoints that keep a tally after entry `after` and through
 * `through`, oldest first, whole: as many as `BATCH_BYTES` of what they say
 * holds, but always one. A reader asks again after the last.
 */
export async function talliedWithin(db: Queryable, after: bigint, through: bigint, limit: number): Promise<StoredEntry[]> {
  const tallied = and(
    entriesOf('signed'), isNotNull(auditLog.relatedSeq),
    gt(auditLog.seq, after), lte(auditLog.seq, through),
  );
  const batch = await withinBytes(db, tallied, limit);
  if (batch === null) return [];
  const rows = await db.select(entryColumns()).from(auditLog)
    .where(and(tallied, gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to))).orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** The vault's newest refusal of a checkpoint for a broken log after entry `after`, or undefined: one step of `audit_log_broken_log_idx` (`KINDS`; T245, R48). */
export async function newestBrokenLog(db: Queryable, after: bigint): Promise<StoredEntry | undefined> {
  return newestOf(db, and(entriesOf('brokenLog'), gt(auditLog.seq, after))!);
}

/** Up to `limit` of the vault's checkpoints that keep a tally after entry `after`, oldest first: each one's entry, and the last entry it signs. */
export async function talliedAfter(db: Queryable, after: bigint, limit: number): Promise<{ seq: bigint; signs: bigint }[]> {
  const rows = await db
    .select({ seq: auditLog.seq, signs: auditLog.relatedSeq })
    .from(auditLog)
    .where(and(entriesOf('signed'), isNotNull(auditLog.relatedSeq), gt(auditLog.seq, after)))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return rows.map(({ seq, signs }) => ({ seq, signs: signs! }));
}

/** The vault's newest allowed access entry about each member who has one. */
export async function newestAccessEntries(db: Queryable): Promise<Map<string, StoredEntry>> {
  const newest = db
    .select({ seq: sql`max(${auditLog.seq})` })
    .from(auditLog)
    .where(accessAllowed())
    .groupBy(auditLog.subjectPrincipal);
  const rows = stored(await db.select(entryColumns()).from(auditLog).where(inArray(auditLog.seq, newest)));
  return new Map(rows.flatMap((row) => (row.subjectPrincipal === null ? [] : [[row.subjectPrincipal, row]])));
}

/** Up to `limit` of the vault's checks of a KEK, oldest first: steps of `audit_log_key_check_idx` (`KINDS`; T245, R48). */
export async function keyChecks(db: Queryable, limit: number): Promise<StoredEntry[]> {
  return stored(await db.select(entryColumns()).from(auditLog).where(entriesOf('keyCheck')).orderBy(asc(auditLog.seq)).limit(limit));
}

/**
 * The key services' intents logged at or after `since` (the database's clock), and every outcome naming one of them,
 * oldest first: what a rotation reads to close those still open (`#rotate`). The intents newest first, a page at a
 * time by `audit_log_action_idx`, until one is older; their outcomes by the same index, above the oldest of them.
 */
export async function recentIntents(db: Queryable, since: number): Promise<StoredEntry[]> {
  const intents: StoredEntry[] = [];
  for (let before: bigint | undefined; ;) {
    const page = await newestVaultEntries(db, 'intent', INTENT_PAGE, before);
    const recent = page.filter((entry) => entry.occurredAt >= since);
    intents.push(...recent);
    if (page.length < INTENT_PAGE || recent.length < page.length) break;
    before = page.at(-1)!.seq;
  }
  if (intents.length === 0) return [];
  const oldest = intents.reduce((min, entry) => (entry.seq < min ? entry.seq : min), intents[0]!.seq);
  const outcomes = await db
    .select(entryColumns())
    .from(auditLog)
    .where(and(
      eq(auditLog.author, 'vault'), inArray(auditLog.action, ['secret.read', 'key.wrap', 'key.rewrap']), gt(auditLog.seq, oldest),
      inArray(auditLog.relatedSeq, intents.map((entry) => entry.seq)),
    ))
    .orderBy(asc(auditLog.seq));
  return [...intents, ...stored(outcomes)].sort((a, b) => (a.seq < b.seq ? -1 : a.seq > b.seq ? 1 : 0));
}

/**
 * How many intents `recentIntents` reads a statement: a bound on one answer's size, an intent's metadata naming each of
 * its keys, up to the bulk limit's (1,000 by default), about 120 bytes each: 100 intents, at most about 12 MB, under a
 * tenth of a Worker's 128 MB. Fewer pages hold no lock longer; the rotation that reads them holds the head throughout.
 */
const INTENT_PAGE = 100;

/** Which of these secrets' newest versions are sensitive, by the versions' own order. */
export async function newestSensitive(db: Queryable, secretIds: readonly string[]): Promise<Set<string>> {
  if (secretIds.length === 0) return new Set();
  const rows = await db
    .select({ secretId: secretVersions.secretId })
    .from(secretVersions)
    .where(and(
      inArray(secretVersions.secretId, [...new Set(secretIds)]),
      eq(secretVersions.sensitive, true),
      sql`${secretVersions.version} = (SELECT max(newest.version) FROM secret_versions newest WHERE newest.secret_id = ${secretVersions.secretId})`,
    ));
  return new Set(rows.map((row) => row.secretId));
}

/** How many grants name `role`: all of them, or those on environments. */
export async function grantsNaming(db: Queryable, role: string, filter: { onEnvironments?: boolean } = {}): Promise<number> {
  const rows = await db
    .select({ count: sql<number | string>`count(*)` })
    .from(grantsTable)
    .where(and(eq(grantsTable.role, role), filter.onEnvironments === true ? or(isNotNull(grantsTable.environmentId), isNotNull(grantsTable.environmentSlug)) : undefined));
  return Number(rows[0]?.count ?? 0);
}

/**
 * A version that still holds its wrapped key. A deleted place's versions are
 * erased, their keys emptied: there is nothing left to open, or to try a
 * vault key on.
 */
function sealed(wrappedDek: SQLWrapper): SQL {
  return sql`length(${wrappedDek}) > 0`;
}

/**
 * A stored version and the binding and key the vault reads for itself;
 * whether its place was deleted, and whether it is its secret's current
 * one, as a read through a reference needs. An erased version outside a
 * deleted place is no version.
 */
export type SecretVersion = {
  id: string;
  /** Its secret, `sensitive` as the version was written. */
  secret: SecretRef;
  wrapped: WrappedKey;
  deleted: boolean;
  current: boolean;
  /** Whether its secret's newest version is sensitive: what a rewrap of it may not loosen. */
  newestSensitive: boolean;
  /**
   * Whether its value was made sensitive since: the newest version of its
   * secret with its very ciphertext, which a mark in place or a restore wraps
   * again unchanged, is. What a rewrap of it may not loosen either.
   */
  heldSensitive: boolean;
};

export async function versions(db: Queryable, ids: readonly string[]): Promise<SecretVersion[]> {
  if (ids.length === 0) return [];
  const rows = await db
    .select({
      id: secretVersions.id,
      version: secretVersions.version,
      secretId: secrets.id,
      projectId: secrets.projectId,
      environmentId: secrets.environmentId,
      project: projects.slug,
      environment: environments.slug,
      key: secrets.key,
      kekProvider: secretVersions.kekProvider,
      kekId: secretVersions.kekId,
      kekVersion: secretVersions.kekVersion,
      wrappedDek: secretVersions.wrappedDek,
      deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!),
      currentVersionId: secrets.currentVersionId,
      sensitive: secretVersions.sensitive,
      // The newest by the versions' own order: the app may write `current_version_id`, never a version.
      newest: sql<number | string>`(SELECT max(newest.version) FROM secret_versions newest WHERE newest.secret_id = ${secretVersions.secretId})`,
      newestSensitive: sql<boolean>`(SELECT newest.sensitive FROM secret_versions newest WHERE newest.secret_id = ${secretVersions.secretId} ORDER BY newest.version DESC LIMIT 1)`,
      heldSensitive: sql<boolean>`(${heldAs(secretVersions, sql`same.sensitive`)})`,
    })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .innerJoin(projects, eq(projects.id, secrets.projectId))
    .where(and(inArray(secretVersions.id, [...new Set(ids)]), or(sealed(secretVersions.wrappedDek), tombstone(environments.slug), tombstone(projects.slug))));
  return rows.map((row) => ({
    id: row.id,
    deleted: row.deleted,
    secret: {
      projectId: row.projectId,
      environmentId: row.environmentId,
      secretId: row.secretId,
      version: row.version,
      path: `${row.project}/${row.environment}/${row.key}`,
      sensitive: row.sensitive,
    },
    wrapped: {
      kekProvider: row.kekProvider,
      kekId: row.kekId,
      kekVersion: row.kekVersion,
      bytes: row.wrappedDek.toString('base64'),
    },
    current: row.currentVersionId === row.id && Number(row.newest) === row.version,
    newestSensitive: Boolean(row.newestSensitive),
    heldSensitive: Boolean(row.heldSensitive),
  }));
}

/**
 * `column` of the newest version of a version's secret with its very ciphertext: its value, as it is held now. Known
 * by its IV and tag, which under one data key name one ciphertext, and which, unlike the ciphertext, no erasure empties.
 */
function heldAs(versions: typeof secretVersions, column: SQL): SQL {
  return sql`SELECT ${column} FROM secret_versions same WHERE same.secret_id = ${versions.secretId}
    AND same.iv = ${versions.iv} AND same.auth_tag = ${versions.authTag} ORDER BY same.version DESC LIMIT 1`;
}

// --- 0.15's log: objects and changes ----------------------------------------------

/**
 * An object of 0.15's log as its rows hold it (inputs.ts), and the seal on
 * them; `row` null when it has none. The roles' and the policy's rows are
 * their objects as the change that made them wrote them.
 *
 * Each object is read from its rows as the change path writes them
 * (objects.ts): an environment is deleted when its own slug is a tombstone,
 * not its project's (a project's deletion writes its environments' rows,
 * plan PR 4b), unprotected until a change or the cutover says otherwise,
 * and holds its project's archival apart from its own; a key's source is
 * its newest reference row's until that row has ended.
 */
export type HeldObject = { row: Input | null; seal: Buffer | null };

/**
 * 0.15's log as stored, whole: its changes and its uses, each with the
 * columns its replay reads (`replayStored`), bytes as the driver gives them.
 */
export async function loggedRows(db: Queryable): Promise<{
  changes: { number: string | number; at: string | number; object: string; payload: string; seal: Uint8Array | null }[];
  uses: { number: string | number; at: string | number; credential: string; secret: string; purpose: number | string; place: string | null; route: string | null; phased: boolean | null }[];
}> {
  return {
    changes: await rowsOf(db, sql`SELECT number, at, object, payload, seal FROM log_changes`),
    uses: await rowsOf(db, sql`SELECT number, at, credential, secret, purpose, place, route, phased FROM log_uses`),
  };
}

/**
 * The kinds whose objects the change path reads: the vault's own, an
 * environment's, a key's (its reference's end), the roles' and the policy's.
 */
export type ReadKind = Exclude<Kind, 'credential' | 'connection' | 'binding'>;

/** `archived`: a key's rows read even while it is archived, as its unarchive would make them (an end's check, T134). */
export async function readObject(db: Queryable, ref: Ref & { kind: ReadKind }, { archived = false } = {}): Promise<HeldObject> {
  switch (ref.kind) {
    case 'principal': {
      const [row] = await db
        .select({ status: principals.status, generation: principals.generation, owner: principals.owner, role: principals.role, scope: principals.scope, seal: principals.seal })
        .from(principals)
        .where(eq(principals.principal, ref.id));
      if (row === undefined) return { row: null, seal: null };
      return {
        row: principalObject({ principal: ref.id, status: row.status, generation: row.generation, ...memberStanding(row) }, await readGrants(db, { principal: ref.id })),
        seal: row.seal ?? null,
      };
    }
    case 'environment': {
      const [row] = await db
        .select({
          projectId: environments.projectId,
          slug: environments.slug,
          owner: environments.owner,
          parentId: environments.parentId,
          protected: environments.protected,
          archivedAt: environments.archivedAt,
          projectArchived: truth(isNotNull(projects.archivedAt)),
          seal: environments.seal,
        })
        .from(environments)
        .leftJoin(projects, eq(projects.id, environments.projectId))
        .where(eq(environments.id, ref.id));
      if (row === undefined) return { row: null, seal: null };
      const { projectId, slug, owner, parentId, archivedAt } = row;
      return {
        row: environmentObject({ id: ref.id, projectId, slug, owner, parentId, protected: row.protected, archived: archivedAt !== null, projectArchived: Boolean(row.projectArchived) }),
        seal: row.seal ?? null,
      };
    }
    case 'secret': {
      // Unarchived (unless asked): an archived key is no object (`secret.delete`). Its version's plaintext, for a plain one's digest.
      const [row] = await rowsOf<{
        project_id: string; environment_id: string; seal: Buffer | Uint8Array | null; version_id: string | null; source: string | null; reference: string | null;
        sensitive: boolean | null; plaintext: string | null; kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | Uint8Array | null;
      }>(db, sql`SELECT s.project_id, s.environment_id, s.seal, s.current_version_id AS version_id, ${newestSource(sql`s.id`)} AS source,
          ${newestReference(sql`s.id`)} AS reference,
          v.sensitive, v.plaintext, v.kek_provider, v.kek_id, v.kek_version, v.wrapped_dek
        FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id WHERE s.id = ${ref.id} ${archived ? sql`` : sql`AND s.archived_at IS NULL`}`);
      if (row === undefined) return { row: null, seal: null };
      const version = row.version_id === null || row.wrapped_dek === null ? null : {
        id: row.version_id, sensitive: Boolean(row.sensitive), plaintext: row.plaintext,
        kekProvider: row.kek_provider!, kekId: row.kek_id!, kekVersion: row.kek_version!, wrappedDek: Buffer.from(row.wrapped_dek).toString('base64'),
      };
      return {
        row: secretObject({
          id: ref.id, projectId: row.project_id, environmentId: row.environment_id,
          source: row.version_id === null ? row.source : null, reference: row.version_id === null ? row.reference : null, version,
        }),
        seal: row.seal === null ? null : Buffer.from(row.seal),
      };
    }
    case 'roles': {
      const [row] = await db.select({ value: logConfig.value, seal: logConfig.seal }).from(logConfig).where(eq(logConfig.name, ref.kind));
      if (row === undefined) return { row: null, seal: null };
      // Whatever it holds: a value that is not the object fails its seal.
      return { row: configObject(row.value), seal: row.seal ?? null };
    }
    case 'policy': {
      const [row] = await db.select().from(policy).where(eq(policy.name, ref.id));
      return row === undefined ? { row: null, seal: null } : { row: policyObject(row), seal: row.seal };
    }
    case 'role': {
      const { scope, name } = roleName(ref.id);
      const [row] = await db.select({ definition: roles.definition, seal: roles.seal }).from(roles).where(and(eq(roles.scope, scope), eq(roles.name, name)));
      return row === undefined ? { row: null, seal: null } : { row: roleRow(ref.id, row.definition), seal: row.seal ?? null };
    }
    case 'proxy': {
      const [row] = await db.select({ items: proxyDefinitions.items, digests: proxyDefinitions.digests, seal: proxyDefinitions.seal }).from(proxyDefinitions)
        .where(eq(proxyDefinitions.environmentId, ref.id));
      if (row === undefined) return { row: null, seal: null };
      const value: unknown = typeof row.items === 'string' ? JSON.parse(row.items) : row.items;
      // Items no save writes (`{"openai": null}`, a list) are no object: the row stands as one with none, and no seal,
      // which fails it (`tampered`), before anything reads an item.
      if (!isRecord(value) || !Object.values(value).every(isRecord)) return { row: { kind: 'proxy', id: ref.id, items: {} }, seal: Buffer.alloc(0) };
      const items = value as Record<string, ProxyItem>;
      // Its seal covers the index its items make; a `digests` column that is not that index is no row the vault wrote,
      // and holds no seal (a use reads that column, PR C): `tampered`, whatever the seal says over the items.
      const intact = indexBytes(items).equals(Buffer.from(row.digests));
      return { row: { kind: 'proxy', id: ref.id, items }, seal: intact ? Buffer.from(row.seal) : Buffer.alloc(0) };
    }
    case 'proxy-reserved': {
      const [row] = await db.select({ names: proxyReserved.names, seal: proxyReserved.seal }).from(proxyReserved).where(eq(proxyReserved.id, 1));
      if (row === undefined) return { row: null, seal: null };
      const value: unknown = typeof row.names === 'string' ? JSON.parse(row.names) : row.names;
      // Names no change writes (`null`, a list of numbers): no names and no seal, which fails it (`tampered`).
      if (!Array.isArray(value) || !value.every((name) => typeof name === 'string')) return { row: { kind: 'proxy-reserved', names: [] }, seal: Buffer.alloc(0) };
      return { row: { kind: 'proxy-reserved', names: value as string[] }, seal: Buffer.from(row.seal) };
    }
  }
}

/** The environments whose proxy objects' rows hold an item of one of `names`: those a `proxy.code` reserving them changes. */
export async function proxiesNaming(db: Queryable, names: readonly string[]): Promise<string[]> {
  if (names.length === 0) return [];
  const rows = await rowsOf<{ id: string }>(db, sql`SELECT environment_id AS id FROM proxy_definitions WHERE items ?| ARRAY[${sql.join(names.map((name) => sql`${name}`), sql`, `)}]::text[] ORDER BY environment_id`);
  return rows.map((row) => row.id);
}

/** The environments whose proxy objects' rows hold an item `member` saved: candidates, each checked against its seal after. */
export async function proxiesSavedBy(db: Queryable, member: string): Promise<string[]> {
  const rows = await rowsOf<{ id: string }>(db, sql`SELECT environment_id AS id FROM proxy_definitions WHERE EXISTS (SELECT 1 FROM jsonb_each(items) AS item WHERE item.value->>'savedBy' = ${member}) ORDER BY environment_id`);
  return rows.map((row) => row.id);
}

/**
 * The object's newest change in the log: whether it has one, the seal it records (HotPathOne's NewestIn), and whether
 * that change's MAC holds over it under one of `macs`, the vault's (T190; HotPathOne.tla, ChangeChecksMac). One that
 * does not is a seal a database writer wrote into the column (a put-back row's, so that a change applied to that row
 * would seal it as the log's): a reader that holds a row to it refuses it (`heldFrom`, `Changes`). One probe and its
 * row, the same however long the object's history.
 */
export async function newestChange(db: Queryable, ref: Ref, macs: readonly LogMacKey[]): Promise<NewestChange | null> {
  const [row] = await db
    .select({ at: logChanges.at, requestId: logChanges.requestId, object: logChanges.object, actor: logChanges.actor, payload: logChanges.payload, seal: logChanges.seal, mac: logChanges.mac })
    .from(logChanges)
    .where(changesOf('log_changes', objectKey(ref)).where)
    .orderBy(changesOf('log_changes', objectKey(ref)).order)
    .limit(1);
  if (row === undefined) return null;
  const seal = row.seal == null ? null : Buffer.from(row.seal);
  const holds = changeHolds(macs, { at: Number(row.at), requestId: row.requestId, object: objectKey(ref), actor: row.actor, payload: row.payload, seal, mac: Buffer.from(row.mac) });
  return { seal, holds };
}

/** An object's newest change as `newestChange` reads it: the seal its row records, and whether its MAC holds over it. */
export type NewestChange = { seal: Buffer | null; holds: boolean };

/**
 * `loggedChanges`' statement, which its cost test explains: each object's newest change's number, and for each of
 * `previous` the one before it too, one probe each of its changes, newest first (`log_changes_object_idx`); then those
 * rows by number, with every column their MAC covers.
 */
export function loggedChangesQuery(refs: readonly Ref[], previous: readonly Ref[] = []): SQL {
  const newest = (ref: Ref) => changesOf('d', objectKey(ref));
  const numbers = [
    ...refs.map((ref) => sql`(SELECT d.number FROM log_changes d WHERE ${newest(ref).where} ORDER BY ${newest(ref).order} LIMIT 1)`),
    ...previous.map((ref) => sql`(SELECT d.number FROM log_changes d WHERE ${newest(ref).where} ORDER BY ${newest(ref).order} LIMIT 1 OFFSET 1)`),
  ];
  return sql`SELECT c.number, c.at, c.request_id, c.object, c.actor, c.payload, c.seal, c.mac FROM log_changes c WHERE c.number IN (${sql.join(numbers, sql`, `)})`;
}

/** A change as `loggedChanges` reads it: its number, its columns, and whether its MAC holds over them (T190). */
export type CheckedChange = { number: bigint; at: number; requestId: string; object: string; actor: string; payload: string; seal: Buffer | null; mac: Buffer; holds: boolean };

/**
 * Each of `refs`' newest change, and for each of `previous` (among `refs`) the one before it, by the object's key in
 * the log, newest first, each with whether its MAC holds under one of `macs` (`changeHolds`); none for an object the
 * log has no change of. One statement however many objects, the same work however long their histories.
 *
 * What a write the vault seals goes on from where the statement that makes it holds a row to its object's newest
 * seal: SQL compares that seal, and cannot check a MAC, so the vault checks it here first (T190). A writer who edits
 * the seal of a change already checked here, between this read and that statement, is not seen unless the statement
 * holds the newest change to the one this read checked, every column its MAC covers and the MAC: not its number,
 * which no MAC covers, nor its seal alone, which an old, authentic change shares with a forged newer one. `sign_in`
 * does (T192), and T179's two-trip writes, their read set held whole (ReadByNumber); `app_change` and `issue_token`
 * outside them do not yet (sealed-inputs.md).
 */
export async function loggedChanges(db: Queryable, macs: readonly LogMacKey[], refs: readonly Ref[], previous: readonly Ref[] = []): Promise<Map<string, CheckedChange[]>> {
  const found = new Map<string, CheckedChange[]>();
  if (refs.length === 0) return found;
  type Read = { number: string | number; at: string | number; request_id: string; object: string; actor: string; payload: string; seal: Buffer | Uint8Array | null; mac: Buffer | Uint8Array };
  for (const row of await rowsOf<Read>(db, loggedChangesQuery(refs, previous))) {
    const seal = bytes(row.seal);
    const at = Number(row.at);
    const mac = Buffer.from(row.mac);
    const holds = changeHolds(macs, { at, requestId: row.request_id, object: row.object, actor: row.actor, payload: row.payload, seal, mac });
    found.set(row.object, [...(found.get(row.object) ?? []), { number: BigInt(row.number), at, requestId: row.request_id, object: row.object, actor: row.actor, payload: row.payload, seal, mac, holds }]);
  }
  for (const changes of found.values()) changes.sort((x, y) => (x.number > y.number ? -1 : x.number < y.number ? 1 : 0));
  return found;
}

/**
 * Whether the indexes that keep request ids unique stand: a
 * second entry under one request is a replay the database refuses, so a
 * walk need hold only its own stretch to it (`RequestIdChecked`).
 */
export async function requestsUnique(db: Queryable): Promise<boolean> {
  // Each index by its definition, so that one of the same name over other columns does not pass: a use's request is
  // unique by its time and id, a change's by its id.
  const defined = (text: string) => text.replace(/[`"\s]/g, '').toLowerCase();
  const wanted = (uses: string | undefined, changes: string | undefined) =>
    uses !== undefined && changes !== undefined && /^createuniqueindex.*on(only)?(public\.)?log_uses(usingbtree)?\(at,request_id\)$/.test(defined(uses))
    && /^createuniqueindex.*on(only)?(public\.)?log_changes(usingbtree)?\(request_id\)$/.test(defined(changes));
  const rows = await rowsOf<{ name: string; def: string }>(db, sql`SELECT c.relname AS name, pg_get_indexdef(i.indexrelid) AS def FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE i.indexrelid IN (to_regclass('public.log_uses_request_idx'), to_regclass('public.log_changes_request_id_key')) AND i.indisunique AND i.indisvalid`);
  const of = (name: string) => rows.find((row) => row.name === name)?.def;
  return wanted(of('log_uses_request_idx'), of('log_changes_request_id_key'));
}

/**
 * `value`, over `y`, of a key's newest reference row, null for a key with
 * none: a seek on `secret_references_holder_idx`, (secret_id, created_seq),
 * to the last row at or before the key's newest, taken only if that row is
 * the key's. `secretId`: the key's id, as its query names it. As `secret_id
 * = key ORDER BY created_seq DESC LIMIT 1`, the equality makes `secret_id` a
 * constant of the order, which `secret_references_created_seq_key` then
 * serves too: where few keys hold many rows, Postgres walks it backwards,
 * through every newer row of every other key's (T220). Only the holder index
 * serves this order. `use_credential`, `change_input` and `end_reference`
 * seek alike (0069).
 */
function ofNewestReference(secretId: SQL, value: SQL): SQL<string | null> {
  return sql<string | null>`(SELECT CASE WHEN y.secret_id = ${secretId} THEN ${value} END FROM secret_references y
    WHERE y.secret_id <= ${secretId} ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1)`;
}

/**
 * A key's source as its object holds it: its newest reference row's, unless
 * that row has ended (`ended_at`, 0029): a reference broken, replaced or
 * cut. Null for a key with no reference row.
 */
function newestSource(secretId: SQL): SQL<string | null> {
  return ofNewestReference(secretId, sql`CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END`);
}

/** ... and that row's id, which the object holds beside its source. */
function newestReference(secretId: SQL): SQL<string | null> {
  return ofNewestReference(secretId, sql`CASE WHEN y.ended_at IS NULL THEN y.id END`);
}

/**
 * The rows' ends of references whose end changes no object, by their ids
 * (`end_reference`, 0029), written beside 0.14's entry: a holder archived,
 * holding a value, standing on another reference, or 0.14's alone (no
 * seal, no change). A standing one of a logged holder is refused: its end
 * is its holder's change.
 */
export async function endReferenceRows(tx: Transaction, ids: readonly string[], at: number): Promise<void> {
  if (ids.length === 0) return;
  if (!Number.isSafeInteger(at) || at < 0) throw new Error('a reference ends at a time, whole ms since the epoch');
  await rowsOf(tx, sql`SELECT end_reference(r.id, ${at}::bigint) FROM unnest(${sql.param([...ids])}::uuid[]) AS r(id)`);
}

/**
 * A change as `change_input` takes it: the object, the request it is (a
 * retry finds its entry), when and by whom, what it does (`payload`, the
 * op as logged), the object it leaves where the function writes it
 * (`value`), the seal it was read at and the one it leaves (none: a key
 * deleted), and the entry's MAC.
 */
export type ChangeCall = {
  ref: Ref;
  requestId: string;
  at: number;
  actor: string;
  payload: string;
  value: string | null;
  sealFrom: Buffer | null;
  seal: Buffer | null;
  mac: Buffer;
};

/**
 * Each change, in order, in one round trip, each `change_input` (0023):
 * its entry's number, or null where the row's seal was no longer the one
 * read, and nothing was done. A row that is not its object's newest
 * change's fails the call (`isStale`), and its transaction with it.
 *
 * The calls are rows of one `VALUES`, scanned in order.
 */
export async function changeInputs(tx: Transaction, calls: readonly ChangeCall[]): Promise<(bigint | null)[]> {
  if (calls.length === 0) return [];
  return numbersIn(await rowsOf(tx, inputCalls(calls, false)), 'change_input');
}

/**
 * `changeInputs` as a decision's last statements, which nothing awaits: asked with `later`, so that they
 * go with its COMMIT, under one Sync; through `change_input_strict` (migration 0052), so that a row moved since it was
 * read fails the transaction (`isMovedChange`: read again), where `change_input`'s null would let it commit without
 * the change. Their numbers answer once the COMMIT has.
 */
export async function laterInputs(tx: Transaction, calls: readonly ChangeCall[]): Promise<ChangeNumbers> {
  const requests = calls.map(({ requestId }) => requestId);
  if (calls.length === 0) return { answer: Promise.resolve([]), requests };
  const answer = laterRows(tx, inputCalls(calls, true)).then((rows) => strictly(numbersIn(rows, 'change_input'), 'decision'));
  answer.catch(() => {});
  return { answer, requests };
}

/** `change_input`, or `change_input_strict`, once per call, in one statement. */
function inputCalls(calls: readonly ChangeCall[], strict: boolean): SQL {
  const rows = sql.join(calls.map((call, i) => sql`(${i}::int, ${call.ref.kind}::text, ${call.ref.id}::text, ${call.requestId}::text, ${call.at}::bigint, ${call.actor}::text, ${call.payload}::text, ${call.value}::text, ${call.sealFrom}::bytea, ${call.seal}::bytea, ${call.mac}::bytea)`), sql`, `);
  // In order: one decision's changes to one object chain, each from the seal the one before leaves. A volatile
  // function in the select list runs after the sort (Postgres 9.6 on), so each call runs in `ord`'s order.
  return sql`
    SELECT c.ord, ${sql.raw(strict ? 'change_input_strict' : 'change_input')}(c.kind, c.id, c.request, c.at, c.actor, c.payload, c.value, c.seal_from, c.seal, c.mac) AS number
      FROM (VALUES ${rows}) AS c(ord, kind, id, request, at, actor, payload, value, seal_from, seal, mac)
     ORDER BY c.ord`;
}

/** Postgres's `data_corrupted`, which `change_input` raises on a row that is not its object's newest change's. */
const STALE = 'XX001';

/** Whether `error` is `change_input`'s refusal of a stale row (ChangeChecksSeal). */
export function isStale(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if ((cause as { code?: unknown }).code === STALE) return true;
  }
  return false;
}

/**
 * Every row of `roles` (T178, 0.16), each with the seal its object's newest change left (`StoredRole`): what the
 * vault's start, and a change of a role, sync the rows from (`roleChanges`). One statement, one probe of
 * each role's changes; a handful of rows, however long the log.
 */
export async function roleRows(db: Queryable): Promise<StoredRole[]> {
  const role = changesOf('c', sql`log_object('role', r.scope || '/' || r.name)`);
  const rows = await rowsOf<{ scope: string; name: string; definition: unknown; seal: Buffer | Uint8Array | null; found: boolean; newest: Buffer | Uint8Array | null }>(db, sql`
    SELECT r.scope, r.name, r.definition, r.seal, l.number IS NOT NULL AS found, l.seal AS newest FROM roles r
      LEFT JOIN LATERAL (SELECT c.number, c.seal FROM log_changes c WHERE ${role.where} ORDER BY ${role.order} LIMIT 1) l ON true`);
  return rows.map((row) => ({
    scope: row.scope, name: row.name, definition: roleRow('', row.definition).definition, seal: bytes(row.seal), newest: row.found ? bytes(row.newest) : undefined,
  }));
}

/** A role's object id, `<scope>/<name>`, split. */
function roleName(id: string): { scope: string; name: string } {
  const slash = id.indexOf('/');
  return slash < 0 ? { scope: '', name: '' } : { scope: id.slice(0, slash), name: id.slice(slash + 1) };
}

/** A row of `roles` as its object: the definition JSON, null as the role ships. */
function roleRow(id: string, definition: unknown): RoleInput {
  return { kind: 'role', id, definition: (typeof definition === 'string' ? JSON.parse(definition) : definition ?? null) as RoleInput['definition'] };
}

/**
 * A credential a token's issue came in on (`Vault.issueToken`, T149): its
 * object's columns, as the app sends them (`CredentialColumns`), its seal,
 * and its object's newest change's seal, with whether that change's MAC holds
 * under `macs` (T190: `issue_token` and `change_bindings` hold the row to
 * that seal, which SQL cannot authenticate), in one read; null for no row.
 */
export async function issuingCredential(db: Queryable, id: string, macs: readonly LogMacKey[]): Promise<{ columns: CredentialColumns; seal: Buffer | null; newest: NewestChange | null } | null> {
  type Read = {
    id: string; principal: string; kind: string; scope: string | null; revoked: boolean; expires_at: number | string; not_after: number | string | null; generation: number; seal: Buffer | null;
    number: string | number | null; at: string | number | null; request_id: string | null; actor: string | null; payload: string | null; newest: Buffer | null; mac: Buffer | null;
  };
  const object = objectKey({ kind: 'credential', id });
  // The credential's columns as 0036's function answers them (the vault's login reads no credential otherwise), and
  // beside them, in the same statement, its newest change's columns, which the vault's login reads.
  const change = changesOf('l', object);
  const newest = sql`SELECT l.number, l.at, l.request_id, l.actor, l.payload, l.seal, l.mac FROM log_changes l WHERE ${change.where} ORDER BY ${change.order} LIMIT 1`;
  const [row] = await rowsOf<Read>(db, sql`SELECT c.id, c.principal, c.kind, c.scope, c.revoked, c.expires_at, c.not_after, c.generation, c.seal,
      l.number, l.at, l.request_id, l.actor, l.payload, l.seal AS newest, l.mac
      FROM issuing_credential(${id}::uuid) c LEFT JOIN LATERAL (${newest}) l ON true`);
  if (row === undefined) return null;
  const ends = [Number(row.expires_at), ...(row.not_after == null ? [] : [Number(row.not_after)])];
  const seal = bytes(row.newest);
  return {
    columns: { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revoked, expiresAt: Math.min(...ends), generation: Number(row.generation) },
    seal: bytes(row.seal),
    newest: row.number == null ? null : {
      seal,
      holds: changeHolds(macs, { at: Number(row.at), requestId: row.request_id!, object, actor: row.actor!, payload: row.payload!, seal, mac: Buffer.from(row.mac!) }),
    },
  };
}

// --- the cutover (cutover.ts) ------------------------------------------------

/** Whether the log is cut over from 0.14: its cutover change, one probe of `log_changes_object_idx`, no lock. */
export async function cutOver(db: Queryable): Promise<boolean> {
  return (await cutoverNumber(db)) !== null;
}

/** The cutover change's number, null for none: one probe of `log_changes_object_idx`, no lock. */
export async function cutoverNumber(db: Queryable): Promise<bigint | null> {
  const [row] = await rowsOf<{ number: string | number }>(db, sql`SELECT number FROM log_changes WHERE object = ${CUTOVER_OBJECT} LIMIT 1`);
  return row === undefined ? null : BigInt(row.number);
}

/** Every object the log has a change of, by its key: before the cutover, the few 0.15's changes made already. */
export async function loggedObjects(db: Queryable): Promise<Set<string>> {
  const rows = await rowsOf<{ object: string }>(db, sql`SELECT DISTINCT object FROM log_changes`);
  return new Set(rows.map((row) => row.object));
}

/** The configuration objects' rows there are, by kind: only `change_input` writes one, sealed (the roles' in `log_config`, the policy's in `policy`). */
export async function configRows(db: Queryable): Promise<Set<string>> {
  const rows = await rowsOf<{ name: string }>(db, sql`SELECT name FROM log_config WHERE name = 'roles' UNION ALL SELECT 'policy' FROM policy`);
  return new Set(rows.map((row) => row.name));
}

/** A member's row's seal, by principal. */
export async function memberSeals(db: Queryable): Promise<Map<string, Buffer | null>> {
  const rows = await rowsOf<{ principal: string; seal: Buffer | Uint8Array | null }>(db, sql`SELECT principal, seal FROM principals`);
  return new Map(rows.map((row) => [row.principal, bytes(row.seal)]));
}

export type ProjectRow = { id: string; slug: string; archived: boolean };
export type EnvironmentRead = { id: string; projectId: string; slug: string; owner: string | null; parentId: string | null; archived: boolean; seal: Buffer | null };
/** A key's rows, archived or not: its current version, and its newest reference row, ended or not. */
export type SecretRead = {
  id: string;
  projectId: string;
  environmentId: string;
  archived: boolean;
  seal: Buffer | null;
  /**
   * Whether its current version is one of its own and its newest by the
   * versions' own order, as 0.14 holds a source's (`versions`, which joins a
   * version to its key): the app may write `current_version_id`, never a
   * version. False for a pointer to another key's version, or to none.
   */
  newest: boolean;
  version: { id: string; sensitive: boolean; plaintext: string | null; kekProvider: string; kekId: string; kekVersion: string; wrappedDek: string } | null;
  /** Its newest reference row: its id, its source, the `reference.create` it names, and whether its row says it ended. */
  reference: { id: string; source: string; createdSeq: bigint; ended: boolean } | null;
};

export async function everyProject(db: Queryable): Promise<ProjectRow[]> {
  const rows = await rowsOf<{ id: string; slug: string; archived: boolean }>(db, sql`SELECT id, slug, archived_at IS NOT NULL AS archived FROM projects`);
  return rows.map((row) => ({ id: row.id, slug: row.slug, archived: row.archived }));
}

export async function everyEnvironment(db: Queryable): Promise<EnvironmentRead[]> {
  const rows = await rowsOf<{ id: string; project_id: string; slug: string; owner: string | null; parent_id: string | null; archived: boolean; seal: Buffer | Uint8Array | null }>(
    db, sql`SELECT id, project_id, slug, owner, parent_id, archived_at IS NOT NULL AS archived, seal FROM environments`,
  );
  return rows.map((row) => ({ id: row.id, projectId: row.project_id, slug: row.slug, owner: row.owner, parentId: row.parent_id, archived: row.archived, seal: bytes(row.seal) }));
}

/** Every key, archived or not, as `readObject` makes one (store.ts), with its newest reference row whole. */
export async function everySecret(db: Queryable): Promise<SecretRead[]> {
  const reference = (column: string) => ofNewestReference(sql`s.id`, sql.raw(`y.${column}`));
  const rows = await rowsOf<{
    id: string; project_id: string; environment_id: string; archived: boolean; seal: Buffer | Uint8Array | null; version_id: string | null;
    sensitive: boolean | null; plaintext: string | null; kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | Uint8Array | null;
    reference_id: string | null; reference_source: string | null; reference_seq: string | number | null; reference_ended: boolean | null;
    newest: boolean | null;
  }>(db, sql`SELECT s.id, s.project_id, s.environment_id, s.archived_at IS NOT NULL AS archived, s.seal, s.current_version_id AS version_id,
      s.current_version_id IS NULL OR (v.secret_id = s.id AND v.version = (SELECT max(w.version) FROM secret_versions w WHERE w.secret_id = s.id)) AS newest,
      v.sensitive, v.plaintext, v.kek_provider, v.kek_id, v.kek_version, v.wrapped_dek,
      ${reference('id')} AS reference_id, ${reference('source_secret_id')} AS reference_source, ${reference('created_seq')} AS reference_seq,
      ${reference('ended_at')} IS NOT NULL AS reference_ended
    FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id`);
  return rows.map((row) => ({
    id: row.id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    archived: row.archived,
    seal: bytes(row.seal),
    newest: row.newest === true,
    // As `readObject` takes a version: none without a wrapped key.
    version: row.version_id === null || row.wrapped_dek === null ? null : {
      id: row.version_id, sensitive: Boolean(row.sensitive), plaintext: row.plaintext,
      kekProvider: row.kek_provider!, kekId: row.kek_id!, kekVersion: row.kek_version!, wrappedDek: Buffer.from(row.wrapped_dek).toString('base64'),
    },
    reference: row.reference_id === null ? null : {
      id: row.reference_id, source: row.reference_source!, createdSeq: BigInt(row.reference_seq!), ended: Boolean(row.reference_ended),
    },
  }));
}

/** A credential the app vouched for, as its row is now (`cutover_credentials`): its object's columns, its seal, and whether the log has a change of it. */
export type CredentialRead = { columns: CredentialColumns; seal: Buffer | null; logged: boolean };
/** A binding the app vouched for, as its row is now: its columns but the instance it was made on, its row's `origin` apart (null on one of 0.14's, which the cutover writes), its seal. */
export type BindingRead = { columns: Omit<BindingColumns, 'origin'>; origin: string | null; seal: Buffer | null; logged: boolean };

export async function credentialsAt(db: Queryable, ids: readonly string[]): Promise<Map<string, CredentialRead>> {
  if (ids.length === 0) return new Map();
  type Read = { id: string; principal: string; kind: string; scope: string | null; revoked: boolean; expires_at: string | number; not_after: string | number | null; generation: number; seal: Buffer | Uint8Array | null; logged: boolean };
  const rows = await rowsOf<Read>(db, sql`SELECT * FROM cutover_credentials(${sql.param([...ids])}::uuid[])`);
  return new Map(rows.map((row) => {
    // As `issuingCredential` reads one (store.ts): its end the earlier of its expiry and its hard end.
    const ends = [Number(row.expires_at), ...(row.not_after == null ? [] : [Number(row.not_after)])];
    const columns: CredentialColumns = { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revoked, expiresAt: Math.min(...ends), generation: Number(row.generation) };
    return [row.id, { columns, seal: bytes(row.seal), logged: row.logged }];
  }));
}

/** An MCP connection the app vouched for, as its row is now (`cutover_connections`, T147): its object's columns, its seal, and whether the log has a change of it. */
export type ConnectionRead = { columns: ConnectionColumns; seal: Buffer | null; logged: boolean };

export async function connectionsAt(db: Queryable, ids: readonly string[]): Promise<Map<string, ConnectionRead>> {
  if (ids.length === 0) return new Map();
  type Read = { id: string; principal: string; generation: number; expires_at: string | number; revoked: boolean; seal: Buffer | Uint8Array | null; logged: boolean };
  const rows = await rowsOf<Read>(db, sql`SELECT * FROM cutover_connections(${sql.param([...ids])}::uuid[])`);
  return new Map(rows.map((row) => {
    const columns: ConnectionColumns = { id: row.id, principal: row.principal, generation: Number(row.generation), expiresAt: Number(row.expires_at), revoked: row.revoked };
    return [row.id, { columns, seal: bytes(row.seal), logged: row.logged }];
  }));
}

export async function bindingsAt(db: Queryable, ids: readonly string[]): Promise<Map<string, BindingRead>> {
  if (ids.length === 0) return new Map();
  type Read = { id: string; principal: string; generation: number; profile: string; issuer: string; origin: string | null; jwks_uri: string; claims: string; scope: string | null; policy: string | null; revoked: boolean; seal: Buffer | Uint8Array | null; logged: boolean };
  const rows = await rowsOf<Read>(db, sql`SELECT * FROM cutover_bindings(${sql.param([...ids])}::uuid[])`);
  return new Map(rows.map((row) => {
    const columns: Omit<BindingColumns, 'origin'> = {
      id: row.id, principal: row.principal, generation: Number(row.generation), profile: row.profile, issuer: row.issuer, jwksUri: row.jwks_uri,
      claims: row.claims, scope: row.scope, policy: row.policy, revoked: row.revoked,
    };
    return [row.id, { columns, origin: row.origin, seal: bytes(row.seal), logged: row.logged }];
  }));
}

/** Whether the app wrote any entry of 0.14's after `seq`: what it vouched for may have moved since. */
export async function appEntriesAfter(db: Queryable, seq: bigint): Promise<boolean> {
  const rows = await rowsOf<{ found: number }>(db, sql`SELECT 1 AS found FROM audit_log WHERE seq > ${seq} AND author = 'app' LIMIT 1`);
  return rows.length > 0;
}

/** The places 0.14 deleted made as 0.15 leaves them: each environment given `<slug>~deleted`, each key archived (`cutover_places`). */
export async function cutoverPlaces(tx: Transaction, at: number, environments: readonly string[], secrets: readonly string[]): Promise<void> {
  if (environments.length === 0 && secrets.length === 0) return;
  await rowsOf(tx, sql`SELECT cutover_places(${at}::bigint, ${sql.param([...environments])}::uuid[], ${sql.param([...secrets])}::uuid[])`);
}

/** A binding's genesis (`seal_binding`): its number, or null if its row is not as its object says, or the log holds it. */
export async function sealBinding(tx: Transaction, call: ChangeCall): Promise<bigint | null> {
  const [row] = await rowsOf<{ n: string | number | null }>(tx, sql`SELECT seal_binding(${call.ref.id}::uuid, ${call.requestId}, ${call.at}::bigint, ${call.actor}, ${call.payload},
    ${call.seal}::bytea, ${call.mac}::bytea) AS n`);
  return row?.n == null ? null : BigInt(row.n);
}

/** The cutover's change (`log_cutover`): its number. */
export async function logCutover(tx: Transaction, row: { requestId: string; at: number; actor: string; payload: string; mac: Buffer }): Promise<bigint> {
  const [found] = await rowsOf<{ n: string | number }>(tx, sql`SELECT log_cutover(${row.requestId}, ${row.at}::bigint, ${row.actor}, ${row.payload}, ${row.mac}::bytea) AS n`);
  return BigInt(found!.n);
}

function bytes(value: Buffer | Uint8Array | null): Buffer | null {
  return value === null ? null : Buffer.from(value);
}

/** A JSON object: not null, not a list. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

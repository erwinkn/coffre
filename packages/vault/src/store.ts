import { EVERYWHERE, ownsInstance, type InstanceRole, type Scope } from '@coffre/core/access';
import type { Author, StoredEntry } from '@coffre/core/audit';
import { deletedWithProject, isTombstone, TOMBSTONE } from '@coffre/core/schemas';
import { ACCESS_ACTIONS, type BindingColumns, type ConnectionColumns, type CredentialColumns, type EnvironmentColumns, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { prepared, tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { changedRows, clockMillis, engineOf, forUpdate, rowsOf, tombstone, truth } from '@coffre/db/dialect';
import { readGrants, roleColumns, storedRole, type GrantRow } from '@coffre/db/grants';
import { entryColumns, withinBytes } from '@coffre/db/log';

import { MAX_BULK_WINDOW_MINUTES } from './config.ts';
import { objectKey, type EnvironmentInput, type Input, type Kind, type Ref } from './inputs.ts';
import { CUTOVER_OBJECT } from './log-entry.ts';
import { configObject, environmentObject, memberStanding, principalObject, secretObject } from './objects.ts';
import { and, asc, count, desc, eq, gt, gte, inArray, isNotNull, isNull, like, lt, lte, or, sql, type SQL, type SQLWrapper } from 'drizzle-orm';

/**
 * Every query the vault makes, and the only code in it that holds them.
 * Each reads or writes one thing; what they add up to, a decision, is in
 * `vault.ts`. The tables are the shared database's: `vault_members` and
 * `vault_grants`, which only the vault writes, the places it decides on,
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
 * On Postgres, fail a lock wait in this transaction after `ms`, rather than
 * wait for ever behind a transaction that never ends; with `statements`,
 * any statement that takes longer, too. A queue for a row each holder
 * updates, as the log's head, is no one wait: a waiter follows each update
 * to the row's new version and waits again, its lock's clock started over,
 * so only the statement's own bound ends it.
 */
export async function boundLockWaits(tx: Transaction, ms: number, statements = false): Promise<void> {
  if (engineOf(tx) !== 'postgres') return;
  const bound = String(Math.trunc(ms));
  await tx.execute(statements
    ? sql`SELECT set_config('lock_timeout', ${bound}, true), set_config('statement_timeout', ${bound}, true)`
    : sql.raw(`SET LOCAL lock_timeout = ${bound}`));
}

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
 * read again. On Postgres the vault's login deletes no row itself, and asks
 * `prune_vault_releases`, which deletes only those (migration 0021). How
 * many went.
 */
export async function pruneReleases(db: Queryable, atMost: number): Promise<number> {
  if (engineOf(db) === 'postgres') {
    const [row] = await rowsOf<{ pruned: number }>(db, sql`SELECT prune_vault_releases(${atMost}::int) AS pruned`);
    return row!.pruned;
  }
  const { vaultReleases } = tablesOf(db);
  const old = db.select({ principal: vaultReleases.principal, key: vaultReleases.key }).from(vaultReleases)
    .where(lt(vaultReleases.releasedAt, sql`${clockMillis(db)} - ${RELEASES_KEPT_MS}`)).limit(atMost);
  return changedRows(await db.delete(vaultReleases).where(sql`(${vaultReleases.principal}, ${vaultReleases.key}) IN ${old}`));
}

/** The database's clock, now. */
export async function now(db: Queryable): Promise<number> {
  const [{ at }] = await clock(db);
  return at;
}

const clock = prepared((db) => db.select({ at: clockMillis(db) }).from(tablesOf(db).auditChainHead));

// --- members --------------------------------------------------------------------

function memberColumns(db: Queryable) {
  const { vaultMembers } = tablesOf(db);
  return {
    principal: vaultMembers.principal,
    status: vaultMembers.status,
    owner: vaultMembers.owner,
    role: vaultMembers.role,
    scope: vaultMembers.scope,
    generation: vaultMembers.generation,
    createdAt: vaultMembers.createdAt,
    createdBy: vaultMembers.createdBy,
    statusChangedAt: vaultMembers.statusChangedAt,
    statusChangedBy: vaultMembers.statusChangedBy,
    accessSeq: vaultMembers.accessSeq,
    mac: vaultMembers.mac,
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
  const { vaultMembers } = tablesOf(db);
  return db.select(memberColumns(db)).from(vaultMembers).where(eq(vaultMembers.principal, sql.placeholder('principal')));
});

export async function allMembers(db: Queryable): Promise<Member[]> {
  const { vaultMembers } = tablesOf(db);
  return ((await db.select(memberColumns(db)).from(vaultMembers).orderBy(asc(vaultMembers.principal))) as StoredMember[]).map(memberOf);
}

/**
 * The rows that say their member is an active Owner of the whole instance
 * (`ownsInstance` in @coffre/core/access), as stored: a row changed around
 * the vault says so too, which the caller checks. The scope is read as the
 * row's MAC reads it, parsed: any way of writing everywhere is everywhere.
 */
export async function instanceOwners(db: Queryable): Promise<Member[]> {
  const { vaultMembers } = tablesOf(db);
  const rows = await db
    .select(memberColumns(db))
    .from(vaultMembers)
    .where(and(eq(vaultMembers.status, 'active'), eq(vaultMembers.role, 'owner')))
    .orderBy(asc(vaultMembers.principal));
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
  const { vaultMembers } = tablesOf(tx);
  const queued: Record<string, SQL> = engineOf(tx) === 'postgres'
    ? { queued: sql`${sql.raw(shared ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock')}(${MEMBER_QUEUE}, hashtext(${vaultMembers.principal}))` }
    : {};
  const rows = await forUpdate(
    tx,
    tx
      .select({ ...memberColumns(tx), ...queued })
      .from(vaultMembers)
      .where(inArray(vaultMembers.principal, [...new Set(principals)]))
      .orderBy(asc(vaultMembers.principal)),
    shared ? 'share' : 'no key update',
  );
  return new Map((rows as (StoredMember & { queued?: unknown })[]).map(({ queued: _, ...row }) => [row.principal, memberOf(row)]));
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
export async function insertMember(tx: Transaction, row: Member): Promise<void> {
  const { vaultMembers } = tablesOf(tx);
  await tx.insert(vaultMembers).values(storedChange(row) as typeof vaultMembers.$inferInsert);
}

export async function updateMember(
  tx: Transaction,
  principal: string,
  change: Partial<Omit<Member, 'principal'>>,
): Promise<void> {
  const { vaultMembers } = tablesOf(tx);
  await tx.update(vaultMembers).set(storedChange(change)).where(eq(vaultMembers.principal, principal));
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
function at(db: Queryable, place: Place) {
  const { vaultGrants } = tablesOf(db);
  if (place.environmentId !== null) return eq(vaultGrants.environmentId, place.environmentId);
  if (place.projectId !== null) return and(eq(vaultGrants.projectId, place.projectId), isNull(vaultGrants.environmentId));
  return and(
    isNull(vaultGrants.projectId),
    isNull(vaultGrants.environmentId),
    place.environmentSlug === null ? isNull(vaultGrants.environmentSlug) : eq(vaultGrants.environmentSlug, place.environmentSlug),
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
 * null for none. The vault checks them before it decides on the row.
 */
export type EnvironmentSeal = { object: EnvironmentInput; seal: Buffer | null; newest: Buffer | null };

/**
 * Each of these environments that exists, by id, with its project, its
 * slug, what grants on one slug in every project match, and whether it was
 * deleted, alone or with its project: then no key under it opens, or is
 * wrapped, whatever grant would cover it. With `seals`, what 0.15's log
 * holds each to as well, in the same statement on Postgres.
 */
export async function environmentsById(
  db: Queryable,
  ids: readonly string[],
  { seals = false }: { seals?: boolean } = {},
): Promise<Map<string, EnvironmentRow>> {
  if (ids.length === 0) return new Map();
  const { environments, projects } = tablesOf(db);
  const postgres = engineOf(db) === 'postgres';
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
    // One probe of its object's changes, newest first (`log_changes_object_idx`, which holds the seal).
    ...(postgres ? { newest: sql<Buffer | Uint8Array | null>`(SELECT l.seal FROM log_changes l WHERE l.object = log_object('environment', ${environments.id}::text) ORDER BY l.number DESC LIMIT 1)` } : {}),
  };
  const rows = (await db
    .select(seals ? { ...columns, ...sealColumns } : columns)
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(inArray(environments.id, [...new Set(ids)]))) as (Omit<EnvironmentRow, 'sealed'> & { id: string } & Partial<SealedColumns>)[];
  // SQLite has no `log_object`: the newest changes in a statement of their own, by the keys the vault computes.
  const newest = seals && !postgres ? await newestSeals(db, rows.map((row) => ({ kind: 'environment', id: row.id }))) : null;
  return new Map(rows.map(({ id, protected: guarded, ownArchived, projectArchived, seal, newest: last, ...environment }) => [id, {
    ...environment,
    ...(seals ? {
      sealed: environmentSeal(
        { id, projectId: environment.projectId, slug: environment.slug, owner: environment.owner, parentId: environment.parentId, protected: guarded == null ? null : Boolean(guarded), archived: Boolean(ownArchived), projectArchived: Boolean(projectArchived) },
        seal ?? null,
        newest === null ? last ?? null : newest.get(objectKey({ kind: 'environment', id })) ?? null,
      ),
    } : {}),
  }]));
}

/** The columns `environmentsById` reads with `seals`, as the drivers answer them. */
type SealedColumns = { protected: boolean | number | null; ownArchived: boolean | number; projectArchived: boolean | number; seal: Buffer | Uint8Array | null; newest: Buffer | Uint8Array | null };

/** An environment's row as 0.15's log holds it to (`EnvironmentSeal`), from its columns and the two seals as read. */
export function environmentSeal(columns: EnvironmentColumns, seal: Buffer | Uint8Array | null, newest: Buffer | Uint8Array | null): EnvironmentSeal {
  return { object: environmentObject(columns), seal: bytes(seal), newest: bytes(newest) };
}

/**
 * The seal each object's newest change left, by its key in the log
 * (`objectKey`), null for one that left none; an object with no change is
 * not in the map. One probe of each object's changes, newest first.
 */
export async function newestSeals(db: Queryable, refs: readonly Ref[]): Promise<Map<string, Buffer | null>> {
  if (refs.length === 0) return new Map();
  const keys = sql.join([...new Set(refs.map((ref) => objectKey(ref)))].map((key) => sql`${key}`), sql`, `);
  const rows = await rowsOf<{ object: string; seal: Buffer | Uint8Array | null }>(
    db, sql`SELECT c.object, c.seal FROM log_changes c WHERE c.object IN (${keys}) AND c.number = (SELECT max(d.number) FROM log_changes d WHERE d.object = c.object)`,
  );
  return new Map(rows.map((row) => [row.object, bytes(row.seal)]));
}

export async function deleteGrant(tx: Transaction, principal: string, place: Place): Promise<void> {
  const { vaultGrants } = tablesOf(tx);
  await tx.delete(vaultGrants).where(and(eq(vaultGrants.principal, principal), at(tx, place)));
}

export async function deleteGrants(tx: Transaction, principal: string): Promise<void> {
  const { vaultGrants } = tablesOf(tx);
  await tx.delete(vaultGrants).where(eq(vaultGrants.principal, principal));
}

/**
 * Up to `limit` of the newest stored data keys wrapped under one KEK, each
 * with the secret it opens for: what proves a KEK is the one the data was
 * wrapped with, before the vault records a check value for it.
 */
export async function wrappedUnder(db: Queryable, provider: string, keyId: string, limit: number) {
  const { secretVersions, secrets } = tablesOf(db);
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
  const { projects } = tablesOf(db);
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
  const { vaultGrants } = tablesOf(db);
  const rows = await db
    .selectDistinct({ principal: vaultGrants.principal })
    .from(vaultGrants)
    .where(and(isNull(vaultGrants.projectId), isNull(vaultGrants.environmentId)))
    .orderBy(asc(vaultGrants.principal));
  return rows.map((row) => row.principal);
}

// --- the log --------------------------------------------------------------------

/** Rows of the log as the chain's codec reads them: `author` and `decision` are checked by the table. */
function stored(rows: object[]): StoredEntry[] {
  return rows as StoredEntry[];
}

/** Up to `limit` entries of either author from `fromSeq`, oldest first: the chain as it runs. */
export async function entriesFrom(db: Queryable, fromSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const batch = await withinBytes(db, gte(auditLog.seq, fromSeq), limit);
  if (batch === null) return [];
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to)))
    .orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** Up to `limit` of the vault's entries after `afterSeq`, oldest first: every one, whatever its action or decision. */
export async function vaultEntriesAfter(db: Queryable, afterSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const vault = eq(auditLog.author, 'vault' satisfies Author);
  const batch = await withinBytes(db, and(vault, gt(auditLog.seq, afterSeq)), limit);
  if (batch === null) return [];
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(vault, gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to)))
    .orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** The hash of the entry at each of `seqs` the log holds, by seq. */
export async function hashesAt(db: Queryable, seqs: readonly bigint[]): Promise<Map<bigint, Buffer>> {
  const { auditLog } = tablesOf(db);
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
  const { auditLog } = tablesOf(db);
  const [row] = await db.select({ hash: auditLog.hash }).from(auditLog).where(eq(auditLog.seq, seq));
  return row?.hash;
}

/** Up to `limit` of the vault's entries before `before` (the newest when undefined), newest first. */
export async function vaultPage(db: Queryable, before: bigint | undefined, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault' satisfies Author), before === undefined ? undefined : lt(auditLog.seq, before)))
    .orderBy(desc(auditLog.seq))
    .limit(limit);
  return stored(rows);
}

/**
 * The seq of the vault's first entry under `keyId`, or undefined. No index
 * serves it: it reads the log from its start up to that entry, which for
 * the key a log began under is among its first.
 */
export async function firstVaultEntryUnder(db: Queryable, keyId: string): Promise<bigint | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select({ seq: auditLog.seq })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault' satisfies Author), eq(auditLog.keyId, keyId)))
    .orderBy(asc(auditLog.seq))
    .limit(1);
  return row?.seq;
}

/** The entries at these seqs, any author, by seq: what a reference names as its seal. */
export async function entriesAt(db: Queryable, seqs: readonly bigint[]): Promise<Map<bigint, StoredEntry>> {
  if (seqs.length === 0) return new Map();
  const { auditLog } = tablesOf(db);
  const rows = stored(await db.select(entryColumns(db)).from(auditLog).where(inArray(auditLog.seq, [...new Set(seqs)])));
  return new Map(rows.map((row) => [row.seq, row]));
}

/**
 * Which of these `reference.create` entries a `reference.end` of the
 * vault's names, allowed: one read through `audit_log_reference_end_idx`.
 * An end that fails its MAC still ends: putting a reference back takes
 * more than a forged end can undo, and refusing is the safe side.
 */
export async function endedReferences(db: Queryable, seqs: readonly bigint[]): Promise<Set<bigint>> {
  if (seqs.length === 0) return new Set();
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ relatedSeq: auditLog.relatedSeq })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'reference.end'), eq(auditLog.decision, 'allow'), inArray(auditLog.relatedSeq, [...new Set(seqs)])));
  return new Set(rows.map((row) => row.relatedSeq!));
}

/**
 * The vault's allowed `reference.end` entries naming these `reference.create`
 * entries, whole, for a caller to hold to their MACs: a break weighs only
 * authentic ends (a forged one must not stop a genuine break), where a read
 * takes any (`endedReferences`).
 */
export async function referenceEnds(db: Queryable, seqs: readonly bigint[]): Promise<StoredEntry[]> {
  if (seqs.length === 0) return [];
  const { auditLog } = tablesOf(db);
  return stored(await db.select(entryColumns(db)).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'reference.end'), eq(auditLog.decision, 'allow'), inArray(auditLog.relatedSeq, [...new Set(seqs)]))));
}

/** The project each environment is in: a holder's ids, checked against each other. */
/** Whether a project of this id is there, and not deleted. */
export async function projectLive(db: Queryable, id: string): Promise<boolean> {
  const { projects } = tablesOf(db);
  const rows = await db.select({ deleted: truth(tombstone(projects.slug)) }).from(projects).where(eq(projects.id, id));
  return rows.length > 0 && !rows[0]!.deleted;
}

export async function projectsOfEnvironments(db: Queryable, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const { environments } = tablesOf(db);
  const rows = await db.select({ id: environments.id, projectId: environments.projectId }).from(environments).where(inArray(environments.id, [...new Set(ids)]));
  return new Map(rows.map((row) => [row.id, row.projectId]));
}

/** A secret as the vault reads it to make a reference to it: where it is, its path, and its current version. */
export type SecretPlace = { secretId: string; projectId: string; environmentId: string; path: string; currentVersionId: string | null };

export async function secretsByIds(db: Queryable, ids: readonly string[]): Promise<Map<string, SecretPlace>> {
  if (ids.length === 0) return new Map();
  const { secrets, environments, projects } = tablesOf(db);
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
  const { secrets, secretVersions } = tablesOf(db);
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
  const { secrets, secretVersions } = tablesOf(db);
  const [current, versions] = await Promise.all([
    db.select({ id: secrets.id, version: secrets.currentVersionId }).from(secrets).where(inArray(secrets.id, [...new Set(items.map((item) => item.secretId))])),
    db.select({
      id: secretVersions.id,
      sensitive: sql<boolean | number>`(${secretVersions.sensitive} OR (${heldAs(secretVersions, sql`same.sensitive`)}))`,
      plain: sql<boolean | number>`(${secretVersions.plaintext} IS NOT NULL AND (${heldAs(secretVersions, sql`same.plaintext IS NOT NULL`)}))`,
    }).from(secretVersions)
      .where(inArray(secretVersions.id, [...new Set(items.map((item) => item.from))])),
  ]);
  const currentOf = new Map(current.map((row) => [row.id, row.version]));
  const natureOf = new Map(versions.map((row) => [row.id, Boolean(row.sensitive) ? 'sensitive' as const : Boolean(row.plain) ? 'plain' as const : 'secret' as const]));
  return items.map(({ secretId, from }) => (currentOf.get(secretId) === from ? null : natureOf.get(from) ?? 'secret'));
}

/** The vault's newest entry of any of these actions, allowed, or undefined. */
export async function latestVaultEntry(db: Queryable, actions: readonly string[]): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), inArray(auditLog.action, [...actions]), eq(auditLog.decision, 'allow')))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  return row === undefined ? undefined : stored([row])[0];
}

/**
 * The vault's newest checkpoint that keeps a tally, allowed, or undefined:
 * one written since 0.10.1, which names the last entry of the prefix it
 * signs as related (`related_seq`); those before name none.
 */
export async function latestTallied(db: Queryable): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'audit.checkpoint'), eq(auditLog.decision, 'allow'), isNotNull(auditLog.relatedSeq)))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  return row === undefined ? undefined : stored([row])[0];
}

/** The vault's newest `audit.checkpoint` entry, signed or refused, or undefined. */
export async function newestCheckpointEntry(db: Queryable): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'audit.checkpoint')))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  return row === undefined ? undefined : stored([row])[0];
}

/**
 * The vault's checkpoints that keep a tally after entry `after` and through
 * `through`, oldest first, whole: as many as `BATCH_BYTES` of what they say
 * holds, but always one. A reader asks again after the last.
 */
export async function talliedWithin(db: Queryable, after: bigint, through: bigint, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const tallied = and(
    eq(auditLog.author, 'vault'), eq(auditLog.action, 'audit.checkpoint'), eq(auditLog.decision, 'allow'), isNotNull(auditLog.relatedSeq),
    gt(auditLog.seq, after), lte(auditLog.seq, through),
  );
  const batch = await withinBytes(db, tallied, limit);
  if (batch === null) return [];
  const rows = await db.select(entryColumns(db)).from(auditLog)
    .where(and(tallied, gte(auditLog.seq, batch.from), lte(auditLog.seq, batch.to))).orderBy(asc(auditLog.seq));
  return stored(rows);
}

/** The vault's newest refusal of `action` with `code` after entry `after`, or undefined: one range of the (author, action, seq) index. */
export async function newestRefusal(db: Queryable, action: string, code: string, after: bigint): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, action), gt(auditLog.seq, after), eq(auditLog.decision, 'deny'), eq(auditLog.code, code)))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  return row === undefined ? undefined : stored([row])[0];
}

/** Up to `limit` of the vault's checkpoints that keep a tally after entry `after`, oldest first: each one's entry, and the last entry it signs. */
export async function talliedAfter(db: Queryable, after: bigint, limit: number): Promise<{ seq: bigint; signs: bigint }[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ seq: auditLog.seq, signs: auditLog.relatedSeq })
    .from(auditLog)
    .where(and(
      eq(auditLog.author, 'vault'),
      eq(auditLog.action, 'audit.checkpoint'),
      eq(auditLog.decision, 'allow'),
      isNotNull(auditLog.relatedSeq),
      gt(auditLog.seq, after),
    ))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return rows.map(({ seq, signs }) => ({ seq, signs: signs! }));
}

/** The vault's newest allowed access entry about each member who has one. */
export async function newestAccessEntries(db: Queryable): Promise<Map<string, StoredEntry>> {
  const { auditLog } = tablesOf(db);
  const newest = db
    .select({ seq: sql`max(${auditLog.seq})` })
    .from(auditLog)
    .where(
      and(eq(auditLog.author, 'vault'), inArray(auditLog.action, [...ACCESS_ACTIONS]), eq(auditLog.decision, 'allow')),
    )
    .groupBy(auditLog.subjectPrincipal);
  const rows = stored(await db.select(entryColumns(db)).from(auditLog).where(inArray(auditLog.seq, newest)));
  return new Map(rows.flatMap((row) => (row.subjectPrincipal === null ? [] : [[row.subjectPrincipal, row]])));
}

/** Up to `limit` of the vault's allowed entries of these actions after `afterSeq`, oldest first. */
export async function vaultEntriesOf(
  db: Queryable,
  actions: readonly string[],
  afterSeq: bigint,
  limit: number,
): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(
      and(
        eq(auditLog.author, 'vault'),
        inArray(auditLog.action, [...actions]),
        eq(auditLog.decision, 'allow'),
        gt(auditLog.seq, afterSeq),
      ),
    )
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return stored(rows);
}

/** Which of these secrets' newest versions are sensitive, by the versions' own order. */
export async function newestSensitive(db: Queryable, secretIds: readonly string[]): Promise<Set<string>> {
  if (secretIds.length === 0) return new Set();
  const { secretVersions } = tablesOf(db);
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
  const { vaultGrants } = tablesOf(db);
  const rows = await db
    .select({ count: sql<number | string>`count(*)` })
    .from(vaultGrants)
    .where(and(eq(vaultGrants.role, role), filter.onEnvironments === true ? or(isNotNull(vaultGrants.environmentId), isNotNull(vaultGrants.environmentSlug)) : undefined));
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
  const { secretVersions, secrets, environments, projects } = tablesOf(db);
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
      newestSensitive: sql<boolean | number>`(SELECT newest.sensitive FROM secret_versions newest WHERE newest.secret_id = ${secretVersions.secretId} ORDER BY newest.version DESC LIMIT 1)`,
      heldSensitive: sql<boolean | number>`(${heldAs(secretVersions, sql`same.sensitive`)})`,
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
    // SQLite answers a subquery's boolean as a number.
    newestSensitive: Boolean(row.newestSensitive),
    heldSensitive: Boolean(row.heldSensitive),
  }));
}

/**
 * `column` of the newest version of a version's secret with its very ciphertext: its value, as it is held now. Known
 * by its IV and tag, which under one data key name one ciphertext, and which, unlike the ciphertext, no erasure empties.
 */
function heldAs(secretVersions: ReturnType<typeof tablesOf>['secretVersions'], column: SQL): SQL {
  return sql`SELECT ${column} FROM secret_versions same WHERE same.secret_id = ${secretVersions.secretId}
    AND same.iv = ${secretVersions.iv} AND same.auth_tag = ${secretVersions.authTag} ORDER BY same.version DESC LIMIT 1`;
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
  uses: { number: string | number; at: string | number; credential: string; secret: string; purpose: number | string; place: string | null }[];
}> {
  return {
    changes: await rowsOf(db, sql`SELECT number, at, object, payload, seal FROM log_changes`),
    uses: await rowsOf(db, sql`SELECT number, at, credential, secret, purpose, place FROM log_uses`),
  };
}

/**
 * The kinds whose objects the change path reads: the vault's own, an
 * environment's, a key's (its reference's end), the roles' and the policy's.
 */
export type ReadKind = Exclude<Kind, 'credential' | 'connection' | 'binding'>;

/** `archived`: a key's rows read even while it is archived, as its unarchive would make them (an end's check, T134). */
export async function readObject(db: Queryable, ref: Ref & { kind: ReadKind }, { archived = false } = {}): Promise<HeldObject> {
  const { vaultMembers, environments, projects, logConfig } = tablesOf(db);
  switch (ref.kind) {
    case 'principal': {
      const [row] = await db
        .select({ status: vaultMembers.status, generation: vaultMembers.generation, owner: vaultMembers.owner, role: vaultMembers.role, scope: vaultMembers.scope, seal: vaultMembers.seal })
        .from(vaultMembers)
        .where(eq(vaultMembers.principal, ref.id));
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
        sensitive: boolean | number | null; plaintext: string | null; kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | Uint8Array | null;
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
    case 'roles': case 'policy': {
      const [row] = await db.select({ value: logConfig.value, seal: logConfig.seal }).from(logConfig).where(eq(logConfig.name, ref.kind));
      if (row === undefined) return { row: null, seal: null };
      // Whatever it holds: a value that is not the object fails its seal.
      return { row: configObject(row.value), seal: row.seal ?? null };
    }
  }
}

/** The object's newest change in the log: whether it has one, and the seal it left (HotPathOne's NewestIn). */
export async function newestChange(db: Queryable, ref: Ref): Promise<{ seal: Buffer | null } | null> {
  const { logChanges } = tablesOf(db);
  const [row] = await db
    .select({ seal: logChanges.seal })
    .from(logChanges)
    .where(eq(logChanges.object, objectKey(ref)))
    .orderBy(desc(logChanges.number))
    .limit(1);
  return row === undefined ? null : { seal: row.seal ?? null };
}

/** `newestSealedChanges`' statement, which its cost test explains. */
export function newestSealedQuery(refs: readonly Ref[]): SQL {
  const newest = sql.join(refs.map((ref) => sql`(SELECT d.number FROM log_changes d WHERE d.object = ${objectKey(ref)} AND d.seal IS NOT NULL ORDER BY d.number DESC LIMIT 1)`), sql`, `);
  return sql`SELECT c.number, c.at, c.object, c.payload, c.seal FROM log_changes c WHERE c.number IN (${newest})`;
}

/**
 * Each object's newest change that left a seal, by its key in the log: what
 * an unarchive restores (an archived key's newest change is its
 * `secret.delete`, which left none). One probe of each object's changes,
 * newest first (`log_changes_object_idx`), then its row by number: the
 * same work however long its history.
 */
export async function newestSealedChanges(db: Queryable, refs: readonly Ref[]): Promise<Map<string, { number: bigint; at: number; object: string; payload: string; seal: Buffer }>> {
  if (refs.length === 0) return new Map();
  const found = await rowsOf<{ number: string | number; at: string | number; object: string; payload: string; seal: Buffer | Uint8Array }>(db, newestSealedQuery(refs));
  return new Map(found.map((row) => [row.object, { number: BigInt(row.number), at: Number(row.at), object: row.object, payload: row.payload, seal: Buffer.from(row.seal) }]));
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
  if (engineOf(db) === 'sqlite') {
    const rows = await rowsOf<{ name: string; sql: string | null }>(db, sql`SELECT name, sql FROM sqlite_master
      WHERE type = 'index' AND name IN ('log_uses_request_idx', 'log_changes_request_id_key')`);
    const of = (name: string) => rows.find((row) => row.name === name)?.sql ?? undefined;
    return wanted(of('log_uses_request_idx'), of('log_changes_request_id_key'));
  }
  const rows = await rowsOf<{ name: string; def: string }>(db, sql`SELECT c.relname AS name, pg_get_indexdef(i.indexrelid) AS def FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE i.indexrelid IN (to_regclass('public.log_uses_request_idx'), to_regclass('public.log_changes_request_id_key')) AND i.indisunique AND i.indisvalid`);
  const of = (name: string) => rows.find((row) => row.name === name)?.def;
  return wanted(of('log_uses_request_idx'), of('log_changes_request_id_key'));
}

/**
 * A key's source as its object holds it: its newest reference row's, unless
 * that row has ended (`ended_at`, 0029): a reference broken, replaced or
 * cut. Null for a key with no reference row. `secretId`: the key's id, as
 * its query names it.
 */
function newestSource(secretId: SQL): SQL<string | null> {
  return sql<string | null>`(SELECT CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END FROM secret_references y WHERE y.secret_id = ${secretId} ORDER BY y.created_seq DESC LIMIT 1)`;
}

/** ... and that row's id, which the object holds beside its source. */
function newestReference(secretId: SQL): SQL<string | null> {
  return sql<string | null>`(SELECT CASE WHEN y.ended_at IS NULL THEN y.id END FROM secret_references y WHERE y.secret_id = ${secretId} ORDER BY y.created_seq DESC LIMIT 1)`;
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
  if (engineOf(tx) === 'postgres') {
    await rowsOf(tx, sql`SELECT end_reference(r.id, ${at}::bigint) FROM unnest(${sql.param([...ids])}::uuid[]) AS r(id)`);
    return;
  }
  // One writer at a time on SQLite: no lock to take.
  const listed = sql.join(ids.map((id) => sql`${id}`), sql`, `);
  const standing = await rowsOf<{ id: string; holder: string; seal: Buffer | Uint8Array | null }>(tx, sql`SELECT y.id, x.id AS holder, x.seal FROM secret_references y JOIN secrets x ON x.id = y.secret_id
    WHERE y.id IN (${listed}) AND y.ended_at IS NULL AND x.archived_at IS NULL AND x.current_version_id IS NULL
      AND y.id = (SELECT z.id FROM secret_references z WHERE z.secret_id = x.id ORDER BY z.created_seq DESC LIMIT 1)`);
  for (const row of standing) {
    if (row.seal !== null || (await newestChange(tx, { kind: 'secret', id: row.holder })) !== null) {
      // Postgres's code for it, `invalid_parameter_value`, as `end_reference` raises it.
      throw Object.assign(new Error(`reference ${row.id} is its holder's standing one: its end is a change of the holder`), { code: '22023' });
    }
  }
  await rowsOf(tx, sql`UPDATE secret_references SET ended_at = ${at} WHERE id IN (${listed}) AND ended_at IS NULL`);
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
 * On Postgres, the calls are rows of one `VALUES`, scanned in order. On
 * SQLite, which has no functions, `changeOnSqlite` does what it does, in
 * the call's transaction, which holds the database's one write lock: the
 * fence there is implicit (plan, "Postgres serves; SQLite is for tests").
 */
export async function changeInputs(tx: Transaction, calls: readonly ChangeCall[]): Promise<(bigint | null)[]> {
  if (calls.length === 0) return [];
  if (engineOf(tx) === 'sqlite') {
    const numbers: (bigint | null)[] = [];
    for (const call of calls) numbers.push(await changeOnSqlite(tx, call));
    return numbers;
  }
  const rows = sql.join(calls.map((call, i) => sql`(${i}::int, ${call.ref.kind}::text, ${call.ref.id}::text, ${call.requestId}::text, ${call.at}::bigint, ${call.actor}::text, ${call.payload}::text, ${call.value}::text, ${call.sealFrom}::bytea, ${call.seal}::bytea, ${call.mac}::bytea)`), sql`, `);
  // In order: one decision's changes to one object chain, each from the seal the one before leaves. A volatile
  // function in the select list runs after the sort (Postgres 9.6 on), so each call runs in `ord`'s order.
  const numbers = await rowsOf<{ ord: number; number: string | number | null }>(tx, sql`
    SELECT c.ord, change_input(c.kind, c.id, c.request, c.at, c.actor, c.payload, c.value, c.seal_from, c.seal, c.mac) AS number
      FROM (VALUES ${rows}) AS c(ord, kind, id, request, at, actor, payload, value, seal_from, seal, mac)
     ORDER BY c.ord`);
  if (numbers.some(({ ord }, i) => Number(ord) !== i)) throw new Error('change_input answered out of order');
  return numbers.map(({ number }) => (number === null ? null : BigInt(number)));
}

/** Postgres's `data_corrupted`, which `change_input` raises on a row that is not its object's newest change's. */
const STALE = 'XX001';

/** Whether `error` is `change_input`'s refusal of a stale row (ChangeChecksSeal). */
export function isStale(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (cause instanceof StaleRow || (cause as { code?: unknown }).code === STALE) return true;
  }
  return false;
}

class StaleRow extends Error {}

/**
 * The ops `change_input` takes, by kind (0023, 0029, 0030): the cutover's genesis on any. A key's: its reference's
 * end, and an archived holder's object deleted again after its end.
 */
const KNOWN_OPS: Record<Kind, readonly string[]> = {
  principal: ['member.add', 'member.role', 'member.remove', 'member.restore', 'access.grant', 'access.revoke'],
  environment: ['environment.protect', 'environment.rename', 'environment.archive'],
  roles: ['role.define'],
  policy: ['bulk.limit'],
  credential: [],
  // The app's changes alone make and end a connection (`app_change`): the change path seals 0.14's at the cutover.
  connection: [],
  // The vault's own statements change a binding (`change_bindings`), never the change path.
  binding: [],
  secret: ['secret.write', 'secret.delete'],
};

/** `change_input`, step for step, on SQLite. */
async function changeOnSqlite(tx: Transaction, call: ChangeCall): Promise<bigint | null> {
  const { logChanges, logUses, vaultMembers, environments, projects, logConfig, credentials, mcpConnections, serviceBindings, secrets, secretReferences } = tablesOf(tx);
  const { ref } = call;
  const target = objectKey(ref);
  const [prior] = await tx.select({ number: logChanges.number, object: logChanges.object, payload: logChanges.payload, seal: logChanges.seal }).from(logChanges).where(eq(logChanges.requestId, call.requestId));
  if (prior !== undefined) {
    if (prior.object !== target || prior.payload !== call.payload || !sameBytes(prior.seal ?? null, call.seal)) {
      throw Object.assign(new Error(`request ${call.requestId} names another change`), { code: 'SQLITE_CONSTRAINT_UNIQUE' });
    }
    return BigInt(prior.number);
  }
  const op = (JSON.parse(call.payload) as { op?: unknown }).op;
  if (ref.kind === 'binding') throw new Error('a binding changes by the vault\'s own statements alone (`change_bindings`)');
  if (typeof op !== 'string' || (op !== 'genesis' && !KNOWN_OPS[ref.kind].includes(op))) throw new Error(`this schema knows no change ${String(op)} to a ${ref.kind}`);
  const named = (JSON.parse(call.payload) as { ref?: { kind?: unknown; id?: unknown } }).ref;
  if ((op !== 'genesis' || named !== undefined) && (named?.kind !== ref.kind || named.id !== ref.id)) throw new Error(`a change names the object it is to: ${ref.kind}, ${ref.id}`);
  const value = call.value === null ? null : (JSON.parse(call.value) as Record<string, unknown>);
  const valued = ref.kind === 'environment' ? op !== 'genesis' && value === null
    : ref.kind === 'secret' ? (op === 'secret.write') === (value === null)
    : ref.kind === 'roles' || ref.kind === 'policy' ? (op === 'genesis') === (value !== null) : value !== null;
  if (valued) throw new Error(`a ${ref.kind} change ${op} carries the object it leaves exactly when change_input writes it`);
  // ChangeChecksSeal.
  const held = await heldSeal(tx, ref);
  const newest = await newestChange(tx, ref);
  if (!sameBytes(held, newest?.seal ?? null)) throw new StaleRow(`the ${ref.kind} object's row is not its newest change's: stale`);
  // ChangeCAS.
  const from = (column: SQLWrapper) => (call.sealFrom === null ? isNull(column) : eq(column as never, call.sealFrom));
  let done: number;
  switch (ref.kind) {
    case 'principal':
      done = changedRows(await tx.update(vaultMembers).set({ seal: call.seal }).where(and(eq(vaultMembers.principal, ref.id), from(vaultMembers.seal))));
      break;
    case 'credential':
      done = changedRows(await tx.update(credentials).set({ seal: call.seal }).where(and(eq(credentials.id, ref.id), from(credentials.seal))))
        || changedRows(await tx.update(serviceBindings).set({ seal: call.seal }).where(and(eq(serviceBindings.id, ref.id), from(serviceBindings.seal))));
      break;
    case 'connection':
      done = changedRows(await tx.update(mcpConnections).set({ seal: call.seal }).where(and(eq(mcpConnections.id, ref.id), from(mcpConnections.seal))));
      break;
    case 'secret': {
      if (value === null) {
        done = changedRows(await tx.update(secrets).set({ seal: call.seal }).where(and(eq(secrets.id, ref.id), from(secrets.seal))));
        break;
      }
      // A reference's end (0029): the holder, with no version of its own, left with no source. Live, from its seal, its
      // newest reference row ended, which must stand; archived, from none, its row ended by its id already
      // (`end_reference`), and its object deleted again after (0030).
      const [row] = await tx.select({ projectId: secrets.projectId, environmentId: secrets.environmentId, archivedAt: secrets.archivedAt }).from(secrets)
        .where(and(eq(secrets.id, ref.id), from(secrets.seal), isNull(secrets.currentVersionId)));
      const ends = row !== undefined && (row.archivedAt === null) === (call.sealFrom !== null)
        && value.kind === 'secret' && value.id === ref.id && row.projectId === value.projectId && row.environmentId === value.environmentId
        && value.version === '' && value.nature === 'secret' && value.key === null && value.digest === null && value.source === null
        && value.reference === null;
      if (!ends) {
        done = 0;
        break;
      }
      done = changedRows(await tx.update(secrets).set({ seal: call.seal }).where(eq(secrets.id, ref.id)));
      if (row.archivedAt !== null) break;
      const [newest] = await tx.select({ id: secretReferences.id, endedAt: secretReferences.endedAt }).from(secretReferences)
        .where(eq(secretReferences.secretId, ref.id)).orderBy(desc(secretReferences.createdSeq)).limit(1);
      if (newest === undefined || newest.endedAt !== null) throw new StaleRow("the secret object's reference has no standing row: stale");
      await tx.update(secretReferences).set({ endedAt: new Date(call.at) }).where(eq(secretReferences.id, newest.id));
      break;
    }
    case 'environment': {
      if (value === null) {
        done = changedRows(await tx.update(environments).set({ seal: call.seal }).where(and(eq(environments.id, ref.id), from(environments.seal))));
        break;
      }
      const [row] = await tx.select({
        projectId: environments.projectId, parentId: environments.parentId, owner: environments.owner, slug: environments.slug, archivedAt: environments.archivedAt, seal: environments.seal,
        projectArchived: truth(isNotNull(projects.archivedAt)),
      }).from(environments).leftJoin(projects, eq(projects.id, environments.projectId)).where(eq(environments.id, ref.id));
      const deleted = value.deleted === true;
      const holds = row !== undefined && sameBytes(row.seal ?? null, call.sealFrom) && value.kind === 'environment' && value.id === ref.id
        && row.projectId === value.projectId && row.parentId === (value.parentId ?? null) && row.owner === (value.owner ?? null)
        // Its project's archival is the project's row's, none once deleted: held, never written here (0029).
        && (!deleted && Boolean(row.projectArchived)) === value.projectArchived
        // A deleted row keeps its tombstone, and its object the slug before it (objects.ts): never written again (0025).
        && isTombstone(row.slug) === deleted && !isTombstone(String(value.slug)) && (!deleted || row.slug.slice(0, row.slug.indexOf(TOMBSTONE)) === value.slug);
      if (!holds) {
        done = 0;
        break;
      }
      done = changedRows(await tx.update(environments).set({
        slug: deleted ? row.slug : String(value.slug),
        protected: value.protected === true,
        archivedAt: value.archived === true ? (row.archivedAt ?? new Date(call.at)) : null,
        seal: call.seal,
      }).where(eq(environments.id, ref.id)));
      break;
    }
    case 'roles': case 'policy': {
      const config = op === 'genesis' ? (JSON.parse(call.payload) as { value?: unknown }).value : value;
      if (ref.id !== 'instance' || config === null || typeof config !== 'object' || Array.isArray(config) || (op === 'genesis' && call.sealFrom !== null)) {
        throw new Error(`the ${ref.kind} object is one, made once from its value and changed from its seal`);
      }
      done = call.sealFrom === null
        ? changedRows(await tx.insert(logConfig).values({ name: ref.kind, value: JSON.stringify(config), seal: call.seal }).onConflictDoNothing())
        : changedRows(await tx.update(logConfig).set({ value: JSON.stringify(config), seal: call.seal }).where(and(eq(logConfig.name, ref.kind), eq(logConfig.seal, call.sealFrom))));
      break;
    }
  }
  if (done === 0) return null;
  // One sequence for both tables, as `log_number` is on Postgres: the transaction holds the database's write lock.
  // Unlike the sequence, the newest number again once its entries are deleted: SQLite is for tests (the plan), where
  // only a test deletes entries.
  const [{ last }] = await tx.select({ last: sql<number | string | null>`max(n)` }).from(
    sql`(SELECT max(${logChanges.number}) AS n FROM ${logChanges} UNION ALL SELECT max(${logUses.number}) FROM ${logUses})`,
  );
  const number = BigInt(last ?? 0) + 1n;
  await tx.insert(logChanges).values({ number, at: call.at, requestId: call.requestId, object: target, actor: call.actor, payload: call.payload, seal: call.seal, mac: call.mac });
  return number;
}

/** The seal on an object's row, null if it has none or no row (the credentials' table first: a binding's id never meets a token's). */
async function heldSeal(db: Queryable, ref: Ref): Promise<Buffer | null> {
  const { credentials, mcpConnections, serviceBindings, secrets } = tablesOf(db);
  switch (ref.kind) {
    case 'connection': {
      const [row] = await db.select({ seal: mcpConnections.seal }).from(mcpConnections).where(eq(mcpConnections.id, ref.id));
      return row?.seal ?? null;
    }
    case 'credential': {
      const [token] = await db.select({ seal: credentials.seal }).from(credentials).where(eq(credentials.id, ref.id));
      if (token !== undefined) return token.seal ?? null;
      const [binding] = await db.select({ seal: serviceBindings.seal }).from(serviceBindings).where(eq(serviceBindings.id, ref.id));
      return binding?.seal ?? null;
    }
    case 'secret': {
      const [row] = await db.select({ seal: secrets.seal }).from(secrets).where(eq(secrets.id, ref.id));
      return row?.seal ?? null;
    }
    default:
      return (await readObject(db, ref as Ref & { kind: ReadKind })).seal;
  }
}

function sameBytes(a: Buffer | null, b: Buffer | null): boolean {
  return a === null || b === null ? a === b : Buffer.compare(a, b) === 0;
}

/**
 * A credential a token's issue came in on (`Vault.issueToken`, T149): its
 * object's columns, as the app sends them (`CredentialColumns`), its seal,
 * and its object's newest change's seal, in one read; null for no row.
 */
export async function issuingCredential(db: Queryable, id: string): Promise<{ columns: CredentialColumns; seal: Buffer | null; newest: Buffer | null } | null> {
  type Read = { id: string; principal: string; kind: string; scope: string | null; revoked: boolean | number; expires_at: number | string; not_after: number | string | null; generation: number; seal: Buffer | null; newest: Buffer | null };
  const [row] = engineOf(db) === 'postgres'
    ? await rowsOf<Read>(db, sql`SELECT * FROM issuing_credential(${id}::uuid)`)
    : await rowsOf<Read>(db, sql`SELECT c.id, c.principal, c.kind, c.scope, c.revoked_at IS NOT NULL AS revoked, c.expires_at, c.not_after, c.generation, c.seal,
        (SELECT l.seal FROM log_changes l WHERE l.object = ${objectKey({ kind: 'credential', id })} ORDER BY l.number DESC LIMIT 1) AS newest
        FROM credentials c WHERE c.id = ${id}`);
  if (row === undefined) return null;
  const ends = [Number(row.expires_at), ...(row.not_after == null ? [] : [Number(row.not_after)])];
  const bytes = (value: Buffer | null) => (value == null ? null : Buffer.from(value));
  return {
    columns: { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: Boolean(row.revoked), expiresAt: Math.min(...ends), generation: Number(row.generation) },
    seal: bytes(row.seal),
    newest: bytes(row.newest),
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

/** The rows `log_config` holds, by name: only `change_input` writes one, sealed (the roles', the policy's). */
export async function configRows(db: Queryable): Promise<Set<string>> {
  const rows = await rowsOf<{ name: string }>(db, sql`SELECT name FROM log_config`);
  return new Set(rows.map((row) => row.name));
}

/** A member's row's seal, by principal. */
export async function memberSeals(db: Queryable): Promise<Map<string, Buffer | null>> {
  const rows = await rowsOf<{ principal: string; seal: Buffer | Uint8Array | null }>(db, sql`SELECT principal, seal FROM vault_members`);
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
  const rows = await rowsOf<{ id: string; slug: string; archived: boolean | number }>(db, sql`SELECT id, slug, archived_at IS NOT NULL AS archived FROM projects`);
  return rows.map((row) => ({ id: row.id, slug: row.slug, archived: Boolean(row.archived) }));
}

export async function everyEnvironment(db: Queryable): Promise<EnvironmentRead[]> {
  const rows = await rowsOf<{ id: string; project_id: string; slug: string; owner: string | null; parent_id: string | null; archived: boolean | number; seal: Buffer | Uint8Array | null }>(
    db, sql`SELECT id, project_id, slug, owner, parent_id, archived_at IS NOT NULL AS archived, seal FROM environments`,
  );
  return rows.map((row) => ({ id: row.id, projectId: row.project_id, slug: row.slug, owner: row.owner, parentId: row.parent_id, archived: Boolean(row.archived), seal: bytes(row.seal) }));
}

/** Every key, archived or not, as `readObject` makes one (store.ts), with its newest reference row whole. */
export async function everySecret(db: Queryable): Promise<SecretRead[]> {
  const newest = (column: string) => sql.raw(`(SELECT y.${column} FROM secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1)`);
  const rows = await rowsOf<{
    id: string; project_id: string; environment_id: string; archived: boolean | number; seal: Buffer | Uint8Array | null; version_id: string | null;
    sensitive: boolean | number | null; plaintext: string | null; kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | Uint8Array | null;
    reference_id: string | null; reference_source: string | null; reference_seq: string | number | null; reference_ended: boolean | number | null;
    newest: boolean | number | null;
  }>(db, sql`SELECT s.id, s.project_id, s.environment_id, s.archived_at IS NOT NULL AS archived, s.seal, s.current_version_id AS version_id,
      s.current_version_id IS NULL OR (v.secret_id = s.id AND v.version = (SELECT max(w.version) FROM secret_versions w WHERE w.secret_id = s.id)) AS newest,
      v.sensitive, v.plaintext, v.kek_provider, v.kek_id, v.kek_version, v.wrapped_dek,
      ${newest('id')} AS reference_id, ${newest('source_secret_id')} AS reference_source, ${newest('created_seq')} AS reference_seq,
      ${newest('ended_at')} IS NOT NULL AS reference_ended
    FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id`);
  return rows.map((row) => ({
    id: row.id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    archived: Boolean(row.archived),
    seal: bytes(row.seal),
    newest: Boolean(row.newest),
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
  type Read = { id: string; principal: string; kind: string; scope: string | null; revoked: boolean | number; expires_at: string | number; not_after: string | number | null; generation: number; seal: Buffer | Uint8Array | null; logged: boolean | number };
  const rows = engineOf(db) === 'postgres'
    ? await rowsOf<Read>(db, sql`SELECT * FROM cutover_credentials(${sql.param([...ids])}::uuid[])`)
    // SQLite has no `log_object`: whether the log holds each is the plan's to see, by its key (`CutoverFacts.logged`).
    : await rowsOf<Read>(db, sql`SELECT c.id, c.principal, c.kind, c.scope, c.revoked_at IS NOT NULL AS revoked, c.expires_at, c.not_after, c.generation, c.seal,
        0 AS logged FROM credentials c WHERE c.id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`);
  return new Map(rows.map((row) => {
    // As `issuingCredential` reads one (store.ts): its end the earlier of its expiry and its hard end.
    const ends = [Number(row.expires_at), ...(row.not_after == null ? [] : [Number(row.not_after)])];
    const columns: CredentialColumns = { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: Boolean(row.revoked), expiresAt: Math.min(...ends), generation: Number(row.generation) };
    return [row.id, { columns, seal: bytes(row.seal), logged: Boolean(row.logged) }];
  }));
}

/** An MCP connection the app vouched for, as its row is now (`cutover_connections`, T147): its object's columns, its seal, and whether the log has a change of it. */
export type ConnectionRead = { columns: ConnectionColumns; seal: Buffer | null; logged: boolean };

export async function connectionsAt(db: Queryable, ids: readonly string[]): Promise<Map<string, ConnectionRead>> {
  if (ids.length === 0) return new Map();
  type Read = { id: string; principal: string; generation: number; expires_at: string | number; revoked: boolean | number; seal: Buffer | Uint8Array | null; logged: boolean | number };
  const rows = engineOf(db) === 'postgres'
    ? await rowsOf<Read>(db, sql`SELECT * FROM cutover_connections(${sql.param([...ids])}::uuid[])`)
    : await rowsOf<Read>(db, sql`SELECT k.id, k.principal, k.generation, k.expires_at, k.revoked_at IS NOT NULL AS revoked, k.seal,
        0 AS logged FROM mcp_connections k WHERE k.id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`);
  return new Map(rows.map((row) => {
    const columns: ConnectionColumns = { id: row.id, principal: row.principal, generation: Number(row.generation), expiresAt: Number(row.expires_at), revoked: Boolean(row.revoked) };
    return [row.id, { columns, seal: bytes(row.seal), logged: Boolean(row.logged) }];
  }));
}

export async function bindingsAt(db: Queryable, ids: readonly string[]): Promise<Map<string, BindingRead>> {
  if (ids.length === 0) return new Map();
  type Read = { id: string; principal: string; generation: number; profile: string; issuer: string; origin: string | null; jwks_uri: string; claims: string; scope: string | null; policy: string | null; revoked: boolean | number; seal: Buffer | Uint8Array | null; logged: boolean | number };
  const rows = engineOf(db) === 'postgres'
    ? await rowsOf<Read>(db, sql`SELECT * FROM cutover_bindings(${sql.param([...ids])}::uuid[])`)
    : await rowsOf<Read>(db, sql`SELECT b.id, b.principal, b.generation, b.profile, b.issuer, b.origin, b.jwks_uri, b.claims, b.scope, b.policy, b.revoked_at IS NOT NULL AS revoked, b.seal,
        0 AS logged FROM service_bindings b WHERE b.id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`);
  return new Map(rows.map((row) => {
    const columns: Omit<BindingColumns, 'origin'> = {
      id: row.id, principal: row.principal, generation: Number(row.generation), profile: row.profile, issuer: row.issuer, jwksUri: row.jwks_uri,
      claims: row.claims, scope: row.scope, policy: row.policy, revoked: Boolean(row.revoked),
    };
    return [row.id, { columns, origin: row.origin, seal: bytes(row.seal), logged: Boolean(row.logged) }];
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
  if (engineOf(tx) === 'postgres') {
    await rowsOf(tx, sql`SELECT cutover_places(${at}::bigint, ${sql.param([...environments])}::uuid[], ${sql.param([...secrets])}::uuid[])`);
    return;
  }
  // `cutover_places`, step for step: the transaction holds the database's write lock.
  const { environments: envs, secrets: keys, projects } = tablesOf(tx);
  if (await cutOver(tx)) throw new Error('the log is cut over from 0.14 already');
  const logged = await loggedObjects(tx);
  const rows = environments.length === 0 ? [] : await tx.select({ id: envs.id, slug: envs.slug, seal: envs.seal, projectSlug: projects.slug })
    .from(envs).innerJoin(projects, eq(projects.id, envs.projectId)).where(inArray(envs.id, [...environments]));
  if (rows.length !== environments.length || rows.some((row) => isTombstone(row.slug) || row.seal !== null || !isTombstone(row.projectSlug) || logged.has(objectKey({ kind: 'environment', id: row.id })))) {
    throw new Error('an environment named is no standing one of a deleted project, 0.14\'s alone');
  }
  for (const row of rows) await tx.update(envs).set({ slug: deletedWithProject(row.slug) }).where(eq(envs.id, row.id));
  const held = secrets.length === 0 ? [] : await tx.select({ id: keys.id, seal: keys.seal, archivedAt: keys.archivedAt, slug: envs.slug, projectSlug: projects.slug })
    .from(keys).innerJoin(envs, eq(envs.id, keys.environmentId)).innerJoin(projects, eq(projects.id, envs.projectId)).where(inArray(keys.id, [...secrets]));
  if (held.length !== secrets.length || held.some((row) => row.archivedAt !== null || row.seal !== null || !(isTombstone(row.slug) || isTombstone(row.projectSlug)) || logged.has(objectKey({ kind: 'secret', id: row.id })))) {
    throw new Error('a key named is no live one under a deleted place, 0.14\'s alone');
  }
  const archived = changedRows(await tx.update(keys).set({ archivedAt: new Date(at) }).where(and(inArray(keys.id, [...secrets]), isNull(keys.archivedAt))));
  if (archived !== secrets.length) throw new Error('a key named was archived meanwhile');
}

/** A binding's genesis (`seal_binding`): its number, or null if its row is not as its object says, or the log holds it. */
export async function sealBinding(tx: Transaction, call: ChangeCall): Promise<bigint | null> {
  if (engineOf(tx) === 'postgres') {
    const [row] = await rowsOf<{ n: string | number | null }>(tx, sql`SELECT seal_binding(${call.ref.id}::uuid, ${call.requestId}, ${call.at}::bigint, ${call.actor}, ${call.payload},
      ${call.seal}::bytea, ${call.mac}::bytea) AS n`);
    return row?.n == null ? null : BigInt(row.n);
  }
  const { serviceBindings, logChanges } = tablesOf(tx);
  if (await cutOver(tx)) throw new Error('the log is cut over from 0.14 already: a binding is the vault\'s to make');
  if ((await loggedObjects(tx)).has(objectKey(call.ref))) return null;
  const origin = (JSON.parse(call.payload) as { value?: { origin?: unknown } }).value?.origin;
  if (typeof origin !== 'string') throw new Error("a binding's genesis names the instance it was made on");
  const done = changedRows(await tx.update(serviceBindings).set({ seal: call.seal, origin })
    .where(and(eq(serviceBindings.id, call.ref.id), isNull(serviceBindings.seal), isNull(serviceBindings.revokedAt), isNull(serviceBindings.origin))));
  if (done === 0) return null;
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: call.at, requestId: call.requestId, object: objectKey(call.ref), actor: call.actor, payload: call.payload, seal: call.seal, mac: call.mac });
  return number;
}

/** The cutover's change (`log_cutover`): its number. */
export async function logCutover(tx: Transaction, row: { requestId: string; at: number; actor: string; payload: string; mac: Buffer }): Promise<bigint> {
  if (engineOf(tx) === 'postgres') {
    const [found] = await rowsOf<{ n: string | number }>(tx, sql`SELECT log_cutover(${row.requestId}, ${row.at}::bigint, ${row.actor}, ${row.payload}, ${row.mac}::bytea) AS n`);
    return BigInt(found!.n);
  }
  const { logChanges, auditChainHead } = tablesOf(tx);
  if (await cutOver(tx)) throw Object.assign(new Error('the log is cut over from 0.14 already'), { code: 'SQLITE_CONSTRAINT_UNIQUE' });
  const { anchor } = JSON.parse(row.payload) as { anchor: { seq: string; hash: string } };
  const [head] = await tx.select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash }).from(auditChainHead);
  if (head === undefined || BigInt(head.nextSeq) !== BigInt(anchor.seq) + 1n || Buffer.from(head.headHash).toString('hex') !== anchor.hash) {
    throw new Error('a cutover names 0.14\'s head as it stands');
  }
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: row.at, requestId: row.requestId, object: CUTOVER_OBJECT, actor: row.actor, payload: row.payload, seal: null, mac: row.mac });
  return number;
}

/** SQLite's next number, both tables one sequence (as `changeOnSqlite` takes it, store.ts). */
async function nextNumber(tx: Transaction): Promise<bigint> {
  const [{ last }] = await rowsOf<{ last: number | string | null }>(tx, sql`SELECT max(n) AS last FROM (SELECT max(number) AS n FROM log_changes UNION ALL SELECT max(number) FROM log_uses)`);
  return BigInt(last ?? 0) + 1n;
}

function bytes(value: Buffer | Uint8Array | null): Buffer | null {
  return value === null ? null : Buffer.from(value);
}

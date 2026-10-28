import { EVERYWHERE, ownsInstance, type InstanceRole, type Scope } from '@coffre/core/access';
import type { Author, StoredEntry } from '@coffre/core/audit';
import { isTombstone, TOMBSTONE } from '@coffre/core/schemas';
import { ACCESS_ACTIONS, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { prepared, tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { changedRows, clockMillis, engineOf, forUpdate, rowsOf, tombstone, truth } from '@coffre/db/dialect';
import { readGrants, roleColumns, storedRole, type GrantRow } from '@coffre/db/grants';
import { entryColumns, withinBytes } from '@coffre/db/log';

import { MAX_BULK_WINDOW_MINUTES } from './config.ts';
import { objectKey, type Input, type Kind, type Ref } from './inputs.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject, secretObject } from './objects.ts';
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

/**
 * Each of these environments that exists, by id, with its project, its
 * slug, what grants on one slug in every project match, and whether it was
 * deleted, alone or with its project: then no key under it opens, or is
 * wrapped, whatever grant would cover it.
 */
/** An environment as a decision reads it. */
export type EnvironmentRow = {
  projectId: string;
  slug: string;
  owner: string | null;
  parentId: string | null;
  deleted: boolean;
  archived: boolean;
};

export async function environmentsById(
  db: Queryable,
  ids: readonly string[],
): Promise<Map<string, EnvironmentRow>> {
  if (ids.length === 0) return new Map();
  const { environments, projects } = tablesOf(db);
  const rows = await db
    .select({
      id: environments.id,
      projectId: environments.projectId,
      slug: environments.slug,
      // A personal config's owner, and the environment it is a config of, whose read it takes.
      owner: environments.owner,
      parentId: environments.parentId,
      deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!),
      // Only what names a fork asks it: nothing is decided on it.
      archived: truth(or(isNotNull(environments.archivedAt), isNotNull(projects.archivedAt))!),
    })
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(inArray(environments.id, [...new Set(ids)]));
  return new Map(rows.map(({ id, ...environment }) => [id, environment]));
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
): Promise<{ projects: Set<string>; environments: Map<string, { projectId: string; slug: string }>; deleted: Set<string> }> {
  const { projects, environments } = tablesOf(db);
  const [foundProjects, foundEnvironments] = await Promise.all([
    projectIds.length === 0
      ? []
      : db.select({ id: projects.id, deleted: truth(tombstone(projects.slug)) }).from(projects).where(inArray(projects.id, [...projectIds])),
    environmentIds.length === 0
      ? []
      : db
          .select({ id: environments.id, projectId: environments.projectId, slug: environments.slug, deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!) })
          .from(environments)
          .innerJoin(projects, eq(projects.id, environments.projectId))
          .where(inArray(environments.id, [...environmentIds])),
  ]);
  return {
    projects: new Set(foundProjects.map((row) => row.id)),
    environments: new Map(foundEnvironments.map((row) => [row.id, { projectId: row.projectId, slug: row.slug }])),
    // The projects and environments among them that were deleted, alone or with their project.
    deleted: new Set([...foundProjects, ...foundEnvironments].filter((row) => row.deleted).map((row) => row.id)),
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
 * Each object is read from its own rows alone, as the change path writes
 * them: an environment is deleted when its own slug is a tombstone, not its
 * project's (a project's deletion writes its environments' rows, plan PR
 * 4b), and it is unprotected until a change or the cutover says otherwise.
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

/** The kinds whose objects the change path reads so far: the vault's own, an environment's, the roles' and the policy's. */
export type ReadKind = Exclude<Kind, 'credential' | 'secret'>;

export async function readObject(db: Queryable, ref: Ref & { kind: ReadKind }): Promise<HeldObject> {
  const { vaultMembers, environments, logConfig } = tablesOf(db);
  switch (ref.kind) {
    case 'principal': {
      const [row] = await db
        .select({ status: vaultMembers.status, owner: vaultMembers.owner, role: vaultMembers.role, scope: vaultMembers.scope, seal: vaultMembers.seal })
        .from(vaultMembers)
        .where(eq(vaultMembers.principal, ref.id));
      if (row === undefined) return { row: null, seal: null };
      return { row: principalObject({ principal: ref.id, status: row.status, ...memberStanding(row) }, await readGrants(db, { principal: ref.id })), seal: row.seal ?? null };
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
          seal: environments.seal,
        })
        .from(environments)
        .where(eq(environments.id, ref.id));
      if (row === undefined) return { row: null, seal: null };
      const { projectId, slug, owner, parentId, archivedAt } = row;
      return { row: environmentObject({ id: ref.id, projectId, slug, owner, parentId, protected: row.protected, archived: archivedAt !== null }), seal: row.seal ?? null };
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

/**
 * An object as its rows hold it, for the verifier's row audit (verifier.ts):
 * its object, null where its rows hold none (a key archived), and the seal
 * on them. A binding is held by its seal alone: no object of the log is
 * made from one yet.
 */
export type Held = { ref: Ref; row: Input | null; seal: Buffer | null; sealOnly?: true; unreadable?: true };

/**
 * Every object the rows hold, by key, each read as the use's statement and
 * the change path read it (`objects.ts`): members with their grants, lapsed
 * ones too; credentials, their end the earlier of expiry and hard end;
 * keys, archived ones with no object, a reference with its newest
 * reference's source; environments; the roles and the policy. Every row:
 * a whole walk's audit, never a page's (verifier.ts). A row a writer
 * made that reads as no object is held as unreadable, never thrown on.
 */
export async function heldObjects(db: Queryable): Promise<Map<string, Held>> {
  const { vaultMembers, credentials, serviceBindings, secrets, secretVersions, secretReferences, environments, logConfig } = tablesOf(db);
  const source = sql<string | null>`(SELECT ${secretReferences.sourceSecretId} FROM ${secretReferences} WHERE ${secretReferences.secretId} = ${secrets.id} ORDER BY ${secretReferences.createdSeq} DESC LIMIT 1)`;
  const [members, held, tokens, bindings, keys, places, config] = await Promise.all([
    db.select({ principal: vaultMembers.principal, status: vaultMembers.status, owner: vaultMembers.owner, role: vaultMembers.role, scope: vaultMembers.scope, seal: vaultMembers.seal }).from(vaultMembers),
    readGrants(db),
    db.select({ id: credentials.id, principal: credentials.principal, kind: credentials.kind, scope: credentials.scope, revokedAt: credentials.revokedAt, expiresAt: credentials.expiresAt, notAfter: credentials.notAfter, seal: credentials.seal }).from(credentials),
    db.select({ id: serviceBindings.id, seal: serviceBindings.seal }).from(serviceBindings).where(isNotNull(serviceBindings.seal)),
    db.select({
      id: secrets.id, projectId: secrets.projectId, environmentId: secrets.environmentId, archivedAt: secrets.archivedAt, seal: secrets.seal, versionId: secrets.currentVersionId,
      sensitive: secretVersions.sensitive, plain: sql<boolean | number | null>`${secretVersions.plaintext} IS NOT NULL`, kekProvider: secretVersions.kekProvider,
      kekId: secretVersions.kekId, kekVersion: secretVersions.kekVersion, wrappedDek: secretVersions.wrappedDek, source,
    }).from(secrets).leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId)),
    db.select({ id: environments.id, projectId: environments.projectId, slug: environments.slug, owner: environments.owner, parentId: environments.parentId, protected: environments.protected, archivedAt: environments.archivedAt, seal: environments.seal }).from(environments),
    db.select({ name: logConfig.name, value: logConfig.value, seal: logConfig.seal }).from(logConfig),
  ]);
  const found = new Map<string, Held>();
  const hold = (ref: Ref, row: Input | null, seal: Buffer | null | undefined, as: { sealOnly?: true; unreadable?: true } = {}) => found.set(objectKey(ref), { ref, row, seal: seal ?? null, ...as });
  const grantsOf = new Map<string, GrantRow[]>();
  for (const grant of held) grantsOf.set(grant.principal, [...(grantsOf.get(grant.principal) ?? []), grant]);
  for (const m of members) hold({ kind: 'principal', id: m.principal }, principalObject({ principal: m.principal, status: m.status, ...memberStanding(m) }, grantsOf.get(m.principal) ?? []), m.seal);
  for (const c of tokens) {
    // Its end in whole ms, as the app sends it (`credentialColumns`): the earlier of expiry and hard end.
    const expiresAt = Math.min(c.expiresAt.getTime(), c.notAfter?.getTime() ?? Infinity);
    hold({ kind: 'credential', id: c.id }, credentialObject({ id: c.id, principal: c.principal, kind: c.kind, scope: c.scope, revoked: c.revokedAt !== null, expiresAt }), c.seal);
  }
  for (const b of bindings) if (!found.has(objectKey({ kind: 'credential', id: b.id }))) hold({ kind: 'credential', id: b.id }, null, b.seal, { sealOnly: true });
  for (const k of keys) {
    const version = k.versionId === null || k.wrappedDek === null ? null : {
      id: k.versionId, sensitive: k.sensitive === true, plain: Boolean(k.plain), kekProvider: k.kekProvider!, kekId: k.kekId!, kekVersion: k.kekVersion!,
      wrappedDek: Buffer.from(k.wrappedDek).toString('base64'),
    };
    const object = k.archivedAt !== null ? null : secretObject({ id: k.id, projectId: k.projectId, environmentId: k.environmentId, source: k.versionId === null ? k.source : null, version });
    hold({ kind: 'secret', id: k.id }, object, k.seal);
  }
  for (const e of places) {
    const { id, projectId, slug, owner, parentId } = e;
    hold({ kind: 'environment', id }, environmentObject({ id, projectId, slug, owner, parentId, protected: e.protected, archived: e.archivedAt !== null }), e.seal);
  }
  for (const c of config) {
    if (c.name !== 'roles' && c.name !== 'policy') continue;
    let object: Input | null = null;
    try {
      object = configObject(c.value);
    } catch {}
    // An object of its own kind, or none: a writer's `{"kind":"principal"}` in the roles' row is no roles (review r12).
    const readable = object !== null && typeof object === 'object' && !Array.isArray(object) && object.kind === c.name;
    hold({ kind: c.name, id: 'instance' }, readable ? object : null, c.seal, readable ? {} : { unreadable: true });
  }
  return found;
}

/**
 * Whole walks of 0.15's log an instance runs at once, at most (review r11):
 * each holds a snapshot, and a call of the vault, for seconds. One more is
 * refused at once (`TreesBusy`), never queued.
 */
export const WHOLE_WALKS = 2;

/** The advisory lock of the whole walks' slots: one of its own, beside the fence's (1668244070). */
const WALKS_LOCK = 1668244071;

/**
 * Whether a whole walk has a slot, for the rest of `tx`: on Postgres, the
 * first of `WHOLE_WALKS` advisory locks free, tried and never waited on, so
 * a walk holds no connection in a lock wait (R44) and lets go at its end.
 * SQLite's transactions take their turns on its one file already.
 */
export async function walkSlot(tx: Queryable): Promise<boolean> {
  if (engineOf(tx) === 'sqlite') return true;
  const tries = Array.from({ length: WHOLE_WALKS }, (_, i) => sql`WHEN pg_try_advisory_xact_lock(${WALKS_LOCK}, ${i}) THEN true`);
  const [row] = await rowsOf<{ got: boolean }>(tx, sql`SELECT CASE ${sql.join(tries, sql` `)} ELSE false END AS got`);
  return row?.got === true;
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
 * A change as `change_input` takes it: the object, the request it is (a
 * retry finds its entry), when and by whom, what it does (`payload`, the
 * op as logged), the object it leaves where the function writes it
 * (`value`), the seal it was read at and the one it leaves, and the
 * entry's MAC.
 */
export type ChangeCall = {
  ref: Ref;
  requestId: string;
  at: number;
  actor: string;
  payload: string;
  value: string | null;
  sealFrom: Buffer | null;
  seal: Buffer;
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

/** The ops `change_input` takes, by kind (0023): the cutover's genesis on any. */
const KNOWN_OPS: Record<Kind, readonly string[]> = {
  principal: ['member.add', 'member.role', 'member.remove', 'member.restore', 'access.grant', 'access.revoke'],
  environment: ['environment.protect', 'environment.rename', 'environment.archive'],
  roles: ['role.define'],
  policy: ['bulk.limit'],
  credential: [],
  secret: [],
};

/** `change_input`, step for step, on SQLite. */
async function changeOnSqlite(tx: Transaction, call: ChangeCall): Promise<bigint | null> {
  const { logChanges, logUses, vaultMembers, environments, logConfig, credentials, serviceBindings, secrets } = tablesOf(tx);
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
  if (typeof op !== 'string' || (op !== 'genesis' && !KNOWN_OPS[ref.kind].includes(op))) throw new Error(`this schema knows no change ${String(op)} to a ${ref.kind}`);
  const named = (JSON.parse(call.payload) as { ref?: { kind?: unknown; id?: unknown } }).ref;
  if ((op !== 'genesis' || named !== undefined) && (named?.kind !== ref.kind || named.id !== ref.id)) throw new Error(`a change names the object it is to: ${ref.kind}, ${ref.id}`);
  const value = call.value === null ? null : (JSON.parse(call.value) as Record<string, unknown>);
  const valued = ref.kind === 'environment' ? op !== 'genesis' && value === null : ref.kind === 'roles' || ref.kind === 'policy' ? (op === 'genesis') === (value !== null) : value !== null;
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
    case 'secret':
      done = changedRows(await tx.update(secrets).set({ seal: call.seal }).where(and(eq(secrets.id, ref.id), from(secrets.seal))));
      break;
    case 'environment': {
      if (value === null) {
        done = changedRows(await tx.update(environments).set({ seal: call.seal }).where(and(eq(environments.id, ref.id), from(environments.seal))));
        break;
      }
      const [row] = await tx.select({ projectId: environments.projectId, parentId: environments.parentId, owner: environments.owner, slug: environments.slug, archivedAt: environments.archivedAt, seal: environments.seal }).from(environments).where(eq(environments.id, ref.id));
      const deleted = value.deleted === true;
      const holds = row !== undefined && sameBytes(row.seal ?? null, call.sealFrom) && value.kind === 'environment' && value.id === ref.id
        && row.projectId === value.projectId && row.parentId === (value.parentId ?? null) && row.owner === (value.owner ?? null)
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
  const { credentials, serviceBindings, secrets } = tablesOf(db);
  switch (ref.kind) {
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

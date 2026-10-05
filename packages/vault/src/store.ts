import type { GrantPlace } from '@coffre/core/access';
import type { Author, StoredEntry } from '@coffre/core/audit';
import { ACCESS_ACTIONS, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { clockMillis, engineOf, forUpdate, tombstone, truth } from '@coffre/db/dialect';
import { readGrants, type GrantRow } from '@coffre/db/grants';
import { and, asc, count, desc, eq, gt, gte, inArray, isNull, lt, lte, or, sql, type SQL, type SQLWrapper } from 'drizzle-orm';

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
  owner: boolean;
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
 * Where a grant applies: a project, one of its environments (with its
 * project, which its row finds through `environments`), every project, or
 * one environment slug in every project.
 */
export type Place = GrantPlace;

/** A grant as stored; `@coffre/db/grants` reads and writes them on any schema since the baseline. */
export type { GrantRow };
export { canGrantEveryProject, insertGrant } from '@coffre/db/grants';

/**
 * On Postgres, fail a lock wait in this transaction after `ms`, rather than
 * wait for ever behind a transaction that never ends.
 */
export async function boundLockWaits(tx: Transaction, ms: number): Promise<void> {
  if (engineOf(tx) === 'postgres') await tx.execute(sql.raw(`SET LOCAL lock_timeout = ${Math.trunc(ms)}`));
}

/** The database's clock, now. */
export async function now(db: Queryable): Promise<number> {
  const { auditChainHead } = tablesOf(db);
  const [{ at }] = await db.select({ at: clockMillis(db) }).from(auditChainHead);
  return at;
}

// --- members --------------------------------------------------------------------

function memberColumns(db: Queryable) {
  const { vaultMembers } = tablesOf(db);
  return {
    principal: vaultMembers.principal,
    status: vaultMembers.status,
    owner: vaultMembers.owner,
    generation: vaultMembers.generation,
    createdAt: vaultMembers.createdAt,
    createdBy: vaultMembers.createdBy,
    statusChangedAt: vaultMembers.statusChangedAt,
    statusChangedBy: vaultMembers.statusChangedBy,
    accessSeq: vaultMembers.accessSeq,
    mac: vaultMembers.mac,
  };
}

export async function member(db: Queryable, principal: string): Promise<Member | undefined> {
  const { vaultMembers } = tablesOf(db);
  const [row] = await db.select(memberColumns(db)).from(vaultMembers).where(eq(vaultMembers.principal, principal));
  return row as Member | undefined;
}

export async function allMembers(db: Queryable): Promise<Member[]> {
  const { vaultMembers } = tablesOf(db);
  return (await db.select(memberColumns(db)).from(vaultMembers).orderBy(asc(vaultMembers.principal))) as Member[];
}

/**
 * Lock these members' rows for the rest of the transaction, in one order
 * everywhere, and read them: those that have none are not in the map. Every
 * decision about a member takes its row first, so two of them, from any
 * process, never interleave.
 */
export async function lockMembers(tx: Transaction, principals: readonly string[]): Promise<Map<string, Member>> {
  const { vaultMembers } = tablesOf(tx);
  const rows = await forUpdate(
    tx,
    tx
      .select(memberColumns(tx))
      .from(vaultMembers)
      .where(inArray(vaultMembers.principal, [...new Set(principals)]))
      .orderBy(asc(vaultMembers.principal)),
    'no key update',
  );
  return new Map((rows as Member[]).map((row) => [row.principal, row]));
}

/**
 * Add `row`. A principal has one row: when two decisions admit the same
 * one at once, the second fails here, and rolls back with its entries.
 */
export async function insertMember(tx: Transaction, row: Member): Promise<void> {
  const { vaultMembers } = tablesOf(tx);
  await tx.insert(vaultMembers).values(row);
}

export async function updateMember(
  tx: Transaction,
  principal: string,
  change: Partial<Omit<Member, 'principal'>>,
): Promise<void> {
  const { vaultMembers } = tablesOf(tx);
  await tx.update(vaultMembers).set(change).where(eq(vaultMembers.principal, principal));
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
export async function environmentsById(
  db: Queryable,
  ids: readonly string[],
): Promise<Map<string, { projectId: string; slug: string; deleted: boolean }>> {
  if (ids.length === 0) return new Map();
  const { environments, projects } = tablesOf(db);
  const rows = await db
    .select({
      id: environments.id,
      projectId: environments.projectId,
      slug: environments.slug,
      deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!),
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

/** Of these projects and environments, the ones that exist, each environment with its project. */
export async function places(
  db: Queryable,
  projectIds: readonly string[],
  environmentIds: readonly string[],
): Promise<{ projects: Set<string>; environments: Map<string, string>; deleted: Set<string> }> {
  const { projects, environments } = tablesOf(db);
  const [foundProjects, foundEnvironments] = await Promise.all([
    projectIds.length === 0
      ? []
      : db.select({ id: projects.id, deleted: truth(tombstone(projects.slug)) }).from(projects).where(inArray(projects.id, [...projectIds])),
    environmentIds.length === 0
      ? []
      : db
          .select({ id: environments.id, projectId: environments.projectId, deleted: truth(or(tombstone(environments.slug), tombstone(projects.slug))!) })
          .from(environments)
          .innerJoin(projects, eq(projects.id, environments.projectId))
          .where(inArray(environments.id, [...environmentIds])),
  ]);
  return {
    projects: new Set(foundProjects.map((row) => row.id)),
    environments: new Map(foundEnvironments.map((row) => [row.id, row.projectId])),
    // The projects and environments among them that were deleted, alone or with their project.
    deleted: new Set([...foundProjects, ...foundEnvironments].filter((row) => row.deleted).map((row) => row.id)),
  };
}

// --- the log --------------------------------------------------------------------

/** The action of an entry that releases a key, which the bulk limit counts. */
export const RELEASE = 'secret.read';

/** How many keys the vault has released to `principal` since `after`. */
export async function releasesSince(db: Queryable, principal: string, after: number): Promise<number> {
  const { auditLog } = tablesOf(db);
  const [{ n }] = await db
    .select({ n: count() })
    .from(auditLog)
    .where(
      and(
        eq(auditLog.author, 'vault'),
        eq(auditLog.actor, principal),
        eq(auditLog.action, RELEASE),
        eq(auditLog.decision, 'allow'),
        gt(auditLog.occurredAt, after),
      ),
    );
  return Number(n);
}

function entryColumns(db: Queryable) {
  const { auditLog } = tablesOf(db);
  return {
    seq: auditLog.seq,
    author: auditLog.author,
    keyId: auditLog.keyId,
    occurredAt: auditLog.occurredAt,
    actor: auditLog.actor,
    action: auditLog.action,
    decision: auditLog.decision,
    code: auditLog.code,
    subjectPrincipal: auditLog.subjectPrincipal,
    projectId: auditLog.projectId,
    environmentId: auditLog.environmentId,
    secretId: auditLog.secretId,
    secretVersionId: auditLog.secretVersionId,
    operationId: auditLog.operationId,
    requestId: auditLog.requestId,
    sourceIp: auditLog.sourceIp,
    relatedSeq: auditLog.relatedSeq,
    metadata: auditLog.metadata,
    prevHash: auditLog.prevHash,
    mac: auditLog.mac,
    hash: auditLog.hash,
  };
}

/** Rows of the log as the chain's codec reads them: `author` and `decision` are checked by the table. */
function stored(rows: object[]): StoredEntry[] {
  return rows as StoredEntry[];
}

/** Up to `limit` entries of either author from `fromSeq`, oldest first: the chain as it runs. */
export async function entriesFrom(db: Queryable, fromSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(gte(auditLog.seq, fromSeq))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return stored(rows);
}

/** Up to `limit` of the vault's entries after `afterSeq`, oldest first: every one, whatever its action or decision. */
export async function vaultEntriesAfter(db: Queryable, afterSeq: bigint, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault' satisfies Author), gt(auditLog.seq, afterSeq)))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
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

/**
 * Whether every entry from the first through `seq` is there. Seqs are the
 * primary key, so the count is `seq + 1` exactly when none is missing: one
 * pass over the key's index, never the entries.
 */
export async function complete(db: Queryable, seq: bigint): Promise<boolean> {
  const { auditLog } = tablesOf(db);
  const [{ n }] = await db.select({ n: count() }).from(auditLog).where(and(gte(auditLog.seq, 0n), lte(auditLog.seq, seq)));
  return BigInt(n) === seq + 1n;
}

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

/** Up to `limit` of the vault's allowed access entries about `principal`, newest first. */
export async function accessEntriesAbout(db: Queryable, principal: string, limit: number): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(
      and(
        eq(auditLog.author, 'vault'),
        eq(auditLog.subjectPrincipal, principal),
        inArray(auditLog.action, [...ACCESS_ACTIONS]),
        eq(auditLog.decision, 'allow'),
      ),
    )
    .orderBy(desc(auditLog.seq))
    .limit(limit);
  return stored(rows);
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
export type SecretVersion = { id: string; secret: SecretRef; wrapped: WrappedKey; deleted: boolean; current: boolean };

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
      // The newest by the versions' own order: the app may write `current_version_id`, never a version.
      newest: sql<number | string>`(SELECT max(newest.version) FROM secret_versions newest WHERE newest.secret_id = ${secretVersions.secretId})`,
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
    },
    wrapped: {
      kekProvider: row.kekProvider,
      kekId: row.kekId,
      kekVersion: row.kekVersion,
      bytes: row.wrappedDek.toString('base64'),
    },
    current: row.currentVersionId === row.id && Number(row.newest) === row.version,
  }));
}

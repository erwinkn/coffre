import { GENESIS_HASH, sealEntry, type LogFields, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { and, asc, count, desc, eq, gt, gte, lt, lte, sql, type Placeholder, type SQL } from 'drizzle-orm';

import { afterCommit } from './commits.ts';
import { tablesOf, type Queryable, type Transaction } from './database.ts';
import { prepared } from './prepared.ts';
import { clockMillis, engineOf, forUpdate } from './dialect.ts';

/**
 * Appending to the audit log, the one table both the app and the vault
 * write, each under its own key (@coffre/core/audit says what an entry's MAC
 * and hash cover).
 *
 * Every append locks the log's head first, `audit_chain_head`, so entries
 * from any process take their numbers in one order. It then reads the
 * database clock, after the lock, and the log's last entry, which the head
 * must name: a head that does not was moved, or entries were deleted behind
 * it, and the append refuses. The same statement says whether the log has
 * moved on from the key it appends under (`KeyRetired`).
 *
 * This is deliberately not a queue and not best-effort: the entries go in
 * the caller's transaction, so if the append fails, what it records does
 * not happen either.
 */

/** An entry to append: what it says. The append numbers, dates, signs and chains it. */
export type NewEntry = {
  actor: string;
  action: string;
  decision: 'allow' | 'deny';
  code?: string | null;
  subjectPrincipal?: string | null;
  projectId?: string | null;
  environmentId?: string | null;
  secretId?: string | null;
  secretVersionId?: string | null;
  operationId?: string | null;
  requestId?: string | null;
  sourceIp?: string | null;
  relatedSeq?: bigint | null;
  /** JSON text. */
  metadata?: string;
};

export type Appended = {
  /** The first entry's number, and the next number after the last. */
  seqStart: bigint;
  nextSeq: bigint;
  headHash: Buffer;
  /** Milliseconds since the epoch, the database's, shared by the batch. */
  occurredAt: number;
};

/** The log's head does not name its last entry: something moved it, or cut the log behind it. */
export class LogHeadMismatch extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogHeadMismatch';
  }
}

/**
 * The log's head is behind one this process wrote: the database was rolled
 * back, or entries were cut off its end. That cannot be told from a restore,
 * so the append refuses and someone has to look.
 */
export class LogRewound extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogRewound';
  }
}

/**
 * An append under a key the log has moved on from: an entry of its
 * author's, `key.reseal` or `key.rotate`, names it as the key it moves
 * from (`MOVES_FROM`), and a key moved from writes no more.
 */
export class KeyRetired extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyRetired';
  }
}

/**
 * The actions by which an author moves to a new key, each under the new one
 * and naming the key it moves from as its subject: from the first, that key
 * writes no more (`KeyRetired`). The app's key rotation writes them
 * (packages/server/src/key-rotation.ts).
 */
export const MOVES_FROM = ['key.reseal', 'key.rotate'] as const;

/**
 * The newest head each writer has written, under each of its keys, while
 * the process lives. A head is remembered only once the transaction that
 * wrote it has committed, all the way out (commits.ts): one that rolls back
 * never puts it ahead of the database, and the last batch committed is
 * covered too. When commits race, the furthest head stays.
 */
const remembered = new WeakMap<LogKey, { epoch: number; nextSeq: bigint; headHash: Buffer }>();
let epoch = 0;

function remember(key: LogKey, head: { nextSeq: bigint; headHash: Buffer }): void {
  const before = remembered.get(key);
  if (before !== undefined && before.epoch === epoch && before.nextSeq >= head.nextSeq) return;
  remembered.set(key, { epoch, ...head });
}

/**
 * Forget every head written so far. For tests that empty the database
 * between cases, which is exactly what the check above refuses.
 */
export function forgetLogHeads(): void {
  epoch += 1;
}

/**
 * Lock the log's head, and read it. A transaction that appends takes this
 * before any other row, so the lock order is the same everywhere; taking it
 * again in the same transaction is free.
 */
export async function lockLogHead(tx: Transaction): Promise<{ nextSeq: bigint; headHash: Buffer }> {
  const [head] = await lockedHead(tx);
  if (head === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
  return head;
}

const lockedHead = prepared((db) => {
  const { auditChainHead } = tablesOf(db);
  return forUpdate(
    db,
    db.select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash }).from(auditChainHead).where(eq(auditChainHead.onlyRow, true)),
  );
});

/**
 * Append `entries` under `key`. `check`, when given, runs once the head is
 * locked and before anything is written: a writer's own condition on the
 * log as it stands, which no other append can change until this one
 * commits. It throws to refuse.
 */
export async function appendEntries(
  tx: Transaction,
  key: LogKey,
  entries: readonly NewEntry[],
  check?: (tx: Transaction) => Promise<void>,
  /**
   * The head as a statement of the caller's locked it, with the log's last
   * entry and the clock as that statement read them once it held the lock:
   * nothing to read again.
   */
  locked?: HeldHead,
): Promise<Appended> {
  if (entries.length === 0) throw new Error('appendEntries called with no entries');
  const { auditChainHead, auditLog } = tablesOf(tx);

  // Every append queues here, if its transaction has not already.
  const head = locked?.head ?? (await lockLogHead(tx));
  await check?.(tx);
  const now = locked?.at ?? (await clockNow(tx))[0]!.now;
  const [read] = locked === undefined ? await lastEntry(tx, { author: key.author, keyId: key.keyId }) : [];
  const last = locked === undefined ? read : locked.last ?? undefined;
  // The log's own last row says whether the log has moved on from this key: one statement, under the lock.
  if (read !== undefined && Boolean(read.retired)) {
    throw new KeyRetired(`the log moved on from ${key.keyId}: a key the ${key.author} rotated from writes no more`);
  }

  const expected = last === undefined ? { nextSeq: 0n, headHash: GENESIS_HASH } : { nextSeq: last.seq + 1n, headHash: last.hash };
  if (head.nextSeq !== expected.nextSeq || !head.headHash.equals(expected.headHash)) {
    throw new LogHeadMismatch(
      `the log's head says entry ${head.nextSeq} comes next, but the log ends ${last === undefined ? 'empty' : `at entry ${last.seq}`}, or with another hash`,
    );
  }
  const before = remembered.get(key);
  if (
    before !== undefined &&
    before.epoch === epoch &&
    (head.nextSeq < before.nextSeq || (head.nextSeq === before.nextSeq && !head.headHash.equals(before.headHash)))
  ) {
    throw new LogRewound(`the log ends before entry ${before.nextSeq}, which this process wrote: it was rolled back`);
  }

  let seq = head.nextSeq;
  let prevHash = head.headHash;
  const rows: (typeof auditLog.$inferInsert)[] = [];
  for (const entry of entries) {
    const fields: LogFields = {
      seq,
      author: key.author,
      keyId: key.keyId,
      occurredAt: now,
      actor: entry.actor,
      action: entry.action,
      decision: entry.decision,
      code: entry.code ?? null,
      subjectPrincipal: entry.subjectPrincipal ?? null,
      projectId: entry.projectId ?? null,
      environmentId: entry.environmentId ?? null,
      secretId: entry.secretId ?? null,
      secretVersionId: entry.secretVersionId ?? null,
      operationId: entry.operationId ?? null,
      requestId: entry.requestId ?? null,
      sourceIp: entry.sourceIp ?? null,
      relatedSeq: entry.relatedSeq ?? null,
      metadata: entry.metadata ?? '{}',
    };
    const { mac, hash } = sealEntry(key, prevHash, fields);
    rows.push({ ...fields, prevHash, mac, hash });
    prevHash = hash;
    seq += 1n;
  }

  if (engineOf(tx) === 'postgres' && rows.length <= ROWS_AT_ONCE) {
    // The entries and the head that names the last of them, in one statement.
    await tx.execute(sql`WITH appended AS (${tx.insert(auditLog).values(rows).getSQL()})
      UPDATE audit_chain_head SET next_seq = ${seq}, head_hash = ${prevHash} WHERE only_row`);
  } else {
    await tx.insert(auditLog).values(rows);
    await tx.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash }).where(eq(auditChainHead.onlyRow, true));
  }
  const written = { nextSeq: seq, headHash: prevHash };
  afterCommit(tx, () => remember(key, written));
  return { seqStart: head.nextSeq, ...written, occurredAt: now };
}

/** A head locked by a statement of the caller's, and what it read under the lock (`appendEntries`). */
export type HeldHead = { head: { nextSeq: bigint; headHash: Buffer }; last: { seq: bigint; hash: Buffer } | null; at: number };

/** Entries one statement inserts at most, at 21 parameters each: Postgres takes 65,535. */
const ROWS_AT_ONCE = 3000;

const clockNow = prepared((db) => db.select({ now: clockMillis(db) }).from(tablesOf(db).auditChainHead));

const lastEntry = prepared((db) => {
  const { auditLog } = tablesOf(db);
  const moved = sql.raw(MOVES_FROM.map((action) => `'${action}'`).join(', '));
  const retired = sql<boolean | number>`EXISTS (SELECT 1 FROM audit_log moved WHERE moved.author = ${sql.placeholder('author')} AND moved.subject_principal = ${sql.placeholder('keyId')} AND moved.action IN (${moved}))`;
  return db.select({ seq: auditLog.seq, hash: auditLog.hash, retired }).from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
});

// --- reading the vault's entries back ---------------------------------------------

/** An entry's columns, as the chain's codec reads them (`StoredEntry`). */
export function entryColumns(db: Queryable) {
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

/**
 * Metadata a reader of many entries holds at once, at most: an entry about
 * a read of several secrets lists them, a thousand some 150 kilobytes, so a
 * count of entries alone does not bound a batch's or a page's memory within
 * a Worker's 128 megabytes.
 */
export const BATCH_BYTES = 8 * 1024 * 1024;

/**
 * Of the entries `where` matches, in `order` of seq, the first `limit` or
 * fewer that hold no more than `BATCH_BYTES` of metadata between them, but
 * always the first: the seqs they run from and to, and whether the bytes
 * cut the run short of `limit`. Null when none matches. A reader asks this
 * first, then reads `where` between the two.
 */
export async function withinBytes(
  db: Queryable,
  where: SQL | undefined,
  limit: number,
  order: 'asc' | 'desc' = 'asc',
): Promise<{ from: bigint; to: bigint; cut: boolean; count: number } | null> {
  const { auditLog } = tablesOf(db);
  const sizes = await db
    .select({ seq: auditLog.seq, bytes: sql<number | string>`length(${auditLog.metadata})` })
    .from(auditLog)
    .where(where)
    .orderBy(order === 'asc' ? asc(auditLog.seq) : desc(auditLog.seq))
    .limit(limit);
  let held = 0;
  let count = 0;
  for (const { bytes } of sizes) {
    held += Number(bytes);
    if (count > 0 && held > BATCH_BYTES) break;
    count += 1;
  }
  if (count === 0) return null;
  return { from: sizes[0]!.seq, to: sizes[count - 1]!.seq, cut: count < sizes.length, count };
}

/**
 * The first entry missing from the log up to `seq`, and the one found in
 * its place, or null when every one is there. Seqs are the primary key, so
 * a stretch is whole exactly when its count is its length: one pass over
 * the key's index, never the entries. Only a log with a gap pays for more,
 * a count per halving to find where.
 *
 *   entries 0..9, 4 cut:  { expected: 4n, found: 5n }
 */
export async function missingEntry(db: Queryable, seq: bigint): Promise<{ expected: bigint; found: bigint | null } | null> {
  const { auditLog } = tablesOf(db);
  const whole = async (to: bigint) => {
    const [{ n }] = await db.select({ n: count() }).from(auditLog).where(and(gte(auditLog.seq, 0n), lte(auditLog.seq, to)));
    return BigInt(n) === to + 1n;
  };
  if (seq < 0n || (await whole(seq))) return null;
  // The first stretch from 0 that is not whole ends at the missing entry.
  let [low, high] = [0n, seq];
  while (low < high) {
    const middle = (low + high) / 2n;
    if (await whole(middle)) low = middle + 1n;
    else high = middle;
  }
  const [next] = await db.select({ seq: auditLog.seq }).from(auditLog).where(gt(auditLog.seq, low)).orderBy(asc(auditLog.seq)).limit(1);
  return { expected: low, found: (next?.seq as bigint | undefined) ?? null };
}

/**
 * How a reader tells the vault's own entries from those forged in its name:
 * by their MAC, which only the vault holds the key to check. Each it finds
 * forged goes to `forged`.
 */
export type Authenticity = { authentic: (entry: StoredEntry) => boolean; forged: (entry: StoredEntry) => void };

/** Up to `limit` of the entries in the vault's name, allowed, of one `action`, before `before` (the newest when undefined), newest first. */
export async function newestVaultEntries(db: Queryable, action: string, limit: number, before?: bigint): Promise<StoredEntry[]> {
  const rows = before === undefined ? await newestEntries(db, { action, limit }) : await entriesBefore(db, { action, limit, before });
  return rows as StoredEntry[];
}

function vaultEntries(db: Queryable, before?: SQL) {
  const { auditLog } = tablesOf(db);
  return db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, sql.placeholder('action')), eq(auditLog.decision, 'allow'), before))
    .orderBy(desc(auditLog.seq))
    .limit(sql.placeholder('limit'));
}

const newestEntries = prepared((db) => vaultEntries(db));
const entriesBefore = prepared((db) => vaultEntries(db, lt(tablesOf(db).auditLog.seq, sql.placeholder('before'))));

/**
 * The number of the newest entry in the vault's name, allowed, of one
 * `action`, or null for none: whether one was appended since, and nothing
 * of what it says, so its MAC is not checked. One indexed read.
 */
export async function newestVaultSeq(db: Queryable, action: string): Promise<bigint | null> {
  const [row] = await newestSeq(db, { action });
  return (row?.seq as bigint | undefined) ?? null;
}

const newestSeq = prepared((db) => newestSeqQuery(db, sql.placeholder('action')));

/**
 * `newestVaultSeq`'s query, to run or to read inside another, as a
 * credential's read takes the newest `policy.change` with it: one rule for
 * what the newest is, wherever it is read.
 */
export function newestSeqQuery(db: Queryable, action: string | Placeholder) {
  const { auditLog } = tablesOf(db);
  return db
    .select({ seq: auditLog.seq })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, action), eq(auditLog.decision, 'allow')))
    .orderBy(desc(auditLog.seq))
    .limit(1);
}

/** How many entries in its name the vault reads back, a page at a time, for its own newest of a kind (`newestAuthentic`). */
export const LOOK_BACK = { page: 32, pages: 32 };

/** What `newestAuthentic` finds: the entry, or why there is none. */
export type Newest = StoredEntry | 'none' | 'forged' | 'unreached';

/**
 * The newest of the entries `page` reads, newest first and before a seq,
 * that `check` finds authentic: the newest alone first, which it is unless
 * entries were forged in the vault's name since, then back a page at a
 * time. 'none' when there are none at all, 'forged' when every one is in
 * the vault's name but not its own, and 'unreached' once it has read
 * LOOK_BACK such entries (1024), whether or not more are left.
 */
export async function newestAuthentic(page: (limit: number, before: bigint | undefined) => Promise<StoredEntry[]>, check: Authenticity): Promise<Newest> {
  const most = LOOK_BACK.page * LOOK_BACK.pages;
  let read = 0;
  let before: bigint | undefined;
  for (let limit = 1; read < most; limit = Math.min(LOOK_BACK.page, most - read)) {
    const entries = await page(limit, before);
    for (const entry of entries) {
      if (check.authentic(entry)) return entry;
      check.forged(entry);
    }
    read += entries.length;
    if (entries.length < limit) return read === 0 ? 'none' : 'forged';
    before = entries.at(-1)!.seq;
  }
  return 'unreached';
}

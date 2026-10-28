import { GENESIS_HASH, sealEntry, type LogFields, type LogKey, type StoredEntry } from '@coffre/core/audit';
import type { PreparedChange } from '@coffre/core/vault';
import { and, asc, count, desc, eq, gt, gte, isNotNull, isNull, lt, lte, sql, type Placeholder, type SQL } from 'drizzle-orm';

import { afterCommit } from './commits.ts';
import { tablesOf, type Queryable, type Transaction } from './database.ts';
import { prepared } from './prepared.ts';
import { changedRows, clockMillis, engineOf, forUpdate, rowsOf } from './dialect.ts';

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
 * As many transactions as may already wait for the log's head do
 * (`lockLogHeadQueued`): this one waits for nothing, and holds nothing.
 * Its code is Postgres's for a lock not available, so every caller already
 * answers it as one that gave up waiting: unavailable, ask again shortly.
 */
export class HeadBusy extends Error {
  readonly code = '55P03';
  constructor() {
    super("too many requests wait for the audit log's head: ask again shortly");
    this.name = 'HeadBusy';
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
 * The transactions that hold the head: an append in one reads what it
 * needs under the lock in one statement, where one that does not first
 * takes the lock in another. A savepoint's transaction is another to this
 * set, so a lock is marked on the object that took it, and an append made
 * through another object locks again, which is free.
 */
const holding = new WeakSet<Transaction>();

/**
 * Lock the log's head, and read it. A transaction that appends takes this
 * before any other row, so the lock order is the same everywhere; taking it
 * again in the same transaction is free.
 */
export async function lockLogHead(tx: Transaction): Promise<{ nextSeq: bigint; headHash: Buffer }> {
  const [head] = await lockedHead(tx);
  if (head === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
  holding.add(tx);
  return head;
}

/**
 * Lock the log's head if no one holds it, without waiting: whether it is
 * held now. For work any caller may do, of which one at a time is enough,
 * which a request that finds the head taken leaves to the one that has it.
 * SQLite's transactions hold the whole file, so the head is always free.
 */
export async function lockLogHeadIfFree(tx: Transaction): Promise<boolean> {
  if (engineOf(tx) === 'sqlite') {
    const held = (await lockedHead(tx)).length > 0;
    if (held) holding.add(tx);
    return held;
  }
  const rows = await rowsOf(tx, sql`SELECT next_seq FROM audit_chain_head WHERE only_row FOR UPDATE SKIP LOCKED`);
  if (rows.length > 0) holding.add(tx);
  return rows.length > 0;
}

/**
 * Lock the log's head, waiting for it as `lockLogHead` does, if fewer than
 * `waiters` other transactions hold one of its places in line; otherwise
 * refuse at once (`HeadBusy`), having waited for nothing. A place is an
 * advisory lock, tried, never waited for, and held to the end of the
 * transaction, which holds the head by then: so at most `waiters`
 * connections wait for the head, or hold it, through here, and a burst
 * beyond them answers in one round trip rather than seconds later, holding
 * a connection all the while. One statement: the place, then, only if one
 * was free, the head; refused, one more says whether the head is there at
 * all. SQLite's transactions hold the whole file.
 */
export async function lockLogHeadQueued(tx: Transaction, waiters: number): Promise<{ nextSeq: bigint; headHash: Buffer }> {
  if (engineOf(tx) === 'sqlite') return lockLogHead(tx);
  const rows = await rowsOf<{ next_seq: string; head_hash: Buffer }>(tx, sql`
    SELECT next_seq, head_hash FROM audit_chain_head
    WHERE only_row AND (SELECT true FROM generate_series(1, ${waiters}::int) AS place WHERE pg_try_advisory_xact_lock(${HEAD_LINE}, place) LIMIT 1)
    FOR UPDATE`);
  const [head] = rows;
  if (head === undefined) {
    // No place, or no head at all: the second, which no one may write past, said as lockLogHead says it.
    const [found] = await rowsOf<{ found: boolean }>(tx, sql`SELECT EXISTS (SELECT 1 FROM audit_chain_head WHERE only_row) AS found`);
    if (found?.found !== true) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
    throw new HeadBusy();
  }
  holding.add(tx);
  return { nextSeq: BigInt(head.next_seq), headHash: head.head_hash };
}

/**
 * The first key of the head's places in line, Postgres's advisory locks:
 * the second is the place. A space apart from the members' queues and the
 * migrator's key.
 */
const HEAD_LINE = 0x636f6668;

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
  /**
   * 0.15's changes of the app's write these entries record (`appChanges`):
   * on Postgres, made in the append's own statement, one round trip less
   * under the head, which every sign-in waits for (T123). Their numbers
   * come back as `changes`.
   */
  changes: readonly PreparedChange[] = [],
): Promise<Appended & { changes: (bigint | null)[] }> {
  if (entries.length === 0) throw new Error('appendEntries called with no entries');
  const { auditChainHead, auditLog } = tablesOf(tx);

  // Every append queues here, if its transaction has not already.
  if (locked === undefined && !holding.has(tx)) await lockLogHead(tx);
  await check?.(tx);
  const held = locked ?? (await readUnderHead(tx, key));
  const { head, at: now } = held;
  const last = held.last ?? undefined;

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

  let numbers: (bigint | null)[] = [];
  if (engineOf(tx) === 'postgres' && rows.length <= ROWS_AT_ONCE && changes.length > 0) {
    // The entries, the head that names the last of them, and the changes, in one statement. The changes run in the
    // select list, in their order; the inserts after it, and their trigger (the fence, for an entry that changes
    // access) at its end: each takes the issue lock before the fence, so either order is the locks' (migration 0026).
    numbers = await callChanges(tx, changes, sql`WITH appended AS (${tx.insert(auditLog).values(rows).getSQL()}),
      moved AS (UPDATE audit_chain_head SET next_seq = ${seq}, head_hash = ${prevHash} WHERE only_row) `);
  } else if (engineOf(tx) === 'postgres' && rows.length <= ROWS_AT_ONCE) {
    // The entries and the head that names the last of them, in one statement.
    await tx.execute(sql`WITH appended AS (${tx.insert(auditLog).values(rows).getSQL()})
      UPDATE audit_chain_head SET next_seq = ${seq}, head_hash = ${prevHash} WHERE only_row`);
  } else {
    await tx.insert(auditLog).values(rows);
    await tx.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash }).where(eq(auditChainHead.onlyRow, true));
    numbers = await appChanges(tx, changes);
  }
  const written = { nextSeq: seq, headHash: prevHash };
  afterCommit(tx, () => remember(key, written));
  return { seqStart: head.nextSeq, ...written, occurredAt: now, changes: numbers };
}

/** A head locked by a statement of the caller's, and what it read under the lock (`appendEntries`). */
export type HeldHead = { head: { nextSeq: bigint; headHash: Buffer }; last: { seq: bigint; hash: Buffer } | null; at: number };

/**
 * What an append reads under the head its transaction holds, in one
 * statement: the head, the clock and the log's last entry, all as of the
 * lock, since locking a head the transaction holds waits for nothing, and
 * after the append's `check`. The log's own last row says whether the log
 * has moved on from `key`.
 */
async function readUnderHead(tx: Transaction, key: LogKey): Promise<HeldHead> {
  const [read] = await underHead(tx, { author: key.author, keyId: key.keyId });
  if (read === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
  if (read.retired) throw new KeyRetired(`the log moved on from ${key.keyId}: a key the ${key.author} rotated from writes no more`);
  return {
    head: { nextSeq: read.nextSeq, headHash: read.headHash },
    last: read.lastSeq === null || read.lastHash === null ? null : { seq: read.lastSeq, hash: read.lastHash },
    at: read.now,
  };
}

/** Entries one statement inserts at most, at 21 parameters each: Postgres takes 65,535. */
const ROWS_AT_ONCE = 3000;

/**
 * `readUnderHead`'s statement. Its `FOR UPDATE` waits for nothing in a
 * transaction that holds the head, and stays for one that would not: there
 * it waits, and if an append committed meanwhile, its head, read again
 * after the wait, disagrees with the last entry its snapshot saw before it,
 * so the append refuses (`LogHeadMismatch`) rather than writing unlocked.
 */
const underHead = prepared((db) => {
  const { auditChainHead, auditLog } = tablesOf(db);
  const moved = sql.raw(MOVES_FROM.map((action) => `'${action}'`).join(', '));
  const newest = (column: SQL) => sql`(SELECT ${column} FROM audit_log ORDER BY seq DESC LIMIT 1)`;
  return forUpdate(
    db,
    db
      .select({
        nextSeq: auditChainHead.nextSeq,
        headHash: auditChainHead.headHash,
        now: clockMillis(db),
        lastSeq: newest(sql`seq`).mapWith(auditLog.seq) as SQL<bigint | null>,
        lastHash: newest(sql`hash`).mapWith(auditLog.hash) as SQL<Buffer | null>,
        retired: sql<boolean | number>`EXISTS (SELECT 1 FROM audit_log moved WHERE moved.author = ${sql.placeholder('author')} AND moved.subject_principal = ${sql.placeholder('keyId')} AND moved.action IN (${moved}))`,
      })
      .from(auditChainHead)
      .where(eq(auditChainHead.onlyRow, true)),
  );
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

// --- 0.15's log: the app's changes -------------------------------------------

/**
 * The app's changes to the objects its rows hold, as the vault sealed them
 * (`Vault.prepare`), each `app_change` (migrations 0025, 0026 and 0030), in its
 * transaction, once its rows and 0.14 entries are written: in order, in one
 * round trip, or in the append's own (`appendEntries`). Each entry's number;
 * 0 for a row of 0.14's, which logs nothing; null where a row's seal moved
 * since the app read it, and nothing was done (ChangeCAS: read again). A row
 * that is not its object's newest change's fails the call (`isStaleChange`),
 * and its transaction with it.
 *
 * On SQLite, which has no functions, the same steps in the transaction,
 * which holds the database's one write lock: the fence is implicit there
 * (0.15's plan, "Postgres serves; SQLite is for tests").
 */
export async function appChanges(tx: Transaction, calls: readonly PreparedChange[]): Promise<(bigint | null)[]> {
  if (calls.length === 0) return [];
  if (engineOf(tx) === 'sqlite') {
    const numbers: (bigint | null)[] = [];
    for (const call of calls) numbers.push(await changeOnSqlite(tx, call, bytes));
    return numbers;
  }
  return callChanges(tx, calls, sql``);
}

const bytes = (b64: string | null) => (b64 === null ? null : Buffer.from(b64, 'base64'));

/** `app_change`, once per call, in order, in one statement: after `before`, a `WITH` of the caller's. */
async function callChanges(tx: Transaction, calls: readonly PreparedChange[], before: SQL): Promise<(bigint | null)[]> {
  const rows = sql.join(calls.map((c, i) => sql`(${i}::int, ${c.kind}::text, ${c.id}::text, ${c.requestId}::text, ${c.at}::bigint, ${c.actor}::text, ${c.payload}::text, ${bytes(c.sealFrom)}::bytea, ${bytes(c.seal)}::bytea, ${bytes(c.mac)}::bytea, ${bytes(c.restores)}::bytea)`), sql`, `);
  // A volatile function in the select list runs after the sort: each call in `ord`'s order, each from the seal the one before leaves.
  const numbers = await rowsOf<{ ord: number; number: string | number | null }>(tx, sql`${before}
    SELECT c.ord, app_change(c.kind, c.id, c.request, c.at, c.actor, c.payload, c.seal_from, c.seal, c.mac, c.restores) AS number
      FROM (VALUES ${rows}) AS c(ord, kind, id, request, at, actor, payload, seal_from, seal, mac, restores)
     ORDER BY c.ord`);
  if (numbers.some(({ ord }, i) => Number(ord) !== i)) throw new Error('app_change answered out of order');
  return numbers.map(({ number }) => (number === null ? null : BigInt(number)));
}

/** Whether `error` is `app_change`'s refusal of a row that is not its object's newest change's: Postgres's `data_corrupted`. */
export function isStaleChange(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (cause instanceof StaleRow || (cause as { code?: unknown }).code === 'XX001') return true;
  }
  return false;
}

class StaleRow extends Error {}

const APP_OPS: Record<PreparedChange['kind'], readonly string[]> = {
  credential: ['credential.issue', 'credential.revoke', 'credential.renew', 'credential.scope'],
  secret: ['secret.write', 'secret.delete'],
  environment: ['environment.create', 'environment.rename', 'environment.archive', 'project.archive', 'environment.delete'],
};

/** `app_change` on SQLite. */
async function changeOnSqlite(tx: Transaction, call: PreparedChange, bytes: (b64: string | null) => Buffer | null): Promise<bigint | null> {
  const { logChanges, logUses } = tablesOf(tx);
  const table = appTable(tx, call.kind);
  const [row] = await tx.select({ seal: table.seal }).from(table).where(eq(table.id, call.id));
  const held = row?.seal ?? null;
  const [newest] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(eq(logChanges.object, call.object)).orderBy(desc(logChanges.number)).limit(1);
  if (call.requestId === null) {
    if (held !== null || newest !== undefined) throw new StaleRow(`the ${call.kind} object's row is not its newest change's: stale`);
    return 0n;
  }
  const seal = bytes(call.seal);
  const [prior] = await tx.select({ number: logChanges.number, object: logChanges.object, payload: logChanges.payload, seal: logChanges.seal }).from(logChanges).where(eq(logChanges.requestId, call.requestId));
  if (prior !== undefined) {
    if (prior.object !== call.object || prior.payload !== call.payload || !sameBytes(prior.seal ?? null, seal)) {
      throw Object.assign(new Error(`request ${call.requestId} names another change`), { code: 'SQLITE_CONSTRAINT_UNIQUE' });
    }
    return BigInt(prior.number);
  }
  const payload = JSON.parse(call.payload ?? 'null') as { op?: unknown; ref?: { kind?: unknown; id?: unknown } } | null;
  if (typeof payload?.op !== 'string' || !(APP_OPS[call.kind] ?? []).includes(payload.op)) throw new Error(`the app makes no change ${String(payload?.op)} to a ${call.kind}`);
  if (payload.ref?.kind !== call.kind || payload.ref.id !== call.id) throw new Error(`a change names the object it is to: ${call.kind}, ${call.id}`);
  // ChangeChecksSeal.
  if (!sameBytes(held, newest?.seal ?? null)) throw new StaleRow(`the ${call.kind} object's row is not its newest change's: stale`);
  // RestorePinned: an unarchive restores the object its key's log last sealed, still so (0030).
  const restores = bytes(call.restores);
  if (restores !== null) {
    if (call.kind !== 'secret' || payload.op !== 'secret.write' || call.sealFrom !== null) throw new Error("only a key's object made again from none restores one");
    const [kept] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(and(eq(logChanges.object, call.object), isNotNull(logChanges.seal))).orderBy(desc(logChanges.number)).limit(1);
    if (!sameBytes(restores, kept?.seal ?? null)) throw new StaleRow('the secret object an unarchive restores is not its newest sealed one: stale');
  }
  // ChangeCAS.
  const from = bytes(call.sealFrom);
  const done = changedRows(await tx.update(table).set({ seal }).where(and(eq(table.id, call.id), from === null ? isNull(table.seal) : eq(table.seal, from))));
  if (done === 0) return null;
  // One sequence for both tables, as `log_number` is on Postgres.
  const [{ last }] = await tx.select({ last: sql<number | string | null>`max(n)` }).from(
    sql`(SELECT max(${logChanges.number}) AS n FROM ${logChanges} UNION ALL SELECT max(${logUses.number}) FROM ${logUses})`,
  );
  const number = BigInt(last ?? 0) + 1n;
  await tx.insert(logChanges).values({ number, at: call.at, requestId: call.requestId, object: call.object, actor: call.actor, payload: call.payload!, seal, mac: bytes(call.mac)! });
  return number;
}

/** The table whose rows hold an object of this kind, the app's. */
function appTable(tx: Transaction, kind: PreparedChange['kind']) {
  const { credentials, secrets, environments } = tablesOf(tx);
  switch (kind) {
    case 'credential': return credentials;
    case 'secret': return secrets;
    case 'environment': return environments;
    default: throw new Error(`no object kind ${String(kind)}`);
  }
}

function sameBytes(a: Buffer | null, b: Buffer | null): boolean {
  return a === null || b === null ? a === b : a.equals(b);
}

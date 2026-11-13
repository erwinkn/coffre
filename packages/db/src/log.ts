import { createHash } from 'node:crypto';
import { GENESIS_HASH, sealEntry, type LogFields, type LogKey, type StoredEntry } from '@coffre/core/audit';
import type { PreparedChange } from '@coffre/core/vault';
import { and, asc, count, desc, eq, gt, gte, lt, lte, sql, type AnyColumn, type SQL } from 'drizzle-orm';

import { authoredBy, entriesOf, keyedBy, KINDS, type Kind } from './access-entries.ts';
import { afterCommit } from './commits.ts';
import { type Queryable, type Transaction } from './database.ts';
import { later, laterRows } from './later.ts';
import { prepared } from './prepared.ts';
import { clockMillis, rowsOf } from './dialect.ts';
import { auditChainHead, auditLog } from './schema.ts';

export { accessAllowed, authoredBy, changeNamed, changesOf, entriesOf, indexOf, keyedBy, KINDS, type Kind } from './access-entries.ts';
export { recordField, recorded, RECORDS, type ChangeRecord } from './change-records.ts';

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
 * Lock the log's head, and read under it what an append of `key`'s reads
 * (`readUnderHead`), asked together: under one Sync on Hyperdrive, the
 * lock first, then the read, a statement of its own that so waits for
 * nothing and sees every append committed before the lock. What the
 * transaction asks beside them, in the same task, goes with them, after
 * (postgres-js's `gather`). Hand the result to the append (`locked`):
 * nothing to read again.
 */
export function lockLogHeadRead(tx: Transaction, key: LogKey): Promise<HeldHead> {
  // Both started now (`.then`), not awaited: made before anything the caller asks after, a work's first `later` write
  // included, so they go first in their group (postgres-js's `flush`, by `made`).
  const locking = lockedHead(tx).then(([head]) => {
    if (head === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
    holding.add(tx);
  });
  const reading = readUnderHead(tx, key);
  return Promise.all([locking, reading]).then(([, held]) => held);
}

/**
 * Lock the log's head and read nothing under it, not waited for (`later`): it goes first in the transaction's next
 * Sync, before whatever is asked after it. For a write that appends no 0.14 entry and still orders itself after every
 * writer that takes the head before its rows (`audited`, `app_change`): 0.16.0's two-trip key write, whose one Sync is
 * BEGIN, this, its hold, its rows, its changes and COMMIT (docs/design/two-trips.md, "Locks").
 */
export function laterHead(tx: Transaction): void {
  later(tx, sql`SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE`);
  holding.add(tx);
}

/**
 * Take the issue lock exclusive (migration 0026's, `1668244070, 1`): every
 * issue in flight, a sign-in or a token's, ends first, and none starts
 * until this transaction does. A write that moves what an issue's policy
 * check compares (`issue_token`: the policy, a protected environment's
 * slug) takes it, after its own rows and before the fence its append's
 * trigger takes, as the checkpointer's barrier does: so the issue is
 * ordered against it, and no use waits behind an issue (formal/Lifecycle.tla's
 * IssuePolicyHeld; T149, review r3).
 */
export async function holdIssues(tx: Transaction, { final = false }: { final?: boolean } = {}): Promise<void> {
  const statement = sql`SELECT pg_advisory_xact_lock(1668244070, 1)`;
  // `final`: nothing awaits it, it goes with what the transaction asks next, in its place (`later`), as `appendEntries`'s.
  if (final) later(tx, statement);
  else await tx.execute(statement);
}

/**
 * Lock the log's head if no one holds it, without waiting: whether it is
 * held now. For work any caller may do, of which one at a time is enough,
 * which a request that finds the head taken leaves to the one that has it.
 */
export async function lockLogHeadIfFree(tx: Transaction): Promise<boolean> {
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
 * all. `line`, whose places: each line's are its own.
 */
export async function lockLogHeadQueued(tx: Transaction, waiters: number, line: HeadLine = 'reads'): Promise<{ nextSeq: bigint; headHash: Buffer }> {
  const rows = await rowsOf<{ next_seq: string; head_hash: Buffer }>(tx, sql`
    SELECT next_seq, head_hash FROM audit_chain_head
    WHERE only_row AND (SELECT true FROM generate_series(1, ${waiters}::int) AS place WHERE pg_try_advisory_xact_lock(${HEAD_LINES[line]}, place) LIMIT 1)
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
 * The first key of each line of the head's places, Postgres's advisory
 * locks: the second is the place. The reads' (the vault's
 * `READ_HEAD_WAITERS`), and the code's proxy names' (`reserveProxy`), a
 * line of its own, so that neither takes the other's places. A space apart
 * from the members' queues and the migrator's key.
 */
const HEAD_LINES = { reads: 0x636f6668, code: 0x636f6670 } as const;

/** Which line of the head's places a wait takes one in (`lockLogHeadQueued`). */
export type HeadLine = keyof typeof HEAD_LINES;

const lockedHead = prepared((db) =>
  db.select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash }).from(auditChainHead).where(eq(auditChainHead.onlyRow, true)).for('update'),
);

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
  /**
   * Whether the writer runs under 0.15's log: its entries carry `log015`,
   * which no MAC covers and 0.14's code never sets. Once the log is cut
   * over, migration 0047's trigger refuses a write's entry without it.
   */
  log015 = false,
  /**
   * `final`: nothing in the transaction awaits the append: on Postgres it
   * goes with what the transaction asks next, its COMMIT at the latest,
   * under one Sync (`later`), and what it fails with fails the transaction.
   * Its changes then go through `app_change_strict`: a row moved since it
   * was read fails the transaction too (`isMovedChange`), never answers
   * null, and their numbers come as `later`, once the COMMIT has answered
   * (`newestCommitted`), `changes` left empty.
   */
  { final = false }: { final?: boolean } = {},
): Promise<Appended & { changes: (bigint | null)[]; later: ChangeNumbers | null }> {
  if (entries.length === 0) throw new Error('appendEntries called with no entries');

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
  const rows: (Omit<typeof auditLog.$inferInsert, 'log015'> & { log015?: SQL })[] = [];
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
    // A literal, not a parameter: a row's 21 parameters are what `ROWS_AT_ONCE` counts (review r5).
    rows.push({ ...fields, prevHash, mac, hash, ...(log015 ? { log015: sql`true` } : {}) });
    prevHash = hash;
    seq += 1n;
  }

  let numbers: (bigint | null)[] = [];
  let numbered: ChangeNumbers | null = null;
  if (rows.length <= ROWS_AT_ONCE && changes.length > 0) {
    // The entries, the head that names the last of them, and the changes, in one statement. The changes run in the
    // select list, in their order; the inserts after it, and their trigger (the fence, for an entry that changes
    // access) at its end: each takes the issue lock before the fence, so either order is the locks' (migration 0026).
    const statement = callsOf(changes, sql`WITH appended AS (${tx.insert(auditLog).values(rows).getSQL()}),
      moved AS (UPDATE audit_chain_head SET next_seq = ${seq}, head_hash = ${prevHash} WHERE only_row) `, final);
    if (final) numbered = numbersOf(laterRows(tx, statement), changes);
    else numbers = numbersIn(await rowsOf(tx, statement));
  } else if (rows.length <= ROWS_AT_ONCE) {
    // The entries and the head that names the last of them, in one statement.
    const statement = sql`WITH appended AS (${tx.insert(auditLog).values(rows).getSQL()})
      UPDATE audit_chain_head SET next_seq = ${seq}, head_hash = ${prevHash} WHERE only_row`;
    if (final) later(tx, statement);
    else await tx.execute(statement);
  } else {
    // In statements of at most as many entries as one may bind (review r3 of #538): a rotation that logs the
    // outcomes of every key service's call still open may log thousands, and one statement past the bound fails.
    for (let start = 0; start < rows.length; start += ROWS_AT_ONCE) await tx.insert(auditLog).values(rows.slice(start, start + ROWS_AT_ONCE));
    await tx.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash }).where(eq(auditChainHead.onlyRow, true));
    if (final && changes.length > 0) numbered = await laterChanges(tx, changes);
    else numbers = await appChanges(tx, changes);
  }
  const written = { nextSeq: seq, headHash: prevHash };
  afterCommit(tx, () => remember(key, written));
  return { seqStart: head.nextSeq, ...written, occurredAt: now, changes: numbers, later: numbered };
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
function readUnderHead(tx: Transaction, key: LogKey): Promise<HeldHead> {
  // Started now, as `.then` starts a statement, not once awaited: `lockLogHeadRead` puts it ahead of what its caller asks next.
  return underHead(tx, { author: key.author, keyId: key.keyId }).then(([read]) => heldOf(read, key));
}

function heldOf(read: Awaited<ReturnType<typeof underHead>>[number] | undefined, key: LogKey): HeldHead {
  if (read === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
  if (read.retired) throw new KeyRetired(`the log moved on from ${key.keyId}: a key the ${key.author} rotated from writes no more`);
  return {
    head: { nextSeq: read.nextSeq, headHash: read.headHash },
    last: read.lastSeq === null || read.lastHash === null ? null : { seq: read.lastSeq, hash: read.lastHash },
    at: read.now,
  };
}

/** Entries one statement inserts at most, at 21 parameters each (`log015` a literal): Postgres takes 65,535. */
const ROWS_AT_ONCE = 3000;

/**
 * `readUnderHead`'s statement. Its `FOR UPDATE` waits for nothing in a
 * transaction that holds the head, and stays for one that would not: there
 * it waits, and if an append committed meanwhile, its head, read again
 * after the wait, disagrees with the last entry its snapshot saw before it,
 * so the append refuses (`LogHeadMismatch`) rather than writing unlocked.
 */
const underHead = prepared((db) => {
  const moved = sql.raw(MOVES_FROM.map((action) => `'${action}'`).join(', '));
  const newest = (column: SQL) => sql`(SELECT ${column} FROM audit_log ORDER BY seq DESC LIMIT 1)`;
  return db
    .select({
      nextSeq: auditChainHead.nextSeq,
      headHash: auditChainHead.headHash,
      now: clockMillis(),
      lastSeq: newest(sql`seq`).mapWith(auditLog.seq) as SQL<bigint | null>,
      lastHash: newest(sql`hash`).mapWith(auditLog.hash) as SQL<Buffer | null>,
      retired: sql<boolean>`EXISTS (SELECT 1 FROM audit_log moved WHERE moved.author = ${sql.placeholder('author')} AND moved.subject_principal = ${sql.placeholder('keyId')} AND moved.action IN (${moved}))`,
    })
    .from(auditChainHead)
    .where(eq(auditChainHead.onlyRow, true))
    .for('update');
});

// --- reading the vault's entries back ---------------------------------------------

/** An entry's columns, as the chain's codec reads them (`StoredEntry`). */
export function entryColumns() {
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
 * Of the entries `where` matches, in order of seq, the first `limit` or
 * fewer that hold no more than `BATCH_BYTES` of metadata between them, but
 * always the first: the seqs they run from and to, each of them (`seqs`),
 * and whether the bytes cut the run short of `limit`. Null when none
 * matches. A reader asks this first, then reads `where` between the two, or
 * the entries `seqs` names.
 */
export async function withinBytes(
  db: Queryable,
  where: SQL | undefined,
  limit: number,
): Promise<{ from: bigint; to: bigint; cut: boolean; count: number; seqs: bigint[] } | null> {
  const sizes = await db
    .select({ seq: auditLog.seq, bytes: sql<number | string>`length(${auditLog.metadata})` })
    .from(auditLog)
    .where(where)
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  let held = 0;
  let count = 0;
  for (const { bytes } of sizes) {
    held += Number(bytes);
    if (count > 0 && held > BATCH_BYTES) break;
    count += 1;
  }
  if (count === 0) return null;
  return { from: sizes[0]!.seq, to: sizes[count - 1]!.seq, cut: count < sizes.length, count, seqs: sizes.slice(0, count).map(({ seq }) => seq) };
}

/**
 * How many entries one count of the log holds at most (T245, R48), so that
 * no count costs more as the log grows: a count is one pass over the
 * primary key's index, 1.2 million entries in 58 ms on the compose
 * Postgres (measured), and one entry's heap page more for each the
 * visibility map has not caught up with, which an append-only log's newest
 * fifth may be (autovacuum's insert threshold). A million keeps the worst
 * of that, a million heap fetches from a cold cache, within the runtime
 * logins' 5 s `statement_timeout`. A log of that many or fewer is counted
 * whole at each checkpoint; a longer one a million at a time, a stretch a
 * checkpoint, round the log (`COUNT_LAP` in the vault).
 */
export const COUNTED_AT_ONCE = 1_000_000n;

/**
 * The first entry missing from the log in [`from`, `seq`], and the one found
 * in its place, or null when every one is there. Seqs are the primary key, so
 * a stretch is whole exactly when its count is its length: one pass over
 * the key's index, never the entries. Only a log with a gap pays for more,
 * a count per halving to find where. A stretch longer than `COUNTED_AT_ONCE`
 * is refused: its caller counts a window of it (`countWindow`).
 *
 *   entries 0..9, 4 cut:  { expected: 4n, found: 5n }
 */
export async function missingEntry(db: Queryable, seq: bigint, from = 0n): Promise<{ expected: bigint; found: bigint | null } | null> {
  if (seq - from + 1n > COUNTED_AT_ONCE) throw new Error(`a count of entries ${from} to ${seq} is longer than ${COUNTED_AT_ONCE.toLocaleString('en')} entries`);
  const whole = async (start: bigint, to: bigint) => {
    const [{ n }] = await db.select({ n: count() }).from(auditLog).where(and(gte(auditLog.seq, start), lte(auditLog.seq, to)));
    return BigInt(n) === to - start + 1n;
  };
  if (seq < from || (await whole(from, seq))) return null;
  // The first stretch from `from` that is not whole ends at the missing entry.
  let [low, high] = [from, seq];
  while (low < high) {
    const middle = (low + high) / 2n;
    if (await whole(from, middle)) low = middle + 1n;
    else high = middle;
  }
  const [next] = await db.select({ seq: auditLog.seq }).from(auditLog).where(gt(auditLog.seq, low)).orderBy(asc(auditLog.seq)).limit(1);
  return { expected: low, found: (next?.seq as bigint | undefined) ?? null };
}

/**
 * The stretch of the prefix through `seq` a count holds, from `at`, where the
 * last one stopped (null for the first entry): the whole prefix when it is
 * `COUNTED_AT_ONCE` or fewer; else `COUNTED_AT_ONCE` from `at`, round to the
 * first entry again past the end. `next`: where the following count goes on
 * from, null when this one reached the end, which ends a lap.
 *
 *   seq 9, at null:            { from: 0n, to: 9n, next: null }
 *   seq 2,500,000, at null:    { from: 0n, to: 999,999n, next: 1,000,000n }
 *   seq 2,500,000, at 2,000,000n: { from: 2,000,000n, to: 2,500,000n, next: null }
 */
export function countWindow(seq: bigint, at: bigint | null, size = COUNTED_AT_ONCE): { from: bigint; to: bigint; next: bigint | null } {
  const from = at === null || at > seq ? 0n : at;
  const to = seq - from + 1n > size ? from + size - 1n : seq;
  return { from, to, next: to >= seq ? null : to + 1n };
}

/** Where a verification's count of the prefix through `seq` starts: its newest `size` entries, all of a log no longer. */
export function newestWindow(seq: bigint, size = COUNTED_AT_ONCE): bigint {
  return seq + 1n > size ? seq + 1n - size : 0n;
}

/**
 * How a reader tells the vault's own entries from those forged in its name:
 * by their MAC, which only the vault holds the key to check. Each it finds
 * forged goes to `forged`.
 */
export type Authenticity = { authentic: (entry: StoredEntry) => boolean; forged: (entry: StoredEntry) => void };

/** Up to `limit` of the entries of `kind` (`KINDS`), before `before` (the newest when undefined), newest first: one step of the kind's index, then a row a step. */
export async function newestVaultEntries(db: Queryable, kind: Kind, limit: number, before?: bigint): Promise<StoredEntry[]> {
  const rows = before === undefined ? await newestEntries[kind](db, { limit }) : await entriesBefore[kind](db, { limit, before });
  return rows as StoredEntry[];
}

function vaultEntries(db: Queryable, kind: Kind, before?: SQL) {
  return db
    .select(entryColumns())
    .from(auditLog)
    .where(and(entriesOf(kind), before))
    .orderBy(desc(auditLog.seq))
    .limit(sql.placeholder('limit'));
}

/** One built statement for each kind, whose condition is constants (`entriesOf`). */
function byKind<T>(build: (kind: Kind) => T): Record<Kind, T> {
  return Object.fromEntries((Object.keys(KINDS) as Kind[]).map((kind) => [kind, build(kind)])) as Record<Kind, T>;
}

const newestEntries = byKind((kind) => prepared((db) => vaultEntries(db, kind)));
const entriesBefore = byKind((kind) => prepared((db) => vaultEntries(db, kind, lt(auditLog.seq, sql.placeholder('before')))));

/**
 * The number of the newest entry of `kind`, or null for none: whether one
 * was appended since, and nothing of what it says, so its MAC is not
 * checked. One step of the kind's index (`KINDS`).
 */
export function newestVaultSeq(db: Queryable, kind: Kind): Promise<bigint | null> {
  // Started now (`.then`): `policyNow` reads it ahead of what a transaction's work asks next.
  return newestSeq[kind](db).then(([row]) => (row?.seq as bigint | undefined) ?? null);
}

const newestSeq = byKind((kind) => prepared((db) => newestSeqQuery(db, kind)));

/**
 * `newestVaultSeq`'s query, to run or to read inside another, as a
 * credential's read takes the newest policy change with it: one rule for
 * what the newest is, wherever it is read.
 */
export function newestSeqQuery(db: Queryable, kind: Kind) {
  return db
    .select({ seq: auditLog.seq })
    .from(auditLog)
    .where(entriesOf(kind))
    .orderBy(desc(auditLog.seq))
    .limit(1);
}

/**
 * The seq of `author`'s first entry under `keyId` that `also` holds, or
 * undefined: one step of its key index (`audit_log_vault_key_idx`, `audit_log_app_key_idx`; `keyedBy`; T245, R48),
 * whether the key wrote nothing, a little, or most of the log.
 */
export async function firstEntryUnder(db: Queryable, author: 'app' | 'vault', keyId: string, also?: SQL): Promise<bigint | undefined> {
  const key = keyedBy(auditLog.keyId, auditLog.seq, 'asc', sql.param([keyId]));
  const [row] = await db.select({ seq: auditLog.seq }).from(auditLog).where(and(authoredBy(author), key.where, also)).orderBy(...key.orderBy).limit(1);
  return (row?.seq as bigint | undefined) ?? undefined;
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
 */
export async function appChanges(tx: Transaction, calls: readonly PreparedChange[]): Promise<(bigint | null)[]> {
  if (calls.length === 0) return [];
  return numbersIn(await rowsOf(tx, callsOf(calls, sql``, false)));
}

/**
 * The numbers of a write's changes, made by a statement nothing in its transaction awaits (`later`): they answer once
 * Postgres has run it, with the transaction's COMMIT at the latest, so only what follows the transaction reads them.
 * Every one is a number: a row moved since it was read failed the transaction (`isMovedChange`).
 */
export type ChangeNumbers = { readonly answer: Promise<bigint[]>; /** The request ids of the calls that make an entry. */ readonly requests: readonly string[] };

/** The calls' request ids, but those that make no entry (0.14's rows: `app_change` answers 0). */
function requestsOf(calls: readonly { requestId: string | null }[]): string[] {
  return calls.flatMap(({ requestId }) => (requestId === null ? [] : [requestId]));
}

/**
 * Once the transaction that made them has committed: the newest of the changes' numbers, which a change's answer
 * waits to see sealed (R51); null when they made no entry. Their answer; or, when the client could not read it though
 * Postgres ran the COMMIT (a row it failed to parse, a notice handler that threw: the transaction is Postgres's to
 * decide, postgres-js/index.ts), their entries, read again by request id: a committed write never answers failed for
 * it, nor answers before its seal.
 */
export async function newestCommitted(db: Queryable, numbers: ChangeNumbers): Promise<bigint | null> {
  const read = await numbers.answer.catch(async (unread: unknown) => {
    // No call made an entry (0.14's rows, each answering 0): committed, there is no seal to wait for (review r2).
    if (numbers.requests.length === 0) return [];
    const requests = sql.join(numbers.requests.map((request) => sql`${request}`), sql`, `);
    const rows = await rowsOf<{ number: string | number | bigint }>(db, sql`SELECT number FROM log_changes WHERE request_id IN (${requests})`)
      .catch((reread: unknown) => { throw new Error('the changes\' numbers could not be read, nor read again by request id', { cause: new AggregateError([unread, reread]) }); });
    if (rows.length !== numbers.requests.length) throw unread;
    return rows.map(({ number }) => BigInt(number));
  });
  return read.reduce<bigint | null>((newest, number) => (number > 0n && (newest === null || number > newest) ? number : newest), null);
}

/**
 * `appChanges` for a write that goes on without their numbers: asked with `later`, so that they go with
 * what the transaction asks next, its COMMIT at the latest, under one Sync; through `app_change_strict` (migration
 * 0052), so that a row moved since it was read fails the transaction (`isMovedChange`), Postgres skipping the COMMIT,
 * where `app_change`'s null would let it keep the rows without their change.
 */
export async function laterChanges(tx: Transaction, calls: readonly PreparedChange[]): Promise<ChangeNumbers> {
  if (calls.length === 0) return { answer: Promise.resolve([]), requests: [] };
  return numbersOf(laterRows(tx, callsOf(calls, sql``, true)), calls);
}

/**
 * Numbers that must all be: a null is a row that moved, which fails the
 * transaction, as `app_change_strict` and `change_input_strict` do. The
 * vault's change path calls it too, so that the rule lives once.
 */
export function strictly(numbers: readonly (bigint | null)[], what = 'write'): bigint[] {
  if (numbers.some((number) => number === null)) throw new MovedRow(`an object this ${what} changes moved since it was read`);
  return numbers as bigint[];
}

const bytes = (b64: string | null) => (b64 === null ? null : Buffer.from(b64, 'base64'));

/** `app_change`, or `app_change_strict`, once per call, in order, in one statement: after `before`, a `WITH` of the caller's. */
function callsOf(calls: readonly PreparedChange[], before: SQL, strict: boolean): SQL {
  const rows = sql.join(calls.map((c, i) => sql`(${i}::int, ${c.kind}::text, ${c.id}::text, ${c.requestId}::text, ${c.at}::bigint, ${c.actor}::text, ${c.payload}::text, ${bytes(c.sealFrom)}::bytea, ${bytes(c.seal)}::bytea, ${bytes(c.mac)}::bytea, ${bytes(c.restores)}::bytea)`), sql`, `);
  const call = strict ? sql.raw('app_change_strict') : sql.raw('app_change');
  // A volatile function in the select list runs after the sort: each call in `ord`'s order, each from the seal the one before leaves.
  return sql`${before}
    SELECT c.ord, ${call}(c.kind, c.id, c.request, c.at, c.actor, c.payload, c.seal_from, c.seal, c.mac, c.restores) AS number
      FROM (VALUES ${rows}) AS c(ord, kind, id, request, at, actor, payload, seal_from, seal, mac, restores)
     ORDER BY c.ord`;
}

type NumberRow = { ord: number; number: string | number | null };

/** The calls' numbers, in their order: `app_change`'s, or `change_input`'s (`function`). */
export function numbersIn(rows: readonly Record<string, unknown>[], function_ = 'app_change'): (bigint | null)[] {
  const numbers = rows as unknown as NumberRow[];
  if (numbers.some(({ ord }, i) => Number(ord) !== i)) throw new Error(`${function_} answered out of order`);
  return numbers.map(({ number }) => (number === null ? null : BigInt(number)));
}

/** A strict call's numbers, as they answer. */
function numbersOf(rows: Promise<Record<string, unknown>[]>, calls: readonly PreparedChange[]): ChangeNumbers {
  const answer = rows.then((read) => strictly(numbersIn(read)));
  answer.catch(() => {});
  return { answer, requests: requestsOf(calls) };
}

/**
 * An object's key in 0.15's log, `log_changes.object`: the first 16 bytes
 * of SHA-256 over its kind and id, as a uuid (`log_object` in SQL). The
 * vault's (`objectKey`), and the app's, which finds a credential's sign-in
 * by it.
 */
export function logObject(kind: string, id: string): string {
  const hex = createHash('sha256').update(`coffre.object.v1\0${kind}\0${id}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** Whether `error` is `app_change`'s refusal of a row that is not its object's newest change's: Postgres's `data_corrupted`. */
export function isStaleChange(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if ((cause as { code?: unknown }).code === 'XX001') return true;
  }
  return false;
}

/**
 * Whether `error` is a strict change's refusal of a row whose seal moved since it was read (`app_change_strict`,
 * `change_input_strict`: SQLSTATE CF001), which its writer reads again: what `app_change` and `change_input` answer null for.
 */
export function isMovedChange(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (cause instanceof MovedRow || (cause as { code?: unknown }).code === MOVED) return true;
  }
  return false;
}

/** The SQLSTATE the strict changes raise for a moved row (migration 0052). */
export const MOVED = 'CF001';

/** A moved row, where no function raised it: a call that answered null. */
export class MovedRow extends Error {
  readonly code = MOVED;
}

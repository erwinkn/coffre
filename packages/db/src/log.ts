import { GENESIS_HASH, sealEntry, type LogFields, type LogKey } from '@coffre/core/audit';
import { desc, eq } from 'drizzle-orm';

import { tablesOf, type Transaction } from './database.ts';
import { clockMillis, forUpdate } from './dialect.ts';

/**
 * Appending to the audit log, the one table both the app and the vault
 * write, each under its own key (@coffre/core/audit says what an entry's MAC
 * and hash cover).
 *
 * Every append locks the log's head first, `audit_chain_head`, so entries
 * from any process take their numbers in one order. It then reads the
 * database clock, after the lock, and the log's last entry, which the head
 * must name: a head that does not was moved, or entries were deleted behind
 * it, and the append refuses.
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
 * The log's head is behind one this process found before: the database was
 * rolled back, or entries were cut off its end. That cannot be told from a
 * restore, so the append refuses and someone has to look.
 */
export class LogRewound extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogRewound';
  }
}

/**
 * The newest head each writer found, under each of its keys, while the
 * process lives. It is the head found under the lock, so already committed:
 * a transaction of ours that rolls back never puts it ahead of the database.
 */
const found = new WeakMap<LogKey, { epoch: number; nextSeq: bigint; headHash: Buffer }>();
let epoch = 0;

/**
 * Forget every head found so far. For tests that empty the database
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
  const { auditChainHead } = tablesOf(tx);
  const [head] = await forUpdate(
    tx,
    tx
      .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash })
      .from(auditChainHead)
      .where(eq(auditChainHead.onlyRow, true)),
  );
  if (head === undefined) throw new Error('audit_chain_head is missing; refusing to write an unchained entry');
  return head;
}

export async function appendEntries(tx: Transaction, key: LogKey, entries: readonly NewEntry[]): Promise<Appended> {
  if (entries.length === 0) throw new Error('appendEntries called with no entries');
  const { auditChainHead, auditLog } = tablesOf(tx);

  // Every append queues here, if its transaction has not already.
  const head = await lockLogHead(tx);
  const [{ now }] = await tx.select({ now: clockMillis(tx) }).from(auditChainHead);
  const [last] = await tx
    .select({ seq: auditLog.seq, hash: auditLog.hash })
    .from(auditLog)
    .orderBy(desc(auditLog.seq))
    .limit(1);

  const expected = last === undefined ? { nextSeq: 0n, headHash: GENESIS_HASH } : { nextSeq: last.seq + 1n, headHash: last.hash };
  if (head.nextSeq !== expected.nextSeq || !head.headHash.equals(expected.headHash)) {
    throw new LogHeadMismatch(
      `the log's head says entry ${head.nextSeq} comes next, but the log ends ${last === undefined ? 'empty' : `at entry ${last.seq}`}, or with another hash`,
    );
  }
  const before = found.get(key);
  if (
    before !== undefined &&
    before.epoch === epoch &&
    (head.nextSeq < before.nextSeq || (head.nextSeq === before.nextSeq && !head.headHash.equals(before.headHash)))
  ) {
    throw new LogRewound(`the log ends before entry ${before.nextSeq}, which this process found it holding: it was rolled back`);
  }
  found.set(key, { epoch, nextSeq: head.nextSeq, headHash: head.headHash });

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

  await tx.insert(auditLog).values(rows);
  await tx.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash }).where(eq(auditChainHead.onlyRow, true));
  return { seqStart: head.nextSeq, nextSeq: seq, headHash: prevHash, occurredAt: now };
}

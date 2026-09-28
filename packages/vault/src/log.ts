import { createHash } from 'node:crypto';

import { asc, desc, lt } from 'drizzle-orm';

import * as schema from './schema.ts';
import type { Store } from './store.ts';
import type { LogEntry, LogPage } from './types.ts';

/** Part of the format: a change to what is hashed changes this too. */
const LOG_VERSION = 'coffre.vault.log.v1';

/** The `prev_hash` of the first entry. */
export const GENESIS = '0'.repeat(64);

/** One entry to append; the log numbers, times and chains it. */
export type Appended = {
  actor: string;
  action: string;
  outcome: 'allow' | 'refuse';
  code?: string | null;
  subject?: string | null;
  detail?: Record<string, unknown>;
};

type Row = typeof schema.log.$inferSelect;

/**
 * SHA-256 over the previous hash and the row, as a JSON array: unambiguous,
 * since JSON quotes and escapes every string, and the same bytes in any
 * runtime. Unkeyed: anyone can recompute it, and what stops a rewrite being
 * re-chained is that only the vault can write here at all.
 */
export function entryHash(prevHash: string, row: Omit<Row, 'prevHash' | 'hash'>): string {
  const canonical = JSON.stringify([
    LOG_VERSION,
    row.seq,
    row.at,
    row.actor,
    row.action,
    row.outcome,
    row.code,
    row.subject,
    row.detail,
  ]);
  return createHash('sha256').update(prevHash).update(canonical).digest('hex');
}

/** Append entries in order. Call inside the transaction that made the decision. */
export function append(db: Store, at: number, entries: readonly Appended[]): void {
  const head = db.select({ seq: schema.log.seq, hash: schema.log.hash }).from(schema.log).orderBy(desc(schema.log.seq)).limit(1).get();
  let seq = head?.seq ?? 0;
  let prevHash = head?.hash ?? GENESIS;
  for (const entry of entries) {
    seq += 1;
    const row = {
      seq,
      at,
      actor: entry.actor,
      action: entry.action,
      outcome: entry.outcome,
      code: entry.code ?? null,
      subject: entry.subject ?? null,
      detail: JSON.stringify(entry.detail ?? {}),
    };
    const hash = entryHash(prevHash, row);
    db.insert(schema.log).values({ ...row, prevHash, hash }).run();
    prevHash = hash;
  }
}

/** Recompute the whole chain from the first entry. */
export function verify(db: Store): LogPage['verification'] {
  let prevHash = GENESIS;
  let expected = 1;
  const rows = db.select().from(schema.log).orderBy(asc(schema.log.seq)).all();
  for (const row of rows) {
    if (row.seq !== expected) return { ok: false, failedAtSeq: row.seq, reason: `expected entry ${expected}` };
    if (row.prevHash !== prevHash) return { ok: false, failedAtSeq: row.seq, reason: 'prev_hash does not match the entry before' };
    if (entryHash(prevHash, row) !== row.hash) return { ok: false, failedAtSeq: row.seq, reason: 'hash does not match the entry' };
    prevHash = row.hash;
    expected += 1;
  }
  return { ok: true, entries: rows.length };
}

/** A page of entries, newest first. */
export function page(db: Store, before: number | undefined, limit: number): LogEntry[] {
  return db
    .select()
    .from(schema.log)
    .where(before === undefined ? undefined : lt(schema.log.seq, before))
    .orderBy(desc(schema.log.seq))
    .limit(limit)
    .all()
    .map((row) => ({
      seq: row.seq,
      at: new Date(row.at).toISOString(),
      actor: row.actor,
      action: row.action,
      outcome: row.outcome,
      code: row.code,
      subject: row.subject,
      detail: JSON.parse(row.detail) as Record<string, unknown>,
      hash: row.hash,
    }));
}

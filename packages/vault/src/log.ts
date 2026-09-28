import { createHash } from 'node:crypto';

import type { LogRow, Store } from './store.ts';
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

/**
 * SHA-256 over the previous hash and the row, as a JSON array: unambiguous,
 * since JSON quotes and escapes every string, and the same bytes in any
 * runtime. Unkeyed: anyone can recompute it, and what stops a rewrite being
 * re-chained is that only the vault can write here at all.
 */
export function entryHash(prevHash: string, row: Omit<LogRow, 'prevHash' | 'hash'>): string {
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
export function append(store: Store, at: number, entries: readonly Appended[]): void {
  const head = store.logHead();
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
    store.appendLog({ ...row, prevHash, hash });
    prevHash = hash;
  }
}

/** Recompute the whole chain from the first entry, one row in memory at a time. */
export function verify(store: Store): LogPage['verification'] {
  let previous = { seq: 0, hash: GENESIS };
  for (const row of store.logAfter(0)) {
    const broken = (reason: string) => ({ ok: false as const, failedAtSeq: row.seq, reason });
    if (row.seq !== previous.seq + 1) return broken(`expected entry ${previous.seq + 1}`);
    if (row.prevHash !== previous.hash) return broken('prev_hash does not match the entry before');
    if (entryHash(row.prevHash, row) !== row.hash) return broken('hash does not match the entry');
    previous = { seq: row.seq, hash: row.hash };
  }
  return { ok: true, entries: previous.seq };
}

/** A row as the log's readers see it. */
export function entry(row: LogRow): LogEntry {
  return {
    seq: row.seq,
    at: new Date(row.at).toISOString(),
    actor: row.actor,
    action: row.action,
    outcome: row.outcome,
    code: row.code,
    subject: row.subject,
    detail: JSON.parse(row.detail) as Record<string, unknown>,
    hash: row.hash,
  };
}

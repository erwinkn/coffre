import { createHash } from 'node:crypto';

import type { LogEntry, LogPage } from '@coffre/core/vault';

import type { LogRow, Store } from './store.ts';

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

/** An entry, and so the chain up to it, as this process last verified it. */
export type Anchor = { seq: number; hash: string };

/** Before the first entry: nothing verified yet. */
export const UNVERIFIED: Anchor = { seq: 0, hash: GENESIS };

type Verification = LogPage['verification'];

/**
 * Check the chain, one row in memory at a time, and return where it is now
 * verified to. Three parts:
 *
 * - `shown`, the page a reader is looking at: each row against its own hash,
 *   and linked to its neighbours and to the entry after it;
 * - `anchor`, the head at the last check: still there, unchanged. A rewrite
 *   of anything before it, re-chained to hide, changes every hash after it,
 *   the anchor's too;
 * - every entry after the anchor, or after the first when `full`.
 *
 * So a view rehashes only what is new since the last one. What it leaves
 * out is an entry before the anchor edited in place, not re-chained, and
 * not on the page: `full` finds that, as does the first view after a start,
 * which has no anchor.
 */
export function verify(
  store: Store,
  shown: readonly LogRow[],
  anchor: Anchor,
  full: boolean,
): { verification: Verification; anchor: Anchor } {
  const broken = (failedAtSeq: number, reason: string) => ({
    verification: { ok: false as const, failedAtSeq, reason },
    anchor,
  });

  const page = [...shown].sort((a, b) => a.seq - b.seq);
  for (const [i, row] of page.entries()) {
    const fault = unlinked(i === 0 ? { seq: row.seq - 1, hash: row.prevHash } : page[i - 1], row);
    if (fault !== null) return broken(row.seq, fault);
  }
  const last = page.at(-1);
  const after = last && store.logEntry(last.seq + 1);
  if (after && after.prevHash !== last.hash) return broken(after.seq, 'prev_hash does not match the entry before');

  if (anchor.seq > 0 && store.logEntry(anchor.seq)?.hash !== anchor.hash) {
    return broken(anchor.seq, 'changed since the vault last verified it');
  }

  let previous = full ? UNVERIFIED : anchor;
  for (const row of store.logAfter(previous.seq)) {
    const fault = unlinked(previous, row);
    if (fault !== null) return broken(row.seq, fault);
    previous = { seq: row.seq, hash: row.hash };
  }
  return { verification: { ok: true, entries: previous.seq }, anchor: previous };
}

/** Why `row` does not follow `previous` in the chain, or null when it does. */
function unlinked(previous: Anchor, row: LogRow): string | null {
  if (row.seq !== previous.seq + 1) return `expected entry ${previous.seq + 1}`;
  if (row.prevHash !== previous.hash) return 'prev_hash does not match the entry before';
  if (entryHash(row.prevHash, row) !== row.hash) return 'hash does not match the entry';
  return null;
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

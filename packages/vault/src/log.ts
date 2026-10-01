import { deriveLogKey, GENESIS_HASH, verifyEntries, type LogKey, type StoredEntry } from '@coffre/core/audit';
import type { LogEntry, LogHead, LogVerification } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';

import { entriesFrom, hashAt } from './store.ts';

/**
 * The vault's half of the one audit log: its entries are the ones it
 * writes, `author = 'vault'`, each under its MAC, in the chain the app's
 * entries share (@coffre/core/audit says what an entry covers). The app
 * checks its own entries by its key; this checks the vault's by the vault's,
 * and the app's only for their place in the chain.
 */

/**
 * The vault's log key, derived from its signing key, so that it is one more
 * secret to hold, not one more to keep. Whoever can write the database but
 * does not hold the vault's configuration cannot write an entry it accepts.
 */
export function vaultLogKey(signingKey: Uint8Array): LogKey {
  return deriveLogKey('vault', signingKey);
}

/**
 * How far this process has verified the chain: every entry before
 * `nextSeq`, the last of which has `hash`, with `vaultEntries` of the
 * vault's among them. In memory only: the database cannot vouch for itself.
 */
export type Anchor = { nextSeq: bigint; hash: Buffer; vaultEntries: number };

/** Before the first entry: nothing verified yet. */
export const UNVERIFIED: Anchor = { nextSeq: 0n, hash: GENESIS_HASH, vaultEntries: 0 };

/** The further of two anchors, when two calls verified at once. */
export function further(a: Anchor, b: Anchor): Anchor {
  return b.nextSeq > a.nextSeq ? b : a;
}

export const VERIFY_BATCH = 1000;

type Verified = { verification: LogVerification; anchor: Anchor };

/**
 * Check the chain, a batch in memory at a time, and return where it is now
 * verified to. Three parts:
 *
 * - `shown`, the page a reader is looking at: each entry against its own
 *   hash and MAC;
 * - `anchor`, the head at the last check: still there, unchanged. A rewrite
 *   of anything before it, chained again to hide, changes its hash;
 * - every entry after the anchor, or from the first.
 *
 * So a view rehashes only what is new since the last one. What it leaves
 * out is an entry before the anchor edited in place, not chained again, and
 * not on the page: a full check, which starts from `UNVERIFIED`, finds that,
 * as does the first view after a start, which has no anchor.
 */
export async function verifyChain(
  db: Queryable,
  key: LogKey,
  shown: readonly StoredEntry[],
  anchor: Anchor,
): Promise<Verified> {
  const broken = (failedAtSeq: bigint, reason: string): Verified => ({
    verification: { ok: false, failedAtSeq: Number(failedAtSeq), reason },
    anchor,
  });
  const keys = { keys: [key], chainOnly: ['app' as const] };

  for (const row of [...shown].sort((a, b) => (a.seq < b.seq ? -1 : 1))) {
    const result = verifyEntries([row], { ...keys, startSeq: row.seq, startPrevHash: row.prevHash });
    if (!result.ok) return broken(result.failedAtSeq, result.reason);
  }

  if (anchor.nextSeq > 0n && !(await hashAt(db, anchor.nextSeq - 1n))?.equals(anchor.hash)) {
    return broken(anchor.nextSeq - 1n, 'changed since the vault last verified it');
  }

  let verified = anchor;
  for (;;) {
    const batch = await entriesFrom(db, verified.nextSeq, VERIFY_BATCH);
    if (batch.length === 0) break;
    const result = verifyEntries(batch, { ...keys, startSeq: verified.nextSeq, startPrevHash: verified.hash });
    if (!result.ok) return broken(result.failedAtSeq, result.reason);
    verified = { nextSeq: result.nextSeq, hash: result.head, vaultEntries: verified.vaultEntries + result.authenticated };
    if (batch.length < VERIFY_BATCH) break;
  }
  return { verification: { ok: true, entries: verified.vaultEntries }, anchor: verified };
}

/**
 * Whether the log still holds `head` where it was: not rewritten, nor cut
 * back before it. A head of 64 zeros is before the first entry, which any
 * log holds.
 */
export async function carries(db: Queryable, head: LogHead): Promise<boolean> {
  if (head.hash === GENESIS_HASH.toString('hex')) return true;
  return (await hashAt(db, BigInt(head.seq)))?.toString('hex') === head.hash;
}

/** An entry's head, as checkpoints and the app record it. */
export function headOf(row: StoredEntry | undefined): LogHead {
  return row === undefined ? { seq: 0, hash: GENESIS_HASH.toString('hex') } : { seq: Number(row.seq), hash: row.hash.toString('hex') };
}

/**
 * An entry as the vault log's readers see it. `subject` is the member an
 * access change is about, or what else the entry names: a secret's path,
 * the audit log, the vault's own.
 */
export function entryView(row: StoredEntry): LogEntry {
  const { subject, ...detail } = JSON.parse(row.metadata) as Record<string, unknown>;
  const ids = {
    projectId: row.projectId,
    environmentId: row.environmentId,
    secretId: row.secretId,
    requestId: row.requestId,
    operationId: row.operationId,
    relatedSeq: row.relatedSeq === null ? null : row.relatedSeq.toString(),
  };
  return {
    seq: Number(row.seq),
    at: new Date(row.occurredAt).toISOString(),
    actor: row.actor,
    action: row.action,
    outcome: row.decision === 'allow' ? 'allow' : 'refuse',
    code: row.code,
    subject: row.subjectPrincipal ?? (typeof subject === 'string' ? subject : null),
    detail: { ...Object.fromEntries(Object.entries(ids).filter(([, value]) => value !== null)), ...detail },
    hash: row.hash.toString('hex'),
  };
}

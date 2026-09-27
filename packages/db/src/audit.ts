import { asc, eq, gte } from 'drizzle-orm';

import { chainHash, type ChainedAuditRow } from '../../core/src/audit/chain.ts';
import type { Queryable, Transaction } from './database.ts';
import { lockAuditHead } from './dialect.ts';
import { auditChainHead, auditLog } from './schema.ts';

export type AuditEntry = {
  actorType: 'user' | 'service' | 'system';
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  projectId?: string | null;
  environmentId?: string | null;
  secretId?: string | null;
  bundleId?: string | null;
  requestId?: string | null;
  sourceIp?: string | null;
  metadata?: Record<string, unknown>;
};

const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/;

/**
 * The one rendering of occurred_at: UTC, microseconds, `Z`.
 *
 * The hash chain covers the timestamp as text, so reading a row back has to
 * reproduce it byte for byte. Databases hand timestamps back in their own
 * shapes (`2026-09-27 12:34:56.1+02` from Postgres), and a Date would drop
 * the microseconds, so every value goes through here on the way in and out:
 *
 *   2026-09-27 12:34:56.1+02  ->  2026-09-27T10:34:56.100000Z
 */
export function canonicalTimestamp(raw: string): string {
  const match = TIMESTAMP.exec(raw);
  if (match === null) throw new Error(`unexpected timestamp from the database: ${raw}`);
  const [, year, month, day, hour, minute, second, fraction = '', zone] = match;
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone.startsWith('-') ? -1 : 1;
    const digits = zone.slice(1).replace(':', '');
    offsetMinutes = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2) || '0'));
  }
  const utc = new Date(
    Date.UTC(+year, +month - 1, +day, +hour, +minute, +second) - offsetMinutes * 60_000,
  );
  return `${utc.toISOString().slice(0, 19)}.${fraction.padEnd(6, '0')}Z`;
}

/**
 * Append entries to the audit log, inside the caller's transaction.
 *
 * This is deliberately NOT a queue, NOT a background write, and NOT
 * best-effort. Infisical's audit queue returned early and dropped every entry
 * silently; that failure mode is the reason this project exists. If the append
 * throws, the caller's transaction rolls back and the read that would have
 * been unlogged does not happen either.
 *
 * Appends are serialised by locking the single audit_chain_head row. A hash
 * chain is meaningless under concurrent unordered appends, and at
 * secrets-manager volumes the resulting throughput ceiling does not matter.
 */
export async function appendAudit(
  tx: Transaction,
  chainKey: Buffer,
  entries: readonly AuditEntry[],
): Promise<{ seqStart: bigint; nextSeq: bigint; headHash: Buffer }> {
  if (entries.length === 0) {
    throw new Error('appendAudit called with no entries');
  }

  // Serialise. Every other appender blocks here until we commit or roll back.
  const head = await lockAuditHead(tx);
  if (head === null) {
    throw new Error('audit_chain_head is missing; refusing to write an unchained audit row');
  }

  // One timestamp for the whole append.
  const occurredAt = canonicalTimestamp(head.now);

  let seq = head.nextSeq;
  const seqStart = seq;
  let prevHash = head.headHash;

  for (const entry of entries) {
    const row: ChainedAuditRow = {
      seq,
      occurredAt,
      actorType: entry.actorType,
      actorId: entry.actorId,
      action: entry.action,
      decision: entry.decision,
      projectId: entry.projectId ?? null,
      environmentId: entry.environmentId ?? null,
      secretId: entry.secretId ?? null,
      bundleId: entry.bundleId ?? null,
      requestId: entry.requestId ?? null,
      sourceIp: entry.sourceIp ?? null,
      metadata: JSON.stringify(entry.metadata ?? {}),
    };

    const hash = chainHash(chainKey, prevHash, row);
    await tx.insert(auditLog).values({ ...row, prevHash, hash });

    prevHash = hash;
    seq += 1n;
  }

  await tx
    .update(auditChainHead)
    .set({ nextSeq: seq, headHash: prevHash, updatedAt: new Date(occurredAt) })
    .where(eq(auditChainHead.onlyRow, true));

  return { seqStart, nextSeq: seq, headHash: prevHash };
}

/** Read rows back in chain order, rendering fields exactly as they were hashed. */
export async function readAuditRows(
  db: Queryable,
  fromSeq = 0n,
  limit = 1000,
): Promise<(ChainedAuditRow & { prevHash: Buffer; hash: Buffer })[]> {
  const rows = await db
    .select({
      seq: auditLog.seq,
      occurredAt: auditLog.occurredAt,
      actorType: auditLog.actorType,
      actorId: auditLog.actorId,
      action: auditLog.action,
      decision: auditLog.decision,
      projectId: auditLog.projectId,
      environmentId: auditLog.environmentId,
      secretId: auditLog.secretId,
      bundleId: auditLog.bundleId,
      requestId: auditLog.requestId,
      sourceIp: auditLog.sourceIp,
      metadata: auditLog.metadata,
      prevHash: auditLog.prevHash,
      hash: auditLog.hash,
    })
    .from(auditLog)
    .where(gte(auditLog.seq, fromSeq))
    .orderBy(asc(auditLog.seq))
    .limit(limit);

  return rows.map((row) => ({ ...row, occurredAt: canonicalTimestamp(row.occurredAt) }));
}

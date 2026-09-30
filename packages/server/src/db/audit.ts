import { chainHash, type ChainedAuditRow } from '@coffre/core/audit';

import type { Transaction } from './database.ts';
import { auditHead, insert, update } from './queries.ts';
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
): Promise<{ seqStart: bigint; nextSeq: bigint; headHash: Buffer; occurredAt: string }> {
  if (entries.length === 0) {
    throw new Error('appendAudit called with no entries');
  }

  // Serialise. Every other appender blocks here until we commit or roll back.
  const head = await auditHead(tx, { lock: true });
  if (head === null) {
    throw new Error('audit_chain_head is missing; refusing to write an unchained audit row');
  }

  // One timestamp for the whole append.
  const occurredAt = head.now;

  let seq = head.nextSeq;
  const seqStart = seq;
  let prevHash = head.headHash;
  const rows: (typeof auditLog.$inferInsert)[] = [];

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
    rows.push({ ...row, id: crypto.randomUUID(), prevHash, hash });

    prevHash = hash;
    seq += 1n;
  }

  await insert(tx, auditLog, rows);
  await update(tx, auditChainHead, { onlyRow: true }, {
    nextSeq: seq,
    headHash: prevHash,
    updatedAt: new Date(occurredAt),
  });

  return { seqStart, nextSeq: seq, headHash: prevHash, occurredAt };
}

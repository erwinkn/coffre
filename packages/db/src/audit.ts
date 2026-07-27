import type { PoolClient } from 'pg';
import { chainHash, type ChainedAuditRow } from '../../core/src/audit/chain.ts';

/**
 * Canonical rendering of occurred_at.
 *
 * The hash chain covers the timestamp as a string, so reading a row back has
 * to reproduce byte-identical text. Letting the driver turn timestamptz into a
 * Date and back would not survive that. Every read path must use this same
 * expression.
 */
export const OCCURRED_AT_SQL =
  `to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

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
  tx: PoolClient,
  chainKey: Buffer,
  entries: readonly AuditEntry[],
): Promise<{ seqStart: bigint; headHash: Buffer }> {
  if (entries.length === 0) {
    throw new Error('appendAudit called with no entries');
  }

  // Serialise. Every other appender blocks here until we commit or roll back.
  const head = await tx.query<{ next_seq: string; head_hash: Buffer }>(
    'SELECT next_seq, head_hash FROM audit_chain_head WHERE only_row LIMIT 1 FOR UPDATE',
  );
  if (head.rowCount !== 1) {
    throw new Error('audit_chain_head is missing; refusing to write an unchained audit row');
  }

  // One timestamp for the whole append, taken from the database clock rather
  // than from an application server. CDR 2024/1774 Art 12(2)(f).
  const clock = await tx.query<{ ts: string }>(
    `SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts`,
  );
  const occurredAt = clock.rows[0].ts;

  let seq = BigInt(head.rows[0].next_seq);
  const seqStart = seq;
  let prevHash = head.rows[0].head_hash;

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

    await tx.query(
      `INSERT INTO audit_log (
           seq, occurred_at, actor_type, actor_id, action, decision,
           project_id, environment_id, secret_id, bundle_id,
           request_id, source_ip, metadata, prev_hash, hash
       ) VALUES ($1, $2::timestamptz, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        row.seq.toString(),
        occurredAt,
        row.actorType,
        row.actorId,
        row.action,
        row.decision,
        row.projectId,
        row.environmentId,
        row.secretId,
        row.bundleId,
        row.requestId,
        row.sourceIp,
        row.metadata,
        prevHash,
        hash,
      ],
    );

    prevHash = hash;
    seq += 1n;
  }

  await tx.query(
    'UPDATE audit_chain_head SET next_seq = $1, head_hash = $2, updated_at = now() WHERE only_row',
    [seq.toString(), prevHash],
  );

  return { seqStart, headHash: prevHash };
}

/** Read rows back in chain order, rendering fields exactly as they were hashed. */
export async function readAuditRows(
  tx: PoolClient,
  fromSeq = 0n,
  limit = 1000,
): Promise<(ChainedAuditRow & { prevHash: Buffer; hash: Buffer })[]> {
  const result = await tx.query(
    `SELECT seq,
            ${OCCURRED_AT_SQL} AS occurred_at,
            actor_type, actor_id, action, decision,
            project_id, environment_id, secret_id, bundle_id,
            request_id, source_ip, metadata, prev_hash, hash
       FROM audit_log
      WHERE seq >= $1
      ORDER BY seq ASC
      LIMIT $2`,
    [fromSeq.toString(), limit],
  );

  return result.rows.map((r) => ({
    seq: BigInt(r.seq),
    occurredAt: r.occurred_at,
    actorType: r.actor_type,
    actorId: r.actor_id,
    action: r.action,
    decision: r.decision,
    projectId: r.project_id,
    environmentId: r.environment_id,
    secretId: r.secret_id,
    bundleId: r.bundle_id,
    requestId: r.request_id,
    sourceIp: r.source_ip,
    metadata: r.metadata,
    prevHash: r.prev_hash,
    hash: r.hash,
  }));
}

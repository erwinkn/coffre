import { count, eq, sql } from 'drizzle-orm';

import { appendAudit, canonicalTimestamp } from '../../../../packages/db/src/audit.ts';
import type { Database } from '../../../../packages/db/src/database.ts';
import { migrations } from '../../../../packages/db/src/dialect.ts';
import { auditHeartbeat } from '../../../../packages/db/src/schema.ts';
import { REQUIRED_MIGRATION_COUNT } from '../../../../packages/db/src/schema-version.ts';

export type HeartbeatLogger = {
  warn: (obj: unknown, msg: string) => void;
};

/**
 * Logging-failure detection.
 *
 * CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to detect a failure of
 * logging systems". This is not box-ticking: Infisical's audit queue returned
 * early and dropped every entry, silently, and nobody noticed until someone
 * went looking for logs that were never there.
 *
 * The scheduled Worker writes a row and records the current chain head. A
 * monitor alerts when `last_beat_at` goes stale, which turns "the audit log
 * stopped receiving writes" into a paging event rather than an audit finding.
 * `/readyz` surfaces it too.
 */
export async function writeAuditHeartbeat(
  db: Database,
  chainKey: Buffer,
  log: HeartbeatLogger,
): Promise<boolean> {
  try {
    return await db.transaction(async (tx) => {
      const [row] = await tx.select({ onlyRow: auditHeartbeat.onlyRow }).from(auditHeartbeat);
      if (row === undefined) {
        log.warn({}, 'audit heartbeat singleton is missing');
        return false;
      }
      const { nextSeq } = await appendAudit(tx, chainKey, [
        {
          actorType: 'system',
          actorId: 'coffre-scheduler',
          action: 'audit.heartbeat',
          decision: 'allow',
          metadata: { source: 'scheduled' },
        },
      ]);
      await tx
        .update(auditHeartbeat)
        .set({ lastBeatAt: sql`CURRENT_TIMESTAMP`, lastSeq: nextSeq })
        .where(eq(auditHeartbeat.onlyRow, true));
      return true;
    });
  } catch (error) {
    // A heartbeat that cannot write is itself the signal.
    log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
    return false;
  }
}

/**
 * How stale the heartbeat is, in seconds. Used by /readyz. Both ends are the
 * database's clock, so a skewed application server cannot hide a stale beat.
 */
export async function heartbeatAgeSeconds(db: Database): Promise<number | null> {
  const [row] = await db
    .select({ lastBeatAt: auditHeartbeat.lastBeatAt, now: sql<string>`CURRENT_TIMESTAMP` })
    .from(auditHeartbeat);
  if (row === undefined) return null;
  return (Date.parse(canonicalTimestamp(row.now)) - row.lastBeatAt.getTime()) / 1000;
}

/**
 * How old the last heartbeat may be before readiness fails. Cron beats every
 * five minutes, so this allows one late or skipped run, plus a minute of
 * scheduling slack, before a monitor sees a failure.
 */
export const HEARTBEAT_STALE_AFTER_SECONDS = 11 * 60;

export type Readiness =
  | { ok: true; auditHeartbeatAgeSeconds: number }
  | { ok: false; auditHeartbeatAgeSeconds: number | null };

/**
 * Readiness includes database access and a recent successful audit heartbeat.
 * Liveness deliberately does not call this: a database incident should mark
 * the service unavailable, not trigger a runtime restart loop.
 */
export async function auditReadiness(
  db: Database,
): Promise<Readiness> {
  try {
    const [applied] = await db.select({ n: count() }).from(migrations);
    if (applied === undefined || applied.n < REQUIRED_MIGRATION_COUNT) {
      return { ok: false, auditHeartbeatAgeSeconds: null };
    }
    const age = await heartbeatAgeSeconds(db);
    if (age === null || !Number.isFinite(age) || age > HEARTBEAT_STALE_AFTER_SECONDS) {
      return { ok: false, auditHeartbeatAgeSeconds: age };
    }
    return { ok: true, auditHeartbeatAgeSeconds: age };
  } catch {
    return { ok: false, auditHeartbeatAgeSeconds: null };
  }
}

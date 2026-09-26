import { REQUIRED_MIGRATION_COUNT } from '../../../../packages/db/src/schema-version.ts';
import { appendAudit } from '../../../../packages/db/src/audit.ts';
import type { Database, DatabaseClient } from './database.ts';

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
  pool: Database,
  chainKey: Buffer,
  log: HeartbeatLogger,
): Promise<boolean> {
  let client: DatabaseClient | undefined;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    await appendAudit(client, chainKey, [
      {
        actorType: 'system',
        actorId: 'coffre-scheduler',
        action: 'audit.heartbeat',
        decision: 'allow',
        metadata: { source: 'scheduled' },
      },
    ]);
    const result = await client.query(
      `UPDATE audit_heartbeat
          SET last_beat_at = now(),
              last_seq = (SELECT next_seq FROM audit_chain_head WHERE only_row)
        WHERE only_row`,
    );
    if (result.rowCount !== 1) {
      log.warn(
        { rowCount: result.rowCount },
        'audit heartbeat singleton is missing',
      );
      await client.query('ROLLBACK');
      return false;
    }
    await client.query('COMMIT');
    return true;
  } catch (error) {
    await client?.query('ROLLBACK').catch(() => {});
    // A heartbeat that cannot write is itself the signal.
    log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
    return false;
  } finally {
    await client?.release();
  }
}

/** How stale the heartbeat is, in seconds. Used by /readyz. */
export async function heartbeatAgeSeconds(pool: Database): Promise<number | null> {
  const result = await pool.query<{ age: string }>(
    `SELECT EXTRACT(EPOCH FROM (now() - last_beat_at)) AS age
       FROM audit_heartbeat WHERE only_row`,
  );
  return result.rowCount === 1 ? Number(result.rows[0].age) : null;
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
  pool: Database,
): Promise<Readiness> {
  try {
    const schema = await pool.query<{ ready: boolean }>(
      `SELECT
         to_regclass('public.projects') IS NOT NULL
         AND to_regclass('public.audit_log') IS NOT NULL
         AND to_regclass('drizzle.__drizzle_migrations') IS NOT NULL
         AND (
           SELECT count(*) >= $1
             FROM drizzle.__drizzle_migrations
         ) AS ready`,
      [REQUIRED_MIGRATION_COUNT],
    );
    if (schema.rows[0]?.ready !== true) {
      return { ok: false, auditHeartbeatAgeSeconds: null };
    }
    const age = await heartbeatAgeSeconds(pool);
    if (age === null || !Number.isFinite(age) || age > HEARTBEAT_STALE_AFTER_SECONDS) {
      return { ok: false, auditHeartbeatAgeSeconds: age };
    }
    return { ok: true, auditHeartbeatAgeSeconds: age };
  } catch {
    return { ok: false, auditHeartbeatAgeSeconds: null };
  }
}

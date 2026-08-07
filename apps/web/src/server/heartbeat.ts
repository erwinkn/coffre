import type { Pool } from 'pg';
import { REQUIRED_MIGRATION_COUNT } from '../../../../packages/db/src/schema-version.ts';

/**
 * Logging-failure detection.
 *
 * CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to detect a failure of
 * logging systems". This is not box-ticking: Infisical's audit queue returned
 * early and dropped every entry, silently, and nobody noticed until someone
 * went looking for logs that were never there.
 *
 * The heartbeat writes a row on a fixed interval and records the current chain
 * head. A monitor alerts when `last_beat_at` goes stale, which turns "the audit
 * log stopped receiving writes" into a paging event rather than an audit
 * finding. `/readyz` surfaces it too.
 */
export type Heartbeat = {
  beat: () => Promise<boolean>;
  firstBeat: Promise<boolean>;
  stop: () => void;
};

export function startHeartbeat(
  pool: Pool,
  log: { warn: (obj: unknown, msg: string) => void },
  intervalMs = 30_000,
): Heartbeat {
  const beat = async (): Promise<boolean> => {
    try {
      await pool.query(
        `UPDATE audit_heartbeat
            SET last_beat_at = now(),
                last_seq = (SELECT next_seq FROM audit_chain_head WHERE only_row)
          WHERE only_row`,
      );
      return true;
    } catch (error) {
      // A heartbeat that cannot write is itself the signal.
      log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
      return false;
    }
  };

  const firstBeat = beat();
  const timer = setInterval(() => void beat(), intervalMs);
  timer.unref();

  return { beat, firstBeat, stop: () => clearInterval(timer) };
}

/** How stale the heartbeat is, in seconds. Used by /readyz. */
export async function heartbeatAgeSeconds(pool: Pool): Promise<number | null> {
  const result = await pool.query<{ age: string }>(
    `SELECT EXTRACT(EPOCH FROM (now() - last_beat_at)) AS age
       FROM audit_heartbeat WHERE only_row`,
  );
  return result.rowCount === 1 ? Number(result.rows[0].age) : null;
}

export type Readiness =
  | { ok: true; auditHeartbeatAgeSeconds: number }
  | { ok: false; auditHeartbeatAgeSeconds: number | null };

/**
 * Readiness includes database access and the audit writer's first successful
 * beat. Liveness deliberately does not call this: a database incident should
 * remove the pod from service, not put it in a restart loop.
 */
export async function auditReadiness(
  pool: Pool,
  heartbeat: Pick<Heartbeat, 'firstBeat'>,
): Promise<Readiness> {
  try {
    if (!(await heartbeat.firstBeat)) {
      return { ok: false, auditHeartbeatAgeSeconds: null };
    }
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
    if (age === null || !Number.isFinite(age) || age > 300) {
      return { ok: false, auditHeartbeatAgeSeconds: age };
    }
    return { ok: true, auditHeartbeatAgeSeconds: age };
  } catch {
    return { ok: false, auditHeartbeatAgeSeconds: null };
  }
}

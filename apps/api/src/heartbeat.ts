import type { Pool } from 'pg';

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
 * finding. `/healthz` surfaces it too.
 */
export type Heartbeat = { stop: () => void };

export function startHeartbeat(
  pool: Pool,
  log: { warn: (obj: unknown, msg: string) => void },
  intervalMs = 30_000,
): Heartbeat {
  const beat = async (): Promise<void> => {
    try {
      await pool.query(
        `UPDATE audit_heartbeat
            SET last_beat_at = now(),
                last_seq = (SELECT next_seq FROM audit_chain_head WHERE only_row)
          WHERE only_row`,
      );
    } catch (error) {
      // A heartbeat that cannot write is itself the signal.
      log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
    }
  };

  void beat();
  const timer = setInterval(() => void beat(), intervalMs);
  timer.unref();

  return { stop: () => clearInterval(timer) };
}

/** How stale the heartbeat is, in seconds. Used by /healthz. */
export async function heartbeatAgeSeconds(pool: Pool): Promise<number | null> {
  const result = await pool.query<{ age: string }>(
    `SELECT EXTRACT(EPOCH FROM (now() - last_beat_at)) AS age
       FROM audit_heartbeat WHERE only_row`,
  );
  return result.rowCount === 1 ? Number(result.rows[0].age) : null;
}

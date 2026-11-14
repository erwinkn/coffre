import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * Sign-in's reads of the app's own (`signin.ts`, `api/routes/signin.ts`).
 * Each reads `device_logins` as it is, its MAC unchecked: what it counts or
 * shows decides nothing, which `device.start` and `device.decide` do.
 *
 * Each takes `at`, the app's clock, never the database's `now()`: the vault
 * dates a row's expiry on its own clock, the app's on the same platform, and
 * the database's may be minutes off it. Skew between the app and the vault
 * moves where these reads draw the line by as much, and nothing else:
 * the vault decides on its own clock whatever they show.
 */

/**
 * The device logins still waiting for a decision, those started from
 * `ip` and all of them: one statement, on the expiry index, whatever the
 * table holds. What `POST /api/auth/device` holds a stranger to, before it
 * asks the vault to write anything.
 */
export async function waitingDeviceLogins(db: Queryable, ip: string | null, at: Date): Promise<{ here: number; all: number }> {
  const [counted] = await rowsOf<{ here: number; all: number }>(
    db,
    sql`
      SELECT count(*) FILTER (WHERE client_ip IS NOT DISTINCT FROM ${ip})::int AS here, count(*)::int AS "all"
      FROM device_logins
      WHERE expires_at > ${at.toISOString()}::timestamptz AND decided_at IS NULL`,
  );
  return counted ?? { here: 0, all: 0 };
}

/** A device login waiting for a decision, as the person asked to decide it sees it: what it called itself and where it came from. */
export type DeviceLoginRow = { userCode: string; clientLabel: string | null; clientIp: string | null; createdAt: string; expiresAt: string };

/** The device login a user code names, while it waits for a decision: one statement, on the code's unique index. */
export async function waitingDeviceLogin(db: Queryable, userCode: string, at: Date): Promise<DeviceLoginRow | null> {
  const [row] = await rowsOf<{ user_code: string; client_label: string | null; client_ip: string | null; created_at: Date | string; expires_at: Date | string }>(
    db,
    sql`
      SELECT user_code, client_label, client_ip, created_at, expires_at
      FROM device_logins
      WHERE user_code = ${userCode} AND expires_at > ${at.toISOString()}::timestamptz AND decided_at IS NULL`,
  );
  if (row === undefined) return null;
  return { userCode: row.user_code, clientLabel: row.client_label, clientIp: row.client_ip, createdAt: new Date(row.created_at).toISOString(), expiresAt: new Date(row.expires_at).toISOString() };
}

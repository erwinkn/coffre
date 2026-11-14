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

/** A session of the caller's own, as `GET /sessions` shows it: never its value. `current` is the one the request came on. */
export type SessionRow = {
  id: string;
  kind: 'browser' | 'cli';
  label: string | null;
  hint: string;
  /** The provider of the account it was opened with; null for a CLI session approved from a device login. */
  provider: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  current: boolean;
};

/** An account of the caller's own, as `GET /identities` shows it. */
export type IdentityRow = { id: string; provider: string; email: string | null; createdAt: string; lastSignInAt: string | null };

const iso = (value: Date | string | null) => (value === null ? null : new Date(value).toISOString());

/**
 * A person's live sessions, browsers' and CLIs', the one last used first:
 * one statement, on the credentials' live index. Live as the vault takes
 * one (`callerOf`): of the person's generation, not revoked, frozen or
 * past `at`, never issued by a trust binding, and opened with an account
 * that is still linked where it names one (a browser's always does). Rows
 * as they are, their MACs unchecked: a list decides nothing, and ending
 * one is the vault's (`credential.end`).
 */
export async function liveSessions(db: Queryable, principal: string, at: Date): Promise<Omit<SessionRow, 'current'>[]> {
  const rows = await rowsOf<{
    id: string; kind: 'browser' | 'cli'; label: string | null; token_hint: string | null; provider: string | null;
    created_at: Date | string; expires_at: Date | string; last_used_at: Date | string | null; last_used_ip: string | null;
  }>(
    db,
    sql`
      SELECT c.id, c.kind, c.label, c.token_hint, i.provider, c.created_at, c.expires_at, c.last_used_at, c.last_used_ip
      FROM principals m
      JOIN credentials c ON c.principal = m.id AND c.generation = m.generation
      LEFT JOIN identities i ON i.id = c.identity_id AND i.principal = c.principal AND i.generation = c.generation
      WHERE m.id = ${principal} AND m.status = 'active'
        AND c.revoked_at IS NULL AND c.expires_at > ${at.toISOString()}::timestamptz AND c.frozen_at IS NULL
        AND c.kind IN ('browser', 'cli') AND c.created_by NOT LIKE 'binding:%'
        AND (CASE WHEN c.identity_id IS NULL THEN c.kind = 'cli' ELSE i.id IS NOT NULL AND i.revoked_at IS NULL END)
      ORDER BY coalesce(c.last_used_at, c.created_at) DESC, c.id`,
  );
  return rows.map((row) => ({
    id: row.id,
    kind: row.kind,
    label: row.label,
    hint: row.token_hint ?? '',
    provider: row.provider,
    createdAt: iso(row.created_at)!,
    expiresAt: iso(row.expires_at)!,
    lastUsedAt: iso(row.last_used_at),
    lastUsedIp: row.last_used_ip,
  }));
}

/**
 * A person's linked accounts, the oldest first: one statement, on the
 * identities' member index. Linked: of the person's generation and not
 * revoked. Rows as they are, their MACs unchecked: unlinking one is the
 * vault's (`account.unlink`).
 */
export async function linkedIdentities(db: Queryable, principal: string): Promise<IdentityRow[]> {
  const rows = await rowsOf<{ id: string; provider: string; email: string | null; created_at: Date | string; last_sign_in_at: Date | string | null }>(
    db,
    sql`
      SELECT i.id, i.provider, i.email, i.created_at, i.last_sign_in_at
      FROM principals m
      JOIN identities i ON i.principal = m.id AND i.generation = m.generation
      WHERE m.id = ${principal} AND m.status = 'active' AND i.revoked_at IS NULL
      ORDER BY i.created_at, i.id`,
  );
  return rows.map((row) => ({ id: row.id, provider: row.provider, email: row.email, createdAt: iso(row.created_at)!, lastSignInAt: iso(row.last_sign_in_at) }));
}

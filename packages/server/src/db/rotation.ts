// What the app's key rotation reads and writes (key-rotation.ts): where the
// log says the app's key stands, and its signed rows, a stretch at a time.
import type { StoredEntry } from '@coffre/core/audit';
import { type Queryable, type Transaction } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { authoredBy, entriesOf, entryColumns, firstEntryUnder, MOVES_FROM } from '@coffre/db/log';
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm';

import type { AuthRow, AuthTable } from '../auth-rows.ts';
import { auditLog, credentials, deviceLogins, enrollmentCodes, identities, mcpConnections, oauthClients, passkeys, serviceBindings } from '@coffre/db/schema';

/**
 * The app's newest `key.reseal` or `key.rotate`, unchecked: one step of
 * `audit_log_moves_idx` (`KINDS`; T245, R48), however many of the app's
 * other entries came since. Before 0.16 Postgres could walk the log back
 * by `seq` from the newest entry to the newest move.
 */
export async function newestMove(db: Queryable): Promise<StoredEntry | undefined> {
  const [row] = await db.select(entryColumns()).from(auditLog).where(entriesOf('moves')).orderBy(desc(auditLog.seq)).limit(1);
  return row as StoredEntry | undefined;
}

/** Which of `keyIds` an app's `key.reseal` or `key.rotate` names as the key it moves from. */
export async function movedFrom(db: Queryable, keyIds: readonly string[]): Promise<Set<string>> {
  const rows = await db
    .selectDistinct({ keyId: auditLog.subjectPrincipal })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), inArray(auditLog.action, [...MOVES_FROM]), inArray(auditLog.subjectPrincipal, [...keyIds])));
  return new Set(rows.map((row) => row.keyId!));
}

/** Whether the app wrote any entry under `keyId`: its first, one step of `audit_log_app_key_idx` (`firstEntryUnder`). */
export async function wroteUnder(db: Queryable, keyId: string): Promise<boolean> {
  return (await firstEntryUnder(db, 'app', keyId)) !== undefined;
}

/**
 * The app's newest entry, unchecked: one step of `audit_log_app_idx` (T245,
 * R48), where the walk back by `seq` read every vault entry since the app's
 * last, at each cold start of an app idle while the vault's beats went on.
 */
export async function newestAppEntry(db: Queryable): Promise<StoredEntry | undefined> {
  const [row] = await db.select(entryColumns()).from(auditLog).where(authoredBy('app')).orderBy(desc(auditLog.seq)).limit(1);
  return row as StoredEntry | undefined;
}

/** Each signed table by its name, as the app's rows name it (`AuthTable`). */
function signedTable(table: AuthTable) {
  return {
    identities,
    credentials,
    device_authorizations: deviceLogins,
    service_bindings: serviceBindings,
    oauth_clients: oauthClients,
    mcp_connections: mcpConnections,
    enrollments: enrollmentCodes,
    passkeys,
  }[table];
}

/**
 * Up to `limit` of a signed table's rows after id `after` (null: from the
 * first), by id, locked until the step commits: a change that does not
 * take the log's head, a session's renewal, waits for it, then finds the
 * row signed again and refuses, rather than the step missing it.
 */
export async function signedRowsAfter(tx: Queryable, table: AuthTable, after: string | null, limit: number): Promise<AuthRow[]> {
  const rows = signedTable(table);
  const query = tx.select().from(rows);
  return (await (after === null ? query : query.where(gt(rows.id, after))).orderBy(asc(rows.id)).limit(limit).for('update')) as AuthRow[];
}

/** A row signed again: its MAC as read, which it must still carry, and its new one; and when it ends, a session signed out or a device's login used up. */
export type Resealed = { id: string; was: Buffer; mac: Buffer; ends: Date | null };

/**
 * Each row given its new MAC, if it still carries the one it was read with:
 * a row changed since keeps its change, and the MAC it was changed under. A
 * session that ends is revoked as coffre revokes one, a device's login is
 * consumed. The ids of those it changed. One statement for each kind.
 */
export async function reseal(tx: Transaction, table: AuthTable, rows: readonly Resealed[]): Promise<string[]> {
  const target = signedTable(table);
  const changed: string[] = [];
  for (const ends of [false, true]) {
    const some = rows.filter((row) => (row.ends !== null) === ends);
    if (some.length === 0) continue;
    const values = sql.join(some.map((row) => sql`(${row.id}::uuid, ${row.was}::bytea, ${row.mac}::bytea)`), sql`, `);
    const at = some[0]!.ends;
    const end = !ends ? sql`` : table === 'device_authorizations' ? sql`, consumed_at = ${at}` : sql`, revoked_at = ${at}, revoked_by = 'coffre'`;
    const updated = await rowsOf<{ id: string }>(tx, sql`UPDATE ${target} AS t SET auth_mac = v.mac${end}
      FROM (VALUES ${values}) AS v(id, was, mac) WHERE t.id = v.id AND t.auth_mac = v.was RETURNING t.id`);
    changed.push(...updated.map((row) => row.id));
  }
  return changed;
}

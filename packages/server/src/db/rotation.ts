// What the app's key rotation reads and writes (key-rotation.ts): where the
// log says the app's key stands, and its signed rows, a stretch at a time.
import type { StoredEntry } from '@coffre/core/audit';
import { tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { changedRows, engineOf, forUpdate, rowsOf } from '@coffre/db/dialect';
import { entryColumns, MOVES_FROM } from '@coffre/db/log';
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm';

import type { AuthRow, AuthTable } from '../auth-rows.ts';

/** The app's newest `key.reseal` or `key.rotate`, unchecked. */
export async function newestMove(db: Queryable): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), inArray(auditLog.action, [...MOVES_FROM])))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  return row as StoredEntry | undefined;
}

/** Which of `keyIds` an app's `key.reseal` or `key.rotate` names as the key it moves from. */
export async function movedFrom(db: Queryable, keyIds: readonly string[]): Promise<Set<string>> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .selectDistinct({ keyId: auditLog.subjectPrincipal })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), inArray(auditLog.action, [...MOVES_FROM]), inArray(auditLog.subjectPrincipal, [...keyIds])));
  return new Set(rows.map((row) => row.keyId!));
}

/** Whether the app wrote any entry under `keyId`: read until the first, which for a key replaced is among the oldest. */
export async function wroteUnder(db: Queryable, keyId: string): Promise<boolean> {
  const { auditLog } = tablesOf(db);
  const [row] = await db.select({ seq: auditLog.seq }).from(auditLog).where(and(eq(auditLog.author, 'app'), eq(auditLog.keyId, keyId))).orderBy(asc(auditLog.seq)).limit(1);
  return row !== undefined;
}

/** The app's newest entry, unchecked. */
export async function newestAppEntry(db: Queryable): Promise<StoredEntry | undefined> {
  const { auditLog } = tablesOf(db);
  const [row] = await db.select(entryColumns(db)).from(auditLog).where(eq(auditLog.author, 'app')).orderBy(desc(auditLog.seq)).limit(1);
  return row as StoredEntry | undefined;
}

/** Each signed table by its name, as the app's rows name it (`AuthTable`). */
function signedTable(db: Queryable, table: AuthTable) {
  const tables = tablesOf(db);
  return {
    identities: tables.identities,
    credentials: tables.credentials,
    device_authorizations: tables.deviceAuthorizations,
    service_bindings: tables.serviceBindings,
    oauth_clients: tables.oauthClients,
    mcp_connections: tables.mcpConnections,
    enrollments: tables.enrollments,
  }[table];
}

/**
 * Up to `limit` of a signed table's rows after id `after` (null: from the
 * first), by id, locked until the step commits: a change that does not
 * take the log's head, a session's renewal, waits for it, then finds the
 * row signed again and refuses, rather than the step missing it.
 */
export async function signedRowsAfter(tx: Transaction, table: AuthTable, after: string | null, limit: number): Promise<AuthRow[]> {
  const rows = signedTable(tx, table);
  const query = tx.select().from(rows);
  return (await forUpdate(tx, (after === null ? query : query.where(gt(rows.id, after))).orderBy(asc(rows.id)).limit(limit))) as AuthRow[];
}

/** A row signed again: its MAC as read, which it must still carry, and its new one; and when it ends, a session signed out or a device's login used up. */
export type Resealed = { id: string; was: Buffer; mac: Buffer; ends: Date | null };

/**
 * Each row given its new MAC, if it still carries the one it was read with:
 * a row changed since keeps its change, and the MAC it was changed under. A
 * session that ends is revoked as coffre revokes one, a device's login is
 * consumed. The ids of those it changed. One statement on Postgres for each
 * kind, one a row on SQLite.
 */
export async function reseal(tx: Transaction, table: AuthTable, rows: readonly Resealed[]): Promise<string[]> {
  const target = signedTable(tx, table);
  const changed: string[] = [];
  if (engineOf(tx) === 'sqlite') {
    for (const row of rows) {
      const set = row.ends === null ? { authMac: row.mac } : { authMac: row.mac, ...ending(table, row.ends) };
      if (changedRows(await tx.update(target).set(set as never).where(and(eq(target.id, row.id), eq(target.authMac, row.was)))) > 0) changed.push(row.id);
    }
    return changed;
  }
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

/** The columns that end a row as a rotation ends it: a device's login consumed, a session revoked. */
function ending(table: AuthTable, at: Date): Record<string, unknown> {
  return table === 'device_authorizations' ? { consumedAt: at } : { revokedAt: at, revokedBy: 'coffre' };
}

// What the app's key rotation reads and writes (key-rotation.ts): where the
// log says the app's key stands, and its signed rows, a stretch at a time.
import type { StoredEntry } from '@coffre/core/audit';
import { type Queryable, type Transaction } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { authoredBy, entriesOf, entryColumns, MOVES_FROM } from '@coffre/db/log';
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm';

import type { AuthRow, AuthTable } from '../auth-rows.ts';
import { auditLog, credentials, deviceLogins, enrollmentCodes, identities, mcpConnections, oauthClients, passkeys, serviceBindings } from '@coffre/db/schema';

/**
 * The app's newest `key.reseal` or `key.rotate`, unchecked: one step of
 * `audit_log_moves_idx` (`KINDS`), however many of the app's
 * other entries came since, each of which a walk back by `seq` would read.
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

/**
 * The app's newest entry, unchecked: one step of `audit_log_app_idx`, where
 * a walk back by `seq` would read every vault entry since the app's last, at
 * each cold start of an app idle while the vault's beats go on.
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
 * first), by id, with no lock. Every change to a signed field
 * (`auth-rows.ts`, `FIELDS`) is compare-and-set on the row's MAC, in its
 * `UPDATE` or under the row's lock, as the step's own write is (`reseal`):
 * whichever of a writer and the step writes second changes nothing, and
 * the step then reads again (`rotateStep`). That alone is the guarantee.
 * The step holds the change lock and the log's head from before its read,
 * so the writers that hold either never meet it: the app's but one (the
 * head) and the vault's (`revoke_credential`, `change_bindings`: the
 * change lock). The one that holds neither (`sweepOauthClients`) does,
 * and the compare settles it. The columns outside the MAC (a last
 * use, a passkey's name or counter) change with neither, which is safe
 * only while the MAC and `endsAt` read none of them: a column that joins
 * `FIELDS` takes the compare-and-set with it.
 */
export async function signedRowsAfter(tx: Queryable, table: AuthTable, after: string | null, limit: number): Promise<AuthRow[]> {
  const rows = signedTable(table);
  const query = tx.select().from(rows);
  return (await (after === null ? query : query.where(gt(rows.id, after))).orderBy(asc(rows.id)).limit(limit)) as AuthRow[];
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

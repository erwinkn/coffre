// What the app's half of 0.15's cutover from 0.14 reads (cutover.ts): the
// entries and rows it vouches for under its key.
import type { StoredEntry } from '@coffre/core/audit';
import type { BindingColumns, ConnectionColumns, CredentialColumns } from '@coffre/core/vault';
import { tablesOf, type Queryable } from '@coffre/db';
import { entryColumns } from '@coffre/db/log';
import { and, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';

import { connectionColumns, credentialColumns, sealedBinding } from '../api/changes.ts';
import { checkAuthRow } from '../auth-rows.ts';
import { tombstoned } from './queries.ts';

/** The app's allowed entries of these actions, whole, for their MACs to be checked. */
export async function appEntries(db: Queryable, actions: readonly string[]): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db.select(entryColumns(db)).from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.decision, 'allow'), inArray(auditLog.action, [...actions])));
  return rows as StoredEntry[];
}

/**
 * Each credential 0.14 accepts as it stands, unsealed: its MAC the app's,
 * neither revoked nor past its end, and its sign-in account's row, if it
 * has one, the app's and not unlinked (`findCredential`). One a binding
 * issued is left out: 0.14 reads its scope from the binding, and its row
 * holds none for a seal to cover; it signs in again through its binding,
 * which is vouched for.
 */
export async function liveCredentials(db: Queryable, chainKey: Buffer, issuers: ReadonlyMap<string, string>): Promise<{ columns: CredentialColumns; identityId: string | null }[]> {
  const { credentials, identities } = tablesOf(db);
  const now = new Date();
  const rows = await db.select({ credential: credentials, identity: identities }).from(credentials)
    .leftJoin(identities, eq(identities.id, credentials.identityId))
    // No hard end: 0.14 gives one only to what a binding issues, left out here, and no MAC covers it (review r6).
    .where(and(isNull(credentials.seal), isNull(credentials.revokedAt), gt(credentials.expiresAt, now), isNull(credentials.notAfter),
      or(isNull(credentials.createdBy), sql`${credentials.createdBy} NOT LIKE 'binding:%'`)));
  return rows
    .filter(({ credential, identity }) => checkAuthRow(chainKey, 'credentials', credential)
      && (credential.identityId === null || (identity !== null && identity.revokedAt === null && checkAuthRow(chainKey, 'identities', identity)))
      // A browser session, of a sign-in provider the deployment still configures (`#liveCredential`: review r6).
      && (credential.kind !== 'browser' || (identity !== null && identity.issuerHash === issuers.get(identity.provider))))
    .map(({ credential }) => ({ columns: credentialColumns(credential), identityId: credential.identityId }));
}

/** Each trust binding 0.14 accepts as it stands, unsealed: its MAC the app's, not revoked, and no `token.unbind` of it. */
export async function liveBindings(db: Queryable, chainKey: Buffer, publicUrl: string): Promise<BindingColumns[]> {
  const { serviceBindings } = tablesOf(db);
  // No `origin`: 0.14 writes none, and its MAC covers none, so a row with one is not 0.14's to vouch for.
  const rows = (await db.select().from(serviceBindings).where(and(isNull(serviceBindings.seal), isNull(serviceBindings.revokedAt), isNull(serviceBindings.origin))))
    .filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
  const dead = await tombstoned(db, rows.map((row) => row.id));
  return rows.filter((row) => !dead.has(row.id)).map((row) => sealedBinding(row, publicUrl).columns);
}

/**
 * Each MCP connection 0.14 accepts as it stands, unsealed (T147): its MAC
 * the app's, neither revoked nor past its end. One of an earlier generation
 * of its account too, which a use refuses on that, as `credentialStill` did.
 */
export async function liveConnections(db: Queryable, chainKey: Buffer): Promise<ConnectionColumns[]> {
  const { mcpConnections } = tablesOf(db);
  const rows = await db.select().from(mcpConnections)
    .where(and(isNull(mcpConnections.seal), isNull(mcpConnections.revokedAt), gt(mcpConnections.expiresAt, new Date())));
  return rows.filter((row) => checkAuthRow(chainKey, 'mcp_connections', row)).map(connectionColumns);
}

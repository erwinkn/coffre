import { createHmac, timingSafeEqual } from 'node:crypto';

import { deriveKey } from '@coffre/core/identity';
import type { credentials, deviceAuthorizations, identities, serviceBindings } from '@coffre/db/schema';

type Rows = {
  identities: typeof identities.$inferSelect;
  credentials: typeof credentials.$inferSelect;
  device_authorizations: typeof deviceAuthorizations.$inferSelect;
  service_bindings: typeof serviceBindings.$inferSelect;
};
export type AuthTable = keyof Rows;

// IDs and userCode bind a MAC to the row an approval or revocation selects.
// decidedAt also matters: clearing it would make a device decidable again.
// A binding's policy is all of it but its label and last use.
const FIELDS = {
  identities: ['id', 'provider', 'issuerHash', 'subject', 'principal', 'generation', 'revokedAt'],
  credentials: ['id', 'tokenHash', 'kind', 'principal', 'generation', 'identityId', 'expiresAt', 'revokedAt'],
  device_authorizations: ['id', 'deviceCodeHash', 'userCode', 'decision', 'decidedAt', 'principal', 'generation', 'expiresAt', 'consumedAt'],
  service_bindings: ['id', 'principal', 'generation', 'profile', 'issuer', 'jwksUri', 'claims', 'revokedAt'],
} as const satisfies { [K in AuthTable]: readonly (keyof Rows[K])[] };

type Fields = { [K in AuthTable]: Pick<Rows[K], Extract<typeof FIELDS[K][number], keyof Rows[K]>> };

export type AuthRow = { [K in AuthTable]: Fields[K] & { authMac: Buffer } }[AuthTable];

/** A versioned tuple: fixed field order, distinct nulls, bytes as hex and dates as milliseconds. */
export function authMac<K extends AuthTable>(chainKey: Buffer, table: K, row: Fields[K]): Buffer {
  const values = FIELDS[table].map((field) => {
    const value = (row as Record<string, unknown>)[field];
    if (value === undefined) throw new Error(`missing ${table}.${field} for its authentication MAC`);
    if (value instanceof Date) return value.getTime();
    if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
    return value;
  });
  const key = deriveKey(chainKey, 'signin-rows/v1');
  try {
    return createHmac('sha256', key).update(JSON.stringify(['coffre.auth.v2', table, ...values])).digest();
  } finally {
    key.fill(0);
  }
}

/** Report without trusting the row's claimed actor, or writing inside a transaction that will roll back. */
export function checkAuthRow<K extends AuthTable>(chainKey: Buffer, table: K, row: Fields[K] & { id: string; authMac: Buffer }): boolean {
  const expected = authMac(chainKey, table, row);
  if (row.authMac instanceof Uint8Array && row.authMac.length === expected.length && timingSafeEqual(row.authMac, expected)) return true;
  console.error({ event: 'auth_row_tampered', table, id: row.id }, 'sign-in row failed authentication');
  return false;
}

/** A sign-in row that fails its MAC: checked and refused, never an outage. */
export class AuthRowTampered extends Error {
  readonly table: AuthTable;
  constructor(table: AuthTable) {
    super('sign-in row failed authentication');
    this.name = 'AuthRowTampered';
    this.table = table;
  }
}

/** Authentication at use still refuses the whole request. */
export function verifyAuthRow<K extends AuthTable>(chainKey: Buffer, table: K, row: Fields[K] & { id: string; authMac: Buffer }): void {
  if (!checkAuthRow(chainKey, table, row)) throw new AuthRowTampered(table);
}

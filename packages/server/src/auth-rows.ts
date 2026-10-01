import { createHmac, timingSafeEqual } from 'node:crypto';

import { deriveKey } from '@coffre/core/identity';
import type { credentials, deviceAuthorizations, identities } from '@coffre/db/schema';

type Rows = {
  identities: typeof identities.$inferSelect;
  credentials: typeof credentials.$inferSelect;
  device_authorizations: typeof deviceAuthorizations.$inferSelect;
};
export type AuthTable = keyof Rows;

// IDs and userCode bind a MAC to the row an approval or revocation selects.
// decidedAt also matters: clearing it would make a device decidable again.
const FIELDS = {
  identities: ['id', 'provider', 'issuerHash', 'subject', 'principalType', 'principalId', 'generation', 'revokedAt'],
  credentials: ['id', 'tokenHash', 'kind', 'principalType', 'principalId', 'generation', 'identityId', 'expiresAt', 'revokedAt'],
  device_authorizations: ['id', 'deviceCodeHash', 'userCode', 'decision', 'decidedAt', 'principalType', 'principalId', 'generation', 'expiresAt', 'consumedAt'],
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
    return createHmac('sha256', key).update(JSON.stringify(['coffre.auth.v1', table, ...values])).digest();
  } finally {
    key.fill(0);
  }
}

/** Report without trusting the row's claimed actor, or writing inside a transaction that will roll back. */
export function verifyAuthRow<K extends AuthTable>(chainKey: Buffer, table: K, row: Fields[K] & { id: string; authMac: Buffer }): void {
  const expected = authMac(chainKey, table, row);
  if (row.authMac instanceof Uint8Array && row.authMac.length === expected.length && timingSafeEqual(row.authMac, expected)) return;
  console.error({ event: 'auth_row_tampered', table, id: row.id }, 'sign-in row failed authentication');
  throw new Error('sign-in row failed authentication');
}

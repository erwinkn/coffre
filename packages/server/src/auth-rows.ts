import { createHmac, timingSafeEqual } from 'node:crypto';

import { deriveKey } from '@coffre/core/identity';
import type { credentials, deviceAuthorizations, enrollments, identities, mcpConnections, oauthClients, serviceBindings } from '@coffre/db/schema';

type Rows = {
  identities: typeof identities.$inferSelect;
  credentials: typeof credentials.$inferSelect;
  device_authorizations: typeof deviceAuthorizations.$inferSelect;
  service_bindings: typeof serviceBindings.$inferSelect;
  oauth_clients: typeof oauthClients.$inferSelect;
  mcp_connections: typeof mcpConnections.$inferSelect;
  enrollments: typeof enrollments.$inferSelect;
};
export type AuthTable = keyof Rows;

// IDs and userCode bind a MAC to the row an approval or revocation selects.
// decidedAt also matters: clearing it would make a device decidable again.
// A binding's policy is all of it but its label and last use, its keys too
// when it carries them (`kindOf`). A registered client is its name and
// redirects; a connection, everything that grants, proves or names
// something: who, which client and how it is shown (its name, host, and
// whether it registered itself, which Connected apps and the log say), what
// scopes, where codes go, its code and refresh token, and how long it lasts.
// An enrollment code is all of it but its hint and when it was made: whose
// binding, its hash, the scope its sessions hold, who minted it, and its end.
const FIELDS = {
  identities: ['id', 'provider', 'issuerHash', 'subject', 'principal', 'generation', 'revokedAt'],
  credentials: ['id', 'tokenHash', 'kind', 'principal', 'generation', 'identityId', 'expiresAt', 'revokedAt'],
  device_authorizations: ['id', 'deviceCodeHash', 'userCode', 'decision', 'decidedAt', 'principal', 'generation', 'expiresAt', 'consumedAt'],
  service_bindings: ['id', 'principal', 'generation', 'profile', 'issuer', 'jwksUri', 'claims', 'revokedAt'],
  oauth_clients: ['id', 'name', 'redirectUris', 'revokedAt'],
  mcp_connections: [
    'id', 'principal', 'generation', 'clientId', 'clientName', 'clientHost', 'registration', 'scopes', 'redirectUri',
    'codeHash', 'codeChallenge', 'codeExpiresAt', 'refreshHash', 'refreshPreviousHash', 'expiresAt', 'revokedAt',
  ],
  enrollments: ['id', 'bindingId', 'codeHash', 'scope', 'createdBy', 'createdWith', 'expiresAt'],
} as const satisfies { [K in AuthTable]: readonly (keyof Rows[K])[] };

type Fields = { [K in AuthTable]: Pick<Rows[K], Extract<typeof FIELDS[K][number], keyof Rows[K]>> };

/**
 * A credential a trust binding issued, for a CI run's ID token, says so in
 * `created_by`: `binding:<id>`. Its MAC is of another kind, which covers
 * that too, so the link cannot be cut, nor added to a token an owner issued:
 * either way the row no longer carries its MAC. Every check of it checks
 * its binding as well (`findCredential`).
 */
const EXCHANGED = 'binding:';

export function issuedBy(bindingId: string): string {
  return `${EXCHANGED}${bindingId}`;
}

/** The binding that issued a credential, by its `created_by`; null for one an owner or a sign-in issued. */
export function issuingBinding(createdBy: unknown): string | null {
  return typeof createdBy === 'string' && createdBy.startsWith(EXCHANGED) ? createdBy.slice(EXCHANGED.length) : null;
}

/**
 * A workload's session (docs/design/workload-access.md, section 11): one
 * kind of its own, which composes with no other, over today's fields and
 * then everything that binds it: who made it, its scope and places, its
 * key, its hard end, its ancestors and limits, its code, and its approval.
 */
const WORKLOAD_FIELDS = [
  ...FIELDS.credentials,
  'createdBy', 'scope', 'places', 'jkt', 'notAfter', 'ancestors', 'constraints', 'enrollmentId', 'approvedAt', 'approvedBy',
] as const satisfies readonly (keyof Rows['credentials'])[];

/**
 * The tuple's kind and fields: an exchanged credential's are its own, and
 * so are a binding's that carries its issuer's keys, which covers them. A
 * token's or a binding's scope makes another kind again, which covers it:
 * the rows of 0.4 had none, and still check as they were sealed until the
 * app seals them with one (`sealScopes`); a scope cleared or changed fails
 * either way. A handle's places do the same, and a binding's policy, last:
 * a binding that carries one never checks as one `/api/auth/oidc` takes.
 * A workload's session is its own kind first, whatever else it carries.
 */
function kindOf(table: AuthTable, row: object): { kind: string; fields: readonly string[] } {
  const { kind: credentialKind, createdBy, scope, jwks, places, policy } = row as {
    kind?: unknown; createdBy?: unknown; scope?: unknown; jwks?: unknown; places?: unknown; policy?: unknown;
  };
  if (table === 'credentials' && credentialKind === 'workload') return { kind: 'workload_credentials', fields: WORKLOAD_FIELDS };
  const exchanged = table === 'credentials' && issuingBinding(createdBy) !== null;
  const uploaded = table === 'service_bindings' && jwks != null;
  const kind = exchanged ? 'exchanged_credentials' : uploaded ? 'uploaded_service_bindings' : table;
  const fields = exchanged ? [...FIELDS.credentials, 'createdBy'] : uploaded ? [...FIELDS.service_bindings, 'jwks'] : FIELDS[table];
  const scoped = scope == null ? { kind, fields } : { kind: `scoped_${kind}`, fields: [...fields, 'scope'] };
  // A handle's places, which the proxy's stable URL resolves to, make a kind of their own: a handle of 0.8 has none, and checks as it was sealed.
  if (table === 'credentials' && places != null) return { kind: `placed_${scoped.kind}`, fields: [...scoped.fields, 'places'] };
  return table === 'service_bindings' && policy != null ? { kind: `policed_${scoped.kind}`, fields: [...scoped.fields, 'policy'] } : scoped;
}

export type AuthRow = { [K in AuthTable]: Fields[K] & { authMac: Buffer } }[AuthTable];

/** A versioned tuple: fixed field order, distinct nulls, bytes as hex and dates as milliseconds. */
export function authMac<K extends AuthTable>(chainKey: Buffer, table: K, row: Fields[K]): Buffer {
  const { kind, fields } = kindOf(table, row);
  const values = fields.map((field) => {
    const value = (row as Record<string, unknown>)[field];
    if (value === undefined) throw new Error(`missing ${table}.${field} for its authentication MAC`);
    if (value instanceof Date) return value.getTime();
    if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
    return value;
  });
  const key = deriveKey(chainKey, 'signin-rows/v1');
  try {
    return createHmac('sha256', key).update(JSON.stringify(['coffre.auth.v2', kind, ...values])).digest();
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

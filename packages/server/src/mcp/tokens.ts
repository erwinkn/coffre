import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { deriveKey } from '@coffre/core/identity';
import { MCP_SCOPES, type McpScope } from '@coffre/core/mcp';

/**
 * What an MCP client holds (docs/design/mcp.md, section 4):
 *
 * - an access token, `coffre_mcp_…`, that names its connection, its scopes
 *   and its hour under a MAC: it has no row, and every request checks its
 *   connection, so revoking that ends it at once;
 * - a refresh token, `coffre_mcr_…`, 256 random bits stored as a hash on the
 *   connection and replaced at every use;
 * - for a minute after consent, a code, likewise random, redeemed once with
 *   its PKCE verifier.
 *
 * The prefixes tell a person, or a secret scanner, what a leaked string is.
 * An access token's shape is never a credential's (`coffre_web_`, `_cli_`,
 * `_svc_`), so the API cannot accept one, and `/mcp` accepts nothing else.
 */

export const ACCESS_PREFIX = 'coffre_mcp_';
export const REFRESH_PREFIX = 'coffre_mcr_';

/** An hour: what a leaked access token is good for, at most, unless its connection ends sooner. */
export const ACCESS_TOKEN_SECONDS = 60 * 60;

const VERSION = 1;
/** Version, connection ID, scopes, issued and expires (seconds), then the MAC. */
const BODY_BYTES = 1 + 16 + 1 + 4 + 4;
const MAC_BYTES = 32;
const ACCESS = new RegExp(`^${ACCESS_PREFIX}[A-Za-z0-9_-]{${Math.ceil(((BODY_BYTES + MAC_BYTES) * 4) / 3)}}$`);

export type AccessClaims = { connectionId: string; scopes: McpScope[]; issuedAt: Date; expiresAt: Date };

function tokenKey(chainKey: Buffer): Buffer {
  return deriveKey(chainKey, 'mcp-tokens/v1');
}

function mac(chainKey: Buffer, body: Buffer): Buffer {
  const key = tokenKey(chainKey);
  try {
    return createHmac('sha256', key).update(body).digest();
  } finally {
    key.fill(0);
  }
}

function scopeBits(scopes: readonly McpScope[]): number {
  return MCP_SCOPES.reduce((bits, scope, index) => (scopes.includes(scope) ? bits | (1 << index) : bits), 0);
}

export function mintAccessToken(chainKey: Buffer, claims: AccessClaims): string {
  const body = Buffer.alloc(BODY_BYTES);
  body.writeUInt8(VERSION, 0);
  Buffer.from(claims.connectionId.replace(/-/g, ''), 'hex').copy(body, 1);
  body.writeUInt8(scopeBits(claims.scopes), 17);
  body.writeUInt32BE(Math.floor(claims.issuedAt.getTime() / 1000), 18);
  body.writeUInt32BE(Math.floor(claims.expiresAt.getTime() / 1000), 22);
  return ACCESS_PREFIX + Buffer.concat([body, mac(chainKey, body)]).toString('base64url');
}

/** Whether a string has an access token's shape, before its MAC is checked. */
export function isAccessToken(value: string): boolean {
  return ACCESS.test(value);
}

/**
 * The claims of an access token whose MAC holds, expired or not; null for
 * anything else. The caller checks the time, and the connection.
 */
export function readAccessToken(chainKey: Buffer, token: string): AccessClaims | null {
  if (!isAccessToken(token)) return null;
  const bytes = Buffer.from(token.slice(ACCESS_PREFIX.length), 'base64url');
  if (bytes.length !== BODY_BYTES + MAC_BYTES) return null;
  const body = bytes.subarray(0, BODY_BYTES);
  if (!timingSafeEqual(bytes.subarray(BODY_BYTES), mac(chainKey, body)) || body.readUInt8(0) !== VERSION) return null;
  const hex = body.subarray(1, 17).toString('hex');
  const bits = body.readUInt8(17);
  return {
    connectionId: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    scopes: MCP_SCOPES.filter((_, index) => (bits & (1 << index)) !== 0),
    issuedAt: new Date(body.readUInt32BE(18) * 1000),
    expiresAt: new Date(body.readUInt32BE(22) * 1000),
  };
}

/** A fresh refresh token, or with no prefix, a code. */
export function secret(prefix = ''): string {
  return prefix + randomBytes(32).toString('base64url');
}

export function hashSecret(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/** RFC 7636's verifier: 43 to 128 unreserved characters. */
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
/** An S256 challenge: the verifier's SHA-256, base64url without padding. */
export const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

/** Whether `verifier` is the one `challenge` was made from, by S256, the only method coffre takes. */
export function pkceMatches(challenge: string, verifier: string): boolean {
  if (!VERIFIER.test(verifier) || !S256_CHALLENGE.test(challenge)) return false;
  const made = createHash('sha256').update(verifier, 'ascii').digest();
  const expected = Buffer.from(challenge, 'base64url');
  return expected.length === made.length && timingSafeEqual(made, expected);
}

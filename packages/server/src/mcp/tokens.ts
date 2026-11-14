import { createHmac, timingSafeEqual } from 'node:crypto';

import { deriveKey } from '@coffre/core/identity';

// What an MCP client carries between the rounds of a call that waits for
// its approval. Its tokens are credentials of the vault's now, drawn by the
// token endpoint (`mcp/http.ts`, `coffre_mcp_…` and `coffre_mcr_…` in
// @coffre/core/identity): no MAC of the app's makes one.

// --- requestState -------------------------------------------------------------

/**
 * What a 2026-07-28 client carries between the rounds of a call that waits
 * for its approval: the approval, its connection, the call's digest and an
 * expiry, under a MAC of its own key. Opaque to the client, which echoes it,
 * and no row: the approval is read by its ID, and only for the connection
 * and the call that asked for it.
 */
export type ApprovalState = { approvalId: string; connectionId: string; digest: string; expiresAt: Date };

function stateMac(chainKey: Buffer, body: string): Buffer {
  const key = deriveKey(chainKey, 'mcp-request-state/v1');
  try {
    return createHmac('sha256', key).update(body).digest();
  } finally {
    key.fill(0);
  }
}

export function sealState(chainKey: Buffer, state: ApprovalState): string {
  const body = Buffer.from(
    JSON.stringify([state.approvalId, state.connectionId, state.digest, Math.floor(state.expiresAt.getTime() / 1000)]),
  ).toString('base64url');
  return `${body}.${stateMac(chainKey, body).toString('base64url')}`;
}

/** A state whose MAC holds, expired or not; null for anything else. */
export function openState(chainKey: Buffer, sealed: string): ApprovalState | null {
  const [body, tag, ...rest] = sealed.split('.');
  if (body === undefined || tag === undefined || rest.length > 0 || sealed.length > 512) return null;
  const given = Buffer.from(tag, 'base64url');
  const expected = stateMac(chainKey, body);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  const [approvalId, connectionId, digest, expires] = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as [string, string, string, number];
  return { approvalId, connectionId, digest, expiresAt: new Date(expires * 1000) };
}

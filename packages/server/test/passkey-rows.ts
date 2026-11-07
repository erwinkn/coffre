// Passkey rows, and a session one confirmed, written as the app writes them
// (docs/design/passkeys.md, sections 5.1 and 5.2), for the tests of what holds
// them; each row's key is a software authenticator's, which `touching` touches.
import { randomUUID } from 'node:crypto';

import { CoffreError } from '@coffre/client';
import { SoftAuthenticator } from '@coffre/conformance/authenticator';
import { generateToken, hashToken, tokenHint } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { eq } from 'drizzle-orm';

import { authMac } from '../src/auth-rows.ts';
import type { SigninService } from '../src/api/signin.ts';
import { memberStanding } from '../src/db/queries.ts';
import { credentials, deviceAuthorizations, mcpConnections, passkeys } from './db/tables.ts';

async function generationOf(owner: Database, email: string): Promise<number> {
  return (await memberStanding(owner, `user:${email}`))!.generation;
}

/** The authenticator behind each passkey `addPasskey` wrote, by its id. */
const keys = new Map<string, SoftAuthenticator>();

/** A live passkey of `email`'s, at their generation, a synced software authenticator's; its id. */
export async function addPasskey(owner: Database, chainKey: Buffer, email: string): Promise<string> {
  const key = await SoftAuthenticator.create('ES256', { synced: true });
  const passkey = {
    id: randomUUID(), principal: `user:${email}`, generation: await generationOf(owner, email), userHandle: Buffer.from(crypto.getRandomValues(new Uint8Array(16))),
    credentialId: Buffer.from(key.credentialId), publicKey: Buffer.from(await key.publicKey()), algorithm: -7, removedAt: null,
  };
  await owner.insert(passkeys).values({ ...passkey, synced: true, name: 'YubiKey 5C', createdBy: `user:${email}`, authMac: authMac(chainKey, 'passkeys', passkey) });
  keys.set(passkey.id, key);
  return passkey.id;
}

/** A touch an act carries (docs/design/passkeys.md, section 4.2). */
export type Touch = { state: string; response: Record<string, unknown> };

/**
 * An act that takes a touch of its own, as coffre's pages do it: sent, and refused `403 touch_required`, sent again
 * with a touch of `passkeyId`'s authenticator for the challenge the refusal carries, at `origin`.
 */
export async function touching<T>(passkeyId: string, send: (touch?: Touch) => Promise<T>, origin = 'https://secrets.acme.example'): Promise<T> {
  try {
    return await send();
  } catch (error) {
    if (!(error instanceof CoffreError) || error.code !== 'touch_required' || error.touch === undefined) throw error;
    return send({ state: error.touch.state, response: await touchFor(passkeyId, error.touch.options, origin) });
  }
}

/** `passkeyId`'s authenticator's answer to a `touch_required`'s options, at `origin`. */
export async function touchFor(passkeyId: string, options: unknown, origin = 'https://secrets.acme.example'): Promise<Record<string, unknown>> {
  const key = keys.get(passkeyId);
  if (key === undefined) throw new Error(`no authenticator holds passkey ${passkeyId}`);
  const { challenge, rpId } = options as { challenge: string; rpId: string };
  return (await key.assert({ rpId, origin, challenge: new Uint8Array(Buffer.from(challenge, 'base64url')) })) as unknown as Record<string, unknown>;
}

/** Its removal, signed again as the app signs one. */
export async function removePasskey(owner: Database, chainKey: Buffer, id: string): Promise<void> {
  const [row] = await owner.select().from(passkeys).where(eq(passkeys.id, id));
  const removed = { ...row!, removedAt: new Date(), removedBy: row!.principal };
  await owner.update(passkeys).set({ removedAt: removed.removedAt, removedBy: removed.removedBy, authMac: authMac(chainKey, 'passkeys', removed) }).where(eq(passkeys.id, id));
}

/** A CLI session of `email`'s that `passkeyId` confirmed at `confirmedAt`, a moment ago unless said: its token. */
export async function confirmedSession(owner: Database, chainKey: Buffer, email: string, passkeyId: string, { confirmedAt = new Date() }: { confirmedAt?: Date } = {}): Promise<string> {
  const token = generateToken('cli');
  const row = {
    id: randomUUID(), kind: 'cli', tokenHash: hashToken(token), generation: await generationOf(owner, email), tokenHint: tokenHint(token), principal: `user:${email}`,
    identityId: null, label: null, createdBy: email, expiresAt: new Date(Date.now() + 3_600_000), scope: null, places: null, revokedAt: null,
    passkeyId, confirmedAt,
  };
  await owner.insert(credentials).values({ ...row, authMac: authMac(chainKey, 'credentials', row) });
  return token;
}

/**
 * A device code `email` approved with a touch of `passkeyId`, a moment ago, that no terminal has redeemed yet: its
 * device code, which `pollDevice` redeems, and its row's id.
 */
export async function approvedCode(owner: Database, chainKey: Buffer, email: string, passkeyId: string): Promise<{ deviceCode: string; id: string }> {
  const deviceCode = randomUUID();
  const row = {
    id: randomUUID(), deviceCodeHash: hashToken(deviceCode), userCode: `${randomUUID().slice(0, 4)}-${randomUUID().slice(0, 4)}`.toUpperCase(), decision: 'approved',
    decidedAt: new Date(), principal: `user:${email}`, generation: await generationOf(owner, email), expiresAt: new Date(Date.now() + 600_000), consumedAt: null, passkeyId,
  };
  await owner.insert(deviceAuthorizations).values({ ...row, clientLabel: 'laptop', clientIp: null, authMac: authMac(chainKey, 'device_authorizations', row) });
  return { deviceCode, id: row.id };
}

/** An app `email` connected with a touch of `passkeyId`, its code redeemed: a live connection, for a day. Its id. */
export async function connectedApp(owner: Database, chainKey: Buffer, email: string, passkeyId: string): Promise<string> {
  const row = {
    id: randomUUID(), principal: `user:${email}`, generation: await generationOf(owner, email), clientId: 'https://claude.ai/oauth/claude-code-client-metadata',
    clientName: 'Claude Code', clientHost: 'claude.ai', registration: 'cimd', scopes: 'read', redirectUri: 'http://127.0.0.1:33418/callback',
    codeHash: null, codeChallenge: null, codeExpiresAt: null, refreshHash: Buffer.from(hashToken(randomUUID())), refreshPreviousHash: null,
    expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null, passkeyId,
  };
  await owner.insert(mcpConnections).values({ ...row, authMac: authMac(chainKey, 'mcp_connections', row) });
  return row.id;
}

/**
 * `email`'s browser session `token`, signed in by the provider alone, stepped up with a touch of a passkey added for
 * them (docs/design/passkeys.md, section 6.5): the new session the step-up issued, through the app's own issue, which
 * 0.15's log holds, confirmed now. What a person who acts on what a fresh check guards holds.
 */
export async function steppedUp(signin: SigninService, owner: Database, chainKey: Buffer, email: string, token: string): Promise<{ token: string; id: string }> {
  const passkey = await addPasskey(owner, chainKey, email);
  const step = await signin.stepUpStep(token, '/');
  if (step === null) throw new Error(`no step-up for ${email}`);
  const stepped = await signin.stepUp(step.state, token, await touchFor(passkey, step.options), { requestId: randomUUID(), sourceIp: null, label: 'Firefox' });
  if (stepped.ok !== true) throw new Error(`${email}'s step-up was refused: ${JSON.stringify(stepped)}`);
  return { token: stepped.credential.token, id: stepped.credential.id };
}

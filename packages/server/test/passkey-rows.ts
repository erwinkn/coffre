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
import { memberStanding } from '../src/db/queries.ts';
import { credentials, passkeys } from './db/tables.ts';

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

/** A CLI session of `email`'s that `passkeyId` confirmed a moment ago: its token. */
export async function confirmedSession(owner: Database, chainKey: Buffer, email: string, passkeyId: string): Promise<string> {
  const token = generateToken('cli');
  const row = {
    id: randomUUID(), kind: 'cli', tokenHash: hashToken(token), generation: await generationOf(owner, email), tokenHint: tokenHint(token), principal: `user:${email}`,
    identityId: null, label: null, createdBy: email, expiresAt: new Date(Date.now() + 3_600_000), scope: null, places: null, revokedAt: null,
    passkeyId, confirmedAt: new Date(),
  };
  await owner.insert(credentials).values({ ...row, authMac: authMac(chainKey, 'credentials', row) });
  return token;
}

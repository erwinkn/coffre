// Passkey rows, and a session one confirmed, written as the app writes them
// (docs/design/passkeys.md, sections 5.1 and 5.2): what the sign-in's touch
// makes once T176 PR 4b lands, for the tests of what holds them before then.
import { randomBytes, randomUUID } from 'node:crypto';

import { generateToken, hashToken, tokenHint } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { eq } from 'drizzle-orm';

import { authMac } from '../src/auth-rows.ts';
import { memberStanding } from '../src/db/queries.ts';
import { credentials, passkeys } from './db/tables.ts';

async function generationOf(owner: Database, email: string): Promise<number> {
  return (await memberStanding(owner, `user:${email}`))!.generation;
}

/** A live passkey of `email`'s, at their generation; its id. */
export async function addPasskey(owner: Database, chainKey: Buffer, email: string): Promise<string> {
  const passkey = {
    id: randomUUID(), principal: `user:${email}`, generation: await generationOf(owner, email), userHandle: randomBytes(16), credentialId: randomBytes(32),
    publicKey: randomBytes(77), algorithm: -7, removedAt: null,
  };
  await owner.insert(passkeys).values({ ...passkey, synced: true, name: 'YubiKey 5C', createdBy: `user:${email}`, authMac: authMac(chainKey, 'passkeys', passkey) });
  return passkey.id;
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

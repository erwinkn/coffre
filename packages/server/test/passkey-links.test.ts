// What the schema allows a sign-in row to say of a passkey (0063_passkeys,
// docs/design/passkeys.md, section 5.2), on both engines: a device login
// names one only once approved, and only a browser or CLI session carries a
// touch. The MAC covers the link either way (auth-rows.test.ts); these
// checks make the rows the design rules out impossible to write at all.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { authMac } from '../src/auth-rows.ts';
import { contextFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';
import { credentials, deviceAuthorizations, passkeys } from './db/tables.ts';

const ROOT = 'admin@acme.example';
const KEY = Buffer.alloc(32, 0xa1);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let passkeyId: string;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await contextFor(testDeps(db.runtime, [ROOT]), ROOT);
  const passkey = {
    id: randomUUID(), principal: `user:${ROOT}`, generation: 1, userHandle: randomBytes(16), credentialId: randomBytes(32), publicKey: randomBytes(77),
    algorithm: -7, removedAt: null,
  };
  await db.owner.insert(passkeys).values({ ...passkey, synced: true, name: 'YubiKey 5C', createdBy: `user:${ROOT}`, authMac: authMac(KEY, 'passkeys', passkey) });
  passkeyId = passkey.id;
});

/** A statement the database refuses, by the constraint its cause names: drizzle wraps the driver's error. */
const refused = (attempt: Promise<unknown>, constraint: RegExp) =>
  assert.rejects(attempt, (error: Error) => constraint.test(String((error as { cause?: unknown }).cause ?? error)));

const device = (decision: 'approved' | 'denied' | null, named: string | null = passkeyId) => ({
  id: randomUUID(), deviceCodeHash: randomBytes(32), userCode: randomBytes(4).toString('hex'), clientLabel: null, clientIp: null,
  expiresAt: new Date(Date.now() + 600_000), decision, decidedAt: decision === null ? null : new Date(),
  principal: decision === 'approved' ? `user:${ROOT}` : null, generation: decision === 'approved' ? 1 : 0, consumedAt: null,
  passkeyId: named, authMac: randomBytes(32),
});

const credential = (kind: string, confirmedAt: Date | null) => ({
  id: randomUUID(), kind, tokenHash: randomBytes(32), tokenHint: 'coffre_…abcd', generation: 1, principal: `user:${ROOT}`, identityId: null,
  label: null, createdBy: `user:${ROOT}`, expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null,
  scope: kind === 'personal' ? '[]' : null, places: kind === 'handle' ? '[]' : null, passkeyId, confirmedAt, authMac: randomBytes(32),
});

test('a device login names a passkey only once approved: never while pending, never denied', async () => {
  for (const decision of [null, 'denied'] as const) {
    await refused(db.owner.insert(deviceAuthorizations).values(device(decision)), /device_authorizations_passkey_check/);
    await db.owner.insert(deviceAuthorizations).values(device(decision, null));
  }
  await db.owner.insert(deviceAuthorizations).values(device('approved'));
});

test('a touch is a browser or CLI session\'s alone: a token or handle copies the passkey, never the touch', async () => {
  for (const kind of ['personal', 'handle']) {
    await refused(db.owner.insert(credentials).values(credential(kind, new Date())), /credentials_confirmed_check/);
    await db.owner.insert(credentials).values(credential(kind, null));
  }
  for (const kind of ['browser', 'cli']) await db.owner.insert(credentials).values(credential(kind, new Date()));
});

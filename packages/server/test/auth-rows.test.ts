import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { authMac, signedAgain, signedBy } from '../src/auth-rows.ts';

// docs/design/passkeys.md, sections 5.1 and 5.2: what a passkey's MAC
// covers, and the kind a sign-in row takes when it names one. No database:
// the MAC is a function of the row.

const KEY = Buffer.alloc(32, 0xa1);
const OTHER = randomUUID();
const at = new Date('2026-11-04T10:02:00Z');

const passkey = {
  id: randomUUID(), principal: 'user:ada@acme.example', generation: 1, userHandle: randomBytes(16), credentialId: randomBytes(32),
  publicKey: randomBytes(77), algorithm: -7, removedAt: null as Date | null,
  // Bookkeeping, outside the MAC.
  signCount: 0, lastChallengeAt: null as Date | null, transports: '["usb"]', aaguid: null, synced: true, name: 'YubiKey 5C', lastUsedAt: null as Date | null,
};
const signedPasskey = { ...passkey, authMac: authMac(KEY, 'passkeys', passkey) };

test("a passkey's MAC covers whose it is, its handle, credential and key, and its removal; not its counter, replay mark, name or last use", () => {
  assert.ok(signedBy(KEY, 'passkeys', signedPasskey));
  const decides: Partial<typeof passkey>[] = [
    { id: randomUUID() }, { principal: 'user:bob@acme.example' }, { generation: 2 }, { userHandle: randomBytes(16) },
    { credentialId: randomBytes(32) }, { publicKey: randomBytes(77) }, { algorithm: -8 }, { removedAt: at },
  ];
  for (const change of decides) assert.equal(signedBy(KEY, 'passkeys', { ...signedPasskey, ...change }), false, Object.keys(change)[0]);
  const bookkeeping: Partial<typeof passkey>[] = [
    { signCount: 7 }, { lastChallengeAt: at }, { name: 'Laptop' }, { lastUsedAt: at }, { transports: '[]' }, { synced: false },
  ];
  for (const change of bookkeeping) assert.ok(signedBy(KEY, 'passkeys', { ...signedPasskey, ...change }), Object.keys(change)[0]);
  // A removal is signed again, as an app key's rotation signs it again.
  const removed = signedAgain(KEY, KEY, 'passkeys', signedPasskey, { removedAt: at });
  assert.ok(removed && signedBy(KEY, 'passkeys', { ...signedPasskey, removedAt: at, authMac: removed }));
});

const credential = {
  id: randomUUID(), tokenHash: randomBytes(32), kind: 'browser', principal: 'user:ada@acme.example', generation: 1, identityId: randomUUID(),
  expiresAt: at, revokedAt: null, createdBy: 'user:ada@acme.example', scope: null, places: null,
};
const device = {
  id: randomUUID(), deviceCodeHash: randomBytes(32), userCode: 'ABCD-EFGH', decision: 'approved', decidedAt: at, principal: 'user:ada@acme.example',
  generation: 1, expiresAt: at, consumedAt: null,
};
const connection = {
  id: randomUUID(), principal: 'user:ada@acme.example', generation: 1, clientId: 'https://claude.ai/client.json', clientName: 'Claude', clientHost: 'claude.ai',
  registration: 'cimd', scopes: 'read', redirectUri: 'https://claude.ai/callback', codeHash: null, codeChallenge: null, codeExpiresAt: null,
  refreshHash: randomBytes(32), refreshPreviousHash: null, expiresAt: at, revokedAt: null,
};

test('a sign-in row that names no passkey signs as before passkeys, whether the field is null or absent', () => {
  const rows = [['credentials', credential], ['device_authorizations', device], ['mcp_connections', connection]] as const;
  for (const [table, row] of rows) {
    const before = authMac(KEY, table, row as never);
    assert.deepEqual(authMac(KEY, table, { ...row, passkeyId: null, confirmedAt: null } as never), before, table);
  }
});

test('a row that names a passkey is a kind of its own: naming one, clearing it or swapping it, or its touch, fails the MAC', () => {
  const confirmed = { ...credential, passkeyId: passkey.id, confirmedAt: at };
  const signed = { ...confirmed, authMac: authMac(KEY, 'credentials', confirmed) };
  assert.ok(signedBy(KEY, 'credentials', signed));
  for (const change of [{ passkeyId: null }, { passkeyId: OTHER }, { confirmedAt: null }, { confirmedAt: new Date(at.getTime() + 60_000) }]) {
    assert.equal(signedBy(KEY, 'credentials', { ...signed, ...change }), false, JSON.stringify(change));
  }
  // A session made with none, named afterwards, fails too: a writer cannot vouch a passkey for it.
  const plain = { ...credential, authMac: authMac(KEY, 'credentials', { ...credential, passkeyId: null, confirmedAt: null }) };
  assert.equal(signedBy(KEY, 'credentials', { ...plain, passkeyId: passkey.id, confirmedAt: at }), false);
  assert.equal(signedBy(KEY, 'credentials', { ...plain, passkeyId: passkey.id, confirmedAt: null }), false);

  // A token a confirmed session made carries the passkey alone; a workload's session, its own kind, is covered too.
  for (const row of [{ ...credential, kind: 'personal', scope: '{}' }, { ...credential, kind: 'handle', places: '[]' }, { ...credential, kind: 'workload', principal: 'token:ci', identityId: null, jkt: 'k', notAfter: at, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null }]) {
    const named = { ...row, passkeyId: passkey.id, confirmedAt: null };
    const mac = authMac(KEY, 'credentials', named);
    assert.notDeepEqual(mac, authMac(KEY, 'credentials', { ...row, passkeyId: null, confirmedAt: null }), row.kind);
    assert.equal(signedBy(KEY, 'credentials', { ...named, passkeyId: OTHER, authMac: mac }), false, row.kind);
  }

  for (const [table, row] of [['device_authorizations', device], ['mcp_connections', connection]] as const) {
    const named = { ...row, passkeyId: passkey.id };
    const mac = authMac(KEY, table, named as never);
    assert.ok(signedBy(KEY, table, { ...named, authMac: mac } as never), table);
    for (const passkeyId of [null, OTHER]) assert.equal(signedBy(KEY, table, { ...named, passkeyId, authMac: mac } as never), false, table);
    assert.equal(signedBy(KEY, table, { ...row, passkeyId: passkey.id, authMac: authMac(KEY, table, row as never) } as never), false, table);
  }
});

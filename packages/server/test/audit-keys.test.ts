// GET /audit/keys: what `coffre verify keys` holds an escrowed key to, on
// the operator's machine. Public check material, and nothing more, for
// owners and root admins alone.
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { appLogKeyId, opensKeyCheck } from '@coffre/core/kek';

import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';

const db = await openTestDatabase();
const deps = testDeps(db.runtime, ['root@acme.example']);
const root = clientFor(deps, 'root@acme.example');
beforeEach(() => resetDatabase(db.owner));
after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

test("a root admin reads the app key's id, the vault key now, and its check, which opens only under that key", async () => {
  const keys = await root.audit.keys();
  assert.deepEqual(keys.app, { keyId: appLogKeyId(deps.chainKey) });
  assert.deepEqual(keys.vault.current, { vaultId: 'test-kek-1', provider: 'local' });
  assert.equal(keys.vault.checks.length, 1);
  const [check] = keys.vault.checks;
  assert.deepEqual(Object.keys(check!).sort(), ['provider', 'seq', 'vaultId', 'version', 'wrapped']);
  const wrapped = { kekProvider: check!.provider, kekId: check!.vaultId, kekVersion: check!.version, bytes: Buffer.from(check!.wrapped, 'base64') };
  assert.equal(await opensKeyCheck(deps.vault.kek, wrapped), true);
  assert.equal(await opensKeyCheck(randomBytes(32), wrapped), false);
  // The check is the vault's own entry, in the log as every other.
  const { entries } = await root.audit.list({ detail: '1', limit: 50 });
  assert.ok(entries.some((entry) => entry.seq === check!.seq && entry.action === 'key.check'));
});

test('an instance owner reads them too; a user, a project owner or a service is refused', async () => {
  await root.members.add('user:owner@acme.example', { owner: true });
  await root.members.add('user:lead@acme.example');
  await root.members.add('token:ci');
  await root.projects.create('market', { name: 'Market' });
  await root.access.set('user:lead@acme.example', { market: 'owner' });
  assert.equal((await clientFor(deps, 'owner@acme.example').audit.keys()).vault.current.vaultId, 'test-kek-1');
  for (const refused of [clientFor(deps, 'lead@acme.example'), clientFor(deps, 'ci', 'service'), clientFor(deps, 'nobody@acme.example')]) {
    await assert.rejects(refused.audit.keys(), { status: 403 });
  }
});

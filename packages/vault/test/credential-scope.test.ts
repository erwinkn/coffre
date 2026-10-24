import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { issuedGrant, type CredentialScope } from '@coffre/core/access';
import type { Through } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { eq } from 'drizzle-orm';

import { emptyDatabase, newEnvironment, newProject, openTestDatabase, places, storedVersions, type TestDatabase, openLocalVault } from './database.ts';

// A request that came in on a service token or a trust binding carries its
// scope, and the vault decides on it in every call that takes one (`Through`):
// the account holds nothing past it. The app applies it too; this holds the
// vault to it on its own (docs/design/instance-roles.md, "Credentials' scopes").

const ROOT = 'user:root@acme.example';
const BO = 'user:bo@acme.example';
/** Owner of market and of billing: reads, writes and manages access in both. */
const CI = 'token:ci';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

test('every call that takes a credential scope decides on it: within it a call goes through, past it the account holds nothing, and a malformed one fails the call', async () => {
  const vault = await openLocalVault(db.vault, {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  });
  // Root signs in first, and the bootstrap makes them the Owner.
  await vault.access(ROOT);
  const market = await places(db.owner);
  const billing = await newProject(db.owner);
  const billingProd = await newEnvironment(db.owner, billing);
  for (const principal of [CI, BO]) assert.ok((await vault.admit({ actor: ROOT, principal })).ok);
  const granted = await vault.setAccess({
    actor: ROOT,
    principal: CI,
    changes: [market.project, billing].map((projectId) => ({ projectId, environmentId: null, role: 'owner' as const, expiresAt: null })),
  });
  assert.ok(granted.ok, JSON.stringify(granted));
  const source = await market.secret(market.prod);
  const key = await vault.wrap({ principal: ROOT, items: [{ secret: source, key: randomBytes(32).toString('base64') }] });
  assert.ok(key.ok);
  const [{ secretVersionId }] = await storedVersions(db.owner, [{ secret: source, wrapped: key.wrapped[0] }]);
  const { secrets } = tablesOf(db.owner);
  await db.owner.update(secrets).set({ currentVersionId: secretVersionId, currentVersion: 1 }).where(eq(secrets.id, source.secretId));
  const holder = () => ({ projectId: billing, environmentId: billingProd, secretId: randomUUID(), path: 'billing/prod/DATABASE_URL' });
  /** A reference into billing/prod, made by root: one for each call that ends one. */
  const reference = async () => {
    const id = randomUUID();
    const made = await vault.reference({ principal: ROOT, items: [{ id, holder: holder(), source: { secretId: source.secretId } }] });
    assert.ok(made.ok, JSON.stringify(made));
    return { reference: id, seq: made.seqs[0]! };
  };

  const marketOwner: CredentialScope = [issuedGrant({ projectId: market.project, environmentId: null, role: 'owner' })];
  const both: CredentialScope = [...marketOwner, issuedGrant({ projectId: billing, environmentId: null, role: 'owner' })];
  const devViewer: CredentialScope = [issuedGrant({ projectId: market.project, environmentId: market.dev, role: 'viewer' })];
  const marketViewer: CredentialScope = [issuedGrant({ projectId: market.project, environmentId: null, role: 'viewer' })];

  /** Each call, as CI with `through`: the scope that lets it through and one that does not, or none for those no service account makes. */
  const calls: { name: string; call: (through: Partial<Through>) => Promise<{ ok: boolean }>; within?: CredentialScope; past?: CredentialScope }[] = [
    {
      name: 'unwrap',
      call: (through) => vault.unwrap({ principal: CI, purpose: 'reveal', items: [{ secretVersionId }], ...through }),
      within: marketViewer,
      past: devViewer,
    },
    {
      name: 'wrap',
      call: async (through) => vault.wrap({ principal: CI, items: [{ secret: await market.secret(market.prod), key: randomBytes(32).toString('base64') }], ...through }),
      within: marketOwner,
      past: marketViewer,
    },
    {
      name: 'rewrap',
      call: (through) => vault.rewrap({ principal: CI, items: [{ secret: { ...source, version: 2 }, secretVersionId }], ...through }),
      within: marketOwner,
      past: devViewer,
    },
    {
      name: 'reference',
      call: (through) => vault.reference({ principal: CI, items: [{ id: randomUUID(), holder: holder(), source: { secretId: source.secretId } }], ...through }),
      within: both,
      past: marketOwner,
    },
    {
      name: 'endReferences',
      call: async (through) => vault.endReferences({ principal: CI, reason: 'replaced', items: [await reference()], ...through }),
      within: both,
      past: marketOwner,
    },
    {
      name: 'setAccess',
      call: (through) => vault.setAccess({ actor: CI, principal: BO, changes: [{ projectId: market.project, environmentId: market.dev, role: 'viewer', expiresAt: null }], ...through }),
      within: marketOwner,
      past: marketViewer,
    },
    { name: 'admit', call: (through) => vault.admit({ actor: CI, principal: 'token:other', ...through }) },
    { name: 'remove', call: (through) => vault.remove({ actor: CI, principal: BO, ...through }) },
    { name: 'setSettings', call: (through) => vault.setSettings({ actor: CI, settings: { serviceAccounts: { projects: 'all', environments: 'all' } }, ...through }) },
  ];

  for (const { name, call, within, past } of calls) {
    for (const malformed of ['all', [{ projectId: market.project, environmentId: null, role: 'root' }], [...marketOwner, ...marketOwner]]) {
      await assert.rejects(call({ credentialScope: malformed as never }), /credentialScope must be a list of grants/, `${name}: ${JSON.stringify(malformed)}`);
    }
    // A workload is held to what its scope lists: one with none is the app's bug, and so is a kind its principal is not.
    for (const credentialScope of [undefined, null]) {
      await assert.rejects(call({ caller: 'workload', credentialScope }), /a workload caller comes with its credential scope/, `${name}: a workload with no scope`);
    }
    await assert.rejects(call({ caller: 'person', credentialScope: marketOwner }), /caller must be person for a user: principal/, `${name}: a service as a person`);
    await assert.rejects(call({ caller: 'admin' as never, credentialScope: marketOwner }), /caller must be/, `${name}: no kind of caller`);
    if (within === undefined || past === undefined) continue;
    assert.equal((await call({ credentialScope: within })).ok, true, `${name}, within its scope`);
    assert.equal((await call({ credentialScope: null })).ok, true, `${name}, a session's`);
    const refused = await call({ credentialScope: past });
    assert.equal(refused.ok, false, `${name}, past its scope`);
    assert.equal((await call({ credentialScope: [] })).ok, false, `${name}, a scope of nothing`);
  }
});

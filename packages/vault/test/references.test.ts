import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { HolderRef, SecretRef, Via } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { appendEntries } from '@coffre/db/log';
import { and, asc, eq, gte } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault, type LocalVault } from '../src/local.ts';
import { emptyDatabase, newEnvironment, newProject, openTestDatabase, places, storedVersions, type TestDatabase } from './database.ts';

// References (docs/design/environments.md): the vault's `reference.create`
// entry is the reference, and a read through one is checked against it.

const ROOT = 'user:root@acme.example';
/** Reads market (the source's project) and writes billing (the holder's). */
const ADA = 'user:ada@acme.example';
/** Reads billing, and nothing in market. */
const BO = 'user:bo@acme.example';
/** Manages market's access, and reads nothing. */
const MAX = 'user:max@acme.example';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

const config = (): ResolvedVaultConfig => ({
  keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
  rootAdmins: ['root@acme.example'],
  signingKeys: [randomBytes(32)],
  bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
});

/** market/prod/DATABASE_URL, a value; billing/prod, where references are held; and the three people. */
async function world() {
  const vault: LocalVault = await openLocalVault(db.vault, config());
  const market = await places(db.owner);
  const billing = await newProject(db.owner);
  const billingProd = await newEnvironment(db.owner, billing);
  const source = await market.secret(market.prod);
  const key = await vault.wrap({ principal: ROOT, items: [{ secret: source, key: randomBytes(32).toString('base64') }] });
  assert.ok(key.ok);
  const [{ secretVersionId }] = await storedVersions(db.owner, [{ secret: source, wrapped: key.wrapped[0] }]);
  const { secrets } = tablesOf(db.owner);
  await db.owner.update(secrets).set({ currentVersionId: secretVersionId, currentVersion: 1 }).where(eq(secrets.id, source.secretId));
  for (const [principal, changes] of [
    [ADA, [{ projectId: market.project, environmentId: market.prod, role: 'viewer' }, { projectId: billing, environmentId: null, role: 'developer' }]],
    [BO, [{ projectId: billing, environmentId: billingProd, role: 'viewer' }]],
    [MAX, [{ projectId: market.project, environmentId: null, role: 'access-manager' }]],
  ] as const) {
    assert.ok((await vault.admit({ actor: ROOT, principal })).ok);
    const set = await vault.setAccess({ actor: ROOT, principal, changes: changes.map((change) => ({ ...change, expiresAt: null })) });
    assert.ok(set.ok, JSON.stringify(set));
  }
  const holder = (key = 'DATABASE_URL'): HolderRef => ({ projectId: billing, environmentId: billingProd, secretId: randomUUID(), path: `billing/prod/${key}` });
  return { vault, market, billing, billingProd, source, secretVersionId, holder };
}

type World = Awaited<ReturnType<typeof world>>;

async function made(w: World, principal = ADA, holder = w.holder()): Promise<{ via: Via; holder: HolderRef }> {
  const id = randomUUID();
  const result = await w.vault.reference({ principal, items: [{ id, holder, source: { secretId: w.source.secretId } }] });
  assert.ok(result.ok, JSON.stringify(result));
  return { via: { reference: id, seq: result.seqs[0]! }, holder };
}

const read = (w: World, principal: string, via?: Via, secretVersionId = w.secretVersionId) =>
  w.vault.unwrap({ principal, purpose: 'run', items: [{ secretVersionId, ...(via === undefined ? {} : { via }) }] });

async function vaultEntries(action: string, from = 0n) {
  const { auditLog } = tablesOf(db.owner);
  const rows = await db.owner.select().from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, action), gte(auditLog.seq, from)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test("a reader of the holder's environment reads the source through a reference, logged as a read of the source", async () => {
  const w = await world();
  assert.deepEqual(await read(w, BO).then((result) => result.ok || result.refusal.code), 'no_grant');
  const { via, holder } = await made(w);
  const through = await read(w, BO, via);
  assert.ok(through.ok, JSON.stringify(through));

  const [create] = await vaultEntries('reference.create');
  assert.deepEqual([create!.actor, create!.projectId, create!.environmentId, create!.secretId], [ADA, w.billing, w.billingProd, null]);
  assert.deepEqual(create!.metadata, {
    reference: via.reference, subject: holder.path, secretId: holder.secretId, source: { path: w.source.path },
    also: { projectId: w.market.project, environmentId: w.market.prod, secretId: w.source.secretId },
  });
  const reads = (await vaultEntries('secret.read')).filter((entry) => entry.decision === 'allow');
  assert.equal(reads.length, 1);
  const [entry] = reads;
  // The read is of the source, at its version: the source's history and offboarding count it.
  assert.deepEqual([entry!.actor, entry!.projectId, entry!.secretId, entry!.secretVersionId], [BO, w.market.project, w.source.secretId, w.secretVersionId]);
  assert.deepEqual(entry!.metadata.via, { reference: via.reference, seq: via.seq, path: holder.path, createdBy: ADA, createdAt: new Date(create!.occurredAt).toISOString() });
  assert.deepEqual(entry!.metadata.also, { projectId: w.billing, environmentId: w.billingProd, secretId: holder.secretId });
});

test('making a reference takes read on the source and write on the holder, by your own grants', async () => {
  const w = await world();
  const ask = (principal: string) => w.vault.reference({ principal, items: [{ id: randomUUID(), holder: w.holder(), source: { secretId: w.source.secretId } }] });
  // Bo reads billing but writes nothing, and has no grant in market; Max manages market's access but reads nothing.
  assert.deepEqual(await ask(BO).then((result) => result.ok || result.refusal.code), 'no_grant');
  assert.deepEqual(await ask(MAX).then((result) => result.ok || result.refusal.code), 'no_grant');
  // Bo reading market's value through a reference is no read on market for making another.
  const { via } = await made(w);
  assert.ok((await read(w, BO, via)).ok);
  assert.deepEqual(await ask(BO).then((result) => result.ok || result.refusal.code), 'no_grant');
  // A holder named in another project than its environment's is no holder.
  const lying = { ...w.holder(), projectId: w.market.project };
  const refused = await w.vault.reference({ principal: ROOT, items: [{ id: randomUUID(), holder: lying, source: { secretId: w.source.secretId } }] });
  assert.deepEqual(refused.ok || refused.refusal.code, 'bad_claim');
  // Nor a secret its own source.
  const self = { ...w.holder(), projectId: w.market.project, environmentId: w.market.prod, secretId: w.source.secretId };
  const itself = await w.vault.reference({ principal: ROOT, items: [{ id: randomUUID(), holder: self, source: { secretId: w.source.secretId } }] });
  assert.deepEqual(itself.ok || itself.refusal.code, 'invalid');
  assert.deepEqual((await vaultEntries('reference.create')).map((entry) => [entry.actor, entry.decision, entry.code]), [
    [BO, 'deny', 'no_grant'], [MAX, 'deny', 'no_grant'], [ADA, 'allow', null], [BO, 'deny', 'no_grant'], [ROOT, 'deny', 'bad_claim'], [ROOT, 'deny', 'invalid'],
  ]);
});

test('a reference the vault did not make is refused: no entry, another one, a forged one, or another secret', async () => {
  const w = await world();
  const { via } = await made(w);
  const refusedAs = async (claim: Via, secretVersionId = w.secretVersionId) => {
    const result = await read(w, BO, claim, secretVersionId);
    return result.ok ? 'released' : result.refusal.code;
  };
  // An entry that is no reference: Ada's grant.
  const [grant] = await vaultEntries('access.grant');
  assert.equal(await refusedAs({ reference: via.reference, seq: Number(grant!.seq) }), 'bad_claim');
  // The genuine entry, claimed as another reference.
  assert.equal(await refusedAs({ reference: randomUUID(), seq: via.seq }), 'bad_claim');
  // An entry written in the vault's name under a key it does not hold.
  const forger = deriveLogKey('vault', randomBytes(32));
  const create = (await vaultEntries('reference.create'))[0]!;
  const forged = await db.vault.transaction((tx) => appendEntries(tx, forger, [{
    actor: ADA, action: 'reference.create', decision: 'allow', projectId: w.billing, environmentId: w.billingProd, metadata: JSON.stringify({ ...create.metadata, reference: via.reference }),
  }]));
  assert.equal(await refusedAs({ reference: via.reference, seq: Number(forged.seqStart) }), 'bad_claim');
  // The genuine reference, presented with another secret's version.
  const other = await w.market.secret(w.market.prod, 'OTHER');
  const key = await w.vault.wrap({ principal: ROOT, items: [{ secret: other, key: randomBytes(32).toString('base64') }] });
  assert.ok(key.ok);
  const [stored] = await storedVersions(db.owner, [{ secret: other, wrapped: key.wrapped[0] }]);
  assert.equal(await refusedAs(via, stored!.secretVersionId), 'bad_claim');
  // A version of the source that is not its current one.
  const { secrets } = tablesOf(db.owner);
  await db.owner.update(secrets).set({ currentVersionId: null }).where(eq(secrets.id, w.source.secretId));
  assert.equal(await refusedAs(via), 'bad_claim');
  await db.owner.update(secrets).set({ currentVersionId: w.secretVersionId }).where(eq(secrets.id, w.source.secretId));
  assert.ok((await read(w, BO, via)).ok, 'the genuine reference still reads');
});

test("a reference ends for good: broken by the source's access manager, or replaced by the holder's writer", async () => {
  const w = await world();
  const first = await made(w);
  const end = (principal: string, reason: 'broken' | 'replaced', via: Via) => w.vault.endReferences({ principal, reason, items: [via] });
  // Max manages market's access: he breaks a reference into it, but replaces nothing in billing.
  assert.deepEqual(await end(MAX, 'replaced', first.via).then((result) => result.ok || result.refusal.code), 'no_grant');
  assert.deepEqual(await end(BO, 'broken', first.via).then((result) => result.ok || result.refusal.code), 'no_grant');
  const broken = await end(MAX, 'broken', first.via);
  assert.ok(broken.ok, JSON.stringify(broken));
  assert.deepEqual(await read(w, BO, first.via).then((result) => result.ok || result.refusal.code), 'ended');
  assert.deepEqual(await end(ROOT, 'broken', first.via).then((result) => result.ok || result.refusal.code), 'ended');

  // Ada, who writes billing, replaces another; it names its creation, and the reason.
  const second = await made(w);
  assert.ok((await end(ADA, 'replaced', second.via)).ok);
  assert.deepEqual(await read(w, BO, second.via).then((result) => result.ok || result.refusal.code), 'ended');
  const ends = (await vaultEntries('reference.end')).filter((entry) => entry.decision === 'allow');
  assert.deepEqual(ends.map((entry) => [entry.actor, Number(entry.relatedSeq), entry.metadata.reason, entry.projectId]), [
    [MAX, first.via.seq, 'broken', w.billing],
    [ADA, second.via.seq, 'replaced', w.billing],
  ]);
  assert.deepEqual(ends[0]!.metadata.also, { projectId: w.market.project, environmentId: w.market.prod, secretId: w.source.secretId });
  // These holders' rows were never written, as when the app's write after the seal fails: no end names a key that is not there.
  assert.deepEqual(ends.map((entry) => entry.secretId), [null, null]);
});

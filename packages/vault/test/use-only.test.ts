import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { issuedGrant, type CredentialScope, type ScopeGrant } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { HolderRef, Purpose, SecretRef, Via } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { and, eq } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { emptyDatabase, openLocalVault, openTestDatabase, places, sealPlaces, storedVersions, type LocalVault, type TestDatabase } from './database.ts';

// A workload is handed back only what its credential lists, by key ID,
// where each value is held (docs/design/workload-access.md, section 6.1):
// the vault refuses anything else `use_only`, whatever the request names,
// a reference's holder or a fork, and whatever a copy would make of it.

const ROOT = 'user:root@acme.example';
const API = 'token:api';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

const config = (): ResolvedVaultConfig => ({
  keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
  owners: ['root@acme.example'],
  signingKeys: [randomBytes(32)],
  bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
});

/**
 * market/prod holds STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET, secrets,
 * and DATABASE_URL, sensitive; market/dev is empty; api, a service, is a
 * viewer of market and a developer of market/dev, issued by an Owner.
 */
async function world() {
  const vault: LocalVault = await openLocalVault(db.vault, config());
  await vault.access(ROOT);
  const market = await places(db.owner);
  const stored = async (secret: SecretRef) => {
    const key = await vault.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] });
    assert.ok(key.ok, JSON.stringify(key));
    const [{ secretVersionId }] = await storedVersions(db.owner, [{ secret, wrapped: key.wrapped[0]! }]);
    const { secrets } = tablesOf(db.owner);
    await db.owner.update(secrets).set({ currentVersionId: secretVersionId, currentVersion: 1 }).where(eq(secrets.id, secret.secretId));
    return { secret, secretVersionId };
  };
  const stripe = await stored(await market.secret(market.prod, 'STRIPE_SECRET_KEY'));
  const webhook = await stored(await market.secret(market.prod, 'STRIPE_WEBHOOK_SECRET'));
  const database = await stored({ ...await market.secret(market.prod), sensitive: true });
  assert.ok((await vault.admit({ actor: ROOT, principal: API })).ok);
  const granted = await vault.setAccess({
    actor: ROOT,
    principal: API,
    changes: [
      { projectId: market.project, environmentId: null, role: 'viewer', expiresAt: null },
      { projectId: market.project, environmentId: market.dev, role: 'developer', expiresAt: null },
    ],
  });
  assert.ok(granted.ok, JSON.stringify(granted));
  const viewer: ScopeGrant = { ...issuedGrant({ projectId: market.project, environmentId: null, role: 'viewer' }), sensitive: true };
  const developer: ScopeGrant = { ...issuedGrant({ projectId: market.project, environmentId: market.dev, role: 'developer' }), sensitive: true };
  /** The scope, with `prod` and `dev` listing those keys, or every one for `'*'`. */
  const scope = (prod?: readonly string[] | '*', dev?: readonly string[] | '*'): CredentialScope => [
    viewer,
    { ...developer, ...(dev === undefined ? {} : { reads: dev }) },
    ...(prod === undefined ? [] : [{ ...issuedGrant({ projectId: market.project, environmentId: market.prod, role: 'viewer' }), sensitive: true, reads: prod }]),
  ];
  return { vault, market, stripe, webhook, database, scope };
}

type World = Awaited<ReturnType<typeof world>>;

/** One read as the workload, with `scope`: true, or why it was refused. */
async function read(w: World, credentialScope: CredentialScope | undefined, purpose: Purpose, items: { secretVersionId: string; via?: Via; through?: string }[], keepsSensitive?: boolean) {
  const asked = items.map(({ secretVersionId, via, through }) => ({ secretVersionId, ...(via === undefined ? {} : { via }), ...(through === undefined ? {} : { through }) }));
  const result = await w.vault.unwrap({ principal: API, caller: 'workload', credentialScope, purpose, items: asked, ...(keepsSensitive === undefined ? {} : { keepsSensitive }) });
  return result.ok || result.refusal.code;
}

/** A reference made by root at market/dev to `source`. */
async function referred(w: World, source: SecretRef): Promise<Via> {
  const holder: HolderRef = { projectId: w.market.project, environmentId: w.market.dev, secretId: randomUUID(), path: 'market/dev/S' };
  const id = randomUUID();
  const made = await w.vault.reference({ principal: ROOT, items: [{ id, holder, source: { secretId: source.secretId } }] });
  assert.ok(made.ok, JSON.stringify(made));
  return { reference: id, seq: made.seqs[0]! };
}

test('a workload reads only the keys its scope lists where they are held, by ID; it uses every other', async () => {
  const w = await world();
  const { stripe, webhook } = w;
  const listed = w.scope([webhook.secret.secretId]);
  assert.equal(await read(w, listed, 'reveal', [webhook]), true);
  assert.equal(await read(w, listed, 'reveal', [stripe]), 'use_only');
  assert.equal(await read(w, listed, 'run', [webhook, stripe]), 'use_only', 'refused whole, as every read');
  // Every purpose that hands a value back: a dry run's compare tells whether a guess was right, the plan exposes it.
  for (const purpose of ['compare', 'expose', 'copy'] as const) assert.equal(await read(w, listed, purpose, [stripe]), 'use_only', purpose);
  assert.equal(await read(w, listed, 'copy', [stripe], true), 'use_only', 'a copy kept sensitive lands where the workload may read it all the same');
  // The proxy uses it, and never hands it back.
  assert.equal(await read(w, listed, 'use', [stripe]), true);
  assert.equal(await read(w, w.scope('*'), 'run', [webhook, stripe]), true, "'*' lists every key of the place");
  assert.equal(await read(w, w.scope(), 'reveal', [webhook]), 'use_only', 'a scope that lists nothing reads nothing');

  // A bearer on the same scope reads it, as before: only a workload is held to its list.
  const bearer = await w.vault.unwrap({ principal: API, caller: 'bearer', credentialScope: listed, purpose: 'reveal', items: [{ secretVersionId: stripe.secretVersionId }] });
  assert.ok(bearer.ok, JSON.stringify(bearer));

  // Each refusal is the vault's entry, of the key it withheld.
  const { auditLog } = tablesOf(db.owner);
  const denied = await db.owner.select().from(auditLog).where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read'), eq(auditLog.code, 'use_only')));
  assert.ok(denied.length > 0 && denied.every((entry) => entry.actor === API && entry.decision === 'deny'));
});

test('a sensitive key a workload lists still needs an Owner to have issued its scope', async () => {
  const w = await world();
  const { database } = w;
  assert.equal(await read(w, w.scope([database.secret.secretId]), 'reveal', [database]), true);
  const notOwners = w.scope([database.secret.secretId]).map(({ sensitive: _, ...grant }) => grant);
  assert.equal(await read(w, notOwners, 'reveal', [database]), 'not_owner_issued');
  assert.equal(await read(w, notOwners.map(({ reads: _, ...grant }) => grant), 'reveal', [database]), 'use_only', 'unlisted, it is used first');
});

test('through a reference, the source is where its value is held: a list at the holder reads nothing of it', async () => {
  const w = await world();
  const via = await referred(w, w.stripe.secret);
  // market/dev/S, a reference to market/prod/STRIPE_SECRET_KEY, is not readable through a "*" listed for market/dev.
  assert.equal(await read(w, w.scope(undefined, '*'), 'reveal', [{ secretVersionId: w.stripe.secretVersionId, via }]), 'use_only');
  assert.equal(await read(w, w.scope(undefined, '*'), 'use', [{ secretVersionId: w.stripe.secretVersionId, via }]), true);
  assert.equal(await read(w, w.scope([w.stripe.secret.secretId]), 'reveal', [{ secretVersionId: w.stripe.secretVersionId, via }]), true, 'listed at its source');
});

test("a fork's inherited key is read at its parent: a list at the fork reads nothing of it", async () => {
  const w = await world();
  const { environments } = tablesOf(db.owner);
  const fork = randomUUID();
  await db.owner.insert(environments).values({ id: fork, projectId: w.market.project, slug: 'pr-7', name: 'pr-7', parentId: w.market.prod });
  await sealPlaces(db.owner, [{ id: fork, projectId: w.market.project, slug: 'pr-7', parentId: w.market.prod }]);
  const granted = await w.vault.setAccess({ actor: ROOT, principal: API, changes: [{ projectId: w.market.project, environmentId: fork, role: 'viewer', expiresAt: null }] });
  assert.ok(granted.ok, JSON.stringify(granted));
  const atFork = [...w.scope(), { ...issuedGrant({ projectId: w.market.project, environmentId: fork, role: 'viewer' }), reads: '*' as const }];
  assert.equal(await read(w, atFork, 'reveal', [{ secretVersionId: w.stripe.secretVersionId, through: fork }]), 'use_only');
  assert.equal(await read(w, [...w.scope([w.stripe.secret.secretId]), atFork[2]!], 'reveal', [{ secretVersionId: w.stripe.secretVersionId, through: fork }]), true);
});

test('a workload refers only to a value it lists where it is held', async () => {
  const w = await world();
  const refer = async (credentialScope: CredentialScope, source: SecretRef) => {
    const holder: HolderRef = { projectId: w.market.project, environmentId: w.market.dev, secretId: randomUUID(), path: 'market/dev/S' };
    const made = await w.vault.reference({ principal: API, caller: 'workload', credentialScope, items: [{ id: randomUUID(), holder, source: { secretId: source.secretId } }] });
    return made.ok || made.refusal.code;
  };
  // "*" at market/dev, where it would hold the reference, and would then read what it moved there: refused.
  assert.equal(await refer(w.scope(undefined, '*'), w.stripe.secret), 'use_only');
  assert.equal(await refer(w.scope([w.webhook.secret.secretId], '*'), w.stripe.secret), 'use_only');
  assert.equal(await refer(w.scope([w.stripe.secret.secretId], '*'), w.stripe.secret), true);
  // A bearer refers to what it reads, as before.
  const holder: HolderRef = { projectId: w.market.project, environmentId: w.market.dev, secretId: randomUUID(), path: 'market/dev/T' };
  const bearer = await w.vault.reference({ principal: API, caller: 'bearer', credentialScope: w.scope(), items: [{ id: randomUUID(), holder, source: { secretId: w.stripe.secret.secretId } }] });
  assert.ok(bearer.ok, JSON.stringify(bearer));
});

test('a workload with no scope is refused outright: nothing would say what it reads', async () => {
  const w = await world();
  const items = [{ secretVersionId: w.stripe.secretVersionId }];
  await assert.rejects(w.vault.unwrap({ principal: API, caller: 'workload', purpose: 'use', items }), /a workload caller comes with its credential scope/);
  await assert.rejects(w.vault.unwrap({ principal: ROOT, caller: 'workload', credentialScope: w.scope('*'), purpose: 'use', items }), /caller must be person for a user: principal/);
  // An app older than 0.11 says no caller, and has no workload: decided as before.
  const older = await w.vault.unwrap({ principal: API, caller: undefined, credentialScope: w.scope(), purpose: 'reveal', items });
  assert.ok(older.ok, JSON.stringify(older));
});

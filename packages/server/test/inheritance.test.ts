import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog, environments, projects, secretReferences, secrets, secretVersions } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

/**
 * Forks that inherit (docs/design/forking.md): an environment with a
 * parent reads its parent's keys live, but for those it sets or removes,
 * and a fork lends nothing: an inherited value is read by the reader's own
 * grants on the parent, and logged there and in the fork.
 */

const ROOT = 'admin@acme.example';
const MAINTAINER = 'maintainer@acme.example';
const ADA = 'ada@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let maintainer: CoffreClient;
let ada: CoffreClient;
let firstSeq: bigint;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  maintainer = clientFor(deps, MAINTAINER);
  ada = clientFor(deps, ADA);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.members.add(`user:${MAINTAINER}`);
  await root.members.add(`user:${ADA}`);
  await root.access.set(`user:${MAINTAINER}`, { market: 'maintainer' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://prod', STRIPE_KEY: 'sk_live_1', SENTRY_DSN: 'https://sentry/prod' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

async function entries(author: 'app' | 'vault', action: string) {
  const rows = await db.owner
    .select({ actor: auditLog.actor, decision: auditLog.decision, code: auditLog.code, projectId: auditLog.projectId, environmentId: auditLog.environmentId, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

/** An environment's id, by its path, `market/prod`, or its slug in market. */
async function environmentId(path: string): Promise<string> {
  const [project, slug] = path.includes('/') ? path.split('/') : ['market', path];
  const [row] = await db.owner
    .select({ id: environments.id })
    .from(environments)
    .innerJoin(projects, eq(projects.id, environments.projectId))
    .where(and(eq(projects.slug, project), eq(environments.slug, slug)));
  return row.id;
}

const values = async (client: CoffreClient, path: string) => ({ ...(await client.secrets.reveal(path)).values });

test('a fork that inherits copies nothing, and reads its parent live: a changed value, a new key', async () => {
  const versions = (await db.owner.select().from(secretVersions)).length;
  const made = await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  assert.deepEqual([made.created, made.forked], [true, { from: 'prod', keys: 0, references: 0, copied: [], inherits: true }]);
  assert.equal((await db.owner.select().from(secretVersions)).length, versions);
  assert.deepEqual((await entries('app', 'environment.create')).map((entry) => entry.metadata), [
    { slug: 'prod-eu', name: 'prod-eu', from: 'prod', inherits: 'prod' },
  ]);

  assert.deepEqual(await values(maintainer, 'market/prod-eu'), { DATABASE_URL: 'postgres://prod', SENTRY_DSN: 'https://sentry/prod', STRIPE_KEY: 'sk_live_1' });
  await root.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2', NEW_KEY: 'new' });
  assert.deepEqual(await values(maintainer, 'market/prod-eu'), {
    DATABASE_URL: 'postgres://prod',
    NEW_KEY: 'new',
    SENTRY_DSN: 'https://sentry/prod',
    STRIPE_KEY: 'sk_live_2',
  });
  // One inherited key, by its path in the fork.
  assert.deepEqual(await values(maintainer, 'market/prod-eu/STRIPE_KEY'), { STRIPE_KEY: 'sk_live_2' });
});

test('a fork sets, adds and removes keys of its own; archiving an override, or restoring a removal, inherits again', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu', EU_REGION: 'eu-west-1' });
  // A removal is a dismissal: the fork does without the key its parent has.
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  assert.deepEqual(await values(maintainer, 'market/prod-eu'), { DATABASE_URL: 'postgres://eu', EU_REGION: 'eu-west-1', STRIPE_KEY: 'sk_live_1' });
  await assert.rejects(maintainer.secrets.reveal('market/prod-eu/SENTRY_DSN'), { status: 404 });
  // The parent is untouched.
  assert.deepEqual(await values(maintainer, 'market/prod'), { DATABASE_URL: 'postgres://prod', SENTRY_DSN: 'https://sentry/prod', STRIPE_KEY: 'sk_live_1' });

  await maintainer.secrets.update('market/prod-eu/DATABASE_URL', { archived: true });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: null });
  assert.deepEqual(await values(maintainer, 'market/prod-eu'), {
    DATABASE_URL: 'postgres://prod',
    EU_REGION: 'eu-west-1',
    SENTRY_DSN: 'https://sentry/prod',
    STRIPE_KEY: 'sk_live_1',
  });
});

test("an inherited value is the parent's read: logged there, and in the fork through `also`", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  firstSeq = (await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead))[0].nextSeq;
  await maintainer.secrets.reveal('market/prod-eu');
  const [prod, eu] = [await environmentId('prod'), await environmentId('prod-eu')];
  const reads = await entries('vault', 'secret.read');
  const also = (environmentId: string) => ({ projectId: reads[0].projectId, environmentId });
  assert.deepEqual(reads.map((read) => [read.decision, read.environmentId, read.metadata.subject, read.metadata.through, read.metadata.also]), [
    ['allow', eu, 'market/prod-eu/DATABASE_URL', undefined, undefined],
    ['allow', prod, 'market/prod/SENTRY_DSN', { environmentId: eu, slug: 'prod-eu' }, also(eu)],
    ['allow', prod, 'market/prod/STRIPE_KEY', { environmentId: eu, slug: 'prod-eu' }, also(eu)],
  ]);
  // So the fork's log lists all three reads, and the parent's the two of its own keys.
  const { entries: forkLog } = await root.audit.list({ path: 'market/prod-eu' });
  assert.equal(forkLog.filter((entry) => entry.action === 'secret.read' && entry.author === 'vault').length, 3);
  const { entries: parentLog } = await root.audit.list({ path: 'market/prod' });
  assert.equal(parentLog.filter((entry) => entry.action === 'secret.read' && entry.author === 'vault').length, 2);
});

test('a fork lends nothing: reading what it inherits takes read on the parent, by your own grants', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'developer' });
  firstSeq = (await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead))[0].nextSeq;

  await assert.rejects(ada.secrets.reveal('market/prod-eu'), (error: { status: number; message: string }) => {
    assert.equal(error.status, 403);
    assert.match(error.message, /market\/prod-eu inherits SENTRY_DSN, STRIPE_KEY from market\/prod, which you cannot read/);
    return true;
  });
  assert.deepEqual((await entries('app', 'secret.read')).map((entry) => [entry.decision, entry.metadata.reason, entry.metadata.parents]), [['deny', 'parent_unreadable', ['prod']]]);
  // Its own keys are hers to read; the vault was asked for nothing else.
  assert.deepEqual(await values(ada, 'market/prod-eu/DATABASE_URL'), { DATABASE_URL: 'postgres://eu' });
  assert.deepEqual((await entries('vault', 'secret.read')).map((entry) => entry.metadata.subject), ['market/prod-eu/DATABASE_URL']);

  await root.access.set(`user:${ADA}`, { 'market/prod': 'viewer' });
  assert.deepEqual(await values(ada, 'market/prod-eu'), { DATABASE_URL: 'postgres://eu', SENTRY_DSN: 'https://sentry/prod', STRIPE_KEY: 'sk_live_1' });
});

test('the vault decides on where a value is held, whatever fork the app names, and takes no fork from another project', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  const [version] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).limit(1);
  const ask = async (reader: string, fork: string) =>
    deps.vault.unwrap({ principal: `user:${reader}`, purpose: 'run', items: [{ secretVersionId: version.id, through: await environmentId(fork) }] });

  // A reader of the fork alone gets nothing of the parent's, though the app names the fork.
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'viewer' });
  const refused = await ask(ADA, 'market/prod-eu');
  assert.deepEqual(refused.ok ? null : refused.refusal.code, 'no_grant');
  // A fork is of the value's project, and is not where the value is.
  for (const fork of ['billing/prod', 'market/prod']) {
    const claimed = await ask(MAINTAINER, fork);
    assert.deepEqual(claimed.ok ? null : claimed.refusal.code, 'bad_claim');
  }
  assert.equal((await ask(MAINTAINER, 'market/prod-eu')).ok, true);
});

test('chains: a fork of a fork reads the nearest value, removals carry down, and a chain stops at three parents', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  await maintainer.environments.create('market/prod-eu-canary', { from: 'prod-eu', inherit: true });
  await maintainer.secrets.set('market/prod-eu-canary', { CANARY: 'yes' });
  assert.deepEqual(await values(maintainer, 'market/prod-eu-canary'), { CANARY: 'yes', DATABASE_URL: 'postgres://eu', STRIPE_KEY: 'sk_live_1' });
  // A value of its own sets a key its parent removed.
  await maintainer.secrets.set('market/prod-eu-canary', { SENTRY_DSN: 'https://sentry/canary' });
  assert.equal((await values(maintainer, 'market/prod-eu-canary')).SENTRY_DSN, 'https://sentry/canary');

  await maintainer.environments.create('market/level-3', { from: 'prod-eu-canary', inherit: true });
  await assert.rejects(maintainer.environments.create('market/level-4', { from: 'level-3', inherit: true }), { status: 409 });
  // A copy of a fork copies what it reads.
  const copied = await maintainer.environments.create('market/snapshot', { from: 'prod-eu-canary' });
  assert.equal(copied.forked?.keys, 4);
  assert.deepEqual(await values(maintainer, 'market/snapshot'), await values(maintainer, 'market/prod-eu-canary'));
});

test('a parent with live forks is not archived; a fork whose parent is archived anyway refuses to read', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await assert.rejects(root.environments.update('market/prod', { archived: true }), (error: { status: number; message: string }) => {
    assert.equal(error.status, 409);
    assert.match(error.message, /market\/prod is inherited by market\/prod-eu: archive it first/);
    return true;
  });
  // Written around the app: the read says why, rather than run without the parent's keys.
  await db.owner.update(environments).set({ archivedAt: new Date() }).where(eq(environments.id, await environmentId('prod')));
  await assert.rejects(maintainer.secrets.reveal('market/prod-eu'), { status: 409, message: /inherits from market\/prod, which is archived/ });

  await db.owner.update(environments).set({ archivedAt: null }).where(eq(environments.id, await environmentId('prod')));
  await root.environments.update('market/prod-eu', { archived: true });
  await root.environments.update('market/prod', { archived: true });
});

test('inheriting and referencing are not one fork, and a fork that inherits is a new environment', async () => {
  await assert.rejects(maintainer.environments.create('market/x', { from: 'prod', inherit: true, references: true }), { status: 400 });
  await root.environments.create('market/empty', { name: 'Empty' });
  await assert.rejects(maintainer.environments.create('market/empty', { from: 'prod', inherit: true }), { status: 409 });
});

test('a value written over a removal ends it: reset afterwards, the key inherits again', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  await maintainer.secrets.set('market/prod-eu', { SENTRY_DSN: 'https://sentry/eu' });
  assert.deepEqual((await maintainer.environments.missing('market/prod-eu')).dismissed, []);
  await maintainer.secrets.update('market/prod-eu/SENTRY_DSN', { archived: true });
  assert.equal((await values(maintainer, 'market/prod-eu')).SENTRY_DSN, 'https://sentry/prod');
});

test("a fork is restored only while its parent is live, and names what it forks", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.environments.update('market/prod-eu', { archived: true });
  await root.environments.update('market/prod', { archived: true });
  await assert.rejects(root.environments.update('market/prod-eu', { archived: false }), { status: 409, message: /inherits from market\/prod, which is archived/ });
  await root.environments.update('market/prod', { archived: false });
  await root.environments.update('market/prod-eu', { archived: false });
  assert.equal((await values(maintainer, 'market/prod-eu')).STRIPE_KEY, 'sk_live_1');

  await assert.rejects(maintainer.environments.create('market/x', { inherit: true }), { status: 400 });
});

test('the vault takes no archived fork', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.environments.update('market/prod-eu', { archived: true });
  const [version] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).limit(1);
  const claimed = await deps.vault.unwrap({ principal: `user:${MAINTAINER}`, purpose: 'run', items: [{ secretVersionId: version.id, through: await environmentId('prod-eu') }] });
  assert.deepEqual(claimed.ok ? null : claimed.refusal.code, 'bad_claim');
});

test("forking a fork as references or copies takes what it resolves to: each key where it is held, with that folder", async () => {
  await root.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-1' });
  // An override reset to prod's: its archived row is no source.
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu' });
  await maintainer.secrets.update('market/prod-eu/STRIPE_KEY', { archived: true });

  const referenced = await maintainer.environments.create('market/eu-refs', { from: 'prod-eu', references: true });
  assert.deepEqual(referenced.forked, { from: 'prod-eu', keys: 4, references: 4, copied: [], inherits: false });
  const { keys } = await maintainer.secrets.list('market/eu-refs');
  assert.deepEqual(keys.map((key) => [key.key, key.reference?.source, key.folder]), [
    ['DATABASE_URL', 'market/prod/DATABASE_URL', 'database'],
    ['EU_REGION', 'market/prod-eu/EU_REGION', null],
    ['SENTRY_DSN', 'market/prod/SENTRY_DSN', null],
    ['STRIPE_KEY', 'market/prod/STRIPE_KEY', null],
  ]);
  // References follow prod's rotations, as inheriting does.
  await root.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2' });
  assert.equal((await values(maintainer, 'market/eu-refs')).STRIPE_KEY, 'sk_live_2');

  await maintainer.environments.create('market/eu-copy', { from: 'prod-eu' });
  assert.deepEqual((await maintainer.secrets.list('market/eu-copy')).keys.map((key) => [key.key, key.folder]), [
    ['DATABASE_URL', 'database'],
    ['EU_REGION', null],
    ['SENTRY_DSN', null],
    ['STRIPE_KEY', null],
  ]);
});

test("a fork's reader who cannot read the parent learns no more than a key's name, broken references included", async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  await root.secrets.set('billing/prod', { PRIVATE_SOURCE: 'billing-secret' });
  await root.secrets.set('market/prod', { SHARED: { ref: 'billing/prod/PRIVATE_SOURCE' } });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.references.break('market/prod/SHARED');
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'viewer' });
  await assert.rejects(ada.secrets.reveal('market/prod-eu'), (error: { status: number; message: string }) => {
    assert.equal(error.status, 403);
    assert.doesNotMatch(error.message, /billing|PRIVATE_SOURCE|broke/);
    assert.match(error.message, /SHARED/);
    return true;
  });
});

test('a value written again as the same reference ends its removal too', async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  await root.secrets.set('billing/prod', { SOURCE: 'billing-secret' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.secrets.set('market/prod-eu', { STRIPE_KEY: { ref: 'billing/prod/SOURCE' } });
  // Reset, then removed: written again as the same reference, it serves, and is no longer removed.
  await root.secrets.inherit('market/prod-eu/STRIPE_KEY', true);
  await root.environments.dismiss('market/prod-eu', { STRIPE_KEY: true });
  await root.secrets.set('market/prod-eu', { STRIPE_KEY: { ref: 'billing/prod/SOURCE' } });
  assert.deepEqual((await root.environments.missing('market/prod-eu')).dismissed, []);
  assert.equal((await values(root, 'market/prod-eu')).STRIPE_KEY, 'billing-secret');
});

test('no copy goes into an empty environment that inherits, and a chain made around the app is not followed', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.secrets.set('market/dev', { DEV_ONLY: 'x' });
  await assert.rejects(maintainer.environments.create('market/prod-eu', { from: 'dev' }), { status: 409, message: /inherits from another environment/ });

  // The database refuses an environment that is its own parent; a loop of two, it cannot, and the read refuses it.
  const [eu, prod] = [await environmentId('prod-eu'), await environmentId('prod')];
  await assert.rejects(db.owner.update(environments).set({ parentId: eu }).where(eq(environments.id, eu)));
  await db.owner.update(environments).set({ parentId: eu }).where(eq(environments.id, prod));
  await assert.rejects(maintainer.secrets.reveal('market/prod-eu'), { status: 409, message: /parents loop or run past 3/ });
});

test('a reset override is overridden again by a write, and a write over a removal ends it', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu_1' });
  await maintainer.secrets.update('market/prod-eu/STRIPE_KEY', { archived: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu_2' });
  assert.equal((await values(maintainer, 'market/prod-eu')).STRIPE_KEY, 'sk_eu_2');

  // Reset and removed, then written: it overrides, and reset again, the key inherits, not stays removed.
  await maintainer.secrets.inherit('market/prod-eu/STRIPE_KEY', true);
  await maintainer.environments.dismiss('market/prod-eu', { STRIPE_KEY: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu_3' });
  assert.equal((await values(maintainer, 'market/prod-eu')).STRIPE_KEY, 'sk_eu_3');
  await maintainer.secrets.inherit('market/prod-eu/STRIPE_KEY', true);
  assert.equal((await values(maintainer, 'market/prod-eu')).STRIPE_KEY, 'sk_live_1');
});

test('a parent is deleted only once no fork names it', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.environments.update('market/prod-eu', { archived: true });
  await root.environments.update('market/prod', { archived: true });
  await assert.rejects(root.environments.delete('market/prod'), { status: 409, message: /market\/prod is the parent of market\/prod-eu: delete it first/ });
  await root.environments.delete('market/prod-eu');
  await root.environments.delete('market/prod');
});

test("forking a fork tells its forker no more of an unreadable parent than a read does", async () => {
  const ADMIN = 'admin2@acme.example';
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  await root.secrets.set('billing/prod', { PRIVATE_SOURCE: 'billing-secret' });
  await root.secrets.set('market/prod', { SHARED: { ref: 'billing/prod/PRIVATE_SOURCE' } });
  await root.references.break('market/prod/SHARED');
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.members.add(`user:${ADMIN}`, { role: 'admin' });
  await root.access.set(`user:${ADMIN}`, { 'market/prod-eu': 'viewer' });
  await assert.rejects(clientFor(deps, ADMIN).environments.create('market/eu-copy', { from: 'prod-eu' }), (error: { status: number; message: string }) => {
    assert.equal(error.status, 403);
    assert.doesNotMatch(error.message, /billing|PRIVATE_SOURCE|broke/);
    return true;
  });
});

test('a reset key written again as the same reference, or previewed, overrides again', async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  await root.secrets.set('billing/prod', { SOURCE: 'billing-secret' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.secrets.set('market/prod-eu', { STRIPE_KEY: { ref: 'billing/prod/SOURCE' }, DATABASE_URL: 'postgres://eu' });
  await root.secrets.update('market/prod-eu/STRIPE_KEY', { archived: true });
  await root.secrets.update('market/prod-eu/DATABASE_URL', { archived: true });

  // An import's preview: a reset key, written again with the value it had, is a change.
  assert.deepEqual((await root.secrets.dryRun('market/prod-eu', { DATABASE_URL: 'postgres://eu' })).keys, { DATABASE_URL: 'changed' });
  await root.secrets.set('market/prod-eu', { STRIPE_KEY: { ref: 'billing/prod/SOURCE' }, DATABASE_URL: 'postgres://eu' });
  const read = await values(root, 'market/prod-eu');
  assert.deepEqual([read.STRIPE_KEY, read.DATABASE_URL], ['billing-secret', 'postgres://eu']);
});

test('an override unarchived, or renamed onto a removed key, ends its removal as a write does', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu', EU_TOKEN: 'token' });
  await root.secrets.update('market/prod-eu/STRIPE_KEY', { archived: true });
  await maintainer.environments.dismiss('market/prod-eu', { STRIPE_KEY: true, SENTRY_DSN: true });
  await root.secrets.update('market/prod-eu/STRIPE_KEY', { archived: false });
  await root.secrets.update('market/prod-eu/EU_TOKEN', { key: 'SENTRY_DSN' });
  await root.secrets.update('market/prod-eu/STRIPE_KEY', { archived: true });
  await root.secrets.update('market/prod-eu/SENTRY_DSN', { archived: true });
  const read = await values(maintainer, 'market/prod-eu');
  assert.deepEqual([read.STRIPE_KEY, read.SENTRY_DSN], ['sk_live_1', 'https://sentry/prod']);
});

test("a fork the vault refuses is named in the refusal, never filed under: another project's log does not get it", async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/dev', { name: 'Dev' });
  const [version] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).limit(1);
  firstSeq = (await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead))[0].nextSeq;
  const billingDev = await environmentId('billing/dev');
  const claimed = await deps.vault.unwrap({ principal: `user:${MAINTAINER}`, purpose: 'run', items: [{ secretVersionId: version.id, through: billingDev }] });
  assert.deepEqual(claimed.ok ? null : claimed.refusal.code, 'bad_claim');
  const refusals = await entries('vault', 'secret.read');
  assert.deepEqual(refusals.map((entry) => [entry.decision, entry.metadata.through, entry.metadata.also]), [
    ['deny', { environmentId: billingDev, refused: true }, undefined],
  ]);
  const { entries: billingLog } = await root.audit.list({ path: 'billing/dev' });
  assert.equal(billingLog.filter((entry) => entry.action === 'secret.read').length, 0);
});

test('a fork is filed under only for a read whose reference holds: a forged pairing is refused, and named nowhere else', async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Prod' });
  await root.secrets.set('billing/prod', { LENT: 'lent', PRIVATE_SOURCE: 'private' });
  await root.secrets.set('market/prod', { SHARED: { ref: 'billing/prod/LENT' } });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  const [reference] = await db.owner.select({ id: secretReferences.id, seq: secretReferences.createdSeq }).from(secretReferences);
  const [unrelated] = await db.owner
    .select({ id: secretVersions.id })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(eq(secrets.key, 'PRIVATE_SOURCE'));
  firstSeq = (await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead))[0].nextSeq;
  const eu = await environmentId('prod-eu');
  const claimed = await deps.vault.unwrap({
    principal: `user:${ROOT}`,
    purpose: 'run',
    items: [{ secretVersionId: unrelated.id, via: { reference: reference.id, seq: Number(reference.seq) }, through: eu }],
  });
  assert.deepEqual(claimed.ok ? null : claimed.refusal.code, 'bad_claim');
  const refusals = await entries('vault', 'secret.read');
  assert.deepEqual(refusals.map((entry) => [entry.decision, entry.metadata.through]), [['deny', { environmentId: eu, refused: true }]]);
  const { entries: forkLog } = await root.audit.list({ path: 'market/prod-eu' });
  assert.equal(forkLog.filter((entry) => entry.action === 'secret.read').length, 0);
});

test("a fork's list says what it inherits, overrides and removes, and its parents; versions only to the parent's readers", async () => {
  await root.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu', EU_REGION: 'eu-west-1' });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  const listed = await maintainer.secrets.list('market/prod-eu');
  assert.deepEqual(listed.parents, ['prod']);
  assert.deepEqual(listed.keys.map((key) => [key.key, key.folder, key.parent, key.version]), [
    ['DATABASE_URL', null, { from: 'prod', state: 'overridden', changed: false, reset: false, held: true }, 1],
    ['EU_REGION', null, null, 1],
    ['SENTRY_DSN', null, { from: 'prod', state: 'removed', changed: false, reset: false, held: true }, null],
    ['STRIPE_KEY', null, { from: 'prod', state: 'inherited', changed: false, reset: false, held: true }, 1],
  ]);
  // An inherited key is listed in its parent's folder; prod moved its own DATABASE_URL, which the override does not follow.
  await root.secrets.update('market/prod/STRIPE_KEY', { folder: 'billing' });
  assert.equal((await maintainer.secrets.list('market/prod-eu')).keys.find((key) => key.key === 'STRIPE_KEY')?.folder, 'billing');

  // prod writes DATABASE_URL after the override: the override is flagged.
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://prod-2' });
  const after = await maintainer.secrets.list('market/prod-eu');
  assert.deepEqual(after.keys.find((key) => key.key === 'DATABASE_URL')?.parent, { from: 'prod', state: 'overridden', changed: true, reset: false, held: true });

  // A reader of the fork alone sees the names and their standing, never when the parent's were written.
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'viewer' });
  const hers = await ada.secrets.list('market/prod-eu');
  assert.deepEqual(hers.keys.map((key) => [key.key, key.parent?.state ?? null, key.version, key.updatedAt === null, key.parent?.changed ?? null]), [
    ['DATABASE_URL', 'overridden', 1, false, false],
    ['EU_REGION', null, 1, false, null],
    ['SENTRY_DSN', 'removed', null, true, false],
    ['STRIPE_KEY', 'inherited', null, true, false],
  ]);
  // Outside forks, nothing changes: no parent, no parents.
  const prod = await root.secrets.list('market/prod');
  assert.deepEqual([prod.parents, prod.keys.every((key) => key.parent === null)], [[], true]);
});

test('a reset is a write: a developer resets an override to the parent, and undoes it; nowhere is it an archive by another name', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu', EU_REGION: 'eu-west-1' });
  await root.access.set(`user:${ADA}`, { market: 'developer' });
  await assert.rejects(ada.secrets.update('market/prod-eu/DATABASE_URL', { archived: true }), { status: 403 });

  assert.deepEqual(await ada.secrets.update('market/prod-eu/DATABASE_URL', { inherit: true }), { key: 'DATABASE_URL', archived: true, folder: null, from: 'prod' });
  assert.equal((await values(ada, 'market/prod-eu')).DATABASE_URL, 'postgres://prod');
  assert.deepEqual((await entries('app', 'secret.reset')).map((entry) => entry.metadata), [{ key: 'DATABASE_URL', from: 'prod' }]);
  // Listed once, as inherited, its own value kept.
  const listed = (await ada.secrets.list('market/prod-eu')).keys.filter((key) => key.key === 'DATABASE_URL');
  assert.deepEqual(listed.map((key) => [key.archived, key.parent]), [[false, { from: 'prod', state: 'inherited', changed: false, reset: true, held: true }]]);
  // Again: nothing to do.
  await ada.secrets.update('market/prod-eu/DATABASE_URL', { inherit: true });
  assert.equal((await entries('app', 'secret.reset')).length, 1);

  // Undone, its override serves again, with the value it had.
  await ada.environments.dismiss('market/prod-eu', { DATABASE_URL: true });
  await ada.secrets.update('market/prod-eu/DATABASE_URL', { inherit: false });
  assert.equal((await values(ada, 'market/prod-eu')).DATABASE_URL, 'postgres://eu');
  assert.deepEqual((await ada.environments.missing('market/prod-eu')).dismissed, []);

  // A key the parent lacks is no override, and an environment with no parent resets nothing.
  await assert.rejects(ada.secrets.update('market/prod-eu/EU_REGION', { inherit: true }), { status: 409, message: /holds EU_REGION: archive it instead/ });
  await assert.rejects(ada.secrets.update('market/prod/DATABASE_URL', { inherit: true }), { status: 409, message: /inherits from no environment/ });
  await assert.rejects(ada.secrets.update('market/prod-eu/DATABASE_URL', { inherit: true, folder: 'x' }), { status: 400 });
});

test('a reset override that others read through a reference waits until they are broken, as archiving does', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.secrets.set('market/dev', { EU_DB: { ref: 'market/prod-eu/DATABASE_URL' } });
  await assert.rejects(maintainer.secrets.update('market/prod-eu/DATABASE_URL', { inherit: true }), { status: 409, message: /1 reference reads/ });
  // A key a fork only inherits is its parent's to refer to.
  await assert.rejects(root.secrets.set('market/dev', { STRIPE: { ref: 'market/prod-eu/STRIPE_KEY' } }), {
    status: 404,
    message: /market\/prod-eu\/STRIPE_KEY is inherited from market\/prod: refer to market\/prod\/STRIPE_KEY instead/,
  });
});

test("a rename carries down to the forks' overrides and removals, forks of forks included, and stops at a fork holding the new name", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.environments.create('market/prod-eu-canary', { from: 'prod-eu', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu' });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  await maintainer.secrets.set('market/prod-eu-canary', { STRIPE_KEY: 'sk_canary' });

  await root.secrets.update('market/prod/STRIPE_KEY', { key: 'STRIPE_SECRET_KEY' });
  await root.secrets.update('market/prod/SENTRY_DSN', { key: 'SENTRY_URL' });
  assert.deepEqual(await values(maintainer, 'market/prod-eu'), { DATABASE_URL: 'postgres://prod', STRIPE_SECRET_KEY: 'sk_eu' });
  assert.deepEqual(await values(maintainer, 'market/prod-eu-canary'), { DATABASE_URL: 'postgres://prod', STRIPE_SECRET_KEY: 'sk_canary' });
  const [eu, canary] = [await environmentId('prod-eu'), await environmentId('prod-eu-canary')];
  assert.deepEqual((await entries('app', 'secret.rename')).map((entry) => [entry.environmentId, entry.metadata]), [
    [await environmentId('prod'), { key: 'STRIPE_KEY', nextKey: 'STRIPE_SECRET_KEY' }],
    [eu, { key: 'STRIPE_KEY', nextKey: 'STRIPE_SECRET_KEY', parent: 'prod' }],
    [canary, { key: 'STRIPE_KEY', nextKey: 'STRIPE_SECRET_KEY', parent: 'prod' }],
    [await environmentId('prod'), { key: 'SENTRY_DSN', nextKey: 'SENTRY_URL' }],
  ]);
  assert.deepEqual((await maintainer.environments.missing('market/prod-eu')).dismissed.map((key) => key.key), ['SENTRY_URL']);

  // A fork that holds the new name already stops the rename, named, and nothing moves.
  await maintainer.secrets.set('market/prod-eu-canary', { DB: 'canary-db' });
  await assert.rejects(root.secrets.update('market/prod/DATABASE_URL', { key: 'DB' }), {
    status: 409,
    message: /market\/prod-eu-canary inherits DATABASE_URL and holds a DB of its own/,
  });
  assert.equal((await values(root, 'market/prod')).DATABASE_URL, 'postgres://prod');
});

test("a rename's new name is no removal a fork made of another key: it inherits what it inherited", async () => {
  await root.secrets.set('market/prod', { OLD: 'old' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.secrets.set('market/dev', { NEW: 'dev' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  // prod-eu dismissed dev's NEW from its missing keys, before prod had one.
  await maintainer.environments.dismiss('market/prod-eu', { NEW: true });
  await root.secrets.update('market/prod/OLD', { key: 'NEW' });
  assert.equal((await values(maintainer, 'market/prod-eu')).NEW, 'old');
});

test('missing keys compare what forks resolve to, and a parent misses nothing only its forks hold', async () => {
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://dev', DEV_ONLY: 'x' });
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-1' });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });

  const eu = await maintainer.environments.missing('market/prod-eu');
  assert.deepEqual(eu.missing.map((key) => [key.key, key.in]), [['DEV_ONLY', ['dev']]]);
  assert.deepEqual(eu.dismissed.map((key) => [key.key, key.in]), [['SENTRY_DSN', ['prod']]]);
  // prod is not missing EU_REGION, which only its fork holds; dev is, and sees prod-eu hold what it inherits.
  assert.deepEqual((await root.environments.missing('market/prod')).missing.map((key) => key.key), ['DEV_ONLY']);
  assert.deepEqual((await root.environments.missing('market/dev')).missing.map((key) => [key.key, key.in]), [
    ['EU_REGION', ['prod-eu']],
    ['SENTRY_DSN', ['prod']],
    ['STRIPE_KEY', ['prod', 'prod-eu']],
  ]);
});

test("projects list each environment's parent, and count what a fork resolves to", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-1' });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  const { projects: listed } = await maintainer.projects.list();
  const market = listed.find((project) => project.slug === 'market')!;
  assert.deepEqual(market.environments.map((environment) => [environment.slug, environment.parent, environment.details?.secretCount]), [
    ['prod', null, 3],
    ['prod-eu', 'prod', 3],
  ]);
});

test('a project that holds forks is archived and deleted whole, its forks with it', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.projects.update('market', { archived: true });
  await root.projects.delete('market');
  assert.equal((await root.projects.list()).projects.some((project) => project.slug === 'market'), false);
});

test('two renames at once: one wins, the other is refused, and the forks follow the winner', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu' });
  const outcomes = await Promise.allSettled([
    root.secrets.update('market/prod/STRIPE_KEY', { key: 'FIRST' }),
    root.secrets.update('market/prod/STRIPE_KEY', { key: 'SECOND' }),
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  const won = Object.keys(await values(root, 'market/prod')).find((key) => key === 'FIRST' || key === 'SECOND')!;
  const eu = await values(maintainer, 'market/prod-eu');
  assert.deepEqual([eu[won], Object.keys(eu).filter((key) => key === 'FIRST' || key === 'SECOND' || key === 'STRIPE_KEY')], ['sk_eu', [won]]);
});

test("in a fork, a write brings back a reset override, never an archived key of the fork's own", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-1', STRIPE_KEY: 'sk_eu' });
  await maintainer.secrets.update('market/prod-eu/EU_REGION', { archived: true });
  await maintainer.secrets.inherit('market/prod-eu/STRIPE_KEY', true);
  await root.access.set(`user:${ADA}`, { market: 'developer' });

  await assert.rejects(ada.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-2' }), { status: 409, message: /EU_REGION is archived; unarchive it/ });
  await assert.rejects(ada.secrets.dryRun('market/prod-eu', { EU_REGION: 'eu-west-2' }), { status: 409 });
  assert.deepEqual((await ada.secrets.dryRun('market/prod-eu', { STRIPE_KEY: 'sk_eu_2' })).keys, { STRIPE_KEY: 'changed' });
  await ada.secrets.set('market/prod-eu', { STRIPE_KEY: 'sk_eu_2' });
  assert.equal((await values(ada, 'market/prod-eu')).STRIPE_KEY, 'sk_eu_2');
});

test("a reference refused on a key a fork inherits names the parent's key only to a reader of the fork", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/dev', { name: 'Dev' });
  await root.access.set(`user:${ADA}`, { 'billing/dev': 'developer' });
  await assert.rejects(ada.secrets.set('billing/dev', { STRIPE: { ref: 'market/prod-eu/STRIPE_KEY' } }), (error: { status: number; message: string }) => {
    assert.equal(error.status, 404);
    assert.equal(error.message, 'market/prod-eu/STRIPE_KEY is no live secret to refer to');
    return true;
  });
});

test('a fork removes only what it inherits: a key it holds a value of is refused, under the head', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu', EU_REGION: 'eu-west-1' });
  await assert.rejects(maintainer.environments.dismiss('market/prod-eu', { DATABASE_URL: true }), {
    status: 409,
    message: /market\/prod-eu holds DATABASE_URL of its own, which removing would not stop it serving: `coffre reset market\/prod-eu\/DATABASE_URL` first/,
  });
  await assert.rejects(maintainer.environments.dismiss('market/prod-eu', { EU_REGION: true }), { status: 409, message: /`coffre archive market\/prod-eu\/EU_REGION` takes it out/ });
  assert.deepEqual((await maintainer.environments.missing('market/prod-eu')).dismissed, []);
  // Reset first, and the removal holds.
  await maintainer.secrets.inherit('market/prod-eu/DATABASE_URL', true);
  await maintainer.environments.dismiss('market/prod-eu', { DATABASE_URL: true });
  assert.equal((await values(maintainer, 'market/prod-eu')).DATABASE_URL, undefined);
  // Outside forks, a dismissal of a key held is as it was: moot, and allowed.
  await root.environments.dismiss('market/prod', { DATABASE_URL: true });
});

test("a project's count is of the names its environments resolve to, a fork-only reader's included", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { EU_REGION: 'eu-west-1' });
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'viewer' });
  const market = (await ada.projects.list()).projects.find((project) => project.slug === 'market')!;
  assert.deepEqual([market.secretCount, market.environments.find((environment) => environment.slug === 'prod-eu')?.details?.secretCount], [4, 4]);
  assert.equal((await maintainer.projects.list()).projects.find((project) => project.slug === 'market')!.secretCount, 4);
});

test('a removal of a key the parent archived since stays listed, as such, until restored', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  await root.secrets.update('market/prod/SENTRY_DSN', { archived: true });
  const listed = (await maintainer.secrets.list('market/prod-eu')).keys.filter((key) => key.key === 'SENTRY_DSN');
  assert.deepEqual(listed.map((key) => [key.archived, key.version, key.parent]), [[false, null, { from: 'prod', state: 'removed', changed: false, reset: false, held: false }]]);
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: null });
  assert.deepEqual((await maintainer.secrets.list('market/prod-eu')).keys.map((key) => key.key), ['DATABASE_URL', 'STRIPE_KEY']);
  // Back in prod, it is inherited again.
  await root.secrets.update('market/prod/SENTRY_DSN', { archived: false });
  assert.equal((await values(maintainer, 'market/prod-eu')).SENTRY_DSN, 'https://sentry/prod');
});

import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog, environments, projects, secretVersions } from './db/tables.ts';
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
  await root.environments.dismiss('market/prod-eu', { STRIPE_KEY: true });
  await root.secrets.set('market/prod-eu', { STRIPE_KEY: { ref: 'billing/prod/SOURCE' } });
  assert.deepEqual((await root.environments.missing('market/prod-eu')).dismissed, []);
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

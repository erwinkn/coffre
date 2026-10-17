import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

/**
 * An environment's version (`GET /api/projects/:project/:environment/version`):
 * what a poller asks before reading. It changes whenever a read of the
 * environment would open something else, inherited keys included, and
 * reads no value, so nothing is logged.
 */

const ROOT = 'admin@acme.example';
const MAINTAINER = 'maintainer@acme.example';
const ADA = 'ada@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let maintainer: CoffreClient;
let ada: CoffreClient;

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
});

/** The log from now on: what a call wrote to it, read once the call is over. */
async function logFromHere(): Promise<() => Promise<{ author: string; action: string; decision: string; metadata: Record<string, unknown> }[]>> {
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  return async () => {
    const rows = await db.owner
      .select({ author: auditLog.author, action: auditLog.action, decision: auditLog.decision, metadata: auditLog.metadata })
      .from(auditLog)
      .where(gte(auditLog.seq, head.nextSeq))
      .orderBy(asc(auditLog.seq));
    return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
  };
}

const versionOf = async (path: string, as = maintainer) => (await as.environments.version(path)).version;

test('a version changes with what a read opens, and with nothing else; asking for it reads no value and logs nothing', async () => {
  const written = await logFromHere();
  const first = await versionOf('market/prod');
  assert.match(first, /^[\w-]{43}$/);
  assert.deepEqual(Object.keys(await maintainer.environments.version('market/prod')), ['version'], 'the version, and nothing of a value');
  assert.equal(await versionOf('market/prod'), first);
  assert.equal(await versionOf('market/prod', root), first, "the environment's, not its reader's");
  assert.deepEqual(await written(), []);
  // A read of the environment answers the version of what it opened; one of a key, none.
  assert.equal((await maintainer.secrets.reveal('market/prod')).version, first);
  assert.equal((await maintainer.secrets.reveal('market/prod/STRIPE_KEY')).version, null);

  // Filing a key is no change to a read; a value, an archive or a new name is.
  await maintainer.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  assert.equal(await versionOf('market/prod'), first);
  const seen = new Set([first]);
  const changes: [string, () => Promise<unknown>][] = [
    ['a new value', () => maintainer.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2' })],
    ['a new key', () => maintainer.secrets.set('market/prod', { REDIS_URL: 'redis://prod' })],
    ['an archive', () => maintainer.secrets.update('market/prod/DATABASE_URL', { archived: true })],
    ['a rename', () => maintainer.secrets.rename('market/prod/SENTRY_DSN', 'SENTRY_URL')],
    ['a rollback', () => maintainer.secrets.restore('market/prod/STRIPE_KEY', 1)],
  ];
  for (const [change, make] of changes) {
    await make();
    const version = await versionOf('market/prod');
    assert.ok(!seen.has(version), `${change} changes the version`);
    seen.add(version);
  }
  // It is of what a read opens, not of the writes that led there: undoing a change brings its version back.
  const archived = await versionOf('market/prod');
  await maintainer.secrets.update('market/prod/DATABASE_URL', { archived: false });
  await maintainer.secrets.update('market/prod/DATABASE_URL', { archived: true });
  const asked = await logFromHere();
  assert.equal(await versionOf('market/prod'), archived);
  assert.deepEqual(await asked(), []);
});

test("a fork's version covers what it inherits: its parent's writes, its overrides, removals and resets", async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  const inherited = await versionOf('market/prod-eu');
  // Inheriting everything, it opens what its parent does.
  assert.equal(inherited, await versionOf('market/prod'));
  assert.equal((await maintainer.secrets.reveal('market/prod-eu')).version, inherited);

  await maintainer.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2' });
  const rotated = await versionOf('market/prod-eu');
  assert.notEqual(rotated, inherited, "a parent's new value");

  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  const overridden = await versionOf('market/prod-eu');
  assert.notEqual(overridden, rotated, 'an override');
  // The parent's write under the override is no change to the fork.
  await maintainer.secrets.set('market/prod', { DATABASE_URL: 'postgres://prod-2' });
  assert.equal(await versionOf('market/prod-eu'), overridden);

  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: true });
  const removed = await versionOf('market/prod-eu');
  assert.notEqual(removed, overridden, 'a removal');
  await maintainer.environments.dismiss('market/prod-eu', { SENTRY_DSN: null });
  assert.equal(await versionOf('market/prod-eu'), overridden, 'inheriting it again');

  await maintainer.secrets.inherit('market/prod-eu/DATABASE_URL', true);
  const reset = await versionOf('market/prod-eu');
  assert.notEqual(reset, overridden, "a reset to the parent's");
  assert.equal(reset, await versionOf('market/prod'), 'reset, it opens what its parent does again');
  await maintainer.secrets.inherit('market/prod-eu/DATABASE_URL', false);
  assert.equal(await versionOf('market/prod-eu'), overridden, 'the override served again');

  // The parent archiving or renaming a key the fork inherits.
  await maintainer.secrets.update('market/prod/STRIPE_KEY', { archived: true });
  const archived = await versionOf('market/prod-eu');
  assert.notEqual(archived, overridden, "the parent's archive");
  await maintainer.secrets.update('market/prod/STRIPE_KEY', { archived: false });
  await maintainer.secrets.rename('market/prod/STRIPE_KEY', 'STRIPE_SECRET');
  assert.ok(![archived, overridden].includes(await versionOf('market/prod-eu')), "the parent's rename");

  // A fork of the fork follows both.
  await maintainer.environments.create('market/prod-eu-west', { from: 'prod-eu', inherit: true });
  const west = await versionOf('market/prod-eu-west');
  await maintainer.secrets.set('market/prod', { SENTRY_DSN: 'https://sentry/prod-2' });
  assert.notEqual(await versionOf('market/prod-eu-west'), west, "the grandparent's new value");
});

test("a reference's version follows its source, and a reference that cannot be read changes it too", async () => {
  await root.environments.create('market/dev', { name: 'Dev' });
  await maintainer.secrets.set('market/dev', { STRIPE_KEY: { ref: 'market/prod/STRIPE_KEY' } });
  const following = await versionOf('market/dev');
  await maintainer.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2' });
  const rotated = await versionOf('market/dev');
  assert.notEqual(rotated, following, "the source's new value");
  await maintainer.references.break('market/dev/STRIPE_KEY');
  assert.notEqual(await versionOf('market/dev'), rotated, 'a broken reference');
});

test('a version takes read on the environment, and on each parent a fork inherits from; refusals are logged, as a read\'s', async () => {
  await maintainer.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await maintainer.secrets.set('market/prod-eu', { DATABASE_URL: 'postgres://eu' });
  const written = await logFromHere();

  await assert.rejects(versionOf('market/prod', ada), { status: 403 });
  await root.access.set(`user:${ADA}`, { 'market/prod-eu': 'developer' });
  // The fork's own keys are hers; its version would say when prod's change, which only prod's readers are told.
  await assert.rejects(versionOf('market/prod-eu', ada), (error: { status: number; message: string }) => {
    assert.equal(error.status, 403);
    assert.match(error.message, /market\/prod-eu inherits SENTRY_DSN, STRIPE_KEY from market\/prod, which you cannot read/);
    return true;
  });
  const refusals = (await written()).filter((entry) => entry.action === 'secret.version');
  assert.deepEqual(refusals.map((entry) => [entry.author, entry.decision, entry.metadata.reason]), [
    ['app', 'deny', 'missing_secret_read'],
    ['app', 'deny', 'parent_unreadable'],
  ]);
  assert.deepEqual(refusals[1]!.metadata.parents, ['prod']);

  // Reading prod too, she is told the fork's version, the one its other readers are.
  await root.access.set(`user:${ADA}`, { 'market/prod': 'viewer' });
  assert.equal(await versionOf('market/prod-eu', ada), await versionOf('market/prod-eu'));
});

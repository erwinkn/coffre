import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog, environments, secretVersions } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const MAINTAINER = 'maintainer@acme.example';
const OWNER = 'owner@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let maintainer: CoffreClient;
let owner: CoffreClient;
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
  owner = clientFor(deps, OWNER);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.members.add(`user:${MAINTAINER}`);
  await root.members.add(`user:${OWNER}`, { owner: true });
  await root.access.set(`user:${MAINTAINER}`, { market: 'maintainer' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://prod', STRIPE_KEY: 'sk_live_1', OLD_KEY: 'gone' });
  await root.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_2' });
  await root.secrets.update('market/prod/OLD_KEY', { archived: true });
  await root.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

async function entries(author: 'app' | 'vault', action: string) {
  const rows = await db.owner
    .select({ actor: auditLog.actor, decision: auditLog.decision, code: auditLog.code, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test('a fork copies each live key, with its value and folder, and none of its history', async () => {
  const made = await maintainer.environments.create('market/staging', { name: 'Staging', from: 'prod' });
  assert.deepEqual([made.created, made.forked], [true, { from: 'prod', keys: 2, references: 0, copied: [] }]);
  // Copying is reading: one entry per key, by the forker, to copy; then a write per key.
  const reads = await entries('vault', 'secret.read');
  assert.deepEqual(reads.map((read) => [read.actor, read.decision, read.metadata.subject, read.metadata.purpose]), [
    [`user:${MAINTAINER}`, 'allow', 'market/prod/DATABASE_URL', 'copy'],
    [`user:${MAINTAINER}`, 'allow', 'market/prod/STRIPE_KEY', 'copy'],
  ]);
  assert.equal((await entries('app', 'secret.write')).length, 2);
  assert.deepEqual((await maintainer.secrets.reveal('market/staging')).values, { DATABASE_URL: 'postgres://prod', STRIPE_KEY: 'sk_live_2' });
  const { keys } = await maintainer.secrets.list('market/staging');
  assert.deepEqual(keys.map((key) => [key.key, key.version, key.folder]), [['DATABASE_URL', 1, 'database'], ['STRIPE_KEY', 1, null]]);
  // The prod values are untouched, and the copy starts its own history.
  assert.equal((await maintainer.secrets.history('market/prod/STRIPE_KEY')).versions.length, 2);
  assert.equal((await db.owner.select().from(secretVersions)).length, 6);

  assert.deepEqual((await entries('app', 'environment.create')).map((entry) => entry.metadata), [{ slug: 'staging', name: 'Staging', from: 'prod' }]);
});

test('forking needs read on what it copies: an owner who manages the project but reads nothing creates nothing', async () => {
  await assert.rejects(owner.environments.create('market/staging', { name: 'Staging', from: 'prod' }), { status: 403 });
  assert.deepEqual((await db.owner.select({ slug: environments.slug }).from(environments)).map((row) => row.slug), ['prod']);
  assert.deepEqual((await entries('app', 'environment.fork')).map((entry) => [entry.actor, entry.decision, entry.metadata]), [
    [`user:${OWNER}`, 'deny', { from: 'prod', slug: 'staging', reason: 'missing_secret_read' }],
  ]);
  // Creating an empty one stays theirs to do.
  assert.equal((await owner.environments.create('market/staging', { name: 'Staging' })).created, true);
});

test('a fork goes into a new or empty environment, which running it again fills', async () => {
  await root.environments.create('market/empty', { name: 'Empty' });
  const filled = await maintainer.environments.create('market/empty', { name: 'Empty', from: 'prod' });
  assert.deepEqual([filled.created, filled.forked?.keys], [false, 2]);
  await assert.rejects(maintainer.environments.create('market/empty', { name: 'Empty', from: 'prod' }), { status: 409 });
  await assert.rejects(maintainer.environments.create('market/prod', { name: 'Prod', from: 'prod' }), { status: 409 });
  await assert.rejects(maintainer.environments.create('market/qa', { name: 'QA', from: 'nowhere' }), { status: 404 });
  // An environment with only archived keys counts as empty; a plain create is unchanged.
  const plain = await maintainer.environments.create('market/plain', { name: 'Plain' });
  assert.deepEqual([plain.created, plain.forked], [true, null]);
});

import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

// Missing keys (docs/design/environments.md): what market/dev lacks of the
// keys its siblings have, compared only with those the viewer reads.

const ROOT = 'admin@acme.example';
/** Develops market/dev, and reads market/staging, not prod. */
const DEV = 'dev@acme.example';
/** Reads market/dev only. */
const VIEWER = 'viewer@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let dev: CoffreClient;
let viewer: CoffreClient;
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
  dev = clientFor(deps, DEV);
  viewer = clientFor(deps, VIEWER);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'staging', 'prod']) await root.environments.create(`market/${environment}`, { name: environment });
  await root.members.add(`user:${DEV}`);
  await root.members.add(`user:${VIEWER}`);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer', 'market/staging': 'viewer' });
  await root.access.set(`user:${VIEWER}`, { 'market/dev': 'viewer' });
  await root.secrets.set('market/dev', { DATABASE_URL: 'dev', OLD_FLAG: 'x' });
  await root.secrets.update('market/dev/OLD_FLAG', { archived: true });
  await root.secrets.set('market/staging', { DATABASE_URL: 's', SENTRY_DSN: 's', OLD_FLAG: 's', STRIPE_KEY: 's' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'p', SENTRY_DSN: 'p', PROD_ONLY: 'p' });
  await root.secrets.update('market/staging/STRIPE_KEY', { folder: 'stripe' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

test('missing keys come only from environments the viewer reads, and an archived key is not missing', async () => {
  assert.deepEqual((await root.environments.missing('market/dev')).missing, [
    { key: 'PROD_ONLY', in: ['prod'], folder: null },
    { key: 'SENTRY_DSN', in: ['prod', 'staging'], folder: null },
    { key: 'STRIPE_KEY', in: ['staging'], folder: 'stripe' },
  ]);
  // Dev reads staging, not prod: prod's names are not theirs to learn.
  assert.deepEqual((await dev.environments.missing('market/dev')).missing.map((key) => [key.key, key.in]), [
    ['SENTRY_DSN', ['staging']], ['STRIPE_KEY', ['staging']],
  ]);
  assert.deepEqual(await viewer.environments.missing('market/dev'), { missing: [], dismissed: [] });
  await assert.rejects(viewer.environments.missing('market/prod'), { status: 403 });
});

test('dismissals are shared, logged, listed and undone; dismissing takes write', async () => {
  await assert.rejects(viewer.environments.dismiss('market/dev', { SENTRY_DSN: true }), { status: 403 });
  assert.deepEqual((await dev.environments.dismiss('market/dev', { SENTRY_DSN: true, STRIPE_KEY: true })).keys, { SENTRY_DSN: 'dismissed', STRIPE_KEY: 'dismissed' });
  // Everyone sees them dismissed: the team's decision, not one person's view.
  const seen = await root.environments.missing('market/dev');
  assert.deepEqual(seen.missing.map((key) => key.key), ['PROD_ONLY']);
  assert.deepEqual(seen.dismissed.map((key) => [key.key, key.dismissedBy]), [['SENTRY_DSN', DEV], ['STRIPE_KEY', DEV]]);
  // Dismissing again changes nothing; restoring brings one back; dismissing it again works.
  assert.deepEqual((await dev.environments.dismiss('market/dev', { SENTRY_DSN: true, STRIPE_KEY: null })).keys, { SENTRY_DSN: 'unchanged', STRIPE_KEY: 'restored' });
  assert.deepEqual((await root.environments.missing('market/dev')).missing.map((key) => key.key), ['PROD_ONLY', 'STRIPE_KEY']);
  assert.deepEqual((await root.environments.dismiss('market/dev', { STRIPE_KEY: true })).keys, { STRIPE_KEY: 'dismissed' });

  const rows = await db.owner
    .select({ actor: auditLog.actor, action: auditLog.action, decision: auditLog.decision, operationId: auditLog.operationId, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  // The viewer's attempt is on the record too, refused.
  assert.deepEqual(rows.filter((row) => row.decision === 'deny').map((row) => [row.actor, row.action]), [[`user:${VIEWER}`, 'missing.dismiss']]);
  const missingRows = rows.filter((row) => row.action.startsWith('missing.') && row.decision === 'allow');
  assert.deepEqual(missingRows.map((row) => [row.actor, row.action, JSON.parse(row.metadata).key]), [
    [`user:${DEV}`, 'missing.dismiss', 'SENTRY_DSN'],
    [`user:${DEV}`, 'missing.dismiss', 'STRIPE_KEY'],
    [`user:${DEV}`, 'missing.restore', 'STRIPE_KEY'],
    [`user:${ROOT}`, 'missing.dismiss', 'STRIPE_KEY'],
  ]);
  // One call, one operation: Dismiss all is one action.
  assert.equal(missingRows[0]!.operationId, missingRows[1]!.operationId);
});

test("a dismissed key the viewer cannot see elsewhere is not listed to them", async () => {
  await root.environments.dismiss('market/dev', { PROD_ONLY: true });
  assert.deepEqual((await dev.environments.missing('market/dev')).dismissed, []);
  assert.deepEqual((await root.environments.missing('market/dev')).dismissed.map((key) => key.key), ['PROD_ONLY']);
});

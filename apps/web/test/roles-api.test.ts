import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { and, asc, eq } from 'drizzle-orm';

import type { CoffreClient } from '../../../packages/client/src/index.ts';
import { assignableToEnvironment, ROLES } from '../../../packages/core/src/access.ts';
import { auditLog, grants, principals } from '../../../packages/db/test/tables.ts';
import {
  clientFor,
  openTestDatabase,
  resetDatabase,
  testDeps,
  type FixtureDeps,
} from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const AUDITOR = 'user:auditor@acme.example';
const ACCESS_MANAGER = 'user:accessmgr@acme.example';
const DEVELOPER = 'user:dev@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let auditor: CoffreClient;
let accessManager: CoffreClient;
let developer: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  auditor = clientFor(deps, 'auditor@acme.example');
  accessManager = clientFor(deps, 'accessmgr@acme.example');
  developer = clientFor(deps, 'dev@acme.example');
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(AUDITOR);
  await root.members.add(ACCESS_MANAGER);
  await root.members.add(DEVELOPER);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.secrets.set('market/prod', { API_KEY: 'sk_live_secret' });
});

async function lastAudit(action: string): Promise<{ decision: string; reason: unknown }> {
  const rows = await db.owner
    .select({ decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog)
    .where(eq(auditLog.action, action))
    .orderBy(asc(auditLog.seq));
  const row = rows.at(-1)!;
  return { decision: row.decision, reason: JSON.parse(row.metadata).reason };
}

test('an auditor reads audit data without being able to read secrets', async () => {
  await root.access.set(AUDITOR, { market: 'auditor' });
  assert.ok((await auditor.audit.list()).entries.length > 0);
  await assert.rejects(auditor.secrets.reveal('market/prod/API_KEY'), { status: 403 });
  await assert.rejects(auditor.secrets.reveal('market/prod'), { status: 403 });
  await assert.rejects(auditor.secrets.list('market/prod'), { status: 403 });
});

test('only instance-wide administrators can verify the complete chain', async () => {
  await root.access.set(AUDITOR, { market: 'auditor' });
  await assert.rejects(auditor.audit.verify(), { status: 403 });
  assert.equal((await root.audit.verify()).ok, true);
});

test('an access manager grants access without being able to read secrets', async () => {
  await root.access.set(ACCESS_MANAGER, { market: 'access-manager' });
  await accessManager.access.set(DEVELOPER, { market: 'developer' });
  const { members } = await accessManager.members.list();
  assert.equal(members.find((entry) => entry.member === DEVELOPER)?.grants[0].project, 'market');
  await assert.rejects(accessManager.secrets.reveal('market/prod/API_KEY'), { status: 403 });
  await assert.rejects(accessManager.secrets.list('market/prod'), { status: 403 });
});

test('a project access manager cannot add an unknown member to the directory', async () => {
  await root.access.set(ACCESS_MANAGER, { market: 'access-manager' });
  await assert.rejects(
    accessManager.access.set('user:unknown@acme.example', { market: 'developer' }),
    { status: 409 },
  );
  await assert.rejects(accessManager.members.add('user:unknown@acme.example'), { status: 403 });
  assert.deepEqual(
    await db.owner
      .select({ id: principals.principalId })
      .from(principals)
      .where(eq(principals.principalId, 'unknown@acme.example')),
    [],
  );
});

test('an access manager cannot read the audit log', async () => {
  await root.access.set(ACCESS_MANAGER, { market: 'access-manager' });
  await assert.rejects(accessManager.audit.list(), { status: 403 });
});

test('an auditor sees only projects on which they hold audit.read', async () => {
  await root.projects.create('other', { name: 'Other' });
  await root.environments.create('other/prod', { name: 'Production' });
  await root.secrets.set('other/prod', { OTHER_KEY: 'x' });
  await root.access.set(AUDITOR, { market: 'auditor' });
  const keys = (await auditor.audit.list({ limit: 200 })).entries
    .map((entry) => entry.metadata.key)
    .filter(Boolean);
  assert.ok(keys.includes('API_KEY'));
  assert.equal(keys.includes('OTHER_KEY'), false);
});

test('an archived-environment audit grant remains meaningful', async () => {
  await root.environments.create('market/dev', { name: 'Development' });
  await root.secrets.set('market/dev', { DEV_KEY: 'not-visible' });
  await root.access.set(AUDITOR, { 'market/prod': 'auditor' });
  await root.environments.update('market/prod', { archived: true });
  const me = await auditor.me();
  assert.deepEqual(me.environments, []);
  assert.equal(me.canReadAudit, true);
  const { entries } = await auditor.audit.list();
  assert.ok(entries.length > 0);
  assert.ok(entries.every((entry) => entry.environment === 'prod'));
  assert.equal(entries.some((entry) => entry.metadata.key === 'DEV_KEY'), false);
});

test('the role catalogue identifies environment-scopable roles', () => {
  assert.equal(assignableToEnvironment('auditor'), true);
  assert.equal(assignableToEnvironment('developer'), true);
  assert.equal(assignableToEnvironment('owner'), false);
  assert.equal((ROLES.auditor.permissions as readonly string[]).includes('secret.read'), false);
});

test('an unknown role is rejected before anything is granted', async () => {
  await assert.rejects(
    root.access.set(DEVELOPER, { market: 'made-up' as 'viewer' }),
    { status: 400 },
  );
  assert.deepEqual(
    await db.owner.select({ id: grants.id }).from(grants).where(eq(grants.principalId, 'dev@acme.example')),
    [],
  );
});

test('an expired grant confers nothing while a live grant works', async () => {
  const until = new Date(Date.now() + 60_000).toISOString();
  await root.access.set(DEVELOPER, { market: { role: 'viewer', until } });
  await db.owner
    .update(grants)
    .set({ expiresAt: new Date(Date.now() - 60_000) })
    .where(and(eq(grants.principalType, 'user'), eq(grants.principalId, 'dev@acme.example')));
  await assert.rejects(developer.secrets.reveal('market/prod/API_KEY'), { status: 403 });
  assert.deepEqual(
    (await root.members.list()).members.find((entry) => entry.member === DEVELOPER)?.grants,
    [],
  );

  assert.deepEqual(
    await root.access.set(DEVELOPER, { market: { role: 'viewer', until } }),
    { changes: { market: 'created' } },
  );
  assert.equal(
    (await developer.secrets.reveal('market/prod/API_KEY')).values.API_KEY,
    'sk_live_secret',
  );
});

test('archiving a secret removes it from reads and bulk fetch', async () => {
  await root.secrets.update('market/prod/API_KEY', { archived: true });
  await assert.rejects(root.secrets.reveal('market/prod/API_KEY'), { status: 404 });
  assert.deepEqual((await root.secrets.reveal('market/prod')).values, {});
});

test('archiving is audited, reversible, and preserves the value', async () => {
  await root.secrets.update('market/prod/API_KEY', { archived: true });
  await root.secrets.update('market/prod/API_KEY', { archived: false });
  assert.equal(
    (await root.secrets.reveal('market/prod/API_KEY')).values.API_KEY,
    'sk_live_secret',
  );
  const actions = (await db.owner.select({ action: auditLog.action }).from(auditLog)).map((row) => row.action);
  assert.ok(actions.includes('secret.archive'));
  assert.ok(actions.includes('secret.restore'));
});

test('a developer cannot archive a secret and the denial is audited', async () => {
  await root.access.set(DEVELOPER, { market: 'developer' });
  await assert.rejects(
    developer.secrets.update('market/prod/API_KEY', { archived: true }),
    { status: 403 },
  );
  assert.deepEqual(await lastAudit('secret.update'), { decision: 'deny', reason: 'missing_secret_archive' });
  await assert.rejects(developer.secrets.set('market/prod', { API_KEY: null }), { status: 403 });
  assert.deepEqual(await lastAudit('secret.write'), { decision: 'deny', reason: 'missing_secret_archive' });
});

test('writing to an archived key requires an explicit restore', async () => {
  await root.secrets.update('market/prod/API_KEY', { archived: true });
  await assert.rejects(root.secrets.set('market/prod', { API_KEY: 'rotated' }), { status: 409 });
  await root.secrets.update('market/prod/API_KEY', { archived: false });
  assert.deepEqual(
    (await root.secrets.set('market/prod', { API_KEY: 'rotated' })).keys,
    { API_KEY: { version: 2 } },
  );
  assert.equal((await root.secrets.reveal('market/prod/API_KEY')).values.API_KEY, 'rotated');
});

test('the audit chain verifies across roles, expiry, and archiving', async () => {
  await root.access.set(AUDITOR, { market: 'auditor' });
  await root.access.set(DEVELOPER, {
    market: { role: 'viewer', until: new Date(Date.now() + 60_000).toISOString() },
  });
  await developer.secrets.reveal('market/prod/API_KEY');
  await root.secrets.update('market/prod/API_KEY', { archived: true });
  assert.equal((await root.audit.verify()).ok, true);
});

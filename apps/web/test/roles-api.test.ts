import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';

import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from '../../../packages/db/test/connections.ts';
import { AccessDenied, NotFound } from '../src/server/services/secrets.ts';
import { requestContext, serviceFixture } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'erwin@equisafe.io';
const root = requestContext(ROOT);
const auditor = requestContext('auditor@equisafe.io');
const accessManager = requestContext('accessmgr@equisafe.io');
const developer = requestContext('dev@equisafe.io');

let pool: pg.Pool;
let runtimePool: pg.Pool;
let services: ReturnType<typeof serviceFixture>;

before(() => {
  pool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  services = serviceFixture({
    pool: runtimePool,
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    auditChainKey: CHAIN_KEY,
    rootAdmins: [ROOT],
  });
});

after(async () => {
  await runtimePool.end();
  await pool.end();
});

beforeEach(async () => {
  await pool.query('DELETE FROM audit_log');
  await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
  );
  await pool.query('UPDATE secrets SET current_version_id = NULL');
  await pool.query('DELETE FROM secret_versions');
  await pool.query('DELETE FROM secrets');
  await pool.query('DELETE FROM grants');
  await pool.query('DELETE FROM principals');
  await pool.query('DELETE FROM environments');
  await pool.query('DELETE FROM projects');

  await services.admin.createProject(root, 'market', 'Market');
  await services.admin.createEnvironment(root, 'market', 'prod', 'Production');
  await services.secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'sk_live_secret');
});

async function grant(
  principalId: string,
  role: string,
  options: { environmentSlug?: string; expiresAt?: string } = {},
) {
  return services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId,
    role,
    ...options,
  });
}

test('an auditor reads audit data without being able to read secrets', async () => {
  await grant(auditor.principal.id, 'auditor');
  assert.ok((await services.audit.list(auditor, { limit: 100 })).length > 0);
  await assert.rejects(
    services.secrets.readSecret(auditor, 'market', 'prod', 'API_KEY'),
    AccessDenied,
  );
  await assert.rejects(
    services.secrets.readEnvironment(auditor, 'market', 'prod'),
    AccessDenied,
  );
});

test('an auditor can verify chain integrity', async () => {
  await grant(auditor.principal.id, 'auditor');
  assert.equal((await services.audit.verify(auditor)).ok, true);
});

test('an access manager grants access without being able to read secrets', async () => {
  await grant(accessManager.principal.id, 'access-manager');
  await services.admin.createGrant(accessManager, 'market', {
    principalType: 'user',
    principalId: developer.principal.id,
    role: 'developer',
  });
  const principals = await services.admin.listPrincipals(accessManager);
  assert.equal(
    principals.find((entry) => entry.principalId === developer.principal.id)?.grants[0]
      .project,
    'market',
  );
  await assert.rejects(
    services.secrets.readSecret(accessManager, 'market', 'prod', 'API_KEY'),
    AccessDenied,
  );
});

test('an access manager cannot read the audit log', async () => {
  await grant(accessManager.principal.id, 'access-manager');
  await assert.rejects(services.audit.list(accessManager, { limit: 100 }), AccessDenied);
});

test('an auditor sees only projects on which they hold audit.read', async () => {
  await services.admin.createProject(root, 'other', 'Other');
  await services.admin.createEnvironment(root, 'other', 'prod', 'Production');
  await services.secrets.writeSecret(root, 'other', 'prod', 'OTHER_KEY', 'x');
  await grant(auditor.principal.id, 'auditor');
  const keys = (await services.audit.list(auditor, { limit: 200 }))
    .map((entry) => entry.metadata.key)
    .filter(Boolean);
  assert.ok(keys.includes('API_KEY'));
  assert.equal(keys.includes('OTHER_KEY'), false);
});

test('an archived-environment audit grant remains meaningful', async () => {
  await grant(auditor.principal.id, 'auditor', { environmentSlug: 'prod' });
  await services.admin.setEnvironmentArchived(root, 'market', 'prod', true);
  assert.deepEqual(await services.secrets.listAccessible(auditor), []);
  assert.equal(await services.audit.canRead(auditor), true);
  assert.ok((await services.audit.list(auditor, { limit: 100 })).length > 0);
});

test('the role catalogue identifies environment-scopable roles', async () => {
  const roles = Object.fromEntries(
    (await services.admin.listRoles()).map((role) => [role.slug, role]),
  );
  assert.equal(roles.auditor.assignableToEnvironment, true);
  assert.equal(roles.developer.assignableToEnvironment, true);
  assert.equal(roles.owner.assignableToEnvironment, false);
  assert.equal(roles.auditor.permissions.includes('secret.read'), false);
});

test('an unknown role is rejected and audited', async () => {
  await assert.rejects(grant(developer.principal.id, 'made-up'), NotFound);
  const row = await pool.query(
    "SELECT decision, metadata FROM audit_log WHERE action = 'grant.create' ORDER BY seq DESC LIMIT 1",
  );
  assert.equal(row.rows[0].decision, 'deny');
  assert.equal(JSON.parse(row.rows[0].metadata).reason, 'unknown_role');
});

test('an expired grant confers nothing while a live grant works', async () => {
  await grant(developer.principal.id, 'viewer', {
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });
  await assert.rejects(
    services.secrets.readSecret(developer, 'market', 'prod', 'API_KEY'),
    AccessDenied,
  );

  await pool.query('DELETE FROM grants WHERE principal_id = $1', [developer.principal.id]);
  await grant(developer.principal.id, 'viewer', {
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  assert.equal(
    (await services.secrets.readSecret(developer, 'market', 'prod', 'API_KEY')).value,
    'sk_live_secret',
  );
});

test('archiving a secret removes it from reads and bulk fetch', async () => {
  await services.secrets.setSecretArchived(root, 'market', 'prod', 'API_KEY', true);
  await assert.rejects(
    services.secrets.readSecret(root, 'market', 'prod', 'API_KEY'),
    NotFound,
  );
  assert.deepEqual(
    (await services.secrets.readEnvironment(root, 'market', 'prod')).secrets,
    {},
  );
});

test('archiving is audited, reversible, and preserves the value', async () => {
  await services.secrets.setSecretArchived(root, 'market', 'prod', 'API_KEY', true);
  await services.secrets.setSecretArchived(root, 'market', 'prod', 'API_KEY', false);
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'prod', 'API_KEY')).value,
    'sk_live_secret',
  );
  const actions = await pool.query(
    "SELECT action FROM audit_log WHERE action LIKE 'secret.%' ORDER BY seq",
  );
  assert.ok(actions.rows.some((row) => row.action === 'secret.archive'));
  assert.ok(actions.rows.some((row) => row.action === 'secret.restore'));
});

test('a developer cannot archive a secret and the denial is audited', async () => {
  await grant(developer.principal.id, 'developer');
  await assert.rejects(
    services.secrets.setSecretArchived(developer, 'market', 'prod', 'API_KEY', true),
    AccessDenied,
  );
  const row = await pool.query(
    "SELECT decision, metadata FROM audit_log WHERE action = 'secret.archive' ORDER BY seq DESC LIMIT 1",
  );
  assert.equal(row.rows[0].decision, 'deny');
  assert.equal(JSON.parse(row.rows[0].metadata).reason, 'missing_secret_archive');
});

test('writing to an archived key restores it with a new version', async () => {
  await services.secrets.setSecretArchived(root, 'market', 'prod', 'API_KEY', true);
  assert.equal(
    (await services.secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'rotated')).version,
    2,
  );
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'prod', 'API_KEY')).value,
    'rotated',
  );
});

test('the audit chain verifies across roles, expiry, and archiving', async () => {
  await grant(auditor.principal.id, 'auditor');
  await grant(developer.principal.id, 'viewer', {
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  await services.secrets.readSecret(developer, 'market', 'prod', 'API_KEY');
  await services.secrets.setSecretArchived(root, 'market', 'prod', 'API_KEY', true);
  assert.equal((await services.audit.verify(root)).ok, true);
});

import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';

import { DevIdp } from '../../dev-idp/src/idp.ts';
import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from '../../../packages/db/test/connections.ts';
import { buildApp } from '../src/app.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HEADER = 'cf-access-jwt-assertion';
const CHAIN_KEY = randomBytes(32);
const ROOT = 'erwin@equisafe.io';

let idp: DevIdp;
let pool: pg.Pool;
let runtimePool: pg.Pool;
let app: FastifyInstance;

const tokens: Record<string, string> = {};

before(async () => {
  idp = new DevIdp();
  await idp.start();
  pool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });

  app = buildApp({
    pool: runtimePool,
    authMode: 'dev',
    verifier: new AccessIdentityVerifier({
      issuer: idp.issuer,
      jwksUrl: idp.jwksUrl,
      audience: AUD,
    }),
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    auditChainKey: CHAIN_KEY,
    rootAdmins: [ROOT],
  });
  await app.ready();

  for (const who of [ROOT, 'auditor@equisafe.io', 'accessmgr@equisafe.io', 'dev@equisafe.io']) {
    tokens[who] = await idp.mintUserToken({ audience: AUD, email: who });
  }
});

after(async () => {
  await app.close();
  await runtimePool.end();
  await pool.end();
  await idp.stop();
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

  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects',
    ...req(ROOT),
    payload: { slug: 'market', name: 'Market' },
  });
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/environments',
    ...req(ROOT),
    payload: { slug: 'prod', name: 'Production' },
  });
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req(ROOT),
    payload: { value: 'sk_live_secret' },
  });
});

function req(who: string) {
  return { headers: { [HEADER]: tokens[who] } };
}

async function grant(payload: Record<string, unknown>) {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/grants',
    ...req(ROOT),
    payload,
  });
  assert.equal(response.statusCode, 201, JSON.stringify(response.json()));
  return response.json();
}

// --- the segregation cases these roles exist for -----------------------------

test('an auditor reads the audit log WITHOUT being able to read secrets', async () => {
  await grant({
    principalType: 'user',
    principalId: 'auditor@equisafe.io',
    role: 'auditor',
  });

  const audit = await app.inject({
    method: 'GET',
    url: '/v1/audit',
    ...req('auditor@equisafe.io'),
  });
  assert.equal(audit.statusCode, 200);
  assert.ok(audit.json().entries.length > 0, 'auditor should see entries');

  // The point of the role: audit visibility without the vault.
  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req('auditor@equisafe.io'),
  });
  assert.equal(read.statusCode, 403);

  const bulk = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets',
    ...req('auditor@equisafe.io'),
  });
  assert.equal(bulk.statusCode, 403);
});

test('an auditor can verify chain integrity', async () => {
  await grant({
    principalType: 'user',
    principalId: 'auditor@equisafe.io',
    role: 'auditor',
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req('auditor@equisafe.io'),
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.json().ok, true);
});

test('an access manager grants access WITHOUT being able to read secrets', async () => {
  await grant({
    principalType: 'user',
    principalId: 'accessmgr@equisafe.io',
    role: 'access-manager',
  });

  // They can administer access...
  const created = await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/grants',
    ...req('accessmgr@equisafe.io'),
    payload: {
      principalType: 'user',
      principalId: 'dev@equisafe.io',
      role: 'developer',
    },
  });
  assert.equal(created.statusCode, 201);

  // The grant-aware operational overview remains available to project access
  // managers even though the instance directory is owner-only.
  const overview = await app.inject({
    method: 'GET',
    url: '/v1/admin/principals',
    ...req('accessmgr@equisafe.io'),
  });
  assert.equal(overview.statusCode, 200);
  const developer = overview
    .json()
    .principals.find(
      (principal: { principalId: string }) =>
        principal.principalId === 'dev@equisafe.io',
    );
  assert.equal(developer.grants[0].project, 'market');

  // ...but cannot read the secrets they are handing out access to.
  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req('accessmgr@equisafe.io'),
  });
  assert.equal(read.statusCode, 403);
});

test('an access manager cannot read the audit log', async () => {
  await grant({
    principalType: 'user',
    principalId: 'accessmgr@equisafe.io',
    role: 'access-manager',
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/audit',
    ...req('accessmgr@equisafe.io'),
  });

  assert.equal(response.statusCode, 403);
});

test('an auditor sees only the projects they hold audit.read on', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects',
    ...req(ROOT),
    payload: { slug: 'other', name: 'Other' },
  });
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/other/environments',
    ...req(ROOT),
    payload: { slug: 'prod', name: 'Production' },
  });
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/other/environments/prod/secrets/OTHER_KEY',
    ...req(ROOT),
    payload: { value: 'x' },
  });

  await grant({
    principalType: 'user',
    principalId: 'auditor@equisafe.io',
    role: 'auditor',
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/audit?limit=200',
    ...req('auditor@equisafe.io'),
  });

  assert.equal(response.statusCode, 200);
  const keys = response
    .json()
    .entries.map((entry: { metadata: { key?: string } }) => entry.metadata.key)
    .filter(Boolean);

  assert.ok(keys.includes('API_KEY'), 'should see the market project');
  assert.equal(keys.includes('OTHER_KEY'), false, 'must not see another project');
});

test('an archived environment audit grant remains visible in the shell', async () => {
  await grant({
    principalType: 'user',
    principalId: 'auditor@equisafe.io',
    role: 'auditor',
    environmentSlug: 'prod',
  });
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/environments/prod/archive',
    ...req(ROOT),
    payload: { archived: true },
  });

  const me = await app.inject({
    method: 'GET',
    url: '/v1/me',
    ...req('auditor@equisafe.io'),
  });
  const audit = await app.inject({
    method: 'GET',
    url: '/v1/audit',
    ...req('auditor@equisafe.io'),
  });

  assert.equal(me.statusCode, 200);
  assert.deepEqual(me.json().environments, []);
  assert.equal(me.json().canReadAudit, true);
  assert.equal(audit.statusCode, 200);
});

// --- roles ------------------------------------------------------------------

test('the role catalogue reports which roles may be scoped to an environment', async () => {
  const response = await app.inject({ method: 'GET', url: '/v1/admin/roles', ...req(ROOT) });
  assert.equal(response.statusCode, 200);

  const roles: Record<string, { assignableToEnvironment: boolean; permissions: string[] }> =
    Object.fromEntries(
      response.json().roles.map((role: { slug: string }) => [role.slug, role]),
    );

  assert.equal(roles.viewer.assignableToEnvironment, true);
  assert.equal(roles.developer.assignableToEnvironment, true);
  assert.equal(roles.auditor.assignableToEnvironment, true);

  // These carry project-only permissions.
  assert.equal(roles.owner.assignableToEnvironment, false);
  assert.equal(roles.maintainer.assignableToEnvironment, false);
  assert.equal(roles['access-manager'].assignableToEnvironment, false);

  // The separation that motivated roles at all.
  assert.equal(roles.auditor.permissions.includes('secret.read'), false);
  assert.equal(roles['access-manager'].permissions.includes('secret.read'), false);
});

test('an unknown role is rejected', async () => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/grants',
    ...req(ROOT),
    payload: { principalType: 'user', principalId: 'x@equisafe.io', role: 'superuser' },
  });

  assert.equal(response.statusCode, 404);
});

// --- grant expiry -----------------------------------------------------------

test('an expired grant confers nothing', async () => {
  await grant({
    principalType: 'user',
    principalId: 'dev@equisafe.io',
    role: 'developer',
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req('dev@equisafe.io'),
  });
  assert.equal(read.statusCode, 403);

  const me = await app.inject({ method: 'GET', url: '/v1/me', ...req('dev@equisafe.io') });
  assert.deepEqual(me.json().environments, []);
});

test('a grant that has not yet expired still works', async () => {
  await grant({
    principalType: 'user',
    principalId: 'dev@equisafe.io',
    role: 'developer',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  });

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req('dev@equisafe.io'),
  });

  assert.equal(read.statusCode, 200);
  assert.equal(read.json().value, 'sk_live_secret');
});

// --- secret archiving -------------------------------------------------------

test('archiving a secret stops it being served and drops it from bulk fetch', async () => {
  const archived = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req(ROOT),
    payload: { archived: true },
  });
  assert.equal(archived.statusCode, 200);

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req(ROOT),
  });
  assert.equal(read.statusCode, 404);

  // The reason archiving matters: a rotated-out credential must stop being
  // injected into every process started by `coffre run`.
  const bulk = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets',
    ...req(ROOT),
  });
  assert.deepEqual(bulk.json().secrets, {});
});

test('archiving a secret is audited and reversible, and the value survives', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req(ROOT),
    payload: { archived: true },
  });
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req(ROOT),
    payload: { archived: false },
  });

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req(ROOT),
  });
  assert.equal(read.statusCode, 200);
  assert.equal(read.json().value, 'sk_live_secret');

  const actions = await pool.query(
    "SELECT action FROM audit_log WHERE action LIKE 'secret.%' ORDER BY seq",
  );
  const names = actions.rows.map((row) => row.action);
  assert.ok(names.includes('secret.archive'));
  assert.ok(names.includes('secret.restore'));
});

test('a developer cannot archive a secret: that needs secret.archive', async () => {
  await grant({
    principalType: 'user',
    principalId: 'dev@equisafe.io',
    role: 'developer',
  });

  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req('dev@equisafe.io'),
    payload: { archived: true },
  });

  assert.equal(response.statusCode, 403);

  const denial = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.archive' AND decision = 'deny'",
  );
  assert.equal(JSON.parse(denial.rows[0].metadata).reason, 'missing_secret_archive');
});

test('writing to an archived key restores it', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req(ROOT),
    payload: { archived: true },
  });

  const written = await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req(ROOT),
    payload: { value: 'rotated' },
  });
  assert.equal(written.statusCode, 200);

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY',
    ...req(ROOT),
  });
  assert.equal(read.json().value, 'rotated');
});

test('the audit chain still verifies across roles, expiry and archiving', async () => {
  await grant({ principalType: 'user', principalId: 'auditor@equisafe.io', role: 'auditor' });
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/prod/secrets/API_KEY/archive',
    ...req(ROOT),
    payload: { archived: true },
  });

  const verify = await app.inject({ method: 'GET', url: '/v1/audit/verify', ...req(ROOT) });
  assert.equal(verify.json().ok, true);
});

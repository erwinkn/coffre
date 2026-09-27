import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';

import { defineSignin, github } from '../../../packages/core/src/identity/signin/config.ts';
import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from '../../../packages/db/test/connections.ts';
import { AdminService } from '../src/server/services/admin.ts';
import { AccessDenied, NotFound, SecretsService } from '../src/server/services/secrets.ts';
import { SigninService } from '../src/server/services/signin.ts';
import { SyncService } from '../src/server/services/sync.ts';
import { requestContext } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'admin@acme.example';
const LEAD = 'lead@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'ci-deploy';
const IP = '203.0.113.7';

const root = requestContext(ROOT);
const lead = requestContext(LEAD);
const dev = requestContext(DEV);

let pool: pg.Pool;
let runtimePool: pg.Pool;
let admin: AdminService;
let secrets: SecretsService;
let signin: SigninService;
let syncs: SyncService;

async function clean(): Promise<void> {
  await pool.query('DELETE FROM sync_keys');
  await pool.query('DELETE FROM syncs');
  await pool.query('DELETE FROM credentials');
  await pool.query('DELETE FROM device_authorizations');
  await pool.query('DELETE FROM identities');
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
}

before(() => {
  pool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  const keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  const deps = { pool: runtimePool, keks, auditChainKey: CHAIN_KEY, rootAdmins: [ROOT] };
  admin = new AdminService(deps);
  secrets = new SecretsService(deps);
  syncs = new SyncService({ ...deps, waitUntil: () => {} });
  signin = new SigninService({
    ...deps,
    signin: defineSignin({
      publicUrl: 'https://secrets.acme.example',
      providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
    }),
  });
});

after(async () => {
  // Later suites delete principals and secrets, which these rows reference.
  await clean();
  await runtimePool.end();
  await pool.end();
});

beforeEach(async () => {
  await clean();
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
     VALUES ('user', $1, 'owner', $4, true), ('user', $2, 'user', $4, true),
            ('service', $3, 'user', $4, true)`,
    [LEAD, DEV, SERVICE, ROOT],
  );
  await admin.createProject(root, 'market', 'Market');
  await admin.createEnvironment(root, 'market', 'prod', 'Production');
  await admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: DEV,
    role: 'developer',
  });
});

function meta() {
  return { requestId: randomUUID(), sourceIp: IP, label: 'Firefox on macOS' };
}

async function browserSession(email: string, subject: string) {
  const result = await signin.completeSignin(
    { provider: 'github', subject, emails: [email], name: null },
    meta(),
  );
  assert.equal(result.ok, true, `expected ${email} to be let in`);
  if (!result.ok) throw new Error('unreachable');
  return result.credential;
}

async function cliSession(ctx: ReturnType<typeof requestContext>) {
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: IP });
  await signin.decideDevice(ctx, started.userCode, true);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: IP });
  assert.equal(polled.status, 'approved');
  if (polled.status !== 'approved') throw new Error('unreachable');
  return polled.credential;
}

function readd(principalType: 'user' | 'service', principalId: string) {
  return admin.addDirectoryPrincipal(root, { principalType, principalId, instanceRole: 'user' });
}

// --- removal ------------------------------------------------------------------

test('removing someone revokes every way in, so re-adding them starts from nothing', async () => {
  const browser = await browserSession(DEV, 'gh-101');
  const cli = await cliSession(dev);

  assert.deepEqual(await admin.removeDirectoryPrincipal(root, 'user', DEV), {
    revoked: 1,
    sessions: 2,
    tokens: 0,
    identities: 1,
  });
  await readd('user', DEV);

  await assert.rejects(signin.verify(browser.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(cli.token), /unknown, expired or revoked/);
  assert.equal((await secrets.listAccessible(dev)).length, 0, 'grants stay gone');

  // The same account signs in again, bound afresh by email.
  const again = await browserSession(DEV, 'gh-101');
  assert.equal((await signin.verify(again.token)).id, DEV);

  const removal = await pool.query(
    `SELECT metadata::jsonb AS metadata FROM audit_log
      WHERE action = 'directory.remove' AND project_id IS NULL`,
  );
  assert.deepEqual(removal.rows[0].metadata, {
    principalType: 'user',
    principalId: DEV,
    revoked: 1,
    sessions: 2,
    tokens: 0,
    identities: 1,
  });
});

test('a removed service loses its tokens for good', async () => {
  const token = await signin.issueServiceToken(lead, SERVICE, { label: 'ci', expiresInDays: 30 });
  assert.deepEqual(await admin.removeDirectoryPrincipal(root, 'service', SERVICE), {
    revoked: 0,
    sessions: 0,
    tokens: 1,
    identities: 0,
  });
  await readd('service', SERVICE);
  await assert.rejects(signin.verify(token.token), /unknown, expired or revoked/);
});

test('a CLI sign-in approved before removal cannot be collected after re-adding', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await signin.decideDevice(dev, started.userCode, true);
  await admin.removeDirectoryPrincipal(root, 'user', DEV);
  await readd('user', DEV);

  assert.deepEqual(
    await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: IP }),
    { status: 'denied' },
  );
  assert.equal((await pool.query("SELECT 1 FROM credentials WHERE kind = 'cli'")).rowCount, 0);
});

// --- the report ---------------------------------------------------------------

test('the report lists the current values someone saw, until each is rotated', async () => {
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-1');
  await secrets.writeSecret(root, 'market', 'prod', 'DB_URL', 'postgres://one');
  await secrets.writeSecret(root, 'market', 'prod', 'SESSION_SECRET', 'secret-1');
  await secrets.readSecret(dev, 'market', 'prod', 'API_KEY');
  await secrets.readEnvironment(dev, 'market', 'prod');
  await secrets.writeSecret(dev, 'market', 'prod', 'NEW_FLAG', 'on');

  const exposed = async () =>
    (await admin.offboardingReport(root, 'user', DEV)).exposed.map(
      ({ key, version, how }) => `${key} v${version} ${how}`,
    );

  assert.deepEqual(await exposed(), [
    'API_KEY v1 read',
    'DB_URL v1 read',
    'NEW_FLAG v1 wrote',
    'SESSION_SECRET v1 read',
  ]);

  // Rotating takes a value off; rolling back to a value they saw puts it back.
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-2');
  await secrets.writeSecret(root, 'market', 'prod', 'SESSION_SECRET', 'secret-2');
  assert.deepEqual(await exposed(), ['DB_URL v1 read', 'NEW_FLAG v1 wrote']);
  assert.equal((await admin.offboardingReport(root, 'user', DEV)).rotated, 2);

  await secrets.rollback(root, 'market', 'prod', 'API_KEY', 1);
  assert.deepEqual(await exposed(), ['API_KEY v1 read', 'DB_URL v1 read', 'NEW_FLAG v1 wrote']);

  // Archived values are not served any more, so they drop off too.
  await secrets.setSecretArchived(root, 'market', 'prod', 'DB_URL', true);
  assert.deepEqual(await exposed(), ['API_KEY v1 read', 'NEW_FLAG v1 wrote']);

  const report = await admin.offboardingReport(root, 'user', DEV);
  assert.equal(report.exposed[0].project, 'market');
  assert.equal(report.exposed[0].environment, 'prod');
  assert.ok(Date.parse(report.exposed[0].at) <= Date.now());
});

test('removed people stay listed, with as many values to rotate as their report', async () => {
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-1');
  await secrets.writeSecret(root, 'market', 'prod', 'DB_URL', 'postgres://one');
  await secrets.readEnvironment(dev, 'market', 'prod');
  await secrets.readSecret(dev, 'market', 'prod', 'API_KEY');
  assert.deepEqual(await admin.listRemoved(root), []);

  await admin.removeDirectoryPrincipal(root, 'user', DEV);
  await admin.removeDirectoryPrincipal(root, 'service', SERVICE);
  const listed = async () =>
    (await admin.listRemoved(root)).map(
      ({ principalType, principalId, toRotate }) => `${principalType}:${principalId} ${toRotate}`,
    );
  assert.deepEqual(await listed(), [`user:${DEV} 2`, `service:${SERVICE} 0`]);
  assert.equal((await admin.offboardingReport(root, 'user', DEV)).exposed.length, 2);

  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-2');
  assert.deepEqual(await listed(), [`user:${DEV} 1`, `service:${SERVICE} 0`]);

  await readd('user', DEV);
  assert.deepEqual(await listed(), [`service:${SERVICE} 0`]);
  await assert.rejects(admin.listRemoved(dev), AccessDenied);
});

test('the report tells who removed someone, and that nothing still lets them in', async () => {
  await browserSession(DEV, 'gh-101');
  const before = await admin.offboardingReport(root, 'user', DEV);
  assert.equal(before.status, 'active');
  assert.equal(before.instanceRole, 'user');
  assert.deepEqual(before.live, { grants: 1, sessions: 1, tokens: 0, identities: 1 });
  assert.equal(before.removedAt, null);

  await admin.removeDirectoryPrincipal(lead, 'user', DEV);
  const after = await admin.offboardingReport(root, 'user', DEV);
  assert.equal(after.status, 'removed');
  assert.equal(after.removedBy, LEAD);
  assert.ok(after.removedAt !== null);
  assert.deepEqual(after.live, { grants: 0, sessions: 0, tokens: 0, identities: 0 });

  await readd('user', DEV);
  const back = await admin.offboardingReport(root, 'user', DEV);
  assert.equal(back.status, 'active');
  assert.equal(back.removedAt, null);
});

test('the report lists service tokens someone issued, while they still work', async () => {
  const token = await signin.issueServiceToken(lead, SERVICE, { label: 'deploys', expiresInDays: 30 });
  await signin.issueServiceToken(root, SERVICE, { label: 'not theirs', expiresInDays: 30 });

  const issued = (await admin.offboardingReport(root, 'user', LEAD)).issuedTokens;
  assert.deepEqual(
    issued.map(({ id, service, label }) => ({ id, service, label })),
    [{ id: token.id, service: SERVICE, label: 'deploys' }],
  );

  await admin.removeDirectoryPrincipal(root, 'service', SERVICE);
  assert.deepEqual((await admin.offboardingReport(root, 'user', LEAD)).issuedTokens, []);
});

test('the syncs someone set up are listed with where they push', async () => {
  await secrets.writeSecret(root, 'market', 'prod', 'GITHUB_TOKEN_FOR_SYNC', 'ghp_fake');
  const ids = await pool.query<{ project_id: string; environment_id: string; id: string }>(
    `SELECT s.project_id, s.environment_id, s.id FROM secrets s WHERE s.key = 'GITHUB_TOKEN_FOR_SYNC'`,
  );
  const { project_id, environment_id, id } = ids.rows[0];
  await pool.query(
    `INSERT INTO syncs (project_id, environment_id, provider, config, credential_secret_id, created_by)
     VALUES ($1, $2, 'github-actions', $3, $4, $5), ($1, $2, 'github-actions', $6, $4, $7)`,
    [
      project_id,
      environment_id,
      JSON.stringify({ owner: 'acme', repo: 'app' }),
      id,
      DEV,
      JSON.stringify({ owner: 'acme', repo: 'other' }),
      ROOT,
    ],
  );

  const listed = await syncs.listCreatedBy(root, DEV);
  assert.deepEqual(
    listed.map(({ project, environment, providerLabel, destination, credential }) => ({
      project,
      environment,
      providerLabel,
      destination,
      credential,
    })),
    [
      {
        project: 'market',
        environment: 'prod',
        providerLabel: 'GitHub Actions',
        destination: 'acme/app',
        credential: 'market/prod/GITHUB_TOKEN_FOR_SYNC',
      },
    ],
  );
});

test('only owners see reports, and only about someone who exists', async () => {
  await assert.rejects(admin.offboardingReport(dev, 'user', DEV), AccessDenied);
  await assert.rejects(syncs.listCreatedBy(dev, DEV), AccessDenied);
  await assert.rejects(admin.offboardingReport(root, 'user', 'nobody@acme.example'), NotFound);

  const rootReport = await admin.offboardingReport(lead, 'user', ROOT);
  assert.equal(rootReport.status, 'active');
  assert.equal(rootReport.instanceRole, 'root-admin');
});

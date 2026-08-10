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
const lead = requestContext('lead@equisafe.io');
const reader = requestContext('reader@equisafe.io');
const outsider = requestContext('outsider@equisafe.io');
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
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
     VALUES
       ('user', $1, 'user', $3, true),
       ('user', $2, 'user', $3, true),
       ('service', 'ci-deploy.access', 'user', $3, true)`,
    [lead.principal.id, reader.principal.id, ROOT],
  );
});

async function seedProject(): Promise<void> {
  await services.admin.createProject(root, 'market', 'Equisafe Market');
  await services.admin.createEnvironment(root, 'market', 'prod', 'Production');
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: lead.principal.id,
    role: 'owner',
  });
}

async function auditActions(): Promise<{ action: string; decision: string }[]> {
  const result = await pool.query('SELECT action, decision FROM audit_log ORDER BY seq');
  return result.rows;
}

function isConflict(error: unknown): boolean {
  return (error as { statusCode?: number }).statusCode === 409;
}

test('root admins and instance owners create projects without implicit secret grants', async () => {
  const owner = requestContext('instance-owner@equisafe.io');
  await services.admin.addDirectoryPrincipal(root, {
    principalType: 'user',
    principalId: owner.principal.id,
    instanceRole: 'owner',
  });
  assert.deepEqual(await services.admin.createProject(root, 'market', 'Market'), {
    slug: 'market',
    name: 'Market',
  });
  assert.deepEqual(await services.admin.createProject(owner, 'operations', 'Operations'), {
    slug: 'operations',
    name: 'Operations',
  });
  await assert.rejects(
    services.admin.createProject(outsider, 'sneaky', 'Sneaky'),
    AccessDenied,
  );
  assert.deepEqual(await auditActions(), [
    { action: 'directory.create', decision: 'allow' },
    { action: 'project.create', decision: 'allow' },
    { action: 'project.create', decision: 'allow' },
    { action: 'project.create', decision: 'deny' },
  ]);
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM projects')).rows[0].n,
    2,
  );
  assert.equal(
    (
      await pool.query(
        'SELECT count(*)::int AS n FROM grants WHERE principal_id = $1',
        [owner.principal.id],
      )
    ).rows[0].n,
    0,
  );
});

test('only configured bootstrap principals project as root admins', async () => {
  assert.equal(await services.admin.instanceRole(root.principal), 'root-admin');
  assert.equal(await services.admin.instanceRole(outsider.principal), 'user');
  assert.equal(await services.audit.canRead(root), true);
  assert.equal(await services.audit.canRead(outsider), false);
});

test('duplicate project slugs are conflicts', async () => {
  await services.admin.createProject(root, 'market', 'Market');
  await assert.rejects(
    services.admin.createProject(root, 'market', 'Again'),
    isConflict,
  );
});

test('renaming a project slug preserves its encrypted secrets', async () => {
  await seedProject();
  await services.secrets.writeSecret(root, 'market', 'prod', 'DATABASE_URL', 'postgres://x');
  await services.admin.updateProject(root, 'market', { slug: 'marketplace' });
  assert.equal(
    (await services.secrets.readSecret(root, 'marketplace', 'prod', 'DATABASE_URL')).value,
    'postgres://x',
  );
});

test('renaming projects and environments to existing slugs is a conflict and is audited', async () => {
  await seedProject();
  await services.admin.createProject(root, 'other', 'Other');
  await services.admin.createEnvironment(root, 'market', 'dev', 'Development');

  await assert.rejects(
    services.admin.updateProject(root, 'market', { slug: 'other' }),
    isConflict,
  );
  await assert.rejects(
    services.admin.updateEnvironment(root, 'market', 'prod', { slug: 'dev' }),
    isConflict,
  );

  const denials = await pool.query(
    `SELECT action, metadata
       FROM audit_log
      WHERE decision = 'deny' AND action IN ('project.update', 'environment.update')
      ORDER BY seq`,
  );
  assert.deepEqual(
    denials.rows.map((row) => [row.action, JSON.parse(row.metadata).reason]),
    [
      ['project.update', 'slug_taken'],
      ['environment.update', 'slug_taken'],
    ],
  );
});

test('project owners create environments; environment-scoped grants do not', async () => {
  await seedProject();
  assert.deepEqual(
    await services.admin.createEnvironment(lead, 'market', 'staging', 'Staging'),
    { slug: 'staging', name: 'Staging' },
  );
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'developer',
    environmentSlug: 'prod',
  });
  await assert.rejects(
    services.admin.createEnvironment(reader, 'market', 'nope', 'Nope'),
    AccessDenied,
  );
  assert.equal((await auditActions()).at(-1)?.action, 'environment.create');
  assert.equal((await auditActions()).at(-1)?.decision, 'deny');
});

test('project-only roles cannot be scoped to one environment', async () => {
  await seedProject();
  await assert.rejects(
    services.admin.createGrant(root, 'market', {
      principalType: 'user',
      principalId: reader.principal.id,
      role: 'owner',
      environmentSlug: 'prod',
    }),
    isConflict,
  );
  assert.equal((await auditActions()).at(-1)?.decision, 'deny');
});

test('environment archiving hides reads, is reversible, and preserves values', async () => {
  await seedProject();
  await services.secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'still-here');
  await services.admin.setEnvironmentArchived(root, 'market', 'prod', true);
  await assert.rejects(
    services.secrets.readSecret(root, 'market', 'prod', 'API_KEY'),
    NotFound,
  );
  assert.deepEqual(await services.secrets.listAccessible(root), []);
  await services.admin.setEnvironmentArchived(root, 'market', 'prod', false);
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'prod', 'API_KEY')).value,
    'still-here',
  );
});

test('project archiving hides every environment', async () => {
  await seedProject();
  await services.admin.createEnvironment(root, 'market', 'dev', 'Development');
  await services.admin.setProjectArchived(root, 'market', true);
  assert.deepEqual(await services.secrets.listAccessible(root), []);
});

test('archived projects stay visible only to project and instance administrators', async () => {
  await seedProject();
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await services.admin.setProjectArchived(root, 'market', true);

  assert.deepEqual(await services.admin.listProjects(reader), []);
  assert.equal((await services.admin.listProjects(lead))[0].archivedAt === null, false);
  assert.equal((await services.admin.listProjects(root))[0].archivedAt === null, false);
});

test('project grants cover every environment and combine with environment grants', async () => {
  await seedProject();
  await services.admin.createEnvironment(root, 'market', 'dev', 'Development');
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'developer',
    environmentSlug: 'prod',
  });
  const access = await services.secrets.listAccessible(reader);
  assert.deepEqual(access.map((entry) => entry.environment).sort(), ['dev', 'prod']);
  assert.deepEqual(
    access.find((entry) => entry.environment === 'prod')?.permissions.sort(),
    ['secret.read', 'secret.write'],
  );
});

test('revoking and updating grants changes access in place and is audited', async () => {
  await seedProject();
  const created = await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  assert.equal((await services.secrets.listAccessible(reader)).length, 1);
  await services.admin.updateGrant(root, 'market', created.id, 'developer');
  assert.ok(
    (await services.secrets.listAccessible(reader))[0].permissions.includes('secret.write'),
  );
  await services.admin.revokeGrant(root, 'market', created.id);
  assert.deepEqual(await services.secrets.listAccessible(reader), []);
  assert.equal(
    (await services.admin.listGrants(root, 'market')).some((grant) => grant.id === created.id),
    false,
  );
  const actions = await auditActions();
  assert.ok(actions.some(({ action }) => action === 'grant.update'));
  assert.ok(actions.some(({ action }) => action === 'grant.revoke'));
});

test('removing a principal revokes every grant and is audited', async () => {
  await seedProject();
  await services.admin.createEnvironment(root, 'market', 'dev', 'Development');
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'developer',
    environmentSlug: 'dev',
  });
  assert.deepEqual(await services.admin.removePrincipal(root, 'user', reader.principal.id), {
    revoked: 2,
  });
  assert.deepEqual(await services.secrets.listAccessible(reader), []);
  assert.ok((await auditActions()).some(({ action }) => action === 'principal.remove'));
});

test('instance owners manage every project without receiving secret access', async () => {
  await seedProject();
  const owner = requestContext('instance-owner@equisafe.io');
  await services.admin.addDirectoryPrincipal(root, {
    principalType: 'user',
    principalId: owner.principal.id,
    instanceRole: 'owner',
  });
  await services.admin.addDirectoryPrincipal(owner, {
    principalType: 'service',
    principalId: 'reporting.access',
    instanceRole: 'user',
  });
  await services.admin.createEnvironment(owner, 'market', 'staging', 'Staging');
  await services.admin.updateProject(owner, 'market', { name: 'Market platform' });
  assert.equal(await services.admin.instanceRole(owner.principal), 'owner');
  assert.deepEqual(await services.secrets.listAccessible(owner), []);
  const project = (await services.admin.listProjects(owner))[0];
  assert.equal(project.name, 'Market platform');
  assert.deepEqual(project.permissions.sort(), [
    'environment.manage',
    'grant.manage',
    'project.manage',
  ]);
  assert.ok(
    project.environments.every(
      (environment) =>
        !environment.accessible
        && environment.details !== null
        && environment.details.secretCount === null,
    ),
  );
  assert.ok(
    (await services.admin.listDirectory(owner)).some(
      (entry) => entry.principalId === 'reporting.access',
    ),
  );
});

test('environment grants expose only the listed names of inaccessible siblings', async () => {
  await seedProject();
  await services.admin.createEnvironment(root, 'market', 'dev', 'Development');
  await services.secrets.writeSecret(root, 'market', 'prod', 'PROD_ONLY', 'one');
  await services.secrets.writeSecret(root, 'market', 'dev', 'DEV_ONLY', 'two');
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
    environmentSlug: 'dev',
  });

  const project = (await services.admin.listProjects(reader))[0];
  const dev = project.environments.find((environment) => environment.slug === 'dev');
  const prod = project.environments.find((environment) => environment.slug === 'prod');
  assert.deepEqual(dev, {
    slug: 'dev',
    name: 'Development',
    accessible: true,
    details: { archivedAt: null, secretCount: 1 },
  });
  assert.deepEqual(prod, {
    slug: 'prod',
    name: 'Production',
    accessible: false,
    details: null,
  });
});

test('offboarded principals must be explicitly re-added before regranting access', async () => {
  await seedProject();
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await services.admin.removeDirectoryPrincipal(root, 'user', reader.principal.id);
  await assert.rejects(
    services.admin.createGrant(root, 'market', {
      principalType: 'user',
      principalId: reader.principal.id,
      role: 'viewer',
    }),
    isConflict,
  );
  await services.admin.addDirectoryPrincipal(root, {
    principalType: 'user',
    principalId: reader.principal.id,
    instanceRole: 'user',
  });
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  assert.equal((await services.secrets.listAccessible(reader)).length, 1);
});

test('ordinary users cannot manage the instance directory', async () => {
  await seedProject();
  await assert.rejects(services.admin.listDirectory(lead), AccessDenied);
  await assert.rejects(
    services.admin.addDirectoryPrincipal(lead, {
      principalType: 'user',
      principalId: 'new@equisafe.io',
      instanceRole: 'user',
    }),
    AccessDenied,
  );
});

test('service accounts cannot be owners and configured roots cannot be edited', async () => {
  await assert.rejects(
    services.admin.addDirectoryPrincipal(root, {
      principalType: 'service',
      principalId: 'service.access',
      instanceRole: 'owner',
    }),
    isConflict,
  );
  await assert.rejects(
    services.admin.updateDirectoryPrincipalRole(root, ROOT, 'user'),
    isConflict,
  );
  await assert.rejects(
    services.admin.removeDirectoryPrincipal(root, 'user', ROOT),
    isConflict,
  );
});

test('service principals receive grants by common name', async () => {
  await seedProject();
  const service = requestContext('ci-deploy.access', 'service');
  await services.admin.createGrant(root, 'market', {
    principalType: 'service',
    principalId: service.principal.id,
    role: 'viewer',
  });
  assert.equal((await services.secrets.listAccessible(service)).length, 1);
});

test('project owners cannot revoke a grant belonging to another project', async () => {
  await seedProject();
  await services.admin.createProject(root, 'other', 'Other');
  const foreign = await services.admin.createGrant(root, 'other', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await assert.rejects(
    services.admin.revokeGrant(lead, 'market', foreign.id),
    NotFound,
  );
  assert.ok(
    (await services.admin.listGrants(root, 'other')).some((grant) => grant.id === foreign.id),
  );
});

test('the audit chain verifies after structural changes', async () => {
  await seedProject();
  const grant = await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: reader.principal.id,
    role: 'viewer',
  });
  await services.admin.updateGrant(root, 'market', grant.id, 'developer');
  await services.admin.updateEnvironment(root, 'market', 'prod', { slug: 'live' });
  await services.admin.setEnvironmentArchived(root, 'market', 'live', true);
  await services.admin.revokeGrant(root, 'market', grant.id);
  assert.equal((await services.audit.verify(root)).ok, true);
});

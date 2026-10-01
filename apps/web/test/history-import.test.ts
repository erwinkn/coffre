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
import { parseDotenv } from '../../../packages/core/src/dotenv.ts';
import { AccessDenied, NotFound } from '../src/server/services/secrets.ts';
import { requestContext, serviceFixture } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'admin@acme.example';
const root = requestContext(ROOT);
const viewer = requestContext('viewer@acme.example');
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
       ('user', $2, 'user', $3, true)`,
    [viewer.principal.id, 'leaver@acme.example', ROOT],
  );
  await services.admin.createProject(root, 'market', 'Market');
  await services.admin.createEnvironment(root, 'market', 'dev', 'Dev');
});

async function importText(content: string, dryRun: boolean) {
  const parsed = parseDotenv(content);
  const imported = await services.secrets.importSecrets(
    root,
    'market',
    'dev',
    parsed.entries,
    dryRun,
  );
  return { ...imported, problems: parsed.problems };
}

test('parses the shapes a real .env file contains', () => {
  const { entries, problems } = parseDotenv(
    [
      '# a comment',
      '',
      'DATABASE_URL=db-demo://user:pw@host/db',
      'export EXPORTED=value',
      'QUOTED="hello world"',
      "SINGLE='literal $NOT_INTERPOLATED'",
      'WITH_ESCAPE="line\\nbreak"',
      'TRAILING=value # trailing comment',
      'EMPTY=',
      '  SPACED  =  padded  ',
    ].join('\n'),
  );
  assert.deepEqual(problems, []);
  assert.deepEqual(Object.fromEntries(entries.map((entry) => [entry.key, entry.value])), {
    DATABASE_URL: 'db-demo://user:pw@host/db',
    EXPORTED: 'value',
    QUOTED: 'hello world',
    SINGLE: 'literal $NOT_INTERPOLATED',
    WITH_ESCAPE: 'line\nbreak',
    TRAILING: 'value',
    EMPTY: '',
    SPACED: 'padded',
  });
});

test('reports malformed lines rather than silently mangling them', () => {
  const { entries, problems } = parseDotenv(
    ['GOOD=1', 'no equals sign here', '1BAD_KEY=x', 'UNTERMINATED="oh dear', 'GOOD=2'].join('\n'),
  );
  assert.deepEqual(entries.map((entry) => entry.key), ['GOOD']);
  assert.equal(problems.length, 4);
  assert.match(problems[0].reason, /no "="/);
  assert.match(problems[1].reason, /key must match/);
  assert.match(problems[2].reason, /unterminated/);
  assert.match(problems[3].reason, /duplicate/);
});

test('version history reports authors and current version without values', async () => {
  for (const value of ['v1', 'v2', 'v3']) {
    await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', value);
  }
  const history = await services.secrets.listVersions(root, 'market', 'dev', 'API_KEY');
  assert.deepEqual(history.versions.map((version) => version.version), [3, 2, 1]);
  assert.equal(history.versions[0].current, true);
  assert.equal(history.versions[1].current, false);
  assert.equal(history.versions[0].createdBy, ROOT);
  assert.equal(typeof history.versions[0].createdAt, 'string');
  assert.match(history.versions[0].createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(JSON.stringify(history).includes('v3'), false);
});

test('version history requires secret.read', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v1');
  await assert.rejects(
    services.secrets.listVersions(viewer, 'market', 'dev', 'API_KEY'),
    AccessDenied,
  );
});

test('rollback repoints without copying and subsequent writes continue forward', async () => {
  for (const value of ['first', 'second', 'third']) {
    await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', value);
  }
  assert.deepEqual(
    await services.secrets.rollback(root, 'market', 'dev', 'API_KEY', 1),
    { key: 'API_KEY', version: 1 },
  );
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'dev', 'API_KEY')).value,
    'first',
  );
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM secret_versions')).rows[0].n,
    3,
  );
  assert.equal(
    (await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'fourth')).version,
    4,
  );
});

test('rollback is audited with both versions and denial without write permission', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v1');
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v2');
  await services.secrets.rollback(root, 'market', 'dev', 'API_KEY', 1);
  const allowed = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.rollback' AND decision = 'allow'",
  );
  assert.deepEqual(JSON.parse(allowed.rows[0].metadata), {
    key: 'API_KEY',
    fromVersion: 2,
    toVersion: 1,
  });
  await assert.rejects(
    services.secrets.rollback(viewer, 'market', 'dev', 'API_KEY', 2),
    AccessDenied,
  );
  const denied = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.rollback' AND decision = 'deny'",
  );
  assert.equal(JSON.parse(denied.rows[0].metadata).reason, 'missing_secret_write');
});

test('rolling back to an unknown version is rejected and audited', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v1');
  await assert.rejects(
    services.secrets.rollback(root, 'market', 'dev', 'API_KEY', 99),
    NotFound,
  );
  const row = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.rollback' AND decision = 'deny'",
  );
  assert.equal(JSON.parse(row.rows[0].metadata).reason, 'unknown_version');
});

test('a dry run reports the plan and writes nothing', async () => {
  const result = await importText('A=one\nB=two', true);
  assert.deepEqual(result.plan.map(({ key, action }) => [key, action]), [
    ['A', 'create'],
    ['B', 'create'],
  ]);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM secrets')).rows[0].n, 0);
});

test('a preview audits every existing secret that it compares', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'A', 'one');
  await services.secrets.writeSecret(root, 'market', 'dev', 'B', 'two');
  await pool.query('DELETE FROM audit_log');
  await importText('A=one\nB=changed\nC=new', true);

  const reads = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.read' ORDER BY metadata",
  );
  assert.deepEqual(
    reads.rows.map((row) => JSON.parse(row.metadata).key).sort(),
    ['A', 'B'],
  );
  assert.equal(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM audit_log WHERE action = 'secret.import.preview'",
      )
    ).rows[0].n,
    1,
  );
});

test('import creates every secret and audits one row per key', async () => {
  await importText('A=one\nB=two\nC=three', false);
  assert.deepEqual(
    (await services.secrets.readEnvironment(root, 'market', 'dev')).secrets,
    { A: 'one', B: 'two', C: 'three' },
  );
  const rows = await pool.query(
    "SELECT metadata, bundle_id FROM audit_log WHERE action = 'secret.import' AND decision = 'allow'",
  );
  assert.equal(rows.rowCount, 3);
  assert.equal(new Set(rows.rows.map((row) => row.bundle_id)).size, 1);
});

test('re-importing unchanged values adds no versions', async () => {
  await importText('A=one\nB=two', false);
  const before = await pool.query('SELECT count(*)::int AS n FROM secret_versions');
  const again = await importText('A=one\nB=two', false);
  assert.deepEqual(again.plan.map(({ action }) => action), ['unchanged', 'unchanged']);
  const after = await pool.query('SELECT count(*)::int AS n FROM secret_versions');
  assert.equal(after.rows[0].n, before.rows[0].n);
});

test('import distinguishes create from update', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'A', 'old');
  const result = await importText('A=new\nB=created', false);
  assert.deepEqual(result.plan.map(({ key, action }) => [key, action]), [
    ['A', 'update'],
    ['B', 'create'],
  ]);
});

test('import reports parse problems alongside valid entries', async () => {
  const result = await importText('A=one\nnot valid\nB=two', false);
  assert.equal(result.plan.length, 2);
  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0].line, 2);
});

test('import requires read and write and audits the denial', async () => {
  await assert.rejects(
    services.secrets.importSecrets(
      viewer,
      'market',
      'dev',
      [{ key: 'A', value: 'one' }],
      false,
    ),
    AccessDenied,
  );
  const row = await pool.query(
    "SELECT metadata FROM audit_log WHERE action LIKE 'secret.import%' AND decision = 'deny'",
  );
  assert.match(JSON.parse(row.rows[0].metadata).reason, /^missing_secret\./);
});

test('the audit chain verifies across history, rollback, and import', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v1');
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v2');
  await services.secrets.rollback(root, 'market', 'dev', 'API_KEY', 1);
  await importText('A=one\nB=two', false);
  assert.equal((await services.audit.verify(root)).ok, true);
});

test('structural project creation does not create an implicit secret grant', async () => {
  const grants = await services.admin.listGrants(root, 'market');
  assert.equal(grants.some((grant) => grant.principalId === ROOT), false);
});

test('the principal view answers what a person still holds', async () => {
  await services.admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: 'leaver@acme.example',
    role: 'auditor',
  });
  const principal = (await services.admin.listPrincipals(root)).find(
    (entry) => entry.principalId === 'leaver@acme.example',
  );
  assert.equal(principal?.grants[0].project, 'market');
  assert.equal(principal?.grants[0].role, 'auditor');
});

test('the principal directory is independent of project permissions', async () => {
  await services.admin.addDirectoryPrincipal(root, {
    principalType: 'user',
    principalId: 'grantless@acme.example',
    instanceRole: 'user',
  });
  const directory = await services.admin.listDirectory(root);
  assert.ok(directory.some((entry) => entry.principalId === 'grantless@acme.example'));
  assert.equal(
    (await services.admin.listPrincipals(root)).some(
      (entry) => entry.principalId === 'grantless@acme.example',
    ),
    false,
  );
});

import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';

import { DevIdp } from '../../dev-idp/src/idp.ts';
import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import { buildApp } from '../src/app.ts';
import { parseDotenv } from '../src/services/dotenv.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HEADER = 'cf-access-jwt-assertion';
const CONNECTION =
  process.env.COFFRE_DATABASE_URL ??
  'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'erwin@equisafe.io';

let idp: DevIdp;
let pool: pg.Pool;
let app: FastifyInstance;
const tokens: Record<string, string> = {};

before(async () => {
  idp = new DevIdp();
  await idp.start();
  pool = new pg.Pool({ connectionString: CONNECTION });

  app = buildApp({
    pool,
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

  for (const who of [ROOT, 'viewer@equisafe.io']) {
    tokens[who] = await idp.mintUserToken({ audience: AUD, email: who });
  }
});

after(async () => {
  await app.close();
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
    payload: { slug: 'dev', name: 'Dev' },
  });
});

function req(who: string) {
  return { headers: { [HEADER]: tokens[who] } };
}

const secretUrl = (key: string) =>
  `/v1/projects/market/environments/dev/secrets/${key}`;

// --- the parser -------------------------------------------------------------

test('parses the shapes a real .env file contains', () => {
  const { entries, problems } = parseDotenv(
    [
      '# a comment',
      '',
      'DATABASE_URL=postgres://user:pw@host/db',
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
  assert.deepEqual(Object.fromEntries(entries.map((e) => [e.key, e.value])), {
    DATABASE_URL: 'postgres://user:pw@host/db',
    EXPORTED: 'value',
    QUOTED: 'hello world',
    SINGLE: 'literal $NOT_INTERPOLATED',
    WITH_ESCAPE: 'line\nbreak',
    TRAILING: 'value',
    EMPTY: '',
    SPACED: 'padded',
  });
});

test('reports malformed lines instead of silently mangling them', () => {
  const { entries, problems } = parseDotenv(
    ['GOOD=1', 'no equals sign here', '1BAD_KEY=x', 'UNTERMINATED="oh dear', 'GOOD=2'].join('\n'),
  );

  assert.deepEqual(entries.map((e) => e.key), ['GOOD']);
  assert.equal(problems.length, 4);
  assert.match(problems[0].reason, /no "="/);
  assert.match(problems[1].reason, /key must match/);
  assert.match(problems[2].reason, /unterminated/);
  assert.match(problems[3].reason, /duplicate/);
});

// --- version history --------------------------------------------------------

test('version history reports who wrote each version and which is current', async () => {
  for (const value of ['v1', 'v2', 'v3']) {
    await app.inject({
      method: 'PUT',
      url: secretUrl('API_KEY'),
      ...req(ROOT),
      payload: { value },
    });
  }

  const response = await app.inject({
    method: 'GET',
    url: `${secretUrl('API_KEY')}/versions`,
    ...req(ROOT),
  });

  assert.equal(response.statusCode, 200);
  const versions = response.json().versions;
  assert.deepEqual(versions.map((v: { version: number }) => v.version), [3, 2, 1]);
  assert.equal(versions[0].current, true);
  assert.equal(versions[1].current, false);
  assert.equal(versions[0].createdBy, ROOT);

  // History is metadata, never values.
  assert.equal(JSON.stringify(versions).includes('v3'), false);
});

test('version history requires secret.read', async () => {
  await app.inject({
    method: 'PUT',
    url: secretUrl('API_KEY'),
    ...req(ROOT),
    payload: { value: 'v1' },
  });

  const response = await app.inject({
    method: 'GET',
    url: `${secretUrl('API_KEY')}/versions`,
    ...req('viewer@equisafe.io'),
  });

  assert.equal(response.statusCode, 403);
});

// --- rollback ---------------------------------------------------------------

test('rollback repoints at an earlier version without copying anything', async () => {
  for (const value of ['first', 'second', 'third']) {
    await app.inject({
      method: 'PUT',
      url: secretUrl('API_KEY'),
      ...req(ROOT),
      payload: { value },
    });
  }

  const rolled = await app.inject({
    method: 'POST',
    url: `${secretUrl('API_KEY')}/rollback`,
    ...req(ROOT),
    payload: { version: 1 },
  });
  assert.equal(rolled.statusCode, 200);

  const read = await app.inject({ method: 'GET', url: secretUrl('API_KEY'), ...req(ROOT) });
  assert.equal(read.json().value, 'first');
  assert.equal(read.json().version, 1);

  // No new rows: rollback is free precisely because versions are append-only.
  const count = await pool.query('SELECT count(*)::int AS n FROM secret_versions');
  assert.equal(count.rows[0].n, 3);
});

test('a write after a rollback continues the numbering forward', async () => {
  for (const value of ['v1', 'v2']) {
    await app.inject({
      method: 'PUT',
      url: secretUrl('API_KEY'),
      ...req(ROOT),
      payload: { value },
    });
  }
  await app.inject({
    method: 'POST',
    url: `${secretUrl('API_KEY')}/rollback`,
    ...req(ROOT),
    payload: { version: 1 },
  });

  const written = await app.inject({
    method: 'PUT',
    url: secretUrl('API_KEY'),
    ...req(ROOT),
    payload: { value: 'v3' },
  });

  // MAX(version) + 1, not current + 1 -- history must read forward.
  assert.equal(written.json().version, 3);
});

test('rollback is audited with both versions, and denied without secret.write', async () => {
  await app.inject({
    method: 'PUT',
    url: secretUrl('API_KEY'),
    ...req(ROOT),
    payload: { value: 'v1' },
  });
  await app.inject({
    method: 'PUT',
    url: secretUrl('API_KEY'),
    ...req(ROOT),
    payload: { value: 'v2' },
  });
  await app.inject({
    method: 'POST',
    url: `${secretUrl('API_KEY')}/rollback`,
    ...req(ROOT),
    payload: { version: 1 },
  });

  const row = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.rollback' AND decision = 'allow'",
  );
  const metadata = JSON.parse(row.rows[0].metadata);
  assert.equal(metadata.fromVersion, 2);
  assert.equal(metadata.toVersion, 1);

  const denied = await app.inject({
    method: 'POST',
    url: `${secretUrl('API_KEY')}/rollback`,
    ...req('viewer@equisafe.io'),
    payload: { version: 1 },
  });
  assert.equal(denied.statusCode, 403);
});

test('rolling back to a version that does not exist is rejected and audited', async () => {
  await app.inject({
    method: 'PUT',
    url: secretUrl('API_KEY'),
    ...req(ROOT),
    payload: { value: 'v1' },
  });

  const response = await app.inject({
    method: 'POST',
    url: `${secretUrl('API_KEY')}/rollback`,
    ...req(ROOT),
    payload: { version: 99 },
  });

  assert.equal(response.statusCode, 404);
  const denial = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.rollback' AND decision = 'deny'",
  );
  assert.equal(JSON.parse(denial.rows[0].metadata).reason, 'unknown_version');
});

// --- import -----------------------------------------------------------------

const ENV_FILE = [
  '# production config',
  'DATABASE_URL=postgres://user:pw@host/db',
  'REDIS_URL=redis://localhost:6379',
  'STRIPE_KEY="sk_live_xyz"',
].join('\n');

test('a dry run reports the plan and writes nothing', async () => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: ENV_FILE, dryRun: true },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(
    response.json().plan.map((p: { key: string; action: string }) => [p.key, p.action]),
    [
      ['DATABASE_URL', 'create'],
      ['REDIS_URL', 'create'],
      ['STRIPE_KEY', 'create'],
    ],
  );

  const count = await pool.query('SELECT count(*)::int AS n FROM secrets');
  assert.equal(count.rows[0].n, 0, 'a dry run must not write');
});

test('import creates every secret and audits one row per key', async () => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: ENV_FILE },
  });

  assert.equal(response.statusCode, 200);

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets',
    ...req(ROOT),
  });
  assert.deepEqual(read.json().secrets, {
    DATABASE_URL: 'postgres://user:pw@host/db',
    REDIS_URL: 'redis://localhost:6379',
    STRIPE_KEY: 'sk_live_xyz',
  });

  const rows = await pool.query(
    "SELECT metadata FROM audit_log WHERE action = 'secret.import' AND decision = 'allow'",
  );
  assert.equal(rows.rowCount, 3, 'one audit row per imported key');

  const bundles = await pool.query(
    "SELECT DISTINCT bundle_id FROM audit_log WHERE action = 'secret.import'",
  );
  assert.equal(bundles.rowCount, 1, 'all sharing one bundle id');
});

test('re-importing the same file reports everything unchanged and adds no versions', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: ENV_FILE },
  });

  const again = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: ENV_FILE },
  });

  assert.deepEqual(
    again.json().plan.map((p: { action: string }) => p.action),
    ['unchanged', 'unchanged', 'unchanged'],
  );

  const versions = await pool.query('SELECT count(*)::int AS n FROM secret_versions');
  assert.equal(versions.rows[0].n, 3, 'unchanged values must not create versions');
});

test('import distinguishes create from update', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: 'DATABASE_URL=old' },
  });

  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: 'DATABASE_URL=new\nNEW_KEY=value' },
  });

  assert.deepEqual(
    response.json().plan.map((p: { key: string; action: string }) => [p.key, p.action]),
    [
      ['DATABASE_URL', 'update'],
      ['NEW_KEY', 'create'],
    ],
  );
});

test('import reports parse problems alongside what it did import', async () => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: 'GOOD=1\ngarbage line\nALSO_GOOD=2' },
  });

  assert.equal(response.json().plan.length, 2);
  assert.equal(response.json().problems.length, 1);
  assert.equal(response.json().problems[0].line, 2);
});

test('import requires secret.write, and the denial is audited', async () => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req('viewer@equisafe.io'),
    payload: { content: ENV_FILE },
  });

  assert.equal(response.statusCode, 403);
  const denial = await pool.query(
    "SELECT metadata FROM audit_log WHERE action LIKE 'secret.import%' AND decision = 'deny'",
  );
  assert.equal(denial.rowCount, 1);
});

test('the audit chain verifies across history, rollback and import', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/projects/market/environments/dev/import',
    ...req(ROOT),
    payload: { content: ENV_FILE },
  });
  await app.inject({
    method: 'PUT',
    url: secretUrl('DATABASE_URL'),
    ...req(ROOT),
    payload: { value: 'changed' },
  });
  await app.inject({
    method: 'POST',
    url: `${secretUrl('DATABASE_URL')}/rollback`,
    ...req(ROOT),
    payload: { version: 1 },
  });

  const verify = await app.inject({ method: 'GET', url: '/v1/audit/verify', ...req(ROOT) });
  assert.equal(verify.json().ok, true);
});

// --- principal view and root admin visibility -------------------------------

test('project access shows the creator as owner, not as a projected root admin', async () => {
  const response = await app.inject({
    method: 'GET',
    url: '/v1/admin/projects/market/grants',
    ...req(ROOT),
  });

  const grants = response.json().grants;
  assert.equal(grants.some((grant: { role: string }) => grant.role === 'root-admin'), false);
  const owner = grants.find((grant: { role: string }) => grant.role === 'owner');
  assert.equal(owner.principalId, ROOT);
  assert.equal(owner.scope, 'project');
});

test('the principal view answers "what does this person still hold"', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/grants',
    ...req(ROOT),
    payload: {
      principalType: 'user',
      principalId: 'leaver@equisafe.io',
      role: 'developer',
      environmentSlug: 'dev',
    },
  });
  await app.inject({
    method: 'POST',
    url: '/v1/admin/projects/market/grants',
    ...req(ROOT),
    payload: { principalType: 'user', principalId: 'leaver@equisafe.io', role: 'auditor' },
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/admin/principals',
    ...req(ROOT),
  });

  assert.equal(response.statusCode, 200);
  const leaver = response
    .json()
    .principals.find((p: { principalId: string }) => p.principalId === 'leaver@equisafe.io');

  assert.equal(leaver.grants.length, 2);
  assert.deepEqual(
    leaver.grants.map((g: { scope: string; role: string }) => [g.scope, g.role]).sort(),
    [
      ['dev', 'developer'],
      ['whole project', 'auditor'],
    ],
  );

  const root = response
    .json()
    .principals.find((p: { principalId: string }) => p.principalId === ROOT);
  assert.equal(root.isRootAdmin, true);
});

test('the principal directory is separate from project permissions', async () => {
  await app.inject({
    method: 'POST',
    url: '/v1/admin/directory',
    ...req(ROOT),
    payload: {
      principalType: 'user',
      principalId: 'grantless@equisafe.io',
      instanceRole: 'user',
    },
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/admin/directory',
    ...req(ROOT),
  });

  assert.equal(response.statusCode, 200);
  const grantless = response
    .json()
    .principals.find(
      (p: { principalId: string }) => p.principalId === 'grantless@equisafe.io',
    );

  assert.equal(grantless.instanceRole, 'user');
  assert.equal('grants' in grantless, false);

  const root = response
    .json()
    .principals.find((p: { principalId: string }) => p.principalId === ROOT);
  assert.equal(root.isRootAdmin, true);
  assert.equal(root.instanceRole, 'root-admin');
});

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
import { AccessDenied } from '../src/server/services/secrets.ts';
import { requestContext, serviceFixture } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'admin@acme.example';
const root = requestContext(ROOT);
const reader = requestContext('reader@acme.example');
const outsider = requestContext('outsider@acme.example');
const ci = requestContext('ci-deploy.access', 'service');

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

  const project = await pool.query(
    "INSERT INTO projects (slug, name) VALUES ('market', 'Market') RETURNING id",
  );
  const dev = await pool.query(
    "INSERT INTO environments (project_id, slug, name) VALUES ($1, 'dev', 'Dev') RETURNING id",
    [project.rows[0].id],
  );
  const prod = await pool.query(
    "INSERT INTO environments (project_id, slug, name) VALUES ($1, 'prod', 'Prod') RETURNING id",
    [project.rows[0].id],
  );
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by)
     VALUES ('user', 'reader@acme.example', 'user', 'test'),
            ('service', 'ci-deploy.access', 'user', 'test')`,
  );
  const viewer = await pool.query("SELECT id FROM roles WHERE slug = 'viewer'");
  await pool.query(
    `INSERT INTO grants (principal_type, principal_id, environment_id, role_id, created_by)
     VALUES ('user', 'reader@acme.example', $1, $3, 'test'),
            ('service', 'ci-deploy.access', $2, $3, 'test')`,
    [dev.rows[0].id, prod.rows[0].id, viewer.rows[0].id],
  );
});

async function auditRows(): Promise<
  { actorId: string; action: string; decision: string; metadata: Record<string, unknown> }[]
> {
  const result = await pool.query(
    'SELECT actor_id, action, decision, metadata FROM audit_log ORDER BY seq ASC',
  );
  return result.rows.map((row) => ({
    actorId: row.actor_id,
    action: row.action,
    decision: row.decision,
    metadata: JSON.parse(row.metadata),
  }));
}

test('the service pool uses the restricted runtime login', async () => {
  const identity = await runtimePool.query<{ current_user: string }>('SELECT current_user');
  assert.equal(identity.rows[0].current_user, 'coffre_runtime');
  assert.deepEqual(
    await services.secrets.writeSecret(root, 'market', 'dev', 'RUNTIME_PROOF', 'works'),
    { key: 'RUNTIME_PROOF', version: 1 },
  );
});

test('writing a secret is audited without its value', async () => {
  const written = await services.secrets.writeSecret(
    root,
    'market',
    'dev',
    'DATABASE_URL',
    'db-demo://user:pw@host/db',
  );
  assert.deepEqual(written, { key: 'DATABASE_URL', version: 1 });
  const rows = await auditRows();
  assert.deepEqual(rows.map(({ action, decision }) => ({ action, decision })), [
    { action: 'secret.write', decision: 'allow' },
  ]);
  assert.equal(JSON.stringify(rows).includes('db-demo://'), false);
});

test('direct writes reject NUL bytes and audit the denial', async () => {
  await assert.rejects(
    services.secrets.writeSecret(root, 'market', 'dev', 'BAD', 'before\u0000after'),
    (error) => (error as { statusCode?: number }).statusCode === 409,
  );
  const rows = await auditRows();
  assert.deepEqual(rows.at(-1), {
    actorId: ROOT,
    action: 'secret.write',
    decision: 'deny',
    metadata: { key: 'BAD', reason: 'invalid_secret_value' },
  });
});

test('writing twice appends a version rather than mutating one', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v1');
  assert.equal(
    (await services.secrets.writeSecret(root, 'market', 'dev', 'API_KEY', 'v2')).version,
    2,
  );
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM secret_versions')).rows[0].n,
    2,
  );
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'dev', 'API_KEY')).value,
    'v2',
  );
});

test('concurrent writes allocate one ordered version sequence', async () => {
  const writes = await Promise.all(
    Array.from({ length: 8 }, (_, index) =>
      services.secrets.writeSecret(root, 'market', 'dev', 'RACING_KEY', `value-${index}`),
    ),
  );
  assert.deepEqual(
    writes.map((write) => write.version).sort((left, right) => left - right),
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  const versions = await pool.query<{ version: number }>(
    `SELECT v.version
       FROM secret_versions v
       JOIN secrets s ON s.id = v.secret_id
      WHERE s.key = 'RACING_KEY'
      ORDER BY v.version`,
  );
  assert.deepEqual(versions.rows.map((row) => row.version), [1, 2, 3, 4, 5, 6, 7, 8]);
});

test('renaming preserves value, versions, and immutable identity', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'OLD_KEY', 'still-secret');
  const before = await pool.query<{ id: string }>("SELECT id FROM secrets WHERE key = 'OLD_KEY'");
  assert.deepEqual(
    await services.secrets.renameSecret(root, 'market', 'dev', 'OLD_KEY', 'NEW_KEY'),
    { key: 'NEW_KEY' },
  );
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'dev', 'NEW_KEY')).value,
    'still-secret',
  );
  const after = await pool.query<{ id: string; versions: number }>(
    `SELECT s.id, count(v.id)::int AS versions
       FROM secrets s JOIN secret_versions v ON v.secret_id = s.id
      WHERE s.key = 'NEW_KEY' GROUP BY s.id`,
  );
  assert.equal(after.rows[0].id, before.rows[0].id);
  assert.equal(after.rows[0].versions, 1);
  assert.ok((await auditRows()).some((row) => row.action === 'secret.rename'));
});

test('a reader cannot write, and the denial is audited', async () => {
  await assert.rejects(
    services.secrets.writeSecret(reader, 'market', 'dev', 'NOPE', 'x'),
    AccessDenied,
  );
  const rows = await auditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].decision, 'deny');
  assert.equal(rows[0].metadata.reason, 'missing_secret_write');
});

test('a granted reader can read, and the read is attributed to them', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'DATABASE_URL', 'the-value');
  assert.equal(
    (await services.secrets.readSecret(reader, 'market', 'dev', 'DATABASE_URL')).value,
    'the-value',
  );
  const reads = (await auditRows()).filter((row) => row.action === 'secret.read');
  assert.equal(reads.length, 1);
  assert.equal(reads[0].actorId, reader.principal.id);
  assert.equal(reads[0].metadata.key, 'DATABASE_URL');
});

test('denied and grantless reads are audited', async () => {
  await assert.rejects(
    services.secrets.readSecret(reader, 'market', 'prod', 'ANYTHING'),
    AccessDenied,
  );
  await assert.rejects(
    services.secrets.readSecret(outsider, 'market', 'dev', 'X'),
    AccessDenied,
  );
  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => row.actorId), [reader.principal.id, outsider.principal.id]);
  assert.ok(rows.every((row) => row.decision === 'deny'));
  assert.equal(rows[0].metadata.reason, 'missing_secret_read');
});

test('a service read is attributed to the service principal', async () => {
  await services.secrets.writeSecret(root, 'market', 'prod', 'STRIPE_KEY', 'sk_live_xxx');
  await services.secrets.readSecret(ci, 'market', 'prod', 'STRIPE_KEY');
  const read = (await auditRows()).find(
    (row) => row.action === 'secret.read' && row.decision === 'allow',
  );
  assert.equal(read?.actorId, ci.principal.id);
});

test('bulk fetch returns every secret and writes one audit row per secret', async () => {
  for (const [key, value] of [
    ['DATABASE_URL', 'postgres://x'],
    ['REDIS_URL', 'redis://y'],
    ['JWT_SECRET', 'shhh'],
  ]) {
    await services.secrets.writeSecret(root, 'market', 'dev', key, value);
  }
  await pool.query('DELETE FROM audit_log');
  await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
  );
  const result = await services.secrets.readEnvironment(reader, 'market', 'dev');
  assert.deepEqual(result.secrets, {
    DATABASE_URL: 'postgres://x',
    JWT_SECRET: 'shhh',
    REDIS_URL: 'redis://y',
  });
  const rows = await auditRows();
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((row) => row.metadata.key).sort(), [
    'DATABASE_URL',
    'JWT_SECRET',
    'REDIS_URL',
  ]);
  assert.equal(
    (await pool.query('SELECT DISTINCT bundle_id FROM audit_log')).rowCount,
    1,
  );
});

test('bulk fetch preserves keys that are also Object prototype property names', async () => {
  for (const [key, value] of [
    ['constructor', 'one'],
    ['toString', 'two'],
    ['__proto__', 'three'],
  ]) {
    await services.secrets.writeSecret(root, 'market', 'dev', key, value);
  }

  const result = await services.secrets.readEnvironment(reader, 'market', 'dev');
  assert.deepEqual(Object.entries(result.secrets).sort(), [
    ['__proto__', 'three'],
    ['constructor', 'one'],
    ['toString', 'two'],
  ]);
});

test('the same key in two environments holds independent values', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'DATABASE_URL', 'dev-value');
  await services.secrets.writeSecret(root, 'market', 'prod', 'DATABASE_URL', 'prod-value');
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'dev', 'DATABASE_URL')).value,
    'dev-value',
  );
  assert.equal(
    (await services.secrets.readSecret(root, 'market', 'prod', 'DATABASE_URL')).value,
    'prod-value',
  );
});

test('ciphertext relocated between environments cannot be decrypted', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'DATABASE_URL', 'dev-only');
  await services.secrets.writeSecret(root, 'market', 'prod', 'DATABASE_URL', 'prod-only');
  await pool.query(
    `UPDATE secret_versions dst
        SET ciphertext = src.ciphertext, iv = src.iv, auth_tag = src.auth_tag,
            wrapped_dek = src.wrapped_dek
       FROM secret_versions src
       JOIN secrets ss ON ss.id = src.secret_id
       JOIN environments se ON se.id = ss.environment_id
      WHERE dst.id = (
              SELECT s.current_version_id FROM secrets s
                JOIN environments e ON e.id = s.environment_id
               WHERE e.slug = 'prod' AND s.key = 'DATABASE_URL')
        AND se.slug = 'dev' AND ss.key = 'DATABASE_URL'`,
  );
  await assert.rejects(
    services.secrets.readSecret(root, 'market', 'prod', 'DATABASE_URL'),
  );
});

test('the audit chain verifies over a realistic mixed workload', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'A', '1');
  await services.secrets.readSecret(reader, 'market', 'dev', 'A');
  await assert.rejects(services.secrets.readSecret(reader, 'market', 'prod', 'A'));
  await services.secrets.readEnvironment(reader, 'market', 'dev');
  assert.equal((await services.audit.verify(root)).ok, true);
});

test('truncating the tail is detected even when surviving rows are consistent', async () => {
  for (const key of ['A', 'B', 'C']) {
    await services.secrets.writeSecret(root, 'market', 'dev', key, 'v');
  }
  assert.equal((await services.audit.verify(root)).ok, true);
  const head = await pool.query<{ next_seq: string }>(
    'SELECT next_seq FROM audit_chain_head WHERE only_row',
  );
  const kept = BigInt(head.rows[0].next_seq) - 2n;
  await pool.query('DELETE FROM audit_log WHERE seq >= $1', [kept.toString()]);
  const result = await services.audit.verify(root);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.failedAtSeq, Number(kept));
    assert.match(result.reason, /removed from the end/);
  }
});

test('verification reports the complete stored row count', async () => {
  for (const key of ['A', 'B', 'C', 'D']) {
    await services.secrets.writeSecret(root, 'market', 'dev', key, 'v');
  }
  const stored = await pool.query<{ count: string }>('SELECT count(*) FROM audit_log');
  const result = await services.audit.verify(root);
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.rows, Number(stored.rows[0].count));
});

test('a caller without audit.read cannot list or verify the audit log', async () => {
  await assert.rejects(services.audit.list(reader, { limit: 100 }), AccessDenied);
  await assert.rejects(services.audit.verify(reader), AccessDenied);
});

test('listing keys never reveals values or logs a secret read', async () => {
  await services.secrets.writeSecret(root, 'market', 'dev', 'SECRET_ONE', 'hidden');
  const result = await services.secrets.listKeys(reader, 'market', 'dev');
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].key, 'SECRET_ONE');
  assert.equal(JSON.stringify(result).includes('hidden'), false);
  assert.equal((await auditRows()).filter((row) => row.action === 'secret.read').length, 0);
});

test('identity projections expose only the environments and audit capability held', async () => {
  assert.equal(await services.admin.instanceRole(reader.principal), 'user');
  assert.equal(await services.audit.canRead(reader), false);
  assert.deepEqual(await services.secrets.listAccessible(reader), [
    { project: 'market', environment: 'dev', permissions: ['secret.read'] },
  ]);
});

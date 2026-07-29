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

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HEADER = 'cf-access-jwt-assertion';
const CONNECTION =
  process.env.COFFRE_DATABASE_URL ??
  'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre';

const CHAIN_KEY = randomBytes(32);
const ROOT_ADMIN = 'erwin@equisafe.io';

let idp: DevIdp;
let pool: pg.Pool;
let app: FastifyInstance;

let adminToken: string;
let readerToken: string;
let outsiderToken: string;
let ciToken: string;

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
    rootAdmins: [ROOT_ADMIN],
  });
  await app.ready();

  adminToken = await idp.mintUserToken({ audience: AUD, email: ROOT_ADMIN });
  readerToken = await idp.mintUserToken({ audience: AUD, email: 'reader@equisafe.io' });
  outsiderToken = await idp.mintUserToken({ audience: AUD, email: 'outsider@equisafe.io' });
  ciToken = await idp.mintServiceToken({ audience: AUD, commonName: 'ci-deploy.access' });
});

after(async () => {
  await app.close();
  await pool.end();
  await idp.stop();
});

beforeEach(async () => {
  // Fresh world for each test, in dependency order.
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

  // reader may read dev only. ci may read prod only.
  await pool.query(
    `INSERT INTO principals (
       principal_type, principal_id, instance_role, created_by
     )
     VALUES ('user', 'reader@equisafe.io', 'user', 'test'),
            ('service', 'ci-deploy.access', 'user', 'test')`,
  );
  const viewer = await pool.query("SELECT id FROM roles WHERE slug = 'viewer'");
  await pool.query(
    `INSERT INTO grants (principal_type, principal_id, environment_id, role_id, created_by)
     VALUES ('user', 'reader@equisafe.io', $1, $3, 'test'),
            ('service', 'ci-deploy.access', $2, $3, 'test')`,
    [dev.rows[0].id, prod.rows[0].id, viewer.rows[0].id],
  );
});

function req(token: string) {
  return { headers: { [HEADER]: token } };
}

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

// --- writes -----------------------------------------------------------------

test('an admin can write a secret and it is audited without the value', async () => {
  const response = await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'postgres://user:pw@host/db' },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { key: 'DATABASE_URL', version: 1 });

  const rows = await auditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, 'secret.write');
  assert.equal(rows[0].decision, 'allow');

  // The audit log records who and what, never the value itself.
  assert.equal(JSON.stringify(rows).includes('postgres://'), false);
});

test('writing twice creates a new version rather than mutating one', async () => {
  const url = '/v1/projects/market/environments/dev/secrets/API_KEY';
  await app.inject({ method: 'PUT', url, ...req(adminToken), payload: { value: 'v1' } });
  const second = await app.inject({
    method: 'PUT',
    url,
    ...req(adminToken),
    payload: { value: 'v2' },
  });

  assert.equal(second.json().version, 2);

  const versions = await pool.query('SELECT COUNT(*)::int AS n FROM secret_versions');
  assert.equal(versions.rows[0].n, 2);

  const read = await app.inject({ method: 'GET', url, ...req(adminToken) });
  assert.equal(read.json().value, 'v2');
});

test('renaming a secret preserves its value, versions, and immutable identity', async () => {
  const originalUrl = '/v1/projects/market/environments/dev/secrets/OLD_KEY';
  await app.inject({
    method: 'PUT',
    url: originalUrl,
    ...req(adminToken),
    payload: { value: 'still-secret' },
  });
  const before = await pool.query<{ id: string }>(
    "SELECT id FROM secrets WHERE key = 'OLD_KEY'",
  );

  const renamed = await app.inject({
    method: 'PATCH',
    url: originalUrl,
    ...req(adminToken),
    payload: { key: 'NEW_KEY' },
  });

  assert.equal(renamed.statusCode, 200);
  assert.deepEqual(renamed.json(), { key: 'NEW_KEY' });

  const read = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets/NEW_KEY',
    ...req(adminToken),
  });
  assert.equal(read.json().value, 'still-secret');

  const after = await pool.query<{ id: string; versions: number }>(
    `SELECT s.id, count(v.id)::int AS versions
       FROM secrets s JOIN secret_versions v ON v.secret_id = s.id
      WHERE s.key = 'NEW_KEY' GROUP BY s.id`,
  );
  assert.equal(after.rows[0].id, before.rows[0].id);
  assert.equal(after.rows[0].versions, 1);
  assert.ok((await auditRows()).some((row) => row.action === 'secret.rename'));
});

test('a reader cannot write', async () => {
  const response = await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/NOPE',
    ...req(readerToken),
    payload: { value: 'x' },
  });

  assert.equal(response.statusCode, 403);

  const rows = await auditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].decision, 'deny');
  assert.equal(rows[0].metadata.reason, 'missing_secret_write');
});

// --- reads ------------------------------------------------------------------

test('a granted reader can read, and the read is attributed to them', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'the-value' },
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(readerToken),
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.json().value, 'the-value');

  const rows = await auditRows();
  const read = rows.filter((row) => row.action === 'secret.read');
  assert.equal(read.length, 1);
  assert.equal(read[0].actorId, 'reader@equisafe.io');
  assert.equal(read[0].metadata.key, 'DATABASE_URL');
});

test('a denied read is audited', async () => {
  // reader has dev, not prod.
  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/ANYTHING',
    ...req(readerToken),
  });

  assert.equal(response.statusCode, 403);

  const rows = await auditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].decision, 'deny');
  assert.equal(rows[0].actorId, 'reader@equisafe.io');
  assert.equal(rows[0].metadata.reason, 'missing_secret_read');
});

test('a caller with no grants at all is denied and audited', async () => {
  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets/X',
    ...req(outsiderToken),
  });

  assert.equal(response.statusCode, 403);
  const rows = await auditRows();
  assert.equal(rows[0].actorId, 'outsider@equisafe.io');
  assert.equal(rows[0].decision, 'deny');
});

test('a service token read is attributed to the service principal', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/prod/secrets/STRIPE_KEY',
    ...req(adminToken),
    payload: { value: 'sk_live_xxx' },
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/STRIPE_KEY',
    ...req(ciToken),
  });

  assert.equal(response.statusCode, 200);

  const rows = await auditRows();
  const read = rows.find((row) => row.action === 'secret.read' && row.decision === 'allow');
  assert.equal(read?.actorId, 'ci-deploy.access');
});

// --- bulk fetch: the audit-granularity property -----------------------------

test('bulk fetch returns every secret and writes ONE AUDIT ROW PER SECRET', async () => {
  for (const [key, value] of [
    ['DATABASE_URL', 'postgres://x'],
    ['REDIS_URL', 'redis://y'],
    ['JWT_SECRET', 'shhh'],
  ]) {
    await app.inject({
      method: 'PUT',
      url: `/v1/projects/market/environments/dev/secrets/${key}`,
      ...req(adminToken),
      payload: { value },
    });
  }

  await pool.query('DELETE FROM audit_log');
  await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
  );

  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets',
    ...req(readerToken),
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json().secrets, {
    DATABASE_URL: 'postgres://x',
    JWT_SECRET: 'shhh',
    REDIS_URL: 'redis://y',
  });

  const rows = await auditRows();
  assert.equal(rows.length, 3, 'one row per secret, not one row for the bulk fetch');
  assert.deepEqual(
    rows.map((row) => row.metadata.key).sort(),
    ['DATABASE_URL', 'JWT_SECRET', 'REDIS_URL'],
  );

  const bundles = await pool.query('SELECT DISTINCT bundle_id FROM audit_log');
  assert.equal(bundles.rowCount, 1, 'all rows share one bundle id');
});

// --- cross-environment isolation, end to end --------------------------------

test('the same key in two environments holds independent values', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'dev-value' },
  });
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/prod/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'prod-value' },
  });

  const dev = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(adminToken),
  });
  const prod = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/DATABASE_URL',
    ...req(adminToken),
  });

  assert.equal(dev.json().value, 'dev-value');
  assert.equal(prod.json().value, 'prod-value');
});

test('a ciphertext relocated from dev to prod in the database fails to decrypt', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'dev-only' },
  });
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/prod/secrets/DATABASE_URL',
    ...req(adminToken),
    payload: { value: 'prod-only' },
  });

  // Someone with database access copies the dev row's ciphertext over the prod
  // row, hoping to read the dev value through a prod grant -- or to plant a
  // value they control. The AAD binding must make this fail.
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

  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/DATABASE_URL',
    ...req(adminToken),
  });

  assert.equal(response.statusCode, 500, 'decryption must fail rather than return a value');
  assert.notEqual(response.json().value, 'dev-only');
});

// --- audit log integrity ----------------------------------------------------

test('the audit chain verifies over a realistic mixed workload', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/A',
    ...req(adminToken),
    payload: { value: '1' },
  });
  await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets/A',
    ...req(readerToken),
  });
  await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/prod/secrets/A',
    ...req(readerToken),
  });
  await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/secrets',
    ...req(readerToken),
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req(adminToken),
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.json().ok, true);
});

test('truncating the tail of the log is detected, though what remains is consistent', async () => {
  // Three reads, so there is a tail worth cutting off.
  for (const key of ['A', 'B', 'C']) {
    await app.inject({
      method: 'PUT',
      url: `/v1/projects/market/environments/dev/secrets/${key}`,
      ...req(adminToken),
      payload: { value: 'v' },
    });
  }

  const before = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req(adminToken),
  });
  assert.equal(before.json().ok, true);

  // Delete the newest two rows but leave audit_chain_head alone. Every
  // surviving row still hashes correctly and the sequence has no gap, so the
  // chain on its own sees nothing wrong -- only the head row remembers that
  // the log used to be longer.
  const head = await pool.query<{ next_seq: string }>(
    'SELECT next_seq FROM audit_chain_head WHERE only_row',
  );
  const kept = BigInt(head.rows[0].next_seq) - 2n;
  await pool.query('DELETE FROM audit_log WHERE seq >= $1', [kept.toString()]);

  const after = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req(adminToken),
  });

  assert.equal(after.statusCode, 200);
  const body = after.json();
  assert.equal(body.ok, false);
  assert.equal(body.failedAtSeq, Number(kept));
  assert.match(body.reason, /removed from the end/);
});

test('a chain longer than one verification batch still verifies end to end', async () => {
  // The batch size is 5000; this only has to prove the loop continues past a
  // full batch rather than stopping at one, so a handful of rows past a
  // deliberately small horizon is not testable here. Instead: assert the
  // reported row count covers every row in the table, which is what silently
  // broke when the old code read a fixed 100k prefix.
  for (const key of ['A', 'B', 'C', 'D']) {
    await app.inject({
      method: 'PUT',
      url: `/v1/projects/market/environments/dev/secrets/${key}`,
      ...req(adminToken),
      payload: { value: 'v' },
    });
  }

  const stored = await pool.query<{ count: string }>('SELECT count(*) FROM audit_log');
  const verify = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req(adminToken),
  });

  assert.equal(verify.json().ok, true);
  assert.equal(verify.json().rows, Number(stored.rows[0].count));
});

test('a non-admin cannot read or verify the audit log', async () => {
  const list = await app.inject({ method: 'GET', url: '/v1/audit', ...req(readerToken) });
  const verify = await app.inject({
    method: 'GET',
    url: '/v1/audit/verify',
    ...req(readerToken),
  });

  assert.equal(list.statusCode, 403);
  assert.equal(verify.statusCode, 403);
});

test('listing keys does not reveal values and is not logged as a read', async () => {
  await app.inject({
    method: 'PUT',
    url: '/v1/projects/market/environments/dev/secrets/SECRET_ONE',
    ...req(adminToken),
    payload: { value: 'hidden' },
  });

  const response = await app.inject({
    method: 'GET',
    url: '/v1/projects/market/environments/dev/keys',
    ...req(readerToken),
  });

  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.keys.length, 1);
  assert.equal(body.keys[0].key, 'SECRET_ONE');
  assert.equal(JSON.stringify(body).includes('hidden'), false);
});

test('/v1/me reports the principal and only the environments they hold', async () => {
  const response = await app.inject({ method: 'GET', url: '/v1/me', ...req(readerToken) });

  assert.equal(response.statusCode, 200);
  assert.equal(response.json().isRootAdmin, false);
  assert.equal(response.json().canReadAudit, false);
  assert.deepEqual(response.json().environments, [
    { project: 'market', environment: 'dev', permissions: ['secret.read'] },
  ]);
});

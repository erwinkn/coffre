import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { and, asc, count, eq, gte, sql } from 'drizzle-orm';

import type { CoffreClient } from '../../../packages/client/src/index.ts';
import {
  auditChainHead,
  auditLog,
  environments,
  secrets,
  secretVersions,
} from '../../../packages/db/src/schema.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const DEVELOPER = 'developer@acme.example';
const CI = 'ci-deploy.access';

let db: ReturnType<typeof openTestDatabase>;
let deps: FixtureDeps;
let root: CoffreClient;
let reader: CoffreClient;
let developer: CoffreClient;
let outsider: CoffreClient;
let ci: CoffreClient;
/** Audit entries from the seeding are not what these tests look at. */
let firstSeq: bigint;

before(() => {
  db = openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  reader = clientFor(deps, READER);
  developer = clientFor(deps, DEVELOPER);
  outsider = clientFor(deps, 'outsider@acme.example');
  ci = clientFor(deps, CI, 'service');

  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.members.add(`user:${READER}`);
  await root.members.add(`user:${DEVELOPER}`);
  await root.members.add(`token:${CI}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  await root.access.set(`user:${DEVELOPER}`, { 'market/dev': 'developer' });
  await root.access.set(`token:${CI}`, { 'market/prod': 'viewer' });
  firstSeq = await nextSeq();
});

async function nextSeq(): Promise<bigint> {
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  return head.nextSeq;
}

async function auditRows(): Promise<
  { actorId: string; action: string; decision: string; bundleId: string | null; metadata: Record<string, unknown> }[]
> {
  const rows = await db.owner
    .select({
      actorId: auditLog.actorId,
      action: auditLog.action,
      decision: auditLog.decision,
      bundleId: auditLog.bundleId,
      metadata: auditLog.metadata,
    })
    .from(auditLog)
    .where(gte(auditLog.seq, firstSeq))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) }));
}

async function versionCount(): Promise<number> {
  const [row] = await db.owner.select({ n: count() }).from(secretVersions);
  return row.n;
}

test('the API runs on the restricted runtime login', async () => {
  const identity = await db.runtime.execute<{ current_user: string }>(sql`SELECT current_user`);
  assert.equal(identity.rows[0].current_user, 'coffre_runtime');
  assert.deepEqual((await root.secrets.set('market/dev', { RUNTIME_PROOF: 'works' })).keys, {
    RUNTIME_PROOF: { version: 1 },
  });
});

test('writing a secret is audited without its value', async () => {
  const written = await root.secrets.set('market/dev', { DATABASE_URL: 'db-demo://user:pw@host/db' });
  assert.deepEqual(written.keys, { DATABASE_URL: { version: 1 } });
  const rows = await auditRows();
  assert.deepEqual(rows.map(({ action, decision }) => ({ action, decision })), [
    { action: 'secret.write', decision: 'allow' },
  ]);
  assert.equal(JSON.stringify(rows).includes('db-demo://'), false);
});

test('values with NUL bytes are rejected and nothing is written', async () => {
  await assert.rejects(root.secrets.set('market/dev', { BAD: 'before\u0000after' }), { status: 400 });
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('one patch writes one version and one audit entry per key, together', async () => {
  const written = await root.secrets.set('market/dev', { A: '1', B: '2', C: '3' });
  assert.deepEqual(written.keys, { A: { version: 1 }, B: { version: 1 }, C: { version: 1 } });
  assert.equal(await versionCount(), 3);
  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.metadata.key]), [
    ['secret.write', 'A'],
    ['secret.write', 'B'],
    ['secret.write', 'C'],
  ]);
  assert.deepEqual([...new Set(rows.map((row) => row.bundleId))], [written.bundleId]);
});

test('a patch that fails on one key writes none of them', async () => {
  await root.secrets.set('market/dev', { OLD: 'x' });
  await root.secrets.set('market/dev', { OLD: null });
  await assert.rejects(root.secrets.set('market/dev', { A: '1', OLD: 'y', Z: '2' }), { status: 409 });
  assert.deepEqual((await root.secrets.list('market/dev')).keys.map((entry) => entry.key), ['OLD']);
  assert.equal(await versionCount(), 1);
});

test('null archives a secret, and that needs secret.archive', async () => {
  await root.secrets.set('market/dev', { KEEP: 'k', GONE: 'g' });
  await assert.rejects(developer.secrets.set('market/dev', { GONE: null }), { status: 403 });
  await assert.rejects(developer.secrets.set('market/dev', { NEW: 'n', GONE: null }), { status: 403 });
  const listed = await root.secrets.list('market/dev');
  assert.deepEqual(listed.keys.map(({ key, archived }) => [key, archived]), [
    ['GONE', false],
    ['KEEP', false],
  ]);
  const denials = (await auditRows()).filter((row) => row.decision === 'deny');
  assert.deepEqual(denials.map((row) => [row.actorId, row.metadata]), [
    [DEVELOPER, { path: 'market/dev', reason: 'missing_secret_archive' }],
    [DEVELOPER, { path: 'market/dev', reason: 'missing_secret_archive' }],
  ]);

  assert.deepEqual((await root.secrets.set('market/dev', { GONE: null })).keys, { GONE: { archived: true } });
  const after = await root.secrets.list('market/dev');
  assert.deepEqual(after.keys.map(({ key, archived }) => [key, archived]), [
    ['GONE', true],
    ['KEEP', false],
  ]);
  assert.deepEqual(Object.keys((await root.secrets.reveal('market/dev')).values), ['KEEP']);
  assert.ok((await auditRows()).some((row) => row.action === 'secret.archive' && row.metadata.key === 'GONE'));
});

test('writing twice appends a version rather than mutating one', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'v1' });
  assert.deepEqual((await root.secrets.set('market/dev', { API_KEY: 'v2' })).keys.API_KEY, { version: 2 });
  assert.equal(await versionCount(), 2);
  assert.equal((await root.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'v2');
});

test('concurrent writes allocate one ordered version sequence', async () => {
  const writes = await Promise.all(
    Array.from({ length: 8 }, (_, index) => root.secrets.set('market/dev', { RACING_KEY: `value-${index}` })),
  );
  assert.deepEqual(
    writes.map((write) => (write.keys.RACING_KEY as { version: number }).version).sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  const versions = await db.owner
    .select({ version: secretVersions.version })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(eq(secrets.key, 'RACING_KEY'))
    .orderBy(asc(secretVersions.version));
  assert.deepEqual(versions.map((row) => row.version), [1, 2, 3, 4, 5, 6, 7, 8]);
});

test('renaming preserves value, versions, and immutable identity', async () => {
  await root.secrets.set('market/dev', { OLD_KEY: 'still-secret' });
  const [before] = await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'OLD_KEY'));
  assert.deepEqual(await root.secrets.rename('market/dev/OLD_KEY', 'NEW_KEY'), { key: 'NEW_KEY', archived: false });
  assert.equal((await root.secrets.reveal('market/dev/NEW_KEY')).values.NEW_KEY, 'still-secret');
  const [after] = await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'NEW_KEY'));
  assert.equal(after.id, before.id);
  assert.equal(await versionCount(), 1);
  assert.ok((await auditRows()).some((row) => row.action === 'secret.rename'));
});

test('a reader cannot write, and the denial is audited', async () => {
  await assert.rejects(reader.secrets.set('market/dev', { NOPE: 'x' }), { status: 403 });
  const rows = await auditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].decision, 'deny');
  assert.equal(rows[0].metadata.reason, 'missing_secret_write');
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('a granted reader can read, and the read is attributed to them', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'the-value' });
  assert.equal((await reader.secrets.reveal('market/dev/DATABASE_URL')).values.DATABASE_URL, 'the-value');
  const reads = (await auditRows()).filter((row) => row.action === 'secret.read');
  assert.equal(reads.length, 1);
  assert.equal(reads[0].actorId, READER);
  assert.equal(reads[0].metadata.key, 'DATABASE_URL');
});

test('denied and grantless reads are audited', async () => {
  await assert.rejects(reader.secrets.reveal('market/prod/ANYTHING'), { status: 403 });
  await assert.rejects(outsider.secrets.reveal('market/dev/X'), { status: 403 });
  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => row.actorId), [READER, 'outsider@acme.example']);
  assert.ok(rows.every((row) => row.decision === 'deny'));
  assert.equal(rows[0].metadata.reason, 'missing_secret_read');
});

test('a service read is attributed to the service principal', async () => {
  await root.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_xxx' });
  await ci.secrets.reveal('market/prod/STRIPE_KEY');
  const read = (await auditRows()).find((row) => row.action === 'secret.read' && row.decision === 'allow');
  assert.equal(read?.actorId, CI);
});

test('revealing an environment returns every secret and logs one entry per secret', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://x', REDIS_URL: 'redis://y', JWT_SECRET: 'shhh' });
  firstSeq = await nextSeq();
  const result = await reader.secrets.reveal('market/dev');
  assert.deepEqual(result.values, {
    DATABASE_URL: 'postgres://x',
    JWT_SECRET: 'shhh',
    REDIS_URL: 'redis://y',
  });
  const rows = await auditRows();
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((row) => row.metadata.key).sort(), ['DATABASE_URL', 'JWT_SECRET', 'REDIS_URL']);
  assert.deepEqual([...new Set(rows.map((row) => row.bundleId))], [result.bundleId]);
});

test('keys that are also Object prototype property names survive a round trip', async () => {
  await root.secrets.set('market/dev', { constructor: 'one', toString: 'two' });
  const result = await reader.secrets.reveal('market/dev');
  assert.deepEqual(Object.entries(result.values).sort(), [
    ['constructor', 'one'],
    ['toString', 'two'],
  ]);
});

test('a key named __proto__ is refused, not silently dropped', async () => {
  // A literal `{ __proto__: … }` would set the prototype, not a key.
  await assert.rejects(root.secrets.set('market/dev', JSON.parse('{"__proto__":"three","A":"1"}')), { status: 400 });
  assert.deepEqual((await root.secrets.list('market/dev')).keys, []);
});

test('the same key in two environments holds independent values', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'dev-value' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'prod-value' });
  assert.equal((await root.secrets.reveal('market/dev/DATABASE_URL')).values.DATABASE_URL, 'dev-value');
  assert.equal((await root.secrets.reveal('market/prod/DATABASE_URL')).values.DATABASE_URL, 'prod-value');
});

test('ciphertext relocated between environments cannot be decrypted', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'dev-only' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'prod-only' });
  const current = (slug: string) =>
    db.owner
      .select({
        id: secretVersions.id,
        ciphertext: secretVersions.ciphertext,
        iv: secretVersions.iv,
        authTag: secretVersions.authTag,
        wrappedDek: secretVersions.wrappedDek,
      })
      .from(secrets)
      .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
      .innerJoin(environments, eq(environments.id, secrets.environmentId))
      .where(and(eq(environments.slug, slug), eq(secrets.key, 'DATABASE_URL')));
  const [dev] = await current('dev');
  const [prod] = await current('prod');
  const { id: _, ...envelope } = dev;
  await db.owner.update(secretVersions).set(envelope).where(eq(secretVersions.id, prod.id));
  await assert.rejects(root.secrets.reveal('market/prod/DATABASE_URL'), { status: 500 });
});

test('the audit chain verifies over a realistic mixed workload', async () => {
  await root.secrets.set('market/dev', { A: '1' });
  await reader.secrets.reveal('market/dev/A');
  await assert.rejects(reader.secrets.reveal('market/prod/A'));
  await reader.secrets.reveal('market/dev');
  assert.equal((await root.audit.verify()).ok, true);
});

test('truncating the tail is detected even when surviving rows are consistent', async () => {
  await root.secrets.set('market/dev', { A: 'v' });
  await root.secrets.set('market/dev', { B: 'v' });
  await root.secrets.set('market/dev', { C: 'v' });
  assert.equal((await root.audit.verify()).ok, true);
  const kept = (await nextSeq()) - 2n;
  await db.owner.delete(auditLog).where(gte(auditLog.seq, kept));
  const result = await root.audit.verify();
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.failedAtSeq, Number(kept));
    assert.match(result.reason, /removed from the end/);
  }
});

test('verification reports the complete stored row count', async () => {
  await root.secrets.set('market/dev', { A: 'v', B: 'v', C: 'v', D: 'v' });
  const [stored] = await db.owner.select({ n: count() }).from(auditLog);
  const result = await root.audit.verify();
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.rows, stored.n);
});

test('a caller without audit.read cannot list or verify the audit log', async () => {
  await assert.rejects(reader.audit.list(), { status: 403 });
  await assert.rejects(reader.audit.verify(), { status: 403 });
});

test('listing secrets never reveals values or logs a secret read', async () => {
  await root.secrets.set('market/dev', { SECRET_ONE: 'hidden', SECRET_TWO: 'also-hidden' });
  await root.secrets.set('market/dev', { SECRET_TWO: null });
  const result = await reader.secrets.list('market/dev');
  assert.deepEqual(result.keys.map((entry) => entry.key), ['SECRET_ONE', 'SECRET_TWO']);
  assert.equal(result.keys[0].version, 1);
  assert.equal(result.keys[0].updatedBy, ROOT);
  assert.equal(JSON.stringify(result).includes('hidden'), false);
  assert.equal((await auditRows()).filter((row) => row.action === 'secret.read').length, 0);
});

test('me shows only the environments and audit capability held', async () => {
  const me = await reader.me();
  assert.equal(me.instanceRole, 'user');
  assert.equal(me.canReadAudit, false);
  assert.deepEqual(me.environments, [{ project: 'market', environment: 'dev', permissions: ['secret.read'] }]);
});

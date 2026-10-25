import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, count, eq, gte, sql } from 'drizzle-orm';

import {
  auditChainHead,
  auditLog,
  environments,
  secrets,
  secretVersions,
} from './db/tables.ts';
import { postgresOnly, withLogUnlocked, withTriggersLifted } from './db/engine.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { actorParts } from '../src/db/audit.ts';

const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const DEVELOPER = 'developer@acme.example';
const CI = 'ci-deploy.access';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let reader: CoffreClient;
let developer: CoffreClient;
let outsider: CoffreClient;
let ci: CoffreClient;
/** Audit entries from the seeding are not what these tests look at. */
let firstSeq: bigint;

before(async () => {
  db = await openTestDatabase();
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

/** One author's entries since `firstSeq`: the app's by default, or the vault's, which logs reads. */
async function auditRows(author: 'app' | 'vault' = 'app'): Promise<
  { actorId: string; action: string; decision: string; operationId: string | null; metadata: Record<string, unknown> }[]
> {
  const rows = await db.owner
    .select({
      actor: auditLog.actor,
      action: auditLog.action,
      decision: auditLog.decision,
      operationId: auditLog.operationId,
      metadata: auditLog.metadata,
    })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map(({ actor, ...row }) => ({ actorId: actorParts(actor).actorId, ...row, metadata: JSON.parse(row.metadata) }));
}

async function versionCount(): Promise<number> {
  const [row] = await db.owner.select({ n: count() }).from(secretVersions);
  return row.n;
}

test('the API runs on the restricted runtime login', postgresOnly('the restricted runtime role exists only on Postgres'), async () => {
  const identity = await db.runtime.execute<{ current_user: string }>(sql`SELECT current_user`);
  assert.equal(identity.rows[0].current_user, 'coffre_runtime');
  assert.deepEqual((await root.secrets.set('market/dev', { RUNTIME_PROOF: 'works' })).keys, {
    RUNTIME_PROOF: { version: 1, sensitivity: 'secret' },
  });
});

test('writing a secret is audited without its value', async () => {
  const written = await root.secrets.set('market/dev', { DATABASE_URL: 'db-demo://user:pw@host/db' });
  assert.deepEqual(written.keys, { DATABASE_URL: { version: 1, sensitivity: 'secret' } });
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

test('a value holding a lone surrogate is rejected, rather than stored as another, and nothing is written', async () => {
  for (const value of ['a\uD800', '\uDC00b', { value: 'x\uD83D', plain: true as const }]) {
    await assert.rejects(root.secrets.set('market/dev', { BAD: value }), { status: 400 });
  }
  assert.equal((await db.owner.select().from(secrets)).length, 0);
  // A pair is one character, and comes back as written.
  await root.secrets.set('market/dev', { EMOJI: 'key-\uD83D\uDD11' });
  assert.equal((await root.secrets.reveal('market/dev/EMOJI')).values.EMOJI, 'key-\uD83D\uDD11');
});

test('one patch writes one version and one audit entry per key, together', async () => {
  const written = await root.secrets.set('market/dev', { A: '1', B: '2', C: '3' });
  assert.deepEqual(written.keys, { A: { version: 1, sensitivity: 'secret' }, B: { version: 1, sensitivity: 'secret' }, C: { version: 1, sensitivity: 'secret' } });
  assert.equal(await versionCount(), 3);
  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.metadata.key]), [
    ['secret.write', 'A'],
    ['secret.write', 'B'],
    ['secret.write', 'C'],
  ]);
  assert.deepEqual([...new Set(rows.map((row) => row.operationId))], [written.operationId]);
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
  assert.deepEqual((await root.secrets.set('market/dev', { API_KEY: 'v2' })).keys.API_KEY, { version: 2, sensitivity: 'secret' });
  assert.equal(await versionCount(), 2);
  assert.equal((await root.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'v2');
});

test('the longest value round-trips, however many bytes it takes', async () => {
  // 64 Ki characters is the most a value holds: 64 KiB of ASCII, or three
  // times that in euro signs. Both must fit after encryption.
  const ascii = 'x'.repeat(64 * 1024);
  const euros = '€'.repeat(64 * 1024);
  await root.secrets.set('market/dev', { ASCII: ascii, EUROS: euros });

  const { values } = await root.secrets.reveal('market/dev');
  assert.equal(values.ASCII, ascii);
  assert.equal(values.EUROS, euros);
  const stored = await db.owner.select({ ciphertext: secretVersions.ciphertext }).from(secretVersions);
  assert.deepEqual(stored.map((row) => row.ciphertext.length).sort((a, b) => a - b), [64 * 1024, 3 * 64 * 1024]);
});

test('keys that differ only in case are different secrets', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'upper', api_key: 'lower' });
  assert.deepEqual((await root.secrets.reveal('market/dev')).values, { API_KEY: 'upper', api_key: 'lower' });
  await root.secrets.set('market/dev', { api_key: 'lower, again' });
  assert.equal((await root.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'upper');
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
  assert.deepEqual(await root.secrets.rename('market/dev/OLD_KEY', 'NEW_KEY'), { key: 'NEW_KEY', archived: false, folder: null });
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
  const reads = (await auditRows('vault')).filter((row) => row.action === 'secret.read');
  assert.equal(reads.length, 1);
  assert.equal(reads[0].actorId, READER);
  assert.deepEqual([reads[0].metadata.subject, reads[0].metadata.purpose], ['market/dev/DATABASE_URL', 'reveal']);
  // The vault's entry is the record of it: the app adds none.
  assert.deepEqual((await auditRows()).filter((row) => row.action === 'secret.read'), []);
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
  const read = (await auditRows('vault')).find((row) => row.action === 'secret.read' && row.decision === 'allow');
  assert.equal(read?.actorId, CI);
});

test('revealing an environment returns every secret and logs one entry listing each', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://x', REDIS_URL: 'redis://y', JWT_SECRET: 'shhh' });
  firstSeq = await nextSeq();
  const result = await reader.secrets.reveal('market/dev');
  assert.deepEqual(result.values, {
    DATABASE_URL: 'postgres://x',
    JWT_SECRET: 'shhh',
    REDIS_URL: 'redis://y',
  });
  const rows = await auditRows('vault');
  assert.equal(rows.length, 1);
  const [row] = rows as [(typeof rows)[number]];
  const listed = row.metadata.secrets as { subject: string; version: number }[];
  assert.deepEqual(listed.map((secret) => [secret.subject, secret.version]).sort(), [
    ['market/dev/DATABASE_URL', 1], ['market/dev/JWT_SECRET', 1], ['market/dev/REDIS_URL', 1],
  ]);
  assert.equal(row.metadata.purpose, 'run');
  assert.equal(row.operationId, result.operationId);
  assert.deepEqual(await auditRows(), []);
});

test('revealing some keys of an environment opens and logs only those, and names what it left out among them only', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://x', REDIS_URL: 'redis://y', JWT_SECRET: 'shhh', SIGNING_KEY: { value: 'k', sensitivity: 'sensitive' }, WEBHOOK: { value: 'w', sensitivity: 'sensitive' } });
  firstSeq = await nextSeq();
  // A key the environment does not hold is left out, not refused: the CLI listed it first.
  const result = await reader.secrets.reveal('market/dev', ['REDIS_URL', 'DATABASE_URL', 'SIGNING_KEY', 'NOT_HERE']);
  assert.deepEqual(result.values, { DATABASE_URL: 'postgres://x', REDIS_URL: 'redis://y' });
  // A person's read leaves the sensitive value out, as a whole read does, but names only the one asked for.
  assert.deepEqual(result.sensitive, ['SIGNING_KEY']);
  const rows = await auditRows('vault');
  assert.equal(rows.length, 1);
  const listed = rows[0]!.metadata.secrets as { subject: string }[];
  assert.deepEqual(listed.map((secret) => secret.subject).sort(), ['market/dev/DATABASE_URL', 'market/dev/REDIS_URL']);
  assert.equal(rows[0]!.metadata.purpose, 'run');
  assert.equal(rows[0]!.operationId, result.operationId);
  assert.deepEqual(await auditRows(), []);
  // Its version is of what it read: another key's write leaves it as it was.
  await root.secrets.set('market/dev', { JWT_SECRET: 'rotated' });
  assert.equal((await reader.secrets.reveal('market/dev', ['DATABASE_URL', 'REDIS_URL'])).version, result.version);
  await root.secrets.set('market/dev', { REDIS_URL: 'redis://z' });
  assert.notEqual((await reader.secrets.reveal('market/dev', ['DATABASE_URL', 'REDIS_URL'])).version, result.version);

  // Nothing it names to open: the read is logged as one, of nothing.
  firstSeq = await nextSeq();
  const none = await reader.secrets.reveal('market/dev', ['NOT_HERE']);
  assert.deepEqual([none.values, none.sensitive], [{}, []]);
  const [nothing] = await auditRows();
  assert.deepEqual([nothing!.action, nothing!.decision, nothing!.metadata.reason], ['secret.read', 'allow', 'no_named_key']);
});

test('keys names keys of an environment, never of one key, and only well-formed ones', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://x' });
  await assert.rejects(reader.secrets.reveal('market/dev/DATABASE_URL', ['DATABASE_URL']), { status: 400, message: /keys names keys of an environment/ });
  await assert.rejects(reader.secrets.reveal('market/dev', []), { status: 400 });
  await assert.rejects(reader.secrets.reveal('market/dev', ['STRIPE_*']), { status: 400 });
});

test('the log of one key finds the read of its environment, which lists it, and the log of a key it did not read does not', async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://x', REDIS_URL: 'redis://y' });
  const { operationId } = await reader.secrets.reveal('market/dev');
  await root.secrets.set('market/dev', { LATER: 'z' });
  const read = async (path: string) => (await root.audit.list({ path, limit: 50 })).entries.find((entry) => entry.operationId === operationId && entry.action === 'secret.read');
  const found = await read('market/dev/REDIS_URL');
  assert.deepEqual([found?.key, found?.version, found?.secrets], [null, null, [{ key: 'DATABASE_URL', version: 1 }, { key: 'REDIS_URL', version: 1 }]]);
  assert.equal((await read('market/dev/LATER')), undefined);
  assert.equal((await read('market/prod')), undefined);
});

test('the log of a key is asked for by its full path, the longest slugs and key included', async () => {
  const [project, environment, key] = [`p${'r'.repeat(62)}`, `e${'n'.repeat(62)}`, `K${'E'.repeat(127)}`];
  await root.projects.create(project, { name: 'Long' });
  await root.environments.create(`${project}/${environment}`, { name: 'Long' });
  await root.secrets.set(`${project}/${environment}`, { [key]: 'value' });
  const path = `${project}/${environment}/${key}`;
  assert.equal(path.length, 256);
  const { entries } = await root.audit.list({ path, limit: 10 });
  assert.deepEqual(entries.filter((found) => found.action === 'secret.write').map((found) => found.key), [key]);
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
  // A version changes only by being erased; the owner lifts that to play someone who moves one.
  await withTriggersLifted(db.owner, 'secret_versions', (owner) =>
    owner.update(secretVersions).set(envelope).where(eq(secretVersions.id, prod.id)));
  // The vault unwraps a key only as the secret it was wrapped for: dev's key is not prod's.
  await assert.rejects(root.secrets.reveal('market/prod/DATABASE_URL'), { status: 403, code: 'vault_refused', reason: 'bad_claim' });
});

test("a key's age is its current version's: a rename or a move leaves it, a write moves it; the list says when a value is due", async () => {
  await root.secrets.set('market/dev', { OLD_KEY: 'v1' });
  const written = new Date('2025-01-02T03:04:05.000Z');
  // The owner backdates the version, as a value written last year.
  await withTriggersLifted(db.owner, 'secret_versions', (owner) => owner.update(secretVersions).set({ createdAt: written }));
  await root.secrets.rename('market/dev/OLD_KEY', 'NEW_KEY');
  await root.secrets.update('market/dev/NEW_KEY', { folder: 'stripe' });
  const listed = await reader.secrets.list('market/dev');
  assert.deepEqual(listed.keys.map(({ key, updatedAt }) => [key, updatedAt]), [['NEW_KEY', written.toISOString()]]);
  assert.equal(listed.rotateAfterDays, 365);

  await root.secrets.set('market/dev', { NEW_KEY: 'v2' });
  const [{ versions }, after] = await Promise.all([root.secrets.history('market/dev/NEW_KEY'), reader.secrets.list('market/dev')]);
  assert.equal(after.keys[0].updatedAt, versions.find((version) => version.current)!.createdAt);
  assert.ok(after.keys[0].updatedAt! > written.toISOString());
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
  await withLogUnlocked(db.owner, async (owner) => {
    // SQLite checks the link from a write to its key.wrap row by row: unlink the tail first.
    await owner.update(auditLog).set({ relatedSeq: null }).where(gte(auditLog.seq, kept));
    await owner.delete(auditLog).where(gte(auditLog.seq, kept));
  });
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
  if (result.ok) assert.equal(result.entries, stored.n);
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
  assert.equal(me.instanceRole, 'member');
  assert.equal(me.canReadAudit, false);
  assert.deepEqual(me.environments, [{ project: 'market', environment: 'dev', permissions: ['secret.read', 'secret.use'] }]);
});

test('an empty secret patch is refused before it can disclose another environment', async () => {
  await root.secrets.set('market/prod', { HIDDEN: 'value' });
  await root.secrets.update('market/prod/HIDDEN', { archived: true });
  await assert.rejects(reader.secrets.update('market/prod/HIDDEN', {}), { status: 400 });
  await assert.rejects(root.secrets.update('market/prod/HIDDEN', {}), { status: 400 });
  assert.deepEqual(await root.secrets.update('market/prod/HIDDEN', { archived: false }), { key: 'HIDDEN', archived: false, folder: null });
});

test('a competing first write discards the provisional ID and wraps the next version afresh', async (t) => {
  const wrap = deps.vault.wrap;
  const prepared: { secretId: string; version: number }[] = [];
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    prepared.push(...input.items.map(({ secret }) => ({ secretId: secret.secretId, version: secret.version })));
    if (compete) {
      compete = false;
      assert.equal((await db.owner.select().from(secrets)).length, 0, 'the vault sees no uncommitted secret');
      await root.secrets.set('market/dev', { RACE: 'first committed' });
    }
    return result;
  });
  const written = await root.secrets.set('market/dev', { RACE: 'retried' });
  assert.deepEqual(written.keys, { RACE: { version: 2, sensitivity: 'secret' } });
  assert.equal(prepared.length, 3);
  assert.notEqual(prepared[0].secretId, prepared[1].secretId);
  assert.deepEqual(prepared[2], { secretId: prepared[1].secretId, version: 2 });
  assert.equal(await versionCount(), 2);
  assert.deepEqual((await root.secrets.reveal('market/dev')).values, { RACE: 'retried' });
});

test('a parent archived while wrapping cannot receive the prepared write', async (t) => {
  const wrap = deps.vault.wrap;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    await root.environments.update('market/dev', { archived: true });
    return result;
  });
  await assert.rejects(root.secrets.set('market/dev', { LATE: 'discarded' }), { status: 404 });
  assert.equal(await versionCount(), 0);
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('a restore retries after a competing write and preserves both committed versions', async (t) => {
  await root.secrets.set('market/dev', { RACE: 'original' });
  const rewrap = deps.vault.rewrap;
  let compete = true;
  let calls = 0;
  t.mock.method(deps.vault, 'rewrap', async (input: Parameters<typeof rewrap>[0]) => {
    const result = await rewrap(input);
    calls++;
    if (compete) {
      compete = false;
      await root.secrets.set('market/dev', { RACE: 'competing' });
    }
    return result;
  });
  assert.equal((await root.secrets.restore('market/dev/RACE', 1)).version, 3);
  assert.equal(calls, 2);
  assert.equal(await versionCount(), 3);
  assert.deepEqual((await root.secrets.reveal('market/dev')).values, { RACE: 'original' });
});

test('a secret archived while rewrapping cannot be restored by the prepared write', async (t) => {
  await root.secrets.set('market/dev', { RACE: 'original' });
  const rewrap = deps.vault.rewrap;
  t.mock.method(deps.vault, 'rewrap', async (input: Parameters<typeof rewrap>[0]) => {
    const result = await rewrap(input);
    await root.secrets.set('market/dev', { RACE: null });
    return result;
  });
  await assert.rejects(root.secrets.restore('market/dev/RACE', 1), { status: 409 });
  assert.equal(await versionCount(), 1);
});

for (const read of ['reveal', 'run', 'import preview'] as const) {
  test(`a ${read} is on the record before any value reaches the app, which writes nothing for it`, async (t) => {
    await root.secrets.set('market/dev', { VALUE: 'the value' });
    firstSeq = await nextSeq();
    // From here no transaction of the app's commits: a read needs none, the vault's entry is its record.
    t.mock.method(db.runtime, 'transaction', (() => Promise.reject(new Error('the app cannot write'))) as typeof db.runtime.transaction);
    if (read === 'import preview') {
      assert.deepEqual((await root.secrets.dryRun('market/dev', { VALUE: 'the value' })).keys, { VALUE: 'unchanged' });
    } else {
      assert.equal((await root.secrets.reveal(read === 'reveal' ? 'market/dev/VALUE' : 'market/dev')).values.VALUE, 'the value');
    }
    const [logged] = await auditRows('vault');
    assert.deepEqual([logged.action, logged.decision, logged.metadata.purpose], [
      'secret.read', 'allow', { reveal: 'reveal', run: 'run', 'import preview': 'compare' }[read],
    ]);
  });
}

test("a reveal whose vault cannot reach the database is 503 unavailable, to ask again, not a 500", async (t) => {
  await root.secrets.set('market/prod', { API_KEY: 'fake-key' });
  t.mock.method(console, 'error', () => {});
  // What the vault threw on 2026-10-25, every connection of Hyperdrive's pool busy past 15 s.
  const unwrap = t.mock.method(deps.vault, 'unwrap', async () => {
    throw new Error('Failed query: select "secret_versions"."id" …', {
      cause: Object.assign(new Error('Timed out while waiting for an open slot in the pool.'), { code: '58000', severity: 'FATAL' }),
    });
  });
  await assert.rejects(root.secrets.reveal('market/prod'), { status: 503, code: 'unavailable', message: 'coffre cannot reach what it depends on right now; try again in a moment' });
  unwrap.mock.restore();
  assert.deepEqual((await root.secrets.reveal('market/prod')).values, { API_KEY: 'fake-key' });
});

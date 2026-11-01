// 0.15's change path for the app's environments and keys, as the API drives it (docs/design/0.15-plan.md, "As built:
// PR 4b", part 2): each write that makes, renames, archives, restores or deletes an environment, or writes, archives,
// restores or erases a key, is a change of 0.15's log, prepared by the vault before the app's transaction and committed
// in it beside the rows. A token then reads through 0.15's use path, which checks every input's seal: a row left other
// than its change sealed would answer `stale` or `tampered`. The vault's tests hold `prepare`, `app_change` and the
// replay themselves (packages/vault/test/app-places.test.ts); these, the app's wiring.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import type { UseOutcome, Vault } from '@coffre/core/vault';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';

import { patchProject } from '../src/api/projects.ts';
import { SigninService } from '../src/api/signin.ts';
import { resolvePath } from '../src/db/queries.ts';
import { auditLog, environments, logChanges, logFence, projects, secretReferences, secrets, secretVersions } from './db/tables.ts';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly, TEST_ENGINE } from './db/engine.ts';
import { clientFor, contextFor, credentialsLogged, openTestDatabase, resetDatabase, sealedNow, nothingHeld, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const CI = 'token:ci';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

/** 0.15's log on, and its use path, over the hot login (the same file on SQLite). */
function vault015() {
  const hotDatabase = TEST_ENGINE === 'postgres' ? TEST_HOT_DATABASE_URL : process.env.COFFRE_TEST_DATABASE_URL!;
  return testVault([ROOT], { hotDatabase }, undefined, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld });
}

/** The instance, with `log`'s vault, and a sign-in, which issues tokens. */
async function instance(vault: ReturnType<typeof testVault>): Promise<void> {
  await resetDatabase(db.owner);
  // Uses go in today's partition, at or past the floor of `at` (schema 0022), as a deployment's checkpointer keeps them.
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  if (TEST_ENGINE === 'postgres') {
    const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
    await db.owner.execute(sql`SELECT make_day(${day(Date.now() - 86_400_000)}::date), make_day(${day(Date.now())}::date), make_day(${day(Date.now() + 86_400_000)}::date)`);
  }
  deps = testDeps(db.runtime, [ROOT], { vault });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  root = clientFor(deps, ROOT);
  await root.members.add(CI);
}

const SIGNIN = defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })] });

beforeEach(() => instance(vault015()));

/** An object's key in 0.15's log, as the fixture's `credentialsLogged` makes it. */
function objectKey(kind: string, id: string): string {
  const hex = createHash('sha256').update(`coffre.object.v1\0${kind}\0${id}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** Each object's ops in 0.15's log, by kind and id. */
async function opsOf(kind: 'secret' | 'environment', id: string): Promise<string[]> {
  return (await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey(kind, id))).orderBy(asc(logChanges.number)))
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
}

/** Every key's and environment's row carries its newest change's seal, or neither has one; and every credential's (`credentialsLogged`). */
async function inputsLogged(): Promise<void> {
  const newest = new Map<string, { number: bigint; seal: Buffer | null }>();
  for (const change of await db.owner.select({ object: logChanges.object, number: logChanges.number, seal: logChanges.seal }).from(logChanges)) {
    const number = BigInt(change.number);
    if ((newest.get(change.object)?.number ?? -1n) < number) newest.set(change.object, { number, seal: change.seal ?? null });
  }
  const strays = (kind: string) => (row: { id: string; seal: Buffer | null }) => {
    const logged = newest.get(objectKey(kind, row.id))?.seal ?? null;
    return row.seal == null || logged === null ? (row.seal ?? null) !== logged : !row.seal.equals(logged);
  };
  assert.deepEqual((await db.owner.select({ id: secrets.id, seal: secrets.seal }).from(secrets)).filter(strays('secret')), [], "every key's row is its newest change's");
  assert.deepEqual((await db.owner.select({ id: environments.id, seal: environments.seal }).from(environments)).filter(strays('environment')), [], "every environment's row is its newest change's");
  await credentialsLogged(db.owner);
}

let request = 0n;

/** A use of `secretId` by credential `credential`, through 0.15's use path. */
async function use(credential: string, secretId: string, place: string | null = null): Promise<UseOutcome> {
  const at = Date.now();
  request += 1n;
  return deps.vault.use!({ credential, secretId, place, purpose: 'run', requestId: ((randomBytes(6).readUIntBE(0, 6) * 1000) + Number(request % 1000n)).toString(), at, deadline: at + 3000 });
}

const codeOf = (outcome: UseOutcome) => (outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : outcome.busy);

async function keyIn(environmentId: string, key: string): Promise<string> {
  const rows = await db.owner.select({ id: secrets.id, key: secrets.key, environmentId: secrets.environmentId }).from(secrets);
  const row = rows.find((each) => each.environmentId === environmentId && each.key === key);
  assert.ok(row !== undefined, `${key} in ${environmentId}`);
  return row.id;
}

async function environmentId(slug: string): Promise<string> {
  const [row] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, slug));
  assert.ok(row !== undefined, slug);
  return row.id;
}

test('each way the API writes an environment or a key is a change of 0.15\'s log; a token reads through the use path as the rows say', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { SOURCE: 'from-prod' });
  await root.secrets.set('market/dev', { A: 'one', B: 'two' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const dev = await environmentId('dev');
  const [a, b] = [await keyIn(dev, 'A'), await keyIn(dev, 'B')];
  assert.equal(codeOf(await use(token.id, a)), 'ok');

  // A value written again, a reference made, a key archived and back, a version restored.
  await root.secrets.set('market/dev', { A: 'one-again', C: { ref: 'market/prod/SOURCE' } });
  const c = await keyIn(dev, 'C');
  await root.secrets.set('market/dev', { B: null });
  const archived = await use(token.id, b);
  assert.ok(!['ok', 'stale', 'tampered'].includes(codeOf(archived)), JSON.stringify(archived));
  await root.secrets.update('market/dev/B', { archived: false });
  await root.secrets.restore('market/dev/A', 1);
  for (const id of [a, b]) assert.equal(codeOf(await use(token.id, id)), 'ok', id);
  assert.ok(!['stale', 'tampered'].includes(codeOf(await use(token.id, c))));
  assert.deepEqual(await opsOf('secret', a), ['secret.write', 'secret.write', 'secret.write']);
  assert.deepEqual(await opsOf('secret', b), ['secret.write', 'secret.delete', 'secret.write']);
  assert.deepEqual(await opsOf('secret', c), ['secret.write']);

  // Renamed, archived and restored: the grant is on its id, and the use goes on, its row its change's.
  await root.environments.update('market/dev', { slug: 'development' });
  await root.environments.update('market/development', { archived: true });
  await root.environments.update('market/development', { archived: false });
  assert.equal(codeOf(await use(token.id, a)), 'ok');
  assert.deepEqual(await opsOf('environment', dev), ['environment.create', 'environment.rename', 'environment.archive', 'environment.archive']);

  // A fork that inherits, its override reset to the parent's and made its own again; a personal config.
  await root.environments.create('market/feature', { from: 'development', inherit: true });
  const feature = await environmentId('feature');
  await root.secrets.set('market/feature', { A: 'override' });
  const own = await keyIn(feature, 'A');
  await root.secrets.inherit('market/feature/A', true);
  await root.secrets.inherit('market/feature/A', false);
  assert.deepEqual(await opsOf('secret', own), ['secret.write', 'secret.delete', 'secret.write']);
  assert.deepEqual(await opsOf('environment', feature), ['environment.create']);
  await root.secrets.set('market/development@me', { MINE: 'mine' });
  const [config] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.owner, `user:${ROOT}`));
  assert.ok(config !== undefined);
  assert.deepEqual(await opsOf('environment', config.id), ['environment.create']);
  await inputsLogged();
});

/** `secretId`'s versions' ids, oldest first. */
async function versionsOf(secretId: string): Promise<string[]> {
  return (await db.owner.select({ id: secretVersions.id }).from(secretVersions).where(eq(secretVersions.secretId, secretId)).orderBy(asc(secretVersions.version))).map(({ id }) => id);
}

/** The vault's refusal of rows its log does not bear out, reported (`vault.tampered`, its code `stale`). */
const notTheLogs = (error: unknown) => (error as { reason?: unknown }).reason === 'tampered';

test("a key's rows put back to an older version while it is archived: its unarchive and an override made again are refused and reported, nothing logged; as archived, each serves its last value (T134)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.secrets.set('market/dev', { A: 'two' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const a = await keyIn(await environmentId('dev'), 'A');
  const [one, two] = await versionsOf(a);
  await root.secrets.update('market/dev/A', { archived: true });
  const ops = await opsOf('secret', a);
  // A writer points the archived key at its first value: one the log sealed once, not the one it last did.
  await db.owner.update(secrets).set({ currentVersionId: one! }).where(eq(secrets.id, a));
  await assert.rejects(root.secrets.update('market/dev/A', { archived: false }), notTheLogs);
  assert.deepEqual(await opsOf('secret', a), ops);
  assert.deepEqual((await db.owner.select({ code: auditLog.code }).from(auditLog).where(eq(auditLog.action, 'vault.tampered'))).map(({ code }) => code), ['stale']);
  assert.ok((await db.owner.select({ archivedAt: secrets.archivedAt }).from(secrets).where(eq(secrets.id, a)))[0]!.archivedAt !== null, 'still archived');
  await db.owner.update(secrets).set({ currentVersionId: two! }).where(eq(secrets.id, a));
  await root.secrets.update('market/dev/A', { archived: false });
  const outcome = await use(token.id, a);
  assert.ok(outcome.ok && outcome.value.versionId === two, JSON.stringify(outcome));

  // A fork's override reset to the parent's, then made its own again: the same.
  await root.environments.create('market/feature', { from: 'dev', inherit: true });
  await root.secrets.set('market/feature', { A: 'override one' });
  await root.secrets.set('market/feature', { A: 'override two' });
  const own = await keyIn(await environmentId('feature'), 'A');
  const [first, last] = await versionsOf(own);
  await root.secrets.inherit('market/feature/A', true);
  await db.owner.update(secrets).set({ currentVersionId: first! }).where(eq(secrets.id, own));
  await assert.rejects(root.secrets.inherit('market/feature/A', false), notTheLogs);
  await db.owner.update(secrets).set({ currentVersionId: last! }).where(eq(secrets.id, own));
  await root.secrets.inherit('market/feature/A', false);
  assert.deepEqual(await opsOf('secret', own), ['secret.write', 'secret.write', 'secret.delete', 'secret.write']);
  await inputsLogged();
});

test("a reference broken through the API: its row's end and its holder's change in the vault's decision, and a token's use through it refused `ended`; a value written over it, then a reference again, read as the rows say (T125)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { SOURCE: 'from-prod' });
  await root.secrets.set('market/dev', { C: { ref: 'market/prod/SOURCE' } });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const c = await keyIn(await environmentId('dev'), 'C');
  assert.equal(codeOf(await use(token.id, c)), 'ok');
  await root.references.break('market/dev/C');
  assert.equal(codeOf(await use(token.id, c)), 'ended');
  assert.deepEqual(await opsOf('secret', c), ['secret.write', 'secret.write']);
  const ends = async () => (await db.owner.select({ endedAt: secretReferences.endedAt }).from(secretReferences).where(eq(secretReferences.secretId, c)).orderBy(asc(secretReferences.createdSeq)))
    .map((row) => row.endedAt !== null);
  assert.deepEqual(await ends(), [true]);
  // A value of its own over the ended reference, then a reference again (the old one ended `replaced` by the vault first).
  await root.secrets.set('market/dev', { C: 'its own' });
  assert.equal(codeOf(await use(token.id, c)), 'ok');
  await root.secrets.set('market/dev', { C: { ref: 'market/prod/SOURCE' } });
  assert.equal(codeOf(await use(token.id, c)), 'ok');
  await root.secrets.set('market/dev', { C: 'its own again' });
  assert.equal(codeOf(await use(token.id, c)), 'ok');
  assert.deepEqual(await ends(), [true, true]);
  await inputsLogged();
});

test("a project archived and restored through the API: each of its live environments' change (`project.archive`), a personal config's and one archived on its own included, and a token's use through a fork of it refused as 0.14 refuses it (T126)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.environments.create('market/feature', { from: 'dev', inherit: true });
  await root.environments.create('market/old');
  await root.environments.update('market/old', { archived: true });
  await root.secrets.set('market/dev@me', { MINE: 'mine' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const [dev, feature, old] = [await environmentId('dev'), await environmentId('feature'), await environmentId('old')];
  const [config] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.owner, `user:${ROOT}`));
  assert.ok(config !== undefined);
  const a = await keyIn(dev, 'A');
  assert.equal(codeOf(await use(token.id, a, feature)), 'ok');
  await root.projects.update('market', { archived: true });
  assert.equal(codeOf(await use(token.id, a, feature)), 'bad_claim');
  for (const id of [dev, feature, old, config.id]) assert.equal((await opsOf('environment', id)).at(-1), 'project.archive', id);
  await inputsLogged();
  await root.projects.update('market', { archived: false });
  assert.equal(codeOf(await use(token.id, a, feature)), 'ok');
  for (const id of [dev, feature, old, config.id]) assert.deepEqual((await opsOf('environment', id)).slice(-2), ['project.archive', 'project.archive'], id);
  // Archived on its own, it stays so once its project is restored: the two apart.
  assert.equal((await opsOf('environment', old)).filter((op) => op === 'environment.archive').length, 1);
  assert.equal(codeOf(await use(token.id, a, old)), 'bad_claim');
  await inputsLogged();
});

test("a project archived through the API, then deleted while one of its keys reads another project's: the reference ends with its holder's change, and the deletion's own changes follow (T125, T126)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.projects.create('web');
  await root.environments.create('web/prod');
  await root.secrets.set('web/prod', { OTHER: 'web-other' });
  await root.secrets.set('market/dev', { OTHER: { ref: 'web/prod/OTHER' } });
  const dev = await environmentId('dev');
  const held = await keyIn(dev, 'OTHER');
  await root.projects.update('market', { archived: true });
  const { deletion } = await root.projects.delete('market');
  assert.equal(deletion.references.length, 1);
  assert.deepEqual((await opsOf('secret', held)).slice(-2), ['secret.write', 'secret.delete']);
  assert.deepEqual((await opsOf('environment', dev)).slice(-2), ['project.archive', 'environment.delete']);
  const [row] = await db.owner.select({ endedAt: secretReferences.endedAt }).from(secretReferences).where(eq(secretReferences.secretId, held));
  assert.ok(row?.endedAt != null);
  await inputsLogged();
});

test('a protected environment\'s fork is made protected: its row and its object say so from its first change', async () => {
  await root.projects.create('market');
  await root.environments.create('market/prod');
  await root.environments.protect('market/prod');
  await root.environments.create('market/staging', { from: 'prod' });
  const staging = await environmentId('staging');
  const [row] = await db.owner.select({ protected: environments.protected }).from(environments).where(eq(environments.id, staging));
  assert.equal(row?.protected, true);
  const [first] = await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey('environment', staging)));
  assert.equal((JSON.parse(first!.payload) as { protected?: boolean }).protected, true);
  await inputsLogged();
});

test('an environment\'s deletion: it and its personal configs deleted, each live key erased, deleted and archived; a use there refused as the log says', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one', B: 'two', GONE: 'archived first' });
  await root.secrets.set('market/dev', { GONE: null });
  await root.secrets.set('market/dev@me', { MINE: 'mine' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const dev = await environmentId('dev');
  const [config] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.owner, `user:${ROOT}`));
  const [a, b, gone, mine] = [await keyIn(dev, 'A'), await keyIn(dev, 'B'), await keyIn(dev, 'GONE'), await keyIn(config!.id, 'MINE')];
  await root.environments.update('market/dev', { archived: true });
  await root.environments.delete('market/dev');
  for (const id of [a, b, mine]) assert.deepEqual((await opsOf('secret', id)).at(-1), 'secret.delete', id);
  assert.deepEqual(await opsOf('secret', gone), ['secret.write', 'secret.delete'], 'archived already: deleted once');
  assert.deepEqual((await opsOf('environment', dev)).at(-1), 'environment.delete');
  assert.deepEqual((await opsOf('environment', config!.id)).at(-1), 'environment.delete');
  const keys = await db.owner.select({ id: secrets.id, archivedAt: secrets.archivedAt }).from(secrets).where(inArray(secrets.id, [a, b, mine]));
  assert.ok(keys.every((key) => key.archivedAt !== null), 'archived: a use reads no key, as the log has none');
  const outcome = await use(token.id, a);
  assert.ok(!['ok', 'stale', 'tampered'].includes(codeOf(outcome)), JSON.stringify(outcome));
  await inputsLogged();
});

test('a project\'s deletion makes each environment `<slug>~deleted`, logs each one deleted, and each live key; its old path still names it', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.secrets.set('market/prod', { A: 'two' });
  await root.access.set(CI, { 'market/prod': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  // An environment deleted alone first, and its slug taken again: the project's deletion takes the new one.
  const old = await environmentId('dev');
  await root.environments.update('market/dev', { archived: true });
  await root.environments.delete('market/dev');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'three' });
  const [dev, prod] = [await environmentId('dev'), await environmentId('prod')];
  const keys = [await keyIn(dev, 'A'), await keyIn(prod, 'A')];
  await root.projects.update('market', { archived: true });
  const { deletion } = await root.projects.delete('market');
  assert.deepEqual(deletion.environments, ['dev', 'prod'], 'named as they were');
  const rows = await db.owner.select({ id: environments.id, slug: environments.slug }).from(environments).where(inArray(environments.id, [old, dev, prod]));
  const slugOf = (id: string) => rows.find((row) => row.id === id)!.slug;
  assert.deepEqual([slugOf(dev), slugOf(prod)], ['dev~deleted', 'prod~deleted']);
  assert.match(slugOf(old), /^dev~deleted-\d{4}-\d{2}-\d{2}$/, 'the one deleted alone keeps its dated tombstone');
  for (const id of [dev, prod]) assert.equal((await opsOf('environment', id)).at(-1), 'environment.delete');
  for (const id of keys) assert.equal((await opsOf('secret', id)).at(-1), 'secret.delete');
  const outcome = await use(token.id, keys[1]!);
  assert.ok(!['ok', 'stale', 'tampered'].includes(codeOf(outcome)), JSON.stringify(outcome));
  await inputsLogged();
  // The log reads each by the path the deletion named it by, and by its tombstone; the one deleted alone, by its own.
  const environmentOf = async (path: string) => {
    const { entries } = await root.audit.list({ path, limit: 500 });
    assert.ok(entries.length > 0, path);
    return new Set(entries.map((entry) => entry.environment));
  };
  for (const [slug, id] of [['dev', dev], ['dev~deleted', dev], ['prod', prod], ['prod~deleted', prod], [slugOf(old), old]] as const) {
    assert.deepEqual(await environmentOf(`${deletion.tombstone}/${slug}`), new Set([slugOf(id)]), slug);
  }
});

test('a key written into a personal config while it is deleted: the deletion reads its keys again, and deletes each one it erases', async (t) => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev@me', { MINE: 'mine' });
  const [config] = await db.owner.select({ id: environments.id, slug: environments.slug }).from(environments).where(eq(environments.owner, `user:${ROOT}`));
  const prepare = deps.vault.prepare!;
  let raced = false;
  t.mock.method(deps.vault as Required<Vault>, 'prepare', async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    // Between the deletion's read of the config's keys and its transaction, its owner writes another.
    if (!raced && input.changes.some((change) => change.kind === 'environment' && change.id === config!.id)) {
      raced = true;
      await root.secrets.set('market/dev@me', { LATE: 'late' });
    }
    return prepared;
  });
  await root.environments.delete(`market/${config!.slug}`);
  assert.ok(raced);
  const late = await keyIn(config!.id, 'LATE');
  assert.deepEqual(await opsOf('secret', late), ['secret.write', 'secret.delete']);
  await inputsLogged();
});

test('a project archived by another request while this one archives it: the second writes and logs nothing of it', async (t) => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const dev = await environmentId('dev');
  const prepare = deps.vault.prepare!;
  let raced = false;
  t.mock.method(deps.vault as Required<Vault>, 'prepare', async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    if (!raced && input.changes.some((change) => change.kind === 'environment' && change.id === dev && change.after.projectArchived)) {
      raced = true;
      await root.projects.update('market', { archived: true });
    }
    return prepared;
  });
  await root.projects.update('market', { archived: true });
  assert.ok(raced);
  const archives = await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(eq(auditLog.action, 'project.archive'));
  assert.equal(archives.length, 1);
  assert.deepEqual((await opsOf('environment', dev)).filter((op) => op === 'project.archive'), ['project.archive']);
  await inputsLogged();
});

test("an archive that prepared nothing (another request had archived the project) while a third restores it before its transaction: it prepares again, and no environment's seal is left behind (review r6)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const a = await keyIn(await environmentId('dev'), 'A');
  const ctx = await contextFor(deps, ROOT);
  const place = await resolvePath(ctx.db, { project: 'market' });
  assert.ok(place !== null);
  // A has the project live; B archives it before A reads its environments, so A prepares nothing.
  await root.projects.update('market', { archived: true });
  let raced = false;
  ctx.db = new Proxy(ctx.db, {
    get(target, name) {
      const value = Reflect.get(target, name) as unknown;
      if (name === 'transaction' && typeof value === 'function') {
        return async (...args: unknown[]) => {
          // C restores it before A takes the head.
          if (!raced) {
            raced = true;
            await root.projects.update('market', { archived: false });
          }
          return (value as (...xs: unknown[]) => unknown).apply(target, args);
        };
      }
      return typeof value === 'function' ? (value as (...xs: unknown[]) => unknown).bind(target) : value;
    },
  });
  await patchProject(ctx, place, { archived: true });
  assert.ok(raced);
  assert.equal(codeOf(await use(token.id, a)), 'ok');
  await root.projects.update('market', { archived: false });
  assert.equal(codeOf(await use(token.id, a)), 'ok');
  await inputsLogged();
});

test("a project a writer marked archived in the database: an archive asked then is refused as tampered, never taken as done, and nothing is logged (review r8)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const dev = await environmentId('dev');
  const before = await opsOf('environment', dev);
  await db.owner.update(projects).set({ archivedAt: new Date() }).where(eq(projects.slug, 'market'));
  await assert.rejects(root.projects.update('market', { archived: true }));
  await db.owner.update(projects).set({ archivedAt: null }).where(eq(projects.slug, 'market'));
  assert.deepEqual(await opsOf('environment', dev), before);
  assert.equal((await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(eq(auditLog.action, 'project.archive'))).length, 0);
});

test("an archive or a restore asked of the project as another request left it, the other undoing it before: each writes what it asks, its environments sealed to match (review r9)", async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const dev = await environmentId('dev');
  const ctx = await contextFor(deps, ROOT);
  // A finds the project archived and asks to archive it; B restores it before A prepares.
  await root.projects.update('market', { archived: true });
  const archived = await resolvePath(ctx.db, { project: 'market' });
  assert.ok(archived !== null);
  await root.projects.update('market', { archived: false });
  await patchProject(ctx, archived, { archived: true });
  assert.ok((await resolvePath(ctx.db, { project: 'market' }))!.project.archivedAt !== null, 'archived, as asked');
  assert.equal((await opsOf('environment', dev)).at(-1), 'project.archive');
  await inputsLogged();
  // And the other way: A finds it live, and asks to restore it; B archives it before A prepares.
  await root.projects.update('market', { archived: false });
  const live = await resolvePath(ctx.db, { project: 'market' });
  await root.projects.update('market', { archived: true });
  await patchProject(ctx, live!, { archived: false });
  assert.equal((await resolvePath(ctx.db, { project: 'market' }))!.project.archivedAt, null, 'restored, as asked');
  await inputsLogged();
});

test("an environment made while its project is archived: the archive reads the project's environments again, and logs `project.archive` on each one (T126)", async (t) => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const dev = await environmentId('dev');
  const prepare = deps.vault.prepare!;
  let raced = false;
  t.mock.method(deps.vault as Required<Vault>, 'prepare', async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    // Between the archive's read of the project's environments and its transaction, one is made.
    if (!raced && input.changes.some((change) => change.kind === 'environment' && change.id === dev && change.after.projectArchived)) {
      raced = true;
      await root.environments.create('market/late');
    }
    return prepared;
  });
  await root.projects.update('market', { archived: true });
  assert.ok(raced);
  assert.deepEqual(await opsOf('environment', await environmentId('late')), ['environment.create', 'project.archive']);
  await inputsLogged();
});

test('a personal config made while its environment is archived: the archive reads its configs again, and archives each one it changes', async (t) => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const dev = await environmentId('dev');
  const prepare = deps.vault.prepare!;
  let raced = false;
  t.mock.method(deps.vault as Required<Vault>, 'prepare', async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    // Between the archive's read of dev's personal configs and its transaction, one is made.
    if (!raced && input.changes.some((change) => change.kind === 'environment' && change.id === dev && change.after.archived)) {
      raced = true;
      await root.secrets.set('market/dev@me', { MINE: 'mine' });
    }
    return prepared;
  });
  await root.environments.update('market/dev', { archived: true });
  assert.ok(raced);
  const [config] = await db.owner.select({ id: environments.id, archivedAt: environments.archivedAt }).from(environments).where(eq(environments.owner, `user:${ROOT}`));
  assert.ok(config?.archivedAt != null);
  assert.deepEqual(await opsOf('environment', config.id), ['environment.create', 'environment.archive']);
  await inputsLogged();
});

/**
 * Key A archived, then unarchived, by others between an archive's read of it and its transaction: `archive` is that
 * archive. A fresh vault object, whose first question (`about`, once per object) comes after the request's first read
 * of A, live, and before the read its changes are prepared from: there another write archives A, so the archive would
 * prepare nothing; an unarchive is then queued on the log's head ahead of the archive's transaction, which so finds A
 * live again. The transaction must read again, never archive A with no change.
 */
async function archivedAndBack(archive: () => Promise<unknown>): Promise<void> {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const a = await keyIn(await environmentId('dev'), 'A');
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let holding: Promise<unknown> = Promise.resolve();
  let unarchiving: Promise<unknown> | null = null;
  const vault = deps.vault;
  deps.vault = { ...vault, about: async () => {
    if (unarchiving === null) {
      unarchiving = Promise.resolve();
      try {
        await root.secrets.set('market/dev', { A: null });
        // The log's head held, so that the unarchive commits first, queued ahead of the archive's transaction.
        holding = db.owner.transaction(async (tx) => {
          await tx.execute(sql`SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE`);
          await held;
        });
        unarchiving = root.secrets.update('market/dev/A', { archived: false });
        await until(async () => (await headWaiters()) === 1, 'the unarchive waits for the head');
        void until(async () => (await headWaiters()) === 2, 'the archive waits for the head').finally(release);
      } catch (error) {
        release();
        throw error;
      }
    }
    return vault.about();
  } } as typeof vault;
  try {
    await archive();
    await unarchiving;
  } finally {
    release();
    await holding;
  }
  // Read again and archived after the unarchive: its row and its log agree, and a use finds no key, never a stale one.
  assert.deepEqual(await opsOf('secret', a), ['secret.write', 'secret.delete', 'secret.write', 'secret.delete']);
  const outcome = await use(token.id, a);
  assert.ok(!['ok', 'stale', 'tampered'].includes(codeOf(outcome)), JSON.stringify(outcome));
  await inputsLogged();
}

const ORDERED = postgresOnly('the order of two writes is held on the log head\'s row lock');

test('a key archived and unarchived by others while `secrets.update` archives it: the transaction finds it live, and reads again', ORDERED, () =>
  archivedAndBack(() => root.secrets.update('market/dev/A', { archived: true })));

test('a key archived and unarchived by others while `secrets.set` archives it: the transaction finds it live, and reads again', ORDERED, () =>
  archivedAndBack(() => root.secrets.set('market/dev', { A: null })));

async function until(condition: () => Promise<boolean>, what: string): Promise<void> {
  for (let tries = 0; !(await condition()); tries += 1) {
    assert.ok(tries < 500, what);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Sessions of the app waiting for a lock: here, on the log head's row, which every write takes first. */
async function headWaiters(): Promise<number> {
  const [row] = (await db.owner.execute(sql`SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`)) as unknown as { n: string }[];
  return Number(row?.n ?? 0);
}

/**
 * Key A of `at` archived, then a request to bring it back (`unarchive`) prepared from it; before its transaction, others
 * unarchive A, write a new value and archive it again (`meanwhile`): its seal is none again, as the request's change moves
 * it from. The transaction must read again, never seal the value it read over the one written.
 */
async function rearchivedMeanwhile(at: string, archive: () => Promise<unknown>, unarchive: () => Promise<unknown>, meanwhile: () => Promise<unknown>): Promise<void> {
  await root.access.set(CI, { [at]: 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const a = await keyIn(await environmentId(at.split('/')[1]!), 'A');
  await archive();
  const prepare = deps.vault.prepare!;
  let raced = false;
  deps.vault = { ...deps.vault, prepare: async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    if (!raced && input.changes.some((change) => change.id === a)) {
      raced = true;
      await meanwhile();
    }
    return prepared;
  } } as typeof deps.vault;
  await unarchive();
  assert.ok(raced);
  // Read again: A back, with the value written meanwhile, its row its newest change's, and a use reads it.
  const outcome = await use(token.id, a);
  assert.equal(codeOf(outcome), 'ok', JSON.stringify(outcome));
  assert.deepEqual((await opsOf('secret', a)).slice(-4), ['secret.write', 'secret.write', 'secret.delete', 'secret.write']);
  await inputsLogged();
}

test('a key unarchived, written and archived again by others while `secrets.update` unarchives it: the transaction reads again', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await rearchivedMeanwhile(
    'market/dev',
    () => root.secrets.update('market/dev/A', { archived: true }),
    () => root.secrets.update('market/dev/A', { archived: false }),
    async () => {
      await root.secrets.update('market/dev/A', { archived: false });
      await root.secrets.set('market/dev', { A: 'two' });
      await root.secrets.update('market/dev/A', { archived: true });
    },
  );
});

test('an override reset, overridden, written and reset again by others while `secrets.inherit` overrides it again: the transaction reads again', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'parent' });
  await root.environments.create('market/feature', { from: 'dev', inherit: true });
  await root.secrets.set('market/feature', { A: 'one' });
  await rearchivedMeanwhile(
    'market/feature',
    () => root.secrets.inherit('market/feature/A', true),
    () => root.secrets.inherit('market/feature/A', false),
    async () => {
      await root.secrets.inherit('market/feature/A', false);
      await root.secrets.set('market/feature', { A: 'two' });
      await root.secrets.inherit('market/feature/A', true);
    },
  );
});

test('a write refused by `prepare` (a key\'s row not the vault\'s) stores nothing, and abandons the references the vault made for it', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { SOURCE: 'from-prod' });
  await root.secrets.set('market/dev', { B: 'two' });
  const b = await keyIn(await environmentId('dev'), 'B');
  // A writer edits B's row and keeps its seal, which no longer covers it.
  await db.owner.update(secrets).set({ seal: randomBytes(16) }).where(eq(secrets.id, b));
  await assert.rejects(root.secrets.set('market/dev', { B: 'three', C: { ref: 'market/prod/SOURCE' } }), (error: { status?: number }) => error.status === 403);
  const made = await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(and(eq(auditLog.action, 'reference.create'), eq(auditLog.decision, 'allow')));
  assert.equal(made.length, 1, 'the vault made the reference before the write was refused');
  const ended = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(and(eq(auditLog.action, 'reference.end'), eq(auditLog.relatedSeq, made[0]!.seq)));
  assert.deepEqual(ended.map((row) => (JSON.parse(row.metadata) as { reason?: string }).reason), ['abandoned']);
  assert.deepEqual(await db.owner.select().from(secretReferences), [], 'nothing stored');
});

test('with 0.14\'s log, a deletion leaves its erased keys unarchived and a project\'s environments\' slugs as they were, and logs nothing of 0.15\'s', async () => {
  await instance(testVault([ROOT], {}, undefined, {}, { log: '0.14' }));
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  const id = await keyIn(await environmentId('dev'), 'A');
  await root.environments.update('market/dev', { archived: true });
  await root.environments.delete('market/dev');
  const [key] = await db.owner.select({ archivedAt: secrets.archivedAt }).from(secrets).where(eq(secrets.id, id));
  assert.equal(key?.archivedAt, null);
  assert.deepEqual(await db.owner.select().from(logChanges), []);
  // A project's deletion leaves its environments' slugs as they were: its entries are read by them under its tombstone.
  await root.environments.create('market/prod');
  const prod = await environmentId('prod');
  await root.projects.update('market', { archived: true });
  await root.projects.delete('market');
  const [row] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.id, prod));
  assert.equal(row!.slug, 'prod');
  const [project] = await db.owner.select({ slug: projects.slug }).from(projects);
  assert.match(project!.slug, /^market~deleted-/);
  assert.ok((await root.audit.list({ path: `${project!.slug}/prod` })).entries.length > 0);
});

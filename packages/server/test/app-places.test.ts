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
import { asc, eq, inArray, sql } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { environments, logChanges, logFence, projects, secrets } from './db/tables.ts';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly, TEST_ENGINE } from './db/engine.ts';
import { clientFor, credentialsLogged, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';

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
  return testVault([ROOT], { hotDatabase }, undefined, {}, { log: '0.15', sealThrough: sealedNow });
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

test('a project\'s deletion makes a tombstone of each environment\'s slug, and logs each one deleted, and each live key', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.secrets.set('market/prod', { A: 'two' });
  const [dev, prod] = [await environmentId('dev'), await environmentId('prod')];
  const keys = [await keyIn(dev, 'A'), await keyIn(prod, 'A')];
  await root.projects.update('market', { archived: true });
  await root.projects.delete('market');
  const rows = await db.owner.select({ id: environments.id, slug: environments.slug }).from(environments).where(inArray(environments.id, [dev, prod]));
  assert.deepEqual(rows.map((row) => row.slug.split('~')[1]?.startsWith('deleted-')), [true, true], 'each slug a tombstone');
  for (const id of [dev, prod]) assert.equal((await opsOf('environment', id)).at(-1), 'environment.delete');
  for (const id of keys) assert.equal((await opsOf('secret', id)).at(-1), 'secret.delete');
  await inputsLogged();
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

test('a key archived, then unarchived, by others between an archive\'s read of it and its transaction: the transaction finds it live, and reads again', postgresOnly('the order of two writes is held on the log head\'s row lock'), async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const a = await keyIn(await environmentId('dev'), 'A');
  // A fresh vault object, whose first question (`about`, once per object) comes between the router's read of the key,
  // live, and the archive's own read of it: archived there by another write, the archive prepares nothing.
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
    await root.secrets.update('market/dev/A', { archived: true });
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
});

async function until(condition: () => Promise<boolean>, what: string): Promise<void> {
  for (let tries = 0; !(await condition()); tries += 1) {
    assert.ok(tries < 500, what);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Sessions of the app waiting for a lock: here, on the log head's row, which every write takes first. */
async function headWaiters(): Promise<number> {
  const [row] = (await db.owner.execute(sql`SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`)).rows as { n: string }[];
  return Number(row?.n ?? 0);
}

test('with 0.14\'s log, a deletion leaves its erased keys unarchived and a project\'s environments\' slugs as they were, and logs nothing of 0.15\'s', async () => {
  await instance(testVault([ROOT], {}, undefined, {}, {}));
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

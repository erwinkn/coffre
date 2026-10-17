import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, eq, isNotNull } from 'drizzle-orm';

import { environments, secrets, secretVersions } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

/**
 * Personal configs (docs/design/forking.md, R8): `market/dev@me` is your own
 * fork of dev, whose values only you read, and only while you read dev; no
 * grant or role reaches them, an Owner's included, and the vault binds each
 * value to its owner, so a forged owner opens nothing. A read of `dev@me`
 * falls back to dev while you have none; a write makes one.
 */

const ROOT = 'admin@acme.example';
const MAINTAINER = 'maintainer@acme.example';
const ADA = 'ada@acme.example';
const BO = 'bo@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let maintainer: CoffreClient;
let ada: CoffreClient;
let bo: CoffreClient;

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
  maintainer = clientFor(deps, MAINTAINER);
  ada = clientFor(deps, ADA);
  bo = clientFor(deps, BO);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.environments.create('market/prod', { name: 'Prod' });
  for (const email of [MAINTAINER, ADA, BO]) await root.members.add(`user:${email}`);
  await root.access.set(`user:${MAINTAINER}`, { market: 'maintainer' });
  // Ada and Bo read dev only, as Viewers: a personal config takes nothing more.
  await root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
  await root.access.set(`user:${BO}`, { 'market/dev': 'viewer' });
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://dev', STRIPE_KEY: 'sk_test_1' });
});

const values = async (client: CoffreClient, path: string) => ({ ...(await client.secrets.reveal(path)).values });

/** Ada's personal config of dev, as the database has it. */
async function adasConfig() {
  const [row] = await db.owner.select().from(environments).where(eq(environments.owner, `user:${ADA}`));
  return row!;
}

test('a write to dev@me makes your personal config; you read its values over dev, live, and so does nobody else', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  assert.deepEqual(await values(ada, 'market/dev@me'), { DATABASE_URL: 'postgres://localhost/ada', STRIPE_KEY: 'sk_test_1' });
  await root.secrets.set('market/dev', { STRIPE_KEY: 'sk_test_2' });
  assert.equal((await values(ada, 'market/dev@me')).STRIPE_KEY, 'sk_test_2');

  // Bo has none: his dev@me is dev, for a read; one committed `coffre run market/dev@me` serves everyone.
  assert.deepEqual(await values(bo, 'market/dev@me'), { DATABASE_URL: 'postgres://dev', STRIPE_KEY: 'sk_test_2' });
  const listed = await bo.secrets.list('market/dev@me');
  assert.deepEqual([listed.personal, listed.parents], [{ of: 'dev', fallback: true }, []]);
  const hers = await ada.secrets.list('market/dev@me');
  assert.deepEqual([hers.personal, hers.parents, hers.keys.map((key) => [key.key, key.parent?.state ?? 'own'])], [
    { of: 'dev', fallback: false },
    ['dev'],
    [['DATABASE_URL', 'overridden'], ['STRIPE_KEY', 'inherited']],
  ]);
  // dev itself is untouched.
  assert.equal((await values(root, 'market/dev')).DATABASE_URL, 'postgres://dev');
});

test("nobody else reads or writes a personal config's values, an instance Owner and the project's maintainer included", async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  const { slug } = await adasConfig();
  for (const client of [root, maintainer]) {
    await assert.rejects(client.secrets.reveal(`market/${slug}`), { status: 403 });
    await assert.rejects(client.secrets.reveal(`market/${slug}/DATABASE_URL`), { status: 403 });
    await assert.rejects(client.secrets.list(`market/${slug}`), { status: 403 });
    await assert.rejects(client.secrets.set(`market/${slug}`, { DATABASE_URL: 'x' }), { status: 403 });
  }
  // Their own dev@me is theirs: the Owner has none, and reads dev.
  assert.equal((await values(root, 'market/dev@me')).DATABASE_URL, 'postgres://dev');
  // A grant on it would decide nothing, so none is made.
  await assert.rejects(root.access.set(`user:${BO}`, { [`market/${slug}`]: 'viewer' }), { status: 400, message: /personal config/ });
});

test('the vault opens a personal value for its owner alone, while they read dev, whatever the app asks', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  const config = await adasConfig();
  const [version] = await db.owner
    .select({ id: secretVersions.id })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(eq(secrets.environmentId, config.id));
  const ask = (reader: string) => deps.vault.unwrap({ principal: `user:${reader}`, purpose: 'run', items: [{ secretVersionId: version!.id }] });
  assert.equal((await ask(ADA)).ok, true);
  for (const reader of [ROOT, MAINTAINER, BO]) {
    const refused = await ask(reader);
    assert.equal(refused.ok ? null : refused.refusal.code, 'personal');
  }
  // Ada loses dev: her personal dev goes with it, in the app and in the vault.
  await root.access.set(`user:${ADA}`, { 'market/dev': null });
  await assert.rejects(ada.secrets.reveal('market/dev@me'), { status: 403 });
  const lost = await ask(ADA);
  assert.equal(lost.ok ? null : lost.refusal.code, 'no_grant');
});

test('a forged owner opens nothing: the value is bound to its owner, not to the column', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  const config = await adasConfig();
  // Written around the app: the config made Bo's. Bo reads dev, so the vault's decision passes, and the unwrap fails.
  await db.owner.update(environments).set({ owner: `user:${BO}` }).where(eq(environments.id, config.id));
  await assert.rejects(bo.secrets.reveal('market/dev@me'), (error: { status: number }) => error.status >= 400);
  assert.equal((await values(bo, 'market/dev@me/STRIPE_KEY')).STRIPE_KEY, 'sk_test_1');
  await assert.rejects(bo.secrets.reveal('market/dev@me/DATABASE_URL'));
  // Cleared, as a release before personal configs would see it: a project grant reaches it, and still opens nothing.
  await db.owner.update(environments).set({ owner: null }).where(eq(environments.id, config.id));
  await assert.rejects(root.secrets.reveal(`market/${config.slug}/DATABASE_URL`));
});

test('maintainers see whose personal configs exist and their key names, and may delete one; its owner may too', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada', ADA_ONLY: 'x' });
  await bo.environments.create('market/dev@me');
  const { configs } = await maintainer.environments.personal('market');
  assert.deepEqual(configs.map(({ owner, of, keys, archived }) => [owner, of, keys, archived]), [
    [`user:${ADA}`, 'dev', ['ADA_ONLY', 'DATABASE_URL'], false],
    [`user:${BO}`, 'dev', [], false],
  ]);
  await assert.rejects(ada.environments.personal('market'), { status: 403 });

  const adas = configs[0]!.slug;
  await assert.rejects(bo.environments.delete(`market/${adas}`), { status: 403 });
  const preview = await maintainer.environments.previewDelete(`market/${adas}`);
  assert.deepEqual([preview.deletion.keys, preview.deletion.versions, preview.deletion.grants], [2, 2, []]);
  await maintainer.environments.delete(`market/${adas}`);
  const erased = await db.owner.select().from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(eq(secrets.environmentId, (await adasConfig()).id));
  assert.ok(erased.every((row) => row.secret_versions.ciphertext.length === 0));
  // Gone: her dev@me is dev again, and her next write makes a new one.
  assert.equal((await values(ada, 'market/dev@me')).DATABASE_URL, 'postgres://dev');
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada-2' });
  assert.equal((await values(ada, 'market/dev@me')).DATABASE_URL, 'postgres://localhost/ada-2');
  // Its owner deletes their own, by dev@me.
  await bo.environments.delete('market/dev@me');
  assert.deepEqual((await maintainer.environments.personal('market')).configs.map((config) => config.owner), [`user:${ADA}`]);
});

test("lists show you your own personal config, as dev@me, and nobody else's; missing keys compare none", async () => {
  await ada.secrets.set('market/dev@me', { ADA_ONLY: 'x' });
  const listed = (client: CoffreClient) => client.projects.list().then(({ projects }) =>
    projects.find((project) => project.slug === 'market')!.environments.map((environment) => [environment.slug, environment.personal, environment.parent]));
  assert.deepEqual(await listed(ada), [['dev', false, null], ['dev@me', true, 'dev'], ['prod', false, null]]);
  for (const client of [root, maintainer, bo]) assert.deepEqual(await listed(client), [['dev', false, null], ['prod', false, null]]);
  assert.deepEqual((await ada.me()).environments.map((environment) => environment.environment), ['dev', 'dev@me']);
  assert.deepEqual((await root.environments.missing('market/prod')).missing.map((key) => key.key), ['DATABASE_URL', 'STRIPE_KEY']);
  assert.deepEqual((await ada.environments.missing('market/dev@me')).missing, []);
});

test('writes never fall back: a key of dev@me you do not have is no key of dev', async () => {
  await assert.rejects(ada.secrets.update('market/dev@me/DATABASE_URL', { archived: true }), { status: 404, message: /no personal config of market\/dev/ });
  await assert.rejects(root.secrets.inherit('market/dev@me/DATABASE_URL', true), { status: 404 });
  await assert.rejects(ada.environments.dismiss('market/dev@me', { DATABASE_URL: true }), { status: 404 });
  // A dry run makes nothing.
  await assert.rejects(ada.secrets.dryRun('market/dev@me', { DATABASE_URL: 'x' }), { status: 404 });
  assert.deepEqual((await maintainer.environments.personal('market')).configs, []);
  // A service account keeps none: its dev@me is dev to read, and writing there is refused.
  await root.members.add('token:ci');
  await root.access.set('token:ci', { 'market/dev': 'developer' });
  const ci = clientFor(deps, 'ci', 'service');
  assert.equal((await values(ci, 'market/dev@me')).DATABASE_URL, 'postgres://dev');
  await assert.rejects(ci.secrets.set('market/dev@me', { DATABASE_URL: 'x' }), { status: 403 });
});

test('a personal config holds values only: no reference out of one, or into one, and nobody forks one', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  await assert.rejects(ada.secrets.set('market/dev@me', { STRIPE: { ref: 'market/dev/STRIPE_KEY' } }), { status: 409, message: /holds values only/ });
  const { slug } = await adasConfig();
  await assert.rejects(root.secrets.set('market/prod', { ADA: { ref: `market/${slug}/DATABASE_URL` } }), { status: 409, message: /personal config/ });
  await assert.rejects(root.environments.create('market/copy', { from: slug }), { status: 409, message: /personal config/ });
});

test('a personal config is archived, restored and deleted with dev, and stops nobody doing so', async () => {
  await ada.secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/ada' });
  await root.environments.update('market/dev', { archived: true });
  assert.notEqual((await adasConfig()).archivedAt, null);
  await root.environments.update('market/dev', { archived: false });
  assert.equal((await adasConfig()).archivedAt, null);
  assert.equal((await values(ada, 'market/dev@me')).DATABASE_URL, 'postgres://localhost/ada');

  await root.environments.update('market/dev', { archived: true });
  await root.environments.delete('market/dev');
  const gone = await adasConfig();
  assert.match(gone.slug, /~deleted-/);
  const held = await db.owner.select().from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(and(eq(secrets.environmentId, gone.id), isNotNull(secretVersions.ciphertext)));
  assert.ok(held.every((row) => row.secret_versions.ciphertext.length === 0));
});

test("a rename in dev renames a personal config's override too; a key of its own in the way moves aside, named to nobody", async () => {
  await ada.secrets.set('market/dev@me', { STRIPE_KEY: 'sk_ada', STRIPE_SECRET_KEY: 'ada-own' });
  await root.secrets.update('market/dev/STRIPE_KEY', { key: 'STRIPE_SECRET_KEY' });
  assert.deepEqual(await values(ada, 'market/dev@me'), { DATABASE_URL: 'postgres://dev', STRIPE_SECRET_KEY: 'sk_ada', STRIPE_SECRET_KEY_2: 'ada-own' });
});

test("a key moved aside takes a name nothing in the personal config reads, inherited ones included, within a key's length", async () => {
  await root.secrets.set('market/dev', { OLD: 'old', NEXT_2: 'inherited' });
  await ada.secrets.set('market/dev@me', { NEXT: 'ada-own' });
  await root.secrets.update('market/dev/OLD', { key: 'NEXT' });
  const read = await values(ada, 'market/dev@me');
  assert.deepEqual([read.NEXT, read.NEXT_2, read.NEXT_3], ['old', 'inherited', 'ada-own']);

  const long = `K${'A'.repeat(127)}`;
  await root.secrets.set('market/dev', { SHORT: 'short' });
  await ada.secrets.set('market/dev@me', { [long]: 'ada-long' });
  await root.secrets.update('market/dev/SHORT', { key: long });
  const after = await values(ada, 'market/dev@me');
  assert.deepEqual([after[long], after[`${long.slice(0, 126)}_2`]], ['short', 'ada-long']);
});

test("deleting dev counts what its personal configs erase with it", async () => {
  await ada.secrets.set('market/dev@me', { A: '1', B: '2' });
  await root.environments.update('market/dev', { archived: true });
  const preview = await root.environments.previewDelete('market/dev');
  assert.deepEqual([preview.deletion.keys, preview.deletion.versions, preview.deletion.environments], [4, 4, ['dev', `dev@${ADA}`]]);
  const done = await root.environments.delete('market/dev');
  assert.deepEqual([done.deletion.keys, done.deletion.versions], [4, 4]);
});

test('asking again for a personal config you have answers that it exists, with no more than read on dev', async () => {
  const first = await ada.environments.create('market/dev@me');
  const again = await ada.environments.create('market/dev@me');
  assert.deepEqual([first.created, again.created], [true, false]);
});

test("your own personal config's log is found by dev@me", async () => {
  await root.secrets.set('market/dev@me', { ROOT_ONLY: 'x' });
  const { entries } = await root.audit.list({ path: 'market/dev@me' });
  assert.ok(entries.some((entry) => entry.action === 'secret.write'));
});

test('a key moved aside onto a name the personal config removed is no longer removed there', async () => {
  await root.secrets.set('market/dev', { OLD: 'old' });
  await ada.secrets.set('market/dev@me', { NEXT: 'ada-own' });
  await ada.environments.dismiss('market/dev@me', { NEXT_2: true });
  await root.secrets.update('market/dev/OLD', { key: 'NEXT' });
  assert.equal((await values(ada, 'market/dev@me')).NEXT_2, 'ada-own');
  // Reset later, dev's NEXT_2 shows through rather than stay removed.
  await root.secrets.set('market/dev', { NEXT_2: 'dev-next-2' });
  await ada.secrets.inherit('market/dev@me/NEXT_2', true);
  assert.equal((await values(ada, 'market/dev@me')).NEXT_2, 'dev-next-2');
});

test('an archived key moved aside leaves the removal of its new name as it was: it serves nothing', async () => {
  await root.secrets.set('market/dev', { OLD: 'old' });
  await ada.secrets.set('market/dev@me', { NEXT: 'ada-own' });
  await ada.secrets.update('market/dev@me/NEXT', { archived: true });
  await ada.environments.dismiss('market/dev@me', { NEXT_2: true });
  await root.secrets.update('market/dev/OLD', { key: 'NEXT' });
  // Her archived NEXT is NEXT_2 now; dev's own NEXT_2, added since, stays removed for her.
  await root.secrets.set('market/dev', { NEXT_2: 'dev-next-2' });
  const read = await values(ada, 'market/dev@me');
  assert.deepEqual([read.NEXT, read.NEXT_2], ['old', undefined]);
});

// A place deleted for good (src/ops/places.ts, `placeDelete`), through the
// contract as the app calls it, held to what 0.14.7 did (its conformance
// check, `checks/deletion.ts`, and its server's deletion tests): who may,
// what a preview says, what is erased, revoked and ended, what stays, the
// slug freed, the personal configs that go with an environment, a fork
// that keeps its parent, a change that moves the rows it read, and the
// bound on how many versions one deletion erases.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import type { PlaceDelete, PlaceDeleted, Presented, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { environments, projects, secrets } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { commit, prepare, type Prepared } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { MOST_ERASED } from '../src/ops/places.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, credential, environment, grant, instance, principal, project, rewrite, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee, fay, gil] = [user('ada'), user('bo'), user('cy'), user('dee'), user('fay'), user('gil')];
const ci = 'token:gone-ci';
let gone: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let dev: ReturnType<typeof environment>;
let adas: ReturnType<typeof environment>;
let cys: ReturnType<typeof environment>;
let pay: ReturnType<typeof secret>;
let link: ReturnType<typeof secret>;
let elsewhere: ReturnType<typeof environment>;
const archivedAt = new Date(Date.UTC(2026, 10, 1));

async function setUp() {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  gone = project('gone');
  prod = environment(gone, 'prod');
  dev = environment(gone, 'dev');
  adas = environment(gone, 'prod-p-ada', { parentId: prod.id, owner: ada });
  cys = environment(gone, 'prod-p-cy', { parentId: prod.id, owner: cy });
  billing = project('billing');
  elsewhere = environment(billing, 'prod');
  // Five versions in gone's environments, as 0.14.7's check wrote them, one of them plain, and one in Ada's personal config.
  const apiKey = value(world, secret(prod, 'API_KEY'), 'prod-key-1');
  const stripe = value(world, secret(elsewhere, 'STRIPE'), 'stripe-key');
  // A reference out of it, to billing's key, and one into it from billing, which held a value of its own before.
  pay = secret(prod, 'PAY', { sourceId: stripe.id });
  link = secret(elsewhere, 'LINK');
  await write(world, ...rows('projects', gone, billing), ...rows('environments', prod, dev, adas, cys, elsewhere),
    ...rows('secrets', apiKey, value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod'), value(world, secret(dev, 'API_KEY'), 'dev-key'),
      value(world, secret(dev, 'FLAG'), 'on', { plain: true }), value(world, secret(adas, 'LOCAL'), 'ada-local'), stripe, pay, value(world, link, 'link-before')),
    ...rows('roles', role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']), role(false, 'viewer', ['secret.read']),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']), role(true, 'admin', ['environment.manage', 'project.manage'], []), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee, { role: 'owner' }), principal(gil, { role: 'admin' }),
      principal(fay, { role: 'admin', scope: JSON.stringify({ projects: { only: [gone.id] }, environments: 'all' }) }), principal(ci)),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: gone }), grant(ada, 'maintainer', { project: billing }), grant(bo, 'viewer', { project: gone }),
      grant(cy, 'viewer', { project: gone }), grant(ci, 'viewer', { environment: prod })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee), credential('fay-cli', fay), credential('gil-cli', gil),
      credential('dee-pat', dee, { kind: 'personal', scope: JSON.stringify([{ projectId: gone.id, environmentId: null, role: 'maintainer' }]) })));
  // A second version of prod's API_KEY: five versions in all in gone's two environments, and Ada's own.
  await rewrite(world, apiKey, 'prod-key-2');
  // LINK becomes a reference to gone/prod/API_KEY: its value before stays history, and it holds none of its own now.
  await amend(world, 'secrets', eq(secrets.id, link.id), { sourceId: apiKey.id, sourceSetAt: new Date(world.now()), sourceSetBy: ada, currentVersion: null, nature: null });
  world.woken.length = 0;
}
beforeEach(setUp);

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const projectDelete = (label: string, slug = 'gone'): Presented & PlaceDelete => ({ ...shown(label), op: 'project.delete', project: slug });
const environmentDelete = (label: string, slug: string, more: { mine?: boolean; project?: string } = {}): Presented & PlaceDelete =>
  ({ ...shown(label), op: 'environment.delete', project: more.project ?? 'gone', environment: slug, mine: more.mine ?? false });
const day = () => new Date(world.now()).toISOString().slice(0, 10);

/** Each version under a project, and how many still hold a ciphertext, a wrapped key or a plain copy. */
async function sealed(projectId: string) {
  const [row] = await rowsOf<{ versions: number; sealed: number }>(world.owner, sql`SELECT count(*)::int AS versions,
    (count(*) FILTER (WHERE octet_length(v.ciphertext) > 0 OR octet_length(v.wrapped_dek) > 0 OR v.plaintext IS NOT NULL))::int AS sealed
    FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.project_id = ${projectId}`);
  return row!;
}
/** The same, of one environment. */
async function sealedIn(environmentId: string) {
  const [row] = await rowsOf<{ sealed: number }>(world.owner, sql`SELECT (count(*) FILTER (WHERE octet_length(v.ciphertext) > 0 OR octet_length(v.wrapped_dek) > 0 OR v.plaintext IS NOT NULL))::int AS sealed
    FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.environment_id = ${environmentId}`);
  return row!.sealed;
}
const slugOf = async (table: typeof projects | typeof environments, id: string) => (await rowsOf<{ slug: string }>(world.owner, sql`SELECT slug FROM ${table} WHERE id = ${id}`))[0]?.slug;
const grantsOf = async (principal: string) => (await rowsOf<{ role: string; project_id: string | null; environment_id: string | null }>(world.owner, sql`SELECT role, project_id, environment_id FROM grants WHERE principal = ${principal} ORDER BY role, project_id`));
const sourceOf = async (id: string) => (await rowsOf<{ source_id: string | null; current_version: number | null }>(world.owner, sql`SELECT source_id, current_version FROM secrets WHERE id = ${id}`))[0]!;
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
const denied = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`))
  .map((row) => entryOf(world.keys, row)!)
  .filter((entry) => typeof entry.detail === 'object' && entry.detail !== null && 'refused' in entry.detail)
  .map((entry) => [entry.action, entry.actor, (entry.detail as { refused: string }).refused]);
const reveal = (label: string, place: string, keys: string[], more: Partial<UseInput> = {}): UseInput => {
  const [projectSlug, environmentSlug] = place.split('/') as [string, string];
  return { ...shown(label), project: projectSlug, environment: environmentSlug, mine: false, keys, purpose: 'reveal', upstream: null, ...more };
};
const archive = async (table: 'projects' | 'environments', id: string) => amend(world, table, eq(table === 'projects' ? projects.id : environments.id, id), { archivedAt });
/** Ada's own write to her config of gone's prod, as she makes it: `secret.write`, `mine`. */
const adaWrites = (keys: { key: string; value: string }[]): Presented & SecretWrite =>
  ({ ...shown('ada-cli'), op: 'secret.write', project: 'gone', environment: 'prod', mine: true, keys: keys.map((one) => ({ ...one, nature: 'secret' as const })) });
const answer = <T>(result: { answer: T } | { refused: string }): T => {
  if ('refused' in result) throw new Error(`refused ${result.refused}`);
  return result.answer;
};

test('only an Admin or Owner of the whole instance deletes, and only what is archived; each refusal is logged and writes nothing', async () => {
  const before = await sealed(gone.id);
  assert.deepEqual(before, { versions: 6, sealed: 6 });
  // Live, it is refused as not archived, to whoever may delete it.
  assert.deepEqual(await vault.change(projectDelete('dee-cli')), { refused: 'not_archived' });
  await archive('projects', gone.id);
  const entries = await kept();
  // A maintainer of the project, an Admin whose scope is that project alone, an Owner's scoped personal token: none runs the instance.
  for (const label of ['ada-cli', 'fay-cli', 'dee-pat']) assert.deepEqual(await vault.change(projectDelete(label)), { refused: 'no_access' }, label);
  // A tombstone is no project, and a project that is not there is none either.
  assert.deepEqual(await vault.change(projectDelete('dee-cli', 'nowhere')), { refused: 'no_access' });
  assert.deepEqual(await sealed(gone.id), before);
  assert.equal(await slugOf(projects, gone.id), 'gone');
  assert.equal((await grantsOf(ci)).length, 1);
  assert.equal(await kept(), entries, 'a refusal keeps no entry');
  assert.deepEqual(await denied(), [
    ['project.delete', dee, 'not_archived'],
    ['project.delete', ada, 'no_access'],
    ['project.delete', fay, 'no_access'],
    // Dee's refusals of the same deletion, logged once a minute (`REFUSED_MS`): the first said it.
  ]);
});

test('a preview says what deleting would take, as the deletion then does, and changes nothing', async () => {
  await archive('projects', gone.id);
  const entries = await kept();
  const weighed = answer(await vault.weigh(projectDelete('gil-cli')));
  const expected: PlaceDeleted = {
    path: 'gone',
    tombstone: `gone~deleted-${day()}`,
    // Ada's and Cy's configs of prod go with it, by the names a deletion of one says.
    environments: ['dev', 'prod', 'prod@ada@acme.example', 'prod@cy@acme.example'],
    // API_KEY, DATABASE_URL and PAY in prod, API_KEY and FLAG in dev, LOCAL in Ada's config; five versions in prod and dev, and Ada's.
    keys: 6,
    versions: 6,
    grants: [
      { member: ci, place: 'gone/prod', role: 'viewer' },
      { member: ada, place: 'gone', role: 'maintainer' },
      { member: bo, place: 'gone', role: 'viewer' },
      { member: cy, place: 'gone', role: 'viewer' },
    ],
    references: [
      { holder: 'billing/prod/LINK', source: 'gone/prod/API_KEY' },
      { holder: 'gone/prod/PAY', source: 'billing/prod/STRIPE' },
    ],
    // The service holds nothing anywhere then, nor do Bo and Cy; Ada keeps billing.
    stranded: [ci, bo, cy].sort(),
  };
  assert.deepEqual(weighed, expected);
  assert.deepEqual(await sealed(gone.id), { versions: 6, sealed: 6 }, 'the preview erased nothing');
  assert.equal(await slugOf(projects, gone.id), 'gone');
  assert.equal(await kept(), entries, 'a preview keeps no entry');
  assert.deepEqual(answer(await vault.change(projectDelete('gil-cli'))), expected);
});

test('who is left holding nothing counts a lapsed grant elsewhere as nothing, and an instance role as something', async () => {
  await archive('projects', gone.id);
  // Bo's grant on billing lapsed; Cy's holds; Gil is an Admin of the whole instance, whose grant on gone is not all Gil holds.
  await write(world, ...rows('grants', grant(bo, 'viewer', { project: billing }, { expiresAt: new Date(Date.UTC(2020, 0, 1)) }), grant(cy, 'viewer', { project: billing }),
    grant(gil, 'viewer', { project: gone })));
  assert.deepEqual(answer(await vault.weigh(projectDelete('gil-cli'))).stranded, [ci, bo].sort());
});

test("deleting a project erases its values, revokes its grants, ends its references, and frees its slug; its rows stay under the tombstone's", async () => {
  await archive('projects', gone.id);
  const deleted = answer(await vault.change(projectDelete('dee-cli')));
  const tombstone = `gone~deleted-${day()}`;
  assert.equal(deleted.tombstone, tombstone);

  // The values are erased, a plain one's copy too; the versions' rows stay, and the keys' names under the tombstone.
  assert.deepEqual(await sealed(gone.id), { versions: 6, sealed: 0 });
  const [plain] = await rowsOf<{ plaintext: string | null; iv: Buffer }>(world.owner, sql`SELECT v.plaintext, v.iv FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.key = 'FLAG'`);
  assert.equal(plain!.plaintext, null);
  assert.equal(plain!.iv.length, 12, "a version's row keeps what the log can name it by");
  assert.equal(await slugOf(projects, gone.id), tombstone);
  assert.equal(await slugOf(environments, prod.id), 'prod', "a project's environments keep their slugs under its tombstone");
  // Its grants are revoked; a grant elsewhere stays.
  assert.deepEqual(await grantsOf(ci), []);
  assert.deepEqual((await grantsOf(ada)).map((row) => row.project_id), [billing.id]);
  // The references into it and out of it end: LINK reads nothing, not the value it held before it was a reference.
  assert.deepEqual(await sourceOf(link.id), { source_id: null, current_version: null });
  assert.deepEqual(await sourceOf(pay.id), { source_id: null, current_version: null });
  const linked = await vault.use(reveal('ada-cli', 'billing/prod', ['LINK', 'STRIPE']));
  assert.ok(!('refused' in linked));
  assert.deepEqual(linked.values.map((item) => ('refused' in item ? [item.key, item.refused] : [item.key, item.value])), [['LINK', 'no_value'], ['STRIPE', 'stripe-key']]);
  // Nothing under the tombstone is read, by its old slug or its new one.
  for (const place of ['gone/prod', `${tombstone}/prod`]) {
    assert.deepEqual(await vault.use(reveal('dee-cli', place, ['API_KEY'])), { refused: 'no_access' }, place);
  }

  // The entry says what it took.
  const entry = await written();
  assert.equal(entry.action, 'project.delete');
  assert.equal(entry.actor, dee);
  assert.deepEqual(entry.detail, { path: 'gone', tombstone, keys: 6, versions: 6, grants: 4, references: 2 });
  for (const object of [`project:${gone.id}`, `principal:${ci}`, `secret:${link.id}`, `secret:${pay.id}`]) assert.ok(entry.objects.includes(object), object);

  // Its slug is another project's now, and a second deletion that day takes the next tombstone.
  const made = answer(await vault.change({ ...shown('dee-cli'), op: 'project.create', project: 'gone' }));
  assert.notEqual(made.id, gone.id);
  await amend(world, 'projects', eq(projects.id, made.id), { archivedAt });
  assert.equal(answer(await vault.change(projectDelete('dee-cli'))).tombstone, `${tombstone}-2`);
  // A tombstone is deleted no further, nor restored.
  assert.deepEqual(await vault.change(projectDelete('dee-cli', tombstone)), { refused: 'no_access' });
  assert.deepEqual(await vault.change({ ...shown('dee-cli'), op: 'project.restore', project: tombstone }), { refused: 'no_access' });
});

test('deleting an environment takes it alone, with its personal configs, once it is archived itself, and frees its slug', async () => {
  // In an archived project, an environment still live is not archived itself.
  await archive('projects', gone.id);
  assert.deepEqual(await vault.change(environmentDelete('dee-cli', 'prod')), { refused: 'not_archived' });
  await amend(world, 'projects', eq(projects.id, gone.id), { archivedAt: null });
  await archive('environments', prod.id);
  // A fork keeps its parent, archived or not: deleted, it would leave the fork naming a tombstone.
  const fork = environment(gone, 'staging', { parentId: prod.id, archivedAt });
  await write(world, ...rows('environments', fork));
  assert.deepEqual(await vault.change(environmentDelete('dee-cli', 'prod')), { refused: 'inherited' });
  await world.owner.execute(sql`DELETE FROM environments WHERE id = ${fork.id}`);

  const deleted = answer(await vault.change(environmentDelete('gil-cli', 'prod')));
  const tombstone = `prod~deleted-${day()}`;
  assert.deepEqual({ ...deleted, references: deleted.references.length }, {
    path: 'gone/prod',
    tombstone,
    environments: ['prod', `prod@ada@acme.example`, `prod@cy@acme.example`],
    keys: 4,
    versions: 4,
    grants: [{ member: ci, place: 'gone/prod', role: 'viewer' }],
    references: 2,
    stranded: [ci],
  });
  assert.equal(await slugOf(environments, prod.id), tombstone);
  // Its personal configs go with it, each under a tombstone of its own; dev keeps its values, and the project its grants.
  assert.equal(await slugOf(environments, adas.id), `prod-p-ada~deleted-${day()}`);
  assert.equal(await slugOf(environments, cys.id), `prod-p-cy~deleted-${day()}`);
  assert.equal(await sealedIn(prod.id), 0);
  assert.equal(await sealedIn(adas.id), 0);
  assert.equal(await sealedIn(dev.id), 2);
  assert.equal((await grantsOf(ada)).length, 2);
  assert.deepEqual((await written()).detail, { path: 'gone/prod', tombstone, keys: 4, versions: 4, grants: 1, references: 2, personal: ['prod-p-ada', 'prod-p-cy'] });
  // Its slug is free in the project.
  answer(await vault.change({ ...shown('dee-cli'), op: 'environment.create', project: 'gone', environment: 'prod', mine: false, parent: null, protected: false }));
  const listed = await vault.use(reveal('ada-cli', 'gone/dev', ['API_KEY']));
  assert.ok(!('refused' in listed) && 'value' in listed.values[0]! && listed.values[0].value === 'dev-key');
});

test("a fork that copied the environment deleted keeps its copies; one that held references to it reads nothing through them, and the rest it holds stay", async () => {
  const fork = (slug: string, references: boolean) =>
    vault.change({ ...shown('ada-cli'), op: 'environment.create', project: 'gone', environment: slug, mine: false, parent: null, protected: false, copy: { from: 'prod', references } }).then(answer);
  await fork('copied', false);
  await fork('referred', true);
  // Prod is archived as a manager archives it: billing's reference broken, and the fork that reads through references archived first.
  answer(await vault.change({ ...shown('ada-cli'), op: 'reference.break', project: 'billing', environment: 'prod', key: 'LINK' }));
  answer(await vault.change({ ...shown('ada-cli'), op: 'environment.archive', project: 'gone', environment: 'referred' }));
  answer(await vault.change({ ...shown('ada-cli'), op: 'environment.archive', project: 'gone', environment: 'prod' }));
  const deleted = answer(await vault.change(environmentDelete('dee-cli', 'prod')));
  assert.deepEqual(deleted.references.filter((one) => one.holder.startsWith('gone/referred/')), [
    { holder: 'gone/referred/API_KEY', source: 'gone/prod/API_KEY' },
    { holder: 'gone/referred/DATABASE_URL', source: 'gone/prod/DATABASE_URL' },
  ]);
  answer(await vault.change({ ...shown('ada-cli'), op: 'environment.restore', project: 'gone', environment: 'referred' }));
  const read = async (place: string) => {
    const used = await vault.use(reveal('ada-cli', place, ['API_KEY', 'DATABASE_URL', 'PAY']));
    assert.ok(!('refused' in used));
    return Object.fromEntries(used.values.map((item) => [item.key, 'refused' in item ? item.refused : item.value]));
  };
  // The copy is a value of its own, sealed again when it was made: the deletion erases nothing of it.
  assert.deepEqual(await read('gone/copied'), { API_KEY: 'prod-key-2', DATABASE_URL: 'postgres://prod', PAY: 'stripe-key' });
  // A reference into prod reads nothing now, not a version of prod's; one to billing, which PAY's source is, still reads.
  assert.deepEqual(await read('gone/referred'), { API_KEY: 'no_value', DATABASE_URL: 'no_value', PAY: 'stripe-key' });
});

test('a personal config is deleted by its owner, or by whoever manages the environments, archived or not', async () => {
  // Bo views the project, and Cy's config is Cy's: neither may delete Ada's.
  assert.deepEqual(await vault.change(environmentDelete('bo-cli', 'prod-p-ada')), { refused: 'no_access' });
  assert.deepEqual(await vault.change(environmentDelete('cy-cli', 'prod-p-ada')), { refused: 'no_access' });
  // Cy deletes their own, as `dev@me` names it: prod, live.
  const own = answer(await vault.change(environmentDelete('cy-cli', 'prod', { mine: true })));
  assert.deepEqual(own, { path: 'gone/prod@cy@acme.example', tombstone: `prod-p-cy~deleted-${day()}`, environments: ['prod-p-cy'], keys: 0, versions: 0, grants: [], references: [], stranded: [] });
  // And has none now.
  assert.deepEqual(await vault.change(environmentDelete('cy-cli', 'prod', { mine: true })), { refused: 'no_access' });
  // Ada manages the project's environments, and deletes hers by its slug, which the list for deletion shows.
  const hers = answer(await vault.change(environmentDelete('ada-cli', 'prod-p-ada')));
  assert.equal(hers.versions, 1);
  assert.equal(await sealedIn(adas.id), 0);
  assert.equal(await sealedIn(prod.id), 3, 'the environment it is a config of keeps its values');
  assert.deepEqual((await written()).detail, { path: 'gone/prod@ada@acme.example', tombstone: `prod-p-ada~deleted-${day()}`, keys: 1, versions: 1, grants: 0, references: 0, personal: true });
});

const ready = async (input: Presented & PlaceDelete) => {
  const prepared = await prepare(world, OPERATIONS[input.op](input as never, { workloads: world.workloads, owners: world.owners }));
  assert.ok(!('refused' in prepared));
  return prepared as Prepared<PlaceDeleted>;
};

test('a deletion whose rows moved since it read them starts over: a grant set meanwhile is revoked with the rest, and a place restored meanwhile is not erased', async () => {
  await archive('projects', gone.id);
  // A grant on it, set after the deletion read: the write finds the rows moved, and writes nothing.
  const first = await ready(projectDelete('dee-cli'));
  await write(world, ...rows('grants', grant(fay, 'viewer', { project: gone })));
  assert.equal(await commit(world, first), false);
  assert.deepEqual(await sealed(gone.id), { versions: 6, sealed: 6 });
  // Asked again, it revokes that one too.
  const again = answer(await vault.change(projectDelete('dee-cli')));
  assert.ok(again.grants.some((one) => one.member === fay));
  assert.deepEqual(await grantsOf(fay), []);

  // Restored after the read: nothing is erased, and asked again it is refused.
  await setUp();
  await archive('projects', gone.id);
  const second = await ready(projectDelete('dee-cli'));
  await amend(world, 'projects', eq(projects.id, gone.id), { archivedAt: null });
  assert.equal(await commit(world, second), false);
  assert.deepEqual(await vault.change(projectDelete('dee-cli')), { refused: 'not_archived' });
  assert.deepEqual(await sealed(gone.id), { versions: 6, sealed: 6 });
  assert.equal(await slugOf(projects, gone.id), 'gone');
});

test('a personal config, live as it is deleted, whose owner writes meanwhile: the deletion starts over, and says and erases what is there then', async () => {
  // Ada's config holds LOCAL, one version. Read for deletion, then she writes LOCAL again and a NEW: no row the deletion read moved, only how many there are.
  const first = await ready(environmentDelete('ada-cli', 'prod', { mine: true }));
  assert.deepEqual([first.answer.keys, first.answer.versions], [1, 1]);
  answer(await vault.change(adaWrites([{ key: 'LOCAL', value: 'ada-local-2' }, { key: 'NEW', value: 'ada-new' }])));
  assert.equal(await sealedIn(adas.id), 3);
  assert.equal(await commit(world, first), false, 'the counts it read moved');
  assert.equal(await sealedIn(adas.id), 3, 'and nothing is erased');
  // Asked again, it says all three, and erases them.
  const again = answer(await vault.change(environmentDelete('ada-cli', 'prod', { mine: true })));
  assert.deepEqual([again.keys, again.versions], [2, 3]);
  assert.equal(await sealedIn(adas.id), 0);
});

test(`one deletion erases ${MOST_ERASED} versions at most, and past that erases nothing`, async () => {
  await archive('environments', dev.id);
  // Dev's two versions, and as many more of API_KEY's as make the bound: one more and it is refused.
  const [key] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE environment_id = ${dev.id} AND key = 'API_KEY'`);
  const add = async (from: number, to: number, of = key!.id) => world.owner.execute(sql`INSERT INTO secret_versions
    (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_at, created_by, first_written_at, plaintext, sensitive)
    SELECT gen_random_uuid(), ${of}, n, 1, ${randomBytes(48)}, ${randomBytes(12)}, ${randomBytes(16)}, ${randomBytes(40)}, 'local', 'k', '1', now(), ${ada}, now(), NULL, false
    FROM generate_series(${from}::int, ${to}::int) n`);
  await add(100, 100 + MOST_ERASED - 3);
  assert.equal(await sealedIn(dev.id), MOST_ERASED);
  await add(100 + MOST_ERASED - 2, 100 + MOST_ERASED - 2);
  assert.deepEqual(await vault.weigh(environmentDelete('dee-cli', 'dev')), { refused: 'too_large' });
  assert.deepEqual(await vault.change(environmentDelete('dee-cli', 'dev')), { refused: 'too_large' });
  assert.equal(await sealedIn(dev.id), MOST_ERASED + 1, 'nothing is erased');
  assert.equal(await slugOf(environments, dev.id), 'dev');
  await world.owner.execute(sql`DELETE FROM secret_versions WHERE secret_id = ${key!.id} AND version = ${100 + MOST_ERASED - 2}`);
  // At the bound, in one change.
  const started = performance.now();
  const deleted = answer(await vault.change(environmentDelete('dee-cli', 'dev')));
  const took = performance.now() - started;
  assert.equal(deleted.versions, MOST_ERASED);
  assert.equal(await sealedIn(dev.id), 0);
  console.log(`# ${MOST_ERASED} versions erased in one deletion: ${Math.round(took)} ms`);

  // A live config at the bound, read for deletion, then written to by its owner: one past it, the deletion starts over and is refused.
  const [local] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE environment_id = ${adas.id} AND key = 'LOCAL'`);
  await add(100, 100 + MOST_ERASED - 2, local!.id);
  assert.equal(await sealedIn(adas.id), MOST_ERASED);
  const prepared = await ready(environmentDelete('ada-cli', 'prod', { mine: true }));
  assert.equal(prepared.answer.versions, MOST_ERASED);
  answer(await vault.change(adaWrites([{ key: 'NEW', value: 'ada-new' }])));
  assert.equal(await commit(world, prepared), false);
  assert.deepEqual(await vault.change(environmentDelete('ada-cli', 'prod', { mine: true })), { refused: 'too_large' });
  assert.equal(await sealedIn(adas.id), MOST_ERASED + 1, 'nothing is erased');
});

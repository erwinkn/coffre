// Projects and environments edited (src/ops/places.ts), through the contract
// as the app calls it: re-slugged, archived and restored, filed in a folder,
// protected and unprotected, an upstream credential frozen and thawed. Who
// may, what is written and logged, each refusal writing nothing but its
// entry, edits decided on the same rows as another change, and a use after.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Change, Presented, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { change, commit, prepare, type Operation, type Parts, type Seen } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee, eve, fay, gil] = [user('ada'), user('bo'), user('cy'), user('dee'), user('eve'), user('fay'), user('gil')];
const api = 'token:api';
const ARCHIVED = new Date(Date.UTC(2026, 10, 1));
let market: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let staging: ReturnType<typeof environment>;
let adas: ReturnType<typeof environment>;
let old: ReturnType<typeof environment>;
let there: ReturnType<typeof environment>;
let reference: ReturnType<typeof secret>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  billing = project('billing');
  const shelved = project('shelved', { archivedAt: ARCHIVED });
  prod = environment(market, 'prod');
  staging = environment(market, 'staging', { parentId: prod.id });
  old = environment(market, 'old', { archivedAt: ARCHIVED });
  adas = environment(market, 'prod-p-0a0b0c0d', { parentId: prod.id, owner: ada });
  there = environment(billing, 'prod');
  const url = value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod');
  // billing/prod/DATABASE_URL reads market/prod's.
  reference = secret(there, 'DATABASE_URL', { sourceId: url.id });
  await write(world, ...rows('projects', market, billing, shelved), ...rows('environments', prod, staging, old, adas, there), ...rows('secrets', url, reference),
    // A maintainer manages environments and reads them, but where one is protected, writes there only.
    ...rows('roles', role(false, 'owner', ['secret.read', 'secret.write', 'secret.use', 'environment.manage', 'project.manage']), role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage'], ['secret.write']), role(false, 'viewer', ['secret.read']),
      role(true, 'owner', ['secret.read', 'secret.write', 'secret.use', 'environment.manage', 'project.manage']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee, { role: 'owner' }), principal(eve),
      // Fay owns every project's prod, and so no project; Gil owns all of market.
      principal(fay, { role: 'owner', scope: JSON.stringify({ projects: 'all', environments: { only: ['prod'] } }) }),
      principal(gil, { role: 'owner', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(api)),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: market }), grant(ada, 'maintainer', { project: billing }), grant(bo, 'viewer', { project: market }), grant(cy, 'owner', { project: market }),
      grant(eve, 'owner', { environment: prod }), grant(api, 'owner', { project: market })),
    ...rows('credentials', ...['ada', 'bo', 'cy', 'dee', 'eve', 'fay', 'gil'].map((name) => credential(`${name}-cli`, user(name))),
      credential('dee-pat', dee, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) }),
      credential('api-token', api, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
type Edit = Extract<Change, { op: `project.${'update' | 'archive' | 'restore' | 'move'}` | `environment.${'update' | 'archive' | 'restore' | 'protect' | 'unprotect'}` | `upstream.${string}` }>;
type Without<T> = T extends unknown ? Omit<T, 'op' | 'project' | 'environment'> : never;
/** An edit of `place`, `market` or `market/prod`, by whoever holds the credential `label`. */
const edit = <K extends Edit['op']>(label: string, op: K, place: string, more: Without<Extract<Edit, { op: K }>> | Record<string, never> = {}) => {
  const [projectSlug, environmentSlug] = place.split('/');
  return vault.change({ ...shown(label), op, project: projectSlug!, ...(environmentSlug === undefined ? {} : { environment: environmentSlug }), ...more } as never) as Promise<{ answer: { id: string } } | { refused: string }>;
};
const answered = async (result: Promise<{ answer: { id: string } } | { refused: string }>) => {
  const settled = await result;
  assert.ok('answer' in settled, JSON.stringify(settled));
  return settled.answer;
};
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
/** Every place's row as it stands, but for when it was made: a refusal changes none. */
const places = async () => [
  ...(await rowsOf(world.owner, sql`SELECT id, slug, archived_at, folder, encode(mac, 'hex') AS mac FROM projects ORDER BY id`)),
  ...(await rowsOf(world.owner, sql`SELECT id, slug, archived_at, protected, frozen_credentials, encode(mac, 'hex') AS mac FROM environments ORDER BY id`)),
];
const state = async () => [await kept(), await places()];
/** The refusals logged, oldest first: who was refused what, where as they named it, and the rows it was about beyond who asked. */
const denied = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`))
  .map((row) => entryOf(world.keys, row)!)
  .filter((entry) => typeof entry.detail === 'object' && entry.detail !== null && 'refused' in entry.detail)
  .map((entry) => [entry.action, entry.actor, entry.detail, entry.objects.filter((object) => !object.startsWith('principal:') && !object.startsWith('credential:'))]);
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
/** What the last entry's rows say, by table: read, made or replaced. */
const named = async () => (await written()).rows.map(({ row, was, now }) => `${(JSON.parse(row) as string[])[0]} ${was === null ? 'made' : was === now ? 'read' : 'replaced'}`).sort();
const projectRow = async (id: string) => (await rowsOf<{ slug: string; archived: boolean; folder: string | null }>(world.owner, sql`SELECT slug, archived_at IS NOT NULL AS archived, folder FROM projects WHERE id = ${id}`))[0];
const environmentRow = async (id: string) =>
  (await rowsOf<{ slug: string; archived: boolean; protected: boolean; frozen: string[] }>(world.owner, sql`SELECT slug, archived_at IS NOT NULL AS archived, protected, frozen_credentials AS frozen FROM environments WHERE id = ${id}`))[0];
const reveal = (label: string, place: string, more: Partial<UseInput> = {}): UseInput => {
  const [projectSlug, environmentSlug] = place.split('/') as [string, string];
  return { ...shown(label), project: projectSlug, environment: environmentSlug, mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null, ...more };
};
const given = async (input: UseInput) => {
  const answer = await vault.use(input);
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};

test('a project re-slugged by whoever manages it, to a slug free as a new one must be; used by its new slug only', async () => {
  const { id } = await answered(edit('cy-cli', 'project.update', 'market', { slug: 'shop' }));
  assert.deepEqual(await projectRow(id), { slug: 'shop', archived: false, folder: null });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['project.update', cy, { from: 'market', slug: 'shop' }]);
  assert.ok(entry.objects.includes(`project:${market.id}`), entry.objects.join());
  // Cy's grant and role, the project replaced, and what the slug's read found: nothing else holds it.
  assert.deepEqual(await named(), ['credentials read', 'grants read', 'principals read', 'projects replaced', 'roles read', 'roles read']);
  assert.deepEqual(await given(reveal('ada-cli', 'shop/prod')), ['postgres://prod']);
  assert.equal(await given(reveal('ada-cli', 'market/prod')), 'no_access');

  const before = await state();
  assert.deepEqual(await edit('ada-cli', 'project.update', 'shop', { slug: 'shop-2' }), { refused: 'no_access' }, 'a maintainer manages environments, not the project');
  assert.deepEqual(await edit('bo-cli', 'project.update', 'shop', { slug: 'shop-2' }), { refused: 'no_access' });
  assert.deepEqual(await edit('eve-cli', 'project.update', 'shop', { slug: 'shop-2' }), { refused: 'no_access' }, 'an Owner of one environment');
  assert.deepEqual(await edit('cy-cli', 'project.update', 'shop', { slug: 'billing' }), { refused: 'exists' });
  assert.deepEqual(await edit('dee-cli', 'project.update', 'shop', { slug: 'shelved' }), { refused: 'exists' }, "an archived project's slug");
  assert.deepEqual(await edit('dee-cli', 'project.update', 'nowhere', { slug: 'shop-2' }), { refused: 'no_access' });
  assert.deepEqual(await edit('nobody', 'project.update', 'shop', { slug: 'shop-2' }), { refused: 'unauthenticated' });
  assert.deepEqual(await state(), [before[0], before[1]]);
  // Logged once a minute for each who stands, as they named it, found from the project as far as it is there.
  const to = { slug: 'shop-2', refused: 'no_access' };
  assert.deepEqual(await denied(), [
    ['project.update', ada, { project: 'shop', ...to }, [`project:${market.id}`]],
    ['project.update', bo, { project: 'shop', ...to }, [`project:${market.id}`]],
    ['project.update', eve, { project: 'shop', ...to }, [`project:${market.id}`]],
    ['project.update', cy, { project: 'shop', slug: 'billing', refused: 'exists' }, [`project:${market.id}`]],
    ['project.update', dee, { project: 'shop', slug: 'shelved', refused: 'exists' }, [`project:${market.id}`]],
  ]);

  // To its own slug: nothing changes, and the entry says it was asked.
  const unchanged = await places();
  await answered(edit('cy-cli', 'project.update', 'shop', { slug: 'shop' }));
  assert.deepEqual(await places(), unchanged);
  assert.equal((await written()).action, 'project.update');
  // An archived project is re-slugged too, by an Owner of the instance.
  await answered(edit('dee-cli', 'project.update', 'shelved', { slug: 'shelved-2' }));
});

test('a project archived, unless a reference held outside it reads a value in it; and restored', async () => {
  const before = await state();
  assert.deepEqual(await edit('cy-cli', 'project.archive', 'market'), { refused: 'referenced' });
  assert.deepEqual(await edit('ada-cli', 'project.archive', 'market'), { refused: 'no_access' });
  assert.deepEqual(await state(), [before[0], before[1]]);
  assert.deepEqual(await denied(), [['project.archive', cy, { project: 'market', refused: 'referenced' }, [`project:${market.id}`]], ['project.archive', ada, { project: 'market', refused: 'no_access' }, [`project:${market.id}`]]]);

  // Each way the reference stops reading lets it go: its key archived, its environment or project archived, or its source or the source's environment archived.
  for (const [table, where, more] of [
    ['secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED }],
    ['environments', sql`id = ${there.id}`, { archivedAt: ARCHIVED }],
    ['projects', sql`id = ${billing.id}`, { archivedAt: ARCHIVED }],
    ['secrets', sql`id = ${reference.sourceId}`, { archivedAt: ARCHIVED }],
    ['environments', sql`id = ${prod.id}`, { archivedAt: ARCHIVED }],
  ] as const) {
    await amend(world, table, where, more as never);
    const { id } = await answered(edit('cy-cli', 'project.archive', 'market'));
    assert.deepEqual(await projectRow(id), { slug: 'market', archived: true, folder: null }, table);
    assert.deepEqual((await written()).detail, { slug: 'market' });
    await answered(edit('cy-cli', 'project.restore', 'market'));
    await amend(world, table, where, { archivedAt: null } as never);
  }
  // A reference held in the project itself goes with it.
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  await write(world, ...rows('secrets', secret(staging, 'DATABASE_URL', { sourceId: reference.sourceId })));
  await answered(edit('gil-cli', 'project.archive', 'market'));
  assert.equal(await given(reveal('ada-cli', 'market/prod')), 'no_access');
  // Archived again, a minute on, or restored again: nothing changes.
  const archived = await places();
  world.tick(60_000);
  await answered(edit('cy-cli', 'project.archive', 'market'));
  assert.deepEqual(await places(), archived);
  await answered(edit('cy-cli', 'project.restore', 'market'));
  assert.equal((await projectRow(market.id))!.archived, false);
  assert.deepEqual(await given(reveal('ada-cli', 'market/prod')), ['postgres://prod']);
  assert.deepEqual(await edit('bo-cli', 'project.restore', 'market'), { refused: 'no_access' });
});

test('a reference whose rows the vault cannot read stops an archive: a row not read never says it reads nothing', async () => {
  // billing/prod's row edited around the vault: whether it is archived is not known. Nor billing's, after.
  await world.owner.execute(sql`UPDATE environments SET archived_at = ${ARCHIVED} WHERE id = ${there.id}`);
  assert.deepEqual(await edit('cy-cli', 'project.archive', 'market'), { refused: 'referenced' });
  await amend(world, 'environments', sql`id = ${there.id}`, { archivedAt: null });
  await world.owner.execute(sql`UPDATE projects SET archived_at = ${ARCHIVED} WHERE id = ${billing.id}`);
  assert.deepEqual(await edit('cy-cli', 'project.archive', 'market'), { refused: 'referenced' });
  // Nor the source's.
  await amend(world, 'projects', sql`id = ${billing.id}`, { archivedAt: null });
  await world.owner.execute(sql`UPDATE secrets SET archived_at = ${ARCHIVED} WHERE id = ${reference.sourceId}`);
  assert.deepEqual(await edit('cy-cli', 'project.archive', 'market'), { refused: 'referenced' });
});

test('a reference that reads nothing now stops no archive: one held in a personal config, or whose source is itself a reference', async () => {
  await amend(world, 'environments', sql`id = ${staging.id}`, { archivedAt: ARCHIVED });
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  // Bo's config of billing's prod holds a reference to market's prod: a personal config reads no reference (use.ts).
  const bos = environment(billing, 'prod-p-0b0b0b0b', { parentId: there.id, owner: bo });
  await write(world, ...rows('environments', bos), ...rows('secrets', secret(bos, 'DATABASE_URL', { sourceId: reference.sourceId })));
  await answered(edit('ada-cli', 'environment.archive', 'market/prod'));
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  // Billing's prod reads prod's LINK, which reads billing's OTHER: a reference reads no reference.
  const other = secret(there, 'OTHER');
  const link = secret(prod, 'LINK', { sourceId: other.id });
  await write(world, ...rows('secrets', other, link, secret(there, 'CHAIN', { sourceId: link.id })));
  await answered(edit('ada-cli', 'environment.archive', 'market/prod'));
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  // Billing's prod reads prod's EMPTY, a key with no value yet: it reads nothing, as 0.14's `source_empty`.
  const empty = secret(prod, 'EMPTY');
  await write(world, ...rows('secrets', empty, secret(there, 'EMPTY', { sourceId: empty.id })));
  assert.deepEqual(await given(reveal('ada-cli', 'billing/prod', { keys: ['EMPTY'] })), ['unreadable']);
  await answered(edit('ada-cli', 'environment.archive', 'market/prod'));
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  await answered(edit('cy-cli', 'project.archive', 'market'));
});

test('an environment of an archived project is archived whatever references it: one into an archived project reads nothing', async () => {
  // Billing archived, then market, which nothing reads then; billing restored, its reference into market reads nothing.
  await amend(world, 'projects', sql`id = ${billing.id}`, { archivedAt: ARCHIVED });
  await answered(edit('cy-cli', 'project.archive', 'market'));
  await amend(world, 'projects', sql`id = ${billing.id}`, { archivedAt: null });
  assert.notDeepEqual(await given(reveal('ada-cli', 'billing/prod')), ['postgres://prod']);
  await answered(edit('ada-cli', 'environment.archive', 'market/staging'));
  await answered(edit('ada-cli', 'environment.archive', 'market/prod'));
  assert.equal((await environmentRow(prod.id))!.archived, true);
});

test('a project filed in a folder by whoever manages it, and taken out of it', async () => {
  await answered(edit('cy-cli', 'project.move', 'market', { folder: 'Payments' }));
  assert.deepEqual(await projectRow(market.id), { slug: 'market', archived: false, folder: 'Payments' });
  assert.deepEqual((await written()).detail, { slug: 'market', from: null, to: 'Payments' });
  await answered(edit('dee-cli', 'project.move', 'market', { folder: null }));
  assert.deepEqual((await written()).detail, { slug: 'market', from: 'Payments', to: null });
  assert.equal((await projectRow(market.id))!.folder, null);
  // 64 characters, each one code point of two UTF-16 units, as the table counts them.
  await answered(edit('cy-cli', 'project.move', 'market', { folder: '🍷'.repeat(64) }));
  assert.deepEqual(await edit('ada-cli', 'project.move', 'market', { folder: 'Mine' }), { refused: 'no_access' });
  assert.deepEqual(await denied(), [['project.move', ada, { project: 'market', refused: 'no_access' }, [`project:${market.id}`]]]);
  for (const folder of ['', ' a', 'a ', 'a/b', 'a\u0007', 'x'.repeat(65), '🍷'.repeat(65), 7, undefined]) {
    await assert.rejects(edit('cy-cli', 'project.move', 'market', { folder } as never), TypeError, JSON.stringify(folder));
  }
});

test('an environment re-slugged by whoever manages the project\'s environments, to a slug free there', async () => {
  const { id } = await answered(edit('ada-cli', 'environment.update', 'market/staging', { slug: 'preview' }));
  assert.equal(id, staging.id);
  assert.equal((await environmentRow(id))!.slug, 'preview');
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['environment.update', { from: 'staging', slug: 'preview' }]);
  assert.ok(entry.objects.includes(`environment:${staging.id}`) && entry.objects.includes(`project:${market.id}`), entry.objects.join());
  // A fork keeps its parent, by its id.
  assert.deepEqual(await given(reveal('ada-cli', 'market/preview')), ['postgres://prod']);

  const before = await state();
  assert.deepEqual(await edit('bo-cli', 'environment.update', 'market/prod', { slug: 'live' }), { refused: 'no_access' }, 'a viewer');
  assert.deepEqual(await edit('ada-cli', 'environment.update', 'market/prod', { slug: 'preview' }), { refused: 'exists' });
  assert.deepEqual(await edit('ada-cli', 'environment.update', 'market/prod', { slug: 'old' }), { refused: 'exists' }, "an archived environment's slug");
  assert.deepEqual(await edit('ada-cli', 'environment.update', 'market/prod', { slug: adas.slug }), { refused: 'exists' }, "a personal config's");
  assert.deepEqual(await edit('ada-cli', 'environment.update', `market/${adas.slug}`, { slug: 'mine' }), { refused: 'no_access' }, 'a personal config is no environment to edit');
  assert.deepEqual(await edit('ada-cli', 'environment.update', 'market/nowhere', { slug: 'live' }), { refused: 'no_access' });
  assert.deepEqual(await state(), [before[0], before[1]]);
  // Found from the project and the environment as far as they are there: a personal config is not.
  assert.deepEqual(await denied(), [
    ['environment.update', bo, { project: 'market', environment: 'prod', slug: 'live', refused: 'no_access' }, [`project:${market.id}`, `environment:${prod.id}`]],
    ['environment.update', ada, { project: 'market', environment: 'prod', slug: 'preview', refused: 'exists' }, [`project:${market.id}`, `environment:${prod.id}`]],
  ]);
  world.tick(60_000);
  assert.deepEqual(await edit('ada-cli', 'environment.update', `market/${adas.slug}`, { slug: 'mine' }), { refused: 'no_access' });
  assert.deepEqual((await denied()).slice(2), [['environment.update', ada, { project: 'market', environment: adas.slug, slug: 'mine', refused: 'no_access' }, [`project:${market.id}`]]]);
  for (const slug of ['settings', 'Dev', 'dev~1', 'x'.repeat(64), 7]) await assert.rejects(edit('ada-cli', 'environment.update', 'market/prod', { slug } as never), TypeError, String(slug));
});

test('an environment archived with its personal configs, unless a live fork inherits from it or a reference outside reads it; restored while its parents are live', async () => {
  const before = await state();
  assert.deepEqual(await edit('ada-cli', 'environment.archive', 'market/prod'), { refused: 'referenced' });
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  assert.deepEqual(await edit('ada-cli', 'environment.archive', 'market/prod'), { refused: 'inherited' });
  assert.deepEqual(await edit('bo-cli', 'environment.archive', 'market/prod'), { refused: 'no_access' });
  assert.deepEqual(await places(), before[1]);
  const at = [`project:${market.id}`, `environment:${prod.id}`];
  assert.deepEqual(await denied(), [['environment.archive', ada, { project: 'market', environment: 'prod', refused: 'referenced' }, at], ['environment.archive', bo, { project: 'market', environment: 'prod', refused: 'no_access' }, at]]);

  await answered(edit('ada-cli', 'environment.archive', 'market/staging'));
  assert.equal((await environmentRow(staging.id))!.archived, true);
  await answered(edit('ada-cli', 'environment.archive', 'market/prod'));
  assert.deepEqual([(await environmentRow(prod.id))!.archived, (await environmentRow(adas.id))!.archived], [true, true]);
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['environment.archive', { slug: 'prod', personal: [adas.slug] }]);
  assert.ok(entry.objects.includes(`environment:${adas.id}`), entry.objects.join());
  assert.equal(await given(reveal('ada-cli', 'market/prod')), 'no_access');

  // Staging inherits from prod, archived: it comes back after prod.
  assert.deepEqual(await edit('ada-cli', 'environment.restore', 'market/staging'), { refused: 'parent_archived' });
  world.tick(60_000);
  assert.deepEqual(await edit('bo-cli', 'environment.restore', 'market/prod'), { refused: 'no_access' });
  assert.deepEqual((await denied()).slice(2), [['environment.restore', ada, { project: 'market', environment: 'staging', refused: 'parent_archived' }, [`project:${market.id}`, `environment:${staging.id}`]], ['environment.restore', bo, { project: 'market', environment: 'prod', refused: 'no_access' }, at]]);
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  assert.deepEqual([(await environmentRow(prod.id))!.archived, (await environmentRow(adas.id))!.archived], [false, false]);
  assert.deepEqual((await written()).detail, { slug: 'prod', personal: [adas.slug] });
  await answered(edit('ada-cli', 'environment.restore', 'market/staging'));
  assert.deepEqual(await given(reveal('ada-cli', 'market/staging')), ['postgres://prod']);
  // Ada's config of prod is hers again.
  assert.deepEqual(await given(reveal('ada-cli', 'market/prod', { mine: true })), ['postgres://prod']);
  // Restored again, or archived again a minute on: nothing changes.
  const restored = await places();
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  assert.deepEqual(await places(), restored);
  await answered(edit('ada-cli', 'environment.archive', 'market/staging'));
  const shelved = await places();
  world.tick(60_000);
  await answered(edit('ada-cli', 'environment.archive', 'market/staging'));
  assert.deepEqual(await places(), shelved);
});

test('a fork is restored only through a chain the vault reads: a parent deleted, or edited around it, keeps it archived', async () => {
  await amend(world, 'environments', sql`id = ${staging.id}`, { archivedAt: ARCHIVED });
  await amend(world, 'environments', sql`id = ${prod.id}`, { slug: 'prod~1' });
  assert.deepEqual(await edit('ada-cli', 'environment.restore', 'market/staging'), { refused: 'parent_archived' }, 'a deleted parent');
  await amend(world, 'environments', sql`id = ${prod.id}`, { slug: 'prod' });
  // Four above it, as no fork is made: a chain too long.
  const [top, a, b] = [environment(market, 'top'), environment(market, 'a'), environment(market, 'b')];
  await write(world, ...rows('environments', top, { ...a, parentId: top.id }, { ...b, parentId: a.id }));
  await amend(world, 'environments', sql`id = ${prod.id}`, { parentId: b.id });
  assert.deepEqual(await edit('ada-cli', 'environment.restore', 'market/staging'), { refused: 'broken_chain' }, 'four above it');
  await amend(world, 'environments', sql`id = ${a.id}`, { parentId: null });
  await answered(edit('ada-cli', 'environment.restore', 'market/staging'));
  // A parent edited around the vault is no row: it never shortens the chain, nor says it is live.
  await amend(world, 'environments', sql`id = ${staging.id}`, { archivedAt: ARCHIVED });
  await world.owner.execute(sql`UPDATE environments SET name = 'Prod!' WHERE id = ${prod.id}`);
  assert.deepEqual(await edit('ada-cli', 'environment.restore', 'market/staging'), { refused: 'broken_chain' });
});

test('an environment protected by whoever manages the project\'s environments, and unprotected by an Owner of the project alone (0.14, R30)', async () => {
  await answered(edit('ada-cli', 'environment.protect', 'market/prod'));
  assert.equal((await environmentRow(prod.id))!.protected, true);
  assert.deepEqual([(await written()).action, (await written()).detail], ['environment.protect', { slug: 'prod' }]);
  // A maintainer only writes where it is protected: Ada reads prod no more.
  assert.equal(await given(reveal('ada-cli', 'market/prod')), 'no_access');

  const before = await state();
  const refusals: [string, string][] = [
    ['ada-cli', 'a maintainer, who protects'],
    ['bo-cli', 'a viewer'],
    ['eve-cli', 'an Owner of the environment, not of its project'],
    ['fay-cli', "an Owner of the instance's every prod, which owns no project"],
    ['dee-pat', "an Owner's personal token"],
    ['api-token', "a service account that holds the project's Owner role"],
  ];
  for (const [label, who] of refusals) assert.deepEqual(await edit(label, 'environment.unprotect', 'market/prod'), { refused: 'no_access' }, who);
  assert.deepEqual(await edit('ada-cli', 'environment.unprotect', `market/${adas.slug}`), { refused: 'no_access' }, 'a personal config, protected through its environment');
  assert.deepEqual(await state(), [before[0], before[1]]);
  assert.deepEqual(await denied(), [ada, bo, eve, fay, dee, api].map((actor) => ['environment.unprotect', actor, { project: 'market', environment: 'prod', refused: 'no_access' }, [`project:${market.id}`, `environment:${prod.id}`]]));

  // An Owner of it by a grant on it, an Owner of the instance, and one whose instance role is scoped to all of it.
  for (const label of ['cy-cli', 'dee-cli', 'gil-cli']) {
    await answered(edit(label, 'environment.unprotect', 'market/prod'));
    assert.equal((await environmentRow(prod.id))!.protected, false, label);
    await answered(edit(label, 'environment.protect', 'market/prod'));
  }
  // Fay, Eve and Bo do not protect it either; Dee's personal token does, which manages the project's environments.
  for (const label of ['fay-cli', 'eve-cli', 'bo-cli']) assert.deepEqual(await edit(label, 'environment.protect', 'market/staging'), { refused: 'no_access' }, label);
  await answered(edit('dee-pat', 'environment.protect', 'market/staging'));
  // Protected again: nothing changes.
  const guarded = await places();
  await answered(edit('ada-cli', 'environment.protect', 'market/prod'));
  assert.deepEqual(await places(), guarded);
  await answered(edit('cy-cli', 'environment.unprotect', 'market/prod'));
  assert.deepEqual(await given(reveal('ada-cli', 'market/prod')), ['postgres://prod']);
  // An archived environment is protected and unprotected too, as 0.14 did.
  await answered(edit('ada-cli', 'environment.protect', 'market/old'));
  await answered(edit('cy-cli', 'environment.unprotect', 'market/old'));
});

test('an Owner of the project unprotects only by a grant that stands and a role with a row, as a person on no credential\'s scope', async () => {
  await amend(world, 'environments', sql`id = ${prod.id}`, { protected: true });
  // Hal, an Admin of the instance, manages every project's environments, and owns market until his grant expires. Dee manages
  // market's environments by a grant beside her instance role.
  const hal = user('hal');
  await write(world, ...rows('roles', role(true, 'admin', ['environment.manage'])), ...rows('principals', principal(hal, { role: 'admin' })), ...rows('credentials', credential('hal-cli', hal)),
    ...rows('grants', grant(hal, 'owner', { project: market }, { expiresAt: new Date(world.now() + 60_000) }), grant(dee, 'maintainer', { project: market })));
  await answered(edit('hal-cli', 'environment.unprotect', 'market/prod'));
  await amend(world, 'environments', sql`id = ${prod.id}`, { protected: true });
  world.tick(60_000);
  assert.deepEqual(await edit('hal-cli', 'environment.unprotect', 'market/prod'), { refused: 'no_access' }, 'an expired grant');
  world.tick(-60_000);
  // The project's Owner role deleted around the vault: Hal's grant names no role, and his instance role still manages environments.
  await world.owner.execute(sql`DELETE FROM roles WHERE id = 'owner' AND NOT instance`);
  assert.deepEqual(await edit('hal-cli', 'environment.unprotect', 'market/prod'), { refused: 'no_access' });
  await answered(edit('hal-cli', 'environment.protect', 'market/staging'));
  // An Owner of the instance needs the instance's Owner role's row too.
  await world.owner.execute(sql`DELETE FROM roles WHERE id = 'owner' AND instance`);
  assert.deepEqual(await edit('dee-cli', 'environment.unprotect', 'market/prod'), { refused: 'no_access' });
  assert.equal((await environmentRow(prod.id))!.protected, true);
});

test("a workload's session neither protects nor unprotects, whatever its service holds: it changes no one's access", async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]), policy: '{}' });
  const pod = session('pod', bound);
  await write(world, ...rows('bindings', bound), ...rows('credentials', pod));
  const by = (op: 'environment.protect' | 'environment.unprotect') => vault.change({ ...shown('pod'), proof: 'pod', op, project: 'market', environment: 'prod' });
  assert.deepEqual(await by('environment.protect'), { refused: 'workload_cannot_issue' });
  await amend(world, 'environments', sql`id = ${prod.id}`, { protected: true });
  assert.deepEqual(await by('environment.unprotect'), { refused: 'workload_cannot_issue' });
  assert.deepEqual(await denied(), ['environment.protect', 'environment.unprotect'].map((action) => [action, api, { project: 'market', environment: 'prod', refused: 'workload_cannot_issue' }, [`project:${market.id}`, `environment:${prod.id}`]]));
  // It still writes there, as its service may.
  assert.ok('answer' in (await vault.change({ ...shown('pod'), proof: 'pod', op: 'secret.write', project: 'market', environment: 'prod', keys: [{ key: 'TOKEN', value: 'tok', nature: 'secret' }] })));
});

test('an upstream credential frozen in an environment by whoever writes there, used by nobody, and thawed by an Owner of the project', async () => {
  const using = (label: string, upstream: string | null) => given(reveal(label, 'market/prod', { upstream }));
  assert.deepEqual(await using('ada-cli', 'stripe'), ['postgres://prod']);
  await answered(edit('ada-cli', 'upstream.freeze', 'market/prod', { upstream: 'stripe' }));
  await answered(edit('ada-cli', 'upstream.freeze', 'market/prod', { upstream: 'github' }));
  assert.deepEqual((await environmentRow(prod.id))!.frozen, ['github', 'stripe']);
  // Uses within the vault's short memory decide on the rows they read before (D218): the next to read again finds it frozen.
  world.memory.reads.clear();
  assert.deepEqual([(await written()).action, (await written()).detail], ['upstream.freeze', { slug: 'prod', upstream: 'github' }]);
  // Frozen for everyone, its Owners included; another upstream, or none, is used as before.
  assert.deepEqual([await using('ada-cli', 'stripe'), await using('dee-cli', 'stripe'), await using('ada-cli', 'slack'), await using('ada-cli', null)], ['frozen', 'frozen', ['postgres://prod'], ['postgres://prod']]);
  // Frozen again: nothing changes.
  const frozen = await places();
  await answered(edit('ada-cli', 'upstream.freeze', 'market/prod', { upstream: 'stripe' }));
  assert.deepEqual(await places(), frozen);

  const before = await state();
  assert.deepEqual(await edit('bo-cli', 'upstream.freeze', 'market/prod', { upstream: 'slack' }), { refused: 'no_access' }, 'a viewer writes nothing');
  assert.deepEqual(await edit('ada-cli', 'upstream.thaw', 'market/prod', { upstream: 'stripe' }), { refused: 'no_access' }, 'a maintainer, who froze it');
  assert.deepEqual(await edit('eve-cli', 'upstream.thaw', 'market/prod', { upstream: 'stripe' }), { refused: 'no_access' }, 'an Owner of the environment');
  assert.deepEqual(await edit('ada-cli', 'upstream.freeze', 'market/old', { upstream: 'stripe' }), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await edit('ada-cli', 'upstream.freeze', `market/${adas.slug}`, { upstream: 'stripe' }), { refused: 'no_access' }, 'a personal config');
  assert.deepEqual(await state(), [before[0], before[1]]);
  assert.deepEqual(await denied(), [
    ['upstream.freeze', bo, { project: 'market', environment: 'prod', upstream: 'slack', refused: 'no_access' }, [`project:${market.id}`, `environment:${prod.id}`]],
    ['upstream.thaw', ada, { project: 'market', environment: 'prod', upstream: 'stripe', refused: 'no_access' }, [`project:${market.id}`, `environment:${prod.id}`]],
    ['upstream.thaw', eve, { project: 'market', environment: 'prod', upstream: 'stripe', refused: 'no_access' }, [`project:${market.id}`, `environment:${prod.id}`]],
    ['upstream.freeze', ada, { project: 'market', environment: 'old', upstream: 'stripe', refused: 'no_access' }, [`project:${market.id}`, `environment:${old.id}`]],
  ]);

  // Nor in an archived project's.
  await amend(world, 'projects', sql`id = ${market.id}`, { archivedAt: ARCHIVED });
  assert.deepEqual(await edit('ada-cli', 'upstream.freeze', 'market/prod', { upstream: 'slack' }), { refused: 'no_access' }, 'an archived project');
  await amend(world, 'projects', sql`id = ${market.id}`, { archivedAt: null });

  await answered(edit('cy-cli', 'upstream.thaw', 'market/prod', { upstream: 'stripe' }));
  assert.deepEqual((await environmentRow(prod.id))!.frozen, ['github']);
  world.memory.reads.clear();
  assert.deepEqual(await using('ada-cli', 'stripe'), ['postgres://prod']);
  await answered(edit('gil-cli', 'upstream.thaw', 'market/prod', { upstream: 'github' }));
  await answered(edit('dee-cli', 'upstream.thaw', 'market/prod', { upstream: 'github' }));
  assert.deepEqual((await environmentRow(prod.id))!.frozen, []);
  for (const upstream of ['Stripe', '1st', 'a'.repeat(33), 'a_b', '', 7, null]) await assert.rejects(edit('ada-cli', 'upstream.freeze', 'market/prod', { upstream } as never), TypeError, String(upstream));
});

test('an edit decided on the same rows as another change: whichever commits second finds the first, and starts over', async () => {
  const deciding = { workloads: world.workloads };
  const prepared = async (input: Presented & Change) => {
    const one = await prepare(world, OPERATIONS[input.op](input as never, deciding) as Operation<Parts, unknown>);
    assert.ok(!('refused' in one), 'refused' in one ? one.refused : '');
    return one;
  };
  const by = (label: string, op: string, more: object) => ({ ...shown(label), op, project: 'market', ...more }) as Presented & Change;
  // A fork made of prod as it is archived: the archive finds the fork.
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  await amend(world, 'environments', sql`id = ${staging.id}`, { archivedAt: ARCHIVED });
  const archive = by('ada-cli', 'environment.archive', { environment: 'prod' });
  const fork = (project: string) => ({ ...by('ada-cli', 'environment.create', { environment: 'preview', mine: false, parent: 'prod', protected: false }), project }) as Presented & Change;
  let [one, two] = [await prepared(fork('market')), await prepared(archive)];
  assert.equal(await commit(world, one), true);
  assert.equal(await commit(world, two), false, 'a row it read for has come');
  assert.deepEqual(await vault.change(archive as never), { refused: 'inherited' });
  // And the other way: billing's prod archived as it is forked, the fork finds its parent archived.
  const shelve = { ...by('ada-cli', 'environment.archive', { environment: 'prod' }), project: 'billing' } as Presented & Change;
  [one, two] = [await prepared(shelve), await prepared(fork('billing'))];
  assert.equal(await commit(world, one), true);
  assert.equal(await commit(world, two), false, 'a row it read has changed');
  assert.deepEqual(await vault.change(fork('billing') as never), { refused: 'no_access' });
  // Two environments re-slugged to one slug at once.
  [one, two] = [await prepared(by('ada-cli', 'environment.update', { environment: 'prod', slug: 'live' })), await prepared(by('ada-cli', 'environment.update', { environment: 'staging', slug: 'live' }))];
  assert.equal(await commit(world, one), true);
  assert.equal(await commit(world, two), false);
  assert.deepEqual(await vault.change(by('ada-cli', 'environment.update', { environment: 'staging', slug: 'live' }) as never), { refused: 'exists' });
  // A write in an environment as it is archived.
  const writing = by('ada-cli', 'secret.write', { environment: 'preview', keys: [{ key: 'TOKEN', value: 'tok', nature: 'secret' }] });
  const [w, a] = [await prepared(writing), await prepared(by('ada-cli', 'environment.archive', { environment: 'preview' }))];
  assert.equal(await commit(world, a), true);
  assert.equal(await commit(world, w), false);
  assert.deepEqual(await vault.change(writing as never), { refused: 'no_access' });
});

test('an edit that is not what the contract says is a fault, before any read', async () => {
  const faults: [Edit['op'], string, Record<string, unknown>][] = [
    ['project.update', 'market', { slug: 'a~1' }], ['project.update', 'market', { slug: '' }], ['project.update', 'market', { project: 7, slug: 'x' }],
    ['project.archive', 'market', { project: 'x'.repeat(257) }], ['environment.archive', 'market/prod', { environment: null }], ['environment.archive', 'market/prod', { environment: undefined }],
    ['environment.protect', 'market/prod', { environment: 'a\0' }],
  ];
  for (const [op, place, more] of faults) await assert.rejects(edit('cy-cli', op, place, more as never), TypeError, `${op} ${JSON.stringify(more)}`);
  assert.equal(world.woken.length, 0);
  // A place named by any text is looked for, and not found: a tombstone's slug is no place.
  await amend(world, 'environments', sql`id = ${staging.id}`, { slug: 'staging~1' });
  assert.deepEqual(await edit('ada-cli', 'environment.archive', 'market/staging~1'), { refused: 'no_access' });
  await amend(world, 'projects', sql`id = ${billing.id}`, { slug: 'billing~1' });
  assert.deepEqual(await edit('dee-cli', 'project.restore', 'billing~1'), { refused: 'no_access' });
  assert.deepEqual(await denied(), [['environment.archive', ada, { project: 'market', environment: null, refused: 'no_access' }, [`project:${market.id}`]], ['project.restore', dee, { project: null, refused: 'no_access' }, []]]);
});

test('an edit holds each row it uses to what it is used for, not only to the conditions it was read by', async () => {
  const sealed = <T extends object>(row: T) => ({ ...row, mac: Buffer.alloc(36) }) as never;
  const deciding = { workloads: world.workloads };
  const seeing = async (input: Presented & Change, more: (seen: Seen<Parts>) => Seen<Parts>) => {
    const operation = OPERATIONS[input.op](input as never, deciding) as Operation<Parts, { id: string }>;
    return change(world, { read: operation.read, decide: (seen, at) => operation.decide(more(seen), at) });
  };
  const by = (label: string, op: string, more: object) => ({ ...shown(label), op, project: 'market', ...more }) as Presented & Change;
  // Billing, live, before market: Ada does not rename billing's prod by naming market's.
  const renamed = await seeing(by('ada-cli', 'environment.update', { environment: 'prod', slug: 'live' }), (seen) => ({ ...seen, project: [sealed(billing), ...seen.project], environment: [sealed(there), ...seen.environment] }));
  assert.ok('answer' in renamed && renamed.answer.id === prod.id);
  await answered(edit('ada-cli', 'environment.update', 'market/live', { slug: 'prod' }));
  // Another project's environment of the new slug holds no place here.
  assert.ok('answer' in (await seeing(by('ada-cli', 'environment.update', { environment: 'staging', slug: 'other' }), (seen) => ({ ...seen, taken: [sealed(environment(billing, 'other'))] }))));
  // A parent read as a personal config, or as another project's, breaks the chain (staging is "other" now).
  await amend(world, 'environments', sql`id = ${staging.id}`, { archivedAt: ARCHIVED });
  for (const [what, forged] of [['a personal config', { ...prod, owner: ada }], ["another project's", { ...prod, projectId: billing.id }]] as const) {
    assert.deepEqual(await seeing(by('ada-cli', 'environment.restore', { environment: 'other' }), (seen) => ({ ...seen, chain: [sealed(forged), ...seen.chain] })), { refused: 'broken_chain' }, what);
  }
  // Another environment's fork, or a fork in another project under prod's id, inherits nothing from prod.
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  const forks = [environment(market, 'x', { parentId: staging.id }), environment(billing, 'y', { parentId: prod.id })];
  assert.ok('answer' in (await seeing(by('ada-cli', 'environment.archive', { environment: 'prod' }), (seen) => ({ ...seen, child: [...forks.map(sealed), ...seen.child] }))));
  // A reference whose source is outside the place, as its row says, reads nothing in it.
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: null });
  assert.deepEqual(await edit('ada-cli', 'environment.archive', 'market/prod'), { refused: 'referenced' });
  const elsewhere = secret(there, 'OTHER');
  assert.ok('answer' in (await seeing(by('ada-cli', 'environment.archive', { environment: 'prod' }), (seen) => ({ ...seen, source: [sealed({ ...elsewhere, id: reference.sourceId })] }))));
  // A reference held in the place itself, as its row says, goes with it.
  await answered(edit('ada-cli', 'environment.restore', 'market/prod'));
  await amend(world, 'secrets', sql`id = ${reference.id}`, { archivedAt: ARCHIVED });
  const inside = secret(prod, 'SELF', { sourceId: reference.sourceId });
  assert.ok('answer' in (await seeing(by('ada-cli', 'environment.archive', { environment: 'prod' }), (seen) => ({ ...seen, reader: [sealed(inside), ...seen.reader] }))));
});

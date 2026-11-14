// Projects and environments over HTTP on the 0.16 contract (docs/design/0.16.md,
// "The server"): each change one call to the vault and no statement of the app,
// each list one call and a fixed number of statements, scoped by the vault's
// answer about its caller.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { credential, dismissed, emptyDatabase, environment, grant, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql, type SQL } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';

import { refusal } from '../src/api/errors.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, bo, cy, dee, ed, gus] = [user('ada'), user('bo'), user('cy'), user('dee'), user('ed'), user('gus')];
const ci = 'token:ci';

/**
 * market, filed in Payments: prod (keys A and B, C archived), staging,
 * protected (S), fork, which inherits from prod and dismissed B (D), old,
 * archived, and Ada's personal config of prod (OWN; GONE, archived). fork's
 * dismissal of A was restored. fork's override of A and Ada's of B are archived (reset): each reads prod's again. billing, in Payments too: prod, whose LINK reads market's A. shelf, archived.
 *
 * Ada views market, Bo maintains it (its environments and the project), Dee
 * owns it by a grant and keeps a config of prod too, Gus stewards its
 * environments and reads none, Ed views market/prod alone, Cy owns the
 * instance, and the service account ci maintains market.
 */
let ids: Record<string, string> = {};
let made: { market: ReturnType<typeof project>; fork: ReturnType<typeof environment> };
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [market, billing, shelf] = [project('market', { folder: 'Payments' }), project('billing', { folder: 'Payments' }), project('shelf', { archivedAt: new Date(0) })];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { protected: true });
  const fork = environment(market, 'fork', { parentId: prod.id });
  const old = environment(market, 'old', { archivedAt: new Date(0) });
  const adas = environment(market, 'prod-ada', { parentId: prod.id, owner: ada });
  const dees = environment(market, 'prod-dee', { parentId: prod.id, owner: dee });
  const billed = environment(billing, 'prod');
  const a = value(world, secret(prod, 'A'), 'a');
  ids = { market: market.id, billing: billing.id, prod: prod.id, adas: adas.id };
  made = { market, fork };
  await write(
    world,
    ...rows('projects', market, billing, shelf),
    ...rows('environments', prod, staging, fork, old, adas, dees, billed, environment(shelf, 'prod')),
    ...rows('secrets', a, secret(prod, 'B'), secret(prod, 'C', { archivedAt: new Date(0) }), secret(staging, 'S'), secret(fork, 'D'), secret(old, 'O'), secret(adas, 'OWN'), secret(adas, 'GONE', { archivedAt: new Date(0) }), secret(fork, 'A', { archivedAt: new Date(0) }), secret(adas, 'B', { archivedAt: new Date(0) }), secret(billed, 'LINK', { sourceId: a.id })),
    ...rows('dismissedKeys', dismissed(fork, 'B'), { ...dismissed(fork, 'A'), restoredAt: new Date(0), restoredBy: dismissed(fork, 'A').dismissedBy }),
    ...rows('roles',
      role(false, 'viewer', ['secret.read'], []),
      role(false, 'steward', ['environment.manage'], []),
      // Holds something in protected environments alone: it reaches every project, and shows those where it holds it.
      role(true, 'auditor', [], ['secret.read']),
      role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']),
      role(false, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' }), principal(dee), principal(ed), principal(gus), principal(ci)),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(gus, 'steward', { project: market }), grant(bo, 'maintainer', { project: market }), grant(dee, 'owner', { project: market }), grant(ed, 'viewer', { environment: prod }), grant(ci, 'maintainer', { project: market })),
    ...rows('credentials', ...[ada, bo, cy, dee, ed].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), credential('gus-cli', gus), credential('ci-token', ci, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) })),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const as = (label: string, init: RequestInit = {}) => ({ ...init, headers: { authorization: `Bearer ${label}`, ...(init.headers as Record<string, string> | undefined) } });
const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, as(label, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
  return [got.status, (await got.json()) as Body];
};
/** What one request cost: its answer, the vault's calls it made, and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: [number, Body]) => [answer[0], answer[1].error, answer[1].reason];
const NO_ACCESS = [403, 'vault_refused', 'no_access'];
const projectRow = async (slug: string) => (await rowsOf<{ slug: string; archived: boolean; folder: string | null }>(world.owner, sql`SELECT slug, archived_at IS NOT NULL AS archived, folder FROM projects WHERE slug = ${slug}`))[0];
const environmentRow = async (slug: string, of = 'market') =>
  (await rowsOf<{ slug: string; archived: boolean; protected: boolean; parent: string | null }>(world.owner, sql`SELECT e.slug, e.archived_at IS NOT NULL AS archived, e.protected, parent.slug AS parent FROM environments e JOIN projects p ON p.id = e.project_id LEFT JOIN environments parent ON parent.id = e.parent_id WHERE p.slug = ${of} AND e.slug = ${slug}`))[0];
const params = (query: unknown) => new PgDialect().sqlToQuery(query as SQL).params;

type Listed = { slug: string; archivedAt: string | null; folder: string | null; permissions: string[]; secretCount: number | null; environments: { slug: string; accessible: boolean; parent: string | null; protected: boolean; unprotectable: boolean; personal: boolean; details: { archivedAt: string | null; secretCount: number | null } | null }[] };
const listed = async (label: string) => (await call(label, 'GET', '/projects'))[1].projects as Listed[];

test('the projects list is one call to the vault and two statements, scoped by its answer, and stays so however much there is', async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'GET', '/projects'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 2], JSON.stringify(body));
  const [market] = body.projects as Listed[];
  assert.deepEqual({ ...market, environments: undefined }, { slug: 'market', name: 'market', archivedAt: null, folder: 'Payments', permissions: ['secret.read', 'secret.write', 'environment.manage', 'project.manage'], secretCount: 4, environments: undefined });
  // Not Ada's personal config: hers alone. A fork's count is of the keys it resolves to: its own, and those of prod it did not dismiss.
  assert.deepEqual(market!.environments.map(({ slug, parent, protected: guarded, unprotectable, personal, accessible, details }) => [slug, parent, guarded, unprotectable, personal, accessible, details?.archivedAt === null ? 'live' : details === null ? null : 'archived', details?.secretCount]), [
    ['fork', 'prod', false, false, false, true, 'live', 2],
    ['old', null, false, false, false, true, 'archived', 1],
    ['prod', null, false, false, false, true, 'live', 2],
    ['staging', null, true, false, false, true, 'live', 1],
  ]);
  // A read of Bo's: his one project, by its id.
  app.executed.length = 0;
  await call('bo-cli', 'GET', '/projects');
  assert.deepEqual(params(app.executed[0]), [[ids.market]]);

  // Ada: her own config of prod, as prod@me, which reads prod's keys under its own; not staging, protected, which a viewer does not read.
  const [hers] = await listed('ada-cli');
  assert.deepEqual(hers!.environments.map(({ slug, accessible, personal, details }) => [slug, accessible, personal, details?.secretCount ?? null]), [['fork', true, false, 2], ['old', true, false, 1], ['prod', true, false, 2], ['prod@me', true, true, 3], ['staging', false, false, null]]);
  // Her project's names: A, B, D and OWN, which her config holds.
  assert.deepEqual([hers!.secretCount, hers!.permissions], [4, ['secret.read']]);
  // prod protected: her config is listed as protected through it.
  await world.owner.execute(sql`UPDATE environments SET protected = true WHERE slug = 'prod' AND owner IS NULL AND project_id = ${ids.market}`);
  assert.deepEqual((await listed('ada-cli'))[0]!.environments.filter((at) => at.slug.startsWith('prod')).map((at) => [at.slug, at.protected]), [['prod', true], ['prod@me', true]]);
  await world.owner.execute(sql`UPDATE environments SET protected = false WHERE slug = 'prod' AND owner IS NULL AND project_id = ${ids.market}`);
  // Ed holds prod alone: the project's other environments by name only, and none of its keys.
  const [eds] = await listed('ed-cli');
  assert.deepEqual([eds!.permissions, eds!.secretCount, eds!.environments.map(({ slug, accessible, details }) => [slug, accessible, details?.secretCount ?? null])], [[], 2, [['fork', false, null], ['old', false, null], ['prod', true, 2], ['staging', false, null]]]);
  // Whoever runs the instance: every project, an archived one too, with no scope in its statement. Dee, who owns market, may unprotect its environments.
  const everything = await listed('cy-cli');
  assert.deepEqual(everything.map(({ slug, archivedAt, secretCount }) => [slug, archivedAt === null ? null : 'archived', secretCount]), [['billing', null, 1], ['market', null, 4], ['shelf', 'archived', null]]);
  assert.deepEqual(params(app.executed.at(-2)), []);
  assert.deepEqual(everything[1]!.environments.every((at) => at.unprotectable), true);
  // Dee's own config of prod: protected as prod is, and no protection of its own to take off.
  assert.deepEqual((await listed('dee-cli'))[0]!.environments.map((at) => [at.slug, at.unprotectable]), [['fork', true], ['old', true], ['prod', true], ['prod@me', false], ['staging', true]]);
  // Gus manages market's environments and opens none: each one's details, and no count.
  const [stewarded] = await listed('gus-cli');
  assert.deepEqual([stewarded!.secretCount, stewarded!.environments.map((at) => [at.slug, at.accessible, at.details?.secretCount, at.details === null])], [null, [['fork', false, null, false], ['old', false, null, false], ['prod', false, null, false], ['staging', false, null, false]]]);

  // Grown: forty more projects, each of three environments and five keys. The same calls, and the same statements.
  const more = Array.from({ length: 40 }, (_, n) => project(`p${n}`));
  const places = more.flatMap((at) => ['dev', 'staging', 'prod'].map((slug) => environment(at, slug)));
  await write(world, ...rows('projects', ...more), ...rows('environments', ...places), ...rows('secrets', ...places.flatMap((at) => ['K1', 'K2', 'K3', 'K4', 'K5'].map((key) => secret(at, key)))), ...rows('grants', ...more.map((at) => grant(bo, 'viewer', { project: at }))));
  world.memory.callers.clear();
  for (const label of ['bo-cli', 'cy-cli', 'ed-cli']) {
    const [[grown], again, count] = await cost(() => call(label, 'GET', '/projects'));
    assert.deepEqual([grown, again, count], [200, ['caller'], 2], label);
  }
  assert.equal((await listed('bo-cli')).length, 41);
  assert.equal((await listed('bo-cli')).find((at) => at.slug === 'p7')!.secretCount, 5);
});

test("a credential scoped to one environment narrows the lists to it, however much its holder holds", async () => {
  // Cy runs the instance; this credential of hers reaches market/prod alone, to read and write there. An Owner's role on one environment is no scope (it holds project-wide permissions): that credential reaches nothing.
  const scoped = (normal: string[]) => JSON.stringify([{ projectId: ids.market, environmentId: ids.prod, role: 'owner', ...(normal.length === 0 ? {} : { permissions: { normal, protected: normal } }) }]);
  await write(world, ...rows('credentials', credential('cy-prod', cy, { kind: 'personal', scope: scoped(['secret.read', 'secret.write']) }), credential('cy-bad', cy, { kind: 'personal', scope: scoped([]) })));
  assert.deepEqual(await listed('cy-bad'), []);
  const [[status, body], calls, statements] = await cost(() => call('cy-prod', 'GET', '/projects'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 2], JSON.stringify(body));
  const projects = body.projects as Listed[];
  assert.deepEqual(projects.map((at) => [at.slug, at.permissions, at.secretCount]), [['market', [], 2]]);
  assert.deepEqual(projects[0]!.environments.map(({ slug, accessible, unprotectable, details }) => [slug, accessible, unprotectable, details?.secretCount ?? null]), [['fork', false, false, null], ['old', false, false, null], ['prod', true, false, 2], ['staging', false, false, null]]);
  app.executed.length = 0;
  await call('cy-prod', 'GET', '/projects');
  assert.deepEqual(params(app.executed[0]), [[ids.market]]);
  // Managing environments is a project's alone, which no credential on one environment holds: no personal configs, anywhere.
  for (const path of ['market', 'billing']) assert.deepEqual(refused(await call('cy-prod', 'GET', `/personal/${path}`)), NO_ACCESS, path);
});

test("a personal config as deep as a chain goes counts each key its chain resolves to: archived overrides passed over, a dismissal restored or not", async () => {
  // market/prod <- fork <- f2 <- f3, three parents, the most a fork has; Bo's config of f3 sits one below, four from prod: the most a use reads
  // through (@coffre/vault's use.ts), though the vault makes no new config that deep (0.14's too_deep). The count follows the use.
  const f2 = environment(made.market, 'f2', { parentId: made.fork.id });
  const f3 = environment(made.market, 'f3', { parentId: f2.id });
  const bos = environment(made.market, 'f3-bo', { parentId: f3.id, owner: bo });
  const restored = { ...dismissed(f2, 'B'), restoredAt: new Date(0), restoredBy: dismissed(f2, 'B').dismissedBy };
  await write(world, ...rows('environments', f2, f3, bos), ...rows('secrets', secret(f2, 'E'), secret(bos, 'MINE'), secret(bos, 'A', { archivedAt: new Date(0) })), ...rows('dismissedKeys', dismissed(f2, 'D'), restored, dismissed(bos, 'E')));
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'GET', '/projects'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 2], JSON.stringify(body));
  const [market] = body.projects as Listed[];
  // f2 and f3: prod's A (fork's override archived, its dismissal restored) and f2's E; D dismissed at f2, B at fork, which a restored dismissal of f2's does not undo.
  // Bo's config: MINE, and prod's A, four up, its own A archived; E dismissed.
  assert.deepEqual(market!.environments.filter((at) => at.slug.startsWith('f')).map(({ slug, personal, details }) => [slug, personal, details?.secretCount]), [['f2', false, 2], ['f3', false, 2], ['f3@me', true, 2], ['fork', false, 2]]);
  // The project's names, each once: A, B, D, S, E and MINE.
  assert.equal(market!.secretCount, 6);
});

test('an archived project is listed to whoever runs the instance or manages it; a project its caller holds nothing in, to nobody', async () => {
  await world.owner.execute(sql`UPDATE projects SET archived_at = now() WHERE slug = 'market'`);
  assert.deepEqual((await listed('ada-cli')).map((at) => at.slug), []);
  const [kept] = await listed('bo-cli');
  assert.deepEqual([kept!.slug, kept!.archivedAt === null, kept!.secretCount], ['market', false, null]);
  // A caller with nothing anywhere: no project, and one statement.
  await write(world, ...rows('principals', principal(user('fay')), principal(user('hal'), { role: 'auditor' })), ...rows('credentials', credential('fay-cli', user('fay')), credential('hal-cli', user('hal'))));
  const [[, none], calls, statements] = await cost(() => call('fay-cli', 'GET', '/projects'));
  assert.deepEqual([none.projects, calls, statements], [[], ['caller'], 1]);
  // Hal's role reaches every project, and holds something in market's staging alone: market, archived, is not his to see, and billing holds nothing of his.
  assert.deepEqual((await listed('hal-cli')).map((at) => at.slug), []);
  await world.owner.execute(sql`UPDATE projects SET archived_at = NULL WHERE slug = 'market'`);
  const [guarded] = await listed('hal-cli');
  assert.deepEqual([guarded!.slug, guarded!.permissions, guarded!.environments.filter((at) => at.accessible).map((at) => at.slug)], ['market', [], ['staging']]);
  assert.deepEqual(refused(await call('nobody', 'GET', '/projects')), [401, 'unauthenticated', 'unauthenticated']);
});

test("a project's personal configs, to whoever manages its environments: whose, of what, and their keys by name", async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'GET', '/personal/market'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 1], JSON.stringify(body));
  assert.deepEqual(body.configs, [
    { owner: ada, of: 'prod', slug: 'prod-ada', keys: ['OWN'], archived: false, createdAt: '2026-11-13T09:00:00.000Z' },
    { owner: dee, of: 'prod', slug: 'prod-dee', keys: [], archived: false, createdAt: '2026-11-13T09:00:00.000Z' },
  ]);
  app.executed.length = 0;
  await call('bo-cli', 'GET', '/personal/market');
  assert.deepEqual(params(app.executed[0]), ['market', [ids.market]]);
  // A viewer, a project she holds nothing in and one that is not there: one answer.
  for (const [label, path] of [['ada-cli', 'market'], ['bo-cli', 'billing'], ['bo-cli', 'nope'], ['cy-cli', 'nope']] as const) assert.deepEqual(refused(await call(label, 'GET', `/personal/${path}`)), NO_ACCESS, `${label} ${path}`);
  assert.deepEqual((await call('cy-cli', 'GET', '/personal/billing'))[1], { configs: [] });
});

test('a project is made by one call to the vault and no statement; one there already is refused', async () => {
  const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'PUT', '/projects/shop', { name: 'Shop' }));
  assert.deepEqual([status, body, calls, statements], [200, { project: { slug: 'shop', name: 'shop', archivedAt: null }, created: true }, ['change'], 0]);
  assert.deepEqual(await projectRow('shop'), { slug: 'shop', archived: false, folder: null });
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/projects/shop')), [409, 'conflict', 'exists']);
  // shelf is archived, and there all the same.
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/projects/shelf')), [409, 'conflict', 'exists']);
  // Who makes no project: told no more than for one that is there.
  for (const slug of ['shop', 'other']) assert.deepEqual(refused(await call('bo-cli', 'PUT', `/projects/${slug}`)), NO_ACCESS);
  app.calls.length = 0;
  for (const [path, body] of [['/projects/Shop', {}], ['/projects/sh%7Eop', {}], ['/projects/shop', { name: '' }], ['/projects/shop', { name: 7 }]] as const) assert.equal((await call('cy-cli', 'PUT', path, body))[0], 400, path);
  assert.deepEqual(app.calls, []);
});

test('an environment, an inheriting fork and a personal config are made by one call each; a fork that copies is not served', async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'PUT', '/projects/market/qa'));
  assert.deepEqual([status, body, calls, statements], [200, { environment: { slug: 'qa', name: 'qa', archivedAt: null, protected: false }, created: true, forked: null }, ['change'], 0]);
  // A fork of staging is protected as staging is, from its first moment.
  assert.deepEqual((await call('bo-cli', 'PUT', '/projects/market/hotfix', { from: 'staging', inherit: true }))[1], { environment: { slug: 'hotfix', name: 'hotfix', archivedAt: null, protected: true }, created: true, forked: { from: 'staging', keys: 0, references: 0, copied: [], inherits: true } });
  assert.deepEqual(await environmentRow('hotfix'), { slug: 'hotfix', archived: false, protected: true, parent: 'staging' });
  // A fork three deep is the deepest: fork inherits from prod, so f2 and f3 may follow, and no fourth.
  await call('bo-cli', 'PUT', '/projects/market/f2', { from: 'fork', inherit: true });
  assert.equal((await call('bo-cli', 'PUT', '/projects/market/f3', { from: 'f2', inherit: true }))[0], 200);
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/f4', { from: 'f3', inherit: true })), [409, 'conflict', 'too_deep']);
  // Bo's own config of staging: protected as staging is.
  const [, mine] = await call('bo-cli', 'PUT', '/projects/market/staging@me');
  assert.deepEqual(mine, { environment: { slug: 'staging@me', name: 'staging@me', archivedAt: null, protected: true }, created: true, forked: null });
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/staging@me')), [409, 'conflict', 'exists']);
  assert.deepEqual(refused(await call('ci-token', 'PUT', '/projects/market/prod@me')), [403, 'forbidden', 'not_a_person']);
  // A viewer makes her config of what she reads, and nothing else.
  assert.equal((await call('ada-cli', 'PUT', '/projects/market/fork@me'))[0], 200);
  for (const path of ['market/qa2', 'market/staging@me', 'billing/qa', 'nope/qa']) assert.deepEqual(refused(await call('ada-cli', 'PUT', `/projects/${path}`)), NO_ACCESS, path);
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/prod')), [409, 'conflict', 'exists']);
  // A fork of itself is the vault's to refuse: prod is there, and qa9 is no parent.
  app.calls.length = 0;
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/prod', { from: 'prod', inherit: true })), [409, 'conflict', 'exists']);
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/qa9', { from: 'qa9', inherit: true })), NO_ACCESS);
  assert.deepEqual(app.calls, ['change', 'change']);
  // An archived parent is no parent.
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/projects/market/f5', { from: 'old', inherit: true })), NO_ACCESS);

  app.calls.length = 0;
  const shapes: [string, unknown, number][] = [
    ['market/copy', { from: 'prod' }, 501], ['market/copy', { from: 'prod', references: true }, 501],
    ['market/copy', { inherit: true }, 400], ['market/copy', { from: 'prod', inherit: true, references: true }, 400],
    ['market/settings', {}, 400], ['market/Qa', {}, 400], ['market/prod@me', { from: 'prod' }, 400], ['market/prod@me', { inherit: false }, 400], ['market/qa', { from: 'Prod', inherit: true }, 400],
  ];
  for (const [path, input, expected] of shapes) assert.equal((await call('bo-cli', 'PUT', `/projects/${path}`, input))[0], expected, `${path} ${JSON.stringify(input)}`);
  assert.deepEqual(app.calls, []);
});

test('a project is re-slugged, archived, restored or filed by one call each, which answers it as it is left; one change a request', async () => {
  const patch = (label: string, body: unknown, slug = 'market') => call(label, 'PATCH', `/projects/${slug}`, body);
  const [[status, body], calls, statements] = await cost(() => patch('bo-cli', { slug: 'shop' }));
  assert.deepEqual([status, body, calls, statements], [200, { project: { slug: 'shop', name: 'shop', archivedAt: null, folder: 'Payments' } }, ['change'], 0]);
  // billing's LINK reads shop's A: archiving shop would stop that read. Once billing is archived, nothing reads it.
  assert.deepEqual(refused(await patch('bo-cli', { archived: true }, 'shop')), [409, 'conflict', 'referenced']);
  assert.match(String((await patch('bo-cli', { archived: true }, 'shop'))[1].message), /^shop: a reference held elsewhere/);
  assert.equal((await patch('cy-cli', { archived: true }, 'billing'))[0], 200);
  const [, archived] = await patch('bo-cli', { archived: true }, 'shop');
  assert.match(String((archived.project as { archivedAt: string }).archivedAt), /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual((await patch('bo-cli', { archived: false }, 'shop'))[1], { project: { slug: 'shop', name: 'shop', archivedAt: null, folder: 'Payments' } });
  assert.deepEqual((await patch('bo-cli', { folder: null }, 'shop'))[1], { project: { slug: 'shop', name: 'shop', archivedAt: null, folder: null } });
  // The slug it has, a name, or nothing: no change, and the project as it is. As the UI's settings send it, the slug with the folder.
  for (const asked of [{}, { name: 'Shop' }, { slug: 'shop' }]) assert.deepEqual((await patch('bo-cli', asked, 'shop'))[1], { project: { slug: 'shop', name: 'shop', archivedAt: null, folder: null } });
  assert.deepEqual((await patch('bo-cli', { slug: 'shop', folder: 'Retail' }, 'shop'))[1], { project: { slug: 'shop', name: 'shop', archivedAt: null, folder: 'Retail' } });
  assert.deepEqual(await projectRow('shop'), { slug: 'shop', archived: false, folder: 'Retail' });

  // Taken, by a live project or an archived one: the new slug's refusal.
  const [taken, said] = await patch('bo-cli', { slug: 'shelf' }, 'shop');
  assert.deepEqual([taken, said.reason, String(said.message).split(':')[0]], [409, 'exists', 'shelf']);
  for (const [label, slug] of [['ada-cli', 'shop'], ['bo-cli', 'billing'], ['bo-cli', 'nope']] as const) assert.deepEqual(refused(await patch(label, { folder: 'Mine' }, slug)), NO_ACCESS, `${label} ${slug}`);

  app.calls.length = 0;
  for (const asked of [{ slug: 'shop2', archived: true }, { archived: false, folder: 'X' }, { slug: 'shop2', folder: 'X' }, { folder: ' X' }, { folder: 'a/b' }, { slug: 'Shop' }, { archived: 'yes' }, { other: 1 }]) {
    assert.equal((await patch('bo-cli', asked, 'shop'))[0], 400, JSON.stringify(asked));
  }
  assert.deepEqual(app.calls, []);
});

test('an environment is re-slugged, archived, restored, protected or unprotected by one call each; its protection off by an Owner of its project alone', async () => {
  const patch = (label: string, environment: string, body: unknown) => call(label, 'PATCH', `/projects/market/${environment}`, body);
  const [[status, body], calls, statements] = await cost(() => patch('bo-cli', 'prod', { protected: true }));
  assert.deepEqual([status, body, calls, statements], [200, { environment: { slug: 'prod', name: 'prod', archivedAt: null, protected: true } }, ['change'], 0]);
  // Who maintains it protects it; only an Owner of market takes that off: Dee by her grant, Cy by the instance's role. Never a service account.
  assert.deepEqual(refused(await patch('bo-cli', 'prod', { protected: false })), NO_ACCESS);
  assert.deepEqual(refused(await patch('ci-token', 'prod', { protected: false })), NO_ACCESS);
  assert.deepEqual((await patch('dee-cli', 'prod', { protected: false }))[1], { environment: { slug: 'prod', name: 'prod', archivedAt: null, protected: false } });
  const [ciStatus, ciBody] = await patch('ci-token', 'prod', { protected: true });
  assert.equal(ciStatus, 200, JSON.stringify(ciBody));
  assert.equal((await patch('cy-cli', 'prod', { protected: false }))[0], 200);
  // billing's LINK reads prod's A, and fork inherits from prod: archived, prod would stop both.
  assert.deepEqual(refused(await patch('bo-cli', 'prod', { archived: true })), [409, 'conflict', 'referenced']);
  assert.equal((await call('cy-cli', 'PATCH', '/projects/billing', { archived: true }))[0], 200);
  assert.deepEqual(refused(await patch('bo-cli', 'prod', { archived: true })), [409, 'conflict', 'inherited']);
  assert.equal((await patch('bo-cli', 'fork', { archived: true }))[0], 200);
  const [, gone] = await patch('bo-cli', 'prod', { archived: true });
  assert.notEqual((gone.environment as { archivedAt: string | null }).archivedAt, null, JSON.stringify(gone));
  // Its personal configs go with it; fork comes back only once prod is.
  assert.deepEqual((await rowsOf<{ archived: boolean }>(world.owner, sql`SELECT archived_at IS NOT NULL AS archived FROM environments WHERE id = ${ids.adas}`))[0], { archived: true });
  assert.deepEqual(refused(await patch('bo-cli', 'fork', { archived: false })), [409, 'conflict', 'parent_archived']);
  await patch('bo-cli', 'prod', { archived: false });
  assert.deepEqual((await patch('bo-cli', 'fork', { archived: false }))[1], { environment: { slug: 'fork', name: 'fork', archivedAt: null, protected: false } });
  // A new slug, which a taken one or a project's page is not.
  assert.deepEqual((await patch('bo-cli', 'fork', { slug: 'preview' }))[1], { environment: { slug: 'preview', name: 'preview', archivedAt: null, protected: false } });
  const [taken, said] = await patch('bo-cli', 'preview', { slug: 'staging' });
  assert.deepEqual([taken, said.reason, String(said.message).split(':')[0]], [409, 'exists', 'market/staging']);
  for (const [label, environment] of [['ada-cli', 'prod'], ['bo-cli', 'nope'], ['bo-cli', 'prod-ada']] as const) assert.deepEqual(refused(await patch(label, environment, { archived: true })), NO_ACCESS, `${label} ${environment}`);
  assert.deepEqual((await patch('bo-cli', 'prod', {}))[1], { environment: { slug: 'prod', name: 'prod', archivedAt: null, protected: false } });

  app.calls.length = 0;
  for (const [environment, asked] of [['prod', { slug: 'p2', archived: true }], ['prod', { archived: true, protected: true }], ['prod', { slug: 'settings' }], ['prod@me', { archived: true }], ['prod', { protected: 'yes' }], ['prod', { folder: 'X' }]] as const) {
    assert.equal((await patch('bo-cli', environment, asked))[0], 400, JSON.stringify(asked));
  }
  assert.deepEqual(app.calls, []);
});

test("a folder of projects is renamed or emptied whole, in one call, by who manages every project in it", async () => {
  const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'PATCH', '/folders/Payments', { name: 'Money' }));
  assert.deepEqual([status, body, calls, statements], [200, { folder: 'Money', moved: ['billing', 'market'] }, ['change'], 0]);
  // Bo manages market, not billing: half a folder renamed would be two folders.
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', '/folders/Money', { name: 'Mine' })), NO_ACCESS);
  assert.deepEqual([(await projectRow('market'))!.folder, (await projectRow('billing'))!.folder], ['Money', 'Money']);
  // Onto one that is there: the two are one.
  await call('bo-cli', 'PATCH', '/projects/market', { folder: 'Mine' });
  assert.deepEqual((await call('cy-cli', 'PATCH', '/folders/Mine', { name: 'Money' }))[1], { folder: 'Money', moved: ['market'] });
  assert.deepEqual((await call('cy-cli', 'DELETE', '/folders/Money'))[1], { folder: null, moved: ['billing', 'market'] });
  assert.deepEqual([(await projectRow('market'))!.folder, (await projectRow('billing'))!.folder], [null, null]);
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', '/folders/Money')), NO_ACCESS);
  app.calls.length = 0;
  for (const [method, path, input] of [['PATCH', '/folders/Money', { name: ' X' }], ['PATCH', '/folders/Money', { name: 'a/b' }], ['PATCH', '/folders/Money', {}], ['PATCH', '/folders/%20Money', { name: 'X' }], ['DELETE', '/folders/%07', undefined]] as const) {
    assert.equal((await call('cy-cli', method, path, input))[0], 400, `${method} ${path}`);
  }
  assert.deepEqual(app.calls, []);
});

test('deleting a place for good is not served yet: 501, and the vault is not asked', async () => {
  for (const path of ['/projects/shelf', '/projects/market/old', '/projects/market/old?dryRun=1']) {
    const [[status, body], calls] = await cost(() => call('cy-cli', 'DELETE', path));
    assert.deepEqual([status, body.error, calls], [501, 'not_implemented', []], path);
    assert.match(String(body.message), /not served yet/);
  }
});

test("each place refusal is answered with 0.14's status for the same case", () => {
  const statuses = Object.fromEntries(['exists', 'referenced', 'inherited', 'parent_archived', 'broken_chain', 'too_deep', 'workload_cannot_issue', 'not_a_person', 'no_access'].map((reason) => {
    const error = refusal(reason);
    return [reason, [error.status, error.code]];
  }));
  assert.deepEqual(statuses, {
    exists: [409, 'conflict'], referenced: [409, 'conflict'], inherited: [409, 'conflict'], parent_archived: [409, 'conflict'], broken_chain: [409, 'conflict'], too_deep: [409, 'conflict'],
    workload_cannot_issue: [403, 'forbidden'], not_a_person: [403, 'forbidden'], no_access: [403, 'vault_refused'],
  });
});

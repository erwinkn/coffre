// Projects and environments made (src/ops/places.ts), through the contract
// as the app calls it: who may, what is written, what its entry names, each
// refusal writing nothing, two makings of one place at once, and a use in
// the new place.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { EnvironmentCreate, Presented, ProjectCreate, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { bindings, environments } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { change, commit, prepare, type Operation, type Parts, type Seen } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee, eve, fay] = [user('ada'), user('bo'), user('cy'), user('dee'), user('eve'), user('fay')];
const api = 'token:api';
let market: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let guarded: ReturnType<typeof environment>;
let billing: ReturnType<typeof project>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  const shelved = project('shelved', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  prod = environment(market, 'prod');
  guarded = environment(market, 'guarded', { protected: true });
  const old = environment(market, 'old', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const adas = environment(market, 'adas', { parentId: prod.id, owner: ada });
  // A chain: staging inherits from prod, qa from staging, and deep from qa, which is as deep as one goes.
  const staging = environment(market, 'staging', { parentId: prod.id });
  const qa = environment(market, 'qa', { parentId: staging.id });
  const deep = environment(market, 'deep', { parentId: qa.id });
  // An archived parent under a live fork, as a row restored around the vault would leave it.
  const stale = environment(market, 'stale', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const orphan = environment(market, 'orphan', { parentId: stale.id });
  billing = project('billing');
  const there = environment(billing, 'prod');
  await write(world, ...rows('projects', market, shelved, billing), ...rows('environments', prod, guarded, old, adas, staging, qa, deep, stale, orphan, there),
    ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod')),
    // A maintainer manages environments and reads them, but where one is protected, writes there only; a developer and a viewer manage none.
    ...rows('roles', role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage'], ['secret.write']), role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'viewer', ['secret.read']),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']), role(true, 'admin', ['environment.manage', 'project.manage'], []), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee, { role: 'owner' }), principal(eve), principal(fay, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(api)),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: market }), grant(ada, 'maintainer', { project: billing }), grant(bo, 'viewer', { project: market }), grant(cy, 'developer', { project: market }),
      grant(eve, 'viewer', { environment: guarded }), grant(api, 'maintainer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee), credential('eve-cli', eve), credential('fay-cli', fay),
      credential('dee-pat', dee, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) }),
      credential('dee-handle', dee, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) }),
      credential('api-token', api, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const making = (label: string, slug: string): Presented & ProjectCreate => ({ ...shown(label), op: 'project.create', project: slug });
const adding = (label: string, slug: string, more: { parent?: string | null; protected?: boolean; project?: string } = {}): Presented & EnvironmentCreate =>
  ({ ...shown(label), op: 'environment.create', project: more.project ?? 'market', environment: slug, mine: false, parent: more.parent ?? null, protected: more.protected ?? false });
const mine = (label: string, of: string, more: { project?: string } = {}): Presented & EnvironmentCreate => ({ ...shown(label), op: 'environment.create', project: more.project ?? 'market', environment: of, mine: true });
const count = async (table: 'projects' | 'environments') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
/** What is made: the entries kept, the projects and the environments. A refusal's entry ages out, and is none of them. */
const counts = async () => [await kept(), await count('projects'), await count('environments')];
/** The refusals logged, oldest first: who was refused what, where as they named it, and the rows it was about beyond who asked. */
const denied = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`))
  .map((row) => entryOf(world.keys, row)!)
  // A read ages out too: a refusal is the entry that says why not.
  .filter((entry) => typeof entry.detail === 'object' && entry.detail !== null && 'refused' in entry.detail)
  .map((entry) => [entry.action, entry.actor, entry.detail, entry.objects.filter((object) => !object.startsWith('principal:') && !object.startsWith('credential:'))]);
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
/** What an entry's rows say, by table: read, made or replaced. */
const named = async () => (await written()).rows.map(({ row, was, now }) => `${(JSON.parse(row) as string[])[0]} ${was === null ? 'made' : was === now ? 'read' : 'replaced'}`).sort();
const environmentRow = async (id: string) => (await rowsOf<{ slug: string; parent_id: string | null; owner: string | null; protected: boolean; project_id: string }>(world.owner, sql`SELECT slug, parent_id, owner, protected, project_id FROM environments WHERE id = ${id}`))[0];
const reveal = (label: string, place: string, keys: string[], more: Partial<UseInput> = {}): UseInput => {
  const [projectSlug, environmentSlug] = place.split('/') as [string, string];
  return { ...shown(label), project: projectSlug, environment: environmentSlug, mine: false, keys, purpose: 'reveal', upstream: null, ...more };
};
const given = async (input: UseInput) => {
  const answer = await vault.use(input);
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
const answered = <A>(result: { answer: A } | { refused: string }): A => {
  assert.ok('answer' in result, JSON.stringify(result));
  return result.answer;
};

test('an Owner of the instance makes a project, an environment in it, and writes and reads there', async () => {
  const before = await counts();
  const { id } = answered(await vault.change(making('dee-cli', 'payments')));
  assert.deepEqual([...(await counts()), world.woken.length], [before[0]! + 1, before[1]! + 1, before[2], 1]);
  const [row] = await rowsOf<{ slug: string; name: string; archived_at: Date | null; folder: string | null }>(world.owner, sql`SELECT slug, name, archived_at, folder FROM projects WHERE id = ${id}`);
  assert.deepEqual(row, { slug: 'payments', name: 'payments', archived_at: null, folder: null });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.credential !== null, entry.request, entry.detail], ['project.create', dee, true, 'req-1', { slug: 'payments' }]);
  assert.ok(entry.objects.includes(`project:${id}`) && entry.objects.includes(`principal:${dee}`), entry.objects.join());
  // Who asked, the instance role that decided, and the project made: no grant, no project's role, since it is about no project yet.
  assert.deepEqual(await named(), ['credentials read', 'principals read', 'projects made', 'roles read']);

  const made = answered(await vault.change(adding('dee-cli', 'live', { project: 'payments' })));
  assert.deepEqual(made, { id: made.id, slug: 'live', protected: false });
  assert.deepEqual(await environmentRow(made.id), { slug: 'live', parent_id: null, owner: null, protected: false, project_id: id });
  assert.ok('answer' in (await vault.change({ ...shown('dee-cli'), op: 'secret.write', project: 'payments', environment: 'live', values: [{ key: 'TOKEN', value: 'tok', nature: 'secret' }] })));
  assert.deepEqual(await given(reveal('dee-cli', 'payments/live', ['TOKEN'])), ['tok']);
});

test('a project is made only by an Admin or Owner of the instance whose scope takes in new projects, on a session, with a role row; and only under a free slug', async () => {
  const before = await counts();
  assert.deepEqual(await vault.change(making('ada-cli', 'payments')), { refused: 'no_access' }, 'a maintainer of a project');
  assert.deepEqual(await vault.change(making('fay-cli', 'payments')), { refused: 'no_access' }, 'an Admin whose scope lists projects');
  assert.deepEqual(await vault.change(making('dee-pat', 'payments')), { refused: 'no_access' }, "an Owner's personal token");
  assert.deepEqual(await vault.change(making('api-token', 'payments')), { refused: 'no_access' }, 'a service');
  assert.deepEqual(await vault.change(making('dee-handle', 'payments')), { refused: 'unauthenticated' }, 'a handle');
  assert.deepEqual(await vault.change(making('nobody', 'payments')), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.change(making('dee-cli', 'market')), { refused: 'exists' });
  assert.deepEqual(await vault.change(making('dee-cli', 'shelved')), { refused: 'exists' }, "an archived project's slug");
  assert.deepEqual(await counts(), before);
  // Each who stands is logged refused, once in the minute: Dee once, by her personal token, though refused three times. Not the handle, nor a token nobody holds.
  const asked = { project: 'payments', refused: 'no_access' };
  assert.deepEqual(await denied(), [['project.create', ada, asked, []], ['project.create', fay, asked, []], ['project.create', dee, asked, []], ['project.create', api, asked, []]]);
  // A minute on, Dee is logged again, with the project there under that slug; one archived is not.
  world.tick(60_000);
  assert.deepEqual(await vault.change(making('dee-cli', 'market')), { refused: 'exists' });
  world.tick(60_000);
  assert.deepEqual(await vault.change(making('dee-cli', 'shelved')), { refused: 'exists' });
  assert.deepEqual((await denied()).slice(4), [['project.create', dee, { project: 'market', refused: 'exists' }, [`project:${market.id}`]], ['project.create', dee, { project: 'shelved', refused: 'exists' }, []]]);
  // A scope that keeps all but some projects takes in new ones.
  await amend(world, 'principals', sql`id = ${fay}`, { scope: JSON.stringify({ projects: { except: [market.id] }, environments: 'all' }) });
  assert.ok('answer' in (await vault.change(making('fay-cli', 'payments'))));
  // A role with no row is no role: the Owner's instance role deleted around the vault makes nothing.
  await world.owner.execute(sql`DELETE FROM roles WHERE id = 'owner' AND instance`);
  assert.deepEqual(await vault.change(making('dee-cli', 'other')), { refused: 'no_access' });
});

test('an environment is made by whoever manages the project\'s environments, in a live project, under a slug free there', async () => {
  const before = await counts();
  const refused = async (label: string, slug: string, more: Parameters<typeof adding>[2] = {}) => vault.change(adding(label, slug, more));
  assert.deepEqual(await refused('cy-cli', 'dev'), { refused: 'no_access' }, 'a developer');
  assert.deepEqual(await refused('bo-cli', 'dev'), { refused: 'no_access' }, 'a viewer');
  assert.deepEqual(await refused('eve-cli', 'dev'), { refused: 'no_access' }, 'a grant on one environment');
  assert.deepEqual(await refused('ada-cli', 'dev', { project: 'nowhere' }), { refused: 'no_access' }, 'no such project');
  assert.deepEqual(await refused('dee-cli', 'dev', { project: 'shelved' }), { refused: 'no_access' }, 'an archived project');
  assert.deepEqual(await refused('ada-cli', 'prod'), { refused: 'exists' });
  assert.deepEqual(await refused('ada-cli', 'old'), { refused: 'exists' }, "an archived environment's slug");
  // Who may not make one is told so before whether the slug is taken: a refusal says nothing of what is there.
  assert.deepEqual(await refused('cy-cli', 'prod'), { refused: 'no_access' });
  assert.deepEqual(await refused('dee-handle', 'dev'), { refused: 'unauthenticated' });
  assert.deepEqual(await counts(), before);
  // Logged once a minute for each who stands, in the place as they named it, found from the project as far as it is there.
  const dev = { environment: 'dev', refused: 'no_access' };
  assert.deepEqual(await denied(), [
    ['environment.create', cy, { project: 'market', ...dev }, [`project:${market.id}`]],
    ['environment.create', bo, { project: 'market', ...dev }, [`project:${market.id}`]],
    ['environment.create', eve, { project: 'market', ...dev }, [`project:${market.id}`]],
    ['environment.create', ada, { project: 'nowhere', ...dev }, []],
    ['environment.create', dee, { project: 'shelved', ...dev }, []],
  ]);

  const made = answered(await vault.change(adding('ada-cli', 'dev', { protected: true })));
  assert.deepEqual(await environmentRow(made.id), { slug: 'dev', parent_id: null, owner: null, protected: true, project_id: market.id });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['environment.create', ada, { slug: 'dev', protected: true }]);
  assert.ok(entry.objects.includes(`environment:${made.id}`) && entry.objects.includes(`project:${market.id}`), entry.objects.join());
  // Her grant on market and its role, the project, the environment it protects, and the one made. Not her grant on billing.
  assert.deepEqual(await named(), ['credentials read', 'environments made', 'environments read', 'grants read', 'principals read', 'projects read', 'roles read', 'roles read']);
  // An Owner of the instance with no grant, and a service's token whose scope manages the project.
  for (const [label, slug] of [['dee-cli', 'dee'], ['api-token', 'ci']]) assert.ok('answer' in (await refused(label, slug)), label);
});

test('a fork inherits from a live environment its maker reads, three deep at most, and is protected where its parent is', async () => {
  const fork = answered(await vault.change(adding('ada-cli', 'preview', { parent: 'prod' })));
  assert.deepEqual(await environmentRow(fork.id), { slug: 'preview', parent_id: prod.id, owner: null, protected: false, project_id: market.id });
  const entry = await written();
  assert.deepEqual(entry.detail, { slug: 'preview', protected: false, inherits: 'prod' });
  assert.ok(entry.objects.includes(`environment:${prod.id}`), entry.objects.join());
  // A use in the fork is given its parent's key.
  assert.deepEqual(await given(reveal('ada-cli', 'market/preview', ['DATABASE_URL'])), ['postgres://prod']);
  // Three deep: qa inherits from two, so its fork from three.
  assert.ok('answer' in (await vault.change(adding('ada-cli', 'qa-2', { parent: 'qa' }))));

  // Made protected by the owner of the instance, though not asked to be: its parent is.
  const safe = answered(await vault.change(adding('dee-cli', 'guarded-2', { parent: 'guarded', protected: false })));
  assert.equal(safe.protected, true);
  assert.equal((await environmentRow(safe.id))!.protected, true);

  const before = await counts();
  const refused = async (label: string, parent: string) => vault.change(adding(label, 'next', { parent }));
  assert.deepEqual(await refused('ada-cli', 'deep'), { refused: 'too_deep' }, 'deep inherits from three already');
  assert.deepEqual(await refused('ada-cli', 'orphan'), { refused: 'broken_chain' }, 'a parent above it archived');
  assert.deepEqual(await refused('ada-cli', 'nowhere'), { refused: 'no_access' });
  assert.deepEqual(await refused('ada-cli', 'old'), { refused: 'no_access' }, 'an archived parent');
  assert.deepEqual(await refused('ada-cli', 'adas'), { refused: 'no_access' }, 'a personal config');
  // Ada manages market's environments and, where one is protected, does not read it: she does not fork it.
  assert.deepEqual(await refused('ada-cli', 'guarded'), { refused: 'no_access' });
  assert.deepEqual(await counts(), before);
  // Ada is logged once in the minute, with the parent she named, found as the environment it is.
  const [deep] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments WHERE project_id = ${market.id} AND slug = 'deep'`);
  assert.deepEqual(await denied(), [['environment.create', ada, { project: 'market', environment: 'next', parent: 'deep', refused: 'too_deep' }, [`project:${market.id}`, `environment:${deep!.id}`]]]);
  world.tick(60_000);
  assert.deepEqual(await refused('ada-cli', 'nowhere'), { refused: 'no_access' });
  assert.deepEqual((await denied()).slice(1), [['environment.create', ada, { project: 'market', environment: 'next', parent: 'nowhere', refused: 'no_access' }, [`project:${market.id}`]]]);
  // A parent above it that is no row, edited around the vault, breaks the chain: a row that is not there never shortens it.
  await world.owner.execute(sql`UPDATE environments SET name = 'Staging!' WHERE slug = 'staging'`);
  assert.deepEqual(await refused('ada-cli', 'qa'), { refused: 'broken_chain' });
  // A parent edited around the vault is no parent.
  await world.owner.execute(sql`UPDATE environments SET name = 'Prod!' WHERE id = ${prod.id}`);
  assert.deepEqual(await refused('ada-cli', 'prod'), { refused: 'no_access' });
});

test('a personal config is a person\'s, of an environment they read or use, one each, under a slug made for it', async () => {
  const made = answered(await vault.change(mine('bo-cli', 'prod')));
  assert.match(made.slug, /^prod-p-[0-9a-f]{8}$/);
  assert.deepEqual(await environmentRow(made.id), { slug: made.slug, parent_id: prod.id, owner: bo, protected: false, project_id: market.id });
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['environment.create', { slug: made.slug, protected: false, personal: 'prod' }]);
  // His `@me` of prod is his config now, which inherits prod's keys.
  assert.deepEqual(await given(reveal('bo-cli', 'market/prod', ['DATABASE_URL'], { mine: true })), ['postgres://prod']);

  const before = await counts();
  assert.deepEqual(await vault.change(mine('bo-cli', 'prod')), { refused: 'exists' }, 'one each');
  assert.deepEqual(await vault.change(mine('ada-cli', 'prod')), { refused: 'exists' }, "Ada's, made before");
  assert.deepEqual(await vault.change(mine('api-token', 'prod')), { refused: 'not_a_person' });
  assert.deepEqual(await vault.change(mine('eve-cli', 'prod')), { refused: 'no_access' }, 'one who reads another environment');
  assert.deepEqual(await vault.change(mine('bo-cli', 'old')), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await vault.change(mine('ada-cli', 'adas')), { refused: 'no_access' }, 'a personal config of a personal config');
  assert.deepEqual(await vault.change(mine('bo-cli', 'deep')), { refused: 'too_deep' });
  assert.deepEqual(await vault.change(mine('bo-cli', 'orphan')), { refused: 'broken_chain' });
  assert.deepEqual(await vault.change(mine('bo-cli', 'prod', { project: 'shelved' })), { refused: 'no_access' });
  assert.deepEqual(await counts(), before);
  // A personal config is named by the environment it is of: logged once a minute for each who stands.
  const of = [`project:${market.id}`, `environment:${prod.id}`];
  assert.deepEqual(await denied(), [
    ['environment.create', bo, { project: 'market', parent: 'prod', refused: 'exists' }, of],
    ['environment.create', ada, { project: 'market', parent: 'prod', refused: 'exists' }, of],
    ['environment.create', api, { project: 'market', parent: 'prod', refused: 'not_a_person' }, of],
    ['environment.create', eve, { project: 'market', parent: 'prod', refused: 'no_access' }, of],
  ]);
  // A viewer of one protected environment reads it: a personal config takes nothing more. It is protected through its environment, not by its own row.
  const hers = answered(await vault.change(mine('eve-cli', 'guarded')));
  assert.equal(hers.protected, false);
  assert.equal((await environmentRow(hers.id))!.protected, false);
});

test('a personal config is made by one who only uses the environment, and again once the last was deleted', async () => {
  // Gus may use prod's values but not read them: a person all the same.
  const gus = user('gus');
  await write(world, ...rows('roles', role(false, 'runner', ['secret.use'])), ...rows('principals', principal(gus)), ...rows('grants', grant(gus, 'runner', { project: market })), ...rows('credentials', credential('gus-cli', gus)));
  const made = answered(await vault.change(mine('gus-cli', 'prod')));
  assert.deepEqual(await environmentRow(made.id), { slug: made.slug, parent_id: prod.id, owner: gus, protected: false, project_id: market.id });
  assert.deepEqual(await vault.change(mine('gus-cli', 'prod')), { refused: 'exists' });
  // Deleted, it leaves a tombstone slug, which holds no place: he makes another.
  await amend(world, 'environments', sql`id = ${made.id}`, { slug: `${made.slug}~1` });
  const again = answered(await vault.change(mine('gus-cli', 'prod')));
  assert.notEqual(again.id, made.id);
  assert.equal((await environmentRow(again.id))!.owner, gus);
});

test('two makings of one place decided on the same rows: the second finds the first, and makes nothing', async () => {
  const deciding = { workloads: world.workloads };
  const race = async (inputs: (Presented & (ProjectCreate | EnvironmentCreate))[]) => {
    const prepared = await Promise.all(inputs.map((input) => prepare(world, OPERATIONS[input.op](input as never, deciding))));
    assert.deepEqual(prepared.map((one) => ('refused' in one ? one.refused : 'prepared')), ['prepared', 'prepared']);
    return prepared;
  };
  for (const inputs of [[making('dee-cli', 'payments'), making('fay-cli', 'payments')], [adding('ada-cli', 'dev'), adding('dee-cli', 'dev', { parent: 'prod' })], [mine('bo-cli', 'prod'), mine('bo-cli', 'prod')]]) {
    if (inputs[1]!.token === shown('fay-cli').token) await amend(world, 'principals', sql`id = ${fay}`, { scope: null });
    const before = await counts();
    const [first, second] = await race(inputs);
    assert.equal(await commit(world, first as never), true);
    assert.equal(await commit(world, second as never), false, 'a row it read for has come');
    assert.deepEqual(await counts(), [before[0]! + 1, before[1]! + (inputs[0]!.op === 'project.create' ? 1 : 0), before[2]! + (inputs[0]!.op === 'project.create' ? 0 : 1)]);
    // Asked again, as `change` does by itself, it is refused.
    assert.deepEqual(await vault.change(inputs[1] as never), { refused: 'exists' });
  }
});

test("a workload's session makes an environment as its service may, with its key; one that is narrowed or stopped makes nothing", async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]), policy: '{}' });
  const pod = session('pod', bound);
  await write(world, ...rows('bindings', bound), ...rows('credentials', pod, session('tool', bound, { ancestors: JSON.stringify([pod.id]) })));
  const by = (label: string, slug: string, proof: string | null = label) => vault.change({ ...adding(label, slug), proof });
  assert.ok('answer' in (await by('pod', 'pod-made')));
  assert.deepEqual(await by('pod', 'other', null), { refused: 'unauthenticated' }, 'without its key');
  assert.deepEqual(await by('tool', 'other'), { refused: 'narrowed' });
  await amend(world, 'bindings', eq(bindings.id, bound.id), { frozenAt: new Date(world.now()) });
  assert.deepEqual(await by('pod', 'other'), { refused: 'frozen' });
});

test('a making that is not what the contract says is a fault, before any read', async () => {
  const projectSlugs: unknown[] = ['', 'A', '-a', 'a_b', 'a~1', 'a'.repeat(64), 7, null];
  for (const slug of projectSlugs) await assert.rejects(vault.change({ ...making('dee-cli', 'x'), project: slug as string }), TypeError, String(slug));
  const bad: Record<string, unknown>[] = [
    { environment: 'settings' }, { environment: 'users' }, { environment: 'Dev' }, { environment: 'dev~1' }, { environment: 'x'.repeat(64) },
    { parent: 7 }, { parent: 'x'.repeat(257) }, { protected: 'yes' }, { protected: undefined }, { mine: 'no' }, { project: null },
  ];
  for (const more of bad) await assert.rejects(vault.change({ ...adding('ada-cli', 'dev'), ...more } as never), TypeError, JSON.stringify(more));
  await assert.rejects(vault.change({ ...mine('bo-cli', 'prod'), environment: 'x'.repeat(257) }), TypeError);
  assert.equal(world.woken.length, 0);
  // A slug of 63, which is the most.
  assert.ok('answer' in (await vault.change(making('dee-cli', 'a'.repeat(63)))));
});

test('the environment a fork names is read by its row: one edited to say it is not protected forks no protection away', async () => {
  // The parent's row says it is protected under its MAC; edited around the vault, it is no row, and no parent.
  await world.owner.execute(sql`UPDATE environments SET protected = false WHERE id = ${guarded.id}`);
  assert.deepEqual(await vault.change(adding('dee-cli', 'guarded-2', { parent: 'guarded' })), { refused: 'no_access' });
  const [left] = await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${environments} WHERE slug = 'guarded-2'`);
  assert.equal(left!.n, 0);
});

test('a decision holds each row it uses to what it is used for, not only to the conditions it was read by', async () => {
  // Rows the read's conditions would never give, put before the right ones in what the decision sees: none of them is taken for what it is not.
  const sealed = <T extends object>(row: T) => ({ ...row, mac: Buffer.alloc(36) });
  const theirs = environment(billing, 'prod');
  const deciding = { workloads: world.workloads };
  const seeing = async (input: Presented & EnvironmentCreate, more: (seen: Seen<Parts>) => Seen<Parts>) => {
    const operation = OPERATIONS['environment.create'](input, deciding) as Operation<Parts, { id: string }>;
    return change(world, { read: operation.read, decide: (seen, at) => operation.decide(more(seen), at) });
  };
  // Another project, live, beside the one named.
  const there = answered(await seeing(adding('ada-cli', 'dev'), (seen) => ({ ...seen, project: [sealed(billing) as never, ...seen.project] })));
  assert.equal((await environmentRow(there.id))!.project_id, market.id);
  // Another project's environment of the parent's slug.
  const fork = answered(await seeing(adding('ada-cli', 'preview', { parent: 'prod' }), (seen) => ({ ...seen, chain: [sealed(theirs) as never, ...seen.chain] })));
  assert.equal((await environmentRow(fork.id))!.parent_id, prod.id);
  // Above the parent, a row of another project under the id the parent names.
  assert.deepEqual(await seeing(adding('ada-cli', 'next', { parent: 'staging' }), (seen) => ({ ...seen, chain: [sealed({ ...theirs, id: prod.id }) as never, ...seen.chain] })), { refused: 'broken_chain' });
  // Another project's environment of the new slug holds no place here, nor, for a fork, a personal config of its parent.
  assert.ok('answer' in (await seeing(adding('ada-cli', 'other'), (seen) => ({ ...seen, taken: [sealed(environment(billing, 'other')) as never] }))));
  assert.ok('answer' in (await seeing(adding('ada-cli', 'again', { parent: 'prod' }), (seen) => ({ ...seen, taken: [sealed(environment(market, 'x', { parentId: prod.id, owner: ada })) as never] }))));
});

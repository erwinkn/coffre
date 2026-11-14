// Keys written in a personal config (`dev@me`, src/ops/secrets.ts's `mine`):
// who may, the config a first value makes, what a bare value is there, and
// that its owner alone then reads it.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, Presented, SecretRefile, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, eve] = [user('ada'), user('bo'), user('cy'), user('eve')];
const api = 'token:api';
let prod: ReturnType<typeof environment>;
let deep: ReturnType<typeof environment>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const market = project('market');
  prod = environment(market, 'prod');
  // Three above it: a config of it would be a fourth.
  const [one, two] = [environment(market, 'one'), environment(market, 'two')];
  const three = environment(market, 'three', { parentId: two.id });
  Object.assign(two, { parentId: one.id });
  deep = environment(market, 'deep', { parentId: three.id });
  const gone = environment(market, 'gone', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const staging = environment(market, 'staging');
  const scope = (role: string) => JSON.stringify([{ projectId: market.id, environmentId: null, role }]);
  await write(world, ...rows('projects', market), ...rows('environments', prod, one, two, three, deep, gone, staging,
    // Bo's config of staging, archived.
    environment(market, 'staging-p-0a0b0c0d', { parentId: staging.id, owner: bo, archivedAt: new Date(Date.UTC(2026, 10, 1)) })),
  ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod'), value(world, secret(prod, 'FLAG'), 'on', { plain: true }), value(world, secret(prod, 'TOKEN'), 'tok', { sensitive: true }),
    value(world, secret(prod, 'SOURCE'), 'src')),
  ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']), role(false, 'contributor', ['secret.use', 'secret.write']),
    role(true, 'member', [])),
  ...rows('principals', principal(ada), principal(bo), principal(cy), principal(eve), principal(api)), ...rows('policy', instance()),
  ...rows('grants', grant(ada, 'developer', { project: market }), grant(bo, 'viewer', { project: market }), grant(cy, 'contributor', { project: market }), grant(api, 'developer', { project: market })),
  ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('eve-cli', eve), credential('api-token', api, { scope: scope('developer') }),
    // A token of Ada's that only reads, and one that writes.
    credential('ada-viewer', ada, { kind: 'personal', scope: scope('viewer') }), credential('ada-developer', ada, { kind: 'personal', scope: scope('developer') }),
    // And two that reach one environment each: prod, whose config they write in, and staging.
    credential('ada-prod', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'developer' }]) }),
    credential('ada-staging', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: staging.id, role: 'developer' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const mine = (label: string, keys: KeyWrite[], more: Partial<SecretWrite> = {}): Presented & SecretWrite => ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', mine: true, keys, ...more });
const typed = (values: Record<string, string>): KeyWrite[] => Object.entries(values).map(([key, item]) => ({ key, value: item }));
const reveal = (label: string, keys: string[], more: Partial<UseInput> = {}): UseInput => ({ ...shown(label), project: 'market', environment: 'prod', mine: true, keys, purpose: 'reveal', upstream: null, ...more });
const given = async (label: string, keys: string[], more: Partial<UseInput> = {}) => {
  // As read now: a use within the vault's memory reads nothing again.
  world.memory.reads.clear();
  const answer = await vault.use(reveal(label, keys, more));
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
const configs = async () => rowsOf<{ slug: string; owner: string; parent: string }>(world.owner, sql`SELECT e.slug, e.owner, p.slug AS parent FROM environments e JOIN environments p ON p.id = e.parent_id WHERE e.owner IS NOT NULL AND e.archived_at IS NULL ORDER BY e.owner`);
const count = async (table: 'log_pending' | 'secret_versions' | 'environments') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};

test("a person's first value in their config of an environment makes it, in the same change, and they alone then read it", async () => {
  // A Viewer keeps a local value: the config takes reading the environment, nothing more.
  assert.deepEqual(await vault.change(mine('bo-cli', typed({ LOCAL: 'mine', DATABASE_URL: 'postgres://bo' }))), { answer: { keys: { LOCAL: { version: 1, nature: 'secret' }, DATABASE_URL: { version: 1, nature: 'secret' } } } });
  const [made] = await configs();
  assert.match(made!.slug, /^prod-p-[0-9a-f]{8}$/);
  assert.deepEqual({ ...made, slug: undefined }, { slug: undefined, owner: bo, parent: 'prod' });
  const entry = await written();
  const [config] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments WHERE owner = ${bo} AND parent_id = ${prod.id}`);
  assert.deepEqual([entry.action, entry.actor, (entry.detail as { personal: string }).personal, (entry.detail as { made: string }).made], ['secret.write', bo, 'prod', made!.slug]);
  // Found from the config's page, and from its environment's.
  assert.ok(entry.objects.includes(`environment:${config!.id}`) && entry.objects.includes(`environment:${prod.id}`), entry.objects.join());
  assert.ok(entry.rows.some(({ row, was }) => (JSON.parse(row) as string[])[0] === 'environments' && was === null), 'the config is a row the change made');
  // Bo reads his own over prod's, and prod's where he holds none; nobody else reads his, an Owner of the project neither.
  assert.deepEqual(await given('bo-cli', ['LOCAL', 'DATABASE_URL', 'FLAG']), ['mine', 'postgres://bo', 'on']);
  assert.deepEqual(await given('ada-cli', ['LOCAL', 'DATABASE_URL']), ['unknown_key', 'postgres://prod']);
  assert.deepEqual(await given('bo-cli', ['DATABASE_URL'], { mine: false }), ['postgres://prod']);

  // The next write is in the same config.
  const before = await count('environments');
  assert.deepEqual(await vault.change(mine('bo-cli', typed({ LOCAL: 'again' }))), { answer: { keys: { LOCAL: { version: 2, nature: 'secret' } } } });
  assert.equal(await count('environments'), before);
  assert.equal((await written()).detail.made, undefined);
  assert.deepEqual(await given('bo-cli', ['LOCAL']), ['again']);
});

test('two first writes at once make one config', async () => {
  const done = await Promise.all([vault.change(mine('ada-cli', typed({ A: '1' }))), vault.change(mine('ada-cli', typed({ B: '2' })))]);
  assert.ok(done.every((answer) => 'answer' in answer), JSON.stringify(done));
  assert.equal((await configs()).length, 1);
  assert.deepEqual(await given('ada-cli', ['A', 'B']), ['1', '2']);
});

test("a value typed with no nature in a config is as strict as what the key reads now, and a plain one stays plain: nobody but its owner lists it", async () => {
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ FLAG: 'off', DATABASE_URL: 'postgres://ada', TOKEN: 'mine', NEW: 'x' }))), {
    answer: { keys: { FLAG: { version: 1, nature: 'plain' }, DATABASE_URL: { version: 1, nature: 'secret' }, TOKEN: { version: 1, nature: 'sensitive' }, NEW: { version: 1, nature: 'secret' } } },
  });
  // Its own plain value stays plain, until a write says otherwise.
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ FLAG: 'on again' }))), { answer: { keys: { FLAG: { version: 2, nature: 'plain' } } } });
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'FLAG', value: 'hidden', nature: 'secret' }])), { answer: { keys: { FLAG: { version: 3, nature: 'secret' } } } });
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ FLAG: 'still hidden' }))), { answer: { keys: { FLAG: { version: 4, nature: 'secret' } } } });
  // Nobody is handed a sensitive value back, in a config either.
  assert.deepEqual(await given('ada-cli', ['FLAG', 'TOKEN']), ['still hidden', 'sensitive']);
});

test('a config is written by its owner alone, a person who reads or uses the environment, as far as their credential reaches there', async () => {
  const before = [await count('log_pending'), await count('environments')];
  assert.deepEqual(await vault.change(mine('api-token', typed({ A: '1' }))), { refused: 'not_a_person' }, 'a service account');
  assert.deepEqual(await vault.change(mine('eve-cli', typed({ A: '1' }))), { refused: 'no_access' }, 'a member with nothing on the environment');
  assert.deepEqual(await vault.change(mine('ada-viewer', typed({ A: '1' }))), { refused: 'no_access' }, "a token of Ada's that only reads");
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ A: '1' }), { environment: 'nowhere' })), { refused: 'no_access' }, 'no such environment');
  assert.deepEqual(await vault.change(mine('bo-cli', typed({ A: '1' }), { environment: 'gone' })), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ A: '1' }), { environment: 'deep' })), { refused: 'too_deep' }, 'an environment that inherits from three already');
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'A', ref: { project: 'market', environment: 'prod', key: 'SOURCE' } }])), { refused: 'no_access' }, 'a reference, which a config holds none of');
  // Anything but a value, asked of a config they do not have, is of a key that is not there.
  for (const item of [{ key: 'DATABASE_URL', archived: true }, { key: 'DATABASE_URL', folder: 'db' }, { key: 'DATABASE_URL', restore: 1 }, { key: 'DATABASE_URL', inherit: true }] satisfies KeyWrite[]) {
    assert.deepEqual(await vault.change(mine('ada-cli', [item])), { refused: 'unknown_key' }, JSON.stringify(item));
  }
  assert.equal(await count('environments'), before[1], 'no config is made');
  // A Contributor uses the environment, which is enough; and Ada's token that writes, writes hers.
  assert.ok('answer' in (await vault.change(mine('cy-cli', typed({ A: '1' })))));
  assert.ok('answer' in (await vault.change(mine('ada-developer', typed({ A: '1' })))));
  assert.deepEqual((await configs()).map((row) => row.owner), [ada, cy]);
  // And once it is there, a token that only reads still writes nothing in it.
  assert.deepEqual(await vault.change(mine('ada-viewer', typed({ A: '2' }))), { refused: 'no_access' });
  assert.deepEqual(await given('ada-viewer', ['A']), ['1'], 'though it reads it');
});

test("a credential scoped to one environment writes in its owner's config of that environment, and of no other", async () => {
  assert.deepEqual(await vault.change(mine('ada-staging', typed({ A: '1' }))), { refused: 'no_access' }, 'a token that reaches staging alone');
  assert.deepEqual(await configs(), [], 'no config is made');
  assert.ok('answer' in (await vault.change(mine('ada-prod', typed({ A: '1' })))));
  assert.deepEqual(await vault.change(mine('ada-staging', typed({ A: '2' }))), { refused: 'no_access' }, 'nor once the config is there');
  assert.deepEqual(await given('ada-prod', ['A']), ['1']);
});

test("a config's keys are archived, brought back, filed, restored and refiled as anywhere, by its owner", async () => {
  await vault.change(mine('ada-cli', typed({ A: 'one' })));
  await vault.change(mine('ada-cli', typed({ A: 'two', B: 'b' })));
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'A', restore: 1 }])), { answer: { keys: { A: { version: 3, nature: 'secret' } } } });
  assert.deepEqual(await given('ada-cli', ['A']), ['one']);
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'A', folder: 'local' }, { key: 'B', folder: 'local' }])), { answer: { keys: {} } });
  const refile = (label: string, more: Partial<SecretRefile> = {}): Presented & SecretRefile => ({ ...shown(label), op: 'secret.refile', project: 'market', environment: 'prod', mine: true, folder: 'local', to: 'mine', ...more });
  assert.deepEqual(await vault.change(refile('ada-cli')), { answer: { moved: ['A', 'B'] } });
  assert.equal((await written()).detail.personal, 'prod');
  // Bo has no config, so no folder, prod's own neither, which a Viewer files nothing in; a service account none at all; and prod's own folders are not hers.
  assert.deepEqual(await vault.change({ ...mine('ada-cli', [{ key: 'DATABASE_URL', folder: 'shared' }]), mine: false }), { answer: { keys: {} } });
  assert.deepEqual(await vault.change(refile('bo-cli', { folder: 'shared' })), { refused: 'no_folder' });
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT folder FROM secrets WHERE environment_id = ${prod.id} AND key = 'DATABASE_URL'`), [{ folder: 'shared' }]);
  assert.deepEqual(await vault.change(refile('bo-cli', { folder: 'mine' })), { refused: 'no_folder' });
  assert.deepEqual(await vault.change(refile('api-token', { folder: 'mine' })), { refused: 'not_a_person' });
  assert.deepEqual(await vault.change(refile('ada-viewer', { folder: 'mine' })), { refused: 'no_access' });
  assert.deepEqual(await vault.change(refile('ada-cli', { folder: 'mine', mine: false })), { refused: 'no_folder' });
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'A', archived: true }])), { answer: { keys: {} } });
  assert.deepEqual(await given('ada-cli', ['A']), ['unknown_key']);
  assert.deepEqual(await vault.change(mine('ada-cli', [{ key: 'A', archived: false }])), { answer: { keys: {} } });
  assert.deepEqual(await given('ada-cli', ['A', 'B']), ['one', 'b']);
  const keys = await rowsOf(world.owner, sql`SELECT s.key, s.folder FROM secrets s JOIN environments e ON e.id = s.environment_id WHERE e.owner = ${ada} ORDER BY s.key`);
  assert.deepEqual(keys, [{ key: 'A', folder: 'mine' }, { key: 'B', folder: 'mine' }]);
});

test('a config whose row was edited behind the vault is not made again beside it, nor written in', async () => {
  await vault.change(mine('ada-cli', typed({ A: 'one' })));
  await world.owner.execute(sql`UPDATE environments SET name = 'mine!' WHERE owner = ${ada}`);
  const before = [await count('environments'), await count('secret_versions')];
  assert.deepEqual(await vault.change(mine('ada-cli', typed({ A: 'two', B: 'b' }))), { refused: 'unreadable' });
  assert.deepEqual(await vault.change({ ...shown('ada-cli'), op: 'secret.refile', project: 'market', environment: 'prod', mine: true, folder: 'x', to: null }), { refused: 'unreadable' });
  assert.deepEqual([await count('environments'), await count('secret_versions')], before);
});

test('an archived config is written in no more than an archived environment, nor made again beside it', async () => {
  const before = await count('environments');
  assert.deepEqual(await vault.change(mine('bo-cli', typed({ A: '1' }), { environment: 'staging' })), { refused: 'no_access' });
  assert.equal(await count('environments'), before);
  // And named by its own slug, a config is no environment to write in.
  assert.deepEqual(await vault.change({ ...mine('bo-cli', typed({ A: '1' })), environment: 'staging-p-0a0b0c0d', mine: false }), { refused: 'no_access' });
});

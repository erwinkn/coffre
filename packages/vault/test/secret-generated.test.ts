// A value a client generated (src/ops/secrets.ts's `secret.write`, 0.14's
// `generated` and `replaces`): the recipe and the key pair on the key's
// sealed row, never plain, and a regenerate written only over the version
// it was listed with, own or inherited.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, Presented, SecretWrite } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, dismissed, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo] = [user('ada'), user('bo')];
const places: Record<string, ReturnType<typeof environment>> = {};
const PAIR = { private: 'JWT_PRIVATE_KEY', public: 'JWT_PUBLIC_KEY' };
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const market = project('market');
  const billing = project('billing');
  const prod = environment(market, 'prod');
  // Staging inherits prod's keys; EU, a fork of it, does without prod's TOKEN.
  const staging = environment(market, 'staging', { parentId: prod.id });
  const eu = environment(market, 'eu', { parentId: staging.id });
  const adas = environment(market, 'prod-p-0a0b0c0d', { parentId: prod.id, owner: ada });
  const there = environment(billing, 'prod');
  Object.assign(places, { prod, staging, eu, adas });
  const source = value(world, secret(there, 'STRIPE_KEY'), 'sk_live');
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, staging, eu, adas, there),
    ...rows('secrets', { ...value(world, secret(prod, 'TOKEN'), 'tok-1'), recipe: 'bytes:32:hex' }, value(world, secret(prod, 'DATABASE_URL'), 'postgres://old'),
      value(world, secret(prod, 'SHOWN'), 'shown', { sensitive: true }), source, secret(prod, 'REF', { sourceId: source.id }),
      value(world, secret(adas, 'LOCAL'), 'on', { plain: true })),
    ...rows('dismissedKeys', dismissed(eu, 'TOKEN')),
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(ada, 'developer', { project: billing }), grant(bo, 'viewer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (keys: KeyWrite[], more: Partial<SecretWrite> = {}, label = 'ada-cli'): Presented & SecretWrite =>
  ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', keys, ...more });
const made = (recipe: string, pair?: typeof PAIR) => ({ recipe, ...(pair === undefined ? {} : { pair }) });
/** How a key's row says its value is kept and was made. */
const said = async (place: string, key: string) => (await rowsOf<{ version: number | null; nature: string | null; recipe: string | null; pair: string | null; half: string | null }>(world.owner,
  sql`SELECT current_version AS version, nature, recipe, pair_id AS pair, pair_half AS half FROM secrets WHERE environment_id = ${places[place]!.id} AND key = ${key}`))[0];
/** The id of a key's current version, as a listing gives it (`versionId`). */
const listed = async (place: string, key: string) => (await rowsOf<{ id: string }>(world.owner,
  sql`SELECT v.id FROM secret_versions v JOIN secrets s ON s.id = v.secret_id AND v.version = s.current_version WHERE s.environment_id = ${places[place]!.id} AND s.key = ${key}`))[0]!.id;
/** The keys a write answers, which it must not refuse. */
const written = async (pending: ReturnType<typeof vault.change<'secret.write'>>) => {
  const got = await pending;
  assert.ok('answer' in got, JSON.stringify(got));
  return got.answer.keys;
};
const versions = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM secret_versions`))[0]!.n;
/** The newest kept entry's lines, each without its secret's id. */
const lines = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return (entryOf(world.keys, row!)!.detail as { keys: Record<string, unknown>[] }).keys.map(({ secret: _, ...line }) => line);
};
const opened = async (environment: string, keys: string[]) => {
  world.memory.reads.clear();
  const answer = await vault.use({ ...shown('ada-cli'), project: 'market', environment, mine: false, keys, purpose: 'run', upstream: null });
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};

test('a value a client made is kept with its recipe, a secret unless said sensitive, and a key pair\'s halves with one id between them; the entry says how', async () => {
  const keys: KeyWrite[] = [
    { key: 'NEW', value: 'abc', generated: made('bytes:32:hex') },
    { key: PAIR.private, value: 'private', nature: 'sensitive', generated: made('ecdsa:p-256', PAIR) },
    { key: PAIR.public, value: 'public', generated: made('ecdsa:p-256', PAIR) },
  ];
  assert.deepEqual(await vault.change(writing(keys)), { answer: {
    keys: { NEW: { version: 1, nature: 'secret' }, [PAIR.private]: { version: 1, nature: 'sensitive' }, [PAIR.public]: { version: 1, nature: 'secret' } },
    outcomes: { NEW: 'added', [PAIR.private]: 'added', [PAIR.public]: 'added' },
  } });
  const [one, priv, pub] = [await said('prod', 'NEW'), await said('prod', PAIR.private), await said('prod', PAIR.public)];
  assert.deepEqual(one, { version: 1, nature: 'secret', recipe: 'bytes:32:hex', pair: null, half: null });
  assert.ok(priv!.pair !== null);
  assert.deepEqual([priv, pub], [{ version: 1, nature: 'sensitive', recipe: 'ecdsa:p-256', pair: priv!.pair, half: 'private' }, { version: 1, nature: 'secret', recipe: 'ecdsa:p-256', pair: priv!.pair, half: 'public' }]);
  assert.deepEqual(await lines(), [
    { key: 'NEW', version: 1, nature: 'secret', made: true, recipe: 'bytes:32:hex' },
    { key: PAIR.private, version: 1, nature: 'sensitive', made: true, recipe: 'ecdsa:p-256', pair: priv!.pair, half: 'private' },
    { key: PAIR.public, version: 1, nature: 'secret', made: true, recipe: 'ecdsa:p-256', pair: priv!.pair, half: 'public' },
  ]);
  assert.deepEqual(await opened('prod', ['NEW', PAIR.public]), ['abc', 'public']);
  // Made again, the pair is a new one: the halves of the first are no more.
  await vault.change(writing(keys.slice(1)));
  const again = await said('prod', PAIR.private);
  assert.ok(again!.pair !== null && again!.pair !== priv!.pair && (await said('prod', PAIR.public))!.pair === again!.pair);
  // A value generated is new by its making, even over a typed value of that same text: a dry run never compares it.
  assert.deepEqual(await vault.weigh(writing([{ key: 'DATABASE_URL', value: 'postgres://old', generated: made('bytes:16:hex') }])),
    { answer: { keys: { DATABASE_URL: { version: 2, nature: 'secret' } }, outcomes: { DATABASE_URL: 'changed' } } });
});

test('a value generated with no nature is never plain: a secret over a plain one, a personal config\'s included, and sensitive over a sensitive one', async () => {
  assert.deepEqual(await vault.change(writing([{ key: 'LOCAL', value: 'typed' }], { mine: true })), { answer: { keys: { LOCAL: { version: 2, nature: 'plain' } }, outcomes: { LOCAL: { compare: { secret: (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE key = 'LOCAL'`))[0]!.id, version: 1 } } } } });
  assert.deepEqual(await written(vault.change(writing([{ key: 'LOCAL', value: 'made', generated: made('bytes:8:hex') }], { mine: true }))), { LOCAL: { version: 3, nature: 'secret' } });
  assert.deepEqual(await written(vault.change(writing([{ key: 'SHOWN', value: 'made', generated: made('bytes:8:hex') }]))), { SHOWN: { version: 2, nature: 'sensitive' } });
});

test('a value that replaces a version is written only over the version the key holds now: anything else is stale, and writes nothing', async () => {
  const first = await listed('prod', 'TOKEN');
  const regenerate = (replaces: string, key = 'TOKEN', environment = 'prod') => vault.change(writing([{ key, value: 'next', generated: made('bytes:32:hex'), replaces }], { environment }));
  assert.deepEqual(await written(regenerate(first)), { TOKEN: { version: 2, nature: 'secret' } });
  assert.deepEqual(await said('prod', 'TOKEN'), { version: 2, nature: 'secret', recipe: 'bytes:32:hex', pair: null, half: null });
  const before = await versions();
  // The version listed is no longer the key's; another key's; one there never was; a reference's, which holds none.
  for (const [key, replaces] of [['TOKEN', first], ['TOKEN', await listed('prod', 'DATABASE_URL')], ['TOKEN', '00000000-0000-4000-8000-000000000000'], ['REF', first]] as const) {
    assert.deepEqual(await regenerate(replaces, key), { refused: 'stale' }, key);
  }
  // One stale key refuses the whole write.
  const stale = await vault.change(writing([{ key: 'DATABASE_URL', value: 'x' }, { key: 'TOKEN', value: 'y', generated: made('bytes:32:hex'), replaces: first }]));
  assert.deepEqual(stale, { refused: 'stale' });
  assert.equal(await versions(), before);
  // A typed value says it too, and is held to it alike.
  const url = await listed('prod', 'DATABASE_URL');
  assert.deepEqual(await written(vault.change(writing([{ key: 'DATABASE_URL', value: 'postgres://new', replaces: url }]))), { DATABASE_URL: { version: 2, nature: 'secret' } });
  assert.deepEqual(await vault.change(writing([{ key: 'DATABASE_URL', value: 'postgres://newer', replaces: url }])), { refused: 'stale' });
  // A key archived since it was listed reads that version no more: the listing is stale, as in 0.14.7, and writes nothing.
  const current = await listed('prod', 'TOKEN');
  await vault.change(writing([{ key: 'TOKEN', archived: true }]));
  const archived = await versions();
  assert.deepEqual(await regenerate(current), { refused: 'stale' });
  assert.equal(await versions(), archived);
  // Without a version to replace, an archived key is brought back first, as for any value.
  assert.deepEqual(await vault.change(writing([{ key: 'TOKEN', value: 'typed' }])), { refused: 'archived' });
});

test('a value that replaces no version is written only where the key reads none and is no reference; one that replaces a reference, only over that one', async () => {
  const before = await versions();
  // A value here, and in a fork one inherited, refuse it, and nothing is written.
  assert.deepEqual(await vault.change(writing([{ key: 'TOKEN', value: 'over', replaces: null }])), { refused: 'stale' });
  assert.deepEqual(await vault.change(writing([{ key: 'TOKEN', value: 'over', replaces: null }], { environment: 'staging' })), { refused: 'stale' });
  assert.equal(await versions(), before);
  // A new key takes it; a reference, which holds no value of its own, is named by its source, and only that one.
  const [{ id: source }] = await rowsOf<{ id: string }>(world.owner, sql`SELECT source_id::text AS id FROM secrets WHERE environment_id = ${places.prod!.id} AND key = 'REF'`);
  assert.deepEqual(await vault.change(writing([{ key: 'FRESH', value: 'first', replaces: { source: source! } }])), { refused: 'stale' }, 'none there');
  assert.deepEqual(await written(vault.change(writing([{ key: 'FRESH', value: 'first', replaces: null }]))), { FRESH: { version: 1, nature: 'secret' } });
  for (const replaces of [null, { source: '00000000-0000-4000-8000-000000000000' }]) {
    assert.deepEqual(await vault.change(writing([{ key: 'REF', value: 'own', replaces }])), { refused: 'stale' }, JSON.stringify(replaces));
  }
  assert.equal(await versions(), before + 1);
  assert.deepEqual(await written(vault.change(writing([{ key: 'REF', value: 'own', replaces: { source: source! } }]))), { REF: { version: 1, nature: 'secret' } });
  // The second of two such writes finds the first's value.
  assert.deepEqual(await vault.change(writing([{ key: 'FRESH', value: 'second', replaces: null }])), { refused: 'stale' });
  assert.deepEqual(await opened('prod', ['FRESH']), ['first']);
});

test('in a fork, a value replaces the version it inherits while it holds none of its own, unless it dismissed the key', async () => {
  const prods = await listed('prod', 'TOKEN');
  const regenerate = (environment: string, replaces = prods) => vault.change(writing([{ key: 'TOKEN', value: `${environment}-next`, generated: made('bytes:32:hex'), replaces }], { environment }));
  // EU does without prod's TOKEN: it reads nothing there to regenerate.
  assert.deepEqual(await regenerate('eu'), { refused: 'stale' });
  assert.deepEqual(await written(regenerate('staging')), { TOKEN: { version: 1, nature: 'secret' } });
  assert.deepEqual(await said('staging', 'TOKEN'), { version: 1, nature: 'secret', recipe: 'bytes:32:hex', pair: null, half: null });
  assert.deepEqual([await opened('prod', ['TOKEN']), await opened('staging', ['TOKEN'])], [['tok-1'], ['staging-next']]);
  // Staging holds its own now: prod's version is not the one it reads.
  assert.deepEqual(await regenerate('staging'), { refused: 'stale' });
  // Reset to prod's, it reads prod's again, and replaces that one.
  assert.ok('answer' in await vault.change(writing([{ key: 'TOKEN', inherit: true }], { environment: 'staging' })));
  assert.deepEqual(await regenerate('staging', await listed('staging', 'TOKEN')), { refused: 'stale' });
  assert.deepEqual(await written(regenerate('staging')), { TOKEN: { version: 2, nature: 'secret' } });
});

test('a fork whose parent was archived since its key was listed reads nothing through it, and regenerates nothing', async () => {
  // Archived with a fork below it, as 0.14 let a database hold; the vault itself refuses that archiving (`inherited`).
  const gone = environment({ id: places.prod!.projectId }, 'gone', { archivedAt: new Date('2026-01-01T00:00:00Z') });
  const below = environment({ id: places.prod!.projectId }, 'below', { parentId: gone.id });
  Object.assign(places, { gone, below });
  await write(world, ...rows('environments', gone, below), ...rows('secrets', value(world, secret(gone, 'TOKEN'), 'tok-gone')));
  const before = await versions();
  const answer = await vault.change(writing([{ key: 'TOKEN', value: 'below-next', generated: made('bytes:32:hex'), replaces: await listed('gone', 'TOKEN') }], { environment: 'below' }));
  assert.deepEqual(answer, { refused: 'stale' });
  assert.equal(await versions(), before);
  assert.equal(await said('below', 'TOKEN'), undefined);
});

test('two regenerates of one version at once: one writes, and the other, decided again on what the first left, is stale', async () => {
  const replaces = await listed('prod', 'TOKEN');
  const both = await Promise.all(['a', 'b'].map((text) => vault.change(writing([{ key: 'TOKEN', value: text, generated: made('bytes:32:hex'), replaces }]))));
  assert.deepEqual(both.map((answer) => ('refused' in answer ? answer.refused : answer.answer.keys.TOKEN!.version)).sort(), [2, 'stale']);
  assert.equal((await said('prod', 'TOKEN'))!.version, 2);
});

test('a row a regenerate is decided on, edited behind the vault, refuses it rather than be taken for what it said', async () => {
  const replaces = await listed('prod', 'TOKEN');
  await world.owner.execute(sql`UPDATE secrets SET recipe = 'bytes:1:hex' WHERE environment_id = ${places.prod!.id} AND key = 'TOKEN'`);
  // Prod's own, and the one staging inherits: neither is read as the version it was.
  for (const environment of ['prod', 'staging']) {
    assert.deepEqual(await vault.change(writing([{ key: 'TOKEN', value: 'next', nature: 'secret', generated: made('bytes:32:hex'), replaces }], { environment })), { refused: 'unreadable' }, environment);
  }
  // Whoever does not write there is told so, whatever the key.
  assert.deepEqual(await vault.change(writing([{ key: 'DATABASE_URL', value: 'x', generated: made('bytes:32:hex') }], {}, 'bo-cli')), { refused: 'no_access' });
});

test('a generated value that is not what the contract says is a fault, before any read', async () => {
  const item = (more: Record<string, unknown>) => ({ key: PAIR.private, value: 'x', ...more }) as KeyWrite;
  const half = { key: PAIR.public, value: 'y', generated: made('ecdsa:p-256', PAIR) } as KeyWrite;
  const bad: KeyWrite[][] = [
    // Plain; a recipe not as it is kept, or none; a pair of a recipe that makes one value; a pair's recipe with none.
    [item({ nature: 'plain', generated: made('bytes:32:hex') })], [item({ generated: made('BYTES:32') })], [item({ generated: made('bytes:32') })], [item({ generated: made('nope') })], [item({ generated: {} })], [item({ generated: 'bytes:32:hex' })],
    [item({ generated: made('bytes:32:hex', PAIR) }), { ...half, generated: made('bytes:32:hex', PAIR) } as KeyWrite], [item({ generated: made('ecdsa:p-256') }), half],
    // A pair written in half, of two recipes, naming another pair, naming no key of its own, or one key twice.
    [item({ generated: made('ecdsa:p-256', PAIR) })], [item({ generated: made('ecdsa:p-384', PAIR) }), half], [item({ generated: made('ecdsa:p-256', { ...PAIR, public: 'OTHER' }) }), half],
    [{ key: 'OTHER', value: 'x', generated: made('ecdsa:p-256', PAIR) } as KeyWrite, half], [item({ generated: made('ecdsa:p-256', { private: PAIR.private, public: PAIR.private }) })],
    // A version replaced that is no UUID, or by anything but a value.
    [item({ replaces: 'v1' })], [item({ replaces: '0A000000-0000-4000-8000-000000000000' })], [{ key: 'TOKEN', restore: 1, replaces: '00000000-0000-4000-8000-000000000000' } as unknown as KeyWrite],
    [{ key: 'TOKEN', restore: 1, generated: made('bytes:32:hex') } as unknown as KeyWrite], [{ key: 'TOKEN', archived: true, generated: made('bytes:32:hex') } as unknown as KeyWrite],
    [{ key: 'TOKEN', inherit: true, replaces: '00000000-0000-4000-8000-000000000000' } as unknown as KeyWrite],
  ];
  for (const keys of bad) await assert.rejects(vault.change(writing(keys)), TypeError, JSON.stringify(keys).slice(0, 120));
  assert.equal(world.woken.length, 0);
});

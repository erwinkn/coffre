// What a write does to a key besides its value (src/ops/secrets.ts):
// archiving it and bringing it back, and filing it in a folder. Through the
// contract, as the app calls it.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, Presented, SecretRefile, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { environments, projects, secrets } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee] = [user('ada'), user('bo'), user('cy'), user('dee')];
let url: { id: string };
let stripe: { id: string };
let held: { id: string };
let primary: { id: string };
let prod: ReturnType<typeof environment>;
let market: ReturnType<typeof project>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  const billing = project('billing');
  prod = environment(market, 'prod');
  const there = environment(billing, 'prod');
  const source = (stripe = value(world, secret(there, 'STRIPE_KEY'), 'sk_live'));
  const database = (url = value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod'));
  const reference = (held = secret(prod, 'STRIPE_KEY', { sourceId: source.id }));
  const read = (primary = value(world, secret(prod, 'PRIMARY'), 'postgres://primary'));
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, there),
    ...rows('secrets', database, source, reference, read, secret(prod, 'ALIAS', { sourceId: read.id }), secret(prod, 'OLD', { archivedAt: new Date(Date.UTC(2026, 10, 1)) })),
    // A maintainer archives and brings back; a developer writes and files, and archives nothing; a releaser archives, and reads nothing, so brings nothing back.
    ...rows('roles', role(false, 'maintainer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']),
      role(false, 'releaser', ['secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read', 'secret.use']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: market }), grant(ada, 'maintainer', { project: billing }), grant(bo, 'developer', { project: market }), grant(cy, 'releaser', { project: market }), grant(dee, 'viewer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (label: string, keys: KeyWrite[], more: Partial<SecretWrite> = {}): Presented & SecretWrite => ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', keys, ...more });
const reveal = (keys: string[], place: Partial<UseInput> = {}): UseInput => ({ ...shown('ada-cli'), project: 'market', environment: 'prod', mine: false, keys, purpose: 'reveal', upstream: null, ...place });
/** Rows of a table: of the log, the entries kept, which are what a change wrote, not the refusals logged. */
const count = async (table: 'log_pending' | 'secret_versions') => (await rowsOf<{ n: number }>(world.owner, table === 'log_pending' ? sql`SELECT count(*)::int AS n FROM log_pending WHERE kept` : sql`SELECT count(*)::int AS n FROM secret_versions`))[0]!.n;
const denied = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`)).map((row) => entryOf(world.keys, row)!);
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
const lines = async () => ((await written()).detail as { keys: Record<string, unknown>[] }).keys.map(({ secret: _, ...line }) => line);
const given = async (keys: string[], place: Partial<UseInput> = {}) => {
  world.tick(2000);
  const answer = await vault.use(reveal(keys, place));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
const key = async (name: string, where = prod.id) => (await rowsOf<{ archived: boolean; folder: string | null; versions: number }>(world.owner, sql`SELECT archived_at IS NOT NULL AS archived, folder, versions FROM secrets WHERE environment_id = ${where} AND key = ${name}`))[0];
/** Nothing written since `before`: no entry kept, no version. */
const nothing = async (before: number[]) => assert.deepEqual([await count('log_pending'), await count('secret_versions')], before);

test('a key archived serves nothing and keeps its versions; brought back, it serves its value again', async () => {
  const versions = await count('secret_versions');
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', archived: true }])), { answer: { keys: {} } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', archived: true }]);
  assert.deepEqual([await key('DATABASE_URL'), await count('secret_versions')], [{ archived: true, folder: null, versions: 1 }, versions]);
  assert.deepEqual(await given(['DATABASE_URL']), ['unknown_key']);

  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', archived: false }])), { answer: { keys: {} } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', archived: false }]);
  assert.deepEqual(await given(['DATABASE_URL']), ['postgres://prod']);

  // Archived already, a key is not archived again: the entry has no line for it, and nothing is written.
  const entries = await count('log_pending');
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'OLD', archived: true }, { key: 'DATABASE_URL', archived: true }])), { answer: { keys: {} } });
  assert.deepEqual([await lines(), await count('log_pending')], [[{ key: 'DATABASE_URL', archived: true }], entries + 1]);
  const [entry] = [await written()];
  assert.deepEqual(entry.rows.filter(({ was, now }) => was !== now).length, 1, 'one row replaced');
});

test('a value is written over an archived key only as it is brought back, which takes reading it', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'OLD', value: 'v', nature: 'secret' }])), { refused: 'archived' });
  // A releaser archives, and does not read: what it would bring back it could not have read.
  assert.deepEqual(await vault.change(writing('cy-cli', [{ key: 'OLD', value: 'v', nature: 'secret', archived: false }])), { refused: 'no_access' });
  assert.deepEqual(await vault.change(writing('cy-cli', [{ key: 'OLD', archived: false }])), { refused: 'no_access' });
  // A developer writes, and archives nothing, nor brings anything back.
  assert.deepEqual(await vault.change(writing('bo-cli', [{ key: 'DATABASE_URL', archived: true }])), { refused: 'no_access' });
  assert.deepEqual(await vault.change(writing('bo-cli', [{ key: 'OLD', archived: false }])), { refused: 'no_access' });
  // A viewer files nothing.
  assert.deepEqual(await vault.change(writing('dee-cli', [{ key: 'DATABASE_URL', folder: 'db' }])), { refused: 'no_access' });
  // One key the caller may not change refuses them all.
  assert.deepEqual(await vault.change(writing('bo-cli', [{ key: 'NEW', value: 'v', nature: 'secret' }, { key: 'DATABASE_URL', archived: true }])), { refused: 'no_access' });
  await nothing(before);
  // Each who was refused is logged, once in the minute, with the first reason.
  assert.deepEqual((await denied()).map((entry) => [entry.actor, entry.detail]), [
    [ada, { project: 'market', environment: 'prod', refused: 'archived' }],
    [cy, { project: 'market', environment: 'prod', refused: 'no_access' }],
    [bo, { project: 'market', environment: 'prod', refused: 'no_access' }],
    [dee, { project: 'market', environment: 'prod', refused: 'no_access' }],
  ]);

  assert.deepEqual(await vault.change(writing('cy-cli', [{ key: 'DATABASE_URL', archived: true }])), { answer: { keys: {} } });
  // Nor does a key with a value come back to one who archives it and does not read it.
  assert.deepEqual(await vault.change(writing('cy-cli', [{ key: 'DATABASE_URL', archived: false }])), { refused: 'no_access' });
  assert.deepEqual(await key('DATABASE_URL'), { archived: true, folder: null, versions: 1 });
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'OLD', value: 'back', nature: 'secret', archived: false }])), { answer: { keys: { OLD: { version: 1, nature: 'secret' } } } });
  assert.deepEqual(await lines(), [{ key: 'OLD', version: 1, nature: 'secret', archived: false }]);
  assert.deepEqual(await given(['OLD']), ['back']);
});

test('only a value makes a key: archiving, bringing back or filing one the environment lacks is refused, and writes nothing', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  for (const item of [{ key: 'NONE', archived: true }, { key: 'NONE', archived: false }, { key: 'NONE', folder: 'db' }] satisfies KeyWrite[]) {
    assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', folder: 'db' }, item])), { refused: 'unknown_key' }, JSON.stringify(item));
  }
  // Nor is a key of another environment of the project one of this one's.
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', archived: true }], { project: 'billing' })), { refused: 'unknown_key' });
  await nothing(before);
});

test('a key read by a reference is not archived while the reference reads it: from another project, or beside it, unless archived together', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'STRIPE_KEY', archived: true }], { project: 'billing' })), { refused: 'referenced' });
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'PRIMARY', archived: true }])), { refused: 'referenced' });
  await nothing(before);
  // A reference brought back in the write that archives its source reads it again: refused.
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'ALIAS', archived: true }]))));
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'ALIAS', archived: false }, { key: 'PRIMARY', archived: true }])), { refused: 'referenced' });
  assert.deepEqual([await key('ALIAS'), await key('PRIMARY')], [{ archived: true, folder: null, versions: 0 }, { archived: false, folder: null, versions: 1 }]);
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'ALIAS', archived: false }]))));
  // Archived with the key that reads it, or once that key holds a value of its own.
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'PRIMARY', archived: true }, { key: 'ALIAS', archived: true }]))));
  assert.deepEqual(await lines(), [{ key: 'PRIMARY', archived: true }, { key: 'ALIAS', archived: true }]);
  // Brought back alone, the reference reads an archived key: archiving that key again changes nothing, and is not refused.
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'ALIAS', archived: false }]))));
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'PRIMARY', archived: true }, { key: 'DATABASE_URL', folder: 'db' }]))));
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', folder: 'db' }]);
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'PRIMARY', archived: false }]))));
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'PRIMARY', archived: true }, { key: 'ALIAS', value: 'own', nature: 'secret' }]))));
  assert.deepEqual(await lines(), [{ key: 'PRIMARY', archived: true }, { key: 'ALIAS', version: 1, nature: 'secret', source: primary.id }]);
});

test('a reference held where nothing reads it any more stops no archive, and one whose place is not found does', async () => {
  const archive = () => vault.change(writing('ada-cli', [{ key: 'STRIPE_KEY', archived: true }], { project: 'billing' }));
  const back = () => vault.change(writing('ada-cli', [{ key: 'STRIPE_KEY', archived: false }], { project: 'billing' }));
  // Its key archived.
  await amend(world, 'secrets', eq(secrets.id, held.id), { archivedAt: new Date(world.now()) });
  assert.ok('answer' in (await archive()));
  assert.ok('answer' in (await back()));
  await amend(world, 'secrets', eq(secrets.id, held.id), { archivedAt: null });
  assert.deepEqual(await archive(), { refused: 'referenced' });
  // Its environment archived, then deleted, then put back.
  await amend(world, 'environments', eq(environments.id, prod.id), { archivedAt: new Date(world.now()) });
  assert.ok('answer' in (await archive()));
  assert.ok('answer' in (await back()));
  await amend(world, 'environments', eq(environments.id, prod.id), { archivedAt: null, slug: 'prod~1' });
  assert.ok('answer' in (await archive()));
  assert.ok('answer' in (await back()));
  await amend(world, 'environments', eq(environments.id, prod.id), { slug: 'prod' });
  // Its project archived.
  await amend(world, 'projects', eq(projects.id, market.id), { archivedAt: new Date(world.now()) });
  assert.ok('answer' in (await archive()));
  assert.ok('answer' in (await back()));
  await amend(world, 'projects', eq(projects.id, market.id), { archivedAt: null });
  // Archived behind the vault's back, its environment's row is no row: not known to be archived, the reference still stops the archive.
  await world.owner.execute(sql`UPDATE environments SET archived_at = now() WHERE id = ${prod.id}`);
  assert.deepEqual(await archive(), { refused: 'referenced' });
  await world.owner.execute(sql`UPDATE projects SET archived_at = now() WHERE id = ${market.id}`);
  assert.deepEqual(await archive(), { refused: 'referenced' });
});

test('a key is filed in a folder, and taken out, by whoever writes it, archived or not; a key made is made in one', async () => {
  assert.deepEqual(await vault.change(writing('bo-cli', [{ key: 'DATABASE_URL', folder: 'db' }, { key: 'OLD', folder: 'db' }, { key: 'NEW', value: 'v', nature: 'plain', folder: 'api keys' }])), { answer: { keys: { NEW: { version: 1, nature: 'plain' } } } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', folder: 'db' }, { key: 'OLD', folder: 'db' }, { key: 'NEW', version: 1, nature: 'plain', made: true, folder: 'api keys' }]);
  assert.deepEqual([await key('DATABASE_URL'), await key('OLD'), await key('NEW')], [{ archived: false, folder: 'db', versions: 1 }, { archived: true, folder: 'db', versions: 0 }, { archived: false, folder: 'api keys', versions: 1 }]);
  // Filed, an archived key keeps the date it was archived on.
  const since = async () => (await rowsOf<{ at: string }>(world.owner, sql`SELECT archived_at::text AS at FROM secrets WHERE environment_id = ${prod.id} AND key = 'OLD'`))[0]!.at;
  const archivedOn = await since();
  world.tick(60_000);
  assert.ok('answer' in (await vault.change(writing('bo-cli', [{ key: 'OLD', folder: 'old' }]))));
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'OLD', folder: 'db', archived: true }]))));
  assert.deepEqual([await lines(), await since()], [[{ key: 'OLD', folder: 'db' }], archivedOn]);
  // Filed where it is, a key is not filed again; out of its folder, it is in none.
  assert.ok('answer' in (await vault.change(writing('bo-cli', [{ key: 'DATABASE_URL', folder: 'db' }, { key: 'OLD', folder: null }]))));
  assert.deepEqual([await lines(), (await key('OLD'))!.folder], [[{ key: 'OLD', folder: null }], null]);
  // A value written keeps the key where it is filed.
  assert.ok('answer' in (await vault.change(writing('bo-cli', [{ key: 'DATABASE_URL', value: 'x', nature: 'secret' }]))));
  assert.equal((await key('DATABASE_URL'))!.folder, 'db');
  // Filing changes nothing a use gives.
  assert.deepEqual(await given(['DATABASE_URL', 'NEW']), ['x', 'v']);
});

test('a folder of keys is renamed, merged or emptied whole, archived keys too, by whoever writes there', async () => {
  const refile = (label: string, folder: string, to: string | null, more: Partial<SecretRefile> = {}) =>
    vault.change({ ...shown(label), op: 'secret.refile', project: 'market', environment: 'prod', folder, to, ...more });
  assert.ok('answer' in (await vault.change(writing('bo-cli', [{ key: 'DATABASE_URL', folder: 'db' }, { key: 'OLD', folder: 'db' }, { key: 'PRIMARY', folder: 'replicas' }]))));
  // Bo's personal config of prod, with a key filed: no route files there yet.
  const mine = environment(market, 'prod-bo', { parentId: prod.id, owner: bo });
  await write(world, ...rows('environments', mine), ...rows('secrets', value(world, secret(mine, 'OWN', { folder: 'db' }), 'his')));
  const before = [await count('log_pending'), await count('secret_versions')];
  // A viewer files nothing, and is told no more than for a project or an environment that is not there, or a personal config.
  for (const [label, more] of [['dee-cli', {}], ['bo-cli', { project: 'nope' }], ['bo-cli', { environment: 'staging' }], ['bo-cli', { environment: 'prod-bo' }]] as const) {
    assert.deepEqual(await refile(label, 'db', 'data', more), { refused: 'no_access' });
  }
  // A folder nothing is filed in is no folder, to whoever may file there.
  assert.deepEqual(await refile('bo-cli', 'nope', 'data'), { refused: 'no_folder' });
  await nothing(before);

  assert.deepEqual(await refile('bo-cli', 'db', 'data'), { answer: { moved: ['DATABASE_URL', 'OLD'] } });
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['secret.refile', { folder: 'db', to: 'data', keys: ['DATABASE_URL', 'OLD'] }]);
  assert.deepEqual([await key('DATABASE_URL'), await key('OLD'), await key('PRIMARY')], [{ archived: false, folder: 'data', versions: 1 }, { archived: true, folder: 'data', versions: 0 }, { archived: false, folder: 'replicas', versions: 1 }]);
  // Renamed onto a folder that is there, the two are one.
  assert.deepEqual(await refile('bo-cli', 'replicas', 'data'), { answer: { moved: ['PRIMARY'] } });
  assert.equal((await key('PRIMARY'))!.folder, 'data');
  // Renamed onto itself, nothing moves, and the entry says it was asked.
  const entries = await count('log_pending');
  assert.deepEqual(await refile('bo-cli', 'data', 'data'), { answer: { moved: ['DATABASE_URL', 'OLD', 'PRIMARY'] } });
  assert.equal(await count('log_pending'), entries + 1);
  // A key's row edited behind the vault may be one filed there: none is left behind, so none moves.
  await world.owner.execute(sql`UPDATE secrets SET folder = 'data' WHERE environment_id = ${prod.id} AND key = 'STRIPE_KEY'`);
  assert.deepEqual(await refile('bo-cli', 'data', null), { refused: 'unreadable' });
  assert.equal((await key('DATABASE_URL'))!.folder, 'data');
  await world.owner.execute(sql`UPDATE secrets SET folder = NULL WHERE environment_id = ${prod.id} AND key = 'STRIPE_KEY'`);
  // Emptied, each key stays where it is, in no folder; and that folder is gone.
  assert.deepEqual(await refile('bo-cli', 'data', null), { answer: { moved: ['DATABASE_URL', 'OLD', 'PRIMARY'] } });
  assert.deepEqual([(await key('DATABASE_URL'))!.folder, (await key('OLD'))!.folder, (await key('PRIMARY'))!.folder], [null, null, null]);
  assert.deepEqual(await refile('bo-cli', 'data', null), { refused: 'no_folder' });
  // What the contract does not say is a fault: no folder to rename, or one no folder could be named.
  for (const [folder, to] of [[null, 'x'], ['db', ' x'], ['db', 'a/b'], ['db', undefined], ['', 'x']] as const) {
    await assert.rejects(refile('bo-cli', folder as never, to as never), TypeError, `${folder} ${to}`);
  }
});

test('an item that is not what the contract says is a fault, before any read', async () => {
  const bad: unknown[][] = [
    [{ key: 'A' }], [{ key: 'A', archived: true, value: 'x', nature: 'secret' }], [{ key: 'A', archived: 'yes' }], [{ key: 'A', nature: 'secret', archived: true }],
    [{ key: 'A', value: 'x', nature: 'hidden' }],
    ...['', ' db', 'db ', 'a/b', 'a\nb', 'x'.repeat(65), '\u00a0db', '\u{1f5c2}'.repeat(33), 7, '\ud83d'].map((folder) => [{ key: 'A', folder }]),
  ];
  for (const keys of bad) await assert.rejects(vault.change(writing('ada-cli', keys as KeyWrite[])), TypeError, JSON.stringify(keys).slice(0, 80));
  assert.equal(world.woken.length, 0);
  // What the contract does say: a folder of 64 characters.
  assert.ok('answer' in (await vault.change(writing('ada-cli', [{ key: 'A', value: 'x', nature: 'secret', folder: 'é'.repeat(64) }]))));
});

// A key's nature marked in place (src/ops/secrets.ts, a `nature` alone,
// `coffre mark`), held to what 0.14.7's sensitive-values.test.ts,
// plain-values.test.ts and owner-powers.test.ts asserted: stricter by
// whoever writes keys there, its value kept as the key's next version,
// which the engine opens and seals again; a sensitive value made a secret
// by an Owner of the project alone, logged `secret.loosen`; plain never.
// Only the environment's own live values are marked. A restore comes back
// no looser than its value's newest copy. And what one change copies is
// bounded by bytes as stored (change.ts, `MOST_COPIED`), weighed before
// any value is read.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { open } from '@coffre/core/envelope';
import { KekUnavailableError } from '@coffre/core/kek';
import type { Nature, Presented, SecretWrite } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { environments, secrets, secretVersions } from '@coffre/db/schema';
import { and, eq, sql } from 'drizzle-orm';

import { change, commit, copying, MOST_COPIED, part, prepare, put, readParts, type Prepared } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { contextOf } from '../src/value.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const day = 86_400_000;
const [ada, bo, cy, dee, fay, gil] = ['ada', 'bo', 'cy', 'dee', 'fay', 'gil'].map(user) as [string, string, string, string, string, string];
const archivedAt = new Date(Date.UTC(2026, 10, 1));
let market: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let ids: Record<string, string>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  prod = environment(market, 'prod');
  // staging inherits prod; ada has a personal config of prod.
  const staging = environment(market, 'staging', { parentId: prod.id });
  const adas = environment(market, 'prod-p-0a0b0c0d', { parentId: prod.id, owner: ada });
  const api = value(world, secret(prod, 'API_KEY'), 'sk_live_0123');
  const pair = randomUUID();
  const keys = [
    value(world, secret(prod, 'REGION'), 'eu-west-3', { plain: true }), api,
    ...['WEBHOOK', 'CY_KEY', 'DEE_KEY', 'GIL_KEY'].map((key) => value(world, secret(prod, key), `${key.toLowerCase()}-value`, { sensitive: true })),
    // A key pair a client generated, each half kept with its recipe.
    { ...value(world, secret(prod, 'JWT_PRIVATE'), 'private-pem'), recipe: 'ecdsa:p-256', pairId: pair, pairHalf: 'private' },
    { ...value(world, secret(prod, 'JWT_PUBLIC'), 'public-pem'), recipe: 'ecdsa:p-256', pairId: pair, pairHalf: 'public' },
    // LINK reads API_KEY; OLD is archived; EMPTY is a reference broken, with no value of its own.
    secret(prod, 'LINK', { sourceId: api.id }),
    { ...value(world, secret(prod, 'OLD'), 'old-value'), archivedAt },
    secret(prod, 'EMPTY', { versions: 1 }),
    value(world, secret(adas, 'LOCAL'), 'ada-local', { plain: true }),
  ];
  ids = Object.fromEntries(keys.map((row) => [`${row.environmentId === prod.id ? '' : 'adas/'}${row.key}`, row.id]));
  await write(world, ...rows('projects', market), ...rows('environments', prod, staging, adas), ...rows('secrets', ...keys),
    ...rows('roles', role(false, 'owner', ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage', 'project.manage']),
      role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage', 'project.manage']), role(true, 'member', [])),
    // Cy owns market by a grant, Dee the instance, Gil market as an instance role scoped to it; Fay every project's prod, and so no project.
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee, { role: 'owner' }),
      principal(fay, { role: 'owner', scope: JSON.stringify({ projects: 'all', environments: { only: ['prod'] } }) }),
      principal(gil, { role: 'owner', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) })),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(bo, 'viewer', { project: market }), grant(cy, 'owner', { project: market })),
    ...rows('credentials', ...['ada', 'bo', 'cy', 'dee', 'fay', 'gil'].map((name) => credential(`${name}-cli`, user(name))),
      // Dee's personal token, scoped to owning market: a credential's scope never owns.
      credential('dee-pat', dee, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (label: string, keys: SecretWrite['keys'], more: Partial<SecretWrite> = {}): Presented & SecretWrite => ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', keys, ...more });
const marking = (label: string, marks: Record<string, Nature>, more: Partial<SecretWrite> = {}) => writing(label, Object.entries(marks).map(([key, nature]) => ({ key, nature })), more);
const mark = (label: string, marks: Record<string, Nature>, more?: Partial<SecretWrite>) => vault.change(marking(label, marks, more));

type Version = { version: number; sensitive: boolean; plaintext: string | null; first: number; created: number; by: string; iv: Buffer };
const versionsOf = async (key: string) =>
  (await rowsOf<Version>(world.owner, sql`SELECT version, sensitive, plaintext, first_written_at AS first, created_at AS created, created_by AS by, iv FROM secret_versions WHERE secret_id = ${ids[key]!} ORDER BY version`))
    .map((row) => ({ ...row, first: new Date(row.first).getTime(), created: new Date(row.created).getTime() }));
const rowOf = async (key: string) => (await rowsOf<{ nature: string | null; versions: number; current: number | null; recipe: string | null; pair: string | null; half: string | null }>(world.owner,
  sql`SELECT nature, versions, current_version AS current, recipe, pair_id AS pair, pair_half AS half FROM secrets WHERE id = ${ids[key]!}`))[0]!;
/** A version's value, opened as a use opens it: under its secret's and its environment's rows and its own label. */
const opened = async (key: string, version: number) => {
  const [held] = await world.owner.select().from(secrets).where(eq(secrets.id, ids[key]!));
  const [place] = await world.owner.select().from(environments).where(eq(environments.id, held!.environmentId));
  const [row] = await world.owner.select().from(secretVersions).where(and(eq(secretVersions.secretId, ids[key]!), eq(secretVersions.version, version)));
  return (await open(row!, contextOf(held!, row!, place!.owner), world.keks)).toString();
};
const counts = async () => (await rowsOf<{ log: number; versions: number }>(world.owner, sql`SELECT (SELECT count(*)::int FROM log_pending WHERE kept) AS log, (SELECT count(*)::int FROM secret_versions) AS versions`))[0]!;
const newest = async (kept = true) => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept = ${kept} ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};

test('a mark makes a key stricter, its value kept as its next version, first written when it was; the nature it has already writes nothing', async () => {
  world.tick(day);
  assert.deepEqual(await mark('ada-cli', { REGION: 'secret', API_KEY: 'sensitive', WEBHOOK: 'sensitive' }), {
    answer: { keys: { REGION: { version: 2, nature: 'secret' }, API_KEY: { version: 2, nature: 'sensitive' }, WEBHOOK: { version: 1, nature: 'sensitive' } }, outcomes: { REGION: 'changed', API_KEY: 'changed', WEBHOOK: 'unchanged' } },
  });
  const [one, two] = await versionsOf('REGION');
  // The plain version keeps its copy for the pages; the secret one has none. Sealed anew, today, by Ada, first written when its value was.
  assert.deepEqual([one!.plaintext, two!.plaintext, two!.sensitive, two!.by, two!.created, two!.first], ['eu-west-3', null, false, ada, world.now(), one!.first]);
  assert.notDeepEqual(two!.iv, one!.iv);
  assert.deepEqual((await versionsOf('API_KEY')).map((row) => [row.version, row.sensitive]), [[1, false], [2, true]]);
  assert.deepEqual([await opened('REGION', 2), await opened('API_KEY', 2)], ['eu-west-3', 'sk_live_0123']);
  assert.deepEqual([(await rowOf('REGION')).nature, (await rowOf('API_KEY')).nature, (await rowOf('WEBHOOK')).versions], ['secret', 'sensitive', 1]);
  // One entry, a write: each key changed, the nature it was and the version whose value it kept.
  const entry = await newest();
  assert.equal(entry.action, 'secret.write');
  assert.deepEqual((entry.detail as { keys: object[] }).keys, [
    { key: 'REGION', secret: ids.REGION, version: 2, nature: 'secret', was: 'plain', kept: 1 },
    { key: 'API_KEY', secret: ids.API_KEY, version: 2, nature: 'sensitive', was: 'secret', kept: 1 },
  ]);
  // As strict already, alone: no version written, and an entry of what was asked, with no key changed.
  const before = await counts();
  assert.deepEqual(await mark('ada-cli', { API_KEY: 'sensitive' }), { answer: { keys: { API_KEY: { version: 2, nature: 'sensitive' } }, outcomes: { API_KEY: 'unchanged' } } });
  assert.deepEqual(await counts(), { ...before, log: before.log + 1 });
  assert.deepEqual([(await newest()).action, ((await newest()).detail as { keys: object[] }).keys], ['secret.write', []]);
  // A reference reads its source's nature as it changes: LINK reads API_KEY sensitive now.
  assert.deepEqual(await vault.use({ ...shown('ada-cli'), project: 'market', environment: 'prod', mine: false, keys: ['LINK'], purpose: 'reveal', upstream: null })
    .then((answer) => ('refused' in answer ? answer.refused : answer.values.map((item) => ('refused' in item ? item.refused : item.value.toString())))), ['sensitive']);
});

test("a mark keeps a generated value's recipe and its pair: the value is the same, and Regenerate still makes the next", async () => {
  assert.ok('answer' in await mark('ada-cli', { JWT_PRIVATE: 'sensitive' }));
  const [privately, publicly] = [await rowOf('JWT_PRIVATE'), await rowOf('JWT_PUBLIC')];
  assert.deepEqual([privately.nature, privately.recipe, privately.half, privately.pair], ['sensitive', 'ecdsa:p-256', 'private', publicly.pair]);
  assert.equal(await opened('JWT_PRIVATE', 2), 'private-pem');
});

test('looser is refused: plain never, by anyone; a sensitive value made a secret by an Owner of the project alone, as a person on no scope, logged secret.loosen', async () => {
  // Anyone who writes there, an Owner included, makes no value plain: that takes it written again.
  for (const [label, key] of [['ada-cli', 'API_KEY'], ['dee-cli', 'API_KEY'], ['dee-cli', 'WEBHOOK']] as const) assert.deepEqual(await mark(label, { [key]: 'plain' }), { refused: 'looser' }, `${label} ${key}`);
  // A sensitive value made a secret: by a developer, an Owner of every prod, an Owner's personal token.
  for (const label of ['ada-cli', 'fay-cli', 'dee-pat']) assert.deepEqual(await mark(label, { WEBHOOK: 'secret' }), { refused: 'not_owner' }, label);
  // Logged as a loosening refused, which it is.
  const refused = await newest(false);
  assert.deepEqual([refused.action, refused.actor, (refused.detail as { refused: string }).refused], ['secret.loosen', dee, 'not_owner']);
  // A viewer writes nothing there at all.
  assert.deepEqual(await mark('bo-cli', { API_KEY: 'sensitive' }), { refused: 'no_access' });
  assert.equal((await versionsOf('WEBHOOK')).length, 1);

  // An Owner of market by a grant, of the instance, or by an instance role scoped to market: the value kept, a secret now.
  for (const [label, key] of [['cy-cli', 'CY_KEY'], ['dee-cli', 'DEE_KEY'], ['gil-cli', 'GIL_KEY']] as const) {
    assert.deepEqual(await mark(label, { [key]: 'secret' }), { answer: { keys: { [key]: { version: 2, nature: 'secret' } }, outcomes: { [key]: 'changed' } } }, label);
    assert.equal(await opened(key, 2), `${key.toLowerCase()}-value`);
    const entry = await newest();
    assert.deepEqual([entry.action, (entry.detail as { keys: object[] }).keys], ['secret.loosen', [{ key, secret: ids[key], version: 2, nature: 'secret', was: 'sensitive', kept: 1 }]]);
  }
  // Its sensitive version stays what it was.
  assert.deepEqual((await versionsOf('CY_KEY')).map((row) => row.sensitive), [true, false]);
});

test('an environment marked secret over plain and sensitive keys: by an Owner, one secret.loosen entry with both; by anyone else, refused whole', async () => {
  const before = await counts();
  assert.deepEqual(await mark('ada-cli', { REGION: 'secret', WEBHOOK: 'secret' }), { refused: 'not_owner' });
  assert.deepEqual(await counts(), before);
  assert.equal((await rowOf('REGION')).nature, 'plain');
  assert.ok('answer' in await mark('cy-cli', { REGION: 'secret', WEBHOOK: 'secret' }));
  const entry = await newest();
  assert.equal(entry.action, 'secret.loosen');
  assert.deepEqual((entry.detail as { keys: { key: string; was: string }[] }).keys.map(({ key, was }) => [key, was]), [['REGION', 'plain'], ['WEBHOOK', 'sensitive']]);
  assert.deepEqual(await counts(), { log: before.log + 1, versions: before.versions + 2 });
});

test('only a value the environment holds is marked: archived, a reference, inherited, none, or not there is refused, and nothing is written', async () => {
  const before = await counts();
  for (const [key, refused] of [['OLD', 'archived'], ['LINK', 'is_reference'], ['EMPTY', 'no_value'], ['NOPE', 'unknown_key']] as const) assert.deepEqual(await mark('ada-cli', { [key]: 'sensitive' }), { refused }, key);
  // staging holds no API_KEY: it reads prod's, which is marked there.
  assert.deepEqual(await mark('ada-cli', { API_KEY: 'sensitive' }, { environment: 'staging' }), { refused: 'inherited_key' });
  // One refused refuses the change, the others' marks included.
  assert.deepEqual(await mark('ada-cli', { API_KEY: 'sensitive', LINK: 'sensitive' }), { refused: 'is_reference' });
  assert.deepEqual(await counts(), before);
  // A mark goes alone: beside a value, an archiving or a folder, it is a fault.
  for (const more of [{ archived: false }, { folder: 'f' }, { restore: 1 }, { ref: { project: 'market', environment: 'prod', key: 'REGION' } }, { generated: { recipe: 'bytes:32' } }]) {
    await assert.rejects(vault.change(writing('ada-cli', [{ key: 'API_KEY', nature: 'sensitive', ...more } as never])), TypeError, JSON.stringify(more));
  }
  await assert.rejects(vault.change(writing('ada-cli', [{ key: 'API_KEY', nature: 'public' } as never])), TypeError);
});

test('a key that was a reference, then given a value of its own, is marked as any: who set the reference, and when, stay cleared', async () => {
  const pointed = async () => (await world.owner.select({ id: secrets.sourceId, at: secrets.sourceSetAt, by: secrets.sourceSetBy }).from(secrets).where(eq(secrets.id, ids.LINK!)))[0];
  assert.notEqual((await pointed())!.at, null);
  assert.ok('answer' in await vault.change(writing('ada-cli', [{ key: 'LINK', value: 'link-own' }])));
  assert.deepEqual(await pointed(), { id: null, at: null, by: null });
  world.tick(day);
  assert.deepEqual(await mark('ada-cli', { LINK: 'sensitive' }), { answer: { keys: { LINK: { version: 2, nature: 'sensitive' } }, outcomes: { LINK: 'changed' } } });
  assert.deepEqual(await pointed(), { id: null, at: null, by: null });
  // The resealed row's MAC holds: the value opens as a use opens it.
  assert.equal(await opened('LINK', 2), 'link-own');
});

test("a personal config's value is marked by its owner, as any: plain to a secret, never back", async () => {
  assert.deepEqual(await mark('ada-cli', { LOCAL: 'secret' }, { mine: true }), { answer: { keys: { LOCAL: { version: 2, nature: 'secret' } }, outcomes: { LOCAL: 'changed' } } });
  assert.equal(await opened('adas/LOCAL', 2), 'ada-local');
  assert.deepEqual(await mark('ada-cli', { LOCAL: 'plain' }, { mine: true }), { refused: 'looser' });
  // Bo has no config: there is no key there to mark.
  assert.deepEqual(await mark('bo-cli', { LOCAL: 'secret' }, { mine: true }), { refused: 'unknown_key' });
});

test('a version that is not what its row says refuses the mark, unreadable, and nothing is written', async () => {
  const before = await counts();
  // Relabelled sensitive behind the vault, against its secret's row.
  await world.owner.execute(sql`UPDATE secret_versions SET sensitive = true WHERE secret_id = ${ids.API_KEY!}`);
  assert.deepEqual(await mark('ada-cli', { API_KEY: 'sensitive' }), { refused: 'unreadable' });
  // Its ciphertext edited: the engine's opening refuses it.
  await world.owner.execute(sql`UPDATE secret_versions SET ciphertext = '\\x00'::bytea || ciphertext WHERE secret_id = ${ids.REGION!}`);
  await world.owner.execute(sql`UPDATE secret_versions SET plaintext = NULL WHERE secret_id = ${ids.REGION!}`);
  assert.deepEqual(await mark('ada-cli', { DEE_KEY: 'sensitive', REGION: 'secret' }), { refused: 'unreadable' });
  assert.deepEqual(await counts(), before);
});

test('a key service that gives out partway, unwrapping or wrapping: the mark fails whole, and nothing is written', async () => {
  const before = await counts();
  const marks = { REGION: 'sensitive', API_KEY: 'sensitive', JWT_PRIVATE: 'sensitive', JWT_PUBLIC: 'sensitive' } as const;
  // Its first `answered` calls are answered, as a key service's; the next is not: each key is one unwrap, then one wrap.
  for (const answered of [4, 5]) {
    let calls = 0;
    const keks = world.keks;
    const flaky = {
      unwrap: (...args: Parameters<typeof keks.unwrap>) => (calls++ < answered ? keks.unwrap(...args) : Promise.reject(new KekUnavailableError('the key service gave out'))),
      wrap: (...args: Parameters<typeof keks.wrap>) => (calls++ < answered ? keks.wrap(...args) : Promise.reject(new KekUnavailableError('the key service gave out'))),
    };
    const down = openLocalVault(world.db, { ...world, keks: flaky as never }, { wake: world.wake, now: world.now });
    await assert.rejects(down.change(marking('ada-cli', marks)), KekUnavailableError);
    assert.equal(calls, answered + 1, 'it stopped at the first that failed');
    assert.deepEqual(await counts(), before);
    assert.deepEqual(await Promise.all(Object.keys(marks).map(async (key) => (await rowOf(key)).versions)), [1, 1, 1, 1]);
  }
  // Answering again, the same mark is made whole.
  assert.ok('answer' in await mark('ada-cli', marks));
});

test('a dry run tells what a mark would do and writes nothing; a looser one is refused as the mark is', async () => {
  const before = await counts();
  assert.deepEqual(await vault.weigh(marking('ada-cli', { REGION: 'sensitive', WEBHOOK: 'sensitive' })), { answer: { keys: { REGION: { version: 2, nature: 'sensitive' }, WEBHOOK: { version: 1, nature: 'sensitive' } }, outcomes: { REGION: 'changed', WEBHOOK: 'unchanged' } } });
  assert.deepEqual(await vault.weigh(marking('ada-cli', { WEBHOOK: 'secret' })), { refused: 'not_owner' });
  assert.ok('answer' in await vault.weigh(marking('cy-cli', { WEBHOOK: 'secret' })));
  assert.deepEqual(await counts(), before);
});

test('a value written over the key between the mark\'s read and its write: the mark starts over, and marks the new value', async () => {
  const input = marking('ada-cli', { API_KEY: 'sensitive' });
  const prepared = await prepare(world, OPERATIONS[input.op](input as never, { workloads: world.workloads, owners: world.owners }));
  assert.ok(!('refused' in prepared));
  assert.ok('answer' in await vault.change(writing('ada-cli', [{ key: 'API_KEY', value: 'sk_live_rotated' }])));
  assert.equal(await commit(world, prepared as Prepared<unknown>), false);
  assert.deepEqual(await mark('ada-cli', { API_KEY: 'sensitive' }), { answer: { keys: { API_KEY: { version: 3, nature: 'sensitive' } }, outcomes: { API_KEY: 'changed' } } });
  assert.equal(await opened('API_KEY', 3), 'sk_live_rotated');
});

test('a restore comes back no looser than its value\'s newest copy: a value marked stricter stays so in its older versions', async () => {
  const restore = async (label: string, key: string, version: number) => {
    const done = await vault.change(writing(label, [{ key, restore: version }]));
    assert.ok('answer' in done, JSON.stringify(done));
    return done.answer.keys[key]!.nature;
  };
  // A day apart: a value is told from another by the date it was first written.
  const typed = async (key: string, text: string, nature: Nature) => {
    world.tick(day);
    assert.ok('answer' in await vault.change(writing('ada-cli', [{ key, value: text, nature }])));
  };
  // Marked sensitive, then written over as a secret by whoever may: its first version comes back sensitive, as marked.
  await mark('ada-cli', { API_KEY: 'sensitive' });
  await typed('API_KEY', 'sk_live_new', 'secret');
  assert.equal(await restore('ada-cli', 'API_KEY', 1), 'sensitive');
  assert.equal(await opened('API_KEY', 4), 'sk_live_0123');
  // Plain, marked a secret, then another value written plain: its plain version comes back a secret.
  await mark('ada-cli', { REGION: 'secret' });
  await typed('REGION', 'us-east-1', 'plain');
  assert.equal(await restore('ada-cli', 'REGION', 1), 'secret');
  assert.equal((await versionsOf('REGION'))[3]!.plaintext, null);
  // An Owner's loosening is its version's own: that one comes back a secret, the sensitive one before it sensitive.
  await mark('cy-cli', { CY_KEY: 'secret' });
  await typed('CY_KEY', 'cy-other', 'secret');
  assert.equal(await restore('ada-cli', 'CY_KEY', 2), 'secret');
  assert.equal(await restore('ada-cli', 'CY_KEY', 1), 'sensitive');
  // A value written again is a value of its own: its plain version comes back plain.
  await typed('DEE_KEY', 'plain-one', 'plain');
  await typed('DEE_KEY', 'secret-two', 'secret');
  assert.equal(await restore('ada-cli', 'DEE_KEY', 2), 'plain');
});

test('two values first written in the same millisecond: a restore of either comes back at the strictest of that date, never looser', async () => {
  const restore = async (version: number) => {
    const done = await vault.change(writing('ada-cli', [{ key: 'SAME_MS', restore: version }]));
    assert.ok('answer' in done, JSON.stringify(done));
    return done.answer.keys.SAME_MS!.nature;
  };
  // The clock never moves: a secret, marked sensitive, then another value written over it as a secret, all at one instant.
  for (const each of [{ key: 'SAME_MS', value: 'original', nature: 'secret' }, { key: 'SAME_MS', nature: 'sensitive' }, { key: 'SAME_MS', value: 'different', nature: 'secret' }] as const) {
    assert.ok('answer' in await vault.change(writing('ada-cli', [each])), JSON.stringify(each));
  }
  ids.SAME_MS = (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE key = 'SAME_MS'`))[0]!.id;
  assert.equal(new Set((await versionsOf('SAME_MS')).flatMap((row) => [row.created, row.first])).size, 1, 'one instant');
  // v1's value comes back sensitive, as v2 marked it, though v3, a value of its own, says a secret.
  assert.equal(await restore(1), 'sensitive');
  assert.equal(await opened('SAME_MS', 4), 'original');
  // And v3's too: which version is whose cannot be told, so each comes back at the strictest.
  assert.equal(await restore(3), 'sensitive');
  assert.equal(await opened('SAME_MS', 5), 'different');
});

/** `count` keys of `size` bytes each, in a new environment of market's: its slug. */
const big = async (slug: string, count: number, size: number) => {
  const place = environment(market, slug);
  await write(world, ...rows('environments', place), ...rows('secrets', ...Array.from({ length: count }, (_, n) => value(world, secret(place, `KEY_${String(n).padStart(4, '0')}`), String(n % 10).repeat(size)))));
  return place;
};
/** What the current versions of an environment's keys weigh, as `MOST_COPIED` counts them. */
const weighed = async (place: { id: string }) => (await rowsOf<{ bytes: number }>(world.owner, sql`SELECT sum(octet_length(v.ciphertext) + octet_length(v.wrapped_dek) + coalesce(octet_length(v.plaintext), 0))::float8 AS bytes
  FROM secret_versions v JOIN secrets s ON s.id = v.secret_id AND v.version = s.current_version WHERE s.environment_id = ${place.id}`))[0]!.bytes;

test(`marks open and seal again ${MOST_COPIED / 2 ** 20} MiB of values at most in one change, weighed from their stored lengths before any is read`, async () => {
  // As many 64 KiB values as fit, and one more.
  const size = 64 * 1024;
  const place = await big('big', Math.floor(MOST_COPIED / size), size);
  const keys = (await rowsOf<{ key: string }>(world.owner, sql`SELECT key FROM secrets WHERE environment_id = ${place.id} ORDER BY key`)).map((row) => row.key);
  assert.ok(await weighed(place) > MOST_COPIED, 'the stored lengths say more than the values: a wrapped key each');
  const all = marking('ada-cli', Object.fromEntries(keys.map((key) => [key, 'sensitive'])), { environment: 'big' });
  const before = await counts();
  assert.deepEqual(await vault.change(all), { refused: 'too_much_to_copy' });
  assert.deepEqual(await counts(), before);
  // Its read found what they weigh, and none of them: no ciphertext came to the vault.
  const operation = OPERATIONS[all.op](all as never, { workloads: world.workloads, owners: world.owners });
  const read = await readParts(world, operation.read, operation.beside);
  assert.deepEqual([(read.seen as unknown as { marked: unknown[] }).marked.length, (read.beside.weighed![0] as { bytes: number }).bytes > MOST_COPIED], [0, true]);
  // One fewer fits: marked, every value kept.
  const fewer = marking('ada-cli', Object.fromEntries(keys.slice(1).map((key) => [key, 'sensitive'])), { environment: 'big' });
  const done = await vault.change(fewer);
  assert.ok('answer' in done && Object.values(done.answer.outcomes).every((outcome) => outcome === 'changed'));
});

test('a mark weighs only the values it changes: those already of the nature asked copy nothing', async () => {
  const size = 64 * 1024;
  const place = await big('big', Math.floor(MOST_COPIED / size), size);
  await write(world, ...rows('secrets', value(world, secret(place, 'SMALL'), 'small', { plain: true })));
  const keys = (await rowsOf<{ key: string }>(world.owner, sql`SELECT key FROM secrets WHERE environment_id = ${place.id} AND key <> 'SMALL'`)).map((row) => row.key);
  assert.ok(await weighed(place) > MOST_COPIED);
  // Every heavy one is a secret already, and only SMALL is changed.
  const done = await mark('ada-cli', { ...Object.fromEntries(keys.map((key) => [key, 'secret' as const])), SMALL: 'secret' }, { environment: 'big' });
  assert.ok('answer' in done, JSON.stringify(done));
  assert.deepEqual(Object.entries(done.answer.outcomes).filter(([, outcome]) => outcome !== 'unchanged'), [['SMALL', 'changed']]);
});

test('the engine weighs what a change copies before it opens any, whatever its operation read', async () => {
  const size = 64 * 1024;
  const place = await big('big', Math.floor(MOST_COPIED / size), size);
  // A change that copies every value of the environment without weighing them first, as a mark would without `copying`.
  const copyAll = () => change(world, {
    read: { held: part(secrets, sql`${secrets.environmentId} = ${place.id}`), place: part(environments, sql`${environments.id} = ${place.id}`),
      version: part(secretVersions, sql`${secretVersions.secretId} IN (SELECT id FROM secrets WHERE environment_id = ${place.id})`) },
    decide: ({ held, version }) => ({
      writes: held.map(({ mac: _, ...row }) => put(secrets, { ...row, versions: 2, currentVersion: 2 }, held.find((each) => each.id === row.id)!)),
      values: held.map((row) => ({ version: { id: randomUUID(), secretId: row.id, version: 2, createdAt: new Date(world.now()), createdBy: ada, sensitive: false, firstWrittenAt: new Date(world.now()), plaintext: null }, copy: version.find((each) => each.secretId === row.id)! })),
      entry: { kept: true, action: 'test.write', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} },
      answer: null,
    }),
  });
  const before = await counts();
  assert.deepEqual(await copyAll(), { refused: 'too_much_to_copy' });
  assert.deepEqual(await counts(), before);
  // `copying` reads the same versions only below the bound.
  const { part: gated } = copying(sql`${secretVersions.secretId} IN (SELECT id FROM secrets WHERE environment_id = ${place.id})`);
  assert.equal((await readParts(world, { version: gated })).seen.version.length, 0);
});

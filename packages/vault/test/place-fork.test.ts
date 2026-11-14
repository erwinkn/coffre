// A fork that copies (src/ops/places.ts, `copied`): an environment made with
// each key its source reads now, copied by the engine or made a reference,
// in one change; who may; what it resolves as a use does; and rows edited
// behind the vault, which refuse it and leave nothing made.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { EnvironmentCreate, Presented, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { secrets } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { change, commit, prepare, type Operation, type Parts } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { MOST_KEYS } from '../src/ops/input.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, dismissed, environment, grant, instance, principal, project, rewrite, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee, eve] = [user('ada'), user('bo'), user('cy'), user('dee'), user('eve')];
const api = 'token:api';
let market: ReturnType<typeof project>;
let ids: Record<string, string>;
let first: Record<string, number>;

/**
 * market: prod holds DATABASE_URL (filed in database), STRIPE_KEY
 * (sensitive), ACCOUNT (plain), OLD (archived), HOLLOW (a reference broken:
 * no value), LINK (a reference to billing's SOURCE) and SIGNING (one to
 * billing's sensitive SIGN). staging inherits from prod, overrides
 * DATABASE_URL, adds S_KEY and dismissed ACCOUNT. guarded is protected.
 * Ada maintains market and billing; Bo maintains market alone; Cy views
 * market; Dee stewards market's environments and views staging alone; Eve
 * curates market, reading and managing its environments and using nothing,
 * and maintains billing; the service api maintains market.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  const billing = project('billing');
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { parentId: prod.id });
  const guarded = environment(market, 'guarded', { protected: true });
  const adas = environment(market, 'adas', { parentId: prod.id, owner: ada });
  const stale = environment(market, 'stale', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const orphan = environment(market, 'orphan', { parentId: stale.id });
  const there = environment(billing, 'prod');
  const source = value(world, secret(there, 'SOURCE'), 'from billing');
  const sign = value(world, secret(there, 'SIGN'), 'sig', { sensitive: true });
  const keys = [
    value(world, secret(prod, 'DATABASE_URL', { folder: 'database' }), 'postgres://prod'),
    value(world, secret(prod, 'STRIPE_KEY'), 'sk_live', { sensitive: true }),
    value(world, secret(prod, 'ACCOUNT'), 'acct_1', { plain: true }),
    value(world, secret(prod, 'OLD', { archivedAt: new Date(Date.UTC(2026, 10, 1)) }), 'gone'),
    secret(prod, 'HOLLOW'),
    secret(prod, 'LINK', { sourceId: source.id, folder: 'links' }),
    secret(prod, 'SIGNING', { sourceId: sign.id }),
    value(world, secret(staging, 'DATABASE_URL'), 'postgres://staging'),
    value(world, secret(staging, 'S_KEY'), 's'),
    value(world, secret(guarded, 'G'), 'g'),
    value(world, secret(adas, 'OWN'), 'mine'),
  ];
  ids = Object.fromEntries([source, sign, ...keys].map((row) => [`${row.environmentId === staging.id ? 'staging/' : ''}${row.key}`, row.id]));
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, staging, guarded, adas, stale, orphan, there), ...rows('secrets', source, sign, ...keys),
    ...rows('dismissedKeys', dismissed(staging, 'ACCOUNT')),
    ...rows('roles', role(false, 'maintainer', ['secret.read', 'secret.use', 'secret.write', 'environment.manage']), role(false, 'steward', ['environment.manage']), role(false, 'curator', ['secret.read', 'environment.manage']),
      role(false, 'viewer', ['secret.read', 'secret.use']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee), principal(eve), principal(api)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: market }), grant(ada, 'maintainer', { project: billing }), grant(bo, 'maintainer', { project: market }), grant(cy, 'viewer', { project: market }),
      grant(dee, 'steward', { project: market }), grant(dee, 'viewer', { environment: staging }), grant(eve, 'curator', { project: market }), grant(eve, 'maintainer', { project: billing }), grant(api, 'maintainer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee), credential('eve-cli', eve)));
  first = Object.fromEntries((await rowsOf<{ secret_id: string; first: Date }>(world.owner, sql`SELECT secret_id, first_written_at AS first FROM secret_versions`)).map((row) => [row.secret_id, new Date(row.first).getTime()]));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const forking = (label: string, slug: string, from: string, references = false): Presented & EnvironmentCreate =>
  ({ ...shown(label), op: 'environment.create', project: 'market', environment: slug, mine: false, parent: null, protected: false, copy: { from, references } });
const answered = <A>(result: { answer: A } | { refused: string }): A => {
  assert.ok('answer' in result, JSON.stringify(result));
  return result.answer;
};
const count = async (table: 'environments' | 'secrets' | 'secret_versions') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
/** What is made: the entries kept, the environments, the keys and their versions. */
const counts = async () => [(await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n, await count('environments'), await count('secrets'), await count('secret_versions')];
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
type Held = { key: string; versions: number; current: number | null; nature: string | null; folder: string | null; source: string | null };
/** An environment's keys, by name: their rows as stored. */
const heldIn = async (slug: string) => Object.fromEntries((await rowsOf<Held>(world.owner, sql`SELECT s.key, s.versions, s.current_version AS current, s.nature, s.folder, s.source_id AS source
  FROM secrets s JOIN environments e ON e.id = s.environment_id WHERE e.project_id = ${market.id} AND e.slug = ${slug} ORDER BY s.key`)).map(({ key, ...row }) => [key, row]));
const environmentRow = async (slug: string) => (await rowsOf<{ parent_id: string | null; protected: boolean }>(world.owner, sql`SELECT parent_id, protected FROM environments WHERE project_id = ${market.id} AND slug = ${slug}`))[0];
const reveal = (label: string, place: string, keys: string[], purpose: UseInput['purpose'] = 'reveal'): UseInput => ({ ...shown(label), project: 'market', environment: place, mine: false, keys, purpose, upstream: null });
/** What a use of the keys is given, each its value or why not. */
const given = async (input: UseInput) => {
  const answer = await vault.use(input);
  if ('refused' in answer) return answer.refused;
  return Object.fromEntries(answer.values.map((item) => [item.key, 'refused' in item ? `refused: ${item.refused}` : item.value.toString()]));
};

test('a fork copies each key its source reads now, as it is kept, in one change: values the vault seals again, and nobody else holds', async () => {
  const before = await counts();
  const made = answered(await vault.change(forking('ada-cli', 'qa', 'prod')));
  // SIGNING reads billing's sensitive SIGN: a copy would hold it under market, so it stays a reference, which Ada may make.
  assert.deepEqual([made.slug, made.protected, made.forked], ['qa', false, { keys: 5, references: 1, copied: [] }]);
  // One entry, one environment, five keys and four values: OLD is archived and HOLLOW has no value, so neither is copied.
  assert.deepEqual(await counts(), [before[0]! + 1, before[1]! + 1, before[2]! + 5, before[3]! + 4]);
  assert.deepEqual(await environmentRow('qa'), { parent_id: null, protected: false });
  assert.deepEqual(await heldIn('qa'), {
    ACCOUNT: { versions: 1, current: 1, nature: 'plain', folder: null, source: null },
    DATABASE_URL: { versions: 1, current: 1, nature: 'secret', folder: 'database', source: null },
    // A reference's value is copied from its source, and the key keeps the reference's folder, where it was filed.
    LINK: { versions: 1, current: 1, nature: 'secret', folder: 'links', source: null },
    SIGNING: { versions: 0, current: null, nature: null, folder: null, source: ids.SIGN! },
    STRIPE_KEY: { versions: 1, current: 1, nature: 'sensitive', folder: null, source: null },
  });
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['DATABASE_URL', 'ACCOUNT', 'LINK', 'STRIPE_KEY', 'SIGNING'])), {
    DATABASE_URL: 'postgres://prod', ACCOUNT: 'acct_1', LINK: 'from billing', STRIPE_KEY: 'refused: sensitive', SIGNING: 'refused: sensitive',
  });
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['STRIPE_KEY', 'SIGNING'], 'use')), { STRIPE_KEY: 'sk_live', SIGNING: 'sig' });

  // Each value is kept as it was and its first date is its source's; its forker made it, and none of its history came.
  const versions = await rowsOf<{ key: string; version: number; sensitive: boolean; plaintext: string | null; first: Date; by: string }>(world.owner, sql`SELECT s.key, v.version, v.sensitive, v.plaintext,
    v.first_written_at AS first, v.created_by AS by FROM secret_versions v JOIN secrets s ON s.id = v.secret_id JOIN environments e ON e.id = s.environment_id WHERE e.slug = 'qa' ORDER BY s.key`);
  assert.deepEqual(versions.map((row) => [row.key, row.version, row.sensitive, row.plaintext, new Date(row.first).getTime(), row.by]), [
    ['ACCOUNT', 1, false, 'acct_1', first[ids.ACCOUNT!], ada],
    ['DATABASE_URL', 1, false, null, first[ids.DATABASE_URL!], ada],
    ['LINK', 1, false, null, first[ids.SOURCE!], ada],
    ['STRIPE_KEY', 1, true, null, first[ids.STRIPE_KEY!], ada],
  ]);

  // The entry names each key made, and the secret it was copied from or refers to; each of those secrets' pages find it, and billing's.
  const entry = await written();
  assert.equal(entry.action, 'environment.create');
  const detail = entry.detail as { keys: Record<string, unknown>[] };
  assert.deepEqual({ ...detail, keys: undefined }, { slug: 'qa', protected: false, from: 'prod', references: false, keys: undefined });
  assert.deepEqual(detail.keys.map(({ secret: _, ...line }) => line), [
    { key: 'ACCOUNT', version: 1, nature: 'plain', copied: ids.ACCOUNT },
    { key: 'DATABASE_URL', version: 1, nature: 'secret', copied: ids.DATABASE_URL, folder: 'database' },
    { key: 'LINK', version: 1, nature: 'secret', copied: ids.SOURCE, folder: 'links' },
    { key: 'SIGNING', refers: ids.SIGN },
    { key: 'STRIPE_KEY', version: 1, nature: 'sensitive', copied: ids.STRIPE_KEY },
  ]);
  for (const id of [ids.ACCOUNT, ids.SOURCE, ids.SIGN, `project:${(await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM projects WHERE slug = 'billing'`))[0]!.id}`]) {
    assert.ok(entry.objects.includes(id!.includes(':') ? id! : `secret:${id}`), id);
  }
  // prod is as it was.
  assert.deepEqual(await given(reveal('ada-cli', 'prod', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://prod' });
  assert.equal((await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM secret_versions WHERE secret_id = ${ids.DATABASE_URL!}`))[0]!.n, 1);
});

test('a fork as references makes each key a reference to where its value is held, one hop, where its forker may make one; it copies the rest, and names them', async () => {
  const made = answered(await vault.change(forking('ada-cli', 'qa', 'prod', true)));
  assert.deepEqual(made.forked, { keys: 5, references: 5, copied: [] });
  const held = await heldIn('qa');
  // LINK refers to billing's SOURCE, not to prod's LINK: a reference reads a value, never another reference.
  assert.deepEqual(Object.fromEntries(Object.entries(held).map(([key, row]) => [key, [row.source, row.current, row.folder]])), {
    ACCOUNT: [ids.ACCOUNT, null, null], DATABASE_URL: [ids.DATABASE_URL, null, 'database'], LINK: [ids.SOURCE, null, 'links'], SIGNING: [ids.SIGN, null, null], STRIPE_KEY: [ids.STRIPE_KEY, null, null],
  });
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['DATABASE_URL', 'LINK'])), { DATABASE_URL: 'postgres://prod', LINK: 'from billing' });
  // Written over in prod, it reads the new value.
  await rewrite(world, { id: ids.DATABASE_URL! }, 'postgres://moved');
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://moved' });

  // Eve reads market and uses nothing there: a reference to prod's sensitive STRIPE_KEY is not hers to make, so it is a copy,
  // sensitive in the same project. SIGNING's source she reads and uses in billing.
  assert.deepEqual(answered(await vault.change(forking('eve-cli', 'eves', 'prod', true))).forked, { keys: 5, references: 4, copied: ['STRIPE_KEY'] });
  assert.deepEqual([(await heldIn('eves')).STRIPE_KEY, (await heldIn('eves')).SIGNING!.source], [{ versions: 1, current: 1, nature: 'sensitive', folder: null, source: null }, ids.SIGN]);

  // Bo reads nothing in billing: SIGNING's sensitive value, reached through a reference, he can neither refer to nor copy, so he forks nothing.
  const before = await counts();
  assert.deepEqual(await vault.change(forking('bo-cli', 'bos', 'prod', true)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(forking('bo-cli', 'bos', 'prod')), { refused: 'no_access' });
  assert.deepEqual(await counts(), before);
  // With SIGNING archived, LINK is copied for him, and said so; the rest are references.
  await amend(world, 'secrets', eq(secrets.id, ids.SIGNING!), { archivedAt: new Date(world.now()) });
  assert.deepEqual(answered(await vault.change(forking('bo-cli', 'bos', 'prod', true))).forked, { keys: 4, references: 3, copied: ['LINK'] });
  assert.deepEqual([(await heldIn('bos')).LINK!.source, (await heldIn('bos')).LINK!.current], [null, 1]);
  assert.deepEqual(await given(reveal('bo-cli', 'bos', ['LINK'])), { LINK: 'from billing' });
  // As copies, nothing is listed: none was asked to be a reference.
  assert.deepEqual(answered(await vault.change(forking('bo-cli', 'bos-2', 'prod'))).forked, { keys: 4, references: 0, copied: [] });
});

test("a fork of a fork holds what it reads: each key from the nearest environment that holds it, or none past a dismissal; who forks reads where each comes from", async () => {
  const made = answered(await vault.change(forking('ada-cli', 'qa', 'staging')));
  assert.deepEqual(made.forked, { keys: 5, references: 1, copied: [] });
  assert.deepEqual(Object.keys(await heldIn('qa')), ['DATABASE_URL', 'LINK', 'SIGNING', 'STRIPE_KEY', 'S_KEY']);
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['DATABASE_URL', 'S_KEY'])), { DATABASE_URL: 'postgres://staging', S_KEY: 's' });
  // staging's override has no folder, where prod's has: the key keeps the folder of the row it is copied from.
  assert.equal((await heldIn('qa')).DATABASE_URL!.folder, null);
  // As references, staging's own keys are referred to where they are, and prod's in prod.
  answered(await vault.change(forking('ada-cli', 'qa-2', 'staging', true)));
  assert.deepEqual([(await heldIn('qa-2')).DATABASE_URL!.source, (await heldIn('qa-2')).STRIPE_KEY!.source], [ids['staging/DATABASE_URL'], ids.STRIPE_KEY]);

  // A fork of a protected environment is protected, as one that inherits.
  assert.equal(answered(await vault.change(forking('ada-cli', 'guarded-2', 'guarded'))).protected, true);
  assert.deepEqual(await environmentRow('guarded-2'), { parent_id: null, protected: true });

  const before = await counts();
  // Dee manages market's environments and reads staging alone: what staging inherits from prod she does not read.
  assert.deepEqual(await vault.change(forking('dee-cli', 'next', 'staging')), { refused: 'parent_unreadable' });
  // Cy reads and manages nothing.
  assert.deepEqual(await vault.change(forking('cy-cli', 'next', 'prod')), { refused: 'no_access' });
  assert.deepEqual(await vault.change(forking('ada-cli', 'next', 'orphan')), { refused: 'broken_chain' }, 'a parent above it archived');
  assert.deepEqual(await vault.change(forking('ada-cli', 'next', 'adas')), { refused: 'no_access' }, 'a personal config');
  assert.deepEqual(await vault.change(forking('ada-cli', 'next', 'stale')), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await vault.change(forking('ada-cli', 'next', 'nowhere')), { refused: 'no_access' });
  assert.deepEqual(await vault.change(forking('ada-cli', 'qa', 'prod')), { refused: 'exists' });
  assert.deepEqual(await counts(), before);
});

test('a workload copies or refers to no value it only uses where it is held', async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]), policy: '{}' });
  await write(world, ...rows('bindings', bound), ...rows('credentials', session('pod', bound)));
  const before = await counts();
  for (const references of [false, true]) assert.deepEqual(await vault.change({ ...forking('pod', 'pod-made', 'prod', references), proof: 'pod' }), { refused: 'use_only' });
  assert.deepEqual(await counts(), before);
  // guarded holds one secret, which it does not list either.
  assert.deepEqual(await vault.change({ ...forking('pod', 'pod-made', 'guarded'), proof: 'pod' }), { refused: 'use_only' });
});

/** Rows edited behind the vault, each in a fork of `from` that reads them. */
const tampered: [string, string, () => ReturnType<typeof sql> | ReturnType<typeof sql>[]][] = [
  ['a key', 'prod', () => sql`UPDATE secrets SET folder = 'moved' WHERE id = ${ids.ACCOUNT!}`],
  ['an archived key, which may be one that is not', 'prod', () => sql`UPDATE secrets SET folder = 'moved' WHERE id = ${ids.OLD!}`],
  ["a reference's source", 'prod', () => sql`UPDATE secrets SET folder = 'moved' WHERE id = ${ids.SOURCE!}`],
  ['a dismissal', 'staging', () => sql`UPDATE dismissed_keys SET dismissed_by = 'nobody' WHERE key = 'ACCOUNT'`],
  ['a parent', 'staging', () => sql`UPDATE environments SET name = 'Prod!' WHERE slug = 'prod' AND project_id = ${market.id}`],
  ['a version relabelled', 'prod', () => sql`UPDATE secret_versions SET sensitive = false WHERE secret_id = ${ids.STRIPE_KEY!}`],
  ['a plain version whose copy is not its value', 'prod', () => sql`UPDATE secret_versions SET plaintext = 'acct_2' WHERE secret_id = ${ids.ACCOUNT!}`],
  ["a version moved to a key with none, which leaves its own key's missing", 'staging', () => sql`UPDATE secret_versions SET secret_id = ${ids.HOLLOW!} WHERE secret_id = ${ids.STRIPE_KEY!}`],
  // Labelled as the key's row says, and found where it is looked for: its own encryption names the key it was written to,
  // and under another it opens as nothing, which only the engine finds.
  ["a version put in another key's place", 'prod', () => [sql`DELETE FROM secret_versions WHERE secret_id = ${ids.DATABASE_URL!}`, sql`UPDATE secret_versions SET secret_id = ${ids.DATABASE_URL!} WHERE secret_id = ${ids['staging/S_KEY']!}`]],
];
for (const [what, from, edit] of tampered) {
  test(`${what} edited behind the vault refuses a fork of ${from} that reads it, and nothing is made`, async () => {
    for (const statement of [edit()].flat()) await world.owner.execute(statement);
    const before = await counts();
    assert.deepEqual(await vault.change(forking('ada-cli', 'qa', from)), { refused: 'unreadable' });
    assert.deepEqual(await counts(), before);
  });
}

test('a reference whose source is archived, or holds no value, reads nothing, and a fork of it is refused rather than leave the key out', async () => {
  // As a restore around the vault would leave it: the vault refuses to archive a source while a reference reads it.
  await amend(world, 'secrets', eq(secrets.id, ids.SOURCE!), { archivedAt: new Date(world.now()) });
  assert.deepEqual(await vault.change(forking('ada-cli', 'qa', 'prod')), { refused: 'unreadable' });
  assert.deepEqual(await vault.change(forking('ada-cli', 'qa', 'prod', true)), { refused: 'unreadable' });
  // So does one whose source holds no value: made a reference itself and broken, around the vault.
  await amend(world, 'secrets', eq(secrets.id, ids.SOURCE!), { archivedAt: null, currentVersion: null, nature: null });
  assert.deepEqual(await vault.change(forking('ada-cli', 'qa', 'prod')), { refused: 'unreadable' });
});

test('a fork holds each row it uses to what it is used for, not only to the conditions it was read by', async () => {
  // A key of billing's, sealed and said to be in prod, put before prod's own: it is no key of prod's, and copies nothing.
  const deciding = { workloads: world.workloads, owners: world.owners };
  const operation = OPERATIONS['environment.create'](forking('ada-cli', 'qa', 'prod'), deciding) as Operation<Parts, { forked?: { keys: number } }>;
  const [prod] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments WHERE project_id = ${market.id} AND slug = 'prod'`);
  const [billing] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM projects WHERE slug = 'billing'`);
  const theirs = { ...secret({ id: prod!.id, projectId: billing!.id }, 'THEIRS', { versions: 1, currentVersion: 1, nature: 'secret' }), mac: Buffer.alloc(36) };
  const made = answered(await change(world, { read: operation.read, decide: (seen, at, unsealed) => operation.decide({ ...seen, held: [theirs as never, ...seen.held] }, at, unsealed, undefined) }));
  assert.equal(made.forked?.keys, 5);
  assert.deepEqual(Object.keys(await heldIn('qa')), ['ACCOUNT', 'DATABASE_URL', 'LINK', 'SIGNING', 'STRIPE_KEY']);
});

test('a fork decided on values written over before its write starts again, and copies what is there then', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const prepared = await prepare(world, OPERATIONS['environment.create'](forking('ada-cli', 'qa', 'prod'), deciding));
  assert.ok(!('refused' in prepared));
  await rewrite(world, { id: ids.DATABASE_URL! }, 'postgres://moved');
  const before = await counts();
  assert.equal(await commit(world, prepared), false, 'a value it copies moved on');
  assert.deepEqual(await counts(), before);
  answered(await vault.change(forking('ada-cli', 'qa', 'prod')));
  assert.deepEqual(await given(reveal('ada-cli', 'qa', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://moved' });
});

test('a fork that copies is asked as the contract says, or it is a fault, before any read', async () => {
  const bad: Record<string, unknown>[] = [
    { parent: 'prod' }, { copy: { from: 7, references: false } }, { copy: { from: 'prod' } }, { copy: { from: 'prod', references: 'yes' } }, { copy: null }, { copy: 'prod' },
  ];
  for (const more of bad) await assert.rejects(vault.change({ ...forking('ada-cli', 'qa', 'prod'), ...more } as never), TypeError, JSON.stringify(more));
  await assert.rejects(vault.change({ ...shown('ada-cli'), op: 'environment.create', project: 'market', environment: 'prod', mine: true, copy: { from: 'prod', references: false } } as never), TypeError);
  assert.equal(world.woken.length, 0);
});

test(`a fork copies ${MOST_KEYS} values at most in its one change: past that it is refused, and nothing is made; by reference, it copies none`, async () => {
  const big = environment(market, 'big');
  const keys = Array.from({ length: MOST_KEYS }, (_, n) => value(world, secret(big, `KEY_${String(n).padStart(4, '0')}`), `value-${n}`));
  await write(world, ...rows('environments', big), ...rows('secrets', ...keys));
  // At the bound, every value copied.
  assert.equal(answered(await vault.change(forking('ada-cli', 'whole', 'big'))).forked!.keys, MOST_KEYS);
  // One more, and the fork is refused, whole: no environment, key or version made.
  await write(world, ...rows('secrets', value(world, secret(big, 'ONE_MORE'), 'more')));
  const before = await counts();
  assert.deepEqual(await vault.change(forking('ada-cli', 'over', 'big')), { refused: 'too_many_keys' });
  assert.deepEqual(await counts(), before);
  // As references, it seals no value, and is made.
  const referred = answered(await vault.change(forking('ada-cli', 'over', 'big', true))).forked!;
  assert.deepEqual([referred.keys, referred.references, referred.copied], [MOST_KEYS + 1, MOST_KEYS + 1, []]);
});

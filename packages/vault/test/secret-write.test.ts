// A value written (src/ops/secrets.ts), through the contract as the app
// calls it: who may, what is written, what its entry names, and that a use
// then opens it. change.test.ts holds how any change reads, compares and
// writes; this holds the first operation made of one.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { allows } from '@coffre/core/access';
import { KekUnavailableError } from '@coffre/core/kek';
import type { Nature, Presented, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { bindings, environments } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { callerFrom, callerParts, type Asking } from '../src/caller.ts';
import { commit, part, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee, eve] = [user('ada'), user('bo'), user('cy'), user('dee'), user('eve')];
let url: { id: string };
let stripe: { id: string };
let market: ReturnType<typeof project>;
const api = 'token:api';
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  market = project('market');
  const [prod, guarded] = [environment(market, 'prod'), environment(market, 'guarded', { protected: true })];
  const adas = environment(market, 'adas', { parentId: prod.id, owner: ada });
  const old = environment(market, 'old', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const billing = project('billing');
  const there = environment(billing, 'prod');
  const source = (stripe = value(world, secret(there, 'STRIPE_KEY'), 'sk_live'));
  const database = (url = value(world, secret(prod, 'DATABASE_URL'), 'postgres://old'));
  const viewer = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, guarded, adas, old, there),
    ...rows('secrets', database, source, secret(prod, 'STRIPE_KEY', { sourceId: source.id }), secret(prod, 'GONE', { archivedAt: new Date(Date.UTC(2026, 10, 1)) })),
    // A developer writes everywhere; a contributor writes, but not where an environment is protected; a viewer reads. An Owner of the instance holds what its role says, with no grant.
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'contributor', ['secret.read', 'secret.write'], ['secret.read']), role(false, 'viewer', ['secret.read']), role(true, 'owner', ['secret.read', 'secret.write']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee, { role: 'owner' }), principal(eve), principal(api)), ...rows('policy', instance()),
    ...rows('grants',
      // Ada's grant on billing, and everyone else's on market, decide nothing of a write of hers in market: none is read.
      grant(ada, 'developer', { project: market }), grant(ada, 'developer', { project: billing }), grant(bo, 'viewer', { project: market }), grant(cy, 'contributor', { project: market }),
      grant(eve, 'developer', { environment: prod }), grant(eve, 'developer', { project: market }, { expiresAt: new Date(world.now() - 1000) }), grant(api, 'developer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee), credential('eve-cli', eve),
      // A personal token reaches no further than its scope, whatever its person holds; a handle changes nothing.
      credential('ada-pat', ada, { kind: 'personal', scope: viewer }), credential('ada-handle', ada, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) }),
      credential('api-token', api, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (label: string, values: Record<string, string | [string, Nature]>, more: Partial<SecretWrite> = {}): Presented & SecretWrite =>
  ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', values: Object.entries(values).map(([key, item]) => (typeof item === 'string' ? { key, value: item, nature: 'secret' as const } : { key, value: item[0], nature: item[1] })), ...more });
const reveal = (label: string, keys: string[]): UseInput => ({ ...shown(label), project: 'market', environment: 'prod', mine: false, keys, purpose: 'reveal', upstream: null });
const count = async (table: 'log_pending' | 'secret_versions') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
/** The newest change's entry, as the signer will read it: under the vault's MAC. */
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
const given = async (label: string, keys: string[]) => {
  const answer = await vault.use(reveal(label, keys));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.values.map((item) => ('refused' in item ? item.refused : [item.version, item.value]));
};

test('a write gives each key its next version, makes the keys the environment lacks, and a use then opens them as written', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  const done = await vault.change(writing('ada-cli', { DATABASE_URL: 'postgres://nëw', API_KEY: ['sk_test', 'sensitive'], ACCOUNT: ['acct_1', 'plain'] }));
  assert.deepEqual(done, { answer: { versions: { DATABASE_URL: 2, API_KEY: 1, ACCOUNT: 1 } } });
  assert.deepEqual([await count('log_pending'), await count('secret_versions')], [before[0]! + 1, before[1]! + 3]);
  // A plain value's row carries its copy for the pages, and no other does.
  const copies = await rowsOf<{ key: string; plaintext: string | null; sensitive: boolean }>(world.owner, sql`SELECT s.key, v.plaintext, v.sensitive FROM secret_versions v JOIN secrets s ON s.id = v.secret_id AND s.current_version = v.version WHERE s.key IN ('DATABASE_URL', 'API_KEY', 'ACCOUNT') ORDER BY s.key`);
  assert.deepEqual(copies, [{ key: 'ACCOUNT', plaintext: 'acct_1', sensitive: false }, { key: 'API_KEY', plaintext: null, sensitive: true }, { key: 'DATABASE_URL', plaintext: null, sensitive: false }]);
  assert.equal(world.woken.length, 1, 'the signer is told of the one entry');
  // Nobody is handed a sensitive value back: it was sealed as one.
  assert.deepEqual(await given('ada-cli', ['DATABASE_URL', 'API_KEY', 'ACCOUNT']), [[2, 'postgres://nëw'], 'sensitive', [1, 'acct_1']]);

  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.request], ['secret.write', ada, 'req-1']);
  assert.deepEqual((entry.detail as { keys: object[] }).keys.map((item) => ({ ...item, secret: undefined })), [
    { key: 'DATABASE_URL', version: 2, nature: 'secret', secret: undefined },
    { key: 'API_KEY', version: 1, nature: 'sensitive', made: true, secret: undefined },
    { key: 'ACCOUNT', version: 1, nature: 'plain', made: true, secret: undefined },
  ]);
  // It names the rows it was decided on, each with its MAC: who asked and what they hold, the place, and each secret, replaced or made.
  const tables = entry.rows.map(({ row: name, was, now }) => `${(JSON.parse(name) as string[])[0]} ${was === null ? 'made' : was === now ? 'read' : 'replaced'}`).sort();
  // One grant and its role, with her role in the instance: not her grant on billing, nor anyone else's on market.
  assert.deepEqual(tables, ['credentials read', 'environments read', 'grants read', 'principals read', 'projects read', 'roles read', 'roles read', 'secrets made', 'secrets made', 'secrets replaced']);
  assert.ok(entry.objects.includes(`secret:${url.id}`) && entry.objects.includes(`principal:${ada}`), entry.objects.join());
  const [by] = await rowsOf<{ by: string }>(world.owner, sql`SELECT created_by AS by FROM secret_versions WHERE secret_id = ${url.id} AND version = 2`);
  assert.equal(by!.by, ada);
});

test('a write is refused to whoever may not write there, with one answer, and writes nothing', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  const refused = async (label: string, more: Partial<SecretWrite> = {}) => vault.change(writing(label, { DATABASE_URL: 'x' }, more));
  assert.deepEqual(await refused('bo-cli'), { refused: 'no_access' }, 'a viewer');
  assert.deepEqual(await refused('ada-cli', { project: 'billing', environment: 'nowhere' }), { refused: 'no_access' }, 'no such environment');
  assert.deepEqual(await refused('ada-cli', { project: 'nowhere' }), { refused: 'no_access' }, 'no such project');
  assert.deepEqual(await refused('cy-cli', { environment: 'guarded' }), { refused: 'no_access' }, 'a contributor, where the environment is protected');
  assert.deepEqual(await refused('eve-cli', { environment: 'guarded' }), { refused: 'no_access' }, 'a grant on another environment, and one that lapsed');
  assert.deepEqual(await refused('ada-cli', { environment: 'adas' }), { refused: 'no_access' }, 'a personal config, named as if it were an environment');
  assert.deepEqual(await refused('ada-cli', { environment: 'old' }), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await refused('ada-pat'), { refused: 'no_access' }, 'a token whose scope only reads');
  assert.deepEqual(await refused('ada-handle'), { refused: 'unauthenticated' }, 'a handle');
  assert.deepEqual(await refused('nobody'), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.change(writing('ada-cli', { GONE: 'x' })), { refused: 'archived' });
  // A deployment whose service accounts are workloads' sessions or nothing takes no service token.
  const useOnly = openLocalVault(world.db, { ...world, workloads: { noReads: false, useOnly: true } }, { wake: world.wake, now: world.now });
  assert.deepEqual(await useOnly.change(writing('api-token', { DATABASE_URL: 'x' })), { refused: 'unauthenticated' });
  assert.deepEqual([await count('log_pending'), await count('secret_versions'), world.woken.length], [...before, 0]);

  // And made where they may: the contributor in prod, the developer where it is protected, a grant on the environment alone,
  // an Owner of the instance with no grant at all, a service's token.
  for (const [label, more] of [['cy-cli', {}], ['ada-cli', { environment: 'guarded' }], ['eve-cli', {}], ['dee-cli', {}], ['api-token', {}]] as const) assert.ok('answer' in (await refused(label, more)), label);
});

test('a row someone wrote around the vault is no row: a role edited in place grants nothing, and one deleted neither', async () => {
  await world.owner.execute(sql`UPDATE roles SET permissions = permissions || '{grant.manage}' WHERE id = 'developer' AND NOT instance`);
  assert.deepEqual(await vault.change(writing('ada-cli', { DATABASE_URL: 'x' })), { refused: 'no_access' });
  await world.owner.execute(sql`DELETE FROM roles WHERE id = 'owner' AND instance`);
  assert.deepEqual(await vault.change(writing('dee-cli', { DATABASE_URL: 'x' })), { refused: 'no_access' });
  await world.owner.execute(sql`UPDATE projects SET name = 'Market!' WHERE slug = 'market'`);
  assert.deepEqual(await vault.change(writing('cy-cli', { DATABASE_URL: 'x' })), { refused: 'no_access' });
});

test('a key service that fails while a value is sealed fails the write, which writes nothing', async () => {
  const before = [await count('log_pending'), await count('secret_versions')];
  const down = openLocalVault(world.db, { ...world, keks: { wrap: () => Promise.reject(new KekUnavailableError('the key service is down')) } as never }, { wake: world.wake, now: world.now });
  await assert.rejects(down.change(writing('ada-cli', { DATABASE_URL: 'x', NEW: 'y' })), /key service is down/);
  assert.deepEqual([await count('log_pending'), await count('secret_versions'), world.woken.length], [...before, 0]);
});

test('a reference written over holds its own value from then on, and its entry says what it referred to', async () => {
  assert.deepEqual(await given('ada-cli', ['STRIPE_KEY']), [[1, 'sk_live']]);
  assert.deepEqual(await vault.change(writing('ada-cli', { STRIPE_KEY: 'sk_own' })), { answer: { versions: { STRIPE_KEY: 1 } } });
  world.tick(2000);
  assert.deepEqual(await given('ada-cli', ['STRIPE_KEY']), [[1, 'sk_own']]);
  const [key] = ((await written()).detail as { keys: { source?: string }[] }).keys;
  assert.equal(key!.source, stripe.id);
});

test('two writes of one key decided on the same rows are two versions, one after the other: the second starts over, and leaves nothing of its first try', async () => {
  const deciding = { workloads: world.workloads };
  // Both read and decided before either writes, as two requests side by side.
  const [first, second] = await Promise.all(['ada-cli', 'cy-cli'].map((label) => prepare(world, OPERATIONS['secret.write'](writing(label, { DATABASE_URL: `by ${label}`, NEW: `new by ${label}` }), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'the row it read has moved on');
  const versions = async () => (await rowsOf<{ version: number }>(world.owner, sql`SELECT version FROM secret_versions WHERE secret_id = ${url.id} ORDER BY version`)).map((row) => row.version);
  assert.deepEqual(await versions(), [1, 2], 'the version it sealed for its first try is not there');
  // Asked again, as `change` does by itself, it is the next version.
  // The key both would have made is there by now: hers is its next version, not a second key.
  assert.deepEqual(await vault.change(writing('cy-cli', { DATABASE_URL: 'by cy-cli', NEW: 'new by cy-cli' })), { answer: { versions: { DATABASE_URL: 3, NEW: 2 } } });
  assert.deepEqual(await versions(), [1, 2, 3]);
  world.tick(2000);
  assert.deepEqual(await given('ada-cli', ['DATABASE_URL', 'NEW']), [[3, 'by cy-cli'], [2, 'new by cy-cli']]);
});

test('a write that is not what the contract says is a fault, before any read', async () => {
  const one = (value: unknown, key: unknown = 'A', nature: unknown = 'secret') => ({ values: [{ key, value, nature }] });
  const bad: Partial<Record<keyof SecretWrite, unknown>>[] = [
    { values: [] }, { values: 'A' }, { values: [null] }, one('x', 'A', 'public'), one(7), one('x'.repeat(64 * 1024 + 1)), one('a\0b'), one('half \ud83d'), one('x', 'a-b'), one('x', '1A'), one('x', 'A'.repeat(129)), one('x', 7),
    { values: [{ key: 'A', value: 'x', nature: 'secret' }, { key: 'A', value: 'y', nature: 'secret' }] },
    { values: Array.from({ length: 2001 }, (_, i) => ({ key: `K${i}`, value: 'x', nature: 'secret' })) },
    // Each within its own bound, and more than a request's body between them.
    { values: Array.from({ length: 17 }, (_, i) => ({ key: `K${i}`, value: 'x'.repeat(64 * 1024), nature: 'secret' })) },
    { project: 7 }, { environment: 'x'.repeat(257) }, { op: 'secret.erase' }, { op: 'toString' },
  ];
  for (const more of bad) await assert.rejects(vault.change(writing('ada-cli', { A: 'x' }, more as Partial<SecretWrite>)), TypeError, JSON.stringify(more).slice(0, 60));
  await assert.rejects(vault.change({ ...writing('ada-cli', { A: 'x' }), token: 'ada-cli' }), TypeError);
  assert.equal(world.woken.length, 0);
  // What the contract does say: 2,000 keys, and a value of 64 Ki characters.
  const most = await vault.change(writing('ada-cli', Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`K${i}`, i === 0 ? 'é'.repeat(64 * 1024) : 'x']))));
  assert.ok('answer' in most && Object.keys(most.answer.versions).length === 2000, JSON.stringify(most).slice(0, 80));
});

test('a workload\'s session writes as its service may, with its key; one that is narrowed or stopped changes nothing', async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]), policy: '{}' });
  const pod = session('pod', bound);
  await write(world, ...rows('bindings', bound), ...rows('credentials', pod, session('tool', bound, { ancestors: JSON.stringify([pod.id]) })));
  const by = (label: string, proof: string | null = label) => vault.change({ ...writing(label, { DATABASE_URL: `by ${label}` }), proof });

  assert.deepEqual(await by('pod'), { answer: { versions: { DATABASE_URL: 2 } } });
  // Its entry names the binding that issued the session and the instance's policy row: both decided it.
  const tables = (await written()).rows.map(({ row }) => (JSON.parse(row) as string[])[0]);
  assert.ok(tables.includes('bindings') && tables.includes('policy'), tables.join());
  assert.deepEqual(await by('pod', null), { refused: 'unauthenticated' }, 'without its key');
  assert.deepEqual(await by('tool'), { refused: 'narrowed' });
  await amend(world, 'bindings', eq(bindings.id, bound.id), { frozenAt: new Date(world.now()) });
  assert.deepEqual(await by('pod'), { refused: 'frozen' });
});

test('what a caller holds is weighed with the environments asked about: which are protected, and where a grant on one is', async () => {
  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = 'market')`;
  const asking = async (label: string) => {
    let found!: { caller: Asking; rows: Parameters<Asking['holding']>[0] };
    const read = { ...callerParts(tokenOf(label), project), environment: part(environments, sql`${environments.projectId} = ${project}`) };
    await prepare(world, { read, decide: (seen, at) => ((found = { caller: callerFrom(seen, { proof: null, ip: null }, world.workloads, at)!, rows: seen.environment }), { refused: 'only a read' }) });
    return found;
  };
  const { caller: cy, rows } = await asking('cy-cli');
  const [prod, guarded] = ['prod', 'guarded'].map((slug) => rows.find((row) => row.slug === slug)!);
  const whole = cy.holding(rows);
  assert.deepEqual(whole.policy!.protected, [guarded!.id]);
  assert.deepEqual(whole.policy!.protectedIn, { [market.id]: [{ environmentId: guarded!.id, slug: 'guarded' }] });
  assert.deepEqual([cy.may('secret.write', prod!), cy.may('secret.write', guarded!)], [true, false]);
  // A grant on one environment is in that environment's project, as its row says, and nowhere without it.
  const { caller: eve } = await asking('eve-cli');
  const there = { projectId: market.id, environmentId: prod!.id, environmentSlug: 'prod' };
  assert.deepEqual([allows(eve.holding([prod!]), 'secret.write', there), allows(eve.holding([]), 'secret.write', there), eve.may('secret.write', guarded!)], [true, false, false]);
});

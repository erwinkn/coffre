// A key made a reference, and a reference broken (src/ops/secrets.ts),
// through the contract as the app calls it: who may, what the source may
// be, one hop, what the entry names, and what a use then reads.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, Presented, ReferenceBreak, SecretPath, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee] = [user('ada'), user('bo'), user('cy'), user('dee')];
const api = 'token:api';
let market: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let there: ReturnType<typeof environment>;
let [stripe, signing, flag, url, link]: ReturnType<typeof secret>[] = [];
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  billing = project('billing');
  prod = environment(market, 'prod');
  const old = environment(market, 'old', { archivedAt: new Date(Date.UTC(2026, 10, 1)) });
  const adas = environment(market, 'adas', { parentId: prod.id, owner: ada });
  there = environment(billing, 'prod');
  stripe = value(world, secret(there, 'STRIPE_KEY'), 'sk_live');
  signing = value(world, secret(there, 'SIGNING'), 'whsec', { sensitive: true });
  flag = value(world, secret(there, 'FLAG'), 'on', { plain: true });
  url = value(world, secret(prod, 'DATABASE_URL'), 'postgres://old');
  link = secret(prod, 'LINK', { sourceId: stripe.id });
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, old, adas, there),
    ...rows('secrets', stripe, signing, flag, url, link,
      value(world, secret(there, 'RETIRED', { archivedAt: new Date(Date.UTC(2026, 10, 1)) }), 'old'),
      value(world, secret(old, 'KEPT'), 'kept'), value(world, secret(adas, 'MINE'), 'mine'),
      secret(prod, 'GONE', { archivedAt: new Date(Date.UTC(2026, 10, 1)) })),
    // A developer reads and writes; an operator uses too, which a sensitive source asks; a manager manages access, and reads nothing.
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.write', 'secret.archive']), role(false, 'operator', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']),
      role(false, 'viewer', ['secret.read']), role(false, 'manager', ['grant.manage']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(dee), principal(api)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(ada, 'operator', { project: billing }), grant(bo, 'viewer', { project: market }),
      grant(cy, 'developer', { project: market }), grant(cy, 'developer', { project: billing }), grant(dee, 'manager', { project: billing }), grant(bo, 'viewer', { project: billing })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('dee-cli', dee)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const to = (path: string): SecretPath => {
  const [projectSlug, environmentSlug, key] = path.split('/');
  return { project: projectSlug!, environment: environmentSlug!, key: key! };
};
/** A write in market/prod, or the place `more` names: each key a path is made a reference to it. */
const writing = (label: string, keys: Record<string, string | Omit<KeyWrite, 'key'>>, more: Partial<SecretWrite> = {}): Presented & SecretWrite =>
  ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', keys: Object.entries(keys).map(([key, item]) => (typeof item === 'string' ? { key, ref: to(item) } : { key, ...item }) as KeyWrite), ...more });
const breaking = (label: string, key: string, more: Partial<ReferenceBreak> = {}): Presented & ReferenceBreak => ({ ...shown(label), op: 'reference.break', project: 'market', environment: 'prod', key, ...more });
const reveal = (label: string, keys: string[], place = { project: 'market', environment: 'prod' }): UseInput => ({ ...shown(label), ...place, mine: false, keys, purpose: 'reveal', upstream: null });
const given = async (label: string, keys: string[], place?: { project: string; environment: string }) => {
  const answer = await vault.use(reveal(label, keys, place));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.values.map((item) => ('refused' in item ? item.refused : [item.version, item.value]));
};
const written = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
type Held = { key: string; source_id: string | null; versions: number; current_version: number | null; nature: string | null; archived: boolean };
const held = async (key: string, environmentId = prod.id) =>
  (await rowsOf<Held>(world.owner, sql`SELECT key, source_id, versions, current_version, nature, archived_at IS NOT NULL AS archived FROM secrets WHERE environment_id = ${environmentId} AND key = ${key}`))[0];
const lines = async () => ((await written()).detail as { keys: Record<string, unknown>[] }).keys.map(({ secret: _, ...line }) => line);

test('a key made a reference reads its source\'s value, as it changes, and its entry names both ends', async () => {
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'billing/prod/STRIPE_KEY' })), { answer: { keys: {} } });
  assert.deepEqual(await held('NEW'), { key: 'NEW', source_id: stripe.id, versions: 0, current_version: null, nature: null, archived: false });
  const entry = await written();
  assert.equal(entry.action, 'secret.write');
  assert.deepEqual(await lines(), [{ key: 'NEW', refers: stripe.id, made: true }]);
  // The source's pages find it too: its secret, environment and project.
  for (const object of [`secret:${stripe.id}`, `environment:${there.id}`, `project:${billing.id}`, `project:${market.id}`]) assert.ok(entry.objects.includes(object), entry.objects.join());
  // Whoever reads market/prod reads it, by their grants there.
  assert.deepEqual(await given('bo-cli', ['NEW']), [[1, 'sk_live']]);
});

test('a key with a value made a reference keeps it as history; re-pointed, the entry says what it read; the same source writes nothing', async () => {
  assert.ok('answer' in await vault.change(writing('ada-cli', { DATABASE_URL: 'billing/prod/FLAG', LINK: 'billing/prod/SIGNING' })));
  assert.deepEqual(await held('DATABASE_URL'), { key: 'DATABASE_URL', source_id: flag.id, versions: 1, current_version: null, nature: null, archived: false });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', refers: flag.id }, { key: 'LINK', refers: signing.id, source: stripe.id }]);
  assert.deepEqual(await given('bo-cli', ['DATABASE_URL', 'LINK']), [[1, 'on'], 'sensitive']);
  // Its next value is numbered after its history, and is its own: a bare one over a plain source is a secret.
  assert.deepEqual(await vault.change(writing('ada-cli', { DATABASE_URL: { value: 'postgres://new' } })), { answer: { keys: { DATABASE_URL: { version: 2, nature: 'secret' } } } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', version: 2, nature: 'secret', source: flag.id }]);
  assert.deepEqual(await given('bo-cli', ['DATABASE_URL']), [[2, 'postgres://new']]);

  const before = await rowsOf(world.owner, sql`SELECT * FROM secrets WHERE id = ${link.id}`);
  assert.ok('answer' in await vault.change(writing('ada-cli', { LINK: 'billing/prod/SIGNING' })));
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT * FROM secrets WHERE id = ${link.id}`), before, 'a key that reads that source already is left as it is');
  assert.ok(!(await lines()).some((line) => line.key === 'LINK'), 'and no entry says it changed');
});

test('a reference is made only to a live key its maker reads where it is held, never in or to a personal config, and a refusal writes nothing', async () => {
  const before = await kept();
  const refused = async (label: string, keys: Record<string, string | Omit<KeyWrite, 'key'>>, more: Partial<SecretWrite> = {}) => vault.change(writing(label, keys, more));
  assert.deepEqual(await refused('bo-cli', { NEW: 'billing/prod/STRIPE_KEY' }), { refused: 'no_access' }, 'a viewer writes nothing');
  assert.deepEqual(await refused('dee-cli', { NEW: 'billing/prod/STRIPE_KEY' }), { refused: 'no_access' }, 'a manager of the source\'s project, who writes nothing here');
  assert.deepEqual(await refused('ada-cli', { NEW: 'billing/nowhere/STRIPE_KEY' }), { refused: 'no_access' }, 'no such environment');
  assert.deepEqual(await refused('ada-cli', { NEW: 'nowhere/prod/STRIPE_KEY' }), { refused: 'no_access' }, 'no such project');
  assert.deepEqual(await refused('ada-cli', { NEW: 'market/old/KEPT' }), { refused: 'no_access' }, 'an archived environment');
  assert.deepEqual(await refused('ada-cli', { NEW: 'market/adas/MINE' }), { refused: 'no_access' }, 'a personal config, its owner\'s alone');
  assert.deepEqual(await refused('ada-cli', { NEW: 'market/prod/DATABASE_URL' }, { environment: 'adas' }), { refused: 'no_access' }, 'held in a personal config');
  assert.deepEqual(await refused('ada-cli', { NEW: 'billing/prod/NOPE' }), { refused: 'unknown_key' });
  assert.deepEqual(await refused('ada-cli', { NEW: 'billing/prod/RETIRED' }), { refused: 'unknown_key' }, 'an archived key');
  // Reading the source is not enough for a sensitive one: its maker uses it there too.
  assert.deepEqual(await refused('cy-cli', { NEW: 'billing/prod/SIGNING' }), { refused: 'no_access' }, 'a sensitive source, read but not used');
  assert.deepEqual(await refused('ada-cli', { DATABASE_URL: 'market/prod/DATABASE_URL' }), { refused: 'reference_to_itself' });
  assert.deepEqual(await refused('ada-cli', { NEW: 'market/prod/LINK' }), { refused: 'reference_to_reference' }, 'a reference reads a value, never another');
  assert.deepEqual(await refused('ada-cli', { GONE: 'billing/prod/STRIPE_KEY' }), { refused: 'archived' }, 'an archived key is brought back, not written over');
  // All or none: one refused key refuses the write.
  assert.deepEqual(await refused('ada-cli', { NEW: 'billing/prod/STRIPE_KEY', OTHER: 'billing/prod/NOPE' }), { refused: 'unknown_key' });
  assert.equal(await kept(), before);
  assert.equal(await held('NEW'), undefined);

  // What may be: a secret read there, a plain value, a sensitive one used there, and an archived key brought back as a reference.
  assert.ok('answer' in await refused('cy-cli', { A: 'billing/prod/STRIPE_KEY', B: 'billing/prod/FLAG' }));
  assert.ok('answer' in await refused('ada-cli', { C: 'billing/prod/SIGNING', GONE: { ref: to('billing/prod/FLAG'), archived: false } }));
  assert.deepEqual(await held('GONE'), { key: 'GONE', source_id: flag.id, versions: 0, current_version: null, nature: null, archived: false });
});

test('an archived key brought back in the same write is a source, in either order, and one left archived is none', async () => {
  assert.ok('answer' in await vault.change(writing('ada-cli', { DATABASE_URL: { archived: true } })));
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL' })), { refused: 'unknown_key' });
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: { folder: 'db' } })), { refused: 'unknown_key' }, 'filed, still archived');
  assert.equal(await held('NEW'), undefined);
  assert.ok('answer' in await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: { archived: false } })));
  assert.deepEqual(await held('NEW'), { key: 'NEW', source_id: url.id, versions: 0, current_version: null, nature: null, archived: false });
  assert.deepEqual(await given('ada-cli', ['NEW']), [[1, 'postgres://old']]);

  // The other way round: brought back first, then made the source.
  assert.ok('answer' in await vault.change(writing('ada-cli', { NEW: { value: 'x', nature: 'secret' } })));
  assert.ok('answer' in await vault.change(writing('ada-cli', { DATABASE_URL: { archived: true } })));
  assert.ok('answer' in await vault.change(writing('ada-cli', { DATABASE_URL: { archived: false }, OTHER: 'market/prod/DATABASE_URL' })));
  assert.deepEqual(await held('OTHER'), { key: 'OTHER', source_id: url.id, versions: 0, current_version: null, nature: null, archived: false });
});

test('one hop: a key others read is made no reference, and each is decided on what the write leaves', async () => {
  // billing/prod/STRIPE_KEY is read by market/prod/LINK.
  assert.deepEqual(await vault.change(writing('ada-cli', { STRIPE_KEY: 'billing/prod/FLAG' }, { project: 'billing' })), { refused: 'referenced' });
  // In one write: a source made a reference, archived, or given a sensitive value its maker does not use.
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: 'billing/prod/FLAG' })), { refused: 'reference_to_reference' });
  // Taken the other way round, the key made a reference is read by the other: refused all the same.
  assert.deepEqual(await vault.change(writing('ada-cli', { DATABASE_URL: 'billing/prod/FLAG', NEW: 'market/prod/DATABASE_URL' })), { refused: 'referenced' });
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: { archived: true } })), { refused: 'referenced' });
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: { value: 'x', nature: 'sensitive' } })), { refused: 'no_access' });
  // A key the write itself refers away from is no reader: LINK given a value, STRIPE_KEY is read by none.
  assert.equal(await held('NEW'), undefined);
  assert.ok('answer' in await vault.change(writing('ada-cli', { NEW: 'market/prod/DATABASE_URL', DATABASE_URL: { value: 'y', nature: 'secret' } })));
  assert.deepEqual(await given('bo-cli', ['NEW']), [[2, 'y']]);

  // A reader held in an archived key reads nothing, and holds nothing back.
  assert.ok('answer' in await vault.change(writing('ada-cli', { LINK: { archived: true } })));
  assert.ok('answer' in await vault.change(writing('ada-cli', { STRIPE_KEY: 'billing/prod/FLAG' }, { project: 'billing' })));
  assert.deepEqual(await held('STRIPE_KEY', there.id), { key: 'STRIPE_KEY', source_id: flag.id, versions: 1, current_version: null, nature: null, archived: false });
});

test('a workload refers only to a value it is handed back where it is held', async () => {
  // A scope names a role as it ships, which uses too: what the service holds by its grants is the rest.
  const scope = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }, { projectId: billing.id, environmentId: null, role: 'developer' }]);
  const bound = binding(api, { profile: 'kubernetes', scope, policy: '{}' });
  // A binding that lists an environment's keys holds a grant of its own there.
  const listing = binding(api, { profile: 'kubernetes', scope: JSON.stringify([...JSON.parse(scope) as object[], { projectId: billing.id, environmentId: there.id, role: 'developer' }]), policy: JSON.stringify({ reads: { [there.id]: { keys: [stripe.id] } } }) });
  await write(world, ...rows('grants', grant(api, 'developer', { project: market }), grant(api, 'operator', { project: billing })), ...rows('bindings', bound, listing), ...rows('credentials', session('pod', bound), session('lister', listing)));
  const by = (label: string, source: string) => vault.change({ ...writing(label, { NEW: source }), proof: label });
  assert.deepEqual(await by('pod', 'billing/prod/STRIPE_KEY'), { refused: 'use_only' });
  assert.deepEqual(await by('pod', 'billing/prod/SIGNING'), { refused: 'use_only' });
  assert.ok('answer' in await by('pod', 'billing/prod/FLAG'), 'a plain value, which is no secret');
  assert.ok('answer' in await by('lister', 'billing/prod/STRIPE_KEY'), 'one its binding lists');
});

test('a source whose row was edited behind the vault is not referred to', async () => {
  await world.owner.execute(sql`UPDATE secrets SET folder = 'moved' WHERE id = ${stripe.id}`);
  assert.deepEqual(await vault.change(writing('ada-cli', { NEW: 'billing/prod/STRIPE_KEY' })), { refused: 'unreadable' });
  assert.equal(await held('NEW'), undefined);
});

test('a reference is broken by whoever writes its key or manages access where its source is, and reads nothing after', async () => {
  assert.deepEqual(await vault.change(breaking('ada-cli', 'LINK')), { answer: { source: { project: 'billing', environment: 'prod', key: 'STRIPE_KEY' } } });
  assert.deepEqual(await held('LINK'), { key: 'LINK', source_id: null, versions: 0, current_version: null, nature: null, archived: false });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['reference.break', ada, { key: 'LINK', secret: link.id, source: stripe.id }]);
  for (const object of [`secret:${link.id}`, `secret:${stripe.id}`, `project:${billing.id}`, `environment:${there.id}`]) assert.ok(entry.objects.includes(object), entry.objects.join());
  assert.deepEqual(await given('bo-cli', ['LINK']), ['no_value']);
  assert.deepEqual(await vault.change(breaking('ada-cli', 'LINK')), { refused: 'no_reference' });
  assert.deepEqual(await vault.change(writing('ada-cli', { LINK: { value: 'own' } })), { answer: { keys: { LINK: { version: 1, nature: 'secret' } } } });

  // A manager of billing's access, who reads nothing in market, breaks what reads billing's keys.
  assert.ok('answer' in await vault.change(writing('ada-cli', { NEW: 'billing/prod/STRIPE_KEY' })));
  assert.ok('answer' in await vault.change(breaking('dee-cli', 'NEW')));
  assert.equal((await held('NEW'))!.source_id, null);
});

test('a reference is broken by nobody else, and a key that is none is told only to its writer', async () => {
  const before = await kept();
  assert.deepEqual(await vault.change(breaking('bo-cli', 'LINK')), { refused: 'no_access' }, 'a viewer of both ends');
  assert.deepEqual(await vault.change(breaking('dee-cli', 'DATABASE_URL')), { refused: 'no_access' }, 'a manager of billing, of a key that reads nothing there');
  assert.deepEqual(await vault.change(breaking('dee-cli', 'NOPE')), { refused: 'no_access' });
  assert.deepEqual(await vault.change(breaking('ada-cli', 'DATABASE_URL')), { refused: 'no_reference' });
  assert.deepEqual(await vault.change(breaking('ada-cli', 'NOPE')), { refused: 'unknown_key' });
  assert.deepEqual(await vault.change(breaking('ada-cli', 'LINK', { environment: 'nowhere' })), { refused: 'no_access' });
  assert.equal(await kept(), before);
  // The key's row edited behind the vault: its writer is told so, and the source's manager cannot see what it reads.
  await world.owner.execute(sql`UPDATE secrets SET folder = 'moved' WHERE id = ${link.id}`);
  assert.deepEqual(await vault.change(breaking('ada-cli', 'LINK')), { refused: 'unreadable' });
  assert.deepEqual(await vault.change(breaking('dee-cli', 'LINK')), { refused: 'no_access' });
});

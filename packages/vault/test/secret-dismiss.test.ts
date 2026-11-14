// Missing keys dismissed, and restored (src/ops/secrets.ts's
// `missing.dismiss`, 0.14's `setDismissals`), held to what 0.14.7's
// missing.test.ts, inheritance.test.ts and personal.test.ts asserted: the
// team's decision, stored and logged, undone; in a fork or a personal
// config a removal, which a use there then goes without; refused for a key
// held there live; and bounded.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, MissingDismiss, Presented, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { commit, prepare, type Prepared } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { MOST_KEYS } from '../src/ops/input.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const ci = 'token:ci';
const archivedAt = new Date(Date.UTC(2026, 10, 1));
const places: Record<string, ReturnType<typeof environment>> = {};
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const market = project('market');
  // prod and staging are siblings; eu inherits prod, and canary inherits eu. old is archived.
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging');
  const eu = environment(market, 'eu', { parentId: prod.id });
  const canary = environment(market, 'canary', { parentId: eu.id });
  const old = environment(market, 'old', { archivedAt });
  // Ada's personal config of prod; Bo has none.
  const adas = environment(market, 'prod-p-0a0b0c0d', { parentId: prod.id, owner: ada });
  // Cy's, archived.
  const cys = environment(market, 'prod-p-0c0c0c0c', { parentId: prod.id, owner: cy, archivedAt });
  Object.assign(places, { prod, staging, eu, canary, adas });
  const stripe = value(world, secret(prod, 'STRIPE_KEY'), 'sk_live');
  await write(world, ...rows('projects', market), ...rows('environments', prod, staging, eu, canary, old, adas, cys),
    ...rows('secrets', ...['DATABASE_URL', 'SENTRY_DSN'].map((key) => value(world, secret(prod, key), `${key.toLowerCase()}-prod`)), stripe,
      value(world, secret(staging, 'DATABASE_URL'), 'database_url-staging'),
      // eu overrides DATABASE_URL, holds EU_REGION of its own, and LINK, a reference to prod's STRIPE_KEY.
      value(world, secret(eu, 'DATABASE_URL'), 'database_url-eu'), value(world, secret(eu, 'EU_REGION'), 'eu-west-1'), secret(eu, 'LINK', { sourceId: stripe.id }),
      value(world, secret(adas, 'LOCAL'), 'ada-local')),
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy), principal(ci)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(cy, 'developer', { project: market }), grant(bo, 'viewer', { project: market }), grant(ci, 'developer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy), credential('ci', ci)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const dismissing = (environment: string, keys: Record<string, boolean>, label = 'ada-cli', more: Partial<MissingDismiss> = {}): Presented & MissingDismiss =>
  ({ ...shown(label), op: 'missing.dismiss', project: 'market', environment, keys: Object.entries(keys).map(([key, dismissed]) => ({ key, dismissed })), ...more });
const dismiss = (environment: string, keys: Record<string, boolean>, label?: string, more?: Partial<MissingDismiss>) => vault.change(dismissing(environment, keys, label, more));
/** What a use of the environment is given for each key: its value, or why not. */
const given = async (environment: string, keys: string[], more: Partial<UseInput> = {}) => {
  world.memory.reads.clear();
  const answer = await vault.use({ ...shown('ada-cli'), project: 'market', environment, mine: false, keys, purpose: 'reveal', upstream: null, ...more });
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
/** Every dismissal row: whose environment, its key, who dismissed it, and who restored it, if anyone. */
const dismissals = async () => rowsOf<{ slug: string; key: string; by: string; restored: string | null }>(world.owner,
  sql`SELECT e.slug, d.key, d.dismissed_by AS by, d.restored_by AS restored FROM dismissed_keys d JOIN environments e ON e.id = d.environment_id ORDER BY e.slug, d.key`);
/** The newest kept entry: its action and what it says. */
const logged = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  const entry = entryOf(world.keys, row!)!;
  return { action: entry.action, detail: entry.detail };
};
const entries = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;

test('dismissals are the team\'s: one change for several keys, stored, logged once, and undone; dismissing one already dismissed changes nothing', async () => {
  assert.deepEqual(await dismiss('staging', { SENTRY_DSN: true, STRIPE_KEY: true }), { answer: { keys: { SENTRY_DSN: 'dismissed', STRIPE_KEY: 'dismissed' } } });
  assert.deepEqual(await dismissals(), [{ slug: 'staging', key: 'SENTRY_DSN', by: ada, restored: null }, { slug: 'staging', key: 'STRIPE_KEY', by: ada, restored: null }]);
  // "Dismiss all" is one action: one entry, naming each key.
  assert.deepEqual(await logged(), { action: 'missing.dismiss', detail: { dismissed: ['SENTRY_DSN', 'STRIPE_KEY'], restored: [] } });

  // Again, nothing changes; restoring one brings it back.
  assert.deepEqual(await dismiss('staging', { SENTRY_DSN: true, STRIPE_KEY: false }), { answer: { keys: { SENTRY_DSN: 'unchanged', STRIPE_KEY: 'restored' } } });
  assert.deepEqual(await logged(), { action: 'missing.dismiss', detail: { dismissed: [], restored: ['STRIPE_KEY'] } });
  assert.deepEqual(await dismissals(), [{ slug: 'staging', key: 'SENTRY_DSN', by: ada, restored: null }, { slug: 'staging', key: 'STRIPE_KEY', by: ada, restored: ada }]);
  // Dismissed again, by someone else: theirs now, and no longer restored. Restoring one that is not dismissed changes nothing.
  assert.deepEqual(await dismiss('staging', { STRIPE_KEY: true, PROD_ONLY: false }, 'cy-cli'), { answer: { keys: { STRIPE_KEY: 'dismissed', PROD_ONLY: 'unchanged' } } });
  assert.deepEqual(await dismissals(), [{ slug: 'staging', key: 'SENTRY_DSN', by: ada, restored: null }, { slug: 'staging', key: 'STRIPE_KEY', by: cy, restored: null }]);
  // Outside a fork, a key the environment holds is dismissed as any other: moot, and allowed, as in 0.14.7. Its value serves still.
  assert.deepEqual(await dismiss('staging', { DATABASE_URL: true }), { answer: { keys: { DATABASE_URL: 'dismissed' } } });
  assert.deepEqual(await given('staging', ['DATABASE_URL']), ['database_url-staging']);
});

test('dismissing takes writing there: a viewer, a place not there and an archived one are refused alike, and nothing is written', async () => {
  const before = await entries();
  assert.deepEqual(await dismiss('staging', { SENTRY_DSN: true }, 'bo-cli'), { refused: 'no_access' });
  assert.deepEqual(await dismiss('nowhere', { SENTRY_DSN: true }), { refused: 'no_access' });
  assert.deepEqual(await dismiss('old', { SENTRY_DSN: true }), { refused: 'no_access' });
  assert.deepEqual(await dismiss('staging', { SENTRY_DSN: true }, 'ada-cli', { project: 'billing' }), { refused: 'no_access' });
  assert.deepEqual(await dismissals(), []);
  assert.equal(await entries(), before);
});

test('in a fork a dismissal is a removal: a use there goes without the key, and so do its forks, until it is restored; the parent is untouched', async () => {
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['sentry_dsn-prod']);
  assert.deepEqual(await dismiss('eu', { SENTRY_DSN: true }), { answer: { keys: { SENTRY_DSN: 'dismissed' } } });
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['unknown_key']);
  assert.deepEqual(await given('canary', ['SENTRY_DSN', 'STRIPE_KEY']), ['unknown_key', 'sk_live']);
  assert.deepEqual(await given('prod', ['SENTRY_DSN']), ['sentry_dsn-prod']);
  assert.deepEqual(await dismiss('eu', { SENTRY_DSN: false }), { answer: { keys: { SENTRY_DSN: 'restored' } } });
  assert.deepEqual(await given('canary', ['SENTRY_DSN']), ['sentry_dsn-prod']);
});

test('a fork removes only what it inherits: a key it holds a value or a reference of is refused, the whole change with it; reset first, it is removed', async () => {
  for (const key of ['DATABASE_URL', 'EU_REGION', 'LINK']) assert.deepEqual(await dismiss('eu', { SENTRY_DSN: true, [key]: true }), { refused: 'held_here' }, key);
  assert.deepEqual(await dismissals(), []);
  // Restoring one it holds is no removal: nothing to refuse, and nothing to do.
  assert.deepEqual(await dismiss('eu', { DATABASE_URL: false }), { answer: { keys: { DATABASE_URL: 'unchanged' } } });
  // Reset to what prod passes down, its own value set aside: the removal holds, and a use goes without the key.
  assert.ok('answer' in await vault.change({ ...shown('ada-cli'), op: 'secret.write', project: 'market', environment: 'eu', keys: [{ key: 'DATABASE_URL', inherit: true }] }));
  assert.deepEqual(await dismiss('eu', { DATABASE_URL: true }), { answer: { keys: { DATABASE_URL: 'dismissed' } } });
  assert.deepEqual(await given('eu', ['DATABASE_URL']), ['unknown_key']);
});

test('a reset key that was then removed, written again as the reference it was: it is the fork\'s own again, and no longer removed', async () => {
  const eu = (keys: KeyWrite[]) => vault.change({ ...shown('ada-cli'), op: 'secret.write', project: 'market', environment: 'eu', keys });
  const link = { key: 'SENTRY_DSN', ref: { project: 'market', environment: 'prod', key: 'STRIPE_KEY' } };
  assert.ok('answer' in await eu([link]));
  assert.ok('answer' in await eu([{ key: 'SENTRY_DSN', inherit: true }]));
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['sentry_dsn-prod']);
  assert.deepEqual(await dismiss('eu', { SENTRY_DSN: true }), { answer: { keys: { SENTRY_DSN: 'dismissed' } } });
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['unknown_key']);
  // The same source: the key reads it already, but it was set aside, and removed.
  assert.deepEqual(await eu([link]), { answer: { keys: {}, outcomes: { SENTRY_DSN: 'changed' } } });
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['sk_live']);
  assert.deepEqual(await dismissals(), [{ slug: 'eu', key: 'SENTRY_DSN', by: ada, restored: ada }]);
});

test("a personal config's dismissals are its owner's, once they have one: a removal for them alone; a key it holds is refused there too", async () => {
  assert.deepEqual(await dismiss('prod', { STRIPE_KEY: true }, 'ada-cli', { mine: true }), { answer: { keys: { STRIPE_KEY: 'dismissed' } } });
  assert.deepEqual(await dismissals(), [{ slug: 'prod-p-0a0b0c0d', key: 'STRIPE_KEY', by: ada, restored: null }]);
  assert.deepEqual((await logged()).detail, { personal: 'prod', dismissed: ['STRIPE_KEY'], restored: [] });
  assert.deepEqual(await given('prod', ['STRIPE_KEY', 'LOCAL'], { mine: true }), ['unknown_key', 'ada-local']);
  assert.deepEqual(await given('prod', ['STRIPE_KEY']), ['sk_live']);
  assert.deepEqual(await dismiss('prod', { LOCAL: true }, 'ada-cli', { mine: true }), { refused: 'held_here' });
  // Bo has no config of prod: a dismissal makes none, and never falls back to prod.
  assert.deepEqual(await dismiss('prod', { STRIPE_KEY: true }, 'bo-cli', { mine: true }), { refused: 'no_config' });
  // A service account keeps none.
  assert.deepEqual(await dismiss('prod', { STRIPE_KEY: true }, 'ci', { mine: true }), { refused: 'not_a_person' });
  // Nobody names another's config by its slug: it is no environment of the team's.
  assert.deepEqual(await dismiss('prod-p-0a0b0c0d', { SENTRY_DSN: true }), { refused: 'no_access' });
  // An archived config is written in no more than an archived environment.
  assert.deepEqual(await dismiss('prod', { STRIPE_KEY: true }, 'cy-cli', { mine: true }), { refused: 'no_access' });
  assert.deepEqual((await dismissals()).length, 1);
});

test("a credential edited behind the vault to name another is nobody: it reaches no one's config", async () => {
  await world.owner.execute(sql`UPDATE credentials SET principal = ${ada} WHERE principal = ${bo}`);
  assert.deepEqual(await dismiss('prod', { STRIPE_KEY: true }, 'bo-cli', { mine: true }), { refused: 'unauthenticated' });
  assert.deepEqual(await dismissals(), []);
});

test('a row of the keys named edited behind the vault is not guessed at: a dismissal, or a key the fork holds', async () => {
  assert.ok('answer' in await dismiss('eu', { SENTRY_DSN: true }));
  await world.owner.execute(sql`UPDATE dismissed_keys SET dismissed_by = 'someone' WHERE key = 'SENTRY_DSN'`);
  assert.deepEqual(await dismiss('eu', { SENTRY_DSN: false }), { refused: 'unreadable' });
  await world.owner.execute(sql`UPDATE secrets SET folder = 'x' WHERE key = 'EU_REGION'`);
  assert.deepEqual(await dismiss('eu', { EU_REGION: true }), { refused: 'unreadable' });
  // Rows of keys not named decide nothing.
  assert.deepEqual(await dismiss('eu', { STRIPE_KEY: true }), { answer: { keys: { STRIPE_KEY: 'dismissed' } } });
});

test(`one change dismisses ${MOST_KEYS} keys at most: one more is refused, nothing read of them or written, once the caller may write there`, async () => {
  const keys = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`KEY_${i}`, true]));
  assert.deepEqual(await dismiss('staging', keys(MOST_KEYS + 1), 'bo-cli'), { refused: 'no_access' });
  assert.deepEqual(await dismiss('staging', keys(MOST_KEYS + 1)), { refused: 'too_many_dismissals' });
  assert.deepEqual(await dismissals(), []);
  const done = await dismiss('staging', keys(MOST_KEYS));
  assert.ok('answer' in done && Object.values(done.answer.keys).every((outcome) => outcome === 'dismissed'));
  assert.equal((await dismissals()).length, MOST_KEYS);
});

test('a key the fork is given a value of between the dismissal\'s read and its write: the dismissal starts over, and is refused', async () => {
  const input = dismissing('eu', { SENTRY_DSN: true });
  const prepared = await prepare(world, OPERATIONS[input.op](input as never, { workloads: world.workloads, owners: world.owners }));
  assert.ok(!('refused' in prepared));
  assert.ok('answer' in await vault.change({ ...shown('cy-cli'), op: 'secret.write', project: 'market', environment: 'eu', keys: [{ key: 'SENTRY_DSN', value: 'sentry-eu' }] }));
  assert.equal(await commit(world, prepared as Prepared<unknown>), false);
  assert.deepEqual(await dismissals(), []);
  assert.deepEqual(await dismiss('eu', { SENTRY_DSN: true }), { refused: 'held_here' });
  assert.deepEqual(await given('eu', ['SENTRY_DSN']), ['sentry-eu']);
});

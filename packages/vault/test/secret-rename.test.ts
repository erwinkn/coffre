// A key renamed (src/ops/secrets.ts's `secret.rename`, 0.14's `patchSecret`
// and `renameBelow`): who may, which names, and the name carried down to
// every fork below, overrides, dismissals and personal configs' keys.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Presented, SecretRename, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, dismissed, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const archivedAt = new Date(Date.UTC(2026, 10, 1));
const places: Record<string, { id: string }> = {};
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const [market, billing] = [project('market'), project('billing')];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { parentId: prod.id });
  // A fork of a fork, and one archived: the name carries down to each.
  const eu = environment(market, 'eu', { parentId: staging.id });
  const old = environment(market, 'old', { parentId: prod.id, archivedAt });
  // Ada's config of staging, and Cy's of prod.
  const adas = environment(market, 'staging-p-0a0b0c0d', { parentId: staging.id, owner: ada });
  const cys = environment(market, 'prod-p-0e0f0a0b', { parentId: prod.id, owner: cy });
  const there = environment(billing, 'prod');
  Object.assign(places, { prod, staging, eu, old, adas, cys });
  const stripe = value(world, secret(prod, 'STRIPE_KEY'), 'stripe-prod');
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, staging, eu, old, adas, cys, there),
    ...rows('secrets', stripe, value(world, secret(prod, 'DATABASE_URL'), 'database-prod'), value(world, secret(prod, 'EXTRA'), 'extra-prod'),
      value(world, secret(prod, 'STRIPE_SECRET_KEY_2'), 'stripe-2-prod'), value(world, secret(prod, 'GONE', { archivedAt }), 'gone-prod'),
      value(world, secret(prod, 'TAKEN', { archivedAt }), 'taken-prod'), value(world, secret(prod, 'SHOWN'), 'shown-prod', { sensitive: true }),
      // Staging overrides it, and holds a key of its own; the archived fork overrides it too.
      value(world, secret(staging, 'STRIPE_KEY'), 'stripe-staging'), value(world, secret(staging, 'ONLY'), 'only-staging'), value(world, secret(old, 'STRIPE_KEY'), 'stripe-old'),
      // Ada overrides it in her config, and holds a key of the name it is about to take, of her own.
      value(world, secret(adas, 'STRIPE_KEY'), 'stripe-ada'), value(world, secret(adas, 'STRIPE_SECRET_KEY'), 'local-ada'),
      // Cy holds one of the name the database's will take, archived.
      value(world, secret(cys, 'DB', { archivedAt }), 'db-cy'),
      // Billing reads prod's STRIPE_KEY.
      secret(there, 'REF', { sourceId: stripe.id })),
    // EU does without it; staging does without the name prod's database is about to take, and without prod's EXTRA.
    ...rows('dismissedKeys', dismissed(eu, 'STRIPE_KEY'), dismissed(staging, 'DB'), dismissed(staging, 'EXTRA'), dismissed(cys, 'DB_2')),
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']), role(false, 'contributor', ['secret.use', 'secret.write']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(ada, 'developer', { project: billing }), grant(bo, 'viewer', { project: market }), grant(cy, 'contributor', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const rename = (label: string, key: string, to: string, more: Partial<SecretRename> = {}) =>
  vault.change({ ...shown(label), op: 'secret.rename', project: 'market', environment: 'prod', key, to, ...more });
const given = async (environment: string, keys: string[], more: Partial<UseInput> = {}) => {
  // As read now: a use within the vault's memory reads nothing again.
  world.memory.reads.clear();
  const answer = await vault.use({ ...shown('ada-cli'), project: 'market', environment, mine: false, keys, purpose: 'reveal', upstream: null, ...more });
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
const nameOf = (id: string) => Object.entries(places).find(([, place]) => place.id === id)?.[0];
/** The last entry kept: its action, and its changes with each environment by name. */
const entry = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  const said = entryOf(world.keys, row!)!;
  const detail = said.detail as { key: string; to: string; changes: Record<string, unknown>[] };
  return { action: said.action, key: detail.key, to: detail.to, changes: detail.changes.map(({ secret: _, environment, ...line }) => ({ in: nameOf(environment as string), ...line })) };
};
const keys = async () => (await rowsOf<{ environment: string; key: string }>(world.owner, sql`SELECT environment_id AS environment, key FROM secrets ORDER BY key`))
  .flatMap((row) => (nameOf(row.environment) === undefined ? [] : [`${nameOf(row.environment)}/${row.key}`])).sort();
const dismissals = async () => (await rowsOf<{ environment: string; key: string; restored: boolean }>(world.owner, sql`SELECT environment_id AS environment, key, restored_at IS NOT NULL AS restored FROM dismissed_keys`))
  .map((row) => `${nameOf(row.environment)}/${row.key}${row.restored ? ' restored' : ''}`).sort();
const count = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;

test('a rename carries down to every fork below: overrides, dismissals, and a personal config\'s own key moved out of the way', async () => {
  const id = (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE environment_id = ${places.prod!.id} AND key = 'STRIPE_KEY'`))[0]!.id;
  assert.deepEqual(await rename('ada-cli', 'STRIPE_KEY', 'STRIPE_SECRET_KEY'), { answer: { id } });
  assert.deepEqual(await entry(), {
    action: 'secret.rename', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY', changes: [
      { in: 'prod', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY' },
      { in: 'eu', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY', dismissed: true },
      { in: 'old', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY' },
      { in: 'staging', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY' },
      // Its own of the new name takes the first name nothing it reads has: prod holds `_2`.
      { in: 'adas', key: 'STRIPE_SECRET_KEY', to: 'STRIPE_SECRET_KEY_3', aside: true },
      { in: 'adas', key: 'STRIPE_KEY', to: 'STRIPE_SECRET_KEY' },
    ],
  });
  assert.ok((await keys()).every((key) => !key.endsWith('/STRIPE_KEY')));
  assert.ok((await keys()).includes('adas/STRIPE_SECRET_KEY_3'));
  assert.deepEqual(await dismissals(), ['cys/DB_2', 'eu/STRIPE_KEY restored', 'eu/STRIPE_SECRET_KEY', 'staging/DB', 'staging/EXTRA']);
  // Each reads what it read, under the new name: no fork exports its old override beside the key renamed.
  assert.deepEqual(await given('prod', ['STRIPE_SECRET_KEY', 'STRIPE_KEY']), ['stripe-prod', 'unknown_key']);
  assert.deepEqual(await given('staging', ['STRIPE_SECRET_KEY', 'STRIPE_KEY']), ['stripe-staging', 'unknown_key']);
  assert.deepEqual(await given('eu', ['STRIPE_SECRET_KEY', 'STRIPE_KEY']), ['unknown_key', 'unknown_key']);
  assert.deepEqual(await given('staging', ['STRIPE_SECRET_KEY', 'STRIPE_SECRET_KEY_3'], { mine: true }), ['stripe-ada', 'local-ada']);
  // A reference reads the key by its id, whatever its name.
  assert.deepEqual(await vault.use({ ...shown('ada-cli'), project: 'billing', environment: 'prod', mine: false, keys: ['REF'], purpose: 'reveal', upstream: null }).then((answer) => ('values' in answer ? answer.values.map((item) => ('value' in item ? item.value : item.refused)) : answer)), ['stripe-prod']);
});

test('a fork that dismissed the new name alone reads the key renamed; one written onto a name its own environment dismissed serves there', async () => {
  assert.deepEqual(await given('staging', ['DB']), ['unknown_key']);
  assert.ok('answer' in (await rename('ada-cli', 'DATABASE_URL', 'DB')));
  assert.deepEqual((await entry()).changes, [
    { in: 'prod', key: 'DATABASE_URL', to: 'DB' },
    // Cy's archived DB is moved out of the way; archived, it serves nothing, so its own dismissal of that name stands.
    { in: 'cys', key: 'DB', to: 'DB_2', aside: true },
    { in: 'staging', key: 'DB', dismissed: false },
  ]);
  assert.deepEqual(await given('staging', ['DB']), ['database-prod']);
  assert.deepEqual(await dismissals(), ['cys/DB_2', 'eu/STRIPE_KEY', 'staging/DB restored', 'staging/EXTRA']);
  // Staging's own key renamed onto EXTRA, which it dismissed: its own serves.
  assert.ok('answer' in (await rename('ada-cli', 'ONLY', 'EXTRA', { environment: 'staging' })));
  assert.deepEqual((await entry()).changes, [{ in: 'staging', key: 'ONLY', to: 'EXTRA' }, { in: 'staging', key: 'EXTRA', dismissed: false }]);
  assert.deepEqual(await given('staging', ['EXTRA', 'ONLY']), ['only-staging', 'unknown_key']);
});

test("a personal config's key moved aside takes no name a parent above the one renamed passes down", async () => {
  // Staging's ONLY becomes STRIPE_SECRET_KEY, which Ada holds of her own: prod, above staging, holds `_2`.
  assert.ok('answer' in (await rename('ada-cli', 'ONLY', 'STRIPE_SECRET_KEY', { environment: 'staging' })));
  assert.deepEqual((await entry()).changes, [
    { in: 'staging', key: 'ONLY', to: 'STRIPE_SECRET_KEY' },
    { in: 'adas', key: 'STRIPE_SECRET_KEY', to: 'STRIPE_SECRET_KEY_3', aside: true },
  ]);
  assert.deepEqual(await given('staging', ['STRIPE_SECRET_KEY', 'STRIPE_SECRET_KEY_3'], { mine: true }), ['only-staging', 'local-ada']);
});

test('a shared fork that holds the new name of its own refuses the rename, and nothing is written', async () => {
  const before = [await keys(), await dismissals(), await count()];
  assert.deepEqual(await rename('ada-cli', 'DATABASE_URL', 'ONLY'), { refused: 'duplicate_key_below' });
  assert.deepEqual([await keys(), await dismissals(), await count()], before);
});

test('a rename takes a live key, onto a name its environment holds nowhere, by whoever writes keys there', async () => {
  assert.deepEqual(await rename('ada-cli', 'NOWHERE', 'X'), { refused: 'unknown_key' });
  assert.deepEqual(await rename('ada-cli', 'GONE', 'X'), { refused: 'archived' });
  assert.deepEqual(await rename('ada-cli', 'DATABASE_URL', 'EXTRA'), { refused: 'duplicate_key' });
  assert.deepEqual(await rename('ada-cli', 'DATABASE_URL', 'TAKEN'), { refused: 'duplicate_key' }, 'an archived key keeps its name');
  assert.deepEqual(await rename('bo-cli', 'DATABASE_URL', 'X'), { refused: 'no_access' }, 'a viewer');
  assert.deepEqual(await rename('ada-cli', 'DATABASE_URL', 'X', { project: 'nowhere' }), { refused: 'no_access' });
  assert.deepEqual(await rename('ada-cli', 'STRIPE_KEY', 'X', { environment: 'old' }), { refused: 'no_access' }, 'an archived environment');
  // A Contributor writes, and does not archive or read: a rename moves no value. Sensitive or not.
  assert.ok('answer' in (await rename('cy-cli', 'SHOWN', 'HIDDEN')));
  assert.deepEqual(await given('prod', ['HIDDEN']), ['sensitive']);
  // Onto its own name, nothing changes, and the entry says it was asked.
  const before = await keys();
  assert.ok('answer' in (await rename('ada-cli', 'EXTRA', 'EXTRA')));
  assert.deepEqual(await entry(), { action: 'secret.rename', key: 'EXTRA', to: 'EXTRA', changes: [] });
  assert.deepEqual(await keys(), before);
});

test("in a personal config, its owner alone renames, and nothing below carries it", async () => {
  assert.ok('answer' in (await rename('ada-cli', 'STRIPE_SECRET_KEY', 'LOCAL', { environment: 'staging', mine: true })));
  assert.deepEqual((await entry()).changes, [{ in: 'adas', key: 'STRIPE_SECRET_KEY', to: 'LOCAL' }]);
  assert.deepEqual(await given('staging', ['LOCAL'], { mine: true }), ['local-ada']);
  // Bo has no config of staging: no key there.
  assert.deepEqual(await rename('bo-cli', 'LOCAL', 'X', { environment: 'staging', mine: true }), { refused: 'unknown_key' });
  assert.deepEqual(await rename('bo-cli', 'LOCAL', 'X', { environment: 'staging' }), { refused: 'no_access' });
});

test('a row the cascade decides on that was edited behind the vault refuses the rename, rather than leave a fork behind', async () => {
  const tampered = async (edit: ReturnType<typeof sql>, undo: ReturnType<typeof sql>, label: string) => {
    await world.owner.execute(edit);
    assert.deepEqual(await rename('ada-cli', 'STRIPE_KEY', 'STRIPE_SECRET_KEY'), { refused: 'unreadable' }, label);
    await world.owner.execute(undo);
  };
  await tampered(sql`UPDATE secrets SET folder = 'x' WHERE environment_id = ${places.old!.id} AND key = 'STRIPE_KEY'`, sql`UPDATE secrets SET folder = NULL WHERE environment_id = ${places.old!.id}`, "an archived fork's override");
  await tampered(sql`UPDATE dismissed_keys SET dismissed_by = 'nobody' WHERE environment_id = ${places.eu!.id}`, sql`UPDATE dismissed_keys SET dismissed_by = 'user:root@acme.example' WHERE environment_id = ${places.eu!.id}`, "a fork's dismissal");
  await tampered(sql`UPDATE environments SET name = 'x' WHERE id = ${places.eu!.id}`, sql`UPDATE environments SET name = 'eu' WHERE id = ${places.eu!.id}`, 'a fork itself');
  // Above, a row decides only the name a key moved aside takes: a rename that moves none goes through.
  await world.owner.execute(sql`UPDATE secrets SET folder = 'x' WHERE environment_id = ${places.prod!.id} AND key = 'STRIPE_SECRET_KEY_2'`);
  assert.deepEqual(await rename('ada-cli', 'ONLY', 'STRIPE_SECRET_KEY', { environment: 'staging' }), { refused: 'unreadable' });
  assert.ok('answer' in (await rename('ada-cli', 'ONLY', 'STRIPE_SECRET', { environment: 'staging' })));
  // Put back, each refusal above refused only what it says: the rename goes through.
  await world.owner.execute(sql`UPDATE secrets SET folder = NULL WHERE environment_id = ${places.prod!.id}`);
  assert.ok('answer' in (await rename('ada-cli', 'STRIPE_KEY', 'STRIPE_SECRET_KEY')));
});

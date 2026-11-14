// A fork's key reset to what a parent passes down, and that undone
// (src/ops/secrets.ts's `inherit`, 0.14's `inheritSecret`): who may, which
// keys, what a use then reads, and a value written over a reset key.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { KeyWrite, Presented, SecretWrite, UseInput } from '@coffre/core/vault';
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
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const [market, billing] = [project('market'), project('billing')];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { parentId: prod.id });
  const old = environment(market, 'old', { archivedAt });
  const child = environment(market, 'child', { parentId: old.id });
  const there = environment(billing, 'prod');
  const shared = value(world, secret(staging, 'SHARED'), 'shared-staging');
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, staging, old, child, there),
    ...rows('secrets',
      ...['DATABASE_URL', 'API', 'SESSION', 'EXTRA', 'SHARED'].map((key) => value(world, secret(prod, key), `${key.toLowerCase()}-prod`)),
      value(world, secret(staging, 'DATABASE_URL'), 'database_url-staging'), value(world, secret(staging, 'ONLY'), 'only-staging'), shared,
      // Reset already: an override set aside, its parent's read instead. And one reset, then dismissed.
      value(world, secret(staging, 'API', { archivedAt }), 'api-staging'), value(world, secret(staging, 'SESSION', { archivedAt }), 'session-staging'),
      // Archived, and no parent holds it: archived as anywhere.
      value(world, secret(staging, 'GONE', { archivedAt }), 'gone-staging'),
      // A sensitive key overridden by a value that is not, and the other way round.
      value(world, secret(prod, 'TOKEN'), 'token-prod', { sensitive: true }), value(world, secret(staging, 'TOKEN'), 'token-staging'),
      value(world, secret(prod, 'PIN'), 'pin-prod'), value(world, secret(staging, 'PIN'), 'pin-staging', { sensitive: true }),
      value(world, secret(old, 'KEY'), 'key-old'), value(world, secret(child, 'KEY'), 'key-child'),
      // Billing reads staging's SHARED.
      secret(there, 'REF', { sourceId: shared.id })),
    ...rows('dismissedKeys', dismissed(staging, 'SESSION'), dismissed(staging, 'EXTRA')),
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(false, 'viewer', ['secret.read']), role(false, 'contributor', ['secret.use', 'secret.write']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'developer', { project: market }), grant(bo, 'viewer', { project: market }), grant(cy, 'contributor', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (label: string, keys: KeyWrite[], more: Partial<SecretWrite> = {}): Presented & SecretWrite => ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'staging', keys, ...more });
const reset = (label: string, key: string, inherit = true, more: Partial<SecretWrite> = {}) => vault.change(writing(label, [{ key, inherit }], more));
const given = async (keys: string[], more: Partial<UseInput> = {}) => {
  // As read now: a use within the vault's memory reads nothing again.
  world.memory.reads.clear();
  const answer = await vault.use({ ...shown('ada-cli'), project: 'market', environment: 'staging', mine: false, keys, purpose: 'reveal', upstream: null, ...more });
  if ('refused' in answer) return answer.refused;
  return answer.values.map((item) => ('refused' in item ? item.refused : item.value));
};
const lines = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return ((entryOf(world.keys, row!)!.detail as { keys: Record<string, unknown>[] }).keys).map(({ secret: _, ...line }) => line);
};
const dismissals = async () => rowsOf(world.owner, sql`SELECT key, restored_by AS by FROM dismissed_keys ORDER BY key`);

test("a fork's key reset reads its parent's, its own kept; undone, its own serves again", async () => {
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL'), { answer: { keys: {} } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', archived: true, reset: true }]);
  assert.deepEqual(await given(['DATABASE_URL']), ['database_url-prod']);
  // Reset already, it is left as it is.
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL'), { answer: { keys: {} } });
  assert.deepEqual(await lines(), []);
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL', false), { answer: { keys: {} } });
  assert.deepEqual(await lines(), [{ key: 'DATABASE_URL', archived: false, reset: false }]);
  assert.deepEqual(await given(['DATABASE_URL']), ['database_url-staging']);
});

test('a reset takes writing there, as an override does; its undoing reading too, since the value serves again', async () => {
  assert.deepEqual(await reset('bo-cli', 'DATABASE_URL'), { refused: 'no_access' }, 'a viewer');
  // A Contributor writes, and does not archive: a reset is no archiving.
  assert.deepEqual(await reset('cy-cli', 'DATABASE_URL'), { answer: { keys: {} } });
  assert.deepEqual(await reset('cy-cli', 'DATABASE_URL', false), { refused: 'no_access' }, 'a contributor, who does not read its value');
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL', false), { answer: { keys: {} } });
});

test("a key no live parent passes down is not reset, nor is its reset undone: that is an archiving", async () => {
  assert.deepEqual(await reset('ada-cli', 'ONLY'), { refused: 'not_inherited' }, 'a key the fork alone holds');
  assert.deepEqual(await reset('ada-cli', 'GONE', false), { refused: 'not_inherited' }, 'an archived key no parent holds');
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL', true, { environment: 'prod' }), { refused: 'not_inherited' }, 'an environment that inherits from none');
  assert.deepEqual(await reset('ada-cli', 'KEY', true, { environment: 'child' }), { refused: 'not_inherited' }, 'a parent archived, through which a use reads nothing');
  assert.deepEqual(await reset('ada-cli', 'NOWHERE'), { refused: 'unknown_key' });
});

test('a reset key is as sensitive as what it then reads, and its undoing as its own value: neither hands a sensitive value back', async () => {
  assert.deepEqual(await given(['TOKEN', 'PIN']), ['token-staging', 'sensitive']);
  for (const key of ['TOKEN', 'PIN']) assert.ok('answer' in (await reset('ada-cli', key)));
  assert.deepEqual(await given(['TOKEN', 'PIN']), ['sensitive', 'pin-prod']);
  // Undone by a Contributor, who does not read: refused; by one who reads, each serves its own again.
  assert.deepEqual(await reset('cy-cli', 'PIN', false), { refused: 'no_access' });
  for (const key of ['TOKEN', 'PIN']) assert.ok('answer' in (await reset('ada-cli', key, false)));
  assert.deepEqual(await given(['TOKEN', 'PIN']), ['token-staging', 'sensitive']);
});

test('a key a reference reads is not reset: its readers would read nothing', async () => {
  assert.deepEqual(await reset('ada-cli', 'SHARED'), { refused: 'referenced' });
});

test('a value, a version or a reference written over a reset key makes it an override again; any other archived key stays archived', async () => {
  assert.deepEqual(await vault.change(writing('cy-cli', [{ key: 'API', value: 'api-new' }])), { answer: { keys: { API: { version: 2, nature: 'secret' } } } });
  assert.deepEqual(await lines(), [{ key: 'API', version: 2, nature: 'secret', archived: false }]);
  assert.deepEqual(await given(['API']), ['api-new']);
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'GONE', value: 'x' }])), { refused: 'archived' });
  assert.deepEqual(await reset('ada-cli', 'API'), { answer: { keys: {} } });
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'API', restore: 1 }])), { answer: { keys: { API: { version: 3, nature: 'secret' } } } });
  assert.deepEqual(await given(['API']), ['api-staging']);
  assert.deepEqual(await reset('ada-cli', 'API'), { answer: { keys: {} } });
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'API', ref: { project: 'market', environment: 'prod', key: 'EXTRA' } }])), { answer: { keys: {} } });
  assert.deepEqual((await lines()).map(({ refers: _, ...line }) => line), [{ key: 'API', archived: false }]);
  assert.deepEqual(await given(['API']), ['extra-prod']);
});

test('a key that holds a value here again is no longer dismissed here: reset later, it reads its parent again', async () => {
  // Reset, then dismissed: a use of staging reads nothing for it.
  assert.deepEqual(await given(['SESSION', 'EXTRA']), ['unknown_key', 'unknown_key']);
  assert.deepEqual(await reset('ada-cli', 'SESSION', false), { answer: { keys: {} } });
  assert.deepEqual(await lines(), [{ key: 'SESSION', archived: false, reset: false, dismissed: false }]);
  assert.deepEqual(await reset('ada-cli', 'SESSION'), { answer: { keys: {} } });
  assert.deepEqual(await given(['SESSION']), ['session-prod']);
  // A value of its own made where it was dismissed.
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'EXTRA', value: 'extra-staging' }])), { answer: { keys: { EXTRA: { version: 1, nature: 'secret' } } } });
  assert.deepEqual(await lines(), [{ key: 'EXTRA', version: 1, nature: 'secret', made: true, dismissed: false }]);
  assert.deepEqual(await dismissals(), [{ key: 'EXTRA', by: ada }, { key: 'SESSION', by: ada }]);
});

test('a parent or a dismissal edited behind the vault is not guessed at', async () => {
  await world.owner.execute(sql`UPDATE secrets SET folder = 'x' WHERE key = 'DATABASE_URL' AND environment_id = (SELECT id FROM environments WHERE slug = 'prod' AND project_id = (SELECT id FROM projects WHERE slug = 'market'))`);
  assert.deepEqual(await reset('ada-cli', 'DATABASE_URL'), { refused: 'unreadable' });
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', archived: true }])), { answer: { keys: {} } }, 'an archiving asks nothing of its parents');
  await world.owner.execute(sql`UPDATE dismissed_keys SET dismissed_by = 'someone' WHERE key = 'SESSION'`);
  assert.deepEqual(await reset('ada-cli', 'SESSION', false), { refused: 'unreadable' });
});

// The vault behind its contract (src/vault.ts), in process: what the app
// sends and is answered, through JSON on the way as over any transport.
// use.test.ts holds what a use decides; this holds what crosses.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { resolveVaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { prepareVault } from '../src/vault.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, environment, grant, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

// The keys a deployment's configuration makes, for the vault that writes the instance and the one under test.
const prepared = prepareVault(resolveVaultConfig({ kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'] }));
const world = await openTestVault(prepared);
const vault = openLocalVault(world.db, prepared, { wake: world.wake, now: world.now });
after(() => world.close());

const ada = user('ada');
beforeEach(async () => {
  await emptyDatabase(world.owner);
  prepared.memory.reads.clear();
  prepared.memory.logged.clear();
  world.woken.length = 0;
  const market = project('market');
  const prod = environment(market, 'prod');
  const url = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://market');
  await write(world, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', url, secret(prod, 'EMPTY')), ...rows('roles', role(false, 'viewer', ['secret.read'])),
    ...rows('principals', principal(ada)), ...rows('grants', grant(ada, 'viewer', { project: market })), ...rows('credentials', credential('ada-cli', ada)));
  world.woken.length = 0;
});

const reveal = (label: string, keys: string[] | null, more: Partial<UseInput> = {}): UseInput =>
  ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7', project: 'market', environment: 'prod', mine: false, keys, purpose: 'reveal', credential: null, ...more });
const waiting = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;

test('a reveal answers who asked and each key, its value as text or why not, and tells the signer of its entry', async () => {
  const before = await waiting();
  const answer = await vault.use(reveal('ada-cli', ['DATABASE_URL', 'EMPTY', 'NOPE']));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  assert.equal(answer.principal, ada);
  assert.equal(answer.workload, null);
  assert.deepEqual(answer.values.map((item) => ('refused' in item ? item : { key: item.key, version: item.version, sensitive: item.sensitive, value: item.value })), [
    { key: 'DATABASE_URL', version: 1, sensitive: false, value: 'postgres://market' },
    { key: 'EMPTY', refused: 'no_value' },
    { key: 'NOPE', refused: 'unknown_key' },
  ]);
  assert.equal(await waiting(), before + 1);
  assert.equal(world.woken.length, 1, 'the signer is told of the one entry');
});

test('a refusal is an answer, which wrote nothing and woke nobody', async () => {
  const before = await waiting();
  assert.deepEqual(await vault.use(reveal('nobody', ['DATABASE_URL'])), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.use(reveal('ada-cli', ['DATABASE_URL'], { project: 'billing' })), { refused: 'no_access' });
  assert.equal(await waiting(), before);
  assert.equal(world.woken.length, 0);
});

test('a use that is not what the contract says is a fault, before any read', async () => {
  const bad: Partial<Record<keyof UseInput, unknown>>[] = [{ token: 'ada-cli' }, { token: tokenOf('ada-cli').toString('hex').toUpperCase() }, { project: 7 }, { mine: 'yes' }, { keys: ['A', 7] }, { keys: Array.from({ length: 1001 }, (_, i) => `K${i}`) }, { ip: 7 }];
  for (const more of bad) {
    await assert.rejects(vault.use(reveal('ada-cli', ['DATABASE_URL'], more as Partial<UseInput>)), TypeError, JSON.stringify(more).slice(0, 60));
  }
  assert.equal(world.woken.length, 0);
});

test('a wake-up that fails costs the caller nothing: the entry is written, and the value given', async (t) => {
  t.mock.method(console, 'error', () => {});
  const deaf = openLocalVault(world.db, prepared, { now: world.now, wake: () => { throw new Error('no signer'); } });
  const before = await waiting();
  const answer = await deaf.use(reveal('ada-cli', ['DATABASE_URL']));
  assert.ok(!('refused' in answer) && 'value' in answer.values[0]! && answer.values[0].value === 'postgres://market', JSON.stringify(answer));
  assert.equal(await waiting(), before + 1);
});

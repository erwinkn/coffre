// The vault behind its contract (src/vault.ts), in process: what the app
// sends and is answered, through JSON on the way as over any transport.
// use.test.ts holds what a use decides; this holds what crosses.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { allows } from '@coffre/core/access';
import type { UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { resolveVaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { openVault, prepareVault } from '../src/vault.ts';
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
  prepared.memory.callers.clear();
  prepared.memory.logged.clear();
  world.woken.length = 0;
  const market = project('market');
  const prod = environment(market, 'prod');
  const url = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://märkt:p€ss@db');
  await write(world, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', url, secret(prod, 'EMPTY')), ...rows('roles', role(false, 'viewer', ['secret.read'])),
    ...rows('principals', principal(ada)), ...rows('grants', grant(ada, 'viewer', { project: market })), ...rows('credentials', credential('ada-cli', ada)));
  world.woken.length = 0;
});

const reveal = (label: string, keys: string[] | null, more: Partial<UseInput> = {}): UseInput =>
  ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7', project: 'market', environment: 'prod', mine: false, keys, purpose: 'reveal', upstream: null, ...more });
const waiting = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;

test('a reveal answers who asked and each key, its value as text or why not, and tells the signer of its entry', async () => {
  const before = await waiting();
  const answer = await vault.use(reveal('ada-cli', ['DATABASE_URL', 'EMPTY', 'NOPE']));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  assert.equal(answer.principal, ada);
  assert.equal(answer.workload, null);
  assert.deepEqual(answer.values.map((item) => ('refused' in item ? item : { key: item.key, version: item.version, sensitive: item.sensitive, value: item.value })), [
    { key: 'DATABASE_URL', version: 1, sensitive: false, value: 'postgres://märkt:p€ss@db' },
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
  const sparse = ['A'];
  sparse[2] = 'C';
  const bad: Partial<Record<keyof UseInput, unknown>>[] = [
    { token: 'ada-cli' }, { token: tokenOf('ada-cli').toString('hex').toUpperCase() }, { project: 7 }, { environment: 'x'.repeat(257) }, { mine: 'yes' },
    { keys: ['A', 7] }, { keys: sparse }, { keys: 'A' }, { keys: Array.from({ length: 1001 }, (_, i) => `K${i}`) }, { keys: ['A\0'] },
    { purpose: 'copy' }, { purpose: 7 }, { ip: 7 }, { request: {} }, { proof: 7 }, { upstream: 'x'.repeat(257) },
  ];
  for (const more of bad) {
    await assert.rejects(vault.use(reveal('ada-cli', ['DATABASE_URL'], more as Partial<UseInput>)), TypeError, JSON.stringify(more).slice(0, 60));
  }
  // Over a Workers binding nothing goes through JSON, and an array arrives with its holes.
  await assert.rejects(openVault(world.db, prepared, { wake: world.wake, now: world.now }).use(reveal('ada-cli', sparse)), TypeError);
  assert.equal(world.woken.length, 0);
  // What the contract does say: every key, and a thousand of them.
  const every = await vault.use(reveal('ada-cli', null));
  assert.ok(!('refused' in every) && every.values.map(({ key }) => key).join() === 'DATABASE_URL,EMPTY', JSON.stringify(every));
  const thousand = await vault.use(reveal('ada-cli', Array.from({ length: 1000 }, (_, i) => `K${i}`)));
  assert.ok(!('refused' in thousand) && thousand.values.length === 1000);
});

test('who a request is crosses as JSON: what it holds, as the app decides on it, and a refusal as an answer', async () => {
  const answer = await vault.caller({ token: tokenOf('ada-cli').toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  // With no transport between, the engine's own answer is what JSON carries of it: no Date, no undefined, no class.
  const direct = await openVault(world.db, prepared, { wake: world.wake, now: world.now }).caller({ token: tokenOf('ada-cli').toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
  assert.deepEqual(direct, JSON.parse(JSON.stringify(direct)));
  assert.deepEqual(direct, answer);
  assert.equal(answer.principal, ada);
  assert.equal(answer.credential.expiresAt, '2027-01-01T00:00:00.000Z');
  const [held] = answer.holds.grants;
  assert.ok(held !== undefined && held.role === 'viewer' && held.environmentId === null);
  assert.equal(allows(answer.holds, 'secret.read', { projectId: held.projectId! }), true);
  assert.equal(allows(answer.holds, 'secret.write', { projectId: held.projectId! }), false);
  assert.deepEqual(await vault.caller({ token: tokenOf('nobody').toString('hex'), proof: null, request: null, ip: null }), { refused: 'unauthenticated' });
  // Asked for the log's head, the answer says so: null here, where nothing is signed yet; anything but `true` asks for none.
  const headed = await vault.caller({ token: tokenOf('ada-cli').toString('hex'), proof: null, request: null, ip: null, head: true });
  assert.ok(!('refused' in headed) && headed.head === null, JSON.stringify(headed));
  const plain = await vault.caller({ token: tokenOf('ada-cli').toString('hex'), proof: null, request: null, ip: null, head: 'yes' as unknown as boolean });
  assert.ok(!('refused' in plain) && !('head' in plain), JSON.stringify(plain));
  // It wrote no entry, and woke nobody.
  assert.equal(world.woken.length, 0);
  for (const bad of [{ token: 'ada-cli' }, { proof: 7 }, { ip: {} }]) {
    await assert.rejects(vault.caller({ token: tokenOf('ada-cli').toString('hex'), proof: null, request: null, ip: null, ...(bad as object) }), TypeError, JSON.stringify(bad));
  }
});

test('the vault runs as its configuration says: its memory, and what it takes of workloads', () => {
  const config = { kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'] };
  const plain = prepareVault(resolveVaultConfig(config));
  assert.deepEqual([plain.memory.seconds, plain.workloads, plain.cap], [2, null, { count: 1000, windowMs: 15 * 60_000 }]);
  const told = prepareVault(resolveVaultConfig({ ...config, memorySeconds: 0, workloads: { useOnly: true }, bulkLimit: { count: 5, windowMinutes: 1 } }));
  assert.deepEqual([told.memory.seconds, told.workloads, told.cap], [0, { noReads: false, useOnly: true }, { count: 5, windowMs: 60_000 }]);
  for (const memorySeconds of [-1, 601, Number.NaN]) assert.throws(() => resolveVaultConfig({ ...config, memorySeconds }), /memorySeconds/);
});

test('a wake-up that fails costs the caller nothing: the entry is written, and the value given', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  const before = await waiting();
  const wakes: (() => void | Promise<void>)[] = [() => { throw new Error('no signer'); }, () => Promise.reject(new Error('the signer is down'))];
  for (const [index, wake] of wakes.entries()) {
    prepared.memory.logged.clear();
    const deaf = openLocalVault(world.db, prepared, { now: world.now, wake });
    const answer = await deaf.use(reveal('ada-cli', ['DATABASE_URL']));
    assert.ok(!('refused' in answer) && 'value' in answer.values[0]! && answer.values[0].value === 'postgres://märkt:p€ss@db', JSON.stringify(answer));
    assert.equal(await waiting(), before + index + 1);
  }
  // The rejection is caught, not left for the process: said in the log, once each.
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(logged.mock.callCount(), 2);
});

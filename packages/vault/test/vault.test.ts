// The vault behind its contract (src/vault.ts), in process: what the app
// sends and is answered, through JSON on the way as over any transport.
// use.test.ts holds what a use decides; this holds what crosses.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';
import { inspect } from 'node:util';

import { allows } from '@coffre/core/access';
import type { UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { resolveVaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { signerOf } from './testing.ts';
import { credential, environment, grant, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

// The keys a deployment's configuration makes, for the vault that writes the instance and the one under test.
const prepared = prepareVault(resolveVaultConfig({ kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'], workloads: null }));
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
  assert.deepEqual(answer.values.map((item) => ('refused' in item ? item : { key: item.key, version: item.version, nature: item.nature, value: item.value })), [
    { key: 'DATABASE_URL', version: 1, nature: 'secret', value: 'postgres://märkt:p€ss@db' },
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
    { purpose: 'copy' }, { purpose: 7 }, { ip: 7 }, { request: {} }, { proof: 7 }, { upstream: 'stripe' }, { upstream: { credential: 'x'.repeat(257) } },
    { upstream: { credential: 'stripe', egress: false } }, { upstream: { credential: 'stripe', path: '/v1' } },
    ...['API.stripe.com', `${'a'.repeat(250)}.com`, 'api.stripe.com:443', '[not:ipv6]', ':', '', 'xn--bcher-kva.de/x', 'bücher.de', 'a%41.example', '2001:db8::1'].map((host) => ({ upstream: { credential: 'stripe', host } })),
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
  // A host as a URL names it, whatever the deployment's upstream is.
  for (const host of ['api.stripe.com', 'api_internal.example', 'xn--bcher-kva.de', '192.0.2.10', '[2001:db8::1]', `${'a'.repeat(249)}.com`]) {
    const used = await vault.use(reveal('ada-cli', ['DATABASE_URL'], { upstream: { credential: 'stripe', host, egress: true } }));
    assert.ok(!('refused' in used), host);
  }
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
  const config = { kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'], workloads: null };
  const plain = prepareVault(resolveVaultConfig(config));
  assert.deepEqual([plain.memory.seconds, plain.memory.outageSeconds, plain.workloads, plain.cap], [2, 0, null, { count: 1000, windowMs: 15 * 60_000 }]);
  const told = prepareVault(resolveVaultConfig({ ...config, memorySeconds: 0, outageSeconds: 330, workloads: { useOnly: true }, bulkLimit: { count: 5, windowMinutes: 1 } }));
  assert.deepEqual([told.memory.seconds, told.memory.outageSeconds, told.workloads, told.cap], [0, 330, { noReads: false, useOnly: true }, { count: 5, windowMs: 60_000 }]);
  for (const memorySeconds of [-1, 601, Number.NaN]) assert.throws(() => resolveVaultConfig({ ...config, memorySeconds }), /memorySeconds/);
  for (const outageSeconds of [-1, 3601, Number.NaN]) assert.throws(() => resolveVaultConfig({ ...config, outageSeconds }), /outageSeconds/);
});

test("0.9's people is refused at configuration, saying what to do instead", () => {
  const config = { kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'], people: 'stand-ins' } as never;
  assert.throws(() => resolveVaultConfig(config), /^Error: people is gone in 0\.10 \(it was "stand-ins"\).*mark the keys no person may read sensitive/);
});

test('the database holds no key: not the KEK, the signing key or a key derived from it, raw or in any encoding', async () => {
  // A local KEK alone, whose key the vault derives its own from, and one given its own signing key.
  for (const given of [{}, { signingKey: randomBytes(32).toString('base64') }]) {
    const kek = randomBytes(32);
    const resolved = resolveVaultConfig({ kek: { id: 'scanned', key: kek.toString('base64') }, owners: ['root@acme.example'], workloads: null, ...given });
    const keyed = prepareVault(resolved);
    const scanned = await openTestVault({ ...keyed, now: world.now });
    try {
      await emptyDatabase(scanned.owner);
      const market = project('market');
      const prod = environment(market, 'prod');
      await write(scanned, ...rows('projects', market), ...rows('environments', prod), ...rows('roles', role(false, 'developer', ['secret.read', 'secret.write'])),
        ...rows('principals', principal(ada)), ...rows('grants', grant(ada, 'developer', { project: market })), ...rows('credentials', credential('ada-cli', ada)));
      // The vault's own work: a write, a read, and the signer's checkpoint over them.
      const scannedVault = openLocalVault(scanned.db, keyed, { wake: scanned.wake, now: scanned.now });
      const shown = { token: tokenOf('ada-cli').toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' };
      assert.ok(!('refused' in (await scannedVault.change({ ...shown, op: 'secret.write', project: 'market', environment: 'prod', keys: [{ key: 'API_KEY', value: 'sk_scanned', nature: 'secret' }] }))));
      assert.ok(!('refused' in (await scannedVault.use({ ...reveal('ada-cli', ['API_KEY']) }))));
      await (await signerOf(scanned)).sign(true);

      // Every row of every table, the app's and the vault's.
      const tables = await rowsOf<{ schema: string; name: string }>(scanned.owner, sql`SELECT table_schema AS schema, table_name AS name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')`);
      const values: Buffer[] = [];
      for (const { schema, name } of tables) {
        for (const row of await rowsOf<Record<string, unknown>>(scanned.owner, sql`SELECT * FROM ${sql.identifier(schema)}.${sql.identifier(name)}`)) {
          for (const value of Object.values(row)) {
            values.push(value instanceof Uint8Array ? Buffer.from(value) : Buffer.from(value instanceof Date ? value.toISOString() : typeof value === 'object' ? JSON.stringify(value) : String(value)));
          }
        }
      }
      const dump = Buffer.concat(values);
      assert.ok(dump.includes(Buffer.from(ada)) && dump.includes(Buffer.from('API_KEY')), 'the dump is real');
      const [signed] = await rowsOf<{ n: number }>(scanned.owner, sql`SELECT count(*)::int AS n FROM log`);
      assert.ok(signed!.n > 0, 'the signer signed');

      const [seed] = resolved.signingKeys;
      const [key] = keyed.keys;
      for (const [what, raw] of [['the KEK', kek], ['the signing key', Buffer.from(seed!)], ["the rows' MAC key", key!.rows], ["the entries' MAC key", key!.entries]] as const) {
        for (const form of [raw, ...(['base64', 'base64url', 'hex'] as const).map((encoding) => Buffer.from(raw.toString(encoding)))]) {
          assert.equal(dump.includes(form), false, `the database holds ${what}`);
        }
      }
    } finally {
      await scanned.close();
    }
  }
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

test("what the vault logs of a failure quotes no value: not a query's parameter, a cast it could not make, or a row a constraint refused", async (t) => {
  const canary = 'coffre-canary-not-for-the-log';
  const failed = (work: () => Promise<unknown>) => work().then(() => assert.fail('the query ran'), (thrown: unknown) => thrown);
  const errors = [
    await failed(() => world.owner.select({ v: sql`${canary}` }).from(sql`no_such_table`)),
    await failed(() => world.owner.execute(sql`SELECT ${canary}::uuid`)),
    await failed(() => world.owner.transaction(async (tx) => {
      await tx.execute(sql`CREATE TEMPORARY TABLE kept (key text CONSTRAINT kept_key_unique UNIQUE) ON COMMIT DROP`);
      await tx.execute(sql`INSERT INTO kept VALUES (${canary}), (${canary})`);
    })),
  ];
  // Each quotes it, as it is: the log is what leaves it out.
  for (const error of errors) assert.ok(inspect(error, { depth: null }).includes(canary));
  const logged = t.mock.method(console, 'error', () => {});
  for (const error of errors) {
    const failing = openLocalVault(world.db, prepared, { now: world.now, wake: () => { throw error; } });
    prepared.memory.logged.clear();
    assert.ok(!('refused' in (await failing.use(reveal('ada-cli', ['DATABASE_URL'])))));
  }
  assert.equal(logged.mock.callCount(), 3);
  const said = logged.mock.calls.map((call) => call.arguments);
  assert.ok(!inspect(said, { depth: null }).includes(canary), 'a value in the log');
  // What went wrong, by Postgres's code and names.
  assert.deepEqual(said.map(([, line]) => (line as { cause: { code: string } }).cause.code), ['42P01', '22P02', '23505']);
  assert.equal((said[2]![1] as { cause: { constraint: string } }).cause.constraint, 'kept_key_unique');
});

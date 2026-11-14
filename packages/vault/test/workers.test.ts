// The vault in workerd, as it runs on Cloudflare: the app's route calls its
// entrypoint over a service binding, the entrypoint its signer's Durable
// Object over another, and each call has one connection through Hyperdrive.
// vault.test.ts holds what crosses the contract, and signer-worker.test.ts
// the signer's object; this holds that one request goes all the way.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test, { after } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { resolveVaultConfig } from '../src/config.ts';
import { checked } from '../src/rows.ts';
import { headText } from '../src/signer.ts';
import { prepareVault } from '../src/vault.ts';
import { emptyDatabase, openTestVault, slowPostgres, VAULT_URL } from './database.ts';
import { vaultWorker, type Answer } from './workers/boot.ts';
import { credential, environment, grant, principal, project, role, rows, secret, user, value, write } from './world.ts';

const VAULT_KEY = randomBytes(32).toString('base64');
// The instance's rows are written here as the Worker's vault would write them: under its keys, and by the real
// clock, which its signer dates entries by.
const prepared = prepareVault(resolveVaultConfig({ kek: { id: 'vault-workers-test', key: VAULT_KEY }, owners: ['root@acme.example'] }));
const world = await openTestVault({ ...prepared, now: Date.now });
after(() => world.close());

const [ada, bo] = [user('ada'), user('bo')];
const KEYS = Array.from({ length: 8 }, (_, i) => `KEY_${i}`);

/** `market/prod` with eight keys, which Ada reads. */
async function instance(): Promise<void> {
  await emptyDatabase(world.owner);
  const market = project('market');
  const prod = environment(market, 'prod');
  const secrets = await Promise.all(KEYS.map((key) => value(world, secret(prod, key), `value of ${key}`)));
  await write(world, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', ...secrets), ...rows('roles', role(false, 'viewer', ['secret.read']), role(false, 'developer', ['secret.read', 'secret.write'])),
    ...rows('principals', principal(ada), principal(bo)), ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market })), ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo)));
}

/** A fresh isolate of the vault Worker and its signer, over the suite's database through the vault's login. */
const freshVault = (database: string, more?: { signer?: boolean }) => vaultWorker(database, { id: 'vault-workers-test', key: VAULT_KEY }, more);

const count = async (table: 'log' | 'log_pending') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
const reads = async () => (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log WHERE NOT kept ORDER BY seq`)).map(({ body }) => JSON.parse(body) as { action: string; actor: string; detail: { keys: { key: string }[] } });

/** `ready`, asked every 100 ms, within `ms`. */
async function until(ready: () => Promise<boolean>, ms: number, what: string): Promise<void> {
  for (const end = Date.now() + ms; !(await ready()); ) {
    assert.ok(Date.now() < end, `${what}, within ${ms} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

const given = ({ body }: Answer) => body.values.map((item) => ('refused' in item ? item : { key: item.key, value: item.value }));

test('a reveal through the app is answered its value, and its entry is in the log a second later, under a head of the vault\'s', { timeout: 120_000 }, async () => {
  await instance();
  const written = await count('log_pending');
  const vault = await freshVault(VAULT_URL);
  try {
    const first = await vault.reveal('ada-cli', 'market/prod', ['KEY_0', 'NOPE']);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.principal, ada);
    assert.deepEqual(given(first), [{ key: 'KEY_0', value: 'value of KEY_0' }, { key: 'NOPE', refused: 'unknown_key' }]);

    // Nothing but the vault's own wake-up starts the signer here: its object does not exist until it is called.
    await until(async () => (await count('log_pending')) === 0, 15_000, 'the signer has taken every entry');
    assert.equal(await count('log'), written + 1);
    assert.deepEqual((await reads()).map((entry) => [entry.action, entry.actor, entry.detail.keys.map(({ key }) => key)]), [['secret.read', ada, ['KEY_0']]]);
    const [head] = await rowsOf<{ size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: number; mac: Buffer }>(
      world.owner,
      sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", (extract(epoch FROM signed_at) * 1000)::float8 AS "signedAt", mac FROM log_head`,
    );
    assert.deepEqual([head!.size, head!.agingSize], [written + 1, 1]);
    assert.ok(checked(world.keys, (each) => each.entries, headText(head!), head!.mac) !== undefined, 'the head is under the vault\'s MAC');

    // The same key again within the minute is given, and logged once.
    const again = await vault.reveal('ada-cli', 'market/prod', ['KEY_0']);
    assert.deepEqual(given(again), [{ key: 'KEY_0', value: 'value of KEY_0' }]);
    assert.deepEqual([await count('log'), await count('log_pending')], [written + 1, 0]);
    // A peek through the binding: what the reveal was given, key by key, and nothing logged.
    const peeked = await vault.peek('ada-cli', 'market/prod', ['KEY_0', 'NOPE']);
    const [held] = first.body.values as { secret: string; version: number; nature: string }[];
    const versionId = (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secret_versions WHERE secret_id = ${held!.secret} AND version = ${held!.version}`))[0]!.id;
    assert.deepEqual([peeked.status, peeked.body.personal, peeked.body.items], [200, false, [{ key: 'KEY_0', secret: held!.secret, version: held!.version, nature: held!.nature, versionId, recipe: null, own: false }, { key: 'NOPE', refused: 'unknown_key' }]]);
    assert.deepEqual([await count('log'), await count('log_pending')], [written + 1, 0]);
  } finally {
    await vault.stop();
  }
});

test('a value written through the app is sealed by the vault, signed into the log, and read back by whoever reads there', { timeout: 120_000 }, async () => {
  await instance();
  const written = await count('log_pending');
  const vault = await freshVault(VAULT_URL);
  try {
    const refused = await vault.write('ada-cli', 'market/prod', { KEY_0: 'not hers to write' });
    assert.deepEqual([refused.status, refused.body], [403, { refused: 'no_access' }]);
    const done = await vault.write('bo-cli', 'market/prod', { KEY_0: 'the next value', KEY_NEW: 'a new këy' });
    // A value over the key's own is the same or not only by opening it: a dry run's to ask.
    assert.deepEqual([done.status, done.body.answer?.keys, done.body.answer?.outcomes.KEY_NEW, Object.keys(done.body.answer?.outcomes.KEY_0 ?? {})], [200, { KEY_0: { version: 2, nature: 'secret' }, KEY_NEW: { version: 1, nature: 'secret' } }, 'added', ['compare']]);
    assert.deepEqual(given(await vault.reveal('ada-cli', 'market/prod', ['KEY_0', 'KEY_NEW'])), [{ key: 'KEY_0', value: 'the next value' }, { key: 'KEY_NEW', value: 'a new këy' }]);

    // The change's entry among those kept for good, the read's among those that age out: both signed, nothing waiting.
    await until(async () => (await count('log_pending')) === 0, 15_000, 'the signer has taken every entry');
    const kept = (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log WHERE kept ORDER BY seq DESC LIMIT 1`)).map(({ body }) => JSON.parse(body) as { action: string; actor: string });
    assert.deepEqual(kept.map((entry) => [entry.action, entry.actor]), [['secret.write', bo]]);
    // And Ada's refused write, said once: three entries in all, two of them among those that age out.
    assert.deepEqual([await count('log'), (await reads()).map((entry) => [entry.action, entry.actor])], [written + 3, [['secret.write', ada], ['secret.read', ada]]]);
  } finally {
    await vault.stop();
  }
});

test('a refusal crosses the binding as an answer, and writes nothing', { timeout: 120_000 }, async () => {
  await instance();
  const written = await count('log_pending');
  const vault = await freshVault(VAULT_URL);
  try {
    const nobody = await vault.reveal('nobody', 'market/prod', ['KEY_0']);
    assert.deepEqual([nobody.status, nobody.body], [401, { refused: 'unauthenticated' }]);
    const elsewhere = await vault.reveal('ada-cli', 'billing/prod', ['KEY_0']);
    assert.deepEqual([elsewhere.status, elsewhere.body], [403, { refused: 'no_access' }]);
    // The entries the instance was written with, signed before the first call was answered (`adopt` in signer-host.ts), and none more.
    assert.deepEqual([await count('log'), await count('log_pending')], [written, 0]);
  } finally {
    await vault.stop();
  }
});

test('a fresh database is adopted at the first call, a sign-in, which is answered: the Owner the configuration names signs in at the first try', { timeout: 120_000 }, async () => {
  await emptyDatabase(world.owner);
  const vault = await freshVault(VAULT_URL);
  try {
    assert.deepEqual(await vault.status(), { checked: (await vault.status()).checked, standing: [], adopted: false, adoption: null, asked: 0 });
    const root = { provider: 'github', issuer: 'github', subject: '1', emails: ['root@acme.example'] };
    const first = await vault.signin(root, 'root-web');
    assert.deepEqual([first.status, first.body.answer?.principal], [200, user('root')], JSON.stringify(first.body));
    assert.deepEqual(await rowsOf(world.owner, sql`SELECT id, role FROM principals`), [{ id: user('root'), role: 'owner' }]);
    assert.deepEqual((await rowsOf<{ action: string }>(world.owner, sql`SELECT body::jsonb ->> 'action' AS action FROM log ORDER BY seq`)).map(({ action }) => action), ['vault.adopt']);
    const status = await vault.status();
    assert.deepEqual([status.adopted, status.adoption, status.standing, status.asked], [true, null, [], 1]);
    // Someone the configuration does not name is no member: refused, by the decision, not the adoption.
    assert.deepEqual((await vault.signin({ ...root, subject: '2', emails: ['ada@acme.example'] }, 'ada-web')).body, { refused: 'not_registered' });
    // Adopted, the isolate asks the signer no more, whatever the call.
    await vault.reveal('root-web', 'market/prod', null);
    await vault.peek('root-web', 'market/prod', null);
    assert.equal((await vault.status()).asked, 1);
  } finally {
    await vault.stop();
  }
});

test('first calls at once, of every kind, adopt once, and each is answered after it', { timeout: 120_000 }, async () => {
  await emptyDatabase(world.owner);
  const vault = await freshVault(VAULT_URL);
  try {
    const root = { provider: 'github', issuer: 'github', subject: '1', emails: ['root@acme.example'] };
    const answers = await Promise.all([vault.signin(root, 'root-web'), vault.reveal('nobody', 'market/prod', ['KEY_0']), vault.signin(root, 'root-cli'), vault.peek('nobody', 'market/prod', null), vault.write('nobody', 'market/prod', { KEY_0: 'x' })]);
    assert.deepEqual(answers.map(({ status }) => status), [200, 401, 200, 401, 401]);
    await until(async () => (await count('log_pending')) === 0, 15_000, 'the signer has taken every entry');
    assert.deepEqual(await rowsOf(world.owner, sql`SELECT body::jsonb ->> 'action' AS action, count(*)::int AS n FROM log GROUP BY 1 ORDER BY 1`), [{ action: 'sign_in', n: 2 }, { action: 'vault.adopt', n: 1 }]);
  } finally {
    await vault.stop();
  }
});

test('an adoption that outlasts the wait has its callers answered `adopting` meanwhile, and the first call after it is served', { timeout: 120_000 }, async () => {
  await emptyDatabase(world.owner);
  // Each of the adoption's statements a while away, as an upgrade's are many.
  const database = await slowPostgres(150);
  const vault = await freshVault(database.url);
  try {
    const root = { provider: 'github', issuer: 'github', subject: '1', emails: ['root@acme.example'] };
    const from = Date.now();
    const first = await vault.signin(root, 'root-web');
    const waited = Date.now() - from;
    assert.deepEqual([first.status, first.body], [503, { refused: 'adopting' }]);
    assert.ok(waited >= 1900 && waited < 5000, `answered after ${waited} ms`);
    await until(async () => (await vault.status()).adopted, 30_000, 'the adoption is done');
    assert.equal((await vault.signin(root, 'root-web')).status, 200);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('a vault Worker that binds no signer answers no call, and says why', { timeout: 120_000 }, async () => {
  await instance();
  const written = await count('log_pending');
  const vault = await freshVault(VAULT_URL, { signer: false });
  try {
    const refused = await vault.reveal('ada-cli', 'market/prod', ['KEY_0']);
    assert.equal(refused.status, 500);
    assert.match(refused.body.error!, /binds its signer/);
    assert.equal(await count('log_pending'), written);
  } finally {
    await vault.stop();
  }
});

test('a fresh isolate answers a burst of first calls, each on one connection: on Cloudflare, a call that opened several at once was cancelled as hung', { timeout: 120_000 }, async () => {
  await instance();
  const database = await slowPostgres(20);
  const vault = await freshVault(database.url);
  try {
    const answers = await Promise.all(KEYS.map((key) => vault.reveal('ada-cli', 'market/prod', [key])));
    assert.deepEqual(answers.map((answer) => [answer.status, answer.body.error]), KEYS.map(() => [200, undefined]), 'every call answered, none cancelled as hung');
    assert.deepEqual(answers.flatMap(given), KEYS.map((key) => ({ key, value: `value of ${key}` })));
    // One a call, its read and its write on it, and the signer's own: its runs a second apart share one.
    assert.ok(database.opened <= KEYS.length + 2, `${database.opened} connections for ${KEYS.length} calls`);
    // The same use eight times at once, before any has read: each reads for itself, on a connection of its own. One
    // that waited on a read another began would be cancelled with it on Cloudflare, which local workerd does not show.
    const before = database.opened;
    const same = await Promise.all(KEYS.map(() => vault.reveal('ada-cli', 'market/prod', ['KEY_0', 'KEY_1'])));
    assert.deepEqual(same.map((answer) => [answer.status, given(answer).length]), KEYS.map(() => [200, 2]));
    const opened = database.opened - before;
    assert.ok(opened >= KEYS.length && opened <= KEYS.length + 2, `${opened} connections for ${KEYS.length} uses of the same keys at once`);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test("`about` is the configuration's alone: answered over the binding with no connection opened, nor the signer asked", { timeout: 120_000 }, async () => {
  const database = await slowPostgres(5);
  const vault = await freshVault(database.url, { signer: false });
  try {
    assert.deepEqual(await Promise.all([vault.get('/about'), vault.get('/about')]), [prepared.about, prepared.about]);
    assert.equal(database.opened, 0);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('in workerd too, a query on the database inside its own transaction is refused at once, not left to hang', { timeout: 120_000 }, async () => {
  const database = await slowPostgres(5);
  const vault = await freshVault(database.url);
  try {
    const refused = await vault.post('/query-outside-transaction');
    assert.match(refused.error!, /^QueryOutsideTransaction: query outside its transaction: use tx/);
  } finally {
    await vault.stop();
    await database.close();
  }
});

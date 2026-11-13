// The vault in workerd, as it runs on Cloudflare: the app's route calls its
// entrypoint over a service binding, the entrypoint its signer's Durable
// Object over another, and each call has one connection through Hyperdrive.
// vault.test.ts holds what crosses the contract, and signer-worker.test.ts
// the signer's object; this holds that one request goes all the way.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import type { Used } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { resolveVaultConfig } from '../src/config.ts';
import { checked } from '../src/rows.ts';
import { headText } from '../src/signer.ts';
import { prepareVault } from '../src/vault.ts';
import { emptyDatabase, openTestVault, VAULT_URL } from './database.ts';
import { credential, environment, grant, principal, project, role, rows, secret, user, value, write } from './world.ts';

const VAULT_KEY = randomBytes(32).toString('base64');
// The instance's rows are written here as the Worker's vault would write them: under its keys, and by the real
// clock, which its signer dates entries by.
const prepared = prepareVault(resolveVaultConfig({ kek: { id: 'vault-workers-test', key: VAULT_KEY }, owners: ['root@acme.example'] }));
const world = await openTestVault({ ...prepared, now: Date.now });
after(() => world.close());

const ada = user('ada');
const KEYS = Array.from({ length: 8 }, (_, i) => `KEY_${i}`);

/** `market/prod` with eight keys, which Ada reads. */
async function instance(): Promise<void> {
  await emptyDatabase(world.owner);
  const market = project('market');
  const prod = environment(market, 'prod');
  const secrets = await Promise.all(KEYS.map((key) => value(world, secret(prod, key), `value of ${key}`)));
  await write(world, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', ...secrets), ...rows('roles', role(false, 'viewer', ['secret.read'])),
    ...rows('principals', principal(ada)), ...rows('grants', grant(ada, 'viewer', { project: market })), ...rows('credentials', credential('ada-cli', ada)));
}

/**
 * Postgres as Hyperdrive serves it from far away: each chunk either way
 * delayed by `ms`. Locally a query answers in well under a millisecond,
 * which hides calls waiting on each other's I/O. `opened` counts the
 * connections made to it.
 */
async function slowPostgres(ms: number): Promise<{ url: string; readonly opened: number; close(): Promise<void> }> {
  const target = new URL(VAULT_URL);
  let opened = 0;
  const server: Server = createServer((client) => {
    opened += 1;
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) =>
      from.on('data', (chunk) => setTimeout(() => to.write(chunk), ms));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  const url = new URL(VAULT_URL);
  url.port = String(address.port);
  return {
    url: url.href,
    get opened() {
      return opened;
    },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

type Answer = { status: number; body: Used & { refused?: string; error?: string } };

/** A fresh isolate of the vault Worker and its signer, over the suite's database through the vault's login. */
async function freshVault(database: string, { signer = true } = {}): Promise<{
  reveal(bearer: string, path: string, keys: string[] | null): Promise<Answer>;
  post(path: string): Promise<{ error?: string }>;
  stop(): Promise<void>;
}> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-worker-'));
  const name = 'coffre-vault-workers-test';
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { VAULT_KEY },
      hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'vault-workers-test', localConnectionString: database }],
      services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
      // As a deployment's vault/wrangler.jsonc.
      durable_objects: { bindings: signer ? [{ name: 'SIGNER', class_name: 'CoffreSigner' }] : [] },
      migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  let worker: Unstable_DevWorker;
  try {
    worker = await unstable_dev(fileURLToPath(new URL('./workers/vault-worker.ts', import.meta.url)), {
      config: join(dir, 'wrangler.json'),
      local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
    });
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  return {
    async reveal(bearer, path, keys) {
      const response = await worker.fetch('/reveals', { method: 'POST', headers: { authorization: `Bearer ${bearer}` }, body: JSON.stringify({ path, keys }), signal: AbortSignal.timeout(20_000) });
      return { status: response.status, body: (await response.json()) as Answer['body'] };
    },
    async post(path) {
      return (await (await worker.fetch(path, { method: 'POST', signal: AbortSignal.timeout(20_000) })).json()) as { error?: string };
    },
    async stop() {
      await worker.stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

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
    assert.deepEqual([await count('log'), await count('log_pending')], [0, written]);
  } finally {
    await vault.stop();
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
    assert.ok(database.opened - before >= KEYS.length, `${database.opened - before} connections for ${KEYS.length} uses of the same keys at once`);
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

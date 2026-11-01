// What each change costs in round trips, with 0.15's log, as on Workers (R42, R57; T179): the app's database one
// Hyperdrive connection per request, the vault's one per call, each behind a proxy that counts the Syncs, which
// Hyperdrive sends on one at a time, so a round trip each. The seal (R51) is the checkpointer's, apart: here a change
// is sealed at once (`sealedNow`). Each route is asked once to warm the isolate, then measured.
// Postgres only: the counts are its Syncs.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import { createDatabase, type Client } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { localVault, type LocalVault } from '@coffre/vault/node';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, nothingHeld, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { watched } from './db/postgres-pool.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';

const POSTGRES = postgresOnly("counts the app's and the vault's Postgres round trips");
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'token:ci-web';

/** A client whose statements go to the pool of the request under way: on Workers, each request opens its own. */
class PerRequest {
  pool: Client | null = null;
  readonly client: Client = new Proxy({} as Client, {
    get: (_, key) => {
      // No hook of a postgres.js client's own: `watched` infers a transaction's BEGIN and end, as for any Hyperdrive pool.
      if (key === 'options' || key === 'then') return undefined;
      if (this.pool === null) throw new Error('no request under way');
      const value: unknown = Reflect.get(this.pool, key, this.pool);
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(this.pool) : value;
    },
  });
}

type Relay = Awaited<ReturnType<typeof postgresProxy>>;
/** A change's round trips: the app's, the vault's, the hot path's, and its vault calls; the statements, for a failure's message. */
type Cost = { app: number; vault: number; hot: number; calls: number; statements: string[] };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let vault: LocalVault;
let vaultPool: HyperdrivePool;
let relays: { app: Relay; vault: Relay; hot: Relay };
let appClient: PerRequest;
let runtime: CoffreRuntime;
let owner: CoffreClient;
let calls = 0;
let statements: string[] = [];
const background: Promise<unknown>[] = [];

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  // Cut over and seeded through a vault of the suite's own, as signin-cost.test.ts does; then measured through one
  // whose connections go through the proxies.
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld }) });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod']) await root.environments.create(path);
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });

  relays = { app: await postgresProxy(TEST_RUNTIME_DATABASE_URL), vault: await postgresProxy(TEST_VAULT_DATABASE_URL), hot: await postgresProxy(TEST_HOT_DATABASE_URL) };
  vaultPool = new HyperdrivePool(relays.vault.url);
  const opened = await localVault(
    { database: createDatabase(watched(vaultPool, ({ text }) => statements.push(`vault: ${shown(text)}`))), hotDatabase: relays.hot.url, kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld },
  );
  vault = opened;
  const counted = new Proxy(opened, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        calls += 1;
        statements.push(`vault call: ${String(key)}`);
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  appClient = new PerRequest();
  const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] });
  runtime = {
    ...createRuntime(
      resolveConfig({ publicUrl: ORIGIN, vault: counted, auth, auditChainKey: deps.chainKey.toString('base64') }),
      createDatabase(watched(appClient.client, ({ text }) => statements.push(`app: ${shown(text)}`))),
      counted,
      { json: async (url) => { throw new Error(`no fetch in this test: ${url.href}`); } },
    ),
    // What a request leaves running, waited for within it: its statements are its own.
    waitUntil: (promise) => void background.push(promise),
  };
  // The Owner's browser session, as a page's calls send it.
  const session = await asRequest(async () => {
    const signed = await runtime.signin!.completeSignin({ provider: 'github', subject: 'root', emails: [ROOT], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
    if (!('credential' in signed)) throw new Error('the Owner was not signed in');
    return signed.credential.token;
  });
  owner = createClient({
    url: ORIGIN,
    headers: () => ({ cookie: `${sessionCookieName(runtime.auth)}=${session}`, 'sec-fetch-site': 'same-origin' }),
    transport: (request) => fetchApi(request, runtime, { sourceIp: null }),
  });
});

after(async () => {
  if (POSTGRES.skip) return;
  await vault.close();
  await vaultPool.end();
  await Promise.all(Object.values(relays).map((relay) => relay.close()));
  await resetDatabase(db.owner);
  await db.close();
});

const shown = (text: string) => text.replace(/\s+/g, ' ').trim().slice(0, 60);

/** `work` on a connection of its own, as one request on Workers, closed after. */
async function asRequest<T>(work: () => Promise<T>): Promise<T> {
  const pool = new HyperdrivePool(relays.app.url, { groupReads: true });
  appClient.pool = pool;
  try {
    return await work();
  } finally {
    while (background.length > 0) await Promise.allSettled(background.splice(0));
    await pool.end();
    appClient.pool = null;
  }
}

/** What `work` costs, as one request. */
async function cost(work: () => Promise<unknown>): Promise<Cost> {
  const from = { app: relays.app.syncs, vault: relays.vault.syncs, hot: relays.hot.syncs, calls };
  statements = [];
  await asRequest(work);
  return { app: relays.app.syncs - from.app, vault: relays.vault.syncs - from.vault, hot: relays.hot.syncs - from.hot, calls: calls - from.calls, statements };
}

type Case = { name: string; setup?: (i: number) => Promise<void>; run: (i: number) => Promise<unknown> };

let made = 0;
const fresh = () => `k${(made += 1)}`;

/** Every change route, as the UI or CLI asks it: once to warm, once measured, each on rows of its own. */
const CASES: Case[] = [
  { name: 'key set, one', run: () => owner.secrets.set('market/dev', { [fresh().toUpperCase()]: 'fake-value' }) },
  { name: 'key set, existing', run: () => owner.secrets.set('market/dev', { API_KEY: `fake-${randomUUID()}` }) },
  { name: 'key set, five', run: () => owner.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 5 }, () => [fresh().toUpperCase(), 'fake-value']))) },
  {
    name: 'key archived',
    setup: async (i) => void (await owner.secrets.set('market/dev', { [`GONE_${i}`]: 'fake-value' })),
    run: (i) => owner.secrets.set('market/dev', { [`GONE_${i}`]: null }),
  },
  {
    name: 'key restored (a version)',
    setup: async (i) => {
      await owner.secrets.set('market/dev', { [`BACK_${i}`]: 'fake-one' });
      await owner.secrets.set('market/dev', { [`BACK_${i}`]: 'fake-two' });
    },
    run: (i) => owner.secrets.restore(`market/dev/BACK_${i}`, 1),
  },
  {
    name: 'key renamed',
    setup: async (i) => void (await owner.secrets.set('market/dev', { [`OLD_${i}`]: 'fake-value' })),
    run: (i) => owner.secrets.rename(`market/dev/OLD_${i}`, `NEW_${i}`),
  },
  {
    name: 'key filed in a folder',
    setup: async (i) => void (await owner.secrets.set('market/dev', { [`FILED_${i}`]: 'fake-value' })),
    run: (i) => owner.secrets.update(`market/dev/FILED_${i}`, { folder: 'stripe' }),
  },
  { name: 'reference made', run: (i) => owner.secrets.set('market/prod', { [`REF_${i}`]: { ref: 'market/dev/API_KEY' } }) },
  {
    name: 'reference broken',
    setup: async (i) => void (await owner.secrets.set('market/prod', { [`CUT_${i}`]: { ref: 'market/dev/API_KEY' } })),
    run: (i) => owner.references.break(`market/prod/CUT_${i}`),
  },
  { name: 'project made', run: (i) => owner.projects.create(`made-${i}`, { name: 'Made' }) },
  {
    name: 'project renamed',
    setup: async (i) => void (await owner.projects.create(`named-${i}`, { name: 'Named' })),
    run: (i) => owner.projects.update(`named-${i}`, { name: `Renamed ${i}` }),
  },
  {
    name: 'project archived',
    setup: async (i) => void (await owner.projects.create(`shelved-${i}`, { name: 'Shelved' })),
    run: (i) => owner.projects.update(`shelved-${i}`, { archived: true }),
  },
  { name: 'environment made', run: (i) => owner.environments.create(`market/env-${i}`) },
  { name: 'environment forked', run: (i) => owner.environments.create(`market/fork-${i}`, { from: 'dev' }) },
  {
    name: 'environment renamed',
    setup: async (i) => void (await owner.environments.create(`market/was-${i}`)),
    run: (i) => owner.environments.update(`market/was-${i}`, { name: `is-${i}` }),
  },
  {
    name: 'environment protected',
    setup: async (i) => void (await owner.environments.create(`market/guarded-${i}`)),
    run: (i) => owner.environments.protect(`market/guarded-${i}`),
  },
  {
    name: 'environment archived',
    setup: async (i) => void (await owner.environments.create(`market/old-${i}`)),
    run: (i) => owner.environments.update(`market/old-${i}`, { archived: true }),
  },
  { name: 'member added', run: (i) => owner.members.add(`user:new-${i}@acme.example`) },
  {
    name: 'access granted',
    setup: async (i) => void (await owner.members.add(`user:granted-${i}@acme.example`)),
    run: (i) => owner.access.set(`user:granted-${i}@acme.example`, { 'market/dev': 'developer' }),
  },
  {
    name: 'member removed',
    setup: async (i) => void (await owner.members.add(`user:leaving-${i}@acme.example`)),
    run: (i) => owner.members.remove(`user:leaving-${i}@acme.example`),
  },
  { name: 'token issued', run: () => owner.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 }) },
  {
    name: 'token revoked',
    setup: async (i) => void tokens.set(i, (await owner.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).id),
    run: (i) => owner.tokens.revoke(SERVICE, tokens.get(i)!),
  },
];
const tokens = new Map<number, string>();

/**
 * Each route's round trips, as measured: the app's Syncs, the vault's, and the hot path's. A change that adds one fails
 * here; one that saves one lowers its row (T179, R42, R57). The seal (R51) is the checkpointer's, apart: about three more
 * on Cloudflare (docs/design/0.15-plan.md, "As built: T171").
 */
const BUDGETS: Record<string, { app: number; vault: number; hot?: number }> = {
  'key set, one': { app: 14, vault: 4 },
  'key set, existing': { app: 14, vault: 4 },
  'key set, five': { app: 18, vault: 4 },
  'key archived': { app: 13, vault: 1 },
  'key restored (a version)': { app: 14, vault: 8 },
  'key renamed': { app: 9, vault: 1 },
  'key filed in a folder': { app: 6, vault: 1 },
  'reference made': { app: 16, vault: 8 },
  'reference broken': { app: 4, vault: 15 },
  'project made': { app: 4, vault: 1 },
  'project renamed': { app: 5, vault: 1 },
  'project archived': { app: 9, vault: 1 },
  'environment made': { app: 6, vault: 1 },
  'environment forked': { app: 45, vault: 4, hot: 1 },
  'environment renamed': { app: 7, vault: 1 },
  'environment protected': { app: 5, vault: 10 },
  'environment archived': { app: 11, vault: 1 },
  'member added': { app: 8, vault: 10 },
  'access granted': { app: 3, vault: 12 },
  'member removed': { app: 10, vault: 12 },
  'token issued': { app: 4, vault: 6 },
  'token revoked': { app: 2, vault: 3 },
};

test('each change route answers in exactly its budget of round trips (T179)', POSTGRES, async () => {
  const table: Record<string, { app: number; vault: number; hot: number; total: number; calls: number }> = {};
  const failures: string[] = [];
  for (const [n, { name, setup, run }] of CASES.entries()) {
    try {
      for (const i of [2 * n, 2 * n + 1]) if (setup !== undefined) await asRequest(() => setup(i));
      await cost(() => run(2 * n));
      const { statements: ran, ...counts } = await cost(() => run(2 * n + 1));
      table[name] = { ...counts, total: counts.app + counts.vault + counts.hot };
      const budget = BUDGETS[name];
      const spent = { app: counts.app, vault: counts.vault, hot: counts.hot };
      const expected = { app: budget?.app, vault: budget?.vault, hot: budget?.hot ?? 0 };
      if (JSON.stringify(spent) !== JSON.stringify(expected)) failures.push(`${name}: ${JSON.stringify(spent)}, not ${JSON.stringify(expected)}\n  ${ran.join('\n  ')}`);
      if (process.env.COFFRE_CHANGE_COST_VERBOSE) console.log(`\n${name}\n  ${ran.join('\n  ')}`);
    } catch (error) {
      failures.push(`${name}: ${(error as Error).message}`);
    }
  }
  if (process.env.COFFRE_CHANGE_COST_VERBOSE || failures.length > 0) console.table(table);
  assert.deepEqual(failures, []);
});

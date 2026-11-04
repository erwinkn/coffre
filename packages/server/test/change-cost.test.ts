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
import type { ProxyDefinition } from '@coffre/core/vault';
import { createDatabase, type Client } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { localVault, spoken, type SpokenVault } from '@coffre/vault/node';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { credentialProxy } from '../src/plugins/credential-proxy.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, entryOf, nothingHeld, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
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
      // Not a postgres.js client (`options`) nor a promise (`then`): the database takes it as a Hyperdrive pool.
      if (key === 'options' || key === 'then') return undefined;
      if (this.pool === null) throw new Error('no request under way');
      const value: unknown = Reflect.get(this.pool, key, this.pool);
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(this.pool) : value;
    },
  });
}

type Relay = Awaited<ReturnType<typeof postgresProxy>>;
/** A change's round trips: the app's, the vault's, the hot path's, and its vault calls; the statements, for a failure's message. */
type Cost = { app: number; vault: number; hot: number; calls: number; ms: number; statements: string[] };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let vault: SpokenVault;
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

  // Each Sync's statements, in the trace a failure prints; with `COFFRE_CHANGE_COST_RTT_MS`, each held that long, as
  // Hyperdrive far from its database holds it, for what a change takes end to end.
  const relay = (url: string, side: string) => postgresProxy(url, { delayMs: RTT_MS, onSync: (sent) => void statements.push(`${side} Sync: ${sent.map(shown).join(' | ') || '(none)'}`) });
  relays = { app: await relay(TEST_RUNTIME_DATABASE_URL, 'app'), vault: await relay(TEST_VAULT_DATABASE_URL, 'vault'), hot: await relay(TEST_HOT_DATABASE_URL, 'hot') };
  vaultPool = new HyperdrivePool(relays.vault.url);
  const opened = spoken(await localVault(
    { database: createDatabase(vaultPool), hotDatabase: relays.hot.url, kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld },
  ));
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
      // The credential proxy, its Proxy tab writing (0.16): what a save of an environment's definitions costs.
      resolveConfig({ publicUrl: ORIGIN, vault: entryOf(counted), auth, auditChainKey: deps.chainKey.toString('base64'), plugins: [credentialProxy({ credentials: {}, editable: true })] }),
      createDatabase(appClient.client),
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

const shown = (text: string) => text.replace(/\s+/g, ' ').trim().slice(0, 48);
const RTT_MS = Number(process.env.COFFRE_CHANGE_COST_RTT_MS ?? 0);

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
  const started = performance.now();
  await asRequest(work);
  const ms = Math.round(performance.now() - started);
  return { app: relays.app.syncs - from.app, vault: relays.vault.syncs - from.vault, hot: relays.hot.syncs - from.hot, calls: calls - from.calls, ms, statements };
}

type Case = { name: string; setup?: (i: number) => Promise<void>; run: (i: number) => Promise<unknown> };

/** A route sending API_KEY, which market/dev holds. */
const ROUTE: ProxyDefinition = {
  kind: 'route', name: 'openai', upstream: 'https://api.openai.com/v1', inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {API_KEY}' }],
  allow: [], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
};

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
  { name: 'member added, a role', run: (i) => owner.members.add(`user:dev-${i}@acme.example`, { role: 'developer', scope: { projects: { only: ['market'] } } }) },
  { name: 'service account added', run: (i) => owner.members.add(`token:ci-${i}`) },
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
  // An environment's proxy definitions (0.16, T186): its first save, and one more item on top of the page it loaded.
  {
    name: 'proxy definitions, first save',
    setup: async (i) => void (await owner.environments.create(`market/routed-${i}`)),
    run: (i) => owner.proxy.save(`market/routed-${i}`, { seal: null, items: { openai: ROUTE } }),
  },
  {
    name: 'proxy definitions, an item added',
    setup: async (i) => {
      await owner.environments.create(`market/routes-${i}`);
      seals.set(i, (await owner.proxy.save(`market/routes-${i}`, { seal: null, items: { openai: ROUTE } })).seal);
    },
    run: (i) => owner.proxy.save(`market/routes-${i}`, { seal: seals.get(i)!, items: { maps: { ...ROUTE, name: 'maps', upstream: 'https://maps.example.com' } } }),
  },
  {
    name: 'token revoked',
    setup: async (i) => void tokens.set(i, (await owner.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).id),
    run: (i) => owner.tokens.revoke(SERVICE, tokens.get(i)!),
  },
];
const tokens = new Map<number, string>();
const seals = new Map<number, string | null>();

/**
 * Each route's round trips, as measured: the app's Syncs, the vault's, and the hot path's. A change that adds one fails
 * here; one that saves one lowers its row (T179, R42, R57). The seal (R51) is the checkpointer's, apart: about three more
 * on Cloudflare (docs/design/0.15-plan.md, "As built: T171").
 *
 * Each `prepare` of a logged object costs the vault one statement (T190): `app_change` holds the app's row to its object's
 * newest change's seal, which SQL cannot authenticate, so the vault reads those changes and checks their MACs first.
 * A fork prepares twice. The pin that would fold it into the write is T179's (sealed-inputs.md).
 */
const BUDGETS: Record<string, { app: number; vault: number; hot?: number }> = {
  // A key write decided on one read (T179; docs/design/two-trips.md): the vault's statement, then the app's one Sync, the
  // head (a lock alone) and everything with the COMMIT, however many keys. No 0.14 entry since 0.16.0's contraction:
  // the changes record the write, in 0.15's log alone.
  'key set, one': { app: 1, vault: 1 },
  'key set, existing': { app: 1, vault: 1 },
  'key set, five': { app: 1, vault: 1 },
  'key archived': { app: 12, vault: 2 },
  'key restored (a version)': { app: 13, vault: 8 },
  'key renamed': { app: 9, vault: 1 },
  'key filed in a folder': { app: 6, vault: 1 },
  'reference made': { app: 15, vault: 8 },
  'reference broken': { app: 4, vault: 13 },
  'project made': { app: 4, vault: 1 },
  'project renamed': { app: 5, vault: 1 },
  'project archived': { app: 8, vault: 1 },
  'environment made': { app: 5, vault: 2 },
  'environment forked': { app: 43, vault: 5, hot: 1 },
  'environment renamed': { app: 6, vault: 2 },
  'environment protected': { app: 5, vault: 9 },
  'environment archived': { app: 10, vault: 2 },
  // A first add decided on one read (T179; docs/design/two-trips.md, "A member add"): the vault's read; then its write,
  // one Sync: the members' rows and 0.14's head (a lock alone), the hold, the row, the change and the COMMIT. No app
  // statement, and no 0.14 `member.add` entry since 0.16.0's contraction: the change records the add.
  'member added': { app: 0, vault: 2 },
  'member added, a role': { app: 0, vault: 2 },
  'service account added': { app: 0, vault: 2 },
  'access granted': { app: 3, vault: 8 },
  // Its answer is their report, which asks the vault for the proxy items they saved (T186 PR D): one read, after the commit.
  'member removed': { app: 10, vault: 9 },
  'token issued': { app: 4, vault: 6 },
  'token revoked': { app: 2, vault: 3 },
  'proxy definitions, first save': { app: 2, vault: 5 },
  'proxy definitions, an item added': { app: 2, vault: 5 },
};

test('each change route answers in exactly its budget of round trips (T179)', POSTGRES, async () => {
  const table: Record<string, { app: number; vault: number; hot: number; total: number; calls: number; ms: number }> = {};
  const failures: string[] = [];
  for (const [n, { name, setup, run }] of CASES.entries()) {
    try {
      // The warm request and the measured one in one bulk refresh period (a minute, at the default 15-minute window): a
      // use that crosses into the next moves its key's row on, a statement more on the hot path (`bulkRule`).
      const left = 60_000 - (Date.now() % 60_000);
      if (left < 5_000) await new Promise((resolve) => setTimeout(resolve, left + 100));
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
  if (process.env.COFFRE_CHANGE_COST_VERBOSE || RTT_MS > 0 || failures.length > 0) console.table(table);
  assert.deepEqual(failures, []);
});

// What each change costs in round trips, with 0.15's log, as on Workers: the app's database one
// Hyperdrive connection per request, the vault's one per call, each behind a proxy that counts the Syncs, which
// Hyperdrive sends on one at a time, so a round trip each. The seal is the checkpointer's, apart: here a change
// is sealed at once (`sealedNow`). Each route is asked once to warm the isolate, then measured.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
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
import { BUDGET, overBudget, type Budget } from './budgets.ts';
import { addPasskey, removePasskey, steppedUp } from './passkey-rows.ts';
import { inBulkPeriod } from './window-fixture.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'token:ci-web';
/** A Viewer of market/dev, who runs no instance: refused a key write there, and any add. */
const VIEWER = 'viewer@acme.example';
/**
 * An Admin, measured on a deployment of its own under the policy `off`, with a session that names no passkey and only a
 * removed passkey behind them: nothing behind the credential is read, as nothing decides on it.
 */
const ADMIN = 'admin-off@acme.example';
/** A Developer of market/dev, who owns no project: a token they issue there is told what it withholds. */
const DEVELOPER = 'developer@acme.example';

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
type Cost = { app: number; vault: number; hot: number; calls: number; ms: number; statements: string[]; connections: number };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let vault: SpokenVault;
let vaultPool: HyperdrivePool;
let relays: { app: Relay; vault: Relay; hot: Relay };
let appClient: PerRequest;
let runtime: CoffreRuntime;
let owner: CoffreClient;
let viewer: CoffreClient;
let admin: CoffreClient;
let developer: CoffreClient;
let calls = 0;
let statements: string[] = [];
const background: Promise<unknown>[] = [];

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  // Cut over and seeded through a vault of the suite's own, as signin-cost.test.ts does; then measured through one
  // whose connections go through the proxies.
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { sealThrough: sealedNow, heldOutside: nothingHeld }) });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod', 'market/base']) await root.environments.create(path);
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  // What a fork copies: two keys of an environment no other case writes to, so that their two periods surely leave a
  // shared stretch to measure in (`inBulkPeriod`). market/dev gathers a key or more a case, and twenty random phases
  // need not leave five seconds between their turns. One is filed, so that the fork's copy of folders is counted.
  await root.secrets.set('market/base', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  await root.secrets.update('market/base/API_KEY', { folder: 'stripe' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  await root.members.add(`user:${VIEWER}`);
  await root.access.set(`user:${VIEWER}`, { 'market/dev': 'viewer' });
  await root.members.add(`user:${ADMIN}`, { role: 'admin' });
  await root.access.set(`user:${ADMIN}`, { 'market/dev': 'developer' });
  await removePasskey(db.owner, deps.chainKey, await addPasskey(db.owner, deps.chainKey, ADMIN));
  await root.members.add(`user:${DEVELOPER}`);
  await root.access.set(`user:${DEVELOPER}`, { 'market/dev': 'developer' });

  // Each Sync's statements, in the trace a failure prints; with `COFFRE_CHANGE_COST_RTT_MS`, each held that long, as
  // Hyperdrive far from its database holds it, for what a change takes end to end.
  const relay = (url: string, side: string) => postgresProxy(url, { delayMs: RTT_MS, onSync: (sent) => void statements.push(`${side} Sync: ${sent.map(shown).join(' | ') || '(none)'}`) });
  relays = { app: await relay(TEST_RUNTIME_DATABASE_URL, 'app'), vault: await relay(TEST_VAULT_DATABASE_URL, 'vault'), hot: await relay(TEST_HOT_DATABASE_URL, 'hot') };
  vaultPool = new HyperdrivePool(relays.vault.url);
  const opened = spoken(await localVault(
    { database: createDatabase(vaultPool), hotDatabase: relays.hot.url, kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { sealThrough: sealedNow, heldOutside: nothingHeld },
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
  const deployment = (passkeys?: 'off'): CoffreRuntime => ({
    ...createRuntime(
      // The credential proxy, its Proxy tab writing (0.16): what a save of an environment's definitions costs.
      resolveConfig({
        publicUrl: ORIGIN, vault: entryOf(counted), auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], passkeys }),
        auditChainKey: deps.chainKey.toString('base64'), plugins: [credentialProxy({ credentials: {} })], deployment: { proxy: { editable: true } },
      }),
      createDatabase(appClient.client),
      counted,
      { json: async (url) => { throw new Error(`no fetch in this test: ${url.href}`); } },
    ),
    // What a request leaves running, waited for within it: its statements are its own.
    waitUntil: (promise) => void background.push(promise),
  });
  runtime = deployment();
  const off = deployment('off');
  // The Owner's browser session, as a page's calls send it; and the Viewer's. Each stepped up with a touch a moment
  // ago, as a session that changes access is (a fresh check, docs/design/passkeys.md, section 4).
  const browser = async (subject: string, email: string, on = runtime): Promise<CoffreClient> => {
    const session = await asRequest(async () => {
      const signed = await on.signin!.completeSignin({ provider: 'github', subject, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
      if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
      // Under `off`, as the provider signed them in: nothing is asked.
      return on === runtime ? (await steppedUp(on.signin!, db.owner, deps.chainKey, email, signed.credential.token)).token : signed.credential.token;
    });
    return createClient({
      url: ORIGIN,
      headers: () => ({ cookie: `${sessionCookieName(on.auth)}=${session}`, 'sec-fetch-site': 'same-origin' }),
      transport: (request) => fetchApi(request, on, { sourceIp: null }),
    });
  };
  owner = await browser('root', ROOT);
  viewer = await browser('viewer', VIEWER);
  admin = await browser('admin-off', ADMIN, off);
  developer = await browser('developer', DEVELOPER);
});

after(async () => {
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
  const from = { app: relays.app.syncs, vault: relays.vault.syncs, hot: relays.hot.syncs, calls, opened: relays.app.opened };
  statements = [];
  const started = performance.now();
  await asRequest(work);
  const ms = Math.round(performance.now() - started);
  return { app: relays.app.syncs - from.app, vault: relays.vault.syncs - from.vault, hot: relays.hot.syncs - from.hot, calls: calls - from.calls, ms, statements, connections: relays.app.opened - from.opened };
}

/** A change route; its budget `BUDGET.change` but where it names another. */
type Case = { name: string; setup?: (i: number) => Promise<void>; run: (i: number) => Promise<unknown>; budget?: Budget };

/** A route sending API_KEY, which market/dev holds. */
const ROUTE: ProxyDefinition = {
  kind: 'route', name: 'openai', upstream: 'https://api.openai.com/v1', inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {API_KEY}' }],
  allow: [], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
};

let made = 0;
const fresh = () => `k${(made += 1)}`;

/** A request the route refuses, 403, as asked: anything else fails the case. */
async function refused(request: Promise<unknown>): Promise<void> {
  try {
    await request;
  } catch (error) {
    if (error instanceof CoffreError && error.status === 403) return;
    throw error;
  }
  throw new Error('it was not refused');
}

/** Every change route, as the UI or CLI asks it: once to warm, once measured, each on rows of its own. */
const CASES: Case[] = [
  { name: 'key set, one', budget: BUDGET.write, run: () => owner.secrets.set('market/dev', { [fresh().toUpperCase()]: 'fake-value' }) },
  { name: 'key set, existing', budget: BUDGET.write, run: () => owner.secrets.set('market/dev', { API_KEY: `fake-${randomUUID()}` }) },
  { name: 'key set, five', budget: BUDGET.write, run: () => owner.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 5 }, () => [fresh().toUpperCase(), 'fake-value']))) },
  // Refused on the vault's read, and recorded by it: a write's budget too.
  { name: 'key set, refused', budget: BUDGET.write, run: () => refused(viewer.secrets.set('market/dev', { API_KEY: `fake-${randomUUID()}` })) },
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
  { name: 'environment forked', run: (i) => owner.environments.create(`market/fork-${i}`, { from: 'base' }) },
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
  { name: 'member added', budget: BUDGET.write, run: (i) => owner.members.add(`user:new-${i}@acme.example`) },
  { name: 'member added, a role', budget: BUDGET.write, run: (i) => owner.members.add(`user:dev-${i}@acme.example`, { role: 'developer', scope: { projects: { only: ['market'] } } }) },
  { name: 'service account added', budget: BUDGET.write, run: (i) => owner.members.add(`token:ci-${i}`) },
  { name: 'member added, refused', budget: BUDGET.write, run: (i) => refused(viewer.members.add(`user:turned-${i}@acme.example`)) },
  // Under `off`, by a person whose only passkey was removed (`ADMIN`): as the Owner's, nothing more read.
  { name: 'key set, under off', budget: BUDGET.write, run: () => admin.secrets.set('market/dev', { [fresh().toUpperCase()]: 'fake-value' }) },
  { name: 'member added, under off', budget: BUDGET.write, run: (i) => admin.members.add(`user:off-${i}@acme.example`) },
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
  { name: 'token issued, by a Developer', run: () => developer.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 }) },
  // An environment's proxy definitions: its first save, and one more item on top of the page it loaded.
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
  // An Owner's reset of someone's passkeys: one passkey or ten, the removals asked together, the same round trips (below).
  ...[1, 10].map((held): Case => ({
    name: `passkeys reset, ${held}`,
    setup: async (i) => {
      const email = `reset-${held}-${i}@acme.example`;
      await owner.members.add(`user:${email}`);
      for (let n = 0; n < held; n++) await addPasskey(db.owner, deps.chainKey, email);
    },
    run: (i) => owner.call('DELETE /members/:member/passkeys', { member: `user:reset-${held}-${i}@acme.example` }),
  })),
  {
    name: 'token revoked',
    setup: async (i) => void tokens.set(i, (await owner.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).id),
    run: (i) => owner.tokens.revoke(SERVICE, tokens.get(i)!),
  },
];
const tokens = new Map<number, string>();
const seals = new Map<number, string | null>();

test('each change route answers within its budget of round trips', async () => {
  const table: Record<string, { app: number; vault: number; hot: number; total: number; calls: number; ms: number }> = {};
  const failures: string[] = [];
  for (const [n, { name, setup, run, budget = BUDGET.change }] of CASES.entries()) {
    try {
      // The warm request and the measured one in one bulk refresh period of every key they use (a minute, at the default
      // 15-minute window, from each key's phase): a use that crosses into the next moves its key's row on, a statement
      // more on the hot path (`bulkRule`). Only a fork uses keys, the owner's of market/base.
      await inBulkPeriod(5_000, db.owner, [`user:${ROOT}`], 'market/base');
      for (const i of [2 * n, 2 * n + 1]) if (setup !== undefined) await asRequest(() => setup(i));
      await cost(() => run(2 * n));
      const { statements: ran, connections, ...counts } = await cost(() => run(2 * n + 1));
      // One app connection a request, however its statements overlap the vault's calls (AGENTS.md, "One connection per call").
      if (connections > 1) failures.push(`${name}: ${connections} app connections, not one`);
      const total = counts.app + counts.vault + counts.hot;
      table[name] = { ...counts, total };
      const over = overBudget({ trips: total }, budget);
      if (over.length > 0) failures.push(`${name}: ${over.join(', ')}\n  ${ran.join('\n  ')}`);
      if (process.env.COFFRE_CHANGE_COST_VERBOSE) console.log(`\n${name}\n  ${ran.join('\n  ')}`);
    } catch (error) {
      failures.push(`${name}: ${(error as Error).message}`);
    }
  }
  // A reset grows with nothing it removes: exactly as many round trips for ten passkeys as for one.
  const [one, ten] = [table['passkeys reset, 1'], table['passkeys reset, 10']];
  if (one?.total !== ten?.total) failures.push(`passkeys reset: ${ten?.total} round trips for ten, ${one?.total} for one`);
  if (process.env.COFFRE_CHANGE_COST_VERBOSE || RTT_MS > 0 || failures.length > 0) console.table(table);
  assert.deepEqual(failures, []);
});

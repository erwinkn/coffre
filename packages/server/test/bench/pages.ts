// The environment and project pages' server render, as Workers runs it, each Sync a round trip of `RTT` ms (34 by
// default, Warsaw's Worker to a Paris database through Hyperdrive, T141): the app's statements on a connection of the
// render's own (`HyperdrivePool`, its reads asked together under one Sync), the vault's on its pool, each through a
// relay that holds each Sync that long (`postgresProxy`). Prints each page's time, p50 and p90, and its Syncs, as
// Owner and as viewer, in an instance as request-cost.test.ts makes it: a reference into the environment and a
// project with a fork. Not a test: run with the test database's settings, on a database migrated as the tests' are,
//
//   COFFRE_TEST_DATABASE=<a migrated scratch database> node --conditions=coffre:source packages/server/test/bench/pages.ts
import { randomBytes, randomUUID } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { localVault } from '@coffre/vault/node';

import { Accesses } from '../../src/accesses.ts';
import { SigninService } from '../../src/api/signin.ts';
import { sessionCookieName } from '../../src/auth.ts';
import { pageClient } from '../../src/fetch-api.ts';
import type { CoffreRuntime } from '../../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testAnchor, waitUntil, type FixtureDeps } from '../api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from '../db/connections.ts';
import { testPostgresPool } from '../db/postgres-pool.ts';
import { postgresProxy } from '../../../../scripts/postgres-proxy.ts';
import { percentile } from './far.ts';

const RTT = Number(process.env.RTT ?? 34);
const SAMPLES = Number(process.env.SAMPLES ?? 20);
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);
if (auth.mode !== 'signin') throw new Error('unreachable');
const signinConfig = auth.signin;

const db = await openTestDatabase();
await resetDatabase(db.owner);
const [app, vaultSide] = await Promise.all([postgresProxy(TEST_RUNTIME_DATABASE_URL, { delayMs: RTT }), postgresProxy(TEST_VAULT_DATABASE_URL, { delayMs: RTT })]);
const vaultPool = testPostgresPool(vaultSide.url);
const setupPool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
const vault = await localVault({ database: createDatabase(vaultPool), kek: { id: 'bench-kek', key: randomBytes(32).toString('base64') }, owners: [ROOT] }, { log: '0.14' });
const base: FixtureDeps = { db: createDatabase(setupPool), vault: vault as unknown as FixtureDeps['vault'], chainKey: randomBytes(32), anchor: testAnchor() };
const accesses = new Accesses();
const setupSignin = new SigninService({ ...base, signin: signinConfig, accesses });
const runtime: CoffreRuntime = {
  db: base.db, vault: base.vault, chainKey: base.chainKey, previousChainKeys: [], signin: setupSignin, workloads: null, mcp: null, auth, publicUrl: ORIGIN,
  verifier: setupSignin, waitUntil, schema: { migrated: true }, appKey: { settled: true }, accesses, rotateAfterDays: 365, plugins: [],
};

const root = clientFor({ ...base, signin: setupSignin }, ROOT);
await root.projects.create('market', { name: 'Market' });
for (const path of ['market/dev', 'market/prod', 'market/busy']) await root.environments.create(path, { name: path });
await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake', WEBHOOK_SECRET: 'fake-webhook-secret' });
await root.members.add(`user:${READER}`);
await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
await root.secrets.set('market/busy', { DEV_API_KEY: { ref: 'market/dev/API_KEY' } });
await root.projects.create('shop', { name: 'Shop' });
await root.environments.create('shop/dev', { name: 'dev' });
await root.secrets.set('shop/dev', { SHOP_KEY: 'fake-shop-key' });
await root.environments.create('shop/dev-eu', { name: 'dev-eu', from: 'dev', inherit: true });

type Persona = 'owner' | 'viewer';
const sessions = new Map<Persona, string>();
for (const [persona, email] of [['owner', ROOT], ['viewer', READER]] as const) {
  const signed = await setupSignin.completeSignin({ provider: 'github', subject: persona, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
  if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
  sessions.set(persona, signed.credential.token);
}

/** One render, as request-cost.test.ts's: its own connection, its Syncs counted. */
async function render(as: Persona, path: string, calls: (client: CoffreClient) => Promise<unknown>): Promise<{ ms: number; app: number; vault: number }> {
  const pool = new HyperdrivePool(app.url, { groupReads: true });
  const renderDb = createDatabase(pool);
  const signin = new SigninService({ ...base, db: renderDb, signin: signinConfig, accesses, scopes: { sealed: true } });
  const page = new Request(`${ORIGIN}${path}`, { headers: { cookie: `${sessionCookieName(auth)}=${sessions.get(as)!}`, 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none' } });
  const [appSyncs, vaultSyncs] = [app.syncs, vaultSide.syncs];
  const started = performance.now();
  try {
    await calls(pageClient(page, { ...runtime, db: renderDb, signin, verifier: signin }, null));
    return { ms: performance.now() - started, app: app.syncs - appSyncs, vault: vaultSide.syncs - vaultSyncs };
  } finally {
    await pool.end();
  }
}

const pages: Record<string, () => Promise<{ ms: number; app: number; vault: number }>> = {};
for (const as of ['owner', 'viewer'] as const) {
  pages[`environment, ${as}`] = () => render(as, '/projects/market/dev', async (client) => {
    const projects = client.projects.list();
    await Promise.all([client.auth(), client.me(), projects, projects.then(() => Promise.all([
      client.secrets.list('market/dev'), client.references.list('market/dev'), client.environments.missing('market/dev'),
    ]))]);
  });
  pages[`project, ${as}`] = () => render(as, '/projects/market', async (client) => {
    const projects = client.projects.list();
    await Promise.all([client.auth(), client.me(), projects, projects.then(async ({ projects: listed }) => {
      if (listed.find((project) => project.slug === 'market')?.permissions.includes('grant.manage')) await client.members.list('market');
    })]);
  });
}

console.log(`rtt ${RTT} ms, ${SAMPLES} samples a page`);
for (const [name, page] of Object.entries(pages)) {
  for (let i = 0; i < 3; i++) await page();
  const runs = [];
  for (let i = 0; i < SAMPLES; i++) runs.push(await page());
  const ms = runs.map((run) => run.ms).sort((a, b) => a - b);
  console.log(`${name.padEnd(20)} p50 ${percentile(ms, 50).toFixed(0).padStart(4)} ms  p90 ${percentile(ms, 90).toFixed(0).padStart(4)} ms  app syncs ${runs.at(-1)!.app}  vault syncs ${runs.at(-1)!.vault}`);
}

await resetDatabase(db.owner);
await Promise.all([vaultPool.end(), setupPool.end(), db.close(), app.close(), vaultSide.close()]);

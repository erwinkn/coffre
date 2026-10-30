// What a read costs through a way in with no credentials row, with 0.15's uses (T147; formal/WaysIn.tla): an MCP
// client's reveal through its connection, a Worker's /use through its Cloudflare binding, and a reveal from a browser
// behind Cloudflare Access. Each value is one `use_credential` call on the hot path's login, deciding on the way in
// itself: no `credentialStill` on the app's connection after it, no vault call but the uses, and nothing of 0.14's
// head. Before, each was 0.14's unwrap under that head, then the app's check of the way in.
// Postgres only: the counts are its statements.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { ACCESS_JWT_HEADER, cloudflareAccess, github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { localVault, type LocalVault } from '@coffre/vault/node';

import { callerFrom, newestPolicySeq } from '../src/api/caller.ts';
import { AppChanges, connectionChange } from '../src/api/changes.ts';
import { audited } from '../src/api/context.ts';
import type { AuthenticatedIdentity } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { insertConnection } from '../src/db/queries.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { bindingRoute, checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';
import { logFence } from './db/tables.ts';

const POSTGRES = postgresOnly("counts the app's and the hot path's Postgres statements");
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const EDGE = 'token:edge';
const API_KEY = 'sk_live_0123456789abcdef';

type Statement = { text: string };

/** Nothing here fetches: no issuer's keys, no workload. */
const transport = { json: async (url: URL): Promise<unknown> => { throw new Error(`no fetch of ${url.href} here`); } };

/** A pool that records each statement run on it while `recording`. */
class RecordingPool {
  readonly pool: PostgresClient;
  readonly client: PostgresClient;
  recording: Statement[] | null = null;

  constructor(url: string) {
    this.pool = testPostgresPool(url);
    this.client = watched(this.pool, ({ text }) => this.recording?.push({ text }));
  }
}

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let app: RecordingPool;
let vaultPool: RecordingPool;
let hot: RecordingPool;
let vault: LocalVault;
let upstream: Server;
/** The deployment that signs in through coffre (the MCP connection's, the binding's), and the one behind Access. */
let own: CoffreRuntime;
let access: CoffreRuntime;
let connectionId: string;

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  const kek = randomBytes(32);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY });
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer' });
  await root.members.add(EDGE);
  await root.access.set(EDGE, { 'market/dev': 'viewer' });

  upstream = createServer((request, response) => response.writeHead(request.headers['x-api-key'] === API_KEY ? 200 : 403).end());
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  app = new RecordingPool(TEST_RUNTIME_DATABASE_URL);
  vaultPool = new RecordingPool(TEST_VAULT_DATABASE_URL);
  hot = new RecordingPool(TEST_HOT_DATABASE_URL);
  vault = await localVault(
    { database: createDatabase(vaultPool.client), hotDatabase: createDatabase(hot.client), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { log: '0.15', sealThrough: sealedNow },
  );
  const runtimeOf = (auth: ReturnType<typeof signin>) => {
    const config = resolveConfig({
      publicUrl: ORIGIN, vault, auth, auditChainKey: deps.chainKey.toString('base64'),
      plugins: [credentialProxy({ credentials: { api: { upstream: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1`, inject: header('x-api-key', '{API_KEY}') } }, insecureUpstreams: true, cacheSeconds: 0 })],
    });
    const runtime = createRuntime(config, createDatabase(app.client), vault, transport);
    runtime.plugins = checkPlugins(config.plugins);
    return runtime;
  };
  own = runtimeOf(signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }));
  access = runtimeOf(cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'coffre-aud' }));

  // The Worker's Cloudflare binding, sealed by the vault as it makes one.
  await own.workloads!.bind(await contextFor(deps, ROOT), EDGE.slice('token:'.length), { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [], policy: {} }, { dryRun: false });
  // Dev's MCP client, connected: its row and its object, made together (T147).
  connectionId = randomUUID();
  const expiresAt = new Date(Date.now() + 86_400_000);
  const member = `user:${DEV}`;
  const changes = await AppChanges.prepare(deps.vault, member, [connectionChange(null, { id: connectionId, principal: member, generation: 0, expiresAt, revokedAt: null })]);
  await audited({ db: deps.db, chainKey: deps.chainKey }, async (tx) => {
    await insertConnection(tx, deps.chainKey, {
      id: connectionId, principal: member, generation: 0, clientId: 'https://client.example/meta', clientName: 'Client', clientHost: 'client.example', registration: 'cimd',
      scopes: 'read reveal', redirectUri: 'https://client.example/back', codeHash: randomBytes(32), codeChallenge: 'challenge', codeExpiresAt: new Date(Date.now() + 60_000), expiresAt,
    });
  }, changes);
  await changes?.sealed();
});

after(async () => {
  if (POSTGRES.skip) return;
  await vault.close();
  await Promise.all([app.pool.end(), vaultPool.pool.end(), hot.pool.end()]);
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await resetDatabase(db.owner);
  await db.close();
});

/**
 * Dev as a request through `way` reads as them: the vault's answer about them, asked once here, as the MCP endpoint and
 * Access's verifier ask as they authenticate, before what this measures; and nothing of a credential.
 */
async function asDev(runtime: CoffreRuntime, way: Pick<AuthenticatedIdentity, 'via' | 'provenance' | 'access'>): Promise<() => Promise<AuthenticatedIdentity>> {
  const principal = { type: 'user' as const, id: DEV };
  const caller = callerFrom(principal, await vault.access(`user:${DEV}`), await newestPolicySeq(runtime.db));
  return async () => ({
    principal: { ...principal, email: DEV, subject: DEV }, registered: true, caller, requestId: randomUUID(), sourceIp: null,
    credentialId: null, credentialExpiresAt: null, personalToken: null, handlePlaces: null, ...way,
  });
}

/** A request's statements, by pool, the request run once before, so that what a process does once is done. */
async function statements(request: () => Promise<Response>): Promise<{ app: string[]; vault: string[]; hot: string[] }> {
  const run = async () => {
    const response = await request();
    assert.ok(response.status === 200 || response.status === 204, `${response.status}: ${await response.clone().text()}`);
    await response.arrayBuffer();
  };
  await run();
  for (const pool of [app, vaultPool, hot]) pool.recording = [];
  await run();
  const shown = (ran: Statement[]) => ran.map(({ text }) => text.replace(/\s+/g, ' ').slice(0, 32));
  const ran = { app: shown(app.recording!), vault: shown(vaultPool.recording!), hot: shown(hot.recording!) };
  for (const pool of [app, vaultPool, hot]) pool.recording = null;
  return ran;
}

const reveal = (runtime: CoffreRuntime, identity: () => Promise<AuthenticatedIdentity>) => () =>
  // Behind Access, its assertion (whose check `identity` stands in for, as for the others' tokens).
  fetchApi(new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: 'Bearer way-in', [ACCESS_JWT_HEADER]: 'way-in', 'content-type': 'application/json' }, body: JSON.stringify({ path: 'market/dev/API_KEY' }) }),
    runtime, { sourceIp: null, authenticate: identity });

const USE = 'SELECT use_credential( $1::uuid,';
/** `credentialStill`'s read of the way in, after the vault released (`wayInStands`): what a use through it no longer needs. */
const STILL = 'select "vault_members"."status",';

test('through an MCP connection, a Cloudflare binding, or behind Access, a value is the hot path\'s one call: no check of the way in after it, no vault call but the use, nothing of 0.14\'s head (T147)', POSTGRES, async () => {
  const cases = [
    ['an MCP client\'s reveal', reveal(own, await asDev(own, { via: { connectionId, clientId: 'https://client.example/meta', clientName: 'Client', scopes: ['read', 'reveal'] }, provenance: connectionId }))],
    ['a Worker\'s /use through its binding', async () => (await bindingRoute(new Request(`${ORIGIN}/use/market/dev/api/v1/charges`), own, EDGE))!],
    ['a reveal behind Access', reveal(access, await asDev(access, { via: null, provenance: null, access: true }))],
  ] as const;
  for (const [name, request] of cases) {
    const ran = await statements(request);
    assert.deepEqual(ran.hot, [USE], `${name}: one use`);
    assert.deepEqual(ran.vault, [], `${name}: no vault call but the use`);
    assert.ok(!ran.app.some((text) => text.startsWith(STILL)), `${name}: no read of the way in after the use: ${JSON.stringify(ran.app)}`);
    assert.ok(!ran.app.some((text) => /audit_chain_head/.test(text)), `${name}: nothing of 0.14's head`);
  }
  // Each use logged under its way in, the kind in the purpose's bits above 512: a connection, a binding, a person.
  const ways = (await usesLogged(db.owner)).map((use) => Math.floor(use.purpose / 512));
  assert.deepEqual([...new Set(ways)].sort(), [1, 2, 3]);
});

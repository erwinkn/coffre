// What a request costs, exactly, and that it does not grow with the
// instance. On Workers' Free plan, an invocation has 10 ms of CPU; each
// statement is a round trip through Hyperdrive, and each connection, the
// app's or one vault call's, costs a TLS socket and a SCRAM login. So each
// hot request has a budget of statements and connections it meets exactly,
// and runs the same statements, reading the same rows, on a log of a few
// entries as on one of thousands, among a handful of members or hundreds,
// after one change to the policy or many.
// `pnpm bench:workers` measures the CPU itself (packages/conformance/scripts/bench.ts).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { localVault } from '@coffre/vault/node';
import type pg from 'pg';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool } from './db/postgres-pool.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci-web';
const POSTGRES = postgresOnly("counts what the app's and the vault's Postgres connections run");
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

type Count = { statements: number; rows: number };

/** A pool that counts the statements run on it, a transaction's included, and the rows they answered. Drizzle checks out a client for a transaction from a class named `…Pool`. */
class CountingPool {
  readonly #pool: pg.Pool;
  readonly count: Count = { statements: 0, rows: 0 };

  constructor(pool: pg.Pool) {
    this.#pool = pool;
  }

  async #counted(query: pg.Pool['query'] | pg.PoolClient['query'], args: unknown[]): Promise<unknown> {
    const answered = await (query as (...queryArgs: unknown[]) => Promise<pg.QueryResult | pg.QueryResult[]>)(...args);
    this.count.statements += 1;
    // A simple query of several statements answers each: BEGIN and its lock timeout, one round trip.
    for (const result of [answered].flat()) this.count.rows += result.rows?.length ?? 0;
    return answered;
  }

  query = ((...args: unknown[]) => this.#counted(this.#pool.query.bind(this.#pool), args)) as pg.Pool['query'];

  async connect() {
    const client = await this.#pool.connect();
    return {
      query: ((...args: unknown[]) => this.#counted(client.query.bind(client), args)) as pg.PoolClient['query'],
      release: () => client.release(),
    };
  }

  end() {
    return this.#pool.end();
  }
}

/** What a request ran: statements and rows on the app's connection and on the vault's, and how many calls the vault answered, each a connection of its own on Workers. */
type Cost = { app: Count; vault: Count; vaultCalls: number };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let app: CountingPool;
let vaultPool: CountingPool;
let vaultCalls = 0;
let root: CoffreClient;
let reader: CoffreClient;
let service: CoffreClient;

/** A client that calls the API as a CLI or a CI run does, its token checked on each request. */
function bearer(runtime: CoffreRuntime, token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
}

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  app = new CountingPool(testPostgresPool(TEST_RUNTIME_DATABASE_URL));
  vaultPool = new CountingPool(testPostgresPool(TEST_VAULT_DATABASE_URL));
  const opened = await localVault({
    database: createDatabase(vaultPool),
    kek: { id: 'test-kek-1', key: randomBytes(32).toString('base64') },
    owners: [ROOT],
  });
  // Every call the app makes of the vault: on Workers, each its own invocation and connection.
  const vault = new Proxy(opened as unknown as Vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        vaultCalls += 1;
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const base: FixtureDeps = { db: createDatabase(app), vault, chainKey: randomBytes(32) };
  const signinService = new SigninService({ ...base, signin: auth.signin });
  const deps: FixtureDeps = { ...base, signin: signinService };
  const runtime: CoffreRuntime = {
    db: deps.db, vault, chainKey: deps.chainKey, signin: signinService, workloads: null, mcp: null, auth, publicUrl: ORIGIN,
    verifier: signinService, waitUntil, schema: { migrated: true }, rotateAfterDays: 365, plugins: [],
  };
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod', 'market/busy']) await root.environments.create(path, { name: path });
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  // One change to the policy, so that there is a newest to read before there are many.
  await root.environments.protect('market/prod');

  // The reader's CLI session, from an approved device login, and the service's token, as a CI run holds them.
  const started = await signinService.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await signinService.decideDevice(await contextFor(deps, READER), started.userCode, true);
  const polled = await signinService.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  reader = bearer(runtime, polled.credential.token);
  service = bearer(runtime, (await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).token);
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await Promise.all([app.end(), vaultPool.end(), db.close()]);
});

async function cost(request: () => Promise<unknown>): Promise<Cost> {
  const before = { app: { ...app.count }, vault: { ...vaultPool.count }, vaultCalls };
  await request();
  const since = (now: Count, then: Count) => ({ statements: now.statements - then.statements, rows: now.rows - then.rows });
  return { app: since(app.count, before.app), vault: since(vaultPool.count, before.vault), vaultCalls: vaultCalls - before.vaultCalls };
}

/**
 * Each hot request, and what it costs warm: its statements on the app's
 * connection and the vault's, and the vault's calls.
 *
 * A reveal: the credential, with the newest policy change; the path; the
 * environment's rows. The vault's `access`: one statement. Its `unwrap`:
 * the versions, then BEGIN with its lock timeout, the reader's row locked,
 * the head locked with everything the decision reads, the entries and the
 * head in one statement, COMMIT.
 */
const requests: Record<string, { request: () => Promise<unknown>; budget: { app: number; vault: number; vaultCalls: number } }> = {
  'a reveal of one key': { request: () => reader.secrets.reveal('market/dev/API_KEY'), budget: { app: 3, vault: 7, vaultCalls: 2 } },
  'a reveal of an environment': { request: () => reader.secrets.reveal('market/dev'), budget: { app: 3, vault: 7, vaultCalls: 2 } },
  'an export, as a service': { request: () => service.secrets.reveal('market/dev'), budget: { app: 3, vault: 7, vaultCalls: 2 } },
  "a request's check of its caller": { request: () => reader.me(), budget: { app: 2, vault: 2, vaultCalls: 2 } },
};

test('each hot request runs exactly its budget of statements, on as many connections', POSTGRES, async () => {
  // Once first, for what the vault does once per process.
  for (const { request } of Object.values(requests)) await request();
  for (const [name, { request, budget }] of Object.entries(requests)) {
    const spent = await cost(request);
    assert.deepEqual({ app: spent.app.statements, vault: spent.vault.statements, vaultCalls: spent.vaultCalls }, budget, name);
  }
});

test('a request runs the same statements, and reads the same rows, however large the log, the members and the policy grow', POSTGRES, async () => {
  for (const { request } of Object.values(requests)) await request();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await cost(request);

  // The log grown by writes elsewhere, each an entry of the app's and one of the vault's.
  for (let i = 0; i < 150; i++) await root.secrets.set('market/busy', { [`KEY_${i % 20}`]: `fake-${i}` });
  // Members, each with a grant, and the reader's own access changed back and forth: entries about them.
  for (let i = 0; i < 40; i++) {
    await root.members.add(`user:member-${i}@acme.example`);
    await root.access.set(`user:member-${i}@acme.example`, { 'market/dev': 'viewer' });
  }
  for (let i = 0; i < 40; i++) await root.access.set(`user:${READER}`, { 'market/dev': i % 2 === 0 ? 'developer' : 'viewer' });
  // The policy changed, again and again: prod unprotected, then protected again.
  for (let i = 0; i < 40; i++) await root.environments.protect('market/prod', i % 2 === 1);

  for (const [name, { request }] of Object.entries(requests)) {
    assert.deepEqual(await cost(request), small[name], `${name} ran more statements or read more rows once the instance grew`);
  }
});

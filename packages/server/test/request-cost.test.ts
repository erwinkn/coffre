// What a request costs does not grow with the instance. On Workers' Free
// plan, an invocation has 10 ms of CPU, and most of a request's goes to the
// statements it runs and the rows they bring back: so a reveal, or any
// request's check of its caller, runs the same statements and reads the
// same rows on a log of a few entries as on one of thousands, among a
// handful of members or hundreds, after one change to the policy or many.
// `pnpm bench:workers` measures the CPU itself (packages/conformance/scripts/bench.ts).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';
import { createDatabase } from '@coffre/db';
import { localVault } from '@coffre/vault/node';
import type pg from 'pg';

import { clientFor, openTestDatabase, resetDatabase, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool } from './db/postgres-pool.ts';

const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const POSTGRES = postgresOnly("counts what the app's and the vault's Postgres connections run");

type Count = { statements: number; rows: number };

/** A pool that counts the statements run on it, a transaction's included, and the rows they answered. Drizzle checks out a client for a transaction from a class named `…Pool`. */
class CountingPool {
  readonly #pool: pg.Pool;
  readonly count: Count = { statements: 0, rows: 0 };

  constructor(pool: pg.Pool) {
    this.#pool = pool;
  }

  async #counted(query: pg.Pool['query'] | pg.PoolClient['query'], args: unknown[]): Promise<unknown> {
    const answered = await (query as (...queryArgs: unknown[]) => Promise<pg.QueryResult>)(...args);
    this.count.statements += 1;
    this.count.rows += answered.rows?.length ?? 0;
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

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let app: CountingPool;
let vaultPool: CountingPool;
let root: CoffreClient;
let reader: CoffreClient;

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  app = new CountingPool(testPostgresPool(TEST_RUNTIME_DATABASE_URL));
  vaultPool = new CountingPool(testPostgresPool(TEST_VAULT_DATABASE_URL));
  const vault = await localVault({
    database: createDatabase(vaultPool),
    kek: { id: 'test-kek-1', key: randomBytes(32).toString('base64') },
    owners: [ROOT],
  });
  const deps: FixtureDeps = { db: createDatabase(app), vault: vault as unknown as FixtureDeps['vault'], chainKey: randomBytes(32) };
  root = clientFor(deps, ROOT);
  reader = clientFor(deps, READER);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod', 'market/busy']) await root.environments.create(path, { name: path });
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  // One change to the policy, so that there is a newest to read before there are many.
  await root.environments.protect('market/prod');
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await Promise.all([app.end(), vaultPool.end(), db.close()]);
});

/** What `request` ran, on the app's connections and the vault's. */
async function cost(request: () => Promise<unknown>): Promise<{ app: Count; vault: Count }> {
  const before = { app: { ...app.count }, vault: { ...vaultPool.count } };
  await request();
  const since = (now: Count, then: Count) => ({ statements: now.statements - then.statements, rows: now.rows - then.rows });
  return { app: since(app.count, before.app), vault: since(vaultPool.count, before.vault) };
}

const requests = {
  'a reveal of one key': () => reader.secrets.reveal('market/dev/API_KEY'),
  'a reveal of an environment': () => reader.secrets.reveal('market/dev'),
  "a request's check of its caller": () => reader.me(),
};

test('a request runs the same statements, and reads the same rows, however large the log, the members and the policy grow', POSTGRES, async () => {
  // Once first, for what the vault does once per process.
  for (const request of Object.values(requests)) await request();
  const small: Record<string, Awaited<ReturnType<typeof cost>>> = {};
  for (const [name, request] of Object.entries(requests)) small[name] = await cost(request);

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

  for (const [name, request] of Object.entries(requests)) {
    assert.deepEqual(await cost(request), small[name], `${name} ran more statements or read more rows once the instance grew`);
  }
});

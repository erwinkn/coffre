// What the credential proxy's `/use` costs with 0.15's uses (T135, R42, R44, R48), a person's handle at a proxy that
// keeps nothing (`cacheSeconds: 0`), the hot path at its worst. On the app's connection, one `app_read` (migration
// 0031): the handle's credential, the place and the key, in one call; then the vault's one `use_credential`, which
// decides on the credential's standing itself, its generation included (T145): no `credentialStill` after it. The stable URL first checks the handle, its
// credential read ahead and the vault asked about its person, for which environments it was made; then the use, as the
// environment's URL makes it, on the answer just kept. Each statement reads as many rows, and
// as many pages, however long the log grows and however many keys, environments and members the instance holds. A
// reveal through the API, of a key, an environment or its named keys, and an export, make one use a value, and no
// `credentialStill` after them either.
// Postgres only: the counts are its statements, and SQLite reads as the app's statements always did.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { localVault, type LocalVault } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';
import { logFence } from './db/tables.ts';
import { answer, type Pages } from './start-fixture.ts';

const POSTGRES = postgresOnly("counts the app's and the hot path's Postgres statements");
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const API_KEY = 'sk_live_0123456789abcdef';

type Statement = { text: string; values: unknown[]; rows: number };

/** Nothing here fetches: no issuer's keys, no workload. */
const transport = { json: async (url: URL): Promise<unknown> => { throw new Error(`no fetch of ${url.href} here`); } };

/** A pool that records each statement run on it while `recording`, with the rows it answered. */
class RecordingPool {
  readonly pool: PostgresClient;
  readonly client: PostgresClient;
  recording: Statement[] | null = null;

  constructor(url: string) {
    this.pool = testPostgresPool(url);
    this.client = watched(this.pool, ({ text, values, rows }) => this.recording?.push({ text, values, rows }));
  }

  /** The pages `statement` touches, run again as this login in a transaction rolled back: its second run, planned. */
  async pages(statement: Statement): Promise<number> {
    const rolledBack = new Error('rolled back');
    let pages = 0;
    await this.pool.begin(async (tx) => {
      for (let run = 0; run < 2; run++) {
        const [row] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] })['QUERY PLAN'];
        pages = plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
      }
      throw rolledBack;
    }).catch((error: unknown) => {
      if (error !== rolledBack) throw error;
    });
    return pages;
  }
}

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let app: RecordingPool;
let vaultPool: RecordingPool;
let hot: RecordingPool;
let vault: LocalVault;
let runtime: CoffreRuntime;
let upstream: Server;
let handle: string;
/** The runtime that made the handles, to make another. */
let setupRuntime: CoffreRuntime;
/** Tokens of a person and of a service, for reveals through the API (`POST /api/reveals`). */
let personal: string;
let service: string;

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  // Uses go in at or past the floor of `at` (schema 0022), as a deployment's checkpointer keeps it.
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  const kek = randomBytes(32);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  const setup = createRuntime(resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64') }), deps.db, deps.vault, transport);
  setupRuntime = setup;
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY, OTHER: 'other-value' });
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer' });
  handle = (await setup.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 600, paths: ['market/dev'] })).token;
  personal = (await setup.signin!.issuePersonalToken(await contextFor(deps, DEV), { label: 'run', expiresInMinutes: 600, scope: { 'market/dev': 'viewer' } })).token;
  await root.members.add('token:ci');
  await root.access.set('token:ci', { 'market/dev': 'viewer' });
  service = (await setup.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;

  upstream = createServer((request, response) => response.writeHead(request.headers['x-api-key'] === API_KEY ? 200 : 403).end());
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  // The app and the vault on pools of their own that record what they run, as a deployment's: the vault's hot path on its own login.
  app = new RecordingPool(TEST_RUNTIME_DATABASE_URL);
  vaultPool = new RecordingPool(TEST_VAULT_DATABASE_URL);
  hot = new RecordingPool(TEST_HOT_DATABASE_URL);
  vault = await localVault(
    { database: createDatabase(vaultPool.client), hotDatabase: createDatabase(hot.client), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { log: '0.15', sealThrough: sealedNow },
  );
  const config = resolveConfig({
    publicUrl: ORIGIN, vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64'),
    plugins: [credentialProxy({ credentials: { api: { upstream: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1`, inject: header('x-api-key', '{API_KEY}') } }, insecureUpstreams: true, cacheSeconds: 0 })],
  });
  runtime = createRuntime(config, createDatabase(app.client), vault, transport);
  runtime.plugins = checkPlugins(config.plugins);
});

after(async () => {
  if (POSTGRES.skip) return;
  await vault.close();
  await Promise.all([app.pool.end(), vaultPool.pool.end(), hot.pool.end()]);
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await resetDatabase(db.owner);
  await db.close();
});

/** A request's statements, by pool, the request run once before, so that what a process does once is done. */
async function statements(url: string, token = handle, { warm = true } = {}): Promise<{ app: Statement[]; vault: Statement[]; hot: Statement[] }> {
  const use = async () => {
    const response = await answer(new Request(url, { headers: { 'x-api-key': token } }), runtime, {} as Pages, '203.0.113.7');
    assert.equal(response.status, 200, await response.clone().text());
    await response.arrayBuffer();
  };
  if (warm) await use();
  for (const pool of [app, vaultPool, hot]) pool.recording = [];
  await use();
  const ran = { app: app.recording!, vault: vaultPool.recording!, hot: hot.recording! };
  for (const pool of [app, vaultPool, hot]) pool.recording = null;
  return ran;
}

const NAMED = `${ORIGIN}/use/market/dev/api/v1/charges`;
const STABLE = `${ORIGIN}/use/api/v1/charges`;
const shown = (ran: Statement[]) => ran.map(({ text }) => text.replace(/\s+/g, ' ').slice(0, 32));

test("a handle's /use is the vault's one call, at its environment's URL or the stable one: its use by the ids it keeps, warm, and, cold, a read by its names, then the use by the ids read; the app runs nothing (T145, D153)", POSTGRES, async () => {
  const use = 'SELECT use_credential( $1::uuid,';
  const named = await statements(NAMED);
  assert.deepEqual(shown(named.app), [], 'the named URL: no statement of the app');
  assert.deepEqual(shown(named.hot), [use], 'warm: the use alone, by the ids its isolate keeps');
  assert.deepEqual(named.vault, [], "no vault statement but the use's: nothing asked about the person, nothing kept");
  // Cold: a handle the vault's isolate has not seen, its names read by the use's own statement, then used by their ids.
  const fresh = (await setupRuntime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'cold', expiresInMinutes: 600, paths: ['market/dev'] })).token;
  const cold = await statements(NAMED, fresh, { warm: false });
  // But a credential's first use in five minutes, which notes when it was last used (`verify`'s touch): not a request's cost.
  assert.deepEqual(shown(cold.app), ['update "credentials" set "last_u'], 'cold: no read of the app, the touch of a new credential alone');
  assert.deepEqual(shown(cold.hot), [use, use]);
  // The stable URL: the use of its one key at the environment the handle was made for, which the vault finds itself, in
  // its one call: one statement, and nothing of `access`.
  const stable = await statements(STABLE);
  assert.deepEqual(shown(stable.app), [], 'the stable URL: no statement of the app');
  assert.deepEqual(shown(stable.hot), [use]);
  assert.deepEqual(stable.vault, [], 'no `access`: the standing is the vault\'s, decided on the sealed rows');
});

test("a handle's /use reads as many rows and pages however the log and the instance grow", POSTGRES, async () => {
  const measure = async () => {
    const out: { url: string; text: string; rows: number; pages: number }[] = [];
    for (const url of [NAMED, STABLE]) {
      const ran = await statements(url);
      for (const statement of ran.app) out.push({ url, text: statement.text.replace(/\s+/g, ' ').slice(0, 60), rows: statement.rows, pages: await app.pages(statement) });
      // The vault's: the same, answering as many rows; their pages are held flat by the vault's own (use-cost.test.ts, `named`).
      for (const statement of ran.hot) out.push({ url, text: statement.text.replace(/\s+/g, ' ').slice(0, 60), rows: statement.rows, pages: 0 });
    }
    return out;
  };
  const before = await measure();
  // The log, a hundred times as long: copies of every entry it holds, older than any, and the policy changed a few
  // times more; eight thousand keys, forty of them market/dev's; fifty members.
  const root = clientFor(deps, ROOT);
  await db.owner.transaction(async (tx) => {
    await tx.execute(sql`ALTER TABLE audit_log DISABLE TRIGGER USER`);
    await tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, project_id, environment_id, secret_id,
        secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - row_number() OVER (ORDER BY g, e.seq), author, key_id, occurred_at - g, actor, action, decision, code,
        subject_principal, project_id, environment_id, secret_id, secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash
      FROM audit_log e CROSS JOIN generate_series(1, 100) g WHERE e.seq >= 0`);
    await tx.execute(sql`ALTER TABLE audit_log ENABLE TRIGGER USER`);
  });
  for (const path of ['market/staging', 'market/prod']) await root.environments.create(path);
  await root.environments.protect('market/prod');
  await root.environments.protect('market/prod', false);
  // Keys spread as an instance spreads them (review r4): twenty projects of ten environments of forty keys, and forty
  // more of market/dev's among them, a page or so apart, as keys added over time land. The planner then reckons an
  // environment's keys a row or two, and a read by environment alone, not by key, reads each of its pages.
  await db.owner.execute(sql`
    WITH p AS (INSERT INTO projects (slug, name) SELECT 'grown-' || g, 'Grown ' || g FROM generate_series(1, 20) g RETURNING id),
    e AS (INSERT INTO environments (project_id, slug, name) SELECT p.id, 'env-' || g, 'env-' || g FROM p CROSS JOIN generate_series(1, 10) g RETURNING id, project_id),
    grown AS (SELECT e.project_id, e.id AS environment_id, 'KEY_' || g AS key, row_number() OVER () AS ord FROM e CROSS JOIN generate_series(1, 40) g),
    spread AS (
      SELECT d.project_id, d.id AS environment_id, 'SPREAD_' || g AS key, g * 200 AS ord
        FROM environments d JOIN projects m ON m.id = d.project_id AND m.slug = 'market' CROSS JOIN generate_series(1, 40) g
       WHERE d.slug = 'dev'
    )
    INSERT INTO secrets (project_id, environment_id, key)
    SELECT project_id, environment_id, key FROM (SELECT * FROM grown UNION ALL SELECT * FROM spread) x ORDER BY ord`);
  for (let i = 0; i < 50; i++) await root.members.add(`user:person-${i}@acme.example`);
  await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0)`);
  const grown = await measure();
  assert.deepEqual(grown.map(({ url, text }) => `${url} ${text}`), before.map(({ url, text }) => `${url} ${text}`), 'the same statements');
  for (const [i, { url, text, rows, pages }] of before.entries()) {
    assert.equal(grown[i]!.rows, rows, `${url}: ${text} answered as many rows`);
    assert.ok(grown[i]!.pages <= 2 * pages + 16, `${url}: ${text} read ${grown[i]!.pages} pages once the instance grew, ${pages} before`);
  }
});

/** A reveal's statements through the API, by pool, as `statements` takes a use's. */
async function revealed(token: string, body: { path: string; keys?: readonly string[] }): Promise<{ app: Statement[]; vault: Statement[]; hot: Statement[] }> {
  const reveal = async () => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/reveals`, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body),
    }), runtime, { sourceIp: null });
    assert.equal(response.status, 200, await response.clone().text());
    await response.arrayBuffer();
  };
  await reveal();
  for (const pool of [app, vaultPool, hot]) pool.recording = [];
  await reveal();
  const ran = { app: app.recording!, vault: vaultPool.recording!, hot: hot.recording! };
  for (const pool of [app, vaultPool, hot]) pool.recording = null;
  return ran;
}

test("a reveal of one key is the vault's one call, as a /use is; a reveal of several, as before, runs no check of the credential after its uses (T145)", POSTGRES, async () => {
  const credential = 'select "credentials"."id", "cred';
  const read = 'SELECT app_read( $1::bytea, $2::';
  const use = 'SELECT use_credential( $1::uuid,';
  const cases = [
    // One key, by its path or as a list of one: the vault's use by name, warm, which answers the rows the app checks.
    ['a reveal of one key', personal, { path: 'market/dev/API_KEY' }, [], [use]],
    ['a reveal of its one named key', personal, { path: 'market/dev', keys: ['API_KEY'] }, [], [use]],
    ['a reveal of one key, as a service', service, { path: 'market/dev/API_KEY' }, [], [use]],
    // Several: the app reads, then one use a value, until PR B2.
    ['a reveal of an environment', personal, { path: 'market/dev' }, [credential, read, 'select "secret_references"."id",', 'select "secrets"."id", "secrets"'], [use, use]],
    ['a reveal of its named keys', personal, { path: 'market/dev', keys: ['API_KEY', 'OTHER'] }, [credential, read], [use, use]],
    ['an export, as a service', service, { path: 'market/dev' }, [credential, read, 'select "secret_references"."id",', 'select "secrets"."id", "secrets"'], [use, use]],
  ] as const;
  // Sorted: an environment's references and keys are read at once, and recorded as each finishes.
  const sorted = (texts: readonly string[]) => [...texts].sort();
  for (const [name, token, body, app, hot] of cases) {
    const ran = await revealed(token, body);
    assert.deepEqual(sorted(shown(ran.app)), sorted(app), name);
    assert.deepEqual(shown(ran.hot), hot, `${name}: one use a value`);
    assert.deepEqual(ran.vault, [], `${name}: no vault call but the uses`);
  }
});

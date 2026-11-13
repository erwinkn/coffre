// What the credential proxy's `/use` costs, a person's handle at a proxy that keeps nothing
// (`proxy: { cacheValues: false }`), the hot path at its worst, and a reveal through the API: each within its class's
// budget (budgets.ts), and each statement reading as many rows, and as many pages, however long the log grows and
// however many keys, environments and members the instance holds.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { defineDeployment } from '@coffre/core/deployment';
import { github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { localVault, spoken, type SpokenVault } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { checkPlugins } from '../src/plugins.ts';
import { proxyCodeWith } from '../src/proxy-code.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import type { ProxyDefinition } from '@coffre/core/vault';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, nothingHeld, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';
import { checkpointFence } from '@coffre/db/schema';
import { answer, type Pages } from './start-fixture.ts';
import { inBulkPeriod } from './window-fixture.ts';
import { assertOver, assertWithin, BUDGET, OVER } from './budgets.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const API_KEY = 'sk_live_0123456789abcdef';

/** What a request and its warm-up need of one bulk-cap period, far more than they take. */
const PERIOD_ROOM_MS = 5000;
/** Whoever uses market/dev's keys here, by handle or token: a person, and a service. */
const PRINCIPALS = [`user:${DEV}`, 'token:ci'];

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
let vault: SpokenVault;
let runtime: CoffreRuntime;
let upstream: Server;
let handle: string;
/** The runtime that made the handles, to make another. */
let setupRuntime: CoffreRuntime;
/** Tokens of a person and of a service, for reveals through the API (`POST /api/reveals`). */
let personal: string;
let service: string;

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  // Uses go in at or past the floor of `at` (schema 0022), as a deployment's checkpointer keeps it.
  await db.owner.update(checkpointFence).set({ atFloor: Date.now() - 60_000 });
  const kek = randomBytes(32);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { sealThrough: sealedNow, heldOutside: nothingHeld }) });
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
  vault = spoken(await localVault(
    { database: createDatabase(vaultPool.client), hotDatabase: createDatabase(hot.client), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] },
    { sealThrough: sealedNow, heldOutside: nothingHeld },
  ));
  const config = resolveConfig({
    publicUrl: ORIGIN, vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64'),
    plugins: [credentialProxy({ credentials: { api: { upstream: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1`, inject: header('x-api-key', '{API_KEY}') } }, insecureUpstreams: true })],
    deployment: { proxy: { cacheValues: false } },
  });
  runtime = createRuntime(config, createDatabase(app.client), vault, transport);
  runtime.plugins = checkPlugins(config.plugins);
});

after(async () => {
  await vault.close();
  await Promise.all([app.pool.end(), vaultPool.pool.end(), hot.pool.end()]);
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await resetDatabase(db.owner);
  await db.close();
});

/** A request's statements, by pool, the request run once before, so that what a process does once is done. */
async function statements(url: string, token = handle, { warm = true, at = runtime } = {}): Promise<{ app: Statement[]; vault: Statement[]; hot: Statement[] }> {
  const use = async () => {
    const response = await answer(new Request(url, { headers: { 'x-api-key': token } }), at, {} as Pages, '203.0.113.7');
    assert.equal(response.status, 200, await response.clone().text());
    await response.arrayBuffer();
  };
  // The warm-up and the measured request share one refresh period of the bulk cap: a use in the next one writes its key's row again.
  await inBulkPeriod(PERIOD_ROOM_MS, db.owner, PRINCIPALS, 'market/dev');
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

/** What a request's statements spent, as a budget measures it. */
const spent = (ran: { app: Statement[]; vault: Statement[]; hot: Statement[] }) => ({ statements: ran.app.length + ran.vault.length + ran.hot.length });
/** `credentialStill`'s read, after the vault released: what a reveal does not need. */
const STILL = 'select "principals"."status",';
const trace = (ran: { app: Statement[]; vault: Statement[]; hot: Statement[] }) => `\n${JSON.stringify({ app: shown(ran.app), vault: shown(ran.vault), hot: shown(ran.hot) })}`;

test("a handle's /use, at its environment's URL or the stable one, runs within a use's budget, and over it only when cold", async () => {
  for (const url of [NAMED, STABLE]) {
    const ran = await statements(url);
    assertWithin(url, spent(ran), BUDGET.use, trace(ran));
  }
  // Cold: a handle the vault's isolate has not seen, its names read by the use's own statement, then used by their ids;
  // and its first use in five minutes notes when it was last used (`verify`'s touch).
  const fresh = (await setupRuntime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'cold', expiresInMinutes: 600, paths: ['market/dev'] })).token;
  assertOver('a cold /use', spent(await statements(NAMED, fresh, { warm: false })), OVER.coldHandleUse);
});

test("a handle's /use reads as many rows and pages however the log and the instance grow", async () => {
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
  // Keys spread as an instance spreads them: twenty projects of ten environments of forty keys, and forty
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

test("a handle's /use of a UI route is the vault's one call too, at either URL and of two segments, the app running nothing; it answers as many rows whether its environment holds one definition or 256 (T186 PR C, R44, R48)", async () => {
  const root = clientFor(deps, ROOT);
  const upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1`;
  const route = (name: string): ProxyDefinition => ({
    kind: 'route', name, upstream: upstreamUrl, inject: [{ kind: 'header', name: 'x-api-key', template: '{API_KEY}' }],
    allow: null, limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  });
  // The same deployment with the Proxy tab on: `api` is code's, `ui` the environment's.
  const plugins = checkPlugins([credentialProxy({ credentials: { api: { upstream: upstreamUrl, inject: header('x-api-key', '{API_KEY}') } }, insecureUpstreams: true })]);
  const ui = { ...runtime, plugins, deployment: defineDeployment({ proxy: { cacheValues: false, editable: true } }) } satisfies CoffreRuntime;
  deps.proxy = proxyCodeWith(plugins, ui.deployment);
  const save = async (items: Record<string, ProxyDefinition>) => root.proxy.save('market/dev', { seal: (await root.proxy.get('market/dev')).seal, items });
  await save({ ui: route('ui') });
  const measure = async () => {
    const out: Record<string, { app: string[]; vault: string[]; hot: string[]; rows: number[] }> = {};
    for (const url of [`${ORIGIN}/use/market/dev/ui/charges`, `${ORIGIN}/use/ui/v1/charges`, `${ORIGIN}/use/ui/charges`]) {
      const ran = await statements(url, handle, { at: ui });
      out[url] = { app: shown(ran.app), vault: shown(ran.vault), hot: shown(ran.hot), rows: ran.hot.map((statement) => statement.rows) };
    }
    return out;
  };
  const one = await measure();
  // The place's URL and a stable one, whatever its segments (docs/design/proxy-ui.md, section 6, "URLs of one or two segments").
  for (const [url, ran] of Object.entries(one)) assertWithin(url, { statements: ran.app.length + ran.vault.length + ran.hot.length }, BUDGET.use, `\n${JSON.stringify(ran)}`);
  // 255 more definitions in the environment, each its own route: the use reads its own item, as many rows.
  // In parts, as a body holds 1,600 values at most (`MAX_BODY_NODES`), and the Proxy tab saves only what changed.
  for (let from = 0; from < 255; from += 64) {
    await save(Object.fromEntries(Array.from({ length: Math.min(64, 255 - from) }, (_, i) => [`route-${from + i}`, route(`route-${from + i}`)] as const)));
  }
  assert.deepEqual(await measure(), one);
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
  await inBulkPeriod(PERIOD_ROOM_MS, db.owner, PRINCIPALS, 'market/dev');
  await reveal();
  for (const pool of [app, vaultPool, hot]) pool.recording = [];
  await reveal();
  const ran = { app: app.recording!, vault: vaultPool.recording!, hot: hot.recording! };
  for (const pool of [app, vaultPool, hot]) pool.recording = null;
  return ran;
}

test("a reveal through the API, of one key, several or an environment, by a person or a service, runs within a use's budget for one key, a read's for more", async () => {
  const cases = [
    ['a reveal of one key', personal, { path: 'market/dev/API_KEY' }, BUDGET.use],
    ['a reveal of its one named key', personal, { path: 'market/dev', keys: ['API_KEY'] }, BUDGET.use],
    ['a reveal of one key, as a service', service, { path: 'market/dev/API_KEY' }, BUDGET.use],
    ['a reveal of an environment', personal, { path: 'market/dev' }, BUDGET.read],
    ['a reveal of its named keys', personal, { path: 'market/dev', keys: ['API_KEY', 'OTHER'] }, BUDGET.read],
    ['an export, as a service', service, { path: 'market/dev' }, BUDGET.read],
    ['an export of named keys, as a service, mapped', service, { path: 'market/dev', keys: ['API_KEY', 'OTHER'] }, BUDGET.read],
  ] as const;
  for (const [name, token, body, budget] of cases) {
    const ran = await revealed(token, body);
    assertWithin(name, spent(ran), budget, trace(ran));
    assert.ok(!ran.app.some(({ text }) => text.startsWith(STILL)), `${name}: no check of the credential after the use${trace(ran)}`);
  }
});

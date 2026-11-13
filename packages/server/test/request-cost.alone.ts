// What a request costs, and that it does not grow with the instance. On Workers' Free plan, an invocation has 10 ms of
// CPU; each statement is a round trip through Hyperdrive, and each connection, the app's or one vault call's, costs a
// TLS socket and a SCRAM login. So each request stays within its class's budget (budgets.ts), and runs the same
// statements, reading the same rows, on a log of a few entries as on one of thousands, among a handful of members or
// hundreds, after one change to the policy or many.
// `pnpm bench:workers` measures the CPU itself (packages/conformance/scripts/bench.ts).
import { defineDeployment } from '@coffre/core/deployment';
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { createHmac, generateKeyPairSync, randomBytes, randomUUID, sign as signWith } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { createClient, type CoffreClient } from '@coffre/client';
import { bodyDigest, createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { github, hashToken, signin, type Gate } from '@coffre/core/identity';
import { createDatabase, type Client } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { appendEntries, type NewEntry } from '@coffre/db/log';
import { ACCESS_ACTIONS, useOfCode } from '@coffre/core/vault';
import { localVault, spoken } from '@coffre/vault/node';
import { desc, eq, gt, sql, type SQL } from 'drizzle-orm';

import { Accesses } from '../src/accesses.ts';
import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import {
  distinctSecretCounts, environmentSecrets, liveKeysIn, lock, originsOf, places, resolvePath, secretFolderOf, secretHeads, secretsInFolder,
  secretObjects, holdingSensitive,
} from '../src/db/queries.ts';
import { eventsPage, memberKeys } from '../src/db/events.ts';
import { fetchApi, pageClient } from '../src/fetch-api.ts';
import { sessionCookieName } from '../src/auth.ts';
import { auditReadiness, writeAuditHeartbeat } from './watch-fixture.ts';
import { appLogKey, CHAIN_WALK } from '../src/db/audit.ts';
import { bindingRoute, checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header, hmac } from '../src/plugins/credential-proxy.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, nothingHeld, openTestDatabase, resetDatabase, sealedNow, testAnchor, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { answer, type Pages } from './start-fixture.ts';
import { assertOver, assertWithin, BUDGET, OVER, overBudget, type Budget } from './budgets.ts';
import { inBulkPeriod, inOnePeriod, pastBulkTurn } from './window-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';
import { withLogUnlocked } from './db/engine.ts';
import { auditLog, credentials as credentialRows, secrets } from '@coffre/db/schema';
import { testPostgresPool, watched } from './db/postgres-pool.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci-web';
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
/** What a CI job reveals: seven keys of the environment it reads. */
const SEVEN = ['CLOUDFLARE_API_TOKEN', 'SCALEWAY_SECRET_KEY', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'SOURCE_REGISTRY_KEY', 'GITHUB_RELEASE_APP_CLIENT_ID', 'GITHUB_RELEASE_APP_PRIVATE_KEY'];
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

type Count = { statements: number; rows: number };

/**
 * A pool that counts the statements run on it, a transaction's included, and the rows they answered; and, apart,
 * those run on a client checked out, which holds its connection from the first to the last. Drizzle checks out a
 * client for a transaction from a class named `…Pool`.
 */
class CountingPool {
  readonly #pool: PostgresClient;
  /** The pool as the database runs on it, counting. */
  readonly client: Client;
  readonly count: Count = { statements: 0, rows: 0 };
  readonly held: Count = { statements: 0, rows: 0 };
  /** Each statement run while set, as it was sent: what `work` replays. */
  recorded: Statement[] | null = null;

  constructor(pool: PostgresClient) {
    this.#pool = pool;
    this.client = this.watch(pool);
  }

  /** `client`, its statements counted here: another connection of the same login, a page's own. */
  watch<C extends Client>(client: C): C {
    return watched(client, ({ text, values, rows, held }) => {
      this.recorded?.push({ text, values });
      for (const count of held ? [this.count, this.held] : [this.count]) {
        count.statements += 1;
        count.rows += rows;
      }
    });
  }

  end() {
    return this.#pool.end();
  }

  /**
   * The shared buffers `statement` touches, read or found in the cache, as
   * this login runs it again now, in a transaction rolled back: null for
   * a write of a row it made, which fails as a duplicate (23505); any other
   * failure fails the test. Run once before, and rolled back, so that a
   * connection that has not yet planned what a function it calls runs (the
   * audit pages' reads of 0.15's uses) reads no catalog for it.
   */
  async work(statement: Statement): Promise<{ pages: number; plan: string; tree: Plan } | null> {
    const rolledBack = new Error('rolled back');
    let work: { pages: number; plan: string; tree: Plan } | null = null;
    await this.#pool.begin(async (tx) => {
      try {
        await tx.unsafe('SAVEPOINT warm');
        await tx.unsafe(`EXPLAIN (ANALYZE, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        await tx.unsafe('ROLLBACK TO SAVEPOINT warm');
        const [row] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: Plan }] })['QUERY PLAN'];
        work = { pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], plan: shown(plan), tree: plan };
      } catch (error) {
        if ((error as { code?: string }).code !== '23505') throw error;
      }
      throw rolledBack;
    }).catch((error: unknown) => {
      if (error !== rolledBack) throw error;
    });
    return work;
  }
}

type Statement = { text: string; values: unknown[] };

type Plan = { 'Node Type': string; 'Relation Name'?: string; 'Index Name'?: string; 'Shared Hit Blocks': number; 'Shared Read Blocks': number; Plans?: Plan[] };

/** A plan's nodes, each with what it reads and the pages it read, one a line: what a failure shows. */
function shown(plan: Plan, depth = 0): string {
  const node = `${'  '.repeat(depth)}${plan['Node Type']}${plan['Index Name'] ? ` using ${plan['Index Name']}` : ''}${plan['Relation Name'] ? ` on ${plan['Relation Name']}` : ''}: ${plan['Shared Hit Blocks'] + plan['Shared Read Blocks']} pages`;
  return [node, ...(plan.Plans ?? []).map((child) => shown(child, depth + 1))].join('\n');
}

/**
 * A page's statements held to the budget `small` measured, call after call on one connection: every SELECT
 * `run` sends, twelve times over on a connection of the app's login opened for it, `makeDay` making a day of reads
 * before the ninth. The first call reads the catalog the connection plans with, as `work` leaves aside; each after it
 * reads what a request does. A statement of PL/pgSQL is planned for each call's values five times, then Postgres
 * weighs a plan for any values, which spans every day's partition; and a day made has a plan it keeps made again.
 * `log_reads_by` and `log_reads_at` asked for one (migration 0054): 23,000 to 30,000 pages at a hundred days, on the
 * sixth call, where a call reads 19 to 35.
 */
async function callAfterCall(name: string, run: () => Promise<unknown>, small: readonly { text: string; pages: number | null }[], makeDay: () => Promise<unknown>) {
  app.recorded = [];
  await run();
  const statements = [...app.recorded].filter((statement) => /^\s*(select|with)\b/i.test(statement.text)).sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
  app.recorded = null;
  assert.deepEqual(statements.map(({ text }) => text.replace(/\s+/g, ' ').slice(0, 80)), small.map(({ text }) => text), `${name} ran other statements`);
  const one = postgresClient(TEST_RUNTIME_DATABASE_URL, { max: 1, connect_timeout: 5, connection: { statement_timeout: 10_000 } });
  try {
    for (let call = 1; call <= 12; call += 1) {
      if (call === 9) await makeDay();
      for (const [i, statement] of statements.entries()) {
        const [row] = await one.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: Plan }] })['QUERY PLAN'];
        const [pages, before] = [plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], small[i]!.pages!];
        if (call > 1) assert.ok(pages <= 2 * before + 16, `${name}, call ${call} on one connection: ${small[i]!.text} read ${pages} pages, ${before} measured:\n${shown(plan)}`);
      }
    }
  } finally {
    await one.end();
  }
}

/** What a request ran: statements and rows on the app's connection and on the vault's, and how many calls the vault answered, each a connection of its own on Workers. */
type Cost = { app: Count; vault: Count; vaultCalls: number };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let app: CountingPool;
let vaultPool: CountingPool;
/** The vault's uses' own login (`hotDatabase`): its statements count as the vault's. */
let hotPool: PostgresClient;
let vaultCalls = 0;
let root: CoffreClient;
let reader: CoffreClient;
let service: CoffreClient;
/** A CI run's sign-in, `POST /api/auth/oidc`, with a fresh ID token of its platform's each time. */
let exchange: () => Promise<void>;
/** The credential a CI run's sign-in bought, as its next requests hold it, and when it ends. */
let ci: CoffreClient;
let ciEnds = 0;
/** A CI run's credential, bought again: it lives five minutes, and a long run outlasts it. */
let buyCi: () => Promise<void>;
/** A workload's request, as its SDK sends it to the credential proxy: a fresh proof each time. */
let workload: () => Promise<void>;
/** A workload's check of an inbound webhook's signature, `verify`, at the proxy; and at one that remembers nothing. */
let verify: () => Promise<void>;
let coldVerify: () => Promise<void>;
/** The same, at a proxy that remembers nothing: what each request costs once its cache has lapsed, on a warm isolate. */
let coldWorkload: () => Promise<void>;
/** The proxy that keeps what it is asked, made new: its entries are as old as the request that fills them. */
let renewProxy: () => void;
/** The same through a Cloudflare service binding, its caller the binding's `props`. */
let bound: () => Promise<void>;
/** The scheduled beat, and `/readyz`'s check, on the counted connections. */
let beat: () => Promise<boolean>;
/** The beat, warnings and all: one that finds the log broken. */
let beatAnyway: () => Promise<boolean>;
/** The vault's checkpoint, asked outside a beat. */
let signLog: () => Promise<{ ok: boolean }>;
let ready: () => Promise<{ ok: boolean }>;
/** `count` entries of the app's appended at once, as many requests would write them: reads, or the `i`-th as `entry` makes it. */
let append: (count: number, entry?: (i: number) => NewEntry) => Promise<void>;
/** A page's server render, as Owner or viewer, on a connection of its own, as on Workers; and the round trips its connections took. */
let environmentPage: (as: Persona) => Promise<void>;
let projectPage: (as: Persona) => Promise<void>;
/** The environment page's own calls, as its render asks them, each answered or refused. */
let environmentCalls: (as: Persona) => Promise<PromiseSettledResult<unknown>[]>;
/** Every other page's render, by its path, as its route's loaders read (`visits`). */
let visit: (as: Persona | null, path: string, options?: VisitOptions) => Promise<void>;
let pageTrips = 0;
/** One more browser session of a persona, as signing in again in another browser makes one. */
let signInAgain: (as: Persona) => Promise<void>;
/** The proxy in front of the app's Postgres that pages' connections go through, counting their Syncs. */
let relay: Awaited<ReturnType<typeof postgresProxy>>;

type Persona = 'owner' | 'viewer';

/** A client that calls the API as a CLI or a CI run does, its token checked on each request. */
function bearer(runtime: CoffreRuntime, token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
}

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  app = new CountingPool(testPostgresPool(TEST_RUNTIME_DATABASE_URL));
  vaultPool = new CountingPool(testPostgresPool(TEST_VAULT_DATABASE_URL));
  const opened = spoken(await localVault({
    database: createDatabase(vaultPool.client),
    hotDatabase: createDatabase(vaultPool.watch(hotPool = testPostgresPool(TEST_HOT_DATABASE_URL))),
    kek: { id: 'test-kek-1', key: randomBytes(32).toString('base64') },
    owners: [ROOT],
    // Every use logged, none a repeat its key's last rides (60 s by default): what a budget holds is a use's whole
    // cost, the same whenever it runs, however long the file has run.
    deployment: defineDeployment({ audit: { repeatsWithinSeconds: 0 } }),
  }, { sealThrough: sealedNow, heldOutside: nothingHeld }));
  // Every call the app makes of the vault: on Workers, each its own invocation and connection.
  const vault = new Proxy(opened as unknown as FixtureDeps['vault'], {
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
  const base: FixtureDeps = { db: createDatabase(app.client), vault, chainKey: randomBytes(32), anchor: testAnchor() };
  beat = () => writeAuditHeartbeat(base.db, base.chainKey, vault, base.anchor, { warn: () => assert.fail('the beat warned') });
  signLog = () => vault.checkpoint();
  beatAnyway = () => writeAuditHeartbeat(base.db, base.chainKey, vault, base.anchor, { warn: () => undefined });
  ready = () => auditReadiness(base.db, vault, base.chainKey, base.anchor);
  append = async (count, entry = () => ({ actor: 'system:load', action: 'secret.read', decision: 'allow', metadata: '{}' })) => {
    for (let done = 0; done < count; done += 1000) {
      const entries = Array.from({ length: Math.min(1000, count - done) }, (_, i) => entry(done + i));
      // Writes of 0.14's among them (a sign-in, a token made), as an upgraded instance's log holds them below its cutover.
      await db.owner.transaction((tx) => appendEntries(tx, appLogKey(base.chainKey), entries));
    }
  };
  // The vault's answers kept between requests, as a configuration keeps them (`Accesses`).
  const accesses = new Accesses();
  const signinService = new SigninService({ ...base, signin: auth.signin, accesses });
  const deps: FixtureDeps = { ...base, signin: signinService, settleAudit: false };
  const runtime: CoffreRuntime = {
    db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], signin: signinService, workloads: null, mcp: null, auth, publicUrl: ORIGIN,
    verifier: signinService, waitUntil, schema: { migrated: true }, appKey: { settled: true }, accesses, rotateAfterDays: 365, deployment: defineDeployment(), plugins: [],
  };
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod', 'market/busy']) await root.environments.create(path, { name: path });
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake', WEBHOOK_SECRET: 'fake-webhook-secret' });
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

  // A page's render, as Workers runs it: the app's database one Hyperdrive connection, which each statement and
  // transaction takes its turn on, through a proxy that counts the Syncs, a round trip each on Hyperdrive. Its calls go
  // in process (`pageClient`), as the visitor, signed in in a browser. A reference into market/dev, as most
  // environments have, so that its page lists one.
  await root.secrets.set('market/busy', { DEV_API_KEY: { ref: 'market/dev/API_KEY' } });
  // And a project with a fork, as most instances hold one, a personal config included: what the project list resolves.
  await root.projects.create('shop', { name: 'Shop' });
  await root.environments.create('shop/dev', { name: 'dev' });
  await root.secrets.set('shop/dev', { SHOP_KEY: 'fake-shop-key' });
  await root.environments.create('shop/dev-eu', { name: 'dev-eu', from: 'dev', inherit: true });
  relay = await postgresProxy(TEST_RUNTIME_DATABASE_URL);
  const sessions = new Map<Persona, string>();
  for (const [persona, email] of [['owner', ROOT], ['viewer', READER]] as const) {
    const signed = await signinService.completeSignin({ provider: 'github', subject: persona, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
    if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
    sessions.set(persona, signed.credential.token);
  }
  signInAgain = async (as) => {
    const signed = await signinService.completeSignin({ provider: 'github', subject: as, emails: [as === 'owner' ? ROOT : READER], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Chrome on Linux' });
    if (!('credential' in signed)) throw new Error(`${as} was not signed in again`);
  };
  const scopes = { sealed: true };
  const render = async <T>(as: Persona, path: string, calls: (client: CoffreClient) => Promise<T>): Promise<T> => {
    const pool = new HyperdrivePool(relay.url, { groupReads: true });
    const db = createDatabase(app.watch(pool));
    // As a configuration keeps them between requests: the vault's answers, and that older releases' scopes are sealed.
    const signin = new SigninService({ ...base, db, signin: auth.signin, accesses, scopes });
    const page = new Request(`${ORIGIN}${path}`, { headers: { cookie: `${sessionCookieName(auth)}=${sessions.get(as)!}`, 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none' } });
    const syncs = relay.syncs;
    try {
      return await calls(pageClient(page, { ...runtime, db, signin, verifier: signin }, null));
    } finally {
      await pool.end();
      pageTrips += relay.syncs - syncs;
    }
  };
  // The loaders' reads, as coffre's routes make them (@coffre/ui, options.ts and lib/queries.ts), which TanStack runs
  // side by side: the shell's (`loadShell`), and the environment's, which asks all three at once once the project list,
  // the shell's own, says its visitor reads it (`loadEnvironment`).
  environmentCalls = (as) => render(as, '/projects/market/dev', async (client) => {
    const projects = client.projects.list();
    const [, , , calls] = await Promise.all([client.auth(), client.me(), projects, projects.then(() => Promise.allSettled([
      client.secrets.list('market/dev'), client.references.list('market/dev'), client.environments.missing('market/dev'),
    ]))]);
    return calls;
  });
  environmentPage = async (as) => {
    for (const outcome of await environmentCalls(as)) if (outcome.status === 'rejected') throw outcome.reason;
  };
  // The shell's, and the project's tabs': once the project list says its visitor manages its access, its grants.
  projectPage = (as) => render(as, '/projects/market', async (client) => {
    const projects = client.projects.list();
    await Promise.all([client.auth(), client.me(), projects, projects.then(async ({ projects: listed }) => {
      if (listed.find((project) => project.slug === 'market')?.permissions.includes('grant.manage')) await client.members.list('market');
    })]);
  });

  visit = async (as, path, options = { reports: true }) => {
    const loaders = visits[path];
    if (loaders === undefined) throw new Error(`no page at ${path}`);
    if (as !== null) return render(as, path, (client) => loaders(client, options));
    // Signed out: no credential, a connection all the same.
    const pool = new HyperdrivePool(relay.url, { groupReads: true });
    const db = createDatabase(app.watch(pool));
    const syncs = relay.syncs;
    try {
      await loaders(pageClient(new Request(`${ORIGIN}${path}`, { headers: { 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none' } }), { ...runtime, db }, null), options);
    } finally {
      await pool.end();
      pageTrips += relay.syncs - syncs;
    }
  };

  // A CI run's ID token, from an issuer of the test's own, for the binding of its workflow.
  await root.secrets.set('market/dev', Object.fromEntries(SEVEN.map((key) => [key, `fake-${key.toLowerCase()}`])));
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' };
  const published = new Map<string, unknown>([[`${ISSUER}/.well-known/openid-configuration`, { issuer: ISSUER, jwks_uri: KEYS }], [KEYS, { keys: [jwk] }]]);
  const transport: WorkloadTransport = {
    json: async (url) => {
      if (!published.has(url.href)) throw new FetchRefused(url, 'answered 404');
      return published.get(url.href);
    },
  };
  const claims = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/market/.github/workflows/build.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const idToken = (aud = ORIGIN, of = claims) => {
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud, sub: 'repo:acme/market:ref:refs/heads/main', iat: now - 5, exp: now + 295, jti: randomUUID(), run_id: '7001', ...of })}`;
    return `${input}.${signWith('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const workloadsAuth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 1000 }) } }).resolve(ORIGIN);
  if (workloadsAuth.mode !== 'signin' || workloadsAuth.signin.workloads === null) throw new Error('unreachable');
  const workloads = new WorkloadService({ db: deps.db, chainKey: deps.chainKey, vault, config: workloadsAuth.signin.workloads, transport, signin: signinService, publicUrl: ORIGIN });
  const made = await workloads.bind(await contextFor(deps, ROOT), 'ci-web', { profile: 'github', issuer: null, claims, label: 'build', replaces: [] }, { dryRun: false });
  if (!('binding' in made)) throw new Error('the binding was not made');
  const trusting = { ...runtime, auth: workloadsAuth, workloads } satisfies CoffreRuntime;
  const signIn = async () => {
    const request = new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: SERVICE, token: idToken() }) });
    const answered = await answer(request, trusting, {} as Pages, '203.0.113.9');
    if (answered.status !== 200) throw new Error(`the exchange was refused: ${await answered.text()}`);
    const issued = (await answered.json()) as { token: string; expiresAt: string };
    // Issued an hour ago, as far as the binding's rate counts, which a long run's sign-ins would pass: the MAC does not cover when.
    await db.owner.update(credentialRows).set({ createdAt: new Date(Date.now() - 3_600_000) }).where(eq(credentialRows.tokenHash, hashToken(issued.token)));
    return issued;
  };
  exchange = async () => void (await signIn());
  buyCi = async () => {
    const issued = await signIn();
    ci = bearer(runtime, issued.token);
    ciEnds = Date.parse(issued.expiresAt);
  };
  await buyCi();

  const gate: Gate = { nonce: async () => 'g1.cost', admit: async () => ({ ok: true, nonce: 'g1.cost' }) };
  // A workload's key-bound session of the service, from `/api/auth/workload` as a CI run's SDK asks for one: its ID
  // token's audience names the proof key, and the vault signs it in. Then a plugin that asks for it as the proxy does.
  // Its binding has a policy, as a binding whose runs hold sessions does, and trusts another workflow than the CI run's,
  // whose sign-in it would otherwise add a candidate to.
  const deploy = { ...claims, workflow_ref: 'acme/market/.github/workflows/deploy.yml@refs/heads/main' };
  const deploying = await workloads.bind(await contextFor(deps, ROOT), 'ci-web', { profile: 'github', issuer: null, claims: deploy, label: 'deploy', replaces: [], policy: {} }, { dryRun: false });
  if (!('binding' in deploying)) throw new Error('the session binding was not made');
  const key = await generateProofKey();
  const token = await (async () => {
    const url = `${ORIGIN}/api/auth/workload`;
    const jwt = idToken(`${ORIGIN}#jkt=${await thumbprint(key.jwk)}`, deploy);
    const request = new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', dpop: await createProof(key, { method: 'POST', url }) }, body: JSON.stringify({ service: SERVICE, proof: { oidc: jwt } }) });
    const answered = await answer(request, { ...trusting, gates: () => gate }, {} as Pages, '203.0.113.9');
    if (answered.status !== 200) throw new Error(`the workload's sign-in was refused: ${await answered.text()}`);
    return ((await answered.json()) as { token: string }).token;
  })();
  // Its last use, written once in five minutes after the answer: waited for, so it lands on its own request's count.
  const background: Promise<unknown>[] = [];
  // The credential proxy itself, its upstream an egress that answers at once: the request costs only what coffre does.
  const credentials = { stripe: { upstream: 'https://api.stripe.example', inject: header('authorization', 'Bearer {API_KEY}'), egress: { fetch: async () => new Response(null, { status: 204 }) } } };
  const verifiers = { webhook: hmac('WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) };
  // The proxy's cache keeps an answer 60 s and asks the vault again in the last 15: that one request costs 2 statements
  // and 1 of the vault's, as a cold one does, not 1 and none. A Cloudflare call's answer is kept 60 s whatever `proxy.cacheValues` says (a binding has no
  // session to outlast it), so a request warmed at second 44 of an entry's life and measured at 45, as a loaded runner
  // does after a long test, was that request. Each `warm` renews the proxy: its entries are then as old as the gap
  // between the warm-up and the measurement.
  const proxy = () => ({
    ...runtime,
    waitUntil: (promise: Promise<unknown>) => void background.push(promise),
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 10 }) } }).resolve(ORIGIN),
    gates: () => gate,
    plugins: checkPlugins([credentialProxy({ credentials, verifiers })]),
  }) satisfies CoffreRuntime;
  let proxied = proxy();
  renewProxy = () => void (proxied = proxy());
  const forgetful = {
    ...proxied,
    deployment: defineDeployment({ proxy: { cacheValues: false } }),
    plugins: checkPlugins([credentialProxy({ credentials, verifiers })]),
  } satisfies CoffreRuntime;
  const through = (at: CoffreRuntime) => async () => {
    const url = `${ORIGIN}/use/stripe/v1/charges`;
    const body = 'amount=2000';
    const headers = { 'content-type': 'application/x-www-form-urlencoded' };
    const proof = await createProof(key, { method: 'POST', url, token, nonce: 'g1.cost', content: { headers, body: await bodyDigest(body) } });
    const answered = await pluginRoute(new Request(url, { method: 'POST', headers: { ...headers, authorization: `DPoP ${token}`, dpop: proof }, body }), at, null);
    if (answered?.status !== 204) throw new Error(`the proxy's workload was refused: ${await answered?.text()}`);
    await Promise.all(background.splice(0));
  };
  workload = () => through(proxied)();
  const verifying = (at: CoffreRuntime) => async () => {
    const url = `${ORIGIN}/use`;
    const message = Buffer.from('{"event_name":"signature_request.done"}');
    const body = JSON.stringify({ verify: { credential: 'webhook', message: message.toString('base64url'), signature: `sha256=${createHmac('sha256', 'fake-webhook-secret').update(message).digest('hex')}` } });
    const headers = { 'content-type': 'application/json' };
    const proof = await createProof(key, { method: 'POST', url, token, nonce: 'g1.cost', content: { headers, body: await bodyDigest(body) } });
    const answered = await pluginRoute(new Request(url, { method: 'POST', headers: { ...headers, authorization: `DPoP ${token}`, dpop: proof }, body }), at, null);
    if (answered?.status !== 200 || (await answered.json() as { valid?: boolean }).valid !== true) throw new Error('the verify was refused');
    await Promise.all(background.splice(0));
  };
  verify = () => verifying(proxied)();
  coldVerify = verifying(forgetful);
  coldWorkload = through(forgetful);
  // Its Cloudflare binding, which the vault makes as for any other.
  const edge = await workloads.bind(await contextFor(deps, ROOT), 'ci-web', { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [] }, { dryRun: false });
  if (!('binding' in edge)) throw new Error('the Cloudflare binding was not made');
  bound = async () => {
    const answered = await bindingRoute(new Request(`${ORIGIN}/use/market/dev/stripe/v1/charges`, { method: 'POST', body: 'amount=2000' }), proxied, SERVICE);
    if (answered?.status !== 204) throw new Error(`the binding's call was refused: ${await answered?.text()}`);
    await Promise.all(background.splice(0));
  };
});

after(async () => {
  await resetDatabase(db.owner);
  await Promise.all([app.end(), vaultPool.end(), hotPool.end(), db.close(), relay.close()]);
});

/**
 * Each request once, unmeasured: what the vault does once per process, or
 * once a caller's access or the policy changed, is done before a request
 * is counted. A CI run's credential near its end is bought again first.
 */
async function warm(): Promise<void> {
  if (ciEnds - Date.now() < 120_000) await buyCi();
  renewProxy();
  for (const { request } of [...Object.values(requests), ...Object.values(renders)]) await request();
}

async function cost(request: () => Promise<unknown>): Promise<Cost> {
  const before = { app: { ...app.count }, vault: { ...vaultPool.count }, vaultCalls };
  await request();
  const since = (now: Count, then: Count) => ({ statements: now.statements - then.statements, rows: now.rows - then.rows });
  return { app: since(app.count, before.app), vault: since(vaultPool.count, before.vault), vaultCalls: vaultCalls - before.vaultCalls };
}

/**
 * The bulk cap's periods: a tenth of its window, at most a minute (the vault's default window, 15 minutes, which this
 * deployment keeps), each principal's key starting its own at a phase of its own (`phaseOf`). A key's first use
 * in a new one moves its row of the cap's, one statement more (`useNamedMany`'s "3, a key entering her cap's set"),
 * whichever request comes first after that key's period turns. The requests' callers: the reader, and ci-web's token,
 * which its CI runs and its workloads use too. Every key they reveal is market/dev's.
 */
const CAPPED = [`user:${READER}`, SERVICE];
const PERIOD_ROOM_MS = 2_000;

/**
 * What `request` costs once its keys' rows of the cap's are their periods': run once, then measured, both within
 * every key's period (`inOnePeriod`: a pair a turn fell in is run again). What a hot request costs any other time; the
 * first after a key's period turned is a test of its own ("a reveal's first use of its keys in a new period").
 */
async function repeated(request: () => Promise<unknown>): Promise<Cost> {
  return inOnePeriod(() => inBulkPeriod(PERIOD_ROOM_MS, db.owner, CAPPED, 'market/dev'), db.owner, CAPPED, 'market/dev', async () => {
    await request();
    return cost(request);
  });
}

/** Each hot request and its class, measured warm, within one period of the bulk cap (`repeated`). */
const requests: Record<string, { request: () => Promise<unknown>; budget: Budget }> = {
  'a reveal of one key': { request: () => reader.secrets.reveal('market/dev/API_KEY'), budget: BUDGET.use },
  'a reveal of an environment': { request: () => reader.secrets.reveal('market/dev'), budget: BUDGET.read },
  'an export, as a service': { request: () => service.secrets.reveal('market/dev'), budget: BUDGET.read },
  "a request's check of its caller": { request: () => reader.me(), budget: BUDGET.caller },
  "a CI run's sign-in": { request: () => exchange(), budget: BUDGET.signIn },
  "a CI run's list": { request: () => ci.secrets.list('market/dev'), budget: BUDGET.read },
  "a CI run's reveal of seven keys": { request: () => ci.secrets.reveal('market/dev', SEVEN), budget: BUDGET.read },
  "a workload's request at the proxy": { request: () => workload(), budget: BUDGET.proxied },
  "a workload's verify at the proxy": { request: () => verify(), budget: BUDGET.proxied },
  "a Cloudflare call at the proxy": { request: () => bound(), budget: BUDGET.proxied },
};

/**
 * What each page's loaders read, as coffre's routes make them (@coffre/ui, options.ts and lib/queries.ts), which
 * TanStack runs side by side: the shell's (`loadShell`), which every page's own awaits for what it decides on.
 * A read that fails is the page's to show, as `uiResult` makes it; the cost is what was asked. As this instance's
 * deployment configures it: coffre's own sign-in, and no trusted workloads, whose bindings a service account's
 * pages would list too (`loadServiceDirectory`, `loadSignIn`). `reports: false` leaves out an Owner's report of a
 * member (`loadMember`), which reads what they ever read.
 */
type VisitOptions = { reports: boolean };
const settle = <T>(promise: Promise<T>) => promise.catch(() => undefined);
function shellOf(client: CoffreClient) {
  const [auth, me, projects] = [client.auth(), settle(client.me()), settle(client.projects.list())];
  const shell = Promise.all([auth, me, projects]).then(([, me, listed]) => ({
    me: me ?? null,
    projects: listed?.projects ?? [],
    administers: me?.instanceRole === 'admin' || me?.instanceRole === 'owner',
  }));
  return shell;
}
type Shell = Awaited<ReturnType<typeof shellOf>>;
const managesGrants = (shell: Shell) => shell.projects.some((project) => project.permissions.includes('grant.manage'));
const listsAccess = (shell: Shell) => shell.administers || shell.me?.setsUpServices === true || managesGrants(shell);
const page = (own: (client: CoffreClient, shell: Promise<Shell>, options: VisitOptions) => Promise<unknown>) => async (client: CoffreClient, options: VisitOptions) => {
  const shell = shellOf(client);
  await Promise.all([shell, own(client, shell, options)]);
};
/** A project's tab: once the list says its visitor may open it (`projectTab`). */
const tab = (permission: string, own: (client: CoffreClient) => Promise<unknown>) => page(async (client, shell) => {
  if ((await shell).projects.find((project) => project.slug === 'market')?.permissions.includes(permission as never)) await own(client);
});
const visits: Record<string, (client: CoffreClient, options: VisitOptions) => Promise<void>> = {
  '/projects': page(async () => {}),
  '/projects/market/users': tab('grant.manage', (client) => Promise.all([settle(client.members.list('market')), settle(client.references.list('market'))])),
  '/projects/market/service-accounts': tab('grant.manage', (client) => settle(client.members.list('market'))),
  '/projects/market/settings': tab('project.manage', async () => {}),
  '/users': page(async (client, shell) => {
    if ((await shell).administers) await settle(client.members.list());
  }),
  '/users/reader@acme.example': page(async (client, shell, { reports }) => {
    const known = await shell;
    await Promise.all([
      known.me?.runsInstance && reports ? settle(client.members.get(`user:${READER}`)) : null,
      listsAccess(known) ? settle(client.members.access(`user:${READER}`)) : null,
    ]);
  }),
  '/service-accounts': page(async (client, shell) => {
    const known = await shell;
    // The list says how each account signs in (`signsIn`): nothing asked of any one account.
    if (known.administers || known.me?.setsUpServices) await settle(client.members.list());
  }),
  '/service-accounts/ci-web': page(async (client, shell, { reports }) => {
    const known = await shell;
    const [, access] = await Promise.all([
      known.me?.runsInstance && reports ? settle(client.members.get(SERVICE)) : null,
      listsAccess(known) ? settle(client.members.access(SERVICE)) : null,
    ]);
    if (access?.managed && access.status === 'active') await settle(client.tokens.list(SERVICE));
  }),
  '/settings': page(async (client, shell) => {
    const known = await shell;
    await Promise.all([
      known.administers ? settle(client.members.list()) : null,
      known.me?.runsInstance ? settle(client.settings.get()) : null,
      known.me?.runsInstance ? settle(client.audit.keys()) : null,
      settle(client.roles.list()),
    ]);
  }),
  '/account': page(async (client, shell) => {
    if ((await shell).me?.principal.type === 'user') await settle(client.identities.list());
  }),
  '/account/sessions': page(async (client, shell) => {
    const { me } = await shell;
    if (me?.principal.type === 'user') await Promise.all([settle(client.sessions.list()), settle(client.tokens.list(`user:${me.principal.id}`))]);
  }),
  '/login': page(async () => {}),
  '/unregistered': page(async () => {}),
  '/auth/device': page(async () => {}),
  '/approvals/00000000-0000-4000-8000-000000000000': page(async (client) => settle(client.approvals.get('00000000-0000-4000-8000-000000000000'))),
  '/oauth/authorize': page(async (client) => settle(client.oauth.describe({ client_id: 'https://app.example/client.json', redirect_uri: 'https://app.example/cb', response_type: 'code' }))),
};

/** What a page's render cost: its statements on every database, its round trips on the app's, and its vault calls. */
type PageCost = { statements: number; trips: number; vaultCalls: number };

async function pageCost(request: () => Promise<unknown>): Promise<PageCost> {
  const trips = pageTrips;
  const spent = await cost(request);
  return { statements: spent.app.statements + spent.vault.statements, trips: pageTrips - trips, vaultCalls: spent.vaultCalls };
}

/**
 * Each page's server render, warm, as Owner and as viewer, held to `BUDGET.page`, and signed out to `BUDGET.signedOut`. On Workers, its app connection
 * takes each statement in turn, a round trip of Hyperdrive's each, but for the reads asked together, which go under one
 * Sync (`groupReads`); each vault call is a connection of its own. Not the audit page: its check reads what was written
 * since the newest checkpoint, which its own test holds. `history`: the render without the reports an Owner's page of
 * a member shows, which list every secret they ever read; the per-statement pages test, which grows the log, measures it.
 */
const renders: Record<string, { request: () => Promise<unknown>; history?: () => Promise<unknown>; budget?: Budget }> = {
  "an Owner's environment page": { request: () => environmentPage('owner') },
  "a viewer's environment page": { request: () => environmentPage('viewer') },
  "an Owner's project page": { request: () => projectPage('owner') },
  "a viewer's project page": { request: () => projectPage('viewer') },
  ...Object.fromEntries(Object.keys(visits).flatMap((path) => (['owner', 'viewer'] as const).map((as) => [`${path}, ${as}`, { request: () => visit(as, path), history: () => visit(as, path, { reports: false }) }]))),
  '/login, signed out': { request: () => visit(null, '/login'), budget: BUDGET.signedOut },
};

test('each page renders within its budget of statements, round trips and vault calls', async () => {
  await warm();
  const over: string[] = [];
  for (const [name, { request, budget = BUDGET.page }] of Object.entries(renders)) over.push(...overBudget(await pageCost(request), budget).map((line) => `${name}: ${line}`));
  assert.deepEqual(over, []);
});

/**
 * A page's reads go under one Sync, as one implicit transaction: one that
 * fails, here the project's references, which its login may no longer
 * read, fails those sent with it: the environment's keys, missing keys and
 * dismissals. Each of the page's calls answers with
 * an error, as one whose own read failed does, and nothing is sent again.
 */
test("a page's read that fails fails the reads sent with it, once, and each of its calls says so", async () => {
  await environmentPage('viewer');
  const answered = await pageCost(() => environmentPage('viewer'));
  await db.owner.execute(sql`REVOKE SELECT ON secret_references FROM coffre_app`);
  try {
    let outcomes: PromiseSettledResult<unknown>[] = [];
    const spent = await pageCost(async () => (outcomes = await environmentCalls('viewer')));
    assert.deepEqual(outcomes.map((outcome) => outcome.status === 'rejected' ? (outcome.reason as { status?: number }).status : 'answered'), [500, 500, 500]);
    // The page's reads, each once, but the references' ends, which their list, failed, never asks: two statements and
    // their round trip fewer than it answered with.
    assert.deepEqual(spent, { statements: answered.statements - 2, trips: answered.trips - 1, vaultCalls: answered.vaultCalls });
  } finally {
    await db.owner.execute(sql`GRANT SELECT ON secret_references TO coffre_app`);
  }
  for (const outcome of await environmentCalls('viewer')) assert.equal(outcome.status, 'fulfilled');
});

/** What a request spent, as a budget measures it. */
const spentOf = (spent: Cost) => ({ statements: spent.app.statements + spent.vault.statements, vaultCalls: spent.vaultCalls });

test('each hot request runs within its budget of statements and vault calls', async () => {
  await warm();
  const over: string[] = [];
  for (const [name, { request, budget }] of Object.entries(requests)) over.push(...overBudget(spentOf(await repeated(request)), budget).map((line) => `${name}: ${line}`));
  assert.deepEqual(over, []);
});

/**
 * A workload's request, or verify, at a proxy whose cache has lapsed, on an isolate that has served one before: a
 * credential's row and `app_read`, then the vault's use, which decides, logs it and opens the value. The app takes no lock.
 */
test("a workload's request at a proxy whose cache lapsed runs its budget, and the app takes no lock", async () => {
  await coldWorkload();
  const held = { ...app.held };
  assertOver('a workload\'s request, cold', spentOf(await cost(coldWorkload)), OVER.coldUse);
  assert.equal(app.held.statements - held.statements, 0, 'no statement of the app\'s in a transaction, and so none under the head');
});

test("a workload's verify at a proxy whose cache lapsed runs a proxied request's budget", async () => {
  await coldVerify();
  assertOver('a workload\'s verify, cold', spentOf(await cost(coldVerify)), OVER.coldUse);
});

/**
 * The same through the proxy, its service's access changed since the
 * proxy's last read: under 0.15's log the app keeps no answer of the
 * vault's to go stale, and the use decides on the vault's rows as they
 * are. One call, as any other, logged as one use.
 */
test("a proxied call whose cache lapsed, after its service's access changed, asks the vault once, as any other", async () => {
  await coldWorkload();
  await root.access.set(SERVICE, { 'market/dev': 'developer' });
  const before = (await usesLogged(db.owner)).length;
  const changed = await cost(coldWorkload);
  const logged = (await usesLogged(db.owner)).slice(before);
  assert.deepEqual(logged.map((use) => useOfCode(use.purpose)?.purpose), ['use']);
  const after = await cost(coldWorkload);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  for (const spent of [changed, after]) assertOver('a proxied call, cold', spentOf(spent), OVER.coldUse);
});

test('a request runs the same statements, and reads the same rows, however large the log, the members, their sessions and tokens, and the policy grow [full]', async () => {
  await warm();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await repeated(request);
  const smallPages: Record<string, PageCost> = {};
  for (const [name, { request }] of Object.entries(renders)) smallPages[name] = await pageCost(request);
  const sessionsPage = (as: Persona) => visit(as, '/account/sessions');
  const sessionRows = { owner: (await cost(() => sessionsPage('owner'))).app.rows, viewer: (await cost(() => sessionsPage('viewer'))).app.rows };

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
  // What the sessions and service accounts pages list: each persona's sessions and personal tokens, and service
  // accounts, each with a token, that both manage, as they manage ci-web.
  for (let i = 0; i < 48; i++) {
    const account = `token:grown-${i}`;
    await root.members.add(account);
    await root.access.set(account, { 'market/dev': 'viewer' });
    await root.tokens.issue(account, { label: 'ci', expiresInDays: 1 });
    for (const persona of ['owner', 'viewer'] as const) await signInAgain(persona);
    await root.tokens.issue(`user:${ROOT}`, { label: `grown-${i}`, expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
    await reader.tokens.issue(`user:${READER}`, { label: `grown-${i}`, expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  }

  // Warm again first: the growth changed the policy and lapsed the proxy's cache, which settle before the measure.
  await warm();
  for (const [name, { request }] of Object.entries(requests)) {
    assert.deepEqual(await repeated(request), small[name], `${name} ran more statements or read more rows once the instance grew`);
  }
  // A page lists what there is, so its rows grow with the members and places it shows; its statements and round trips do not.
  for (const as of ['owner', 'viewer'] as const) {
    assert.equal((await cost(() => sessionsPage(as))).app.rows - sessionRows[as], 96, `${as}'s sessions page reads each of their 48 sessions and 48 personal tokens added once`);
  }
  for (const [name, { request }] of Object.entries(renders)) {
    assert.deepEqual(await pageCost(request), smallPages[name], `${name} ran more statements or round trips once the instance grew`);
  }
});

/**
 * A request's work in the database does not grow with the log. Each
 * statement of each hot request, run again under EXPLAIN, reads as many
 * pages of the database (shared buffers, cached or not) on a log of ten
 * thousand entries as on one ten times longer, grown as Equisafe's grows:
 * the vault's reads of a few principals and the proxy's uses, over the last
 * day, some within the bulk limit's window, and the changes to what its
 * members hold, which the member list reads by principal. No statement scans the log, nor
 * one principal's reads in it (the bulk count reads `vault_releases`).
 */
test("each hot request's statements read as many pages however long the log grows [full]", async () => {
  /** `count` entries more, older than any, copies of the reads and uses the log holds: what the hot paths would scan. */
  const grow = async (count: number) => {
    // In parts, each within a statement's time on the fixture's connections. Each copy is older than the read it
    // copies, so the copies release no key later than the log already did, and the trigger that keeps
    // `vault_releases` is off while they go in. On, it would move the same few rows on thousands of times in each
    // part's one transaction, which no read does: seconds a part, past the statement timeout on a loaded runner, and
    // a table and its index hundreds of pages past their rows, whose ratio then picks the bulk count's plan.
    const releases = async () => [...await db.owner.execute(sql`SELECT principal, key, released_at FROM vault_releases ORDER BY principal, key`)];
    const released = await releases();
    for (let left = count; left > 0; left -= 5000) {
      await db.owner.transaction(async (tx) => {
        // Planned for thousands of times the rows it makes, a part would compile them first (JIT), longer than it runs.
        await tx.execute(sql`SET LOCAL jit = off`);
        await tx.execute(sql`ALTER TABLE audit_log DISABLE TRIGGER audit_log_releases`);
        await tx.execute(more(Math.min(5000, left)));
        await tx.execute(sql`ALTER TABLE audit_log ENABLE TRIGGER audit_log_releases`);
      });
    }
    assert.deepEqual(await releases(), released, 'the copies released no key later than the log did');
    // And a tenth as many keys, each read once by each reader over a day ago, past any window and its margin: what a
    // count of every key ever released would read. A checkpoint, as each scheduled run asks, forgets them.
    for (let left = count / 10; left > 0; left -= 5000) await db.owner.execute(keys(Math.min(5000, left)));
    // As many runs as it takes, each forgetting up to 10,000: the keys of every reader, a day and an hour old.
    const old = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM vault_releases WHERE released_at < (extract(epoch from clock_timestamp()) * 1000)::bigint - 25 * 3600000`))[0]!.n;
    const runs = Math.ceil((await old()) / 10_000) + 1;
    for (let run = 0; run < runs; run++) assert.ok((await signLog()).ok);
    assert.equal(await old(), 0, 'the checkpoints forgot them all');
    // And reference rows, a tenth as many as the entries, of a key archived in market/prod, which no page reads: rows
    // of the app's (no seal), as an instance's history leaves them. A read of the references that scans them reads
    // ten times as many pages; one that goes by its indexes, no more.
    await db.owner.execute(sql`
      INSERT INTO secrets (project_id, environment_id, key, archived_at)
      SELECT e.project_id, e.id, 'GROWN_REFERENCED', now() FROM environments e JOIN projects p ON p.id = e.project_id
      WHERE p.slug = 'market' AND e.slug = 'prod'
      ON CONFLICT DO NOTHING`);
    await db.owner.execute(sql`
      INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
      SELECT gen_random_uuid(), s.project_id, s.environment_id, s.id, s.project_id, s.environment_id, s.id,
        (SELECT least(min(created_seq), 0) FROM secret_references) - g, 'system:load'
      FROM secrets s CROSS JOIN generate_series(1, ${count / 10}) g WHERE s.key = 'GROWN_REFERENCED'`);
    // As autovacuum leaves it: the releases the checkpoints forgot taken back, and the grown log's statistics. One
    // process, as autovacuum's: parallel workers share their dead rows through the container's small /dev/shm.
    await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0)`);
  };
  const keys = (count: number) => sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash, metadata)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - row_number() OVER (), 'vault', e.key_id, e.occurred_at - 26 * 3600000 - g, e.actor,
        'secret.read', 'allow', e.prev_hash, e.mac, e.hash, json_build_object('secrets', json_build_array(json_build_object('secretId', gen_random_uuid()::text)))::text
      FROM (SELECT DISTINCT ON (actor) * FROM audit_log WHERE author = 'vault' AND action = 'secret.read' AND decision = 'allow' AND seq >= 0 ORDER BY actor, seq DESC) e
      CROSS JOIN generate_series(1, ${count}) g`;
  // As many rounds of copies as make `count`, no more: `count` rounds, each numbered before the limit, would sort
  // hundreds of megabytes on disk a part.
  const more = (count: number) => sql`
      WITH e AS (SELECT * FROM audit_log WHERE seq >= 0 AND action IN ('secret.read', 'credential.use', ${sql.join(ACCESS_ACTIONS.map((action) => sql`${action}`), sql`, `)}))
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, project_id, environment_id, secret_id,
        secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - row_number() OVER (ORDER BY g, e.seq), author, key_id, occurred_at - (g * 7919) % 86400000, actor,
        action, decision, code, subject_principal, project_id, environment_id, secret_id, secret_version_id, operation_id, request_id, source_ip, related_seq,
        metadata, prev_hash, mac, hash
      FROM e CROSS JOIN generate_series(1, ceil(${count}::numeric / greatest((SELECT count(*) FROM e), 1))::int) g
      ORDER BY g, e.seq LIMIT ${count}`;
  /** Each hot request's statements, and the pages each reads run again; null for a write that cannot run twice. */
  const pages = async () => {
    await warm();
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, request] of Object.entries(measured)) {
      // Both calls within every key's period of the bulk cap, as `repeated`'s: a turn between them adds a statement.
      const run = await inOnePeriod(() => inBulkPeriod(PERIOD_ROOM_MS, db.owner, CAPPED, 'market/dev'), db.owner, CAPPED, 'market/dev', async () => {
        await request();
        app.recorded = [];
        vaultPool.recorded = [];
        await request();
        const recorded = [...app.recorded.map((statement) => ({ pool: app, statement })), ...vaultPool.recorded.map((statement) => ({ pool: vaultPool, statement }))];
        app.recorded = vaultPool.recorded = null;
        return recorded;
      });
      read[name] = [];
      for (const { pool, statement } of run) {
        if (!/^\s*(select|with|insert|update|delete)\b/i.test(statement.text)) continue;
        const work = await pool.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  // The hot requests, and those whose cost the budgets above leave out: a proxied call or verify whose cache
  // lapsed, and a handle for `coffre run`.
  const measured: Record<string, () => Promise<unknown>> = {
    ...Object.fromEntries(Object.entries(requests).map(([name, { request }]) => [name, request])),
    "a workload's request at a proxy whose cache lapsed": coldWorkload,
    "a workload's verify at a proxy whose cache lapsed": coldVerify,
    'a handle for `coffre run`': () => reader.handles.create({ label: 'run', paths: ['market/dev'] }),
    ...Object.fromEntries(Object.entries(renders).map(([name, { request, history }]) => [name, history ?? request])),
  };
  await grow(10_000);
  const small = await pages();
  // 110,000 entries in all: a statement that reads the log, or a principal's reads in it, reads hundreds of pages more.
  // One that does not reads a few more at most, as an index grows a level, or as the window holds the reads made here.
  await grow(100_000);
  const grown = await pages();
  for (const [name, statements] of Object.entries(small)) {
    assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
    for (const [i, { text, pages: before }] of statements.entries()) {
      const { pages: after, plan } = grown[name]![i]!;
      if (before === null || after === null) {
        // Only a write that cannot run twice, which writes the rows it is given.
        assert.equal(before, after, `${name}: ${text} ran again once, not twice`);
        assert.match(text, /^\s*(with appended as \(insert|insert|select use_)/i, `${name}: ${text} could not run again`);
        continue;
      }
      assert.ok(after <= 2 * before + 16, `${name}: ${text} read ${after} pages once the log grew tenfold, ${before} before:\n${plan}`);
    }
  }
});

/**
 * A reveal after the reader's role changed: under 0.15's log the app keeps
 * no answer of the vault's about them to go stale, and the use decides on
 * the vault's rows as they are. One call, one statement, as any other.
 */
test("a reveal after the reader's access changed costs what any other does", async () => {
  const readers = [`user:${READER}`];
  const { before, changed, after, answers } = await inOnePeriod(() => inBulkPeriod(PERIOD_ROOM_MS, db.owner, readers, 'market/dev'), db.owner, readers, 'market/dev', async () => {
    await reader.secrets.reveal('market/dev/API_KEY');
    const before = spentOf(await cost(() => reader.secrets.reveal('market/dev/API_KEY')));
    await root.access.set(`user:${READER}`, { 'market/dev': 'developer' });
    const answers: unknown[] = [];
    const revealed = async () => void answers.push(await reader.secrets.reveal('market/dev/API_KEY'));
    const changed = await cost(revealed);
    const after = await cost(revealed);
    await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
    return { before, changed, after, answers };
  });
  // Each a reveal that answered, not one refused early.
  for (const answer of answers) assert.match(JSON.stringify(answer), /fake-api-key/);
  for (const spent of [changed, after]) assert.deepEqual(spentOf(spent), before);
});

/**
 * A reveal of an environment, the first use of its keys after one of their
 * periods of the bulk cap turned (`pastBulkTurn`): that key's row of the
 * cap's moves to the new period, one statement more, once. The next costs
 * its budget.
 */
test("a reveal's first use of its keys in a new period of the bulk cap moves their rows: one statement more, once", async () => {
  await reader.secrets.reveal('market/dev');
  const readers = [`user:${READER}`];
  const { first, next } = await inOnePeriod(() => pastBulkTurn(PERIOD_ROOM_MS, db.owner, readers, 'market/dev'), db.owner, readers, 'market/dev', async () => ({
    first: await cost(() => reader.secrets.reveal('market/dev')),
    next: await cost(() => reader.secrets.reveal('market/dev')),
  }));
  assert.deepEqual(spentOf(first), { ...spentOf(next), statements: spentOf(next).statements + 1 });
  assertWithin('a reveal of an environment, its keys in a new period', spentOf(first), BUDGET.read);
});

test("a caller's check reads nothing of a project they reach nothing in", async () => {
  await reader.me();
  const before = await cost(() => reader.me());
  await root.projects.create('elsewhere', { name: 'Elsewhere' });
  for (const environment of ['dev', 'prod', 'qa']) await root.environments.create(`elsewhere/${environment}`, { name: environment });
  await root.secrets.set('elsewhere/dev', { A: 'fake-a', B: 'fake-b' });
  assert.deepEqual(await cost(() => reader.me()), before);
});

/**
 * The instance grown every way at once, in an order Hegel draws: other
 * environments written, other projects and their forks made, members granted, the
 * reader's own role flipped, environments protected and not, roles edited
 * and made, references made into the environment the requests read, keys
 * made sensitive, tokens issued. Whatever it grew by, each request costs
 * what it did before.
 */
const growth = gs.record({
  kind: gs.sampledFrom(['write', 'project', 'fork', 'member', 'flip', 'protect', 'role', 'reference', 'sensitive', 'token'] as const),
  place: gs.integers({ minValue: 0, maxValue: 7 }),
  count: gs.integers({ minValue: 1, maxValue: 12 }),
  on: gs.booleans(),
});
const growthSettings = propertySettings(4, 10);

test(`a request costs the same after any growth of the instance, seed ${growthSettings.seed} [full]`, async () => {
  await warm();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await repeated(request);
  const smallPages: Record<string, PageCost> = {};
  for (const [name, { request }] of Object.entries(renders)) smallPages[name] = await pageCost(request);
  // Places made so far: names from a counter, since the instance keeps what every case made. So Hegel's replay of a
  // failing case runs on a larger instance, and may pass, which it reports as flaky: the first failure is printed whole.
  const made = { projects: [] as string[], environments: ['market/busy', 'market/prod'], keys: [] as string[] };
  let n = 0;
  await hegel.testAsync(async (tc) => {
    const steps = tc.draw(gs.arrays(growth, { minSize: 1, maxSize: 8 }));
    for (const step of steps) {
      const at = made.environments[step.place % made.environments.length]!;
      const id = n++;
      switch (step.kind) {
        case 'write': {
          const keys = Object.fromEntries(Array.from({ length: step.count }, (_, i) => [`GROWN_${id}_${i}`, `fake-${id}-${i}`]));
          await root.secrets.set(at, keys);
          made.keys.push(...Object.keys(keys).map((key) => `${at}/${key}`));
          break;
        }
        case 'project': {
          await root.projects.create(`grown-${id}`, { name: `Grown ${id}` });
          for (const environment of ['dev', 'prod']) await root.environments.create(`grown-${id}/${environment}`, { name: environment });
          made.projects.push(`grown-${id}`);
          made.environments.push(`grown-${id}/dev`, `grown-${id}/prod`);
          break;
        }
        case 'fork': {
          // In another project than market: a caller reads the environments of the projects they reach, its forks among them.
          const [project, from] = at.split('/');
          if (project === 'market') break;
          await root.environments.create(`${project}/fork-${id}`, { name: `Fork ${id}`, from });
          made.environments.push(`${project}/fork-${id}`);
          break;
        }
        case 'member': {
          const member = `user:grown-${id}@acme.example`;
          await root.members.add(member);
          await root.access.set(member, { [step.on ? 'market/dev' : at]: step.count % 2 === 0 ? 'viewer' : 'developer' });
          break;
        }
        case 'flip':
          await root.access.set(`user:${READER}`, { 'market/dev': step.on ? 'developer' : 'viewer' });
          break;
        case 'protect':
          // Never market/dev, which the reader reads: protected, a viewer there only uses.
          await root.environments.protect(at, step.on);
          break;
        case 'role':
          await root.roles.set(step.on ? `grown-${step.count % 3}` : 'auditor', {
            name: `Grown ${step.count}`, description: '', permissions: step.count % 2 === 0 ? ['audit.read'] : ['audit.read', 'secret.read', 'secret.use'], protected: ['audit.read'],
          }, step.on ? undefined : { instance: true });
          break;
        case 'reference':
          await root.secrets.set(at, { [`REFERS_${id}`]: { ref: step.on ? 'market/dev/API_KEY' : 'market/dev/DATABASE_URL' } });
          break;
        case 'sensitive': {
          const grown = made.keys.filter((path) => !path.startsWith('market/dev/'));
          if (grown.length === 0) break;
          const path = grown[step.count % grown.length]!;
          const slash = path.lastIndexOf('/');
          await root.secrets.set(path.slice(0, slash), { [path.slice(slash + 1)]: { sensitivity: step.on ? 'sensitive' : 'secret' } });
          break;
        }
        case 'token':
          await (step.on
            ? root.tokens.issue(SERVICE, { label: `grown-${id}`, expiresInDays: 1 })
            : root.tokens.issue(`user:${ROOT}`, { label: `grown-${id}`, expiresInMinutes: 60, scope: { [at]: 'viewer' } }));
          break;
      }
    }
    // Warm again first, as above.
    await warm();
    for (const [name, { request }] of Object.entries(requests)) {
      const spent = await repeated(request);
      const why = `${name} ran more statements or read more rows once the instance grew by ${JSON.stringify(steps)}: ${JSON.stringify(spent)}, not ${JSON.stringify(small[name])}`;
      if (JSON.stringify(spent) !== JSON.stringify(small[name])) console.error(why);
      assert.deepEqual(spent, small[name], why);
    }
    for (const [name, { request }] of Object.entries(renders)) {
      const spent = await pageCost(request);
      const why = `${name} ran more statements or round trips once the instance grew by ${JSON.stringify(steps)}: ${JSON.stringify(spent)}, not ${JSON.stringify(smallPages[name])}`;
      if (JSON.stringify(spent) !== JSON.stringify(smallPages[name])) console.error(why);
      assert.deepEqual(spent, smallPages[name], why);
    }
  }, growthSettings);
});

test('readiness costs the same however long the log, and however far it ran past the anchor [full]', async () => {
  await beat();
  assert.equal((await ready()).ok, true);
  const small = await cost(ready);
  // The log grown by writes, then a beat that walks them.
  for (let i = 0; i < 150; i++) await root.secrets.set('market/busy', { [`READY_${i % 20}`]: `fake-${i}` });
  await beat();
  assert.equal((await ready()).ok, true);
  assert.deepEqual(await cost(ready), small, 'readiness ran more statements or read more rows once the log grew');
  // Twice a walk's worth since the newest beat: the next beat's to walk, not readiness's.
  await append(2 * CHAIN_WALK);
  assert.equal((await ready()).ok, true);
  assert.deepEqual(await cost(ready), small, 'readiness read the entries past the anchor');
  // A beat walks one walk of them, and readiness is red until the beats catch up, at the same cost.
  assert.equal(await beat(), true, 'a backlog is no failure');
  assert.equal((await ready()).ok, false);
  assert.deepEqual(await cost(ready), small);
  await beat();
  await beat();
  assert.equal((await ready()).ok, true);
});

const logLength = async () => (await db.owner.select({ n: sql<number>`count(*)::int` }).from(auditLog))[0]!.n;

/**
 * The vault's checkpoint walks the log on from the last one, up to a walk
 * of entries, a batch a statement, in no transaction: on Workers, a
 * transaction holds its Hyperdrive connection, one of a few the vault
 * shares, from BEGIN to COMMIT, and a long walk took seconds. What its
 * transactions read, the members' rows, where it resumes, a stretch of
 * the past rehashed and the head, is the same after a long stretch of the
 * log as after a short one.
 */
test("a checkpoint's transactions read the same however far its walk goes", async () => {
  // The first checkpoint, and the first after access changed, keeps the members and grants itself, and the one that
  // resumes from it reads them a statement fewer: one signed first, so that no measured call resumes from it. And more
  // than two stretches of the rehash of the past (`walks.scrub`, 100 entries), so that a lap started over the whole log
  // is mid-lap at its second call.
  assert.ok((await signLog()).ok);
  await append(200);
  const held = async (count: number): Promise<{ statements: number; rows: number; walked: number } | null> => {
    assert.ok((await signLog()).ok);
    await append(count);
    const before = { ...vaultPool.held };
    let signed: { ok: boolean } = { ok: false };
    const all = await cost(async () => (signed = await signLog()));
    assert.ok(signed.ok, 'the measured checkpoint signed');
    // The call that ends a lap of the rehash rehashes the rest of the log, fewer rows than a stretch; the checkpoint
    // says so (`scrub` null). The next call starts a lap over the whole log, so the measured call after it is mid-lap.
    const [newest] = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog)
      .where(eq(auditLog.action, 'audit.checkpoint')).orderBy(desc(auditLog.seq)).limit(1);
    if ((JSON.parse(newest!.metadata) as { scrub: unknown }).scrub === null) return null;
    return { statements: vaultPool.held.statements - before.statements, rows: vaultPool.held.rows - before.rows, walked: all.vault.rows };
  };
  const measured = async (count: number) => (await held(count)) ?? (await held(count))
    ?? assert.fail(`two measured checkpoints in a row ended a lap of the rehash, the log ${await logLength()} entries long`);
  const short = await measured(10);
  // Past a batch (`VERIFY_BATCH`): the walk reads two.
  const long = await measured(6000);
  assert.ok(long.walked > short.walked + 6000, `the long walk read ${long.walked} rows, the short ${short.walked}`);
  assert.deepEqual({ statements: long.statements, rows: long.rows }, { statements: short.statements, rows: short.rows });
});

/**
 * The beat's own walk, the app's, goes on from where the anchor says the
 * app verified, up to a walk of entries, a batch a statement, in no
 * transaction either: on Workers it held one of the app's Hyperdrive
 * connections for the whole walk. What the beat's transactions read on
 * the app's side, its row under the head, is the same after a long
 * backlog as after a short one.
 */
test("a beat's transactions read the same however far its walk goes", async () => {
  // The file's anchor store starts empty, so the beats re-anchor, a walk of the log each, and the beat that ends
  // it logs `audit.reanchor`, a transaction more. Beaten until it has, so that no measured beat ends it.
  const reanchored = async () => (await db.owner.select({ seq: auditLog.seq }).from(auditLog)
    .where(eq(auditLog.action, 'audit.reanchor')).limit(1)).length > 0;
  for (let beats = 0; !(await reanchored()); beats++) {
    if (beats === 10) assert.fail(`ten beats left the re-anchor unended, the log ${await logLength()} entries long`);
    assert.equal(await beat(), true);
  }
  const held = async (count: number) => {
    assert.equal(await beat(), true);
    await append(count);
    const before = { ...app.held };
    let walked = false;
    const all = await cost(async () => (walked = await beat()));
    assert.equal(walked, true, 'the measured beat walked clean');
    assert.equal((await ready()).ok, true, 'and caught up');
    return { statements: app.held.statements - before.statements, rows: app.held.rows - before.rows, walked: all.app.rows };
  };
  const short = await held(10);
  // Past a batch: the walk reads two.
  const long = await held(6000);
  assert.ok(long.walked > short.walked + 6000, `the long walk read ${long.walked} rows, the short ${short.walked}`);
  assert.deepEqual({ statements: long.statements, rows: long.rows }, { statements: short.statements, rows: short.rows });
});

test('a standing finding costs each beat the same on the app\'s side, however long it stands and the log grows [full]', async () => {
  assert.equal(await beat(), true);
  await append(1);
  const [x] = await db.owner.select().from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
  // Signed, then edited in place: the app's walk finds it.
  assert.ok((await signLog()).ok);
  const edit = (metadata: string) => withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ metadata }).where(eq(auditLog.seq, x!.seq)));
  await edit('{"edited":true}');
  assert.equal(await beatAnyway(), false);
  const first = await cost(beatAnyway);
  // Two walks' worth of requests since: the beat still reads the flagged entry, and the anchor, alone.
  await append(2 * CHAIN_WALK);
  const later = await cost(beatAnyway);
  assert.equal((await ready()).ok, false);
  assert.ok(later.app.rows <= first.app.rows && later.app.statements <= first.app.statements, `${JSON.stringify(first.app)} then ${JSON.stringify(later.app)}`);
  // Put back, it clears, and the beats walk the backlog, a walk each.
  await edit(x!.metadata);
  for (let i = 0; i < 4; i++) await beatAnyway();
  assert.equal((await ready()).ok, true);
});

/**
 * A read of one environment's keys costs the same however many keys
 * the others hold, and however many archived keys its own live ones have
 * beside them. With only (project_id, environment_id, key) on `secrets`, a
 * read that knows the environment and not the project, the places tree's
 * counts in every `me` among them, scans the table: archived keys of every
 * project included. Each statement run again under EXPLAIN reads as many
 * pages once 10,000 archived keys sit in market/prod beside its live ones and
 * thirty more projects hold theirs.
 */
test("a read of an environment's keys reads as many pages however many keys the instance archives and holds elsewhere", async () => {
  const counted = createDatabase(app.client);
  const [market] = (await places(counted)).filter((project) => project.slug === 'market');
  const ids = Object.fromEntries(market!.environments.map((environment) => [environment.slug, environment.id]));
  const everything = [ids.dev!, ids.prod!, ids.busy!];
  // A sensitive value of market/prod's own, and one market/busy reads through a reference into shop. With none, a plan
  // of `holdingSensitive` that scans a table can stop at an empty join after a handful of pages, and the count said which
  // plan Postgres picked, not what the statement reads; with them, a scan shows. The growth above keeps what it
  // made, a sensitive value of market/busy's own among what it may, so these add to what the environments held before.
  const before = await holdingSensitive(counted, everything);
  await root.secrets.set('market/prod', { COST_SENSITIVE: { value: 'fake-sensitive', sensitivity: 'sensitive' } });
  await root.secrets.set('shop/dev', { COST_SENSITIVE: { value: 'fake-sensitive', sensitivity: 'sensitive' } });
  await root.secrets.set('market/busy', { COST_REFERS: { ref: 'shop/dev/COST_SENSITIVE' } });
  const shop = (await places(counted)).find((project) => project.slug === 'shop')!;
  assert.deepEqual(await holdingSensitive(counted, everything), new Set([...before, ids.prod!, ids.busy!]));
  // A key with a value of its own, and market/busy's reference, as 0.15's objects take them (`secretObjects`): its source
  // and its newest reference row read by the holder's index, never through other keys' references.
  const idOf = async (where: SQL) => (await db.owner.execute<{ id: string }>(sql`SELECT id FROM secrets WHERE archived_at IS NULL AND ${where}`))[0]!.id;
  const plain = await idOf(sql`environment_id = ${ids.dev!} AND key = 'API_KEY'`);
  const refers = await idOf(sql`environment_id = ${ids.busy!} AND key = 'COST_REFERS'`);
  assert.equal((await secretObjects(counted, { ids: [refers] })).get(refers)?.columns.source, await idOf(sql`project_id = ${shop.id} AND key = 'COST_SENSITIVE'`));
  /** Each statement of these reads, run under EXPLAIN: its pages. */
  const reads: Record<string, () => Promise<unknown>> = {
    'the places tree of everything': () => places(counted),
    'the places tree of one project': () => places(counted, { within: [market!.id] }),
    "an environment's keys": () => environmentSecrets(counted, ids.dev!),
    "an environment's key": () => environmentSecrets(counted, ids.dev!, { key: 'API_KEY' }),
    "a key's object": () => secretObjects(counted, { ids: [plain] }),
    "a reference's object": () => secretObjects(counted, { ids: [refers] }),
    // The environment that piles up archived keys of its own, read by key.
    "an archiving environment's key": () => environmentSecrets(counted, ids.prod!, { key: 'API_KEY' }),
    "an archiving environment's heads by key": () => secretHeads(counted, ids.prod!, { keys: ['API_KEY', 'DATABASE_URL'] }),
    "an archiving environment's lock on keys": () => counted.transaction((tx) => lock(tx, secrets, { projectId: market!.id, environmentId: ids.prod!, key: ['API_KEY', 'DATABASE_URL'] })),
    'the keys of three environments': () => liveKeysIn(counted, everything),
    'their distinct counts': () => distinctSecretCounts(counted, everything),
    'their sensitive values': () => holdingSensitive(counted, everything),
    "an environment's heads by key": () => secretHeads(counted, ids.dev!, { keys: ['API_KEY', 'DATABASE_URL'] }),
    'a path with a key': () => resolvePath(counted, { project: 'market', environment: 'dev', key: 'API_KEY' }),
    "an environment's folders": () => secretFolderOf(counted, ids.dev!),
    "a folder's keys": () => secretsInFolder(counted, ids.dev!, 'tools'),
    "a write's lock on keys": () => counted.transaction((tx) => lock(tx, secrets, { projectId: market!.id, environmentId: ids.dev!, key: ['API_KEY', 'DATABASE_URL'] })),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      // By text: a read that runs statements together (`holdingSensitive`) records them in the order they happen to land.
      const statements = [...app.recorded].sort((x, y) => x.text.localeCompare(y.text));
      app.recorded = null;
      read[name] = [];
      for (const statement of statements) {
        if (!/^\s*(select|with)\b/i.test(statement.text)) continue;
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  /** As autovacuum leaves it: the table's statistics and visibility map, which the plans read. */
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects, secret_versions, secret_references`);
  await settle();
  const small = await pages();
  // 10,000 archived keys in market/prod, beside the live ones the places tree counts.
  await db.owner.execute(sql`
    INSERT INTO secrets (project_id, environment_id, key, current_version, archived_at)
    SELECT e.project_id, e.id, 'ARCHIVED_' || g, 0, now() FROM environments e CROSS JOIN generate_series(1, 10000) g
    WHERE e.project_id = ${market!.id} AND e.id = ${ids.prod!}`);
  await settle();
  const archived = await pages();
  // Thirty projects of two environments, each with twenty live keys and a hundred archived.
  await db.owner.execute(sql`
    INSERT INTO projects (id, slug, name) SELECT gen_random_uuid(), 'other-' || g, 'Other ' || g FROM generate_series(1, 30) g`);
  await db.owner.execute(sql`
    INSERT INTO environments (id, project_id, slug, name)
    SELECT gen_random_uuid(), p.id, e.slug, e.slug FROM projects p CROSS JOIN (VALUES ('dev'), ('prod')) AS e(slug) WHERE p.slug LIKE 'other-%'`);
  await db.owner.execute(sql`
    INSERT INTO secrets (project_id, environment_id, key, current_version, archived_at)
    SELECT e.project_id, e.id, 'KEY_' || g, 0, CASE WHEN g > 20 THEN now() END
    FROM environments e JOIN projects p ON p.id = e.project_id CROSS JOIN generate_series(1, 120) g WHERE p.slug LIKE 'other-%'`);
  await settle();
  const elsewhere = await pages();
  // market/busy's reference made long ago, and a key of shop's repointed 5,000 times since: newer rows of another
  // holder's, which a lookup of market/busy's newest that walks the references by `created_seq` reads one by one.
  // Their entries in the log, at seqs before any other, copy its oldest, as the log's growth above does.
  await withLogUnlocked(db.owner, (owner) => owner.execute(sql`
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash, metadata)
    SELECT e.seq - g, e.author, e.key_id, e.occurred_at, e.actor, e.action, e.decision, e.prev_hash, e.mac, e.hash, e.metadata
    FROM (SELECT * FROM audit_log ORDER BY seq LIMIT 1) e CROSS JOIN generate_series(1, 5001) g`));
  await db.owner.execute(sql`
    UPDATE secret_references SET created_seq = (SELECT min(seq) FROM audit_log)
    WHERE secret_id = (SELECT id FROM secrets WHERE environment_id = ${ids.busy!} AND key = 'COST_REFERS')`);
  await db.owner.execute(sql`
    INSERT INTO secrets (project_id, environment_id, key, archived_at) VALUES (${shop.id}, (SELECT environment_id FROM secrets
      WHERE project_id = ${shop.id} AND key = 'COST_SENSITIVE'), 'COST_REPOINTED', now())`);
  await db.owner.execute(sql`
    INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
    SELECT gen_random_uuid(), s.project_id, s.environment_id, s.id, s.project_id, s.environment_id, s.id,
      (SELECT min(seq) FROM audit_log) + g, 'system:load'
    FROM secrets s CROSS JOIN generate_series(1, 5000) g WHERE s.key = 'COST_REPOINTED'`);
  await settle();
  const history = await pages();
  for (const [name, statements] of Object.entries(small)) {
    for (const [grown, label] of [[archived, 'archived keys of its own'], [elsewhere, 'keys of other projects'], [history, 'references made since']] as const) {
      // The places tree of everything counts every live key of every project, which the second growth adds and the third keeps:
      // only the first bears on it.
      if (name === 'the places tree of everything' && grown !== archived) continue;
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with ${label}, ${before} before:\n${plan}`);
      }
    }
  }
});

/**
 * A project's audit page, through the API, as coffre's own pages ask it: where 0.15's log records key writes alone,
 * it reads the project's environments, and only those, never a count of each one's keys, which grows
 * with every key the project holds.
 */
test("a project's audit page reads as many pages however many keys the project holds", async () => {
  const asked = () => root.audit.list({ path: 'market', limit: 50 });
  const pages = async () => {
    await asked();
    app.recorded = [];
    await asked();
    const statements = [...app.recorded].filter((statement) => /^\s*(select|with)\b/i.test(statement.text)).sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
    app.recorded = null;
    const read: { text: string; pages: number | null; plan?: string }[] = [];
    for (const statement of statements) {
      const work = await app.work(statement);
      read.push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
    }
    return read;
  };
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects`);
  await settle();
  const small = await pages();
  try {
    // 20,000 live keys in market/dev.
    await db.owner.execute(sql`
      INSERT INTO secrets (project_id, environment_id, key, current_version)
      SELECT e.project_id, e.id, 'PAGE_KEY_' || g, 0 FROM environments e JOIN projects p ON p.id = e.project_id CROSS JOIN generate_series(1, 20000) g
      WHERE p.slug = 'market' AND e.slug = 'dev'`);
    await settle();
    const grown = await pages();
    assert.deepEqual(grown.map(({ text }) => text), small.map(({ text }) => text), 'the page ran other statements');
    for (const [i, { text, pages: before }] of small.entries()) {
      const { pages: after, plan } = grown[i]!;
      assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${text} read ${after} pages with 20,000 keys more, ${before} before:\n${plan}`);
    }
  } finally {
    await db.owner.execute(sql`DELETE FROM secrets WHERE starts_with(key, 'PAGE_KEY_')`);
  }
});

/**
 * The reads that name the places, and count nothing in them: a member's report, `me`, the members list. Each reads no
 * key, so as many pages however many the instance holds. A count of them would read every live key of the places, a
 * page for each when Postgres picks an index scan for each environment (1,184 pages for 1,282 keys), 30 to 48 when it
 * picks one bitmap scan, as the statistics of `secrets` decide: with keys counted, these grow with the keys, whichever
 * plan runs. The earlier tests leave the log due for an auto-analyze, which may land between the two counts and change
 * the plan of the missing members' read (`missingMembers`, which the next test holds). The log is analyzed before each count here, so that both are planned on fresh statistics, and
 * no auto-analyze is left due to land between them.
 */
test("a member's report, `me` and the members list read as many pages however many keys the instance holds [full]", async () => {
  const someone = (await root.members.list()).members.find((entry) => entry.member.startsWith('user:'))!.member;
  const reads: Record<string, () => Promise<unknown>> = {
    "a member's report": () => root.members.get(someone),
    me: () => root.me(),
    'the members list': () => root.members.list(),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const statements = [...app.recorded].filter((statement) => /^\s*(select|with)\b/i.test(statement.text)).sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
      app.recorded = null;
      read[name] = [];
      for (const statement of statements) {
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects, audit_log`);
  await settle();
  const small = await pages();
  try {
    // 400 live keys more in each live environment, about 25,000 in all, each environment's among the others' in the heap.
    await db.owner.execute(sql`
      INSERT INTO secrets (project_id, environment_id, key, current_version)
      SELECT e.project_id, e.id, 'PLACE_KEY_' || g, 0 FROM generate_series(1, 400) g CROSS JOIN environments e WHERE e.archived_at IS NULL`);
    await settle();
    const grown = await pages();
    for (const [name, statements] of Object.entries(small)) {
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with 25,000 keys more, ${before} before:\n${plan}`);
      }
    }
  } finally {
    await db.owner.execute(sql`DELETE FROM secrets WHERE starts_with(key, 'PLACE_KEY_')`);
    await settle();
  }
});

/**
 * The missing members' read (`missingMembers`) looks for an access entry only of the principals the log names with no
 * member row. Left to the planner, it may look for one of every principal first, once the log's statistics are fresh,
 * each a step down the subject index to an allowed entry: 155 pages to 370 in the test above, whenever an auto-analyze
 * lands between its counts. So the log is analyzed here, as that auto-analyze does, and the read is held, beyond
 * the walk that names the principals, to the rowless principals' log: a ceiling of its own, not a baseline an earlier
 * plan could raise. This file leaves no principal rowless, so the ceiling is 16 pages, which the other order passes by
 * about 170 (172 against 0 over 20 analyzes, each a fresh sample of the ~190,000 entries this file leaves): a bound for
 * this fixture, not for any log, where a hash join may scan the log for a few rowless principals. Beyond that walk, the
 * read looks for no access entry at all: `audit_log_access_idx` holds the allowed ones alone, which name the principals, and
 * the next test holds that walk flat.
 */
test("the missing members' read looks in the log, beyond naming its principals, only for those with no member row (T233)", async () => {
  await db.owner.execute(sql`ANALYZE audit_log`);
  await root.members.list();
  app.recorded = [];
  await root.members.list();
  const statement = app.recorded.find((recorded) => /^\s*select principal from \(\s*with recursive named\b/i.test(recorded.text));
  app.recorded = null;
  assert.ok(statement, 'the members list read the missing members');
  const { plan, tree } = (await app.work(statement))!;
  const rowless = await db.owner.execute<{ n: number }>(sql`
    SELECT count(DISTINCT subject_principal)::int AS n FROM audit_log
    WHERE author = 'vault' AND (subject_principal LIKE 'user:%' OR subject_principal LIKE 'token:%')
      AND NOT EXISTS (SELECT 1 FROM principals WHERE principals.principal = audit_log.subject_principal)`);
  const inLog = (node: Plan): number => node['Node Type'] === 'Recursive Union' ? 0
    : (node['Relation Name'] === 'audit_log' ? node['Shared Hit Blocks'] + node['Shared Read Blocks'] : 0) + (node.Plans ?? []).reduce((sum, child) => sum + inLog(child), 0);
  assert.ok(inLog(tree) <= 8 * rowless[0]!.n + 16, `the missing members' read read ${inLog(tree)} pages of the log beyond naming its principals, ${rowless[0]!.n} of them with no member row:\n${plan}`);
});

/**
 * The missing members' read (`missingMembers`), of everyone and of one: the vault's refusals of access changes
 * about someone with no member row, which name them in the log as its allowed changes do, cost it nothing however many
 * there are; nor do the other changes of 0.15's log. Without `audit_log_access_idx`, the read of everyone would name
 * them by any entry of the vault's about them, then look through every one for an allowed access change, and the read
 * of one would scan the log for it: 33 pages to 233 from 1,000 refusals to 10,000, and the whole log. Each refusal here is a
 * copy of the vault's own, older than any entry.
 */
test("the missing members' read reads as many pages however many refusals the log holds about someone with no member row (T239)", async () => {
  const REFUSED = 'user:refused@acme.example';
  const ROOT_PRINCIPAL = `user:${ROOT}`;
  // An entry of the vault's, whose key and chain columns each copy keeps: a refusal is 0.14's log's alone, which an
  // upgraded instance keeps, as 0.15's records its refusals in its own (`refusedAdd`).
  const [vaultEntry] = await db.owner.execute<{ seq: string }>(sql`SELECT CAST(max(seq) AS text) AS seq FROM audit_log WHERE author = 'vault'`);
  assert.ok(vaultEntry?.seq, 'the vault logged an entry');
  const reads: Record<string, () => Promise<unknown>> = {
    'the members list': () => root.members.list(),
    "the report of someone with no member row, whom the log names": () => root.members.get(REFUSED).catch(() => undefined),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const statements = [...app.recorded].filter((statement) => /^\s*(select|with)\b/i.test(statement.text)).sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
      app.recorded = null;
      // `missingMembers` names its tables bare, as no other read does.
      assert.ok(statements.some((statement) => /\bfrom\s+audit_log\b/i.test(statement.text)), `${name} read no missing members`);
      read[name] = [];
      for (const statement of statements) {
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  let changes = 50_000_000;
  /** `count` refusals to grant `REFUSED` a place, each older than any entry, and as many changes of 0.15's log that no read lists. */
  const grow = async (count: number) => {
    await db.owner.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, project_id, environment_id, secret_id,
        secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - g, author, key_id, occurred_at - g, ${ROOT_PRINCIPAL}, 'access.grant', 'deny', 'not_a_member', ${REFUSED},
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '{}', prev_hash, mac, hash
      FROM audit_log CROSS JOIN generate_series(1, ${count}) g WHERE seq = ${vaultEntry.seq}`);
    await db.owner.execute(sql`
      INSERT INTO log_changes (number, at, request_id, object, actor, payload, mac)
      SELECT ${changes} + g, ${changes} + g, 'renewed-' || (${changes} + g), gen_random_uuid(), 'system:load',
        '{"expiresAt":' || g || ',"op":"credential.renew","ref":{"id":"r","kind":"credential"}}', decode(repeat('00', 16), 'hex')
      FROM generate_series(1, ${count}) g`);
    changes += count;
    await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0) audit_log, log_changes, principals`);
  };
  await grow(1_000);
  const small = await pages();
  await grow(10_000);
  const grown = await pages();
  for (const [name, statements] of Object.entries(small)) {
    assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
    for (const [i, { text, pages: before }] of statements.entries()) {
      const { pages: after, plan } = grown[name]![i]!;
      assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with 11,000 refusals about someone with no member row, ${before} with 1,000:\n${plan}`);
    }
  }
});


/**
 * What the project list and a render's shell count of the places: each environment's live keys, each project's
 * team keys. A count reads the keys, so it grows with them: here, with the table's and its live index's pages, as one
 * bitmap scan reads them, where an index scan for each environment read a page for each key (29,889 pages for 29,262
 * live keys in 706). Postgres can still pick an index scan of the keys that reads a page for each, when the archived
 * keys' order makes the table look sorted by environment (`countedPlaceRows`): this holds the shape, not every plan.
 */
test("the project list and a render's shell count the keys within twice their table's and index's pages [full]", async () => {
  const reads: Record<string, () => Promise<unknown>> = {
    'the project list': () => root.projects.list(),
    "an owner's project page": () => projectPage('owner'),
    "a viewer's environment page": () => environmentPage('viewer'),
  };
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects`);
  try {
    // 400 live keys more in each live environment, about 25,000 in all, each environment's among the others' in the heap.
    await db.owner.execute(sql`
      INSERT INTO secrets (project_id, environment_id, key, current_version)
      SELECT e.project_id, e.id, 'COUNTED_KEY_' || g, 0 FROM generate_series(1, 400) g CROSS JOIN environments e WHERE e.archived_at IS NULL`);
    await settle();
    const [{ pages: table }] = await db.owner.execute<{ pages: number }>(sql`
      SELECT sum(relpages)::int AS pages FROM pg_class WHERE relname IN ('secrets', 'secrets_live_idx')`);
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const counts = [...app.recorded].filter((statement) => /\bcount\(/i.test(statement.text) && /"secrets"/.test(statement.text));
      app.recorded = null;
      assert.ok(counts.some((statement) => statement.text.includes('"team_keys"')), `${name} counted no places`);
      for (const statement of counts) {
        const { pages, plan } = (await app.work(statement))!;
        assert.ok(pages <= 2 * table! + 16, `${name}: ${statement.text.replace(/\s+/g, ' ').slice(0, 80)} read ${pages} pages, the keys' table and index ${table}:\n${plan}`);
      }
    }
  } finally {
    await db.owner.execute(sql`DELETE FROM secrets WHERE starts_with(key, 'COUNTED_KEY_')`);
    await settle();
  }
});

/**
 * The keys of deleted places, which 0.14's log leaves unarchived: a count names the standing
 * environments, so Postgres can seek their keys alone. 100 deleted environments of 400 keys each: the project list's
 * count read 166 pages, then 169; a count over every live key read 308, then 945. This holds that plan's shape, not
 * every plan: with fewer, larger environments Postgres can scan the table and filter the deleted ones' keys out (one
 * standing environment of 4,000 keys beside two deleted ones of 4,000 each: 67 pages, then 191).
 */
test("the project list and a render's shell count no deleted place's keys in this fixture (T221)", async () => {
  const reads: Record<string, () => Promise<unknown>> = {
    'the project list': () => root.projects.list(),
    "an owner's project page": () => projectPage('owner'),
    "a viewer's environment page": () => environmentPage('viewer'),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const counts = [...app.recorded].filter((statement) => /\bcount\(/i.test(statement.text) && /"secrets"/.test(statement.text));
      app.recorded = null;
      assert.ok(counts.some((statement) => statement.text.includes('"team_keys"')), `${name} counted no places`);
      read[name] = [];
      for (const statement of counts) {
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects`);
  await settle();
  const small = await pages();
  try {
    // 100 deleted environments in the live projects, 400 keys each, left live as 0.14's log leaves a deleted place's keys.
    await db.owner.execute(sql`
      INSERT INTO environments (project_id, slug, name)
      SELECT p.id, 'gone~counted-' || g, 'gone' FROM (SELECT id FROM projects WHERE slug NOT LIKE '%~%' ORDER BY slug LIMIT 10) p CROSS JOIN generate_series(1, 10) g`);
    await db.owner.execute(sql`
      INSERT INTO secrets (project_id, environment_id, key, current_version)
      SELECT e.project_id, e.id, 'GONE_KEY_' || g, 0 FROM environments e CROSS JOIN generate_series(1, 400) g WHERE starts_with(e.slug, 'gone~counted-')`);
    await settle();
    const grown = await pages();
    for (const [name, statements] of Object.entries(small)) {
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with 40,000 deleted places' keys, ${before} before:\n${plan}`);
      }
    }
  } finally {
    await db.owner.execute(sql`DELETE FROM secrets WHERE starts_with(key, 'GONE_KEY_')`);
    await db.owner.execute(sql`DELETE FROM environments WHERE starts_with(slug, 'gone~counted-')`);
    await settle();
  }
});


/**
 * The audit pages and the offboarding report read the projection: a page of everyone's, a member's, a
 * place's, a reader of some places', with each filter that passes over rows, and a member's report, read as many pages
 * however many entries the projection holds. Planted as rows, as only their reads are measured, a tenth of them first,
 * then all, and gone again after.
 */
test("the audit pages and the offboarding report are each one statement, and read as many pages however many entries the projection holds", async (t) => {
  const counted = createDatabase(app.client);
  const u = (kind: number, n: number) => `00000000-0000-4000-${8000 + kind}-${String(n).padStart(12, '0')}`;
  const ADA = 'user:u3@x';
  // Entries of ten members at sixty keys of six environments of two projects: a third sign-ins, a tenth refused.
  const plant = async (from: number, count: number) => {
    await db.owner.execute(sql`
      INSERT INTO audit_events (at, number, log, author, action, shown, allowed, code, actor, subject, credential, project, environment, secret, version, places,
                                request_id, operation_id, related, source_ip, detail, mac)
      SELECT 1700000000000 + i * 10, i, CASE WHEN i % 10 = 0 THEN 14 WHEN i % 10 = 1 THEN 15 ELSE 16 END, 'vault',
        CASE WHEN i % 3 = 0 THEN 'sign_in' ELSE 'secret.read' END, i % 3 <> 0, i % 10 <> 7, CASE WHEN i % 10 = 7 THEN 'no_grant' END, 'user:u' || (i % 10) || '@x',
        NULL, NULL, p.id, e.id, s.id, s.id, ARRAY[p.id, e.id, s.id], NULL, NULL, NULL, NULL, '{}', ${Buffer.alloc(16)}
      FROM generate_series(${from}::bigint, ${from + count - 1}::bigint) i,
        LATERAL (SELECT CAST(format('00000000-0000-4000-8002-%s', lpad((1 + i % 60)::text, 12, '0')) AS uuid) AS id) s,
        LATERAL (SELECT CAST(format('00000000-0000-4000-8001-%s', lpad((1 + (1 + i % 60) % 6)::text, 12, '0')) AS uuid) AS id) e,
        LATERAL (SELECT CAST(format('00000000-0000-4000-8000-%s', lpad((1 + (1 + (1 + i % 60) % 6) % 2)::text, 12, '0')) AS uuid) AS id) p`);
    await db.owner.execute(sql`INSERT INTO audit_event_places (place, at, number, log) SELECT unnest(places), at, number, log FROM audit_events
      WHERE number BETWEEN ${from} AND ${from + count - 1} ON CONFLICT DO NOTHING`);
    await db.owner.execute(sql`INSERT INTO audit_member_keys (principal, secret, version, wrote, at, number)
      SELECT actor, secret, version, false, max(at), max(number) FROM audit_events WHERE shown AND allowed GROUP BY actor, secret, version
      ON CONFLICT (principal, secret, version, wrote) DO UPDATE SET at = excluded.at, number = excluded.number`);
    await db.owner.execute(sql`VACUUM (ANALYZE) audit_events, audit_event_places, audit_member_keys`);
  };
  const reads: Record<string, () => Promise<unknown>> = {
    "everyone's page": () => eventsPage(counted, { stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 100 }),
    'with the detail': () => eventsPage(counted, { stream: { all: true, shownOnly: false }, match: {}, detail: true, counted: false, limit: 100 }),
    'counting what it hides': () => eventsPage(counted, { stream: { all: true, shownOnly: false }, match: {}, detail: false, counted: true, limit: 100 }),
    'refusals': () => eventsPage(counted, { stream: { all: true, shownOnly: true }, match: { allowed: false }, detail: false, counted: false, limit: 100 }),
    "a member's page": () => eventsPage(counted, { stream: { actors: [ADA] }, match: {}, detail: false, counted: false, limit: 50 }),
    "a name's page, a person's or a service's": () => eventsPage(counted, { stream: { actors: [ADA, 'token:u3@x', 'system:u3@x', 'u3@x'] }, match: {}, detail: false, counted: false, limit: 50 }),
    "an environment's page": () => eventsPage(counted, { stream: { places: [u(1, 3)] }, match: { within: [u(1, 3)] }, detail: false, counted: false, limit: 100 }),
    "a key's page": () => eventsPage(counted, { stream: { places: [u(2, 8)] }, match: { within: [u(2, 8)] }, detail: false, counted: false, limit: 100 }),
    "a reader of a project but for an environment": () => eventsPage(counted, { stream: { places: [u(0, 1)] }, match: { except: [u(1, 2)] }, detail: false, counted: false, limit: 100 }),
    'a reader of three environments': () => eventsPage(counted, { stream: { places: [u(1, 1), u(1, 3), u(1, 5)] }, match: {}, detail: false, counted: false, limit: 100 }),
    // More places than a page reads apart (`PLACES_APART`): everyone's stream, held to them, one window in all.
    'a reader of twenty keys': () => eventsPage(counted, { stream: { places: Array.from({ length: 20 }, (_, i) => u(2, 1 + i)) }, match: {}, detail: false, counted: false, limit: 100 }),
    'an older page': () => eventsPage(counted, { stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 100, before: { at: 1700000000000 + 10 * 1000, number: 1000n, log: 16 } }),
    "a member's report": () => memberKeys(counted, [ADA]),
    "ten removed members' counts": () => memberKeys(counted, Array.from({ length: 10 }, (_, i) => `user:u${i}@x`)),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const statements = [...app.recorded];
      app.recorded = null;
      read[name] = [];
      for (const statement of statements) {
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  try {
    // A page's stream holds more than a page and its window (`WINDOW`) at the smaller size too: a member's 2,000 rows, a
    // key's 330, so that the larger compares like with like.
    await plant(1, 20_000);
    const small = await pages();
    for (const [name, statements] of Object.entries(small)) assert.equal(statements.length, 1, `${name} is one statement`);
    // And they read what was planted: a full page of each, the newest first.
    const planted = async (newest: bigint) => {
      const page = await eventsPage(counted, { stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 2 });
      assert.deepEqual(page.rows.map(({ number }) => number), [newest, newest - 1n]);
      const member = await eventsPage(counted, { stream: { actors: [ADA] }, match: {}, detail: false, counted: false, limit: 2 });
      assert.deepEqual(member.rows.map(({ actor, shown }) => [actor, shown]), [[ADA, true], [ADA, true]]);
    };
    await planted(20_000n);
    await t.test('as many pages with the projection grown tenfold [full]', async () => {
      await plant(20_001, 180_000);
      const grown = await pages();
      for (const [name, statements] of Object.entries(small)) {
        const [{ text, pages: before }] = statements as [{ text: string; pages: number | null }];
        const { pages: after, plan } = grown[name]![0]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with the projection grown tenfold, ${before} before:\n${plan}`);
      }
      await planted(200_000n);
    });
  } finally {
    await db.owner.execute(sql`TRUNCATE audit_events, audit_event_places, audit_member_keys`);
  }
});

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
import { createHmac, generateKeyPairSync, randomBytes, randomUUID, sign as signWith } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { createClient, type CoffreClient } from '@coffre/client';
import { bodyDigest, createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { generateToken, github, hashToken, signin, tokenHint, type Gate } from '@coffre/core/identity';
import { createDatabase, type Client } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { appendEntries } from '@coffre/db/log';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { localVault } from '@coffre/vault/node';
import { desc, eq, gt, sql, type SQL } from 'drizzle-orm';

import { Accesses } from '../src/accesses.ts';
import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import {
  distinctSecretCounts, environmentSecrets, insertBinding, liveKeysIn, lock, memberStanding, originsOf, places, resolvePath, secretFolderOf, secretHeads, secretsInFolder,
  HIDDEN_COUNTED, sealedHidden, sealedPage, sealedReach, sensitiveFrom, type ChangePoint,
} from '../src/db/queries.ts';
import { insertSession } from '../src/db/workloads.ts';
import { readsByStanding, readsPage, readsStanding } from '../src/db/reads.ts';
import { fetchApi, pageClient } from '../src/fetch-api.ts';
import { sessionCookieName } from '../src/auth.ts';
import { auditReadiness, writeAuditHeartbeat } from './watch-fixture.ts';
import { appLogKey, CHAIN_WALK } from '../src/db/audit.ts';
import { bindingRoute, checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header, hmac } from '../src/plugins/credential-proxy.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testAnchor, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { answer, type Pages } from './start-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';
import { postgresOnly, withLogUnlocked } from './db/engine.ts';
import { auditLog, credentials as credentialRows, secrets } from './db/tables.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci-web';
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
/** What a CI job reveals: seven keys of the environment it reads. */
const SEVEN = ['CLOUDFLARE_API_TOKEN', 'SCALEWAY_SECRET_KEY', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'SOURCE_REGISTRY_KEY', 'GITHUB_RELEASE_APP_CLIENT_ID', 'GITHUB_RELEASE_APP_PRIVATE_KEY'];
const POSTGRES = postgresOnly("counts what the app's and the vault's Postgres connections run");
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
   * audit pages' reads of 0.15's uses, T166) reads no catalog for it.
   */
  async work(statement: Statement): Promise<{ pages: number; plan: string } | null> {
    const rolledBack = new Error('rolled back');
    let work: { pages: number; plan: string } | null = null;
    await this.#pool.begin(async (tx) => {
      try {
        await tx.unsafe('SAVEPOINT warm');
        await tx.unsafe(`EXPLAIN (ANALYZE, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        await tx.unsafe('ROLLBACK TO SAVEPOINT warm');
        const [row] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
        const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: Plan }] })['QUERY PLAN'];
        work = { pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], plan: shown(plan) };
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

/** What a request ran: statements and rows on the app's connection and on the vault's, and how many calls the vault answered, each a connection of its own on Workers. */
type Cost = { app: Count; vault: Count; vaultCalls: number };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let app: CountingPool;
let vaultPool: CountingPool;
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
/** `count` entries of the app's appended at once, as many requests would write them. */
let append: (count: number) => Promise<void>;
/** A page's server render, as Owner or viewer, on a connection of its own, as on Workers; and the round trips its connections took. */
let environmentPage: (as: Persona) => Promise<void>;
let projectPage: (as: Persona) => Promise<void>;
/** The environment page's own calls, as its render asks them, each answered or refused. */
let environmentCalls: (as: Persona) => Promise<PromiseSettledResult<unknown>[]>;
/** Every other page's render, by its path, as its route's loaders read (`visits`). */
let visit: (as: Persona | null, path: string, options?: VisitOptions) => Promise<void>;
let pageTrips = 0;
/** The proxy in front of the app's Postgres that pages' connections go through, counting their Syncs. */
let relay: Awaited<ReturnType<typeof postgresProxy>>;

type Persona = 'owner' | 'viewer';

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
    database: createDatabase(vaultPool.client),
    kek: { id: 'test-kek-1', key: randomBytes(32).toString('base64') },
    owners: [ROOT],
  }, { log: '0.14' });
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
  append = async (count) => {
    for (let left = count; left > 0; left -= 1000) {
      const entries = Array.from({ length: Math.min(1000, left) }, () => ({ actor: 'system:load', action: 'secret.read', decision: 'allow' as const, metadata: '{}' }));
      await db.owner.transaction((tx) => appendEntries(tx, appLogKey(base.chainKey), entries));
    }
  };
  // The vault's answers kept between requests, as a configuration keeps them (`Accesses`).
  const accesses = new Accesses();
  const signinService = new SigninService({ ...base, signin: auth.signin, accesses });
  const deps: FixtureDeps = { ...base, signin: signinService };
  const runtime: CoffreRuntime = {
    db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], signin: signinService, workloads: null, mcp: null, auth, publicUrl: ORIGIN,
    verifier: signinService, waitUntil, schema: { migrated: true }, appKey: { settled: true }, accesses, rotateAfterDays: 365, plugins: [],
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
  const idToken = () => {
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/market:ref:refs/heads/main', iat: now - 5, exp: now + 295, jti: randomUUID(), run_id: '7001', ...claims })}`;
    return `${input}.${signWith('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const workloadsAuth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }).resolve(ORIGIN);
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

  // A workload's key-bound session of the service, as `/api/auth/workload` makes one, and a plugin that asks for it as the proxy does.
  const standing = (await memberStanding(deps.db, SERVICE))!;
  const bindingId = randomUUID();
  await insertBinding(deps.db, deps.chainKey, {
    id: bindingId, principal: SERVICE, generation: standing.generation, profile: 'kubernetes', issuer: 'https://cluster.acme.example', jwksUri: 'https://cluster.acme.example/keys',
    jwks: null, claims: '{"sub":"x"}', scope: null, policy: '{}', label: null, createdBy: ROOT,
  });
  const dev = (await places(deps.db)).find((project) => project.slug === 'market')!.environments.find((environment) => environment.slug === 'dev')!.id;
  const key = await generateProofKey();
  const token = generateToken('workload');
  const now = Date.now();
  await insertSession(deps.db, deps.chainKey, {
    id: randomUUID(), kind: 'workload', tokenHash: hashToken(token), tokenHint: tokenHint(token), generation: standing.generation, principal: SERVICE, identityId: null,
    label: null, createdBy: `binding:${bindingId}`, expiresAt: new Date(now + 3_600_000), revokedAt: null, scope: null,
    places: JSON.stringify([{ environmentId: dev, personal: false }]), jkt: await thumbprint(key.jwk), notAfter: new Date(now + 86_400_000),
    ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null,
  });
  const gate: Gate = { nonce: async () => 'g1.cost', admit: async () => ({ ok: true, nonce: 'g1.cost' }) };
  // Its last use, written once in five minutes after the answer: waited for, so it lands on its own request's count.
  const background: Promise<unknown>[] = [];
  // The credential proxy itself, its upstream an egress that answers at once: the request costs only what coffre does.
  const credentials = { stripe: { upstream: 'https://api.stripe.example', inject: header('authorization', 'Bearer {API_KEY}'), egress: { fetch: async () => new Response(null, { status: 204 }) } } };
  const verifiers = { webhook: hmac('WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) };
  // The proxy's cache keeps an answer 60 s and asks the vault again in the last 15: that one request costs 4 statements
  // and 7 of the vault's, not 1. A Cloudflare call's answer is kept 60 s whatever `cacheSeconds` says (a binding has no
  // session to outlast it), so a request warmed at second 44 of an entry's life and measured at 45, as a loaded runner
  // does after a long test, was that request. Each `warm` renews the proxy: its entries are then as old as the gap
  // between the warm-up and the measurement.
  const proxy = () => ({
    ...runtime,
    waitUntil: (promise: Promise<unknown>) => void background.push(promise),
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 10, total: 10 }) } }).resolve(ORIGIN),
    gates: () => gate,
    plugins: checkPlugins([credentialProxy({ credentials, verifiers })]),
  }) satisfies CoffreRuntime;
  let proxied = proxy();
  renewProxy = () => void (proxied = proxy());
  const forgetful = {
    ...proxied,
    plugins: checkPlugins([credentialProxy({ cacheSeconds: 0, credentials, verifiers })]),
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
  await insertBinding(deps.db, deps.chainKey, {
    id: randomUUID(), principal: SERVICE, generation: standing.generation, profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare',
    jwks: null, claims: '{}', scope: null, policy: '{}', label: null, createdBy: ROOT,
  });
  bound = async () => {
    const answered = await bindingRoute(new Request(`${ORIGIN}/use/market/dev/stripe/v1/charges`, { method: 'POST', body: 'amount=2000' }), proxied, SERVICE);
    if (answered?.status !== 204) throw new Error(`the binding's call was refused: ${await answered?.text()}`);
    await Promise.all(background.splice(0));
  };
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await Promise.all([app.end(), vaultPool.end(), db.close(), relay.close()]);
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
 * Each hot request, and what it costs warm: its statements on the app's
 * connection and the vault's, and the vault's calls. A workload's request
 * at the proxy: one statement, and nothing of the vault's.
 *
 * A reveal: the credential, with the newest policy change; the path; the
 * environment's rows; once the vault has released, the credential and its
 * member again (`credentialStill`). One vault call, its `unwrap`, decided
 * on the vault's answer about the reader kept from their last request,
 * which it checks (`Accesses`): the versions, then BEGIN, its lock
 * timeout, the reader's row locked, the head locked with everything the
 * decision reads, the entries and the head in one statement, COMMIT.
 *
 * A CI run's sign-in: its service's bindings on the issuer, with whether
 * the token was spent and the newest policy change; the vault's `access`;
 * then BEGIN, the head, the member, binding and rate in one read, the token
 * spent with the credential issued and the binding stamped in one
 * statement, the head again with the clock and the last entry, the entry
 * and the head, COMMIT. Six of its statements hold the head. Its list and
 * its reveal cost a service token's, and one statement more: its binding's
 * standing (`standingBinding`).
 */
const requests: Record<string, { request: () => Promise<unknown>; budget: { app: number; vault: number; vaultCalls: number } }> = {
  'a reveal of one key': { request: () => reader.secrets.reveal('market/dev/API_KEY'), budget: { app: 4, vault: 7, vaultCalls: 1 } },
  'a reveal of an environment': { request: () => reader.secrets.reveal('market/dev'), budget: { app: 4, vault: 7, vaultCalls: 1 } },
  'an export, as a service': { request: () => service.secrets.reveal('market/dev'), budget: { app: 4, vault: 7, vaultCalls: 1 } },
  // Only shown: its credential and what the vault's rows say of its caller in one statement, its places in another, and no vault call.
  "a request's check of its caller": { request: () => reader.me(), budget: { app: 2, vault: 0, vaultCalls: 0 } },
  "a CI run's sign-in": { request: () => exchange(), budget: { app: 8, vault: 1, vaultCalls: 1 } },
  "a CI run's list": { request: () => ci.secrets.list('market/dev'), budget: { app: 4, vault: 1, vaultCalls: 1 } },
  "a CI run's reveal of seven keys": { request: () => ci.secrets.reveal('market/dev', SEVEN), budget: { app: 5, vault: 7, vaultCalls: 1 } },
  // Section 5.3's one statement: the session, its member, binding, ancestors and freezes; the vault is not asked, its
  // decision warm in the proxy's cache.
  "a workload's request at the proxy": { request: () => workload(), budget: { app: 1, vault: 0, vaultCalls: 0 } },
  // The same for an inbound webhook's signature: the secret warm in the proxy's cache, no entry in the log.
  "a workload's verify at the proxy": { request: () => verify(), budget: { app: 1, vault: 0, vaultCalls: 0 } },
  // A Cloudflare call naming its environment: its binding, member, place and freezes in one statement; the vault's decision warm.
  "a Cloudflare call at the proxy": { request: () => bound(), budget: { app: 1, vault: 0, vaultCalls: 0 } },
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
    if (!(known.administers || known.me?.setsUpServices)) return;
    const listed = await settle(client.members.list());
    await Promise.all((listed?.members ?? []).filter((member) => member.principalType === 'service' && member.managed).flatMap((member) => [
      settle(client.tokens.list(member.member)),
    ]));
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

/** What a page's render cost: its statements on the app's connection and the round trips they took there, and the vault's statements and calls. */
type PageCost = { app: number; trips: number; vault: number; vaultCalls: number };

async function pageCost(request: () => Promise<unknown>): Promise<PageCost> {
  const trips = pageTrips;
  const spent = await cost(request);
  return { app: spent.app.statements, trips: pageTrips - trips, vault: spent.vault.statements, vaultCalls: spent.vaultCalls };
}

/**
 * Each page's server render, warm, as Owner and as viewer. On Workers, its
 * app connection takes each statement in turn, a round trip of Hyperdrive's
 * each, but for the reads asked together, which go under one Sync
 * (`groupReads`); each vault call is a connection of its own.
 *
 * The environment page: the session, with the newest policy change and
 * the instance's settings (who sets up service accounts, for `me`); the
 * vault's `access`; the places the caller reaches, each
 * project's team keys with them, and the keys and dismissals of the
 * projects with a fork, which the project list resolves; then, at once,
 * the environment's secrets, the project's references, and the keys and
 * dismissals of the environment's siblings, for its missing keys; then
 * both ends of its references (two), and for an Owner, who manages its
 * access, who reads through them: the members, their grants and the
 * vault's findings about them. The project page: the session and the
 * places, and an Owner its grants, which are the members, their grants,
 * findings and those the log names with no row (`missingMembers`), and the
 * vault's `about`, which reads nothing.
 */
/**
 * `history`: an Owner's page of a member, whose report lists every secret they ever read (`memberActivity`, the
 * offboarding report's exposure): it reads their history in the log, as main did, by design. Its statements are its
 * budget's; the per-statement pages test, which grows the log, measures the page without that report.
 */
const renders: Record<string, { request: () => Promise<unknown>; budget: PageCost; history?: () => Promise<unknown> }> = {
  "an Owner's environment page": { request: () => environmentPage('owner'), budget: { app: 13, trips: 4, vault: 1, vaultCalls: 1 } },
  "a viewer's environment page": { request: () => environmentPage('viewer'), budget: { app: 10, trips: 4, vault: 1, vaultCalls: 1 } },
  "an Owner's project page": { request: () => projectPage('owner'), budget: { app: 8, trips: 3, vault: 1, vaultCalls: 2 } },
  "a viewer's project page": { request: () => projectPage('viewer'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  // Every other page, as Owner and viewer (`visits`); the sign-in page signed out too, which reads nothing. Not the
  // audit page's: its check reads what was written since the newest checkpoint (R25), which its own test holds.
  "/projects, owner": { request: () => visit('owner', '/projects'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/projects, viewer": { request: () => visit('viewer', '/projects'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/projects/market/users, owner": { request: () => visit('owner', '/projects/market/users'), budget: { app: 14, trips: 4, vault: 1, vaultCalls: 2 } },
  "/projects/market/users, viewer": { request: () => visit('viewer', '/projects/market/users'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/projects/market/service-accounts, owner": { request: () => visit('owner', '/projects/market/service-accounts'), budget: { app: 8, trips: 3, vault: 1, vaultCalls: 2 } },
  "/projects/market/service-accounts, viewer": { request: () => visit('viewer', '/projects/market/service-accounts'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/projects/market/settings, owner": { request: () => visit('owner', '/projects/market/settings'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/projects/market/settings, viewer": { request: () => visit('viewer', '/projects/market/settings'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/users, owner": { request: () => visit('owner', '/users'), budget: { app: 8, trips: 3, vault: 1, vaultCalls: 2 } },
  "/users, viewer": { request: () => visit('viewer', '/users'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  // Its report reads what they read under 0.15's log, as the projection lists them, and how far it does (T166), beside
  // its first reads: a statement, no trip.
  "/users/reader@acme.example, owner": { request: () => visit('owner', '/users/reader@acme.example'), budget: { app: 17, trips: 6, vault: 1, vaultCalls: 2 }, history: () => visit('owner', '/users/reader@acme.example', { reports: false }) },
  "/users/reader@acme.example, viewer": { request: () => visit('viewer', '/users/reader@acme.example'), budget: { app: 5, trips: 3, vault: 1, vaultCalls: 1 } },
  "/service-accounts, owner": { request: () => visit('owner', '/service-accounts'), budget: { app: 11, trips: 4, vault: 2, vaultCalls: 3 } },
  "/service-accounts, viewer": { request: () => visit('viewer', '/service-accounts'), budget: { app: 14, trips: 5, vault: 4, vaultCalls: 5 } },
  // Its report reads their reads too, and how far they are listed (T166), beside its first reads.
  "/service-accounts/ci-web, owner": { request: () => visit('owner', '/service-accounts/ci-web'), budget: { app: 20, trips: 7, vault: 2, vaultCalls: 3 }, history: () => visit('owner', '/service-accounts/ci-web', { reports: false }) },
  "/service-accounts/ci-web, viewer": { request: () => visit('viewer', '/service-accounts/ci-web'), budget: { app: 10, trips: 5, vault: 4, vaultCalls: 4 } },
  "/settings, owner": { request: () => visit('owner', '/settings'), budget: { app: 11, trips: 3, vault: 3, vaultCalls: 4 } },
  "/settings, viewer": { request: () => visit('viewer', '/settings'), budget: { app: 6, trips: 3, vault: 1, vaultCalls: 1 } },
  "/account, owner": { request: () => visit('owner', '/account'), budget: { app: 7, trips: 3, vault: 1, vaultCalls: 1 } },
  "/account, viewer": { request: () => visit('viewer', '/account'), budget: { app: 7, trips: 3, vault: 1, vaultCalls: 1 } },
  "/account/sessions, owner": { request: () => visit('owner', '/account/sessions'), budget: { app: 10, trips: 3, vault: 1, vaultCalls: 1 } },
  "/account/sessions, viewer": { request: () => visit('viewer', '/account/sessions'), budget: { app: 11, trips: 3, vault: 1, vaultCalls: 1 } },
  "/login, owner": { request: () => visit('owner', '/login'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/login, viewer": { request: () => visit('viewer', '/login'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/unregistered, owner": { request: () => visit('owner', '/unregistered'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/unregistered, viewer": { request: () => visit('viewer', '/unregistered'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/auth/device, owner": { request: () => visit('owner', '/auth/device'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/auth/device, viewer": { request: () => visit('viewer', '/auth/device'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/approvals/00000000-0000-4000-8000-000000000000, owner": { request: () => visit('owner', '/approvals/00000000-0000-4000-8000-000000000000'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/approvals/00000000-0000-4000-8000-000000000000, viewer": { request: () => visit('viewer', '/approvals/00000000-0000-4000-8000-000000000000'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/oauth/authorize, owner": { request: () => visit('owner', '/oauth/authorize'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/oauth/authorize, viewer": { request: () => visit('viewer', '/oauth/authorize'), budget: { app: 4, trips: 2, vault: 1, vaultCalls: 1 } },
  "/login, signed out": { request: () => visit(null, '/login'), budget: { app: 0, trips: 0, vault: 0, vaultCalls: 0 } },
};

test('each page renders in exactly its budget of statements and round trips', POSTGRES, async () => {
  await warm();
  for (const [name, { request, budget }] of Object.entries(renders)) assert.deepEqual(await pageCost(request), budget, name);
});

/**
 * A page's reads go under one Sync, as one implicit transaction: one that
 * fails, here the project's references, which its login may no longer
 * read, fails those sent with it: the environment's keys, missing keys and
 * dismissals. Each of the page's calls answers with
 * an error, as one whose own read failed does, and nothing is sent again.
 */
test("a page's read that fails fails the reads sent with it, once, and each of its calls says so", POSTGRES, async () => {
  await environmentPage('viewer');
  await db.owner.execute(sql`REVOKE SELECT ON secret_references FROM coffre_app`);
  try {
    let outcomes: PromiseSettledResult<unknown>[] = [];
    const spent = await pageCost(async () => (outcomes = await environmentCalls('viewer')));
    assert.deepEqual(outcomes.map((outcome) => outcome.status === 'rejected' ? (outcome.reason as { status?: number }).status : 'answered'), [500, 500, 500]);
    // The page's reads, each once, but the references' ends, which their list, failed, never asks.
    assert.deepEqual(spent, { app: 8, trips: 3, vault: 1, vaultCalls: 1 }, 'each read sent once');
  } finally {
    await db.owner.execute(sql`GRANT SELECT ON secret_references TO coffre_app`);
  }
  for (const outcome of await environmentCalls('viewer')) assert.equal(outcome.status, 'fulfilled');
});

test('each hot request runs exactly its budget of statements, on as many connections', POSTGRES, async () => {
  await warm();
  for (const [name, { request, budget }] of Object.entries(requests)) {
    const spent = await cost(request);
    assert.deepEqual({ app: spent.app.statements, vault: spent.vault.statements, vaultCalls: spent.vaultCalls }, budget, name);
  }
});

/**
 * A workload's request at a proxy whose cache has lapsed, on an isolate
 * that has served one before: the session's statement, the path and the
 * environment's rows, the vault's unwrap, on the answer about the service
 * kept from its last request, which appends the proxy's `credential.use`
 * beside its read, under the head it holds for it; then the credential
 * still, with no lock. The app takes the head not at all: before 0.14.5 it
 * did, for its own entry, for six statements more, which every append in
 * the instance waited for.
 */
test("a workload's request at a proxy whose cache lapsed runs its budget, and the app takes no lock", POSTGRES, async () => {
  await coldWorkload();
  const held = { ...app.held };
  const spent = await cost(coldWorkload);
  assert.deepEqual({ app: spent.app.statements, vault: spent.vault.statements, vaultCalls: spent.vaultCalls }, { app: 4, vault: 7, vaultCalls: 1 });
  assert.equal(app.held.statements - held.statements, 0, 'no statement of the app\'s in a transaction, and so none under the head');
});

/** A workload's verify at a proxy whose cache has lapsed: what a proxied request costs then, the secret opened and its use logged. */
test("a workload's verify at a proxy whose cache lapsed runs a proxied request's budget", POSTGRES, async () => {
  await coldVerify();
  const spent = await cost(coldVerify);
  assert.deepEqual({ app: spent.app.statements, vault: spent.vault.statements, vaultCalls: spent.vaultCalls }, { app: 4, vault: 7, vaultCalls: 1 });
});

/**
 * The same through the proxy, its service's access changed since the
 * proxy's last read: the read on the kept answer, refused by the vault,
 * goes again, asking, through the session it already checked.
 */
test("a proxied call whose cache lapsed, after its service's access changed, asks the vault again, once", POSTGRES, async () => {
  await coldWorkload();
  await root.access.set(SERVICE, { 'market/dev': 'developer' });
  const [{ seq: since }] = await db.owner.select({ seq: auditLog.seq }).from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
  const changed = await cost(coldWorkload);
  // Logged as one read that asked: the vault's read and the proxy's use, and no refusal.
  const logged = await db.owner.select({ action: auditLog.action, decision: auditLog.decision }).from(auditLog).where(gt(auditLog.seq, since!)).orderBy(auditLog.seq);
  assert.deepEqual(logged.map((entry) => `${entry.action} ${entry.decision}`), ['secret.read allow', 'credential.use allow']);
  const after = await cost(coldWorkload);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  assert.equal(changed.vaultCalls, 3);
  assert.deepEqual({ app: after.app.statements, vault: after.vault.statements, vaultCalls: after.vaultCalls }, { app: 4, vault: 7, vaultCalls: 1 });
});

test('a request runs the same statements, and reads the same rows, however large the log, the members and the policy grow', POSTGRES, async () => {
  await warm();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await cost(request);
  const smallPages: Record<string, PageCost> = {};
  for (const [name, { request }] of Object.entries(renders)) smallPages[name] = await pageCost(request);

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

  // Once first: a request whose caller's access, or the policy, changed since their last asks the vault again, once.
  await warm();
  for (const [name, { request }] of Object.entries(requests)) {
    assert.deepEqual(await cost(request), small[name], `${name} ran more statements or read more rows once the instance grew`);
  }
  // A page lists what there is, so its rows grow with the members and places it shows; its statements and round trips do not.
  for (const [name, { request }] of Object.entries(renders)) {
    assert.deepEqual(await pageCost(request), smallPages[name], `${name} ran more statements or round trips once the instance grew`);
  }
});

/**
 * R48: a request's work in the database does not grow with the log. Each
 * statement of each hot request, run again under EXPLAIN, reads as many
 * pages of the database (shared buffers, cached or not) on a log of ten
 * thousand entries as on one ten times longer, grown as Equisafe's grows:
 * the vault's reads of a few principals and the proxy's uses, over the last
 * day, some within the bulk limit's window, and the changes to what its
 * members hold, which the member list reads by principal. No statement scans the log, nor
 * one principal's reads in it (the bulk count reads `vault_releases`).
 */
test("each hot request's statements read as many pages however long the log grows", POSTGRES, async () => {
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
    // count of every key ever released would read. A checkpoint, as each scheduled run asks, forgets them (T111).
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
      await request();
      app.recorded = [];
      vaultPool.recorded = [];
      await request();
      const run = [...app.recorded.map((statement) => ({ pool: app, statement })), ...vaultPool.recorded.map((statement) => ({ pool: vaultPool, statement }))];
      app.recorded = vaultPool.recorded = null;
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
        assert.match(text, /^\s*(with appended as \(insert|insert)/i, `${name}: ${text} could not run again`);
        continue;
      }
      assert.ok(after <= 2 * before + 16, `${name}: ${text} read ${after} pages once the log grew tenfold, ${before} before:\n${plan}`);
    }
  }
});

/**
 * A reveal decided on a kept answer about its reader that is no longer the
 * vault's, their role changed since: the vault refuses it, reading and
 * logging nothing, and the request goes again, asking. Three calls, once:
 * the next is one again.
 */
test("a reveal after the reader's access changed asks the vault again, once", POSTGRES, async () => {
  await reader.secrets.reveal('market/dev/API_KEY');
  await root.access.set(`user:${READER}`, { 'market/dev': 'developer' });
  const changed = await cost(() => reader.secrets.reveal('market/dev/API_KEY'));
  const after = await cost(() => reader.secrets.reveal('market/dev/API_KEY'));
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  assert.deepEqual({ app: changed.app.statements, vaultCalls: changed.vaultCalls }, { app: 7, vaultCalls: 3 });
  assert.deepEqual({ app: after.app.statements, vault: after.vault.statements, vaultCalls: after.vaultCalls }, { app: 4, vault: 7, vaultCalls: 1 });
});

test("a caller's check reads nothing of a project they reach nothing in", POSTGRES, async () => {
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

test(`a request costs the same after any growth of the instance, seed ${growthSettings.seed}`, POSTGRES, async () => {
  await warm();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await cost(request);
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
    // Once first, as above: a caller whose access, or the policy, changed asks the vault again, once.
    await warm();
    for (const [name, { request }] of Object.entries(requests)) {
      const spent = await cost(request);
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

test('readiness costs the same however long the log, and however far it ran past the anchor', POSTGRES, async () => {
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

/**
 * The vault's checkpoint walks the log on from the last one, up to a walk
 * of entries, a batch a statement, in no transaction: on Workers, a
 * transaction holds its Hyperdrive connection, one of a few the vault
 * shares, from BEGIN to COMMIT, and a long walk took seconds. What its
 * transactions read, the members' rows, where it resumes, a stretch of
 * the past rehashed and the head, is the same after a long stretch of the
 * log as after a short one.
 */
test("a checkpoint's transactions read the same however far its walk goes", POSTGRES, async () => {
  const held = async (count: number) => {
    assert.ok((await signLog()).ok);
    await append(count);
    const before = { ...vaultPool.held };
    let signed: { ok: boolean } = { ok: false };
    const all = await cost(async () => (signed = await signLog()));
    assert.ok(signed.ok, 'the measured checkpoint signed');
    return { statements: vaultPool.held.statements - before.statements, rows: vaultPool.held.rows - before.rows, walked: all.vault.rows };
  };
  const short = await held(10);
  // Past a batch (`VERIFY_BATCH`): the walk reads two.
  const long = await held(6000);
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
test("a beat's transactions read the same however far its walk goes", POSTGRES, async () => {
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

test('a standing finding costs each beat the same on the app\'s side, however long it stands and the log grows', POSTGRES, async () => {
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
 * T152: a read of one environment's keys costs the same however many keys
 * the others hold, and however many archived keys its own live ones have
 * beside them. `secrets` had only (project_id, environment_id, key), so a
 * read that knew the environment and not the project, the places tree's
 * counts in every `me` among them, scanned the table: archived keys of every
 * project included. Each statement run again under EXPLAIN reads as many
 * pages once 10,000 archived keys sit in market/prod beside its live ones and
 * thirty more projects hold theirs.
 */
test("a read of an environment's keys reads as many pages however many keys the instance archives and holds elsewhere", POSTGRES, async () => {
  const counted = createDatabase(app.client);
  const [market] = (await places(counted)).filter((project) => project.slug === 'market');
  const ids = Object.fromEntries(market!.environments.map((environment) => [environment.slug, environment.id]));
  const everything = [ids.dev!, ids.prod!, ids.busy!];
  /** Each statement of these reads, run under EXPLAIN: its pages. */
  const reads: Record<string, () => Promise<unknown>> = {
    'the places tree of everything': () => places(counted),
    'the places tree of one project': () => places(counted, { within: [market!.id] }),
    "an environment's keys": () => environmentSecrets(counted, ids.dev!),
    "an environment's key": () => environmentSecrets(counted, ids.dev!, { key: 'API_KEY' }),
    // The environment that piles up archived keys of its own, read by key.
    "an archiving environment's key": () => environmentSecrets(counted, ids.prod!, { key: 'API_KEY' }),
    "an archiving environment's heads by key": () => secretHeads(counted, ids.prod!, { keys: ['API_KEY', 'DATABASE_URL'] }),
    "an archiving environment's lock on keys": () => counted.transaction((tx) => lock(tx, secrets, { projectId: market!.id, environmentId: ids.prod!, key: ['API_KEY', 'DATABASE_URL'] })),
    'the keys of three environments': () => liveKeysIn(counted, everything),
    'their distinct counts': () => distinctSecretCounts(counted, everything),
    'their sensitive values': () => sensitiveFrom(counted, everything),
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
      // By text: a read that runs statements together (`sensitiveFrom`) records them in the order they happen to land.
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
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) secrets, environments, projects, secret_versions`);
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
  for (const [name, statements] of Object.entries(small)) {
    for (const [grown, label] of [[archived, 'archived keys of its own'], [elsewhere, 'keys of other projects']] as const) {
      // The places tree of everything counts every live key of every project, which the second growth adds: only the first bears on it.
      if (name === 'the places tree of everything' && grown === elsewhere) continue;
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with ${label}, ${before} before:\n${plan}`);
      }
    }
  }
});

/**
 * What the audit pages read of what 0.15's log alone records (D147): the
 * sign-ins through trust bindings (T156), and the token issues, revokes and
 * sign-outs (T164). A page of them, every member's and one's, with the
 * detail and without; what a page hides, counted over its stretch; and how
 * the credentials a page's entries name came to be. Each reads as many
 * pages however many other changes, and other members' records, the log
 * holds (R48): members' changes, renewals, the revokes a binding's end makes,
 * all around them in time. Planted as rows, as only their reads are
 * measured, and gone again after.
 */
test("the audit pages' records of 0.15's log read as many pages however many other changes the log holds", POSTGRES, async () => {
  const counted = createDatabase(app.client);
  const ADA = 'user:ada@acme.example';
  const credentials = Array.from({ length: 20 }, () => randomUUID());
  /** How far a page below Ada's stretch counts, read before each measure. */
  let reached: ChangePoint | null = null;
  const tokens = Array.from({ length: 20 }, () => randomUUID());
  // A stretch of Ada's time, 100 of her records, which a page that hides them counts; and a point in it, an older page's.
  const stretch = { from: { at: 150_100 }, before: { at: 150_200, number: 150_201n } };
  const reads: Record<string, () => Promise<unknown>> = {
    "every service's sign-ins": () => sealedPage(counted, { detail: false, limit: 100 }),
    "a service's sign-ins": () => sealedPage(counted, { actors: ['token:planted'], detail: false, limit: 100 }),
    "an older page of a service's": () => sealedPage(counted, { actors: ['token:planted'], detail: false, before: { at: 100_150, number: 100_150n }, limit: 100 }),
    "every member's records": () => sealedPage(counted, { detail: true, limit: 100 }),
    "a person's records": () => sealedPage(counted, { actors: [ADA], detail: true, limit: 100 }),
    "a person's older page, below a time": () => sealedPage(counted, { actors: [ADA], detail: true, before: stretch.before, limit: 100 }),
    "a name's records, a person's or a service's": () => sealedPage(counted, { actors: ['user:planted', 'token:planted', 'system:planted', 'planted'], detail: true, limit: 100 }),
    "what a page hides of a person's": () => sealedHidden(counted, { actors: [ADA], ...stretch }),
    "what a page hides of everyone's": () => sealedHidden(counted, stretch),
    // A page past the last entry it shows counts no further than `sealedReach`, however long the history below it.
    "how far a page counts of a person's": () => sealedReach(counted, { actors: [ADA], before: stretch.before }),
    "how far a page counts of everyone's": () => sealedReach(counted, { before: stretch.before }),
    "what a page counts of a person's, as far as it reaches": () => sealedHidden(counted, { actors: [ADA], from: reached!, before: stretch.before }),
    // Whole pages through the API, every statement each makes, as coffre's own pages ask them and counted (`hidden`): a
    // service's, its runs' sign-outs above its sign-ins, and a person's, nothing but their records (reviews r3, r4).
    "through the API, a service's page": () => root.audit.list({ actor: 'token:planted', sealed: '1', limit: 50 }),
    "through the API, a person's page": () => root.audit.list({ actor: ADA, sealed: '1', limit: 50 }),
    "through the API, a service's page, counted": () => root.audit.list({ actor: 'token:planted', sealed: '1', hidden: '1', limit: 50 }),
    "through the API, a person's page, counted": () => root.audit.list({ actor: ADA, sealed: '1', hidden: '1', limit: 50 }),
    "how a page's credentials came to be": () => originsOf(counted, [...credentials, ...tokens]),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      // A page's reads go side by side, in no set order: each is matched to itself by its text.
      const statements = [...app.recorded].sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
      app.recorded = null;
      read[name] = [];
      for (const statement of statements) {
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  const credential = (record: string) => sql.raw(`'{"op":"credential.${record}","ref":{"id":"' || gen_random_uuid() || '","kind":"credential"}'`);
  // Each kind of change as the vault writes its payload, canonical (keys in order): `g` its row's place in the batch.
  const payloads: Record<'signIn' | 'member' | 'issue' | 'revoke' | 'signOut' | 'unbound' | 'renew', (actor: string) => SQL> = {
    signIn: () => sql`${credential('issue')} || ',"signIn":{"binding":"b","issuer":"i","proof":"oidc","run":{"run_id":"' || g || '"}}}'`,
    member: () => sql`'{"op":"member.add","ref":{"id":"token:x","kind":"principal"}}'`,
    issue: (actor: string) => sql.raw(`'{"caller":"person","expiresAt":1,"generation":1,"issue":{"by":"${actor}","kind":"personal","label":"l' || g || '","via":null},"op":"credential.issue","principal":"${actor}","ref":{"id":"' || gen_random_uuid() || '","kind":"credential"},"scope":[]}'`),
    revoke: (actor: string) => sql`${credential('revoke')} || ${`,"revoke":{"kind":"cli","principal":"${actor}","reason":"revoke","via":null}}`}`,
    signOut: (actor: string) => sql`${credential('revoke')} || ${`,"revoke":{"kind":"browser","principal":"${actor}","reason":"sign_out","via":null}}`}`,
    unbound: (actor: string) => sql`${credential('revoke')} || ${`,"revoke":{"binding":"b","kind":"service","principal":"${actor}","reason":"unbound","via":null}}`}`,
    renew: () => sql`'{"expiresAt":' || g || ',"op":"credential.renew","ref":{"id":"r","kind":"credential"}}'`,
  };
  /**
   * `count` changes numbered from `from`, each asked at the millisecond `at` + its place (`from`'s by default), long
   * before any checkpoint's floor: of `actor`, one kind's, each its own object or `object`'s.
   */
  const plant = (from: number, count: number, actor: string, kind: keyof typeof payloads, options: { object?: SQL; at?: number } = {}) => db.owner.execute(sql`
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, mac)
    SELECT ${from} + g, ${options.at ?? from} + g, 'planted-' || (${from} + g), ${options.object ?? sql`gen_random_uuid()`}, ${actor}, ${payloads[kind](actor)},
      decode(repeat('00', 16), 'hex')
    FROM generate_series(1, ${count}) g`);
  const settle = () => db.owner.execute(sql`VACUUM (ANALYZE) log_changes`);
  try {
    // A log whose indexes are as deep as they get for long (a probe of each is its depth's pages): 60,000 changes of
    // members, 20,000 sign-ins of another service, 20,000 records of another person's, and the service's and Ada's own.
    await plant(0, 60_000, 'user:admin@acme.example', 'member');
    await plant(200_000, 20_000, 'token:other', 'signIn');
    for (const [i, kind] of (['issue', 'revoke', 'signOut'] as const).entries()) await plant(220_000 + 7_000 * i, 7_000, 'user:other@acme.example', kind);
    await plant(100_000, 200, 'token:planted', 'signIn');
    for (const [i, kind] of (['issue', 'revoke', 'signOut', 'issue'] as const).entries()) await plant(150_000 + 100 * i, 100, ADA, kind);
    for (const [i, id] of credentials.entries()) await plant(100_200 + i, 1, 'token:planted', 'signIn', { object: sql`log_object('credential', ${id})` });
    for (const [i, id] of tokens.entries()) await plant(150_400 + i, 1, ADA, 'issue', { object: sql`log_object('credential', ${id})` });
    // Ada's history below her stretch: more issues than a page counts. And the service's runs signing out, more than a
    // page counts, after its sign-ins.
    await plant(800_000, 1_500, ADA, 'issue', { at: 140_000 });
    await plant(1_100_000, 1_500, 'token:planted', 'signOut', { at: 560_000 });
    await settle();
    reached = await sealedReach(counted, { actors: [ADA], before: stretch.before });
    const small = await pages();
    // 100,000 changes of members more; 50,000 sign-ins of the other service, and 50,000 of its own since; 50,000
    // records of the other person's, and 50,000 of Ada's since; and, asked in her stretch's time, 50,000 renewals of
    // one of the page's tokens (a session's history, its own object's), and 50,000 revokes a binding's end made.
    await plant(300_000, 100_000, 'user:admin@acme.example', 'member');
    await plant(400_000, 50_000, 'token:other', 'signIn');
    await plant(500_000, 50_000, 'token:planted', 'signIn');
    for (const [i, kind] of (['issue', 'revoke'] as const).entries()) await plant(550_000 + 25_000 * i, 25_000, 'user:other@acme.example', kind);
    for (const [i, kind] of (['issue', 'signOut'] as const).entries()) await plant(600_000 + 25_000 * i, 25_000, ADA, kind);
    await plant(700_000, 50_000, ADA, 'renew', { object: sql`log_object('credential', ${tokens[0]!})`, at: 150_100 });
    await plant(750_000, 50_000, ADA, 'unbound', { at: 150_100 });
    // And 50,000 more of Ada's own, older still: what a page past her last shown entry would count but for its reach.
    await plant(850_000, 50_000, ADA, 'issue', { at: 90_000 });
    // And 50,000 more of the service's runs signing out, after every sign-in of its own.
    await plant(950_000, 50_000, 'token:planted', 'signOut');
    await settle();
    reached = await sealedReach(counted, { actors: [ADA], before: stretch.before });
    const grown = await pages();
    for (const [name, statements] of Object.entries(small)) {
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      if (!name.startsWith('through the API')) assert.equal(statements.length, 1, `${name} is one statement`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with the log grown, ${before} before:\n${plan}`);
      }
    }
    // And they read what was planted: a page of the service's, the older page below it; Ada's newest, and those
    // below her stretch, passing over renewals and a binding's revokes; her stretch's count; each credential's origin.
    assert.deepEqual((await sealedPage(counted, { actors: ['token:planted'], detail: false, limit: 100 })).rows.length, 100);
    assert.deepEqual((await sealedPage(counted, { actors: ['token:planted'], detail: false, before: { at: 100_150, number: 100_150n }, limit: 100 })).rows.map(({ number }) => number).slice(0, 2), [100_149n, 100_148n]);
    assert.deepEqual((await sealedPage(counted, { actors: [ADA], detail: true, limit: 2 })).rows.map(({ number }) => number), [650_000n, 649_999n]);
    assert.deepEqual((await sealedPage(counted, { actors: [ADA], detail: true, before: stretch.before, limit: 2 })).rows.map(({ number }) => number), [150_200n, 150_199n]);
    assert.deepEqual((await sealedPage(counted, { detail: true, limit: 1 })).rows.map(({ number }) => number), [1_000_000n]);
    // The service's first page, counted: its runs' newest sign-outs, as many as a page counts, and none of its sign-ins
    // below them. Not counted: its sign-ins at once.
    const first = await root.audit.list({ actor: 'token:planted', sealed: '1', hidden: '1', limit: 50 });
    assert.deepEqual([first.entries.length, first.hidden], [0, [{ action: 'sign_out', count: HIDDEN_COUNTED }]]);
    const shown = await root.audit.list({ actor: 'token:planted', sealed: '1', limit: 50 });
    assert.deepEqual([shown.entries.length, shown.entries[0]?.action, shown.hidden], [50, 'token.exchange', undefined]);
    assert.deepEqual(await sealedHidden(counted, { actors: [ADA], ...stretch }), [{ action: 'token.revoke', count: 100 }]);
    // Below her stretch's time alone, every one of hers: 100 issues, the 100 revokes the stretch holds but its end, and
    // the older history planted.
    assert.deepEqual(
      (await sealedHidden(counted, { actors: [ADA], before: { at: 150_200 } })).sort((a, b) => (a.action < b.action ? -1 : 1)),
      [{ action: 'token.create', count: 100 + 1_500 + 50_000 }, { action: 'token.revoke', count: 100 }],
    );
    // A page counts as far as it reaches: the newest `HIDDEN_COUNTED` below her stretch, the 200 there and 800 older.
    assert.deepEqual(reached, { at: 140_701, number: 800_701n });
    assert.deepEqual(
      (await sealedHidden(counted, { actors: [ADA], from: reached!, before: stretch.before })).sort((a, b) => (a.action < b.action ? -1 : 1)),
      [{ action: 'token.create', count: 900 }, { action: 'token.revoke', count: 100 }],
    );
    const origins = await originsOf(counted, [...credentials, ...tokens]);
    assert.deepEqual(credentials.map((id) => origins.get(id)?.kind), credentials.map(() => 'signIn'));
    assert.deepEqual(tokens.map((id) => origins.get(id)), tokens.map(() => ({ kind: 'personal', label: 'l1', principal: ADA })));
  } finally {
    await db.owner.execute(sql`DELETE FROM log_changes WHERE request_id LIKE 'planted-%'`);
  }
});

test("the audit pages' reads, each a use of 0.15's log as the vault's projector lists it, read as many pages however many other reads the log holds (T166)", POSTGRES, async () => {
  const counted = createDatabase(app.client);
  const ADA = 'user:ada@acme.example';
  const OTHER = 'user:other@acme.example';
  const AHEAD = 100;
  const ids = async (where: SQL) => (await db.owner.execute<{ id: string }>(sql`SELECT CAST(id AS text) AS id FROM ${where}`)).map((row) => row.id);
  // Ada's reads are of market's keys, of their current versions, as the offboarding report weighs them; everyone else's
  // are of keys anywhere, in forks and through references whose source moves on (review r5): none is on her pages.
  await root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`READS_COST_${i}`, `value-${i}`])));
  // A member, whose report the page reads.
  await root.members.add(ADA).catch(() => {});
  const [market] = await ids(sql`projects WHERE slug = 'market'`);
  const [dev] = await ids(sql`environments WHERE slug = 'dev' AND project_id = ${market}`);
  const keys = (await db.owner.execute<{ id: string; version: string }>(sql`
    SELECT CAST(id AS text) AS id, CAST(current_version_id AS text) AS version FROM secrets WHERE environment_id = ${dev} AND key LIKE 'READS_COST_%' ORDER BY key`));
  const now = Date.now();
  const day = (at: number) => new Date(at).toISOString().slice(0, 10);
  await db.owner.execute(sql`SELECT make_reads_day(${day(now - 86_400_000)}::date), make_reads_day(${day(now)}::date)`);
  const array = (values: readonly string[]) => sql.raw(`ARRAY[${values.map((value) => `'${value}'`).join(',')}]::uuid[]`);
  let next = 5_000_000;
  /**
   * `count` reads numbered on from the last, asked from `from` ms ago, one every `every` ms, by `principal`: of Ada's
   * keys, at their versions, or of keys of nowhere in particular, each read in a fork of its own of `forks`, and
   * through a reference to one of `sources`, whichever are given.
   */
  const plant = async (count: number, principal: string, from: number, every: number, options: { own?: boolean; forks?: number; sources?: number } = {}) => {
    const first = next;
    next += count;
    const pick = (n: number | undefined) => (n === undefined ? sql`NULL::uuid` : sql`md5(${String(first)} || '-' || (g % ${n}))::uuid`);
    await db.owner.execute(sql`
      INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, place, source, source_environment, source_project, version, mac)
      SELECT CAST(${first} AS bigint) + g, CAST(${now - from} AS bigint) + g * CAST(${every} AS bigint), gen_random_uuid(), 1, ${principal},
             ${options.own === true ? sql`(${array(keys.map((key) => key.id))})[1 + g % ${keys.length}]` : sql`gen_random_uuid()`},
             ${options.own === true ? sql`${dev}::uuid` : sql`gen_random_uuid()`}, ${market}::uuid, ${pick(options.forks)},
             ${pick(options.sources)}, ${options.sources === undefined ? sql`NULL::uuid` : sql`gen_random_uuid()`}, ${options.sources === undefined ? sql`NULL::uuid` : sql`${market}::uuid`},
             ${options.own === true ? sql`(${array(keys.map((key) => key.version))})[1 + g % ${keys.length}]` : sql`NULL::uuid`}, decode(repeat('00', 16), 'hex')
        FROM generate_series(1, ${count}) g`);
    // And the days each member's reads are on, as the projector writes them beside the reads.
    await db.owner.execute(sql`
      INSERT INTO log_read_days (principal, day) SELECT DISTINCT principal, CAST(at / 86400000 AS integer) FROM log_reads
       WHERE number > ${first} AND number <= ${first + count} ON CONFLICT DO NOTHING`);
  };
  const reads: Record<string, () => Promise<unknown>> = {
    'every read': () => readsPage(counted, { limit: 100 }),
    "a member's reads": () => readsPage(counted, { actors: [ADA], limit: 100 }),
    "a member's older page": () => readsPage(counted, { actors: [ADA], before: { at: now - 2 * 3_600_000 }, limit: 100 }),
    'how far the reads are listed': () => readsStanding(counted),
    "an offboarding report's reads, and how far they are listed": () => readsByStanding(counted, [ADA]),
    // Whole pages and the report through the API, every statement each makes, the vault's vouching aside.
    'through the API, the whole log': () => root.audit.list({ sealed: '1', limit: 50 }),
    "through the API, a member's page": () => root.audit.list({ actor: ADA, sealed: '1', limit: 50 }),
    "through the API, a member's report": () => root.members.get(ADA),
  };
  const pages = async () => {
    const read: Record<string, { text: string; pages: number | null; plan?: string }[]> = {};
    for (const [name, run] of Object.entries(reads)) {
      await run();
      app.recorded = [];
      await run();
      const statements = [...app.recorded].sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
      app.recorded = null;
      read[name] = [];
      for (const statement of statements) {
        // A report's transaction's own statements read nothing to measure.
        if (!/^\s*(select|with)\b/i.test(statement.text)) continue;
        const work = await app.work(statement);
        read[name].push({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: work?.pages ?? null, plan: work?.plan });
      }
    }
    return read;
  };
  const flat = (small: Awaited<ReturnType<typeof pages>>, grown: Awaited<ReturnType<typeof pages>>, names: readonly string[]) => {
    for (const name of names) {
      const statements = small[name]!;
      assert.deepEqual(grown[name]!.map(({ text }) => text), statements.map(({ text }) => text), `${name} ran other statements`);
      for (const [i, { text, pages: before }] of statements.entries()) {
        const { pages: after, plan } = grown[name]![i]!;
        assert.ok(after !== null && before !== null && after <= 2 * before + 16, `${name}: ${text} read ${after} pages with the log grown, ${before} before:\n${plan}`);
      }
    }
  };
  // Every table's statistics fresh before each measure, so that none flips a plan between two (autovacuum's analyze of
  // audit_log, landing mid-test on CI's slower runner, tipped the directory's walk of it from 159 pages to 380).
  const settle = async () => {
    await db.owner.execute(sql`VACUUM (ANALYZE) log_reads`);
    await db.owner.execute(sql`ANALYZE`);
  };
  try {
    // Today's: 20,000 reads by another member, a tenth in forks and a twentieth through references; and Ada's 2,000 of
    // her keys through the day.
    await plant(18_000, OTHER, 12 * 3_600_000, 2_000);
    await plant(1_000, OTHER, 11 * 3_600_000, 20_000, { forks: 50 });
    await plant(1_000, OTHER, 11 * 3_600_000, 20_000, { sources: 50 });
    await plant(2_000, ADA, 10 * 3_600_000, 15_000, { own: true });
    await settle();
    const small = await pages();
    // A hundred days of others' reads after all of Ada's, each of its own partition, alone first (reviews r6, r8: her
    // page read a probe of each, then her report each whole, whichever plan the others' other reads tipped it to).
    await db.owner.execute(sql`SELECT make_reads_day(CAST(${day(now)} AS date) + d) FROM generate_series(1, ${AHEAD + 1}) d`);
    await plant(20_000, OTHER, -86_400_000, (AHEAD * 86_400_000) / 20_000);
    await settle();
    flat(small, await pages(), Object.keys(reads));
    // Then twenty times the others' since, all newer than what the pages show: reads anywhere, in 5,000 forks, and
    // through references repointed to 20,000 sources between them.
    await plant(300_000, OTHER, 6 * 3_600_000, 50);
    await plant(50_000, OTHER, 5 * 3_600_000, 200, { forks: 5_000 });
    await plant(50_000, OTHER, 5 * 3_600_000, 200, { sources: 20_000 });
    await settle();
    flat(small, await pages(), Object.keys(reads));
    // And Ada's own, older than her page: her pages read as many, her report all of hers, as 0.14's did.
    await plant(100_000, ADA, 20 * 3_600_000, 300, { own: true });
    await settle();
    flat(small, await pages(), ['every read', "a member's reads", 'how far the reads are listed', 'through the API, the whole log', "through the API, a member's page"]);
    // And they read what was planted: full pages, Ada's hers alone, her report each of her keys once.
    const page = (filter: Parameters<typeof readsPage>[1]) => readsPage(counted, filter).then(({ rows }) => rows);
    assert.equal((await page({ limit: 100 })).length, 100);
    const hers = await page({ actors: [ADA], limit: 100 });
    assert.ok(hers.length === 100 && hers.every((read) => read.principal === ADA));
    const report = await readsByStanding(counted, [ADA]);
    assert.deepEqual(new Set(report.reads.map((read) => read.secret)), new Set(keys.map((key) => key.id)));
  } finally {
    await db.owner.execute(sql`DELETE FROM log_reads WHERE number > 5000000`);
    await db.owner.execute(sql`DELETE FROM log_read_days`);
    // The days made ahead, but those the migration made the uses of, which `drop_reads_day` keeps while the log does.
    await db.owner.execute(sql`SELECT drop_reads_day(CAST(${day(now)} AS date) + d) FROM generate_series(1, ${AHEAD + 1}) d`);
  }
});

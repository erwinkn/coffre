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
import { appendEntries } from '@coffre/db/log';
import { localVault } from '@coffre/vault/node';
import { desc, eq, gt, sql } from 'drizzle-orm';

import { Accesses } from '../src/accesses.ts';
import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import {
  distinctSecretCounts, environmentSecrets, insertBinding, liveKeysIn, lock, memberStanding, places, resolvePath, secretFolderOf, secretHeads, secretsInFolder, sensitiveFrom,
} from '../src/db/queries.ts';
import { insertSession } from '../src/db/workloads.ts';
import { fetchApi } from '../src/fetch-api.ts';
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
    this.client = watched(pool, ({ text, values, rows, held }) => {
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
   * failure fails the test.
   */
  async work(statement: Statement): Promise<{ pages: number; plan: string } | null> {
    const rolledBack = new Error('rolled back');
    let work: { pages: number; plan: string } | null = null;
    await this.#pool.begin(async (tx) => {
      try {
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
  });
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
  await Promise.all([app.end(), vaultPool.end(), db.close()]);
});

/**
 * Each request once, unmeasured: what the vault does once per process, or
 * once a caller's access or the policy changed, is done before a request
 * is counted. A CI run's credential near its end is bought again first.
 */
async function warm(): Promise<void> {
  if (ciEnds - Date.now() < 120_000) await buyCi();
  renewProxy();
  for (const { request } of Object.values(requests)) await request();
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
  "a request's check of its caller": { request: () => reader.me(), budget: { app: 2, vault: 2, vaultCalls: 2 } },
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
});

/**
 * R48: a request's work in the database does not grow with the log. Each
 * statement of each hot request, run again under EXPLAIN, reads as many
 * pages of the database (shared buffers, cached or not) on a log of ten
 * thousand entries as on one ten times longer, grown as Equisafe's grows:
 * the vault's reads of a few principals and the proxy's uses, over the last
 * day, some within the bulk limit's window. No statement scans the log, nor
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
      WITH e AS (SELECT * FROM audit_log WHERE seq >= 0 AND action IN ('secret.read', 'credential.use'))
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

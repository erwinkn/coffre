import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type pg from 'pg';

import { shownMember } from '@coffre/core/schemas';
import type { Role } from '@coffre/core/access';
import { github, signin, type BindingClaims, type RateLimiter, type WorkloadProfile } from '@coffre/core/identity';
import { createDatabase, type Database } from '@coffre/db';
import { asc, eq, sql, type SQL } from 'drizzle-orm';

import { auditLog, consumedTokens, credentials, serviceBindings } from './db/tables.ts';
import { authMac } from '../src/auth-rows.ts';
import { answer, type Pages } from './start-fixture.ts';
import { resolveConfig } from '../src/config.ts';
import { runScheduled } from '../src/app.ts';
import { exchangeCandidates, exchangesSince, pruneSpentTokens } from '../src/db/queries.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { postgresOnly, TEST_ENGINE } from './db/engine.ts';
import { testPostgresPool } from './db/postgres-pool.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'api-deploy';
const MEMBER = `token:${SERVICE}`;
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const IP = '203.0.113.9';

/** `deploy.yml`, pushed to `main` of `acme/api`. */
const DEPLOY: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};

type Key = { kid: string; alg: 'RS256' | 'ES256'; privateKey: KeyObject; jwk: Record<string, unknown> };

function key(alg: Key['alg'], kid: string): Key {
  const { privateKey, publicKey } = alg === 'RS256'
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kid, alg, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' } };
}

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

/** A token as GitHub would sign it for a run of `deploy.yml` on main, for this instance. */
function token(by: Key, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}): string {
  const input = `${part({ alg: by.alg, kid: by.kid, typ: 'JWT', ...header })}.${part({
    iss: ISSUER,
    aud: ORIGIN,
    sub: 'repo:acme/api:ref:refs/heads/main',
    iat: seconds() - 5,
    exp: seconds() + 295,
    jti: crypto.randomUUID(),
    run_id: '7001',
    sha: 'f'.repeat(40),
    repository: 'acme/api',
    ...DEPLOY,
    ...claims,
  })}`;
  const signature = by.alg === 'RS256'
    ? signWith('sha256', Buffer.from(input), by.privateKey)
    : signWith('sha256', Buffer.from(input), { key: by.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let config: ReturnType<typeof resolveConfig>;
let rsa: Key;
let ec: Key;
/** What the issuer publishes, by URL; `down` makes it unreachable, `hold` keeps a fetch waiting. */
let published: Map<string, unknown>;
let issuer: { down: boolean; fetches: number; hold?: () => Promise<void> };
let limits: { perSource: RateLimiter; total: RateLimiter };
let vaultCalls: number;
/** Waited for before the vault is asked about the member: the last step before the commit. */
let beforeAccess: (() => Promise<void>) | undefined;
/** The binding every test starts with, of `deploy.yml` on main. */
let bound: string;

const transport: WorkloadTransport = {
  json: async (url) => {
    issuer.fetches++;
    await issuer.hold?.();
    if (issuer.down || !published.has(url.href)) throw new FetchRefused(url, issuer.down ? 'could not be fetched' : 'answered 404');
    return published.get(url.href);
  },
};

before(async () => {
  db = await openTestDatabase();
  [rsa, ec] = [key('RS256', 'rs-1'), key('ES256', 'es-1')];
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetKeys();
  issuer = { down: false, fetches: 0 };
  published = new Map<string, unknown>([
    [`${ISSUER}/.well-known/openid-configuration`, { issuer: ISSUER, jwks_uri: KEYS }],
    [KEYS, { keys: [rsa.jwk, ec.jwk] }],
  ]);
  limits = processLimits({ perSource: 1000, total: 1000 });
  deps = testDeps(db.runtime, [ROOT]);
  vaultCalls = 0;
  beforeAccess = undefined;
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    vaultCalls++;
    await beforeAccess?.();
    return access(principal);
  };
  config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: { perSource: { limit: (o) => limits.perSource.limit(o) }, total: { limit: (o) => limits.total.limit(o) } } } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport);
  for (const [principal, owner] of [[`user:${DEV}`, false], [MEMBER, false]] as const) {
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal, ...(owner ? { role: 'admin' as const } : {}) })).ok, true);
  }
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
  bound = await bind(DEPLOY);
});

async function bind(claims: BindingClaims, replaces: string[] = [], profile: WorkloadProfile = 'github'): Promise<string> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile, issuer: null, claims, label: 'deploys', replaces }, { dryRun: false });
  assert.ok('binding' in made);
  return made.binding.id;
}

const ui = {} as Pages;

async function exchange(body: unknown, sourceIp: string | null = IP): Promise<{ status: number; body: Record<string, string> }> {
  const response = await answer(
    new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body) }),
    runtime,
    ui,
    sourceIp,
  );
  return { status: response.status, body: (await response.json()) as Record<string, string> };
}

const trade = (jwt: string, service = MEMBER) => exchange({ service, token: jwt });

/** Who a credential reads as, through the API: the service, or a 401. */
async function caller(credential: string): Promise<number | string> {
  const response = await answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${credential}` } }), runtime, ui, IP);
  if (response.status !== 200) return response.status;
  const me = (await response.json()) as { principal: { type: string; id: string } };
  return `${me.principal.type}:${me.principal.id}`;
}

async function appEntries(action: string) {
  const rows = await db.owner.select({ actor: auditLog.actor, decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog).where(eq(auditLog.action, action)).orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test("a run's token buys a five-minute credential of the service, logged with its run, reading as the service", async () => {
  const before = Date.now();
  const { status, body } = await trade(token(rsa));
  assert.equal(status, 200, JSON.stringify(body));
  assert.match(body.token!, /^coffre_svc_/);
  const lifetime = Date.parse(body.expiresAt!) - before;
  assert.ok(lifetime > 4 * 60_000 && lifetime <= 5 * 60_000 + 1000, `lives five minutes, not ${lifetime} ms`);
  assert.equal(await caller(body.token!), `service:${SERVICE}`);

  const [entry] = await appEntries('token.exchange');
  assert.equal(entry!.actor, MEMBER);
  assert.equal(entry!.decision, 'allow');
  assert.deepEqual(Object.keys(entry!.metadata).sort(), ['bindingId', 'credentialId', 'expiresAt', 'generation', 'issuer', 'run']);
  assert.deepEqual((entry!.metadata.run as Record<string, unknown>).run_id, '7001');
  // The service's token list is for tokens people keep.
  assert.deepEqual((await runtime.signin!.listTokens(await contextFor(deps, ROOT), { type: 'service', id: SERVICE })), []);
  const [binding] = await db.owner.select().from(serviceBindings);
  assert.notEqual(binding!.lastUsedAt, null);
  // An ES256 issuer is the same.
  assert.equal((await trade(token(ec))).status, 200);
});

test("a run's credential reaches what both its binding's scope and the account hold: a grant the account gets later reaches no binding made before", async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key` });
  }
  await root.access.set(MEMBER, { 'market/dev': 'developer' });
  // A binding made now takes what the account holds now, or less when told; one that replaces another, what that one reached.
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY, label: null, replaces: [] }, { dryRun: false });
  assert.ok('binding' in made);
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });

  const reveal = async (credential: string, path: string) =>
    (await answer(new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }), runtime, ui, IP)).status;
  const credential = (await trade(token(rsa))).body.token!;
  assert.equal(await reveal(credential, 'market/dev'), 200);
  assert.equal(await reveal(credential, 'market/prod'), 403, "the account's later grant does not reach the run");
  // Narrowing the account narrows the run's credential at once.
  await root.access.set(MEMBER, { 'market/dev': null });
  assert.equal(await reveal(credential, 'market/dev'), 403);
  assert.deepEqual(made.binding.scope, { 'api-deploy-reads': 'viewer', 'market/dev': 'developer' });
  // A binding is made at most as wide as the account, whoever makes it.
  await assert.rejects(
    runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY, scope: { 'market/dev': 'viewer' }, label: null, replaces: [] }, { dryRun: true }),
    { status: 403 },
  );
});

test('a binding 0.4 makes after the app sealed is sealed by its first exchange, and a run credential of one by its first check: an account widened after reaches neither', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key` });
  }
  await root.access.set(MEMBER, { 'market/dev': 'developer' });
  // The app checks a credential, and so seals what there is, before 0.4 makes one.
  assert.equal(await caller((await trade(token(rsa))).body.token!), `service:${SERVICE}`);
  /** Put `id` back as 0.4 would have made it: no scope, its MAC over 0.4's tuple. */
  const unseal = async (id: string) => {
    const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id));
    const { authMac: _, ...fields } = { ...row!, scope: null };
    await db.owner.update(serviceBindings).set({ scope: null, authMac: authMac(deps.chainKey, 'service_bindings', fields) }).where(eq(serviceBindings.id, id));
  };
  const scope = async () => (await db.owner.select({ scope: serviceBindings.scope }).from(serviceBindings).where(eq(serviceBindings.id, bound)))[0]!.scope;
  const seals = async () => (await appEntries('token.seal')).map((entry) => entry.metadata.bindings);
  const reveal = async (credential: string, path: string) =>
    (await answer(new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }), runtime, ui, IP)).status;

  await unseal(bound);
  const first = (await trade(token(rsa))).body.token!;
  assert.notEqual(await scope(), null, 'sealed as it exchanged, before the run used its credential');
  assert.deepEqual(await seals(), [[bound]]);
  // A run's credential whose binding carries no scope, as one 0.4's binding issued: its first check seals the binding.
  await unseal(bound);
  assert.equal(await reveal(first, 'market/dev'), 200);
  assert.notEqual(await scope(), null);
  assert.deepEqual(await seals(), [[bound], [bound]]);

  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  const later = (await trade(token(rsa))).body.token!;
  for (const credential of [first, later]) {
    assert.equal(await reveal(credential, 'market/prod'), 403, "the account's later grant reaches no run");
    assert.equal(await reveal(credential, 'market/dev'), 200);
  }
});

test("a binding's scope of the wrong shape is refused before its issuer is asked anything", async () => {
  const fetches = issuer.fetches;
  const shapes: Record<string, Role>[] = [{ 'market/dev/KEY': 'viewer' }, { 'market/dev': 'owner' }];
  for (const scope of shapes) {
    await assert.rejects(
      runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY, scope, label: null, replaces: [] }, { dryRun: true }),
      { status: 400 },
    );
  }
  assert.equal(issuer.fetches, fetches);
});

test('a token is spent once used, in any spelling: the ES256 twin of a signature is refused as replayed', async () => {
  const jwt = token(ec);
  assert.equal((await trade(jwt)).status, 200);
  assert.deepEqual(await trade(jwt), { status: 401, body: { error: 'unauthenticated', reason: 'replayed', message: 'this token was exchanged already: ask your CI for a fresh one' } });
  const [input, signature] = [jwt.slice(0, jwt.lastIndexOf('.')), Buffer.from(jwt.slice(jwt.lastIndexOf('.') + 1), 'base64url')];
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt(`0x${signature.subarray(32).toString('hex')}`);
  const twin = `${input}.${Buffer.concat([signature.subarray(0, 32), Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex')]).toString('base64url')}`;
  assert.equal((await trade(twin)).body.reason, 'replayed');
  // Two at once: one buys a credential, the other finds it spent.
  const both = token(rsa);
  const outcomes = await Promise.all([trade(both), trade(both)]);
  assert.deepEqual(outcomes.map((outcome) => outcome.status).sort(), [200, 401]);
  assert.equal((await db.owner.select().from(credentials)).length, 2, 'one for the first token, one for the pair');
});

test('the scheduled beat forgets a token two hours after it was spent, never sooner, and a bounded number at a time', async () => {
  const jwt = token(ec);
  assert.equal((await trade(jwt)).status, 200);
  // Records the owner dates: three spent just over two hours ago, one just under.
  const spent = (byte: number, minutes: number) => ({ hash: Buffer.alloc(32, byte), consumedAt: new Date(Date.now() - minutes * 60_000) });
  await db.owner.insert(consumedTokens).values([spent(1, 121), spent(2, 121), spent(3, 121), spent(4, 119)]);
  // Which of those are left, by their byte.
  const left = async () => (await db.owner.select({ hash: consumedTokens.hash }).from(consumedTokens))
    .flatMap(({ hash }) => (hash.equals(Buffer.alloc(32, hash[0])) ? [hash[0]] : [])).sort().join();
  assert.equal(await pruneSpentTokens(db.runtime, 2), 2);
  assert.equal((await left()).split(',').length, 2);
  await runScheduled(runtime);
  assert.equal(await left(), '4', 'the beat took the third, and the young one stays');
  assert.equal(await pruneSpentTokens(db.runtime, 10), 0);
  assert.equal((await trade(jwt)).body.reason, 'replayed', 'the token just spent stays spent');
});

test('refusals say why, never what a binding expects, and a stranger never reaches the vault', async () => {
  const reason = async (jwt: string, service = MEMBER) => (await trade(jwt, service)).body;
  // The claims that differ, by name.
  const feature = await reason(token(rsa, { ref: 'refs/heads/feature', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/feature' }));
  assert.deepEqual([feature.reason, feature.message], ['no_match', `no binding of ${shownMember(MEMBER)} trusts these claims: ref, workflow_ref differ`]);
  assert.ok(!feature.message!.includes('refs/heads/main'));
  assert.equal((await reason(token(rsa, { event_name: 'pull_request_target' }))).reason, 'no_match');
  assert.equal((await reason(token(rsa, { repository_id: '1' }))).reason, 'no_match');
  // An unknown service and an issuer it does not trust answer alike, before any vault call or fetch.
  vaultCalls = 0;
  issuer.fetches = 0;
  const nobody = await reason(token(rsa), 'token:nobody');
  const elsewhere = await reason(token(rsa, { iss: 'https://gitlab.com' }));
  assert.deepEqual([nobody.reason, elsewhere.reason], ['no_match', 'no_match']);
  assert.equal(nobody.message, `no binding of service:nobody trusts tokens from ${ISSUER}`);
  assert.equal(await reason(token(rsa), `user:${DEV}`).then((body) => body.reason), 'no_match');
  assert.equal((await reason('not.a.token')).reason, 'malformed');
  assert.deepEqual([vaultCalls, issuer.fetches], [0, 0], 'a stranger costs no vault call and no fetch');
  // Its times, its audience, its signature.
  assert.equal((await reason(token(rsa, { exp: seconds() - 60 }))).reason, 'expired');
  assert.equal((await reason(token(rsa, { iat: seconds() - 3700 }))).reason, 'too_old');
  assert.equal((await reason(token(rsa, { nbf: seconds() + 120 }))).reason, 'not_yet_valid');
  assert.equal((await reason(token(rsa, { aud: 'https://other.example' }))).reason, 'audience');
  assert.equal((await reason(token(rsa, { aud: [ORIGIN, 'https://other.example'] }))).reason, 'audience');
  const forged = token(rsa);
  assert.equal((await reason(`${forged.slice(0, forged.lastIndexOf('.'))}.${Buffer.alloc(256).toString('base64url')}`)).reason, 'signature');
  assert.equal(vaultCalls, 0, 'nor does a token that does not verify');
  // None of it is in the audit log.
  assert.deepEqual(await appEntries('token.exchange'), []);
});

type Statement = { text: string; values: unknown[]; rows: number };

/** `pool`, telling `seen` every statement it sends to the server, inside a transaction or not, and how many rows it answered. */
function counted(pool: pg.Pool, seen: Statement[]): pg.Pool {
  const watch = <T extends object>(target: T): T => new Proxy(target, {
    get(on, key) {
      const value: unknown = Reflect.get(on, key, on);
      if (typeof value !== 'function') return value;
      if (key === 'query') {
        return async (query: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          const statement = typeof query === 'string'
            ? { text: query, values: values ?? [], rows: 0 }
            : { text: query.text, values: query.values ?? values ?? [], rows: 0 };
          seen.push(statement);
          const result = (await value.call(on, query, values)) as { rowCount?: number | null };
          statement.rows = result.rowCount ?? 0;
          return result;
        };
      }
      if (key === 'connect') return async () => watch(await value.call(on));
      return value.bind(on);
    },
  });
  return watch(pool);
}

test('a token no binding can take costs its admission and one indexed read: no other query, no transaction, no vault call, no fetch', postgresOnly('it counts the statements that reach the server'), async () => {
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const seen: Statement[] = [];
  try {
    const stranger = createRuntime(config, createDatabase(counted(pool, seen)), deps.vault, transport);
    // The door's read of the migrations is the isolate's, once, not an exchange's (app.ts).
    stranger.schema.migrated = true;
    /** What one exchange cost: the statements it sent, its vault calls and its fetches. */
    const ask = async (service: string, jwt: string) => {
      seen.length = 0;
      [vaultCalls, issuer.fetches] = [0, 0];
      const response = await answer(
        new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service, token: jwt }) }),
        stranger, ui, IP,
      );
      const { reason } = (await response.json()) as { reason?: string };
      return { status: response.status, reason, statements: seen.map((statement) => statement.text), vaultCalls, fetches: issuer.fetches };
    };
    /** Each one refused for its reason, on one read of the bindings: no other statement, no vault call, no fetch but `fetches`. */
    const refused = async (cases: (readonly [string, string, string, number?])[]) => {
      for (const [service, jwt, reason, fetches = 0] of cases) {
        const { statements, ...rest } = await ask(service, jwt);
        assert.deepEqual({ ...rest, statements: statements.length }, { status: 401, reason, statements: 1, vaultCalls: 0, fetches }, statements.join('\n'));
        assert.match(statements[0]!, /from "service_bindings"/);
      }
    };
    // Not a token at all: nothing reaches the database.
    assert.deepEqual(await ask(MEMBER, 'not.a.token'), { status: 401, reason: 'malformed', statements: [], vaultCalls: 0, fetches: 0 });
    // A service with no binding, and an issuer the service's binding does not name.
    await refused([['token:nobody', token(rsa), 'no_match'], [MEMBER, token(rsa, { iss: 'https://gitlab.com' }), 'no_match']]);
    // On the issuer it does name: a forged signature, its keys fetched once; then the issuer's own token for another branch.
    const genuine = token(rsa);
    const forged = `${genuine.slice(0, genuine.lastIndexOf('.'))}.${Buffer.alloc(256).toString('base64url')}`;
    await refused([
      [MEMBER, forged, 'signature', 1],
      [MEMBER, token(rsa, { ref: 'refs/heads/feature', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/feature' }), 'no_match'],
    ]);
    // The binding removed: its token is a stranger's too.
    const id = (await db.owner.select().from(serviceBindings))[0]!.id;
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, id);
    await refused([[MEMBER, token(rsa), 'no_match']]);
  } finally {
    await pool.end();
  }
});

/**
 * `pool` as a Hyperdrive config with caching on answers it outside
 * transactions: a read that calls no stable or volatile function is answered
 * with what it returned the first time, and writes invalidate nothing
 * (developers.cloudflare.com/hyperdrive/concepts/query-caching). Its cache
 * here lasts the test, where Hyperdrive's lasts a minute by default.
 */
function hyperdriveCached(pool: pg.Pool): pg.Pool {
  const cache = new Map<string, unknown>();
  const UNCACHEABLE = /\b(now|current_timestamp|current_date|current_time|localtime|localtimestamp|clock_timestamp|statement_timestamp|txid_current|timeofday|random|lastval)\b/i;
  return new Proxy(pool, {
    get(on, key) {
      const value: unknown = Reflect.get(on, key, on);
      if (typeof value !== 'function') return value;
      if (key !== 'query') return value.bind(on);
      return async (query: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
        const text = typeof query === 'string' ? query : query.text;
        if (!/^\s*select\b/i.test(text) || / for update\b/i.test(text) || UNCACHEABLE.test(text)) return value.call(on, query, values);
        const keyed = JSON.stringify([text, typeof query === 'string' ? values : (query.values ?? values)]);
        if (!cache.has(keyed)) cache.set(keyed, await value.call(on, query, values));
        return cache.get(keyed);
      };
    },
  });
}

test("Hyperdrive's cache revives nothing: rows put back after a removal stay dead, and a replay never reaches the vault", postgresOnly('it models Hyperdrive, which caches Postgres reads'), async () => {
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  try {
    const cached = createRuntime(config, createDatabase(hyperdriveCached(pool)), deps.vault, transport);
    const send = (request: Request) => answer(request, cached, ui, IP);
    const trade = async (jwt: string) => {
      const response = await send(new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: jwt }) }));
      return { status: response.status, body: (await response.json()) as Record<string, string> };
    };
    const me = async (credential: string) => (await send(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${credential}` } }))).status;

    const jwt = token(rsa);
    const { body } = await trade(jwt);
    assert.equal(await me(body.token!), 200);
    // The same token again: spent, said before the vault is asked.
    vaultCalls = 0;
    assert.deepEqual([(await trade(jwt)).body.reason, vaultCalls], ['replayed', 0]);

    const [binding] = await db.owner.select().from(serviceBindings);
    const [credential] = await db.owner.select().from(credentials);
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, binding!.id);
    assert.equal(await me(body.token!), 401);
    // Whoever owns the database puts both rows back as they were: the tombstone is read afresh, and holds.
    await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: binding!.authMac }).where(eq(serviceBindings.id, binding!.id));
    await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: credential!.authMac }).where(eq(credentials.id, credential!.id));
    assert.equal(await me(body.token!), 401);
  } finally {
    await pool.end();
  }
});

type PlanNode = {
  'Relation Name'?: string;
  'Index Name'?: string;
  'Actual Rows'?: number;
  'Actual Loops'?: number;
  'Rows Removed by Filter'?: number;
  Plans?: PlanNode[];
};

/**
 * How `statement` ran, by EXPLAIN ANALYZE: every index it used, and how
 * many rows of `table` it visited, kept or filtered out, over every loop.
 */
async function planOf(pool: pg.Pool, statement: Statement, table: string): Promise<{ indexes: string[]; visited: number }> {
  const { rows: [explained] } = await pool.query(`EXPLAIN (ANALYZE, FORMAT JSON) ${statement.text}`, statement.values);
  const nodes: PlanNode[] = [];
  const walk = (node: PlanNode) => {
    nodes.push(node);
    node.Plans?.forEach(walk);
  };
  walk((explained as { 'QUERY PLAN': { Plan: PlanNode }[] })['QUERY PLAN'][0]!.Plan);
  return {
    indexes: nodes.flatMap((node) => node['Index Name'] ?? []),
    visited: nodes
      .filter((node) => node['Relation Name'] === table)
      .reduce((n, node) => n + ((node['Actual Rows'] ?? 0) + (node['Rows Removed by Filter'] ?? 0)) * (node['Actual Loops'] ?? 1), 0),
  };
}

test("an exchange's first read visits the live bindings only, whatever the retired and earlier history", postgresOnly('it reads Postgres query plans'), async () => {
  const [live] = await db.owner.select().from(serviceBindings);
  // 50,000 replaced over the years, and 5,000 left from before the service was removed and admitted again.
  for (const [count, generation, revoked] of [[50_000, live!.generation, true], [5_000, live!.generation - 1, false]] as const) {
    await run(sql`INSERT INTO service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, claims, created_by, created_at, revoked_at, revoked_by)
      SELECT gen_random_uuid(), decode(repeat('00', 32), 'hex'), ${MEMBER}, ${generation}, 'github', ${ISSUER}, ${KEYS}, '{}', 'history',
        now() - interval '30 days', ${revoked ? sql`now() - interval '1 day'` : sql`NULL`}, ${revoked ? 'history' : null}
      FROM generate_series(1, ${count})`);
  }
  await run(sql`ANALYZE service_bindings`);
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const seen: Statement[] = [];
  try {
    const candidates = await exchangeCandidates(createDatabase(counted(pool, seen)), deps.chainKey, MEMBER, ISSUER, 16);
    assert.deepEqual(candidates.map((candidate) => candidate.id), [live!.id]);
    const plan = await planOf(pool, seen.find((statement) => /from "service_bindings"/i.test(statement.text))!, 'service_bindings');
    assert.ok(plan.indexes.includes('service_bindings_live_idx'), plan.indexes.join(', '));
    assert.ok(plan.visited <= 2, `visited ${plan.visited} binding rows for one live binding`);
  } finally {
    await pool.end();
  }
});

test("a binding's rate is counted over its last minute, whatever the credentials it issued before", postgresOnly('it reads Postgres query plans'), async () => {
  const [binding] = await db.owner.select().from(serviceBindings);
  // 50,000 runs a month ago, each with its credential, expired since; then one now.
  await run(sql`INSERT INTO credentials (kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at)
    SELECT 'service', decode(repeat('00', 32), 'hex'), sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'coffre_svc_…', ${binding!.generation}, ${MEMBER},
      ${`binding:${binding!.id}`}, now() - interval '30 days', now() - interval '30 days' + interval '5 minutes'
    FROM generate_series(1, 50000)`);
  await run(sql`ANALYZE credentials`);
  assert.equal((await trade(token(rsa))).status, 200);
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const seen: Statement[] = [];
  try {
    const recent = await exchangesSince(createDatabase(counted(pool, seen)), MEMBER, `binding:${binding!.id}`, new Date(Date.now() - 60_000), 60);
    assert.equal(recent, 1);
    const plan = await planOf(pool, seen.find((statement) => /from "credentials"/i.test(statement.text))!, 'credentials');
    assert.ok(plan.indexes.includes('credentials_issued_by_idx'), plan.indexes.join(', '));
    assert.ok(plan.visited <= 2, `visited ${plan.visited} credential rows for one recent credential`);
  } finally {
    await pool.end();
  }
});

test('removing a binding revokes only what is live: its expired history costs nothing there, nor on the members page', postgresOnly('it counts the statements and rows that reach the server'), async () => {
  const [binding] = await db.owner.select().from(serviceBindings);
  // A thousand runs long over, and one under way.
  const over = new Date(Date.now() - 3_600_000);
  await db.owner.transaction(async (tx) => {
    for (let i = 0; i < 1000; i++) {
      await runtime.signin!.issueExchanged(tx, SERVICE, { generation: binding!.generation, bindingId: binding!.id, label: null, expiresAt: over });
    }
  });
  // Issued then, too, outside the binding's rate; the MAC does not cover when.
  await db.owner.update(credentials).set({ createdAt: new Date(over.getTime() - 300_000) }).where(eq(credentials.expiresAt, over));
  const { body } = await trade(token(rsa));
  assert.ok(body.token, JSON.stringify(body));
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const seen: Statement[] = [];
  try {
    const counting = { ...deps, db: createDatabase(counted(pool, seen)) };
    const read = (table: string) => seen.filter((statement) => new RegExp(`from "${table}"`, 'i').test(statement.text)).reduce((n, statement) => n + statement.rows, 0);
    await createRuntime(config, counting.db, deps.vault, transport).workloads!.unbind(await contextFor(counting, ROOT), SERVICE, binding!.id);
    assert.equal(seen.filter((statement) => /^update "credentials"/i.test(statement.text)).length, 1, 'the run under way, not the thousand over');
    assert.ok(read('credentials') <= 2, `read ${read('credentials')} credential rows`);
    assert.equal(await caller(body.token!), 401);
    seen.length = 0;
    await clientFor(counting, ROOT).members.list();
    assert.equal(read('credentials'), 0, 'no credential is live, so the members page reads none');
  } finally {
    await pool.end();
  }
});

test("a revocation is its caller's act: the credential it ends is its target, never the entry's run", async () => {
  /** A run's credential, by its run_id: the token, and its ID from the exchange's entry. */
  const runOf = async (runId: string) => {
    const { body } = await trade(token(rsa, { run_id: runId }));
    const entry = (await appEntries('token.exchange')).find((exchange) => (exchange.metadata.run as { run_id?: string }).run_id === runId);
    return { token: body.token!, id: entry!.metadata.credentialId as string };
  };
  const [a, b, c] = [await runOf('7001'), await runOf('7002'), await runOf('7003')];
  const revoke = (credential: string, id: string) =>
    answer(new Request(`${ORIGIN}/api/sessions/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${credential}` } }), runtime, ui, IP);
  // Run A revokes a credential that is no one's, then run B's, its own service's.
  const nobody = '22222222-2222-4222-8222-222222222222';
  assert.equal((await revoke(a.token, nobody)).status, 404);
  assert.equal((await revoke(a.token, b.id)).status, 200);
  // The Owner, signed in as a person, revokes run C's.
  await runtime.signin!.revokeCredential(await contextFor(deps, ROOT), c.id);

  const revocations = (await appEntries('token.revoke')).map(({ actor, decision, metadata }) => ({
    actor, decision, credentialId: metadata.credentialId, targetCredentialId: metadata.targetCredentialId,
  }));
  assert.deepEqual(revocations, [
    { actor: MEMBER, decision: 'deny', credentialId: a.id, targetCredentialId: nobody },
    { actor: MEMBER, decision: 'allow', credentialId: a.id, targetCredentialId: b.id },
    { actor: `user:${ROOT}`, decision: 'allow', credentialId: undefined, targetCredentialId: c.id },
  ]);
  // On the audit page: A's run for A's two, and no run for the admin's.
  const { entries } = await clientFor(deps, ROOT).audit.list({ detail: '1' });
  const shown = entries.filter((entry) => entry.action === 'token.revoke').sort((x, y) => x.seq - y.seq).map((entry) => entry.run?.claims.run_id ?? null);
  assert.deepEqual(shown, ['7001', '7001', null]);
});

test('a key the issuer rotated in is fetched once; while the issuer cannot be reached, a 503, and cached keys still work', async () => {
  assert.equal((await trade(token(rsa))).status, 200);
  const rotated = key('RS256', 'rs-2');
  published.set(KEYS, { keys: [rsa.jwk, rotated.jwk] });
  issuer.fetches = 0;
  assert.equal((await trade(token(rotated))).status, 200);
  assert.equal(issuer.fetches, 1);
  // Another unknown key within the minute: not fetched again.
  const unknown = await trade(token(key('RS256', 'rs-3')));
  assert.deepEqual([unknown.status, unknown.body.reason], [503, 'issuer_unavailable']);
  assert.equal(issuer.fetches, 1);
  // The issuer down: fresh cached keys still verify.
  issuer.down = true;
  assert.equal((await trade(token(rsa))).status, 200);
  forgetKeys();
  const down = await trade(token(rsa));
  assert.deepEqual([down.status, down.body.reason], [503, 'issuer_unavailable']);
});

test('removing a binding ends its credentials at once; a denied attempt changes nothing; rows put back stay dead', async () => {
  const id = (await db.owner.select().from(serviceBindings))[0]!.id;
  const { body } = await trade(token(rsa));
  const credential = body.token!;
  const [row] = await db.owner.select().from(serviceBindings);
  const [issued] = await db.owner.select().from(credentials);

  // Someone who does not manage it tries: logged as a denial, and the credential still works.
  const devContext = await contextFor(deps, DEV);
  await assert.rejects(runtime.workloads!.unbind(devContext, SERVICE, id), /only those who manage this service account may remove its trust bindings/);
  assert.equal(await caller(credential), `service:${SERVICE}`);
  assert.equal((await trade(token(rsa))).status, 200, 'its entry is no tombstone');

  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, id);
  assert.equal(await caller(credential), 401);
  assert.equal((await trade(token(rsa))).body.reason, 'no_match');

  // Whoever owns the database puts both rows back, MACs and all: the tombstone holds.
  await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: row!.authMac }).where(eq(serviceBindings.id, id));
  await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: issued!.authMac }).where(eq(credentials.id, issued!.id));
  assert.equal(await caller(credential), 401);
  assert.equal((await trade(token(rsa))).body.reason, 'no_match');
  // And cutting the link to the binding breaks the credential's MAC instead.
  await db.owner.update(credentials).set({ createdBy: `user:${ROOT}` }).where(eq(credentials.id, issued!.id));
  assert.equal(await caller(credential), 401);
});

test('an exchange racing a removal never leaves a credential the removal missed', async () => {
  const id = (await db.owner.select().from(serviceBindings))[0]!.id;
  const root = await contextFor(deps, ROOT);
  const [exchanged] = await Promise.all([trade(token(rsa)), runtime.workloads!.unbind(root, SERVICE, id)]);
  if (exchanged.status === 200) assert.equal(await caller(exchanged.body.token!), 401);
  // A service removed, then admitted again: its old binding signs no one in.
  await bind(DEPLOY);
  const { body } = await trade(token(rsa));
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  assert.equal(await caller(body.token!), 401);
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  assert.equal(await caller(body.token!), 401);
  assert.equal((await trade(token(rsa))).body.reason, 'no_match');
});

test('one binding trusts a workflow on several events: a pull request into its branch, by its own run, and the push, but no other event', async () => {
  const ci = {
    ...DEPLOY,
    workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main',
    event_name: ['push', 'pull_request'],
  };
  await bind(ci, [await bindingId()]);
  const pr = {
    workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/pull/12/merge',
    ref: 'refs/pull/12/merge',
    base_ref: 'main',
    head_ref: 'feature',
    event_name: 'pull_request',
    sub: 'repo:acme/api:pull_request',
  };
  assert.equal((await trade(token(rsa, { workflow_ref: ci.workflow_ref }))).status, 200);
  const { status, body } = await trade(token(rsa, pr));
  assert.equal(status, 200, JSON.stringify(body));
  // Its entry says which pull request: its merge ref, and the branches it goes from and into.
  const run = (await appEntries('token.exchange')).at(-1)!.metadata.run as Record<string, unknown>;
  assert.deepEqual([run.event_name, run.ref, run.base_ref, run.head_ref], ['pull_request', 'refs/pull/12/merge', 'main', 'feature']);
  // Into another branch, or another event at the same ref, no binding takes it.
  const elsewhere = await trade(token(rsa, { ...pr, base_ref: 'release' }));
  assert.deepEqual([elsewhere.body.reason, elsewhere.body.message], ['no_match', `no binding of ${shownMember(MEMBER)} trusts these claims: ref, workflow_ref differ`]);
  assert.equal((await trade(token(rsa, { workflow_ref: ci.workflow_ref, event_name: 'workflow_dispatch' }))).body.reason, 'no_match');
});

/** The service's one live binding. */
async function bindingId(): Promise<string> {
  const [binding] = await db.owner.select({ id: serviceBindings.id }).from(serviceBindings);
  return binding!.id;
}

test("a reusable workflow's binding names its caller's ref: a feature branch calling the same pinned commit is refused", async () => {
  const called = { job_workflow_ref: 'acme/workflows/.github/workflows/deploy.yml@refs/tags/v1', job_workflow_sha: 'a'.repeat(40) };
  const id = await bind({ repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push', ...called }, [], 'github-reusable');
  const caller = (ref: string) => ({ ...called, ref, workflow_ref: `acme/api/.github/workflows/release.yml@${ref}` });
  const feature = (await trade(token(rsa, caller('refs/heads/feature')))).body;
  assert.deepEqual([feature.reason, feature.message], ['no_match', `no binding of ${shownMember(MEMBER)} trusts these claims: ref differ`]);
  assert.equal((await trade(token(rsa, caller('refs/heads/main')))).status, 200);
  assert.equal((await appEntries('token.exchange'))[0]!.metadata.bindingId, id);
});

test('a binding that names a GitHub environment takes only jobs in it, whatever their sub, the plain and the reusable profile alike', async () => {
  const id = await bind({ ...DEPLOY, environment: 'production' }, [bound]);
  const inside = (environment: string) => ({ environment, sub: `repo:acme/api:environment:${environment}` });
  // GitHub names the environment in sub, which no GitHub binding reads; ref and workflow_ref stay as they were.
  assert.equal((await trade(token(rsa, inside('production')))).status, 200);
  assert.equal((await trade(token(rsa, inside('Production')))).status, 200, 'GitHub environment names are case-insensitive');
  const staging = (await trade(token(rsa, inside('staging')))).body;
  assert.deepEqual([staging.reason, staging.message], ['no_match', `no binding of ${shownMember(MEMBER)} trusts these claims: environment differ`]);
  assert.equal((await trade(token(rsa))).body.reason, 'no_match', 'a job in no environment');
  assert.equal(((await appEntries('token.exchange')).at(-1)!.metadata.run as Record<string, unknown>).environment, 'Production');

  const called = { job_workflow_ref: 'acme/workflows/.github/workflows/deploy.yml@refs/tags/v1', job_workflow_sha: 'a'.repeat(40) };
  await bind({ repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push', ...called, environment: 'production' }, [id], 'github-reusable');
  const caller = { ...called, workflow_ref: 'acme/api/.github/workflows/release.yml@refs/heads/main' };
  assert.equal((await trade(token(rsa, { ...caller, ...inside('production') }))).status, 200);
  assert.equal((await trade(token(rsa, caller))).body.reason, 'no_match');
});

test('a GitLab binding names the namespace by ID: the same project moved to another namespace is refused', async () => {
  const gitlab = 'https://gitlab.com';
  published.set(`${gitlab}/.well-known/openid-configuration`, { issuer: gitlab, jwks_uri: `${gitlab}/oauth/discovery/keys` });
  published.set(`${gitlab}/oauth/discovery/keys`, { keys: [rsa.jwk] });
  const pipeline = { namespace_id: '77', project_id: '4242', ref_type: 'branch', ref: 'main', pipeline_source: 'push' };
  await bind(pipeline, [], 'gitlab');
  const run = (claims: Record<string, unknown>) => token(rsa, { iss: gitlab, sub: 'project_path:acme/api:ref_type:branch:ref:main', ...pipeline, ...claims });
  const moved = (await trade(run({ namespace_id: '78', namespace_path: 'other' }))).body;
  assert.deepEqual([moved.reason, moved.message], ['no_match', `no binding of ${shownMember(MEMBER)} trusts these claims: namespace_id differ`]);
  assert.equal((await trade(run({}))).status, 200);
});

test("keys that moved, replaced while a run exchanges: its credential stands only while the binding it came from does", async () => {
  const old = (await db.owner.select().from(serviceBindings))[0]!.id;
  const moved = `${ISSUER}/.well-known/jwks-2`;
  published.set(`${ISSUER}/.well-known/openid-configuration`, { issuer: ISSUER, jwks_uri: moved });
  published.set(moved, { keys: [rsa.jwk, ec.jwk] });
  const [exchanged, made] = await Promise.all([trade(token(rsa)), bind(DEPLOY)]);
  assert.equal((await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, old)))[0]!.revokedAt !== null, true, 'the old binding was replaced');
  if (exchanged.status === 200) {
    const [issued] = await db.owner.select().from(credentials);
    assert.equal(await caller(exchanged.body.token!), issued!.createdBy === `binding:${made}` ? `service:${SERVICE}` : 401);
  }
  // The next run is verified under the keys' new URL, by the binding that replaced it.
  assert.equal((await trade(token(rsa))).status, 200);
  assert.equal((await appEntries('token.exchange')).at(-1)!.metadata.bindingId, made);
});

test("two first exchanges at once each fetch the issuer's keys, rather than one waiting on the other's request", async () => {
  forgetKeys();
  issuer.fetches = 0;
  let started = 0;
  let bothStarted!: () => void;
  const both = new Promise<void>((resolve) => (bothStarted = resolve));
  // Each fetch waits until the other has begun, or two seconds: one that waited on the other would never begin.
  issuer.hold = async () => {
    if (++started === 2) bothStarted();
    await Promise.race([both, sleep(2000)]);
  };
  const outcomes = await Promise.all([trade(token(rsa)), trade(token(ec))]);
  assert.deepEqual(outcomes.map((outcome) => outcome.status), [200, 200]);
  assert.equal(issuer.fetches, 2);
});

test('admission comes first: both limits, a limiter that fails, and the body\'s size', async () => {
  limits = processLimits({ perSource: 1, total: 1000 });
  assert.equal((await trade(token(rsa))).status, 200);
  vaultCalls = 0;
  const limited = await trade(token(rsa));
  assert.deepEqual([limited.status, limited.body.reason], [429, 'busy']);
  // Another address has its own allowance, under the same total.
  assert.equal((await exchange({ service: MEMBER, token: token(rsa) }, '198.51.100.4')).status, 200);
  limits = { perSource: processLimits().perSource, total: processLimits({ total: 1 }).total };
  assert.equal((await trade(token(rsa))).status, 200);
  assert.equal((await exchange({ service: MEMBER, token: token(rsa) }, '198.51.100.5')).status, 429);
  limits = { perSource: { limit: async () => { throw new Error('binding gone'); } }, total: processLimits().total };
  const failing = await trade(token(rsa));
  assert.deepEqual([failing.status, failing.body.reason], [503, 'busy']);
  limits = processLimits();
  assert.equal((await exchange(JSON.stringify({ service: MEMBER, token: 'x'.repeat(17 * 1024) }))).status, 400);
  assert.equal((await exchange({ service: MEMBER, token: token(rsa), extra: true })).status, 400);
});

test('an hour at most, exactly, at the commit too: a token in time when verified and past the hour when committed is refused', async () => {
  // In time by a second when verified; held two before the commit.
  beforeAccess = () => sleep(2100);
  const late = await trade(token(rsa, { iat: seconds() - 3599 }));
  assert.deepEqual([late.status, late.body.reason], [401, 'too_old']);
  assert.deepEqual(await db.owner.select().from(credentials), []);
  beforeAccess = undefined;
  assert.equal((await trade(token(rsa, { iat: seconds() - 3590 }))).status, 200);
});

test('a binding issues at most 60 credentials a minute', async () => {
  const outcomes = [];
  for (let i = 0; i < 61; i++) outcomes.push((await trade(token(rsa))).status);
  assert.deepEqual([outcomes.filter((status) => status === 200).length, outcomes.at(-1)], [60, 429]);
});

/** Raw SQL as the owner, on either engine. */
async function run(query: SQL): Promise<void> {
  if (TEST_ENGINE === 'sqlite') await (db.owner as unknown as { run: (q: SQL) => Promise<unknown> }).run(query);
  else await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}

test('every entry a run\'s credential causes names it, the vault\'s too; the audit page reads its run, after the credential row is gone', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.secrets.set('market/prod', { API_KEY: 'sk_live' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  // A binding reaches what its account held when it was made: one made now reaches prod.
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  await bind(DEPLOY);

  const { body } = await trade(token(rsa));
  const [exchange] = await appEntries('token.exchange');
  const credentialId = exchange!.metadata.credentialId as string;
  const reveal = (path: string) => answer(
    new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${body.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }),
    runtime, ui, IP,
  );
  assert.equal((await reveal('market/prod/API_KEY')).status, 200);
  // And one refused: every entry the run caused names its credential, the app's and the vault's, allowed or not.
  assert.equal((await reveal('market/nowhere/API_KEY')).status, 404);
  const caused = (await db.owner.select({ author: auditLog.author, action: auditLog.action, decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog).where(eq(auditLog.actor, MEMBER)).orderBy(asc(auditLog.seq)))
    .map((entry) => ({ ...entry, credentialId: (JSON.parse(entry.metadata) as { credentialId?: string }).credentialId }));
  assert.deepEqual(caused.map(({ author, action, decision }) => `${author} ${action} ${decision}`), ['app token.exchange allow', 'vault secret.read allow', 'app secret.read deny']);
  assert.ok(caused.every((entry) => entry.credentialId === credentialId));

  // Whoever owns the database deletes the credential's row: the log still leads from the read to its run.
  await db.owner.delete(credentials).where(eq(credentials.id, credentialId));
  const { entries } = await root.audit.list({ detail: '1' });
  const shown = entries.find((entry) => entry.action === 'secret.read')!;
  assert.deepEqual(shown.run, { exchangeSeq: entries.find((entry) => entry.action === 'token.exchange')!.seq, claims: exchange!.metadata.run });
  assert.equal(entries.find((entry) => entry.action === 'token.exchange')!.run!.claims.run_id, '7001');
  // An entry no exchanged credential wrote has no run.
  assert.equal(entries.find((entry) => entry.action === 'secret.write')!.run, null);
});

// --- Keys uploaded with a binding ----------------------------------------------

/** A private Kubernetes cluster: an issuer coffre could not fetch from, which names a `.local` host. */
const CLUSTER = 'https://kubernetes.default.svc.cluster.local';
const UID = '4f1c8d2a-7b3e-4c1d-9a2f-0e6b5c4d3a21';
/** `deploy` of namespace `ci`, by its name and its UID: a deleted account made again under the same name has another. */
const ACCOUNT: BindingClaims = { sub: 'system:serviceaccount:ci:deploy', 'kubernetes.io.serviceaccount.uid': UID };

/** A projected service-account token, as the kubelet writes it: an hour's lifetime unless told. */
function projected(by: Key, claims: Record<string, unknown> = {}): string {
  const iat = seconds() - 5;
  return token(by, {
    iss: CLUSTER,
    sub: ACCOUNT.sub,
    iat,
    exp: iat + 3600,
    'kubernetes.io': { namespace: 'ci', pod: { name: 'deploy-7f9c', uid: 'p-1' }, serviceaccount: { name: 'deploy', uid: UID } },
    ...claims,
  });
}

async function bindCluster(keys: Key[], claims: BindingClaims = ACCOUNT, replaces: string[] = []) {
  return runtime.workloads!.bind(
    await contextFor(deps, ROOT),
    SERVICE,
    { profile: 'custom', issuer: CLUSTER, claims, label: 'cluster', replaces, jwks: { keys: keys.map((each) => each.jwk) } as never },
    { dryRun: false },
  );
}

const replaceKeys = async (keys: Key[], dryRun = false, at = CLUSTER) =>
  runtime.workloads!.replaceKeys(await contextFor(deps, ROOT), SERVICE, { issuer: at, jwks: { keys: keys.map((each) => each.jwk) } as never }, { dryRun });

test('a binding that carries its keys takes a private issuer\'s tokens, by a nested claim, and fetches nothing', async () => {
  issuer.fetches = 0;
  const made = await bindCluster([rsa]);
  assert.ok('binding' in made);
  assert.match(made.binding.jwksUri, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(made.binding.keys?.map(({ kid, alg }) => [kid, alg]), [['rs-1', 'RS256']]);
  const ok = await trade(projected(rsa));
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(issuer.fetches, 0, 'neither discovery nor keys');
  assert.equal(((await appEntries('token.exchange')).at(-1)!.metadata.run as Record<string, unknown>)['kubernetes.io.pod.name'], 'deploy-7f9c');
  const bound = await appEntries('token.bind');
  assert.deepEqual((bound.at(-1)!.metadata.keys as { kid: string }[]).map(({ kid }) => kid), ['rs-1']);

  const refused = async (jwt: string) => {
    const { status, body } = await trade(jwt);
    return [status, body.reason, body.message];
  };
  // Another account under the same name, made again: its UID differs, and the claim is named, never its value.
  const [, reason, message] = await refused(projected(rsa, { 'kubernetes.io': { serviceaccount: { name: 'deploy', uid: 'another' } } }));
  assert.equal(reason, 'no_match');
  assert.match(message as string, /kubernetes\.io\.serviceaccount\.uid differ/);
  assert.doesNotMatch(message as string, new RegExp(UID));
  // A key outside the set: no fetch, a 401 that says to replace the keys.
  assert.deepEqual((await refused(projected(ec))).slice(0, 2), [401, 'unknown_key']);
  assert.match((await refused(projected(ec)))[2] as string, /not among those uploaded for https:\/\/kubernetes\.default\.svc\.cluster\.local/);
  // Longer than an hour, iat to exp, though issued just now.
  const long = seconds() - 5;
  assert.deepEqual((await refused(projected(rsa, { iat: long, exp: long + 3601 }))).slice(0, 2), [401, 'too_long']);
  // Spent once, as any token.
  const once = projected(rsa);
  assert.equal((await trade(once)).status, 200);
  assert.deepEqual((await refused(once)).slice(0, 2), [401, 'replayed']);
  assert.equal(issuer.fetches, 0);
  // A binding without uploaded keys still needs an issuer coffre can fetch.
  await assert.rejects(
    runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'custom', issuer: CLUSTER, claims: ACCOUNT, label: null, replaces: [] }, { dryRun: true }),
    /the issuer must be a public host name/,
  );
});

test("uploaded keys are checked when bound: public keys alone, of the two algorithms, never for github.com's issuer", async () => {
  const bindWith = async (jwks: unknown, issuer = CLUSTER, profile: WorkloadProfile = 'custom', claims: BindingClaims = ACCOUNT) =>
    runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile, issuer, claims, label: null, replaces: [], jwks: jwks as never }, { dryRun: true });
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await assert.rejects(bindWith({ keys: [privateKey.export({ format: 'jwk' })] }), { status: 400, message: /private or a secret key/ });
  await assert.rejects(bindWith({ keys: [{ kty: 'oct', k: 'c2VjcmV0' }] }), { status: 400, message: /private or a secret key/ });
  await assert.rejects(bindWith({ keys: [generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' })] }), { status: 400, message: /RSA key for RS256 or a P-256 key for ES256/ });
  await assert.rejects(bindWith({ keys: [generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' })] }), { status: 400, message: /under 2048 bits/ });
  await assert.rejects(bindWith({ keys: [{ ...rsa.jwk, use: 'enc' }] }), { status: 400, message: /no key that signs/ });
  await assert.rejects(bindWith({ keys: [rsa.jwk, { ...ec.jwk, kid: rsa.kid }] }), { status: 400, message: /two keys are key rs-1/ });
  await assert.rejects(bindWith({ keys: [rsa.jwk] }, ISSUER, 'github', DEPLOY), { status: 400, message: /publishes its keys/ });
  // The same keys, however written, are one set: extra members and their order change nothing.
  const plain = await bindWith({ keys: [rsa.jwk] });
  const written = await bindWith({ keys: [{ x5c: ['MIIB'], ...Object.fromEntries(Object.entries(rsa.jwk).reverse()) }] });
  assert.ok('jwksUri' in plain && 'jwksUri' in written);
  assert.equal(plain.jwksUri, written.jwksUri);
  // Any issuer string at all, matched exactly.
  const named = await bindWith({ keys: [rsa.jwk] }, 'kapsule:fr-par:5f2a');
  assert.ok('issuer' in named && named.issuer === 'kapsule:fr-par:5f2a');
  await assert.rejects(bindWith({ keys: [rsa.jwk] }, ' kapsule'), { status: 400 });
});

test("replacing an issuer's keys replaces each binding on it, the same but for them; a set of old and new takes both while it rotates", async () => {
  const first = await bindCluster([rsa]);
  const other = await bindCluster([rsa], { sub: 'system:serviceaccount:ci:migrate' });
  assert.ok('binding' in first && 'binding' in other);
  const credential = (await trade(projected(rsa))).body.token!;
  // A binding of other keys on the issuer would leave the others behind: refused, unless it replaces them.
  await assert.rejects(bindCluster([ec], { sub: 'system:serviceaccount:ci:seed' }), { status: 409, message: /verify with other keys/ });

  const plan = await replaceKeys([rsa, ec], true);
  assert.ok(!('bindings' in plan));
  assert.deepEqual(plan.replaces, [first.binding.id, other.binding.id]);
  assert.deepEqual(plan.keys.map(({ kid }) => kid).sort(), ['es-1', 'rs-1']);
  assert.deepEqual(plan.withheld, [], 'an Owner re-keys them');
  assert.equal((await db.owner.select().from(serviceBindings)).filter((row) => row.revokedAt === null).length, 3, 'a dry run writes nothing');

  const done = await replaceKeys([rsa, ec]);
  assert.ok('bindings' in done);
  assert.deepEqual(done.replaced, plan.replaces);
  assert.deepEqual(done.bindings.map((binding) => [binding.label, binding.claims, binding.scope]), [
    [first.binding.label, first.binding.claims, first.binding.scope],
    [other.binding.label, other.binding.claims, other.binding.scope],
  ]);
  assert.equal(await caller(credential), 401, 'the credentials the old bindings issued ended with them');
  assert.equal((await trade(projected(rsa))).status, 200);
  assert.equal((await trade(projected(ec))).status, 200);
  assert.deepEqual(
    (await appEntries('token.unbind')).map((entry) => [entry.metadata.bindingId, entry.metadata.reason]),
    [[first.binding.id, 'keys_replaced'], [other.binding.id, 'keys_replaced']],
  );

  // The rotation done: the old key goes.
  await replaceKeys([ec]);
  assert.equal((await trade(projected(rsa))).body.reason, 'unknown_key');
  assert.equal((await trade(projected(ec))).status, 200);
  // Nothing to do, or nobody bound there.
  await assert.rejects(replaceKeys([ec]), { status: 409, message: /carry these keys already/ });
  await assert.rejects(replaceKeys([ec], false, 'https://elsewhere.local'), { status: 404 });
  // GitHub's binding, on the same service, kept its fetched keys throughout.
  assert.equal((await trade(token(rsa))).status, 200);
});

test("a binding's uploaded keys are under its MAC: keys swapped in the database verify nothing", async () => {
  const made = await bindCluster([rsa]);
  assert.ok('binding' in made);
  await db.owner.update(serviceBindings).set({ jwks: JSON.stringify({ keys: [ec.jwk] }) }).where(eq(serviceBindings.id, made.binding.id));
  const { status, body } = await trade(projected(ec));
  assert.deepEqual([status, body.reason], [401, 'no_match']);
  assert.deepEqual((await runtime.workloads!.listBindings(await contextFor(deps, ROOT), SERVICE)).map((binding) => binding.id), [bound]);
});

test('replacing keys keeps which binding a run matches: of two that take the same token, the older still wins', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) await root.environments.create(`market/${environment}`, { name: environment });
  await root.access.set(MEMBER, { 'market/dev': 'viewer', 'market/prod': 'viewer' });
  const scoped = async (label: string, path: string) => {
    const made = await runtime.workloads!.bind(
      await contextFor(deps, ROOT),
      SERVICE,
      { profile: 'custom', issuer: CLUSTER, claims: ACCOUNT, scope: { [path]: 'viewer' }, label, replaces: [], jwks: { keys: [rsa.jwk] } as never },
      { dryRun: false },
    );
    assert.ok('binding' in made);
    return made.binding.id;
  };
  await scoped('dev', 'market/dev');
  await scoped('prod', 'market/prod');
  const matched = async () => {
    assert.equal((await trade(projected(rsa))).status, 200);
    const id = (await appEntries('token.exchange')).at(-1)!.metadata.bindingId;
    return (await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id as string)))[0]!.label;
  };
  assert.equal(await matched(), 'dev');
  for (let rotation = 0; rotation < 4; rotation++) {
    await replaceKeys(rotation % 2 === 0 ? [rsa, ec] : [rsa]);
    assert.equal(await matched(), 'dev', `after rotation ${rotation + 1}`);
  }
});

test("/api/auth/oidc takes only a binding of today's five profiles with no policy: a workload's binding never buys a reading credential there", async () => {
  // The same binding, its MAC good for each change: one with a policy, then one of a profile a key-bound session signs in with.
  const rebind = async (change: { policy?: string | null; profile?: string }) => {
    const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
    const { authMac: _, ...fields } = { ...row!, ...change };
    await db.owner.update(serviceBindings).set({ ...change, authMac: authMac(deps.chainKey, 'service_bindings', fields) }).where(eq(serviceBindings.id, bound));
  };
  const listed = async () => (await runtime.workloads!.listBindings(await contextFor(deps, ROOT), SERVICE)).map((binding) => binding.id);
  assert.equal((await trade(token(rsa))).status, 200);

  await rebind({ policy: '{"keyAudience":true}' });
  // Its MAC holds, policy and all: it is refused for what it is, not as a row changed around the app.
  assert.deepEqual(await listed(), [bound]);
  const policed = await trade(token(rsa));
  assert.deepEqual([policed.status, policed.body.reason], [401, 'no_match']);
  // A policy changed, or cleared, under the same MAC fails it.
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
  await db.owner.update(serviceBindings).set({ policy: null }).where(eq(serviceBindings.id, bound));
  assert.deepEqual(await listed(), []);
  await db.owner.update(serviceBindings).set({ policy: row!.policy, authMac: row!.authMac }).where(eq(serviceBindings.id, bound));

  await rebind({ policy: null, profile: 'kubernetes' });
  assert.deepEqual(await listed(), [bound]);
  const kubernetes = await trade(token(rsa));
  assert.deepEqual([kubernetes.status, kubernetes.body.reason], [401, 'no_match']);

  await rebind({ profile: 'github' });
  assert.equal((await trade(token(rsa))).status, 200, 'and the bearer binding it was takes it again');
  // A binding of any other profile carries a policy, and a bearer profile's one when given: `/api/auth/workload` takes those.
  published.set('https://cluster.acme.example/.well-known/openid-configuration', { issuer: 'https://cluster.acme.example', jwks_uri: KEYS });
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'kubernetes', issuer: 'https://cluster.acme.example', claims: { sub: 'system:serviceaccount:prod:api', 'kubernetes.io.serviceaccount.uid': 'b9f0c6a2-7d3e-4c1a-9f00-2c6d5e4b3a10' }, label: null, replaces: [] }, { dryRun: false });
  assert.ok('binding' in made);
  assert.deepEqual(made.binding.policy, {});
  const keyed = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: { ...DEPLOY, ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' }, label: null, replaces: [], policy: {} }, { dryRun: false });
  assert.ok('binding' in keyed);
  assert.deepEqual(keyed.binding.policy, { keyAudience: true });
  const workload = await trade(token(rsa, { ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' }));
  assert.deepEqual([workload.status, workload.body.reason], [401, 'no_match']);
});

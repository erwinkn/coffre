import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign as signWith, type KeyObject } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';


import { shownMember, SIGN_IN_BODY_BYTES } from '@coffre/core/schemas';
import type { Role } from '@coffre/core/access';
import { createClient } from '@coffre/client';
import { github, MAX_BINDINGS, signin, type BindingClaims, type RateLimiter, type WorkloadProfile } from '@coffre/core/identity';
import { createDatabase, type Client, type Database } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { versioned, type Vault, type VaultEntry } from '@coffre/core/vault';
import { asc, desc, eq, isNotNull, isNull, sql, type SQL } from 'drizzle-orm';

import { auditLog, spentIdTokens, credentials, logChanges, projects, serviceBindings } from '@coffre/db/schema';
import { authMac } from '../src/auth-rows.ts';
import { answer, type Pages } from './start-fixture.ts';
import { resolveConfig } from '../src/config.ts';
import { runScheduled, SPENT_TOKENS_PER_BEAT } from '../src/app.ts';
import { AFTER_REMOVAL_CALLS, UNBIND_BATCH } from '../src/api/workloads.ts';
import { countedEntry, countingCalls, WORKERS_BATCH, workersRemovalBudget } from '../src/removal.ts';
import { serveApi } from '../src/api/router.ts';
import { drainBackgroundTasks } from './background-tasks.ts';
import { exchangeCandidates, exchangeStill, exchangeToken, issuedSoonest, liveIssued, pruneSpentTokens } from '../src/db/queries.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { auditWatch } from '../src/plugins/audit-watch.ts';
import { clientFor, contextFor, entryOf, decisionInputs, holdSomething, openTestDatabase, resetDatabase, revokesLogged, signInsLogged, speaking, testDeps, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { keeps015 } from '../src/api/changes.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';

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
let limits: { perSource: RateLimiter };
/** Every key the limiter was asked to count, in order. */
let keysAsked: string[];
let vaultCalls: number;
/** Waited for before the vault is asked about the member: the last step before the commit. */
let beforeAccess: (() => Promise<void>) | undefined;
/** Waited for once the vault has answered about the member, before the head is taken: what changes then, only the re-check under the head sees. */
let afterAccess: (() => Promise<void>) | undefined;
/** The binding every test starts with, of `deploy.yml` on main. */
let bound: string;

const transport: WorkloadTransport = {
  json: async (url) => {
    issuer.fetches++;
    await issuer.hold?.();
    if (issuer.down) throw FetchRefused.unreached(url, new DOMException('The operation was aborted due to timeout', 'TimeoutError'));
    if (!published.has(url.href)) throw FetchRefused.answered(url, 404);
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
  limits = processLimits({ perSource: 1000 });
  keysAsked = [];
  deps = testDeps(db.runtime, [ROOT]);
  vaultCalls = 0;
  beforeAccess = undefined;
  afterAccess = undefined;
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    vaultCalls++;
    await beforeAccess?.();
    const answered = await access(principal);
    await afterAccess?.();
    return answered;
  };
  // With 0.15's log the vault makes the credential, asking `access` nothing: the same moments come before its one call.
  const signIn = deps.vault.signIn?.bind(deps.vault);
  if (signIn !== undefined) {
    deps.vault.signIn = async (input) => {
      vaultCalls++;
      await beforeAccess?.();
      await afterAccess?.();
      return signIn(input);
    };
  }
  config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: { perSource: { limit: (o) => (keysAsked.push(o.key), limits.perSource.limit(o)) } } } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: [auditWatch({ anchor: deps.anchor })],
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

async function exchange(body: unknown, sourceIp: string | null = IP): Promise<{ status: number; body: Record<string, string>; retryAfter: string | null }> {
  const response = await answer(
    new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body) }),
    runtime,
    ui,
    sourceIp,
  );
  return { status: response.status, body: (await response.json()) as Record<string, string>, retryAfter: response.headers.get('retry-after') };
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

  // Its record: the vault's change, which says who, through what, for which run, and when (its `at`).
  const [signedIn] = await signInsLogged(db.owner);
  assert.equal(signedIn!.actor, MEMBER);
  assert.equal(signedIn!.run.run_id, '7001');
  assert.deepEqual(Object.keys(signedIn!.record).sort(), ['caller', 'expiresAt', 'generation', 'op', 'principal', 'ref', 'scope', 'signIn']);
  assert.deepEqual(signedIn!.record.signIn, { binding: bound, issuer: ISSUER, proof: 'oidc', run: signedIn!.run });
  assert.deepEqual(await appEntries('token.exchange'), [], 'no entry of its own');
  // The service's token list is for tokens people keep.
  assert.deepEqual((await runtime.signin!.listTokens(await contextFor(deps, ROOT), { type: 'service', id: SERVICE })), []);
  const [binding] = await db.owner.select().from(serviceBindings);
  assert.notEqual(binding!.lastUsedAt, null);
  // An ES256 issuer is the same.
  assert.equal((await trade(token(ec))).status, 200);
});

test("a run's token.exchange changes no decision input but the credential it issues, and logs its issue alone: the trigger lets it by unfenced (0026, ExchangeOnlyIssues)", async () => {
  const before = await decisionInputs(db.owner);
  const changes = await db.owner.select({ number: logChanges.number }).from(logChanges);
  const { status, body } = await trade(token(rsa));
  assert.equal(status, 200, JSON.stringify(body));
  const issued = (await signInsLogged(db.owner))[0]!.credentialId;
  assert.deepEqual(await decisionInputs(db.owner, [issued]), before);
  // By number: the heap need not keep the new rows after the old (use.test.ts, replayAgrees).
  const logged = (await db.owner.select({ payload: logChanges.payload }).from(logChanges).orderBy(asc(logChanges.number))).slice(changes.length).map(({ payload }) => JSON.parse(payload) as { op: string; ref: { id: string } });
  assert.deepEqual(logged.map(({ op, ref }) => [op, ref.id]), (await keeps015(deps.vault)) ? [['credential.issue', issued]] : []);
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
  assert.deepEqual(await trade(jwt), { status: 401, retryAfter: null, body: { error: 'unauthenticated', reason: 'replayed', message: 'this token was exchanged already: ask your CI for a fresh one' } });
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
  await db.owner.insert(spentIdTokens).values([spent(1, 121), spent(2, 121), spent(3, 121), spent(4, 119)]);
  // Which of those are left, by their byte.
  const left = async () => (await db.owner.select({ hash: spentIdTokens.hash }).from(spentIdTokens))
    .flatMap(({ hash }) => (hash.equals(Buffer.alloc(32, hash[0])) ? [hash[0]] : [])).sort().join();
  assert.equal(await pruneSpentTokens(db.runtime, 2), 2);
  assert.equal((await left()).split(',').length, 2);
  await runScheduled(runtime);
  assert.equal(await left(), '4', 'the beat took the third, and the young one stays');
  assert.equal(await pruneSpentTokens(db.runtime, 10), 0);
  assert.equal((await trade(jwt)).body.reason, 'replayed', 'the token just spent stays spent');
});

test("the beat forgets spent tokens by their place, a stretch of the table at a time, never through the primary key (0080, 0082)", async () => {
  // 50,000 spent within the two hours, three before.
  await run(sql`INSERT INTO spent_id_tokens (hash, consumed_at) SELECT sha256(int8send(i)), now() - interval '1 hour' FROM generate_series(1, 50000) i`);
  await run(sql`INSERT INTO spent_id_tokens (hash, consumed_at) SELECT sha256(int8send(-i)), now() - interval '3 hours' FROM generate_series(1, 3) i`);
  await run(sql`ANALYZE spent_id_tokens`);
  // The scans the prune made, on one backend: its counts not yet flushed, before and after (they include earlier
  // statements' until the backend flushes them, so the difference).
  const scans = await db.owner.transaction(async (tx) => {
    const execute = (tx as unknown as { execute: (q: SQL) => Promise<{ seq: string; indexed: string }[]> }).execute.bind(tx);
    const stats = sql`SELECT seq_scan::text AS seq, idx_scan::text AS indexed FROM pg_stat_xact_user_tables WHERE relname = 'spent_id_tokens'`;
    const [before] = await execute(stats);
    await execute(sql`SELECT prune_consumed_tokens(${SPENT_TOKENS_PER_BEAT})`);
    const [after] = await execute(stats);
    return { seq: Number(after!.seq) - Number(before!.seq), indexed: Number(after!.indexed) - Number(before!.indexed) };
  });
  // No primary-key lookup (50,000 cost 1.85 s on a table of 7.5 million) and no scan of the whole table: a TID range
  // scan of at most 16,384 blocks (migration 0082), which Postgres counts as neither.
  assert.deepEqual(scans, { seq: 0, indexed: 0 });
  assert.equal((await db.owner.select().from(spentIdTokens)).length, 50_000);
  // The sweep goes on past the stretch it read, the table's end here, and round from its start the next time.
  const next = async () => Number((await db.owner.execute<{ next: string }>(sql`SELECT next_block::text AS next FROM spent_tokens_sweep`) as unknown as [{ next: string }])[0].next);
  assert.equal(await next(), 16_384);
  await run(sql`INSERT INTO spent_id_tokens (hash, consumed_at) SELECT sha256(int8send(-i)), now() - interval '3 hours' FROM generate_series(10, 12) i`);
  assert.equal(await pruneSpentTokens(db.owner, SPENT_TOKENS_PER_BEAT), 3);
  assert.equal(await next(), 16_384);
  // Twice what 1,000 sign-ins a second spend in a five-minute beat.
  assert.equal(SPENT_TOKENS_PER_BEAT, 600_000);
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

/** `pool`, telling `seen` every statement it sends to the server, inside a transaction or not, and how many rows it read or changed. */
function counted(pool: PostgresClient, seen: Statement[]): Client {
  return watched(pool, ({ text, values, count }) => void seen.push({ text, values, rows: count }));
}

test('a token no binding can take costs its admission and one indexed read: no other query, no transaction, no vault call, no fetch', async () => {
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const seen: Statement[] = [];
  try {
    const stranger = createRuntime(config, createDatabase(counted(pool, seen)), deps.vault, transport);
    // The door's reads of the migrations and of the app key's standing are the isolate's, once, not an exchange's (app.ts).
    stranger.schema.migrated = true;
    stranger.appKey.settled = true;
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
function hyperdriveCached(pool: PostgresClient): Client {
  const cache = new Map<string, Promise<unknown>>();
  const UNCACHEABLE = /\b(now|current_timestamp|current_date|current_time|localtime|localtimestamp|clock_timestamp|statement_timestamp|txid_current|timeofday|random|lastval)\b/i;
  return new Proxy(pool, {
    get(on, key) {
      const value: unknown = Reflect.get(on, key, on);
      if (typeof value !== 'function') return value;
      // A transaction's statements, through `begin`, are never cached.
      if (key !== 'unsafe') return value.bind(on);
      return (text: string, values: unknown[] = []) => {
        if (!/^\s*select\b/i.test(text) || / for update\b/i.test(text) || UNCACHEABLE.test(text)) return on.unsafe(text, values as never[]);
        let arrays = false;
        const statement = {
          values: () => {
            arrays = true;
            return statement;
          },
          then: (resolve: (rows: unknown) => unknown, reject: (error: unknown) => unknown) => {
            const keyed = JSON.stringify([text, values, arrays], (_, v: unknown) => (typeof v === 'bigint' ? `${v}n` : v));
            if (!cache.has(keyed)) {
              const query = on.unsafe(text, values as never[]);
              // What failed is asked again: Hyperdrive caches answers, not errors.
              const answer = Promise.resolve(arrays ? query.values() : query);
              cache.set(keyed, answer);
              answer.catch(() => cache.delete(keyed));
            }
            return cache.get(keyed)!.then(resolve, reject);
          },
        };
        return statement;
      };
    },
  });
}

test("Hyperdrive's cache revives nothing: rows put back after a removal stay dead, and a replay never reaches the vault", async () => {
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
async function planOf(pool: PostgresClient, statement: Statement, table: string): Promise<{ indexes: string[]; visited: number }> {
  const [explained] = await pool.unsafe(`EXPLAIN (ANALYZE, FORMAT JSON) ${statement.text}`, statement.values as never[]);
  const nodes: PlanNode[] = [];
  const walk = (node: PlanNode) => {
    nodes.push(node);
    node.Plans?.forEach(walk);
  };
  walk((explained as unknown as { 'QUERY PLAN': { Plan: PlanNode }[] })['QUERY PLAN'][0]!.Plan);
  return {
    indexes: nodes.flatMap((node) => node['Index Name'] ?? []),
    visited: nodes
      .filter((node) => node['Relation Name'] === table)
      .reduce((n, node) => n + ((node['Actual Rows'] ?? 0) + (node['Rows Removed by Filter'] ?? 0)) * (node['Actual Loops'] ?? 1), 0),
  };
}

test("an exchange's first read visits the live bindings only, whatever the retired and earlier history", async () => {
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
    const { bindings } = await exchangeCandidates(createDatabase(counted(pool, seen)), deps.chainKey, MEMBER, ISSUER, 16, randomBytes(32));
    assert.deepEqual(bindings.map((candidate) => candidate.id), [live!.id]);
    const plan = await planOf(pool, seen.find((statement) => /from "service_bindings"/i.test(statement.text))!, 'service_bindings');
    assert.ok(plan.indexes.includes('service_bindings_live_idx'), plan.indexes.join(', '));
    assert.ok(plan.visited <= 2, `visited ${plan.visited} binding rows for one live binding`);
  } finally {
    await pool.end();
  }
});

test('removing a binding revokes only what is live: its expired history costs nothing there, nor on the members page', async () => {
  const [binding] = await db.owner.select().from(serviceBindings);
  // A thousand runs long over, and one under way.
  const over = new Date(Date.now() - 3_600_000);
  await db.owner.transaction(async (tx) => {
    for (let i = 0; i < 1000; i++) {
      await tx.insert(credentials).values(runtime.signin!.exchangedCredential(SERVICE, { generation: binding!.generation, bindingId: binding!.id, label: null, expiresAt: over }).row);
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
    // The vault's one statement ends the binding and the run under way: the app writes none.
    assert.equal(seen.filter((statement) => /^update "credentials"/i.test(statement.text)).length, 0, 'the run under way, not the thousand over');
    assert.equal((await db.owner.select().from(credentials).where(isNotNull(credentials.revokedAt))).length, 1, 'the run under way, not the thousand over');
    assert.ok(read('credentials') <= 2, `read ${read('credentials')} credential rows`);
    assert.equal(await caller(body.token!), 401);
    seen.length = 0;
    await clientFor(counting, ROOT).members.list();
    assert.equal(read('credentials'), 0, 'no credential is live, so the members page reads none');
  } finally {
    await pool.end();
  }
});

test("a binding made on another public URL is still the vault's to end, with what it issued, and takes no token for this one (PR 3b: its row keeps the origin its seal covers)", async () => {
  const { body } = await trade(token(rsa));
  assert.ok(body.token, JSON.stringify(body));
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
  assert.equal(row!.origin, ORIGIN, 'the instance it was made on, as sealed');
  // The instance moves to another URL.
  const MOVED = 'https://moved.acme.example';
  const moved = createRuntime({ ...config, publicUrl: MOVED }, deps.db, deps.vault, transport);
  const refused = await answer(
    new Request(`${MOVED}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: token(rsa, { aud: MOVED }) }) }),
    moved, ui, IP,
  );
  assert.equal(refused.status, 401);
  assert.equal(((await refused.json()) as { reason: string }).reason, 'audience', "a token for the new URL is none of a binding made on the old");
  // Bound again on the new URL, the old one still live beside it: the old shadows nothing.
  const again = await moved.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY, label: 'deploys', replaces: [] }, { dryRun: false });
  assert.ok('binding' in again);
  const signedIn = await answer(
    new Request(`${MOVED}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: token(rsa, { aud: MOVED }) }) }),
    moved, ui, IP,
  );
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  await moved.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  assert.ok((await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound)))[0]!.revokedAt !== null, 'ended');
  assert.equal(await caller(body.token!), 401, 'with the run it issued');
});

test("a revocation is its caller's act: the credential it ends is its target, never the entry's run", async () => {
  /** A run's credential, by its run_id: the token, and its ID from the exchange's entry. */
  const runOf = async (runId: string) => {
    const { body } = await trade(token(rsa, { run_id: runId }));
    const signedIn = (await signInsLogged(db.owner)).find((exchange) => exchange.run.run_id === runId);
    return { token: body.token!, id: signedIn!.credentialId };
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
  // The refusal is the app's entry; each revoke, the vault's change, naming the credential it came in on.
  assert.deepEqual(revocations, [{ actor: MEMBER, decision: 'deny', credentialId: a.id, targetCredentialId: nobody }]);
  assert.deepEqual(await revokesLogged(db.owner), [
    { actor: MEMBER, reason: 'revoke', targetCredentialId: b.id },
    { actor: `user:${ROOT}`, reason: 'revoke', targetCredentialId: c.id },
  ]);
  const vias = (await db.owner.select({ payload: logChanges.payload }).from(logChanges)).flatMap(({ payload }) => {
    const { revoke } = JSON.parse(payload) as { revoke?: { via: string | null } };
    return revoke === undefined ? [] : [revoke.via];
  });
  assert.deepEqual(vias, [a.id, null]);
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
  issuer.fetches = 0;
  const down = await trade(token(rsa));
  // Asked twice, then not again for ten seconds: no sooner, it says, which the CLI waits for (`unavailableWait`).
  assert.deepEqual([down.status, down.body.reason, down.retryAfter, issuer.fetches], [503, 'issuer_unavailable', '10', 2]);
  assert.match(down.body.message!, /^coffre could not fetch the signing keys of the issuer https:\/\/token\.actions\.githubusercontent\.com \(.*: timed out after 5 s\): its own request to the issuer failed, not the token or the job that sent it; try again in 10 s$/);
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

test('a binding removed, or a member removed or admitted again, while an exchange waits for the head: refused there, and nothing written', async () => {
  const root = await contextFor(deps, ROOT);
  const nothingWritten = async () => {
    assert.deepEqual(await db.owner.select().from(credentials), []);
    assert.deepEqual(await db.owner.select().from(spentIdTokens), []);
  };
  // Unbound once the bindings were read: the vault still answers for the member, and only the binding's re-check refuses.
  beforeAccess = async () => {
    beforeAccess = undefined;
    await runtime.workloads!.unbind(root, SERVICE, bound);
  };
  assert.deepEqual((await trade(token(rsa))).body.reason, 'no_match');
  await nothingWritten();

  // Removed once the vault answered that it stands.
  await bind(DEPLOY);
  afterAccess = async () => {
    afterAccess = undefined;
    assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  };
  assert.deepEqual((await trade(token(rsa))).body.reason, 'no_match');
  await nothingWritten();

  // Removed and admitted again: active once more, but at a generation the binding and the vault's answer are not.
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  const [reads] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, `${SERVICE}-reads`));
  assert.equal((await speaking(deps.vault).setAccess({ actor: `user:${ROOT}`, principal: MEMBER, changes: [{ projectId: reads!.id, environmentId: null, role: 'viewer', expiresAt: null }] })).ok, true);
  await bind(DEPLOY);
  afterAccess = async () => {
    afterAccess = undefined;
    assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  };
  assert.deepEqual((await trade(token(rsa))).body.reason, 'no_match');
  await nothingWritten();
});

test('the spend writes the credential and stamps the binding only when it spent the token itself', async () => {
  const [before] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
  const row = () => runtime.signin!.exchangedCredential(SERVICE, { generation: before!.generation, bindingId: bound, label: null, expiresAt: new Date(Date.now() + 300_000) }).row;
  const credentialRows = async (id: string) => (await db.owner.select({ id: credentials.id }).from(credentials).where(eq(credentials.id, id))).length;
  const lastUsed = async () => (await db.owner.select({ at: serviceBindings.lastUsedAt }).from(serviceBindings).where(eq(serviceBindings.id, bound)))[0]!.at?.getTime() ?? null;
  // A token spent already: refused, no credential, the binding's last use as it was.
  const spentHash = randomBytes(32);
  await db.owner.insert(spentIdTokens).values({ hash: spentHash });
  const refused = row();
  assert.equal(await exchangeToken(db.runtime, spentHash, refused, bound, new Date(Date.now() + 1000)), false);
  assert.equal(await credentialRows(refused.id!), 0);
  assert.equal(await lastUsed(), before!.lastUsedAt?.getTime() ?? null);
  // A fresh one: spent, the credential written, the binding stamped.
  const fresh = randomBytes(32);
  const issued = row();
  const at = new Date(Date.now() + 2000);
  assert.equal(await exchangeToken(db.runtime, fresh, issued, bound, at), true);
  assert.equal(await credentialRows(issued.id!), 1);
  assert.equal((await db.owner.select().from(spentIdTokens).where(eq(spentIdTokens.hash, fresh))).length, 1);
  assert.equal(await lastUsed(), at.getTime());
});

test("the re-check under the head stands only for the binding's own principal and a binding whose MAC is the app's", async () => {
  const [binding] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
  assert.equal((await exchangeStill(db.runtime, deps.chainKey, binding!)).stands, true);
  // Another principal than the binding's: refused (a foreign key keeps a member row for every binding; the member's status and
  // generation are driven to refusals through the exchange itself, in the test above).
  assert.equal((await exchangeStill(db.runtime, deps.chainKey, { ...binding!, principal: 'token:ghost' })).stands, false);
  // The member's binding, its MAC not the app's.
  await db.owner.update(serviceBindings).set({ authMac: Buffer.alloc(32) }).where(eq(serviceBindings.id, bound));
  assert.equal((await exchangeStill(db.runtime, deps.chainKey, binding!)).stands, false);
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
  const run = (await signInsLogged(db.owner)).at(-1)!.run;
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
  assert.equal((await signInsLogged(db.owner))[0]!.bindingId, id);
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
  assert.equal((await signInsLogged(db.owner)).at(-1)!.run.environment, 'Production');

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
  assert.equal((await signInsLogged(db.owner)).at(-1)!.bindingId, made);
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

test('admission comes first: the address\'s limit at this entry point, a limiter that fails, and the body\'s size', async () => {
  limits = processLimits({ perSource: 1 });
  assert.equal((await trade(token(rsa))).status, 200);
  vaultCalls = 0;
  const limited = await trade(token(rsa));
  // Asked again once the window has moved on: 10 s, not a minute.
  assert.deepEqual([limited.status, limited.body.reason, limited.retryAfter], [429, 'busy', '10']);
  assert.equal(vaultCalls, 0);
  // Another address has its own allowance, and no limit counts them all together.
  for (let i = 4; i < 10; i++) assert.equal((await exchange({ service: MEMBER, token: token(rsa) }, `198.51.100.${i}`)).status, 200);
  // Each entry point counted apart, the key naming it.
  assert.deepEqual(new Set(keysAsked), new Set([`exchange:${IP}`, ...Array.from({ length: 6 }, (_, n) => `exchange:198.51.100.${n + 4}`)]));
  limits = { perSource: { limit: async () => { throw new Error('binding gone'); } } };
  const failing = await trade(token(rsa));
  // A limiter that could not count is coffre not answering for a moment: back in 5 s, not a minute.
  assert.deepEqual([failing.status, failing.body.reason, failing.retryAfter], [503, 'busy', '1']);
  limits = processLimits();
  // Past the bound of every body before sign-in (`SIGN_IN_BODY_BYTES`), which bounds the token too: 413.
  const over = await exchange(JSON.stringify({ service: MEMBER, token: 'x'.repeat(SIGN_IN_BODY_BYTES) }));
  assert.deepEqual([over.status, over.body.error], [413, 'too_large']);
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

test('a binding issues as many credentials as its runs ask: 61 in a minute, each made (W331, D177)', async () => {
  const outcomes = [];
  for (let i = 0; i < 61; i++) outcomes.push((await trade(token(rsa))).status);
  assert.deepEqual(outcomes, Array.from({ length: 61 }, () => 200));
});

/** Raw SQL as the owner. */
async function run(query: SQL): Promise<void> {
  await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
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
  const [exchange] = await signInsLogged(db.owner);
  const credentialId = exchange!.credentialId;
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
  // The read is a use, and names the credential as its own column: the vault's read is no entry here.
  assert.deepEqual(caused.map(({ author, action, decision }) => `${author} ${action} ${decision}`), ['app secret.read deny']);
  assert.ok(caused.every((entry) => entry.credentialId === credentialId));
  assert.deepEqual((await usesLogged(db.owner)).map((use) => use.credential), [credentialId]);

  // Whoever owns the database deletes the credential's row: the log still leads from the read to its run.
  await db.owner.delete(credentials).where(eq(credentials.id, credentialId));
  await deps.vault.listReads();
  const { entries } = await root.audit.list({ detail: '1', sealed: '1' });
  // Its sign-in, the vault's change, which the page lists as a `token.exchange` entry; and every read it shows, the refused one included, with the run.
  const signedIn = entries.find((entry) => entry.action === 'token.exchange')!;
  assert.equal(signedIn.log, '0.15');
  assert.deepEqual(signedIn.run, { exchangeSeq: signedIn.seq, log: '0.15', claims: exchange!.run });
  assert.equal(signedIn.run!.claims.run_id, '7001');
  // The allowed read is the vault's use, listed as a `secret.read` entry, by the service, as the credential's
  // sign-in names it though its row is gone.
  const reads = entries.filter((entry) => entry.action === 'secret.read');
  assert.equal(reads.length, 2);
  for (const shown of reads) assert.deepEqual(shown.run, signedIn.run);
  assert.deepEqual(reads.map((read) => [read.log, read.decision, read.actorId, read.key]),
    [['0.14', 'deny', SERVICE, null], ['0.15', 'allow', SERVICE, 'API_KEY']]);
  // An entry no exchanged credential wrote has no run.
  assert.equal(entries.find((entry) => entry.action === 'secret.write')!.run, null);
});

/**
 * A run's sign-in on the audit pages: the vault's change, which is its record, listed as a
 * `token.exchange` entry with what it said: the service, the binding, the generation, the
 * issuer, the credential and its end, the run, and when. On every list of the instance's entries, and the service's;
 * on none of a place's, nor of refusals: a refused sign-in is logged by neither (the server's log says why).
 */
test("a run's sign-in is on the audit list as a `token.exchange` entry; a refused one, not", async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  const before = Date.now();
  const { body } = await trade(token(rsa));
  assert.equal((await trade(token(rsa, { aud: 'https://elsewhere.example' }))).status, 401);
  const after = Date.now();
  const [logged] = await signInsLogged(db.owner);
  const expected = {
    credentialId: logged!.credentialId, bindingId: bound, generation: logged!.record.generation, issuer: ISSUER, expiresAt: body.expiresAt, run: logged!.run,
  };
  for (const query of [{}, { detail: '1' as const }, { actor: MEMBER }, { actor: SERVICE }]) {
    const shown = (await root.audit.list({ ...query, sealed: '1' })).entries.filter((entry) => entry.action === 'token.exchange');
    assert.equal(shown.length, 1, `${JSON.stringify(query)} lists the one sign-in`);
    const [entry] = shown;
    assert.deepEqual(
      { log: entry!.log, author: entry!.author, actorType: entry!.actorType, actorId: entry!.actorId, decision: entry!.decision, detail: entry!.detail, project: entry!.project },
      { log: '0.15', author: 'vault', actorType: 'service', actorId: SERVICE, decision: 'allow', detail: false, project: null },
    );
    assert.deepEqual(Object.fromEntries(Object.keys(expected).map((name) => [name, entry!.metadata[name]])), expected);
    assert.deepEqual(entry!.run, { exchangeSeq: entry!.seq, log: '0.15', claims: logged!.run });
    const at = Date.parse(entry!.occurredAt);
    assert.ok(at >= before - 1000 && at <= after + 1000, `${entry!.occurredAt} is when it signed in`);
  }
  assert.equal(logged!.run.repository, 'acme/api');
  for (const query of [{ decision: 'deny' as const }, { path: 'market' }, { actor: DEV }]) {
    assert.deepEqual((await root.audit.list({ ...query, detail: '1', sealed: '1' })).entries.filter((entry) => entry.action === 'token.exchange'), [], JSON.stringify(query));
  }
});

/**
 * Pages of the audit list tile both logs: each entry on one page, newest first, a sign-in 0.15's log records
 * among 0.14's entries by when; each page's `next`, `before` for the one after, says where it stopped in each. The
 * detail entries a page leaves out are counted on one page each, as with 0.14's log alone.
 */
test('pages of the audit list tile both logs: every entry once, newest first, and every hidden one counted once', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  for (let i = 0; i < 3; i++) {
    await root.secrets.set('market/dev', { [`KEY_${i}`]: 'value' });
    for (let k = 0; k < 2; k++) assert.equal((await trade(token(rsa))).status, 200);
  }
  const named = (entries: { log: string; seq: number }[]) => entries.map((entry) => `${entry.log}:${entry.seq}`);
  for (const query of [{}, { detail: '1' as const }, { actor: SERVICE }]) {
    // Counted too (`hidden`), as a caller that asks for it pages.
    const whole = await root.audit.list({ ...query, sealed: '1', hidden: '1', limit: 500 });
    assert.deepEqual([whole.more, whole.next], [false, null]);
    assert.equal(whole.entries.filter((entry) => entry.action === 'token.exchange').length, 6);
    for (const [i, entry] of whole.entries.entries()) {
      if (i > 0) assert.ok(Date.parse(whole.entries[i - 1]!.occurredAt) >= Date.parse(entry.occurredAt), 'newest first');
    }
    for (const limit of [1, 2, 5]) {
      const paged: typeof whole.entries = [];
      const hidden = new Map<string, number>();
      let before: string | undefined;
      do {
        const page = await root.audit.list({ ...query, sealed: '1', hidden: '1', limit, ...(before === undefined ? {} : { before }) });
        assert.ok(page.entries.length <= limit);
        assert.equal(page.more, page.next !== null);
        paged.push(...page.entries);
        for (const { action, count } of page.hidden ?? []) hidden.set(action, (hidden.get(action) ?? 0) + count);
        before = page.next ?? undefined;
      } while (before !== undefined);
      assert.deepEqual(named(paged), named(whole.entries), `${JSON.stringify(query)}, ${limit} a page`);
      assert.deepEqual(hidden, new Map((whole.hidden ?? []).map(({ action, count }) => [action, count])), `${JSON.stringify(query)}, ${limit} a page: hidden`);
    }
  }
  // A client that does not ask for 0.15's sealed log, as one before 0.15, pages 0.14's log alone, by the last seq it
  // read: whole, each entry once; and a seq alone pages 0.14's log, whatever it asks.
  const legacy: number[] = [];
  for (let before: number | undefined; ;) {
    const page = await root.audit.list({ limit: 1, ...(before === undefined ? {} : { before }) });
    assert.ok(page.entries.every((entry) => entry.log === '0.14'));
    legacy.push(...page.entries.map((entry) => entry.seq));
    // A full page says there may be more: below the first entry, 0, there is none to ask for.
    if (!page.more || page.entries.at(-1)!.seq === 0) break;
    before = page.entries.at(-1)!.seq;
  }
  const whole = (await root.audit.list({ limit: 500, sealed: '1' })).entries.filter((entry) => entry.log === '0.14');
  assert.deepEqual(legacy, whole.map((entry) => entry.seq));
  const newest = whole.at(0)!;
  assert.ok((await root.audit.list({ before: newest.seq, sealed: '1', limit: 500 })).entries.every((entry) => entry.log === '0.14' && entry.seq < newest.seq));
});

/**
 * A sign-in takes its number when it commits, after any wait for a lock, but is listed by when the vault asked (its
 * `at`), as everything else on the page is by when it happened: one that asked later but waited less is the newer,
 * on the first page. Here the first, numbered first, says it asked after the second.
 */
test("sign-ins are listed newest first by when they were asked, not by the number a wait gave them", async () => {
  for (let i = 0; i < 2; i++) assert.equal((await trade(token(rsa))).status, 200);
  const [first, second] = await db.owner.select({ number: logChanges.number, at: logChanges.at }).from(logChanges)
    .where(sql`${logChanges.payload} LIKE '%"signIn":{%'`).orderBy(asc(logChanges.number));
  await db.owner.update(logChanges).set({ at: second!.at + 50 }).where(eq(logChanges.number, first!.number));
  const root = clientFor(deps, ROOT);
  const one = await root.audit.list({ actor: SERVICE, sealed: '1', limit: 1 });
  assert.deepEqual(one.entries.map((entry) => BigInt(entry.seq)), [first!.number]);
  const two = await root.audit.list({ actor: SERVICE, limit: 1, before: one.next! });
  assert.deepEqual(two.entries.map((entry) => BigInt(entry.seq)), [second!.number]);
  assert.deepEqual((await root.audit.list({ actor: SERVICE, sealed: '1', limit: 500 })).entries.filter((entry) => entry.log === '0.15').map((entry) => BigInt(entry.seq)), [first!.number, second!.number]);
});

/**
 * A row under the sign-ins' index that is no sign-in, which only a database writer leaves there: passed over, the
 * page going on past it, never a failure. Under either log: the page reads 0.15's changes as
 * they are.
 */
test("a change the sign-ins' index holds that is no sign-in is passed over, and the pages go on past it", async () => {
  assert.equal((await trade(token(rsa))).status, 200);
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges).orderBy(desc(logChanges.number)).limit(1);
  await db.owner.insert(logChanges).values({
    number: (newest?.number ?? 0n) + 1000n, at: Date.now() + 60_000, requestId: crypto.randomUUID(), object: crypto.randomUUID(), actor: MEMBER,
    payload: '{"op":"member.add","signIn":{"binding":"none"}}', mac: Buffer.alloc(16),
  });
  const root = clientFor(deps, ROOT);
  const seen: string[] = [];
  let before: string | undefined;
  let pages = 0;
  do {
    const page = await root.audit.list({ actor: SERVICE, sealed: '1', limit: 1, ...(before === undefined ? {} : { before }) });
    seen.push(...page.entries.map((entry) => `${entry.log} ${entry.action}`));
    before = page.next ?? undefined;
    pages++;
  } while (before !== undefined && pages < 10);
  assert.deepEqual(seen, ['0.15 token.exchange']);
  assert.ok(pages >= 2, 'the planted row took a page of its own, which showed nothing');
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
  assert.equal((await signInsLogged(db.owner)).at(-1)!.run['kubernetes.io.pod.name'], 'deploy-7f9c');
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

test("replacing keys asks each binding's change on its own: one that moved is asked again, those done stand (PR 3a, review r1)", async (t) => {
  const first = await bindCluster([rsa]);
  const other = await bindCluster([rsa], { sub: 'system:serviceaccount:ci:migrate' });
  assert.ok('binding' in first && 'binding' in other);
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let calls = 0;
  // The second binding's change finds a row moved (a sign-in through it, say), once.
  t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) => {
    calls += 1;
    return calls === 2 ? { ok: false as const, refused: 'moved' as const } : change(input);
  });
  const done = await replaceKeys([rsa, ec]);
  assert.ok('bindings' in done);
  assert.deepEqual(done.replaced, [first.binding.id, other.binding.id]);
  // The second moved, so closed (a sweep of none: no sign-in through it while it ends), then asked again.
  assert.equal(calls, 4, 'the first once, the second three times');
  assert.equal((await db.owner.select().from(serviceBindings)).filter((row) => row.revokedAt === null && row.issuer === first.binding.issuer).length, 2);
});

test("a binding made on the issuer while keys are replaced is no part of it: a conflict, not a success that leaves it on the old keys (PR 3a, review r2)", async (t) => {
  const first = await bindCluster([rsa]);
  assert.ok('binding' in first);
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let calls = 0;
  t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) => {
    calls += 1;
    // Once the replacement is planned, before its first change: another binding on the issuer, on the old keys.
    if (calls === 1) assert.ok('binding' in await bindCluster([rsa], { sub: 'system:serviceaccount:ci:late' }));
    return change(input);
  });
  await assert.rejects(replaceKeys([rsa, ec]), { status: 409, message: /changed while their keys were replaced/ });
});

test("a replacement of keys that stopped part way is finished by asking again with the same keys (PR 3a, review r3)", async (t) => {
  const first = await bindCluster([rsa]);
  const other = await bindCluster([rsa], { sub: 'system:serviceaccount:ci:migrate' });
  assert.ok('binding' in first && 'binding' in other);
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let calls = 0;
  // The vault busy for the second binding's change: the first done, the request answers 503.
  const busy = t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) => {
    calls += 1;
    return calls === 2 ? { ok: false as const, refused: 'busy' as const } : change(input);
  });
  await assert.rejects(replaceKeys([rsa, ec]), { status: 503 });
  busy.mock.restore();
  const done = await replaceKeys([rsa, ec]);
  assert.ok('bindings' in done);
  assert.deepEqual(done.replaced, [other.binding.id], 'what the first left');
  const live = (await db.owner.select().from(serviceBindings)).filter((row) => row.revokedAt === null && row.issuer === first.binding.issuer);
  assert.equal(live.length, 2);
  assert.ok(live.every((row) => row.jwks !== null && row.jwksUri !== first.binding.jwksUri), 'both on the new keys');
});

test("a row a writer broke is no wedge: a credential whose MAC fails ends with its binding, and a binding row whose MAC fails stops no other bind (PR 3a, Fable)", async () => {
  const id = (await db.owner.select().from(serviceBindings))[0]!.id;
  const { body } = await trade(token(rsa));
  assert.ok(body.token);
  // The run's credential, its MAC broken: dead to the app's checks, still a live row to the vault's statement.
  await db.owner.update(credentials).set({ authMac: Buffer.alloc(32, 7) });
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, id);
  assert.ok((await db.owner.select().from(credentials)).every((row) => row.revokedAt !== null), 'ended with its binding');
  assert.notEqual((await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id)))[0]!.revokedAt, null);
  // A binding row whose MAC a writer broke: the next bind of the account goes ahead, and the broken one is still ended.
  const broken = await bind(DEPLOY);
  await db.owner.update(serviceBindings).set({ authMac: Buffer.alloc(32, 9) }).where(eq(serviceBindings.id, broken));
  await bind({ ...DEPLOY, environment: 'staging' } as BindingClaims);
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, broken);
  assert.notEqual((await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, broken)))[0]!.revokedAt, null);
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
    const id = (await signInsLogged(db.owner)).at(-1)!.bindingId;
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

test("a token with fractional times, and one with every claim a run records, sign in as any other (the record's bounds are runClaims')", async () => {
  // Times in fractional seconds, which the token's checks take: the proof's end is whole ms, down.
  assert.equal((await trade(token(rsa, { iat: seconds() - 5.5, exp: seconds() + 295.0001 }))).status, 200);
  const every = {
    actor: 'octocat', base_ref: '', head_ref: '', run_attempt: '1', job_workflow_ref: DEPLOY.workflow_ref, job_workflow_sha: 'f'.repeat(40), environment: 'Production',
    project_path: 'acme/api', project_id: '1', namespace_id: '2', pipeline_id: '3', pipeline_source: 'push', job_id: '4', 'kubernetes.io': { pod: { name: 'deploy-7f9c' } },
  };
  const { status, body } = await trade(token(rsa, every));
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(Object.keys((await signInsLogged(db.owner)).at(-1)!.run).length > 16, true, 'more than 16 claims recorded');
});

test('no limit counts every address together: 301 exchanges in a minute, from 301 addresses, all past admission (W331, D177)', async () => {
  limits = processLimits();
  // One after another: 32 at once is the isolate's bound on exchanges in flight, which stays.
  const answers = [];
  for (let n = 0; n < 301; n++) answers.push(await exchange({ service: MEMBER, token: 'not.a.token' }, `198.51.${n >> 8}.${n & 255}`));
  // Each refused for its token, after admission: none for a count.
  assert.deepEqual(new Set(answers.map(({ status, body }) => `${status} ${body.reason}`)), new Set(['401 malformed']));
});

test("one binding's sign-ins share its row: one goes through while another holds it, and waits only for an unbind's lock (W331)", async () => {
  /** The binding's row held in a transaction of the owner's, `mode`, until `release`; the hold once it has the row. */
  const hold = async (mode: 'KEY SHARE' | 'UPDATE') => {
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    let locked!: () => void;
    const holding = new Promise<void>((resolve) => (locked = resolve));
    const done = db.owner.transaction(async (tx) => {
      await (tx as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(sql`SELECT 1 FROM service_bindings WHERE id = ${bound} FOR ${sql.raw(mode)}`);
      locked();
      await released;
    });
    await holding;
    return { release: async () => (release(), await done) };
  };
  // As another sign-in in flight holds it: this one does not wait for it.
  const shared = await hold('KEY SHARE');
  const started = performance.now();
  assert.equal((await trade(token(rsa))).status, 200);
  assert.ok(performance.now() - started < 900, `a sign-in waited ${(performance.now() - started).toFixed(0)} ms behind another's share of its binding`);
  await shared.release();
  // As an unbind holds it: the sign-in waits, and goes ahead once the unbind lets go.
  const ending = await hold('UPDATE');
  let settled = false;
  const waiting = trade(token(rsa)).finally(() => (settled = true));
  await sleep(300);
  assert.equal(settled, false, "a sign-in went ahead under an unbind's lock on its binding");
  await ending.release();
  assert.equal((await waiting).status, 200);
  // Held past the statement's `lock_timeout`: refused as a moment's wait, asked again in a second.
  const long = await hold('UPDATE');
  const busy = await trade(token(rsa));
  await long.release();
  assert.deepEqual([busy.status, busy.body.reason, busy.retryAfter], [503, 'busy', '1']);
});

test('sign-ins racing an unbind of their binding: every credential it issued ends, made before the unbind or refused after it', async () => {
  const runs = Array.from({ length: 8 }, () => trade(token(rsa)));
  const unbound = runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  const outcomes = await Promise.all(runs);
  await unbound;
  for (const { status, body } of outcomes) assert.ok(status === 200 || (status === 401 && body.reason === 'no_match'), `${status} ${body.reason}`);
  const live = (await db.owner.select({ revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.createdBy, `binding:${bound}`)))
    .filter(({ revokedAt }) => revokedAt === null);
  assert.deepEqual(live, [], 'a credential the binding issued outlived its unbind');
  for (const { status, body } of outcomes) if (status === 200) assert.equal(await caller(body.token!), 401);
});

test("a binding's last use is stamped at most once a minute, whatever its sign-ins (W331, D177)", async () => {
  const lastUsed = async () => (await db.owner.select({ at: serviceBindings.lastUsedAt }).from(serviceBindings).where(eq(serviceBindings.id, bound)))[0]!.at;
  assert.equal((await trade(token(rsa))).status, 200);
  const first = await lastUsed();
  assert.notEqual(first, null, 'a first sign-in stamps it');
  await Promise.all(Array.from({ length: 4 }, () => trade(token(rsa))));
  assert.equal((await lastUsed())!.getTime(), first!.getTime(), 'stamped again within the minute');
  // A minute on: the next sign-in stamps it.
  const old = new Date(Date.now() - 61_000);
  await db.owner.update(serviceBindings).set({ lastUsedAt: old }).where(eq(serviceBindings.id, bound));
  assert.equal((await trade(token(rsa))).status, 200);
  assert.ok((await lastUsed())!.getTime() > old.getTime() + 60_000);
});


/** `count` sign-ins through the binding, 16 at a time: their credentials, each live. */
async function signIns(count: number): Promise<string[]> {
  const made: string[] = [];
  for (let n = 0; n < count; n += 16) {
    for (const { status, body } of await Promise.all(Array.from({ length: Math.min(16, count - n) }, () => trade(token(rsa))))) {
      assert.equal(status, 200, JSON.stringify(body));
      made.push(body.token!);
    }
  }
  return made;
}

/** The binding's credentials not revoked, and whether its row is closed and ended. */
async function bindingState(id: string): Promise<{ live: number; closed: boolean; ended: boolean }> {
  const rows = await db.owner.select({ revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.createdBy, `binding:${id}`));
  const [row] = await db.owner.select({ closedAt: serviceBindings.closedAt, revokedAt: serviceBindings.revokedAt }).from(serviceBindings).where(eq(serviceBindings.id, id));
  return { live: rows.filter(({ revokedAt }) => revokedAt === null).length, closed: row!.closedAt !== null, ended: row!.revokedAt !== null };
}

test(`a binding with more live credentials than one call revokes (${UNBIND_BATCH}) is removed in batches: closed first, every credential revoked, then ended (W331)`, {
  timeout: 600_000,
}, async () => {
  limits = processLimits();
  // Past what one Node vault message carries (about 15,000), as a binding signing in at 1,000 a second has in 30 s.
  const count = Number(process.env.UNBIND_COUNT ?? 31_000);
  await signIns(count);
  const calls: { sweep: boolean; credentials: number }[] = [];
  const change = deps.vault.changeBindings!.bind(deps.vault);
  deps.vault.changeBindings = async (input) => {
    calls.push({ sweep: input.sweep === true, credentials: input.ends.reduce((sum, end) => sum + end.credentials.length, 0) });
    return change(input);
  };
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  assert.ok(calls.every(({ credentials: n }) => n <= UNBIND_BATCH), 'a call named more than a batch');
  assert.equal(calls.filter(({ sweep }) => sweep).length, Math.ceil((count - UNBIND_BATCH) / UNBIND_BATCH));
  assert.deepEqual(calls.at(-1), { sweep: false, credentials: count - calls.filter(({ sweep }) => sweep).length * UNBIND_BATCH });
  assert.equal((await trade(token(rsa))).body.reason, 'no_match');
});

/** The vault calls made through the isolate's counted entry, in order (`workersRequest`). */
const askedOfVault: string[] = [];
/** The isolate's entry of the suite's vault, each call named in `askedOfVault`: one for every request, as on Workers. */
const isolateEntries = new WeakMap<object, VaultEntry>();

/**
 * One Worker request's coffre (cloudflare-handler.ts, `runtimeFor`): the isolate's vault, through its counted entry as
 * a service binding's calls are, and a removal held to what one invocation may spend (removal.ts); `run` its work, for
 * its calls to count as its own. `asked` names the calls it made.
 */
function workersRequest() {
  let entry = isolateEntries.get(deps.vault);
  if (entry === undefined) {
    const inner = entryOf(deps.vault);
    entry = { call: (release, method, args) => (askedOfVault.push(method), inner.call(release, method, args)) } satisfies VaultEntry;
    isolateEntries.set(deps.vault, entry);
  }
  const vault = versioned(countedEntry(entry));
  const counter = countingCalls();
  const runtime = createRuntime(config, deps.db, vault, transport, undefined, undefined, workersRemovalBudget(counter.calls));
  const from = askedOfVault.length;
  return {
    runtime, vault, run: counter.run, calls: counter.calls, asked: () => askedOfVault.slice(from),
    context: (id: string) => contextFor({ ...deps, vault: vault as never, workloads: runtime.workloads! }, id),
  };
}

/** A request to the API as ROOT, each one a Worker request of its own. */
async function asWorker(request: Request): Promise<Response> {
  const worker = workersRequest();
  return worker.run(async () => serveApi(request, await worker.context(ROOT)));
}

test("a Worker's requests share the isolate's vault, for its caches, and each counts only its own calls, run at once (review r8)", async () => {
  const [one, two] = [workersRequest(), workersRequest()];
  assert.equal(one.vault, two.vault, 'one vault for the isolate');
  await Promise.all([
    one.run(async () => { await one.vault.about(); await one.vault.about(); }),
    two.run(async () => { await two.vault.about(); }),
  ]);
  assert.deepEqual([one.calls(), two.calls()], [2, 1]);
});

test("on Workers, a removal past what one request revokes answers 202 with what is left, its binding closed; the client asks again until it is done (W331)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const count = 5 * WORKERS_BATCH + 7;
  await signIns(count);
  const remove = () => new Request(`https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings/${bound}`, { method: 'DELETE' });
  const first = await asWorker(remove());
  assert.equal(first.status, 202);
  // Two batches a request (removal.ts, `WORKERS_BATCHES`), each a vault call; left, the credentials and the binding to end.
  assert.deepEqual(await first.json(), { removing: { left: count - 2 * WORKERS_BATCH + 1, progressed: true } });
  assert.deepEqual(await bindingState(bound), { live: count - 2 * WORKERS_BATCH, closed: true, ended: false });
  assert.equal((await trade(token(rsa))).body.reason, 'no_match');
  // Shown as being removed, by whom and since when.
  const listed = (await createClient({ url: 'https://coffre.test', transport: asWorker }).bindings.list(MEMBER)).bindings.find(({ id }) => id === bound)!;
  assert.equal(listed.removing?.by, `user:${ROOT}`);
  assert.ok(listed.removing !== null && Date.parse(listed.removing.since) <= Date.now());

  const told: number[] = [];
  const client = createClient({ url: 'https://coffre.test', transport: asWorker, onRemoving: (left) => told.push(left) });
  await client.bindings.remove(MEMBER, bound);
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  assert.deepEqual(told, [count - 4 * WORKERS_BATCH + 1]);
  assert.deepEqual((await appEntries('token.unbind')).map(({ actor }) => actor), [`user:${ROOT}`]);
});

test("a removal left under way is finished by the scheduled run, as the system, each change naming whom it continues (W331)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const count = 3 * WORKERS_BATCH;
  await signIns(count);
  const before = (await db.owner.select({ number: logChanges.number }).from(logChanges)).length;
  const response = await asWorker(new Request(`https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings/${bound}`, { method: 'DELETE' }));
  assert.equal(response.status, 202);
  const [{ closedAt }] = await db.owner.select({ closedAt: serviceBindings.closedAt }).from(serviceBindings).where(eq(serviceBindings.id, bound));
  // Each beat goes on as far as a Worker's invocation may, two batches; this one ends it.
  const beat = workersRequest();
  await beat.run(() => runScheduled(beat.runtime));
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  const changes = (await db.owner.select({ payload: logChanges.payload }).from(logChanges).orderBy(asc(logChanges.number))).slice(before)
    .map(({ payload }) => JSON.parse(payload) as { op: string; unbind?: { by: string; continues?: unknown }; revoke?: { continues?: { by: string; at: number } } });
  const continued = { by: `user:${ROOT}`, at: closedAt!.getTime() };
  const ending = changes.filter(({ op }) => op === 'binding.revoke');
  assert.deepEqual(ending.map(({ unbind }) => unbind), [{ by: 'system:schedule', reason: 'unbound', replacedBy: null, continues: continued }]);
  const revokes = changes.filter(({ revoke }) => revoke !== undefined);
  assert.equal(revokes.length, count);
  assert.equal(revokes.filter(({ revoke }) => revoke!.continues?.by === continued.by && revoke!.continues.at === continued.at).length, count - 2 * WORKERS_BATCH);
  const [unbound] = await appEntries('token.unbind');
  assert.equal(unbound!.actor, 'system:schedule');
  assert.deepEqual([unbound!.metadata.removedBy, unbound!.metadata.closedAt], [`user:${ROOT}`, closedAt!.toISOString()]);
  // Nothing left: the next beat finds no removal to go on with.
  const next = workersRequest();
  await next.run(() => runScheduled(next.runtime));
  assert.equal((await appEntries('token.unbind')).length, 1);
});

test("on Workers, a replacement of keys of more bindings than a request replaces is asked again until every one is on the new keys, runs signing in on those not yet replaced (reviews r8, r9)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const jobs = Array.from({ length: 5 }, (_, n) => ({ sub: `system:serviceaccount:ci:job-${n}` }));
  for (const job of jobs) assert.ok('binding' in await bindCluster([rsa], job));
  // Each with more credentials than a call revokes, so that each one's make is a sweep's.
  for (const job of jobs) {
    for (let n = 0; n < 2 * WORKERS_BATCH; n += 16) {
      for (const { status, body } of await Promise.all(Array.from({ length: 16 }, () => trade(projected(rsa, job))))) assert.equal(status, 200, JSON.stringify(body));
    }
  }
  // The last one's runs keep signing in, adding to what is left of it, until its own turn comes.
  let signing = true;
  const runs = (async () => { while (signing) await trade(projected(rsa, jobs[4]!)); })();
  const told: number[] = [];
  const client = createClient({ url: 'https://coffre.test', transport: asWorker, onRemoving: (left) => told.push(left) });
  await client.bindings.replaceKeys(MEMBER, { issuer: CLUSTER, jwks: { keys: [rsa.jwk, ec.jwk] } } as never);
  signing = false;
  await runs;
  // A request replaces two, each its one call; what is left is the bindings not yet replaced.
  assert.deepEqual(told, [3, 1]);
  const rows = (await db.owner.select().from(serviceBindings)).filter((row) => row.issuer === CLUSTER);
  const fresh = rows.filter((row) => row.closedAt === null && row.revokedAt === null);
  assert.equal(fresh.length, 5);
  assert.equal(new Set(fresh.map(({ jwksUri }) => jwksUri)).size, 1, 'every one on the new keys');
  // The old ones closed, signing nobody in; the scheduled run ends them, a beat at a time.
  for (let beat = 0; beat < 10 && rows.some((row) => row.closedAt !== null && row.revokedAt === null); beat += 1) {
    const worker = workersRequest();
    await worker.run(() => runScheduled(worker.runtime));
    rows.splice(0, rows.length, ...(await db.owner.select().from(serviceBindings)).filter((row) => row.issuer === CLUSTER));
  }
  assert.ok(rows.every((row) => row.closedAt === null || row.revokedAt !== null), 'every old one ended');
});

test("on Workers, a replacement answers once its first call has made the new binding, as it closes the old one: the scheduled run ends that (reviews r8, r9)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const tokens = await signIns(3 * WORKERS_BATCH);
  const release = { ...DEPLOY, ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' };
  const path = `https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings`;
  // One request, as MCP's trust_workload makes it from inside its own: no 202 to ask again on.
  const answered = await asWorker(new Request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profile: 'github', issuer: null, claims: release, label: null, replaces: [bound] }) }));
  assert.equal(answered.status, 200, await answered.clone().text());
  const made = (await answered.json()) as { binding: { id: string }; replaced: string[] };
  assert.deepEqual(made.replaced, [bound]);
  assert.equal((await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.binding.id))).length, 1);
  assert.deepEqual(await bindingState(bound), { live: 2 * WORKERS_BATCH, closed: true, ended: false });
  assert.equal((await trade(token(rsa, release))).status, 200, 'the new binding signs its runs in');
  assert.equal((await trade(token(rsa))).body.reason, 'no_match', 'the old one none');
  // No tombstone of the old one before its end: a credential of it not yet revoked reads as the vault,
  // which a use by name asks first, still takes it, and the app refuses nothing the vault does not.
  assert.deepEqual((await appEntries('token.unbind')).length, 0);
  assert.equal(await caller(tokens.at(-1)!), `service:${SERVICE}`);
  const beat = workersRequest();
  await beat.run(() => runScheduled(beat.runtime));
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  assert.deepEqual((await appEntries('token.unbind')).map(({ actor }) => actor), ['system:schedule']);
  assert.equal(await caller(tokens.at(-1)!), 401);
});

test("a service at the cap replaces one binding in another's place, its old one closed and not yet ended, and then another: the cap counts open bindings (review r10)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const others: string[] = [];
  for (let n = 1; n < MAX_BINDINGS; n += 1) others.push(await bind({ ...DEPLOY, ref: `refs/heads/b${n}`, workflow_ref: `acme/api/.github/workflows/deploy.yml@refs/heads/b${n}` }));
  await signIns(3 * WORKERS_BATCH);
  const path = `https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings`;
  const replace = (replaces: string, ref: string) => asWorker(new Request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    profile: 'github', issuer: null, claims: { ...DEPLOY, ref, workflow_ref: `acme/api/.github/workflows/deploy.yml@${ref}` }, label: null, replaces: [replaces],
  }) }));
  const first = await replace(bound, 'refs/heads/next');
  assert.equal(first.status, 200, await first.clone().text());
  assert.deepEqual((await bindingState(bound)).closed, true);
  const second = await replace(others[0]!, 'refs/heads/after');
  assert.equal(second.status, 200, await second.text());
});

test("a removal asked again once the scheduled run has finished it is done, not unknown: answered once its end is sealed (review r9)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  await signIns(3 * WORKERS_BATCH);
  const remove = () => new Request(`https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings/${bound}`, { method: 'DELETE' });
  assert.equal((await asWorker(remove())).status, 202);
  const beat = workersRequest();
  await beat.run(() => runScheduled(beat.runtime));
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  const again = await asWorker(remove());
  assert.equal(again.status, 200, await again.text());
  // One whose columns a writer set around coffre, with no end the app logged: unknown still.
  const forged = await bind({ ...DEPLOY, ref: 'refs/heads/forged', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/forged' });
  await db.owner.update(serviceBindings).set({ closedAt: new Date(), revokedAt: new Date(), closedBy: `user:${ROOT}` }).where(eq(serviceBindings.id, forged));
  assert.equal((await asWorker(new Request(`https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings/${forged}`, { method: 'DELETE' }))).status, 404);
  // One never closed, and ended, is still unknown.
  const other = await bind({ ...DEPLOY, ref: 'refs/heads/other', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/other' });
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, other);
  assert.equal((await asWorker(new Request(`https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings/${other}`, { method: 'DELETE' }))).status, 404);
});

test("the scheduled run reads a removal again when another remover moved it, and one the vault refuses stops no other (Fable on #520)", async (t) => {
  limits = processLimits();
  const other = await bind({ ...DEPLOY, ref: 'refs/heads/other', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/other' });
  await signIns(3);
  // Both closed by removals left under way, the first one earlier.
  await db.owner.update(serviceBindings).set({ closedAt: new Date(Date.now() - 60_000), closedBy: `user:${ROOT}` }).where(eq(serviceBindings.id, bound));
  await db.owner.update(serviceBindings).set({ closedAt: new Date(), closedBy: `user:${ROOT}` }).where(eq(serviceBindings.id, other));
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let movedOnce = false;
  t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) => {
    // The first, edited around the vault: refused for good. The second, moved once by a request revoking beside it.
    if (input.ends.some((end) => end.before.columns.id === bound)) return { ok: false as const, refused: 'stale' as const };
    if (!movedOnce) {
      movedOnce = true;
      return { ok: false as const, refused: 'moved' as const };
    }
    return change(input);
  });
  const logged = t.mock.method(console, 'error', () => {});
  // And, closed before both, one whose close a writer left without its remover.
  const malformed = await bind({ ...DEPLOY, ref: 'refs/heads/malformed', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/malformed' });
  await db.owner.update(serviceBindings).set({ closedAt: new Date(Date.now() - 120_000), closedBy: null }).where(eq(serviceBindings.id, malformed));
  const { resumed, failed } = await runtime.workloads!.resumeRemovals();
  assert.deepEqual(resumed, [other]);
  assert.deepEqual(failed.map(({ id }) => id), [malformed, bound]);
  assert.ok(logged.mock.calls.length >= 1);
  assert.deepEqual(await bindingState(other), { live: 0, closed: true, ended: true });
  assert.deepEqual((await bindingState(bound)).ended, false);
  await assert.rejects(runScheduled(runtime), new RegExp(`removal could not be gone on with: ${malformed}: its close names no remover`));
});

test("a removal the scheduled run cannot read again after a move is its failure alone: the next one ends all the same (review r13)", async (t) => {
  limits = processLimits();
  const other = await bind({ ...DEPLOY, ref: 'refs/heads/other', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/other' });
  await signIns(3);
  await db.owner.update(serviceBindings).set({ closedAt: new Date(Date.now() - 60_000), closedBy: `user:${ROOT}` }).where(eq(serviceBindings.id, bound));
  await db.owner.update(serviceBindings).set({ closedAt: new Date(), closedBy: `user:${ROOT}` }).where(eq(serviceBindings.id, other));
  const change = deps.vault.changeBindings!.bind(deps.vault);
  t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) =>
    input.ends.some((end) => end.before.columns.id === bound) ? { ok: false as const, refused: 'moved' as const } : change(input));
  // The first one's read again fails: its row is gone from under the read (a dropped connection, say).
  const drop = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bound));
  let reads = 0;
  t.mock.method(console, 'error', () => {});
  const original = deps.db.select.bind(deps.db);
  t.mock.method(deps.db, 'select', ((...args: Parameters<typeof original>) => {
    const query = original(...args);
    return new Proxy(query, {
      get(target, key, receiver) {
        const value = Reflect.get(target, key, receiver);
        if (key !== 'from' || typeof value !== 'function') return value;
        return (table: unknown, ...rest: unknown[]) => {
          if (table === serviceBindings && drop.length > 0) {
            reads += 1;
            // The first read is `closedBindings`'; the next is the retry's, which fails.
            if (reads === 2) throw new Error('the connection went away');
          }
          return (value as (...a: unknown[]) => unknown).call(target, table, ...rest);
        };
      },
    });
  }) as typeof original);
  const { resumed, failed } = await runtime.workloads!.resumeRemovals();
  t.mock.restoreAll();
  assert.deepEqual(failed.map(({ id, error }) => [id, error]), [[bound, 'the connection went away']]);
  assert.deepEqual(resumed, [other]);
  assert.deepEqual(await bindingState(other), { live: 0, closed: true, ended: true });
});

test("a removal reads what is live on the database's clock, which the end names on: an app clock ahead of it ends the binding all the same (Fable on #520)", async (t) => {
  limits = processLimits();
  // Credentials ending within the two minutes the app's clock is ahead: live on the database's, expired on the app's.
  await run(sql`INSERT INTO credentials (kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at)
    SELECT 'service', decode(repeat('00', 32), 'hex'), sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'coffre_svc_…', 0, ${MEMBER}, ${`binding:${bound}`}, now(), now() + n * interval '1 second'
    FROM generate_series(1, 60) n`);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 120_000 });
  try {
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  } finally {
    t.mock.timers.reset();
  }
  assert.deepEqual((await bindingState(bound)).ended, true);
});

test(`a binding change's request counts its vault calls: after its removal's last, it makes ${AFTER_REMOVAL_CALLS} (W331, removal.ts)`, {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const after = async (request: Request) => {
    const worker = workersRequest();
    const response = await worker.run(async () => {
      const answered = await serveApi(request, await worker.context(ROOT));
      await drainBackgroundTasks();
      return answered;
    });
    assert.ok(response.status < 300, `${response.status} ${await response.text()}`);
    const asked = worker.asked();
    const last = asked.lastIndexOf('changeBindings');
    assert.ok(last >= 0, asked.join(', '));
    return asked.length - 1 - last;
  };
  const path = `https://coffre.test/api/members/${encodeURIComponent(MEMBER)}/bindings`;
  const json = (body: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  await signIns(3);
  const release = { ...DEPLOY, ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' };
  const counts = [
    // A binding made in place of another, which issued three credentials.
    await after(new Request(path, json({ profile: 'github', issuer: null, claims: release, label: null, replaces: [bound] }))),
  ];
  const [made] = await db.owner.select({ id: serviceBindings.id }).from(serviceBindings).where(isNull(serviceBindings.revokedAt));
  // And removed.
  counts.push(await after(new Request(`${path}/${made!.id}`, { method: 'DELETE' })));
  assert.deepEqual(counts.map((n) => n <= AFTER_REMOVAL_CALLS), counts.map(() => true), `calls after the last: ${counts.join(', ')}`);
  assert.equal(Math.max(...counts), AFTER_REMOVAL_CALLS, 'the constant is no larger than any route needs');
});

test('a removal that fails midway leaves its binding closed, signing nobody in, and run again ends it (W331)', {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  const tokens = await signIns(3 * UNBIND_BATCH);
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let calls = 0;
  deps.vault.changeBindings = async (input) => {
    if (++calls === 3) throw new Error('the app went away');
    return change(input);
  };
  await assert.rejects(runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound), /the app went away/);
  // Two sweeps done: closed, a batch or two revoked, the rest still live; no run signs in through it any more.
  const midway = await bindingState(bound);
  assert.deepEqual([midway.closed, midway.ended, midway.live], [true, false, 3 * UNBIND_BATCH - 2 * UNBIND_BATCH]);
  assert.deepEqual([(await trade(token(rsa))).status, (await trade(token(rsa))).body.reason], [401, 'no_match']);
  // The credentials it exchanged not yet revoked still read until their batch (or their own end, five minutes at most):
  // the vault decides a use by name before the app reads the binding, so the app may refuse nothing it does not
  // (`bindingStands`). Its sessions it refuses at once (workload-sessions.test.ts).
  const reading = async () => (await Promise.all(tokens.map((credential) => caller(credential)))).filter((who) => who === `service:${SERVICE}`).length;
  assert.equal(await reading(), UNBIND_BATCH);
  deps.vault.changeBindings = change;
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  assert.equal(await reading(), 0);
});

test('a removal ends a binding that runs keep signing in through: closed, it stops taking them, rather than being moved forever (W331)', {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  await signIns(2 * UNBIND_BATCH);
  let signing = true;
  const refused: string[] = [];
  const runs = Array.from({ length: 8 }, async () => {
    while (signing) {
      const { status, body } = await trade(token(rsa));
      if (status !== 200) refused.push(`${status} ${body.reason}`);
    }
  });
  const change = deps.vault.changeBindings!.bind(deps.vault);
  const asked: string[] = [];
  deps.vault.changeBindings = async (input) => {
    const answer = await change(input);
    asked.push(`${input.sweep === true ? 'sweep' : 'end'} ${answer.ok ? 'ok' : answer.refused}`);
    return answer;
  };
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound);
  signing = false;
  await Promise.all(runs);
  assert.deepEqual(await bindingState(bound), { live: 0, closed: true, ended: true });
  assert.ok(asked.length <= 6, `${asked.length} calls: ${asked.join(', ')}`);
  assert.equal(asked.at(-1), 'end ok');
  assert.ok(refused.length > 0 && refused.every((why) => why === '401 no_match'), refused.slice(0, 5).join(', '));
});

test('a bind that ends nothing, moved by another bind, is asked again as it was, closing nothing (W331)', async (t) => {
  const change = deps.vault.changeBindings!.bind(deps.vault);
  const asked: boolean[] = [];
  t.mock.method(deps.vault as Required<Vault>, 'changeBindings', async (input: Parameters<typeof change>[0]) => {
    asked.push(input.sweep === true);
    return asked.length === 1 ? { ok: false as const, refused: 'moved' as const } : change(input);
  });
  await bind({ ...DEPLOY, ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' });
  assert.deepEqual(asked, [false, false]);
  assert.deepEqual(await bindingState(bound), { live: 0, closed: false, ended: false });
});


test('a removal cuts its batches by bytes too: credentials reaching a hundred places go a few hundred a call, each call well inside a vault message (review r4)', {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  // The account holds a hundred projects more, which a binding made now reaches, and each credential it issues names.
  const ids = Array.from({ length: 100 }, () => crypto.randomUUID());
  await db.owner.insert(projects).values(ids.map((id, n) => ({ id, slug: `wide-${n}`, name: `wide ${n}` })));
  const granted = await speaking(deps.vault).setAccess({ actor: `user:${ROOT}`, principal: MEMBER, changes: ids.map((projectId) => ({ projectId, environmentId: null, role: 'viewer' as Role, expiresAt: null })) });
  assert.ok(granted.ok);
  const release = { ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' };
  const wide = await bind({ ...DEPLOY, ...release });
  for (let n = 0; n < 800; n += 16) {
    for (const { status, body } of await Promise.all(Array.from({ length: 16 }, () => trade(token(rsa, release))))) assert.equal(status, 200, JSON.stringify(body));
  }
  const calls: { credentials: number; bytes: number }[] = [];
  const change = deps.vault.changeBindings!.bind(deps.vault);
  deps.vault.changeBindings = async (input) => {
    calls.push({ credentials: input.ends.reduce((sum, end) => sum + end.credentials.length, 0), bytes: JSON.stringify(input).length });
    return change(input);
  };
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, wide);
  assert.deepEqual(await bindingState(wide), { live: 0, closed: true, ended: true });
  assert.ok(calls.length > 2 && calls.every(({ credentials, bytes }) => credentials < UNBIND_BATCH && bytes < 5 * 1024 * 1024), JSON.stringify(calls));
  assert.equal(calls.reduce((sum, { credentials }) => sum + credentials, 0), 800);
});

test("what a removal under way says is left costs the same however long the binding's history (T245)", async () => {
  // 3,000 live of the binding, 20,000 live of another binding of the service; then history, as it grows: credentials
  // that ended long ago, a third revoked before they ended.
  const insert = (count: number, by: string, ends: SQL, revoked: SQL = sql`NULL`) => run(sql`INSERT INTO credentials (kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at, revoked_at)
    SELECT 'service', decode(repeat('00', 32), 'hex'), sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'coffre_svc_…', 0, ${MEMBER}, ${by}, now() - interval '31 days', ${ends}, ${revoked}
    FROM generate_series(1, ${count}) n`);
  await insert(3_000, `binding:${bound}`, sql`now() + n * interval '1 millisecond' + interval '2 minutes'`);
  await insert(20_000, 'binding:00000000-0000-4000-8000-000000000000', sql`now() + n * interval '1 millisecond' + interval '1 minute'`);
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const left = async (history: number) => {
    // In stretches, each well within the test pool's statement timeout.
    for (let made = 0; made < history; made += 150_000) {
      await insert(Math.min(150_000, history - made), `binding:${bound}`, sql`now() - interval '30 days'`, sql`CASE WHEN n % 3 = 0 THEN now() - interval '30 days' END`);
    }
    await run(sql`ANALYZE credentials`);
    const seen: Statement[] = [];
    assert.equal(await liveIssued(createDatabase(counted(pool, seen)), MEMBER, [bound]), 3_000);
    return planOf(pool, seen[0]!, 'credentials');
  };
  try {
    // At 150,000 ended and at five times that, the count reads the principal's live credentials alone, through
    // `credentials_live_idx`: as the history grows, the share of credentials live falls, and with it Postgres's
    // estimate of what the index reads, so no scan of the table, nor of the binding's history (the index by issuer),
    // is ever cheaper.
    const small = await left(150_000);
    const grown = await left(600_000);
    for (const plan of [small, grown]) {
      assert.ok(plan.indexes.includes('credentials_live_idx'), `indexes [${plan.indexes.join(', ')}], visited ${plan.visited}`);
      assert.ok(plan.visited <= 3_000 + 20_000 + 16, `visited ${plan.visited} credential rows for 3,000 live`);
    }
  } finally {
    await pool.end();
  }
});

test("a removal's batch read walks live credentials only, soonest to end, past the last batch: never the binding's history, and another binding's that end sooner once a removal (reviews r5, r6)", async () => {
  // 50,000 long expired; 3,000 live; and 20,000 live of another binding of the service, each ending before any of these.
  const insert = (count: number, by: string, ends: SQL) => run(sql`INSERT INTO credentials (kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at)
    SELECT 'service', decode(repeat('00', 32), 'hex'), sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'coffre_svc_…', 0, ${MEMBER}, ${by}, now(), ${ends}
    FROM generate_series(1, ${count}) n`);
  await insert(50_000, `binding:${bound}`, sql`now() - interval '30 days'`);
  await insert(3_000, `binding:${bound}`, sql`now() + n * interval '1 millisecond' + interval '2 minutes'`);
  await insert(20_000, 'binding:00000000-0000-4000-8000-000000000000', sql`now() + n * interval '1 millisecond' + interval '1 minute'`);
  await run(sql`ANALYZE credentials`);
  const pool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
  const read = async (after: Date | null) => {
    const seen: Statement[] = [];
    const soonest = await issuedSoonest(createDatabase(counted(pool, seen)), MEMBER, [bound], UNBIND_BATCH + 1, after);
    return { soonest, plan: await planOf(pool, seen[0]!, 'credentials') };
  };
  try {
    // The first walks the other binding's, which end sooner, once.
    const first = await read(null);
    assert.equal(first.soonest.length, UNBIND_BATCH + 1);
    assert.ok(first.plan.indexes.includes('credentials_live_idx'), first.plan.indexes.join(', '));
    assert.ok(first.plan.visited <= 20_000 + 2 * (UNBIND_BATCH + 1), `visited ${first.plan.visited} credential rows for the first batch`);
    // A batch revoked, as a sweep does; the next read from where it ended: about a batch, whatever ended sooner.
    const batch = first.soonest.slice(0, UNBIND_BATCH);
    await run(sql`UPDATE credentials SET revoked_at = now() WHERE id = ANY(${sql.param(batch.map(({ id }) => id))}::uuid[])`);
    const next = await read(batch.at(-1)!.expiresAt);
    assert.equal(next.soonest.length, UNBIND_BATCH + 1);
    assert.ok(!next.soonest.some(({ id }) => batch.some((done) => done.id === id)));
    assert.ok(next.plan.visited <= 2 * (UNBIND_BATCH + 1), `visited ${next.plan.visited} credential rows for the next batch`);
  } finally {
    await pool.end();
  }
});

test("a binding a removal closed shadows no other: a run another binding takes signs in through it while the removal is under way (review r6)", {
  timeout: 300_000,
}, async () => {
  limits = processLimits();
  // A second binding, made later, that takes the same runs: the older wins while both are live.
  const newer = await bind({ ...DEPLOY, event_name: ['push', 'workflow_dispatch'] } as unknown as BindingClaims);
  await signIns(2 * UNBIND_BATCH);
  const change = deps.vault.changeBindings!.bind(deps.vault);
  let calls = 0;
  deps.vault.changeBindings = async (input) => {
    if (++calls === 2) throw new Error('the app went away');
    return change(input);
  };
  await assert.rejects(runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, bound), /the app went away/);
  deps.vault.changeBindings = change;
  assert.equal((await bindingState(bound)).closed, true);
  // The closed one passed over: the newer signs the run in.
  const run = await trade(token(rsa));
  assert.equal(run.status, 200, JSON.stringify(run.body));
  const [made] = await db.owner.select({ createdBy: credentials.createdBy }).from(credentials).orderBy(desc(credentials.createdAt)).limit(1);
  assert.equal(made!.createdBy, `binding:${newer}`);
});


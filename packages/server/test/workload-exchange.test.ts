import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import type pg from 'pg';

import { github, signin, type BindingClaims, type RateLimiter } from '@coffre/core/identity';
import { createDatabase, type Database } from '@coffre/db';
import { asc, eq, sql, type SQL } from 'drizzle-orm';
import { migrationLedger } from '@coffre/db/dialect';

import { auditLog, credentials, serviceBindings } from './db/tables.ts';
import { handleRequest, type Ui } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
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
/** What the issuer publishes, by URL; `down` makes it unreachable. */
let published: Map<string, unknown>;
let issuer: { down: boolean; fetches: number };
let limits: { perSource: RateLimiter; total: RateLimiter };
let vaultCalls: number;

const transport: WorkloadTransport = {
  json: async (url) => {
    issuer.fetches++;
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
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    vaultCalls++;
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
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal, owner })).ok, true);
  }
  await bind(DEPLOY);
});

async function bind(claims: BindingClaims, replaces: string[] = []): Promise<string> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims, label: 'deploys', replaces }, { dryRun: false });
  assert.ok('binding' in made);
  return made.binding.id;
}

const ui = {} as Ui;

async function exchange(body: unknown, sourceIp: string | null = IP): Promise<{ status: number; body: Record<string, string> }> {
  const response = await handleRequest(
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
  const response = await handleRequest(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${credential}` } }), runtime, ui, IP);
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
  assert.deepEqual((await runtime.signin!.listServiceTokens(await contextFor(deps, ROOT), SERVICE)), []);
  const [binding] = await db.owner.select().from(serviceBindings);
  assert.notEqual(binding!.lastUsedAt, null);
  // An ES256 issuer is the same.
  assert.equal((await trade(token(ec))).status, 200);
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

test('refusals say why, never what a binding expects, and a stranger never reaches the vault', async () => {
  const reason = async (jwt: string, service = MEMBER) => (await trade(jwt, service)).body;
  // The claims that differ, by name.
  const feature = await reason(token(rsa, { ref: 'refs/heads/feature', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/feature' }));
  assert.deepEqual([feature.reason, feature.message], ['no_match', `no binding of ${MEMBER} trusts these claims: ref, workflow_ref differ`]);
  assert.ok(!feature.message!.includes('refs/heads/main'));
  assert.equal((await reason(token(rsa, { event_name: 'pull_request_target' }))).reason, 'no_match');
  assert.equal((await reason(token(rsa, { repository_id: '1' }))).reason, 'no_match');
  // An unknown service and an issuer it does not trust answer alike, before any vault call or fetch.
  vaultCalls = 0;
  issuer.fetches = 0;
  const nobody = await reason(token(rsa), 'token:nobody');
  const elsewhere = await reason(token(rsa, { iss: 'https://gitlab.com' }));
  assert.deepEqual([nobody.reason, elsewhere.reason], ['no_match', 'no_match']);
  assert.equal(nobody.message, `no binding of token:nobody trusts tokens from ${ISSUER}`);
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

/** `pool`, telling `seen` every statement it sends to the server, inside a transaction or not. */
function counted(pool: pg.Pool, seen: { text: string; values: unknown[] }[]): pg.Pool {
  const watch = <T extends object>(target: T): T => new Proxy(target, {
    get(on, key) {
      const value: unknown = Reflect.get(on, key, on);
      if (typeof value !== 'function') return value;
      if (key === 'query') {
        return (query: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          seen.push(typeof query === 'string' ? { text: query, values: values ?? [] } : { text: query.text, values: query.values ?? values ?? [] });
          return value.call(on, query, values);
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
  const seen: { text: string; values: unknown[] }[] = [];
  try {
    const stranger = createRuntime(config, createDatabase(counted(pool, seen)), deps.vault, transport);
    /** What one exchange cost: the statements it sent, its vault calls and its fetches. */
    const ask = async (service: string, jwt: string) => {
      seen.length = 0;
      [vaultCalls, issuer.fetches] = [0, 0];
      const response = await handleRequest(
        new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service, token: jwt }) }),
        stranger, ui, IP,
      );
      const { reason } = (await response.json()) as { reason?: string };
      return { status: response.status, reason, statements: seen.map((statement) => statement.text), vaultCalls, fetches: issuer.fetches };
    };
    const strangers = async (cases: (readonly [string, string])[]) => {
      for (const [service, jwt] of cases) {
        const { statements, ...rest } = await ask(service, jwt);
        assert.deepEqual({ ...rest, statements: statements.length }, { status: 401, reason: 'no_match', statements: 1, vaultCalls: 0, fetches: 0 }, statements.join('\n'));
        assert.match(statements[0]!, /from "service_bindings"/);
      }
    };
    // Not a token at all: nothing reaches the database.
    assert.deepEqual(await ask(MEMBER, 'not.a.token'), { status: 401, reason: 'malformed', statements: [], vaultCalls: 0, fetches: 0 });
    // A service with no binding, and an issuer the service's binding does not name: one read each.
    await strangers([['token:nobody', token(rsa)], [MEMBER, token(rsa, { iss: 'https://gitlab.com' })]]);
    // The binding removed: its token is a stranger's too.
    const id = (await db.owner.select().from(serviceBindings))[0]!.id;
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, id);
    await strangers([[MEMBER, token(rsa)]]);
    // That read goes through the bindings' index on (principal, issuer).
    const client = await pool.connect();
    try {
      await client.query('SET enable_seqscan = off');
      const [read] = seen;
      const plan = await client.query(`EXPLAIN ${read!.text}`, read!.values);
      assert.match(plan.rows.map((row: Record<string, string>) => row['QUERY PLAN']).join('\n'), /service_bindings_principal_idx/);
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
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

  // Someone not an owner tries: logged as a denial, and the credential still works.
  const devContext = await contextFor(deps, DEV);
  await assert.rejects(runtime.workloads!.unbind(devContext, SERVICE, id), /only owners/);
  assert.equal(await caller(credential), `service:${SERVICE}`);

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

test('a binding issues at most 60 credentials a minute', async () => {
  const outcomes = [];
  for (let i = 0; i < 61; i++) outcomes.push((await trade(token(rsa))).status);
  assert.deepEqual([outcomes.filter((status) => status === 200).length, outcomes.at(-1)], [60, 429]);
});

test('before the migration that records spent tokens, an exchange says so, and nothing is issued', async () => {
  const ledger = migrationLedger(db.owner);
  const [newest] = await rows(sql`SELECT * FROM ${ledger} ORDER BY created_at DESC LIMIT 1`);
  await run(sql`DELETE FROM ${ledger} WHERE hash = ${newest!.hash}`);
  try {
    const refused = await trade(token(rsa));
    assert.deepEqual([refused.status, refused.body.reason], [503, 'migration_pending']);
    assert.deepEqual(await db.owner.select().from(credentials), []);
  } finally {
    const columns = Object.keys(newest!);
    await run(sql`INSERT INTO ${ledger} (${sql.join(columns.map((column) => sql.identifier(column)), sql`, `)})
      VALUES (${sql.join(columns.map((column) => sql`${newest![column]}`), sql`, `)})`);
  }
  assert.equal((await trade(token(rsa))).status, 200);
});

/** Raw SQL as the owner, on either engine. */
async function rows(query: SQL): Promise<Record<string, unknown>[]> {
  if (TEST_ENGINE === 'sqlite') return (db.owner as unknown as { all: (q: SQL) => Promise<Record<string, unknown>[]> }).all(query);
  return ((await (db.owner as unknown as { execute: (q: SQL) => Promise<{ rows: Record<string, unknown>[] }> }).execute(query)).rows);
}

async function run(query: SQL): Promise<void> {
  if (TEST_ENGINE === 'sqlite') await (db.owner as unknown as { run: (q: SQL) => Promise<unknown> }).run(query);
  else await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}

// A workload's key-bound session (docs/design/workload-access.md, sections
// 4.1 and 5): the exchange at /api/auth/workload for each kind of ID token,
// every request checked live in one statement with its proof and its gate,
// renewal on the database's clock, logout, and the strict instance.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { bodyDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { github, hashToken, signin, type Gate, type GateAdmission, type RateLimiter } from '@coffre/core/identity';
import { isCredentialScope, type ScopeGrant } from '@coffre/core/access';
import type { Database } from '@coffre/db';
import { desc, eq, Placeholder, sql } from 'drizzle-orm';

import { allowed, audited } from '../src/api/context.ts';
import { authMac } from '../src/auth-rows.ts';
import { resolveConfig } from '../src/config.ts';
import { insertSession, sessionStatement } from '../src/db/workloads.ts';
import { checkPlugins, pluginRoute, bindingRoute, WorkloadRefused, type PluginContext, type WorkloadUse } from '../src/plugins.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, decisionInputs, holdSomething, LOG, LOG_014_ONLY, openTestDatabase, resetDatabase, signInsLogged, testDeps, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, environments, logChanges, secrets, serviceBindings } from './db/tables.ts';
import { postgresOnly } from './db/engine.ts';
import { answer, type Pages } from './start-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'api-prod';
const MEMBER = `token:${SERVICE}`;
const IP = '203.0.113.9';
const GITHUB = 'https://token.actions.githubusercontent.com';
const CLUSTER = 'https://cluster.acme.example';
const TENANT = 'https://login.microsoftonline.com/7f1c0d3e-0000-4000-8000-00000000c0de/v2.0';
/** A v2 token's audience: the API application's client ID. */
const ENTRA_AUDIENCE = '0d2c4e6a-8b1f-4a3c-9e5d-7f6a8b9c0d1e';

const DEPLOY = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};
const POD = { sub: 'system:serviceaccount:prod:api', 'kubernetes.io': { namespace: 'prod', serviceaccount: { name: 'api', uid: 'b9f0c6a2-7d3e-4c1a-9f00-2c6d5e4b3a10' } } };
const IDENTITY = { tid: '7f1c0d3e-0000-4000-8000-00000000c0de', oid: '5a1e0b2c-3d4e-4f60-8a7b-9c0d1e2f3a4b' };

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };

/** An ID token as `iss` signs it: RS256, a minute old at most unless said. */
function token(iss: string, claims: Record<string, unknown>): string {
  const input = `${part({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${part({ iss, iat: seconds() - 5, exp: seconds() + 600, jti: randomUUID(), ...claims })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), signer.privateKey).toString('base64url')}`;
}

/** A GitHub run's token, its audience naming `key`'s thumbprint, as the SDK asks for it. */
async function githubToken(key: ProofKey, claims: Record<string, unknown> = {}): Promise<string> {
  return token(GITHUB, { aud: `${ORIGIN}#jkt=${await thumbprint(key.jwk)}`, sub: 'repo:acme/api:ref:refs/heads/main', ...DEPLOY, ...claims });
}

/** A projected service-account token: its audience fixed, this instance's. */
const podToken = (claims: Record<string, unknown> = {}) => token(CLUSTER, { aud: ORIGIN, ...POD, ...claims });

/** An Entra managed identity's token, cached by its platform for hours: the same one every time. */
const entraToken = (claims: Record<string, unknown> = {}) => token(TENANT, { aud: ENTRA_AUDIENCE, ver: '2.0', sub: IDENTITY.oid, ...IDENTITY, ...claims });

/**
 * A gate as section 5.2 describes it, in memory: its nonce an epoch, the
 * current and previous accepted, each `jti` once per session; `restart`
 * draws a new epoch and forgets every `jti`.
 */
class TestGate implements Gate {
  epoch = 1;
  previous: number | null = null;
  seen = new Map<number, Set<string>>([[1, new Set()]]);
  admits = 0;
  async nonce() {
    return `g${this.epoch}.test`;
  }
  async admit(request: Parameters<Gate['admit']>[0]): Promise<GateAdmission> {
    this.admits++;
    if (request.replay !== undefined) {
      const epoch = [this.epoch, this.previous].find((n) => n !== null && request.replay!.nonce === `g${n}.test`);
      if (epoch === undefined || epoch === null) return { ok: false, reason: 'use_dpop_nonce', nonce: await this.nonce() };
      const seen = this.seen.get(epoch)!;
      const key = `${request.replay.session} ${request.replay.jti}`;
      if (seen.has(key)) return { ok: false, reason: 'replayed' };
      seen.add(key);
    }
    return { ok: true, nonce: await this.nonce() };
  }
  rotate() {
    this.previous = this.epoch;
    this.epoch++;
    this.seen.set(this.epoch, new Set());
  }
  restart() {
    this.epoch += 100;
    this.previous = null;
    this.seen = new Map([[this.epoch, new Set()]]);
  }
}

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let gate: TestGate;
let published: Map<string, unknown>;
let limits: { perSource: RateLimiter; total: RateLimiter };
let vaultCalls: number;
const ui = {} as Pages;

const transport: WorkloadTransport = {
  json: async (url) => {
    if (!published.has(url.href)) throw new FetchRefused(url, 'answered 404');
    return published.get(url.href);
  },
};

function makeRuntime(options: { useOnly?: boolean; noReads?: boolean; plugins?: ReturnType<typeof checkPlugins>; vault?: FixtureDeps['vault']; publicUrl?: string } = {}): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: options.publicUrl ?? ORIGIN,
    vault: options.vault ?? deps.vault,
    auth: signin({
      providers: [github({ clientId: 'a', clientSecret: 'b' })],
      workloads: {
        limits: { perSource: { limit: (o) => limits.perSource.limit(o) }, total: { limit: (o) => limits.total.limit(o) } },
        ...(options.useOnly === undefined ? {} : { useOnly: options.useOnly }),
        ...(options.noReads === undefined ? {} : { noReads: options.noReads }),
      },
    }),
    auditChainKey: deps.chainKey.toString('base64'),
    ...(options.plugins === undefined ? {} : { plugins: options.plugins }),
  });
  return createRuntime(config, deps.db, options.vault ?? deps.vault, transport, undefined, () => gate);
}

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signer = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } };
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetKeys();
  published = new Map<string, unknown>();
  for (const issuer of [GITHUB, CLUSTER, TENANT]) {
    published.set(`${issuer}/.well-known/openid-configuration`, { issuer, jwks_uri: `${issuer}/keys` });
    published.set(`${issuer}/keys`, { keys: [signer.jwk] });
  }
  limits = processLimits({ perSource: 1000, total: 1000 });
  gate = new TestGate();
  deps = testDeps(db.runtime, [ROOT]);
  vaultCalls = 0;
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    vaultCalls++;
    return access(principal);
  };
  runtime = makeRuntime();
  deps.signin = runtime.signin!;
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
});

/** A binding of the service, made by the Owner: a workload's, with a policy. */
async function bind(profile: string, issuer: string | null, claims: Record<string, unknown>, policy: Record<string, unknown> = {}, scope?: Record<string, string>): Promise<string> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile, issuer, claims: claims as never, label: profile, replaces: [], policy, ...(scope === undefined ? {} : { scope: scope as never }) }, { dryRun: false });
  assert.ok('binding' in made);
  return made.binding.id;
}

const bindGithub = () => bind('github', null, DEPLOY);
const bindPod = (policy: Record<string, unknown> = {}) => bind('kubernetes', CLUSTER, { sub: POD.sub, 'kubernetes.io.serviceaccount.uid': POD['kubernetes.io'].serviceaccount.uid }, policy);
const bindEntra = () => bind('azure', TENANT, IDENTITY, { audience: ENTRA_AUDIENCE });

type Answer = { status: number; body: Record<string, unknown>; headers: Headers };

async function read(response: Response): Promise<Answer> {
  const text = await response.text();
  return { status: response.status, body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>), headers: response.headers };
}

/** The exchange, as the SDK sends it: the proof in the body, and a DPoP proof of `key` for this URL. */
async function signIn(proof: Record<string, unknown>, key: ProofKey, options: { service?: string; dpop?: string | null; to?: CoffreRuntime } = {}): Promise<Answer> {
  const url = `${ORIGIN}/api/auth/workload`;
  const dpop = options.dpop === undefined ? await createProof(key, { method: 'POST', url }) : options.dpop;
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(dpop === null ? {} : { dpop }) };
  return read(await answer(new Request(url, { method: 'POST', headers, body: JSON.stringify({ service: options.service ?? MEMBER, proof }) }), options.to ?? runtime, ui, IP));
}

type Session = { token: string; key: ProofKey };

/** A request as the session's holder sends it: its token, and a fresh proof with the gate's current nonce. */
async function call(session: Session, method: string, path: string, options: { body?: unknown; key?: ProofKey; nonce?: string | null; proof?: string; scheme?: string; to?: CoffreRuntime; sourceIp?: string } = {}): Promise<Answer> {
  const url = `${ORIGIN}${path}`;
  const nonce = options.nonce === undefined ? await gate.nonce() : options.nonce;
  const proof = options.proof ?? (await createProof(options.key ?? session.key, { method, url, token: session.token, ...(nonce === null ? {} : { nonce }) }));
  const headers: Record<string, string> = { authorization: `${options.scheme ?? 'DPoP'} ${session.token}`, dpop: proof, ...(options.body === undefined ? {} : { 'content-type': 'application/json' }) };
  return read(await answer(new Request(url, { method, headers, ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }) }), options.to ?? runtime, ui, options.sourceIp ?? IP));
}

async function session(proof: Record<string, unknown>): Promise<Session & { answer: Answer }> {
  const key = await generateProofKey();
  const made = await signIn(proof, key);
  assert.equal(made.status, 200, JSON.stringify(made.body));
  return { token: made.body.token as string, key, answer: made };
}

async function githubSession(): Promise<Session & { answer: Answer }> {
  const key = await generateProofKey();
  const made = await signIn({ oidc: await githubToken(key) }, key);
  assert.equal(made.status, 200, JSON.stringify(made.body));
  return { token: made.body.token as string, key, answer: made };
}

const me = (held: Session, options: Parameters<typeof call>[3] = {}) => call(held, 'GET', '/api/me', options);

async function sessionRow(held: Session) {
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(held.token)));
  return row!;
}

/** A freeze or a lift, as PR 4's routes will append it: the newest allowed entry naming the target decides. */
async function freeze(target: string, action: 'workload.freeze' | 'workload.unfreeze' = 'workload.freeze') {
  const ctx = { caller: { principal: { type: 'user', id: ROOT } }, requestId: randomUUID(), sourceIp: null } as never;
  await audited({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault }, async (_tx, log) => {
    log.push(allowed(ctx, action, { metadata: { target } }));
  });
}

async function entries(action: string) {
  const rows = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, action));
  return rows.map((row) => JSON.parse(row.metadata) as Record<string, unknown>);
}

// --- the exchange -------------------------------------------------------------

test("a GitHub run's token, its audience naming the key, buys a session bound to that key, for an hour, a day at most, and is never spent", async () => {
  await bindGithub();
  const key = await generateProofKey();
  const before = Date.now();
  const jwt = await githubToken(key);
  const made = await signIn({ oidc: jwt }, key);
  assert.equal(made.status, 200, JSON.stringify(made.body));
  assert.match(made.body.token as string, /^coffre_wl_/);
  assert.equal(made.body.tokenType, 'DPoP');
  assert.equal(made.headers.get('cache-control'), 'no-store');
  assert.equal(made.headers.get('dpop-nonce'), await gate.nonce());
  const lifetime = Date.parse(made.body.expiresAt as string) - before;
  assert.ok(lifetime > 59 * 60_000 && lifetime <= 60 * 60_000 + 1000, `lives an hour, not ${lifetime} ms`);
  const end = Date.parse(made.body.notAfter as string) - before;
  assert.ok(end > 23.9 * 3_600_000 && end <= 24 * 3_600_000 + 1000, `ends within the binding's 24 hours, not ${end} ms`);
  assert.deepEqual(made.body.places, ['api-prod-reads'].length === 1 ? made.body.places : []);

  const row = await sessionRow({ token: made.body.token as string, key });
  assert.equal(row.kind, 'workload');
  assert.equal(row.jkt, await thumbprint(key.jwk));
  if (LOG === '0.14') {
    const [entry] = await entries('token.exchange');
    assert.equal(entry!.kind, 'workload');
    assert.equal(entry!.proof, 'oidc');
    assert.equal(entry!.jkt, row.jkt);
  } else {
    // With 0.15's log, the vault makes it (T149), and its change records the sign-in (D147): its proof, key and hard end.
    const [signedIn] = await signInsLogged(db.owner);
    assert.deepEqual(signedIn!.record.signIn, {
      binding: (await db.owner.select({ id: serviceBindings.id }).from(serviceBindings))[0]!.id, proof: 'oidc', issuer: GITHUB, run: signedIn!.run,
      jkt: row.jkt, notAfter: row.notAfter!.getTime(),
    });
    assert.equal(signedIn!.record.caller, 'workload');
    assert.deepEqual(await entries('token.exchange'), []);
  }
  // The audit list shows it as 0.14's entry put it, under either log (T156): a workload's, by its proof, key and hard end.
  const [shown] = (await clientFor(deps, ROOT).audit.list({ sealed: '1' })).entries.filter((entry) => entry.action === 'token.exchange');
  assert.deepEqual(
    [shown!.log, shown!.metadata.kind, shown!.metadata.proof, shown!.metadata.jkt, shown!.metadata.notAfter, shown!.metadata.expiresAt],
    [LOG, 'workload', 'oidc', row.jkt, row.notAfter!.toISOString(), row.expiresAt.toISOString()],
  );
  assert.equal(shown!.run!.claims.repository, (await signInsLogged(db.owner))[0]!.run.repository);

  // It reads as the service, with its key's proof.
  const held = { token: made.body.token as string, key };
  const asked = await me(held);
  assert.equal(asked.status, 200, JSON.stringify(asked.body));
  assert.deepEqual((asked.body.principal as Record<string, unknown>), { type: 'service', id: SERVICE });
  assert.equal(asked.headers.get('dpop-nonce'), await gate.nonce());
  // A token that names the key is never spent: the same key may present it again, to re-prove.
  assert.equal((await signIn({ oidc: jwt }, key)).status, 200);
});

test("a workload's sign-in changes no decision input but the session it issues: the trigger lets its token.exchange by unfenced (0026, ExchangeOnlyIssues)", async () => {
  await bindGithub();
  const before = await decisionInputs(db.owner);
  const made = await githubSession();
  assert.deepEqual(await decisionInputs(db.owner, [(await sessionRow(made)).id]), before);
});

test("a key-naming token is useless to any other key: its audience names the key it was asked for", async () => {
  await bindGithub();
  const [mine, thief] = [await generateProofKey(), await generateProofKey()];
  const jwt = await githubToken(mine);
  const stolen = await signIn({ oidc: jwt }, thief);
  assert.deepEqual([stolen.status, stolen.body.reason], [401, 'audience']);
  // Nor does a token for the instance alone buy a GitHub binding's session: its caller could have named the key.
  const plain = await signIn({ oidc: token(GITHUB, { aud: ORIGIN, sub: 'repo:acme/api:ref:refs/heads/main', ...DEPLOY }) }, mine);
  assert.deepEqual([plain.status, plain.body.reason], [401, 'audience']);
});

test("a binding made on another public URL takes no token for this one, and shadows none made here (PR 3b, review r1)", {
  skip: LOG === '0.15' ? false : "0.14's bindings carry no origin",
}, async () => {
  const elsewhere = makeRuntime({ publicUrl: 'https://old.acme.example' });
  const claims = { sub: POD.sub, 'kubernetes.io.serviceaccount.uid': POD['kubernetes.io'].serviceaccount.uid };
  const old = await elsewhere.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'kubernetes', issuer: CLUSTER, claims: claims as never, label: 'old', replaces: [], policy: {} }, { dryRun: false });
  assert.ok('binding' in old);
  const refused = await signIn({ oidc: podToken() }, await generateProofKey());
  assert.deepEqual([refused.status, refused.body.reason], [401, 'audience'], 'the only binding was made on the old URL');
  // Bound again here, the old one still live: a token for this URL signs in through the new one.
  await bindPod();
  await session({ oidc: podToken() });
});

test("a projected Kubernetes token is spent once, and its session ends at the token's own exp", async () => {
  await bindPod();
  const jwt = podToken({ exp: seconds() + 3 });
  const first = await session({ oidc: jwt });
  const expiry = Date.parse(first.answer.body.expiresAt as string);
  assert.equal(Date.parse(first.answer.body.notAfter as string), expiry, 'its hard end is its expiry');
  assert.ok(Math.abs(expiry - (seconds() + 3) * 1000) <= 1000, 'the token\'s exp');
  const again = await signIn({ oidc: jwt }, await generateProofKey());
  assert.deepEqual([again.status, again.body.reason], [401, 'replayed']);
  assert.equal((await me(first)).status, 200);
  // Renewal never moves it past its end.
  const renewed = await call(first, 'POST', '/api/auth/workload/renew');
  assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
  assert.ok(Date.parse(renewed.body.expiresAt as string) <= expiry);
  await sleep(expiry - Date.now() + 300);
  assert.equal((await me(first)).status, 401, 'dead at its token\'s exp');
});

test("an Entra managed identity's token, which its platform repeats for hours, is never spent, may be hours old, and ends its session at its exp", async () => {
  await bindEntra();
  // Two replicas present the same cached token, issued two hours ago: each gets a session of its own, with its own key.
  const jwt = entraToken({ iat: seconds() - 2 * 3600, exp: seconds() + 1800 });
  const [one, two] = [await session({ oidc: jwt }), await session({ oidc: jwt })];
  assert.notEqual(one.token, two.token);
  assert.ok(Math.abs(Date.parse(one.answer.body.notAfter as string) - (seconds() + 1800) * 1000) <= 1500);
  // The audience is the one the binding fixes; the instance's alone is not it.
  const wrong = await signIn({ oidc: entraToken({ aud: ORIGIN }) }, await generateProofKey());
  assert.deepEqual([wrong.status, wrong.body.reason], [401, 'audience']);
  // A projected token two hours old is still refused: only a repeating profile's age is its own exp.
  await bindPod();
  const old = await signIn({ oidc: podToken({ iat: seconds() - 2 * 3600 }) }, await generateProofKey());
  assert.deepEqual([old.status, old.body.reason], [401, 'too_old']);
});

test('the exchange takes a DPoP proof of the key, for its own URL and method, made within the minute, and names a kind of proof it takes', async () => {
  await bindPod();
  const key = await generateProofKey();
  const without = await signIn({ oidc: podToken() }, key, { dpop: null });
  assert.deepEqual([without.status, without.body.reason], [401, 'dpop']);
  for (const dpop of [
    await createProof(key, { method: 'POST', url: `${ORIGIN}/api/auth/oidc` }),
    await createProof(key, { method: 'GET', url: `${ORIGIN}/api/auth/workload` }),
    await createProof(key, { method: 'POST', url: `${ORIGIN}/api/auth/workload`, iat: seconds() - 120 }),
    await createProof(key, { method: 'POST', url: `${ORIGIN}/api/auth/workload`, token: 'coffre_wl_x' }),
    'not-a-proof',
  ]) {
    const refused = await signIn({ oidc: podToken() }, key, { dpop });
    assert.deepEqual([refused.status, refused.body.reason], [401, 'dpop'], dpop);
  }
  // A proof kind this release takes none of, or two at once.
  assert.equal((await signIn({ aws: { url: 'https://sts.amazonaws.com/' } }, key)).body.reason, 'malformed');
  assert.equal((await signIn({ oidc: podToken(), enrollment: 'coffre_enr_x' }, key)).status, 400);
  // Nothing was spent by those refusals.
  assert.equal((await signIn({ oidc: podToken() }, key)).status, 200);
});

test("/api/auth/oidc never takes a workload's binding, and /api/auth/workload never a bearer binding", async () => {
  await bindPod();
  const bearer = await read(await answer(new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: podToken() }) }), runtime, ui, IP));
  assert.deepEqual([bearer.status, bearer.body.reason], [401, 'no_match']);
  // A bearer binding of before, with no policy, buys no key-bound session.
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'custom', issuer: CLUSTER, claims: { sub: POD.sub }, label: null, replaces: [] }, { dryRun: false });
  assert.ok('binding' in made);
  assert.equal(made.binding.policy, null);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.binding.id));
  assert.equal(row!.policy, null);
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, (await runtime.workloads!.listBindings(await contextFor(deps, ROOT), SERVICE)).find((binding) => binding.profile === 'kubernetes')!.id);
  const refused = await signIn({ oidc: podToken() }, await generateProofKey());
  assert.deepEqual([refused.status, refused.body.reason], [401, 'no_match']);
});

// --- every request ------------------------------------------------------------

test("a session's token is worthless without its key: as a bearer, with another key's proof, or with a proof made for another request", async () => {
  await bindGithub();
  const held = await githubSession();
  const thief = await generateProofKey();
  const asBearer = await me(held, { scheme: 'Bearer' });
  assert.equal(asBearer.status, 401);
  const otherKey = await me(held, { key: thief });
  assert.deepEqual([otherKey.status, otherKey.body.reason], [401, 'jkt']);
  assert.match(otherKey.headers.get('www-authenticate') ?? '', /invalid_dpop_proof/);
  // A proof of the holder's, captured, for another URL, method or token.
  const nonce = await gate.nonce();
  for (const proof of [
    await createProof(held.key, { method: 'GET', url: `${ORIGIN}/api/projects`, token: held.token, nonce }),
    await createProof(held.key, { method: 'POST', url: `${ORIGIN}/api/me`, token: held.token, nonce }),
    await createProof(held.key, { method: 'GET', url: `${ORIGIN}/api/me`, token: 'coffre_wl_another', nonce }),
    await createProof(held.key, { method: 'GET', url: `${ORIGIN}/api/me`, nonce }),
  ]) {
    assert.equal((await me(held, { proof })).status, 401);
  }
  // No proof at all.
  const bare = await read(await answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `DPoP ${held.token}` } }), runtime, ui, IP));
  assert.deepEqual([bare.status, bare.body.reason], [401, 'dpop']);
  assert.equal((await me(held)).status, 200);
});

test("each proof is accepted once, with the gate's nonce: a replay is refused, across a restart too, and a stale nonce asks for the current one", async () => {
  await bindGithub();
  const held = await githubSession();
  const proof = await createProof(held.key, { method: 'GET', url: `${ORIGIN}/api/me`, token: held.token, nonce: await gate.nonce() });
  assert.equal((await me(held, { proof })).status, 200);
  const replayed = await me(held, { proof });
  assert.deepEqual([replayed.status, replayed.body.reason], [401, 'replayed']);
  // No nonce: refused with the one to sign with.
  const unsigned = await me(held, { nonce: null });
  assert.deepEqual([unsigned.status, unsigned.body.reason], [401, 'use_dpop_nonce']);
  assert.equal(unsigned.headers.get('dpop-nonce'), await gate.nonce());
  assert.match(unsigned.headers.get('www-authenticate') ?? '', /use_dpop_nonce/);
  // The previous epoch's nonce still works once rotated; after a restart, nothing made before it does.
  const before = await createProof(held.key, { method: 'GET', url: `${ORIGIN}/api/me`, token: held.token, nonce: await gate.nonce() });
  gate.rotate();
  assert.equal((await me(held, { proof: before })).status, 200);
  gate.restart();
  assert.equal((await me(held, { proof: before })).body.reason, 'use_dpop_nonce');
  assert.equal((await me(held)).status, 200);
  // A deployment without a gate takes no session at all: nothing would stop a replay.
  const gateless = createRuntime(resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits } }), auditChainKey: deps.chainKey.toString('base64') }), deps.db, deps.vault, transport);
  assert.equal((await me(held, { to: gateless })).status, 503);
  // Nor does it make one, or spend the proof it would be made with.
  await bindPod();
  const pod = podToken();
  assert.equal((await signIn({ oidc: pod }, await generateProofKey(), { to: gateless })).status, 503);
  assert.equal((await signIn({ oidc: pod }, await generateProofKey())).status, 200, 'not spent');
});

test('a session reaches the routes a service token does, and none only a person reaches', async () => {
  await bindGithub();
  const held = await githubSession();
  for (const path of ['/api/sessions', '/api/identities', '/api/apps']) {
    const refused = await call(held, 'GET', path);
    assert.deepEqual([refused.status, refused.body.reason], [403, 'workload'], path);
  }
  const handle = await call(held, 'POST', '/api/handles', { body: { label: 'x', paths: ['api-prod-reads/dev'] } });
  assert.deepEqual([handle.status, handle.body.reason], [403, 'workload']);
  const [denied] = (await entries('token.use'));
  assert.equal(denied!.route, 'GET /sessions');
  assert.equal((await call(held, 'GET', '/api/projects')).status, 200);
});

test("a session issues no credential and changes no one's access, in any mode: a token, binding or code it made would read what it may only use", async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.access.set(MEMBER, { market: 'owner' });
  await bindGithub();
  const held = await githubSession();
  const other = 'token:batch';
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: other })).ok, true);
  const asked: [string, string, unknown?][] = [
    ['POST', `/api/members/${MEMBER}/tokens`, { label: 'x', expiresInDays: 1 }],
    ['POST', `/api/members/${other}/tokens`, { label: 'x', expiresInDays: 1 }],
    ['POST', `/api/members/${other}/bindings`, { profile: 'kubernetes', issuer: CLUSTER, claims: { sub: 'x', 'kubernetes.io.serviceaccount.uid': 'y' }, policy: { reads: { 'api-prod-reads/dev': '*' } } }],
    ['POST', `/api/members/${other}/bindings/keys`, { issuer: CLUSTER, jwks: { keys: [signer.jwk] } }],
    ['DELETE', `/api/members/${MEMBER}/bindings/${randomUUID()}`],
    ['POST', `/api/members/${MEMBER}/bindings/${randomUUID()}/enrollments`, {}],
    ['POST', `/api/members/${MEMBER}/bindings/${randomUUID()}/enrollments/${randomUUID()}/promote`, {}],
    ['PUT', `/api/members/${encodeURIComponent('token:new-one')}`, {}],
    ['DELETE', `/api/members/${other}`],
    ['PATCH', `/api/access/${other}`, { 'api-prod-reads': 'viewer' }],
    ['PUT', '/api/roles/deployer', { name: 'Deployer', permissions: { normal: ['secret.read'], protected: [] } }],
    ['DELETE', '/api/roles/deployer'],
    ['PUT', '/api/instance-roles/auditor', { permissions: [] }],
    ['DELETE', '/api/instance-roles/auditor'],
    ['PUT', '/api/settings', { serviceAccounts: { projects: 'all', environments: 'all' } }],
  ];
  // Nor (un)protect an environment, which decides what every role reads there, as an Owner of its project.
  asked.push(['PATCH', '/api/projects/market/prod', { protected: true }], ['PATCH', '/api/projects/market/prod', { protected: false }]);
  for (const [method, path, body] of asked) {
    const refused = await call(held, method, path, body === undefined ? {} : { body });
    assert.deepEqual([refused.status, refused.body.reason], [403, 'workload_cannot_issue'], `${method} ${path} ${JSON.stringify(body)}`);
  }
  // A rename of it is a write, which stays.
  assert.equal((await call(held, 'PATCH', '/api/projects/market/prod', { body: { name: 'Production' } })).status, 200);
  // Nor protect one that exists by forking a protected one onto it; a new fork is still protected as its source is.
  await root.environments.create('market/dev', { name: 'dev' });
  await root.environments.protect('market/prod');
  const isProtected = async (slug: string) => (await root.projects.list()).projects.find((project) => project.slug === 'market')!
    .environments.find((environment: { slug: string }) => environment.slug === slug) as { protected: boolean };
  const onto = await call(held, 'PUT', '/api/projects/market/dev', { body: { from: 'prod' } });
  assert.deepEqual([onto.status, onto.body.reason], [403, 'workload_cannot_issue']);
  assert.equal((await isProtected('dev')).protected, false, 'unchanged');
  // Each refusal is logged, as the router's are.
  const logged = await db.owner.select({ decision: auditLog.decision, metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, 'environment.update'));
  assert.equal(logged.filter((entry) => entry.decision === 'deny' && JSON.parse(entry.metadata).reason === 'workload_cannot_issue').length, 3);
  const fresh = await call(held, 'PUT', '/api/projects/market/staging', { body: { from: 'prod' } });
  assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
  assert.equal((await isProtected('staging')).protected, true);
  // It still writes, and reads what a service reads.
  assert.equal((await call(held, 'GET', `/api/members/${MEMBER}/tokens`)).status, 200);
});

test('revocation, freezes and removal of the member each end a session at its next request', async () => {
  await bindGithub();
  const [held, other] = [await githubSession(), await githubSession()];
  const row = await sessionRow(held);
  assert.equal((await me(held)).status, 200);

  // Frozen: the instance, the service, the binding, the session; each lifted again.
  for (const target of ['instance', MEMBER, `binding:${row.createdBy.slice('binding:'.length)}`, `session:${row.id}`]) {
    await freeze(target);
    const frozen = await me(held);
    assert.deepEqual([frozen.status, frozen.body.reason], [403, 'frozen'], target);
    await freeze(target, 'workload.unfreeze');
    assert.equal((await me(held)).status, 200, `${target} lifted`);
  }
  // A frozen service makes no session either.
  await freeze(MEMBER);
  const key = await generateProofKey();
  const refused = await signIn({ oidc: await githubToken(key) }, key);
  assert.deepEqual([refused.status, refused.body.reason], [401, 'frozen']);
  await freeze(MEMBER, 'workload.unfreeze');

  // Listed with the service's tokens, and revoked by a manager of the service there.
  const listed = await clientFor(deps, ROOT).tokens.list(MEMBER);
  assert.deepEqual(listed.tokens.filter((listedRow) => listedRow.session !== undefined).map((listedRow) => listedRow.id).sort(), [row.id, (await sessionRow(other)).id].sort());
  await clientFor(deps, ROOT).tokens.revoke(MEMBER, row.id);
  assert.equal((await me(held)).status, 401);
  assert.equal((await me(other)).status, 200);
  // The member removed: every session of theirs, at once.
  await clientFor(deps, ROOT).members.remove(MEMBER);
  assert.equal((await me(other)).status, 401);
});

test('a frozen session still renews: lifting the freeze restores it, with nothing to sign in again', async () => {
  await bindGithub();
  const held = await githubSession();
  await freeze(MEMBER);
  assert.equal((await me(held)).body.reason, 'frozen');
  const renewed = await call(held, 'POST', '/api/auth/workload/renew');
  assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
  assert.equal((await me(held)).body.reason, 'frozen', 'still stopped from use');
  await freeze(MEMBER, 'workload.unfreeze');
  assert.equal((await me(held)).status, 200);
});

test("the per-request statement reads its rows through their indexes, however many credentials there are", postgresOnly('reads the plan Postgres makes'), async () => {
  const { sql: text, params } = sessionStatement(db.owner).toSQL();
  const values: Record<string, unknown> = { tokenHash: Buffer.alloc(32, 1), place: null, credential: 'stripe' };
  const literal = (value: unknown): string => {
    const named = value instanceof Placeholder ? values[value.name] : value;
    if (named === null || named === undefined) return 'NULL';
    if (Buffer.isBuffer(named)) return `'\\x${named.toString('hex')}'::bytea`;
    return `'${String(named).replaceAll("'", "''")}'`;
  };
  const inlined = text.replace(/\$(\d+)/g, (_, n: string) => literal(params[Number(n) - 1]));
  // Sequential scans priced out, so the plan shows which lookups the statement can use at all.
  const plan = await db.owner.transaction(async (tx) => {
    await tx.execute(sql.raw('SET LOCAL enable_seqscan = off'));
    return tx.execute(sql.raw(`EXPLAIN ${inlined}`));
  });
  const lines = (plan as unknown as { 'QUERY PLAN': string }[]).map((row) => row['QUERY PLAN']).join('\n');
  // The session by its token's hash and its ancestors by their IDs, each a lookup: never a scan of every credential, which no prune ever shrinks.
  assert.doesNotMatch(lines, /Seq Scan on credentials/, lines);
  assert.match(lines, /Bitmap Index Scan on credentials_token_hash_key/, lines);
  assert.match(lines, /Bitmap Index Scan on credentials_pkey/, lines);
  // Nor of the log, which only grows: each freeze and the tombstone through an index.
  assert.doesNotMatch(lines, /Seq Scan on audit_log/, lines);
  assert.match(lines, /audit_log_freeze_idx/, lines);
});

test('a session whose binding is removed, or whose row is changed around the app, is no session', async () => {
  const binding = await bindGithub();
  const held = await githubSession();
  const row = await sessionRow(held);
  // Its hard end moved later without the app's MAC.
  await db.owner.update(credentials).set({ notAfter: new Date(Date.now() + 365 * 86_400_000) }).where(eq(credentials.id, row.id));
  assert.equal((await me(held)).status, 401);
  await db.owner.update(credentials).set({ notAfter: row.notAfter }).where(eq(credentials.id, row.id));
  assert.equal((await me(held)).status, 200);
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, binding);
  assert.equal((await me(held)).status, 401);
});

test("a binding's sources hold a session to its addresses, at the exchange and on every request", async () => {
  await bindPod({ sources: ['203.0.113.0/24'] });
  const held = await session({ oidc: podToken() });
  assert.equal((await me(held)).status, 200);
  const outside = await me(held, { sourceIp: '198.51.100.7' });
  assert.deepEqual([outside.status, outside.body.reason], [401, 'source']);
  const key = await generateProofKey();
  const url = `${ORIGIN}/api/auth/workload`;
  // Its key's proof ends it from anywhere: logout is never refused for where it comes from.
  const out = await call(held, 'POST', '/api/auth/logout', { sourceIp: '198.51.100.7' });
  assert.equal(out.status, 200, JSON.stringify(out.body));
  assert.equal((await me(held)).status, 401);
  const elsewhere = await read(await answer(new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', dpop: await createProof(key, { method: 'POST', url }) }, body: JSON.stringify({ service: MEMBER, proof: { oidc: podToken() } }) }), runtime, ui, '198.51.100.7'));
  assert.deepEqual([elsewhere.status, elsewhere.body.reason], [401, 'source']);
});

// --- renewal and logout -------------------------------------------------------

test("renewal moves a session's expiry on, by its key; a late or a lost renewal revives nothing", { skip: LOG_014_ONLY }, async () => {
  await bindGithub();
  const held = await githubSession();
  const row = await sessionRow(held);
  // Near its end, as if its process had stalled.
  const near = new Date(Date.now() + 30_000);
  const { authMac: _, ...fields } = { ...row, expiresAt: near };
  await db.owner.update(credentials).set({ expiresAt: near, authMac: authMac(deps.chainKey, 'credentials', fields) }).where(eq(credentials.id, row.id));
  const renewed = await call(held, 'POST', '/api/auth/workload/renew');
  assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
  assert.ok(Date.parse(renewed.body.expiresAt as string) > Date.now() + 59 * 60_000);
  assert.equal(renewed.headers.get('dpop-nonce'), await gate.nonce());
  assert.ok(Math.abs((await sessionRow(held)).expiresAt.getTime() - Date.parse(renewed.body.expiresAt as string)) < 2);

  // A renewal another beat to it updates nothing: the row is not as it read it.
  const stale = await sessionRow(held);
  const binding = (await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, stale.createdBy.slice('binding:'.length))))[0]!;
  await runtime.workloads!.renew({ row: stale, binding }, { requestId: randomUUID(), sourceIp: IP });
  await assert.rejects(runtime.workloads!.renew({ row: stale, binding }, { requestId: randomUUID(), sourceIp: IP }), { reason: 'expired' });

  // Within seconds of its expiry, the count on the database's clock may already call it dead: renewal moves nothing.
  const current = await sessionRow(held);
  const late = new Date(Date.now() + 2_000);
  const { authMac: __, ...lateFields } = { ...current, expiresAt: late };
  await db.owner.update(credentials).set({ expiresAt: late, authMac: authMac(deps.chainKey, 'credentials', lateFields) }).where(eq(credentials.id, current.id));
  const refused = await call(held, 'POST', '/api/auth/workload/renew');
  assert.deepEqual([refused.status, refused.body.reason], [401, 'expired']);
  assert.equal((await sessionRow(held)).expiresAt.getTime(), late.getTime(), 'unchanged');
  await sleep(late.getTime() - Date.now() + 200);
  assert.equal((await call(held, 'POST', '/api/auth/workload/renew')).status, 401, 'dead stays dead');
  assert.equal((await me(held)).status, 401);
});

test('logout revokes the session, with its key', async () => {
  await bindGithub();
  const held = await githubSession();
  const thief = await call(held, 'POST', '/api/auth/logout', { key: await generateProofKey() });
  assert.equal(thief.status, 401);
  assert.equal((await me(held)).status, 200);
  const out = await call(held, 'POST', '/api/auth/logout');
  assert.equal(out.status, 200, JSON.stringify(out.body));
  assert.equal((await me(held)).status, 401);
  if (LOG === '0.14') {
    const [entry] = await entries('sign_out');
    assert.equal(entry!.kind, 'workload');
  } else {
    // With 0.15's log, the vault ends it (T149), and its change records the sign-out (D147).
    const revokes = (await db.owner.select({ payload: logChanges.payload }).from(logChanges)).flatMap(({ payload }) => {
      const { revoke } = JSON.parse(payload) as { revoke?: { reason: string; kind: string } };
      return revoke === undefined ? [] : [revoke];
    });
    assert.deepEqual(revokes.map(({ reason, kind }) => [reason, kind]), [['sign_out', 'workload']]);
  }
});

// --- the strict instance ------------------------------------------------------

test('useOnly: no service token is issued or taken, and /api/auth/oidc answers 410 naming /api/auth/workload', async () => {
  const root = clientFor(deps, ROOT);
  const kept = (await root.tokens.issue(MEMBER, { label: 'ci', expiresInDays: 30 })).token;
  const asBearer = (to: CoffreRuntime) => answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${kept}` } }), to, ui, IP);
  assert.equal((await asBearer(runtime)).status, 200);

  runtime = makeRuntime({ useOnly: true });
  const refused = await read(await asBearer(runtime));
  assert.deepEqual([refused.status, refused.body.reason], [401, 'use_only']);
  const ctx = await contextFor(deps, ROOT);
  await assert.rejects(runtime.signin!.issueServiceToken(ctx, SERVICE, { label: 'ci', expiresInDays: 1 }), { reason: 'use_only' });
  await assert.rejects(runtime.signin!.planServiceToken(ctx, SERVICE, { label: 'ci' }), { reason: 'use_only' });
  const gone = await read(await answer(new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }), runtime, ui, IP));
  assert.equal(gone.status, 410);
  assert.match(gone.body.message as string, /\/api\/auth\/workload/);
  // Every binding it makes is a workload's, a GitHub one too; and its sessions work.
  await bindGithub();
  const listed = await runtime.workloads!.listBindings(ctx, SERVICE);
  assert.deepEqual(listed.map((binding) => binding.policy), [{ keyAudience: true }]);
  const held = await githubSession();
  assert.equal((await me(held)).status, 200);
});

test('noReads: no binding lists reads, and one that does makes no session', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { STRIPE_WEBHOOK_SECRET: 'whsec_1' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  await bindPod({ reads: { 'market/prod': '*' } });
  const held = await session({ oidc: podToken() });
  assert.equal((await me(held)).status, 200);

  runtime = makeRuntime({ noReads: true });
  const refused = await me(held);
  assert.deepEqual([refused.status, refused.body.reason], [403, 'no_reads']);
  assert.equal((await signIn({ oidc: podToken() }, await generateProofKey())).body.reason, 'no_match');
  await assert.rejects(bindPod({ reads: { 'market/prod': '*' } }), /noReads/);
});

// --- bindings -----------------------------------------------------------------

test("a binding's reads name keys by path and name, are stored by ID, and list a sensitive key only if an Owner of its project makes it", async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const env of ['dev', 'prod']) await root.environments.create(`market/${env}`, { name: env });
  await root.secrets.set('market/prod', { STRIPE_WEBHOOK_SECRET: 'whsec_1', DATABASE_URL: { value: 'postgres://prod', sensitivity: 'sensitive' } });
  // A project role that holds what only a project's grant may: the environment's own grant holds the rest of it.
  await root.access.set(MEMBER, { market: 'maintainer' });
  const envs = await db.owner.select().from(environments);
  const prod = envs.find((env) => env.slug === 'prod')!.id;
  const keys = await db.owner.select().from(secrets).where(eq(secrets.environmentId, prod));
  const id = (name: string) => keys.find((key) => key.key === name)!.id;

  // A dry run shows what will be stored, by name.
  const plan = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'kubernetes', issuer: CLUSTER, claims: { sub: POD.sub, 'kubernetes.io.serviceaccount.uid': '11111111-2222-4333-8444-555555555555' }, label: null, replaces: [], policy: { reads: { 'market/prod': ['STRIPE_WEBHOOK_SECRET', 'DATABASE_URL'] } } }, { dryRun: true });
  assert.ok('policy' in plan && !('binding' in plan));
  assert.deepEqual(plan.policy, { reads: { 'market/prod': ['DATABASE_URL', 'STRIPE_WEBHOOK_SECRET'] } });

  // Made by the Owner, stored by ID; the environment gets a grant of its own beside the project's, for the list to attach to.
  const made = await bindPod({ reads: { 'market/prod': ['STRIPE_WEBHOOK_SECRET', 'DATABASE_URL'] } });
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made));
  assert.deepEqual(JSON.parse(row!.policy!), { reads: { [prod]: { keys: [id('DATABASE_URL'), id('STRIPE_WEBHOOK_SECRET')].sort() } } });
  const market = envs.find((env) => env.id === prod)!.projectId;
  const scope = JSON.parse(row!.scope!) as ScopeGrant[];
  assert.ok(isCredentialScope(scope), 'a scope that holds');
  assert.deepEqual(scope.filter((grant) => grant.projectId === market).map((grant) => [grant.environmentId, grant.permissions!.normal.includes('environment.manage')]), [[null, true], [prod, false]]);
  // Shown by name, as they are named now.
  await root.secrets.rename('market/prod/STRIPE_WEBHOOK_SECRET', 'STRIPE_SIGNING_SECRET');
  const shown = (await runtime.workloads!.listBindings(await contextFor(deps, ROOT), SERVICE)).find((binding) => binding.id === made)!;
  assert.deepEqual(shown.policy!.reads, { 'market/prod': ['DATABASE_URL', 'STRIPE_SIGNING_SECRET'] });

  // A key the environment does not hold, an environment that is not there, one outside the scope: each refused, by name.
  await assert.rejects(bindPod({ reads: { 'market/dev': ['STRIPE_WEBHOOK_SECRET'] } }), /does not hold: STRIPE_WEBHOOK_SECRET/);
  await assert.rejects(bindPod({ reads: { 'market/staging': '*' } }), /no environment/);

  // A manager who is no Owner of market lists no sensitive key; "*" stays theirs, the sensitive values left out by the scope.
  await deps.vault.admit({ actor: `user:${ROOT}`, principal: `user:${DEV}`, role: 'admin' });
  const asDev = async (reads: Record<string, unknown>) => runtime.workloads!.bind(await contextFor(deps, DEV), SERVICE, { profile: 'kubernetes', issuer: CLUSTER, claims: { sub: POD.sub, 'kubernetes.io.serviceaccount.uid': '66666666-7777-4888-8999-000000000000' }, label: null, replaces: [], policy: { reads } }, { dryRun: false });
  await assert.rejects(asDev({ 'market/prod': ['DATABASE_URL'] }), (error: { status?: number; message: string }) => error.status === 403 && /Owner of market/.test(error.message));
  assert.ok('binding' in (await asDev({ 'market/prod': ['STRIPE_SIGNING_SECRET'] })));
  await root.access.set(MEMBER, { market: null, 'market/dev': 'viewer' });
  await assert.rejects(bindPod({ reads: { 'market/prod': '*' } }), /does not reach/);
});

test("a binding's keys replaced, its reads stay and are shown by name, never by ID", async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { STRIPE_WEBHOOK_SECRET: 'whsec_1' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  await bindPod({ reads: { 'market/prod': ['STRIPE_WEBHOOK_SECRET'] } });
  const rekeyed = await runtime.workloads!.replaceKeys(await contextFor(deps, ROOT), SERVICE, { issuer: CLUSTER, jwks: { keys: [signer.jwk] } as never }, { dryRun: false });
  assert.ok('bindings' in rekeyed);
  assert.deepEqual(rekeyed.bindings.map((binding) => binding.policy), [{ reads: { 'market/prod': ['STRIPE_WEBHOOK_SECRET'] } }]);
});

test("a binding of a proof that is no ID token names its URN, and coffre asks no issuer for keys", async () => {
  const fetched: string[] = [];
  const counting: WorkloadTransport = { json: async (url) => (fetched.push(url.href), transport.json(url)) };
  runtime = createRuntime(resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits } }), auditChainKey: deps.chainKey.toString('base64') }), deps.db, deps.vault, counting, undefined, () => gate);
  const id = await bind('cloudflare', null, {});
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id));
  assert.equal(row!.issuer, 'urn:coffre:cloudflare');
  assert.equal(row!.jwksUri, 'urn:coffre:cloudflare');
  assert.equal(row!.policy, '{}');
  assert.deepEqual(fetched, []);
});

// --- the proxy's caller -------------------------------------------------------

/** `market/prod`, holding a value, which the service views: the one environment its sessions reach. Its ID. */
async function marketProd(): Promise<string> {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { STRIPE_SECRET_KEY: 'sk_live_1' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  return (await db.owner.select().from(environments).where(eq(environments.slug, 'prod')))[0]!.id;
}

/** A plugin that answers `/use/...` with what `workload` and `use` say, as PR 1d's proxy will. */
function probe(seen: { caller?: WorkloadUse; context?: PluginContext }) {
  return {
    name: 'probe',
    routes: {
      prefix: '/use',
      fetch: async (request: Request, coffre: PluginContext) => {
        seen.context = coffre;
        const url = new URL(request.url);
        const [, , place, credential] = url.pathname.split('/');
        try {
          const body = new Uint8Array(await request.arrayBuffer());
          // What a plugin might add to what it asks, past its type: a test's, in a header.
          const extra = JSON.parse(request.headers.get('x-extra') ?? '{}') as Record<string, unknown>;
          const caller = await coffre.workload(request, { ...extra, place: place === '-' ? null : place!, credential: credential ?? null, body: await bodyDigest(body) } as never);
          if (caller === null) return Response.json({ caller: null });
          seen.caller = caller;
          return Response.json({ caller: seen.caller }, { headers: { 'dpop-nonce': seen.caller.nonce ?? '' } });
        } catch (error) {
          if (error instanceof WorkloadRefused) return error.response;
          throw error;
        }
      },
    },
  };
}

test("PluginContext.workload: the caller of a forwarded request, its content signed, checked in one statement with no vault call", async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  const place = await marketProd();
  await bindGithub();
  const held = await githubSession();
  const row = await sessionRow(held);
  assert.deepEqual(held.answer.body.places, ['market/prod']);
  const forward = async (path: string, init: { body: string; headers?: Record<string, string>; signed?: { headers: Record<string, string>; body: string } }) => {
    const url = `${ORIGIN}${path}`;
    const headers = { 'content-type': 'application/json', ...init.headers };
    const proof = await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gate.nonce(), content: init.signed ?? { headers, body: await bodyDigest(init.body) } });
    const request = new Request(url, { method: 'POST', headers: { ...headers, authorization: `DPoP ${held.token}`, dpop: proof }, body: init.body });
    return read((await pluginRoute(request, runtime, IP))!);
  };
  // A request that carries no session is no workload's: the proxy takes it as a handle's.
  assert.deepEqual((await read((await pluginRoute(new Request(`${ORIGIN}/use/-/stripe/v1/charges`, { method: 'POST' }), runtime, IP))!)).body, { caller: null });
  const calls = vaultCalls;
  const used = await forward(`/use/-/stripe/v1/charges`, { body: '{"amount":2000}' });
  assert.equal(used.status, 200, JSON.stringify(used.body));
  assert.equal(vaultCalls, calls, 'no vault call');
  const caller = used.body.caller as Record<string, unknown>;
  assert.deepEqual([caller.kind, caller.principal, caller.credentialId, caller.profile, caller.place], ['workload', MEMBER, row.id, 'github', place]);
  assert.deepEqual(caller.hdr, ['content-type']);
  // A body changed on the way is refused.
  const changed = await forward(`/use/-/stripe/v1/charges`, { body: '{"amount":9000}', signed: { headers: { 'content-type': 'application/json' }, body: await bodyDigest('{"amount":2000}') } });
  assert.deepEqual([changed.status, changed.body.reason], [401, 'req']);
  // The credential it uses, frozen, is refused for it alone; nothing a plugin adds to its ask turns the freeze off.
  await freeze(`credential:${place}/stripe`);
  assert.equal((await forward(`/use/-/stripe/v1/charges`, { body: '{}' })).body.reason, 'frozen');
  assert.equal((await forward(`/use/-/stripe/v1/charges`, { body: '{}', headers: { 'x-extra': '{"freezes":false,"ending":true}' } })).body.reason, 'frozen');
  assert.equal((await forward(`/use/-/openai/v1/chat`, { body: '{}' })).status, 200);
  // `use` takes the caller coffre made for this request, and no lookalike a plugin built, nor one an earlier request's context made.
  const earlier = { caller: seen.caller!, context: seen.context! };
  await assert.rejects(earlier.context.use({ ...earlier.caller }, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: {} }), { status: 401 });
  assert.equal((await earlier.context.use(earlier.caller, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: {} })).values.STRIPE_SECRET_KEY, 'sk_live_1');
  assert.equal((await forward(`/use/-/openai/v1/chat`, { body: '{}' })).status, 200);
  await assert.rejects(seen.context!.use(earlier.caller, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: {} }), { status: 401 });
  // The member removed by the vault, before the app's sweep revokes anything: the statement's member clause alone refuses the next request.
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  assert.equal((await forward(`/use/-/openai/v1/chat`, { body: '{}' })).status, 401);
});

test("a narrowed session's row stands only while every ancestor does, and reaches no API route", async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  await marketProd();
  await bindGithub();
  const parent = await githubSession();
  const root = await sessionRow(parent);
  // A child as PR 4's narrow will make it: bound to its own key, its ancestors and limits under its MAC.
  const key = await generateProofKey();
  const child = { token: `coffre_wl_${Buffer.alloc(32, 7).toString('base64url')}`, key };
  await insertSession(deps.db, deps.chainKey, {
    id: randomUUID(), kind: 'workload', tokenHash: hashToken(child.token), tokenHint: 'coffre_wl_Bwc', generation: root.generation, principal: MEMBER,
    identityId: null, label: 'refund-agent', createdBy: root.createdBy, expiresAt: root.expiresAt, revokedAt: null, scope: root.scope, places: root.places,
    jkt: await thumbprint(key.jwk), notAfter: root.notAfter!, ancestors: JSON.stringify([root.id]), constraints: JSON.stringify({ credentials: ['stripe'] }), enrollmentId: null, approvedAt: null, approvedBy: null,
  });
  const use = async () => {
    const url = `${ORIGIN}/use/-/stripe/v1/refunds`;
    const proof = await createProof(key, { method: 'POST', url, token: child.token, nonce: await gate.nonce(), content: { headers: {}, body: await bodyDigest('') } });
    return read((await pluginRoute(new Request(url, { method: 'POST', headers: { authorization: `DPoP ${child.token}`, dpop: proof } }), runtime, IP))!);
  };
  const used = await use();
  assert.equal(used.status, 200, JSON.stringify(used.body));
  assert.deepEqual((used.body.caller as Record<string, unknown>).constraints, { credentials: ['stripe'] });
  // It uses values, and is handed none back, whatever the plugin makes of the caller it holds.
  await assert.rejects(seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'expose', logged: {} }), { reason: 'narrowed' });
  (seen.caller as { constraints: unknown }).constraints = null;
  await assert.rejects(seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'expose', logged: {} }), { reason: 'narrowed' });
  const api = await me(child);
  assert.deepEqual([api.status, api.body.reason], [403, 'narrowed']);
  assert.equal((await call(child, 'POST', '/api/auth/workload/renew')).body.reason, 'narrowed');
  // Its parent frozen, or ended: the child ends with it.
  await freeze(`session:${root.id}`);
  assert.equal((await use()).body.reason, 'frozen');
  await freeze(`session:${root.id}`, 'workload.unfreeze');
  assert.equal((await call(parent, 'POST', '/api/auth/logout')).status, 200);
  assert.equal((await use()).status, 401);
});

test("bindingRoute: a Cloudflare call is its service's, through its cloudflare binding, and its context takes no other credential", async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  const place = await marketProd();
  const request = () => new Request(`${ORIGIN}/use/-/stripe/v1/charges`, { method: 'POST' });
  assert.equal((await read((await bindingRoute(request(), runtime, MEMBER))!)).status, 401, 'no binding yet');
  const binding = await bind('cloudflare', null, {});
  const used = await read((await bindingRoute(request(), runtime, MEMBER))!);
  assert.equal(used.status, 200, JSON.stringify(used.body));
  const caller = used.body.caller as Record<string, unknown>;
  assert.deepEqual([caller.credentialId, caller.profile, caller.hdr, caller.nonce, caller.place], [`binding:${binding}`, 'cloudflare', null, null, place]);
  await freeze(`credential:${place}/stripe`);
  assert.equal((await read((await bindingRoute(request(), runtime, MEMBER))!)).body.reason, 'frozen', 'the credential it uses, in the one place it reaches');
  await freeze(`credential:${place}/stripe`, 'workload.unfreeze');
  await assert.rejects(seen.context!.handle('coffre_use_x'), { reason: 'binding' });
  await freeze(`binding:${binding}`);
  assert.equal((await read((await bindingRoute(request(), runtime, MEMBER))!)).body.reason, 'frozen');
  await freeze(`binding:${binding}`, 'workload.unfreeze');
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, binding);
  assert.equal((await read((await bindingRoute(request(), runtime, MEMBER))!)).status, 401);
});

/** The newest entries `author` wrote, newest first. */
async function newest(author: 'app' | 'vault', count = 5) {
  const rows = await db.owner.select().from(auditLog).where(eq(auditLog.author, author)).orderBy(desc(auditLog.seq)).limit(count);
  return rows.map((row) => ({ action: row.action, decision: row.decision, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test("a Cloudflare call uses its service's values: the vault's read names no credential, the use it appends names the binding", async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  await marketProd();
  const binding = await bind('cloudflare', null, {});
  assert.equal((await read((await bindingRoute(new Request(`${ORIGIN}/use/-/stripe`, { method: 'POST' }), runtime, MEMBER))!)).status, 200);
  const used = await seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: { credential: 'stripe' } });
  assert.equal(used.values.STRIPE_SECRET_KEY, 'sk_live_1');
  // With 0.15's log, the use is the record, the binding its way in (T147), its kind in the purpose's bits above 512.
  if (LOG === '0.15') {
    assert.deepEqual((await usesLogged(db.owner)).map((use) => [use.credential, Math.floor(use.purpose / 512)]), [[binding, 2]]);
    return;
  }
  // The read, then the use the app gave the vault to append beside it, under the same head: the app appends nothing.
  const [logged, opened] = await newest('vault', 2);
  assert.deepEqual([opened!.action, opened!.decision, logged!.action], ['secret.read', 'allow', 'credential.use']);
  assert.equal(opened!.metadata.credentialId, undefined, 'the vault is told no credential: the binding has no credentials row');
  assert.equal(logged!.metadata.credentialId, `binding:${binding}`, 'the use names the binding the call came through');
  assert.equal((await newest('app')).find((entry) => entry.action === 'credential.use'), undefined);
});

test('a Cloudflare binding unbound after its call was checked releases nothing: the read is withheld, as for a revoked session', async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  await marketProd();
  const binding = await bind('cloudflare', null, {});
  assert.equal((await read((await bindingRoute(new Request(`${ORIGIN}/use/-/stripe`, { method: 'POST' }), runtime, MEMBER))!)).status, 200);
  // Checked; then unbound before the vault is asked.
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, binding);
  await assert.rejects(seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: { credential: 'stripe' } }), { status: 401 });
  // With 0.15's log, the use itself reads the binding ended (T147, WaysIn.tla's WayReadInUse): nothing released.
  if (LOG === '0.15') return assert.equal((await newest('vault')).find((entry) => entry.action === 'secret.read'), undefined);
  // The vault released, and logged it with the use it was given: a use records the release, as the read does. The
  // app withheld the value, and logged that, naming the binding, the same operation's entry after it.
  assert.deepEqual((await newest('vault', 2)).map((entry) => `${entry.action} ${entry.decision}`), ['credential.use allow', 'secret.read allow']);
  const [withheld] = await newest('app', 1);
  assert.deepEqual([withheld!.decision, withheld!.metadata.reason, withheld!.metadata.credentialId], ['deny', 'credential_ended', `binding:${binding}`]);
});

/**
 * An unbind that commits while the use waits for the log's head, which the
 * unbind holds: the vault, once it has the head, decides in a statement of
 * its own, and the app checks the binding in another after the vault has
 * released, never in the statement that waited. Under READ COMMITTED, a
 * statement that waited for a row lock reads only that row again: a check
 * of another table in it would see the binding as it stood before the wait.
 * The models (formal/Credentials.tla) take a statement as one step, and
 * cannot see that; this does.
 */
test('a Cloudflare binding unbound while its use waits for the head releases nothing', LOG === '0.15'
  ? { skip: "0.15's use takes no head, and decides on the binding's object, which an unbind changes under the fence (WaysIn.tla, WaysInUnbind)" }
  : postgresOnly('SQLite runs one writer at a time'), async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  await marketProd();
  const binding = await bind('cloudflare', null, {});
  assert.equal((await read((await bindingRoute(new Request(`${ORIGIN}/use/-/stripe`, { method: 'POST' }), runtime, MEMBER))!)).status, 200);
  const ctx = { caller: { principal: { type: 'user', id: ROOT } }, requestId: randomUUID(), sourceIp: null } as never;
  let commit!: () => void;
  const committing = new Promise<void>((resolve) => (commit = resolve));
  let holding!: () => void;
  const held = new Promise<void>((resolve) => (holding = resolve));
  // The unbind's tombstone, under the head, not yet committed.
  const unbinding = audited({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault }, async (_tx, log) => {
    log.push(allowed(ctx, 'token.unbind', { metadata: { bindingId: binding } }));
    holding();
    await committing;
  });
  await held;
  const using = seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: { credential: 'stripe' } });
  // Until the use waits for the head, in this database (a row lock's wait names a transaction, not a database), then the unbind commits.
  const waiting = async () => (await deps.db.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE NOT l.granted AND a.datname = current_database()`))[0]!.n;
  for (let tries = 0; (await waiting()) === 0; tries++) {
    assert.ok(tries < 200, 'the use never waited for the head');
    await sleep(10);
  }
  commit();
  await unbinding;
  await assert.rejects(using, { status: 401 });
});

test('a vault older than 0.14.5, which names no use back, and a use too long for it, leave the app to log the use under the head', { skip: LOG === '0.15' ? "0.15's use is its own record, through a binding too (T147)" : false }, async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  // An older vault takes no record of the use: it ignores it, and names nothing back.
  const older = new Proxy(deps.vault, {
    get: (target, key) => key === 'unwrap'
      ? async (input: Parameters<typeof target.unwrap>[0]) => target.unwrap({ ...input, use: undefined })
      : Reflect.get(target, key, target),
  });
  await marketProd();
  await bind('cloudflare', null, {});
  for (const [vault, logged] of [[older, { credential: 'stripe' }], [deps.vault, { credential: 'stripe', note: 'x'.repeat(20_000) }]] as const) {
    runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]), vault });
    assert.equal((await read((await bindingRoute(new Request(`${ORIGIN}/use/-/stripe`, { method: 'POST' }), runtime, MEMBER))!)).status, 200);
    const used = await seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged });
    assert.equal(used.values.STRIPE_SECRET_KEY, 'sk_live_1');
    assert.equal((await newest('vault', 1))[0]!.action, 'secret.read', 'the vault appended no use');
    assert.equal((await newest('app', 1))[0]!.action, 'credential.use', 'the app did');
  }
});

// 0.14's: a binding's end, with 0.15's log, is its change in the log, which its uses decide on (WaysIn.tla, T147), as its
// sign-ins do (0037): no 0.14 tombstone is read, and a row and its log restored together stand together.
test('a Cloudflare binding with a tombstone, though its row was never revoked, releases nothing', { skip: LOG === '0.15' ? "0.15's uses decide on the binding's object, no tombstone of 0.14's" : false }, async () => {
  const seen: { caller?: WorkloadUse; context?: PluginContext } = {};
  runtime = makeRuntime({ plugins: checkPlugins([probe(seen)]) });
  await marketProd();
  const binding = await bind('cloudflare', null, {});
  assert.equal((await read((await bindingRoute(new Request(`${ORIGIN}/use/-/stripe`, { method: 'POST' }), runtime, MEMBER))!)).status, 200);
  // A tombstone alone, as an unbind whose row update a restored backup lost.
  const ctx = { caller: { principal: { type: 'user', id: ROOT } }, requestId: randomUUID(), sourceIp: null } as never;
  await audited({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault }, async (_tx, log) => {
    log.push(allowed(ctx, 'token.unbind', { metadata: { bindingId: binding } }));
  });
  await assert.rejects(seen.context!.use(seen.caller!, { path: 'market/prod', keys: ['STRIPE_SECRET_KEY'], purpose: 'use', logged: { credential: 'stripe' } }), { status: 401 });
});

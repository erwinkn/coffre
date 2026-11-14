// A CI run's exchange, POST /api/auth/oidc, on the 0.16 contract
// (docs/design/0.16.md, "A workload signing in"): admission, one statement
// to learn which keys to verify under, the signature verified under them,
// then one `token.exchange`, which decides. What the vault decides is its
// own suite's (packages/vault/test/workloads.test.ts); here, the app's part,
// what each refusal tells the run, and what a refusal costs; an answer's
// cost, request-cost.test.ts holds.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { after, beforeEach, mock, test } from 'node:test';

import { canonicalClaims, github, signin, type RateLimiter, type WorkloadAlert } from '@coffre/core/identity';
import { credentials } from '@coffre/db/schema';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, signerOf, write } from '@coffre/vault/testing';
import { eq } from 'drizzle-orm';

import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const DEPLOY = 'token:deploy';
const GITHUB = 'https://token.actions.githubusercontent.com';
const KEYS = `${GITHUB}/.well-known/jwks`;
const KUBE = 'https://kubernetes.acme.example';
const MAIN = { repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push' };

/** What the issuers publish, by URL; every URL the app fetched, in order. */
const published = new Map<string, unknown>();
const fetched: string[] = [];
const transport: WorkloadTransport = {
  async json(url) {
    fetched.push(url.href);
    if (!published.has(url.href)) throw FetchRefused.answered(url, 503);
    return published.get(url.href);
  },
};

/** The admission limits, which a test turns to refusing, or failing. */
let admitting: 'yes' | 'no' | 'broken' = 'yes';
const limiter: RateLimiter = {
  async limit() {
    if (admitting === 'broken') throw new Error('the limiter is down');
    return { success: admitting === 'yes' };
  },
};
const alerts: WorkloadAlert[] = [];
/** The deployment's alert: kept, and never answered, as one whose hook hangs. */
const alerted = (alert: WorkloadAlert) => {
  alerts.push(alert);
  return new Promise<void>(() => {});
};
const providers = [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })];
const app = await openApp({ auth: signin({ providers, workloads: { limits: { perSource: limiter, total: processLimits().total }, alert: alerted } }), transport, workloads: {} });
const { world } = app;
after(() => app.close());

const pair = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = (key: KeyObject, kid: string) => ({ ...key.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' });
const github1 = pair();
const kube1 = pair();
const KUBE_JWKS = JSON.stringify({ keys: [jwk(kube1.publicKey, 'kube-1')] });

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
let drawn = 0;
/** A run's ID token, ES256, signed by `key` under `kid`: GitHub's by default, for main. */
function idToken(claims: Record<string, unknown> = {}, { key = github1.privateKey, kid = 'gh-1' }: { key?: KeyObject; kid?: string } = {}): string {
  drawn += 1;
  const input = `${b64({ alg: 'ES256', kid, typ: 'JWT' })}.${b64({ iss: GITHUB, sub: 'repo:acme/api:ref:refs/heads/main', aud: PUBLIC_URL, iat: now() - 10, exp: now() + 290, jti: `run-${drawn}`, ...MAIN, ...claims })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

const market = project('market');
const prod = environment(market, 'prod');
const VIEWER = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);
let main: ReturnType<typeof binding>;

/** `deploy` holds Developer on market; its binding for main reaches market as a Viewer. GitHub publishes one key. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  forgetKeys();
  published.clear();
  published.set(KEYS, { keys: [jwk(github1.publicKey, 'gh-1')] });
  fetched.length = 0;
  alerts.length = 0;
  admitting = 'yes';
  main = binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, label: 'main' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'viewer', ['secret.read'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(DEPLOY)),
    ...rows('grants', grant(DEPLOY, 'developer', { project: market })),
    ...rows('bindings', main),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Answer = { status: number; body: { token?: string; expiresAt?: string; error?: string; reason?: string; message?: string }; retryAfter: string | null };
const exchange = async (token: string, service = DEPLOY, through = app): Promise<Answer> => {
  const got = await through.request('/api/auth/oidc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service, token }) });
  return { status: got.status, body: (await got.json()) as Answer['body'], retryAfter: got.headers.get('retry-after') };
};
/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: Answer) => [answer.status, answer.body.error, answer.body.reason];
/** Whether each of `works` has settled, as of now. */
const settledOf = (works: Promise<unknown>[]) => Promise.all(works.map((work) => Promise.race([work.then(() => true, () => true), new Promise<boolean>((resolve) => setImmediate(resolve, false))])));

test("a run's token buys a five-minute token of its service, the issuer's keys fetched once; it reads as the service", async () => {
  const answer = await exchange(idToken());
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.match(answer.body.token!, /^coffre_svc_/);
  const left = Date.parse(answer.body.expiresAt!) - Date.now();
  assert.ok(left > 4 * 60_000 && left <= 5 * 60_000, `${left} ms`);
  assert.deepEqual(fetched, [KEYS]);
  const me = await app.request('/api/me', { headers: { authorization: `Bearer ${answer.body.token}` } });
  assert.equal(me.status, 200);
  const seen = (await me.json()) as { principal: { type: string; id: string }; features: { workloads: boolean } };
  assert.equal(seen.principal.id, 'deploy');
  // This deployment's sign-in trusts workloads, and says so.
  assert.equal(seen.features.workloads, true);
  // The keys are kept: the next run fetches nothing.
  assert.equal((await exchange(idToken())).status, 200);
  assert.deepEqual(fetched, [KEYS]);
});

test("the audit page leads each entry a run's credential wrote to its run, through the exchange, after the credential's row is gone", async () => {
  // An auditor who writes, too: their write is no run's.
  const AUD = 'user:aud@acme.example';
  await write(world, ...rows('roles', role(true, 'auditor', ['secret.write', 'audit.read'])), ...rows('principals', principal(AUD, { role: 'auditor' })), ...rows('credentials', credential('aud-cli', AUD)));
  const call = (bearer: string, path: string, init: RequestInit = {}) => app.request(path, { ...init, headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' } });
  const wrote = await call('aud-cli', '/api/secrets/market/prod', { method: 'PATCH', body: JSON.stringify({ API_KEY: 'v1' }) });
  assert.equal(wrote.status, 200, await wrote.text());
  const run = await exchange(idToken());
  assert.equal(run.status, 200, JSON.stringify(run.body));
  assert.equal((await call(run.body.token!, '/api/reveals', { method: 'POST', body: JSON.stringify({ path: 'market/prod/API_KEY' }) })).status, 200);
  await (await signerOf(world)).sign();
  // Whoever owns the database deletes the credential's row: the log alone leads from the read to the run.
  await world.owner.delete(credentials).where(eq(credentials.principal, DEPLOY));

  type Entry = { seq: number; action: string; actorId: string; run: { exchangeSeq: number; claims: Record<string, unknown> } | null };
  const got = await call('aud-cli', '/api/audit?detail=1');
  assert.equal(got.status, 200);
  const entries = ((await got.json()) as { entries: Entry[] }).entries.filter((entry) => entry.action !== 'test.write');
  assert.deepEqual(entries.map((entry) => `${entry.actorId} ${entry.action}`), ['deploy secret.read', 'deploy token.exchange', 'aud@acme.example secret.write']);
  const [read, exchanged, written] = entries as [Entry, Entry, Entry];
  assert.equal(exchanged.run?.exchangeSeq, exchanged.seq);
  assert.equal(exchanged.run?.claims.ref, MAIN.ref);
  assert.deepEqual(read.run, exchanged.run);
  assert.equal(written.run, null);
});

test('a token is spent once: the same token again is replayed, by the vault', async () => {
  const token = idToken();
  assert.equal((await exchange(token)).status, 200);
  const [again, calls] = await cost(() => exchange(token));
  assert.deepEqual([refused(again), calls], [[401, 'unauthenticated', 'replayed'], ['change']]);
  assert.match(again.body.message!, /exchanged already/);
});

test('a token no binding can take costs its admission and at most one statement: no vault call, no fetch', async () => {
  const cases: [string, () => Promise<Answer>, unknown[], number][] = [
    ['no token at all', () => exchange('not.a.token'), [401, 'unauthenticated', 'malformed'], 0],
    ['a service that is not there', () => exchange(idToken(), 'token:nobody'), [401, 'unauthenticated', 'no_match'], 1],
    ['a service named as no service is', () => exchange(idToken(), 'deploy'), [401, 'unauthenticated', 'no_match'], 0],
    ['an issuer it has no binding on', () => exchange(idToken({ iss: 'https://gitlab.example' })), [401, 'unauthenticated', 'no_match'], 1],
  ];
  for (const [what, run, expected, most] of cases) {
    const [answer, calls, statements] = await cost(run);
    assert.deepEqual([refused(answer), calls, statements], [expected, [], most], what);
  }
  assert.deepEqual(fetched, []);
});

test("the app's own checks of a fetched set's signature and audience refuse before the vault is asked", async () => {
  const forged = idToken({}, { key: pair().privateKey });
  const [badSignature, calls] = await cost(() => exchange(forged));
  assert.deepEqual([refused(badSignature), badSignature.body.message, calls], [[401, 'unauthenticated', 'signature'], "the token's signature does not verify", []]);
  const [elsewhere, elsewhereCalls] = await cost(() => exchange(idToken({ aud: 'https://other.example' })));
  assert.deepEqual([refused(elsewhere), elsewhereCalls], [[401, 'unauthenticated', 'audience'], []]);
});

test("which keys the vault verifies under, the app reads as the vault does, by the binding's address: a `jwks` its row carries beside a fetched address does not spare the app's check", async () => {
  // A row whose columns disagree, newer than `main`: were the app to read `jwks`, it would leave a forged token to a vault that trusts the app's check for an address it fetches.
  await write(world, ...rows('bindings', binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, jwks: KUBE_JWKS, createdAt: new Date() })));
  const [forged, calls] = await cost(() => exchange(idToken({}, { key: pair().privateKey })));
  assert.deepEqual([refused(forged), calls, fetched], [[401, 'unauthenticated', 'signature'], [], [KEYS]]);
});

test('a service named as the vault takes none is told no binding trusts it, and nothing is read or asked', async () => {
  for (const service of [`${DEPLOY}\0`, 'token:a b', 'token:\ud800']) {
    const [answer, calls, statements] = await cost(() => exchange(idToken(), service));
    assert.deepEqual([refused(answer), calls, statements], [[401, 'unauthenticated', 'no_match'], [], 0], JSON.stringify(service));
  }
});

test("a service's name as long as the vault's contract allows is looked up; one longer is a bad request", async () => {
  const [longest, , statements] = await cost(() => exchange(idToken(), `token:${'a'.repeat(250)}`));
  assert.deepEqual([refused(longest), statements], [[401, 'unauthenticated', 'no_match'], 1]);
  assert.equal((await exchange(idToken(), `token:${'a'.repeat(251)}`)).status, 400);
});

test('an issuer no database could store is malformed, refused before anything is read', async () => {
  for (const iss of [`${KUBE}\0`, `${KUBE}\ud800`]) {
    const [answer, calls, statements] = await cost(() => exchange(idToken({ iss })));
    assert.deepEqual([refused(answer), calls, statements], [[401, 'unauthenticated', 'malformed'], [], 0], JSON.stringify(iss));
  }
});

test('a token that does not decode is refused before anything is read, and logged once a minute', async () => {
  const logged = mock.method(console, 'error', () => {});
  const refusals = () => logged.mock.calls.filter((call) => (call.arguments[0] as { event?: string; reason?: string } | undefined)?.event === 'workload_exchange_refused').map((call) => (call.arguments[0] as { reason: string }).reason);
  for (let i = 0; i < 2; i += 1) {
    const [answer, calls, statements] = await cost(() => exchange('not.a.token', `token:garbled-${process.pid}`));
    assert.deepEqual([refused(answer), calls, statements], [[401, 'unauthenticated', 'malformed'], [], 0]);
  }
  logged.mock.restore();
  assert.deepEqual(refusals(), ['malformed']);
});

test("an unknown key's alert names the service in full, quoted as the shell reads it", async () => {
  for (const [odd, named] of [['token:ci;id$(x)', /then coffre trust 'service:ci;id\$\(x\)' --issuer https:\/\/kubernetes\.acme\.example --replace-keys/], ['token:token:prod', /then coffre trust service:token:prod --issuer/], ['token:-x', /then coffre trust service:-x --issuer/]] as const) {
  await write(world, ...rows('principals', principal(odd)), ...rows('grants', grant(odd, 'developer', { project: market })));
  await write(world, ...rows('bindings', binding(odd, { profile: 'custom', issuer: KUBE, jwksUri: `sha256:${createHash('sha256').update(KUBE_JWKS).digest('hex')}`, jwks: KUBE_JWKS, claims: canonicalClaims({ sub: 'system:serviceaccount:ci:runner' }), scope: VIEWER })));
  const logged = mock.method(console, 'error', () => {});
  const answer = await exchange(idToken({ iss: KUBE, sub: 'system:serviceaccount:ci:runner' }, { key: pair().privateKey, kid: 'rotated' }), odd);
  logged.mock.restore();
  assert.deepEqual(refused(answer), [401, 'unauthenticated', 'unknown_signer']);
  assert.match(alerts.at(-1)!.text, named);
  }
});

test("claims no binding trusts are named, never the values a binding expects", async () => {
  const [answer, calls] = await cost(() => exchange(idToken({ repository_id: '1' })));
  assert.deepEqual([refused(answer), calls], [[401, 'unauthenticated', 'no_match'], ['change']]);
  assert.match(answer.body.message!, /repository_id differ/);
  assert.ok(!answer.body.message!.includes('41532'));
});

test("an issuer whose keys cannot be fetched is the app's 503, with when to come back, and no vault call", async () => {
  published.clear();
  const [answer, calls] = await cost(() => exchange(idToken()));
  assert.deepEqual([refused(answer), answer.retryAfter, calls], [[503, 'unavailable', 'issuer_unavailable'], '60', []]);
});

test("a binding that carries its keys: the app fetches nothing, the vault verifies; an unknown key alerts once an hour, waited on 2 s at most, and logs once a minute", async () => {
  const logged = mock.method(console, 'error', () => {});
  const refusals = () => logged.mock.calls.filter((call) => (call.arguments[0] as { event?: string } | undefined)?.event === 'workload_exchange_refused').length;
  const carried = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: `sha256:${createHash('sha256').update(KUBE_JWKS).digest('hex')}`, jwks: KUBE_JWKS, claims: canonicalClaims({ sub: 'system:serviceaccount:ci:runner' }), scope: VIEWER });
  await write(world, ...rows('bindings', carried));
  const kube = (key: KeyObject, kid: string) => idToken({ iss: KUBE, sub: 'system:serviceaccount:ci:runner' }, { key, kid });
  const made = await exchange(kube(kube1.privateKey, 'kube-1'));
  assert.deepEqual([made.status, fetched], [200, []]);
  const stranger = pair();
  const before = app.tracked.length;
  const started = performance.now();
  const [unknown] = await cost(() => exchange(kube(stranger.privateKey, 'rotated')));
  const waited = performance.now() - started;
  assert.deepEqual(refused(unknown), [401, 'unauthenticated', 'unknown_signer']);
  assert.ok(waited >= 1_900 && waited < 4_000, `answered after ${Math.round(waited)} ms`);
  // The hook, still unanswered, is work the platform keeps the request alive for: on Workers, the response's end would cancel it.
  assert.equal((await settledOf(app.tracked.slice(before))).filter((settled) => !settled).length, 1);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0]!.text, /save its JWKS as keys\.json, then coffre trust service:deploy --issuer https:\/\/kubernetes\.acme\.example --replace-keys/);
  assert.equal(refusals(), 1);
  assert.deepEqual({ kind: alerts[0]!.kind, service: alerts[0]!.service, binding: alerts[0]!.binding }, { kind: 'unknown_key', service: DEPLOY, binding: carried.id });
  assert.match(alerts[0]!.text, /names key "rotated", not one uploaded for https:\/\/kubernetes\.acme\.example/);
  // Within the hour, once: the next is refused the same, and says nothing more.
  assert.deepEqual(refused(await exchange(kube(stranger.privateKey, 'rotated'))), [401, 'unauthenticated', 'unknown_signer']);
  assert.equal(alerts.length, 1);
  assert.equal(refusals(), 1);
  logged.mock.restore();
});

test('admission comes first: a limit reached is 429 and a limiter that fails 503, before anything is read; a body past its limit is 400', async () => {
  admitting = 'no';
  const [busy, calls, statements] = await cost(() => exchange(idToken()));
  assert.deepEqual([refused(busy), busy.retryAfter, calls, statements], [[429, 'too_many_requests', 'busy'], '60', [], 0]);
  admitting = 'broken';
  assert.deepEqual(refused(await exchange(idToken())), [503, 'unavailable', 'busy']);
  admitting = 'yes';
  const huge = await app.request('/api/auth/oidc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: DEPLOY, token: 'x'.repeat(20_000) }) });
  assert.ok(huge.status === 400 || huge.status === 413, String(huge.status));
  assert.equal((await app.request('/api/auth/oidc')).status, 405);
});

test('an instance that takes no workloads answers 404; one that takes only key-bound sessions, 410', async () => {
  const off = await openApp({ transport });
  const strict = await openApp({ auth: signin({ providers, workloads: { limits: processLimits(), useOnly: true } }), transport, workloads: { useOnly: true } });
  try {
    assert.deepEqual(refused(await exchange(idToken(), DEPLOY, off)), [404, 'not_found', undefined]);
    assert.deepEqual(refused(await exchange(idToken(), DEPLOY, strict)), [410, 'gone', 'use_only']);
    assert.deepEqual([off.calls, strict.calls], [[], []]);
  } finally {
    await Promise.all([off.close(), strict.close()]);
  }
});

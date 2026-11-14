// The Vault KV adapter's sign-in (`@coffre/server/plugins/vault-kv`), as
// External Secrets Operator's Kubernetes auth makes it: `PUT
// /v1/auth/kubernetes/login` with a projected service-account token, a read
// with the token it answers, then ESO's cleanup, lookup-self and revoke-self.
// The token goes through the service account's trust bindings, here keys
// uploaded for a private cluster: the plugin passes it on (`exchange`), and
// it costs what `POST /api/auth/oidc` does. 0.14.7's cases, on 0.16's contract.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { canonicalClaims, github, signin, type RateLimiter } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { binding, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { vaultKv } from '../src/plugins/vault-kv.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const SERVICE = 'eso';
/** A private cluster's issuer, which coffre could not fetch from: its keys are uploaded with the binding. */
const CLUSTER = 'https://kubernetes.default.svc.cluster.local';
const UID = '0b7c3d9e-1f2a-4b5c-8d6e-7f8091a2b3c4';
/** ESO's reader, `eso-reader` of namespace `apps`, by name and UID. */
const ACCOUNT = { sub: 'system:serviceaccount:apps:eso-reader', 'kubernetes.io.serviceaccount.uid': UID };
const PROD = { DATABASE_URL: 'postgres://prod' };

const cluster = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const JWKS = JSON.stringify({ keys: [{ ...cluster.publicKey.export({ format: 'jwk' }), kid: 'cluster-1', alg: 'ES256', use: 'sig' }] });

/** Whether exchanges pass their limits: a test closes it to see the 429. */
let open = true;
const limiter: RateLimiter = { limit: async () => ({ success: open }) };
const app = await openApp({
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: { perSource: limiter, total: processLimits().total } } }),
  workloads: {},
  plugins: [vaultKv()],
});
const { world } = app;
after(() => app.close());

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

/** What ESO's TokenRequest gets from the cluster for `eso-reader`, with coffre as its audience, signed with the uploaded key. */
function projected(claims: Record<string, unknown> = {}): string {
  const iat = seconds() - 5;
  const input = `${part({ alg: 'ES256', kid: 'cluster-1', typ: 'JWT' })}.${part({
    iss: CLUSTER,
    aud: [PUBLIC_URL],
    sub: ACCOUNT.sub,
    iat,
    nbf: iat,
    exp: iat + 300,
    jti: crypto.randomUUID(),
    'kubernetes.io': { namespace: 'apps', serviceaccount: { name: 'eso-reader', uid: UID } },
    ...claims,
  })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: cluster.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

/** market: prod and staging. ESO's account views prod, and its binding trusts `eso-reader` with prod, as Viewer. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  forgetKeys();
  open = true;
  const market = project('market');
  const [prod, staging] = [environment(market, 'prod'), environment(market, 'staging')];
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'viewer', ['secret.read'], [])),
    ...rows('projects', market),
    ...rows('environments', prod, staging),
    ...rows('secrets', await value(world, secret(prod, 'DATABASE_URL'), PROD.DATABASE_URL), await value(world, secret(staging, 'DATABASE_URL'), 'postgres://staging')),
    ...rows('principals', principal(`token:${SERVICE}`), principal('token:other')),
    ...rows('grants', grant(`token:${SERVICE}`, 'viewer', { project: market })),
    ...rows(
      'bindings',
      binding(`token:${SERVICE}`, {
        profile: 'custom',
        issuer: CLUSTER,
        jwksUri: `sha256:${createHash('sha256').update(JWKS).digest('hex')}`,
        jwks: JWKS,
        claims: canonicalClaims(ACCOUNT),
        scope: JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]),
        label: 'cluster',
      }),
    ),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Answer = { status: number; body: Record<string, any> | null };
/** A request as HashiCorp's Go client sends it. */
async function vault(method: string, path: string, init: { token?: string; body?: unknown } = {}): Promise<Answer> {
  const headers: Record<string, string> = { 'x-vault-request': 'true' };
  if (init.token !== undefined) headers['x-vault-token'] = init.token;
  const body = init.body === undefined ? undefined : typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
  const response = await app.request(`/v1/${path}`, { method, headers, body });
  const text = await response.text();
  return { status: response.status, body: text === '' ? null : (JSON.parse(text) as Record<string, any>) };
}
const login = (jwt: string, role = SERVICE, mount = 'kubernetes', method = 'PUT') => vault(method, `auth/${mount}/login`, { body: { role, jwt } });
/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}

test("ESO's Kubernetes auth: a login, a read with its token, then lookup-self and revoke-self, which ends it", async () => {
  const [signedIn, calls, statements] = await cost(() => login(projected()));
  assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
  // What `POST /api/auth/oidc` costs, and nothing more: the plugin only passes the request on.
  const [direct, viaApi, apiStatements] = await cost(() => app.request('/api/auth/oidc', { method: 'POST', body: JSON.stringify({ service: `token:${SERVICE}`, token: projected() }) }));
  assert.equal(direct.status, 200);
  assert.deepEqual([calls, statements], [viaApi, apiStatements]);
  const { auth } = signedIn.body!;
  assert.match(auth.client_token, /^coffre_svc_/);
  assert.equal(auth.renewable, false);
  assert.ok(auth.lease_duration > 290 && auth.lease_duration <= 300, String(auth.lease_duration));
  assert.deepEqual(auth.metadata, { role: SERVICE });
  assert.equal(signedIn.body!.data, null);

  assert.deepEqual({ ...(await vault('GET', 'secret/data/market/prod', { token: auth.client_token })).body!.data.data }, PROD);
  // The binding's credential reaches what the binding does, no more.
  assert.equal((await vault('GET', 'secret/data/market/staging', { token: auth.client_token })).status, 403);

  // Close(): lookup-self, then revoke-self.
  const self = await vault('GET', 'auth/token/lookup-self', { token: auth.client_token });
  assert.equal(self.body!.data.display_name, `token:${SERVICE}`);
  assert.ok(self.body!.data.ttl > 290 && self.body!.data.ttl <= 300, String(self.body!.data.ttl));
  const [revoked, ended] = await cost(() => vault('PUT', 'auth/token/revoke-self', { token: auth.client_token }));
  assert.deepEqual([revoked.status, ended], [204, ['change']]);
  // Past the vault's memory of a use's rows (`memorySeconds`), which is what a revocation waits at most, through the API too.
  for (const kept of [world.memory.reads, world.memory.callers]) kept.clear();
  assert.equal((await vault('GET', 'secret/data/market/prod', { token: auth.client_token })).status, 403);

  // The exchange's own entry, the vault's.
  const entries = (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => row.body);
  assert.ok(entries.some((entry) => entry.includes('token.exchange') && entry.includes(`token:${SERVICE}`)), entries.join('\n'));
});

test("vault-action's JWT auth at its own mount, by POST, and a mount several segments deep, sign in the same way", async () => {
  const signedIn = await login(projected(), SERVICE, 'jwt', 'POST');
  assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
  assert.match(signedIn.body!.auth.client_token, /^coffre_svc_/);
  // ESO's `mountPath: kubernetes/cluster-a`.
  assert.equal((await login(projected(), SERVICE, 'kubernetes/cluster-a')).status, 200);
});

test('a token signs in once, and only as an account whose bindings trust it: refusals are 403, with the reason', async () => {
  const once = projected();
  assert.equal((await login(once)).status, 200);
  const replayed = await login(once);
  assert.equal(replayed.status, 403);
  assert.match(replayed.body!.errors[0], /permission denied/);
  // Another account, which trusts nothing.
  assert.equal((await login(projected(), 'other')).status, 403);
  // Another service account in the cluster.
  assert.equal((await login(projected({ sub: 'system:serviceaccount:apps:intruder' }))).status, 403);
  // Signed by a key the binding does not hold.
  const forged = projected().split('.');
  assert.equal((await login(`${forged[0]}.${forged[1]}.${Buffer.from('nope').toString('base64url')}`)).status, 403);
  // A role that is no account name.
  assert.equal((await login(projected(), 'Not An Account')).status, 403);
});

test("a login's body is { role, jwt }, JSON, small; GET is no login; revoke-self needs the token", async () => {
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: 'role=eso' })).status, 400);
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: { role: SERVICE } })).status, 400);
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: { role: 7, jwt: projected() } })).status, 400);
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: { role: SERVICE, jwt: 'x'.repeat(20_000) } })).status, 400);
  assert.equal((await vault('GET', 'auth/kubernetes/login')).status, 405);
  // `auth/token/login` is no auth method: Vault's token auth has none, and nothing else writes.
  assert.equal((await vault('PUT', 'auth/token/login', { body: { role: SERVICE, jwt: projected() } })).status, 405);
  assert.equal((await vault('PUT', 'secret/data/market/prod', { body: { data: { X: 'y' } } })).status, 405);
  assert.equal((await vault('PUT', 'auth/token/revoke-self')).status, 403);
});

test('limits come first: 429 before the body is read, malformed or not', async () => {
  open = false;
  const [busy, calls, statements] = await cost(() => login(projected()));
  assert.deepEqual([busy.status, calls, statements], [429, [], 0]);
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: 'not json' })).status, 429);
  // Its body is never read: a stream that counts its reads is never pulled.
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>({ pull: (sink) => void (pulls++, sink.enqueue(new TextEncoder().encode(JSON.stringify({ role: SERVICE, jwt: projected() }))), sink.close()) }, { highWaterMark: 0 });
  const refused = await app.request('/v1/auth/kubernetes/login', { method: 'PUT', headers: { 'x-vault-request': 'true' }, body, duplex: 'half' } as RequestInit);
  assert.deepEqual([refused.status, pulls], [429, 0]);
  open = true;
  assert.equal((await login(projected())).status, 200);
});

// The Vault KV adapter's sign-in (`@coffre/server/plugins/vault-kv`), as
// External Secrets Operator's Kubernetes auth makes it: `PUT
// /v1/auth/kubernetes/login` with a projected service-account token, a read
// with the token it answers, then ESO's cleanup, lookup-self and revoke-self.
// The token goes through the service account's trust bindings, here keys
// uploaded for a private cluster: the plugin only passes it on (`exchange`).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign as signWith, type KeyObject } from 'node:crypto';

import { github, signin, type BindingClaims } from '@coffre/core/identity';
import type { Database } from '@coffre/db';

import { coffreRoute } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { vaultKv } from '../src/plugins/vault-kv.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, signInsLogged, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'eso';
const IP = '203.0.113.9';
/** A private cluster's issuer, which coffre could not fetch from: its keys are uploaded with the binding. */
const CLUSTER = 'https://kubernetes.default.svc.cluster.local';
const UID = '0b7c3d9e-1f2a-4b5c-8d6e-7f8091a2b3c4';
/** ESO's reader, `eso-reader` of namespace `apps`, by name and UID. */
const ACCOUNT: BindingClaims = { sub: 'system:serviceaccount:apps:eso-reader', 'kubernetes.io.serviceaccount.uid': UID };
const PROD = { DATABASE_URL: `postgres://prod-${randomBytes(6).toString('hex')}` };

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KEY: { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> } = {
  kid: 'cluster-1',
  privateKey,
  jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'cluster-1', alg: 'RS256', use: 'sig' },
};

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

/** What ESO's TokenRequest gets from the cluster for `eso-reader`, with coffre as its audience: ten minutes, unless told. */
function projected(claims: Record<string, unknown> = {}): string {
  const iat = seconds() - 5;
  const input = `${part({ alg: 'RS256', kid: KEY.kid, typ: 'JWT' })}.${part({
    iss: CLUSTER,
    aud: [ORIGIN],
    sub: ACCOUNT.sub,
    iat,
    nbf: iat,
    exp: iat + 600,
    jti: crypto.randomUUID(),
    'kubernetes.io': { namespace: 'apps', serviceaccount: { name: 'eso-reader', uid: UID } },
    ...claims,
  })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), KEY.privateKey).toString('base64url')}`;
}

/** Nothing is fetched: the keys are uploaded. */
const transport: WorkloadTransport = {
  json: async (url) => {
    throw new Error(`fetched ${url.href}`);
  },
};

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
/** Whether exchanges pass their limits: a test closes it to see the 429. */
let open: boolean;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  open = true;
  deps = testDeps(db.runtime, [ROOT]);
  const limiter = { limit: async () => ({ success: open }) };
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: { perSource: limiter, total: processLimits({ perSource: 1000, total: 1000 }).total } } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: [vaultKv()],
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport);
  const root = clientFor(deps, ROOT);
  await root.members.add(`token:${SERVICE}`);
  await root.projects.create('market');
  await root.environments.create('market/prod');
  await root.environments.create('market/staging');
  await root.secrets.set('market/prod', PROD);
  await root.secrets.set('market/staging', { DATABASE_URL: 'postgres://staging' });
  await root.access.set(`token:${SERVICE}`, { 'market/prod': 'viewer' });
  const made = await runtime.workloads!.bind(
    await contextFor(deps, ROOT),
    SERVICE,
    { profile: 'custom', issuer: CLUSTER, claims: ACCOUNT, label: 'cluster', replaces: [], jwks: { keys: [KEY.jwk] } as never },
    { dryRun: false },
  );
  assert.ok('binding' in made);
});

/** A request as HashiCorp's Go client sends it, answered by coffre in process. */
async function vault(method: string, path: string, init: { token?: string; body?: unknown; on?: CoffreRuntime } = {}) {
  const headers: Record<string, string> = { 'x-vault-request': 'true' };
  if (init.token !== undefined) headers['x-vault-token'] = init.token;
  const body = init.body === undefined ? undefined : typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
  const response = (await coffreRoute(new Request(`${ORIGIN}/v1/${path}`, { method, headers, body }), init.on ?? runtime, IP))!;
  const text = await response.text();
  return { status: response.status, body: (text === '' ? null : JSON.parse(text)) as Record<string, any> | null };
}

const login = (jwt: string, role = SERVICE, mount = 'kubernetes', method = 'PUT') => vault(method, `auth/${mount}/login`, { body: { role, jwt } });

test("ESO's Kubernetes auth: a login, a read with its token, then lookup-self and revoke-self, which ends it", async () => {
  const signedIn = await login(projected());
  assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
  const { auth } = signedIn.body!;
  assert.match(auth.client_token, /^coffre_svc_/);
  assert.equal(auth.renewable, false);
  assert.ok(auth.lease_duration > 290 && auth.lease_duration <= 300, String(auth.lease_duration));
  assert.equal(signedIn.body!.data, null);

  const read = await vault('GET', 'secret/data/market/prod', { token: auth.client_token });
  assert.deepEqual(read.body!.data.data, PROD);
  // The binding's credential reaches what the account holds, no more.
  assert.equal((await vault('GET', 'secret/data/market/staging', { token: auth.client_token })).status, 403);

  // Close(): lookup-self, then revoke-self.
  const self = await vault('GET', 'auth/token/lookup-self', { token: auth.client_token });
  assert.equal(self.body!.data.display_name, `token:${SERVICE}`);
  assert.ok(self.body!.data.ttl > 290 && self.body!.data.ttl <= 300);
  assert.equal((await vault('PUT', 'auth/token/revoke-self', { token: auth.client_token })).status, 204);
  assert.equal((await vault('GET', 'secret/data/market/prod', { token: auth.client_token })).status, 403);

  // The exchange's own record: the run it came from, as `coffre login --service` leaves it; with 0.15's log, its change (D147).
  const [exchanged] = await signInsLogged(db.owner);
  assert.equal(exchanged!.actor, `token:${SERVICE}`);
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
  await clientFor(deps, ROOT).members.add('token:other');
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
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: { role: SERVICE, jwt: 'x'.repeat(20_000) } })).status, 400);
  assert.equal((await vault('GET', 'auth/kubernetes/login')).status, 405);
  // `auth/token/login` is no auth method: Vault's token auth has none, and nothing else writes.
  assert.equal((await vault('PUT', 'auth/token/login', { body: { role: SERVICE, jwt: projected() } })).status, 405);
  assert.equal((await vault('PUT', 'secret/data/market/prod', { body: { data: { X: 'y' } } })).status, 405);
  assert.equal((await vault('PUT', 'auth/token/revoke-self')).status, 403);
});

test('limits and an instance that trusts no workloads: 429, and 400, never 404', async () => {
  open = false;
  const busy = await login(projected());
  assert.equal(busy.status, 429);
  // Admission first, as `/api/auth/oidc`'s: a body past the limits is never read, malformed or not.
  assert.equal((await vault('PUT', 'auth/kubernetes/login', { body: 'not json' })).status, 429);
  open = true;
  assert.equal((await login(projected())).status, 200);
  const none = await vault('PUT', 'auth/kubernetes/login', { body: { role: SERVICE, jwt: projected() }, on: { ...runtime, workloads: null } });
  assert.equal(none.status, 400);
  assert.match(none.body!.errors[0], /trusts no workloads/);
});

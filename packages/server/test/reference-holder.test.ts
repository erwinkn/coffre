// A reference is used and read as the environment it lives in allows, its
// sensitive value too (R20, R71; A516): a workload, a service token or a
// person with a grant on landing/prod alone, none on backend, uses and reads
// landing/prod/CLERK_SECRET_KEY, a reference to backend/prod's, as they do
// landing's own keys. Its source is checked when it is made (R24), never at a
// read. Both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import { bodyDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { github, signin } from '@coffre/core/identity';

import { coffreRoute } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import type { Gates } from '../src/gate.ts';
import { checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, openTestDatabase, refusedIn, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { answer, type Pages } from './start-fixture.ts';
import { pinnedGates } from './window-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
/** A Developer of landing/prod, with nothing on backend. */
const LIN = 'lin@acme.example';
const SERVICE = 'landing-prod';
const MEMBER = `token:${SERVICE}`;
const IP = '203.0.113.9';
const GITHUB = 'https://token.actions.githubusercontent.com';
const DEPLOY = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/landing/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};
const CLERK = 'sk_live_clerk_0123456789abcdef';
const STRIPE = 'sk_live_stripe_0123456789abcdef';

const ui = {} as Pages;
let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let gates: Gates;
let root: CoffreClient;
let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };
let upstream: Server;
let upstreamAt: string;
let reached: { url: string; headers: IncomingMessage['headers'] }[];

const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${GITHUB}/.well-known/openid-configuration`) return { issuer: GITHUB, jwks_uri: `${GITHUB}/keys` };
    if (url.href === `${GITHUB}/keys`) return { keys: [signer.jwk] };
    throw new FetchRefused(url, 'answered 404');
  },
};

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signer = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } };
  upstream = createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      reached.push({ url: request.url!, headers: request.headers });
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    });
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  upstreamAt = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  upstream.closeAllConnections();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetKeys();
  reached = [];
  gates = pinnedGates();
  deps = testDeps(db.runtime, [ROOT]);
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: checkPlugins([credentialProxy({
      credentials: {
        clerk: { upstream: `${upstreamAt}/clerk`, inject: header('authorization', 'Bearer {CLERK_SECRET_KEY}') },
        stripe: { upstream: `${upstreamAt}/stripe`, inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}') },
      },
      insecureUpstreams: true,
    })]),
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport, () => {}, gates);
  deps.signin = runtime.signin!;
  deps.workloads = runtime.workloads!;
  root = clientFor(deps, ROOT);
  await root.projects.create('backend');
  await root.projects.create('landing');
  await root.environments.create('backend/prod');
  await root.environments.create('landing/prod');
  await root.secrets.set('backend/prod', { CLERK_SECRET_KEY: { value: CLERK, sensitivity: 'sensitive' }, STRIPE_SECRET_KEY: STRIPE });
  await root.secrets.set('landing/prod', { CLERK_SECRET_KEY: { ref: 'backend/prod/CLERK_SECRET_KEY' }, STRIPE_SECRET_KEY: { ref: 'backend/prod/STRIPE_SECRET_KEY' } });
  await root.members.add(MEMBER);
  await root.access.set(MEMBER, { 'landing/prod': 'viewer' });
  await root.members.add(`user:${LIN}`);
  await root.access.set(`user:${LIN}`, { 'landing/prod': 'developer' });
});

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** The service's GitHub binding, made by `by`, the Owner unless named, with `policy`. */
async function bind(policy: Record<string, unknown> = {}, by = ROOT): Promise<void> {
  const made = await runtime.workloads!.bind(await contextFor(deps, by), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY as never, label: 'github', replaces: [], policy }, { dryRun: false });
  assert.ok('binding' in made, JSON.stringify(made));
}

type Session = { token: string; key: ProofKey };

async function session(): Promise<Session> {
  const key = await generateProofKey();
  const seconds = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${part({ iss: GITHUB, aud: `${ORIGIN}#jkt=${await thumbprint(key.jwk)}`, sub: 'repo:acme/landing:ref:refs/heads/main', iat: seconds - 5, exp: seconds + 600, jti: randomUUID(), ...DEPLOY })}`;
  const jwt = `${input}.${signWith('sha256', Buffer.from(input), signer.privateKey).toString('base64url')}`;
  const url = `${ORIGIN}/api/auth/workload`;
  const made = await answer(new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', dpop: await createProof(key, { method: 'POST', url }) }, body: JSON.stringify({ service: MEMBER, proof: { oidc: jwt } }) }), runtime, ui, IP);
  const body = (await made.json()) as { token: string };
  assert.equal(made.status, 200, JSON.stringify(body));
  return { token: body.token, key };
}

/** A GET through the proxy, as the SDK sends it. */
async function use(held: Session, path: string): Promise<{ status: number; body: string }> {
  const url = `${ORIGIN}${path}`;
  const proof = await createProof(held.key, { method: 'GET', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: {}, body: await bodyDigest('') } });
  const response = (await pluginRoute(new Request(url, { headers: { authorization: `DPoP ${held.token}`, dpop: proof } }), runtime, IP))!;
  return { status: response.status, body: await response.text() };
}

function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, IP).then((response) => response!) });
}

/** A key's value revealed by `client`, or why it was refused: its status and the reason the app's entry logs (D153). */
async function revealed(client: CoffreClient, path: string): Promise<string> {
  try {
    return Object.values((await client.secrets.reveal(path)).values).join();
  } catch (error) {
    const { status, code, reason } = error as { status: number; code?: string; reason?: string };
    return `${status} ${code === 'not_available' ? await refusedIn(db.owner) : reason ?? code}`;
  }
}

/** A reveal as the workload's session sends it, DPoP-bound, through the app's front door. */
async function sessionReveal(held: Session, path: string): Promise<string> {
  const url = `${ORIGIN}/api/reveals`;
  const proof = await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce() });
  const response = await answer(new Request(url, { method: 'POST', headers: { authorization: `DPoP ${held.token}`, dpop: proof, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }), runtime, ui, IP);
  const body = (await response.json()) as { values?: Record<string, string> };
  return response.status === 200 ? Object.values(body.values!).join() : `${response.status} ${await refusedIn(db.owner)}`;
}

test('a workload bound to landing/prod alone uses its references into backend/prod through the proxy, sensitive or secret', async () => {
  await bind();
  const held = await session();
  for (const credential of ['clerk', 'stripe']) {
    const sent = await use(held, `/use/landing/prod/${credential}/v1/x`);
    assert.equal(sent.status, 200, `${credential}: ${sent.body}`);
  }
  assert.deepEqual(reached.map((one) => one.headers.authorization), [`Bearer ${CLERK}`, `Bearer ${STRIPE}`]);
});

test('a workload listing "*" at landing/prod alone reads its references into backend/prod, as landing\'s own keys', async () => {
  await bind({ reads: { 'landing/prod': '*' } });
  const held = await session();
  assert.equal(await sessionReveal(held, 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await sessionReveal(held, 'landing/prod/CLERK_SECRET_KEY'), CLERK, 'an Owner of landing bound it: its sensitive values are theirs to give');
});

test('a workload listing one of landing/prod\'s references by name reads it, by its own ID, and not the other', async () => {
  await bind({ reads: { 'landing/prod': ['STRIPE_SECRET_KEY'] } });
  const held = await session();
  assert.equal(await sessionReveal(held, 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await sessionReveal(held, 'landing/prod/CLERK_SECRET_KEY'), '404 use_only');
});

test('a workload listing both of landing/prod\'s references by name reads both; a listed reference is as sensitive as its source', async () => {
  await bind({ reads: { 'landing/prod': ['CLERK_SECRET_KEY', 'STRIPE_SECRET_KEY'] } });
  const again = await session();
  assert.equal(await sessionReveal(again, 'landing/prod/CLERK_SECRET_KEY'), CLERK);
  assert.equal(await sessionReveal(again, 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  await assert.rejects(bind({ reads: { 'landing/prod': ['MISSING'] } }), /does not hold: MISSING/);
});

test('a listed reference is as sensitive as its source is now (R23): a Developer of landing/prod lists the secret one, and only an Owner the sensitive one (R32)', async () => {
  await root.access.set(`user:${LIN}`, { 'landing/prod': 'developer', 'landing': 'developer' });
  await bind({ reads: { 'landing/prod': ['STRIPE_SECRET_KEY'] } }, LIN);
  await assert.rejects(bind({ reads: { 'landing/prod': ['CLERK_SECRET_KEY'] } }, LIN), /only an Owner of landing lets a service read its sensitive values \(R32\): CLERK_SECRET_KEY/);
});

test('a broken reference holds nothing a binding can list, under either log', async () => {
  await root.secrets.set('landing/prod', { BROKEN: { ref: 'backend/prod/STRIPE_SECRET_KEY' } });
  await root.references.break('landing/prod/BROKEN');
  await assert.rejects(bind({ reads: { 'landing/prod': ['BROKEN'] } }), /does not hold: BROKEN/);
  await bind({ reads: { 'landing/prod': ['STRIPE_SECRET_KEY'] } });
});

test('a service token of landing/prod alone, issued by an Owner of landing, reads its references, sensitive and secret; one a Developer issued, the secret alone', async () => {
  const issued = await root.tokens.issue(MEMBER, { expiresInDays: 30, scope: { 'landing/prod': 'viewer' } });
  assert.deepEqual(issued.withheld, []);
  const token = bearer(issued.token);
  assert.equal(await revealed(token, 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await revealed(token, 'landing/prod/CLERK_SECRET_KEY'), CLERK);
  assert.deepEqual((await token.secrets.reveal('landing/prod')).values, { CLERK_SECRET_KEY: CLERK, STRIPE_SECRET_KEY: STRIPE });
  // Lin, a Developer of landing/prod, gives it what she holds there, and no sensitive value: the token says so when made.
  const lin = clientFor(deps, LIN);
  const hers = await lin.tokens.issue(MEMBER, { expiresInDays: 30, scope: { 'landing/prod': 'viewer' } });
  assert.deepEqual(hers.withheld, ['landing/prod']);
  assert.equal(await revealed(bearer(hers.token), 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await revealed(bearer(hers.token), 'landing/prod/CLERK_SECRET_KEY'), '404 not_owner_issued');
  await assert.rejects(bearer(hers.token).secrets.reveal('landing/prod'), {
    status: 403,
    message: 'landing/prod holds CLERK_SECRET_KEY (a reference to backend/prod/CLERK_SECRET_KEY), sensitive: a service account reads it only on a token or trust binding an Owner of landing issued',
  });
});

test('a Developer of landing/prod alone reads its reference to a secret, and is never shown a sensitive one', async () => {
  const lin = clientFor(deps, LIN);
  assert.equal(await revealed(lin, 'landing/prod/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await revealed(lin, 'landing/prod/CLERK_SECRET_KEY'), '404 sensitive');
});

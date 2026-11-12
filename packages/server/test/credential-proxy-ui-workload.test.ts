// UI routes served to workloads (0.16, T186 PR C2b; docs/design/proxy-ui.md, section 3, "Workloads"), end to end: a
// key-bound session, or a Cloudflare service binding's call, at the environment its statement checks, a route saved in
// the Proxy tab, and a fake upstream over HTTP. The item comes after the proof: the body is carried by its headers
// alone, the route's limit is counted from this isolate's copy or the vault's `proxyItem`, and the vault's one route use
// decides the values and the item, by which every check runs again before the send (BoundToDefinition): the allow
// list, and whether it takes the body as it came (503 `moved`). (A `narrow` child's constraints are weighed on the URL
// the decided item's upstream makes too; no test makes one here: 0.15's log refuses a child planted around the app, and
// `/api/auth/workload/narrow` answers 501 until its PR.)
// A revocation stops the next request whatever the value cache holds. 0.15's log.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomUUID, sign as signWith, verify as verifyWith, type KeyObject } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { WebSocket } from 'ws';

import { bodyDigest, contentDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { defineDeployment } from '@coffre/core/deployment';
import { github, hashToken, signin } from '@coffre/core/identity';
import { BODY_READ_WHOLE_BYTES } from '@coffre/core/memory';
import type { ProxyDefinition, Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { eq, sql, type SQL } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import type { Gates } from '../src/gate.ts';
import { upgrade } from '../src/node-sockets.ts';
import { bindingRoute, checkPlugins, pluginRoute } from '../src/plugins.ts';
import { proxyCodeWith } from '../src/proxy-code.ts';
import { forgetProxyGates } from '../src/proxy-gate.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, holdSomething, LOG, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { credentials } from './db/tables.ts';
import { answer, type Pages } from './start-fixture.ts';
import { pinnedGates } from './window-fixture.ts';

const ON_015 = { skip: LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const LIN = 'lin@acme.example';
const SERVICE = 'api-prod';
const MEMBER = `token:${SERVICE}`;
const IP = '203.0.113.9';
const GITHUB = 'https://token.actions.githubusercontent.com';
const DEPLOY = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};
const OPENAI = 'sk-openai-prod-0123456789abcdef';

const ui = {} as Pages;
let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let gates: Gates;
let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };
/** The vault's calls, by method. */
let calls: Map<string, number>;

let upstream: Server;
let upstreamAt: string;
let reached: { method: string; url: string; headers: IncomingMessage['headers']; body: string }[];

const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${GITHUB}/.well-known/openid-configuration`) return { issuer: GITHUB, jwks_uri: `${GITHUB}/keys` };
    if (url.href === `${GITHUB}/keys`) return { keys: [signer.jwk] };
    throw new FetchRefused(url, 'answered 404');
  },
};

/**
 * The deployment: code's `stripe`, the Proxy tab writing, local fakes allowed, values kept a minute or none; its R
 * `revokedWithinSeconds` where a case sets it, below its 3 s floor where a case needs a tunnel's checks in
 * milliseconds: a test's own object, which `defineDeployment` refuses, given to the runtime once made.
 */
function makeRuntime(cacheValues = false, revokedWithinSeconds?: number): CoffreRuntime {
  const plugins = checkPlugins([credentialProxy({
    credentials: { stripe: { upstream: `${upstreamAt}/stripe`, inject: header('authorization', 'Bearer {OPENAI_API_KEY}') } },
    insecureUpstreams: true,
  })]);
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000 }), alert: () => {} } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins,
    deployment: { proxy: { editable: true, cacheValues } },
  });
  const made = createRuntime(config, deps.db, deps.vault, transport, () => {}, gates);
  if (revokedWithinSeconds !== undefined) made.deployment = { ...defineDeployment(), proxy: { ...made.deployment.proxy, revokedWithinSeconds } };
  deps.proxy = proxyCodeWith(plugins, made.deployment);
  return made;
}

before(async () => {
  db = await openTestDatabase();
  const { privateKey: key, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signer = { privateKey: key, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } };
  upstream = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      reached.push({ method: request.method!, url: request.url!, headers: request.headers, body: Buffer.concat(chunks).toString() });
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
  forgetProxyGates();
  forgetKeys();
  reached = [];
  gates = pinnedGates();
  deps = testDeps(db.runtime, [ROOT]);
  calls = new Map();
  const vault = deps.vault as unknown as Record<string, unknown>;
  for (const name of ['access', 'useRoute', 'proxyItem', 'useNamed', 'useNamedMany', 'useMany', 'use'] as const) {
    const real = vault[name];
    if (typeof real !== 'function') continue;
    vault[name] = (...args: unknown[]) => {
      calls.set(name, (calls.get(name) ?? 0) + 1);
      return (real as (...given: unknown[]) => unknown).apply(deps.vault, args);
    };
  }
  runtime = makeRuntime();
  deps.signin = runtime.signin!;
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { OPENAI_API_KEY: OPENAI, OTHER_KEY: 'other-0123456789abcdef', REGION: { value: 'eu-west-3', plain: true } });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
});

/** A route saved in market/prod's Proxy tab: `name` to `path` under the fake upstream, its key in Authorization. */
function uiRoute(name: string, path: string, extra: Partial<Extract<ProxyDefinition, { kind: 'route' }>> = {}): ProxyDefinition {
  return {
    kind: 'route', name, upstream: `${upstreamAt}${path}`, inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' }],
    allow: [{ methods: ['GET'], path: '/v1/models/**' }, { methods: ['POST', 'PUT'], path: '/v1/**' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null, ...extra,
  };
}

/** A save in market/prod's Proxy tab, on the seal it shows now, by `who` (the Owner by default). */
async function save(items: Record<string, ProxyDefinition | null>, who = ROOT): Promise<void> {
  const as = clientFor(deps, who);
  const page = await as.proxy.get('market/prod');
  await as.proxy.save('market/prod', { seal: page.seal, items });
}

async function bind(policy: Record<string, unknown> = {}): Promise<string> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY as never, label: 'github', replaces: [], policy }, { dryRun: false });
  assert.ok('binding' in made);
  return made.binding.id;
}

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

type Session = { token: string; key: ProofKey };

async function session(): Promise<Session> {
  const key = await generateProofKey();
  const seconds = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${part({ iss: GITHUB, aud: `${ORIGIN}#jkt=${await thumbprint(key.jwk)}`, sub: 'repo:acme/api:ref:refs/heads/main', iat: seconds - 5, exp: seconds + 600, jti: randomUUID(), ...DEPLOY })}`;
  const jwt = `${input}.${signWith('sha256', Buffer.from(input), signer.privateKey).toString('base64url')}`;
  const url = `${ORIGIN}/api/auth/workload`;
  const made = await answer(new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', dpop: await createProof(key, { method: 'POST', url }) }, body: JSON.stringify({ service: MEMBER, proof: { oidc: jwt } }) }), runtime, ui, IP);
  const body = (await made.json()) as { token: string };
  assert.equal(made.status, 200, JSON.stringify(body));
  return { token: body.token, key };
}

type Sent = { status: number; body: Record<string, unknown> };

async function read(response: Response): Promise<Sent> {
  const text = await response.text();
  return { status: response.status, body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>) };
}

/** A request as the SDK signs it: method, URL, the headers set and the body's line (its digest, or `line`). */
async function use(held: Session, method: string, path: string, init: { headers?: Record<string, string>; body?: string | ReadableStream<Uint8Array>; line?: string } = {}): Promise<Sent> {
  const url = `${ORIGIN}${path}`;
  const headers = init.headers ?? {};
  const proof = await createProof(held.key, {
    method, url, token: held.token, nonce: await gates(MEMBER).nonce(),
    content: { headers, body: init.line ?? (await bodyDigest(typeof init.body === 'string' ? init.body : '')) },
  });
  const request = new Request(url, { method, headers: { ...headers, authorization: `DPoP ${held.token}`, dpop: proof }, ...(init.body === undefined ? {} : { body: init.body, duplex: 'half' }) } as RequestInit);
  return read((await pluginRoute(request, runtime, IP))!);
}

/** What the vault was asked since `from`, by method. */
function since(from: Map<string, number>): Record<string, number> {
  return Object.fromEntries([...calls].flatMap(([name, n]) => (n - (from.get(name) ?? 0) === 0 ? [] : [[name, n - (from.get(name) ?? 0)]])));
}

async function run(query: SQL): Promise<void> {
  await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}

test("a session's UI route: by its stable URL and its place's, sent by the decided item, its key injected, one vault call a use", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  await bind();
  const held = await session();
  let from = new Map(calls);
  const cold = await use(held, 'GET', '/use/openai/v1/models/gpt', { headers: { 'x-trace': 't-1' } });
  assert.equal(cold.status, 200, JSON.stringify(cold.body));
  assert.equal(reached.at(-1)!.url, '/openai/v1/models/gpt');
  assert.equal(reached.at(-1)!.headers.authorization, `Bearer ${OPENAI}`);
  assert.equal(reached.at(-1)!.headers['x-trace'], 't-1');
  assert.ok(!JSON.stringify(reached.at(-1)!.headers).includes(held.token), 'the session token goes nowhere');
  // Cold: the item for its counts, then the use, which decides the workload's standing too: no `access()`.
  assert.deepEqual(since(from), { proxyItem: 1, useRoute: 1 });
  from = new Map(calls);
  const warm = await use(held, 'POST', '/use/openai/v1/chat', { headers: { 'content-type': 'application/json' }, body: '{"q":1}' });
  assert.equal(warm.status, 200, JSON.stringify(warm.body));
  assert.deepEqual([reached.at(-1)!.method, reached.at(-1)!.url, reached.at(-1)!.body], ['POST', '/openai/v1/chat', '{"q":1}']);
  assert.deepEqual(since(from), { useRoute: 1 }, 'warm, cache off: one vault call');
  // The place's URL, as a client of several environments writes it: the same route, read the other way, its proof spent once.
  from = new Map(calls);
  const placed = await use(held, 'GET', '/use/market/prod/openai/v1/models/x');
  assert.equal(placed.status, 200, JSON.stringify(placed.body));
  assert.equal(reached.at(-1)!.url, '/openai/v1/models/x');
  assert.deepEqual(since(from), { useRoute: 1 });
  // The decided item's allow list: nothing sent.
  const before = reached.length;
  assert.equal((await use(held, 'DELETE', '/use/openai/v1/models/x')).status, 405);
  assert.equal((await use(held, 'GET', '/use/openai/files/x')).status, 403);
  // A name neither code nor the tab has: 404, after the proof.
  assert.equal((await use(held, 'GET', '/use/maps/v1/models/x')).status, 404);
  assert.equal(reached.length, before);
  // Code's name is code's, as ever.
  assert.equal((await use(held, 'GET', '/use/stripe/v1/balance')).status, 200);
  assert.equal(reached.at(-1)!.url, '/stripe/v1/balance');
});

test("a Cloudflare call's UI route is its binding's, at the one environment it reaches, and at its place's URL", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [], policy: {} }, { dryRun: false });
  for (const path of ['/use/openai/v1/models/a', '/use/market/prod/openai/v1/models/b']) {
    const sent = await read((await bindingRoute(new Request(`${ORIGIN}${path}`, { headers: { 'x-trace': 't-1' } }), runtime, MEMBER))!);
    assert.equal(sent.status, 200, `${path}: ${JSON.stringify(sent.body)}`);
    assert.equal(reached.at(-1)!.headers.authorization, `Bearer ${OPENAI}`);
    assert.equal(reached.at(-1)!.headers['x-trace'], 't-1');
  }
  assert.deepEqual(reached.map((one) => one.url), ['/openai/v1/models/a', '/openai/v1/models/b']);
});

test("past 1 MiB, a Cloudflare call's body streams through a UI route nothing of which signs its hash; a SigV4 route, or a session's proof, needs the hash declared (review r1)", ON_015, async () => {
  const s3: ProxyDefinition = { ...uiRoute('files', '/s3'), inject: [{ kind: 'sigv4', accessKeyId: '{OPENAI_API_KEY}', secretAccessKey: '{OTHER_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }] } as ProxyDefinition;
  await save({ openai: uiRoute('openai', '/openai'), files: s3 });
  await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [], policy: {} }, { dryRun: false });
  const bytes = 'b'.repeat(BODY_READ_WHOLE_BYTES + 1);
  const viaBinding = async (path: string) => read((await bindingRoute(new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-length': String(bytes.length) }, body: new Blob([bytes]).stream(), duplex: 'half' } as RequestInit), runtime, MEMBER))!);
  const streamed = await viaBinding('/use/openai/v1/files');
  assert.equal(streamed.status, 200, JSON.stringify(streamed.body));
  assert.deepEqual([reached.at(-1)!.body.length, reached.at(-1)!.headers['content-length'], reached.at(-1)!.headers.authorization], [bytes.length, String(bytes.length), `Bearer ${OPENAI}`]);
  // Through SigV4, whose signature needs the hash: refused, nothing sent.
  const before = reached.length;
  const unsigned = await viaBinding('/use/files/v1/bucket/a.bin');
  assert.equal(unsigned.status, 413, JSON.stringify(unsigned.body));
  assert.match(unsigned.body.message as string, /as files signs its hash; one that says its length and declares its SHA-256 streams/);
  // A session's proof signs the body's hash: past 1 MiB, it is declared or refused.
  await bind();
  const held = await session();
  const proven = await use(held, 'POST', '/use/openai/v1/files', { headers: { 'content-length': String(bytes.length) }, body: new Blob([bytes]).stream(), line: createHash('sha256').update(bytes).digest('hex') });
  assert.equal(proven.status, 413, JSON.stringify(proven.body));
  assert.equal(reached.length, before);
});

test("a UI route's limit is counted on a cold isolate before the gate, from the vault's item; a raised one refuses one request more at most", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai', { limit: { perMinute: 2, perDay: null } }) });
  await bind();
  const held = await session();
  for (let i = 0; i < 2; i++) assert.equal((await use(held, 'GET', `/use/openai/v1/models/${i}`)).status, 200);
  const past = await use(held, 'GET', '/use/openai/v1/models/2');
  assert.deepEqual([past.status, past.body.reason], [429, 'limit']);
  assert.equal(reached.length, 2);
  // Code's credential counts apart.
  assert.equal((await use(held, 'GET', '/use/stripe/v1/balance')).status, 200);
  // Raised: the copy said 2, so one more refusal at most, which asks the vault for the item; then counted on 10.
  await save({ openai: uiRoute('openai', '/openai', { limit: { perMinute: 10, perDay: null } }) });
  const statuses: number[] = [];
  for (let i = 0; i < 3; i++) statuses.push((await use(held, 'GET', `/use/openai/v1/models/r${i}`)).status);
  assert.ok(statuses.filter((status) => status === 429).length <= 1, statuses.join(','));
  assert.equal(statuses.at(-1), 200, statuses.join(','));
});

test("BoundToDefinition: kept values go where the item they were decided on says, as another session's use brings a newer copy", ON_015, async () => {
  runtime = makeRuntime(true);
  await save({ openai: uiRoute('openai', '/v7') });
  await bind();
  const a = await session();
  const b = await session();
  assert.equal((await use(a, 'GET', '/use/openai/v1/models/1')).status, 200);
  await save({ openai: uiRoute('openai', '/v8') });
  // B's use brings version 8, and this isolate's copy with it.
  assert.equal((await use(b, 'GET', '/use/openai/v1/models/2')).status, 200);
  // A's values, decided on version 7, are sent by version 7's item, never the copy's.
  const from = new Map(calls);
  assert.equal((await use(a, 'GET', '/use/openai/v1/models/3')).status, 200);
  assert.deepEqual(since(from), {}, "A's kept values: no vault call");
  assert.deepEqual(reached.map((one) => one.url), ['/v7/v1/models/1', '/v8/v1/models/2', '/v7/v1/models/3']);
});

test("kept values answer to their own item's allow list alone, not to a newer copy another session's use brought", ON_015, async () => {
  // Version 7 allows /v1/**, version 8 /v2/**, both /health/**. A keeps 7's values; B's use brings 8's copy. A's requests are
  // held to 7 alone: /v1 goes, /v2 is refused, never both refused nor both let through to the kept check (review r1 of #477).
  runtime = makeRuntime(true);
  const allow = (path: string) => [{ methods: ['GET' as const], path: '/health/**' }, { methods: ['GET' as const], path }];
  await save({ openai: uiRoute('openai', '/openai', { allow: allow('/v1/**') }) });
  await bind();
  const a = await session();
  const b = await session();
  assert.equal((await use(a, 'GET', '/use/openai/v1/models/1')).status, 200);
  await save({ openai: uiRoute('openai', '/openai', { allow: allow('/v2/**') }) });
  const health = await use(b, 'GET', '/use/openai/health/live');
  assert.equal(health.status, 200, JSON.stringify(health.body));
  const kept = await use(a, 'GET', '/use/openai/v1/models/2');
  assert.equal(kept.status, 200, JSON.stringify(kept.body));
  assert.equal((await use(a, 'GET', '/use/openai/v2/models/3')).status, 403);
  // B, deciding on 8, is held to 8.
  assert.equal((await use(b, 'GET', '/use/openai/v2/models/4')).status, 200);
  assert.equal((await use(b, 'GET', '/use/openai/v1/models/5')).status, 403);
  assert.deepEqual(reached.map((one) => one.url), ['/openai/v1/models/1', '/openai/health/live', '/openai/v1/models/2', '/openai/v2/models/4']);
});

test('the session revoked stops the next request whatever the value cache holds', ON_015, async () => {
  runtime = makeRuntime(true);
  await save({ openai: uiRoute('openai', '/openai') });
  await bind();
  const held = await session();
  assert.equal((await use(held, 'GET', '/use/openai/v1/models/1')).status, 200);
  await db.owner.update(credentials).set({ revokedAt: new Date() }).where(eq(credentials.tokenHash, hashToken(held.token)));
  assert.equal((await use(held, 'GET', '/use/openai/v1/models/2')).status, 401);
  assert.equal(reached.length, 1);
});

test("an inject-kind edit between the copy and the answer: a body the decided item takes otherwise is 503 moved, nothing sent", ON_015, async () => {
  const s3: ProxyDefinition = { ...uiRoute('files', '/s3'), inject: [{ kind: 'sigv4', accessKeyId: '{OPENAI_API_KEY}', secretAccessKey: '{OTHER_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }] } as ProxyDefinition;
  await save({ files: s3 });
  await bind();
  const held = await session();
  const bytes = 'hello s3';
  const hash = createHash('sha256').update(bytes).digest('hex');
  const put = () => use(held, 'PUT', '/use/files/v1/bucket/a.txt', { headers: { 'x-amz-content-sha256': hash, 'content-length': String(bytes.length) }, body: new Blob([bytes]).stream(), line: hash });
  const first = await put();
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(reached.at(-1)!.body, bytes);
  // Now a header route: its body is bound by its bytes, which no x-amz-content-sha256 says.
  await save({ files: uiRoute('files', '/s3') });
  const before = reached.length;
  const moved = await put();
  assert.deepEqual([moved.status, moved.body.reason], [503, 'moved']);
  assert.equal(reached.length, before);
});

test('a JSON route reached by a body that streams under its Content-Digest is read whole, its key in the field, the digest still checked', ON_015, async () => {
  await save({ hooks: { ...uiRoute('hooks', '/hooks'), inject: [{ kind: 'json', name: 'api_key', template: '{OPENAI_API_KEY}' }] } as ProxyDefinition });
  await bind();
  const held = await session();
  const body = '{"api_key":"placeholder","event":"x"}';
  const line = createHash('sha256').update(body).digest('hex');
  const digest = contentDigest(line);
  const sent = await use(held, 'POST', '/use/hooks/v1/events', { headers: { 'content-type': 'application/json', 'content-digest': digest, 'content-length': String(body.length) }, body: new Blob([body]).stream(), line });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.deepEqual(JSON.parse(reached.at(-1)!.body), { api_key: OPENAI, event: 'x' });
  // Bytes other than the digest the proof bound: refused, nothing sent.
  const other = '{"api_key":"placeholder","event":"y"}';
  const refused = await use(held, 'POST', '/use/hooks/v1/events', { headers: { 'content-type': 'application/json', 'content-digest': digest, 'content-length': String(other.length) }, body: new Blob([other]).stream(), line });
  assert.equal(refused.status, 400, JSON.stringify(refused.body));
  assert.equal(reached.length, 1);
});

test('EditorStillHolds: a route whose editor no longer reads its key answers the workload 403 route_not_cleared, nothing sent', ON_015, async () => {
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${LIN}`);
  await root.roles.set('router', { name: 'Router', description: 'routes keys', permissions: ['secret.read', 'secret.use', 'proxy.edit'], protected: ['secret.use'] });
  await root.access.set(`user:${LIN}`, { market: 'router' });
  await save({ openai: uiRoute('openai', '/lin') }, LIN);
  await bind();
  const held = await session();
  assert.equal((await use(held, 'GET', '/use/openai/v1/models/1')).status, 200);
  await root.access.set(`user:${LIN}`, { market: 'contributor' });
  const stopped = await use(held, 'GET', '/use/openai/v1/models/2');
  assert.deepEqual([stopped.status, stopped.body.reason], [403, 'route_not_cleared']);
  assert.equal(reached.length, 1);
});

test("a workload's plan names its environment's UI routes, giving values only as it reads them; one forged item answers 503", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  await bind();
  const held = await session();
  const plan = await use(held, 'GET', '/use/market/prod');
  assert.equal(plan.status, 200, JSON.stringify(plan.body));
  assert.deepEqual([...(plan.body.credentials as string[])].sort(), ['openai', 'stripe']);
  assert.deepEqual(plan.body.values, { REGION: 'eu-west-3' }, 'its plain value alone: it uses the others');
  await run(sql`UPDATE proxy_definitions SET items = jsonb_set(items, '{openai,savedAt}', '1')`);
  const forged = await use(held, 'GET', '/use/market/prod');
  assert.equal(forged.status, 503, JSON.stringify(forged.body));
  assert.ok(!JSON.stringify(forged.body).includes(OPENAI));
  // And its use: no value of a forged route, ever.
  const used = await use(held, 'GET', '/use/openai/v1/models/1');
  assert.equal(used.status, 503, JSON.stringify(used.body));
  assert.equal(reached.length, 0);
});

// For `Vault` in the import list: the methods counted above are the vault's own.
void (null as unknown as Vault);

const NO_LIMIT = { perMinute: null, perDay: null };
const HOOK = 'whsec-prod-0123456789abcdef';

/** `text` with its underscores percent-encoded `layers` times over: `%5F`, `%255F`, `%25255F`… */
const deeply = (text: string, layers: number) => text.replaceAll('_', `%${'25'.repeat(layers - 1)}5F`);
const AWS_ID = 'AKIAREALPROD00000001';
const AWS_SECRET = 'real/prod+secret/key0123456789ABCDEFGHI';

/** `POST <path>` with `body` as JSON, the proof signing it: a sign, verify or presign. */
const compute = (held: Session, body: unknown, path = '/use') => use(held, 'POST', path, { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test("a workload signs, verifies and presigns with items saved in the UI: the signer's limit counted before the gate from the vault's item, one use a sign (C2b2)", ON_015, async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  await clientFor(deps, ROOT).secrets.set('market/prod', { HOOK_SECRET: HOOK, DFNS_PEM: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), AWS_ACCESS_KEY_ID: AWS_ID, AWS_SECRET_ACCESS_KEY: AWS_SECRET });
  await save({
    hooks: { kind: 'signer', name: 'hooks', signer: { kind: 'hmac', key: 'HOOK_SECRET', encoding: 'hex', prefix: 'sha256=', maxBytes: null }, limit: { perMinute: 3, perDay: null } },
    inbound: { kind: 'verifier', name: 'inbound', hmac: { key: 'HOOK_SECRET', encoding: 'base64', prefix: '', maxBytes: null }, limit: NO_LIMIT },
    dfns: { kind: 'signer', name: 'dfns', signer: { kind: 'private-key', key: 'DFNS_PEM' }, limit: NO_LIMIT },
    s3: {
      kind: 'route', name: 's3', upstream: 'https://s3.eu-west-3.example.test/files',
      inject: [{ kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }],
      allow: [{ methods: ['GET'], path: '/bucket/**' }], limit: NO_LIMIT, placeholder: null, egress: null,
    },
  });
  await bind();
  const held = await session();
  const message = Buffer.from('transfer 10').toString('base64url');
  const expected = `sha256=${createHmac('sha256', HOOK).update('transfer 10').digest('hex')}`;
  // Cold: the item for its counts, before the gate, then the use; warm, cache off: the use alone.
  let from = new Map(calls);
  const cold = await compute(held, { sign: { credential: 'hooks', message } });
  assert.deepEqual([cold.status, cold.body.signature], [200, expected], JSON.stringify(cold.body));
  assert.deepEqual(since(from), { proxyItem: 1, useRoute: 1 });
  from = new Map(calls);
  // The place's URL names the environment, as a workload of several writes it.
  const warm = await compute(held, { sign: { credential: 'hooks', message } }, '/use/market/prod');
  assert.deepEqual([warm.status, warm.body.signature], [200, expected], JSON.stringify(warm.body));
  assert.deepEqual(since(from), { useRoute: 1 });
  // Its limit, 3 a minute, the item's: the third use, then 429, no use decided; the item asked again, as a refusal by a
  // kept copy's limit does (an Owner may have raised it).
  assert.equal((await compute(held, { verify: { credential: 'hooks', message, signature: expected } })).body.valid, true);
  from = new Map(calls);
  const past = await compute(held, { sign: { credential: 'hooks', message } });
  assert.deepEqual([past.status, past.body.reason], [429, 'limit']);
  assert.deepEqual(since(from), { proxyItem: 1 });
  // A verifier, counted apart.
  const checked = await compute(held, { verify: { credential: 'inbound', message, signature: createHmac('sha256', HOOK).update('transfer 10').digest('base64') } });
  assert.deepEqual([checked.status, checked.body.valid], [200, true], JSON.stringify(checked.body));
  // A private key's: a use each, never kept.
  from = new Map(calls);
  const signed = await compute(held, { sign: { credential: 'dfns', message } });
  assert.equal(signed.status, 200, JSON.stringify(signed.body));
  assert.ok(verifyWith(null, Buffer.from('transfer 10'), publicKey, Buffer.from(signed.body.signature as string, 'base64url')));
  assert.deepEqual(since(from), { proxyItem: 1, useRoute: 1 });
  // A presign, by the decided route: its upstream, its allow list, the real pair, the session token in none of it.
  const url = await compute(held, { presign: { credential: 's3', path: '/bucket/report.csv', expiresIn: 60 } });
  assert.equal(url.status, 200, JSON.stringify(url.body));
  const made = new URL(url.body.url as string);
  assert.equal(`${made.origin}${made.pathname}`, 'https://s3.eu-west-3.example.test/files/bucket/report.csv');
  assert.match(made.searchParams.get('X-Amz-Credential')!, new RegExp(`^${AWS_ID}/`));
  assert.ok(!made.href.includes(AWS_SECRET) && !made.href.includes(held.token));
  assert.equal((await compute(held, { presign: { credential: 's3', path: '/other/report.csv' } })).status, 403);
  // Nor in any URL it asks for: its token in the query, or the path, as it is, escaped, or escaped twice, is 400, nothing signed (review r1 of #480).
  for (const presign of [
    { path: '/bucket/report.csv', query: { trace: held.token } },
    { path: `/bucket/${held.token}` },
    { path: `/bucket/${held.token.replaceAll('_', '%5F')}` },
    { path: `/bucket/${held.token.replaceAll('_', '%255F')}` },
    // Seven times over in the query, which the URL encodes an eighth: the last reading checked shows it.
    { path: '/bucket/report.csv', query: { trace: deeply(held.token, 7) } },
  ]) {
    const carried = await compute(held, { presign: { credential: 's3', expiresIn: 60, ...presign } });
    assert.deepEqual([carried.status, carried.body.message], [400, 'the session token goes in no presigned URL'], JSON.stringify(presign));
  }
  // Eight times over, a ninth by the URL: past what is checked, refused as such, never signed (review r2 of #480).
  const deep = await compute(held, { presign: { credential: 's3', expiresIn: 60, path: '/bucket/report.csv', query: { trace: deeply(held.token, 8) } } });
  assert.deepEqual([deep.status, deep.body.message], [400, 'the URL is encoded too many times over to check'], JSON.stringify(deep.body));
  assert.equal((await compute(held, { presign: { credential: 's3', expiresIn: 60, path: `/bucket/${deeply(held.token, 9)}` } })).status, 400);
  // Kinds: a verifier signs nothing; a name nothing defines is 404, after the proof.
  assert.equal((await compute(held, { sign: { credential: 'inbound', message } })).status, 404);
  assert.equal((await compute(held, { sign: { credential: 'nothing', message } })).status, 404);
  assert.equal(reached.length, 0, 'nothing went upstream');
});

test("an Owner saves another kind under a kept HMAC signer's name: the kept signs still count against the item's limit (review r2 of #480)", ON_015, async () => {
  // A keeps an HMAC signer's values, 3 a minute. The name becomes a verifier with the same limit, and B's verify brings
  // its copy to this isolate. A's kept values still sign, for R, by the signer they were decided on: each
  // sign is counted against the limit the item at the name has now, never let through uncounted for the verifier's kind.
  runtime = makeRuntime(true);
  await clientFor(deps, ROOT).secrets.set('market/prod', { HOOK_SECRET: HOOK });
  const limit = { perMinute: 3, perDay: null };
  await save({ hooks: { kind: 'signer', name: 'hooks', signer: { kind: 'hmac', key: 'HOOK_SECRET', encoding: 'hex', prefix: '', maxBytes: null }, limit } });
  await bind();
  const a = await session();
  const b = await session();
  const message = Buffer.from('transfer 10').toString('base64url');
  const expected = createHmac('sha256', HOOK).update('transfer 10').digest('hex');
  assert.deepEqual((await compute(a, { sign: { credential: 'hooks', message } })).body.signature, expected);
  await save({ hooks: { kind: 'verifier', name: 'hooks', hmac: { key: 'HOOK_SECRET', encoding: 'hex', prefix: '', maxBytes: null }, limit } });
  const checked = await compute(b, { verify: { credential: 'hooks', message, signature: expected } });
  assert.deepEqual([checked.status, checked.body.valid], [200, true], JSON.stringify(checked.body));
  const kept = await compute(a, { sign: { credential: 'hooks', message } });
  assert.deepEqual([kept.status, kept.body.signature], [200, expected], 'A signs by its kept signer');
  const past = await compute(a, { sign: { credential: 'hooks', message } });
  assert.deepEqual([past.status, past.body.reason], [429, 'limit'], JSON.stringify(past.body));
});

test("a Cloudflare call signs with a UI signer as its binding, at the one environment it reaches (C2b2)", ON_015, async () => {
  await clientFor(deps, ROOT).secrets.set('market/prod', { HOOK_SECRET: HOOK });
  await save({ hooks: { kind: 'signer', name: 'hooks', signer: { kind: 'hmac', key: 'HOOK_SECRET', encoding: 'hex', prefix: '', maxBytes: null }, limit: NO_LIMIT } });
  await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [], policy: {} }, { dryRun: false });
  for (const path of ['/use', '/use/market/prod']) {
    const request = new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sign: { credential: 'hooks', message: Buffer.from('hi').toString('base64url') } }) });
    const sent = await read((await bindingRoute(request, runtime, MEMBER))!);
    assert.deepEqual([sent.status, sent.body.signature], [200, createHmac('sha256', HOOK).update('hi').digest('hex')], `${path}: ${JSON.stringify(sent.body)}`);
  }
});

test("a session's UI route with a path rule: the segment its SDK wrote, whatever it holds, gets the value; one vault call warm", ON_015, async () => {
  // Telegram's shape: the token in `/bot<token>/…`, here OPENAI_API_KEY's value, which goes as it is.
  await save({ telegram: uiRoute('telegram', '/tg', { inject: [{ kind: 'path', template: 'bot{OPENAI_API_KEY}' }], allow: [{ methods: ['POST'], path: '/*/sendMessage' }, { methods: ['GET'], path: '/file/*/**' }] }) });
  await bind();
  const held = await session();
  // As `new Bot('coffre', …)` sends it: the stand-in an SDK wanted, replaced.
  assert.equal((await use(held, 'POST', '/use/telegram/botcoffre/sendMessage', { headers: { 'content-type': 'application/json' }, body: '{"text":"hi"}' })).status, 200);
  assert.equal(reached.at(-1)!.url, `/tg/bot${OPENAI}/sendMessage`);
  const from = new Map(calls);
  const file = await use(held, 'GET', '/use/market/prod/telegram/file/bot0:coffre/photos/file_0.jpg');
  assert.equal(file.status, 200, JSON.stringify(file.body));
  assert.equal(reached.at(-1)!.url, `/tg/file/bot${OPENAI}/photos/file_0.jpg`);
  assert.deepEqual(since(from), { useRoute: 1 }, 'warm, cache off: one vault call');
  // The allow list reads the path as sent, and a path with no such segment goes nowhere.
  const before = reached.length;
  assert.equal((await use(held, 'GET', '/use/telegram/botcoffre/sendMessage')).status, 405);
  assert.equal((await use(held, 'GET', '/use/telegram/file/x/y')).status, 400);
  assert.equal(reached.length, before);
});

test("a session's tunnel to a database saved in the Proxy tab: dialled by the decided item, ended within a recheck of an edit to it, and not of another's (C2b3)", { ...ON_015, timeout: 30_000 }, async () => {
  runtime = makeRuntime(false, 2);
  await clientFor(deps, ROOT).secrets.set('market/prod', { DATABASE_URL: 'postgres://app:pw@127.0.0.1:5432/app?sslmode=disable' });
  const database = (hosts: string[]): ProxyDefinition => ({ kind: 'tunnel', name: 'db', key: 'DATABASE_URL', hosts, network: null });
  await save({ db: database(['127.0.0.1']) });
  await bind();
  const held = await session();
  // The plan lists it as code's tunnels are.
  const plan = await use(held, 'GET', '/use/market/prod');
  assert.deepEqual(plan.body.tunnels, { db: { key: 'DATABASE_URL', url: 'wss://secrets.acme.example/use/market/prod/db' } });
  const server = createServer((_, response) => response.writeHead(404).end());
  server.on('upgrade', (request, socket, head) => void upgrade(runtime, request, socket, head));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  try {
    const open = async () => {
      const url = `${ORIGIN}/use/market/prod/db`;
      const proof = await createProof(held.key, { method: 'GET', url, token: held.token, nonce: await gates(MEMBER).nonce() });
      const ws = new WebSocket(`ws://127.0.0.1:${(server.address() as AddressInfo).port}/use/market/prod/db`, { headers: { authorization: `DPoP ${held.token}`, dpop: proof } });
      let nonce: string | null = null;
      const opened = await Promise.race([once(ws, 'open').then(() => true), once(ws, 'unexpected-response').then(([, response]) => {
        nonce = ((response as IncomingMessage).headers['dpop-nonce'] as string | undefined) ?? null;
        return (response as IncomingMessage).statusCode;
      })]);
      return { ws, opened, nonce };
    };
    const first = await open();
    assert.equal(first.opened, true);
    const closed = once(first.ws, 'close').then(() => Date.now());
    // Another item of the environment saved, and the rechecks of three bounds: it stands.
    await save({ openai: uiRoute('openai', '/openai') });
    await sleep(3000);
    assert.equal(first.ws.readyState, WebSocket.OPEN, 'still open: another item changed, not its own');
    // Its own item saved anew: ended within R, a recheck and its deadline.
    await save({ db: database(['db.acme.example']) });
    const editedAt = Date.now();
    const at = await closed;
    assert.ok(at - editedAt <= 2000 + 300, `ended ${at - editedAt} ms after the edit`);
    // The reconnect dials by the new item, which reaches no 127.0.0.1: refused, with the nonce its next proof signs (review r1 of #485).
    const again = await open();
    assert.equal(again.opened, 403);
    assert.equal(again.nonce, await gates(MEMBER).nonce(), "the refusal carries the gate's nonce");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    // A recheck still being written would meet the next test's reset: let it land first.
    await sleep(1000);
  }
});

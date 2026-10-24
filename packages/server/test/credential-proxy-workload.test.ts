// The credential proxy's workload caller (docs/design/workload-access.md,
// sections 5.1, 7.1 and 8): a key-bound session uses credentials through
// coffre, its proof signing the request whole. Only the headers it signs go
// upstream; a query, header or body changed on the way is refused; a
// streamed SigV4 upload is bound by its declared hash, and an unsigned one
// only where the binding says so; a revocation or a freeze stops the next
// request whatever the value cache holds; limits answer 429 and alert once
// a window; a narrowed session is held to its constraints on the URL sent;
// a tunnel ends within a recheck of a freeze. Both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { bodyDigest, createProof, generateProofKey, thumbprint, UNSIGNED_BODY, type ProofKey } from '@coffre/client/dpop';
import { github, hashToken, signin, type WorkloadAlert } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { eq } from 'drizzle-orm';
import { WebSocket } from 'ws';

import { allowed, audited } from '../src/api/context.ts';
import { resolveConfig } from '../src/config.ts';
import { insertSession } from '../src/db/workloads.ts';
import { processGates, type Gates } from '../src/gate.ts';
import { upgrade } from '../src/node-sockets.ts';
import { bindingRoute, checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header, postgres, privateKey, sigv4 } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, environments } from './db/tables.ts';
import { answer, type Pages } from './start-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
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
const STRIPE_KEY = 'sk_live_0123456789abcdefghij';
const AWS = { AWS_ACCESS_KEY_ID: 'AKIAREAL0123456789AB', AWS_SECRET_ACCESS_KEY: 'real/secret/0123456789abcdefghijklmnopqr' };
const SIGNING_KEY = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const ui = {} as Pages;
let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let gates: Gates;
let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };
let vaultCalls: number;
let alerts: WorkloadAlert[];
let background: Promise<unknown>[];

/** The upstream: what reached it, each request's method, URL, headers and body's SHA-256. */
let upstream: Server;
let upstreamAt: string;
let reached: { method: string; url: string; headers: IncomingMessage['headers']; sha256: string; length: number }[];

const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${GITHUB}/.well-known/openid-configuration`) return { issuer: GITHUB, jwks_uri: `${GITHUB}/keys` };
    if (url.href === `${GITHUB}/keys`) return { keys: [signer.jwk] };
    throw new FetchRefused(url, 'answered 404');
  },
};

function proxy(options: { recheckSeconds?: number } = {}) {
  return credentialProxy({
    credentials: {
      stripe: { upstream: `${upstreamAt}/stripe`, inject: header('authorization', `Bearer {STRIPE_KEY}`) },
      // The same key, counted: three a minute for this service, and none for any other.
      metered: { upstream: `${upstreamAt}/stripe`, inject: header('authorization', `Bearer {STRIPE_KEY}`), limit: (service) => (service === MEMBER ? { perMinute: 3 } : undefined) },
      // A rule that sends its key under the DPoP scheme: a handle's app sends its handle there.
      dpopped: { upstream: `${upstreamAt}/dpopped`, inject: header('authorization', 'DPoP {STRIPE_KEY}') },
      s3: { upstream: `${upstreamAt}/s3`, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
    },
    signers: { 'dfns-key': privateKey('SIGNING_KEY') },
    tunnels: { db: postgres('DATABASE_URL') },
    insecureUpstreams: true,
    ...(options.recheckSeconds === undefined ? {} : { recheckSeconds: options.recheckSeconds }),
  });
}

function makeRuntime(options: { recheckSeconds?: number; plugins?: ReturnType<typeof checkPlugins> } = {}): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }), alert: (alert) => void alerts.push(alert) } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: options.plugins ?? checkPlugins([proxy(options)]),
  });
  return createRuntime(config, deps.db, deps.vault, transport, (promise) => void background.push(promise), gates);
}

before(async () => {
  db = await openTestDatabase();
  const { privateKey: key, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signer = { privateKey: key, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } };
  upstream = createServer((request, response) => {
    const hash = createHash('sha256');
    let length = 0;
    request.on('data', (chunk: Buffer) => {
      hash.update(chunk);
      length += chunk.length;
    });
    request.on('end', () => {
      reached.push({ method: request.method!, url: request.url!, headers: request.headers, sha256: hash.digest('hex'), length });
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true }));
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
  alerts = [];
  background = [];
  gates = processGates();
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
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { STRIPE_KEY, ...AWS, SIGNING_KEY, DATABASE_URL: 'postgres://app:pw@127.0.0.1:5999/app?sslmode=disable', REGION: { value: 'eu-west-3', plain: true } });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
});

/** The service's GitHub binding, made by the Owner, with `policy`. */
async function bind(policy: Record<string, unknown> = {}): Promise<string> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: DEPLOY as never, label: 'github', replaces: [], policy }, { dryRun: false });
  assert.ok('binding' in made);
  return made.binding.id;
}

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

type Session = { token: string; key: ProofKey };

/** A session of the service, from a GitHub run's token whose audience names its key. */
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

type Sent = { status: number; body: Record<string, unknown>; headers: Headers };

async function read(response: Response): Promise<Sent> {
  const text = await response.text();
  return { status: response.status, body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>), headers: response.headers };
}

/**
 * A request as the SDK sends it: its proof signs the method, URL, the
 * headers set and the body (`signed` in place of what is sent, for a
 * request changed on the way), and `added` headers join it afterwards, as
 * a library or a proxy on the way adds them.
 */
async function use(held: Session, method: string, path: string, init: { headers?: Record<string, string>; body?: string; signed?: { url?: string; headers?: Record<string, string>; body?: string; line?: string }; added?: Record<string, string> } = {}): Promise<Sent> {
  const url = `${ORIGIN}${path}`;
  const headers = init.headers ?? {};
  const proof = await createProof(held.key, {
    method,
    url: init.signed?.url ?? url,
    token: held.token,
    nonce: await gates(MEMBER).nonce(),
    content: { headers: init.signed?.headers ?? headers, body: init.signed?.line ?? (await bodyDigest(init.signed?.body ?? init.body ?? '')) },
  });
  const request = new Request(url, { method, headers: { ...headers, ...init.added, authorization: `DPoP ${held.token}`, dpop: proof }, ...(init.body === undefined ? {} : { body: init.body }) });
  return read((await pluginRoute(request, runtime, IP))!);
}

async function freeze(target: string, action: 'workload.freeze' | 'workload.unfreeze' = 'workload.freeze') {
  const ctx = { caller: { principal: { type: 'user', id: ROOT } }, requestId: randomUUID(), sourceIp: null } as never;
  await audited({ db: deps.db, chainKey: deps.chainKey }, async (_tx, log) => {
    log.push(allowed(ctx, action, { metadata: { target } }));
  });
}

async function prodId(): Promise<string> {
  return (await db.owner.select().from(environments).where(eq(environments.slug, 'prod')))[0]!.id;
}

async function entries(action: string) {
  const rows = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, action));
  return rows.map((row) => JSON.parse(row.metadata) as Record<string, unknown>);
}

test('only the headers the proof signs go upstream, with the real key in place of none; the session token goes nowhere', async () => {
  await bind();
  const held = await session();
  const sent = await use(held, 'POST', '/use/stripe/v1/charges?expand[]=balance', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'idempotency-key': 'k-1' },
    body: 'amount=2000&currency=eur',
    added: { 'x-injected': 'by a proxy on the way', via: '1.1 middlebox' },
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(sent.headers.get('dpop-nonce'), await gates(MEMBER).nonce(), 'the answer carries the gate\'s nonce');
  const [one] = reached;
  assert.equal(one!.url, '/stripe/v1/charges?expand[]=balance');
  assert.equal(one!.headers.authorization, `Bearer ${STRIPE_KEY}`);
  assert.equal(one!.headers['idempotency-key'], 'k-1');
  assert.equal(one!.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(one!.headers['x-injected'], undefined, 'a header outside hdr is not forwarded');
  assert.equal(one!.headers.via, undefined);
  assert.equal(one!.headers.dpop, undefined);
  assert.equal(one!.sha256, createHash('sha256').update('amount=2000&currency=eur').digest('hex'));
  // The named environment's URL reaches the same credential; a path that names no environment is refused, once the proof holds.
  assert.equal((await use(held, 'GET', '/use/market/prod/stripe/v1/balance')).status, 200);
  const nowhere = await use(held, 'GET', '/use/market/staging/stripe/v1/balance');
  assert.equal(nowhere.status, 404, JSON.stringify(nowhere.body));
  // The token in what goes upstream, signed by the app itself, is refused: it goes no further than coffre.
  const leaked = await use(held, 'POST', '/use/stripe/v1/notes', { headers: { 'x-note': held.token }, body: '' });
  assert.equal(leaked.status, 400, JSON.stringify(leaked.body));
  // A handle sent under the DPoP scheme, as a rule that takes `DPoP {KEY}` has its app send it, is a handle's request: the proxy's own refusal, no session's.
  const handled = await read((await pluginRoute(new Request(`${ORIGIN}/use/dpopped/v1/x`, { headers: { authorization: `DPoP coffre_use_${'h'.repeat(43)}` } }), runtime, IP))!);
  assert.equal(handled.status, 401);
  assert.equal(handled.headers.get('www-authenticate'), null, JSON.stringify(handled.body));
  assert.match(leaked.body.message as string, /session token/);
  assert.equal(reached.length, 2);
});

test('a query, a header or a body changed on the way is refused, and nothing reaches the upstream', async () => {
  await bind();
  const held = await session();
  const base = { headers: { 'content-type': 'application/json', 'idempotency-key': 'k-1' }, body: '{"amount":2000}' };
  const query = await use(held, 'POST', '/use/stripe/v1/charges?amount=9000', { ...base, signed: { url: `${ORIGIN}/use/stripe/v1/charges?amount=2000` } });
  assert.deepEqual([query.status, query.body.reason], [401, 'req']);
  const headers = await use(held, 'POST', '/use/stripe/v1/charges', { ...base, headers: { ...base.headers, 'idempotency-key': 'k-2' }, signed: { headers: base.headers } });
  assert.deepEqual([headers.status, headers.body.reason], [401, 'req']);
  const body = await use(held, 'POST', '/use/stripe/v1/charges', { ...base, body: '{"amount":9000}', signed: { body: base.body } });
  assert.deepEqual([body.status, body.body.reason], [401, 'req']);
  // Two objects to S3 under one htu: the path as sent is signed too.
  const path = await use(held, 'GET', '/use/s3/bucket//a', { signed: { url: `${ORIGIN}/use/s3/bucket/a` } });
  assert.deepEqual([path.status, path.body.reason], [401, 'req']);
  assert.equal(reached.length, 0);
  assert.equal((await use(held, 'POST', '/use/stripe/v1/charges', base)).status, 200);
});

test('a streamed SigV4 upload is bound by the payload hash it declares; UNSIGNED-PAYLOAD only where the binding says unsignedUploads', async () => {
  const strict = await bind();
  const held = await session();
  const bytes = new Uint8Array(64 * 1024).fill(7);
  const declared = createHash('sha256').update(bytes).digest('hex');
  const upload = async (who: Session, hash: string, signedBody: string) => {
    const url = `${ORIGIN}/use/s3/bucket/object`;
    const headers = { 'x-amz-content-sha256': hash, 'content-type': 'application/octet-stream' };
    const proof = await createProof(who.key, { method: 'PUT', url, token: who.token, nonce: await gates(MEMBER).nonce(), content: { headers, body: signedBody } });
    const request = new Request(url, { method: 'PUT', headers: { ...headers, 'content-length': String(bytes.length), authorization: `DPoP ${who.token}`, dpop: proof }, body: new Blob([bytes]).stream(), duplex: 'half' } as RequestInit);
    return read((await pluginRoute(request, runtime, IP))!);
  };
  // Its proof signs the declared hash, which the upstream checks against the bytes, signed again with the real key.
  const sent = await upload(held, declared, declared);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const [put] = reached;
  assert.equal(put!.headers['x-amz-content-sha256'], declared);
  assert.match(put!.headers.authorization as string, new RegExp(`^AWS4-HMAC-SHA256 Credential=${AWS.AWS_ACCESS_KEY_ID}/`));
  assert.equal(put!.sha256, declared);
  // Another hash than the one signed: refused, nothing sent.
  const other = createHash('sha256').update('another object').digest('hex');
  assert.deepEqual([(await upload(held, other, declared)).body.reason], ['req']);
  // An unsigned upload binds no body: refused unless the binding says so.
  const unsigned = await upload(held, 'UNSIGNED-PAYLOAD', UNSIGNED_BODY);
  assert.deepEqual([unsigned.status, unsigned.body.reason], [403, 'unsigned_upload']);
  assert.equal(reached.length, 1);
  // A request with no body binds its empty body, whatever its header says: a GET needs no unsignedUploads.
  const get = await use(held, 'GET', '/use/s3/bucket/object', { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } });
  assert.equal(get.status, 200, JSON.stringify(get.body));
  // A buffered body with its hash declared signs that hash, as a streamed one does; an unsigned buffered one is unsigned too.
  const small = 'a small object';
  const hash = createHash('sha256').update(small).digest('hex');
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/small', { headers: { 'x-amz-content-sha256': hash }, body: small, signed: { body: '' } })).body.reason, 'req');
  const buffered = await read((await pluginRoute(new Request(`${ORIGIN}/use/s3/bucket/small`, { method: 'PUT', headers: { 'x-amz-content-sha256': hash, authorization: `DPoP ${held.token}`, dpop: await createProof(held.key, { method: 'PUT', url: `${ORIGIN}/use/s3/bucket/small`, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: { 'x-amz-content-sha256': hash }, body: hash } }) }, body: small }), runtime, IP))!);
  assert.equal(buffered.status, 200, JSON.stringify(buffered.body));
  assert.equal(reached.at(-1)!.sha256, hash);
  assert.equal(reached.length, 3);
  // A copier adds the hash of the signed body to a buffered request, with other bytes: the bytes are not that hash.
  const good = 'the body the app signed';
  const evil = 'the bytes a copier sent';
  const goodHash = createHash('sha256').update(good).digest('hex');
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/swapped', { body: evil, signed: { body: good }, added: { 'x-amz-content-sha256': goodHash } })).status, 400);
  // Nor may it add the header to choose the line, streamed or not: the proof must sign the header that does.
  const evilHash = createHash('sha256').update(evil).digest('hex');
  const chosen = await use(held, 'PUT', '/use/s3/bucket/swapped', { body: evil, signed: { line: evilHash }, added: { 'x-amz-content-sha256': evilHash } });
  assert.equal(chosen.status, 400, JSON.stringify(chosen.body));
  assert.match(chosen.body.message as string, /name it in hdr/);
  // Signed, the header and the bytes it declares go through.
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/declared', { headers: { 'x-amz-content-sha256': goodHash }, body: good, signed: { line: goodHash } })).status, 200);
  // An empty body is no body, whatever its header says, on every platform.
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/empty', { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: '' })).status, 200);
  assert.equal(reached.length, 5);
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, strict);
  await bind({ unsignedUploads: true });
  const loose = await session();
  const taken = await upload(loose, 'UNSIGNED-PAYLOAD', UNSIGNED_BODY);
  assert.equal(taken.status, 200, JSON.stringify(taken.body));
  assert.equal(reached.at(-1)!.headers['x-amz-content-sha256'], 'UNSIGNED-PAYLOAD');
});

test('a revocation or a freeze stops the next request, though the values are warm in the cache', async () => {
  await bind();
  const held = await session();
  const charge = () => use(held, 'POST', '/use/stripe/v1/charges', { body: 'amount=1' });
  assert.equal((await charge()).status, 200);
  const cold = vaultCalls;
  assert.equal((await charge()).status, 200);
  assert.equal(vaultCalls, cold, 'warm: the values come from the cache, no vault call');
  // A freeze of the credential, of the session, of the instance: each refuses the very next request.
  for (const target of [`credential:${await prodId()}/stripe`, `session:${(await sessionRow(held)).id}`, 'instance']) {
    await freeze(target);
    const frozen = await charge();
    assert.deepEqual([frozen.status, frozen.body.reason], [403, 'frozen'], target);
    await freeze(target, 'workload.unfreeze');
    assert.equal((await charge()).status, 200, `${target} lifted`);
  }
  // Logout revokes the session: the cache still holds its values, and serves nothing.
  const url = `${ORIGIN}/api/auth/logout`;
  const out = await answer(new Request(url, { method: 'POST', headers: { authorization: `DPoP ${held.token}`, dpop: await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce() }) } }), runtime, ui, IP);
  assert.equal(out.status, 200);
  assert.equal((await charge()).status, 401);
  assert.equal(reached.length, 5);
});

async function sessionRow(held: Session) {
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(held.token)));
  return row!;
}

test('past a limit, 429 with Retry-After and nothing sent; one alert per workload, credential and window, logged and delivered', async () => {
  await bind();
  const held = await session();
  for (let i = 0; i < 3; i++) assert.equal((await use(held, 'GET', '/use/metered/v1/balance')).status, 200);
  const past = await use(held, 'GET', '/use/metered/v1/balance');
  assert.deepEqual([past.status, past.body.reason], [429, 'limit']);
  assert.ok(Number(past.headers.get('retry-after')) >= 1);
  assert.equal((await use(held, 'GET', '/use/metered/v1/balance')).status, 429);
  assert.equal(reached.length, 3);
  // Another credential has no limit, and counts apart.
  assert.equal((await use(held, 'GET', '/use/stripe/v1/balance')).status, 200);
  await Promise.all(background);
  const logged = await entries('workload.alert');
  assert.equal(logged.length, 1, 'one alert for the window');
  assert.deepEqual([logged[0]!.kind, logged[0]!.service, logged[0]!.credential, logged[0]!.count, logged[0]!.ip], ['limit', MEMBER, 'metered', 'metered per minute', IP]);
  assert.equal(logged[0]!.session, (await sessionRow(held)).id);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0]!.text, /^api-prod is past its limit for metered per minute, from 203\.0\.113\.9/);
});

test("a narrowed session is held to its constraints on the URL sent, and one limited to paths signs nothing", async () => {
  await bind();
  const parent = await session();
  const root = await sessionRow(parent);
  const key = await generateProofKey();
  const child = { token: `coffre_wl_${Buffer.alloc(32, 7).toString('base64url')}`, key };
  await insertSession(deps.db, deps.chainKey, {
    id: randomUUID(), kind: 'workload', tokenHash: hashToken(child.token), tokenHint: 'coffre_wl_Bwc', generation: root.generation, principal: MEMBER,
    identityId: null, label: 'refund-agent', createdBy: root.createdBy, expiresAt: root.expiresAt, revokedAt: null, scope: root.scope, places: root.places,
    jkt: await thumbprint(key.jwk), notAfter: root.notAfter!, ancestors: JSON.stringify([root.id]), constraints: JSON.stringify({ credentials: ['stripe'], methods: ['POST'], paths: ['/stripe/v1/refunds'] }), enrollmentId: null, approvedAt: null, approvedBy: null,
  });
  // Its paths are the URL sent's, the upstream's own path (`/stripe` here) included.
  assert.equal((await use(child, 'POST', '/use/stripe/v1/refunds/re_1', { body: '' })).status, 200);
  for (const [method, path] of [['POST', '/use/stripe/v1/refunds/%2e%2e/charges'], ['POST', '/use/stripe/v1/refundsX'], ['GET', '/use/stripe/v1/refunds'], ['POST', '/use/s3/v1/refunds']]) {
    const refused = await use(child, method!, path!, method === 'POST' ? { body: '' } : {});
    assert.ok(refused.status === 403 || refused.status === 400, `${method} ${path}: ${refused.status}`);
  }
  const signed = await use(child, 'POST', '/use', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sign: { credential: 'dfns-key', message: 'aGk' } }) });
  assert.deepEqual([signed.status, signed.body.reason], [403, 'narrowed']);
  assert.equal(reached.length, 1);
});

test('sign and presign take a workload, its proof signing what is asked; the plan gives plain values only', async () => {
  await bind();
  const held = await session();
  const ask = JSON.stringify({ sign: { credential: 'dfns-key', message: Buffer.from('transfer 10').toString('base64url') } });
  const signed = await use(held, 'POST', '/use', { headers: { 'content-type': 'application/json' }, body: ask });
  assert.equal(signed.status, 200, JSON.stringify(signed.body));
  assert.equal(typeof signed.body.signature, 'string');
  // Another message than the one signed: refused.
  const other = JSON.stringify({ sign: { credential: 'dfns-key', message: Buffer.from('transfer 9999').toString('base64url') } });
  assert.equal((await use(held, 'POST', '/use/market/prod', { headers: { 'content-type': 'application/json' }, body: other, signed: { body: ask } })).body.reason, 'req');
  const presigned = await use(held, 'POST', '/use/market/prod', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ presign: { credential: 's3', path: '/bucket/report.pdf', expiresIn: 60 } }) });
  assert.equal(presigned.status, 200, JSON.stringify(presigned.body));
  assert.match(presigned.body.url as string, /X-Amz-Credential=AKIAREAL0123456789AB/);
  const plan = await use(held, 'GET', '/use/market/prod');
  assert.equal(plan.status, 200, JSON.stringify(plan.body));
  assert.equal(plan.body.environment, 'market/prod');
  assert.deepEqual(plan.body.values, { REGION: 'eu-west-3' }, 'its plain value, and no secret one: it uses them');
  assert.deepEqual([...(plan.body.credentials as string[])].sort(), ['dfns-key', 'dpopped', 'metered', 's3', 'stripe']);
  assert.deepEqual(plan.body.tunnels, { db: { key: 'DATABASE_URL', url: 'wss://secrets.acme.example/use/market/prod/db' } });
  assert.deepEqual([...(plan.body.useOnly as string[])].sort(), ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'DATABASE_URL', 'SIGNING_KEY', 'STRIPE_KEY']);
});

test("a Cloudflare call is its binding's: every header the calling Worker set goes on, as nobody between could change it", async () => {
  await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'cloudflare', issuer: null, claims: {} as never, label: 'edge', replaces: [], policy: {} }, { dryRun: false });
  const sent = await read((await bindingRoute(new Request(`${ORIGIN}/use/stripe/v1/charges`, { method: 'POST', headers: { 'x-trace': 't-1' }, body: 'a=1' }), runtime, MEMBER))!);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(reached[0]!.headers['x-trace'], 't-1');
  assert.equal(reached[0]!.headers.authorization, `Bearer ${STRIPE_KEY}`);
});

test('a workload tunnel ends within one recheck of a freeze, and stands while nothing changes', { timeout: 30_000 }, async () => {
  runtime = makeRuntime({ recheckSeconds: 1.5 });
  await bind();
  const held = await session();
  const server = createServer((_, response) => response.writeHead(404).end());
  server.on('upgrade', (request, socket, head) => void upgrade(runtime, request, socket, head));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const open = async (who: Session) => {
      const url = `${ORIGIN}/use/market/prod/db`;
      const proof = await createProof(who.key, { method: 'GET', url, token: who.token, nonce: await gates(MEMBER).nonce() });
      const ws = new WebSocket(`ws://127.0.0.1:${(server.address() as AddressInfo).port}/use/market/prod/db`, { headers: { authorization: `DPoP ${who.token}`, dpop: proof } });
      await once(ws, 'open');
      return ws;
    };
    const ws = await open(held);
    const closed = once(ws, 'close').then(() => Date.now());
    // Three bounds and more with nothing changed: its rechecks keep it open.
    await sleep(5000);
    assert.equal(ws.readyState, WebSocket.OPEN, 'still open while it stands');
    // Its app logs in with no password: coffre asks for none (AuthenticationCleartextPassword, R 3), and goes on to dial.
    const login = await open(held);
    const said: Buffer[] = [];
    login.on('message', (data: Buffer) => said.push(Buffer.from(data)));
    const params = Buffer.from('user\0app\0database\0app\0\0');
    const startup = Buffer.alloc(8 + params.length);
    startup.writeInt32BE(startup.length, 0);
    startup.writeInt32BE(196608, 4);
    params.copy(startup, 8);
    login.send(startup);
    await once(login, 'close');
    const bytes = Buffer.concat(said);
    assert.ok(!(bytes[0] === 0x52 && bytes.readInt32BE(5) === 3), 'no password asked');
    await freeze('token:api-prod');
    const frozenAt = Date.now();
    const at = await closed;
    assert.ok(at - frozenAt <= 1500 + 300, `ended ${at - frozenAt} ms after the freeze`);
    // Frozen, a new one is refused at once.
    await assert.rejects(open(held), /403/);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    // A recheck or a last use still being written would meet the next test's reset: let them land first.
    await sleep(1000);
    await Promise.all(background);
  }
});

test("a workload's use reads the environment its statement checked: a path that resolves elsewhere is refused before anything is logged or opened", async () => {
  // A plugin that asks for market/prod's place, then reads another path with the caller it got: a rename in between, in effect.
  runtime = makeRuntime({
    plugins: checkPlugins([{
      name: 'probe',
      routes: {
        prefix: '/use',
        fetch: async (request, coffre) => {
          const caller = (await coffre.workload(request, { place: 'market/prod', credential: 'stripe', body: await bodyDigest('') }))!;
          const read = await coffre.use(caller, { path: 'market/staging', keys: ['STRIPE_KEY'], purpose: 'use', logged: {} }).then(() => 200, (error: { status: number }) => error.status);
          return new Response(null, { status: read });
        },
      },
    }]),
  });
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/staging', { name: 'staging' });
  await root.secrets.set('market/staging', { STRIPE_KEY: 'sk_live_staging_0123456789' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer', 'market/staging': 'viewer' });
  await bind();
  const held = await session();
  let unwraps = 0;
  const unwrap = deps.vault.unwrap.bind(deps.vault);
  deps.vault.unwrap = async (...args: Parameters<typeof unwrap>) => {
    unwraps++;
    return unwrap(...args);
  };
  const used = (await entries('credential.use')).length;
  const url = `${ORIGIN}/use/market/prod/stripe`;
  const proof = await createProof(held.key, { method: 'GET', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: {}, body: await bodyDigest('') } });
  const answered = await pluginRoute(new Request(url, { headers: { authorization: `DPoP ${held.token}`, dpop: proof } }), runtime, IP);
  assert.equal(answered!.status, 409);
  assert.equal((await entries('credential.use')).length, used, 'nothing logged');
  assert.equal(unwraps, 0, 'nothing opened');
});

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
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { bodyDigest, bodyLine, contentDigest, createProof, generateProofKey, thumbprint, UNSIGNED_BODY, type ProofKey } from '@coffre/client/dpop';
import { keyAudience, workload } from '@coffre/client/workload';
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
import { credentialProxy, form, header, hmac, json, postgres, privateKey, sigv4 } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, holdSomething, LOG, LOG_014_ONLY, openTestDatabase, resetDatabase, testDeps, usesLogged, type FixtureDeps } from './api-fixture.ts';
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
const WEBHOOK_SECRET = 'whsec_0123456789abcdefghij';
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

/** The upstream: what reached it, each request's method, URL, headers and body's SHA-256; what it got of each it never got whole; the bytes so far. */
let upstream: Server;
let upstreamAt: string;
let reached: { method: string; url: string; headers: IncomingMessage['headers']; sha256: string; length: number }[];
let broken: { url: string; length: number }[];
let received: number;

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
      yousign: { upstream: `${upstreamAt}/yousign`, inject: header('authorization', `Bearer {STRIPE_KEY}`) },
      s3: { upstream: `${upstreamAt}/s3`, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
    },
    signers: { 'dfns-key': privateKey('SIGNING_KEY') },
    verifiers: { webhook: hmac('WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) },
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
      received += chunk.length;
    });
    request.on('close', () => {
      if (!request.complete) broken.push({ url: request.url!, length });
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
  broken = [];
  received = 0;
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
  await root.secrets.set('market/prod', { STRIPE_KEY, ...AWS, SIGNING_KEY, WEBHOOK_SECRET, DATABASE_URL: 'postgres://app:pw@127.0.0.1:5999/app?sslmode=disable', REGION: { value: 'eu-west-3', plain: true } });
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

/** A GitHub run's ID token for `audience`, the instance's URL naming a key. */
function runToken(audience: string): string {
  const seconds = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${part({ iss: GITHUB, aud: audience, sub: 'repo:acme/api:ref:refs/heads/main', iat: seconds - 5, exp: seconds + 600, jti: randomUUID(), ...DEPLOY })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), signer.privateKey).toString('base64url')}`;
}

/** A session of the service, from a GitHub run's token whose audience names its key. */
async function session(): Promise<Session> {
  const key = await generateProofKey();
  const jwt = runToken(`${ORIGIN}#jkt=${await thumbprint(key.jwk)}`);
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
  // Nor in the URL, as it is or escaped, nor in an upload that streams: nothing of it reaches the upstream.
  for (const query of [`?t=${held.token}`, `?t=${held.token.replace('_', '%5F')}`]) {
    const inUrl = await use(held, 'GET', `/use/stripe/v1/notes${query}`);
    assert.equal(inUrl.status, 400, `${query}: ${JSON.stringify(inUrl.body)}`);
  }
  const carrying = new TextEncoder().encode(`prefix ${held.token} suffix`);
  const carryingHash = createHash('sha256').update(carrying).digest('hex');
  const s3Url = `${ORIGIN}/use/s3/bucket/leak`;
  const s3Headers = { 'x-amz-content-sha256': carryingHash };
  const s3Proof = await createProof(held.key, { method: 'PUT', url: s3Url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: s3Headers, body: carryingHash } });
  const streamedLeak = await pluginRoute(new Request(s3Url, { method: 'PUT', headers: { ...s3Headers, 'content-length': String(carrying.length), authorization: `DPoP ${held.token}`, dpop: s3Proof }, body: new Blob([carrying]).stream(), duplex: 'half' } as RequestInit), runtime, IP);
  assert.notEqual(streamedLeak!.status, 200);
  await streamedLeak!.body?.cancel();
  assert.ok(reached.every((one) => !one.url.includes('/s3/bucket/leak') || one.length === 0), 'nothing of the upload reached the upstream');
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
  // An empty body is no body, whatever its header says, on every platform: buffered, or streamed with content-length 0.
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/empty', { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: '' })).status, 200);
  const marker = `${ORIGIN}/use/s3/bucket/prefix/`;
  const empty = createHash('sha256').digest('hex');
  const markerHeaders = { 'x-amz-content-sha256': empty };
  const markerProof = await createProof(held.key, { method: 'PUT', url: marker, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: markerHeaders, body: await bodyDigest('') } });
  const streamedEmpty = await read((await pluginRoute(new Request(marker, { method: 'PUT', headers: { ...markerHeaders, 'content-length': '0', authorization: `DPoP ${held.token}`, dpop: markerProof }, body: new Blob([]).stream(), duplex: 'half' } as RequestInit), runtime, IP))!);
  assert.equal(streamedEmpty.status, 200, JSON.stringify(streamedEmpty.body));
  assert.equal(reached.at(-1)!.length, 0);
  // As the SDK signs an empty stream that says its content-length, UNSIGNED-PAYLOAD and all: the line `bodyLine` gives both sides.
  const sdkHeaders = { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' };
  const sdkProof = await createProof(held.key, { method: 'PUT', url: marker, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: sdkHeaders, body: await bodyLine({ declared: 'UNSIGNED-PAYLOAD', length: 0 }) } });
  const sdkEmpty = await read((await pluginRoute(new Request(marker, { method: 'PUT', headers: { ...sdkHeaders, 'content-length': '0', authorization: `DPoP ${held.token}`, dpop: sdkProof }, body: new Blob([]).stream(), duplex: 'half' } as RequestInit), runtime, IP))!);
  assert.equal(sdkEmpty.status, 200, JSON.stringify(sdkEmpty.body));
  assert.equal(reached.length, 7);
  await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, strict);
  await bind({ unsignedUploads: true });
  const loose = await session();
  const taken = await upload(loose, 'UNSIGNED-PAYLOAD', UNSIGNED_BODY);
  assert.equal(taken.status, 200, JSON.stringify(taken.body));
  assert.equal(reached.at(-1)!.headers['x-amz-content-sha256'], 'UNSIGNED-PAYLOAD');
});

/** A Yousign document upload as the app makes it: a PDF of `size` bytes and the document's nature, as multipart. */
function document(size: number): { type: string; body: Buffer<ArrayBuffer> } {
  const boundary = `----coffre${randomBytes(8).toString('hex')}`;
  const head = `--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="contract.pdf"\r\ncontent-type: application/pdf\r\n\r\n`;
  const tail = `\r\n--${boundary}\r\ncontent-disposition: form-data; name="nature"\r\n\r\nsignable_document\r\n--${boundary}--\r\n`;
  return { type: `multipart/form-data; boundary=${boundary}`, body: Buffer.concat([Buffer.from(head), randomBytes(size), Buffer.from(tail)]) };
}

/** `bytes` as a stream of 1 MiB chunks, which waits before the chunk at `pause` until `until()` holds: what a body sent on as it comes sees. */
function chunked(bytes: Uint8Array, pause?: { at: number; until: () => boolean }): ReadableStream<Uint8Array> {
  const size = 1024 * 1024;
  let at = 0;
  return new ReadableStream({
    async pull(out) {
      if (at >= bytes.length) return out.close();
      if (pause !== undefined && at === pause.at * size) {
        for (let waited = 0; !pause.until(); waited += 10) {
          if (waited > 20_000) return out.error(new Error(`the upstream got ${received} bytes while coffre held the rest: it buffered the body`));
          await sleep(10);
        }
      }
      out.enqueue(bytes.subarray(at, at + size));
      at += size;
    },
  });
}

test('a 55 MB document that declares its Content-Digest streams through the SDK and coffre to the upstream byte for byte, never held whole', { timeout: 120_000 }, async () => {
  await bind();
  // The SDK as the app runs it, its requests answered by this runtime.
  const coffre = await workload({
    url: ORIGIN,
    service: SERVICE,
    proof: { name: 'github', kind: 'oidc', prove: async (context) => ({ oidc: runToken(keyAudience(context)) }) },
    fetch: (input, init) => answer(new Request(input, init), runtime, ui, IP),
    log: () => undefined,
    sigterm: false,
  });
  try {
    const { type, body } = document(55_000_000);
    const sha256 = createHash('sha256').update(body).digest('hex');
    // Read whole by the SDK, which declares its digest: coffre streams it on all the same, past the 16 MiB it reads whole.
    const whole = await coffre.fetch(`${coffre.url('yousign')}/v3/signature_requests/sr-1/documents`, { method: 'POST', headers: { 'content-type': type }, body });
    assert.equal(whole.status, 200, await whole.text());
    assert.deepEqual([reached.at(-1)!.length, reached.at(-1)!.sha256], [body.length, sha256]);
    assert.equal(reached.at(-1)!.headers['content-digest'], contentDigest(sha256));
    assert.equal(reached.at(-1)!.headers['content-type'], type);
    assert.equal(reached.at(-1)!.headers['content-length'], String(body.length));
    assert.equal(reached.at(-1)!.headers.authorization, `Bearer ${STRIPE_KEY}`);
    // Declared by whoever holds the bytes, as `coffre serve` does, and streamed: the upstream has 17 MiB of it before the app
    // sends past 24 MiB, so coffre holds no more than a chunk of it at a time.
    const start = received;
    const streamed = await coffre.fetch(`${coffre.url('yousign')}/v3/signature_requests/sr-1/documents`, {
      method: 'POST',
      headers: { 'content-type': type, 'content-digest': contentDigest(sha256), 'content-length': String(body.length) },
      body: chunked(body, { at: 24, until: () => received - start >= 17 * 1024 * 1024 }),
      duplex: 'half',
    } as RequestInit);
    assert.equal(streamed.status, 200, await streamed.text());
    assert.deepEqual([reached.at(-1)!.length, reached.at(-1)!.sha256], [body.length, sha256]);
    assert.equal(reached.length, 2);
    assert.deepEqual(broken, []);
  } finally {
    await coffre.close();
  }
});

test('a body other than its Content-Digest says, short of its length, past it, or declaring it badly is refused, and the upstream never gets it whole', { timeout: 60_000 }, async () => {
  await bind();
  const held = await session();
  const url = `${ORIGIN}/use/yousign/v3/documents`;
  const bytes = randomBytes(3 * 1024 * 1024);
  const digest = createHash('sha256').update(bytes).digest('hex');
  /** `sent` streamed, saying `length`, its proof signing `signed` headers (the digest header, unless told) and `line`. */
  const upload = async (sent: Uint8Array, options: { length?: number; header?: string; signed?: Record<string, string>; line?: string } = {}) => {
    const headers = { 'content-type': 'application/pdf', 'content-digest': options.header ?? contentDigest(digest) };
    const proof = await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: options.signed ?? headers, body: options.line ?? digest } });
    const request = new Request(url, { method: 'POST', headers: { ...headers, 'content-length': String(options.length ?? sent.length), authorization: `DPoP ${held.token}`, dpop: proof }, body: chunked(sent), duplex: 'half' } as RequestInit);
    return read((await pluginRoute(request, runtime, IP))!);
  };
  // Other bytes of the same length: the digest fails at the end, and the upstream, which had all but the last of it, stores nothing.
  const tampered = Buffer.from(bytes);
  tampered[1000] = tampered[1000]! ^ 1;
  const swapped = await upload(tampered);
  assert.deepEqual([swapped.status, swapped.body.message], [400, 'the body is not what its Content-Digest says']);
  // Short of the length it says, and past it.
  const short = await upload(bytes.subarray(0, bytes.length - 1), { length: bytes.length });
  assert.deepEqual([short.status, short.body.message], [400, 'the body ended short of the length it declared']);
  const long = await upload(Buffer.concat([bytes, Buffer.from('x')]), { length: bytes.length });
  assert.deepEqual([long.status, long.body.message], [400, 'the body ran past the length it declared']);
  for (let waited = 0; broken.length < 3 && waited < 5000; waited += 10) await sleep(10);
  // A sha-256 member that is no SHA-256, or two of them: refused before anything goes.
  const before = broken.length;
  for (const header of ['sha-256=:bm90IGEgZGlnZXN0:', `${contentDigest(digest)}, ${contentDigest(digest)}`, 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFV=:']) {
    const malformed = await upload(bytes, { header, signed: { 'content-type': 'application/pdf', 'content-digest': header } });
    assert.equal(malformed.status, 400, header);
    assert.match(malformed.body.message as string, /Content-Digest declares a body's SHA-256 once/);
  }
  // The proof must sign the header that chose the line; and a header other than the one signed fails the proof.
  const unsigned = await upload(bytes, { signed: { 'content-type': 'application/pdf' } });
  assert.deepEqual([unsigned.status, unsigned.body.message], [400, 'content-digest says what binds the body, so the proof signs it: name it in hdr']);
  const other = createHash('sha256').update('another document').digest('hex');
  const resigned = await upload(bytes, { header: contentDigest(other) });
  assert.deepEqual([resigned.status, resigned.body.reason], [401, 'req']);
  assert.equal(broken.length, before, 'nothing reached the upstream of a request refused before it streams');
  assert.equal(reached.length, 0, 'the upstream got no request whole');
  assert.equal(broken.length, 3);
  assert.ok(broken.every((one) => one.length < bytes.length), JSON.stringify(broken));
  assert.ok(broken.some((one) => one.length > 1024 * 1024), 'the refused bodies streamed until their end');
  // An empty body that declares the empty body's digest, as `coffre serve` sends an empty POST: its line is that digest anyway.
  const empty = createHash('sha256').digest('hex');
  const none = await read((await pluginRoute(new Request(url, { method: 'POST', headers: { 'content-digest': contentDigest(empty), 'content-length': '0', authorization: `DPoP ${held.token}`, dpop: await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: { 'content-digest': contentDigest(empty) }, body: empty } }) }, body: chunked(new Uint8Array(0)), duplex: 'half' } as RequestInit), runtime, IP))!);
  assert.equal(none.status, 200, JSON.stringify(none.body));
  assert.equal(reached.at(-1)!.length, 0);
  // Another digest on it, added on the way: an empty request is whole once its headers are, so it is refused before any go.
  const [whole, cut] = [reached.length, broken.length];
  const stale = await read((await pluginRoute(new Request(url, { method: 'POST', headers: { 'content-digest': contentDigest(other), 'content-length': '0', authorization: `DPoP ${held.token}`, dpop: await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: {}, body: empty } }) }, body: chunked(new Uint8Array(0)), duplex: 'half' } as RequestInit), runtime, IP))!);
  assert.deepEqual([stale.status, stale.body.message], [400, 'the body is not what its Content-Digest says']);
  await sleep(50);
  assert.deepEqual([reached.length, broken.length], [whole, cut], 'nothing of it reached the upstream');
  // Through an AWS-signed credential, a Content-Digest alone is the payload hash coffre signs again, which S3 checks too.
  const s3Url = `${ORIGIN}/use/s3/bucket/digested`;
  const s3Proof = await createProof(held.key, { method: 'PUT', url: s3Url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: { 'content-digest': contentDigest(digest) }, body: digest } });
  const s3 = await read((await pluginRoute(new Request(s3Url, { method: 'PUT', headers: { 'content-digest': contentDigest(digest), 'content-length': String(bytes.length), authorization: `DPoP ${held.token}`, dpop: s3Proof }, body: chunked(bytes), duplex: 'half' } as RequestInit), runtime, IP))!);
  assert.equal(s3.status, 200, JSON.stringify(s3.body));
  assert.deepEqual([reached.at(-1)!.headers['x-amz-content-sha256'], reached.at(-1)!.sha256], [digest, digest]);
  assert.match(reached.at(-1)!.headers.authorization as string, new RegExp(`^AWS4-HMAC-SHA256 Credential=${AWS.AWS_ACCESS_KEY_ID}/`));
  // An app's own digest of another algorithm declares nothing: read whole, under 16 MiB, and sent on as it is.
  const sha512 = `sha-512=:${createHash('sha512').update(bytes).digest('base64')}:`;
  const own = await use(held, 'POST', '/use/yousign/v3/documents', { headers: { 'content-digest': sha512 }, body: 'a small body' });
  assert.equal(own.status, 200, JSON.stringify(own.body));
  assert.equal(reached.at(-1)!.headers['content-digest'], sha512);
  // Past 16 MiB with no digest declared: the refusal names the way through.
  const big = new Uint8Array(randomBytes(17 * 1024 * 1024));
  const proof = await createProof(held.key, { method: 'POST', url, token: held.token, nonce: await gates(MEMBER).nonce(), content: { headers: {}, body: createHash('sha256').update(big).digest('hex') } });
  const refused = await read((await pluginRoute(new Request(url, { method: 'POST', headers: { authorization: `DPoP ${held.token}`, dpop: proof }, body: big }), runtime, IP))!);
  assert.equal(refused.status, 413);
  assert.match(refused.body.message as string, /Content-Digest: sha-256=:<base64>:, as coffre serve and @coffre\/client\/workload send it/);
  // Past 95 MiB, said by its length: refused before a byte is read.
  const huge = await upload(bytes, { length: 95 * 1024 * 1024 + 1 });
  assert.equal(huge.status, 413);
  assert.match(huge.body.message as string, /up to 95 MiB, under the 100 MB a Cloudflare zone takes/);
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

// Its child is planted in the database, as `narrow` would make it, sealed by nothing.
test("a narrowed session is held to its constraints on the URL sent, and one limited to paths signs nothing", { skip: LOG_014_ONLY }, async () => {
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
  const verified = await use(child, 'POST', '/use', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ verify: { credential: 'webhook', message: 'aGk', signature: 'sha256=00' } }) });
  assert.deepEqual([verified.status, verified.body.reason], [403, 'narrowed']);
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
  assert.deepEqual([...(plan.body.credentials as string[])].sort(), ['dfns-key', 'dpopped', 'metered', 's3', 'stripe', 'webhook', 'yousign']);
  assert.deepEqual(plan.body.tunnels, { db: { key: 'DATABASE_URL', url: 'wss://secrets.acme.example/use/market/prod/db' } });
  assert.deepEqual([...(plan.body.useOnly as string[])].sort(), ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'DATABASE_URL', 'SIGNING_KEY', 'STRIPE_KEY', 'WEBHOOK_SECRET']);
});

test("verify takes a workload, its proof binding the body and signature checked; the secret is opened once a minute and never answered", async () => {
  await bind();
  const held = await session();
  const body = '{"event_name":"signature_request.done","data":{"signature_request":{"id":"sr-1"}}}';
  const signature = `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex')}`;
  const ask = (message: string, given: string) => JSON.stringify({ verify: { credential: 'webhook', message: Buffer.from(message).toString('base64url'), signature: given } });
  const opened = vaultCalls;
  for (const [message, given, valid] of [[body, signature, true], [`${body} `, signature, false], [body, signature.replace('sha256=', ''), false], [body, signature, true]] as const) {
    const verified = await use(held, 'POST', '/use', { headers: { 'content-type': 'application/json' }, body: ask(message, given) });
    assert.equal(verified.status, 200, JSON.stringify(verified.body));
    assert.deepEqual(verified.body, { valid });
  }
  // A body or a signature changed on the way, a valid one in place of the one the proof signed: refused.
  const swapped = await use(held, 'POST', '/use/market/prod', { headers: { 'content-type': 'application/json' }, body: ask(body, signature), signed: { body: ask(body, 'sha256=00') } });
  assert.equal(swapped.body.reason, 'req');
  assert.ok(vaultCalls - opened <= 1, 'the vault asked once at most, then the cache');
  if (LOG === '0.14') {
    const uses = (await entries('credential.use')).filter((entry) => entry.credential === 'webhook');
    assert.deepEqual(uses.map((entry) => entry.hmac), [true]);
  } else {
    // 0.15's record: one use of the secret, its row slim (R53), naming no verifier.
    assert.equal((await usesLogged(db.owner)).filter((use) => use.purpose === 4).length, 1);
  }
  // A verifier signs nothing.
  const signed = await use(held, 'POST', '/use', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sign: { credential: 'webhook', message: 'aGk' } }) });
  assert.equal(signed.status, 404);
  assert.ok(![...reached].some((request) => JSON.stringify(request).includes(WEBHOOK_SECRET)));
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

test("a form or JSON rule fills its field whatever the app put there, once the proof holds for the body as sent; the Content-Digest that goes on is the new body's", async () => {
  runtime = makeRuntime({
    plugins: checkPlugins([credentialProxy({
      credentials: {
        turnstile: { upstream: `${upstreamAt}/turnstile`, inject: json('secret', '{STRIPE_KEY}') },
        gather: { upstream: `${upstreamAt}/gather`, inject: form('refresh_token', '{STRIPE_KEY}') },
      },
      insecureUpstreams: true,
    })]),
  });
  await bind();
  const held = await session();
  const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');
  // As the SDK and `coffre serve` send it: the body's digest declared, and signed with the rest.
  const body = '{"secret":"coffre","response":"XXXX.DUMMY.TOKEN"}';
  const headers = { 'content-type': 'application/json', 'content-digest': contentDigest(await bodyDigest(body)) };
  const sent = await use(held, 'POST', '/use/turnstile/siteverify', { headers, body });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const filled = JSON.stringify({ secret: STRIPE_KEY, response: 'XXXX.DUMMY.TOKEN' });
  assert.deepEqual([reached[0]!.sha256, reached[0]!.length], [sha256(filled), filled.length]);
  assert.equal(reached[0]!.headers['content-digest'], contentDigest(sha256(filled)));
  assert.equal((await use(held, 'POST', '/use/market/prod/gather/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=refresh_token&refresh_token=' })).status, 200);
  assert.equal(reached[1]!.sha256, sha256(`grant_type=refresh_token&refresh_token=${STRIPE_KEY}`));

  // A body changed on the way is the proof's to refuse, before anything is filled; the field missing, or the session token anywhere else, coffre's.
  const changed = await use(held, 'POST', '/use/turnstile/siteverify', { headers: { 'content-type': 'application/json' }, body: '{"secret":"x","response":"other"}', signed: { body } });
  assert.deepEqual([changed.status, changed.body.reason], [401, 'req']);
  const missing = await use(held, 'POST', '/use/turnstile/siteverify', { headers: { 'content-type': 'application/json' }, body: '{"response":"x"}' });
  assert.equal(missing.status, 400, JSON.stringify(missing.body));
  for (const leak of [JSON.stringify({ secret: 'x', note: held.token }), `{"secret":"x","note":"\\u0063${held.token.slice(1)}"}`]) {
    const leaked = await use(held, 'POST', '/use/turnstile/siteverify', { headers: { 'content-type': 'application/json' }, body: leak });
    assert.equal(leaked.status, 400, JSON.stringify(leaked.body));
    assert.match(leaked.body.message as string, /session token/);
  }
  const encoded = await use(held, 'POST', '/use/gather/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `refresh_token=x&note=${held.token.replace('_', '%5F')}` });
  assert.equal(encoded.status, 400, JSON.stringify(encoded.body));
  assert.equal(reached.length, 2);
});

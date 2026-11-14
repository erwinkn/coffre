// A workload's requests through the credential proxy on 0.16 (docs/design/workload-access.md,
// sections 5.1, 7.1 and 8; docs/design/0.16.md, "The proxy"), 0.14.7's
// credential-proxy-workload.test.ts on the 0.16 contract: a key-bound session's proof signs
// the request whole, so only the headers it signs go upstream, and a query, header, path or
// body changed on the way is refused; a streamed upload is bound by the digest it declares
// and streams on, never held whole; a limit answers 429 with Retry-After; a narrowed session
// is held to the URL sent; and the body and path rules fill their slot once the proof holds.
// What a session's request costs, its gate and its nonce are proxy-use.test.ts's and
// workload-requests.test.ts's; the limit's alert is proxy-use.test.ts's. The upstream is a
// real one on loopback, so that what it got of a body cut off is seen.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, beforeEach, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

import { bodyDigest, bodyLine, contentDigest, createProof, generateProofKey, thumbprint, UNSIGNED_BODY, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';

import { processGates } from '../src/gate.ts';
import { credentialProxy, form, header, json, path as pathRule, query, sigv4 } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const STRIPE_KEY = 'sk_live_0123456789abcdefghij';
const AWS = { AWS_ACCESS_KEY_ID: 'AKIAREAL0123456789AB', AWS_SECRET_ACCESS_KEY: 'real/secret/0123456789abcdefghijklmnopqr' };
const sha256 = (bytes: string | Uint8Array) => createHash('sha256').update(bytes).digest('hex');

/** The upstream: each request it got whole (method, URL, headers, its body's SHA-256 and length); what it got of each it never got whole; the bytes so far. */
let reached: { method: string; url: string; headers: IncomingMessage['headers']; sha256: string; length: number }[] = [];
let broken: { url: string; length: number }[] = [];
let received = 0;
const upstream: Server = createServer((request, response) => {
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
    // A redirect relative to the URL it came to: `#top` and `""` keep its query whole.
    const at = new URL(request.url!, 'http://upstream').pathname;
    if (at.endsWith('/fragment') || at.endsWith('/here')) response.writeHead(302, { location: at.endsWith('/here') ? '' : '#top' }).end();
    else response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true }));
  });
});
upstream.listen(0, '127.0.0.1');
await once(upstream, 'listening');
const at = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

const proxy = credentialProxy({
  credentials: {
    stripe: { upstream: `${at}/stripe`, inject: header('authorization', 'Bearer {STRIPE_KEY}') },
    // The same key, counted: three a minute.
    metered: { upstream: `${at}/stripe`, inject: header('authorization', 'Bearer {STRIPE_KEY}'), limit: { perMinute: 3 } },
    // A rule that sends its key under the DPoP scheme: a handle's app sends its handle there.
    dpopped: { upstream: `${at}/dpopped`, inject: header('authorization', 'DPoP {STRIPE_KEY}') },
    yousign: { upstream: `${at}/yousign`, inject: header('authorization', 'Bearer {STRIPE_KEY}') },
    s3: { upstream: `${at}/s3`, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
    telegram: { upstream: `${at}/tg`, inject: pathRule('bot{STRIPE_KEY}') },
    keyed: { upstream: `${at}/keyed`, inject: query('api_key', '{STRIPE_KEY}') },
    turnstile: { upstream: `${at}/turnstile`, inject: json('secret', '{STRIPE_KEY}') },
    gather: { upstream: `${at}/gather`, inject: form('refresh_token', '{STRIPE_KEY}') },
  },
  insecureUpstreams: true,
});

let gates = processGates();
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates: (service) => gates(service), plugins: [proxy] });
const { world } = app;

after(async () => {
  upstream.closeAllConnections();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await app.close();
});

const market = project('market');
const prod = environment(market, 'prod');
const ON_PROD = JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]);

type Session = { token: string; key: ProofKey };
/** The deploy service's session, its binding taking no unsigned upload; and its binding. */
let held: Session;
let strict: ReturnType<typeof binding>;
/** Ada's handle on prod, as `coffre run` gives one. */
let handle: string;

/** Another session of the deploy service: of `by`, its binding (the strict one unless told), narrowed to `constraints` if given. */
async function sessionOf(more: { by?: ReturnType<typeof binding>; constraints?: Record<string, unknown> } = {}): Promise<Session> {
  const key = await generateProofKey();
  const token = generateToken('workload');
  const row = session(token, more.by ?? strict, { jkt: await thumbprint(key.jwk), scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000), ...(more.constraints === undefined ? {} : { constraints: JSON.stringify(more.constraints) }) });
  await write(world, ...rows('credentials', row));
  return { token, key };
}

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  gates = processGates();
  reached = [];
  broken = [];
  received = 0;
  strict = binding(DEPLOY, { policy: '{}', scope: ON_PROD });
  handle = generateToken('handle');
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'viewer', ['secret.read', 'secret.use'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(ADA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'viewer', { project: market }), grant(DEPLOY, 'viewer', { project: market })),
    ...rows('secrets', value(world, secret(prod, 'STRIPE_KEY'), STRIPE_KEY), ...Object.entries(AWS).map(([key, real]) => value(world, secret(prod, key), real))),
    ...rows('bindings', strict),
    ...rows('credentials', credential(handle, ADA, { kind: 'handle', scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) })),
  );
  held = await sessionOf();
});

type Sent = { status: number; body: Record<string, unknown>; headers: Headers };

async function read(response: Response): Promise<Sent> {
  const text = await response.text();
  return { status: response.status, body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>), headers: response.headers };
}

/** A proof of `who`'s for a request, under its gate's nonce: `headers` and `body` (its line) what it signs. */
const proofOf = async (who: Session, method: string, url: string, headers: Record<string, string>, body: string) =>
  createProof(who.key, { method, url, token: who.token, nonce: await gates(DEPLOY).nonce(), content: { headers, body } });

/**
 * A request as the SDK sends it: its proof signs the method, URL, the
 * headers set and the body (`signed` in place of what is sent, for a
 * request changed on the way), and `added` headers join it afterwards, as
 * a library or a proxy on the way adds them.
 */
async function use(who: Session, method: string, path: string, init: { headers?: Record<string, string>; body?: string; signed?: { url?: string; headers?: Record<string, string>; body?: string; line?: string }; added?: Record<string, string> } = {}): Promise<Sent> {
  const headers = init.headers ?? {};
  const proof = await proofOf(who, method, init.signed?.url ?? `${PUBLIC_URL}${path}`, init.signed?.headers ?? headers, init.signed?.line ?? (await bodyDigest(init.signed?.body ?? init.body ?? '')));
  return read(await app.request(path, { method, headers: { ...headers, ...init.added, authorization: `DPoP ${who.token}`, dpop: proof }, ...(init.body === undefined ? {} : { body: init.body }) }));
}

/** A streamed request of `who`'s, `content-length` set: its body `body`, its proof signing `headers` (`signed` in their place, if given) and `line`. */
async function streamed(who: Session, method: string, path: string, body: ReadableStream<Uint8Array>, options: { headers: Record<string, string>; length: number; line: string; signed?: Record<string, string> }): Promise<Sent> {
  const proof = await proofOf(who, method, `${PUBLIC_URL}${path}`, options.signed ?? options.headers, options.line);
  return read(await app.request(path, { method, headers: { ...options.headers, 'content-length': String(options.length), authorization: `DPoP ${who.token}`, dpop: proof }, body, duplex: 'half' } as RequestInit));
}

/** `bytes` as a stream of 1 MiB chunks, which waits before the chunk at `pause` until `until()` holds: what a body sent on as it comes sees. */
function chunked(bytes: Uint8Array, pause?: { at: number; until: () => boolean }): ReadableStream<Uint8Array> {
  const size = 1024 * 1024;
  let from = 0;
  return new ReadableStream({
    async pull(out) {
      if (from >= bytes.length) return out.close();
      if (pause !== undefined && from === pause.at * size) {
        for (let waited = 0; !pause.until(); waited += 10) {
          if (waited > 20_000) return out.error(new Error(`the upstream got ${received} bytes while coffre held the rest: it buffered the body`));
          await sleep(10);
        }
      }
      out.enqueue(bytes.subarray(from, from + size));
      from += size;
    },
  });
}

test('only the headers the proof signs go upstream, with the real key in place of none; the session token goes nowhere', async () => {
  const sent = await use(held, 'POST', '/use/stripe/v1/charges?expand[]=balance', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'idempotency-key': 'k-1' },
    body: 'amount=2000&currency=eur',
    added: { 'x-injected': 'by a proxy on the way', via: '1.1 middlebox' },
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const [one] = reached;
  assert.equal(one!.url, '/stripe/v1/charges?expand[]=balance');
  assert.equal(one!.headers.authorization, `Bearer ${STRIPE_KEY}`);
  assert.deepEqual([one!.headers['idempotency-key'], one!.headers['content-type']], ['k-1', 'application/x-www-form-urlencoded']);
  assert.deepEqual([one!.headers['x-injected'], one!.headers.via, one!.headers.dpop], [undefined, undefined, undefined], 'a header the proof does not sign is not forwarded');
  assert.equal(one!.sha256, sha256('amount=2000&currency=eur'));
  // The token in what goes upstream, signed by the app itself, is refused: it goes no further than coffre.
  const leaked = await use(held, 'POST', '/use/stripe/v1/notes', { headers: { 'x-note': held.token }, body: '' });
  assert.equal(leaked.status, 400, JSON.stringify(leaked.body));
  assert.match(leaked.body.message as string, /session token/);
  // Nor in the URL, as it is or escaped.
  for (const query of [`?t=${held.token}`, `?t=${held.token.replace('_', '%5F')}`]) {
    const inUrl = await use(held, 'GET', `/use/stripe/v1/notes${query}`);
    assert.equal(inUrl.status, 400, `${query}: ${JSON.stringify(inUrl.body)}`);
  }
  // Nor in an upload that streams: nothing of it reaches the upstream whole.
  const carrying = new TextEncoder().encode(`prefix ${held.token} suffix`);
  const leak = await streamed(held, 'PUT', '/use/s3/bucket/leak', new Blob([carrying]).stream(), { headers: { 'x-amz-content-sha256': sha256(carrying) }, length: carrying.length, line: sha256(carrying) });
  assert.equal(leak.status, 400, JSON.stringify(leak.body));
  // A handle sent under the DPoP scheme, as a rule that takes `DPoP {KEY}` has its app send it, is a handle's request, no
  // session's: it goes, its key in its place; an unknown one gets the handle's refusal, with no DPoP challenge.
  const handled = await app.request('/use/dpopped/v1/x', { headers: { authorization: `DPoP ${handle}` } });
  assert.equal(handled.status, 200, await handled.text());
  assert.equal(reached.at(-1)!.headers.authorization, `DPoP ${STRIPE_KEY}`);
  const unknown = await app.request('/use/dpopped/v1/x', { headers: { authorization: `DPoP coffre_use_${'h'.repeat(43)}` } });
  assert.equal(unknown.status, 401);
  assert.equal(unknown.headers.get('www-authenticate'), null, await unknown.text());
  assert.equal(reached.length, 2);
});

test('a query, a header, a path or a body changed on the way is refused, and nothing reaches the upstream', async () => {
  const base = { headers: { 'content-type': 'application/json', 'idempotency-key': 'k-1' }, body: '{"amount":2000}' };
  const query = await use(held, 'POST', '/use/stripe/v1/charges?amount=9000', { ...base, signed: { url: `${PUBLIC_URL}/use/stripe/v1/charges?amount=2000` } });
  assert.deepEqual([query.status, query.body.reason], [401, 'req']);
  const headers = await use(held, 'POST', '/use/stripe/v1/charges', { ...base, headers: { ...base.headers, 'idempotency-key': 'k-2' }, signed: { headers: base.headers } });
  assert.deepEqual([headers.status, headers.body.reason], [401, 'req']);
  const body = await use(held, 'POST', '/use/stripe/v1/charges', { ...base, body: '{"amount":9000}', signed: { body: base.body } });
  assert.deepEqual([body.status, body.body.reason], [401, 'req']);
  // Two objects to S3 under one htu: the path as sent is signed too.
  const path = await use(held, 'GET', '/use/s3/bucket//a', { signed: { url: `${PUBLIC_URL}/use/s3/bucket/a` } });
  assert.deepEqual([path.status, path.body.reason], [401, 'req']);
  assert.equal(reached.length, 0);
  assert.equal((await use(held, 'POST', '/use/stripe/v1/charges', base)).status, 200);
});

test('a streamed SigV4 upload is bound by the payload hash it declares, and signed again; UNSIGNED-PAYLOAD only where the binding says unsignedUploads', async () => {
  const bytes = new Uint8Array(64 * 1024).fill(7);
  const declared = sha256(bytes);
  const upload = (who: Session, hash: string, line: string) => streamed(who, 'PUT', '/use/s3/bucket/object', new Blob([bytes]).stream(), { headers: { 'x-amz-content-sha256': hash, 'content-type': 'application/octet-stream' }, length: bytes.length, line });
  // Its proof signs the declared hash, which the upstream checks against the bytes, signed again with the real key.
  const sent = await upload(held, declared, declared);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.deepEqual([reached[0]!.headers['x-amz-content-sha256'], reached[0]!.sha256], [declared, declared]);
  assert.match(reached[0]!.headers.authorization as string, new RegExp(`^AWS4-HMAC-SHA256 Credential=${AWS.AWS_ACCESS_KEY_ID}/`));
  // Another hash than the one signed: refused, nothing sent.
  assert.equal((await upload(held, sha256('another object'), declared)).body.reason, 'req');
  // An unsigned upload binds no body: refused unless the binding says so.
  const unsigned = await upload(held, 'UNSIGNED-PAYLOAD', UNSIGNED_BODY);
  assert.deepEqual([unsigned.status, unsigned.body.reason], [403, 'unsigned_upload']);
  assert.equal(reached.length, 1);
  // A request with no body binds its empty body, whatever its header says: a GET needs no unsignedUploads.
  assert.equal((await use(held, 'GET', '/use/s3/bucket/object', { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } })).status, 200);
  // A buffered body with its hash declared signs that hash, as a streamed one does.
  const small = 'a small object';
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/small', { headers: { 'x-amz-content-sha256': sha256(small) }, body: small, signed: { body: '' } })).body.reason, 'req');
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/small', { headers: { 'x-amz-content-sha256': sha256(small) }, body: small, signed: { line: sha256(small) } })).status, 200);
  assert.equal(reached.at(-1)!.sha256, sha256(small));
  // A copier adds the hash of the signed body to a buffered request, with other bytes: the bytes are not that hash.
  const [good, evil] = ['the body the app signed', 'the bytes a copier sent'];
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/swapped', { body: evil, signed: { body: good }, added: { 'x-amz-content-sha256': sha256(good) } })).status, 400);
  // Nor may it add the header to choose the line: the proof must sign the header that does.
  const chosen = await use(held, 'PUT', '/use/s3/bucket/swapped', { body: evil, signed: { line: sha256(evil) }, added: { 'x-amz-content-sha256': sha256(evil) } });
  assert.equal(chosen.status, 400, JSON.stringify(chosen.body));
  assert.match(chosen.body.message as string, /name it in hdr/);
  // An empty body is no body, whatever its header says: buffered, streamed with content-length 0, and as the SDK signs an empty stream.
  assert.equal((await use(held, 'PUT', '/use/s3/bucket/empty', { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: '' })).status, 200);
  const empty = await streamed(held, 'PUT', '/use/s3/bucket/prefix/', new Blob([]).stream(), { headers: { 'x-amz-content-sha256': sha256('') }, length: 0, line: await bodyDigest('') });
  assert.equal(empty.status, 200, JSON.stringify(empty.body));
  const sdk = await streamed(held, 'PUT', '/use/s3/bucket/prefix/', new Blob([]).stream(), { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, length: 0, line: await bodyLine({ declared: 'UNSIGNED-PAYLOAD', length: 0 }) });
  assert.equal(sdk.status, 200, JSON.stringify(sdk.body));
  assert.equal(reached.length, 6);
  // A binding that says unsignedUploads: its session's unsigned upload goes on, unsigned.
  const loose = binding(DEPLOY, { policy: JSON.stringify({ unsignedUploads: true }), scope: ON_PROD });
  await write(world, ...rows('bindings', loose));
  const taken = await upload(await sessionOf({ by: loose }), 'UNSIGNED-PAYLOAD', UNSIGNED_BODY);
  assert.equal(taken.status, 200, JSON.stringify(taken.body));
  assert.deepEqual([reached.at(-1)!.headers['x-amz-content-sha256'], reached.at(-1)!.sha256], ['UNSIGNED-PAYLOAD', declared]);
});

test('a 55 MB document that declares its Content-Digest streams through coffre to the upstream byte for byte, never held whole', { timeout: 120_000 }, async () => {
  const boundary = `----coffre${randomBytes(8).toString('hex')}`;
  const type = `multipart/form-data; boundary=${boundary}`;
  const body = Buffer.concat([Buffer.from(`--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="contract.pdf"\r\ncontent-type: application/pdf\r\n\r\n`), randomBytes(55_000_000), Buffer.from(`\r\n--${boundary}--\r\n`)]);
  const digest = sha256(body);
  // Declared by whoever holds the bytes, as `coffre serve` does, and streamed: the upstream has 17 MiB of it before the app
  // sends past 24 MiB, so coffre holds no more than a chunk of it at a time.
  const headers = { 'content-type': type, 'content-digest': contentDigest(digest) };
  const sent = await streamed(held, 'POST', '/use/yousign/v3/signature_requests/sr-1/documents', chunked(body, { at: 24, until: () => received >= 17 * 1024 * 1024 }), { headers, length: body.length, line: digest });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const [one] = reached;
  assert.deepEqual([one!.length, one!.sha256], [body.length, digest]);
  assert.deepEqual([one!.headers['content-digest'], one!.headers['content-type'], one!.headers['content-length'], one!.headers.authorization], [contentDigest(digest), type, String(body.length), `Bearer ${STRIPE_KEY}`]);
  assert.deepEqual(broken, []);
});

test('a body other than its Content-Digest says, short of its length, past it, or declaring it badly is refused, and the upstream never gets it whole', { timeout: 60_000 }, async () => {
  const path = '/use/yousign/v3/documents';
  const bytes = randomBytes(3 * 1024 * 1024);
  const digest = sha256(bytes);
  /** `sent` streamed, saying `length`, its proof signing `signed` headers (the digest header, unless told) and `line`. */
  const upload = (sent: Uint8Array, options: { length?: number; header?: string; signed?: Record<string, string>; line?: string } = {}) => {
    const headers = { 'content-type': 'application/pdf', 'content-digest': options.header ?? contentDigest(digest) };
    return streamed(held, 'POST', path, chunked(sent), { headers, length: options.length ?? sent.length, line: options.line ?? digest, ...(options.signed === undefined ? {} : { signed: options.signed }) });
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
  const resigned = await upload(bytes, { header: contentDigest(sha256('another document')) });
  assert.deepEqual([resigned.status, resigned.body.reason], [401, 'req']);
  assert.equal(broken.length, before, 'nothing reached the upstream of a request refused before it streams');
  assert.equal(reached.length, 0, 'the upstream got no request whole');
  assert.equal(broken.length, 3);
  assert.ok(broken.every((one) => one.length < bytes.length), JSON.stringify(broken));
  assert.ok(broken.some((one) => one.length > 1024 * 1024), 'the refused bodies streamed until their end');
  // An empty body that declares the empty body's digest, as `coffre serve` sends an empty POST: its line is that digest anyway.
  const none = await streamed(held, 'POST', path, chunked(new Uint8Array(0)), { headers: { 'content-digest': contentDigest(sha256('')) }, length: 0, line: sha256('') });
  assert.equal(none.status, 200, JSON.stringify(none.body));
  assert.equal(reached.at(-1)!.length, 0);
  // Through an AWS-signed credential, a Content-Digest alone is the payload hash coffre signs again, which S3 checks too.
  const s3 = await streamed(held, 'PUT', '/use/s3/bucket/digested', chunked(bytes), { headers: { 'content-digest': contentDigest(digest) }, length: bytes.length, line: digest });
  assert.equal(s3.status, 200, JSON.stringify(s3.body));
  assert.deepEqual([reached.at(-1)!.headers['x-amz-content-sha256'], reached.at(-1)!.sha256], [digest, digest]);
  // An app's own digest of another algorithm declares nothing: read whole, under 16 MiB, and sent on as it is.
  const sha512 = `sha-512=:${createHash('sha512').update(bytes).digest('base64')}:`;
  const own = await use(held, 'POST', path, { headers: { 'content-digest': sha512 }, body: 'a small body' });
  assert.equal(own.status, 200, JSON.stringify(own.body));
  assert.equal(reached.at(-1)!.headers['content-digest'], sha512);
  // Past 16 MiB with no digest declared: the refusal names the way through.
  const big = new Uint8Array(randomBytes(17 * 1024 * 1024));
  const refused = await read(await app.request(path, { method: 'POST', headers: { authorization: `DPoP ${held.token}`, dpop: await proofOf(held, 'POST', `${PUBLIC_URL}${path}`, {}, sha256(big)) }, body: big }));
  assert.equal(refused.status, 413);
  assert.match(refused.body.message as string, /Content-Digest: sha-256=:<base64>:, as coffre serve and @coffre\/client\/workload send it/);
  // Past 95 MiB, said by its length: refused before a byte is read.
  const huge = await upload(bytes, { length: 95 * 1024 * 1024 + 1 });
  assert.equal(huge.status, 413);
  assert.match(huge.body.message as string, /up to 95 MiB, under the 100 MB a Cloudflare zone takes/);
});

test("past a credential's limit, 429 with Retry-After and nothing sent; another credential counts apart", async () => {
  for (let i = 0; i < 3; i++) assert.equal((await use(held, 'GET', '/use/metered/v1/balance')).status, 200);
  const past = await use(held, 'GET', '/use/metered/v1/balance');
  assert.deepEqual([past.status, past.body.reason], [429, 'limit']);
  const retry = Number(past.headers.get('retry-after'));
  assert.ok(Number.isInteger(retry) && retry >= 1 && retry <= 60, `retry-after ${past.headers.get('retry-after')}`);
  assert.equal((await use(held, 'GET', '/use/metered/v1/balance')).status, 429);
  assert.equal(reached.length, 3);
  assert.equal((await use(held, 'GET', '/use/stripe/v1/balance')).status, 200);
});

test('a narrowed session is held to its constraints on the URL sent, the upstream\'s own path included', async () => {
  const child = await sessionOf({ constraints: { credentials: ['stripe'], methods: ['POST'], paths: ['/stripe/v1/refunds'] } });
  assert.equal((await use(child, 'POST', '/use/stripe/v1/refunds/re_1', { body: '' })).status, 200);
  for (const [method, path] of [['POST', '/use/stripe/v1/refunds/%2e%2e/charges'], ['POST', '/use/stripe/v1/refundsX'], ['GET', '/use/stripe/v1/refunds'], ['POST', '/use/s3/v1/refunds']] as const) {
    const refused = await use(child, method, path, method === 'POST' ? { body: '' } : {});
    assert.ok(refused.status === 403 || refused.status === 400, `${method} ${path}: ${refused.status} ${JSON.stringify(refused.body)}`);
  }
  assert.equal(reached.length, 1);
});

test('a path rule fills the first segment its template frames, whatever the app put there; the session token anywhere in the URL is refused', async () => {
  const sent = await use(held, 'POST', '/use/telegram/botcoffre/sendMessage', { headers: { 'content-type': 'application/json' }, body: '{"chat_id":1}' });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(reached[0]!.url, `/tg/bot${STRIPE_KEY}/sendMessage`);
  assert.equal((await use(held, 'GET', '/use/market/prod/telegram/file/bot0:coffre/photos/file_0.jpg')).status, 200);
  assert.equal(reached[1]!.url, `/tg/file/bot${STRIPE_KEY}/photos/file_0.jpg`);
  const none = await use(held, 'GET', '/use/telegram/getMe');
  assert.equal(none.status, 400, JSON.stringify(none.body));
  const leaked = await use(held, 'GET', `/use/telegram/botcoffre/getMe?note=${held.token}`);
  assert.equal(leaked.status, 400, JSON.stringify(leaked.body));
  assert.match(leaked.body.message as string, /session token/);
  assert.equal(reached.length, 2);
});

// A narrowed child's paths are weighed on the URL the app sent, its segment as the app wrote it, never the token's: a
// child no one could write without the token is no child at all.
test("a narrowed session's paths are weighed on the app's segment, before the token goes in", async () => {
  const send = async (paths: string[]) => use(await sessionOf({ constraints: { credentials: ['telegram'], methods: ['POST'], paths } }), 'POST', '/use/telegram/botcoffre/sendMessage', { headers: { 'content-type': 'application/json' }, body: '{"chat_id":1}' });
  const sent = await send(['/tg/botcoffre/sendMessage']);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(reached.at(-1)!.url, `/tg/bot${STRIPE_KEY}/sendMessage`);
  const refused = await send([`/tg/bot${STRIPE_KEY}/sendMessage`]);
  assert.deepEqual([refused.status, refused.body.reason], [403, 'narrowed']);
  assert.ok(!JSON.stringify(refused.body).includes(STRIPE_KEY));
  assert.equal(reached.length, 1);
});

// A relative redirect resolves against the URL the app sent, not the one the key went out in: `#top` or `""` from
// behind a query rule hands the workload back its own query, never the key (before 0.14.7 it handed back the key's).
test("a query rule's relative redirect to `#top` or `\"\"` gives a workload its own query back, never the key", async () => {
  for (const to of ['fragment', 'here']) {
    const moved = await use(held, 'GET', `/use/keyed/v1/${to}?page=2`);
    assert.equal(moved.status, 302, `${to}: ${JSON.stringify(moved.body)}`);
    assert.equal(reached.at(-1)!.url, `/keyed/v1/${to}?page=2&api_key=${STRIPE_KEY}`);
    const location = moved.headers.get('location')!;
    assert.ok(location.endsWith(`/use/keyed/v1/${to}?page=2`), location);
    assert.ok(!location.includes(STRIPE_KEY) && !decodeURIComponent(location).includes(STRIPE_KEY), location);
  }
});

test("a form or JSON rule fills its field whatever the app put there, once the proof holds for the body as sent; the Content-Digest that goes on is the new body's", async () => {
  // As the SDK and `coffre serve` send it: the body's digest declared, and signed with the rest.
  const body = '{"secret":"coffre","response":"XXXX.DUMMY.TOKEN"}';
  const sent = await use(held, 'POST', '/use/turnstile/siteverify', { headers: { 'content-type': 'application/json', 'content-digest': contentDigest(await bodyDigest(body)) }, body });
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

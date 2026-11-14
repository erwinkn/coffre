// What the app asks coffre to make with an environment's values, which it never holds (docs/design/0.16.md, "The
// proxy"): a presigned URL, a signature, a signature checked, AES-256-GCM. Each is one `use` of the vault, naming what
// makes it as its upstream, for a handle or a workload's session, and nothing is kept. That each makes what Node and
// the providers make is credential-proxy-sign, -hmac, -aes and -s3.test.ts's; here, the caller: a session's proof,
// gate and limits, a narrowed session, a revoked or frozen credential, and how long a presigned URL lasts.
import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac, generateKeyPairSync, verify } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, contentDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { amend, binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates, type Gates } from '../src/gate.ts';
import { aesGcm, credentialProxy, hmac, privateKey, sigv4 } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const pair = generateKeyPairSync('ed25519');
const SIGNING_KEY = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const WEBHOOK_SECRET = 'whsec-0123456789abcdef';
const CIPHER_KEY = Buffer.alloc(32, 9);
const AWS_ID = 'AKIAREAL0123456789AB';

const proxy = credentialProxy({
  credentials: { s3: { upstream: 'https://s3.eu-west-3.example', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) } },
  signers: { 'dfns-key': privateKey('SIGNING_KEY'), 'sumsub-key': hmac('WEBHOOK_SECRET', { encoding: 'hex' }) },
  verifiers: { webhook: hmac('WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) },
  ciphers: { tokens: aesGcm('CIPHER_KEY', { keyEncoding: 'hex', limit: { perMinute: 2 } }) },
});

let held = processGates();
const asked: string[] = [];
const gates: Gates = (service) => {
  asked.push(service);
  return held(service);
};
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates, plugins: [proxy] });
const { world } = app;
after(() => app.close());

const market = project('market');
const prod = environment(market, 'prod');
const ON_PROD = JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'developer' }]);
const b64 = (text: string | Buffer) => Buffer.from(text).toString('base64url');

let handle: string;
let handleId: string;
/** A session of the deploy service: its token, key and row. */
type Held = { token: string; key: ProofKey; id: string };
let deploy: Held;
let deployBinding: ReturnType<typeof binding>;

/** A session of the deploy service, reaching prod alone, written as `more` says. */
async function sessionOf(more: Parameters<typeof session>[2] = {}): Promise<Held> {
  const key = await generateProofKey();
  const token = generateToken('workload');
  const row = session(token, deployBinding, { jkt: await thumbprint(key.jwk), scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000), ...more });
  await write(world, ...rows('credentials', row));
  return { token, key, id: row.id };
}

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  held = processGates();
  handle = generateToken('handle');
  const handleRow = credential(handle, ADA, { kind: 'handle', scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) });
  handleId = handleRow.id;
  deployBinding = binding(DEPLOY, { policy: '{}', scope: ON_PROD });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(ADA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'developer', { project: market }), grant(DEPLOY, 'developer', { project: market })),
    ...rows('secrets',
      value(world, secret(prod, 'SIGNING_KEY'), SIGNING_KEY, { sensitive: true }), value(world, secret(prod, 'WEBHOOK_SECRET'), WEBHOOK_SECRET),
      value(world, secret(prod, 'CIPHER_KEY'), CIPHER_KEY.toString('hex')), value(world, secret(prod, 'AWS_ACCESS_KEY_ID'), AWS_ID, { plain: true }), value(world, secret(prod, 'AWS_SECRET_ACCESS_KEY'), 'aws-real-secret')),
    ...rows('bindings', deployBinding),
    ...rows('credentials', handleRow),
  );
  deploy = await sessionOf();
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  await world.owner.execute(sql`DELETE FROM log_pending`);
  app.calls.length = 0;
  asked.length = 0;
});

/** What a request cost: its answer, the vault's calls, the app's statements and the gates asked. */
async function cost(run: () => Promise<Response>): Promise<[Response, string[], number, string[]]> {
  const [calls, statements, gated] = [app.calls.length, app.statements, asked.length];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements, asked.slice(gated)];
}

const failed = async (response: Response) => [response.status, ((await response.clone().json()) as { reason?: string }).reason];
const json = async <T = Record<string, unknown>>(response: Response): Promise<T> => {
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as T;
};

/** An ask as the handle's holder sends it, `credential(name)`'s way: the handle its bearer token. */
const asHandle = (body: unknown, path = '/use/market/prod') => app.request(path, { method: 'POST', headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });

/** An ask as a session sends it, its proof signing the body (`signed`, unless told another) under the gate's nonce. */
async function asSession(who: Held, body: unknown, path = '/use', options: { signed?: unknown } = {}): Promise<Response> {
  const bytes = Buffer.from(JSON.stringify(body));
  const signedBytes = options.signed === undefined ? bytes : Buffer.from(JSON.stringify(options.signed));
  const headers = { 'content-type': 'application/json' };
  const proof = await createProof(who.key, { method: 'POST', url: `${PUBLIC_URL}${path}`, token: who.token, nonce: await held(DEPLOY).nonce(), content: { headers, body: await bodyDigest(signedBytes) } });
  return app.request(path, { method: 'POST', headers: { authorization: `DPoP ${who.token}`, dpop: proof, ...headers }, body: bytes });
}

/** The vault's log entries not yet signed in: the credential each names. */
async function logged(): Promise<(string | undefined)[]> {
  const bodies = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`);
  return bodies.map(({ body }) => (JSON.parse(body) as { detail: { credential?: string } }).detail.credential);
}

/** As a request a moment later, past the vault's memory (two seconds). */
const later = () => {
  world.memory.reads.clear();
  world.memory.callers.clear();
};

const SIGN = { sign: { credential: 'dfns-key', message: b64('transfer 10') } };
const ASKS = {
  presign: { presign: { credential: 's3', path: '/bucket/report.pdf', expiresIn: 60 } },
  sign: SIGN,
  hmac: { sign: { credential: 'sumsub-key', message: b64('hello') } },
  verify: { verify: { credential: 'webhook', message: b64('{"event":"paid"}'), signature: `sha256=${createHmac('sha256', WEBHOOK_SECRET).update('{"event":"paid"}').digest('hex')}` } },
  encrypt: { encrypt: { credential: 'tokens', plaintext: b64('pennylane-token'), aad: b64('workspace-1') } },
};

test("a session's ask: one statement routes it, its gate takes the proof once, then one use; each makes what a handle's does, logged under its name", async () => {
  const made: Record<string, Record<string, unknown>> = {};
  for (const [name, body] of Object.entries(ASKS)) {
    for (const path of ['/use', '/use/market/prod']) {
      const [answer, calls, statements, gated] = await cost(() => asSession(deploy, body, path));
      made[name] = await json(answer);
      assert.deepEqual([calls, statements, gated], [['use'], 1, [DEPLOY]], `${name} at ${path}`);
      assert.equal(answer.headers.get('dpop-nonce'), await held(DEPLOY).nonce());
    }
  }
  assert.match(made.presign!.url as string, new RegExp(`^https://s3\\.eu-west-3\\.example/bucket/report\\.pdf\\?.*X-Amz-Credential=${AWS_ID}`));
  assert.ok(verify(undefined, Buffer.from('transfer 10'), pair.publicKey, Buffer.from(made.sign!.signature as string, 'base64url')));
  assert.equal(made.hmac!.signature, createHmac('sha256', WEBHOOK_SECRET).update('hello').digest('hex'));
  assert.equal(made.verify!.valid, true);
  const { iv, ciphertext, tag } = made.encrypt as { iv: string; ciphertext: string; tag: string };
  const decipher = createDecipheriv('aes-256-gcm', CIPHER_KEY, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from('workspace-1'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  assert.equal(Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]).toString(), 'pennylane-token');
  // Each logged once a minute under its own name, by the vault; nothing of what was signed, checked or encrypted.
  assert.deepEqual(await logged(), ['s3', 'dfns-key', 'sumsub-key', 'tokens']);
  const text = (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending`)).map((row) => row.body).join('\n');
  for (const leaked of ['transfer 10', 'pennylane', WEBHOOK_SECRET, b64('transfer 10')]) assert.ok(!text.includes(leaked), leaked);
  // A handle's, the same: one use, and no statement where it names its place.
  const [answer, calls, statements] = await cost(() => asHandle(SIGN));
  assert.ok(verify(undefined, Buffer.from('transfer 10'), pair.publicKey, Buffer.from((await json(answer)).signature as string, 'base64url')));
  assert.deepEqual([calls, statements], [['use'], 0]);
});

test('the proof signs what is asked: another message under it, or none, is refused, and the vault hears nothing', async () => {
  const other = { sign: { credential: 'dfns-key', message: b64('transfer 9999') } };
  const [refused, calls] = await cost(() => asSession(deploy, other, '/use', { signed: SIGN }));
  assert.deepEqual([...(await failed(refused)), calls], [401, 'req', []]);
  // A handle names its place: `POST /use` is a workload's alone.
  const [unnamed, unnamedCalls] = await cost(() => asHandle(SIGN, '/use'));
  assert.deepEqual([(await failed(unnamed))[0], unnamedCalls], [405, []]);
  const [nobody, nobodyCalls] = await cost(() => app.request('/use/market/prod', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(SIGN) }));
  assert.deepEqual([(await failed(nobody))[0], nobodyCalls], [401, []]);
});

test("a session's raw message is bound by its Content-Digest, which its proof signs; other bytes, or none declared, sign nothing", async () => {
  const body = Buffer.from('1761480000POST/resources/applicants/abc/info/idDoc');
  const digest = createHash('sha256').update(body).digest('hex');
  const url = `${PUBLIC_URL}/use?sign=sumsub-key`;
  const raw = async (bytes: Buffer, headers: Record<string, string>, signed = headers) => {
    const proof = await createProof(deploy.key, { method: 'POST', url, token: deploy.token, nonce: await held(DEPLOY).nonce(), content: { headers: signed, body: digest } });
    return app.request('/use?sign=sumsub-key', { method: 'POST', headers: { authorization: `DPoP ${deploy.token}`, dpop: proof, 'content-type': 'application/octet-stream', 'content-length': String(bytes.length), ...headers }, body: new Uint8Array(bytes) });
  };
  const declared = { 'content-digest': contentDigest(digest) };
  const [signed, calls, statements] = await cost(() => raw(body, declared));
  assert.equal((await json(signed)).signature, createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex'));
  assert.deepEqual([calls, statements], [['use'], 1]);
  // None declared: refused before anyone is asked.
  const [undeclared, undeclaredCalls] = await cost(() => raw(body, {}));
  assert.deepEqual([(await failed(undeclared))[0], undeclaredCalls], [400, []]);
  // Declared, and not among what the proof signs: refused before the secret is opened.
  const [unsigned, unsignedCalls] = await cost(() => raw(body, { ...declared, 'x-other': 'one' }, { 'x-other': 'one' }));
  assert.deepEqual([(await failed(unsigned))[0], unsignedCalls], [400, []]);
  // Other bytes than the digest says, of the same length: opened, and nothing signed.
  const tampered = Buffer.from(body);
  tampered[0] = 0x30;
  const [other, otherCalls] = await cost(() => raw(tampered, declared));
  assert.deepEqual([(await failed(other))[0], otherCalls], [400, ['use']]);
});

test("a cipher's limit is the gate's: past it, 429 and nothing opened", async () => {
  for (let i = 0; i < 2; i++) await json(await asSession(deploy, ASKS.encrypt));
  const [limited, calls] = await cost(() => asSession(deploy, ASKS.encrypt));
  assert.deepEqual([...(await failed(limited)), calls], [429, 'limit', []]);
  // A handle's is no workload's: no limit.
  for (let i = 0; i < 3; i++) await json(await asHandle(ASKS.encrypt));
});

test("a narrowed session makes nothing past its limits: the vault holds it to its credentials, the app to its methods and paths", async () => {
  const narrowed = (constraints: object) => sessionOf({ ancestors: JSON.stringify([deploy.id]), constraints: JSON.stringify(constraints) });
  // Narrowed to s3: every signer, verifier and cipher is refused by the vault, at its use.
  const s3Only = await narrowed({ credentials: ['s3'] });
  for (const name of ['sign', 'hmac', 'verify', 'encrypt'] as const) {
    const [refused, calls] = await cost(() => asSession(s3Only, ASKS[name]));
    assert.deepEqual([(await failed(refused))[0], calls], [403, ['use']], name);
  }
  // Narrowed to paths: a presigned URL within them only, and nothing signed, there being no request to hold them to.
  const paths = await narrowed({ credentials: ['s3', 'dfns-key'], methods: ['GET'], paths: ['/bucket/public'] });
  await json(await asSession(paths, { presign: { credential: 's3', path: '/bucket/public/a.pdf' } }));
  for (const body of [{ presign: { credential: 's3', path: '/bucket/private/a.pdf' } }, { presign: { credential: 's3', path: '/bucket/public/a.pdf', method: 'HEAD' } }, SIGN]) {
    const [refused, calls] = await cost(() => asSession(paths, body));
    assert.deepEqual([...(await failed(refused)), calls], [403, 'narrowed', ['use']], JSON.stringify(body));
  }
});

test('a revoked handle, or a signer frozen in its place, makes nothing at its next ask; nothing is kept to make it', async () => {
  await json(await asHandle(SIGN));
  await amend(world, 'environments', sql`id = ${prod.id}`, { frozenCredentials: ['dfns-key'] });
  later();
  for (const ask of [() => asHandle(SIGN), () => asSession(deploy, SIGN)]) assert.equal((await failed(await ask()))[0], 403);
  // Frozen by name: another signer of the same place still signs.
  await json(await asHandle(ASKS.hmac));
  await amend(world, 'credentials', sql`id = ${handleId}`, { revokedAt: new Date(), revokedBy: ADA });
  later();
  const [revoked, calls] = await cost(() => asHandle(ASKS.hmac));
  assert.deepEqual([(await failed(revoked))[0], calls], [401, ['use']]);
});

test("a presigned URL lasts no longer than its credential's end, the vault's word: a handle's, a session's hard end, a session above it's", async () => {
  const lasting = async (answer: Response) => {
    const { url, expiresAt } = await json<{ url: string; expiresAt: string }>(answer);
    return { seconds: Number(new URL(url).searchParams.get('X-Amz-Expires')), expiresAt: Date.parse(expiresAt) };
  };
  const PRESIGN = { presign: { credential: 's3', path: '/bucket/report.pdf', expiresIn: 3600 } };
  // As asked, within the hour and the handle's.
  assert.equal((await lasting(await asHandle({ presign: { ...PRESIGN.presign, expiresIn: 900 } }))).seconds, 900);
  const end = Date.now() + 120_000;
  await amend(world, 'credentials', sql`id = ${handleId}`, { expiresAt: new Date(end) });
  later();
  const capped = await lasting(await asHandle(PRESIGN));
  assert.ok(capped.seconds <= 120 && capped.seconds >= 118, String(capped.seconds));
  assert.ok(capped.expiresAt <= end);
  // A session's hard end comes first; and a narrowed one's, the end of the session above it.
  const brief = await sessionOf({ notAfter: new Date(Date.now() + 60_000) });
  assert.ok((await lasting(await asSession(brief, PRESIGN))).seconds <= 60);
  await amend(world, 'credentials', sql`id = ${deploy.id}`, { notAfter: new Date(Date.now() + 30_000) });
  const child = await sessionOf({ ancestors: JSON.stringify([deploy.id]) });
  later();
  assert.ok((await lasting(await asSession(child, PRESIGN))).seconds <= 30);
  // A handle that ends within the second presigns nothing.
  await amend(world, 'credentials', sql`id = ${handleId}`, { expiresAt: new Date(Date.now() + 500) });
  later();
  assert.equal((await failed(await asHandle(PRESIGN)))[0], 401);
});

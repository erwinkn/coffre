// S3 through the credential proxy (docs/design/credential-proxy.md, "S3 and
// SigV4"): the AWS SDK signs with the handle as its access key, at the
// proxy's endpoint, and the proxy discards that signature and signs again
// with the real keys, for the upstream. The fake S3 here checks each request
// with the SDK's own signer (`@smithy/signature-v4`) under the real secret,
// as S3 would, and keeps objects in memory; MinIO in Docker did the same by
// hand (the design's section 5).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, type Hash, type Hmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { SignatureV4 } from '@smithy/signature-v4';
import { contentDigest } from '@coffre/client/dpop';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, sigv4 } from '../src/plugins/credential-proxy.ts';
import { presignV4, signV4 } from '../src/plugins/sigv4.ts';

const ACCESS_KEY_ID = 'AKIAREALKEY000000001';
const SECRET = 'real/secret+access/key0123456789ABCDEFGH';
const REGION = 'eu-west-3';

let s3: Server;
let s3Url: string;
let coffre: Server;
let coffreUrl: string;
const objects = new Map<string, string>();
const seen: { method: string; url: string; verified: boolean; authorization: string; hash: string }[] = [];

/** SHA-256 and its HMAC, as the SDK's signer takes a hash. */
/** What the signer hands a hash: a string, or bytes in any view. */
type SourceData = string | ArrayBuffer | ArrayBufferView;
const bytes = (data: SourceData) => (typeof data === 'string' ? data : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data));

class Sha256 {
  readonly #hash: Hash | Hmac;
  constructor(secret?: SourceData) {
    this.#hash = secret === undefined ? createHash('sha256') : createHmac('sha256', bytes(secret));
  }
  update(data: SourceData): void {
    this.#hash.update(bytes(data));
  }
  async digest(): Promise<Uint8Array> {
    return new Uint8Array(this.#hash.digest());
  }
}

/** Whether S3 would take the request: its signature, recomputed with the real secret. */
async function verified(request: IncomingMessage, body: Buffer): Promise<boolean> {
  const authorization = request.headers.authorization ?? '';
  const signedHeaders = /SignedHeaders=([^,]+)/.exec(authorization)?.[1]?.split(';') ?? [];
  if (!authorization.includes(`Credential=${ACCESS_KEY_ID}/`)) return false;
  const url = new URL(request.url!, s3Url);
  const headers: Record<string, string> = {};
  for (const name of signedHeaders) headers[name] = String(request.headers[name]);
  const signer = new SignatureV4({ credentials: { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET }, region: REGION, service: 's3', sha256: Sha256, uriEscapePath: false, applyChecksum: false });
  const stamp = String(request.headers['x-amz-date']);
  const date = new Date(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`);
  const query: Record<string, string> = {};
  for (const [name, value] of url.searchParams) query[name] = value;
  const expected = await signer.sign(
    { method: request.method!, protocol: 'http:', hostname: url.hostname, port: Number(url.port), path: url.pathname, query, headers, body },
    { signingDate: date, unsignableHeaders: new Set(), signableHeaders: new Set(signedHeaders) },
  );
  const hash = String(request.headers['x-amz-content-sha256']);
  const bodyOk = hash === 'UNSIGNED-PAYLOAD' || hash === createHash('sha256').update(body).digest('hex');
  return bodyOk && expected.headers.authorization === authorization;
}

before(async () => {
  s3 = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    try {
      for await (const chunk of request) chunks.push(chunk as Buffer);
    } catch {
      // An upload the proxy stopped mid-way: S3 stores nothing of it.
      return;
    }
    const body = Buffer.concat(chunks);
    const ok = await verified(request, body);
    seen.push({ method: request.method!, url: request.url!, verified: ok, authorization: request.headers.authorization ?? '', hash: String(request.headers['x-amz-content-sha256']) });
    if (!ok) return response.writeHead(403, { 'content-type': 'application/xml' }).end('<Error><Code>SignatureDoesNotMatch</Code></Error>');
    const url = new URL(request.url!, s3Url);
    const [, bucket, ...segments] = url.pathname.split('/');
    const key = segments.map(decodeURIComponent).filter((segment, i) => segment !== '' || i < segments.length - 1);
    if (request.method === 'PUT') {
      objects.set(`${bucket}/${key.join('/')}`, body.length > 1024 * 1024 ? `${body.length} bytes` : body.toString());
      return response.writeHead(200, { etag: '"e"' }).end();
    }
    if (request.method === 'GET' && key.length > 0) {
      const object = objects.get(`${bucket}/${key.join('/')}`);
      return object === undefined ? response.writeHead(404).end() : response.writeHead(200, { 'content-type': 'text/plain' }).end(object);
    }
    if (request.method === 'GET' && url.searchParams.get('list-type') === '2') {
      const keys = [...objects.keys()].filter((name) => name.startsWith(`${bucket}/`)).map((name) => name.slice(bucket!.length + 1));
      const xml = `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>${bucket}</Name><KeyCount>${keys.length}</KeyCount><IsTruncated>false</IsTruncated>${keys.map((name) => `<Contents><Key>${name}</Key></Contents>`).join('')}</ListBucketResult>`;
      return response.writeHead(200, { 'content-type': 'application/xml' }).end(xml);
    }
    response.writeHead(400).end();
  });
  await new Promise<void>((resolve) => s3.listen(0, '127.0.0.1', resolve));
  s3Url = `http://127.0.0.1:${(s3.address() as AddressInfo).port}`;
  // coffre over HTTP, as the SDK reaches it: each request handed to its routes as it came.
  coffre = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) if (typeof value === 'string') headers.set(name, value);
    const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
    const answer = (await coffreRoute(new Request(`${ORIGIN}${request.url}`, { method: request.method, headers, body }), runtime, '127.0.0.1'))!;
    response.writeHead(answer.status, Object.fromEntries(answer.headers));
    response.end(Buffer.from(await answer.arrayBuffer()));
  });
  await new Promise<void>((resolve) => coffre.listen(0, '127.0.0.1', resolve));
  coffreUrl = `http://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => s3.close(() => resolve()));
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
});

useMcp(
  async () => {
    runtime.plugins = checkPlugins([
      credentialProxy({
        credentials: {
          s3: {
            upstream: s3Url,
            inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: REGION, service: 's3' }),
          },
        },
        insecureUpstreams: true,
      }),
    ]);
    objects.clear();
    seen.length = 0;
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { AWS_ACCESS_KEY_ID: ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY: { value: SECRET, sensitivity: 'sensitive' } });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
  },
);

/** The app's S3 client, its keys from what `coffre run` gave it and its endpoint the proxy's stable URL, as an app configures one for MinIO. */
async function appClient(): Promise<{ client: S3Client; handle: string }> {
  const handle = (await (await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) })).json() as { token: string }).token;
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string> };
  assert.equal(plan.env.AWS_ACCESS_KEY_ID, handle);
  const client = new S3Client({
    region: REGION,
    // The app's own config: `<publicUrl>/use/s3`, which the test's coffre, on loopback, answers.
    endpoint: `${coffreUrl}/use/s3`,
    forcePathStyle: true,
    credentials: { accessKeyId: plan.env.AWS_ACCESS_KEY_ID!, secretAccessKey: plan.env.AWS_SECRET_ACCESS_KEY! },
    // No aws-chunked uploads: their chunk signatures chain from one only the real key makes.
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  });
  return { client, handle };
}

test('put, get and list through the proxy: the SDK signs with the handle, S3 sees the real key and a signature that verifies', async () => {
  const { client, handle } = await appClient();
  await client.send(new PutObjectCommand({ Bucket: 'uploads', Key: 'kyc/a b+c.txt', Body: 'hello s3', ContentType: 'text/plain' }));
  const got = await client.send(new GetObjectCommand({ Bucket: 'uploads', Key: 'kyc/a b+c.txt' }));
  assert.equal(await got.Body!.transformToString(), 'hello s3');
  const listed = await client.send(new ListObjectsV2Command({ Bucket: 'uploads', Prefix: 'kyc/' }));
  assert.deepEqual(listed.Contents?.map((object) => object.Key), ['kyc/a b+c.txt']);

  // A client that sends no payload hash, as a bare fetch to an AWS API would: signed with the empty body's SHA-256.
  const bare = await route('/use/market/dev/s3/uploads/?list-type=2', { headers: { authorization: `AWS4-HMAC-SHA256 Credential=${handle}/20261018/${REGION}/s3/aws4_request, SignedHeaders=host, Signature=00` } });
  assert.equal(bare.status, 200);
  assert.equal(seen.at(-1)!.hash, createHash('sha256').update('').digest('hex'));

  assert.equal(seen.length, 4);
  assert.ok(seen.every((request) => request.verified), JSON.stringify(seen));
  assert.ok(seen.every((request) => !request.authorization.includes(handle)), 'the handle never reaches S3');
  // One opening of the pair for the minute.
  const uses = await entries('credential.use');
  assert.deepEqual(uses.filter((entry) => entry.metadata.credential === 's3').map((entry) => entry.metadata.keys), [['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']]);
});

test("aws-chunked uploads and presigned URLs are refused, before anything reaches S3", async () => {
  const { handle } = await appClient();
  const chunked = await route('/use/market/dev/s3/uploads/x', {
    method: 'PUT',
    headers: { authorization: `AWS4-HMAC-SHA256 Credential=${handle}/20261018/${REGION}/s3/aws4_request, SignedHeaders=host, Signature=00`, 'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD', 'content-encoding': 'aws-chunked' },
    body: 'x',
  });
  assert.equal(chunked.status, 400);
  assert.match(await chunked.text(), /aws-chunked|STREAMING/);
  const presigned = await route(`/use/market/dev/s3/uploads/x?X-Amz-Credential=${handle}%2F20261018%2F${REGION}%2Fs3%2Faws4_request&X-Amz-Signature=00`);
  assert.equal(presigned.status, 400);
  assert.equal(seen.length, 0);
});

test("coffre's signer signs as the AWS SDK's does: S3's path encoded once, another service's twice, header whitespace AWS's way", async () => {
  const date = new Date('2026-10-18T10:00:00Z');
  const cases = [
    ['s3', '/uploads/a%20b%2Bc/%C3%A9t%C3%A9.txt'],
    ['s3', '/uploads/a//b/'],
    ['execute-api', '/prod/a%20b/c%2Bd'],
    ['execute-api', '/prod/a//b/'],
    ['execute-api', '/prod/a+b/c@d=e/%7e/./x/../y'],
  ] as const;
  for (const [service, path] of cases) {
    const url = new URL(`https://upstream.example${path}?b=2&a=1&empty=&a=0`);
    const headers = new Headers({ 'content-type': 'text/plain', 'x-amz-meta-description': '  a b \t c  ', 'x-amz-user-agent': 'aws-sdk-js/3' });
    await signV4('PUT', url, headers, 'UNSIGNED-PAYLOAD', { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, sessionToken: 'session-token' }, { region: REGION, service }, date);
    const signedHeaders = /SignedHeaders=([^,]+)/.exec(headers.get('authorization')!)![1]!.split(';');
    const signer = new SignatureV4({ credentials: { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, sessionToken: 'session-token' }, region: REGION, service, sha256: Sha256, uriEscapePath: service !== 's3', applyChecksum: false });
    const query: Record<string, string | string[]> = {};
    for (const [name, value] of url.searchParams) query[name] = name in query ? [query[name]!, value].flat() : value;
    const sent: Record<string, string> = { host: url.host };
    for (const name of signedHeaders) if (name !== 'host') sent[name] = headers.get(name)!;
    const expected = await signer.sign({ method: 'PUT', protocol: 'https:', hostname: url.hostname, path: url.pathname, query, headers: sent }, { signingDate: date, signableHeaders: new Set(signedHeaders) });
    assert.equal(headers.get('authorization'), expected.headers.authorization, `${service} ${path}`);
  }
});

test('a key no header can carry is refused, and quoted nowhere', async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: { s3: { upstream: s3Url, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: '{AWS_SESSION_TOKEN}', region: REGION, service: 's3' }) } }, insecureUpstreams: true })]);
  await clientFor(deps, ROOT).secrets.set('market/dev', { AWS_SESSION_TOKEN: 'token-line\nbreak-0123456789' });
  const { handle } = await appClient();
  const logged: unknown[] = [];
  const error = console.error;
  console.error = (...args: unknown[]) => void logged.push(...args);
  let answer: Response;
  try {
    answer = await route('/use/market/dev/s3/uploads/x', { headers: { authorization: `AWS4-HMAC-SHA256 Credential=${handle}/20261018/${REGION}/s3/aws4_request, SignedHeaders=host, Signature=00`, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } });
  } finally {
    console.error = error;
  }
  assert.equal(answer.status, 409);
  assert.equal(JSON.stringify([await answer.text(), logged.map(String)]).includes('0123456789'), false);
  assert.equal(seen.length, 0);
});

test("coffre's presigned URLs are the AWS SDK's own, byte for byte", async () => {
  const date = new Date('2026-10-18T10:00:00Z');
  for (const [service, path, query] of [['s3', '/uploads/kyc/a%20b%2Bc.pdf', { 'response-content-disposition': 'attachment; filename="a b.pdf"' }], ['s3', '/uploads/x', {}]] as const) {
    const url = new URL(`https://upstream.example${path}`);
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
    const ours = await presignV4('GET', url, { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, sessionToken: 'session-token' }, { region: REGION, service }, 300, date);
    const signer = new SignatureV4({ credentials: { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, sessionToken: 'session-token' }, region: REGION, service, sha256: Sha256, uriEscapePath: false, applyChecksum: false });
    // As the SDK's S3 presigner asks it: the payload unsigned, said in a header it does not sign.
    const theirs = await signer.presign({ method: 'GET', protocol: 'https:', hostname: url.hostname, path: url.pathname, query: { ...query }, headers: { host: url.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } }, { signingDate: date, expiresIn: 300, unsignableHeaders: new Set(['x-amz-content-sha256']), unhoistableHeaders: new Set(['x-amz-content-sha256']) });
    assert.equal(ours.searchParams.get('X-Amz-Signature'), theirs.query!['X-Amz-Signature'], path);
    assert.equal(ours.searchParams.get('X-Amz-Credential'), theirs.query!['X-Amz-Credential']);
  }
  // Another service signs the empty body a GET has, as the SDK's own presigner does with no payload hash said.
  const api = new URL('https://abc.execute-api.eu-west-3.amazonaws.com/prod/a%20b');
  const ours = await presignV4('GET', api, { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET }, { region: REGION, service: 'execute-api' }, 300, date);
  const signer = new SignatureV4({ credentials: { accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET }, region: REGION, service: 'execute-api', sha256: Sha256, uriEscapePath: true, applyChecksum: false });
  const theirs = await signer.presign({ method: 'GET', protocol: 'https:', hostname: api.hostname, path: api.pathname, query: {}, headers: { host: api.host } }, { signingDate: date, expiresIn: 300 });
  assert.equal(ours.searchParams.get('X-Amz-Signature'), theirs.query!['X-Amz-Signature'], 'execute-api');
});

test('the app asks coffre to presign a GET: the URL is the upstream\'s, with the real key\'s id, for as long as asked, logged as a use', async () => {
  const { handle } = await appClient();
  const ask = (presign: Record<string, unknown>, token = handle) =>
    route('/use/market/dev', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ presign }) });
  const answer = await ask({ credential: 's3', path: '/uploads/kyc/a%20b.pdf', expiresIn: 300, query: { 'response-content-disposition': 'attachment' } });
  assert.equal(answer.status, 200, await answer.clone().text());
  const { url, expiresAt } = (await answer.json()) as { url: string; expiresAt: string };
  const presigned = new URL(url);
  assert.equal(presigned.origin, new URL(s3Url).origin, 'the upstream itself, not the proxy');
  assert.equal(presigned.pathname, '/uploads/kyc/a%20b.pdf');
  assert.match(presigned.searchParams.get('X-Amz-Credential')!, new RegExp(`^${ACCESS_KEY_ID}/`));
  assert.equal(presigned.searchParams.get('X-Amz-Expires'), '300');
  assert.equal(url.includes(SECRET) || url.includes(handle), false, 'neither the secret nor the handle');
  assert.ok(Math.abs(Date.parse(expiresAt) - Date.now() - 300_000) < 5000);
  const [use] = (await entries('credential.use')).filter((entry) => entry.metadata.presign !== undefined);
  assert.deepEqual(use!.metadata.presign, { method: 'GET', path: '/uploads/kyc/a%20b.pdf', expiresIn: 300 });

  // What it does not sign: an upload, a long life, a path outside, a credential that does not sign, or without the handle.
  assert.equal((await ask({ credential: 's3', path: '/uploads/x', method: 'PUT' })).status, 400);
  assert.equal((await ask({ credential: 's3', path: '/uploads/x', expiresIn: 86_400 })).status, 400);
  assert.equal((await ask({ credential: 's3', path: '/uploads/%2e%2e/x' })).status, 400);
  // A tab or a line break inside an encoded slash or backslash, which the URL would drop, joining it again.
  for (const path of ['/uploads/..%2\tfprivate', '/uploads/..%5\ncprivate', '/uploads/a\rb']) assert.equal((await ask({ credential: 's3', path })).status, 400, JSON.stringify(path));
  assert.equal((await ask({ credential: 's3', path: '/uploads/x?X-Amz-Expires=99' })).status, 400);
  assert.equal((await ask({ credential: 's3', path: '/uploads/x', query: { 'X-Amz-Expires': '99' } })).status, 400);
  assert.equal((await ask({ credential: 'nope', path: '/uploads/x' })).status, 404);
  // No URL to share carries the handle, in its path or its query.
  assert.equal((await ask({ credential: 's3', path: `/uploads/${handle}` })).status, 400);
  assert.equal((await ask({ credential: 's3', path: '/uploads/x', query: { 'response-content-disposition': `attachment; filename=${handle}` } })).status, 400);
  // Encoded, beside a byte that is no UTF-8: still the handle.
  assert.equal((await ask({ credential: 's3', path: `/uploads/%FF/${handle.replace('_', '%5F')}` })).status, 400);
  assert.equal((await route('/use/market/dev', { method: 'POST', body: JSON.stringify({ presign: { credential: 's3', path: '/x' } }) })).status, 401);
});

test('a streamed upload sends nothing of a handle split across chunks, and nothing past or short of its declared length', async () => {
  const { handle } = await appClient();
  const upload = (parts: Uint8Array[], declared: number, gap = 0) => {
    const body = new ReadableStream<Uint8Array>({
      async start(controller) {
        for (const part of parts) {
          controller.enqueue(part);
          if (gap > 0) await new Promise((resolve) => setTimeout(resolve, gap));
        }
        controller.close();
      },
    });
    return route('/use/market/dev/s3/uploads/streamed', {
      method: 'PUT',
      headers: { authorization: `AWS4-HMAC-SHA256 Credential=${handle}/20261018/${REGION}/s3/aws4_request, SignedHeaders=host, Signature=00`, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD', 'content-length': String(declared) },
      body,
      duplex: 'half',
    } as RequestInit);
  };
  const bytes = new TextEncoder().encode(`data:${handle}:end`);
  const cut = 5 + handle.length - 1;
  assert.notEqual((await upload([bytes.slice(0, cut), bytes.slice(cut)], bytes.length, 20)).status, 200);
  assert.equal(objects.has('uploads/streamed'), false, 'nothing stored');
  const four = new TextEncoder().encode('abcd');
  assert.notEqual((await upload([four, new TextEncoder().encode('e')], 4, 20)).status, 200, 'a byte past the length declared');
  assert.notEqual((await upload([four], 5)).status, 200, 'short of it');
  assert.equal(objects.has('uploads/streamed'), false);
  assert.equal((await upload([four], 4)).status, 200, 'exactly as declared');
  assert.equal(objects.get('uploads/streamed'), 'abcd');
});

test("a handle's upload past 16 MiB that declares its Content-Digest streams, S3 checking that digest too; other bytes, or the handle split across chunks, never reach it whole", async () => {
  const { handle } = await appClient();
  const upload = (key: string, bytes: Buffer, declared: Buffer = bytes, cut = 1024 * 1024) => {
    let at = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(out) {
        if (at >= bytes.length) return out.close();
        // At `cut`, then each MiB: a boundary the test places.
        const end = at < cut ? cut : at + 1024 * 1024;
        out.enqueue(bytes.subarray(at, end));
        at = end;
      },
    });
    return route(`/use/market/dev/s3/uploads/${key}`, {
      method: 'PUT',
      headers: {
        authorization: `AWS4-HMAC-SHA256 Credential=${handle}/20261018/${REGION}/s3/aws4_request, SignedHeaders=host, Signature=00`,
        'content-digest': contentDigest(createHash('sha256').update(declared).digest('hex')),
        'content-length': String(bytes.length),
      },
      body,
      duplex: 'half',
    } as RequestInit);
  };
  const document = randomBytes(20 * 1024 * 1024);
  const sent = await upload('digested.pdf', document);
  assert.equal(sent.status, 200, await sent.text());
  assert.equal(objects.get('uploads/digested.pdf'), `${document.length} bytes`);
  assert.ok(seen.at(-1)!.verified);
  assert.equal(seen.at(-1)!.hash, createHash('sha256').update(document).digest('hex'), 'signed with the digest it declared');
  const tampered = Buffer.from(document);
  tampered[12345] = tampered[12345]! ^ 1;
  const swapped = await upload('tampered.pdf', tampered, document);
  assert.deepEqual([swapped.status, ((await swapped.json()) as { message: string }).message], [400, 'the body is not what its Content-Digest says']);
  const carrying = Buffer.concat([document.subarray(0, 3 * 1024 * 1024), Buffer.from(handle), document.subarray(3 * 1024 * 1024)]);
  const leaked = await upload('leaked.pdf', carrying, carrying, 3 * 1024 * 1024 + 20);
  assert.deepEqual([leaked.status, ((await leaked.json()) as { message: string }).message], [400, 'the handle is in the body']);
  assert.equal(objects.has('uploads/tampered.pdf') || objects.has('uploads/leaked.pdf'), false, 'S3 stored neither');
});

test('an upload past what the proxy holds streams through: 20 MiB, signed again, the handle nowhere in it', async () => {
  const { client } = await appClient();
  const big = Buffer.alloc(20 * 1024 * 1024, 7);
  await client.send(new PutObjectCommand({ Bucket: 'uploads', Key: 'big.bin', Body: big, ContentLength: big.length }));
  assert.equal(objects.get('uploads/big.bin'), `${big.length} bytes`);
  assert.ok(seen.at(-1)!.verified);
});

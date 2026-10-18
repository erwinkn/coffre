// S3 through the credential proxy (docs/design/credential-proxy.md, "S3 and
// SigV4"): the AWS SDK signs with the handle as its access key, at the
// proxy's endpoint, and the proxy discards that signature and signs again
// with the real keys, for the upstream. The fake S3 here checks each request
// with the SDK's own signer (`@smithy/signature-v4`) under the real secret,
// as S3 would, and keeps objects in memory; MinIO in Docker did the same by
// hand (the design's section 5).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { SignatureV4 } from '@smithy/signature-v4';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, sigv4 } from '../src/plugins/credential-proxy.ts';

const ACCESS_KEY_ID = 'AKIAREALKEY000000001';
const SECRET = 'real/secret+access/key0123456789ABCDEFGH';
const REGION = 'eu-west-3';

let s3: Server;
let s3Url: string;
let coffre: Server;
let coffreUrl: string;
const objects = new Map<string, string>();
const seen: { method: string; url: string; verified: boolean; authorization: string }[] = [];

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
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const body = Buffer.concat(chunks);
    const ok = await verified(request, body);
    seen.push({ method: request.method!, url: request.url!, verified: ok, authorization: request.headers.authorization ?? '' });
    if (!ok) return response.writeHead(403, { 'content-type': 'application/xml' }).end('<Error><Code>SignatureDoesNotMatch</Code></Error>');
    const url = new URL(request.url!, s3Url);
    const [, bucket, ...segments] = url.pathname.split('/');
    const key = segments.map(decodeURIComponent).filter((segment, i) => segment !== '' || i < segments.length - 1);
    if (request.method === 'PUT') {
      objects.set(`${bucket}/${key.join('/')}`, body.toString());
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
            baseUrl: 'AWS_ENDPOINT_URL_S3',
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
    await root.secrets.set('market/dev', { AWS_ACCESS_KEY_ID: ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY: SECRET });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
  },
  { people: 'stand-ins' },
);

/** The app's S3 client, configured from what `coffre run` gave it, as an app configures one for MinIO. */
async function appClient(): Promise<{ client: S3Client; handle: string }> {
  const handle = (await (await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) })).json() as { token: string }).token;
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string> };
  assert.equal(plan.env.AWS_ACCESS_KEY_ID, handle);
  assert.equal(plan.env.AWS_ENDPOINT_URL_S3, `${ORIGIN}/use/market/dev/s3`);
  const client = new S3Client({
    region: REGION,
    // The test's coffre listens on loopback; deployed, the plan's URL is it.
    endpoint: plan.env.AWS_ENDPOINT_URL_S3!.replace(ORIGIN, coffreUrl),
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

  assert.equal(seen.length, 3);
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

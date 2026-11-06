// What the credential proxy holds of a request's body (`@coffre/core/memory`): 1 MiB at most read whole, a larger body
// streamed where nothing signs its hash, and all the bodies an isolate reads whole held to their share, past which a
// request is refused at once, 503 with Retry-After, and given back as each request ends.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient } from '@coffre/client';
import { contentDigest } from '@coffre/client/dpop';
import { BODIES_BYTES, BODY_READ_WHOLE_BYTES } from '@coffre/core/memory';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, form, header, query, sigv4 } from '../src/plugins/credential-proxy.ts';

/** The fake upstream: what reached it, its body's length and SHA-256, and its Content-Length as sent. */
let upstream: Server;
let upstreamUrl: string;
const reached: { url: string; headers: IncomingMessage['headers']; length: number; sha256: string }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    const hash = createHash('sha256');
    let length = 0;
    request.on('data', (chunk: Buffer) => {
      hash.update(chunk);
      length += chunk.length;
    });
    request.on('end', () => {
      reached.push({ url: request.url!, headers: request.headers, length, sha256: hash.digest('hex') });
      response.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
    request.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

const KEY = 'sk-real-key-0123456789abcdef';

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({
    credentials: {
      bearer: { upstream: `${upstreamUrl}/bearer`, inject: header('authorization', 'Bearer {API_KEY}') },
      basic: { upstream: `${upstreamUrl}/basic`, inject: basic('{API_KEY}', '') },
      query: { upstream: `${upstreamUrl}/query`, inject: query('key', '{API_KEY}') },
      s3: { upstream: `${upstreamUrl}/s3`, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
      gather: { upstream: `${upstreamUrl}/gather`, inject: form('refresh_token', '{API_KEY}') },
    },
    insecureUpstreams: true,
  })]);
  reached.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY: { value: KEY, sensitivity: 'sensitive' }, AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE0123456789', AWS_SECRET_ACCESS_KEY: { value: 'aws-secret-0123456789abcdef0123456789', sensitivity: 'sensitive' } });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** A handle for DEV on market/dev, as `coffre run` makes one. */
async function handle(): Promise<string> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  return (await api.handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] })).token;
}

/** `bytes` as a stream that says no length of its own: sent with a Content-Length only if the request says one. */
function stream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  let at = 0;
  return new ReadableStream({
    pull(controller) {
      if (at >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(at, at + 256 * 1024));
      at += 256 * 1024;
    },
  });
}

/**
 * A POST through `credential` at market/dev, its handle in x-coffre-handle, with `body` and the headers given: bytes
 * with their Content-Length, as an HTTP client sends them (a `Request` made here says none), a stream with none.
 */
async function post(credential: string, held: string, body: Uint8Array | ReadableStream<Uint8Array>, headers: Record<string, string> = {}) {
  const length = body instanceof Uint8Array ? { 'content-length': String(body.length) } : {};
  const response = await route(`/use/market/dev/${credential}/upload`, { method: 'POST', headers: { 'x-coffre-handle': held, ...length, ...headers }, body, duplex: 'half' } as RequestInit);
  return { status: response.status, headers: response.headers, body: (await response.json()) as { message?: string; reason?: string } };
}

/** `length` bytes, the handle last: what tells a body read whole (refused before anything goes) from one streamed (stopped as the handle passes). */
function endingIn(held: string, length: number): Uint8Array {
  const bytes = new Uint8Array(length).fill(0x61);
  bytes.set(new TextEncoder().encode(held), length - held.length);
  return bytes;
}

test('through a credential that only sets a header, Basic or the query, a body of 1 MiB is read whole, and one byte more streams on with its length', async () => {
  const held = await handle();
  for (const credential of ['bearer', 'basic', 'query']) {
    // Read whole: the handle found in it before anything goes.
    const whole = await post(credential, held, endingIn(held, BODY_READ_WHOLE_BYTES));
    assert.deepEqual([whole.status, whole.body.message], [400, `the handle is somewhere ${credential} does not take its key: the body`], credential);
    // Streamed: the handle found as it passes, the upstream left a broken request.
    const streamed = await post(credential, held, endingIn(held, BODY_READ_WHOLE_BYTES + 1));
    assert.deepEqual([streamed.status, streamed.body.message], [400, 'the handle is in the body'], credential);
    // And a body of its own reaches the upstream whole, every byte and its length.
    reached.length = 0;
    const bytes = new Uint8Array(BODY_READ_WHOLE_BYTES + 1).fill(0x62);
    const sent = await post(credential, held, stream(bytes), { 'content-length': String(bytes.length) });
    assert.equal(sent.status, 200, JSON.stringify(sent.body));
    assert.deepEqual([reached.length, reached[0]!.length, reached[0]!.headers['content-length'], reached[0]!.sha256], [1, bytes.length, String(bytes.length), createHash('sha256').update(bytes).digest('hex')], credential);
    // A body past 1 MiB that says no length is never streamed: the refusal says what to send.
    const unsaid = await post(credential, held, stream(bytes));
    assert.equal(unsaid.status, 413, credential);
    assert.match(unsaid.body.message!, /at most 1 MiB read whole; a larger one streams when it says its length: send its Content-Length/);
  }
});

test('through sigv4, whose signature needs the body\'s hash, a body past 1 MiB streams only once it declares that hash', async () => {
  const held = await handle();
  const bytes = new Uint8Array(BODY_READ_WHOLE_BYTES + 1).fill(0x63);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  // 1 MiB, read whole and hashed for the signature.
  reached.length = 0;
  const whole = new Uint8Array(BODY_READ_WHOLE_BYTES).fill(0x63);
  assert.equal((await post('s3', held, whole)).status, 200);
  assert.equal(reached[0]!.headers['x-amz-content-sha256'], createHash('sha256').update(whole).digest('hex'));
  // One byte more, no hash declared: refused, naming the way through.
  const refused = await post('s3', held, bytes);
  assert.equal(refused.status, 413);
  assert.match(refused.body.message!, /at most 1 MiB read whole, as s3 signs its hash; one that says its length and declares its SHA-256 streams/);
  // Declared, it streams: x-amz-content-sha256, which S3 checks, or a Content-Digest, which coffre checks as it passes.
  reached.length = 0;
  assert.equal((await post('s3', held, stream(bytes), { 'content-length': String(bytes.length), 'x-amz-content-sha256': sha256 })).status, 200);
  assert.equal((await post('s3', held, stream(bytes), { 'content-length': String(bytes.length), 'content-digest': contentDigest(sha256) })).status, 200);
  assert.deepEqual(reached.map((one) => [one.length, one.sha256, one.headers['x-amz-content-sha256']]), [[bytes.length, sha256, sha256], [bytes.length, sha256, sha256]]);
});

test('a form or JSON rule still reads its body whole, 64 KiB at most, whatever its length says', async () => {
  const held = await handle();
  const big = new TextEncoder().encode(`refresh_token=${held}&pad=${'x'.repeat(BODY_READ_WHOLE_BYTES)}`);
  const refused = await post('gather', held, big, { 'content-type': 'application/x-www-form-urlencoded' });
  assert.deepEqual([refused.status, refused.body.message], [413, 'gather fills a field of a body read whole, 64 KiB at most']);
});

/** A body of `length` bytes that the test lets come: nothing until `send`, or never, an error, at `fail`; `asked` once it is read. */
function held(length: number) {
  let send!: () => void;
  let fail!: () => void;
  let asked!: () => void;
  const come = new Promise<boolean>((resolve) => {
    send = () => resolve(true);
    fail = () => resolve(false);
  });
  const read = new Promise<void>((resolve) => (asked = resolve));
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      asked();
      if (!(await come)) return controller.error(new Error('the client went'));
      controller.enqueue(new Uint8Array(length).fill(0x64));
      controller.close();
    },
  }, { highWaterMark: 0 });
  return { body, read, send, fail };
}

test("the bodies an isolate reads whole are held to their share: past it, 503 at once with Retry-After, and each request's given back as it ends, however it ends", async () => {
  const handleOf = await handle();
  // Each body read whole is held twice at most, so this many of 1 MiB fill the share.
  const fill = BODIES_BYTES / (2 * BODY_READ_WHOLE_BYTES);
  const start = () => {
    const body = held(BODY_READ_WHOLE_BYTES);
    const answer = route('/use/market/dev/bearer/upload', { method: 'POST', headers: { 'x-coffre-handle': handleOf, 'content-length': String(BODY_READ_WHOLE_BYTES) }, body: body.body, duplex: 'half' } as RequestInit);
    // Read, or answered before a byte of it was: a refusal.
    const reached = Promise.race([body.read.then(() => 'read'), answer.then((response) => response.status)]);
    return { ...body, answer, reached };
  };
  const waiting = Array.from({ length: fill }, start);
  assert.deepEqual(new Set(await Promise.all(waiting.map((one) => one.reached))), new Set(['read']));
  // Full: the next body read whole is refused before a byte of it is read, even a small one.
  const refused = await post('bearer', handleOf, new Uint8Array(10));
  assert.deepEqual([refused.status, refused.headers.get('retry-after'), refused.body.reason], [503, '1', 'overloaded']);
  assert.match(refused.body.message!, /holds as many bodies read whole as it takes, 16 MiB: send it again in a moment, or stream it/);
  // A body that streams holds nothing, and goes.
  assert.equal((await post('bearer', handleOf, stream(new Uint8Array(BODY_READ_WHOLE_BYTES + 1)), { 'content-length': String(BODY_READ_WHOLE_BYTES + 1) })).status, 200);
  // One request answered, one whose client went: both given back.
  waiting[0]!.send();
  assert.equal((await waiting[0]!.answer).status, 200);
  waiting[1]!.fail();
  await waiting[1]!.answer.then((response) => response.body?.cancel(), () => undefined);
  // Room for two again, and no more.
  const again = [start(), start()];
  assert.deepEqual(await Promise.all(again.map((one) => one.reached)), ['read', 'read']);
  assert.equal((await post('bearer', handleOf, new Uint8Array(10))).status, 503);
  for (const one of [...waiting.slice(2), ...again]) one.send();
  assert.deepEqual(new Set(await Promise.all([...waiting.slice(2), ...again].map(async (one) => (await one.answer).status))), new Set([200]));
  // All given back: the share is whole again.
  assert.equal((await post('bearer', handleOf, new Uint8Array(10))).status, 200);
});

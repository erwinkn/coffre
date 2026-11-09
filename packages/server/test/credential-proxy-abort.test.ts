// The credential proxy sets no time bound of its own on an upstream request (docs/design/config.md, Q7):
// it ends the request when the app's does. Under srvx, as `coffre serve`'s Node deployments run, an app that
// hangs up while the upstream has not answered, while it is still sending a body the proxy streams on, or
// while the upstream's answer is still streaming back, ends the upstream's connection with it. The Workers
// side, with `enable_request_signal`, is `credential-proxy-egress-workers.test.ts`.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { serve, type Server as Srvx } from 'srvx';

import type { PluginContext } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';

const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const KEY = 'sk_schumann_real_0123456789abcdef';

/** coffre as the proxy calls it: every handle stands, for market/dev, and opens this value. */
const coffre = {
  publicUrl: 'https://secrets.acme.example',
  workload: async () => null,
  handle: async () => ({ expiresAt: new Date(Date.now() + 3_600_000).toISOString(), paths: ['market/dev'] }),
  use: async () => ({
    values: { SCHUMANN_API_KEY: KEY },
    plain: [],
    keys: ['SCHUMANN_API_KEY'],
    environment: { path: 'market/dev', personal: false },
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }),
} as unknown as PluginContext;

/** What the upstream saw of a request: that it arrived, and that its connection ended before its answer was whole. */
type Seen = { arrived: Promise<IncomingMessage>; ended: Promise<{ received: number; answered: boolean }> };
const seen = new Map<string, Seen & { arrive(request: IncomingMessage): void; end(received: number, answered: boolean): void }>();
const watch = (path: string) => {
  let arrive!: (request: IncomingMessage) => void;
  let end!: (received: number, answered: boolean) => void;
  const entry = {
    arrived: new Promise<IncomingMessage>((resolve) => (arrive = resolve)),
    ended: new Promise<{ received: number; answered: boolean }>((resolve) => (end = (received, answered) => resolve({ received, answered }))),
    arrive: (request: IncomingMessage) => arrive(request),
    end: (received: number, answered: boolean) => end(received, answered),
  };
  seen.set(path, entry);
  return entry;
};

let upstream: Server;
let proxy: Srvx;
let proxyAt: URL;

before(async () => {
  // Each request its path says what to do: `/hang` never answers, `/upload` reads a body and never answers, `/stream` sends a
  // first chunk of its answer and never the rest.
  upstream = createServer((request: IncomingMessage, response: ServerResponse) => {
    const path = request.url!.split('?')[0]!;
    const entry = seen.get(path);
    let received = 0;
    request.on('data', (chunk: Buffer) => (received += chunk.length));
    // The connection closed under the request: the proxy's fetch was aborted.
    response.on('close', () => entry?.end(received, response.writableEnded));
    entry?.arrive(request);
    if (path === '/stream') response.writeHead(200, { 'content-type': 'text/plain' }).write('first chunk\n');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const routes = credentialProxy({
    insecureUpstreams: true,
    credentials: { schumann: { upstream: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/`, inject: header('x-api-key', '{SCHUMANN_API_KEY}') } },
  }).routes!;
  proxy = serve({ port: 0, hostname: '127.0.0.1', silent: true, fetch: (request) => routes.fetch(request, coffre) });
  await proxy.ready();
  proxyAt = new URL(proxy.url!);
});

after(async () => {
  await proxy?.close(true);
  upstream.closeAllConnections();
  upstream.close();
});

/** A request to the proxy that the test hangs up by hand: its `send` and `hangUp`, and the answer if there is one. */
function call(path: string, headers: Record<string, string>) {
  const request = httpRequest({ host: proxyAt.hostname, port: proxyAt.port, path: `/use/schumann${path}`, method: 'POST', headers: { 'x-api-key': HANDLE, ...headers } });
  const answer = new Promise<IncomingMessage>((resolve) => request.on('response', resolve));
  request.on('error', () => {});
  return { request, answer, hangUp: () => request.destroy() };
}

const within = <T>(promise: Promise<T>, what: string, ms = 5000) =>
  Promise.race([promise, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${what}: not within ${ms} ms`)), ms).unref())]);

test('an app that hangs up before the upstream answers ends the upstream request', { timeout: 30_000 }, async () => {
  const hung = watch('/hang');
  const { request, hangUp } = call('/hang', { 'content-length': '2' });
  request.end('{}');
  const got = await within(hung.arrived, 'the upstream got the request');
  assert.equal(got.headers['x-api-key'], KEY);
  hangUp();
  assert.deepEqual(await within(hung.ended, 'the upstream request ended'), { received: 2, answered: false });
});

test('an app that hangs up while sending a body the proxy streams ends the upstream request, which has only a part of it', { timeout: 30_000 }, async () => {
  const size = 4 * 1024 * 1024;
  const uploading = watch('/upload');
  // Past the 1 MiB a body is read whole to, with its length declared: it streams on as it comes.
  const { request, hangUp } = call('/upload', { 'content-length': String(size), 'content-type': 'application/octet-stream' });
  request.write(Buffer.alloc(size >> 2));
  await within(uploading.arrived, 'the upstream got the request');
  hangUp();
  const { received, answered } = await within(uploading.ended, 'the upstream request ended');
  assert.equal(answered, false);
  assert.ok(received < size, `the upstream got ${received} bytes of ${size}`);
});

test("an app that hangs up while the upstream's answer is streaming back ends the upstream request", { timeout: 30_000 }, async () => {
  const streaming = watch('/stream');
  const { request, answer, hangUp } = call('/stream', { 'content-length': '0' });
  request.end();
  const response = await within(answer, 'the proxy answered');
  assert.equal(response.statusCode, 200);
  const [first] = (await within(once(response, 'data'), 'the first chunk')) as [Buffer];
  assert.equal(first.toString(), 'first chunk\n');
  await within(streaming.arrived, 'the upstream got the request');
  hangUp();
  assert.deepEqual((await within(streaming.ended, 'the upstream request ended')).answered, false);
});

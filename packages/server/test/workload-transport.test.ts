import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { isPublicAddress } from '../src/workloads/addresses.ts';
import { discoverKeys, DiscoveryFailed } from '../src/workloads/discovery.ts';
import { nodeTransport, publicFetch, publicLookup } from '../src/workloads/node-transport.ts';
import { fetchTransport, FetchRefused, MAX_BODY_BYTES, type WorkloadTransport } from '../src/workloads/transport.ts';

test('only globally routable unicast addresses are public', () => {
  for (const address of ['140.82.112.3', '8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2a00:1450:4001:80b::200e']) {
    assert.equal(isPublicAddress(address), true, address);
  }
  for (const address of [
    '0.0.0.0', '10.1.2.3', '100.64.0.1', '100.127.255.254', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.8', '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.51.100.7', '203.0.113.9', '224.0.0.1', '240.0.0.1',
    '255.255.255.255', '::', '::1', '::ffff:10.0.0.1', '::ffff:8.8.8.8', '64:ff9b::808:808', 'fc00::1', 'fd12:3456::1', 'fe80::1',
    'ff02::1', '2001:db8::1', '2001::1', '2002:c000:0204::1', '3fff::1', 'not an address',
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('the resolver refuses a name with any answer that is not public, at connect time', async () => {
  const lookup = (hostname: string) =>
    new Promise<unknown>((resolve, reject) =>
      publicLookup(hostname, { all: true }, (error, addresses) => (error ? reject(error) : resolve(addresses))),
    );
  await assert.rejects(lookup('localhost'), /localhost resolves to an address that is not public/);
  await assert.rejects(lookup('127.0.0.1'), (error: NodeJS.ErrnoException) => error.code === 'ENOTPUBLIC');
  // Through a real request: TLS never starts, since the connection is refused first.
  await assert.rejects(
    nodeTransport().json(new URL('https://localhost:1/.well-known/openid-configuration')),
    (error: Error) => error instanceof FetchRefused && /resolves to an address that is not public/.test(String((error.cause as Error).message)),
  );
});

let server: Server;
let origin: string;
/** What the next request answers, by path. */
const answers = new Map<string, (res: import('node:http').ServerResponse) => void>();

before(async () => {
  server = createServer((req, res) => (answers.get(req.url ?? '') ?? ((r) => r.writeHead(404).end()))(res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

for (const [name, transport] of [
  ['the Node transport', nodeTransport()],
  ['the fetch transport', fetchTransport()],
] as const satisfies readonly [string, WorkloadTransport][]) {
  test(`${name} takes a 200 with JSON, follows no redirect, and stops reading past the limit`, async () => {
    const json = (body: string, type = 'application/json') => (res: import('node:http').ServerResponse) =>
      res.writeHead(200, { 'content-type': type }).end(body);
    answers.set('/ok', json('{"keys":[]}'));
    answers.set('/jwk-set', json('{"keys":[]}', 'application/jwk-set+json; charset=utf-8'));
    answers.set('/moved', (res) => res.writeHead(302, { location: `${origin}/ok` }).end());
    answers.set('/html', json('<html></html>', 'text/html'));
    answers.set('/broken', json('{"keys":'));
    answers.set('/huge', json(JSON.stringify({ pad: 'x'.repeat(MAX_BODY_BYTES) })));
    answers.set('/gone', (res) => res.writeHead(500).end());
    // A 200 that says HTML, then breaks off: the answer was given before the body broke (review r2 of #565).
    answers.set('/html-reset', (res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.write('<html>'.padEnd(64 * 1024, ' '));
      setTimeout(() => res.destroy(), 20);
    });

    answers.set('/cached', (res) => res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600, must-revalidate' }).end('{"keys":[]}'));

    const said: (string | null)[] = [];
    assert.deepEqual(await transport.json(new URL(`${origin}/ok`), (value) => said.push(value)), { keys: [] });
    assert.deepEqual(await transport.json(new URL(`${origin}/jwk-set`)), { keys: [] });
    // How long the issuer says its answer may be kept, for its keys' stand-in (`workloads/keys.ts`).
    assert.deepEqual(await transport.json(new URL(`${origin}/cached`), (value) => said.push(value)), { keys: [] });
    assert.deepEqual(said, [null, 'public, max-age=3600, must-revalidate']);
    for (const [path, why] of [
      ['/moved', /answered 302/],
      ['/html', /is not JSON/],
      ['/html-reset', /is not JSON/],
      ['/broken', /is not valid JSON/],
      ['/huge', new RegExp(`is larger than ${MAX_BODY_BYTES} bytes`)],
      ['/gone', /answered 500/],
    ] as const) {
      await assert.rejects(transport.json(new URL(`${origin}${path}`)), (error: Error) => error instanceof FetchRefused && why.test(error.message) && error.transient === (path === '/gone'), path);
    }
    // A host that is not there: a moment later it may be.
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    await assert.rejects(transport.json(new URL(`http://127.0.0.1:${port}/keys`)), (error: Error) => error instanceof FetchRefused && error.transient && /could not be fetched/.test(error.message));
  });

  test(`${name} closes a refused answer at its status, never reading its body`, async () => {
    // An issuer, or a CDN before it, that answers 503 and goes on sending: 2 MiB, 16 KiB at a time.
    let written = 0;
    let closed!: () => void;
    const gone = new Promise<void>((resolve) => (closed = resolve));
    answers.set('/flood', (res) => {
      res.writeHead(503, { 'content-type': 'text/plain' });
      res.on('close', () => closed());
      const chunk = Buffer.alloc(16 * 1024, 'x');
      const timer = setInterval(() => {
        if (res.destroyed || written >= 2 * 1024 * 1024) {
          clearInterval(timer);
          if (!res.destroyed) res.end();
          return;
        }
        res.write(chunk);
        written += chunk.byteLength;
      }, 2);
    });
    await assert.rejects(transport.json(new URL(`${origin}/flood`)), /answered 503/);
    await Promise.race([gone, sleep(2000).then(() => assert.fail('the connection stayed open'))]);
    assert.ok(written < 1024 * 1024, `the issuer sent ${written} bytes before the connection closed`);
  });
}

test('a fetch the deadline ended says so, and is transient, as is any status that says the host cannot answer now; an address refused is not', () => {
  const url = new URL('https://token.actions.githubusercontent.com/.well-known/jwks');
  // fetch's abort, then Node's `http`, whose `AbortError` carries the deadline's.
  for (const deadline of [new DOMException('The operation was aborted due to timeout', 'TimeoutError'), Object.assign(new Error('The operation was aborted'), { name: 'AbortError', cause: new DOMException('timeout', 'TimeoutError') })]) {
    const refused = FetchRefused.unreached(url, deadline);
    assert.deepEqual([refused.message, refused.transient], [`${url.href}: timed out after 5 s`, true]);
  }
  assert.deepEqual([FetchRefused.unreached(url, Object.assign(new Error('reset'), { code: 'ECONNRESET' }), 'could not be read').message, FetchRefused.unreached(url, new Error('reset')).transient], [`${url.href}: could not be read`, true]);
  assert.equal(FetchRefused.unreached(url, Object.assign(new Error('not public'), { code: 'ENOTPUBLIC' })).transient, false);
  assert.deepEqual([408, 429, 500, 502, 503, 504, 400, 403, 404, 410].map((status) => FetchRefused.answered(url, status).transient), [true, true, true, true, true, true, false, false, false, false]);
});

test('a status that says the host cannot answer now stays transient when its body cannot even be cancelled (review r1 of #565)', async () => {
  const url = new URL('https://token.actions.githubusercontent.com/.well-known/jwks');
  const errored = () => new ReadableStream({ start: (controller) => controller.error(new Error('reset')) });
  for (const [status, transient] of [[503, true], [404, false]] as const) {
    const transport = fetchTransport(async () => new Response(errored(), { status }));
    await assert.rejects(transport.json(url), (error: unknown) => error instanceof FetchRefused && error.status === status && error.transient === transient);
  }
});

test('a 200 that is not JSON is refused as such, never as transient, when its body then breaks (review r2 of #565)', async () => {
  const url = new URL('https://token.actions.githubusercontent.com/.well-known/jwks');
  const errored = () => new ReadableStream({ start: (controller) => controller.error(new Error('reset')) });
  const transport = fetchTransport(async () => new Response(errored(), { status: 200, headers: { 'content-type': 'text/html' } }));
  await assert.rejects(transport.json(url), (error: unknown) => error instanceof FetchRefused && /is not JSON/.test(error.message) && !error.transient);
});

test("the public fetch, a UI route's upstream's on Node, dials no address that is not public, checked as it connects (review r2 of #467)", async () => {
  // `localhost` resolves to loopback: refused before any byte, whatever the certificate would have said.
  await assert.rejects(publicFetch()(new URL('https://localhost:8443/v1/models'), { method: 'GET' }), (error: Error) => /resolves to an address that is not public/.test(String((error.cause as Error | undefined)?.message)));
  // A name resolving to a private address a moment later gains nothing: the lookup runs at connect time.
  let asked = 0;
  const rebinding: typeof publicLookup = (hostname, options, callback) => {
    asked += 1;
    publicLookup('localhost', options, callback);
  };
  await assert.rejects(publicFetch(rebinding)(new URL('https://api.openai.example/v1/models'), { method: 'GET' }), (error: Error) => /not public/.test(String((error.cause as Error | undefined)?.message)));
  assert.ok(asked >= 1);
});

test('the public fetch dials no address written as one that is not public, which Node connects to without a lookup (review r3 of #467)', async () => {
  let asked = 0;
  const counting: typeof publicLookup = (hostname, options, callback) => {
    asked += 1;
    publicLookup(hostname, options, callback);
  };
  const fetch = publicFetch(counting);
  for (const host of ['240.0.0.1', '10.0.0.5', '127.0.0.1', '169.254.169.254', '100.64.0.1', '[::1]', '[::ffff:a00:5]', '[fd12:3456::1]', '[fe80::1]', '[64:ff9b::a00:5]']) {
    await assert.rejects(
      fetch(new URL(`https://${host}:8443/v1/models`), { method: 'GET' }),
      (error: Error) => (error.cause as NodeJS.ErrnoException | undefined)?.code === 'ENOTPUBLIC',
      host,
    );
    await assert.rejects(
      nodeTransport().json(new URL(`https://${host}/.well-known/openid-configuration`)),
      (error: Error) => error instanceof FetchRefused && (error.cause as NodeJS.ErrnoException | undefined)?.code === 'ENOTPUBLIC',
      host,
    );
  }
  // Refused before undici is asked: no lookup, no connection.
  assert.equal(asked, 0);
});

test('the Node transport speaks plain HTTP only to loopback', async () => {
  await assert.rejects(nodeTransport().json(new URL('http://idp.acme.example/x')), /plain HTTP reaches only loopback/);
});

test('discovery takes the keys\' URL from a document that names the issuer exactly', async () => {
  const issuer = 'https://idp.acme.example';
  const documents = new Map<string, unknown>();
  const transport: WorkloadTransport = {
    json: async (url) => {
      if (!documents.has(url.href)) throw new FetchRefused(url, 'answered 404');
      return documents.get(url.href);
    },
  };
  const at = (document: unknown, name = issuer) => {
    documents.set(`${name.replace(/\/$/, '')}/.well-known/openid-configuration`, document);
    return discoverKeys(transport, name, { allowLoopback: false });
  };
  assert.equal(await at({ issuer, jwks_uri: `${issuer}/keys` }), `${issuer}/keys`);
  // An issuer with a trailing slash keeps it, and discovery is still under it.
  assert.equal(await at({ issuer: `${issuer}/`, jwks_uri: `${issuer}/keys` }, `${issuer}/`), `${issuer}/keys`);
  // Keys elsewhere are fine, as Google's are: the discovery document is the issuer's word.
  assert.equal(await at({ issuer, jwks_uri: 'https://keys.acme-cdn.example/v3/certs' }), 'https://keys.acme-cdn.example/v3/certs');
  for (const [document, why] of [
    [{ issuer: 'https://evil.example', jwks_uri: `${issuer}/keys` }, /names "https:\/\/evil.example", not "https:\/\/idp.acme.example"/],
    [{ issuer: `${issuer}/`, jwks_uri: `${issuer}/keys` }, /not "https:\/\/idp.acme.example"/],
    [{ jwks_uri: `${issuer}/keys` }, /names no issuer/],
    [{ issuer }, /names no jwks_uri/],
    [{ issuer, jwks_uri: 'http://idp.acme.example/keys' }, /jwks_uri must use https/],
    [{ issuer, jwks_uri: 'https://169.254.169.254/keys' }, /jwks_uri names a host, not an IP address/],
    [['not', 'an', 'object'], /names no issuer/],
  ] as const) {
    await assert.rejects(at(document), (error: Error) => error instanceof DiscoveryFailed && why.test(error.message), JSON.stringify(document));
  }
  await assert.rejects(discoverKeys(transport, 'https://unknown.example', { allowLoopback: false }), /discovery document: .*answered 404/);
});

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { isPublicAddress } from '../src/workloads/addresses.ts';
import { discoverKeys, DiscoveryFailed } from '../src/workloads/discovery.ts';
import { nodeTransport, publicLookup } from '../src/workloads/node-transport.ts';
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

    assert.deepEqual(await transport.json(new URL(`${origin}/ok`)), { keys: [] });
    assert.deepEqual(await transport.json(new URL(`${origin}/jwk-set`)), { keys: [] });
    for (const [path, why] of [
      ['/moved', /answered 302/],
      ['/html', /is not JSON/],
      ['/broken', /is not valid JSON/],
      ['/huge', new RegExp(`is larger than ${MAX_BODY_BYTES} bytes`)],
      ['/gone', /answered 500/],
    ] as const) {
      await assert.rejects(transport.json(new URL(`${origin}${path}`)), (error: Error) => error instanceof FetchRefused && why.test(error.message), path);
    }
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

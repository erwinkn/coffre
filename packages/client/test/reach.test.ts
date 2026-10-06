import test from 'node:test';
import assert from 'node:assert/strict';

import { createClient, Unreachable, unreachable } from '../src/index.ts';

const ORIGIN = 'https://secrets.acme.example';

/** What Node's `fetch` throws: `fetch failed`, and Node's own error as its cause. */
const failed = (message: string, fields: Record<string, unknown> = {}) => new TypeError('fetch failed', { cause: Object.assign(new Error(message), fields) });

/** Each way a request can fail to reach the instance, as Node 24 says it, and what the client says of it. */
const CASES: [what: string, thrown: unknown, said: string][] = [
  [
    'a name that does not resolve',
    failed('getaddrinfo ENOTFOUND secrets.acme.example', { code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: 'secrets.acme.example' }),
    "getaddrinfo ENOTFOUND secrets.acme.example; the name does not resolve here: check the address, or flush this machine's DNS cache",
  ],
  [
    'a resolver that does not answer',
    failed('getaddrinfo EAI_AGAIN secrets.acme.example', { code: 'EAI_AGAIN', syscall: 'getaddrinfo', hostname: 'secrets.acme.example' }),
    "getaddrinfo EAI_AGAIN secrets.acme.example; the name does not resolve here: check the address, or flush this machine's DNS cache",
  ],
  ['a refusal on IPv4', failed('connect ECONNREFUSED 127.0.0.1:443', { code: 'ECONNREFUSED', address: '127.0.0.1', port: 443 }), 'connect ECONNREFUSED 127.0.0.1:443'],
  [
    'a refusal on IPv6',
    failed('connect ECONNREFUSED ::1:443', { code: 'ECONNREFUSED', address: '::1', port: 443 }),
    'connect ECONNREFUSED ::1:443; it was tried over IPv6, which this network may not carry: try NODE_OPTIONS=--dns-result-order=ipv4first',
  ],
  [
    'a connect timeout on IPv6',
    failed('Connect Timeout Error (attempted address: 2001:db8::1:443, timeout: 10000ms)', { name: 'ConnectTimeoutError', code: 'UND_ERR_CONNECT_TIMEOUT' }),
    'Connect Timeout Error (attempted address: 2001:db8::1:443, timeout: 10000ms) (UND_ERR_CONNECT_TIMEOUT); it was tried over IPv6, which this network may not carry: try NODE_OPTIONS=--dns-result-order=ipv4first',
  ],
  [
    'a connect timeout on IPv4',
    failed('Connect Timeout Error (attempted address: 10.255.255.1:443, timeout: 10000ms)', { name: 'ConnectTimeoutError', code: 'UND_ERR_CONNECT_TIMEOUT' }),
    'Connect Timeout Error (attempted address: 10.255.255.1:443, timeout: 10000ms) (UND_ERR_CONNECT_TIMEOUT)',
  ],
  [
    'every address timing out, IPv6 among them, which says nothing of its own',
    new TypeError('fetch failed', {
      cause: Object.assign(
        new AggregateError(
          [
            Object.assign(new Error('connect ETIMEDOUT 2606:4700::1:443'), { code: 'ETIMEDOUT', address: '2606:4700::1', port: 443 }),
            Object.assign(new Error('connect ETIMEDOUT 104.16.1.1:443'), { code: 'ETIMEDOUT', address: '104.16.1.1', port: 443 }),
          ],
          '',
        ),
        { code: 'ETIMEDOUT' },
      ),
    }),
    'connect ETIMEDOUT 2606:4700::1:443, connect ETIMEDOUT 104.16.1.1:443; it was tried over IPv6, which this network may not carry: try NODE_OPTIONS=--dns-result-order=ipv4first',
  ],
  [
    'a self-signed certificate',
    failed('self-signed certificate', { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' }),
    'self-signed certificate (DEPTH_ZERO_SELF_SIGNED_CERT); something between you and the instance, such as a proxy or a network filter, presents its own certificate',
  ],
  [
    "a certificate for another name",
    failed("Hostname/IP does not match certificate's altnames: Host: secrets.acme.example. is not in the cert's altnames: DNS:filter.example", { code: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
    "Hostname/IP does not match certificate's altnames: Host: secrets.acme.example. is not in the cert's altnames: DNS:filter.example (ERR_TLS_CERT_ALTNAME_INVALID); something between you and the instance, such as a proxy or a network filter, presents its own certificate",
  ],
  [
    'a certificate no authority here vouches for',
    failed('unable to verify the first certificate', { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }),
    'unable to verify the first certificate (UNABLE_TO_VERIFY_LEAF_SIGNATURE); something between you and the instance, such as a proxy or a network filter, presents its own certificate',
  ],
  ['a connection reset, with no hint', failed('socket hang up', { code: 'ECONNRESET' }), 'socket hang up (ECONNRESET)'],
  ['a browser, which says nothing more', new TypeError('Failed to fetch'), 'Failed to fetch'],
];

for (const [what, thrown, said] of CASES) {
  test(`unreachable: ${what}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => {
      throw thrown;
    });
    const coffre = createClient({ url: `${ORIGIN}/` });
    await assert.rejects(coffre.me(), (error: unknown) => {
      assert.ok(error instanceof Unreachable);
      assert.equal(error.message, `could not reach ${ORIGIN}: ${said}`);
      assert.equal(error.origin, ORIGIN);
      assert.equal(error.cause, thrown, "what fetch threw, kept as the cause");
      return true;
    });
  });
}

test("unreachable says the code and the address when the cause's message does not", () => {
  const thrown = failed('connect failed', { code: 'ECONNREFUSED', address: '192.0.2.1', port: 8443 });
  assert.equal(unreachable(ORIGIN, thrown), `could not reach ${ORIGIN}: connect failed (ECONNREFUSED, 192.0.2.1:8443)`);
});

test('a transport of its own throws what it throws: only the default one says the instance is unreachable', async () => {
  const thrown = new Error('the router refused');
  const coffre = createClient({
    url: ORIGIN,
    transport: async () => {
      throw thrown;
    },
  });
  await assert.rejects(coffre.me(), (error) => error === thrown);
});

import test from 'node:test';
import assert from 'node:assert/strict';

import { base64url, bodyDigest, createProof, generateProofKey, UNSIGNED_BODY, type ProofKey } from '@coffre/client/dpop';

import { canonicalHtu, canonicalRequest, parseProof, thumbprint, verifyProof, type ProofExpectation } from '../src/identity/dpop.ts';

const URL_ = 'https://secrets.acme.example/use/stripe/v1/charges?expand[]=balance_transaction';
const TOKEN = `coffre_wl_${'A'.repeat(43)}`;
const NOW = 1_792_805_400;
const BODY = 'amount=2000&currency=eur&source=tok_visa';

const headers = () => new Headers({ 'content-type': 'application/x-www-form-urlencoded', 'idempotency-key': '5f1c', 'stripe-account': 'acct_1Nv', 'user-agent': 'node' });

async function signed(key: ProofKey, overrides: Partial<Parameters<typeof createProof>[1]> = {}) {
  return createProof(key, {
    method: 'POST',
    url: URL_,
    token: TOKEN,
    nonce: 'g1.7Hq2',
    content: { headers: headers(), body: await bodyDigest(BODY) },
    iat: NOW,
    ...overrides,
  });
}

async function expectation(key: ProofKey, overrides: Partial<ProofExpectation> = {}): Promise<ProofExpectation> {
  return { method: 'POST', url: URL_, jkt: await thumbprint(key.jwk), token: TOKEN, content: { headers: headers(), body: await bodyDigest(BODY) }, now: NOW * 1000, ...overrides };
}

const ENCODER = new TextEncoder();

/** A proof of any header and claims, signed by `key`: what a client of its own could send. */
async function forged(key: ProofKey, header: object, claims: object): Promise<string> {
  const input = `${base64url(ENCODER.encode(JSON.stringify(header)))}.${base64url(ENCODER.encode(JSON.stringify(claims)))}`;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, ENCODER.encode(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

const reason = (result: { ok: boolean; reason?: string }) => (result.ok ? 'ok' : result.reason);

test('a proof verifies for the request it signs, and names its key, its jti, its nonce and the headers it signs', async () => {
  const key = await generateProofKey();
  const proof = await signed(key);
  const verified = await verifyProof(proof, await expectation(key));
  assert.ok(verified.ok, JSON.stringify(verified));
  assert.equal(verified.jkt, await thumbprint(key.jwk));
  assert.match(verified.jti, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(verified.nonce, 'g1.7Hq2');
  // Every header the app set but the transport's own, in Headers' order: user-agent too, which is the app's.
  assert.deepEqual(verified.hdr, ['content-type', 'idempotency-key', 'stripe-account', 'user-agent']);
  // The key is the proof's: the private half never left the process.
  await assert.rejects(crypto.subtle.exportKey('jwk', key.privateKey));
});

test("the exchange's proof signs no token and no content, and checks its time within 60 seconds", async () => {
  const key = await generateProofKey();
  const proof = await createProof(key, { method: 'POST', url: 'https://secrets.acme.example/api/auth/workload', iat: NOW });
  const expect = { method: 'POST', url: 'https://secrets.acme.example/api/auth/workload', skewSeconds: 60, now: NOW * 1000 };
  assert.equal(reason(await verifyProof(proof, expect)), 'ok');
  assert.equal(reason(await verifyProof(proof, { ...expect, now: (NOW + 61) * 1000 })), 'iat');
  assert.equal(reason(await verifyProof(proof, { ...expect, token: TOKEN })), 'ath');
  assert.equal(reason(await verifyProof(proof, { ...expect, content: { headers: new Headers(), body: await bodyDigest('') } })), 'req');
  // And a session's proof is no exchange's: it signs a token the exchange has none of.
  assert.equal(reason(await verifyProof(await signed(key), { ...expect, method: 'POST', url: URL_ })), 'ath');
});

test('each part of the request a proof signs, changed, is refused for what it is', async () => {
  const key = await generateProofKey();
  const proof = await signed(key);
  const other = await generateProofKey();
  const cases: [string, Partial<ProofExpectation>, string][] = [
    ['another key', { jkt: await thumbprint(other.jwk) }, 'jkt'],
    ['another method', { method: 'PUT' }, 'htm'],
    // Methods are case-sensitive: `post` is POST as Fetch sends it, and no proof of POST is one of `patch`.
    ['the method in lower case, normalized by Fetch', { method: 'post' }, 'ok'],
    ['another path', { url: URL_.replace('charges', 'refunds') }, 'htu'],
    ['another host', { url: URL_.replace('secrets.acme', 'secrets.evil') }, 'htu'],
    ['another query', { url: URL_.replace('balance_transaction', 'customer') }, 'req'],
    ['no query', { url: URL_.split('?')[0] }, 'req'],
    ['another token', { token: `coffre_wl_${'B'.repeat(43)}` }, 'ath'],
    ['another header value', { content: { headers: new Headers({ ...Object.fromEntries(headers()), 'stripe-account': 'acct_other' }), body: await bodyDigest(BODY) } }, 'req'],
    ['a signed header missing', { content: { headers: new Headers({ 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'node' }), body: await bodyDigest(BODY) } }, 'req'],
    ['another body', { content: { headers: headers(), body: await bodyDigest(`${BODY}&x=1`) } }, 'req'],
    ['an unsigned body', { content: { headers: headers(), body: UNSIGNED_BODY } }, 'req'],
    ['too late', { now: (NOW + 301) * 1000 }, 'iat'],
    ['too early', { now: (NOW - 301) * 1000 }, 'iat'],
  ];
  for (const [what, change, expected] of cases) {
    assert.equal(reason(await verifyProof(proof, await expectation(key, change))), expected, what);
  }
  const patch = await signed(key, { method: 'PATCH' });
  assert.equal(reason(await verifyProof(patch, await expectation(key, { method: 'PATCH' }))), 'ok');
  assert.equal(reason(await verifyProof(patch, await expectation(key, { method: 'patch' }))), 'htm', 'patch is not PATCH');
  const lower = await signed(key, { method: 'patch' });
  assert.equal(reason(await verifyProof(lower, await expectation(key, { method: 'patch' }))), 'ok', 'a proof signs patch as given');
  assert.equal(reason(await verifyProof(lower, await expectation(key, { method: 'PATCH' }))), 'htm');
  // A header the proof did not name is dropped, not refused: the proxy forwards only what `hdr` names.
  const added = headers();
  added.set('via', '1.1 proxy');
  assert.equal(reason(await verifyProof(proof, await expectation(key, { content: { headers: added, body: await bodyDigest(BODY) } }))), 'ok');
  // Within the skew either way.
  assert.equal(reason(await verifyProof(proof, await expectation(key, { now: (NOW + 300) * 1000 }))), 'ok');
});

test('a proof is refused by its shape, its key and its claims before anything is asked', async () => {
  const key = await generateProofKey();
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk };
  const claims = { jti: base64url(new Uint8Array(16)), htm: 'GET', htu: 'https://secrets.acme.example/use/x', iat: NOW };
  const cases: [string, object, object, string][] = [
    ['another typ', { ...header, typ: 'jwt' }, claims, 'malformed'],
    ['another alg', { ...header, alg: 'ES384' }, claims, 'malformed'],
    ['a header member more', { ...header, kid: 'x' }, claims, 'malformed'],
    ['a private key', { ...header, jwk: { ...key.jwk, d: key.jwk.x } }, claims, 'key'],
    ['another curve', { ...header, jwk: { ...key.jwk, crv: 'P-384' } }, claims, 'key'],
    ['a short coordinate', { ...header, jwk: { ...key.jwk, x: key.jwk.x.slice(0, 42) } }, claims, 'key'],
    ['a jti of 15 bytes', header, { ...claims, jti: base64url(new Uint8Array(15)) }, 'malformed'],
    ['an iat that is no integer', header, { ...claims, iat: NOW + 0.5 }, 'malformed'],
    ['a claim more', header, { ...claims, sub: 'x' }, 'malformed'],
    ['hdr without req', header, { ...claims, hdr: 'accept' }, 'malformed'],
    ['hdr naming authorization', header, { ...claims, hdr: 'authorization', req: base64url(new Uint8Array(32)) }, 'malformed'],
    ['hdr naming cookie', header, { ...claims, hdr: 'cookie', req: base64url(new Uint8Array(32)) }, 'malformed'],
    ['hdr naming a header twice', header, { ...claims, hdr: 'accept accept', req: base64url(new Uint8Array(32)) }, 'malformed'],
    ['hdr naming 33 headers', header, { ...claims, hdr: Array.from({ length: 33 }, (_, i) => `x-${i}`).join(' '), req: base64url(new Uint8Array(32)) }, 'malformed'],
    ['hdr in upper case', header, { ...claims, hdr: 'Accept', req: base64url(new Uint8Array(32)) }, 'malformed'],
  ];
  for (const [what, h, c, expected] of cases) assert.equal(reason(parseProof(await forged(key, h, c))), expected, what);

  const proof = await forged(key, header, claims);
  const [head, payload, signature] = proof.split('.') as [string, string, string];
  assert.equal(reason(parseProof(`${head}.${payload}`)), 'malformed', 'two parts');
  assert.equal(reason(parseProof(`${head}.${payload}.${signature.slice(0, -2)}`)), 'malformed', 'a short signature');
  assert.equal(reason(parseProof(`${head}=.${payload}.${signature}`)), 'malformed', 'padding');
  assert.equal(reason(parseProof(`${head}.${payload}.${signature}${'A'.repeat(2048)}`)), 'malformed', 'longer than 2 KiB');

  // A point off the curve parses, and is refused by the key's import.
  const off = { ...key.jwk, y: base64url(new Uint8Array(32).fill(1)) };
  const refused = await verifyProof(await forged(key, { ...header, jwk: off }, claims), { method: 'GET', url: claims.htu, now: NOW * 1000 });
  assert.equal(reason(refused), 'key');
  // A payload changed after signing.
  const changed = base64url(ENCODER.encode(JSON.stringify({ ...claims, htu: 'https://secrets.acme.example/use/y' })));
  assert.equal(reason(await verifyProof(`${head}.${changed}.${signature}`, { method: 'GET', url: 'https://secrets.acme.example/use/y', now: NOW * 1000 })), 'signature');
});

/** P-256's order, for the signature twin. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

test('the (r, n − s) twin of a signature verifies too, and carries the one jti the gate takes once', async () => {
  const key = await generateProofKey();
  const proof = await signed(key);
  const [head, payload, signature] = proof.split('.') as [string, string, string];
  const bytes = parseProof(proof);
  assert.ok(bytes.ok);
  const s = BigInt(`0x${Buffer.from(bytes.signature.slice(32)).toString('hex')}`);
  const twin = Buffer.concat([Buffer.from(bytes.signature.slice(0, 32)), Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex')]);
  const twinProof = `${head}.${payload}.${base64url(twin)}`;
  assert.notEqual(twinProof, proof);
  assert.notEqual(signature, base64url(twin));
  const [one, other] = await Promise.all([verifyProof(proof, await expectation(key)), verifyProof(twinProof, await expectation(key))]);
  assert.ok(one.ok && other.ok);
  assert.equal(one.jti, other.jti);
});

test('the thumbprint is RFC 7638\'s, whatever order the proof\'s key lists its members in', async () => {
  const key = await generateProofKey();
  const expected = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', ENCODER.encode(`{"crv":"P-256","kty":"EC","x":"${key.jwk.x}","y":"${key.jwk.y}"}`))));
  assert.equal(await thumbprint(key.jwk), expected);
  assert.equal(expected.length, 43);
  const claims = { jti: base64url(new Uint8Array(16)), htm: 'GET', htu: 'https://secrets.acme.example/use/x', iat: NOW };
  const reordered = await forged(key, { jwk: { y: key.jwk.y, x: key.jwk.x, kty: 'EC', crv: 'P-256' }, alg: 'ES256', typ: 'dpop+jwt' }, claims);
  const verified = await verifyProof(reordered, { method: 'GET', url: claims.htu, jkt: expected, now: NOW * 1000 });
  assert.ok(verified.ok);
});

test('htu is the URL as Cloudflare normalizes its path, and canonicalHtu is idempotent', () => {
  const cases: [string, string][] = [
    ['HTTPS://Secrets.Acme.Example:443/use/x?y=1#z', 'https://secrets.acme.example/use/x'],
    ['https://user:pass@secrets.acme.example/use/x', 'https://secrets.acme.example/use/x'],
    ['https://secrets.acme.example:8443/use/x', 'https://secrets.acme.example:8443/use/x'],
    ['http://127.0.0.1:3000/use/x', 'http://127.0.0.1:3000/use/x'],
    ['https://secrets.acme.example/use/%7estripe/%41b', 'https://secrets.acme.example/use/~stripe/Ab'],
    ['https://secrets.acme.example/use/a%2fb/c%3a', 'https://secrets.acme.example/use/a%2Fb/c%3A'],
    ['https://secrets.acme.example/use/a/../b/./c', 'https://secrets.acme.example/use/b/c'],
    ['https://secrets.acme.example/use/a/%2e%2E/b', 'https://secrets.acme.example/use/b'],
    ['https://secrets.acme.example//use///a\\b', 'https://secrets.acme.example/use/a/b'],
    // Cloudflare's own example: slashes merged before dot segments go.
    ['https://secrets.acme.example/hello//../path', 'https://secrets.acme.example/path'],
    ['https://secrets.acme.example/use/a b/é', 'https://secrets.acme.example/use/a%20b/%C3%A9'],
    ['https://secrets.acme.example', 'https://secrets.acme.example/'],
  ];
  for (const [given, expected] of cases) {
    assert.equal(canonicalHtu(given), expected, given);
    assert.equal(canonicalHtu(canonicalHtu(given)), expected, `${given}, again`);
  }
  assert.throws(() => canonicalHtu('wss://secrets.acme.example/use/db'), TypeError);
  // A lone %, which would make `%3%41` and `%3A` one path.
  for (const lone of ['https://secrets.acme.example/use/%3%41', 'https://secrets.acme.example/use/%%32%65/', 'https://secrets.acme.example/use/%', 'https://secrets.acme.example/use/%zz']) {
    assert.throws(() => canonicalHtu(lone), TypeError, lone);
  }
});

test('a canonical request is one line each, and holds no line break nor a body that is no digest', () => {
  const digest = 'a'.repeat(64);
  assert.equal(canonicalRequest({ query: 'a=1', headers: [['content-type', 'text/plain'], ['x-a', 'b, c']], body: digest }), `a=1\ncontent-type:text/plain\nx-a:b, c\n${digest}`);
  assert.equal(canonicalRequest({ query: '', headers: [], body: UNSIGNED_BODY }), `\n${UNSIGNED_BODY}`);
  assert.throws(() => canonicalRequest({ query: 'a\n', headers: [], body: digest }), TypeError);
  assert.throws(() => canonicalRequest({ query: '', headers: [['x', 'a\r\nb']], body: digest }), TypeError);
  for (const body of ['A'.repeat(64), 'a'.repeat(63), 'STREAMING-UNSIGNED-PAYLOAD-TRAILER', '']) {
    assert.throws(() => canonicalRequest({ query: '', headers: [], body }), TypeError, body);
  }
});

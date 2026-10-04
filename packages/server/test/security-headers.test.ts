import test from 'node:test';
import assert from 'node:assert/strict';

import {
  contentSecurityPolicy,
  cspNonce,
  setSecurityHeaders,
} from '../src/security-headers.ts';

const https = { nonce: 'abc', publicUrl: 'https://coffre.example.com' };

test('each nonce is fresh, and 128 bits', () => {
  const nonce = cspNonce();
  assert.equal(Buffer.from(nonce, 'base64').length, 16);
  assert.notEqual(cspNonce(), nonce);
});

test('scripts need the nonce; nothing may frame the page', () => {
  const policy = contentSecurityPolicy({ nonce: 'abc' }).split('; ');
  assert.ok(policy.includes("script-src 'self' 'nonce-abc'"));
  assert.ok(policy.includes("frame-ancestors 'none'"));
  assert.ok(policy.includes("form-action 'self'"));
  assert.ok(policy.includes("object-src 'none'"));
  assert.ok(!policy.some((directive) => directive.startsWith('script-src') && directive.includes('unsafe')));

  const access = contentSecurityPolicy({
    nonce: 'abc',
    formOrigins: ['https://acme.cloudflareaccess.com'],
  });
  assert.match(access, /form-action 'self' https:\/\/acme\.cloudflareaccess\.com;/);
});

test('a response gets the headers in place: the same response, nothing it carries lost', async () => {
  const redirect = new Response(null, { status: 302, headers: { location: 'https://coffre.example.com/login' } });
  const marked = Object.assign(redirect, { options: { to: '/login' } });
  const secured = setSecurityHeaders(marked, https);

  assert.equal(secured, marked);
  assert.deepEqual(secured.options, { to: '/login' });
  assert.equal(secured.status, 302);
  assert.equal(secured.headers.get('location'), 'https://coffre.example.com/login');
  assert.match(secured.headers.get('content-security-policy')!, /'nonce-abc'/);
  assert.equal(secured.headers.get('x-frame-options'), 'DENY');
  assert.equal(secured.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(secured.headers.get('referrer-policy'), 'same-origin');
  assert.equal(secured.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(secured.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
  assert.equal(secured.headers.get('cache-control'), 'no-store');

  const body = setSecurityHeaders(new Response('hello'), https);
  assert.equal(await body.text(), 'hello');
});

test('a public URL on plain HTTP, which is development, gets no HSTS', () => {
  const secured = setSecurityHeaders(new Response(null), { nonce: 'abc', publicUrl: 'http://127.0.0.1:3000' });
  assert.match(secured.headers.get('content-security-policy')!, /'nonce-abc'/);
  assert.equal(secured.headers.get('strict-transport-security'), null);
});

test('a response that chose its caching keeps it', () => {
  const cached = new Response(null, { headers: { 'cache-control': 'public, max-age=60' } });
  const secured = setSecurityHeaders(cached, https);
  assert.equal(secured.headers.get('cache-control'), 'public, max-age=60');
});

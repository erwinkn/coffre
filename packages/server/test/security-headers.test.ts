import test from 'node:test';
import assert from 'node:assert/strict';

import {
  contentSecurityPolicy,
  cspNonce,
  withSecurityHeaders,
} from '../src/security-headers.ts';

const page = new Request('https://coffre.example.com/projects');

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

test('a response gets the headers, on a copy it can change', async () => {
  const redirect = Response.redirect('https://coffre.example.com/login', 302);
  const secured = withSecurityHeaders(page, redirect, { nonce: 'abc' });

  assert.equal(secured.status, 302);
  assert.equal(secured.headers.get('location'), 'https://coffre.example.com/login');
  assert.match(secured.headers.get('content-security-policy')!, /'nonce-abc'/);
  assert.equal(secured.headers.get('x-frame-options'), 'DENY');
  assert.equal(secured.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(secured.headers.get('referrer-policy'), 'same-origin');
  assert.equal(secured.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(secured.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
  assert.equal(secured.headers.get('cache-control'), 'no-store');

  const body = withSecurityHeaders(page, new Response('hello'), { nonce: 'abc' });
  assert.equal(await body.text(), 'hello');
});

test('plain HTTP, which is development, gets no HSTS', () => {
  const secured = withSecurityHeaders(
    new Request('http://127.0.0.1:3000/projects'),
    new Response(null),
    { nonce: 'abc' },
  );
  assert.match(secured.headers.get('content-security-policy')!, /'nonce-abc'/);
  assert.equal(secured.headers.get('strict-transport-security'), null);
});

test('a response that chose its caching keeps it', () => {
  const cached = new Response(null, { headers: { 'cache-control': 'public, max-age=60' } });
  const secured = withSecurityHeaders(page, cached, { nonce: 'abc' });
  assert.equal(secured.headers.get('cache-control'), 'public, max-age=60');
});

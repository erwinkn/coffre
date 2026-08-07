import test from 'node:test';
import assert from 'node:assert/strict';

import {
  cliAuthHeader,
  cloudflareApiUrl,
  isCloudflareAccessRedirect,
  isJsonContentType,
} from '../src/auth-mode.ts';

test('dev CLI sends its local Access-shaped token directly to the API', () => {
  assert.deepEqual(cliAuthHeader('dev', 'local-jwt'), {
    'cf-access-jwt-assertion': 'local-jwt',
  });
});

test('production CLI sends the user token to the Cloudflare edge', () => {
  assert.deepEqual(cliAuthHeader('cloudflare', 'access-user-token'), {
    'cf-access-token': 'access-user-token',
  });
});

test('production CLI requires an explicit HTTPS API origin', () => {
  assert.equal(
    cloudflareApiUrl('https://coffre-api.example.com'),
    'https://coffre-api.example.com',
  );
  assert.throws(() => cloudflareApiUrl(undefined), /explicit HTTPS origin/);
  assert.throws(
    () => cloudflareApiUrl('http://coffre-api.example.com'),
    /explicit HTTPS origin/,
  );
});

test('production CLI rejects credentialed or path-bearing API URLs', () => {
  assert.throws(
    () => cloudflareApiUrl('https://user:secret@coffre-api.example.com'),
    /explicit HTTPS origin/,
  );
  assert.throws(
    () => cloudflareApiUrl('https://coffre-api.example.com/api'),
    /explicit HTTPS origin/,
  );
});

test('production CLI treats Access login redirects as authentication failures', () => {
  assert.equal(isCloudflareAccessRedirect('cloudflare', 302), true);
  assert.equal(isCloudflareAccessRedirect('cloudflare', 307), true);
  assert.equal(isCloudflareAccessRedirect('cloudflare', 401), false);
  assert.equal(isCloudflareAccessRedirect('dev', 302), false);
});

test('CLI parses only JSON response media types', () => {
  assert.equal(isJsonContentType('application/json'), true);
  assert.equal(isJsonContentType('application/problem+json; charset=utf-8'), true);
  assert.equal(isJsonContentType('text/html; charset=utf-8'), false);
  assert.equal(isJsonContentType(null), false);
});

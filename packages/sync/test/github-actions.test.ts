import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';

import { getProvider, providers, SyncConfigError, SyncProviderError } from '../src/index.ts';
import { fromBase64, toBase64 } from '../src/base64.ts';
import { sealNonce } from '../src/sealed-box.ts';
import { assertNoLeak, fakeFetch, rejection } from './fake-fetch.ts';

const github = providers['github-actions'];
const TOKEN = 'github_pat_11AAAAAAA0secrettokenvalue';
const REPO = 'https://api.github.com/repos/erwinkn/app';
const ENV = `${REPO}/environments/prod%2Feu/secrets`;

const recipient = nacl.box.keyPair();
const publicKey = { status: 200, body: { key_id: '568250167242549743', key: toBase64(recipient.publicKey) } };

function open(encryptedValue: string): string {
  const sealed = fromBase64(encryptedValue);
  const nonce = sealNonce(sealed.subarray(0, 32), recipient.publicKey);
  const plain = nacl.box.open(sealed.subarray(32), nonce, sealed.subarray(0, 32), recipient.secretKey);
  assert.ok(plain, 'the secret must open with the repository key');
  return new TextDecoder().decode(plain);
}

test('is registered under its kind', () => {
  assert.equal(getProvider('github-actions'), github);
  assert.equal(github.label, 'GitHub Actions');
  assert.equal(getProvider('nope'), null);
  assert.equal(getProvider('toString'), null);
});

test('parses a config and rejects bad ones readably', () => {
  assert.deepEqual(github.parseConfig({ owner: 'erwinkn', repo: 'app' }), {
    owner: 'erwinkn',
    repo: 'app',
    environment: undefined,
  });
  assert.deepEqual(github.parseConfig({ owner: 'erwinkn', repo: 'my.app', environment: 'prod/eu' }), {
    owner: 'erwinkn',
    repo: 'my.app',
    environment: 'prod/eu',
  });

  assert.throws(() => github.parseConfig(null), SyncConfigError);
  assert.throws(() => github.parseConfig({ repo: 'app' }), /"owner" is required/);
  assert.throws(() => github.parseConfig({ owner: 'erwinkn/app', repo: 'app' }), /"owner" must be a GitHub/);
  assert.throws(() => github.parseConfig({ owner: 'erwinkn', repo: 'a/b' }), /"repo" must be a repository name/);
  assert.throws(() => github.parseConfig({ owner: 'erwinkn', repo: 'app', environment: 7 }), /must be a string/);
  assert.throws(() => github.parseConfig({ owner: 'erwinkn', repo: 'app', enviroment: 'x' }), /unknown field "enviroment"/);
});

test('describes the destination in one line', () => {
  assert.equal(github.describe({ owner: 'erwinkn', repo: 'app' }), 'erwinkn/app');
  assert.equal(
    github.describe({ owner: 'erwinkn', repo: 'app', environment: 'production' }),
    'erwinkn/app · environment production',
  );
});

test('checks names against GitHub rules', () => {
  assert.deepEqual(github.checkKey('DATABASE_URL'), { ok: true });
  assert.deepEqual(github.checkKey('_PRIVATE_2'), { ok: true });
  for (const [key, reason] of [
    ['', /letters, digits and underscores/],
    ['API-KEY', /letters, digits and underscores/],
    ['MY KEY', /letters, digits and underscores/],
    ['1PASSWORD', /cannot start with a digit/],
    ['GITHUB_TOKEN', /GITHUB_/],
    ['github_token', /GITHUB_/],
    ['database_url', /name it DATABASE_URL/],
  ] as const) {
    const check = github.checkKey(key);
    assert.equal(check.ok, false, key);
    assert.match((check as { reason: string }).reason, reason);
  }
});

test('lists repository secrets across pages', async () => {
  const names = (from: number, count: number) =>
    Array.from({ length: count }, (_, i) => ({ name: `KEY_${from + i}`, created_at: '', updated_at: '' }));
  const { fetch, requests } = fakeFetch({
    [`GET ${REPO}/actions/secrets?per_page=100&page=1`]: { body: { total_count: 130, secrets: names(0, 100) } },
    [`GET ${REPO}/actions/secrets?per_page=100&page=2`]: { body: { total_count: 130, secrets: names(100, 30) } },
  });

  const keys = await github.listKeys({ token: TOKEN, fetch }, { owner: 'erwinkn', repo: 'app' });

  assert.equal(keys.length, 130);
  assert.equal(keys[129], 'KEY_129');
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[0]!.headers, {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${TOKEN}`,
    'x-github-api-version': '2022-11-28',
    'user-agent': 'coffre-sync',
  });
});

test('lists environment secrets with the environment name URL-encoded', async () => {
  const { fetch } = fakeFetch({
    [`GET ${ENV}?per_page=100&page=1`]: { body: { total_count: 1, secrets: [{ name: 'ONLY' }] } },
  });
  const keys = await github.listKeys({ token: TOKEN, fetch }, { owner: 'erwinkn', repo: 'app', environment: 'prod/eu' });
  assert.deepEqual(keys, ['ONLY']);
});

test('encrypts each value to the repository key and deletes removed secrets', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${ENV}/public-key`]: publicKey,
    [`PUT ${ENV}/DATABASE_URL`]: { status: 201 },
    [`PUT ${ENV}/API_KEY`]: { status: 204 },
    [`DELETE ${ENV}/OLD_KEY`]: { status: 204 },
    [`DELETE ${ENV}/ALREADY_GONE`]: { status: 404, body: { message: 'Not Found' } },
  });

  const result = await github.apply(
    { token: TOKEN, fetch },
    { owner: 'erwinkn', repo: 'app', environment: 'prod/eu' },
    {
      upsert: [
        { key: 'DATABASE_URL', value: 'postgres://u:hunter2@db/app' },
        { key: 'API_KEY', value: 'sk_live_abc' },
      ],
      delete: ['OLD_KEY', 'ALREADY_GONE'],
    },
  );

  assert.deepEqual(result.upserted.sort(), ['API_KEY', 'DATABASE_URL']);
  assert.deepEqual(result.deleted.sort(), ['ALREADY_GONE', 'OLD_KEY']);
  assert.deepEqual(result.failed, []);

  const put = requests.find((request) => request.url.endsWith('/DATABASE_URL'))!;
  const body = put.body as { encrypted_value: string; key_id: string };
  assert.deepEqual(Object.keys(body).sort(), ['encrypted_value', 'key_id']);
  assert.equal(body.key_id, '568250167242549743');
  assert.equal(open(body.encrypted_value), 'postgres://u:hunter2@db/app');
  assert.equal(put.headers['content-type'], 'application/json');

  const del = requests.find((request) => request.method === 'DELETE')!;
  assert.equal(del.body, undefined);
});

test('reports invalid and oversized keys without sending them, and keeps going', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${REPO}/actions/secrets/public-key`]: publicKey,
    [`PUT ${REPO}/actions/secrets/GOOD`]: { status: 201 },
    [`PUT ${REPO}/actions/secrets/REFUSED`]: { status: 422, body: { message: 'Invalid request: sk_value_1 is bad' } },
  });

  const result = await github.apply(
    { token: TOKEN, fetch },
    { owner: 'erwinkn', repo: 'app' },
    {
      upsert: [
        { key: 'GITHUB_TOKEN', value: 'x' },
        { key: 'HUGE', value: 'a'.repeat(48 * 1024 + 1) },
        { key: 'REFUSED', value: 'sk_value_1' },
        { key: 'GOOD', value: 'fine' },
      ],
      delete: [],
    },
  );

  assert.deepEqual(result.upserted, ['GOOD']);
  assert.deepEqual(
    result.failed.map((failure) => [failure.key, failure.operation]),
    [
      ['GITHUB_TOKEN', 'upsert'],
      ['HUGE', 'upsert'],
      ['REFUSED', 'upsert'],
    ],
  );
  assert.match(result.failed[1]!.message, /48 KB/);
  // The upstream echoed the value back; the guard must strip it.
  assert.equal(result.failed[2]!.message, 'GitHub rejected this secret: Invalid request: [redacted] is bad (HTTP 422)');
  assert.ok(!requests.some((request) => request.url.endsWith('/GITHUB_TOKEN') || request.url.endsWith('/HUGE')));
});

test('maps bad credentials to unauthorized without leaking the token', async () => {
  const { fetch } = fakeFetch({
    [`GET ${REPO}/actions/secrets/public-key`]: {
      status: 401,
      body: { message: `Bad credentials for ${TOKEN}`, documentation_url: 'https://docs.github.com/rest' },
    },
  });

  const error = await rejection(
    github.apply({ token: TOKEN, fetch }, { owner: 'erwinkn', repo: 'app' }, {
      upsert: [{ key: 'A_KEY', value: 'value-that-must-not-leak' }],
      delete: [],
    }),
  );

  assert.ok(error instanceof SyncProviderError);
  assert.equal(error.code, 'unauthorized');
  assert.equal(error.status, 401);
  assertNoLeak(error.message, [TOKEN, 'value-that-must-not-leak']);
  assert.match(error.message, /Bad credentials/);
});

test('a missing environment is not_found for the whole call', async () => {
  const { fetch } = fakeFetch({
    [`GET ${REPO}/environments/staging/secrets/public-key`]: { status: 404, body: { message: 'Not Found' } },
  });
  const error = await rejection(
    github.apply({ token: TOKEN, fetch }, { owner: 'erwinkn', repo: 'app', environment: 'staging' }, {
      upsert: [],
      delete: ['OLD'],
    }),
  );
  assert.equal((error as SyncProviderError).code, 'not_found');
});

test('a permission 403 is forbidden, a rate-limit 403 is retried then rate_limited', async () => {
  const forbidden = fakeFetch({
    [`GET ${REPO}/actions/secrets?per_page=100&page=1`]: {
      status: 403,
      body: { message: 'Resource not accessible by personal access token' },
    },
  });
  const denied = await rejection(github.listKeys({ token: TOKEN, fetch: forbidden.fetch }, { owner: 'erwinkn', repo: 'app' }));
  assert.equal((denied as SyncProviderError).code, 'forbidden');
  assert.equal(forbidden.requests.length, 1);

  const limited = fakeFetch({
    [`GET ${REPO}/actions/secrets?per_page=100&page=1`]: {
      status: 403,
      headers: { 'retry-after': '0' },
      body: { message: 'You have exceeded a secondary rate limit.' },
    },
  });
  const slowed = await rejection(github.listKeys({ token: TOKEN, fetch: limited.fetch }, { owner: 'erwinkn', repo: 'app' }));
  assert.equal((slowed as SyncProviderError).code, 'rate_limited');
  assert.equal(limited.requests.length, 3, 'one try plus two retries');
});

test('a rate limit mid-apply stops the run rather than failing every key', async () => {
  const { fetch } = fakeFetch({
    [`GET ${REPO}/actions/secrets/public-key`]: publicKey,
    [`PUT ${REPO}/actions/secrets/A_KEY`]: { status: 429, headers: { 'retry-after': '3600' } },
  });
  const error = await rejection(
    github.apply({ token: TOKEN, fetch }, { owner: 'erwinkn', repo: 'app' }, {
      upsert: [{ key: 'A_KEY', value: 'secret-value-a' }],
      delete: [],
    }),
  );
  assert.equal((error as SyncProviderError).code, 'rate_limited');
});

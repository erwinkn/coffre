import test from 'node:test';
import assert from 'node:assert/strict';

import { getProvider, providers, SyncConfigError, SyncProviderError } from '../src/index.ts';
import { assertNoLeak, fakeFetch, rejection } from './fake-fetch.ts';

const cloudflare = providers['cloudflare-workers'];
const TOKEN = 'cf_api_token_0123456789abcdefSECRET';
const ACCOUNT = '023e105f4ecef8ad9ca31a8372d0c353';
const SCRIPT = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/coffre-web`;
const config = { accountId: ACCOUNT, scriptName: 'coffre-web' };

const ok = (result: unknown = {}) => ({ body: { success: true, errors: [], messages: [], result } });
const failed = (status: number, code: number, message: string) => ({
  status,
  body: { success: false, errors: [{ code, message }], messages: [], result: null },
});
const listed = (...names: string[]) => ok(names.map((name) => ({ name, type: 'secret_text' })));

test('is registered under its kind', () => {
  assert.equal(getProvider('cloudflare-workers'), cloudflare);
  assert.equal(cloudflare.label, 'Cloudflare Workers');
});

test('parses a config and rejects bad ones readably', () => {
  assert.deepEqual(cloudflare.parseConfig(config), config);
  assert.throws(() => cloudflare.parseConfig([]), SyncConfigError);
  assert.throws(() => cloudflare.parseConfig({ accountId: ACCOUNT }), /"scriptName" is required/);
  assert.throws(() => cloudflare.parseConfig({ ...config, accountId: 'my-account' }), /"accountId" must be a Cloudflare account ID/);
  assert.throws(() => cloudflare.parseConfig({ ...config, scriptName: 'Coffre Web' }), /"scriptName" must be a Worker name/);
  assert.throws(() => cloudflare.parseConfig({ ...config, scriptName: '../zones' }), /"scriptName" must be a Worker name/);
  assert.throws(() => cloudflare.parseConfig({ ...config, script: 'x' }), /unknown field "script"/);
});

test('describes the destination and checks names', () => {
  assert.equal(cloudflare.describe(config), 'Worker coffre-web · account 023e105f');
  assert.deepEqual(cloudflare.checkKey('database-url'), { ok: true });
  assert.equal(cloudflare.checkKey('').ok, false);
});

test('lists secret_text names with a bearer token', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${SCRIPT}/secrets`]: ok([
      { name: 'DATABASE_URL', type: 'secret_text' },
      { name: 'SIGNING_KEY', type: 'secret_key' },
      { name: 'API_KEY', type: 'secret_text' },
    ]),
  });

  assert.deepEqual(await cloudflare.listKeys({ token: TOKEN, fetch }, config), ['DATABASE_URL', 'API_KEY']);
  assert.deepEqual(requests[0]!.headers, { authorization: `Bearer ${TOKEN}` });
});

test('applies upserts and deletes in one bulk merge patch, skipping absent secrets', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${SCRIPT}/secrets`]: listed('OLD_KEY', 'UNMANAGED'),
    [`PATCH ${SCRIPT}/secrets-bulk`]: ok({}),
  });

  const result = await cloudflare.apply({ token: TOKEN, fetch }, config, {
    upsert: [
      { key: 'DATABASE_URL', value: 'postgres://u:hunter2@db/app' },
      { key: 'API_KEY', value: 'sk_live_abc' },
    ],
    delete: ['OLD_KEY', 'NEVER_EXISTED'],
  });

  assert.deepEqual(result, {
    upserted: ['DATABASE_URL', 'API_KEY'],
    deleted: ['NEVER_EXISTED', 'OLD_KEY'],
    failed: [],
  });
  const patch = requests[1]!;
  assert.equal(patch.headers['content-type'], 'application/json');
  assert.deepEqual(patch.body, {
    secrets: {
      DATABASE_URL: { name: 'DATABASE_URL', text: 'postgres://u:hunter2@db/app', type: 'secret_text' },
      API_KEY: { name: 'API_KEY', text: 'sk_live_abc', type: 'secret_text' },
      OLD_KEY: null,
    },
  });
});

test('an upsert-only plan skips the listing', async () => {
  const { fetch, requests } = fakeFetch({ [`PATCH ${SCRIPT}/secrets-bulk`]: ok({}) });
  await cloudflare.apply({ token: TOKEN, fetch }, config, { upsert: [{ key: 'A', value: 'a-value' }], delete: [] });
  assert.deepEqual(requests.map((request) => request.method), ['PATCH']);
});

test('splits large plans into bulk requests of 100', async () => {
  const { fetch, requests } = fakeFetch({ [`PATCH ${SCRIPT}/secrets-bulk`]: ok({}) });
  const upsert = Array.from({ length: 130 }, (_, i) => ({ key: `KEY_${i}`, value: `value-${i}` }));

  const result = await cloudflare.apply({ token: TOKEN, fetch }, config, { upsert, delete: [] });

  assert.equal(result.upserted.length, 130);
  assert.deepEqual(
    requests.map((request) => Object.keys((request.body as { secrets: object }).secrets).length),
    [100, 30],
  );
});

test('falls back to one request per key when the bulk patch is refused', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${SCRIPT}/secrets`]: listed('OLD/KEY', 'GONE_MEANWHILE'),
    [`PATCH ${SCRIPT}/secrets-bulk`]: failed(400, 10021, 'Invalid secret: value too long'),
    [`PUT ${SCRIPT}/secrets`]: (request) =>
      (request.body as { name: string }).name === 'TOO_BIG'
        ? failed(400, 10021, `Secret value ${'x'.repeat(6000).slice(0, 12)} exceeds 5 KB`)
        : ok({ name: 'GOOD', type: 'secret_text' }),
    [`DELETE ${SCRIPT}/secrets/OLD%2FKEY?url_encoded=true`]: ok({}),
    [`DELETE ${SCRIPT}/secrets/GONE_MEANWHILE?url_encoded=true`]: failed(404, 10056, 'Secret not found'),
  });

  const result = await cloudflare.apply({ token: TOKEN, fetch }, config, {
    upsert: [
      { key: 'TOO_BIG', value: 'x'.repeat(6000) },
      { key: 'GOOD', value: 'fine-value' },
    ],
    delete: ['OLD/KEY', 'GONE_MEANWHILE'],
  });

  assert.deepEqual(result.upserted, ['GOOD']);
  assert.deepEqual(result.deleted, ['OLD/KEY', 'GONE_MEANWHILE']);
  assert.deepEqual(result.failed.map((failure) => [failure.key, failure.operation]), [['TOO_BIG', 'upsert']]);
  assert.match(result.failed[0]!.message, /^Cloudflare rejected this secret: .*exceeds 5 KB \(HTTP 400, code 10021\)$/);
  assert.deepEqual(
    requests.map((request) => request.method),
    ['GET', 'PATCH', 'PUT', 'PUT', 'DELETE', 'DELETE'],
  );
  assert.deepEqual(requests[3]!.body, { name: 'GOOD', text: 'fine-value', type: 'secret_text' });
});

test('an undeployed latest version fails the whole call without a per-key fallback', async () => {
  const { fetch, requests } = fakeFetch({
    [`PATCH ${SCRIPT}/secrets-bulk`]: failed(
      400,
      10215,
      "Secret edit failed. You attempted to modify a secret, but the latest version of your Worker isn't currently deployed.",
    ),
  });

  const error = await rejection(
    cloudflare.apply({ token: TOKEN, fetch }, config, { upsert: [{ key: 'A', value: 'a-value' }], delete: [] }),
  );

  assert.ok(error instanceof SyncProviderError);
  assert.equal(error.code, 'upstream');
  assert.match(error.message, /latest version of your Worker isn't currently deployed\. \(HTTP 400, code 10215\)/);
  assert.equal(requests.length, 1);
});

test('maps an authentication error to unauthorized without leaking the token', async () => {
  const { fetch } = fakeFetch({
    [`PATCH ${SCRIPT}/secrets-bulk`]: failed(403, 10000, `Authentication error for ${TOKEN}`),
  });

  const error = await rejection(
    cloudflare.apply({ token: TOKEN, fetch }, config, {
      upsert: [{ key: 'A', value: 'value-that-must-not-leak' }],
      delete: [],
    }),
  );

  assert.ok(error instanceof SyncProviderError);
  assert.equal(error.code, 'unauthorized');
  assert.equal(error.status, 403);
  assertNoLeak(error.message, [TOKEN, 'value-that-must-not-leak']);
  assert.match(error.message, /Authentication error/);
});

test('a missing Worker is not_found, a rate limit is rate_limited', async () => {
  const missing = fakeFetch({ [`GET ${SCRIPT}/secrets`]: failed(404, 10007, 'This Worker does not exist on your account.') });
  const notFound = await rejection(cloudflare.listKeys({ token: TOKEN, fetch: missing.fetch }, config));
  assert.equal(notFound.code, 'not_found');

  // Cloudflare blocks for five minutes; that is reported, not waited out.
  const limited = fakeFetch({
    [`PATCH ${SCRIPT}/secrets-bulk`]: { ...failed(429, 971, 'Please wait and consider throttling your request speed'), headers: { 'retry-after': '300' } },
  });
  const slowed = await rejection(
    cloudflare.apply({ token: TOKEN, fetch: limited.fetch }, config, { upsert: [{ key: 'A', value: 'a-value' }], delete: [] }),
  );
  assert.equal(slowed.code, 'rate_limited');
  assert.equal(limited.requests.length, 1);
});

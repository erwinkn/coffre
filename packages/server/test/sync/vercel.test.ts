import test from 'node:test';
import assert from 'node:assert/strict';

import { SyncConfigError, SyncProviderError, vercel as vercelProvider } from '../../src/sync/index.ts';
import { guard } from '../../src/sync/guard.ts';
import { assertNoLeak, fakeFetch, rejection } from './fake-fetch.ts';

const vercel = guard(vercelProvider());
const TOKEN = 'vcp_secrettokenvalue0123456789';
const PROJECT = 'https://api.vercel.com/v10/projects/prj_abc/env';
const RECORD = 'https://api.vercel.com/v9/projects/prj_abc/env';
const TEAM = 'teamId=team_xyz';

const allTargets = { projectId: 'prj_abc', teamId: 'team_xyz', targets: ['production', 'preview', 'development'] };
const productionOnly = { projectId: 'prj_abc', teamId: 'team_xyz', targets: ['production'] };

const list = (...envs: object[]) => ({ body: { envs, pagination: { count: envs.length, next: null, prev: null } } });
const created = { status: 201, body: { created: [], failed: [] } };

test('parses a config, normalising the target order', () => {
  assert.deepEqual(vercel.parseConfig({ projectId: 'prj_abc', targets: ['development', 'production'] }), {
    projectId: 'prj_abc',
    teamId: undefined,
    targets: ['production', 'development'],
    gitBranch: undefined,
  });
  assert.deepEqual(
    vercel.parseConfig({ projectId: 'my-app', teamId: 'team_xyz', targets: ['preview'], gitBranch: 'feature/login' }),
    { projectId: 'my-app', teamId: 'team_xyz', targets: ['preview'], gitBranch: 'feature/login' },
  );
});

test('rejects bad configs readably', () => {
  assert.throws(() => vercel.parseConfig({ projectId: 'prj_abc' }), SyncConfigError);
  assert.throws(() => vercel.parseConfig({ projectId: 'prj_abc', targets: [] }), /at least one/);
  assert.throws(() => vercel.parseConfig({ projectId: 'prj_abc', targets: ['staging'] }), /unknown target "staging"/);
  assert.throws(() => vercel.parseConfig({ targets: ['production'] }), /"projectId" is required/);
  assert.throws(
    () => vercel.parseConfig({ projectId: 'prj_abc', teamId: 'my-team', targets: ['production'] }),
    /team ID/,
  );
  assert.throws(
    () => vercel.parseConfig({ projectId: 'prj_abc', targets: ['production', 'preview'], gitBranch: 'main' }),
    /"gitBranch" only applies to the "preview" target/,
  );
});

test('describes the destination in one line', () => {
  assert.equal(vercel.describe(vercel.parseConfig(allTargets)), 'prj_abc · production + preview + development');
  assert.equal(
    vercel.describe(vercel.parseConfig({ projectId: 'app', targets: ['preview'], gitBranch: 'next' })),
    'app · preview · branch next',
  );
});

test('rejects the names Vercel reserves', () => {
  assert.deepEqual(vercel.checkKey('DATABASE_URL'), { ok: true });
  assert.equal(vercel.checkKey('TZ').ok, false);
  assert.equal(vercel.checkKey('AWS_LAMBDA_FUNCTION_NAME').ok, false);
  assert.equal(vercel.checkKey('').ok, false);
});

test('lists only the keys at our targets and branch', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list(
      { id: '1', key: 'PROD_ONLY', type: 'sensitive', target: ['production'] },
      { id: '2', key: 'PREVIEW_ONLY', type: 'encrypted', target: ['preview'] },
      { id: '3', key: 'BRANCH', type: 'encrypted', target: ['production'], gitBranch: 'feature' },
      { id: '4', key: 'PROD_ONLY', type: 'encrypted', target: 'development' },
    ),
  });

  const keys = await vercel.listKeys({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly));

  assert.deepEqual(keys, ['PROD_ONLY']);
  assert.equal(requests[0]!.headers.authorization, `Bearer ${TOKEN}`);
});

test('creates sensitive records where allowed and an encrypted one for development', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list(),
    [`POST ${PROJECT}?upsert=true&${TEAM}`]: created,
  });

  const result = await vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(allTargets), {
    upsert: [{ key: 'API_KEY', value: 'sk_live_1' }],
    delete: [],
  });

  assert.deepEqual(result, { upserted: ['API_KEY'], deleted: [], failed: [] });
  assert.deepEqual(requests[1]!.body, [
    { key: 'API_KEY', value: 'sk_live_1', type: 'sensitive', target: ['production', 'preview'] },
    { key: 'API_KEY', value: 'sk_live_1', type: 'encrypted', target: ['development'] },
  ]);
});

test('sends gitBranch on branch-scoped records', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}`]: list({ id: 'x', key: 'API_KEY', type: 'sensitive', target: ['preview'] }),
    [`POST ${PROJECT}?upsert=true`]: created,
  });

  await vercel.apply(
    { token: TOKEN, fetch },
    vercel.parseConfig({ projectId: 'prj_abc', targets: ['preview'], gitBranch: 'next' }),
    { upsert: [{ key: 'API_KEY', value: 'v' }], delete: [] },
  );

  // The branchless preview record is someone else's and is left alone.
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1]!.body, [
    { key: 'API_KEY', value: 'v', type: 'sensitive', target: ['preview'], gitBranch: 'next' },
  ]);
});

test('updates a matching record in place instead of creating a duplicate', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list({ id: 'env_1', key: 'API_KEY', type: 'sensitive', target: ['production'] }),
    [`PATCH ${RECORD}/env_1?${TEAM}`]: { body: { id: 'env_1' } },
  });

  const result = await vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly), {
    upsert: [{ key: 'API_KEY', value: 'rotated' }],
    delete: [],
  });

  assert.deepEqual(result.upserted, ['API_KEY']);
  assert.deepEqual(
    requests.map((request) => request.method),
    ['GET', 'PATCH'],
  );
  assert.deepEqual(requests[1]!.body, { value: 'rotated', target: ['production'] });
});

test('narrows a record that spans targets we do not own, then creates ours', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list({ id: 'env_1', key: 'API_KEY', type: 'encrypted', target: ['production', 'preview'] }),
    [`PATCH ${RECORD}/env_1?${TEAM}`]: { body: { id: 'env_1' } },
    [`POST ${PROJECT}?upsert=true&${TEAM}`]: created,
  });

  await vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly), {
    upsert: [{ key: 'API_KEY', value: 'mine' }],
    delete: [],
  });

  assert.deepEqual(
    requests.map((request) => [request.method, request.body]),
    [
      ['GET', undefined],
      // Preview keeps its own value; only production is taken over.
      ['PATCH', { target: ['preview'] }],
      ['POST', [{ key: 'API_KEY', value: 'mine', type: 'sensitive', target: ['production'] }]],
    ],
  );
});

test('replaces a record whose type cannot become sensitive in place', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list({ id: 'env_1', key: 'API_KEY', type: 'encrypted', target: ['production', 'development'] }),
    [`PATCH ${RECORD}/env_1?${TEAM}`]: { body: {} },
    [`POST ${PROJECT}?upsert=true&${TEAM}`]: created,
  });

  await vercel.apply(
    { token: TOKEN, fetch },
    vercel.parseConfig({ projectId: 'prj_abc', teamId: 'team_xyz', targets: ['production', 'development'] }),
    { upsert: [{ key: 'API_KEY', value: 'v2' }], delete: [] },
  );

  // The encrypted record is reused for development; production moves to a new
  // sensitive record, created only after the old one let go of it.
  assert.deepEqual(
    requests.map((request) => [request.method, request.body]),
    [
      ['GET', undefined],
      ['PATCH', { value: 'v2', target: ['development'] }],
      ['POST', [{ key: 'API_KEY', value: 'v2', type: 'sensitive', target: ['production'] }]],
    ],
  );
});

test('deletes our records, narrows shared ones, and treats absent keys as deleted', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list(
      { id: 'env_1', key: 'OURS', type: 'sensitive', target: ['production'] },
      { id: 'env_2', key: 'SHARED', type: 'encrypted', target: ['production', 'preview'] },
    ),
    [`DELETE ${RECORD}/env_1?${TEAM}`]: { body: {} },
    [`PATCH ${RECORD}/env_2?${TEAM}`]: { body: {} },
  });

  const result = await vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly), {
    upsert: [],
    delete: ['OURS', 'SHARED', 'NEVER_EXISTED'],
  });

  assert.deepEqual(result.deleted.sort(), ['NEVER_EXISTED', 'OURS', 'SHARED']);
  assert.deepEqual(requests.find((request) => request.method === 'PATCH')!.body, { target: ['preview'] });
  assert.equal(requests.length, 3);
});

test('reports per-key refusals, including 201s with failed entries and conflict 403s', async () => {
  const { fetch } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: list({ id: 'env_9', key: 'CONFLICT', type: 'sensitive', target: ['production'] }),
    [`POST ${PROJECT}?upsert=true&${TEAM}`]: (request) => {
      const [record] = request.body as { key: string }[];
      if (record!.key === 'PARTIAL') {
        return {
          status: 201,
          body: { created: [], failed: [{ error: { code: 'bad_value', message: 'value sk_partial_1 is invalid', key: 'PARTIAL' } }] },
        };
      }
      return created;
    },
    [`PATCH ${RECORD}/env_9?${TEAM}`]: {
      status: 403,
      body: { error: { code: 'ENV_ALREADY_EXISTS', message: 'The environment variable cannot be created because it already exists' } },
    },
  });

  const result = await vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly), {
    upsert: [
      { key: 'PARTIAL', value: 'sk_partial_1' },
      { key: 'CONFLICT', value: 'v' },
      { key: 'FINE', value: 'ok' },
    ],
    delete: [],
  });

  assert.deepEqual(result.upserted, ['FINE']);
  const byKey = Object.fromEntries(result.failed.map((failure) => [failure.key, failure.message]));
  assert.equal(byKey.PARTIAL, 'Vercel rejected this variable: value [redacted] is invalid (bad_value)');
  assert.match(byKey.CONFLICT!, /already exists \(HTTP 403, ENV_ALREADY_EXISTS\)/);
});

test('maps an invalid token to unauthorized without leaking it', async () => {
  const { fetch } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: {
      status: 403,
      body: { error: { code: 'forbidden', message: `Not authorized: ${TOKEN}`, invalidToken: true } },
    },
  });

  const error = await rejection(
    vercel.apply({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly), {
      upsert: [{ key: 'API_KEY', value: 'must-not-leak-1' }],
      delete: [],
    }),
  );

  assert.ok(error instanceof SyncProviderError);
  assert.equal(error.code, 'unauthorized');
  assertNoLeak(error.message, [TOKEN, 'must-not-leak-1']);
});

test('a plain 403 is forbidden and a missing project is not_found', async () => {
  const forbidden = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: { status: 403, body: { error: { code: 'forbidden', message: 'Not authorized' } } },
  });
  const denied = await rejection(vercel.listKeys({ token: TOKEN, fetch: forbidden.fetch }, vercel.parseConfig(productionOnly)));
  assert.equal((denied as SyncProviderError).code, 'forbidden');

  const missing = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: { status: 404, body: { error: { code: 'not_found', message: 'Project not found' } } },
  });
  const gone = await rejection(vercel.listKeys({ token: TOKEN, fetch: missing.fetch }, vercel.parseConfig(productionOnly)));
  assert.equal((gone as SyncProviderError).code, 'not_found');
});

test('retries a 5xx, then reports upstream', async () => {
  const { fetch, requests } = fakeFetch({
    [`GET ${PROJECT}?${TEAM}`]: [{ status: 502, body: 'Bad Gateway' }, list({ id: '1', key: 'A', type: 'sensitive', target: ['production'] })],
  });
  assert.deepEqual(await vercel.listKeys({ token: TOKEN, fetch }, vercel.parseConfig(productionOnly)), ['A']);
  assert.equal(requests.length, 2);

  const down = fakeFetch({ [`GET ${PROJECT}?${TEAM}`]: { status: 503, body: 'Service Unavailable' } });
  const error = await rejection(vercel.listKeys({ token: TOKEN, fetch: down.fetch }, vercel.parseConfig(productionOnly)));
  assert.equal((error as SyncProviderError).code, 'upstream');
  assert.equal(down.requests.length, 3);
});

test('redacts credentials across the text-error cut before shortening the message', async () => {
  const token = 'sensitive-token-' + 'x'.repeat(80);
  for (const offset of [190, 490]) {
    const upstream = fakeFetch({
      [`GET ${PROJECT}?${TEAM}`]: { status: 403, body: `${'.'.repeat(offset)}${token} rejected` },
    });
    const error = await rejection(vercel.listKeys({ token, fetch: upstream.fetch }, vercel.parseConfig(productionOnly)));
    assert.equal(error.code, 'forbidden');
    assertNoLeak(error.message, ['sensitive-', token]);
    assert.match(error.message, /\[redacted\]/);
  }
});

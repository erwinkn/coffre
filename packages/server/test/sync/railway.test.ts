import test from 'node:test';
import assert from 'node:assert/strict';

import { getProvider, providers, SyncConfigError, SyncProviderError } from '../../src/sync/index.ts';
import { assertNoLeak, fakeFetch, rejection, type RecordedRequest, type Reply } from './fake-fetch.ts';

const railway = providers.railway;
const TOKEN = '8f2c1d4e-rail-way0-toke-n00000secret';
const ROUTE = 'POST https://backboard.railway.com/graphql/v2';
const PROJECT = '0b7c8a4e-3f1d-4c2a-9e5b-1a2b3c4d5e6f';
const ENVIRONMENT = '1c8d9b5f-4a2e-4d3b-8f6c-2b3c4d5e6f70';
const SERVICE = '2d9eac60-5b3f-4e4c-9a7d-3c4d5e6f7081';
const config = { projectId: PROJECT, environmentId: ENVIRONMENT, serviceId: SERVICE };

type GraphQLRequest = { query: string; variables: Record<string, any> };
const operation = (request: RecordedRequest) => /^(?:query|mutation) (\w+)/.exec((request.body as GraphQLRequest).query)![1];
const variablesOf = (request: RecordedRequest) => (request.body as GraphQLRequest).variables;

/** Every Railway call is a POST to one URL, so replies are chosen by operation name. */
function graphql(replies: Record<string, Reply | ((request: RecordedRequest) => Reply)>) {
  return fakeFetch({
    [ROUTE]: (request) => {
      const reply = replies[operation(request)!];
      assert.ok(reply, `unexpected operation ${operation(request)}`);
      return typeof reply === 'function' ? reply(request) : reply;
    },
  });
}

const listed = (names: string[]) => ({
  body: { data: { variables: Object.fromEntries(names.map((name) => [name, `value of ${name}`])) } },
});
const notAuthorized = { body: { data: null, errors: [{ message: 'Not Authorized' }] } };

test('is registered under its kind', () => {
  assert.equal(getProvider('railway'), railway);
  assert.equal(railway.label, 'Railway');
});

test('parses a config and rejects bad ones readably', () => {
  assert.deepEqual(railway.parseConfig({ projectId: PROJECT, environmentId: ENVIRONMENT }), {
    projectId: PROJECT,
    environmentId: ENVIRONMENT,
    serviceId: undefined,
    tokenKind: undefined,
  });
  assert.equal(railway.parseConfig({ ...config, tokenKind: 'project' }).tokenKind, 'project');

  assert.throws(() => railway.parseConfig('railway'), SyncConfigError);
  assert.throws(() => railway.parseConfig({ projectId: PROJECT }), /"environmentId" is required/);
  assert.throws(() => railway.parseConfig({ ...config, projectId: 'my-project' }), /"projectId" must be a Railway project ID/);
  assert.throws(() => railway.parseConfig({ ...config, serviceId: 'web' }), /"serviceId" must be a Railway service ID/);
  assert.throws(() => railway.parseConfig({ ...config, tokenKind: 'team' }), /"tokenKind" must be one of "account", "project"/);
  assert.throws(() => railway.parseConfig({ ...config, service: SERVICE }), /unknown field "service"/);
});

test('describes the destination in one line', () => {
  assert.equal(railway.describe(config), 'service 2d9eac60 · environment 1c8d9b5f · project 0b7c8a4e');
  assert.equal(
    railway.describe({ projectId: PROJECT, environmentId: ENVIRONMENT }),
    'shared variables · environment 1c8d9b5f · project 0b7c8a4e',
  );
});

test('checks names against Railway rules', () => {
  assert.deepEqual(railway.checkKey('DATABASE_URL'), { ok: true });
  assert.deepEqual(railway.checkKey('lower-case.ok'), { ok: true });
  assert.equal(railway.checkKey('').ok, false);
  assert.match((railway.checkKey('RAILWAY_TOKEN') as { reason: string }).reason, /RAILWAY_/);
});

test('lists unrendered variables with an account token, hiding Railway-provided ones', async () => {
  const { fetch, requests } = graphql({ variables: listed(['DATABASE_URL', 'RAILWAY_PUBLIC_DOMAIN', 'API_KEY']) });

  const keys = await railway.listKeys({ token: TOKEN, fetch }, config);

  assert.deepEqual(keys, ['DATABASE_URL', 'API_KEY']);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0]!.headers, { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' });
  assert.deepEqual(variablesOf(requests[0]!), {
    projectId: PROJECT,
    environmentId: ENVIRONMENT,
    serviceId: SERVICE,
    unrendered: true,
  });
  assert.match((requests[0]!.body as GraphQLRequest).query, /variables\(projectId: \$projectId/);
});

test('sends a project token in Project-Access-Token and asks for shared variables without a service', async () => {
  const { fetch, requests } = graphql({ variables: listed(['SHARED']) });

  await railway.listKeys({ token: TOKEN, fetch }, { projectId: PROJECT, environmentId: ENVIRONMENT, tokenKind: 'project' });

  assert.deepEqual(requests[0]!.headers, { 'project-access-token': TOKEN, 'content-type': 'application/json' });
  assert.equal(variablesOf(requests[0]!).serviceId, null);
});

test('upserts in one call without replacing, and deletes only what exists', async () => {
  const { fetch, requests } = graphql({
    variables: listed(['OLD_KEY', 'UNMANAGED']),
    variableDelete: { body: { data: { variableDelete: true } } },
    variableCollectionUpsert: { body: { data: { variableCollectionUpsert: true } } },
  });

  const result = await railway.apply({ token: TOKEN, fetch }, config, {
    upsert: [
      { key: 'DATABASE_URL', value: 'postgres://u:hunter2@db/app' },
      { key: 'API_KEY', value: 'sk_live_abc' },
    ],
    delete: ['OLD_KEY', 'NEVER_EXISTED'],
  });

  assert.deepEqual(result, {
    upserted: ['DATABASE_URL', 'API_KEY'],
    deleted: ['OLD_KEY', 'NEVER_EXISTED'],
    failed: [],
  });
  assert.deepEqual(requests.map(operation), ['variables', 'variableDelete', 'variableCollectionUpsert']);
  assert.deepEqual(variablesOf(requests[1]!), {
    input: { projectId: PROJECT, environmentId: ENVIRONMENT, serviceId: SERVICE, name: 'OLD_KEY' },
  });
  assert.deepEqual(variablesOf(requests[2]!), {
    input: {
      projectId: PROJECT,
      environmentId: ENVIRONMENT,
      serviceId: SERVICE,
      variables: { DATABASE_URL: 'postgres://u:hunter2@db/app', API_KEY: 'sk_live_abc' },
      replace: false,
      skipDeploys: false,
    },
  });
});

test('an upsert-only plan does not list first, and shared variables omit serviceId', async () => {
  const { fetch, requests } = graphql({
    variableCollectionUpsert: { body: { data: { variableCollectionUpsert: true } } },
  });

  await railway.apply({ token: TOKEN, fetch }, { projectId: PROJECT, environmentId: ENVIRONMENT }, {
    upsert: [{ key: 'SHARED', value: 'shared-value' }],
    delete: [],
  });

  assert.deepEqual(requests.map(operation), ['variableCollectionUpsert']);
  assert.ok(!('serviceId' in variablesOf(requests[0]!).input));
});

test('reports a refused delete per key and keeps going; a refused upsert fails its batch', async () => {
  const { fetch } = graphql({
    variables: listed(['LOCKED', 'FREE']),
    variableDelete: (request) =>
      variablesOf(request).input.name === 'LOCKED'
        ? { body: { data: null, errors: [{ message: 'Variable is referenced by another service' }] } }
        : { body: { data: { variableDelete: true } } },
    variableCollectionUpsert: {
      body: { data: null, errors: [{ message: 'Invalid variable value "sk_value_1"' }] },
    },
  });

  const result = await railway.apply({ token: TOKEN, fetch }, config, {
    upsert: [
      { key: 'RAILWAY_TOKEN', value: 'never-sent' },
      { key: 'A_KEY', value: 'sk_value_1' },
    ],
    delete: ['LOCKED', 'FREE'],
  });

  assert.deepEqual(result.deleted, ['FREE']);
  assert.deepEqual(result.upserted, []);
  assert.deepEqual(
    result.failed.map((failure) => [failure.key, failure.operation, failure.message]),
    [
      ['RAILWAY_TOKEN', 'upsert', 'Railway reserves names starting with RAILWAY_'],
      ['LOCKED', 'delete', 'Railway rejected this change: Variable is referenced by another service'],
      // The upstream echoed the value back; the guard must strip it.
      ['A_KEY', 'upsert', 'Railway rejected this change: Invalid variable value "[redacted]"'],
    ],
  );
});

test('maps "Not Authorized" on HTTP 200 to unauthorized without leaking the token', async () => {
  const { fetch } = graphql({ variableCollectionUpsert: notAuthorized });

  const error = await rejection(
    railway.apply({ token: TOKEN, fetch }, config, {
      upsert: [{ key: 'A_KEY', value: 'value-that-must-not-leak' }],
      delete: [],
    }),
  );

  assert.ok(error instanceof SyncProviderError);
  assert.equal(error.code, 'unauthorized');
  assert.equal(error.status, 200);
  assert.equal(error.message, 'Railway: Not Authorized');
  assertNoLeak(error.message, [TOKEN, 'value-that-must-not-leak']);
});

test('a denied delete stops the run instead of failing every key', async () => {
  const { fetch, requests } = graphql({ variables: listed(['A', 'B']), variableDelete: notAuthorized });
  const error = await rejection(railway.apply({ token: TOKEN, fetch }, config, { upsert: [], delete: ['A', 'B'] }));
  assert.equal(error.code, 'unauthorized');
  assert.equal(requests.length, 2);
});

test('HTTP-level failures map to whole-call codes', async () => {
  const upstream = graphql({ variables: { status: 503, body: 'upstream connect error' } });
  const down = await rejection(railway.listKeys({ token: TOKEN, fetch: upstream.fetch }, config));
  assert.equal(down.code, 'upstream');
  assert.equal(upstream.requests.length, 3, 'one try plus two retries');

  const limited = graphql({ variables: { status: 429, headers: { 'retry-after': '60' } } });
  const slowed = await rejection(railway.listKeys({ token: TOKEN, fetch: limited.fetch }, config));
  assert.equal(slowed.code, 'rate_limited');

  const malformed = graphql({ variables: { status: 400, body: { errors: [{ message: 'Unknown argument "unrendered"' }] } } });
  const broken = await rejection(railway.listKeys({ token: TOKEN, fetch: malformed.fetch }, config));
  assert.equal(broken.code, 'upstream');
  assert.match(broken.message, /Unknown argument/);
});

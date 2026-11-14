// A service account's trust bindings over HTTP on the 0.16 contract
// (docs/design/0.16.md, "A workload signing in"): the list is one call to
// the vault (`caller`) and one statement; making, re-keying and removing one
// is one `change` and no statement, and one `caller` and one statement more
// before the app asks an issuer anything. The app asks an issuer where its keys
// are, and words a binding's mistakes, before the vault is asked anything.
// Who may bind, and what a binding reaches, is the vault's
// (packages/vault/test/bindings.test.ts); here, what the app does around it.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { PERMISSIONS } from '@coffre/core/access';
import { github, signin } from '@coffre/core/identity';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';

import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp } from './app-fixture.ts';

const KUBE = 'https://kubernetes.acme.example';
const KEYS = `${KUBE}/openid/v1/jwks`;
const POD = { sub: 'system:serviceaccount:ci:runner' };

/** What the issuers publish, by URL; every URL the app fetched, in order. */
const published = new Map<string, unknown>();
const fetched: string[] = [];
const transport: WorkloadTransport = {
  async json(url) {
    fetched.push(url.href);
    if (!published.has(url.href)) throw FetchRefused.answered(url, 404);
    return published.get(url.href);
  },
};

const workloads = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth: workloads, transport, workloads: {} });
const { world } = app;
after(() => app.close());

const [root, ada, bo] = [user('root'), user('ada'), user('bo')];
const ci = 'token:ci';
const ids: Record<string, string> = {};

/**
 * Root owns the instance. market has dev and a protected prod. Ada owns
 * market by a grant; Bo is a Developer of market/dev. The service `ci`
 * holds Developer on market/dev and Viewer on market/prod; dev holds
 * DATABASE_URL. `ci-cli` is the service's own token; `root-token` Root's
 * personal token, scoped to market.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  published.clear();
  published.set(`${KUBE}/.well-known/openid-configuration`, { issuer: KUBE, jwks_uri: KEYS });
  fetched.length = 0;
  const market = project('market');
  const dev = environment(market, 'dev');
  const prod = environment(market, 'prod', { protected: true });
  const url = value(world, secret(dev, 'DATABASE_URL'), 'postgres://dev');
  Object.assign(ids, { market: market.id, dev: dev.id, prod: prod.id, url: url.id });
  await write(
    world,
    ...rows('roles', role(true, 'owner', [...PERMISSIONS]), role(true, 'member', []), role(false, 'owner', [...PERMISSIONS]),
      role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'], ['secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use'], ['secret.use'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(ci)),
    ...rows('projects', market),
    ...rows('environments', dev, prod),
    ...rows('grants', grant(ada, 'owner', { project: market }), grant(bo, 'developer', { environment: dev }), grant(ci, 'developer', { environment: dev }), grant(ci, 'viewer', { environment: prod })),
    ...rows('secrets', url),
    ...rows('policy', instance()),
    ...rows('credentials', credential('root-cli', root), credential('ada-cli', ada), credential('bo-cli', bo), credential('ci-cli', ci),
      credential('root-token', root, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })),
  );
  // The schema's check, made once: no request below pays it.
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = ([status, body]: [number, Body]) => [status, body.error, body.reason];
const bind = (label: string, body: Record<string, unknown>, query = '') => cost(() => call(label, 'POST', `/members/${ci}/bindings${query}`, { profile: 'custom', issuer: KUBE, claims: POD, ...body }));
const list = (label: string, member = ci) => cost(() => call(label, 'GET', `/members/${member}/bindings`));

type View = { id: string; profile: string; issuer: string; jwksUri: string; keys: unknown; claims: unknown; scope: unknown; policy: unknown; label: string | null; createdAt: string; createdBy: string; lastUsedAt: string | null };

test('a manager makes a binding: weighed as one, its issuer asked where its keys are, then one change; its service\'s list shows it, one caller and one statement', async () => {
  const [[status, body], calls, statements] = await bind('ada-cli', { label: 'pods', scope: { 'market/dev': 'developer' } });
  assert.equal(status, 200, JSON.stringify(body));
  const { binding: made, replaced } = body as { binding: { id: string; scope: unknown }; replaced: string[] };
  assert.deepEqual({ scope: made.scope, replaced }, { scope: { 'market/dev': 'developer' }, replaced: [] });
  assert.deepEqual([calls, statements], [['caller', 'change'], 1]);
  // The discovery document, once, and never the keys: those are fetched by an exchange.
  assert.deepEqual(fetched, [`${KUBE}/.well-known/openid-configuration`]);

  const [[listed, shown], listCalls, listStatements] = await list('ada-cli');
  assert.equal(listed, 200);
  assert.deepEqual([listCalls, listStatements], [['caller'], 1]);
  const [only] = (shown as { bindings: View[] }).bindings;
  assert.deepEqual({ ...only!, createdAt: undefined }, {
    id: made.id, profile: 'custom', issuer: KUBE, jwksUri: KEYS, keys: null, claims: POD, scope: { 'market/dev': 'developer' }, policy: null,
    label: 'pods', createdAt: undefined, createdBy: ada, lastUsedAt: null,
  });
  assert.ok(!Number.isNaN(Date.parse(only!.createdAt)));
});

test('the list is the service\'s own, and its managers\': anyone else is told no more than of a service that is not there', async () => {
  await write(world, ...rows('bindings', binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: JSON.stringify(POD), scope: JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'developer' }]) })));
  for (const label of ['root-cli', 'ada-cli', 'ci-cli']) {
    const [[status, body], calls, statements] = await list(label);
    assert.deepEqual([status, (body as { bindings: View[] }).bindings.length, calls, statements], [200, 1, ['caller'], 1], label);
  }
  // Bo holds less than the service, and a scoped token of whoever runs the instance manages nothing.
  for (const label of ['bo-cli', 'root-token']) {
    const [answer, calls, statements] = await list(label);
    assert.deepEqual([refused(answer), calls, statements], [[403, 'vault_refused', 'no_access'], ['caller'], 1], label);
  }
  assert.deepEqual(refused((await list('ada-cli', 'token:nobody'))[0]), [403, 'vault_refused', 'no_access']);
  assert.deepEqual(refused((await list('root-cli', 'token:nobody'))[0]), [404, 'not_found', 'unknown_principal']);
  assert.deepEqual(refused((await list('root-cli', 'user:ada@acme.example'))[0]), [400, 'bad_request', undefined]);
});

test("a service removed and let back in lists its bindings of now: those of before stay its history", async () => {
  const back = 'token:back';
  const old = binding(back, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: JSON.stringify(POD), scope: '[]', generation: 0 });
  const now = binding(back, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: JSON.stringify({ sub: 'system:serviceaccount:ci:next' }), scope: '[]', generation: 1 });
  await write(world, ...rows('principals', principal(back, { generation: 1 })), ...rows('bindings', old, now));
  const [[status, body]] = await list('root-cli', back);
  assert.deepEqual([status, (body as { bindings: View[] }).bindings.map((row) => row.id)], [200, [now.id]]);
});

test('the list names places and keys as they are named now, a key\'s reads by name, and an uploaded set by its keys', async () => {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwks = JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' }] });
  const scope = JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'developer' }, { projectId: ids.market, environmentId: ids.prod, role: 'viewer' }]);
  const policy = JSON.stringify({ reads: { [ids.dev!]: { keys: [ids.url] } } });
  await write(world, ...rows('bindings', binding(ci, { profile: 'kubernetes', issuer: KUBE, jwksUri: 'sha256:00', jwks, claims: JSON.stringify(POD), scope, policy })));
  const [[, body]] = await list('ada-cli');
  const [only] = (body as { bindings: View[] }).bindings;
  assert.deepEqual({ scope: only!.scope, policy: only!.policy, keys: (only!.keys as { kid: string }[]).map((key) => key.kid) }, {
    scope: { 'market/dev': 'developer', 'market/prod': 'viewer' },
    policy: { reads: { 'market/dev': ['DATABASE_URL'] } },
    keys: ['k1'],
  });
});

test('a binding is checked before anything is asked: its profile\'s rules, its keys, its issuer\'s discovery; each a 400 that says why', async () => {
  const cases: [string, Record<string, unknown>][] = [
    ['a claim its profile does not take', { profile: 'github', issuer: null, claims: { nope: 'x' } }],
    ['keys that are no JWKS', { jwks: { keys: [{ kty: 'oct', k: 'c2VjcmV0' }] } }],
    ['a policy its profile refuses', { policy: { sessionHours: 1_000 } }],
    // The contract's shape, which the vault takes as a fault, never a refusal: told here first.
    ['a label with a control character', { label: 'pods\nci' }],
    ['a scope that names no place', { scope: { Market: 'viewer' } }],
    ['an empty scope', { scope: {} }],
    ['a read of a project, not an environment', { policy: { reads: { market: '*' } } }],
    ['a binding replaced twice', { replaces: [ids.dev, ids.dev] }],
    ['an issuer with a NUL', { issuer: 'https://kube\u0000.acme.example' }],
  ];
  for (const [what, body] of cases) {
    const [[status, answer], calls, statements] = await bind('ada-cli', body);
    assert.deepEqual([status, answer.error, calls, statements], [400, 'bad_request', [], 0], what);
    assert.ok(typeof answer.message === 'string' && answer.message.length > 0, what);
  }
  // An issuer's discovery, asked once the caller is weighed: a document there is none of, and one whose keys' address is longer than a binding keeps.
  const [[status, answer], calls, statements] = await bind('ada-cli', { issuer: 'https://elsewhere.acme.example' });
  assert.deepEqual([status, calls, statements], [400, ['caller'], 1]);
  assert.match(String(answer.message), /coffre could not use https:\/\/elsewhere\.acme\.example/);
  const LONG = 'https://long.acme.example';
  published.set(`${LONG}/.well-known/openid-configuration`, { issuer: LONG, jwks_uri: `${LONG}/${'k'.repeat(2_100)}` });
  const [long] = await bind('ada-cli', { issuer: LONG });
  assert.deepEqual(refused(long), [400, 'bad_request', undefined]);
  assert.match(String(long[1].message), /longer than the 2,048 characters a binding keeps/);
  // The input's own shape, and a member that is no service.
  assert.equal((await bind('ada-cli', { claims: 'x' }))[0][0], 400);
  assert.deepEqual(refused(await call('ada-cli', 'POST', `/members/${ada}/bindings`, { profile: 'custom', issuer: KUBE, claims: POD })), [400, 'bad_request', undefined]);
});

test('a preview is not served yet: 501, and nothing asked', async () => {
  const [answer, calls, statements] = await bind('ada-cli', {}, '?dryRun=1');
  assert.deepEqual([refused(answer), calls, statements], [[501, 'not_implemented', undefined], [], 0]);
  const [keysAnswer] = await cost(() => call('ada-cli', 'POST', `/members/${ci}/bindings/keys?dryRun=1`, { issuer: KUBE, jwks: { keys: [] } }));
  assert.equal(keysAnswer[0], 501);
});

test("the vault's refusals, in words: who does not manage the service, a role the instance lacks, a service that is not there", async () => {
  // Whoever does not manage the service makes coffre ask no issuer anything: a member with no grant on it, a scoped token, the service itself.
  for (const label of ['bo-cli', 'root-token', 'ci-cli']) {
    const [answer, calls, statements] = await bind(label, {});
    assert.deepEqual([refused(answer), calls, statements, fetched], [[403, 'vault_refused', 'no_access'], ['caller'], 1, []], label);
  }
  // Keys it carries are asked of no one: the vault alone weighs who binds.
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const [carried, carriedCalls] = await bind('bo-cli', { jwks: { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' }] } });
  assert.deepEqual([refused(carried), carriedCalls], [[403, 'vault_refused', 'no_access'], ['change']]);
  const [invalid] = await bind('ada-cli', { scope: { 'market/dev': 'nope' } });
  assert.deepEqual(refused(invalid), [409, 'conflict', 'invalid']);
  assert.match(String(invalid[1].message), /^service:ci: a role the instance does not have, a read outside its scope/);
  const [[status, body]] = await cost(() => call('root-cli', 'POST', '/members/token:nobody/bindings', { profile: 'custom', issuer: KUBE, claims: POD }));
  assert.deepEqual([status, body.reason], [404, 'unknown_principal']);
});

test("an issuer's bindings re-keyed: each replaced by one the same but for its keys, in one change", async () => {
  const [[, first]] = await bind('ada-cli', { scope: { 'market/dev': 'developer' } });
  const was = (first as { binding: { id: string } }).binding.id;
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k2', alg: 'ES256', use: 'sig' }] };
  const [[status, body], calls, statements] = await cost(() => call('ada-cli', 'POST', `/members/${ci}/bindings/keys`, { issuer: KUBE, jwks }));
  assert.equal(status, 200, JSON.stringify(body));
  const { bindings, replaced } = body as { bindings: { id: string; scope: unknown }[]; replaced: string[] };
  assert.deepEqual([bindings.map((made) => made.scope), replaced, calls, statements], [[{ 'market/dev': 'developer' }], [was], ['change'], 0]);
  const [[, listed]] = await list('ada-cli');
  const [only] = (listed as { bindings: View[] }).bindings;
  assert.deepEqual([only!.id, only!.jwksUri.startsWith('sha256:'), (only!.keys as { kid: string }[]).map((key) => key.kid)], [bindings[0]!.id, true, ['k2']]);
  // The same keys again, and an issuer with no binding.
  assert.deepEqual(refused((await cost(() => call('ada-cli', 'POST', `/members/${ci}/bindings/keys`, { issuer: KUBE, jwks })))[0]), [409, 'conflict', 'same_keys']);
  assert.deepEqual(refused((await cost(() => call('ada-cli', 'POST', `/members/${ci}/bindings/keys`, { issuer: 'https://other.acme.example', jwks })))[0]), [404, 'not_found', 'unknown_binding']);
});

test('removing a binding is one change; one not live is not found, and whoever does not manage the service is refused', async () => {
  const [[, first]] = await bind('ada-cli', {});
  const id = (first as { binding: { id: string } }).binding.id;
  const remove = (label: string) => cost(() => call(label, 'DELETE', `/members/${ci}/bindings/${id}`));
  assert.deepEqual(refused((await remove('bo-cli'))[0]), [403, 'vault_refused', 'no_access']);
  const [[status, body], calls, statements] = await remove('ada-cli');
  assert.deepEqual([status, body, calls, statements], [200, { unbound: true }, ['change'], 0]);
  assert.deepEqual(refused((await remove('ada-cli'))[0]), [404, 'not_found', 'unknown_binding']);
  assert.deepEqual((await list('ada-cli'))[0][1], { bindings: [] });
});

test('a service named as the vault takes none, or a binding by an id in capitals: the first a 400 with nothing asked, the second the same binding', async () => {
  const jwks = { keys: [] };
  for (const member of ['token:a b', 'token::x', 'token:']) {
    const named = encodeURIComponent(member);
    for (const [method, path, body] of [['GET', `/members/${named}/bindings`], ['POST', `/members/${named}/bindings`, { profile: 'custom', issuer: KUBE, claims: POD }], ['POST', `/members/${named}/bindings/keys`, { issuer: KUBE, jwks }], ['DELETE', `/members/${named}/bindings/${crypto.randomUUID()}`]] as const) {
      const [answer, calls, statements] = await cost(() => call('root-cli', method, path, body));
      assert.deepEqual([refused(answer), calls, statements], [[400, 'bad_request', undefined], [], 0], `${method} ${path}`);
    }
  }
  const [[, first]] = await bind('ada-cli', {});
  const id = (first as { binding: { id: string } }).binding.id;
  const [[status, again]] = await bind('ada-cli', { replaces: [id.toUpperCase()] });
  assert.deepEqual([status, (again as { replaced: string[] }).replaced], [200, [id]]);
  const next = (again as { binding: { id: string } }).binding.id;
  assert.deepEqual((await cost(() => call('ada-cli', 'DELETE', `/members/${ci}/bindings/${next.toUpperCase()}`)))[0], [200, { unbound: true }]);
});

test('a row kept in a shape the vault would not write is listed as best it reads, never as a binding a CI run takes; a place deleted, by its id', async () => {
  const old = environment({ id: ids.market! }, 'old~deleted-2026-10-05');
  await write(world, ...rows('environments', old));
  const scope = JSON.stringify([{ projectId: ids.market, environmentId: old.id, role: 'viewer' }]);
  const policies = ['{"reads":null}', `{"reads":{"${ids.dev}":null}}`, '{"reads":{"x":{"keys":5}}}', 'not json', '[1]'];
  await write(world, ...rows('bindings', ...policies.map((policy) => binding(ci, { profile: 'kubernetes', issuer: KUBE, jwksUri: KEYS, claims: JSON.stringify(POD), scope, policy }))));
  const [[status, body]] = await list('ada-cli');
  assert.equal(status, 200, JSON.stringify(body));
  const shown = (body as { bindings: View[] }).bindings;
  assert.deepEqual(new Set(shown.map((row) => JSON.stringify(row.policy))), new Set(['{"reads":{}}', '{}']));
  assert.deepEqual(shown[0]!.scope, { [old.id]: 'viewer' });
});

test('with workloads off, each route says how to turn them on, and asks nothing', async () => {
  const off = await openApp();
  try {
    for (const [method, path, body] of [['GET', `/members/${ci}/bindings`], ['POST', `/members/${ci}/bindings`, { profile: 'custom', issuer: KUBE, claims: POD }], ['DELETE', `/members/${ci}/bindings/${crypto.randomUUID()}`]] as const) {
      const got = await off.request(`/api${path}`, { method, headers: { authorization: 'Bearer ada-cli' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const answer = (await got.json()) as Body;
      assert.deepEqual([got.status, answer.error, off.calls], [404, 'not_found', []], `${method} ${path}`);
      assert.match(String(answer.message), /signin\(\{ workloads/);
    }
  } finally {
    await off.close();
  }
});

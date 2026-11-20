// A credential's rules, `rules: [allow(…), deny(…)]`: the first that matches a request's method and path decides, and
// a request none matches is refused, before the vault opens anything or a byte goes upstream. The credential here is
// shaped like a database provider's, whose key reaches every instance of a project, the live one included: its rules
// let a holder snapshot the live instance and do anything to the others, and nothing else to the live one.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates } from '../src/gate.ts';
import { allow, credentialProxy, decide, deny, header, json, sigv4, type Egress, type Place, type Rule } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const KEY = 'rdb-key-0123456789';
const LIVE = '0d6f2c4e-8b1a-4c3d-9e5f-a7b6c5d4e3f2';
const COPY = '7f3ab21c-5d4e-4f60-8a9b-0c1d2e3f4a5b';
const UPSTREAM = 'https://rdb.example/v1';

/** Every request the egress was asked to send. */
const sent: { method: string; url: URL; body: string | null; headers: Headers }[] = [];
const egress: Egress = {
  async fetch(input, init) {
    sent.push({ method: init.method ?? 'GET', url: input, body: init.body == null ? null : new TextDecoder().decode(init.body as Uint8Array), headers: new Headers(init.headers) });
    return Response.json({ ok: true });
  },
};

/** The addresses a copy's endpoint may take, by environment: a body that names another, the live instance's or another environment's, never goes. */
const POOLS: Record<string, string[]> = { prod: ['192.168.255.240', '192.168.255.241'], dev: ['192.168.255.224'] };
const NETWORK = '5b1c9e0a-3f2d-4c8b-9a7e-6d5c4b3a2f10';
/** An endpoint on the private network, at one of its environment's pool addresses, and nothing else in the body. */
const onPool = (body: unknown, { environment }: Place) => {
  const spec = (body as { endpoint_spec?: { private_network?: Record<string, unknown> } }).endpoint_spec;
  const network = spec?.private_network;
  return Object.keys(body as object).length === 1 && Object.keys(spec!).length === 1 && network !== undefined
    && Object.keys(network).sort().join() === 'private_network_id,service_ip' && network.private_network_id === NETWORK
    && typeof network.service_ip === 'string' && (POOLS[environment] ?? []).includes(network.service_ip.split('/')[0]!) && /^[0-9.]+\/\d{1,2}$/.test(network.service_ip);
};
const endpoint = (ip: string) => ({ endpoint_spec: { private_network: { private_network_id: NETWORK, service_ip: ip } } });

/** What `counted` was given, and its rule: a limit that is a number. */
const given: { body: unknown; place: Place }[] = [];
const counted = (body: unknown, place: Place) => {
  given.push({ body, place });
  return typeof (body as { limit?: unknown }).limit === 'number';
};

const rules: Rule[] = [
  allow('GET', '/instances'),
  allow('GET', '/instances/{uuid}'),
  allow('POST', `/instances/${LIVE}/snapshots`),
  deny('*', `/instances/${LIVE}/**`),
  allow('POST', '/instances'),
  allow('POST', '/snapshots/{uuid}/create-instance'),
  // Any other instance, itself and everything under it.
  allow('*', '/instances/{uuid}/**'),
];

const proxy = credentialProxy({
  credentials: {
    rdb: { upstream: UPSTREAM, inject: header('x-auth-token', '{RDB_KEY}'), rules, egress },
    // Rules beside methods and paths: each holds, and the rules decide what the other two let through.
    narrow: { upstream: UPSTREAM, inject: header('x-auth-token', '{RDB_KEY}'), methods: ['GET', 'POST'], paths: ['/instances'], rules: [deny('POST', '/instances'), allow('*', '/**')], egress },
    // A body rule: a copy's endpoint only at a pool address, and the rules after it never reached for that path.
    endpoints: { upstream: UPSTREAM, inject: header('x-auth-token', '{RDB_KEY}'), rules: [allow('POST', '/instances/{uuid}/endpoints', { body: onPool }), allow('*', '/**')], egress },
    // A body rule that keeps what it was given, to show which value and place it checks.
    limited: { upstream: UPSTREAM, inject: header('x-auth-token', '{RDB_KEY}'), rules: [allow('POST', '/limit', { body: counted })], egress },
    s3: {
      upstream: 'https://s3.example',
      inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }),
      rules: [allow('GET', '/reports/*'), deny('*', '/**')],
    },
  },
});

let held = processGates();
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates: (service) => held(service), plugins: [proxy] });
const { world } = app;
after(() => app.close());

const ops = project('ops');
const prod = environment(ops, 'prod');
const scope = JSON.stringify([{ projectId: ops.id, environmentId: prod.id, role: 'developer' }]);
let handle: string;
let deploy: { token: string; key: ProofKey };

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  held = processGates();
  sent.length = 0;
  given.length = 0;
  handle = generateToken('handle');
  const bound = binding(DEPLOY, { policy: '{}', scope });
  const key = await generateProofKey();
  deploy = { token: generateToken('workload'), key };
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', ops),
    ...rows('environments', prod),
    ...rows('principals', principal(ADA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'developer', { project: ops }), grant(DEPLOY, 'developer', { project: ops })),
    ...rows('secrets', value(world, secret(prod, 'RDB_KEY'), KEY, { sensitive: true }), value(world, secret(prod, 'AWS_ACCESS_KEY_ID'), 'AKIAPROD', { plain: true }), value(world, secret(prod, 'AWS_SECRET_ACCESS_KEY'), 'aws-secret-0123')),
    ...rows('bindings', bound),
    ...rows('credentials',
      credential(handle, ADA, { kind: 'handle', scope, places: JSON.stringify([{ environmentId: prod.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) }),
      session(deploy.token, bound, { jkt: await thumbprint(key.jwk), scope, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) })),
  );
  await app.request('/livez');
  await world.owner.execute(sql`DELETE FROM log_pending`);
  app.calls.length = 0;
});

/** `method path` through a credential with Ada's handle, the stable URL's. */
const asHandle = (method: string, path: string, init: RequestInit = {}) =>
  app.request(`/use/${path.replace(/^\//, '')}`, { ...init, method, headers: { ...(init.headers as Record<string, string>), "x-auth-token": handle }, ...(method === 'GET' || method === 'HEAD' ? {} : { body: '{}' }) });

/** The same as the deploy service's session, its proof under the gate's nonce: `{}`, unless `sending` says the body and its type. */
async function asSession(method: string, path: string, sending?: { body: string | Uint8Array<ArrayBuffer>; type?: string; headers?: Record<string, string> }): Promise<Response> {
  const url = `${PUBLIC_URL}/use/${path.replace(/^\//, '')}`;
  const given = sending?.body ?? (method === 'GET' || method === 'HEAD' ? '' : '{}');
  const body = typeof given === 'string' ? new TextEncoder().encode(given) : given;
  const headers: Record<string, string> = body.length === 0 ? {} : { 'content-type': sending?.type ?? 'application/json', 'content-digest': `sha-256=:${Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')}:`, ...sending?.headers };
  const proof = await createProof(deploy.key, { method, url, token: deploy.token, nonce: await held(DEPLOY).nonce(), content: { headers, body: await bodyDigest(body) } });
  return app.request(`/use/${path.replace(/^\//, '')}`, { method, headers: { ...headers, authorization: `DPoP ${deploy.token}`, dpop: proof }, ...(body.length === 0 ? {} : { body }) });
}

/** What a refusal says, and that nothing opened or went. */
async function refused(answer: Response, message: RegExp, opened: number) {
  const body = (await answer.json()) as { error: string; reason: string; message: string };
  assert.deepEqual([answer.status, body.reason, answer.headers.get('coffre-proxy')], [403, 'rule', 'refused'], JSON.stringify(body));
  assert.match(body.message, message);
  assert.equal(app.calls.filter((call) => call === 'use').length, opened, 'the vault opened nothing');
  assert.equal(sent.length, 0, 'nothing went upstream');
}

test('each request a rule allows goes on with the key, as a handle and as a session', async () => {
  const allowed: [string, string][] = [
    ['GET', '/instances'],
    ['GET', `/instances/${LIVE}`],
    ['POST', `/instances/${LIVE}/snapshots`],
    ['POST', '/instances'],
    ['POST', `/snapshots/${COPY}/create-instance`],
    ['PATCH', `/instances/${COPY}`],
    ['DELETE', `/instances/${COPY}`],
    ['POST', `/instances/${COPY}/users`],
    ['PATCH', `/instances/${COPY}/users/app`],
    ['DELETE', `/instances/${COPY}/acls`],
    ['PUT', `/instances/${COPY}/users/app`],
  ];
  for (const send of [asHandle, asSession]) {
    for (const [method, path] of allowed) {
      sent.length = 0;
      const answer = await send(method, `/rdb${path}`);
      assert.equal(answer.status, 200, `${send.name} ${method} ${path}: ${await answer.clone().text()}`);
      assert.deepEqual([sent.length, sent[0]!.method, sent[0]!.url.href], [1, method, `${UPSTREAM}${path}`], `${method} ${path}`);
    }
  }
});

test('a request a deny matches is refused before anything opens, quoting the rule, as a handle and as a session', async () => {
  for (const send of [asHandle, asSession]) {
    for (const [method, path] of [['PATCH', `/instances/${LIVE}`], ['DELETE', `/instances/${LIVE}`], ['POST', `/instances/${LIVE}/users`], ['PATCH', `/instances/${LIVE}/users/app`], ['PUT', `/instances/${LIVE}/acls`], ['GET', `/instances/${LIVE}/logs`], ['POST', `/instances/${LIVE}/snapshots/x`], ['DELETE', `/instances/${LIVE}/`]]) {
      await refused(await send(method!, `/rdb${path}`), new RegExp(`^rdb refuses ${method} ${path!.replace(/[/]/g, '\\/')}: deny\\(\\*, \\/instances\\/${LIVE}\\/\\*\\*\\)$`), 0);
    }
  }
});

test('a request no rule matches is refused: a path the rules do not name, a method they do not list, a mutation of the root', async () => {
  for (const [method, path] of [['DELETE', '/endpoints/aa'], ['POST', '/backups'], ['POST', `/endpoints/${COPY}/migrate`], ['DELETE', '/instances'], ['PUT', `/snapshots/${COPY}`], ['POST', `/snapshots/${COPY}`], ['GET', '/'], ['HEAD', '/snapshots']]) {
    await refused(await asHandle(method!, `/rdb${path}`), new RegExp(`^rdb has no rule that allows ${method} `), 0);
  }
  // The credential itself, with no path or a bare slash.
  await refused(await asHandle('GET', '/rdb'), /^rdb has no rule that allows GET \/$/, 0);
  await refused(await asHandle('GET', '/rdb/'), /^rdb has no rule that allows GET \/$/, 0);
});

test('another spelling of a denied id matches no allow: case, braces, urn, bare digits, an encoded digit, a parameter, an empty segment', async () => {
  const bare = LIVE.replace(/-/g, '');
  for (const spelled of [LIVE.toUpperCase(), `{${LIVE}}`, `urn:uuid:${LIVE}`, bare, `%30${LIVE.slice(1)}`, `${LIVE};v=1`, `${LIVE}.json`]) {
    for (const path of [`/instances/${spelled}`, `/instances/${spelled}/users`]) {
      await refused(await asHandle('DELETE', `/rdb${path}`), /^rdb has no rule that allows DELETE /, 0);
    }
  }
  for (const path of [`/instances//${LIVE}`, `/instances//${LIVE}/users`, `//instances/${COPY}`]) {
    await refused(await asHandle('DELETE', `/rdb${path}`), /^rdb has no rule that allows DELETE /, 0);
  }
});

test('a method is read in capitals: a lowercase patch is held to the rules for PATCH', async () => {
  const lowercase = credentialProxy({ credentials: { x: { upstream: UPSTREAM, inject: header('x', '{K}'), rules: [deny('PATCH', '/a'), allow('*', '/**')] } } });
  assert.ok(lowercase);
  assert.deepEqual(decide([deny('PATCH', '/a'), allow('*', '/**')], 'patch', '/a'), { allowed: false, rule: 'deny(PATCH, /a)' });
  // Through the proxy, as fetch sends it: `patch` as written.
  await refused(await asHandle('patch', `/rdb/instances/${LIVE}`), /^rdb refuses PATCH \/instances\//, 0);
});

test('with rules, a method override is refused whatever it names, in a header or the query, before anything opens', async () => {
  for (const answer of [
    await asHandle('POST', `/rdb/instances/${COPY}/users`, { headers: { 'x-http-method-override': 'DELETE' } }),
    await asHandle('GET', `/rdb/instances/${COPY}?_method=DELETE`),
  ]) {
    const body = (await answer.json()) as { message: string };
    assert.equal(answer.status, 405);
    assert.match(body.message, /^rdb holds each method to its rules, and this request names a method in /);
  }
  assert.deepEqual([app.calls.filter((call) => call === 'use').length, sent.length], [0, 0]);
});

test("rules hold beside methods and paths: each refuses what it refuses", async () => {
  assert.equal((await asHandle('GET', '/narrow/instances')).status, 200);
  [sent.length, app.calls.length] = [0, 0];
  await refused(await asHandle('POST', '/narrow/instances'), /^narrow refuses POST \/instances: deny\(POST, \/instances\)$/, 0);
  assert.equal((await asHandle('DELETE', '/narrow/instances')).status, 405);
  assert.equal((await asHandle('GET', '/narrow/snapshots')).status, 403);
  assert.equal(sent.length, 0);
});

test('a presigned URL is made only for a path the rules allow', async () => {
  const presign = (path: string) => app.request('/use/ops/prod', { method: 'POST', headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/json' }, body: JSON.stringify({ presign: { credential: 's3', path } }) });
  const made = await presign('/reports/q3.pdf');
  assert.equal(made.status, 200, await made.clone().text());
  await refused(await presign('/private/q3.pdf'), /^s3 refuses GET \/private\/q3\.pdf: deny\(\*, \/\*\*\)$/, 1);
});

test('decide answers as the proxy does, naming the rule that decided', () => {
  assert.deepEqual(decide(rules, 'POST', `/instances/${LIVE}/snapshots`), { allowed: true, rule: `allow(POST, /instances/${LIVE}/snapshots)` });
  assert.deepEqual(decide(rules, 'DELETE', `/instances/${LIVE}`), { allowed: false, rule: `deny(*, /instances/${LIVE}/**)` });
  assert.deepEqual(decide(rules, 'DELETE', `/instances/${COPY}`), { allowed: true, rule: 'allow(*, /instances/{uuid}/**)' });
  assert.deepEqual(decide(rules, 'DELETE', '/endpoints/x'), { allowed: false, rule: null });
  // `**` takes nothing too: the instance itself, and everything under it.
  assert.equal(decide([allow('*', '/a/**')], 'GET', '/a').allowed, true);
  assert.equal(decide([allow('*', '/a/**')], 'GET', '/a/b/c').allowed, true);
  assert.equal(decide([allow('*', '/a/**')], 'GET', '/ab').allowed, false);
  assert.equal(decide([allow('GET', '/a/*')], 'GET', '/a/').allowed, false);
});

test('rules are a list of allow and deny, each methods and a pattern of segments as sent, *, {uuid} or a last **', () => {
  const made = (rules: unknown) => () => credentialProxy({ credentials: { a: { upstream: UPSTREAM, inject: header('x', '{K}'), rules: rules as Rule[] } } });
  assert.throws(made([]), /a's rules are a list of allow\(…\) and deny\(…\), at least one/);
  assert.throws(made('allow GET /'), /a's rules are a list/);
  assert.throws(made([{ verdict: 'maybe', methods: '*', path: '/' }]), /each allow\(methods, pattern\) or deny\(methods, pattern\)/);
  assert.throws(made([allow([], '/')]), /methods 'GET', \['PATCH', 'DELETE'\] or '\*'/);
  assert.throws(made([allow('GET POST', '/')]), /methods 'GET'/);
  assert.throws(made([allow('GET', 'instances')]), /a's allow\(GET, instances\) is for a path under the upstream: it starts with \//);
  assert.throws(made([allow('GET', '/instances/{id}')]), /a segment is one as the app sends it, \*, \{uuid\}, or \*\* last; got "\{id\}"/);
  assert.throws(made([allow('GET', '/a/**/b')]), /got "\*\*"/);
  assert.throws(made([allow('GET', '/a*')]), /got "a\*"/);
  assert.throws(made([allow('GET', '/a/../b')]), /got "\.\."/);
  assert.throws(made([allow('GET', '/a?b=1')]), /got "a\?b=1"/);
  assert.doesNotThrow(made([allow(['get', 'post'], '/a/*/{uuid}/**'), deny('*', '/')]));
});

/** A POST to a copy's endpoints with `body` as the app wrote it, as a handle. */
const postEndpoint = (body: string | Uint8Array<ArrayBuffer>, headers: Record<string, string> = { 'content-type': 'application/json' }) =>
  app.request(`/use/endpoints/instances/${COPY}/endpoints`, { method: 'POST', headers: { ...headers, 'x-auth-token': handle }, body });

test('an allow with body lets a body it passes go on, as the JSON it read, as a handle and as a session', async () => {
  const written = JSON.stringify(endpoint('192.168.255.240/22'));
  // As the app wrote it, spaced and with an escape: what goes is the value, written again.
  const given = `{ "endpoint_spec": { "private_network": { "private_network_id": "${NETWORK}", "service\\u005fip": "192.168.255.240/22" } } }`;
  const handled = await postEndpoint(given, { 'content-type': 'application/json; charset=utf-8' });
  assert.equal(handled.status, 200, await handled.clone().text());
  assert.deepEqual([sent.length, sent[0]!.body, sent[0]!.headers.get('content-type')], [1, written, 'application/json']);
  sent.length = 0;
  // A session's body declares its digest, so it would stream: one a rule checks is read whole, and its digest made again.
  const session = await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: given });
  assert.equal(session.status, 200, await session.clone().text());
  assert.deepEqual([sent.length, sent[0]!.body, sent[0]!.headers.get('content-type')], [1, written, 'application/json']);
  assert.equal(sent[0]!.headers.get('content-digest'), `sha-256=:${Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(written))).toString('base64')}:`);
  // The rules after it are for other paths: a body is read for none of theirs.
  sent.length = 0;
  assert.equal((await asHandle('POST', `/endpoints/instances/${COPY}/users`)).status, 200);
});

test('a key the body gives twice goes as JSON.parse read it, the last: the check and the upstream read one value', async () => {
  const twice = (first: string, last: string) => `{"endpoint_spec":{"private_network":{"private_network_id":"${NETWORK}","service_ip":"${first}","service_ip":"${last}"}}}`;
  assert.equal((await postEndpoint(twice('192.168.0.2/22', '192.168.255.241/22'))).status, 200);
  assert.equal(sent[0]!.body, JSON.stringify(endpoint('192.168.255.241/22')));
  [sent.length, app.calls.length] = [0, 0];
  await refused(await postEndpoint(twice('192.168.255.241/22', '192.168.0.2/22')), /^endpoints refuses POST \/instances\/[0-9a-f-]+\/endpoints: its body is none its allow takes$/, 0);
});

test('an allow with body refuses, before anything opens, a body it does not pass, and one it cannot read', async () => {
  const none = /^endpoints refuses POST \/instances\/[0-9a-f-]+\/endpoints: its body is none its allow takes$/;
  const json = /^endpoints allows POST \/instances\/[0-9a-f-]+\/endpoints with a JSON body it checks/;
  for (const body of [
    endpoint('192.168.0.2/22'),
    endpoint('192.168.255.240'),
    { endpoint_spec: { private_network: { private_network_id: NETWORK, ipam_config: {} } } },
    { endpoint_spec: { load_balancer: {} } },
    { endpoint_spec: { private_network: { private_network_id: NETWORK, service_ip: '192.168.255.240/22' }, load_balancer: {} } },
    { ...endpoint('192.168.255.240/22'), extra: 1 },
    [endpoint('192.168.255.240/22')],
    null,
    '192.168.255.240/22',
  ]) {
    await refused(await postEndpoint(JSON.stringify(body)), none, 0);
  }
  // A check that throws refuses: here, on a body with no endpoint_spec.
  await refused(await postEndpoint('{}'), none, 0);
  await refused(await postEndpoint(''), json, 0);
  await refused(await postEndpoint('{"endpoint_spec":'), json, 0);
  await refused(await postEndpoint(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])), json, 0);
  const good = JSON.stringify(endpoint('192.168.255.240/22'));
  const types: Record<string, string>[] = [{ 'content-type': 'text/plain' }, {}, { 'content-type': 'application/json; charset=latin1' }, { 'content-type': 'application/json; charset = iso-8859-1' }, { 'content-type': 'application/json; charset=utf-8; charset=latin1' }, { 'content-type': 'application/json, text/plain' }, { 'content-type': 'application/json', 'content-encoding': 'gzip' }, { 'content-type': 'application/x-www-form-urlencoded' }];
  for (const headers of types) {
    await refused(await postEndpoint(good, headers), json, 0);
  }
  // Another environment's address, from prod: each environment's pool is its own.
  await refused(await postEndpoint(JSON.stringify(endpoint('192.168.255.224/22'))), none, 0);
  // As a session too, the proof valid: the body is what the rule holds, not who sent it.
  await refused(await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: JSON.stringify(endpoint('192.168.0.2/22')) }), none, 0);
  await refused(await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: JSON.stringify(endpoint('192.168.255.224/22')) }), none, 0);
  await refused(await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: good, type: 'application/json; charset = iso-8859-1' }), json, 0);
  await refused(await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: good, headers: { 'content-encoding': 'gzip' } }), json, 0);
});

test('a body is checked as it goes: written, read again, from its place, its type said again', async () => {
  const limited = (body: string, headers: Record<string, string> = { 'content-type': 'application/json' }) =>
    app.request('/use/limited/limit', { method: 'POST', headers: { ...headers, 'x-auth-token': handle }, body });
  // 1e400 parses as Infinity and goes as null: the check is given null, and refuses it, as a handle and as a session.
  await refused(await limited('{"limit":1e400}'), /^limited refuses POST \/limit: its body is none its allow takes$/, 0);
  await refused(await asSession('POST', '/limited/limit', { body: '{"limit":1e400}' }), /^limited refuses POST \/limit: its body is none its allow takes$/, 0);
  assert.deepEqual(given.map((one) => one.body), [{ limit: null }, { limit: null }]);
  given.length = 0;
  // -0 goes as 0, which is what the check is given; the type goes as application/json whatever its parameters said.
  const answer = await limited('{"limit":-0}', { 'content-type': 'Application/JSON ; Charset = "UTF-8"' });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.deepEqual([sent[0]!.body, sent[0]!.headers.get('content-type')], ['{"limit":0}', 'application/json']);
  assert.ok(Object.is((given[0]!.body as { limit: number }).limit, 0));
  // The place is the handle's, and the session's.
  sent.length = 0;
  assert.equal((await asSession('POST', '/limited/limit', { body: '{"limit":2}' })).status, 200);
  assert.deepEqual(given.map((one) => one.place), [{ project: 'ops', environment: 'prod' }, { project: 'ops', environment: 'prod' }]);
  // decide gives its check the same value and place.
  given.length = 0;
  assert.equal(decide([allow('POST', '/limit', { body: counted })], 'POST', '/limit', { body: { limit: Infinity }, place: 'ops/dev@me' }).allowed, false);
  assert.deepEqual(given, [{ body: { limit: null }, place: { project: 'ops', environment: 'dev' } }]);
});

test('a body a rule checks is read whole, 64 KiB at most, a session\'s too', async () => {
  const long = JSON.stringify({ ...endpoint('192.168.255.240/22'), pad: 'x'.repeat(64 * 1024) });
  for (const answer of [await postEndpoint(long), await asSession('POST', `/endpoints/instances/${COPY}/endpoints`, { body: long })]) {
    assert.equal(answer.status, 413, await answer.clone().text());
    assert.match(((await answer.json()) as { message: string }).message, /^endpoints checks a body read whole, 64 KiB at most$/);
  }
  assert.equal(sent.length, 0);
});

test('decide checks a body as the proxy does: the value written and read again, none refused', () => {
  const checked = [allow('POST', '/instances/{uuid}/endpoints', { body: onPool }), deny('*', '/**')];
  const at = `/instances/${COPY}/endpoints`;
  const prod = (body: unknown) => ({ body, place: 'ops/prod' });
  assert.deepEqual(decide(checked, 'POST', at, prod(endpoint('192.168.255.241/22'))), { allowed: true, rule: 'allow(POST, /instances/{uuid}/endpoints, { body })' });
  assert.deepEqual(decide(checked, 'POST', at, prod(endpoint('192.168.0.2/22'))), { allowed: false, rule: 'allow(POST, /instances/{uuid}/endpoints, { body })' });
  // Each environment's pool: dev's address from dev, and not from prod.
  assert.equal(decide(checked, 'POST', at, { body: endpoint('192.168.255.224/22'), place: 'ops/dev' }).allowed, true);
  assert.equal(decide(checked, 'POST', at, prod(endpoint('192.168.255.224/22'))).allowed, false);
  assert.equal(decide(checked, 'POST', at).allowed, false);
  // Written and read again: what JSON drops, the check never sees.
  assert.equal(decide([allow('POST', '/a', { body: (body) => !('gone' in (body as object)) })], 'POST', '/a', prod({ gone: undefined })).allowed, true);
  assert.equal(decide(checked, 'GET', at).allowed, false);
});

test("a rule's body is an allow's function, on a credential whose key neither goes in the body nor signs it", () => {
  const made = (rules: unknown, inject = header('x', '{K}') as never) => () => credentialProxy({ credentials: { a: { upstream: UPSTREAM, inject, rules: rules as Rule[] } } });
  assert.throws(made([{ ...deny('POST', '/a'), body: () => true }]), /a's deny\(POST, \/a, \{ body \}\): body is an allow's, a function of the parsed JSON body/);
  assert.throws(made([allow('POST', '/a', { body: 'service_ip' as never })]), /body is an allow's, a function/);
  assert.throws(made([allow('POST', '/a', { body: () => true })], sigv4({ accessKeyId: '{A}', secretAccessKey: '{B}', region: 'eu-west-3', service: 's3' }) as never), /a's rules check a body, which a sigv4 rule's key would change or sign as the app sent it/);
  assert.throws(made([allow('POST', '/a', { body: () => true })], json('token', '{K}') as never), /a's rules check a body, which a json rule's key/);
  assert.doesNotThrow(made([allow('POST', '/a', { body: () => true })]));
});

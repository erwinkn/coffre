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
import { allow, credentialProxy, decide, deny, header, sigv4, type Egress, type Rule } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const KEY = 'rdb-key-0123456789';
const LIVE = '0d6f2c4e-8b1a-4c3d-9e5f-a7b6c5d4e3f2';
const COPY = '7f3ab21c-5d4e-4f60-8a9b-0c1d2e3f4a5b';
const UPSTREAM = 'https://rdb.example/v1';

/** Every request the egress was asked to send. */
const sent: { method: string; url: URL }[] = [];
const egress: Egress = {
  async fetch(input, init) {
    sent.push({ method: init.method ?? 'GET', url: input });
    return Response.json({ ok: true });
  },
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

/** The same as the deploy service's session, its proof under the gate's nonce. */
async function asSession(method: string, path: string): Promise<Response> {
  const url = `${PUBLIC_URL}/use/${path.replace(/^\//, '')}`;
  const body = method === 'GET' || method === 'HEAD' ? new Uint8Array() : new TextEncoder().encode('{}');
  const headers: Record<string, string> = body.length === 0 ? {} : { 'content-type': 'application/json', 'content-digest': `sha-256=:${Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')}:` };
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

// A credential with an upstream for each environment, `upstream: { prod: …, staging: … }`, for a provider whose
// production has a host of its own: prod's key and the sandbox's go by one name, YOUSIGN_API_KEY, and each request goes
// to its own environment's host with its own environment's key. So a prod key never reaches a sandbox host: and an
// environment the map does not name, a copy of prod holding prod's key, is refused before the vault opens anything.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates } from '../src/gate.ts';
import { credentialProxy, header, jwt, sigv4, type Egress } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const PROD_KEY = 'yousign-prod-key-0123';
const SANDBOX_KEY = 'yousign-sandbox-key-0123';
// A JWT, whose `org` claim a dfns placeholder copies.
const DFNS_TOKEN = `e30.${Buffer.from(JSON.stringify({ org: 'or-prod' })).toString('base64url')}.signature`;
const PROD = 'api.yousign.example';
const SANDBOX = 'api-sandbox.yousign.example';

/** The upstreams, through the credential's egress: where each request went, and with what. */
const sent: { url: URL; headers: Headers }[] = [];
const egress: Egress = {
  async fetch(input, init) {
    sent.push({ url: input, headers: new Headers(init.headers) });
    return Response.json({ ok: true });
  },
};

const proxy = credentialProxy({
  credentials: {
    yousign: { upstream: { prod: `https://${PROD}/v3`, staging: `https://${SANDBOX}/v3` }, inject: header('authorization', 'Bearer {YOUSIGN_API_KEY}'), egress },
    // Two more credentials of dfns's key with an upstream for staging alone, one declared before it and one after: in prod, neither takes its placeholder.
    'sandbox-dfns': { upstream: { staging: 'https://api.sandbox.dfns.example' }, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: ['org'] }) },
    dfns: { upstream: { prod: 'https://api.dfns.example', staging: 'https://api.sandbox.dfns.example' }, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: ['org'] }) },
    'dfns-sandbox': { upstream: { staging: 'https://api.sandbox.dfns.example' }, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: ['org'] }) },
    s3: { upstream: { prod: 'https://s3.prod.example', staging: 'https://s3.sandbox.example' }, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
  },
});

let held = processGates();
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates: (service) => held(service), plugins: [proxy] });
const { world } = app;
after(() => app.close());

type Place = 'prod' | 'staging' | 'prod-copy';
const market = project('market');
const places = { prod: environment(market, 'prod'), staging: environment(market, 'staging'), 'prod-copy': environment(market, 'prod-copy') };
// prod-copy: an environment the credential names no upstream for, holding prod's own key, a copy of prod or one added since.
const scopeOf = (place: Place) => JSON.stringify([{ projectId: market.id, environmentId: places[place].id, role: 'developer' }]);

/** A handle of Ada's, and a session of the deploy service, for each environment. */
let handles: Record<Place, string>;
let sessions: Record<Place, { token: string; key: ProofKey }>;

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  held = processGates();
  sent.length = 0;
  const deployBinding = binding(DEPLOY, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, role: 'developer' }]) });
  const made = [];
  handles = {} as typeof handles;
  sessions = {} as typeof sessions;
  for (const name of Object.keys(places) as Place[]) {
    handles[name] = generateToken('handle');
    made.push(credential(handles[name], ADA, { kind: 'handle', scope: scopeOf(name), places: JSON.stringify([{ environmentId: places[name].id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) }));
    const key = await generateProofKey();
    const token = generateToken('workload');
    made.push(session(token, deployBinding, { jkt: await thumbprint(key.jwk), scope: scopeOf(name), places: JSON.stringify([{ environmentId: places[name].id }]), expiresAt: new Date(Date.now() + 3_600_000) }));
    sessions[name] = { token, key };
  }
  const { prod, staging } = places;
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', ...Object.values(places)),
    ...rows('principals', principal(ADA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'developer', { project: market }), grant(DEPLOY, 'developer', { project: market })),
    ...rows('secrets',
      value(world, secret(prod, 'YOUSIGN_API_KEY'), PROD_KEY, { sensitive: true }), value(world, secret(staging, 'YOUSIGN_API_KEY'), SANDBOX_KEY), value(world, secret(places['prod-copy'], 'YOUSIGN_API_KEY'), PROD_KEY, { sensitive: true }),
      ...(Object.keys(places) as Place[]).flatMap((name) => [value(world, secret(places[name], 'DFNS_AUTH_TOKEN'), DFNS_TOKEN, { sensitive: true }), value(world, secret(places[name], 'AWS_ACCESS_KEY_ID'), `AKIA${name.toUpperCase().replace('-', '')}`, { plain: true }), value(world, secret(places[name], 'AWS_SECRET_ACCESS_KEY'), `aws-${name}`)])),
    ...rows('bindings', deployBinding),
    ...rows('credentials', ...made),
  );
  await app.request('/livez');
  await world.owner.execute(sql`DELETE FROM log_pending`);
  app.calls.length = 0;
});

/** A request through `yousign` with the environment's handle where it takes its key. */
const asHandle = (name: Place, path: string) => app.request(path, { headers: { authorization: `Bearer ${handles[name]}` } });

/** A request through `yousign` as the environment's session, its proof under the gate's nonce. */
async function asSession(name: Place, path: string): Promise<Response> {
  const { token, key } = sessions[name];
  const proof = await createProof(key, { method: 'GET', url: `${PUBLIC_URL}${path}`, token, nonce: await held(DEPLOY).nonce(), content: { headers: {}, body: await bodyDigest(new Uint8Array()) } });
  return app.request(path, { headers: { authorization: `DPoP ${token}`, dpop: proof } });
}

/** The credential and host each of the vault's log entries not yet signed in names, where it names one. */
async function logged(): Promise<Set<string>> {
  const bodies = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`);
  return new Set(bodies.flatMap(({ body }) => {
    const { credential, host } = (JSON.parse(body) as { detail: { credential?: string; host?: string } }).detail;
    return host === undefined ? [] : [`${credential} ${host}`];
  }));
}

const last = () => sent.at(-1)!;

test("each environment's request goes to its own host with its own key: prod's, under the sandbox's name, reaches prod's host alone", async () => {
  for (const path of ['/use/yousign/documents', '/use/market/prod/yousign/documents']) {
    const answer = await asHandle('prod', path);
    assert.equal(answer.status, 200, await answer.clone().text());
    assert.equal(last().url.href, `https://${PROD}/v3/documents`, path);
    assert.equal(last().headers.get('authorization'), `Bearer ${PROD_KEY}`);
  }
  for (const path of ['/use/yousign/documents', '/use/market/staging/yousign/documents']) {
    assert.equal((await asHandle('staging', path)).status, 200);
    assert.equal(last().url.href, `https://${SANDBOX}/v3/documents`, path);
    assert.equal(last().headers.get('authorization'), `Bearer ${SANDBOX_KEY}`);
  }
  assert.deepEqual(new Set(sent.filter((one) => one.headers.get('authorization') === `Bearer ${PROD_KEY}`).map((one) => one.url.hostname)), new Set([PROD]));
  // The log names the host each went to.
  assert.deepEqual(await logged(), new Set([`yousign ${PROD}`, `yousign ${SANDBOX}`]));
});

test("a session's request goes to its place's host, at the stable URL and naming the place", async () => {
  for (const path of ['/use/yousign/documents', '/use/market/prod/yousign/documents']) {
    const answer = await asSession('prod', path);
    assert.equal(answer.status, 200, await answer.clone().text());
    assert.equal(last().url.href, `https://${PROD}/v3/documents`, path);
    assert.equal(last().headers.get('authorization'), `Bearer ${PROD_KEY}`);
  }
  assert.equal((await asSession('staging', '/use/yousign/documents')).status, 200);
  assert.equal(last().url.href, `https://${SANDBOX}/v3/documents`);
  assert.equal(last().headers.get('authorization'), `Bearer ${SANDBOX_KEY}`);
  assert.deepEqual(await logged(), new Set([`yousign ${PROD}`, `yousign ${SANDBOX}`]));
});

test("a personal config's request goes to its environment's host: prod@me's to prod's", async () => {
  const mine = environment(market, 'prod-ada', { parentId: places.prod.id, owner: ADA });
  const personal = generateToken('handle');
  await write(world,
    ...rows('environments', mine),
    ...rows('secrets', value(world, secret(mine, 'YOUSIGN_API_KEY'), 'ada-own-prod-key')),
    ...rows('credentials', credential(personal, ADA, { kind: 'handle', scope: scopeOf('prod'), places: JSON.stringify([{ environmentId: places.prod.id, personal: true }]), expiresAt: new Date(Date.now() + 3_600_000) })));
  const answer = await app.request('/use/yousign/documents', { headers: { authorization: `Bearer ${personal}` } });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.equal(last().url.href, `https://${PROD}/v3/documents`);
  assert.equal(last().headers.get('authorization'), 'Bearer ada-own-prod-key');
});

test('an environment the credential names no upstream for is refused before anything opens: the prod key it holds never leaves', async () => {
  for (const answer of [await asHandle('prod-copy', '/use/yousign/documents'), await asHandle('prod-copy', '/use/market/prod-copy/yousign/documents'), await asSession('prod-copy', '/use/yousign/documents')]) {
    const { message, reason } = (await answer.json()) as { message: string; reason: string };
    assert.deepEqual([answer.status, reason], [403, 'no_upstream']);
    assert.match(message, /^yousign has no upstream for prod-copy, only for prod, staging/);
  }
  assert.deepEqual(app.calls.filter((call) => call === 'use'), [], 'the vault opened nothing');
  assert.equal(sent.length, 0, 'nothing went upstream');
});

test("a presigned URL is for its environment's host, and none is made for an environment the credential names no upstream for", async () => {
  const presign = (name: Place) => app.request(`/use/market/${name}`, { method: 'POST', headers: { authorization: `Bearer ${handles[name]}`, 'content-type': 'application/json' }, body: JSON.stringify({ presign: { credential: 's3', path: '/bucket/report.pdf' } }) });
  const host = async (name: Place) => {
    const answer = await presign(name);
    assert.equal(answer.status, 200, await answer.clone().text());
    return new URL(((await answer.json()) as { url: string }).url).hostname;
  };
  assert.equal(await host('prod'), 's3.prod.example');
  assert.equal(await host('staging'), 's3.sandbox.example');
  const calls = app.calls.length;
  assert.deepEqual([(await presign('prod-copy')).status, sent.length], [403, 0]);
  assert.deepEqual(app.calls.slice(calls).filter((call) => call === 'use'), []);
});

test("a JWT placeholder copies its claims only for an environment a credential names an upstream for: elsewhere the plan opens nothing, nor overwrites one that does", async () => {
  const planned = async (name: Place) => {
    const calls = app.calls.length;
    const answer = await asHandle(name, `/use/market/${name}`);
    assert.equal(answer.status, 200, await answer.clone().text());
    const { env } = (await answer.json()) as { env: Record<string, string> };
    return { token: env.DFNS_AUTH_TOKEN!, opened: app.calls.slice(calls).filter((call) => call === 'use').length };
  };
  const prod = await planned('prod');
  assert.equal(JSON.parse(Buffer.from(prod.token.split('.')[1]!, 'base64url').toString()).org, 'or-prod');
  assert.ok(prod.token.endsWith(`.${handles.prod}`));
  assert.equal(prod.opened, 1);
  assert.deepEqual(await planned('prod-copy'), { token: handles['prod-copy'], opened: 0 });
});

test('upstreams by environment are each a public HTTPS URL, for an environment by its name, all on one path', () => {
  const refused = (upstream: unknown, error: RegExp) => assert.throws(() => credentialProxy({ credentials: { a: { upstream: upstream as string, inject: header('x', '{K}') } } }), error);
  refused({}, /a's upstream is a URL, or one for each environment/);
  refused({ prod: 'https://api.example/v3', dev: 'https://sandbox.example/v2' }, /a's upstreams are on one path, only the host differing by environment; got \/v3 and \/v2/);
  // Only the host differs: a trailing slash is a path of its own, as a single upstream's is.
  refused({ prod: 'https://api.example/v3', dev: 'https://sandbox.example/v3/' }, /on one path/);
  refused({ 'dev@me': 'https://api.example' }, /each for an environment by its name/);
  refused({ Prod: 'https://api.example' }, /each for an environment by its name/);
  refused({ prod: 'http://api.example' }, /a's prod upstream is HTTPS/);
  refused({ prod: 'https://10.0.0.1' }, /a's prod upstream 10\.0\.0\.1 is a private address/);
  refused({ prod: 'https://api.example?key=1' }, /a's prod upstream is an origin and a path/);
  refused({ prod: 42 }, /a's prod upstream is a URL/);
  assert.doesNotThrow(() => credentialProxy({ credentials: { a: { upstream: { prod: 'https://api.example/v3', dev: 'https://sandbox.example/v3' }, inject: header('x', '{K}') } } }));
});

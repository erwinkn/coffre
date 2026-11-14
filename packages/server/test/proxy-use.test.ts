// The credential proxy on the 0.16 contract (docs/design/0.16.md, "The
// proxy"): a request through a credential is one `use` of the vault, by the
// handle or the workload's session the request carries, and the proxy keeps
// no value. The app reads the credential's row only to route: the place a
// stable URL goes to, and a session's gate and key. What the vault decides of
// a use is its own suite's (packages/vault/test/use.test.ts); here, what a
// request costs, that nothing is kept, that an edited row opens nothing, and
// what an upstream's answer gives back.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, createProof, generateProofKey, thumbprint, UNSIGNED_BODY, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, hashToken, signin } from '@coffre/core/identity';
import { amend, binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates, type Gates } from '../src/gate.ts';
import { basic, credentialProxy, header, sigv4, type Egress } from '../src/plugins/credential-proxy.ts';
import { routedCredential } from '../src/db/queries/sessions.ts';
import { checkPlugins, routed } from '../src/plugins.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
const SID = 'AC0123456789abcdef';
const TOKEN = 'twilio-auth-token-0123';
const STRIPE = 'sk_live_0123456789';

/** The upstream, through each credential's egress: what it was sent, and what it answers. */
const sent: { url: URL; headers: Headers }[] = [];
let answer: (url: URL, headers: Headers) => Response = () => Response.json({ ok: true });
const egress: Egress = {
  async fetch(input, init) {
    const headers = new Headers(init.headers);
    sent.push({ url: input, headers });
    return answer(input, headers);
  },
};

const proxy = credentialProxy({
  credentials: {
    twilio: { upstream: 'https://api.twilio.example/2010-04-01', inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), egress },
    stripe: { upstream: 'https://api.stripe.example/v1', inject: header('authorization', 'Bearer {STRIPE_KEY}'), egress, limit: { perMinute: 3 } },
    s3: { upstream: 'https://s3.eu-west-3.example', inject: sigv4({ accessKeyId: '{TWILIO_SID}', secretAccessKey: '{TWILIO_TOKEN}', region: 'eu-west-3', service: 's3' }), egress },
  },
});

let held = processGates();
const asked: string[] = [];
const gates: Gates = (service) => {
  asked.push(service);
  return held(service);
};

const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates, plugins: [proxy] });
const { world } = app;
after(() => app.close());

const market = project('market');
const prod = environment(market, 'prod');
const staging = environment(market, 'staging');
const ON_PROD = JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]);

let handle: string;
let handleId: string;
/** The deploy service's session: its token, key and row. */
let deploy: { token: string; key: ProofKey; id: string };

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  held = processGates();
  sent.length = 0;
  answer = () => Response.json({ ok: true });
  handle = generateToken('handle');
  const handleRow = credential(handle, ADA, { kind: 'handle', scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) });
  handleId = handleRow.id;
  const key = await generateProofKey();
  const token = generateToken('workload');
  const deployBinding = binding(DEPLOY, { policy: '{}', scope: ON_PROD });
  const sessionRow = session(token, deployBinding, { jkt: await thumbprint(key.jwk), scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) });
  deploy = { token, key, id: sessionRow.id };
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use'])),
    ...rows('projects', market),
    ...rows('environments', prod, staging),
    ...rows('principals', principal(ADA), principal(DEPLOY), principal('token:other')),
    ...rows('grants', grant(ADA, 'developer', { project: market }), grant(DEPLOY, 'developer', { project: market })),
    ...rows('secrets', value(world, secret(prod, 'TWILIO_SID'), SID, { plain: true }), value(world, secret(prod, 'TWILIO_TOKEN'), TOKEN), value(world, secret(prod, 'STRIPE_KEY'), STRIPE, { sensitive: true })),
    ...rows('bindings', deployBinding),
    ...rows('credentials', handleRow, sessionRow),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
  asked.length = 0;
});

/** What a request cost: the vault's calls, the app's statements and the gates asked. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number, string[]]> {
  const [calls, statements, gated] = [app.calls.length, app.statements, asked.length];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements, asked.slice(gated)];
}

const basicOf = (user: string, password: string) => `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

/** A request through `twilio` with the handle where its Basic authentication takes the key. */
const throughTwilio = (path: string) => app.request(path, { headers: { authorization: basicOf(handle, handle) } });

/** A request through `stripe` as the deploy session, its proof signing the request whole under the gate's nonce unless told otherwise. */
async function asDeploy(path: string, options: { nonce?: string | null; jti?: string } = {}): Promise<Response> {
  const url = `${PUBLIC_URL}${path}`;
  const nonce = options.nonce === null ? undefined : (options.nonce ?? (await held(DEPLOY).nonce()));
  const signed = { 'x-request': 'one' };
  const proof = await createProof(deploy.key, { method: 'GET', url, token: deploy.token, ...(nonce === undefined ? {} : { nonce }), content: { headers: signed, body: await bodyDigest(new Uint8Array()) }, ...(options.jti === undefined ? {} : { jti: options.jti }) });
  return app.request(path, { headers: { authorization: `DPoP ${deploy.token}`, dpop: proof, ...signed } });
}

const failed = async (response: Response) => [response.status, ((await response.json()) as { reason?: string }).reason];

test("a handle's request: the stable URL reads its row for the place, then one use; naming the place, the use alone; nothing is kept", async () => {
  const [stable, calls, statements] = await cost(() => throughTwilio('/use/twilio/Accounts.json'));
  assert.equal(stable.status, 200, await stable.clone().text());
  assert.deepEqual([calls, statements], [['use'], 1]);
  assert.equal(sent.at(-1)!.url.href, 'https://api.twilio.example/2010-04-01/Accounts.json');
  assert.equal(sent.at(-1)!.headers.get('authorization'), basicOf(SID, TOKEN), 'the real values in, the handle gone');

  const [named, namedCalls, namedStatements] = await cost(() => throughTwilio('/use/market/prod/twilio/Accounts.json'));
  assert.equal(named.status, 200);
  assert.deepEqual([namedCalls, namedStatements], [['use'], 0]);

  // Every request asks the vault again: no value is kept here.
  const [, againCalls] = await cost(() => throughTwilio('/use/market/prod/twilio/Accounts.json'));
  assert.deepEqual(againCalls, ['use']);
});

test('a handle revoked stops its next request, with no value kept to serve it', async () => {
  assert.equal((await throughTwilio('/use/twilio/Accounts.json')).status, 200);
  await amend(world, 'credentials', sql`id = ${handleId}`, { revokedAt: new Date(), revokedBy: ADA });
  // Past the vault's memory (two seconds), as a request a moment later is.
  world.memory.reads.clear();
  world.memory.callers.clear();
  const before = sent.length;
  const [status] = await failed(await throughTwilio('/use/market/prod/twilio/Accounts.json'));
  assert.equal(status, 401);
  assert.equal(sent.length, before, 'nothing went upstream');
});

test("an upstream's answer comes back with the values it echoes redacted, but a plain one, which is no secret", async () => {
  answer = (_url, headers) => Response.json({ sid: SID, token: TOKEN, auth: headers.get('authorization') });
  const echoed = (await (await throughTwilio('/use/twilio/Accounts.json')).json()) as { sid: string; token: string };
  assert.equal(echoed.sid, SID, 'the plain value, intact');
  assert.equal(echoed.token, '[redacted by coffre]');

  // A sensitive value, which a person's handle uses and never reads.
  answer = () => Response.json({ key: STRIPE });
  const stripe = await app.request('/use/stripe/charges', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(stripe.status, 200, await stripe.clone().text());
  assert.equal(sent.at(-1)!.headers.get('authorization'), `Bearer ${STRIPE}`);
  assert.deepEqual(await stripe.json(), { key: '[redacted by coffre]' });
});

test("a handle's row edited to name another place routes there, and the vault, which sealed its places, opens nothing", async () => {
  await world.owner.execute(sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: staging.id, personal: false }])} WHERE id = ${handleId}`);
  await write(world, ...rows('secrets', value(world, secret(staging, 'TWILIO_SID'), 'ACstaging', { plain: true }), value(world, secret(staging, 'TWILIO_TOKEN'), 'staging-token')));
  const [status] = await failed(await throughTwilio('/use/twilio/Accounts.json'));
  // Its MAC no longer holds: the vault finds no credential, and opens nothing.
  assert.equal(status, 401);
  assert.equal(sent.length, 0);
  // And a places that is no JSON array routes nowhere, rather than failing the statement.
  await world.owner.execute(sql`UPDATE credentials SET places = 'not json' WHERE id = ${handleId}`);
  assert.equal((await throughTwilio('/use/twilio/Accounts.json')).status, 409);
});

test("a session's request: one statement finds its gate, key and place; the gate takes the proof once and counts the credential; then one use; the answer carries the nonce", async () => {
  const [first, firstCalls, firstStatements, firstGates] = await cost(() => asDeploy('/use/stripe/charges', { nonce: null }));
  assert.deepEqual(await failed(first.clone()), [401, 'use_dpop_nonce']);
  assert.deepEqual([firstCalls, firstStatements, firstGates], [[], 1, [DEPLOY]]);

  const [ok, calls, statements, gated] = await cost(() => asDeploy('/use/stripe/charges'));
  assert.equal(ok.status, 200, `${await ok.clone().text()} ${JSON.stringify([calls, statements, gated])}`);
  assert.deepEqual([calls, statements, gated], [['use'], 1, [DEPLOY]]);
  assert.equal(ok.headers.get('dpop-nonce'), await held(DEPLOY).nonce());
  const out = sent.at(-1)!;
  assert.equal(out.headers.get('authorization'), `Bearer ${STRIPE}`);
  assert.equal(out.headers.get('x-request'), 'one', 'a header the proof signs goes on');
  assert.equal(out.headers.get('dpop'), null);

  // The same proof again: the gate refuses it, and the vault hears nothing.
  const jti = Buffer.alloc(16, 7).toString('base64url');
  const named = await asDeploy('/use/market/prod/stripe/charges', { jti });
  assert.equal(named.status, 200, await named.clone().text());
  const [again, againCalls] = await cost(() => asDeploy('/use/market/prod/stripe/charges', { jti }));
  assert.deepEqual([...(await failed(again)), againCalls], [401, 'replayed', []]);

  // The credential's limit, three a minute, counted by the gate before the vault (a replay refused counts nothing): the fourth is refused, unasked.
  assert.equal((await asDeploy('/use/stripe/charges')).status, 200);
  const [limited, limitedCalls] = await cost(() => asDeploy('/use/stripe/charges'));
  assert.deepEqual([...(await failed(limited)), limitedCalls], [429, 'limit', []]);
});

test("a row that is not what its token's shape says routes nothing: a handle-shaped token on a session's row, a session's token on a handle's; neither asks the vault", async () => {
  // A session's row whose token has a handle's shape, as a row written behind the vault could.
  const shaped = generateToken('handle');
  await world.owner.execute(sql`UPDATE credentials SET token_hash = ${hashToken(shaped)} WHERE id = ${deploy.id}`);
  const [asHandle, handleCalls] = await cost(() => app.request('/use/stripe/charges', { headers: { authorization: `Bearer ${shaped}` } }));
  assert.deepEqual([...(await failed(asHandle)), handleCalls], [401, 'unauthenticated', []]);
  // A handle's row under a session's token, its key and all, its proof under the gate the row names.
  await world.owner.execute(sql`UPDATE credentials SET token_hash = ${hashToken(deploy.token)}, kind = 'handle', principal = ${ADA} WHERE id = ${deploy.id}`);
  const proof = await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}/use/stripe/charges`, token: deploy.token, nonce: await held(ADA).nonce(), content: { headers: {}, body: await bodyDigest(new Uint8Array()) } });
  const [asSession, sessionCalls] = await cost(() => app.request('/use/stripe/charges', { headers: { authorization: `DPoP ${deploy.token}`, dpop: proof } }));
  assert.deepEqual([...(await failed(asSession)), sessionCalls], [401, undefined, []]);
});

test("a session made for several places names one: the stable URL does not choose", async () => {
  await world.owner.execute(sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: prod.id }, { environmentId: staging.id }])} WHERE id = ${deploy.id}`);
  const [several, calls] = await cost(() => asDeploy('/use/stripe/charges'));
  assert.deepEqual([several.status, calls], [409, []]);
});

test("an unsigned upload binds no body to its session's proof: the vault's answer says the binding does not allow one, and nothing goes upstream", async () => {
  const path = '/use/s3/bucket/key';
  const signed = { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD', 'content-length': '5' };
  const proof = await createProof(deploy.key, { method: 'PUT', url: `${PUBLIC_URL}${path}`, token: deploy.token, nonce: await held(DEPLOY).nonce(), content: { headers: signed, body: UNSIGNED_BODY } });
  const [refusal, calls] = await cost(() => app.request(path, { method: 'PUT', body: 'hello', headers: { authorization: `DPoP ${deploy.token}`, dpop: proof, ...signed } }));
  assert.deepEqual([...(await failed(refusal)), calls], [403, 'unsigned_upload', ['use']]);
  assert.equal(sent.length, 0);
});

test("a session's row edited to name another service sends its proof to a gate that never issued its nonce; one edited to another key refuses its proof; neither asks the vault", async () => {
  const nonce = await held(DEPLOY).nonce();
  await world.owner.execute(sql`UPDATE credentials SET principal = 'token:other' WHERE id = ${deploy.id}`);
  const [moved, movedCalls] = await cost(() => asDeploy('/use/stripe/charges', { nonce }));
  assert.deepEqual([...(await failed(moved)), movedCalls], [401, 'use_dpop_nonce', []]);
  await world.owner.execute(sql`UPDATE credentials SET principal = ${DEPLOY}, jkt = 'another-key' WHERE id = ${deploy.id}`);
  const [rekeyed, rekeyedCalls] = await cost(() => asDeploy('/use/stripe/charges'));
  assert.deepEqual([...(await failed(rekeyed)), rekeyedCalls], [401, 'jkt', []]);
  assert.equal(sent.length, 0);
});

test('a handle on a session route, or a session token as a bearer, is no session: the handle path reads it and the vault refuses', async () => {
  const [asBearer, calls] = await cost(() => app.request('/use/market/prod/stripe/charges', { headers: { authorization: `Bearer ${deploy.token}` } }));
  assert.equal(asBearer.status, 401);
  assert.deepEqual(calls, []);
  // On the stable URL, its row is no handle's: it routes nowhere, and the vault is not asked.
  const [stable, stableCalls] = await cost(() => app.request('/use/stripe/charges', { headers: { authorization: `Bearer coffre_use_${'x'.repeat(43)}` } }));
  assert.deepEqual([...(await failed(stable)), stableCalls], [401, 'unauthenticated', []]);
  await world.owner.execute(sql`UPDATE credentials SET kind = 'cli' WHERE id = ${handleId}`);
  assert.equal(await routedCredential(world.owner, hashToken(handle)), null, 'the routing read finds handles and sessions alone');
  const [notHandle, notHandleCalls] = await cost(() => app.request('/use/stripe/charges', { headers: { authorization: `Bearer ${handle}` } }));
  assert.deepEqual([...(await failed(notHandle)), notHandleCalls], [401, 'unauthenticated', []]);
  assert.equal(sent.length, 0);
});

test("the root says the credentials; a POST that asks for nothing to be made is a 400, and asks the vault nothing", async () => {
  const root = await app.request('/use');
  assert.deepEqual(await root.json(), { proxy: 'coffre', credentials: ['twilio', 'stripe', 's3'] });
  // What it makes is proxy-compute.test.ts's, and the plan proxy-plan.test.ts's.
  const [refused, calls] = await cost(() => app.request('/use/market/prod', { method: 'POST', headers: { authorization: `Bearer ${handle}` } }));
  assert.deepEqual([(await failed(refused))[0], calls], [400, []]);
});

test('through an outage of the database, a credential is routed by the row read last for it, and only then; a failure is remembered two seconds', async () => {
  const row = { id: 'c1', kind: 'handle', principal: ADA, jkt: null, expires_at: new Date(Date.now() + 60_000).toISOString(), places: [{ path: 'market/prod', personal: false }] };
  let down = false;
  let asks = 0;
  const unreachable = Object.assign(new Error('connect ECONNREFUSED'), { code: '08006' });
  const db = {
    execute: async (): Promise<unknown[]> => {
      asks += 1;
      if (down) throw unreachable;
      return [{ ...row, expiresAt: row.expires_at }];
    },
  };
  const runtime = { db, plugins: checkPlugins([credentialProxy({ credentials: {} })]) } as unknown as CoffreRuntime;
  const hash = Buffer.alloc(32, 1);
  assert.deepEqual((await routed(runtime, hash))?.places, row.places);
  down = true;
  assert.deepEqual((await routed(runtime, hash))?.places, row.places, 'the row read last');
  assert.equal(asks, 2);
  // Within two seconds of the failure, the database is not asked again for a row it holds.
  await routed(runtime, hash);
  assert.equal(asks, 2);
  // A credential never read before has nothing to route by: the failure stands.
  await assert.rejects(routed(runtime, Buffer.alloc(32, 2)), (error) => error === unreachable);
  // Any other failure is no outage, for a credential read before too.
  await new Promise((resolve) => setTimeout(resolve, 2100));
  down = false;
  await routed(runtime, hash);
  db.execute = async () => {
    throw new Error('syntax error');
  };
  await assert.rejects(routed(runtime, hash), /syntax error/);
});

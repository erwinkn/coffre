// Signing in behind Cloudflare Access (docs/design/0.16.md, "Behind
// Cloudflare Access"): every request's assertion verified against the team's
// keys, a browser's first request signed in to a session of coffre's, the
// companion cookie that ties it to the Access subject, and what the CLI,
// machines and people coffre does not know are told. The dev IdP plays
// Access: its keys, its assertions.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';

import { createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { DevIdp } from '@coffre/conformance/idp';
import { generateToken, type Auth, type AuthConfig } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { binding, credential, emptyDatabase, identity, instance, principal, role, rows, session, user, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { ACCESS_SUBJECT_COOKIE, BROWSERS_ONLY } from '../src/behind-access.ts';
import { processGates, type Gates } from '../src/gate.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, SESSION } from './app-fixture.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const idp = new DevIdp();
await idp.start();
after(() => idp.stop());

/** The team's keys, fetched through the app's transport: counted, and failing when told to. */
const keys = { fetched: 0, down: false };
const transport: WorkloadTransport = {
  async json(url) {
    keys.fetched += 1;
    if (keys.down) throw new FetchRefused(url, 'could not be fetched');
    return (await fetch(url)).json();
  },
};
// `cloudflareAccess()` takes a `*.cloudflareaccess.com` team alone; the dev IdP's is on loopback.
const config: AuthConfig = { mode: 'cloudflare', access: { issuer: idp.issuer, jwksUrl: idp.jwksUrl, audience: AUD }, browserSessionHours: 12 };
const auth: Auth = { resolve: () => config };
/** The deployment's workload gates, each service asked of them in order: behind Access, none ever is. */
const gated: string[] = [];
const held = processGates();
const gates: Gates = (service) => {
  gated.push(service);
  return held(service);
};
const app = await openApp({ auth, transport, gates });
const { world } = app;
after(() => app.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const hex = (token: string) => createHash('sha256').update(token).digest('hex');
/** Access's own cookie, which a browser it signed in carries. */
const CF = 'CF_Authorization=cf-browser';

/** Ada and Bo are members, Cy was removed; none signed in through Access yet, as a 0.14 Access deployment upgrades. Bo has a CLI session. */
before(async () => {
  // The schema's question and the keys, asked once of a fresh app.
  await app.request('/api/auth');
});
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  keys.down = false;
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 })),
    ...rows('credentials', credential('bo-cli', bo)),
  );
  app.calls.length = 0;
  gated.length = 0;
});

/** A key Access never published, signing as RS256 does. */
const strangerKey = () => crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);

/** An assertion Access would send for this person. */
const assertion = (email: string, sub = `cf-${email.split('@')[0]}`) => idp.mintUserToken({ audience: AUD, email, sub });

/** A browser's request through Access: its assertion, Access's cookie, and the cookies coffre set it. */
async function browser(path: string, as: string | null, cookies: string[] = [], init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (as !== null) headers.set('cf-access-jwt-assertion', as);
  headers.set('cookie', [CF, ...cookies].join('; '));
  return app.request(path, { ...init, headers });
}

/** The cookies a response sets, by name: their value and their attributes. */
function cookiesOf(response: Response): Record<string, { value: string; attributes: string }> {
  return Object.fromEntries(response.headers.getSetCookie().map((line) => {
    const [pair, ...attributes] = line.split('; ');
    const at = pair!.indexOf('=');
    return [pair!.slice(0, at), { value: pair!.slice(at + 1), attributes: attributes.join('; ') }];
  }));
}
/** What a browser keeps of a response's cookies, to send with its next request. */
const kept = (response: Response) => Object.entries(cookiesOf(response)).filter(([, { value }]) => value !== '').map(([name, { value }]) => `${name}=${value}`);

/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(request: () => Promise<T>): Promise<[T, string[], number]> {
  app.calls.length = 0;
  const before = app.statements;
  const answer = await request();
  return [answer, [...app.calls], app.statements - before];
}
const body = async (response: Response) => [response.status, (await response.json()) as { principal?: { id: string }; registered?: boolean; error?: string; message?: string }] as const;
const who = async (response: Response) => {
  const [status, answer] = await body(response);
  return status === 200 ? answer.principal!.id : `${status} ${answer.error}`;
};

test("a browser's first request through Access signs its person in: one `signin`, both cookies set; the next asks nothing more", async () => {
  const ada1 = await assertion('ada@acme.example');
  const [first, calls] = await cost(async () => browser('/api/me', ada1));
  assert.deepEqual([await who(first), calls], ['ada@acme.example', ['change', 'caller']]);
  const cookies = cookiesOf(first);
  assert.match(cookies[SESSION]!.value, /^coffre_web_/);
  for (const name of [SESSION, ACCESS_SUBJECT_COOKIE]) {
    const maxAge = Number(/Max-Age=(\d+)/.exec(cookies[name]!.attributes)![1]);
    assert.ok(maxAge > 12 * 3600 - 60 && maxAge <= 12 * 3600, cookies[name]!.attributes);
    assert.match(cookies[name]!.attributes, /^Path=\/; HttpOnly; SameSite=Lax; Max-Age=\d+; Secure$/);
  }
  // Bound once, by the email Access vouched for, to the account Access names: its subject, under the team's issuer.
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT provider, issuer_hash, subject FROM identities WHERE principal = ${ada}`), [{ provider: 'cloudflare-access', issuer_hash: hex(idp.issuer), subject: 'cf-ada' }]);
  const [next, nextCalls] = await cost(async () => browser('/api/me', ada1, kept(first)));
  assert.deepEqual([await who(next), nextCalls, next.headers.getSetCookie()], ['ada@acme.example', ['caller'], []]);
  // A fresh assertion of hers, as Access sends one on each request, is the same person.
  assert.deepEqual(await cost(async () => who(await browser('/api/me', await assertion('ada@acme.example'), kept(first)))).then(([id, c]) => [id, c]), ['ada@acme.example', ['caller']]);
});

test('a page renders as the person Access admitted, and its response sets the cookies the sign-in made', async () => {
  const ada1 = await assertion('ada@acme.example');
  let seen = '';
  const [page, calls] = await cost(async () => app.render({ headers: { 'cf-access-jwt-assertion': ada1, cookie: CF } }, async ({ client }) => (seen = (await client.me()).principal.id)));
  assert.deepEqual([page.status, seen, calls], [200, 'ada@acme.example', ['change', 'caller']]);
  assert.deepEqual(Object.keys(cookiesOf(page)).sort(), [ACCESS_SUBJECT_COOKIE, SESSION].sort());
});

test("someone else's assertion with the session on a shared browser signs them in, and ends the session it found", async () => {
  const signedIn = await browser('/api/me', await assertion('ada@acme.example'));
  const adas = kept(signedIn);
  const [bos, calls] = await cost(async () => browser('/api/me', await assertion('bo@acme.example'), adas));
  assert.deepEqual([await who(bos), calls], ['bo@acme.example', ['change', 'caller']]);
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS live FROM credentials WHERE principal = ${ada} AND revoked_at IS NULL`), [{ live: 0 }]);
  // Ada's cookies, back with Ada: her session ended, so the browser is told to sign in again, and does on its next request.
  // Past the two seconds the vault remembers a caller for (`Memory`, @coffre/vault's use.ts).
  world.memory.callers.clear();
  const ended = await browser('/api/me', await assertion('ada@acme.example'), adas);
  assert.equal(await who(ended), '401 unauthenticated');
  assert.deepEqual(Object.values(cookiesOf(ended)).map(({ value }) => value), ['', '']);
  assert.equal(await who(await browser('/api/me', await assertion('ada@acme.example'), kept(ended))), 'ada@acme.example');
});

test('a session counts only beside the companion sealed for it: a forged, missing or swapped one signs in again', async () => {
  const adas = kept(await browser('/api/me', await assertion('ada@acme.example')));
  const session = adas.find((cookie) => cookie.startsWith(`${SESSION}=`))!;
  const bos = kept(await browser('/api/me', await assertion('bo@acme.example')));
  const bosCompanion = bos.find((cookie) => cookie.startsWith(`${ACCESS_SUBJECT_COOKIE}=`))!;
  for (const cookies of [[session], [session, `${ACCESS_SUBJECT_COOKIE}=v1.forged`], [session, bosCompanion]]) {
    const [response, calls] = await cost(async () => browser('/api/me', await assertion('ada@acme.example'), cookies));
    assert.deepEqual([await who(response), calls], ['ada@acme.example', ['change', 'caller']], cookies.join('; '));
  }
  // Bo's session, which Ada came by, beside her own companion and her own assertion: she is signed in as herself, never as Bo.
  const adasCompanion = kept(await browser('/api/me', await assertion('ada@acme.example'))).find((cookie) => cookie.startsWith(`${ACCESS_SUBJECT_COOKIE}=`))!;
  const bosSession = bos.find((cookie) => cookie.startsWith(`${SESSION}=`))!;
  const [taken, calls] = await cost(async () => browser('/api/me', await assertion('ada@acme.example'), [bosSession, adasCompanion]));
  assert.deepEqual([await who(taken), calls], ['ada@acme.example', ['change', 'caller']]);
});

test('with no assertion, or one that does not verify, a session counts for nothing, and the vault is asked nothing', async () => {
  const adas = kept(await browser('/api/me', await assertion('ada@acme.example')));
  const { privateKey } = await strangerKey();
  const forged = [
    null,
    'not-a-jwt',
    await idp.mintUserToken({ audience: 'another-application', email: 'ada@acme.example', sub: 'cf-ada' }),
    await idp.mintUserToken({ audience: AUD, email: 'ada@acme.example', sub: 'cf-ada', key: privateKey }),
    await idp.mintUserToken({ audience: AUD, email: 'ada@acme.example', sub: 'cf-ada', issuer: 'https://evil.cloudflareaccess.com' }),
    await idp.mintUserToken({ audience: AUD, email: 'ada@acme.example', sub: 'cf-ada', expiresIn: -60 }),
  ];
  for (const as of forged) {
    const [response, calls] = await cost(async () => browser('/api/me', as, adas));
    assert.deepEqual([await who(response), calls, response.headers.getSetCookie()], ['401 unauthenticated', [], []], String(as));
  }
});

test('the CLI through cloudflared, an Access service token and a bearer token are told behind Access only browsers sign in, and nobody signs in', async () => {
  const ada1 = await assertion('ada@acme.example');
  const asked = [
    // cloudflared: an assertion, and no Access cookie.
    app.request('/api/me', { headers: { 'cf-access-jwt-assertion': ada1 } }),
    browser('/api/me', await idp.mintServiceToken({ audience: AUD })),
    browser('/api/me', ada1, [], { headers: { authorization: 'Bearer bo-cli' } }),
  ];
  const [answers, calls] = await cost(async () => Promise.all(asked));
  for (const response of answers) assert.deepEqual(await body(response), [401, { error: 'unauthenticated', message: BROWSERS_ONLY }]);
  assert.deepEqual(calls, []);
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS made FROM credentials WHERE kind = 'browser'`), [{ made: 0 }]);
});

test("a workload's DPoP session, its proof good, is a machine's credential: refused as the CLI is, before its row is read or its gate asked", async () => {
  const key = await generateProofKey();
  const token = generateToken('workload');
  const of = binding('token:deploy', { policy: '{}' });
  await write(world, ...rows('principals', principal('token:deploy')), ...rows('bindings', of), ...rows('credentials', session(token, of, { jkt: await thumbprint(key.jwk), expiresAt: new Date(Date.now() + 3_600_000) })));
  const nonce = await held('token:deploy').nonce();
  const proven = async (headers: Record<string, string>) => {
    const dpop = await createProof(key, { method: 'GET', url: 'https://secrets.acme.example/api/me', token, nonce });
    return { ...headers, authorization: `DPoP ${token}`, dpop };
  };
  const ada1 = await assertion('ada@acme.example');
  // As a machine through cloudflared would send it, and beside a browser's Access cookie: neither signs in.
  const asked = [
    await proven({ 'cf-access-jwt-assertion': ada1 }),
    await proven({ 'cf-access-jwt-assertion': ada1, cookie: CF }),
  ];
  for (const headers of asked) {
    const [response, calls, statements] = await cost(() => app.request('/api/me', { headers }));
    assert.deepEqual([await body(response), calls, statements, gated, response.headers.get('dpop-nonce')], [[401, { error: 'unauthenticated', message: BROWSERS_ONLY }], [], 0, [], null]);
  }
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS made FROM credentials WHERE kind = 'browser'`), [{ made: 0 }]);
});

test("someone Access vouches for and coffre has no member for, or a removed member, is told they are not registered; nothing is bound", async () => {
  for (const email of ['eve@acme.example', 'cy@acme.example']) {
    const as = await assertion(email);
    const [me, calls] = await cost(async () => browser('/api/me', as));
    const [status, answer] = await body(me);
    assert.deepEqual([status, answer.principal, answer.registered, calls], [200, { type: 'user', id: email }, false, ['change']], email);
    assert.deepEqual(await body(await browser('/api/projects', as)).then(([s, b]) => [s, b.error]), [403, 'registration_required'], email);
  }
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS bound FROM identities`), [{ bound: 0 }]);
});

test("an Access account other than the one a membership is bound to is refused, and the membership's own still signs in", async () => {
  await browser('/api/me', await assertion('ada@acme.example', 'cf-ada'));
  // Her IdP user made again: the same email, another subject.
  const [response, calls] = await cost(async () => browser('/api/me', await assertion('ada@acme.example', 'cf-ada-again')));
  const [status, answer] = await body(response);
  assert.deepEqual([status, answer.error, calls], [401, 'unauthenticated', ['change']]);
  assert.match(answer.message!, /not the one your membership is bound to/);
  assert.equal(await who(await browser('/api/me', await assertion('ada@acme.example', 'cf-ada'))), 'ada@acme.example');
});

test("signing out ends coffre's session, clears both cookies and sends the browser on to Access's logout", async () => {
  const ada1 = await assertion('ada@acme.example');
  const adas = kept(await browser('/api/me', ada1));
  const out = (cookies: string[], site = 'same-origin') => browser('/auth/signout', ada1, cookies, { method: 'POST', headers: { 'sec-fetch-site': site } });
  assert.equal((await out(adas, 'cross-site')).status, 403);
  const [response, calls] = await cost(async () => out(adas));
  assert.deepEqual([response.status, response.headers.get('location'), calls], [303, '/cdn-cgi/access/logout', ['change']]);
  assert.deepEqual(Object.entries(cookiesOf(response)).map(([name, { value }]) => [name, value]).sort(), [[ACCESS_SUBJECT_COOKIE, ''], [SESSION, '']].sort());
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS live FROM credentials WHERE principal = ${ada} AND revoked_at IS NULL`), [{ live: 0 }]);
});

test("signing out on the request that signs in clears the session it just made, and sets nothing else", async () => {
  const ada1 = await assertion('ada@acme.example');
  // No cookies of coffre's, or a companion that does not open: the check signs in, and the sign-out ends that session.
  for (const path of ['/auth/signout', '/api/auth/logout']) for (const cookies of [[], [`${ACCESS_SUBJECT_COOKIE}=x`]]) {
    const [response, calls] = await cost(async () => browser(path, ada1, [...cookies], { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } }));
    assert.deepEqual([path, calls], [path, ['change', 'change']]);
    assert.deepEqual([path, response.headers.getSetCookie().map((line) => line.split(';')[0]).sort()], [path, [`${ACCESS_SUBJECT_COOKIE}=`, `${SESSION}=`].sort()]);
  }
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT count(*)::int AS live FROM credentials WHERE principal = ${ada} AND revoked_at IS NULL`), [{ live: 0 }]);
});

test("a change with the browser's session comes from coffre's own pages, as with coffre's own sign-in", async () => {
  const ada1 = await assertion('ada@acme.example');
  const adas = kept(await browser('/api/me', ada1));
  const [response, calls] = await cost(async () => browser('/api/projects/market', ada1, adas, { method: 'PUT', headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' }, body: '{}' }));
  assert.deepEqual([(await body(response))[1].error, calls], ['cross_origin', []]);
});

test("health and how the instance signs in answer without an assertion; the team's keys are kept from an earlier request", async () => {
  const fetched = keys.fetched;
  assert.equal((await app.request('/livez')).status, 200);
  assert.deepEqual(await (await app.request('/api/auth', { headers: { 'cf-access-jwt-assertion': 'x' } })).json(), { signin: null, access: { assertion: true } });
  for (const email of ['ada@acme.example', 'bo@acme.example']) assert.equal(await who(await browser('/api/me', await assertion(email))), email);
  assert.ok(keys.fetched - fetched <= 1, `${keys.fetched - fetched} fetches`);
});

test("when the team's keys cannot be fetched no assertion can be checked: 503, said in the server's log, and the vault is asked nothing", async (t) => {
  const down: WorkloadTransport = { json: (url) => Promise.reject(new FetchRefused(url, 'could not be fetched')) };
  const cut = await openApp({ auth: { resolve: () => ({ ...config }) }, transport: down });
  t.after(() => cut.close());
  const logged = t.mock.method(console, 'error', () => {});
  const response = await cut.request('/api/me', { headers: { 'cf-access-jwt-assertion': await assertion('ada@acme.example'), cookie: CF } });
  const [status, answer] = await body(response);
  assert.deepEqual([status, answer.error, cut.calls], [503, 'unavailable', []]);
  assert.match(String(logged.mock.calls[0]?.arguments[0]), /Cloudflare Access keys could not be fetched/);
});

// Which credential a request carries, and what a page's render forwards
// (src/fetch-api.ts). A cookie is ambient: the browser attaches it to every
// request to this origin, whichever site's page sent it, so a change made
// with one must come from coffre's own pages (app.test.ts holds that). A
// read needs no such check: another site's page cannot see the answer. A
// header is there only when its caller put it there, so it is the
// credential whenever there is one, and each sign-in mode reads only its
// own. A page's server render forwards the visitor's session cookie and
// nothing else of the page's request.
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';
import { cloudflareAccess, github, signin } from '@coffre/core/identity';
import { credential, emptyDatabase, environment, grant, identity, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';

import type { Admission } from '../src/behind-access.ts';
import { apiCredential, pageCredential } from '../src/fetch-api.ts';
import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const BROWSER = `coffre_web_${'b'.repeat(43)}`;
const own = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(PUBLIC_URL);
const cloudflare = cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'a'.repeat(64) }).resolve(PUBLIC_URL);

/** Ada views market and Bo develops it, Bo on his browser's session; Cy runs the instance. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const prod = environment(market, 'prod');
  const flag = value(world, secret(prod, 'FLAG'), 'on', { plain: true });
  const github = identity(bo);
  await write(
    world,
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('secrets', flag),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(false, 'developer', ['secret.read', 'secret.write']), role(true, 'owner', ['secret.read', 'secret.write', 'audit.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' })),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market })),
    ...rows('identities', github),
    ...rows('credentials', credential('ada-cli', ada), credential('cy-cli', cy), credential(BROWSER, bo, { kind: 'browser', identityId: github.id })),
  );
  await app.request('/livez');
  app.calls.length = 0;
});

type Body = { error?: string; principal?: { id: string } } & Record<string, unknown>;
const answered = async (response: Promise<Response>): Promise<[number, Body]> => {
  const got = await response;
  return [got.status, (await got.json()) as Body];
};
const cookie = `${SESSION}=${BROWSER}`;
const reveal = (headers: Record<string, string>) => answered(app.request('/api/reveals', { method: 'POST', headers, body: JSON.stringify({ path: 'market/prod/FLAG' }) }));

test("a read with the browser's cookie is answered whatever site sent it: the origin check is for changes, and another site cannot see the answer", async () => {
  for (const site of ['cross-site', 'same-site', 'none', 'same-origin']) {
    const [status, me] = await answered(app.request('/api/me', { headers: { cookie, 'sec-fetch-site': site } }));
    assert.deepEqual([status, me.principal?.id], [200, 'bo@acme.example'], site);
  }
  assert.equal((await app.request('/api/me', { headers: { cookie, origin: 'https://evil.example' } })).status, 200);
  // The same cookie on a change from another site: refused, and the vault asked nothing.
  app.calls.length = 0;
  assert.deepEqual((await reveal({ cookie, 'sec-fetch-site': 'cross-site' }))[1].error, 'cross_origin');
  assert.deepEqual(app.calls, []);
});

test('with a header and a cookie, the header is the credential: the call is its caller\'s, and needs no origin', async () => {
  const [, me] = await answered(app.request('/api/me', { headers: { cookie, authorization: 'Bearer ada-cli' } }));
  assert.equal(me.principal?.id, 'ada@acme.example');
  // A change from another site with both: the header's, which no other site's page can make the browser send.
  const [status, body] = await reveal({ cookie, authorization: 'Bearer ada-cli', 'sec-fetch-site': 'cross-site' });
  assert.deepEqual([status, body.error], [200, undefined], JSON.stringify(body));
  // A header that names nobody is refused, not passed over for the cookie.
  assert.deepEqual((await answered(app.request('/api/me', { headers: { cookie, authorization: 'Bearer nobody' } })))[0], 401);
});

test('each sign-in mode reads its own credential, and only its own', () => {
  const all = { cookie: `${SESSION}=browser; CF_Authorization=jwt`, 'cf-access-jwt-assertion': 'access', authorization: 'Bearer cli' };
  const at = (headers: Record<string, string>) => new Request(`${PUBLIC_URL}/api/me`, { headers });
  assert.deepEqual(apiCredential(at(all), own), { token: 'cli', ambient: false });
  assert.deepEqual(apiCredential(at({ cookie: all.cookie, 'cf-access-jwt-assertion': 'access' }), own), { token: 'browser', ambient: true });
  // Signing in through coffre, Access's assertion and cookie are nothing.
  assert.equal(apiCredential(at({ 'cf-access-jwt-assertion': 'access', cookie: 'CF_Authorization=jwt' }), own), null);
  // A personal token planted in the cookie is no session.
  assert.equal(apiCredential(at({ cookie: `${SESSION}=coffre_pat_${'c'.repeat(43)}` }), own), null);
  // Behind Access: the session the check admitted the request with, and nothing the request names itself.
  const admitted: Admission = { session: 'admitted', cookies: [], unregistered: null, why: '', ended: () => {} };
  assert.deepEqual(apiCredential(at({ cookie: all.cookie, 'cf-access-jwt-assertion': 'access' }), cloudflare, admitted), { token: 'admitted', ambient: true });
  assert.equal(apiCredential(at({ cookie: all.cookie, 'cf-access-jwt-assertion': 'access' }), cloudflare), null);
  // A machine's credential is refused there, not passed over: browsers only.
  assert.throws(() => apiCredential(at(all), cloudflare, admitted), { code: 'unauthenticated', reason: 'browsers_only' });
});

test("a page's render forwards the visitor's session cookie, and nothing else of the page's request", async () => {
  const page = (headers: Record<string, string>) => new Request(`${PUBLIC_URL}/projects`, { headers });
  const smuggled = { authorization: 'Bearer cy-cli', 'cf-access-jwt-assertion': 'smuggled', 'x-forwarded-for': '203.0.113.9' };
  assert.deepEqual(pageCredential(page({ cookie: `theme=dark; ${cookie}; _ga=1`, ...smuggled }), own), { cookie: `${SESSION}=${encodeURIComponent(BROWSER)}` });
  assert.deepEqual(pageCredential(page(smuggled), own), {});
  // Behind Access the page's calls carry the session it was admitted with (`pageClient`), never the request's own.
  assert.deepEqual(pageCredential(page({ cookie: `${cookie}; CF_Authorization=jwt`, ...smuggled }), cloudflare), {});

  // As a page renders: Bo, by his cookie, though the page's request also names Cy, the Owner, in a header.
  const rendered = await app.render({ headers: { cookie: `theme=dark; ${cookie}`, ...smuggled } }, async ({ client }) => (await client.me()).principal.id);
  assert.equal(await rendered.json(), 'bo@acme.example');
  // With the header alone, the render is signed out, and the vault is not asked.
  app.calls.length = 0;
  const signedOut = await app.render({ headers: smuggled }, ({ client }) => client.me().then(() => 'answered', (error: unknown) => (error instanceof CoffreError ? error.code : String(error))));
  assert.deepEqual([await signedOut.json(), app.calls], ['unauthenticated', []]);
});

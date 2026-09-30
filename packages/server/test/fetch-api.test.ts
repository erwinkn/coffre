import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';
import { github, signin, type AuthConfig, type Principal } from '@coffre/core/identity';

import { SyncRunner } from '../src/api/syncs.ts';
import { apiCredential, fetchApi as serveApi, pageClient as clientForPage, pageCredential } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://coffre.test';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';

const own: AuthConfig = signin({
  providers: [github({ clientId: 'id', clientSecret: 'secret' })],
  title: 'Acme secrets',
}).resolve(ORIGIN);
/** The browser's session cookie, over HTTPS. */
const SESSION = '__Host-coffre_session';
const cloudflare: AuthConfig = {
  mode: 'cloudflare',
  access: { issuer: 'https://acme.cloudflareaccess.com', jwksUrl: 'https://acme.cloudflareaccess.com/certs', audience: 'aud' },
};

// Straight to the app, with no adapter in front to vouch for an address.
const fetchApi = (request: Request, runtime: CoffreRuntime) => serveApi(request, runtime, { sourceIp: null });
const pageClient = (page: Request, runtime: CoffreRuntime) => clientForPage(page, runtime, null);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

/** The app's runtime, where every token is simply the email of whoever holds it. */
function runtimeFor(auth: AuthConfig): CoffreRuntime {
  return {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    syncs: new SyncRunner({ db: deps.db, vault: deps.vault, chainKey: deps.chainKey }),
    signin: null,
    auth,
    publicUrl: ORIGIN,
    verifier: { verify: async (token: string): Promise<Principal> => ({ type: 'user', id: token, email: token, subject: token }) },
    waitUntil: () => {},
  };
}

/** A change to the API: creating a project, which is easy to look for afterwards. */
function createProject(slug: string, headers: Record<string, string>): Request {
  return new Request(`${ORIGIN}/api/projects/${slug}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ name: slug }),
  });
}

async function refusal(response: Response): Promise<{ status: number; error: string }> {
  return { status: response.status, error: ((await response.json()) as { error: string }).error };
}

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await clientFor(deps, ROOT).members.add(`user:${DEV}`);
});

test('a change made with a browser cookie from another site is refused and changes nothing', async () => {
  const runtime = runtimeFor(own);
  const cookie = `${SESSION}=${ROOT}`;
  for (const headers of [
    { cookie, 'sec-fetch-site': 'cross-site' } as Record<string, string>,
    // A sibling subdomain is the same site, and still not coffre.
    { cookie, 'sec-fetch-site': 'same-site' },
    { cookie, origin: 'https://evil.test' },
    // Neither header: nothing vouches for where it came from.
    { cookie },
  ]) {
    assert.deepEqual(await refusal(await fetchApi(createProject('sneaky', headers), runtime)), {
      status: 403,
      error: 'cross_origin',
    });
  }
  assert.deepEqual((await clientFor(deps, ROOT).projects.list()).projects, []);
});

test('a change made with a browser cookie from coffre itself goes through', async () => {
  const runtime = runtimeFor(own);
  const cookie = `${SESSION}=${ROOT}`;
  const bySecFetch = await fetchApi(createProject('market', { cookie, 'sec-fetch-site': 'same-origin' }), runtime);
  assert.equal(bySecFetch.status, 200);
  const byOrigin = await fetchApi(createProject('web', { cookie, origin: ORIGIN }), runtime);
  assert.equal(byOrigin.status, 200);
});

test('reads with a browser cookie need no origin: another site cannot see the answer', async () => {
  const response = await fetchApi(
    new Request(`${ORIGIN}/api/me`, { headers: { cookie: `${SESSION}=${DEV}`, 'sec-fetch-site': 'cross-site' } }),
    runtimeFor(own),
  );
  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as { principal: { id: string } }).principal.id, DEV);
});

test('tokens in headers are not checked for origin: the CLI and service tokens send none', async () => {
  const access = await fetchApi(createProject('market', { 'cf-access-jwt-assertion': ROOT }), runtimeFor(cloudflare));
  assert.equal(access.status, 200);
  const bearer = await fetchApi(
    createProject('web', { authorization: `Bearer ${ROOT}`, 'sec-fetch-site': 'cross-site' }),
    runtimeFor(own),
  );
  assert.equal(bearer.status, 200);
  // The session cookie is the browser's, and checked.
  const cookie = await fetchApi(createProject('ops', { cookie: `${SESSION}=${ROOT}` }), runtimeFor(own));
  assert.deepEqual(await refusal(cookie), { status: 403, error: 'cross_origin' });
});

test('behind Cloudflare Access, the browser is the request carrying the Access cookie', () => {
  const cli = new Request(`${ORIGIN}/api/me`, { headers: { 'cf-access-jwt-assertion': 'jwt' } });
  const browser = new Request(`${ORIGIN}/api/me`, {
    headers: { 'cf-access-jwt-assertion': 'jwt', cookie: 'CF_Authorization=jwt' },
  });
  assert.deepEqual(apiCredential(cli, cloudflare), { token: 'jwt', ambient: false });
  assert.deepEqual(apiCredential(browser, cloudflare), { token: 'jwt', ambient: true });
});

test('a header wins over a cookie, and each mode reads its own', () => {
  const request = new Request(`${ORIGIN}/api/me`, {
    headers: { cookie: `${SESSION}=browser`, 'cf-access-jwt-assertion': 'access', authorization: 'Bearer cli' },
  });
  assert.deepEqual(apiCredential(request, own), { token: 'cli', ambient: false });
  assert.deepEqual(apiCredential(request, cloudflare), { token: 'access', ambient: false });
  assert.deepEqual(apiCredential(new Request(ORIGIN, { headers: { 'cf-access-jwt-assertion': 'a' } }), own), null);
  assert.deepEqual(apiCredential(new Request(ORIGIN, { headers: { authorization: 'Bearer t' } }), cloudflare), null);
});

test('a page render forwards the visitor credential and nothing else', () => {
  const page = new Request(`${ORIGIN}/projects`, {
    headers: {
      cookie: `theme=dark; ${SESSION}=${DEV}; _ga=1`,
      authorization: 'Bearer smuggled',
      'cf-access-jwt-assertion': 'smuggled',
      'x-forwarded-for': '203.0.113.9',
    },
  });
  assert.deepEqual(pageCredential(page, own), { cookie: `${SESSION}=${encodeURIComponent(DEV)}` });
  assert.deepEqual(pageCredential(page, cloudflare), { 'cf-access-jwt-assertion': 'smuggled' });
  assert.deepEqual(pageCredential(new Request(`${ORIGIN}/projects`), own), {});
});

test('a page render reads as the visitor, and cannot change anything', async () => {
  const runtime = runtimeFor(own);
  const page = new Request(`${ORIGIN}/projects`, {
    headers: { cookie: `${SESSION}=${ROOT}`, 'sec-fetch-site': 'same-origin' },
  });
  const client = pageClient(page, runtime);
  assert.equal((await client.me()).principal.id, ROOT);
  // The page's own `Sec-Fetch-Site` stays behind, so a write has no origin to show.
  await assert.rejects(client.projects.create('market', { name: 'Market' }), { status: 403, code: 'cross_origin' });

  const signedOut = pageClient(new Request(`${ORIGIN}/projects`), runtime);
  await assert.rejects(signedOut.me(), (error: unknown) => error instanceof CoffreError && error.status === 401);
});

test('someone signed in but not a member reaches /me and nothing else', async () => {
  const client = pageClient(
    new Request(`${ORIGIN}/projects`, { headers: { cookie: `${SESSION}=new@acme.example` } }),
    runtimeFor(own),
  );
  const me = await client.me();
  assert.equal(me.registered, false);
  assert.deepEqual(me.environments, []);
  await assert.rejects(client.projects.list(), { status: 403, code: 'registration_required' });
});

test('how to sign in is public', async () => {
  if (own.mode !== 'signin') throw new Error('unreachable');
  const anyone = pageClient(new Request(`${ORIGIN}/login`), { ...runtimeFor(own), signin: { config: own.signin } as never });
  assert.deepEqual(await anyone.auth(), {
    signin: { title: 'Acme secrets', note: null, providers: [{ id: 'github', label: 'GitHub', brand: 'github' }] },
    access: null,
  });
  const behindAccess = (headers: Record<string, string>) =>
    pageClient(new Request(`${ORIGIN}/login`, { headers }), runtimeFor(cloudflare)).auth();
  assert.deepEqual(await behindAccess({ 'cf-access-jwt-assertion': 'expired' }), { signin: null, access: { assertion: true } });
  assert.deepEqual(await behindAccess({}), { signin: null, access: { assertion: false } });
});

import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '../../../packages/client/src/index.ts';
import type { AuthConfig } from '../../../packages/core/src/identity/auth-mode.ts';
import type { Principal } from '../../../packages/core/src/identity/types.ts';
import { SyncRunner } from '../src/server/api/syncs.ts';
import { DEV_TOKEN_COOKIE } from '../src/server/auth.ts';
import { apiCredential, fetchApi, pageClient, pageCredential } from '../src/server/fetch-api.ts';
import type { CoffreRuntime } from '../src/server/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://coffre.test';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';

const dev: AuthConfig = {
  mode: 'dev',
  access: { issuer: 'http://127.0.0.1:8081', jwksUrl: 'http://127.0.0.1:8081/certs', audience: 'aud' },
  devIdpUrl: 'http://127.0.0.1:8081',
};
const signin = { mode: 'signin', signin: { publicUrl: ORIGIN } } as AuthConfig;
const cloudflare: AuthConfig = {
  mode: 'cloudflare',
  access: { issuer: 'https://acme.cloudflareaccess.com', jwksUrl: 'https://acme.cloudflareaccess.com/certs', audience: 'aud' },
};

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
  const runtime = runtimeFor(dev);
  const cookie = `${DEV_TOKEN_COOKIE}=${ROOT}`;
  for (const headers of [
    { cookie, 'sec-fetch-site': 'cross-site' },
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
  const runtime = runtimeFor(dev);
  const cookie = `${DEV_TOKEN_COOKIE}=${ROOT}`;
  const bySecFetch = await fetchApi(createProject('market', { cookie, 'sec-fetch-site': 'same-origin' }), runtime);
  assert.equal(bySecFetch.status, 200);
  const byOrigin = await fetchApi(createProject('web', { cookie, origin: ORIGIN }), runtime);
  assert.equal(byOrigin.status, 200);
});

test('reads with a browser cookie need no origin: another site cannot see the answer', async () => {
  const response = await fetchApi(
    new Request(`${ORIGIN}/api/me`, { headers: { cookie: `${DEV_TOKEN_COOKIE}=${DEV}`, 'sec-fetch-site': 'cross-site' } }),
    runtimeFor(dev),
  );
  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as { principal: { id: string } }).principal.id, DEV);
});

test('tokens in headers are not checked for origin: the CLI and service tokens send none', async () => {
  const dev_ = await fetchApi(createProject('market', { 'cf-access-jwt-assertion': ROOT }), runtimeFor(dev));
  assert.equal(dev_.status, 200);
  const bearer = await fetchApi(
    createProject('web', { authorization: `Bearer ${ROOT}`, 'sec-fetch-site': 'cross-site' }),
    runtimeFor(signin),
  );
  assert.equal(bearer.status, 200);
  // In signin mode the session cookie is the browser's, and checked.
  const cookie = await fetchApi(createProject('ops', { cookie: `__Host-coffre_session=${ROOT}` }), runtimeFor(signin));
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

test('a header wins over a cookie, and dev mode reads no bearer token', () => {
  const request = new Request(`${ORIGIN}/api/me`, {
    headers: { cookie: `${DEV_TOKEN_COOKIE}=browser`, 'cf-access-jwt-assertion': 'cli', authorization: 'Bearer other' },
  });
  assert.deepEqual(apiCredential(request, dev), { token: 'cli', ambient: false });
  assert.deepEqual(apiCredential(new Request(ORIGIN, { headers: { authorization: 'Bearer t' } }), dev), null);
});

test('a page render forwards the visitor credential and nothing else', () => {
  const page = new Request(`${ORIGIN}/projects`, {
    headers: {
      cookie: `theme=dark; ${DEV_TOKEN_COOKIE}=${DEV}; _ga=1`,
      authorization: 'Bearer smuggled',
      'cf-access-jwt-assertion': 'smuggled',
      'x-forwarded-for': '203.0.113.9',
    },
  });
  assert.deepEqual(pageCredential(page, dev), { cookie: `${DEV_TOKEN_COOKIE}=${encodeURIComponent(DEV)}` });
  assert.deepEqual(pageCredential(page, cloudflare), { 'cf-access-jwt-assertion': 'smuggled' });
  assert.deepEqual(pageCredential(new Request(`${ORIGIN}/projects`), dev), {});
});

test('a page render reads as the visitor, and cannot change anything', async () => {
  const runtime = runtimeFor(dev);
  const page = new Request(`${ORIGIN}/projects`, {
    headers: { cookie: `${DEV_TOKEN_COOKIE}=${ROOT}`, 'sec-fetch-site': 'same-origin' },
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
    new Request(`${ORIGIN}/projects`, { headers: { cookie: `${DEV_TOKEN_COOKIE}=new@acme.example` } }),
    runtimeFor(dev),
  );
  const me = await client.me();
  assert.equal(me.registered, false);
  assert.deepEqual(me.environments, []);
  await assert.rejects(client.projects.list(), { status: 403, code: 'registration_required' });
});

test('how to sign in is public', async () => {
  const anyone = pageClient(new Request(`${ORIGIN}/login`), runtimeFor(dev));
  assert.deepEqual(await anyone.auth(), { mode: 'dev', accessAssertion: false, signin: null });
  const behindAccess = pageClient(
    new Request(`${ORIGIN}/login`, { headers: { 'cf-access-jwt-assertion': 'expired' } }),
    runtimeFor(cloudflare),
  );
  assert.equal((await behindAccess.auth()).accessAssertion, true);
});

import test from 'node:test';
import assert from 'node:assert/strict';

import { credentialHeaders, emptyStore, resolveTarget } from '../src/instance.ts';
import { exchange, idToken } from '../src/workload.ts';

const ORIGIN = 'https://secrets.acme.example';
const noFile = async (path: string): Promise<string> => {
  throw new Error(`no ${path}`);
};
const noFetch = async (): Promise<Response> => {
  throw new Error('nothing to fetch');
};

test('COFFRE_SERVICE, and no COFFRE_TOKEN, signs the run in as the service, by its ID token', () => {
  const target = resolveTarget({ COFFRE_API_URL: ORIGIN, COFFRE_SERVICE: 'api-deploy' }, emptyStore());
  assert.deepEqual(target, { origin: ORIGIN, mode: 'signin', credential: { kind: 'workload', service: 'token:api-deploy' } });
  assert.deepEqual(resolveTarget({ COFFRE_API_URL: ORIGIN, COFFRE_SERVICE: 'token:api-deploy' }, emptyStore()).credential, { kind: 'workload', service: 'token:api-deploy' });
  // A token, when given, wins: nothing is exchanged.
  assert.equal(resolveTarget({ COFFRE_API_URL: ORIGIN, COFFRE_SERVICE: 'api-deploy', COFFRE_TOKEN: 'coffre_svc_x' }, emptyStore()).credential.kind, 'token');
  assert.throws(() => resolveTarget({ COFFRE_API_URL: ORIGIN, COFFRE_SERVICE: 'api-deploy', COFFRE_AUTH_MODE: 'cloudflare' }, emptyStore()), /behind Cloudflare Access/);
  assert.deepEqual(credentialHeaders('signin', target.credential, 'coffre_svc_issued'), { authorization: 'Bearer coffre_svc_issued' });
  assert.throws(() => credentialHeaders('signin', target.credential), /no credential was exchanged/);
});

test('the ID token comes from COFFRE_ID_TOKEN, its file, or a fresh one from GitHub for this instance', async () => {
  assert.equal(await idToken({ COFFRE_ID_TOKEN: ' a.b.c \n' }, ORIGIN, { fetch: noFetch, readFile: noFile }), 'a.b.c');
  assert.equal(await idToken({ COFFRE_ID_TOKEN_FILE: '/var/run/token' }, ORIGIN, { fetch: noFetch, readFile: async () => 'd.e.f\n' }), 'd.e.f');
  await assert.rejects(idToken({ COFFRE_ID_TOKEN_FILE: '/nope' }, ORIGIN, { fetch: noFetch, readFile: noFile }), /COFFRE_ID_TOKEN_FILE names \/nope, which could not be read/);
  let asked: { url: string; authorization: string | null } | null = null;
  const github = async (url: string, init?: RequestInit) => {
    asked = { url, authorization: new Headers(init?.headers).get('authorization') };
    return Response.json({ value: 'g.h.i' });
  };
  const env = { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://pipelines.actions.githubusercontent.com/abc?api-version=2.0', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-bearer' };
  assert.equal(await idToken(env, ORIGIN, { fetch: github, readFile: noFile }), 'g.h.i');
  assert.deepEqual(asked, {
    url: 'https://pipelines.actions.githubusercontent.com/abc?api-version=2.0&audience=https%3A%2F%2Fsecrets.acme.example',
    authorization: 'bearer runner-bearer',
  });
  await assert.rejects(idToken(env, ORIGIN, { fetch: async () => new Response('', { status: 403 }), readFile: noFile }), /GitHub did not give this job an ID token \(status 403\)/);
  await assert.rejects(idToken({}, ORIGIN, { fetch: noFetch, readFile: noFile }), /permissions: id-token: write/);
});

test('the exchange answers a credential, or says why the instance refused', async () => {
  let sent: unknown = null;
  const ok = async (url: string, init?: RequestInit) => {
    sent = { url, body: JSON.parse(String(init?.body)) };
    return Response.json({ token: 'coffre_svc_x', expiresAt: '2026-10-04T00:05:00.000Z' });
  };
  assert.deepEqual(await exchange(ORIGIN, 'token:api-deploy', 'a.b.c', ok), { token: 'coffre_svc_x', expiresAt: '2026-10-04T00:05:00.000Z' });
  assert.deepEqual(sent, { url: `${ORIGIN}/api/auth/oidc`, body: { service: 'token:api-deploy', token: 'a.b.c' } });
  const refused = async () => Response.json({ error: 'unauthenticated', reason: 'no_match', message: 'no binding of token:api-deploy trusts these claims: ref differ' }, { status: 401 });
  await assert.rejects(exchange(ORIGIN, 'token:api-deploy', 'a.b.c', refused), new RegExp(`${ORIGIN} would not sign this run in as token:api-deploy \\(no_match\\): no binding`));
  await assert.rejects(exchange(ORIGIN, 'token:api-deploy', 'a.b.c', async () => new Response('down', { status: 502 })), /status 502/);
});

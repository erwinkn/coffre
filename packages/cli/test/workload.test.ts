import test from 'node:test';
import assert from 'node:assert/strict';

import { credentialHeaders, emptyStore, resolveTarget } from '../src/instance.ts';
import { exchange, idToken } from '../src/workload.ts';

const ORIGIN = 'https://secrets.acme.example';
const noFetch = async (): Promise<Response> => {
  throw new Error('nothing to fetch');
};

test('--service, and no --token-file, signs the run in as the service, by its ID token', () => {
  const target = resolveTarget({ url: ORIGIN, service: 'api-deploy' }, emptyStore());
  assert.deepEqual(target, { origin: ORIGIN, mode: 'signin', credential: { kind: 'workload', service: 'token:api-deploy' } });
  assert.deepEqual(resolveTarget({ url: ORIGIN, service: 'token:api-deploy' }, emptyStore()).credential, { kind: 'workload', service: 'token:api-deploy' });
  assert.deepEqual(resolveTarget({ url: ORIGIN, service: 'api-deploy', idToken: 'a.b.c' }, emptyStore()).credential, { kind: 'workload', service: 'token:api-deploy', idToken: 'a.b.c' });
  // One way to sign in, said: a token beside a service is a mistake, not a precedence.
  assert.throws(() => resolveTarget({ url: ORIGIN, service: 'api-deploy', token: 'coffre_svc_x' }, emptyStore()), /--token-file and --service are two ways to sign in: give one/);
  assert.throws(() => resolveTarget({ url: ORIGIN, idToken: 'a.b.c' }, emptyStore()), /--id-token-file goes with --service/);
  assert.throws(() => resolveTarget({ url: ORIGIN, service: 'api-deploy', authMode: 'cloudflare' }, emptyStore()), /behind Cloudflare Access/);
  assert.deepEqual(credentialHeaders('signin', target.credential, 'coffre_svc_issued'), { authorization: 'Bearer coffre_svc_issued' });
  assert.throws(() => credentialHeaders('signin', target.credential), /no credential was exchanged/);
});

test('the ID token is the one --id-token-file gave, or a fresh one from GitHub for this instance', async () => {
  const runner = { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://pipelines.actions.githubusercontent.com/abc?api-version=2.0', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-bearer' };
  assert.equal(await idToken('a.b.c', runner, ORIGIN, noFetch), 'a.b.c');
  let asked: { url: string; authorization: string | null } | null = null;
  const github = async (url: string, init?: RequestInit) => {
    asked = { url, authorization: new Headers(init?.headers).get('authorization') };
    return Response.json({ value: 'g.h.i' });
  };
  assert.equal(await idToken(undefined, runner, ORIGIN, github), 'g.h.i');
  assert.deepEqual(asked, {
    url: 'https://pipelines.actions.githubusercontent.com/abc?api-version=2.0&audience=https%3A%2F%2Fsecrets.acme.example',
    authorization: 'bearer runner-bearer',
  });
  await assert.rejects(idToken(undefined, runner, ORIGIN, async () => new Response('', { status: 403 })), /GitHub did not give this job an ID token \(status 403\)/);
  await assert.rejects(idToken(undefined, {}, ORIGIN, noFetch), /permissions: id-token: write`; elsewhere, pass it in --id-token-file/);
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

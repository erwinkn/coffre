import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';

import { DevIdp } from '../../src/idp/idp.ts';
import { GITHUB_RUN } from '../../src/idp/workloads.ts';
import { form, get } from './helpers.ts';

const AUDIENCE = 'http://127.0.0.1:3000';

let idp: DevIdp;

before(async () => {
  idp = new DevIdp();
  await idp.start();
});

after(async () => {
  await idp.stop();
});

/** A token verified as coffre would: under the keys its issuer's discovery names, for its audience. */
async function verified(token: string, audience = AUDIENCE) {
  const discovery = (await (await get(`${idp.workloads.issuer}/.well-known/openid-configuration`)).json()) as { issuer: string; jwks_uri: string };
  assert.equal(discovery.issuer, idp.workloads.issuer);
  const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(discovery.jwks_uri)), { issuer: discovery.issuer, audience, algorithms: ['RS256', 'ES256'] });
  return payload;
}

test("a run's token, RS256 or ES256, verifies under the keys discovery names, with GitHub's claims", async () => {
  for (const alg of ['RS256', 'ES256'] as const) {
    const token = await idp.workloads.mint(AUDIENCE, {}, alg);
    assert.equal(decodeProtectedHeader(token).alg, alg);
    const claims = await verified(token);
    assert.equal(claims.workflow_ref, GITHUB_RUN.workflow_ref);
    assert.equal((claims.exp ?? 0) - (claims.iat ?? 0), 300);
  }
  const feature = await verified(await idp.workloads.mint(AUDIENCE, { ref: 'refs/heads/feature' }));
  assert.equal(feature.ref, 'refs/heads/feature');
});

test("the runner's endpoint gives a job's token to the bearer of its request token, for the audience asked", async () => {
  const url = new URL(idp.workloads.requestUrl);
  url.searchParams.set('audience', 'https://secrets.acme.example');
  assert.equal((await get(url)).status, 401);
  assert.equal((await get(url, { headers: { authorization: 'bearer not-it' } })).status, 401);
  const answer = await get(url, { headers: { authorization: `bearer ${idp.workloads.requestToken}` } });
  const { value } = (await answer.json()) as { value: string };
  assert.equal((await verified(value, 'https://secrets.acme.example')).run_id, GITHUB_RUN.run_id);
});

test('POST /workloads/token mints one by hand, for the audience in its form', async () => {
  const answer = await get(`${idp.origin}/workloads/token`, form({ aud: 'http://127.0.0.1:3100', alg: 'ES256' }));
  const { token } = (await answer.json()) as { token: string };
  assert.equal(decodeProtectedHeader(token).alg, 'ES256');
  assert.equal((await verified(token, 'http://127.0.0.1:3100')).repository, GITHUB_RUN.repository);
});

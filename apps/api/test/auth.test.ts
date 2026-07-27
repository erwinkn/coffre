import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { DevIdp } from '../../dev-idp/src/idp.ts';
import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import { registerAuth } from '../src/auth.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HEADER = 'cf-access-jwt-assertion';

let idp: DevIdp;
let app: FastifyInstance;

before(async () => {
  idp = new DevIdp();
  await idp.start();

  app = Fastify({ logger: false });
  registerAuth(app, {
    verifier: new AccessIdentityVerifier({
      issuer: idp.issuer,
      jwksUrl: idp.jwksUrl,
      audience: AUD,
    }),
    publicPaths: ['/healthz'],
  });

  app.get('/healthz', async () => ({ ok: true }));
  app.get('/whoami', async (request) => request.principal);

  await app.ready();
});

after(async () => {
  await app.close();
  await idp.stop();
});

test('a request that bypasses the proxy is rejected', async () => {
  // No Cf-Access-Jwt-Assertion header at all: this is what an attacker who
  // reaches the origin directly, going around Cloudflare Access, sends.
  const response = await app.inject({ method: 'GET', url: '/whoami' });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), { error: 'unauthenticated' });
});

test('an authenticated user request succeeds and is attributed', async () => {
  const token = await idp.mintUserToken({ audience: AUD, email: 'erwin@equisafe.io' });

  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: token },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    type: 'user',
    id: 'erwin@equisafe.io',
    email: 'erwin@equisafe.io',
    subject: '0f9a1c2e-1111-2222-3333-444455556666',
  });
});

test('an authenticated service token is attributed to the service, not to nobody', async () => {
  const token = await idp.mintServiceToken({ audience: AUD, commonName: 'ci-deploy.access' });

  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: token },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    type: 'service',
    id: 'ci-deploy.access',
    commonName: 'ci-deploy.access',
  });
});

test('a forged token is rejected', async () => {
  const parts = (await idp.mintUserToken({ audience: AUD })).split('.');
  // Keep the header and payload, replace the signature.
  const forged = `${parts[0]}.${parts[1]}.${Buffer.from('forged').toString('base64url')}`;

  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: forged },
  });

  assert.equal(response.statusCode, 401);
});

test('a token for a different Access application is rejected', async () => {
  const token = await idp.mintUserToken({ audience: 'a-different-access-app' });

  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: token },
  });

  assert.equal(response.statusCode, 401);
});

test('an expired token is rejected', async () => {
  const token = await idp.mintUserToken({ audience: AUD, expiresIn: -60 });

  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: token },
  });

  assert.equal(response.statusCode, 401);
});

test('a request carrying x-middleware-subrequest is rejected outright', async () => {
  const token = await idp.mintUserToken({ audience: AUD });

  // CVE-2025-29927's payload. We do not run auth in Next.js middleware, so
  // this is belt-and-braces -- but a header whose only purpose is to assert
  // "I am an internal request" has no business reaching this service.
  const response = await app.inject({
    method: 'GET',
    url: '/whoami',
    headers: { [HEADER]: token, 'x-middleware-subrequest': 'middleware' },
  });

  assert.equal(response.statusCode, 400);
});

test('the health endpoint is public but everything else defaults to protected', async () => {
  const health = await app.inject({ method: 'GET', url: '/healthz' });
  assert.equal(health.statusCode, 200);

  const other = await app.inject({ method: 'GET', url: '/whoami' });
  assert.equal(other.statusCode, 401);
});

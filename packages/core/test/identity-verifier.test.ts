import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT, UnsecuredJWT } from 'jose';

import { DevIdp } from '@coffre/conformance/idp';
import { AccessIdentityVerifier } from '../src/identity/verifier.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';

let idp: DevIdp;
let verifier: AccessIdentityVerifier;

before(async () => {
  idp = new DevIdp();
  await idp.start();

  verifier = new AccessIdentityVerifier({
    issuer: idp.issuer,
    jwksUrl: idp.jwksUrl,
    audience: AUD,
  });
});

after(async () => {
  await idp.stop();
});

// --- the happy paths, so the negative tests below mean something -------------

test('a valid identity token yields a user principal', async () => {
  const token = await idp.mintUserToken({ audience: AUD, email: 'admin@acme.example' });

  const principal = await verifier.verify(token);

  assert.equal(principal.type, 'user');
  assert.equal(principal.id, 'admin@acme.example');
  assert.equal(principal.type === 'user' && principal.email, 'admin@acme.example');
});

test('a valid service token yields a service principal, never a null actor', async () => {
  const token = await idp.mintServiceToken({
    audience: AUD,
    commonName: 'ci-deploy.access',
  });

  const principal = await verifier.verify(token);

  // The bug this guards: keying identity off `claims.email` gives `undefined`
  // for every machine caller, and audit rows land with no actor at all.
  assert.equal(principal.type, 'service');
  assert.equal(principal.id, 'ci-deploy.access');
  assert.ok(principal.id.length > 0, 'a service principal must have a non-empty id');
});

// --- adversarial ------------------------------------------------------------

test('rejects a token signed by a key we do not trust', async () => {
  const attacker = await generateKeyPair('RS256', { extractable: true });
  const forged = await idp.mintUserToken({ audience: AUD, key: attacker.privateKey });

  await assert.rejects(() => verifier.verify(forged), /signature|verification failed/i);
});

test('rejects a valid token minted for a different application (wrong aud)', async () => {
  const token = await idp.mintUserToken({ audience: 'some-other-access-app-aud-tag' });

  await assert.rejects(() => verifier.verify(token), /audience|aud/i);
});

test('rejects an expired token', async () => {
  const token = await idp.mintUserToken({ audience: AUD, expiresIn: -60 });

  await assert.rejects(() => verifier.verify(token), /exp|expired/i);
});

test('rejects a token that is not yet valid', async () => {
  const token = await idp.mintUserToken({ audience: AUD, notBefore: 600 });

  await assert.rejects(() => verifier.verify(token), /nbf|not.*valid/i);
});

test('rejects a token from a different issuer', async () => {
  const token = await idp.mintUserToken({
    audience: AUD,
    issuer: 'https://evil.cloudflareaccess.com',
  });

  await assert.rejects(() => verifier.verify(token), /issuer|iss/i);
});

test('rejects an unsigned (alg=none) token', async () => {
  // The classic downgrade. jose refuses to produce this through SignJWT, so we
  // build it the way an attacker would.
  const unsecured = new UnsecuredJWT({ email: 'admin@acme.example', sub: 'x' })
    .setIssuer(idp.issuer)
    .setAudience(AUD)
    .setExpirationTime('5m')
    .encode();

  await assert.rejects(() => verifier.verify(unsecured));
});

test('rejects an HMAC token that reuses the public key as the shared secret', async () => {
  // Algorithm-confusion: sign HS256 using the RSA public key material as the
  // secret, hoping the verifier picks the algorithm from the token header.
  const publicJwkBytes = Buffer.from(JSON.stringify(idp.publicJwk), 'utf8');

  const confused = await new SignJWT({ email: 'attacker@evil.com', sub: 'x' })
    .setProtectedHeader({ alg: 'HS256', kid: idp.kid })
    .setIssuer(idp.issuer)
    .setAudience(AUD)
    .setExpirationTime('5m')
    .sign(publicJwkBytes);

  await assert.rejects(() => verifier.verify(confused));
});

test('rejects an empty or missing token', async () => {
  await assert.rejects(() => verifier.verify(''), /token/i);
  await assert.rejects(() => verifier.verify(undefined as unknown as string), /token/i);
  await assert.rejects(() => verifier.verify('not-a-jwt'), /.+/);
});

test('rejects a well-signed token that carries no usable identity', async () => {
  // Signed by the right key, right aud, right issuer -- but no email, no
  // common_name. This must not become an anonymous-but-authenticated caller.
  const anonymous = await new SignJWT({ sub: '' })
    .setProtectedHeader({ alg: 'RS256', kid: idp.kid })
    .setIssuer(idp.issuer)
    .setAudience(AUD)
    .setExpirationTime('5m')
    .sign(idp.privateKey);

  await assert.rejects(() => verifier.verify(anonymous), /identity/i);
});

test('rejects a user token whose email claim is empty', async () => {
  const token = await idp.mintUserToken({ audience: AUD, email: '' });

  await assert.rejects(() => verifier.verify(token), /identity/i);
});

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { errors as joseErrors, exportJWK, generateKeyPair, SignJWT, UnsecuredJWT } from 'jose';

import { DevIdp } from '@coffre/conformance/idp';
import { AccessIdentityVerifier, AccessKeysUnavailable } from '../src/identity/verifier.ts';

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

// --- the team's keys, as an isolate keeps them ----------------------------------

const ISSUER = 'https://acme.cloudflareaccess.com';
const JWKS_URL = `${ISSUER}/cdn-cgi/access/certs`;

/** A signing key of the team's, by its `kid`, and the set Access would publish with it. */
async function teamKey(kid: string) {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const sign = (sub = 'cf-ada') =>
    new SignJWT({ email: 'ada@acme.example', sub }).setProtectedHeader({ alg: 'RS256', kid }).setIssuer(ISSUER).setAudience(AUD).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  return { jwk, sign };
}

/** A verifier on a fake clock, whose fetches of the key set are counted and answer what `published` holds. */
function keptVerifier(published: { keys: object[] }) {
  const clock = { now: 1_000_000 };
  const fetches: string[] = [];
  const verifier = new AccessIdentityVerifier({ issuer: ISSUER, jwksUrl: JWKS_URL, audience: AUD }, {
    json: async (url) => {
      fetches.push(url.href);
      return structuredClone(published);
    },
    now: () => clock.now,
  });
  return { verifier, clock, fetches };
}

test("the team's keys are fetched once and kept ten minutes; a key they lack is asked for again, at most every 30 seconds", async () => {
  const [a, b] = [await teamKey('a'), await teamKey('b')];
  const published = { keys: [a.jwk] };
  const { verifier, clock, fetches } = keptVerifier(published);
  for (let i = 0; i < 3; i += 1) assert.equal((await verifier.verify(await a.sign())).id, 'ada@acme.example');
  assert.deepEqual(fetches, [JWKS_URL]);
  // Access rotates `b` in. Within 30 seconds of the last fetch, an assertion under it is refused without one.
  published.keys = [a.jwk, b.jwk];
  clock.now += 29_000;
  await assert.rejects(verifier.verify(await b.sign()), (error: Error) => error instanceof joseErrors.JWKSNoMatchingKey);
  assert.equal(fetches.length, 1);
  // Past them, it is asked for once, and kept.
  clock.now += 2_000;
  assert.equal((await verifier.verify(await b.sign())).id, 'ada@acme.example');
  assert.equal((await verifier.verify(await b.sign())).id, 'ada@acme.example');
  assert.equal(fetches.length, 2);
  // Ten minutes on, the set is fetched again whatever the key.
  clock.now += 10 * 60_000;
  await verifier.verify(await a.sign());
  assert.equal(fetches.length, 3);
});

test('the 30 seconds hold for a burst and for a refresh that failed: one fetch starts, the rest are refused as the key unknown', async () => {
  const [a, b] = [await teamKey('a'), await teamKey('b')];
  const clock = { now: 1_000_000 };
  const waiting: (() => void)[] = [];
  const access = { down: false, fetches: 0 };
  const verifier = new AccessIdentityVerifier({ issuer: ISSUER, jwksUrl: JWKS_URL, audience: AUD }, {
    json: () => {
      access.fetches += 1;
      if (access.down) return Promise.reject(new Error('unreachable'));
      return new Promise((resolve) => waiting.push(() => resolve({ keys: access.fetches === 1 ? [a.jwk] : [a.jwk, b.jwk] })));
    },
    now: () => clock.now,
  });
  const first = verifier.verify(await a.sign());
  waiting.shift()!();
  await first;
  // Access rotates `b` in; a minute on, five assertions under it arrive at once, while the set is still warm.
  clock.now += 60_000;
  const tokens = await Promise.all(Array.from({ length: 5 }, () => b.sign()));
  const burst = tokens.map((token) => verifier.verify(token).then(() => 'verified', (error: Error) => error.constructor.name));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(access.fetches, 2);
  waiting.shift()!();
  assert.deepEqual((await Promise.all(burst)).sort(), ['JWKSNoMatchingKey', 'JWKSNoMatchingKey', 'JWKSNoMatchingKey', 'JWKSNoMatchingKey', 'verified']);
  // A refresh that fails counts as one: within its 30 seconds no other starts.
  const c = await teamKey('c');
  clock.now += 60_000;
  access.down = true;
  await assert.rejects(verifier.verify(await c.sign()), (error: Error) => error instanceof AccessKeysUnavailable);
  clock.now += 29_000;
  await assert.rejects(verifier.verify(await c.sign()), (error: Error) => error instanceof joseErrors.JWKSNoMatchingKey);
  assert.equal(access.fetches, 3);
  clock.now += 2_000;
  await assert.rejects(verifier.verify(await c.sign()), (error: Error) => error instanceof AccessKeysUnavailable);
  assert.equal(access.fetches, 4);
});

test('concurrent first requests each fetch their own key set: no request awaits a fetch another started', async () => {
  const a = await teamKey('a');
  const waiting: (() => void)[] = [];
  let fetches = 0;
  const verifier = new AccessIdentityVerifier({ issuer: ISSUER, jwksUrl: JWKS_URL, audience: AUD }, {
    json: () => {
      fetches += 1;
      return new Promise((resolve) => waiting.push(() => resolve({ keys: [a.jwk] })));
    },
  });
  const both = Promise.all([verifier.verify(await a.sign()), verifier.verify(await a.sign())]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(fetches, 2);
  for (const go of waiting) go();
  assert.deepEqual((await both).map((principal) => principal.id), ['ada@acme.example', 'ada@acme.example']);
});

test('a malformed assertion, or one under an algorithm never taken, is refused before any key is fetched; a set that cannot be fetched is AccessKeysUnavailable', async () => {
  const { verifier, fetches } = keptVerifier({ keys: [] });
  for (const token of ['x', 'a.b.c', new UnsecuredJWT({ sub: 'x', email: 'x@acme.example' }).encode()]) await assert.rejects(verifier.verify(token));
  assert.deepEqual(fetches, []);
  const down = new AccessIdentityVerifier({ issuer: ISSUER, jwksUrl: JWKS_URL, audience: AUD }, { json: () => Promise.reject(new Error('unreachable')) });
  await assert.rejects(down.verify(await (await teamKey('a')).sign()), (error: Error) => error instanceof AccessKeysUnavailable);
  const notASet = new AccessIdentityVerifier({ issuer: ISSUER, jwksUrl: JWKS_URL, audience: AUD }, { json: async () => ({ keys: 'none' }) });
  await assert.rejects(notASet.verify(await (await teamKey('a')).sign()), (error: Error) => error instanceof AccessKeysUnavailable);
});

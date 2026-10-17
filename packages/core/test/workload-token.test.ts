import test from 'node:test';
import assert from 'node:assert/strict';

import { decodeWorkloadToken, keySummaries, KeysInvalid, uploadedKeys, verifyWorkloadToken, WorkloadTokenRefused } from '@coffre/core/identity';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

const ISSUER = 'https://token.actions.githubusercontent.com';
const AUDIENCE = 'https://secrets.acme.example';
const NOW = new Date('2026-10-03T12:00:00Z');
const at = (seconds: number) => Math.floor(NOW.getTime() / 1000) + seconds;

async function signer(alg: 'RS256' | 'ES256', kid: string) {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg, use: 'sig' };
  const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = {}) =>
    new SignJWT({ iss: ISSUER, sub: 'repo:acme/api:ref:refs/heads/main', aud: AUDIENCE, iat: at(-10), exp: at(290), ...claims })
      .setProtectedHeader({ alg, kid, ...header })
      // A critical header the signer knows, so that only the verifier refuses it.
      .sign(privateKey, header.crit === undefined ? {} : { crit: { 'x-nope': true } });
  return { jwk, sign };
}

const verify = (token: string, keys: JWK[]) => verifyWorkloadToken(token, { keys }, { issuer: ISSUER, audience: AUDIENCE, now: NOW });
const refused = async (promise: Promise<unknown>, reason: string) =>
  assert.rejects(promise, (error: unknown) => error instanceof WorkloadTokenRefused && error.reason === reason, reason);

test('a token signed by the issuer, for this instance alone, within its times, verifies under RS256 and ES256', async () => {
  for (const alg of ['RS256', 'ES256'] as const) {
    const { jwk, sign } = await signer(alg, `${alg}-1`);
    const claims = await verify(await sign({ repository_id: '41532' }), [jwk]);
    assert.equal(claims.repository_id, '41532');
    // A one-element audience array is the same audience.
    await verify(await sign({ aud: [AUDIENCE] }), [jwk]);
  }
});

test('an ES256 signature has a twin that verifies the same claims; the signing input is one spelling of both', async () => {
  const { jwk, sign } = await signer('ES256', 'es');
  const token = await sign({});
  const [header, payload, signature] = token.split('.');
  const bytes = Buffer.from(signature!, 'base64url');
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt(`0x${bytes.subarray(32).toString('hex')}`);
  const twin = `${header}.${payload}.${Buffer.concat([bytes.subarray(0, 32), Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex')]).toString('base64url')}`;
  assert.notEqual(twin, token);
  await verify(twin, [jwk]);
  assert.deepEqual(decodeWorkloadToken(twin).signingInputHash, decodeWorkloadToken(token).signingInputHash);
});

test('an hour at most, exactly: issued 3,600 seconds ago it verifies, 3,601 not; 30 seconds ahead it verifies, 31 not', async () => {
  const { jwk, sign } = await signer('RS256', 'age');
  await verify(await sign({ iat: at(-3600) }), [jwk]);
  await refused(verify(await sign({ iat: at(-3601) }), [jwk]), 'too_old');
  await verify(await sign({ iat: at(30) }), [jwk]);
  await refused(verify(await sign({ iat: at(31) }), [jwk]), 'too_old');
});

test('refusals say why: audience, times, signature, algorithm and key', async () => {
  const { jwk, sign } = await signer('RS256', 'rs');
  await refused(verify(await sign({ aud: 'https://other.example' }), [jwk]), 'audience');
  await refused(verify(await sign({ aud: [AUDIENCE, 'https://other.example'] }), [jwk]), 'audience');
  await refused(verify(await sign({ exp: at(-31) }), [jwk]), 'expired');
  await verify(await sign({ exp: at(-29) }), [jwk]);
  await refused(verify(await sign({ iat: at(-3700) }), [jwk]), 'too_old');
  await refused(verify(await sign({ iat: at(60) }), [jwk]), 'too_old');
  await refused(verify(await sign({ nbf: at(60) }), [jwk]), 'not_yet_valid');
  await refused(verify(await sign({ iss: 'https://evil.example' }), [jwk]), 'signature');
  const other = await signer('RS256', 'rs');
  await refused(verify(await other.sign({}), [jwk]), 'signature');
  await refused(verify(await sign({}, { kid: 'elsewhere' }), [jwk]), 'unknown_key');
  // A key in the header is never used, and an unknown critical header is refused.
  await refused(verify(await other.sign({}, { jwk: other.jwk }), [jwk]), 'signature');
  await refused(verify(await sign({}, { crit: ['x-nope'], 'x-nope': true }), [jwk]), 'signature');
  // HS256, and alg none, under any key: never.
  const hs = await new SignJWT({ iss: ISSUER, sub: 's', aud: AUDIENCE, iat: at(0), exp: at(60) })
    .setProtectedHeader({ alg: 'HS256', kid: 'rs' })
    .sign(new TextEncoder().encode('a'.repeat(32)));
  await refused(verify(hs, [jwk]), 'signature');
  const none = `${Buffer.from(JSON.stringify({ alg: 'none', kid: 'rs' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: ISSUER, sub: 's', aud: AUDIENCE, iat: at(0), exp: at(60) })).toString('base64url')}.`;
  assert.throws(() => decodeWorkloadToken(none), /not a compact JWS/);
});

test('the shape is checked before anything is trusted', () => {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const token = (claims: unknown) => `${part({ alg: 'RS256' })}.${part(claims)}.c2ln`;
  const good = { iss: ISSUER, sub: 's', exp: 1, iat: 1 };
  assert.equal(decodeWorkloadToken(token(good)).claims.iss, ISSUER);
  for (const [claims, why] of [
    [{ ...good, iss: '' }, /no iss/],
    [{ ...good, sub: 7 }, /no sub/],
    [{ ...good, exp: '1' }, /no exp/],
    [{ ...good, iat: null }, /no iat/],
    [{ ...good, nbf: 'soon' }, /nbf that is not a finite number/],
    [[1, 2], /not an object/],
  ] as const) {
    assert.throws(() => decodeWorkloadToken(token(claims)), why);
  }
  assert.throws(() => decodeWorkloadToken('a.b'), /not a compact JWS/);
  assert.throws(() => decodeWorkloadToken(`${'a'.repeat(9000)}.b.c`), /longer than 8192 bytes/);
});

test('with a lifetime given, a token that lives longer, iat to exp, is refused, however recently issued', async () => {
  const { jwk, sign } = await signer('RS256', 'k8s');
  const within = { issuer: ISSUER, audience: AUDIENCE, now: NOW, maxLifetime: 3600 };
  await verifyWorkloadToken(await sign({ iat: at(-10), exp: at(3590) }), { keys: [jwk] }, within);
  await refused(verifyWorkloadToken(await sign({ iat: at(-10), exp: at(3591) }), { keys: [jwk] }, within), 'too_long');
  // Without one, as for an issuer whose keys coffre fetches, only the age counts.
  await verify(await sign({ iat: at(-10), exp: at(86_400) }), [jwk]);
});

test('an uploaded key set keeps the public keys that sign, written one way, and its digest names it', async () => {
  const rsa = await signer('RS256', 'rs');
  const ec = await signer('ES256', 'es');
  const set = await uploadedKeys({ keys: [{ ...rsa.jwk, x5c: ['MIIB'] }, ec.jwk, { ...ec.jwk, kid: 'enc', use: 'enc' }] });
  assert.deepEqual(set.keys.map(({ kid, alg }) => [kid, alg]).sort(), [['es', 'ES256'], ['rs', 'RS256']]);
  assert.deepEqual(set.keys.map(({ thumbprint }) => thumbprint), set.keys.map(({ thumbprint }) => thumbprint).sort(), 'kept in the order of their thumbprints');
  assert.match(set.digest, /^[0-9a-f]{64}$/);
  assert.deepEqual(keySummaries(set.jwks), set.keys);
  assert.ok((JSON.parse(set.jwks) as { keys: Record<string, unknown>[] }).keys.every((key) => key.x5c === undefined));
  const reordered = await uploadedKeys({ keys: [Object.fromEntries(Object.entries(rsa.jwk).reverse()), ec.jwk] });
  assert.equal(reordered.digest, set.digest);
  // The thumbprint is RFC 7638's: the same as jose's.
  const { calculateJwkThumbprint } = await import('jose');
  assert.equal(set.keys.find(({ kid }) => kid === 'rs')!.thumbprint, await calculateJwkThumbprint(rsa.jwk));
  // What it keeps verifies.
  await verify(await rsa.sign({}), JSON.parse(set.jwks).keys);

  const invalid = (value: unknown, message: RegExp) => assert.rejects(uploadedKeys(value), (error: unknown) => error instanceof KeysInvalid && message.test(error.message));
  await invalid([rsa.jwk], /a JWKS/);
  await invalid({ keys: [] }, /no key that signs/);
  await invalid({ keys: Array.from({ length: 33 }, () => rsa.jwk) }, /at most 32/);
  await invalid({ keys: [{ ...rsa.jwk, d: 'x' }] }, /private or a secret key/);
  await invalid({ keys: [{ ...rsa.jwk, alg: 'RS512' }] }, /RS256 or a P-256 key/);
  await invalid({ keys: [{ ...rsa.jwk, n: 'AQAB' }] }, /under 2048 bits/);
  // 256 bytes, but its first holds a single bit: 2041 bits, which jose would refuse to verify with.
  const short = Buffer.from(rsa.jwk.n!, 'base64url');
  short[0] = 0x01;
  await invalid({ keys: [{ ...rsa.jwk, n: short.toString('base64url') }] }, /under 2048 bits/);
  await invalid({ keys: [{ ...ec.jwk, x: 'AQAB' }] }, /not a valid EC key/);
  await invalid({ keys: [rsa.jwk, { ...ec.jwk, kid: 'rs' }] }, /two keys are key rs/);
  // RSA parameters jose would take, though they verify what nobody signed: an exponent of 1 makes a signature its own message.
  for (const e of ['AQ', 'Aw', 'AQAA', 'AAEAAQ', 'AQAB=']) await invalid({ keys: [{ ...rsa.jwk, e }] }, /exponent|n and e/);
  const even = Buffer.from(rsa.jwk.n!, 'base64url');
  even[even.length - 1]! &= 0xfe;
  await invalid({ keys: [{ ...rsa.jwk, n: even.toString('base64url') }] }, /not a valid RSA key/);
  await invalid({ keys: [{ ...rsa.jwk, n: `AA${rsa.jwk.n}` }] }, /fewest bytes/);
  // One set, however listed: one digest.
  assert.equal((await uploadedKeys({ keys: [ec.jwk, rsa.jwk] })).digest, (await uploadedKeys({ keys: [rsa.jwk, ec.jwk] })).digest);
});

test('a token that names no key verifies under whichever key of the set signed it, as while an issuer rotates', async () => {
  const [old, next] = [await signer('RS256', 'old'), await signer('RS256', 'next')];
  const unnamed = (jwk: JWK) => Object.fromEntries(Object.entries(jwk).filter(([name]) => name !== 'kid')) as JWK;
  const token = await next.sign({}, { kid: undefined });
  const keys = [unnamed(old.jwk), unnamed(next.jwk)];
  assert.equal((await verify(token, keys)).sub, 'repo:acme/api:ref:refs/heads/main');
  await refused(verify(await (await signer('RS256', 'other')).sign({}, { kid: undefined }), keys), 'signature');
  // Its claims are still checked, under the key that signed it.
  await refused(verify(await next.sign({ aud: 'https://elsewhere.example' }, { kid: undefined }), keys), 'audience');
});

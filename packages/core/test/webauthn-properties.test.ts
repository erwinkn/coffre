import assert from 'node:assert/strict';
import test, { before } from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { encodeCbor, SoftAuthenticator, toBase64url, type CborValue, type SoftAlgorithm } from '@coffre/conformance/authenticator';

import { readCbor, verifyAssertion, verifyRegistration, type PasskeyAlgorithm, type StoredPasskey } from '../src/identity/webauthn.ts';
import { propertySettings } from './properties.ts';

// docs/design/passkeys.md, section 9: a passkey answers its own ceremony on
// its own site, and nothing else. Keys come from the host's generator, once
// per run (an RSA key per case would cost more than the budget); Hegel draws
// which key, the site, the challenge, the handle and what is changed.

const ALGORITHMS: SoftAlgorithm[] = ['Ed25519', 'ES256', 'RS256'];
const COSE: Record<SoftAlgorithm, PasskeyAlgorithm> = { Ed25519: -8, ES256: -7, RS256: -257 };
const POOL: Record<string, SoftAuthenticator> = {};
before(async () => {
  for (const algorithm of ALGORITHMS) {
    for (const synced of [false, true]) POOL[`${algorithm}/${synced}`] = await SoftAuthenticator.create(algorithm, { synced });
  }
});

const label = gs.fromRegex('[a-z][a-z0-9-]{0,14}[a-z0-9]', { fullmatch: true });
type Site = { rpId: string; origin: string };
/** A deployment: its RP ID, and the origin it answers on, the RP ID's host itself or a host under it. */
const site = gs.composite((tc): Site => {
  const rpId = tc.draw(gs.arrays(label, { minSize: 2, maxSize: 4 })).join('.');
  const host = tc.draw(gs.booleans()) ? rpId : `${tc.draw(label)}.${rpId}`;
  return { rpId, origin: `https://${host}` };
});
const challenge = gs.binary({ minSize: 16, maxSize: 64 });
const handle = gs.binary({ minSize: 1, maxSize: 64 });
const keyName = gs.sampledFrom(ALGORITHMS.flatMap((algorithm) => [`${algorithm}/false`, `${algorithm}/true`]));

async function stored(key: SoftAuthenticator, userHandle: Uint8Array): Promise<StoredPasskey> {
  return { credentialId: key.credentialId, publicKey: await key.publicKey(), algorithm: COSE[key.algorithm], userHandle };
}

const roundTrip = propertySettings(60);
test(`a passkey registered on a site signs in on it, with the key, algorithm and flags it registered, seed ${roundTrip.seed}`, () => hegel.testAsync(async (tc) => {
  const key = POOL[tc.draw(keyName)];
  const where = tc.draw(site);
  const userHandle = tc.draw(handle);
  const sent = tc.draw(challenge);
  const registered = await verifyRegistration(await key.register({ ...where, challenge: sent, userHandle }), { ...where, challenge: sent });
  assert.ok(registered.ok, JSON.stringify(registered));
  assert.deepEqual(registered.publicKey, await key.publicKey());
  assert.equal(registered.algorithm, COSE[key.algorithm]);
  assert.equal(registered.backupEligible, key.synced);
  const asked = tc.draw(challenge);
  const assertion = await key.assert({ ...where, challenge: asked });
  const asserted = await verifyAssertion(assertion, { ...where, challenge: asked, passkey: { credentialId: registered.credentialId, publicKey: registered.publicKey, algorithm: registered.algorithm, userHandle } });
  assert.ok(asserted.ok, JSON.stringify(asserted));
  assert.equal(asserted.backedUp, key.synced);
}, roundTrip));

type Part = 'authenticatorData' | 'clientDataJSON' | 'signature';
const flipped = propertySettings(200);
test(`an assertion with any bit flipped in any byte it signs, or in its signature, is refused, seed ${flipped.seed}`, () => hegel.testAsync(async (tc) => {
  const key = POOL[tc.draw(keyName)];
  const where = tc.draw(site);
  const asked = tc.draw(challenge);
  const userHandle = tc.draw(handle);
  key.userHandle = userHandle;
  const assertion = await key.assert({ ...where, challenge: asked });
  const part = tc.draw(gs.sampledFrom<Part>(['authenticatorData', 'clientDataJSON', 'signature']));
  const bytes = new Uint8Array(Buffer.from(assertion.response[part], 'base64url'));
  // A position drawn from a fixed range, then folded onto the part: an ES256 signature's length varies with its key's random nonce.
  const at = tc.draw(gs.integers({ minValue: 0, maxValue: 1 << 16 })) % bytes.length;
  bytes[at] ^= 1 << tc.draw(gs.integers({ minValue: 0, maxValue: 7 }));
  assertion.response[part] = toBase64url(bytes);
  const result = await verifyAssertion(assertion, { ...where, challenge: asked, passkey: await stored(key, userHandle) });
  assert.equal(result.ok, false, `${part}[${at}] flipped and still taken`);
}, flipped));

/** Another origin than the deployment's: a near miss, or another site altogether. */
const otherOrigin = (origin: string) => gs.oneOf(
  gs.sampledFrom([`${origin}/`, `${origin}:443`, origin.replace('https://', 'http://'), origin.replace('https://', 'https://evil.'), origin.toUpperCase(), `${origin}.`, origin.replace(/\.[^.]+$/, '-evil$&')]),
  site.map((other) => other.origin),
).filter((other) => other !== origin);

const elsewhere = propertySettings(100);
test(`an assertion made for one origin or RP ID is refused on any other, for that reason, seed ${elsewhere.seed}`, () => hegel.testAsync(async (tc) => {
  const key = POOL[tc.draw(keyName)];
  const where = tc.draw(site);
  const asked = tc.draw(challenge);
  key.userHandle = null;
  const assertion = await key.assert({ ...where, challenge: asked });
  const passkey = await stored(key, new Uint8Array(16));
  const origin = tc.draw(otherOrigin(where.origin));
  assert.equal((await verifyAssertion(assertion, { ...where, origin, challenge: asked, passkey }) as { reason?: string }).reason, 'origin');
  const rpId = tc.draw(site.map((other) => other.rpId).filter((other) => other !== where.rpId));
  assert.equal((await verifyAssertion(assertion, { ...where, rpId, challenge: asked, passkey }) as { reason?: string }).reason, 'rp_id');
  // And a registration, the same.
  const registration = await key.register({ ...where, challenge: asked, userHandle: new Uint8Array(16) });
  assert.equal((await verifyRegistration(registration, { ...where, origin, challenge: asked }) as { reason?: string }).reason, 'origin');
  assert.equal((await verifyRegistration(registration, { ...where, rpId, challenge: asked }) as { reason?: string }).reason, 'rp_id');
}, elsewhere));

// --- whatever arrives is answered ---------------------------------------------

/** Any JSON value a client could post, a few levels deep. */
const anyJson: gs.Generator<unknown> = gs.composite((tc): unknown => {
  const leaf = () => tc.draw(gs.oneOf<unknown>(gs.just(null), gs.booleans(), gs.integers({ minValue: -1e6, maxValue: 1e6 }), gs.text({ maxSize: 24 }), gs.binary({ maxSize: 48 }).map((bytes) => toBase64url(bytes))));
  const value = (depth: number): unknown => {
    const kind = depth > 2 ? 'leaf' : tc.draw(gs.sampledFrom(['leaf', 'array', 'object'] as const));
    if (kind === 'leaf') return leaf();
    const size = tc.draw(gs.integers({ minValue: 0, maxValue: 4 }));
    if (kind === 'array') return Array.from({ length: size }, () => value(depth + 1));
    const keys = ['id', 'rawId', 'type', 'response', 'clientDataJSON', 'authenticatorData', 'attestationObject', 'signature', 'userHandle', 'transports'];
    return Object.fromEntries(Array.from({ length: size }, () => [tc.draw(gs.oneOf(gs.sampledFrom(keys), gs.text({ maxSize: 8 }))), value(depth + 1)]));
  };
  return value(0);
});

const junk = propertySettings(200);
test(`any JSON, or an honest envelope around any bytes, is refused with a reason and never throws, seed ${junk.seed}`, () => hegel.testAsync(async (tc) => {
  const where = { rpId: 'secrets.acme.example', origin: 'https://secrets.acme.example' };
  const asked = new Uint8Array(32);
  const key = POOL['ES256/false'];
  const passkey = await stored(key, new Uint8Array(16));
  const id = toBase64url(key.credentialId);
  const field = () => toBase64url(tc.draw(gs.binary({ minSize: 1, maxSize: 300 })));
  const input = tc.draw(gs.booleans())
    ? tc.draw(anyJson)
    : { id, rawId: id, type: 'public-key', response: { clientDataJSON: field(), authenticatorData: field(), signature: field(), attestationObject: field() } };
  for (const result of [await verifyAssertion(input, { ...where, challenge: asked, passkey }), await verifyRegistration(input, { ...where, challenge: asked })]) {
    assert.equal(result.ok, false);
    assert.equal(typeof (result as { reason: string }).reason, 'string');
  }
}, junk));

/** A CBOR value of the subset, with unique map keys. */
const cbor: gs.Generator<CborValue> = gs.composite((tc): CborValue => {
  const value = (depth: number): CborValue => {
    const kind = tc.draw(gs.sampledFrom(depth > 3 ? (['int', 'text', 'bytes', 'simple'] as const) : (['int', 'text', 'bytes', 'simple', 'array', 'map'] as const)));
    if (kind === 'int') return tc.draw(gs.integers({ minValue: -Number.MAX_SAFE_INTEGER, maxValue: Number.MAX_SAFE_INTEGER }));
    if (kind === 'text') return tc.draw(gs.text({ codec: 'utf-8', maxSize: 40 }));
    if (kind === 'bytes') return new Uint8Array(tc.draw(gs.binary({ maxSize: 300 })));
    if (kind === 'simple') return tc.draw(gs.sampledFrom([true, false, null]));
    const size = tc.draw(gs.integers({ minValue: 0, maxValue: 5 }));
    if (kind === 'array') return Array.from({ length: size }, () => value(depth + 1));
    const map = new Map<CborValue, CborValue>();
    for (let i = 0; i < size; i++) map.set(tc.draw(gs.oneOf<number | string>(gs.integers({ minValue: -300, maxValue: 300 }), gs.text({ codec: 'utf-8', maxSize: 6 }))), value(depth + 1));
    return map;
  };
  return value(0);
});

const cborCases = propertySettings(300);
test(`CBOR reads back every value of its subset as written, to the byte it ends at, seed ${cborCases.seed}`, () => hegel.test((tc) => {
  const value = tc.draw(cbor);
  const bytes = encodeCbor(value);
  const tail = tc.draw(gs.binary({ maxSize: 4 }));
  const [read, end] = readCbor(new Uint8Array([...bytes, ...tail]));
  assert.equal(end, bytes.length);
  assert.deepEqual(read, value);
}, cborCases));

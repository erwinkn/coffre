import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { encodeCbor, FLAGS, SoftAuthenticator, toBase64url, type CborValue, type SoftAlgorithm, type Tweak } from '@coffre/conformance/authenticator';

import {
  readCbor,
  verifyAssertion,
  verifyRegistration,
  type AssertionExpectation,
  type PasskeyAlgorithm,
  type RegistrationExpectation,
  type StoredPasskey,
} from '../src/identity/webauthn.ts';

// docs/design/passkeys.md, sections 7.2 and 9: the W3C's vectors and
// SimpleWebAuthn's fixtures, read as data; then one negative case per
// check, each from a software authenticator that answers honestly but for
// the one thing changed.

const vectors = JSON.parse(readFileSync(new URL('./vectors/webauthn.json', import.meta.url), 'utf8'));
const hex = (text: string) => new Uint8Array(Buffer.from(text, 'hex'));
const b64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const reason = (result: { ok: boolean; reason?: string }) => (result.ok ? 'ok' : result.reason);

// --- the W3C's vectors --------------------------------------------------------

type W3cVector = {
  id: string;
  registration: { challenge: string; aaguid: string; credential_id: string; clientDataJSON: string; attestationObject: string };
  authentication: { challenge: string; clientDataJSON: string; authenticatorData: string; signature: string };
};

/** What a browser's `toJSON()` would have sent for the vector's bytes. */
const asRegistration = (v: W3cVector) => ({
  id: toBase64url(hex(v.registration.credential_id)),
  rawId: toBase64url(hex(v.registration.credential_id)),
  type: 'public-key',
  response: { clientDataJSON: toBase64url(hex(v.registration.clientDataJSON)), attestationObject: toBase64url(hex(v.registration.attestationObject)) },
});
const asAssertion = (v: W3cVector) => ({
  id: toBase64url(hex(v.registration.credential_id)),
  rawId: toBase64url(hex(v.registration.credential_id)),
  type: 'public-key',
  response: { clientDataJSON: toBase64url(hex(v.authentication.clientDataJSON)), authenticatorData: toBase64url(hex(v.authentication.authenticatorData)), signature: toBase64url(hex(v.authentication.signature)) },
});

const W3C_SITE = { origin: 'https://example.org', rpId: 'example.org' };

// What each vector must answer, read from its title, not from the verifier:
// ES384, ES512 and Ed448 are no algorithm a passkey may use here, and a
// cross-origin frame or a top origin is no ceremony on the deployment's page.
const W3C_REFUSED: Record<string, string> = {
  'none-es256-crossOrigin': 'origin',
  'none-es256-topOrigin': 'origin',
  'packed-es384': 'algorithm',
  'packed-es512': 'algorithm',
  'packed-ed448': 'algorithm',
};

test('the W3C vectors register and assert, with their credential ID, AAGUID and counter, but those coffre does not take', async () => {
  assert.equal(vectors.w3c.length, 15);
  for (const v of vectors.w3c as W3cVector[]) {
    const registered = await verifyRegistration(asRegistration(v), { ...W3C_SITE, challenge: hex(v.registration.challenge), requireUserVerification: false });
    assert.equal(reason(registered), W3C_REFUSED[v.id] ?? 'ok', v.id);
    if (!registered.ok) continue;
    assert.deepEqual(registered.credentialId, hex(v.registration.credential_id), v.id);
    assert.deepEqual(registered.aaguid, hex(v.registration.aaguid), v.id);
    const passkey: StoredPasskey = { credentialId: registered.credentialId, publicKey: registered.publicKey, algorithm: registered.algorithm, userHandle: new Uint8Array(16) };
    const asserted = await verifyAssertion(asAssertion(v), { ...W3C_SITE, challenge: hex(v.authentication.challenge), passkey, requireUserVerification: false });
    assert.equal(reason(asserted), 'ok', v.id);
    const authData = hex(v.authentication.authenticatorData);
    assert.ok(asserted.ok);
    assert.equal(asserted.signCount, new DataView(authData.buffer).getUint32(33), v.id);
    assert.equal(asserted.userVerified, Boolean(authData[32] & 0x04), v.id);
    // Where the vector's UV bit is clear, coffre's default, which asks for it, refuses.
    const strict = await verifyAssertion(asAssertion(v), { ...W3C_SITE, challenge: hex(v.authentication.challenge), passkey });
    assert.equal(reason(strict), authData[32] & 0x04 ? 'ok' : 'user_verification', v.id);
    // And the registration's challenge answers no assertion.
    assert.equal(reason(await verifyAssertion(asAssertion(v), { ...W3C_SITE, challenge: hex(v.registration.challenge), passkey, requireUserVerification: false })), 'challenge', v.id);
  }
});

test("a W3C vector's assertion is no registration, and its registration no assertion", async () => {
  const v = (vectors.w3c as W3cVector[]).find((vector) => vector.id === 'none-es256')!;
  const registered = await verifyRegistration(asRegistration(v), { ...W3C_SITE, challenge: hex(v.registration.challenge), requireUserVerification: false });
  assert.ok(registered.ok);
  const passkey = { credentialId: registered.credentialId, publicKey: registered.publicKey, algorithm: registered.algorithm, userHandle: new Uint8Array(16) };
  // The registration's clientDataJSON, sent as an assertion's: `webauthn.create` is not `.get`.
  const crossed = asAssertion(v);
  crossed.response.clientDataJSON = toBase64url(hex(v.registration.clientDataJSON));
  assert.equal(reason(await verifyAssertion(crossed, { ...W3C_SITE, challenge: hex(v.registration.challenge), passkey, requireUserVerification: false })), 'type');
});

// --- SimpleWebAuthn's fixtures: real authenticators ---------------------------

type Fixture = {
  response: Record<string, unknown>;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  requireUserVerification: boolean;
  credential?: { id: string; publicKey: string; counter: number };
};

test("SimpleWebAuthn's registrations, from U2F and packed security keys, TPM, Android and RSA, verify", async () => {
  const registrations = Object.entries(vectors.simplewebauthn.registration as Record<string, Fixture>);
  assert.equal(registrations.length, 8);
  for (const [name, f] of registrations) {
    const result = await verifyRegistration(f.response, { challenge: b64(f.expectedChallenge), origin: f.expectedOrigin, rpId: f.expectedRPID, requireUserVerification: f.requireUserVerification });
    assert.equal(reason(result), 'ok', name);
    assert.ok(result.ok);
    assert.deepEqual(result.credentialId, b64(f.response.id as string), name);
  }
});

test("SimpleWebAuthn's assertions verify against their credentials, and their counters come back", async () => {
  const counters: Record<string, number> = {
    'should verify an assertion response': 144,
    'should not compare counters if both are 0': 0,
  };
  // SimpleWebAuthn's extension test reads the extensions back without
  // asking whether the signature verified, and it does not: the key it
  // gives signed none of it. Coffre reads the same extensions (ED) and gets
  // as far as the signature, which it refuses.
  const refused: Record<string, string> = { 'should return authenticator extension output': 'signature' };
  for (const [name, f] of Object.entries(vectors.simplewebauthn.authentication as Record<string, Fixture>)) {
    const response = f.response as { id: string; response: { userHandle?: string } };
    // The Android fixture names a credential row other than the one that
    // answered (SimpleWebAuthn does not compare them); coffre does, so the
    // stored ID is the response's. Its user handle is the row's.
    const passkey: StoredPasskey = {
      credentialId: b64(response.id),
      publicKey: b64(f.credential!.publicKey),
      algorithm: -7,
      userHandle: response.response.userHandle ? b64(response.response.userHandle) : new Uint8Array(16),
    };
    const expected: AssertionExpectation = { challenge: b64(f.expectedChallenge), origin: f.expectedOrigin, rpId: f.expectedRPID, requireUserVerification: f.requireUserVerification, passkey };
    const result = await verifyAssertion(f.response, expected);
    assert.equal(reason(result), refused[name] ?? 'ok', name);
    if (!result.ok) continue;
    assert.equal(result.signCount, counters[name], name);
    // The row's own ID, when the fixture's differs, is another credential.
    if (f.credential!.id !== response.id) {
      assert.equal(reason(await verifyAssertion(f.response, { ...expected, passkey: { ...passkey, credentialId: b64(f.credential!.id) } })), 'credential', name);
    }
  }
});

// --- one negative case per check ----------------------------------------------

const SITE = { origin: 'https://secrets.acme.example', rpId: 'secrets.acme.example' };
const CHALLENGE = hex('5c'.repeat(32));
const HANDLE = hex('a1'.repeat(16));

const keys: Partial<Record<SoftAlgorithm, SoftAuthenticator>> = {};
async function authenticator(algorithm: SoftAlgorithm = 'ES256'): Promise<SoftAuthenticator> {
  keys[algorithm] ??= await SoftAuthenticator.create(algorithm);
  return keys[algorithm];
}

async function stored(key: SoftAuthenticator): Promise<StoredPasskey> {
  const algorithm = ({ Ed25519: -8, ES256: -7, RS256: -257 } as const)[key.algorithm] as PasskeyAlgorithm;
  return { credentialId: key.credentialId, publicKey: await key.publicKey(), algorithm, userHandle: HANDLE };
}

async function register(tweak: Tweak = {}, expected: Partial<RegistrationExpectation> = {}, key?: SoftAuthenticator) {
  const k = key ?? (await authenticator());
  return verifyRegistration(await k.register({ ...SITE, challenge: CHALLENGE, userHandle: HANDLE }, tweak), { ...SITE, challenge: CHALLENGE, ...expected });
}

async function assertion(tweak: Tweak = {}, expected: Partial<AssertionExpectation> = {}, key?: SoftAuthenticator) {
  const k = key ?? (await authenticator());
  k.userHandle = HANDLE;
  return verifyAssertion(await k.assert({ ...SITE, challenge: CHALLENGE }, tweak), { ...SITE, challenge: CHALLENGE, passkey: await stored(k), ...expected });
}

const json = (edit: (response: Record<string, unknown>) => void) => (response: Record<string, unknown>) => {
  const copy = structuredClone(response);
  edit(copy);
  return copy;
};
const inner = (edit: (fields: Record<string, unknown>) => void) => json((response) => edit(response.response as Record<string, unknown>));
const append = (...bytes: number[]) => (data: Uint8Array) => new Uint8Array([...data, ...bytes]);
const flip = (index: number) => (data: Uint8Array) => {
  const copy = new Uint8Array(data);
  copy[index] ^= 1;
  return copy;
};

type Case = [name: string, tweak: Tweak, expected: Partial<AssertionExpectation> & Partial<RegistrationExpectation>, reason: string];

// Each of section 7.2's checks that both ceremonies share, broken alone.
const SHARED: Case[] = [
  ['an honest answer', {}, {}, 'ok'],
  // 2. the response's shape
  ['a type other than public-key', { response: json((r) => void (r.type = 'password')) }, {}, 'malformed'],
  ['an id that is not rawId', { response: json((r) => void (r.rawId = toBase64url(new Uint8Array(32)))) }, {}, 'malformed'],
  ['an id with base64 padding', { response: json((r) => void (r.id = r.rawId = `${r.id}=`)) }, {}, 'malformed'],
  ['an id in base64, not base64url', { response: json((r) => void (r.id = r.rawId = Buffer.from(String(r.id), 'base64url').toString('base64'))) }, {}, 'malformed'],
  ['no response', { response: json((r) => void delete r.response) }, {}, 'malformed'],
  ['clientDataJSON missing', { response: inner((r) => void delete r.clientDataJSON) }, {}, 'malformed'],
  ['clientDataJSON not JSON', { clientDataJSON: (text) => text.slice(1) }, {}, 'malformed'],
  ['clientDataJSON an array', { clientDataJSON: (text) => `[${text}]` }, {}, 'malformed'],
  ['clientDataJSON not UTF-8', { response: inner((r) => void (r.clientDataJSON = toBase64url(Uint8Array.of(0x7b, 0xff, 0x7d)))) }, {}, 'malformed'],
  ['clientDataJSON past 4 KiB', { clientData: { padding: 'x'.repeat(4096) } }, {}, 'malformed'],
  ['ED set with nothing after', { flags: FLAGS.UP | FLAGS.UV | FLAGS.ED }, {}, 'malformed'],
  ['extensions that are no map', { extensions: encodeCbor([1, 2]) }, {}, 'malformed'],
  ['extensions keyed by an integer, not a name', { extensions: encodeCbor(new Map<CborValue, CborValue>([[1, true]])) }, {}, 'malformed'],
  ['extensions in a map head wider than it needs', { extensions: Uint8Array.of(0xb8, 0x01, 0x61, 0x78, 0xf5) }, {}, 'malformed'],
  ['bytes after the authenticator data', { authenticatorData: append(0) }, {}, 'malformed'],
  // 5. clientDataJSON
  ['a challenge sent for something else', {}, { challenge: hex('5d'.repeat(32)) }, 'challenge'],
  ['the challenge spelled in base64', { clientData: { challenge: Buffer.from(CHALLENGE).toString('base64') } }, {}, 'challenge'],
  ['another origin', {}, { origin: 'https://secrets-acme.example' }, 'origin'],
  ["a subdomain of the RP ID's", { clientData: { origin: 'https://evil.secrets.acme.example' } }, {}, 'origin'],
  ['the origin with a trailing slash', { clientData: { origin: 'https://secrets.acme.example/' } }, {}, 'origin'],
  ['the origin over http', { clientData: { origin: 'http://secrets.acme.example' } }, {}, 'origin'],
  ['the origin with a port', { clientData: { origin: 'https://secrets.acme.example:443' } }, {}, 'origin'],
  ['crossOrigin true', { clientData: { crossOrigin: true } }, {}, 'origin'],
  ['crossOrigin the text false', { clientData: { crossOrigin: 'false' } }, {}, 'origin'],
  ['a topOrigin', { clientData: { topOrigin: 'https://secrets.acme.example' } }, {}, 'origin'],
  ['no crossOrigin at all', { clientData: { crossOrigin: undefined } }, {}, 'ok'],
  ['fields the spec may add later', { clientData: { other_keys_can_be_added_here: 'do not compare clientDataJSON against a template' } }, {}, 'ok'],
  // 6. authenticator data
  ['another RP ID', { rpId: 'acme.example' }, {}, 'rp_id'],
  ['the parent RP ID the deployment did not name', { rpId: 'acme.example' }, { rpId: 'secrets.acme.example' }, 'rp_id'],
  ['UP clear', { flags: FLAGS.UV }, {}, 'user_presence'],
  ['UV clear', { flags: FLAGS.UP }, {}, 'user_verification'],
  ['UV clear, where presence is enough', { flags: FLAGS.UP }, { requireUserVerification: false }, 'ok'],
  ['BS set, BE clear', { flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }, {}, 'backup_state'],
  ['BE and BS set: a synced passkey', { flags: FLAGS.UP | FLAGS.UV | FLAGS.BE | FLAGS.BS }, {}, 'ok'],
  ['the reserved flag bits set, which are ignored', { flags: FLAGS.UP | FLAGS.UV | 0x02 | 0x20 }, {}, 'ok'],
  ['extensions, which are ignored', { extensions: encodeCbor(new Map<CborValue, CborValue>([['credProtect', 2], ['hmac-secret', true]])) }, {}, 'ok'],
];

test("an assertion is refused for each of section 7.2's checks, alone, with that check's reason", async () => {
  const other = await SoftAuthenticator.create('ES256');
  const own: Case[] = [
    ['a signature past 1 KiB', { signature: () => new Uint8Array(1025) }, {}, 'malformed'],
    ['a registration answering a sign-in', { clientData: { type: 'webauthn.create' } }, {}, 'type'],
    ['no type in clientDataJSON', { clientData: { type: undefined } }, {}, 'type'],
    ['AT set', { flags: FLAGS.UP | FLAGS.UV | FLAGS.AT, exactFlags: true }, {}, 'malformed'],
    ['shorter than 37 bytes', { authenticatorData: (data) => data.subarray(0, 36) }, {}, 'malformed'],
    // 3 and 4: the passkey named
    ['another credential than the row', {}, { passkey: { ...(await stored(other)), publicKey: await (await authenticator()).publicKey() } }, 'credential'],
    ["another person's user handle", { response: inner((r) => void (r.userHandle = toBase64url(hex('b2'.repeat(16))))) }, {}, 'user_handle'],
    ['no user handle: a security key that keeps none', { response: inner((r) => void delete r.userHandle) }, {}, 'ok'],
    ['a null user handle', { response: inner((r) => void (r.userHandle = null)) }, {}, 'ok'],
    ['an empty user handle, which is present and matches nothing', { response: inner((r) => void (r.userHandle = '')) }, {}, 'user_handle'],
    ['a user handle past 64 bytes', { response: inner((r) => void (r.userHandle = toBase64url(new Uint8Array(65)))) }, {}, 'malformed'],
    // 7. the signature
    ['signed by another key', {}, { passkey: { ...(await stored(other)), credentialId: (await authenticator()).credentialId } }, 'signature'],
    ['a bit of the signature flipped', { signature: flip(40) }, {}, 'signature'],
    ['the signature raw, not DER', { signature: (der) => der.subarray(der.length - 64) }, {}, 'signature'],
    ['bytes after the DER', { signature: append(0) }, {}, 'signature'],
    ['the authenticator data changed after signing', { response: inner((r) => void (r.authenticatorData = toBase64url(flip(34)(b64(String(r.authenticatorData)))))) }, {}, 'signature'],
    ['the stored key of another algorithm than the row says', {}, { passkey: { ...(await stored(await authenticator())), algorithm: -8 } }, 'algorithm'],
  ];
  for (const [name, tweak, expected, wanted] of [...SHARED, ...own]) {
    assert.equal(reason(await assertion(tweak, expected)), wanted, name);
  }
});

test('a DER integer with a needless leading zero is refused, though it is the same number', async () => {
  // A fixed signature whose r is 32 bytes and starts below 0x80: padded, it
  // is 33 bytes, within the length an integer may have, so only the
  // minimality check refuses it. (A generated r may already be 33 bytes.)
  const v = (vectors.w3c as W3cVector[]).find((vector) => vector.id === 'packed-self-es256')!;
  const der = hex(v.authentication.signature);
  assert.equal(der[3], 32);
  assert.ok(der[4] < 0x80);
  const body = [0x02, 33, 0, ...der.subarray(4)];
  const padded = Uint8Array.from([0x30, body.length, ...body]);
  const registered = await verifyRegistration(asRegistration(v), { ...W3C_SITE, challenge: hex(v.registration.challenge), requireUserVerification: false });
  assert.ok(registered.ok);
  const passkey = { credentialId: registered.credentialId, publicKey: registered.publicKey, algorithm: registered.algorithm, userHandle: new Uint8Array(16) };
  const expected = { ...W3C_SITE, challenge: hex(v.authentication.challenge), passkey, requireUserVerification: false };
  assert.equal(reason(await verifyAssertion(asAssertion(v), expected)), 'ok');
  const sent = asAssertion(v);
  sent.response.signature = toBase64url(padded);
  assert.equal(reason(await verifyAssertion(sent, expected)), 'signature');
});

/** A COSE key, from a map an authenticator could have written. */
const cose = (...entries: [CborValue, CborValue][]) => () => encodeCbor(new Map<CborValue, CborValue>(entries));
const attestationMap = (edit: (map: Map<CborValue, CborValue>) => void) => (map: Map<CborValue, CborValue>) => {
  edit(map);
  return map;
};

test("a registration is refused for each of section 7.2's checks, alone, with that check's reason", async () => {
  const ec = await authenticator('ES256');
  const point = cborMap(await ec.publicKey());
  const x = point.get(-2) as Uint8Array;
  const y = point.get(-3) as Uint8Array;
  const own: Case[] = [
    ['an assertion answering a registration', { clientData: { type: 'webauthn.get' } }, {}, 'type'],
    ['transports that are no list', { response: inner((r) => void (r.transports = 'usb')) }, {}, 'malformed'],
    ['a transport that is no name', { response: inner((r) => void (r.transports = ['USB 3'])) }, {}, 'malformed'],
    // The attestation object
    ['attestationObject missing', { response: inner((r) => void delete r.attestationObject) }, {}, 'malformed'],
    ['the attestation object in a map head wider than it needs', { response: inner((r) => {
      const bytes = b64(String(r.attestationObject));
      assert.equal(bytes[0], 0xa3);
      r.attestationObject = toBase64url(Uint8Array.from([0xb8, 0x03, ...bytes.subarray(1)]));
    }) }, {}, 'malformed'],
    ['an attestation object with a fourth key', { attestation: attestationMap((map) => void map.set('epAtt', true)) }, {}, 'malformed'],
    ['an attestation object without fmt', { attestation: attestationMap((map) => void map.delete('fmt')) }, {}, 'malformed'],
    ['fmt not text', { attestation: attestationMap((map) => void map.set('fmt', 1)) }, {}, 'malformed'],
    ['authData not bytes', { attestation: attestationMap((map) => void map.set('authData', 'bytes')) }, {}, 'malformed'],
    ['an attestation statement, ignored whatever its format', { attestation: attestationMap((map) => void map.set('fmt', 'packed').set('attStmt', new Map<CborValue, CborValue>([['alg', -7], ['sig', new Uint8Array(70)], ['x5c', [new Uint8Array(300)]]]))) }, {}, 'ok'],
    ['bytes after the attestation object', { response: inner((r) => void (r.attestationObject = toBase64url(append(0)(b64(String(r.attestationObject)))))) }, {}, 'malformed'],
    // The attested credential
    ['AT clear', { flags: FLAGS.UP | FLAGS.UV, exactFlags: true }, {}, 'malformed'],
    ['bytes after the COSE key', { authenticatorData: append(0) }, {}, 'malformed'],
    ['an attested ID other than the response id', { response: json((r) => void (r.id = r.rawId = toBase64url(new Uint8Array(32)))) }, {}, 'credential'],
    // The key
    ['ES384, not asked for', { publicKey: cose([1, 2], [3, -35], [-1, 2], [-2, new Uint8Array(48)], [-3, new Uint8Array(48)]) }, {}, 'algorithm'],
    ['no alg', { publicKey: cose([1, 2], [-1, 1], [-2, x], [-3, y]) }, {}, 'algorithm'],
    ['ES256 where only Ed25519 was asked for', {}, { algorithms: [-8] }, 'algorithm'],
    ['ES256 on an OKP key', { publicKey: cose([1, 1], [3, -7], [-1, 1], [-2, x], [-3, y]) }, {}, 'key'],
    ['ES256 on P-384', { publicKey: cose([1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]) }, {}, 'key'],
    ['an x of 31 bytes', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]) }, {}, 'key'],
    ['a compressed point', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x], [-3, true]) }, {}, 'key'],
    ['a point off the curve', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x], [-3, flip(31)(y)]) }, {}, 'key'],
    ['a key that is no map', { publicKey: () => encodeCbor([1, 2]) }, {}, 'key'],
    ['EdDSA on Ed448', { publicKey: cose([1, 1], [3, -8], [-1, 7], [-2, new Uint8Array(57)]) }, {}, 'key'],
    ['RS256 of 1024 bits', { publicKey: cose([1, 3], [3, -257], [-1, new Uint8Array([0x80, ...new Uint8Array(127)])], [-2, Uint8Array.of(1, 0, 1)]) }, {}, 'key'],
    ['RS256 of 8192 bits', { publicKey: cose([1, 3], [3, -257], [-1, new Uint8Array([0x80, ...new Uint8Array(1023)])], [-2, Uint8Array.of(1, 0, 1)]) }, {}, 'key'],
    ['RS256 with an even exponent', { publicKey: cose([1, 3], [3, -257], [-1, new Uint8Array([0x80, ...new Uint8Array(255)])], [-2, Uint8Array.of(1, 0, 0)]) }, {}, 'key'],
    ['RS256 on an EC2 key', { publicKey: cose([1, 2], [3, -257], [-1, 1], [-2, x], [-3, y]) }, {}, 'key'],
    // WebAuthn 6.5.1: no optional parameter but alg.
    ['a key with key_ops', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x], [-3, y], [4, [1]]) }, {}, 'key'],
    ['a key with a kid', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x], [-3, y], [2, new Uint8Array(4)]) }, {}, 'key'],
    ['a key carrying its private part', { publicKey: cose([1, 2], [3, -7], [-1, 1], [-2, x], [-3, y], [-4, new Uint8Array(32)]) }, {}, 'key'],
    ['an Ed25519 key with a y', { publicKey: cose([1, 1], [3, -8], [-1, 6], [-2, x], [-3, y]) }, {}, 'key'],
    ['an RSA key with a private exponent', { publicKey: cose([1, 3], [3, -257], [-1, new Uint8Array([0x80, ...new Uint8Array(255)])], [-2, Uint8Array.of(1, 0, 1)], [-3, new Uint8Array(256)]) }, {}, 'key'],
    // RFC 8949, 3.1: CBOR text keeps a leading byte order mark; `\uFEFFfmt` is no `fmt`.
    ['fmt spelled with a byte order mark', { attestation: (map) => new Map([['\uFEFFfmt', 'none'], ...[...map].filter(([key]) => key !== 'fmt')]) }, {}, 'malformed'],
  ];
  for (const [name, tweak, expected, wanted] of [...SHARED, ...own]) {
    assert.equal(reason(await register(tweak, expected)), wanted, name);
  }
  // A credential ID of 15 bytes, and of 1,024, which no browser sends.
  const short = await SoftAuthenticator.create('ES256', { credentialId: new Uint8Array(15) });
  assert.equal(reason(await register({}, {}, short)), 'credential');
  const long = await SoftAuthenticator.create('ES256', { credentialId: new Uint8Array(1024) });
  assert.equal(reason(await register({}, {}, long)), 'malformed');
  const longest = await SoftAuthenticator.create('ES256', { credentialId: new Uint8Array(1023) });
  assert.equal(reason(await register({}, {}, longest)), 'ok');
  // A refusal's message never carries the browser's text: an alg of 20,000 characters is named by its type.
  const wordy = await register({ publicKey: cose([1, 2], [3, 'x\n'.repeat(10_000)], [-1, 1], [-2, x], [-3, y]) });
  assert.equal(reason(wordy), 'algorithm');
  assert.ok(!wordy.ok && wordy.message === 'algorithm string was not asked for', !wordy.ok ? wordy.message : '');
});

function cborMap(bytes: Uint8Array): Map<number | string, unknown> {
  const [value] = readCbor(bytes);
  assert.ok(value instanceof Map);
  return value;
}

test('a registration answers what the row stores: the ID, the COSE key as attested, the algorithm, the AAGUID, the flags and the transports', async () => {
  for (const algorithm of ['Ed25519', 'ES256', 'RS256'] as const) {
    const aaguid = hex('ee882879721c491397753dfcce97072a'); // YubiKey 5 Series
    for (const synced of [false, true]) {
      const key = await SoftAuthenticator.create(algorithm, { synced, aaguid: synced ? undefined : aaguid });
      const result = await register({}, {}, key);
      assert.ok(result.ok, `${algorithm} ${reason(result)}`);
      assert.deepEqual(result.credentialId, key.credentialId);
      assert.deepEqual(result.publicKey, await key.publicKey());
      assert.equal(result.algorithm, { Ed25519: -8, ES256: -7, RS256: -257 }[algorithm]);
      assert.deepEqual(result.aaguid, synced ? null : aaguid);
      assert.equal(result.backupEligible, synced);
      assert.equal(result.backedUp, synced);
      assert.equal(result.userVerified, true);
      assert.deepEqual(result.transports, synced ? ['hybrid', 'internal'] : ['usb']);
      // And the passkey it makes signs in, with its counter: a synced one's stays 0.
      key.userHandle = HANDLE;
      const passkey: StoredPasskey = { credentialId: result.credentialId, publicKey: result.publicKey, algorithm: result.algorithm, userHandle: HANDLE };
      const first = await verifyAssertion(await key.assert({ ...SITE, challenge: CHALLENGE }), { ...SITE, challenge: CHALLENGE, passkey });
      const second = await verifyAssertion(await key.assert({ ...SITE, challenge: CHALLENGE }), { ...SITE, challenge: CHALLENGE, passkey });
      assert.ok(first.ok && second.ok, algorithm);
      assert.deepEqual([first.signCount, second.signCount], synced ? [0, 0] : [2, 3]);
    }
  }
});

test('each algorithm refuses what each check refuses, not only ES256', async () => {
  for (const algorithm of ['Ed25519', 'RS256'] as const) {
    const key = await authenticator(algorithm);
    for (const [name, tweak, expected, wanted] of SHARED) {
      assert.equal(reason(await assertion(tweak, expected, key)), wanted, `${algorithm}: ${name}`);
    }
    assert.equal(reason(await assertion({ signature: flip(10) }, {}, key)), 'signature', algorithm);
    assert.equal(reason(await assertion({ signature: (sig) => sig.subarray(1) }, {}, key)), 'signature', algorithm);
  }
});

// --- CBOR ---------------------------------------------------------------------

test('CBOR reads the subset WebAuthn writes and refuses the rest', () => {
  const malformed = (bytes: number[]) => assert.throws(() => readCbor(Uint8Array.from(bytes)), { message: /CBOR/ }, Buffer.from(bytes).toString('hex'));
  assert.deepEqual(readCbor(Uint8Array.of(0x18, 0x64)), [100, 2]);
  assert.deepEqual(readCbor(Uint8Array.of(0x38, 0x63)), [-100, 2]);
  assert.deepEqual(readCbor(Uint8Array.of(0x1b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), [Number.MAX_SAFE_INTEGER, 9]);
  assert.deepEqual(readCbor(Uint8Array.of(0x82, 0xf5, 0xf6)), [[true, null], 3]);
  assert.deepEqual(readCbor(encodeCbor(new Map<CborValue, CborValue>([[1, 'a'], ['b', new Uint8Array(2)]])))[0], new Map<number | string, unknown>([[1, 'a'], ['b', new Uint8Array(2)]]));
  malformed([0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0]); // 2^53: past what a number holds exactly
  malformed([0x5f, 0x41, 0, 0xff]); // an indefinite byte string
  malformed([0x9f, 0xff]); // an indefinite array
  malformed([0xc2, 0x41, 1]); // a tag: a bignum
  malformed([0xf9, 0x3c, 0]); // a half float
  malformed([0xf7]); // undefined
  malformed([0x1c]); // a reserved length
  malformed([0x42, 1]); // a byte string longer than its input
  malformed([0x9a, 0xff, 0xff, 0xff, 0xff]); // an array of four billion items in four bytes: refused before allocating
  malformed([0xa2, 1, 1, 1, 2]); // a key twice
  malformed([0xa1, 0x80, 1]); // a key that is an array
  malformed([0x62, 0xc3, 0x28]); // text that is not UTF-8
  // Each argument in its shortest head (CTAP2's canonical form).
  assert.deepEqual(readCbor(Uint8Array.of(0x17)), [23, 1]);
  assert.deepEqual(readCbor(Uint8Array.of(0x18, 0x18)), [24, 2]);
  assert.deepEqual(readCbor(Uint8Array.of(0x19, 0x01, 0x00)), [256, 3]);
  assert.deepEqual(readCbor(Uint8Array.of(0x1a, 0, 1, 0, 0)), [65536, 5]);
  assert.deepEqual(readCbor(Uint8Array.of(0x1b, 0, 0, 0, 1, 0, 0, 0, 0)), [2 ** 32, 9]);
  malformed([0x18, 0x17]); // 23 in a byte of its own
  malformed([0x19, 0, 0xff]); // 255 in two
  malformed([0x1a, 0, 0, 0xff, 0xff]); // 65535 in four
  malformed([0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]); // 2^32 - 1 in eight
  malformed([0x38, 0x00]); // -1, likewise
  malformed([0x58, 0x01, 0x00]); // a byte string's length
  malformed([0x78, 0x01, 0x61]); // a text's
  malformed([0x98, 0x01, 0x00]); // an array's
  malformed([0xb8, 0x01, 0x01, 0x01]); // a map's
  malformed([]);
  malformed(Array.from({ length: 20 }, () => 0x81).concat([0])); // twenty arrays deep
  // A byte order mark is a character of the text, kept: two keys that differ by one are two keys.
  assert.deepEqual(readCbor(encodeCbor('\uFEFFhello'))[0], '\uFEFFhello');
  assert.equal((readCbor(encodeCbor(new Map<CborValue, CborValue>([['x', 1], ['\uFEFFx', 2]])))[0] as Map<string, unknown>).size, 2);
});

test("a challenge under WebAuthn's 16 bytes is the caller's mistake, and throws rather than check nothing", async () => {
  const key = await authenticator();
  key.userHandle = HANDLE;
  const empty = new Uint8Array(0);
  const response = await key.assert({ ...SITE, challenge: empty });
  await assert.rejects(verifyAssertion(response, { ...SITE, challenge: empty, passkey: await stored(key) }), /at least 16 bytes/);
  const registration = await key.register({ ...SITE, challenge: empty, userHandle: HANDLE });
  await assert.rejects(verifyRegistration(registration, { ...SITE, challenge: new Uint8Array(15) }), /at least 16 bytes/);
});

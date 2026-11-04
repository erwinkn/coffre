/**
 * Passkeys' verifier (docs/design/passkeys.md, sections 7.2 and 9): the
 * relying party's half of WebAuthn Level 3, its "Registering a new
 * credential" and "Verifying an authentication assertion", over WebCrypto
 * and nothing else. Coffre asks for no attestation, so it reads none: the
 * attestation statement is skipped whatever its format, and the key is the
 * one the browser says was made.
 *
 * What it checks, each refusal naming its check (`PasskeyReason`):
 *
 *   a. the response's shape: `type` is `public-key`, `id` is `rawId`, every
 *      field is canonical base64url within its size, CBOR and JSON decode
 *      and nothing trails                                     `malformed`
 *   b. an assertion's credential: the stored passkey's ID, and `userHandle`,
 *      when the authenticator returns one, the stored handle
 *                                                `credential` `user_handle`
 *   c. `clientDataJSON`: its `type` is the ceremony's (`webauthn.create` or
 *      `.get`), its challenge the one sent, its origin exactly the
 *      deployment's, `crossOrigin` false or absent, `topOrigin` absent
 *                                            `type` `challenge` `origin`
 *   d. `authenticatorData`: the RP ID's hash, then the flags: UP set, BS
 *      only with BE, AT set for a registration and clear for an assertion,
 *      ED followed by one CBOR map, whose extensions are ignored
 *                                     `rp_id` `user_presence` `backup_state`
 *   e. a registration's credential: its ID 16 to 1023 bytes and the
 *      response's `id`, its key a COSE key of an algorithm asked for
 *      (Ed25519, ES256, RS256 of 2048 to 4096 bits), its `alg` the one its
 *      type allows                              `credential` `algorithm` `key`
 *   f. an assertion's signature, over `authenticatorData ‖
 *      SHA-256(clientDataJSON)` with the stored key; ES256's DER turned into
 *      the raw form WebCrypto verifies                        `signature`
 *   g. UV set: the touch was a fingerprint, a face or a PIN, not presence
 *      alone (`USER_VERIFICATION`)                    `user_verification`
 *
 * A registration runs a, c, d, e and g; an assertion a, b, c, d, f and g, in
 * section 7.2's order but for g, which comes last: a response refused for
 * `user_verification` passed every other check. That costs nothing (UV is
 * one bit the signature covers, and a refusal returns nothing), and it
 * keeps the W3C vectors whose UV bit is clear verifying every other step.
 *
 * What it leaves to its caller: the sealed state the challenge came in,
 * which passkey row the ID names and whether it is live, and the counter and
 * replay mark, which one conditional statement moves (section 7.3). It never
 * throws on what a browser sent: every input gets an answer. It throws on a
 * challenge under 16 bytes, the caller's mistake.
 */
import { base64url, fromBase64url } from '@coffre/client/dpop';

/** The COSE algorithms a passkey may use, in the order `create()` asks for them: Ed25519, ES256, RS256. */
export const PASSKEY_ALGORITHMS = [-8, -7, -257] as const;
export type PasskeyAlgorithm = (typeof PASSKEY_ALGORITHMS)[number];

/**
 * What `create()` and `get()` ask for and the verifier holds every response
 * to (section 7.4): a PIN or a biometric, never presence alone. One value,
 * not a setting.
 */
export const USER_VERIFICATION = 'required';

/** Why a response was refused; `passkey.check`'s denials name it. */
export type PasskeyReason =
  | 'malformed'
  | 'type'
  | 'challenge'
  | 'origin'
  | 'rp_id'
  | 'user_presence'
  | 'user_verification'
  | 'backup_state'
  | 'credential'
  | 'user_handle'
  | 'algorithm'
  | 'key'
  | 'signature';

export type PasskeyRefusal = { ok: false; reason: PasskeyReason; message: string };

/** What the ceremony expects: the challenge it sent, the deployment's origin and RP ID. */
export type CeremonyExpectation = {
  challenge: Uint8Array;
  /** `publicUrl`'s origin, exactly: `https://secrets.acme.example`. */
  origin: string;
  /** `publicUrl`'s host, or the parent of it the deployment names. */
  rpId: string;
};

export type RegistrationExpectation = CeremonyExpectation & {
  /** The algorithms `create()` asked for; `PASSKEY_ALGORITHMS` unless said. */
  algorithms?: readonly PasskeyAlgorithm[];
};

/** The passkey row an assertion is checked against. */
export type StoredPasskey = {
  credentialId: Uint8Array;
  /** The COSE key exactly as registered. */
  publicKey: Uint8Array;
  algorithm: PasskeyAlgorithm;
  userHandle: Uint8Array;
};

export type AssertionExpectation = CeremonyExpectation & { passkey: StoredPasskey };

/** The flags a response's authenticator data carried; UV is always set on one that verified. */
export type PasskeyFlags = { backupEligible: boolean; backedUp: boolean };

export type VerifiedRegistration = PasskeyFlags & {
  ok: true;
  credentialId: Uint8Array;
  /** The COSE key, the exact bytes the authenticator wrote: what the row stores and an assertion is verified with. */
  publicKey: Uint8Array;
  algorithm: PasskeyAlgorithm;
  signCount: number;
  /** The authenticator's model, or null when it gives none (all zeros). */
  aaguid: Uint8Array | null;
  /** How the browser says it can reach the authenticator: `internal`, `hybrid`, `usb`… Display only. */
  transports: string[];
};

export type VerifiedAssertion = PasskeyFlags & { ok: true; signCount: number };

const refuse = (reason: PasskeyReason, message: string): PasskeyRefusal => ({ ok: false, reason, message });

/** A refusal thrown inside the parsers and turned back into one at the top: every path out answers. */
class Refused extends Error {
  readonly reason: PasskeyReason;
  constructor(reason: PasskeyReason, message: string) {
    super(message);
    this.reason = reason;
  }
}
const fail = (reason: PasskeyReason, message: string): never => {
  throw new Refused(reason, message);
};

// Bounds on what a browser may send, decoded. From the spec: a credential
// ID is 16 to 1,023 bytes (WebAuthn L3, "Credential ID"), a user handle 64
// at most (5.4.3). From the algorithms coffre takes: an RSA key of 2,048 to
// 4,096 bits (docs/design/passkeys.md, section 7.2), whose signature is as
// long as its modulus, the longest of the three (Ed25519's is 64 bytes,
// ES256's DER at most 72). The rest bound input the spec leaves open
// (client data, extensions, an attestation statement's certificate chain, a
// TPM's the longest at a few KiB) to what one request may make the parser
// hold, which no protocol or platform sets: open under R70.
export const MAX_CREDENTIAL_ID = 1023;
const MIN_CREDENTIAL_ID = 16;
const MIN_RSA_BITS = 2048;
const MAX_RSA_BITS = 4096;
const MAX_SIGNATURE = MAX_RSA_BITS / 8;
const MAX_USER_HANDLE = 64;
const MAX_CLIENT_DATA = 4096;
const MAX_AUTHENTICATOR_DATA = 4096;
const MAX_ATTESTATION_OBJECT = 32768;
const MAX_CBOR_DEPTH = 16;

/** The transports WebAuthn L3 names (5.8.4), the ones a browser acts on when handed back. */
const TRANSPORTS: ReadonlySet<string> = new Set(['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);

/** How long a base64url text of `bytes` bytes is, unpadded. */
export const base64urlLength = (bytes: number): number => Math.ceil((bytes * 4) / 3);

// clientDataJSON is decoded as WebAuthn says, UTF-8 decode, which drops a
// leading byte order mark; CBOR text keeps every character it holds
// (RFC 8949, 3.1), so that `\uFEFFfmt` is never read as `fmt`.
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const CBOR_TEXT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const ENCODER = new TextEncoder();

// --- CBOR, the subset WebAuthn writes ----------------------------------------

/** A CBOR value: safe integers (-2^53 to 2^53 - 1), byte and text strings, arrays, maps keyed by integers or text, and true, false and null. */
export type Cbor = number | string | boolean | null | Uint8Array | Cbor[] | Map<number | string, Cbor>;

/**
 * Reads one CBOR item at `offset` and answers it with where it ends.
 * Definite lengths only, each in its shortest head; no tags, floats or
 * `undefined`; no duplicate map keys; text that is UTF-8. A length longer than what is left is refused
 * before anything is allocated for it.
 */
export function readCbor(bytes: Uint8Array, offset = 0, depth = 0): [Cbor, number] {
  if (depth > MAX_CBOR_DEPTH) fail('malformed', 'CBOR nested too deep');
  if (offset >= bytes.length) fail('malformed', 'CBOR ends early');
  const head = bytes[offset];
  const major = head >> 5;
  const info = head & 0x1f;
  let at = offset + 1;
  if (major === 7) {
    if (info === 20) return [false, at];
    if (info === 21) return [true, at];
    if (info === 22) return [null, at];
    return fail('malformed', `CBOR simple value or float ${info} is not taken`);
  }
  let argument: number;
  if (info < 24) argument = info;
  else if (info <= 27) {
    const size = 1 << (info - 24);
    if (at + size > bytes.length) fail('malformed', 'CBOR ends early');
    argument = 0;
    for (let i = 0; i < size; i++) argument = argument * 256 + bytes[at + i];
    if (!Number.isSafeInteger(argument)) fail('malformed', 'CBOR integer past 2^53');
    // CTAP2's canonical form: the shortest head that holds the argument.
    if (argument < (info === 24 ? 24 : 2 ** (4 * size))) fail('malformed', 'CBOR argument wider than it needs');
    at += size;
  } else return fail('malformed', 'CBOR indefinite length or reserved value');
  switch (major) {
    case 0:
      return [argument, at];
    case 1:
      return [-1 - argument, at];
    case 2:
    case 3: {
      if (argument > bytes.length - at) fail('malformed', 'CBOR string longer than its input');
      const slice = bytes.subarray(at, at + argument);
      if (major === 2) return [slice, at + argument];
      try {
        return [CBOR_TEXT.decode(slice), at + argument];
      } catch {
        return fail('malformed', 'CBOR text is not UTF-8');
      }
    }
    case 4: {
      if (argument > bytes.length - at) fail('malformed', 'CBOR array longer than its input');
      const items: Cbor[] = [];
      for (let i = 0; i < argument; i++) {
        const [item, end] = readCbor(bytes, at, depth + 1);
        items.push(item);
        at = end;
      }
      return [items, at];
    }
    case 5: {
      if (argument * 2 > bytes.length - at) fail('malformed', 'CBOR map longer than its input');
      const map = new Map<number | string, Cbor>();
      for (let i = 0; i < argument; i++) {
        const [key, afterKey] = readCbor(bytes, at, depth + 1);
        if (typeof key !== 'number' && typeof key !== 'string') fail('malformed', 'CBOR map key is neither an integer nor text');
        if (map.has(key as number | string)) fail('malformed', 'CBOR map repeats a key');
        const [value, end] = readCbor(bytes, afterKey, depth + 1);
        map.set(key as number | string, value);
        at = end;
      }
      return [map, at];
    }
    default:
      return fail('malformed', 'CBOR tags are not taken');
  }
}

/** Exactly one CBOR item, nothing after it. */
function cborWhole(bytes: Uint8Array): Cbor {
  const [value, end] = readCbor(bytes);
  if (end !== bytes.length) fail('malformed', 'bytes trail the CBOR');
  return value;
}

// --- the response's fields ---------------------------------------------------

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => typeof value === 'object' && value !== null && !Array.isArray(value);

/** A field that must be canonical base64url of 1 to `max` bytes. */
function bytesOf(record: Json, field: string, max: number): Uint8Array {
  const text = record[field];
  // Four characters for three bytes: a longer string cannot decode within `max`.
  if (typeof text !== 'string' || text.length === 0 || text.length > base64urlLength(max)) return fail('malformed', `${field} is not base64url within ${max} bytes`);
  const bytes = fromBase64url(text);
  if (bytes === null || bytes.length > max) return fail('malformed', `${field} is not canonical base64url within ${max} bytes`);
  return bytes;
}

/** The parts every response shares: the credential's ID, `rawId` equal to it, and its `response`. */
function envelope(input: unknown): { id: Uint8Array; response: Json } {
  if (!isObject(input) || input.type !== 'public-key') return fail('malformed', "the credential's type is not public-key");
  if (input.id !== input.rawId) return fail('malformed', 'id is not rawId');
  const id = bytesOf(input, 'id', MAX_CREDENTIAL_ID);
  if (!isObject(input.response)) return fail('malformed', 'the response is missing');
  return { id, response: input.response };
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * The caller's challenge, held to WebAuthn's 16-byte minimum. Its mistakes
 * are coffre's, not the browser's, so they throw: an empty challenge, say
 * from a sealed state missing its field, would otherwise check nothing. (A
 * wrong origin or RP ID needs no guard: it refuses every response.)
 */
function checkExpectation(expected: CeremonyExpectation): void {
  if (!(expected.challenge instanceof Uint8Array) || expected.challenge.length < 16) throw new Error('a ceremony challenge is at least 16 bytes');
}

/** Step 2: what the browser says it signed for. */
function checkClientData(bytes: Uint8Array, type: 'webauthn.create' | 'webauthn.get', expected: CeremonyExpectation): void {
  let data: unknown;
  try {
    data = JSON.parse(UTF8.decode(bytes));
  } catch {
    return fail('malformed', 'clientDataJSON is not UTF-8 JSON');
  }
  if (!isObject(data)) return fail('malformed', 'clientDataJSON is not an object');
  if (data.type !== type) return fail('type', `clientDataJSON's type is not ${type}`);
  if (data.challenge !== base64url(expected.challenge)) return fail('challenge', 'the challenge is not the one sent');
  if (data.origin !== expected.origin) return fail('origin', `the origin is not ${expected.origin}`);
  if (data.crossOrigin !== undefined && data.crossOrigin !== false) return fail('origin', 'the ceremony ran in a cross-origin frame');
  if (data.topOrigin !== undefined) return fail('origin', 'the ceremony ran inside another origin');
}

// Authenticator data's flags (WebAuthn Level 3, 6.1). Bits 1 and 5 are reserved and ignored.
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

type AuthenticatorData = PasskeyFlags & { userVerified: boolean; signCount: number; attested: { aaguid: Uint8Array; credentialId: Uint8Array; publicKey: Uint8Array } | null };

/** Step 3: the RP ID's hash, the flags, and for a registration the attested credential. */
async function readAuthenticatorData(bytes: Uint8Array, attested: boolean, expected: CeremonyExpectation): Promise<AuthenticatorData> {
  if (bytes.length < 37) return fail('malformed', 'authenticatorData is shorter than 37 bytes');
  if (!equal(bytes.subarray(0, 32), await sha256(ENCODER.encode(expected.rpId)))) return fail('rp_id', `the RP ID is not ${expected.rpId}`);
  const flags = bytes[32];
  if (!(flags & UP)) return fail('user_presence', 'the user was not present');
  if (flags & BS && !(flags & BE)) return fail('backup_state', 'backed up but not backup eligible');
  if (Boolean(flags & AT) !== attested) return fail('malformed', attested ? 'no attested credential data' : 'attested credential data in an assertion');
  const signCount = new DataView(bytes.buffer, bytes.byteOffset + 33, 4).getUint32(0);
  let at = 37;
  let credential: AuthenticatorData['attested'] = null;
  if (attested) {
    if (bytes.length < at + 18) return fail('malformed', 'attested credential data ends early');
    const aaguid = bytes.slice(at, at + 16);
    const length = (bytes[at + 16] << 8) | bytes[at + 17];
    at += 18;
    if (length < MIN_CREDENTIAL_ID || length > MAX_CREDENTIAL_ID) return fail('credential', `the credential ID is ${length} bytes, not 16 to 1023`);
    if (bytes.length < at + length) return fail('malformed', 'the credential ID ends early');
    const credentialId = bytes.slice(at, at + length);
    at += length;
    const [, end] = readCbor(bytes, at);
    credential = { aaguid, credentialId, publicKey: bytes.slice(at, end) };
    at = end;
  }
  if (flags & ED) {
    const [extensions, end] = readCbor(bytes, at);
    if (!(extensions instanceof Map) || ![...extensions.keys()].every((key) => typeof key === 'string')) return fail('malformed', 'extensions are not a map keyed by name');
    at = end;
  }
  if (at !== bytes.length) return fail('malformed', 'bytes trail the authenticator data');
  return { signCount, attested: credential, userVerified: Boolean(flags & UV), backupEligible: Boolean(flags & BE), backedUp: Boolean(flags & BS) };
}

// --- keys and signatures -----------------------------------------------------

// COSE (RFC 9052, 9053): key labels and values.
const KTY = 1;
const ALG = 3;
const OKP = 1;
const EC2 = 2;
const RSA = 3;

/** The integer with its leading zero bytes dropped: a modulus's or an exponent's magnitude. */
function unsigned(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start++;
  return bytes.subarray(start);
}

function byteParam(key: Map<number | string, Cbor>, label: number, length?: number): Uint8Array {
  const value = key.get(label);
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) return fail('key', `COSE parameter ${label} is not ${length ?? 'a'} byte string`);
  return value;
}

/** A COSE key as WebCrypto's, held to the algorithm its `alg` names and its type allows. */
async function importCoseKey(cose: Uint8Array, allowed: readonly PasskeyAlgorithm[]): Promise<{ algorithm: PasskeyAlgorithm; key: CryptoKey }> {
  const key = cborWhole(cose);
  if (!(key instanceof Map)) return fail('key', 'the public key is not a COSE map');
  const alg = key.get(ALG);
  if (!(allowed as readonly unknown[]).includes(alg)) return fail('algorithm', `algorithm ${typeof alg === 'number' ? alg : typeof alg} was not asked for`);
  const algorithm = alg as PasskeyAlgorithm;
  const kty = key.get(KTY);
  // WebAuthn 6.5.1: `alg` and each key type's own parameters, and no other
  // (no `kid`, no `key_ops`, no private part).
  const labels = { [-8]: [KTY, ALG, -1, -2], [-7]: [KTY, ALG, -1, -2, -3], [-257]: [KTY, ALG, -1, -2] }[algorithm];
  if (key.size !== labels.length || !labels.every((label) => key.has(label))) return fail('key', `the COSE key has parameters other than ${labels.join(', ')}`);
  try {
    if (algorithm === -8) {
      if (kty !== OKP || key.get(-1) !== 6) return fail('key', 'EdDSA key is not OKP Ed25519');
      return { algorithm, key: await crypto.subtle.importKey('raw', byteParam(key, -2, 32) as Uint8Array<ArrayBuffer>, { name: 'Ed25519' }, false, ['verify']) };
    }
    if (algorithm === -7) {
      if (kty !== EC2 || key.get(-1) !== 1) return fail('key', 'ES256 key is not EC2 P-256');
      const point = new Uint8Array(65);
      point[0] = 0x04;
      point.set(byteParam(key, -2, 32), 1);
      point.set(byteParam(key, -3, 32), 33);
      return { algorithm, key: await crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']) };
    }
    if (kty !== RSA) return fail('key', 'RS256 key is not RSA');
    const n = unsigned(byteParam(key, -1));
    const e = unsigned(byteParam(key, -2));
    // Whole bytes, less the leading zero bits of the first: clz32 counts 24 more on a byte.
    const bits = n.length === 0 ? 0 : n.length * 8 - (Math.clz32(n[0]) - 24);
    if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) return fail('key', `RSA modulus of ${bits} bits, not ${MIN_RSA_BITS} to ${MAX_RSA_BITS}`);
    if (e.length === 0 || e.length > 4 || !(e[e.length - 1] & 1) || (e.length === 1 && e[0] < 3)) return fail('key', 'RSA exponent is not an odd number from 3 to 2^32');
    const jwk = { kty: 'RSA', n: base64url(n), e: base64url(e), alg: 'RS256', ext: true };
    return { algorithm, key: await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']) };
  } catch (error) {
    if (error instanceof Refused) throw error;
    return fail('key', 'the public key does not import');
  }
}

/**
 * ES256's DER signature, `SEQUENCE { INTEGER r, INTEGER s }`, as the 64
 * bytes WebCrypto verifies. Strict DER: short lengths, minimal positive
 * integers of at most 32 bytes of magnitude, nothing trailing.
 *
 * Strict DER does not make a signature unique: `(r, n - s)` verifies as
 * well as `(r, s)`. Replay is the row's mark (section 7.3); a signature's
 * bytes must never be a replay or dedup key.
 */
function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> | null {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2 || der[1] > 0x7f) return null;
  const raw = new Uint8Array(64);
  let at = 2;
  for (const half of [0, 32]) {
    if (der[at] !== 0x02) return null;
    const length = der[at + 1];
    const start = at + 2;
    if (length === 0 || length > 33 || start + length > der.length) return null;
    const integer = der.subarray(start, start + length);
    if (integer[0] & 0x80) return null; // negative
    if (integer[0] === 0 && (length === 1 || !(integer[1] & 0x80))) return null; // not minimal
    const magnitude = integer[0] === 0 ? integer.subarray(1) : integer;
    if (magnitude.length > 32) return null;
    raw.set(magnitude, half + 32 - magnitude.length);
    at = start + length;
  }
  return at === der.length ? raw : null;
}

/** Whether the signature verifies; a signature of the wrong length for its key is one that does not. */
async function verifySignature(algorithm: PasskeyAlgorithm, key: CryptoKey, signature: Uint8Array, signed: Uint8Array): Promise<boolean> {
  const data = signed as Uint8Array<ArrayBuffer>;
  try {
    if (algorithm === -7) {
      const raw = derToRaw(signature);
      return raw !== null && (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, data));
    }
    const name = algorithm === -8 ? 'Ed25519' : 'RSASSA-PKCS1-v1_5';
    return await crypto.subtle.verify({ name }, key, signature as Uint8Array<ArrayBuffer>, data);
  } catch {
    return false;
  }
}

// --- the two ceremonies ------------------------------------------------------

async function answer<T>(run: () => Promise<T>): Promise<T | PasskeyRefusal> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof Refused) return refuse(error.reason, error.message);
    throw error;
  }
}

/**
 * The transports the browser listed that WebAuthn names, once each: a hint handed back to `get()`, whose browser
 * ignores any other (5.8.4), so one it does not know hints nothing and is dropped, not refused.
 */
function transportsOf(response: Json): string[] {
  const list = response.transports;
  if (list === undefined) return [];
  if (!Array.isArray(list)) return fail('malformed', 'transports is not a list');
  return [...TRANSPORTS].filter((transport) => list.includes(transport));
}

/** A `create()` response, `credential.toJSON()`, held to section 7.2's registration checks. */
export function verifyRegistration(input: unknown, expected: RegistrationExpectation): Promise<VerifiedRegistration | PasskeyRefusal> {
  return answer(async () => {
    checkExpectation(expected);
    const { id, response } = envelope(input);
    const clientData = bytesOf(response, 'clientDataJSON', MAX_CLIENT_DATA);
    const attestation = cborWhole(bytesOf(response, 'attestationObject', MAX_ATTESTATION_OBJECT));
    const transports = transportsOf(response);
    if (!(attestation instanceof Map) || attestation.size !== 3) return fail('malformed', 'the attestation object is not fmt, attStmt and authData');
    const authData = attestation.get('authData');
    if (typeof attestation.get('fmt') !== 'string' || !(attestation.get('attStmt') instanceof Map) || !(authData instanceof Uint8Array)) {
      return fail('malformed', 'the attestation object is not fmt, attStmt and authData');
    }
    checkClientData(clientData, 'webauthn.create', expected);
    const data = await readAuthenticatorData(authData, true, expected);
    const credential = data.attested!;
    if (!equal(credential.credentialId, id)) return fail('credential', "the attested credential is not the response's id");
    const { algorithm } = await importCoseKey(credential.publicKey, expected.algorithms ?? PASSKEY_ALGORITHMS);
    checkVerified(data);
    return {
      ok: true as const,
      credentialId: credential.credentialId,
      publicKey: credential.publicKey,
      algorithm,
      signCount: data.signCount,
      aaguid: credential.aaguid.some((byte) => byte !== 0) ? credential.aaguid : null,
      transports,
      backupEligible: data.backupEligible,
      backedUp: data.backedUp,
    };
  });
}

/** Check g, the last: `USER_VERIFICATION` is `required`, so UV is set. */
function checkVerified(data: AuthenticatorData): void {
  if (!data.userVerified) fail('user_verification', 'the user was not verified, only present');
}

/** A returned user handle: canonical base64url of 1 to 64 bytes, or, empty, one that matches no passkey. */
function handleOf(value: unknown): Uint8Array {
  if (value === '') return fail('user_handle', 'the user handle is empty');
  return bytesOf({ userHandle: value }, 'userHandle', MAX_USER_HANDLE);
}

/** A `get()` response, `credential.toJSON()`, held to section 7.2's assertion checks against the stored passkey. */
export function verifyAssertion(input: unknown, expected: AssertionExpectation): Promise<VerifiedAssertion | PasskeyRefusal> {
  return answer(async () => {
    checkExpectation(expected);
    const { id, response } = envelope(input);
    const clientData = bytesOf(response, 'clientDataJSON', MAX_CLIENT_DATA);
    const authData = bytesOf(response, 'authenticatorData', MAX_AUTHENTICATOR_DATA);
    const signature = bytesOf(response, 'signature', MAX_SIGNATURE);
    // Absent or null: the authenticator kept no handle (a security key's non-discoverable credential). Present, it is compared.
    const handle = response.userHandle === undefined || response.userHandle === null ? null : handleOf(response.userHandle);
    const { passkey } = expected;
    if (!equal(id, passkey.credentialId)) return fail('credential', 'the assertion is by another credential');
    if (handle !== null && !equal(handle, passkey.userHandle)) return fail('user_handle', "the user handle is not the passkey's");
    checkClientData(clientData, 'webauthn.get', expected);
    const data = await readAuthenticatorData(authData, false, expected);
    const { key } = await importCoseKey(passkey.publicKey, [passkey.algorithm]);
    const signed = new Uint8Array(authData.length + 32);
    signed.set(authData);
    signed.set(await sha256(clientData), authData.length);
    if (!(await verifySignature(passkey.algorithm, key, signature, signed))) return fail('signature', 'the signature does not verify');
    checkVerified(data);
    return { ok: true as const, signCount: data.signCount, backupEligible: data.backupEligible, backedUp: data.backedUp };
  });
}

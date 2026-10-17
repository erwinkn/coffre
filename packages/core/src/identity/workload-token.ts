import { createHash } from 'node:crypto';

import { createLocalJWKSet, errors, importJWK, jwtVerify, type JSONWebKeySet, type JWK, type JWTPayload } from 'jose';

export type { JSONWebKeySet };

/**
 * An ID token a CI platform signed for a run, as the exchange checks it
 * (docs/design/oidc.md, section 3). The checks run in this order; each
 * refusal says which, as a reason a CI user can act on.
 */

/** A compact JWS is three base64url parts; the whole token at most this long. */
export const MAX_TOKEN_BYTES = 8 * 1024;
/** Each side of every time check. */
export const CLOCK_TOLERANCE_SECONDS = 30;
/** The oldest token accepted, by its `iat`: tokens handed to a job at its start fit, day-old ones do not. */
export const MAX_TOKEN_AGE_SECONDS = 3600;
/** RS256 and ES256 (P-256), as for Access assertions: never `none`, never HS*. */
export const WORKLOAD_ALGORITHMS = ['RS256', 'ES256'] as const;

export type WorkloadRefusal =
  /** Not a compact JWS, or claims that are not the right types. */
  | 'malformed'
  /** The signature does not verify under the issuer's keys. */
  | 'signature'
  /** Signed by a key the issuer's set does not hold, now. */
  | 'unknown_key'
  /** Past its `exp`. */
  | 'expired'
  /** Its `iat` is more than an hour ago, or not yet. */
  | 'too_old'
  /** It lives longer than an hour, `exp` − `iat`, where its binding carries its keys. */
  | 'too_long'
  /** Its `nbf` is still to come. */
  | 'not_yet_valid'
  /** Its audience is not this instance alone. */
  | 'audience';

export class WorkloadTokenRefused extends Error {
  readonly reason: WorkloadRefusal;
  constructor(reason: WorkloadRefusal, message: string) {
    super(message);
    this.name = 'WorkloadTokenRefused';
    this.reason = reason;
  }
}

/** What a token says before anything about it is trusted: enough to find the binding it would match. */
export type DecodedToken = {
  header: Record<string, unknown>;
  claims: Record<string, unknown> & { iss: string; sub: string; exp: number; iat: number };
  /**
   * SHA-256 of `header.payload`, exactly as received: what the signature
   * covers, and so the one spelling of the token. Hashing the whole token
   * would not do: an ES256 signature (r, s) has a twin, (r, n − s), that
   * verifies the same claims, so the whole token has two spellings.
   */
  signingInputHash: Buffer;
};

const PART = /^[A-Za-z0-9_-]+$/;

/** A token's parts and claims, checked for shape and types only. Throws `WorkloadTokenRefused('malformed')`. */
export function decodeWorkloadToken(token: string): DecodedToken {
  const malformed = (why: string) => new WorkloadTokenRefused('malformed', `the token ${why}`);
  if (typeof token !== 'string' || token.length === 0) throw malformed('is empty');
  if (token.length > MAX_TOKEN_BYTES) throw malformed(`is longer than ${MAX_TOKEN_BYTES} bytes`);
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => PART.test(part))) throw malformed('is not a compact JWS');
  const json = (part: string): Record<string, unknown> => {
    let value: unknown;
    try {
      value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    } catch {
      throw malformed('has a part that is not JSON');
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw malformed('has a part that is not an object');
    return value as Record<string, unknown>;
  };
  const [header, claims] = [json(parts[0]!), json(parts[1]!)];
  for (const name of ['iss', 'sub'] as const) {
    if (typeof claims[name] !== 'string' || claims[name] === '') throw malformed(`has no ${name}, as a nonempty string`);
  }
  for (const name of ['exp', 'iat'] as const) {
    if (typeof claims[name] !== 'number' || !Number.isFinite(claims[name])) throw malformed(`has no ${name}, as a finite number`);
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf))) throw malformed('has an nbf that is not a finite number');
  return {
    header,
    claims: claims as DecodedToken['claims'],
    signingInputHash: createHash('sha256').update(`${parts[0]}.${parts[1]}`, 'ascii').digest(),
  };
}

/**
 * Verify a token under an issuer's keys: the signature by jose, with the
 * algorithms fixed and nothing taken from the header but `alg` and `kid`;
 * the issuer exactly; `exp`, `nbf` and `iat` within the tolerance, `iat` at
 * most an hour old; and the audience, this instance's public URL alone.
 * With `maxLifetime`, in seconds, a token whose `exp` is further than that
 * from its `iat` is refused too. Returns the verified claims.
 */
export async function verifyWorkloadToken(
  token: string,
  keys: JSONWebKeySet,
  expected: { issuer: string; audience: string; now: Date; maxLifetime?: number },
): Promise<JWTPayload & DecodedToken['claims']> {
  const options = {
    algorithms: [...WORKLOAD_ALGORITHMS],
    issuer: expected.issuer,
    // For exp and nbf; iat's bounds are issuedRefusal's, since jose would stretch the hour by the tolerance too.
    clockTolerance: CLOCK_TOLERANCE_SECONDS,
    requiredClaims: ['iss', 'sub', 'exp', 'iat'],
    currentDate: expected.now,
  };
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, createLocalJWKSet(keys), options));
  } catch (error) {
    if (!(error instanceof errors.JWKSMultipleMatchingKeys)) throw refusalOf(error);
    payload = await anyKey(token, error, options);
  }
  const issued = issuedRefusal(payload.iat!, expected.now.getTime() / 1000);
  if (issued !== null) throw issued;
  if (expected.maxLifetime !== undefined && payload.exp! - payload.iat! > expected.maxLifetime) {
    throw new WorkloadTokenRefused('too_long', `the token lives longer than ${expected.maxLifetime / 60} minutes, from its iat to its exp: ask for a shorter one`);
  }
  const { aud } = payload;
  if (!(aud === expected.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === expected.audience))) {
    throw new WorkloadTokenRefused('audience', `the token is for ${JSON.stringify(aud ?? null)}, not ${expected.audience} alone`);
  }
  return payload as JWTPayload & DecodedToken['claims'];
}

/**
 * Why a token issued at `iat` may not be exchanged at `now`, both in
 * seconds, or null: issued an hour ago at most, exactly, and no further
 * ahead than the clock tolerance. Verification and the exchange's commit
 * both ask it.
 */
export function issuedRefusal(iat: number, now: number): WorkloadTokenRefused | null {
  if (now - iat > MAX_TOKEN_AGE_SECONDS) {
    return new WorkloadTokenRefused('too_old', `the token was issued more than ${MAX_TOKEN_AGE_SECONDS / 60} minutes ago`);
  }
  if (iat - now > CLOCK_TOLERANCE_SECONDS) return new WorkloadTokenRefused('too_old', 'the token says it was issued in the future');
  return null;
}

/**
 * A token that names no key, or one several keys share, verified by
 * whichever of them signed it: a set may hold several, as while its issuer
 * rotates. At most `MAX_KEYS` tries, each a signature check alone.
 */
async function anyKey(token: string, matching: errors.JWKSMultipleMatchingKeys, options: Parameters<typeof jwtVerify>[2]): Promise<JWTPayload> {
  for await (const key of matching) {
    try {
      return (await jwtVerify(token, key, options)).payload;
    } catch (error) {
      if (!(error instanceof errors.JWSSignatureVerificationFailed)) throw refusalOf(error);
    }
  }
  throw new WorkloadTokenRefused('signature', "the token's signature does not verify");
}

function refusalOf(error: unknown): WorkloadTokenRefused {
  if (error instanceof errors.JWKSNoMatchingKey) return new WorkloadTokenRefused('unknown_key', "the token's key is not among the issuer's");
  if (error instanceof errors.JWTExpired) {
    return error.claim === 'iat'
      ? new WorkloadTokenRefused('too_old', `the token was issued more than ${MAX_TOKEN_AGE_SECONDS / 60} minutes ago`)
      : new WorkloadTokenRefused('expired', 'the token has expired');
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'nbf') return new WorkloadTokenRefused('not_yet_valid', 'the token is not valid yet');
    if (error.claim === 'iat') return new WorkloadTokenRefused('too_old', 'the token says it was issued in the future');
    if (error.claim === 'iss') return new WorkloadTokenRefused('signature', 'the token is not from the binding\'s issuer');
    return new WorkloadTokenRefused('malformed', `the token's ${error.claim} is not as required`);
  }
  if (error instanceof errors.JOSEAlgNotAllowed || error instanceof errors.JOSENotSupported) {
    return new WorkloadTokenRefused('signature', 'the token is signed with an algorithm coffre does not accept');
  }
  if (error instanceof errors.JWSSignatureVerificationFailed || error instanceof errors.JWSInvalid || error instanceof errors.JWTInvalid) {
    return new WorkloadTokenRefused('signature', "the token's signature does not verify");
  }
  if (error instanceof errors.JOSEError) return new WorkloadTokenRefused('signature', `the token does not verify: ${error.code}`);
  return new WorkloadTokenRefused('signature', 'the token does not verify');
}

/** At most this many keys in a set, fetched or uploaded. */
export const MAX_KEYS = 32;

/** One key of an uploaded set, as an owner sees it: its `kid`, its algorithm, and its RFC 7638 thumbprint. */
export type KeySummary = { kid: string | null; alg: (typeof WORKLOAD_ALGORITHMS)[number]; thumbprint: string };

/**
 * A key set uploaded with a binding, as the binding keeps it: its public
 * keys alone, as canonical JSON, and that JSON's SHA-256, in hex, which
 * stands in the binding where a URL would and so is under its MAC.
 */
export type UploadedKeys = { jwks: string; digest: string; keys: KeySummary[] };

/** A key set that cannot be uploaded, said so an owner can fix it. */
export class KeysInvalid extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeysInvalid';
  }
}

/** Members that only a private or a symmetric key has. */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/**
 * An issuer's public keys, as uploaded for a binding: a JWKS, `{ "keys": [
 * … ] }`, of RSA keys of 2048 bits or more, for RS256, and P-256 keys, for
 * ES256, each kept with only the members that verify (`kty`, `kid`, `use`,
 * `alg` and the key), in the order of their thumbprints, so that one set
 * however listed has one digest. An RSA key's parameters are checked
 * before jose sees them, since it takes some that verify anything: an
 * exponent of 1 makes every signature its message. Keys for encryption are
 * left out, as from a fetched set; a private or a symmetric key refuses the
 * whole set, since coffre keeps no secret of an issuer's. Throws
 * `KeysInvalid`.
 */
export async function uploadedKeys(value: unknown): Promise<UploadedKeys> {
  const listed = (value as { keys?: unknown } | null)?.keys;
  if (typeof value !== 'object' || value === null || !Array.isArray(listed)) throw new KeysInvalid('the keys are a JWKS: { "keys": [ … ] }');
  if (listed.length > MAX_KEYS) throw new KeysInvalid(`a key set holds at most ${MAX_KEYS} keys`);
  const keys: JWK[] = [];
  for (const [i, given] of listed.entries()) {
    if (typeof given !== 'object' || given === null || Array.isArray(given)) throw new KeysInvalid(`key ${i + 1} is not a JWK`);
    const jwk = given as Record<string, unknown>;
    const named = typeof jwk.kid === 'string' ? `key ${jwk.kid}` : `key ${i + 1}`;
    if (PRIVATE_MEMBERS.some((member) => member in jwk)) {
      throw new KeysInvalid(`${named} is a private or a secret key: upload the issuer's public keys only`);
    }
    if (jwk.use === 'enc') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') throw new KeysInvalid(`${named} has use ${JSON.stringify(jwk.use)}: sig, or none`);
    if (jwk.kid !== undefined && (typeof jwk.kid !== 'string' || jwk.kid === '' || jwk.kid.length > 256)) throw new KeysInvalid(`key ${i + 1}'s kid is not a string`);
    if (jwk.kid !== undefined && keys.some((key) => key.kid === jwk.kid)) throw new KeysInvalid(`two keys are ${named}`);
    let alg: KeySummary['alg'];
    let key: JWK;
    if (jwk.kty === 'RSA' && (jwk.alg === undefined || jwk.alg === 'RS256')) {
      alg = 'RS256';
      const [n, e] = [integer(jwk.n), integer(jwk.e)];
      if (n === null || e === null) throw new KeysInvalid(`${named} is an RSA key without n and e, each a base64url integer in its fewest bytes`);
      // The modulus's bits counted from its highest set bit, as jose counts them when it verifies.
      if (n.toString(2).length < 2048) throw new KeysInvalid(`${named} is an RSA key under 2048 bits`);
      if (n % 2n === 0n) throw new KeysInvalid(`${named} is not a valid RSA key`);
      // As NIST SP 800-56B has it: odd, above 2^16, below 2^256.
      if (e % 2n === 0n || e <= 65536n || e >= 2n ** 256n) throw new KeysInvalid(`${named}'s exponent is not one an RSA key signs with: odd, from 65537`);
      key = { kty: 'RSA', ...kidAndUse(jwk), alg, n: jwk.n as string, e: jwk.e as string };
    } else if (jwk.kty === 'EC' && jwk.crv === 'P-256' && (jwk.alg === undefined || jwk.alg === 'ES256')) {
      alg = 'ES256';
      if (!coordinate(jwk.x) || !coordinate(jwk.y)) throw new KeysInvalid(`${named} is an EC key without x and y, each 32 bytes in base64url`);
      key = { kty: 'EC', ...kidAndUse(jwk), alg, crv: 'P-256', x: jwk.x, y: jwk.y };
    } else {
      throw new KeysInvalid(`${named} is not an RSA key for RS256 or a P-256 key for ES256, the two coffre accepts`);
    }
    try {
      await importJWK(key, alg);
    } catch {
      throw new KeysInvalid(`${named} is not a valid ${key.kty} key`);
    }
    keys.push(key);
  }
  if (keys.length === 0) throw new KeysInvalid('the key set holds no key that signs');
  // By thumbprint, then whole: two kids may name the same key.
  const sorted = keys.map((key) => [`${thumbprint(key)} ${JSON.stringify(key)}`, key] as const).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const jwks = JSON.stringify({ keys: sorted.map(([, key]) => key) });
  return { jwks, digest: createHash('sha256').update(jwks, 'utf8').digest('hex'), keys: keySummaries(jwks) };
}

/** The keys of a set `uploadedKeys` kept, as an owner sees them. */
export function keySummaries(jwks: string): KeySummary[] {
  return (JSON.parse(jwks) as JSONWebKeySet).keys.map((key) => ({
    kid: key.kid ?? null,
    alg: key.kty === 'RSA' ? 'RS256' : 'ES256',
    thumbprint: thumbprint(key),
  }));
}

/** A key's RFC 7638 thumbprint: the SHA-256 of its required members alone, in lexicographic order. */
function thumbprint(key: JWK): string {
  const required = key.kty === 'RSA' ? { e: key.e, kty: key.kty, n: key.n } : { crv: key.crv, kty: key.kty, x: key.x, y: key.y };
  return createHash('sha256').update(JSON.stringify(required), 'utf8').digest('base64url');
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** A P-256 coordinate as JWK writes one: 32 bytes, in base64url exactly, so that one key has one spelling. */
function coordinate(value: unknown): value is string {
  if (typeof value !== 'string' || !BASE64URL.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === value;
}

/** An unsigned integer as JWK writes one, base64url in its fewest bytes; null for anything else. */
function integer(value: unknown): bigint | null {
  if (typeof value !== 'string' || !BASE64URL.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes[0] === 0 || bytes.toString('base64url') !== value) return null;
  return BigInt(`0x${bytes.toString('hex')}`);
}

function kidAndUse(jwk: Record<string, unknown>): Pick<JWK, 'kid' | 'use'> {
  return { ...(jwk.kid === undefined ? {} : { kid: jwk.kid as string }), ...(jwk.use === undefined ? {} : { use: 'sig' }) };
}

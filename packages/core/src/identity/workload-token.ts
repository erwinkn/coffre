import { createHash } from 'node:crypto';

import { createLocalJWKSet, errors, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';

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
 * Returns the verified claims.
 */
export async function verifyWorkloadToken(
  token: string,
  keys: JSONWebKeySet,
  expected: { issuer: string; audience: string; now: Date },
): Promise<JWTPayload & DecodedToken['claims']> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, createLocalJWKSet(keys), {
      algorithms: [...WORKLOAD_ALGORITHMS],
      issuer: expected.issuer,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      maxTokenAge: MAX_TOKEN_AGE_SECONDS,
      requiredClaims: ['iss', 'sub', 'exp', 'iat'],
      currentDate: expected.now,
    }));
  } catch (error) {
    throw refusalOf(error);
  }
  const { aud } = payload;
  if (!(aud === expected.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === expected.audience))) {
    throw new WorkloadTokenRefused('audience', `the token is for ${JSON.stringify(aud ?? null)}, not ${expected.audience} alone`);
  }
  return payload as JWTPayload & DecodedToken['claims'];
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

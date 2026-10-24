/**
 * Checking a workload's proof (docs/design/workload-access.md, section
 * 5.1): the verifying half of `@coffre/client/dpop`, whose canonicalization
 * it runs, so both sides agree on every byte. Cheapest first:
 *
 *   1. shape     at most 2 KiB, `typ` exactly `dpop+jwt`, `alg` exactly `ES256`
 *   2. the key   `jwk` exactly `kty`, `crv`, `x` and `y`, a point on P-256
 *   3. claims    `jti` 16 bytes, `iat` an integer, `hdr` at most 32 names, none unsigned
 *                                                          (`parseProof`, no I/O)
 *   4. the session row, from the token's hash: the server's, between the two
 *   5. key and signature   the thumbprint is the row's `jkt`, then ES256
 *   6. what was signed     `htm`, `htu`, `ath`, `req`, then `iat` within ±300 s
 *                                                          (`verifyProof`)
 *   7. the gate's nonce and `jti`: the server's again (`Gate`)
 *
 * Each claim the caller expects (`ath` with a token, `hdr` and `req` with a
 * request's content) must be there, and one it does not expect must not.
 * Two signatures of one payload, `(r, s)` and `(r, n − s)`, both verify:
 * they carry one `jti`, which the gate takes once.
 */
import {
  canonicalHtu,
  fetchMethod,
  fromBase64url,
  MAX_PROOF_LENGTH,
  requestDigest,
  sentTarget,
  thumbprint,
  tokenDigest,
  UNSIGNED_HEADERS,
  type ProofClaims,
  type PublicJwk,
} from '@coffre/client/dpop';

export { canonicalHtu, canonicalRequest, fetchMethod, MAX_PROOF_LENGTH, sentTarget, thumbprint, type ProofClaims, type PublicJwk } from '@coffre/client/dpop';

/** The most headers one proof signs. */
export const MAX_SIGNED_HEADERS = 32;
/** How far a proof's `iat` may be from now: the nonce, not the clock, is what makes a proof fresh. */
export const PROOF_SKEW_SECONDS = 300;

/** Why a proof was refused, which a 401's `reason` names under `error="invalid_dpop_proof"`. */
export type ProofReason = 'malformed' | 'key' | 'jkt' | 'signature' | 'htm' | 'htu' | 'ath' | 'req' | 'iat';

export type ProofRefusal = { ok: false; reason: ProofReason; message: string };

/** A proof whose shape, key and claims hold: what `verifyProof` checks against the request. */
export type ParsedProof = {
  ok: true;
  jwk: PublicJwk;
  claims: ProofClaims;
  /** The headers it signs, in `hdr`'s order; null for a proof that signs no content. */
  hdr: readonly string[] | null;
  signingInput: string;
  signature: Uint8Array;
};

/** A proof that holds for its request: its key's thumbprint, and what the gate checks. */
export type VerifiedProof = { ok: true; jkt: string; jti: string; nonce: string | null; iat: number; hdr: readonly string[] | null };

/** What the request says a proof must sign. */
export type ProofExpectation = {
  /** The request's method and URL, as received: `Request.method`, which the Fetch API has normalized as `fetchMethod` does. */
  method: string;
  url: string | URL;
  /** The session row's `jkt`; none at the exchange, where the proof's key becomes the session's. */
  jkt?: string;
  /** The session token the request carries, which `ath` signs; none at the exchange. */
  token?: string;
  /** The request's headers and its body's digest, which `hdr` and `req` sign: for a request coffre forwards. */
  content?: { headers: Headers; body: string };
  /** Seconds `iat` may be from now: 300 unless said, 60 at the exchange. */
  skewSeconds?: number;
  /** Now, in milliseconds, for tests. */
  now?: number;
};

const refuse = (reason: ProofReason, message: string): ProofRefusal => ({ ok: false, reason, message });

const DECODER = new TextDecoder('utf-8', { fatal: true });
const ENCODER = new TextEncoder();
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;
/** A method, a token of RFC 9110: in any case, compared exactly. */
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,16}$/;
const CLAIMS = new Set(['jti', 'htm', 'htu', 'iat', 'ath', 'nonce', 'hdr', 'req']);

/** A part of the proof as a JSON object, or null for anything else. */
function jsonPart(part: string): Record<string, unknown> | null {
  const bytes = fromBase64url(part);
  if (bytes === null) return null;
  try {
    const value: unknown = JSON.parse(DECODER.decode(bytes));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function exactly(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

const isDigest = (value: unknown): value is string => typeof value === 'string' && fromBase64url(value)?.length === 32;

/** Steps 1 to 3: the proof's shape, its key's and its claims', with no I/O. */
export function parseProof(proof: string): ParsedProof | ProofRefusal {
  if (proof.length > MAX_PROOF_LENGTH) return refuse('malformed', `a proof is at most ${MAX_PROOF_LENGTH} characters`);
  const parts = proof.split('.');
  if (parts.length !== 3) return refuse('malformed', 'a proof is a compact JWS: three parts');
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = jsonPart(headerPart);
  if (header === null || !exactly(header, ['typ', 'alg', 'jwk']) || header.typ !== 'dpop+jwt' || header.alg !== 'ES256') {
    return refuse('malformed', 'a proof\'s header is exactly { typ: "dpop+jwt", alg: "ES256", jwk }');
  }
  const jwk = header.jwk as Record<string, unknown>;
  if (
    typeof jwk !== 'object' || jwk === null || Array.isArray(jwk) || !exactly(jwk, ['kty', 'crv', 'x', 'y'])
    || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !isCoordinate(jwk.x) || !isCoordinate(jwk.y)
  ) {
    return refuse('key', "a proof's key is a P-256 public key: exactly kty, crv, x and y");
  }
  const signature = fromBase64url(signaturePart);
  if (signature === null || signature.length !== 64) return refuse('malformed', 'an ES256 signature is 64 bytes, r then s');
  const claims = jsonPart(payloadPart);
  if (claims === null || Object.keys(claims).some((name) => !CLAIMS.has(name))) return refuse('malformed', "a proof's claims are jti, htm, htu, iat, and ath, nonce, hdr, req where they apply");
  if (typeof claims.jti !== 'string' || fromBase64url(claims.jti)?.length !== 16) return refuse('malformed', 'jti is 16 random bytes, in base64url');
  if (typeof claims.htm !== 'string' || !METHOD.test(claims.htm)) return refuse('malformed', 'htm is the request\'s method');
  if (typeof claims.htu !== 'string') return refuse('malformed', 'htu is the request\'s URL');
  if (!Number.isSafeInteger(claims.iat)) return refuse('malformed', 'iat is an integer, in seconds');
  if (claims.ath !== undefined && !isDigest(claims.ath)) return refuse('malformed', 'ath is a SHA-256, in base64url');
  if (claims.nonce !== undefined && (typeof claims.nonce !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(claims.nonce))) {
    return refuse('malformed', 'nonce is the one coffre gave');
  }
  if ((claims.hdr === undefined) !== (claims.req === undefined)) return refuse('malformed', 'hdr and req come together');
  let hdr: string[] | null = null;
  if (claims.hdr !== undefined) {
    if (typeof claims.hdr !== 'string' || !isDigest(claims.req)) return refuse('malformed', 'hdr names headers, and req is a SHA-256');
    hdr = claims.hdr === '' ? [] : claims.hdr.split(' ');
    if (hdr.length > MAX_SIGNED_HEADERS) return refuse('malformed', `a proof signs at most ${MAX_SIGNED_HEADERS} headers`);
    if (hdr.some((name) => !HEADER_NAME.test(name) || UNSIGNED_HEADERS.has(name)) || new Set(hdr).size !== hdr.length) {
      return refuse('malformed', 'hdr names each header once, in lower case, and none the transport or the request to coffre owns');
    }
  }
  return { ok: true, jwk: jwk as PublicJwk, claims: claims as ProofClaims, hdr, signingInput: `${headerPart}.${payloadPart}`, signature };
}

function isCoordinate(value: unknown): value is string {
  return typeof value === 'string' && fromBase64url(value)?.length === 32;
}

/**
 * Steps 5 and 6: the proof against its request, `parseProof`'s first when
 * given a string. Nothing here reads a store, so the gate (step 7) still
 * decides whether this `jti` was seen.
 */
export async function verifyProof(proof: string | ParsedProof, expect: ProofExpectation): Promise<VerifiedProof | ProofRefusal> {
  const parsed = typeof proof === 'string' ? parseProof(proof) : proof;
  if (!parsed.ok) return parsed;
  const { jwk, claims, hdr } = parsed;
  const jkt = await thumbprint(jwk);
  if (expect.jkt !== undefined && jkt !== expect.jkt) return refuse('jkt', 'the proof is signed by another key than the session\'s');
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch {
    return refuse('key', "the proof's key is no point on P-256");
  }
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, parsed.signature as Uint8Array<ArrayBuffer>, ENCODER.encode(parsed.signingInput));
  if (!valid) return refuse('signature', 'the proof\'s signature does not verify');

  if (claims.htm !== fetchMethod(expect.method)) return refuse('htm', 'the proof signs another method');
  let htu: string;
  try {
    htu = canonicalHtu(expect.url);
  } catch {
    return refuse('htu', 'the request\'s URL cannot be signed');
  }
  if (claims.htu !== htu) return refuse('htu', 'the proof signs another URL');
  if ((expect.token === undefined) !== (claims.ath === undefined)) {
    return refuse('ath', expect.token === undefined ? 'this proof signs no token' : 'the proof signs no token: ath');
  }
  if (expect.token !== undefined && claims.ath !== (await tokenDigest(expect.token))) return refuse('ath', 'the proof signs another token');
  if ((expect.content === undefined) !== (hdr === null)) {
    return refuse('req', expect.content === undefined ? 'this proof signs no request content' : 'the proof signs no request content: hdr and req');
  }
  if (expect.content !== undefined) {
    const headers: [string, string][] = [];
    for (const name of hdr!) {
      const value = expect.content.headers.get(name);
      if (value === null) return refuse('req', `the proof signs a header the request lacks: ${name}`);
      headers.push([name, value]);
    }
    let digest: string;
    try {
      digest = await requestDigest({ ...sentTarget(expect.url), headers, body: expect.content.body });
    } catch {
      return refuse('req', 'the request cannot be signed: a line break in its path, query or headers');
    }
    if (claims.req !== digest) return refuse('req', 'the proof signs another path as sent, query, header or body');
  }
  const skew = expect.skewSeconds ?? PROOF_SKEW_SECONDS;
  const now = Math.floor((expect.now ?? Date.now()) / 1000);
  if (Math.abs(now - claims.iat) > skew) return refuse('iat', `the proof was made more than ${skew} seconds from now`);
  return { ok: true, jkt, jti: claims.jti, nonce: claims.nonce ?? null, iat: claims.iat, hdr };
}

/** A count a request asks the gate for: the requests under `key` in the last `windowMs`, at most `most`. */
export type GateCount = { key: string; windowMs: number; most: number };

/** What the gate answers a request: its nonce on success, or why not. */
export type GateAdmission =
  | { ok: true; nonce: string }
  | { ok: false; reason: 'use_dpop_nonce'; nonce: string }
  | { ok: false; reason: 'replayed' | 'overloaded' }
  /** `first`: the first refusal of this key in its window, which alerts. */
  | { ok: false; reason: 'limit'; key: string; retryAfterMs: number; first: boolean };

/**
 * One workload's gate (section 5.2): a Durable Object on Workers, an object
 * in the process on Node. Its nonces are epochs: a gate accepts the current
 * and the previous one, remembers each epoch's `jti`s, and draws a new epoch
 * when it starts, so a restart forgets nothing that matters. It decides no
 * one's access: freezes, revocations and grants are the database's.
 */
export interface Gate {
  /** Its current nonce, `g<n>.<epoch>`, for an answer that admits no proof: the exchange's `DPoP-Nonce`. */
  nonce(): Promise<string>;
  /**
   * Replay and nonce, for a request that carries a proof (a Cloudflare call
   * carries none, and has counts only); then, in the same call, every count
   * the request asks for. A nonce of an epoch gone gets `use_dpop_nonce`; a
   * proof with none never reaches the gate, and gets `nonce()`'s.
   */
  admit(request: { replay?: { session: string; jti: string; nonce: string }; counts?: readonly GateCount[] }): Promise<GateAdmission>;
}

/**
 * The signing half of a workload's proofs (docs/design/workload-access.md,
 * section 5.1): DPoP (RFC 9449) with two claims of coffre's own, `hdr` and
 * `req`, which sign the request's headers, query and body as well as its
 * method and URL. The SDK and the server run this one canonicalization, so
 * what a workload signs is exactly what coffre recomputes and forwards;
 * the server's verifier is `verifyProof` in `@coffre/core/identity`.
 *
 * WebCrypto only, and no dependency, like the rest of the client.
 *
 * A proof is a compact JWS:
 *
 *   { "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
 *   { "jti": "pA6p8w2Yb3fQe1kHn0S9qg", "htm": "POST", "htu": "https://secrets.acme.example/use/stripe/v1/charges",
 *     "iat": 1792805400, "ath": "fUHy…", "nonce": "g1.7Hq2…",
 *     "hdr": "content-type idempotency-key", "req": "kq9V…" }
 */

/** The longest proof, in characters, which the verifier refuses past and the signer never makes. */
export const MAX_PROOF_LENGTH = 2048;
/** The most headers one proof signs: the verifier refuses more, and the signer signs no more. */
export const MAX_SIGNED_HEADERS = 32;

/** A P-256 public key, as a proof carries it: these four members and nothing else. */
export type PublicJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };

/** A workload's key: the private half non-extractable, and the public half as a proof names it. */
export type ProofKey = { privateKey: CryptoKey; jwk: PublicJwk };

/** What a proof's payload holds. `ath` signs the token, `hdr` and `req` the rest of the request. */
export type ProofClaims = {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  nonce?: string;
  hdr?: string;
  req?: string;
};

/**
 * Headers a proof never signs, so neither forwards: those the transport
 * owns and an intermediary may rewrite, the credentials of the request to
 * coffre itself, and cookies. Coffre sets the transport's own on the way out.
 */
export const UNSIGNED_HEADERS: ReadonlySet<string> = new Set([
  'accept-encoding',
  'authorization',
  'connection',
  'content-length',
  'cookie',
  'dpop',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const ENCODER = new TextEncoder();

/** Bytes as base64url, without padding. */
export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64url without padding, back to bytes; null for anything else, or for a
 * spelling that is not the one `base64url` writes (stray bits in its last
 * character), so that one value has one spelling.
 */
export function fromBase64url(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return base64url(bytes) === text ? bytes : null;
}

async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? ENCODER.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** The key's RFC 7638 thumbprint, `jkt`: base64url SHA-256 of its required members in this order, 43 characters. */
export async function thumbprint(jwk: PublicJwk): Promise<string> {
  return base64url(await sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })));
}

/** A new key for a process: P-256, its private half never exportable, never written anywhere. */
export async function generateProofKey(): Promise<ProofKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { privateKey: pair.privateKey, jwk: { kty: kty as 'EC', crv: crv as 'P-256', x: x!, y: y! } };
}

/** A method, as RFC 9110 writes one: a token, of any length the proof's own limit leaves. */
export const METHOD_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** RFC 3986's unreserved characters, which an escape never needs. */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/**
 * A URL as `htu` names it: scheme and host lowercased, no default port, no
 * user, query or fragment, and its path as Cloudflare's zones normalize an
 * incoming one by default, in their order: an escaped unreserved character
 * decoded and every other escape's hex in upper case (RFC 3986, section
 * 6.2.2), `\` made `/`, runs of `/` merged, then dot segments removed.
 * Both sides sign this form, so a zone's normalization changes nothing, and
 * a mismatch fails closed. Idempotent. Throws on a URL that is not http or
 * https, and on a `%` that two hex digits do not follow, which would let
 * two paths read as one.
 *
 *   canonicalHtu('HTTPS://Secrets.Acme.Example:443//use/%7estripe/a%2fb?x=1')
 *     === 'https://secrets.acme.example/use/~stripe/a%2Fb'
 *   canonicalHtu('https://secrets.acme.example/hello//../path')
 *     === 'https://secrets.acme.example/path'
 */
export function canonicalHtu(input: string | URL): string {
  const url = new URL(String(input));
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new TypeError(`a proof signs an http or https URL, not ${url.protocol}`);
  // The path as given, before the WHATWG parser removes its dot segments, which it would do before merging slashes.
  // A `\` ends the authority as `/` does, and any run of either starts it, as the WHATWG parser reads an http(s) URL: the path fetch sends.
  const raw = typeof input === 'string' ? /^[^:/\\?#]+:[/\\]{2,}[^/\\?#]*([^?#]*)/.exec(input)?.[1] ?? url.pathname : url.pathname;
  if (/%(?![0-9A-Fa-f]{2})/.test(raw)) throw new TypeError('a URL a proof signs escapes a character with % and two hex digits, never a lone %');
  const decoded = raw.replace(/%([0-9A-Fa-f]{2})/g, (_, code: string) => {
    const char = String.fromCharCode(parseInt(code, 16));
    return UNRESERVED.test(char) ? char : `%${code.toUpperCase()}`;
  });
  const merged = decoded.replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  // Then as the parser writes a path: characters a path never holds raw escaped, as fetch sends them.
  return `${url.protocol}//${url.host}${new URL(withoutDotSegments(merged.startsWith('/') ? merged : `/${merged}`), url.origin).pathname}`;
}

/** RFC 3986's `remove_dot_segments` (section 5.2.4), on an absolute path. */
function withoutDotSegments(path: string): string {
  const kept: string[] = [];
  const parts = path.split('/').slice(1);
  parts.forEach((part, i) => {
    if (part !== '.' && part !== '..') kept.push(part);
    else {
      if (part === '..') kept.pop();
      // `/a/b/..` is `/a/`: a dot segment last leaves its slash.
      if (i === parts.length - 1) kept.push('');
    }
  });
  return `/${kept.join('/')}`;
}

/**
 * A method as `htm` names it, and the Fetch API sends it: one of DELETE,
 * GET, HEAD, OPTIONS, POST and PUT in upper case, whatever case it was
 * given in, and any other exactly as given. Methods are case-sensitive
 * (RFC 9110, section 9.1), so `patch` is not `PATCH`, and a proof signs one.
 */
export function fetchMethod(method: string): string {
  if (!METHOD_TOKEN.test(method)) throw new TypeError(`${JSON.stringify(method)} is no HTTP method: a method is a token (RFC 9110, section 9.1)`);
  const upper = method.toUpperCase();
  return ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'].includes(upper) ? upper : method;
}

/** The SHA-256 of a buffered body, in hex, as a canonical request's last line holds it. */
export async function bodyDigest(body: Uint8Array | string): Promise<string> {
  return hex(await sha256(body));
}

/** `ath`: base64url SHA-256 of the session token the proof is sent with. */
export async function tokenDigest(token: string): Promise<string> {
  return base64url(await sha256(token));
}

/**
 * A canonical request's last line for a body no digest binds: a streamed
 * upload whose SigV4 `x-amz-content-sha256` is `UNSIGNED-PAYLOAD` or
 * `STREAMING-…`. Coffre takes it only through a credential that says
 * `unsignedUploads`, whose page notes what that leaves open.
 */
export const UNSIGNED_BODY = 'UNSIGNED-PAYLOAD';

const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * What `req` signs, one line each:
 *
 *   <the path as sent, as the WHATWG parser writes it: every slash and escape kept>
 *   <the raw query string as sent, without "?", or empty>
 *   <name>:<value>    for each header `hdr` names, in its order, its value as received
 *   <the body's SHA-256, in lower-case hex>
 *
 * `htu` signs the path as a zone normalizes it, so a proof still holds
 * behind one; this line signs it as it goes upstream, so `/use/s3/a/b` and
 * `/use/s3/a//b`, one object and another to S3, are two requests. A path a
 * zone changed fails closed. The body's line is its buffered bytes' digest
 * (`bodyDigest`), or, for a streamed upload through a credential `sigv4`
 * signs, the 64 hex digits its `x-amz-content-sha256` declares, which S3
 * checks against the bytes; any other declared value is `UNSIGNED_BODY`. A
 * header sent several times is one value, joined by `, `, as `Headers`
 * gives it. No line holds a line break, so no two requests read as one;
 * throws on one that does, or on a body line that is neither.
 */
export function canonicalRequest(request: { path: string; query: string; headers: readonly (readonly [string, string])[]; body: string }): string {
  const lines = [request.path, request.query, ...request.headers.map(([name, value]) => `${name}:${value}`)];
  if (lines.some((line) => /[\r\n]/.test(line))) throw new TypeError('a signed request holds no line break in its path, query or headers');
  if (!SHA256_HEX.test(request.body) && request.body !== UNSIGNED_BODY) throw new TypeError('a signed request\'s body is a SHA-256 in hex, or UNSIGNED_BODY');
  return `${lines.map((line) => `${line}\n`).join('')}${request.body}`;
}

/** The path and the query a URL sends, as `canonicalRequest` signs them. */
export function sentTarget(url: string | URL): { path: string; query: string } {
  const parsed = new URL(String(url));
  return { path: parsed.pathname, query: parsed.search.slice(1) };
}

/** `req`: base64url SHA-256 of the canonical request. */
export async function requestDigest(request: Parameters<typeof canonicalRequest>[0]): Promise<string> {
  return base64url(await sha256(canonicalRequest(request)));
}

/** The headers a proof signs from what the app set: every one but `UNSIGNED_HEADERS`, lowercased, in `Headers`' order. */
export function signedHeaders(headers: HeadersInit): [string, string][] {
  return [...new Headers(headers)].filter(([name]) => !UNSIGNED_HEADERS.has(name));
}

/**
 * A proof for one request, signed by `key`.
 *
 * - `token` adds `ath`, for a request made with a session; the exchange has none.
 * - `nonce` is the gate's newest, from the last answer's `DPoP-Nonce`.
 * - `content` adds `hdr` and `req`: the headers the app set, and the body's
 *   line (`bodyDigest`, a streamed SigV4 upload's declared digest, or
 *   `UNSIGNED_BODY`).
 *   Whatever it names is all coffre forwards.
 */
export async function createProof(
  key: ProofKey,
  request: {
    method: string;
    url: string | URL;
    token?: string;
    nonce?: string;
    content?: { headers: HeadersInit; body: string };
    /** For tests: the proof's time, in seconds, and its ID. */
    iat?: number;
    jti?: string;
  },
): Promise<string> {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: key.jwk.kty, crv: key.jwk.crv, x: key.jwk.x, y: key.jwk.y } };
  const claims: ProofClaims = {
    jti: request.jti ?? base64url(crypto.getRandomValues(new Uint8Array(16))),
    htm: fetchMethod(request.method),
    htu: canonicalHtu(request.url),
    iat: request.iat ?? Math.floor(Date.now() / 1000),
  };
  if (request.token !== undefined) claims.ath = await tokenDigest(request.token);
  if (request.nonce !== undefined) claims.nonce = request.nonce;
  if (request.content !== undefined) {
    const headers = signedHeaders(request.content.headers);
    if (headers.length > MAX_SIGNED_HEADERS) throw new TypeError(`a proof signs at most ${MAX_SIGNED_HEADERS} headers: this request sets ${headers.length}`);
    claims.hdr = headers.map(([name]) => name).join(' ');
    claims.req = await requestDigest({ ...sentTarget(request.url), headers, body: request.content.body });
  }
  const input = `${base64url(ENCODER.encode(JSON.stringify(header)))}.${base64url(ENCODER.encode(JSON.stringify(claims)))}`;
  // 86 characters of signature and its dot: a proof the verifier would refuse for its size is never made.
  if (input.length + 87 > MAX_PROOF_LENGTH) throw new TypeError(`a proof is at most ${MAX_PROOF_LENGTH} characters: this request's URL or headers are too long to sign`);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, ENCODER.encode(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

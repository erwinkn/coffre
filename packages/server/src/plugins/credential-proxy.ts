/**
 * The credential proxy (docs/design/credential-proxy.md): a person's app,
 * an agent's included, uses secrets without ever holding them. `coffre run`
 * gives it a placeholder for each, a handle (`coffre_use_…`) that reaches
 * nothing but this proxy, and the app's own config points its client here;
 * the proxy swaps in the real value at the edge, for the credential's own
 * upstream only. In the deployment's configuration:
 *
 *   import { credentialProxy, header, hmac, privateKey, sigv4 } from '@coffre/server/plugins/credential-proxy';
 *   plugins: [credentialProxy({
 *     credentials: {
 *       schumann: { upstream: 'https://api.schumann.example/v1', inject: header('x-api-key', '{SCHUMANN_API_KEY}') },
 *       s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
 *     },
 *     signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY') },
 *     verifiers: { yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) },
 *   })],
 *
 * and its app's route, `routes/use.$.ts`, `createFileRoute('/use/$')({ ...plugin })`.
 * Then, for a person's `coffre run market/dev`:
 *
 *   GET /use/market/dev                     what the app's environment holds: placeholders, and the values its person reads
 *   ANY /use/schumann/<path>                the request, sent to https://api.schumann.example/v1/<path> with market/dev's key
 *   ANY /use/market/dev/schumann/<path>     the same, naming the environment
 *   POST /use/market/dev                    a presigned URL, a signature by a signer's key, or whether a webhook's signature is a verifier's, made with the values and never them
 *
 * The first is the stable URL, the same for every environment, which the
 * app's own config names: its environment is the one the handle was made
 * for. `/use/<a>/<b>/…` names an environment when `<a>/<b>` is one the
 * handle was made for, and is the stable URL of credential `<a>` otherwise.
 *
 * Each credential names the keys its rule reads, from the environment the
 * request names, and one upstream: the request goes there or nowhere, over
 * HTTPS, through the global `fetch` or the credential's `egress` (a VPC
 * Service binding, for an upstream that allowlists the addresses it lets
 * in), its redirects never followed, and a value the upstream echoes is
 * redacted from its answer, unless it is plain. A handle opens values for
 * its person as a read does, by their grants and its scope, never handed
 * back. The app holds as they are the values its person may read, plain
 * and secret ones, never a sensitive one (docs/design/credential-proxy.md,
 * section 2).
 *
 * On 0.16 (docs/design/0.16.md, "The proxy"), each request is one `use` of
 * the vault, which decides on its own rows and logs it once a minute per
 * key and credential; the proxy keeps no value. `/use/<credential>` reads
 * the handle's or session's row first, unchecked, for the place it was made
 * for. The plan of an environment is a peek and one use, which opens only
 * what the app is handed. Presigning, signing, verifying, a cipher's work
 * and tunnels answer 501 until each is moved onto `use`, and so does the
 * plan of an environment the deployment generates values for.
 */
import { createHash } from 'node:crypto';

import { CoffreError } from '@coffre/client';
import { bodyDigest, bodyLine, contentDigest, declaredDigest, MAX_DIGESTED_BODY, UNSIGNED_BODY } from '@coffre/client/dpop';
import { constraintsAllow } from '@coffre/core/identity';

import { UNAVAILABLE_RETRY_AFTER } from '../api/errors.ts';
import { WorkloadRefused, type CoffrePlugin, type Exposed, type PluginContext, type WorkloadAt, type WorkloadUse } from '../plugins.ts';
import type { Encoding } from './hmac.ts';
import { signV4 } from './sigv4.ts';
import type { WorkersSocket } from '../workers-socket.ts';

/** How a credential's values reach its upstream: in a header, a query parameter, a field of a form or JSON body, a segment of the path, Basic authentication, or an AWS signature. */
export type Inject =
  | { kind: 'header'; name: string; template: string }
  | { kind: 'query'; name: string; template: string }
  | { kind: 'form' | 'json'; name: string; template: string }
  | { kind: 'path'; template: string }
  | { kind: 'basic'; user: string; password: string }
  | ({ kind: 'sigv4' } & SigV4);

/** An AWS Signature Version 4 key pair, each a template, and where it signs for. */
export type SigV4 = { accessKeyId: string; secretAccessKey: string; sessionToken?: string; region: string; service: string };

/** A header the upstream reads its key from: `header('authorization', 'Bearer {OPENAI_API_KEY}')`, each `{KEY}` the environment's value. */
export function header(name: string, template: string): Inject {
  return { kind: 'header', name: name.toLowerCase(), template };
}

/** A query parameter the upstream reads its key from: `query('key', '{MAPS_API_KEY}')`. */
export function query(name: string, template: string): Inject {
  return { kind: 'query', name, template };
}

/**
 * A field of a form body (`application/x-www-form-urlencoded`) the upstream
 * reads its key from: `form('refresh_token', '{GATHER_REFRESH_TOKEN}')`. The
 * app sends the body with the handle as that field's value, once; coffre
 * puts the value in its place and leaves every other byte as it was. A
 * body of 64 KiB at most, read whole.
 */
export function form(name: string, template: string): Inject {
  return { kind: 'form', name, template };
}

/**
 * A field at the top of a JSON body's object the upstream reads its key
 * from, as a string: `json('secret', '{TURNSTILE_SECRET_KEY}')`. As `form`,
 * the handle is that field's value, once, and every other byte stays as it
 * was.
 */
export function json(name: string, template: string): Inject {
  return { kind: 'json', name, template };
}

/**
 * A segment of the path the upstream reads its key from, as Telegram's Bot
 * API does: `path('bot{TELEGRAM_BOT_TOKEN}')`. The app's SDK puts what it
 * holds for the key there (`/botcoffre_use_…/sendMessage`); coffre puts the
 * value in its place, percent-encoded, in the first segment under the
 * upstream that the template frames, after `methods` and `paths` have read
 * the path as the app sent it. A value a server might read as another path
 * (`/`, `..`, `?`, `%`, …) goes nowhere.
 */
export function path(template: string): Inject {
  return { kind: 'path', template };
}

/** HTTP Basic authentication: `basic('{TWILIO_SID}', '{TWILIO_TOKEN}')`. */
export function basic(user: string, password: string): Inject {
  return { kind: 'basic', user, password };
}

/**
 * The request signed again with an AWS key pair, for S3 and the like:
 * `sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey:
 * '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' })`. The
 * app's SDK signs with the handle as its access key, and the proxy discards
 * that signature. Its payload hash stands: a literal SHA-256, which the
 * upstream checks against the body, or `UNSIGNED-PAYLOAD`. An aws-chunked
 * upload (`STREAMING-…`) and a presigned URL are refused: each signs with
 * the real key in a way the proxy cannot sign again.
 */
export function sigv4(keys: SigV4): Inject {
  return { kind: 'sigv4', ...keys };
}

/**
 * What the app holds in place of a credential's key, when its client checks
 * the key's shape before it sends it: a JWT whose claims it reads, or a
 * prefix it expects. Unless set, the handle as it is.
 */
export type Placeholder = { kind: 'jwt'; claims: readonly string[] } | { kind: 'prefix'; prefix: string };

/**
 * A placeholder shaped as a JWT, for a client that reads the token's claims
 * before it sends it, as DFNS's SDK reads its organization from
 * `https://custom/app_metadata`: `jwt({ claims: ['https://custom/app_metadata'] })`.
 * The app holds `header.payload.<handle>`, an unsigned header, and a payload
 * of the named claims, copied from the real token when the plan is made,
 * with `exp` the handle's end. The proxy takes the handle from the third
 * part and replaces the whole token with the real one.
 */
export function jwt(options: { claims?: readonly string[] } = {}): Placeholder {
  return { kind: 'jwt', claims: options.claims ?? [] };
}

/** A placeholder that starts as the real key does, for a client that checks it: `prefix('sk_test_')` gives `sk_test_coffre_use_…`. */
export function prefix(prefix: string): Placeholder {
  return { kind: 'prefix', prefix };
}

/**
 * What a credential's requests leave through, in place of the global
 * `fetch`: a Workers VPC Service binding (`env.SCHUMAN_EGRESS`), a service
 * binding, or the deployment's own `{ fetch }`. It is given the request as
 * the proxy made it, real key and all, and its answer goes back to the app
 * as the upstream's would, redacted.
 */
export type Egress = { fetch(input: URL, init: RequestInit): Promise<Response> };

/** One credential: its upstream, how its keys reach it, and what of it a caller may ask. */
export type Credential = {
  /** Where its requests go, `https://api.schumann.example/v1`: `/use/<name>/<path>` goes to `<upstream>/<path>`, and nowhere else. */
  upstream: string;
  inject: Inject;
  /**
   * @deprecated Gone in 0.9, and refused: `coffre run` sets no base URL.
   * The app's own config points at the proxy's stable URL for the
   * credential, `<publicUrl>/use/<name>`, the same for every environment.
   */
  baseUrl?: "gone in 0.9: point the app's own config at <publicUrl>/use/<name>, the proxy's stable URL for this credential";
  /** @deprecated Called `placeholder` in 0.10, and refused: rename it. */
  standIn?: 'called placeholder in 0.10: rename it';
  /**
   * @deprecated Gone in 0.10, and refused: mark each key plain instead
   * (`coffre set <env>/TWILIO_SID <sid> --plain`), which says it in the data,
   * for every environment and fork alike.
   */
  identifiers?: 'gone in 0.10: mark each key plain instead, coffre set <env>/<KEY> <value> --plain';
  /** The shape of what the app holds for its key, `jwt(…)` or `prefix(…)`, where a header, query, form, JSON or path rule carries that one key: the handle as it is, unless set. */
  placeholder?: Placeholder;
  /** The methods it may be used with, `['GET', 'POST']`; any, unless set. */
  methods?: readonly string[];
  /** The paths under `upstream` it may be used on, by prefix, `['/companies']`; any, unless set. */
  paths?: readonly string[];
  /**
   * What its requests leave through, for an upstream that lets in only
   * known addresses: `env.SCHUMAN_EGRESS`, a VPC Service binding whose
   * host is `upstream`'s. The global `fetch` unless set; named but missing
   * (a binding the Worker lacks is `undefined`), the configuration fails,
   * and never falls back to it.
   */
  egress?: Egress;
  /**
   * How often a workload may use it (docs/design/workload-access.md, section
   * 8.1): `{ perMinute: 120, perDay: 20_000 }`, counted per workload by its
   * gate, in fixed windows on the clock; or, for a limit per workload, a
   * function of the service, `token:<name>`. Past one, 429 with
   * `Retry-After`, nothing sent, and one `workload.alert` per workload,
   * credential and window. No limit unless set; a person's handle is not
   * counted.
   */
  limit?: Limits;
};

/** How many uses of a credential or signer a workload makes, a minute and a day: each a whole number, at least 1, or no limit there. */
export type Limit = { perMinute?: number; perDay?: number };

/** A limit for every workload, or one per workload, a function of its service, `token:<name>` (undefined: none). */
export type Limits = Limit | ((service: string) => Limit | undefined);

/**
 * What a tunnel dials through, in place of the platform's TCP: a Workers
 * VPC Network binding (`env.REPLICA_NET`), whose `connect('10.0.1.5:5432')`
 * reaches a private network through a Cloudflare Tunnel, plaintext.
 */
export type Network = { connect(address: string): WorkersSocket | Promise<WorkersSocket> };

/** A database the proxy tunnels to: the key that holds its URL, the hosts that URL may name, and what it dials through. */
export type Tunnel = { kind: 'postgres'; key: string; hosts?: readonly string[]; connect?: Network };

/**
 * A Postgres database, reached through `coffre run`'s local listener and
 * coffre's tunnel: `postgres('DATABASE_URL', { hosts: ['db.acme.example'] })`.
 * The environment's `DATABASE_URL` is the real one, `postgres://…`, which
 * coffre logs in with; the app's is the listener's, with the handle as its
 * password. `hosts`, when set, are the only ones the URL may name.
 * Without them, the URL names its host by address, never by name: whoever
 * writes the value picks the name, and a name may resolve to a private
 * address. `insecureUpstreams` lifts this, as it lifts the rest.
 *
 * A database inside a private network, through a VPC Network binding:
 * `postgres('REPLICA_URL', { hosts: ['10.0.1.5'], connect: env.REPLICA_NET })`.
 * Then `hosts` is required, may name private addresses, and the URL says
 * `sslmode=disable`: the binding carries plaintext TCP only, and the last
 * leg, from the tunnel's connector to the database, stays inside that
 * network. Named but missing (a binding the Worker lacks is `undefined`),
 * the configuration fails, and never dials without it.
 */
export function postgres(key: string, options: { hosts?: readonly string[]; connect?: Network } = {}): Tunnel {
  return { kind: 'postgres', key, ...options };
}

/** A key coffre signs with for the app, which never holds it: a private key, `privateKey(…)`, or an HMAC secret, `hmac(…)`. */
export type Signer = { kind: 'private-key'; key: string; limit?: Limits } | Hmac;

/**
 * A private key the app signs with through coffre, `credential(name).sign(message)`:
 * `privateKey('DFNS_PRIVATE_KEY')`. The environment's value is a PKCS#8
 * PEM, Ed25519, P-256 or RSA; the app holds the handle where it was, and
 * each signature is one use in the log. `limit`, as a credential's, counts
 * a workload's signatures: `privateKey('DFNS_PRIVATE_KEY', { limit: { perMinute: 10 } })`.
 */
export function privateKey(key: string, options: { limit?: Limits } = {}): Signer {
  return { kind: 'private-key', key, ...options };
}

export type { Encoding };

/** An HMAC-SHA256 secret coffre signs or checks signatures with for the app: the key that holds it, how its signatures are written, and how often a workload may use it. */
export type Hmac = { kind: 'hmac'; key: string; encoding: Encoding; prefix?: string; keyEncoding?: Encoding; maxBytes?: number; limit?: Limits };

/**
 * An HMAC-SHA256 secret the app never holds: an inbound webhook's, among
 * `verifiers`, which the app asks whether a signature is the secret's
 * (`credential(name).verify(body, signature)`), or a key of the app's own
 * among `signers`, which also signs (`credential(name).sign(message)`).
 * The key is the environment's value, as its UTF-8 bytes, or the bytes it
 * writes in `keyEncoding`, `hex`, `base64` or `base64url`: a value outside
 * its alphabet or padding is a 409, never signed with. The signature
 * is written in `encoding`, one of the same, after
 * `prefix`: `hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' })`
 * checks Yousign's `x-yousign-signature-256`, and
 * `hmac('MONERIUM_WEBHOOK_SECRET', { encoding: 'base64', prefix: 'v1,', keyEncoding: 'base64' })`
 * one of Standard Webhooks' `v1,<base64>` signatures, its value the base64 after `whsec_`. `maxBytes` is the longest
 * message it signs or checks, 64 KiB unless set. A message goes as JSON up
 * to 1 MiB (about 5 ms of CPU, of a Worker's 10 ms on the Free plan); a
 * signer's longer one goes raw, its bytes as the request's body, never
 * held (`signRaw`), up to `MAX_RAW_MESSAGE_BYTES`: SumSub's document
 * upload, `hmac('SUMSUB_SECRET_KEY', { encoding: 'hex', maxBytes: 11 * 1024 * 1024 })`.
 * A verifier checks JSON alone, 1 MiB at most: a webhook's body is small.
 * `limit`, as a credential's.
 */
export function hmac(key: string, options: { encoding: Encoding; prefix?: string; keyEncoding?: Encoding; maxBytes?: number; limit?: Limits }): Hmac {
  return { kind: 'hmac', key, ...options };
}

/** An AES-256-GCM key coffre encrypts and decrypts with for the app: the key that holds it, how its value writes the 32 bytes, and how much it takes. */
export type Cipher = { kind: 'aes-gcm'; key: string; keyEncoding: Encoding; maxBytes?: number; limit?: Limits };

/**
 * An AES-256-GCM key the app never holds, among `ciphers`: `credential(name).encrypt(plaintext, aad?)` and
 * `.decrypt({ iv, ciphertext, tag }, aad?)`. The key is exactly 32 bytes, written in `keyEncoding`, `hex`, `base64` or
 * `base64url`: `aesGcm('BILLING_TOKEN_KEY', { keyEncoding: 'hex' })`. coffre derives nothing: a key made from a
 * passphrase is derived once, outside, and stored as its bytes. `maxBytes` is the longest plaintext with its AAD, 64 KiB
 * unless set, 1 MiB at most; `limit`, as a credential's.
 */
export function aesGcm(key: string, options: { keyEncoding: Encoding; maxBytes?: number; limit?: Limits }): Cipher {
  return { kind: 'aes-gcm', key, ...options };
}

export type CredentialProxyOptions = {
  /** By name, as the proxy's URLs say it: lowercase letters, digits and dashes. */
  credentials: Record<string, Credential>;
  /** Databases, by name as credentials are, which `coffre run` tunnels to: `{ db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) }`. */
  tunnels?: Record<string, Tunnel>;
  /** Private keys and HMAC secrets, by name as credentials are, that coffre signs with for the app: `{ 'dfns-key': privateKey('DFNS_PRIVATE_KEY') }`. */
  signers?: Record<string, Signer>;
  /** HMAC secrets, by name as credentials are, that coffre checks signatures with for the app, and never signs with: an inbound webhook's, `{ yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) }`. */
  verifiers?: Record<string, Hmac>;
  /** AES-256-GCM keys, by name as credentials are, that coffre encrypts and decrypts with for the app: `{ 'billing-tokens': aesGcm('BILLING_TOKEN_KEY', { keyEncoding: 'hex' }) }`. */
  ciphers?: Record<string, Cipher>;
  /**
   * How often an open tunnel checks its handle still stands, ending when it
   * does not: 60 seconds unless set. Checked, and unused until tunnels are
   * served on 0.16.
   */
  recheckSeconds?: number;
  /**
   * @deprecated Gone in 0.10, and refused: each key says who sees it now. A
   * person's app holds as they are the values they may read; mark sensitive
   * those it must use only through the proxy (`coffre mark <env> sensitive`).
   */
  expose?: 'gone in 0.10: a person\'s app holds the values they may read; mark the rest sensitive, coffre mark <env> sensitive';
  /**
   * The environments whose keys each person gets a value of their own for,
   * by exact path, and which keys: `{ 'backend/local': 'all' }`. A person's
   * use of one reads their personal config of it (`backend/local@me`, or
   * the environment while they have none), and a key their app would go
   * without, which its current value's recipe made (`coffre set …
   * --generate`), `coffre run` generates into that personal config, by the
   * same recipe, once: their app's own encryption or webhook key, kept for
   * their next runs. For a local environment, never a real one: a value
   * made this way protects nothing but the person's own data.
   */
  generate?: Record<string, 'all' | readonly string[]>;
  /** Upstreams over plain HTTP, and at private, loopback or link-local addresses: for local fakes in development, never in production. */
  insecureUpstreams?: boolean;
  /**
   * @deprecated Read and ignored through 0.16 (docs/design/0.16.md, "The
   * proxy"): the proxy keeps no value, and each request asks the vault,
   * whose memory (`memorySeconds`) is the only one. What a deployment set it
   * to for outages is the vault's `outageSeconds` now.
   */
  cacheSeconds?: number;
};

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** A key a rule's template names, `{SCHUMANN_API_KEY}`. */
const TEMPLATE_KEY = /\{([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;
/** A handle, wherever the app put it: alone, or inside a header the upstream's own scheme frames. */
const HANDLE = /coffre_use_[A-Za-z0-9_-]{43}/;
/** A request's body that declares no digest is read whole before it is sent on: an API call's, not an upload's. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;
/** A body a form or JSON rule fills a field of is read whole, and parsed: a token refresh's or a siteverify's, never an upload's. */
const MAX_FIELD_BODY = 64 * 1024;
/**
 * And it holds a few fields, a siteverify's four: past this many, or nested
 * this deep, it is refused before it is parsed, so a body made to cost the
 * most, 65,000 empty pairs, costs no more than a real one, unauthenticated.
 */
const MAX_FIELDS = 256;
const MAX_DEPTH = 32;
/** An AWS-signed upload streams through, up to S3's own limit for one request; past it, a multipart upload's parts each pass. */
const MAX_STREAM_BYTES = 5 * 1024 ** 3;
const HANDLE_LENGTH = 'coffre_use_'.length + 43;
/**
 * The longest message `sign` and `verify` take, raw, unless an `hmac()`
 * says `maxBytes`: an inbound webhook's body. Equisafe's largest in 90 days
 * of production was DFNS's, 5,234 bytes, and this is twelve times that
 * (docs/design/credential-proxy.md, section 5). What asks carries the
 * message as base64url, in JSON beside the rest.
 */
const MESSAGE_BYTES = 64 * 1024;
/**
 * The most an `hmac()`'s `maxBytes` may say: the body read before anyone is
 * authenticated (the proxy reads a request to compute up to what the
 * longest message takes) stays a fraction of a request through a
 * credential's, and the CPU within a Worker's Free plan.
 */
const MAX_MESSAGE_BYTES = 1024 * 1024;
/**
 * The longest message an `hmac()` signer's `maxBytes` may take, raw (`signRaw`): what 20 ms of a request's CPU holds of
 * the signing's own work, two passes of SHA-256 over the message (the HMAC's and a workload's `Content-Digest` check),
 * 1.2 ms per MiB, past about 4 ms of every request's: (20 − 4) ÷ 1.2, about 13 MiB, rounded down. SumSub's document
 * upload is 10.1 MiB at most.
 */
const MAX_RAW_MESSAGE_BYTES = 12 * 1024 * 1024;
/** What `binary` decodes bytes widened to UTF-16 units with: before anything below calls it. */
const UTF16 = new TextDecoder('utf-16le');
/** What heads a JWT placeholder: no signature, which the third part, the handle, takes the place of. */
const UNSIGNED = base64url(new TextEncoder().encode('{"alg":"none","typ":"JWT"}'));
/** Values shorter than this are not redacted from answers: too short to tell from the text around them. */
const MIN_REDACTED = 8;
const REDACTED = '[redacted by coffre]';
/** Headers about one hop, and those that would tell the upstream about coffre's caller, its cookies or its handle. */
const DROPPED = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'cookie', 'content-length', 'expect', 'x-coffre-handle', 'forwarded', 'x-real-ip', 'cdn-loop', 'true-client-ip',
]);
const DROPPED_ANSWER = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'set-cookie', 'content-length', 'content-encoding', 'trailer']);

/**
 * `shape`: what a shaped placeholder's slot must be, the handle its one group; a path rule's is always one, the bare
 * handle in the key's place without a placeholder. `framed`: a path rule's template, the text around its key.
 */
type Resolved = Credential & { name: string; base: URL; keys: string[]; shape?: RegExp; framed?: { before: string; after: string } };

/**
 * A `path()` rule's template: one segment, its key once, `bot{TELEGRAM_BOT_TOKEN}`. The text around the key goes out as
 * written, so it is a segment's own characters (RFC 3986's pchar) but `%` and `;`, which a server behind may read as
 * another: letters, digits and -._~!$&'()*+,=:@.
 */
const PATH_TEMPLATE = /^([A-Za-z0-9._~!$&'()*+,=:@-]*)\{([A-Za-z_][A-Za-z0-9_]{0,127})\}([A-Za-z0-9._~!$&'()*+,=:@-]*)$/;

/**
 * Where a `path()` rule's key goes in a path under the upstream, as the app sent it (`/botcoffre_use_…/sendMessage`):
 * the index, in its segments split at `/`, of the first that the template frames, decoded once, at least one character
 * between; -1 for none. What the app sent, never the value, decides it.
 *
 *   bot{T}, /botcoffre_use_…/sendMessage             1
 *   bot{T}, /file/botcoffre_use_…/photos/file_0.jpg  2
 *   bot{T}, /getMe                                   -1
 */
function pathSlot({ before, after }: { before: string; after: string }, relative: string): number {
  const segments = relative.split('/');
  for (let at = 1; at < segments.length; at++) {
    const decoded = bytesOf(segments[at]!);
    if (decoded.length > before.length + after.length && decoded.startsWith(before) && decoded.endsWith(after)) return at;
  }
  return -1;
}

/**
 * A value as the part of a path segment a `path()` rule puts it in: percent-encoded, but letters, digits, -._~ and `:`
 * (Telegram's `123456789:AAE…` goes as it is). Null for one a server behind might read as another path however it is
 * encoded: empty, or holding `/`, `\`, `?`, `#`, `%`, `;`, `..`, whitespace or a control character.
 */
function pathValue(value: string): string | null {
  if (value === '' || /[/\\?#%;\s\u0000-\u001f\u007f]/.test(value) || value.includes('..')) return null;
  try {
    return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).replaceAll('%3A', ':');
  } catch {
    // A lone surrogate, which no UTF-8 holds.
    return null;
  }
}

/** The credential proxy, as a plugin of the deployment's (`plugins: [credentialProxy({…})]`). */
export function credentialProxy(options: CredentialProxyOptions): CoffrePlugin {
  const credentials = new Map(Object.entries(options.credentials).map(([name, credential]) => [name, resolve(name, credential, options.insecureUpstreams === true)]));
  // The app holds one value for a key: every credential that reads it gives it the same placeholder.
  for (const one of credentials.values()) {
    const other = [...credentials.values()].find((two) => two.keys.some((key) => one.keys.includes(key)) && JSON.stringify(two.placeholder) !== JSON.stringify(one.placeholder));
    if (other !== undefined) throw new Error(`credentialProxy: ${one.name} and ${other.name} read ${one.keys.find((key) => other.keys.includes(key))} with different placeholders, and the app holds one value for it`);
  }
  if (options.expose !== undefined) {
    throw new Error("credentialProxy: expose is gone in 0.10, as each key says who sees it: a person's app holds as they are the values they may read. Remove expose, and mark sensitive the keys no person may read (coffre mark <env> sensitive)");
  }
  const generate = checkListed('generate', options.generate ?? {});
  const tunnels = new Map(Object.entries(options.tunnels ?? {}).map(([name, tunnel]) => [name, checkTunnel(name, tunnel, credentials, options.insecureUpstreams === true)]));
  const signers = new Map(Object.entries(options.signers ?? {}).map(([name, signer]) => [name, checkSigner(name, signer, credentials, tunnels, new Map(), 'signer')]));
  const verifiers = new Map(Object.entries(options.verifiers ?? {}).map(([name, verifier]) => [name, checkSigner(name, verifier, credentials, tunnels, signers, 'verifier') as Hmac]));
  const ciphers = new Map(Object.entries(options.ciphers ?? {}).map(([name, cipher]) => [name, checkSigner(name, cipher, credentials, tunnels, signers, 'cipher', verifiers) as Cipher]));
  const recheckMs = (options.recheckSeconds ?? 60) * 1000;
  if (!(recheckMs > 0 && recheckMs <= 3_600_000)) throw new Error('credentialProxy: recheckSeconds is above 0, an hour at most');
  // Read and ignored through 0.16 (docs/design/0.16.md, "The proxy"): the vault's memory is the only one.
  const cacheMs = (options.cacheSeconds ?? 60) * 1000;
  if (!Number.isFinite(cacheMs) || cacheMs < 0 || cacheMs > 3_600_000) throw new Error('credentialProxy: cacheSeconds is between 0 and 3600');
  const proxy: Proxy = { credentials, tunnels, signers, verifiers, ciphers, insecure: options.insecureUpstreams === true, generate };
  return {
    name: 'credential-proxy',
    routes: {
      prefix: '/use',
      fetch: async (request, coffre) => {
        try {
          return await serve(request, coffre, proxy);
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code);
          throw error;
        }
      },
    },
  };
}

type Proxy = {
  credentials: Map<string, Resolved>;
  tunnels: Map<string, Tunnel>;
  signers: Map<string, Signer>;
  /** HMAC secrets that check signatures and make none. */
  verifiers: Map<string, Hmac>;
  ciphers: Map<string, Cipher>;
  insecure: boolean;
  generate: Map<string, 'all' | readonly string[]>;
};

/** A credential's values, opened, and which keys of it are plain, no secret: what the answer's redaction leaves as it is. */
type Opened = { values: Record<string, string>; plain: readonly string[] };

/**
 * What the proxy does not serve on 0.16 yet, which 0.14.7 did: a presigned
 * URL, a signature, a verification or a cipher's work, a tunnel, and the
 * plan of an environment the deployment generates values for. Each comes
 * back on `use` in a pull request of its own (docs/design/0.16.md, "The proxy").
 */
const notYet = (what: string) => failure(501, `${what} is not served by this version of coffre yet`, 'not_implemented');

async function serve(request: Request, coffre: PluginContext, proxy: Proxy): Promise<Response> {
  const url = new URL(request.url);
  // The raw segments after `/use`: the place and credential decoded, the rest sent on as the app wrote it.
  const raw = url.pathname.slice('/use'.length).split('/').slice(1);
  if (raw.length === 0 || (raw.length === 1 && raw[0] === '')) {
    // What `coffre run` asks first: whether this instance has the proxy. It holds no secret.
    if (request.method === 'GET') return answer({ proxy: 'coffre', credentials: [...proxy.credentials.keys()] });
    return request.method === 'POST' ? notYet('a presigned URL, a signature or a cipher\'s work') : failure(405, 'GET only');
  }
  let place: string[];
  try {
    place = raw.slice(0, 3).map(decodeURIComponent);
  } catch {
    return failure(400, 'the path is not valid percent-encoding');
  }
  const stable = proxy.credentials.get(place[0]!);
  // A workload's: `/use/<credential>/<path>` whenever `<credential>` is one, for the one environment it reaches, and
  // `/use/<project>/<env>/<credential>/<path>` otherwise. Nothing tells a session's environments by name before its
  // one statement, so the URL alone decides; a handle's are below.
  const named = stable === undefined && raw.length >= 3 ? proxy.credentials.get(place[2]!) : undefined;
  if (stable !== undefined || named !== undefined) {
    const used = await workloadForward(request, coffre, proxy, stable !== undefined ? null : `${place[0]}/${place[1]}`, (stable ?? named)!, raw.slice(stable !== undefined ? 1 : 3), url.search);
    if (used !== null) return used;
  }
  // A form or JSON rule's body, as the stable URL read it to find the handle: what the route then sends, read once.
  const peeked = new Map<Resolved, Fillable>();
  // `/use/<credential>/<path>`, the stable URL, for the environment the handle was made for; unless `<a>/<b>` is an
  // environment the handle was made for, which `/use/<project>/<env>/…` names below. Never a guess: the URL and the handle decide.
  if (stable !== undefined) {
    const named = place[2] === undefined ? undefined : proxy.credentials.get(place[2]);
    // A form or JSON rule's refusal of the body, which says more than that no handle came: the named credential's, if both refuse.
    let refused: Response | null = null;
    // Each by its own path under its upstream, `rest`: `/use/bots/bot<handle>/getMe` is `/bot<handle>/getMe` to `bots`.
    const found = async (credential: Resolved, rest: string[]) => {
      const read = await peekField(request, credential);
      if (read instanceof Response) refused = read;
      else if (read !== null) peeked.set(credential, read);
      return handleIn(request, credential, url, within(credential, rest, url.search)?.relative ?? null, read instanceof Response ? null : (read?.field.value ?? null));
    };
    const handle = (await found(stable, raw.slice(1))) ?? (named === undefined ? null : await found(named, raw.slice(3))) ?? HANDLE.exec(bearer(request) ?? '')?.[0] ?? null;
    if (handle === null) return refused ?? failure(401, `send the handle \`coffre run\` gave your app where ${stable.name} takes its key, or as x-coffre-handle`);
    // The row's places, unchecked: where to ask. Whether the handle reaches the one asked about is the vault's to say.
    const { paths } = await coffre.handle(handle);
    if (raw.length === 1 || !paths.includes(`${place[0]}/${place[1]}`)) {
      // As many as it was made for, a deleted one too: what the handle names decides, never what is left of it.
      const live = paths.filter((path) => path !== null);
      if (paths.length > 1) {
        const urls = live.map((path) => `${coffre.publicUrl}/use/${path}/${stable.name}`).join(' or ');
        return failure(409, `this handle stands in for ${paths.length} environments, and the stable URL is for a run of one: name it${live.length === 0 ? '' : `, ${urls}`}`);
      }
      if (live.length === 0) return failure(409, 'the environment this handle was made for is gone');
      return forward(request, coffre, proxy, live[0]!, stable, raw.slice(1), url.search, peeked.get(stable));
    }
  }
  if (raw.length === 2) {
    if (request.method === 'POST') return notYet('a presigned URL, a signature or a cipher\'s work');
    if (request.method !== 'GET') return failure(405, 'GET for the plan, POST to presign or sign');
    return plan(request, coffre, proxy, `${place[0]}/${place[1]}`);
  }
  if (raw.length < 3) return failure(404, 'name /use/<credential>/<path>, or /use/<project>/<environment>/<credential>/<path>');
  const credential = proxy.credentials.get(place[2]!);
  if (credential === undefined && proxy.tunnels.has(place[2]!)) return notYet('a tunnel');
  if (credential === undefined && proxy.signers.has(place[2]!)) return failure(404, `${place[2]} is a signer, which reaches no upstream: credential(${JSON.stringify(place[2])}).sign(message)`);
  if (credential === undefined && proxy.verifiers.has(place[2]!)) return failure(404, `${place[2]} is a verifier, which reaches no upstream: credential(${JSON.stringify(place[2])}).verify(message, signature)`);
  if (credential === undefined && proxy.ciphers.has(place[2]!)) return failure(404, `${place[2]} is a cipher, which reaches no upstream: credential(${JSON.stringify(place[2])}).encrypt(plaintext)`);
  if (credential === undefined) return failure(404, `this instance has no credential ${JSON.stringify(place[2])}: its deployment's credentialProxy names them`);
  return forward(request, coffre, proxy, `${place[0]}/${place[1]}`, credential, raw.slice(3), url.search, peeked.get(credential));
}

/** A plan's bearer, a handle whole: a person's session or token reads its own values through the API, never here. */
const WHOLE_HANDLE = new RegExp(`^${HANDLE.source}$`);

/**
 * What `coffre run` gives the app for an environment (docs/design/credential-proxy.md,
 * section 2): each credential whose keys the environment holds, its keys as
 * the handle, or the placeholder its client checks; the values its person
 * reads, plain ones and secrets as they are, never a sensitive one, and
 * never one a credential covers but a plain one its rule leaves no slot of
 * the handle in; each signer's, verifier's and cipher's key as the handle,
 * and its name where `credential(name)` finds it; each tunnel, for its key,
 * the URL `coffre run`'s listener stands in for; and every key the
 * environment holds that none of these covers, a sensitive one, or one its
 * person only uses, in `left`, for `coffre run` to say.
 *
 * Two calls to the vault and no statement (docs/design/0.16.md, "The
 * proxy"): `held`, a peek, which says each key the handle may use and its
 * nature and opens nothing; then one `expose` of the keys the app is
 * handed, which opens and logs them alone, so a covered secret is never
 * opened. Each value is placed by the nature the use opened it under, not
 * the peek's: a key the peek saw plain that opens a secret, under a
 * credential, stays its placeholder, its value dropped. A credential with a
 * JWT placeholder adds its own use and the handle's row (`shaped`).
 */
async function plan(request: Request, coffre: PluginContext, proxy: Proxy, path: string): Promise<Response> {
  // A workload's proof signs the request's content as every request under /use does: here, no body.
  const caller = await workloadOf(request, coffre, { place: path, body: await bodyDigest(new Uint8Array(0)) });
  if (caller instanceof Response) return caller;
  if (caller !== null) return answering(caller, () => workloadPlan(coffre, proxy, caller, caller.path ?? path));
  // The personal config's recipes, which a plan names for `coffre run` to make, come with that config's writes (W418).
  if (proxy.generate.has(path.replace(/@me$/, ''))) return notYet(`the plan of ${path}, an environment the deployment generates values for (\`generate\`),`);
  const handle = bearer(request);
  if (handle === null || !WHOLE_HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  const held = await coffre.held(handle, path);
  // What the handle may use, by the nature its rows say: what chooses which keys to open, and nothing more.
  const usable = new Map(held.flatMap((item) => ('refused' in item ? [] : [[item.key, item.nature] as const])));
  const holds = (key: string) => usable.has(key);
  const using = [...proxy.credentials.values()].filter((credential) => credential.keys.every(holds));
  const signers = keyed(proxy).filter(([, signer]) => holds(signer.key));
  const tunnels = [...proxy.tunnels].filter(([, tunnel]) => holds(tunnel.key));
  const covered = new Set([...using.flatMap((credential) => credential.keys), ...signers.map(([, signer]) => signer.key), ...tunnels.map(([, tunnel]) => tunnel.key)]);
  // What the proxy fills in itself, never the value the environment holds: a tunnel's URL, a signer's handle, and a
  // credential's plain keys where giving them would leave the handle nowhere the proxy finds it (S3's access key id, which
  // the SDK sends as `Credential=`, or every key of a header's). Those stay placeholders, as secrets do.
  const plain = new Set([...usable].filter(([, nature]) => nature === 'plain').map(([key]) => key));
  const filled = new Set([...signers.map(([, signer]) => signer.key), ...tunnels.map(([, tunnel]) => tunnel.key), ...using.filter((credential) => !carriesHandle(credential.inject, plain)).flatMap((credential) => credential.keys)]);
  // A plain value is no secret, wherever it is held; a secret no credential covers, its person reads where it is held.
  const asked = [...usable].filter(([key, nature]) => (nature === 'plain' && !filled.has(key)) || (nature !== 'sensitive' && !covered.has(key))).map(([key]) => key);
  // A person who only uses the environment, a Developer's protected prod, reads none of it: every value is left.
  const exposed = asked.length === 0 ? null : await coffre.expose(handle, { path, keys: asked }).catch((error: unknown) => {
    if (error instanceof CoffreError && error.reason === 'no_access') return null;
    throw error;
  });
  const env: Record<string, string> = Object.create(null);
  const credentials: Record<string, string> = {};
  const placed = new Set<string>();
  for (const credential of using) {
    // The environment's URL, which a run of several environments tells apart.
    credentials[credential.name] = `${coffre.publicUrl}/use/${path}/${credential.name}`;
    const placeholder = credential.placeholder === undefined ? handle : await shaped(coffre, credential, handle, path);
    for (const key of credential.keys) {
      env[key] = placeholder;
      placed.add(key);
    }
  }
  for (const [key, value] of Object.entries(exposed?.values ?? {})) {
    // As the use opened it: a covered key is given only plain, and never one the proxy fills in.
    if (filled.has(key) || (covered.has(key) && !exposed!.plain.includes(key))) continue;
    env[key] = value;
    placed.add(key);
  }
  // A signer's, verifier's or cipher's key the handle, and its name where `credential(name)` finds it: the key never leaves coffre.
  for (const [name, signer] of signers) {
    credentials[name] = `${coffre.publicUrl}/use/${path}/${name}`;
    env[signer.key] = handle;
    placed.add(signer.key);
  }
  // A database's URL is `coffre run`'s to make, its listener's, with the handle as the password: never the real one.
  const listeners: Record<string, { key: string; url: string }> = {};
  for (const [name, tunnel] of tunnels) {
    listeners[name] = { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` };
    delete env[tunnel.key];
    placed.add(tunnel.key);
  }
  return answer({ environment: path, env: { ...env }, credentials, tunnels: listeners, left: held.map((item) => item.key).filter((key) => !placed.has(key)) });
}

/**
 * What a workload's environment holds for it (docs/design/workload-access.md,
 * section 6.2): the values it reads, plain ones and those its binding lists
 * in `reads`, as the vault hands them; the names of the credentials and
 * signers it uses through coffre, and its tunnels, each with the key whose
 * URL the local listener stands in for, as a handle's plan has them; and
 * every key it holds but is not handed, `useOnly`. No placeholder: its
 * requests carry its proof, never a value in a slot. One `expose` of every
 * key, after its gate.
 */
async function workloadPlan(coffre: PluginContext, proxy: Proxy, caller: WorkloadUse, path: string): Promise<Response> {
  const exposed: Exposed = await coffre.expose(caller, { path, keys: null });
  const keys = [...Object.keys(exposed.values), ...Object.keys(exposed.refused)].sort();
  const holds = (wanted: readonly string[]) => wanted.every((key) => keys.includes(key));
  return answer({
    environment: path,
    values: { ...exposed.values },
    credentials: [...[...proxy.credentials.values()].filter((credential) => holds(credential.keys)).map((credential) => credential.name), ...keyed(proxy).filter(([, signer]) => holds([signer.key])).map(([name]) => name)],
    tunnels: Object.fromEntries([...proxy.tunnels].filter(([, tunnel]) => holds([tunnel.key])).map(([name, tunnel]) => [name, { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` }])),
    useOnly: keys.filter((key) => !Object.hasOwn(exposed.values, key)),
    mints: [],
  });
}

/**
 * A credential's placeholder in the shape its client checks: the handle behind
 * a prefix, or a JWT of the real token's named claims, which are opened for
 * it as a use of the credential, logged under its name, and go no further
 * than those; it ends when the handle does, which its row says.
 */
async function shaped(coffre: PluginContext, credential: Resolved, handle: string, path: string): Promise<string> {
  const placeholder = credential.placeholder!;
  if (placeholder.kind === 'prefix') return `${placeholder.prefix}${handle}`;
  const key = credential.keys[0]!;
  const used = await coffre.use(handle, { path, keys: [key], purpose: 'use', upstream: credential.name });
  const real = claimsOf(used.values[key]);
  if (real === null) throw new CoffreError(409, 'conflict', `${path}'s ${key} is no JWT, which ${credential.name}'s placeholder copies its claims from`);
  const { expiresAt } = await coffre.handle(handle);
  const claims = Object.fromEntries(placeholder.claims.filter((claim) => Object.hasOwn(real, claim)).map((claim) => [claim, real[claim]]));
  return `${UNSIGNED}.${base64url(new TextEncoder().encode(JSON.stringify({ ...claims, exp: Math.floor(Date.parse(expiresAt) / 1000) })))}.${handle}`;
}

/** A JWT's claims, its middle part read as base64url JSON: null if it is no JWT. */
function claimsOf(token: string | undefined): Record<string, unknown> | null {
  const parts = token?.split('.') ?? [];
  if (parts.length !== 3) return null;
  try {
    const claims: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')), (char) => char.charCodeAt(0))));
    return typeof claims === 'object' && claims !== null && !Array.isArray(claims) ? (claims as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** The signers, verifiers and ciphers, by name: each a key the app holds the handle for, which coffre computes with. */
function keyed(proxy: Proxy): [string, Signer | Cipher][] {
  return [...proxy.signers, ...proxy.verifiers, ...proxy.ciphers];
}

/** Whether a credential's rule still has a slot for the handle once its plain keys are given as they are: a key in it that is not plain. */
function carriesHandle(inject: Inject, plain: ReadonlySet<string>): boolean {
  const slots = inject.kind === 'basic' ? [inject.user, inject.password] : inject.kind === 'sigv4' ? [inject.accessKeyId] : [inject.template];
  return slots.some((slot) => [...slot.matchAll(TEMPLATE_KEY)].some((match) => !plain.has(match[1]!)));
}

function base64url(bytes: Uint8Array): string {
  return btoa(binary(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * What a person's use of `path` reads: their personal config of it, or the
 * environment while they have none, where the deployment generates values
 * for it; the environment itself anywhere else.
 */
function readOf(proxy: Proxy, path: string): string {
  return proxy.generate.has(path) ? `${path}@me` : path;
}

/** The longest message a signer, verifier or cipher takes. */
function longest(signer: Signer | Cipher): number {
  return signer.kind === 'private-key' ? MESSAGE_BYTES : (signer.maxBytes ?? MESSAGE_BYTES);
}

const sized = (bytes: number) => (bytes % 1024 ** 2 === 0 ? `${bytes / 1024 ** 2} MiB` : bytes % 1024 === 0 ? `${bytes / 1024} KiB` : `${bytes} bytes`);

/**
 * Where a request through a credential goes, under its upstream, once its path is checked: the URL, the upstream's own
 * path, the request's within it as the app sent it, and, through a `path()` rule, the index of its segment there (`pathSlot`).
 */
type Aim = { target: URL; under: string; relative: string; slot: number };

/**
 * Nothing the app writes leaves the credential's upstream: no slash or backslash smuggled in a segment, and no dot
 * segment as a server reads one, decoded, with its `;` parameters dropped as Tomcat and Spring drop them (`..;`).
 * Decoded as often as it changes, since a server behind another decodes twice: `%252e%252e` is `..` to it. No control
 * byte either, which a server may cut a segment at (`..%00`), nor an overlong lead byte, which an old one decodes to a
 * dot (`%c0%ae`); and a dot segment is one with trailing blanks too (`..%20`).
 */
function climbs(segment: string): boolean {
  const read = bytesOf(segment);
  return /[/\\\x00-\x1f\x7f\xc0\xc1]/.test(read) || /^\.{1,2}[ \t]*$/.test(read.split(';')[0]!) || (read !== segment && climbs(read));
}

/**
 * The credential's own URL for a request's path under it, `rest`, as the app asked for it: `…/schumann` is the upstream
 * itself, `…/schumann/` the upstream and a slash; with the upstream's own path, and the request's under it. Null for a
 * URL that leaves the upstream.
 */
function within(credential: Resolved, rest: readonly string[], search: string): Omit<Aim, 'slot'> | null {
  const target = new URL(`${rest.length === 0 ? credential.base.href : `${credential.base.href.replace(/\/$/, '')}/${rest.join('/')}`}${search}`);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) return null;
  return { target, under, relative: target.pathname.slice(under.length) || '/' };
}

/**
 * The upstream URL a request through `credential` goes to, or the refusal:
 * nothing the app writes leaves the credential's upstream, and its methods
 * and paths hold. Whoever sends it, a handle's holder or a workload.
 */
function aim(request: Request, credential: Resolved, rest: string[], search: string): Aim | Response {
  if (rest.some(climbs)) return failure(400, 'the path may not climb out of the credential\'s upstream');
  const at = within(credential, rest, search);
  if (at === null) return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  const { target, under, relative } = at;
  if (credential.methods !== undefined && !credential.methods.includes(request.method)) return failure(405, `${credential.name} takes ${credential.methods.join(', ')}`);
  if (credential.paths !== undefined && !credential.paths.some((prefix) => relative === prefix || relative.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) {
    return failure(403, `${credential.name} is not for ${relative}`);
  }
  // A path rule's segment, found in the path as the app sent it, before anything is opened: the value never decides it.
  const slot = credential.framed === undefined ? -1 : pathSlot(credential.framed, relative);
  if (credential.framed !== undefined && slot === -1) return failure(400, `${credential.name} takes its key in a segment of the path, ${(credential.inject as { template: string }).template}, and this path has none`);
  if (credential.inject.kind === 'sigv4') {
    if (target.searchParams.has('X-Amz-Signature') || target.searchParams.has('X-Amz-Credential')) return failure(400, `a presigned URL signs with the real key: ${credential.name} takes requests the SDK signs in their headers`);
    const hash = request.headers.get('x-amz-content-sha256') ?? '';
    if (hash.startsWith('STREAMING-') || /aws-chunked/i.test(request.headers.get('content-encoding') ?? '')) {
      return failure(400, `aws-chunked uploads chain their chunks' signatures from the real key: set requestChecksumCalculation: 'WHEN_REQUIRED' in the SDK, for UNSIGNED-PAYLOAD or a literal hash`);
    }
    if (hash !== '' && hash !== 'UNSIGNED-PAYLOAD' && !/^[0-9a-f]{64}$/.test(hash)) return failure(400, 'x-amz-content-sha256 is a SHA-256, hex, or UNSIGNED-PAYLOAD');
  }
  return { target, under, relative, slot };
}

/**
 * What a request through a credential carries: a body read whole, up to
 * 16 MiB, or, for one that says its length and declares its digest, the
 * length it streams with, never held whole: an AWS-signed upload's
 * `x-amz-content-sha256`, which S3 checks (an S3 object may be gigabytes,
 * and its signature needs no byte of it), or a `Content-Digest`'s SHA-256,
 * `digest`, which coffre checks as the bytes pass (`scanned`), up to
 * `MAX_DIGESTED_BODY`; or the refusal. A body read whole is what its
 * `Content-Digest` declares, too.
 */
type Carried = { body: Uint8Array<ArrayBuffer> | undefined; streamed: boolean; declared: string; digest: string | null };

async function carried(request: Request, credential: Resolved): Promise<Carried | Response> {
  const declared = request.headers.get('content-length') ?? '';
  // A body whose field coffre fills is read whole, and small: it is parsed, and changed.
  const field = inBody(credential.inject);
  const amz = credential.inject.kind === 'sigv4' && request.headers.has('x-amz-content-sha256');
  let digest: string | null = null;
  try {
    digest = amz ? null : declaredDigest(request.headers.get('content-digest') ?? '');
  } catch (error) {
    return failure(400, (error as Error).message);
  }
  // An empty body is checked before anything goes: with no last byte to hold back, its request is whole once its headers are.
  const streamed = !field && (amz || (digest !== null && Number(declared) > 0)) && request.body !== null && /^\d+$/.test(declared);
  if (streamed && amz && Number(declared) > MAX_STREAM_BYTES) return failure(413, `an upload through the proxy carries at most ${MAX_STREAM_BYTES / 1024 ** 3} GiB: send a larger one in parts`);
  if (streamed && !amz && Number(declared) > MAX_DIGESTED_BODY) {
    return failure(413, `a body that declares its digest streams through the proxy up to ${MAX_DIGESTED_BODY / 1024 / 1024} MiB, under the 100 MB a Cloudflare zone takes: send a larger one in parts`);
  }
  const body = request.method === 'GET' || request.method === 'HEAD' || streamed ? undefined : await boundedBody(request, field ? MAX_FIELD_BODY : MAX_BODY_BYTES);
  if (body === null && field) return failure(413, `${credential.name} fills a field of a body read whole, ${MAX_FIELD_BODY / 1024} KiB at most`);
  if (body === null) {
    return failure(413, `a request through the proxy carries at most ${MAX_BODY_BYTES / 1024 / 1024} MiB read whole; one that says its length and declares its SHA-256 streams, up to ${MAX_DIGESTED_BODY / 1024 / 1024} MiB: Content-Digest: sha-256=:<base64>:, as coffre serve and @coffre/client/workload send it, or x-amz-content-sha256 through an AWS-signed credential`);
  }
  if (digest !== null && !streamed && (await bodyDigest(body ?? new Uint8Array(0))) !== digest) return failure(400, 'the body is not what its Content-Digest says');
  // As a number writes it: `00` is the 0 it says, as it goes on and as the body's line reads it.
  return { body, streamed, declared: streamed ? String(Number(declared)) : declared, digest };
}

/**
 * One request through a credential, a handle's: the handle checked, its
 * values opened (or remembered), the request sent on with them. `peeked`,
 * a form or JSON rule's body as the stable URL already read it.
 */
async function forward(request: Request, coffre: PluginContext, proxy: Proxy, path: string, credential: Resolved, rest: string[], search: string, peeked?: Fillable): Promise<Response> {
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return aimed;
  const { target, relative } = aimed;
  const inject = credential.inject;
  // A form or JSON rule's handle is in the body's field: the body read whole first, and the field found.
  const early = peeked ?? (inBody(inject) ? await fillable(request, credential, inject) : null);
  if (early instanceof Response) return early;
  const field = early?.field ?? null;
  const handle = handleIn(request, credential, target, relative, field?.value ?? null);
  if (handle === null) return failure(401, `send what \`coffre run\` gave your app for its key where ${credential.name} takes it, or the handle as x-coffre-handle`);
  // The field holds the handle the request is let in on, x-coffre-handle's too: the value goes nowhere the app did not put it.
  if (field !== null && handleOf(credential, field.value) !== handle) return failure(400, `the handle is not in the field where ${credential.name} takes its key`);
  // So does a path rule's segment.
  if (inject.kind === 'path' && handleOf(credential, appSegment(credential, relative) ?? '') !== handle) {
    return failure(400, `the handle is not in the segment of the path where ${credential.name} takes its key, ${inject.template}`);
  }
  // A query rule's parameter as the app sent it, if it stands in for this handle, its shape and all: what a redirect
  // under the upstream gives back. Otherwise the placeholder's shape around the handle, which the proxy reads as the app's own
  // (`e30` is `{}`: the proxy reads no claim).
  const given = inject.kind === 'query' ? target.searchParams.get(inject.name) : null;
  const back = inject.kind !== 'query' ? null : given !== null && handleOf(credential, given) === handle ? given
    : credential.placeholder === undefined ? handle : render(inject.template, { [credential.keys[0]!]: credential.placeholder.kind === 'prefix' ? `${credential.placeholder.prefix}${handle}` : `${UNSIGNED}.e30.${handle}` });
  // Read whole first, however long it takes to come, so the handle is checked, and the values opened, as the request goes out.
  const content = early?.content ?? (await carried(request, credential));
  if (content instanceof Response) return content;
  const opened = await valuesFor(coffre, proxy, handle, path, credential);
  const headers = new Headers();
  for (const [name, value] of request.headers) if (sent(name)) headers.set(name, value);
  // Where its redirects stay: the environment's URL, the stable one's included. Under the stable URL, a path that begins
  // with an environment of the handle's would name that environment, and another credential (`/use/schumann/dev/maps/…`).
  return send(request, credential, { ...aimed, ...content, opened, headers, proxied: `${coffre.publicUrl}/use/${path}/${credential.name}`, back, field, secret: { pattern: HANDLE, length: HANDLE_LENGTH, what: 'the handle' } });
}

/** Whether a header of the app's goes on upstream: none about one hop, nor any that would tell the upstream about coffre's caller. */
const sent = (name: string) => !DROPPED.has(name) && !name.startsWith('cf-') && !name.startsWith('x-forwarded-');

/** The session token a workload's request carries (`Authorization: DPoP coffre_wl_…`), which goes no further than coffre; null for none, a Cloudflare call's. */
function sessionToken(request: Request): string | null {
  return SESSION.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
}

const SESSION = /^DPoP\s+(coffre_wl_\S+)$/i;

/**
 * The request's workload (`PluginContext.workload`), its refusal as the
 * answer, or null for no workload. A credential whose rule sends its key
 * under the DPoP scheme (`header('authorization', 'DPoP {TOKEN}')`) has the
 * app send its handle there: that is a handle's request, and no session's.
 */
async function workloadOf(request: Request, coffre: PluginContext, at: WorkloadAt): Promise<WorkloadUse | Response | null> {
  if (sessionToken(request) === null && /^DPoP\s/i.test(request.headers.get('authorization') ?? '')) return null;
  return refused(coffre.workload(request, at));
}

/** The request's answer with the gate's newest nonce on it, which the workload signs its next proof with (`DPoP-Nonce`); as it is for any other caller. */
function nonced(response: Response, caller: WorkloadUse | null): Response {
  if (caller === null || caller.nonce === null) return response;
  const headers = new Headers(response.headers);
  headers.set('dpop-nonce', caller.nonce);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** A workload's refusal (`WorkloadRefused`) is its answer, as coffre made it; anything else goes on. */
async function refused<T>(asking: Promise<T>): Promise<T | Response> {
  try {
    return await asking;
  } catch (error) {
    if (error instanceof WorkloadRefused) return error.response;
    throw error;
  }
}

/**
 * One request through a credential, a workload's session's
 * (docs/design/workload-access.md, section 7.1), or null when it carries no
 * session, which a handle's path then takes, its body unread. The session
 * comes as `Authorization: DPoP` with a proof, which signs the request
 * whole (`req`): its path and query, the headers it names (`hdr`), which
 * alone go on, and its body, read whole and hashed, or, through a sigv4
 * credential, bound by the payload hash it declares, which coffre signs
 * again and the upstream checks against the bytes, so an upload streams;
 * `UNSIGNED-PAYLOAD` there binds nothing. The session's gate takes the
 * proof once, with the credential's `limit`, before the vault is asked.
 * Then one use, which the vault decides on its own rows, and on its answer
 * about the session what only the app can hold the request to: a narrowed
 * session's methods and paths, on the URL about to be sent, and an
 * unsigned upload, which only a binding that says `unsignedUploads` takes.
 * (A Cloudflare service binding's call is not served on 0.16 yet.)
 */
async function workloadForward(request: Request, coffre: PluginContext, proxy: Proxy, path: string | null, credential: Resolved, rest: string[], search: string): Promise<Response | null> {
  if (sessionToken(request) === null) return null;
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return aimed;
  const content = await carried(request, credential);
  if (content instanceof Response) return content;
  // The body's line in `req`, and the payload hash a sigv4 credential signs again: one value, so what goes out is what
  // the proof bound. A body of any bytes signs the SHA-256 its `Content-Digest` declares, which `carried` and `scanned`
  // hold the bytes to, streamed or not; through a sigv4 credential, the hash its `x-amz-content-sha256` declares, which
  // the upstream checks against them (any other value binds nothing); every other request, an empty body's included
  // whatever its header says, the bytes' own digest.
  // The header that chose the line must be one the proof signs, and a buffered body must be what it declares: neither is
  // left for a copier to pick.
  // The rule the SDK signs by (`bodyLine`), from the body's length as coffre holds it: a stream's declared content-length,
  // which `scanned` keeps it to, or the bytes read.
  const amz = content.digest === null && credential.inject.kind === 'sigv4' ? request.headers.get('x-amz-content-sha256') : null;
  const declared = content.digest ?? amz;
  const length = content.streamed ? Number(content.declared) : (content.body?.byteLength ?? 0);
  const declaring = declared === null || length === 0 ? null : content.digest !== null ? 'content-digest' : 'x-amz-content-sha256';
  const body = await bodyLine({ declared, length, bytes: content.body ?? null });
  if (amz !== null && length !== 0 && !content.streamed && body !== UNSIGNED_BODY && body !== (await bodyDigest(content.body!))) return failure(400, 'the body is not what its x-amz-content-sha256 says');
  const payload = body === UNSIGNED_BODY ? 'UNSIGNED-PAYLOAD' : body;
  const caller = await workloadOf(request, coffre, { place: path, body, ...countsOf(credential.name, credential.limit) });
  if (caller === null || caller instanceof Response) return caller;
  return answering(caller, async () => {
    if (declaring !== null && caller.hdr !== null && !caller.hdr.includes(declaring)) {
      return failure(400, `${declaring} says what binds the body, so the proof signs it: name it in hdr`);
    }
    if (caller.path === null) return failure(409, `name the environment, ${coffre.publicUrl}/use/<project>/<environment>/${credential.name}: this session was made for none, several, or one since deleted`);
    // A form or JSON rule's field, whatever the app put there, as a header rule's header: it holds no handle.
    const field = inBody(credential.inject) ? fieldIn(request, content.body, credential.name, credential.inject) : null;
    if (field instanceof Response) return field;
    const used = await coffre.use(caller, { path: caller.path, keys: credential.keys, purpose: 'use', upstream: credential.name });
    const constraints = used.workload?.constraints ?? null;
    if (!constraintsAllow(constraints, { place: caller.path, credential: credential.name, request: { method: request.method, url: aimed.target } })) {
      return failure(403, `this narrowed session may not ${request.method} ${aimed.relative} through ${credential.name}`, 'narrowed');
    }
    if (body === UNSIGNED_BODY && used.workload?.policy.unsignedUploads !== true) {
      return failure(403, "an unsigned upload (UNSIGNED-PAYLOAD) binds no body to its proof, and this workload's binding does not say unsignedUploads: send x-amz-content-sha256 as the body's SHA-256", 'unsigned_upload');
    }
    // Only what the proof signs goes on, of what the app sent: a header added on the way, by a library or a proxy, is dropped.
    const headers = new Headers();
    for (const [name, value] of request.headers) if ((caller.hdr === null || caller.hdr.includes(name)) && sent(name)) headers.set(name, value);
    const proxied = `${coffre.publicUrl}/use/${path === null ? '' : `${path}/`}${credential.name}`;
    const token = sessionToken(request)!;
    const secret = { pattern: new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), length: token.length, what: 'the session token' };
    return send(request, credential, { ...aimed, ...content, opened: { values: used.values, plain: used.plain }, headers, proxied, back: null, field, secret, payload });
  });
}

/** What a workload's request answers, a refusal of coffre's included, with the gate's newest nonce on it. */
async function answering(caller: WorkloadUse, work: () => Promise<Response>): Promise<Response> {
  try {
    return nonced(await work(), caller);
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return nonced(failure(error.status, error.message, error.reason ?? error.code), caller);
  }
}

/** What `send` takes: where to, what is carried, the values, the headers going on, and what must not leak. */
type Sending = Aim & Carried & {
  opened: Opened;
  headers: Headers;
  /** The proxy's URL for the credential, which a redirect under the upstream is made into. */
  proxied: string;
  /** A query rule's parameter, the app's placeholder, put back on a redirect to the proxy. */
  back: string | null;
  /** A form or JSON rule's field, which the body goes out with the value in. */
  field: Field | null;
  /** What authenticated the request to coffre and goes no further: the handle, a workload's session token; null for a Cloudflare call. */
  secret: { pattern: RegExp; length: number; what: string } | null;
  /** The payload hash a sigv4 credential signs, as a session's proof bound it (its body line); else the request's own, or its bytes'. */
  payload?: string;
};

/**
 * The request as it goes out, with the values injected, then the
 * upstream's answer, redacted: a redirect stays on the proxy, and what
 * authenticated the request to coffre goes nowhere upstream.
 */
async function send(request: Request, credential: Resolved, out: Sending): Promise<Response> {
  const { target, under, slot, streamed, declared, digest, headers, opened: { values, plain }, secret } = out;
  let { body } = out;
  const inject = credential.inject;
  // The URL as the app sent it, before a path rule put a value in it: what a relative redirect resolves against (`""`,
  // `getMe`, `?offset=1`), so it inherits the app's placeholder, never the value.
  const asSent = new URL(target.href);
  // A path rule's segment as it went out, the value's part of it, and the segment as the app sent it: a redirect that
  // quotes the one gets the other back.
  let swap: { sent: string; encoded: string; app: string } | null = null;
  if (inject.kind === 'path') {
    // The value as a segment's part, or nothing goes: a value a server might read as another path, encoded or not.
    const key = credential.keys[0]!;
    const encoded = pathValue(values[key]!);
    const segment = encoded === null ? null : `${credential.framed!.before}${encoded}${credential.framed!.after}`;
    // Whole, as a server behind reads it: no dot segment, and none that goes as no segment (`..{T}` with `.` is `...`).
    if (segment === null || climbs(segment) || /^\.+$/.test(segment)) return failure(409, `${credential.name}'s ${key} is no segment of a path: empty, or with a /, \\, ?, #, %, ;, .., a space or a control character in it`);
    // The path as the app sent it, that one segment changed, and nothing else: the URL setter encodes nothing more of it.
    const segments = target.pathname.slice(under.length).split('/');
    const app = segments[slot]!;
    segments[slot] = segment;
    const pathname = `${under}${segments.join('/')}`;
    target.pathname = pathname;
    if (target.pathname !== pathname) return failure(409, `${credential.name}'s ${key} is no segment of a path`);
    swap = { sent: segment, encoded: encoded!, app };
  }
  // A streamed body says its length itself, which S3 requires of a PutObject.
  if (streamed) headers.set('content-length', declared);
  try {
    if (inject.kind === 'header') headers.set(inject.name, render(inject.template, values));
    if (inject.kind === 'basic') headers.set('authorization', `Basic ${btoa(binary(new TextEncoder().encode(`${render(inject.user, values)}:${render(inject.password, values)}`)))}`);
    if (inject.kind === 'query') target.searchParams.set(inject.name, render(inject.template, values));
    if (inject.kind === 'form' || inject.kind === 'json') body = out.field!.fill(render(inject.template, values));
    if (inject.kind === 'sigv4') {
      // The app's own signature and the headers it signed are its handle's: signed again, for the upstream's host and path.
      for (const name of ['authorization', 'x-amz-date', 'x-amz-security-token']) headers.delete(name);
      // The hash the session's proof bound; else the client's own, as a streamed upload declared it or as sent on, or as its
      // Content-Digest declares it; or the body's, an empty one's included, as SigV4 has it when no header says otherwise.
      const given = out.payload ?? (streamed ? request.headers.get('x-amz-content-sha256') : headers.get('x-amz-content-sha256')) ?? digest;
      const payload = given ?? hex(await crypto.subtle.digest('SHA-256', body ?? new Uint8Array(0)));
      await signV4(request.method, target, headers, payload, {
        accessKeyId: render(inject.accessKeyId, values),
        secretAccessKey: render(inject.secretAccessKey, values),
        ...(inject.sessionToken === undefined ? {} : { sessionToken: render(inject.sessionToken, values) }),
      }, inject);
    }
  } catch {
    // The platform's error quotes the value it refused: neither it nor its message goes anywhere, a log included.
    return failure(409, `${credential.name}'s value is no valid ${inject.kind === 'query' ? 'query parameter' : 'header value'}: a line break in it, say`);
  }
  // The body changed: a digest of it is made again, of what goes out, and Content-Length is fetch's.
  if (out.field !== null) {
    for (const name of ['repr-digest', 'digest', 'content-md5']) headers.delete(name);
    if (headers.has('content-digest')) headers.set('content-digest', contentDigest(await bodyDigest(body!)));
  }
  // What authenticated the request goes no further than coffre: anywhere else the app put it, the request stops, as it is or in Basic's base64,
  // or, in a form or JSON body, decoded.
  if (secret !== null) {
    const leaked = [...headers].find(([, value]) => carries(value, secret.pattern)) ?? (carries(bytesOf(target.href), secret.pattern) ? ['URL'] : undefined)
      ?? ((body !== undefined && secret.pattern.test(LATIN1.decode(body))) || (out.field !== null && secret.pattern.test(out.field.rest)) ? ['body'] : undefined);
    if (leaked !== undefined) {
      return failure(400, `${secret.what} is somewhere ${credential.name} does not take its key: ${leaked[0] === 'URL' || leaked[0] === 'body' ? `the ${leaked[0]}` : `the ${leaked[0]} header`}`);
    }
  }

  // What the request carried: each secret value, and what the rule made of them, Basic's base64, as stored and as they went
  // out (`Headers` trims a value's surrounding whitespace), in each form an honest upstream may echo it in (`echoed`). A plain
  // value is no secret, and an upstream quotes an account's id back as a matter of course: it stays.
  // A path rule's, its segment and the value's encoded form, which the segment alone would not catch quoted apart from the text around it.
  const injected = inject.kind === 'header' ? [headers.get(inject.name)!] : inject.kind === 'form' || inject.kind === 'json' ? [render(inject.template, values)]
    : inject.kind === 'basic' ? [headers.get('authorization')!.slice('Basic '.length)]
    : inject.kind === 'sigv4' ? [headers.get('authorization')!] : inject.kind === 'path' ? [swap!.sent, swap!.encoded] : [target.searchParams.get(inject.name)!];
  const secrets = Object.entries(values).filter(([key]) => !plain.includes(key)).map(([, value]) => value);
  // What the rule made of them too, unless it is made of plain values alone: an account's id in a header is quoted back.
  const made = credential.keys.some((key) => !plain.includes(key)) ? injected : [];
  const known = [...secrets.flatMap((value) => [value, value.trim()]), ...made];
  const redact = redactor(known.flatMap(echoed));

  // A streamed body's refusal, once `scanned` stops it: the answer, whatever the upstream made of the broken request.
  const upload = streamed ? scanned(request.body!, Number(declared), secret, digest) : null;
  let upstream: Response;
  try {
    upstream = await (credential.egress ?? globalThis).fetch(target, {
      method: request.method,
      headers,
      body: upload?.body ?? body,
      redirect: 'manual',
      ...(streamed ? { duplex: 'half' } : {}),
    } as RequestInit);
  } catch (error) {
    const refused = upload?.refused() ?? null;
    if (refused !== null) return failure(400, refused);
    // The error may quote the request, its URL a query rule's value and all, an egress's more so: redacted, as its UTF-8 bytes.
    const said = binary(new TextEncoder().encode(error instanceof Error ? error.message : String(error)));
    const message = new TextDecoder().decode(Uint8Array.from(redact.whole(said), (char) => char.charCodeAt(0)));
    return failure(502, `${target.host} did not answer${credential.egress === undefined ? '' : ` through ${credential.name}'s egress`}: ${message}`);
  }
  // A redirect stays on the proxy: under the upstream, it is the proxy's URL for it; anywhere else, the app never learns of it.
  // Redacted as the bytes it came in, before a URL encodes them again; through a path rule, read as a URL first, so its
  // segment gets the app's back (`swappedBack`) and a swap never makes a scheme or a host of it, then redacted. Each byte
  // beyond ASCII as its `%XX` then, the same bytes to a URL, which would encode the character instead.
  const raw = upstream.headers.get('location');
  const location = raw === null ? null : swap === null ? redact.whole(raw) : raw.replace(/[\u0080-\u00ff]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  let at: string | null = null;
  if (location !== null) {
    // A `Location` no URL reads, `//` say, is nowhere under the upstream. A relative one is the app's URL's, not the
    // target's; one whose first segment has a raw colon (`bot123:AAE/getMe`) parses as a scheme, so it is not under the upstream.
    const to = URL.canParse(location, asSent) ? new URL(location, asSent) : null;
    const inside = to !== null && to.origin === credential.base.origin && (to.pathname === under || to.pathname.startsWith(`${under}/`));
    if (inside) {
      // The proxy's URL for it, a path rule's segment and a query rule's parameter, kept or not, the app's placeholder, for
      // it to follow and be let in.
      const moved = new URL(`${out.proxied}${swap === null ? to.pathname.slice(under.length) : swappedBack(to.pathname.slice(under.length), swap)}${to.search}`);
      if (inject.kind === 'query' && out.back !== null) moved.searchParams.set(inject.name, out.back);
      at = swap === null ? moved.href : redact.whole(moved.href);
    } else if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel();
      // Where to is the upstream's to say, and may hold anything: the refusal names only the credential.
      return failure(502, `the upstream redirected outside ${credential.name}'s, where its key does not go`);
    } else at = redact.whole(raw!);
    // Read as the app's HTTP client reads it, a path rule's Location holds no value either: a form no list above names
    // (`%3a` for `%3A`, `%41` for `A`, `%253A`), or an echo whose backslashes a parse made `/` (Go's `foo\u003cbar`), is a 502.
    if (swap !== null && at !== null) {
      const read = readAsURL(at);
      if (redactor(known.flatMap(echoed).flatMap((form) => [form, readAsURL(form)])).whole(read) !== read) {
        await upstream.body?.cancel();
        return failure(502, `the upstream's Location quoted what ${credential.name} sent, in a form coffre does not mask`);
      }
    }
  }
  const refused = upload?.refused() ?? null;
  if (refused !== null) {
    await upstream.body?.cancel();
    return failure(400, refused);
  }
  return redacted(upstream, redact, at);
}

/**
 * A URL as an HTTP client reads what it holds: decoded once, without the tabs and newlines a parser drops, and each
 * backslash a `/`, as a URL with a scheme like `https` reads it.
 */
function readAsURL(text: string): string {
  return bytesOf(text).replace(/[\t\n\r]/g, '').replaceAll('\\', '/');
}

/**
 * A redirect's path, under the upstream and parsed, with each segment that is the one a path rule sent, decoded once,
 * the app's again, so a redirect it follows goes through the proxy with its placeholder: `/bot123:AAE…/getMe`, or
 * `/bot123%3aAAE…/getMe` and `/bot%31%323:AAE…/getMe`, which decode to the same, is `/botcoffre_use_…/getMe`. Only the
 * path: a host or a scheme that happens to spell the value stays as it is. Any other copy of the value is then redacted.
 */
function swappedBack(path: string, { sent, app }: { sent: string; app: string }): string {
  const value = bytesOf(sent);
  return path
    .split('/')
    .map((segment) => (bytesOf(segment) === value ? app : segment))
    .join('/');
}

/**
 * The forms a string takes when an honest upstream quotes it back, in an
 * echo or an error message: as it is; URL-encoded both ways; HTML's and
 * XML's entities; and as a JSON string, as JavaScript writes one, as Go's
 * does (escaping <, > and &), as PHP's does (escaping /), and as Python's
 * does (every non-ASCII character as \uXXXX). This is the whole list
 * (docs/design/credential-proxy.md, section 4): a hostile upstream holds
 * the key anyway, and could encode it in any way at all.
 */
function echoed(value: string): string[] {
  const js = JSON.stringify(value).slice(1, -1);
  const go = js.replace(/[<>&]/g, (char) => `\\u00${char.charCodeAt(0).toString(16)}`);
  const python = js.replace(/[\u0080-\uffff]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
  const entities = (text: string, quote: string) => text.replace(/[&<>"']/g, (char) => (char === "'" ? quote : `&${{ '&': 'amp', '<': 'lt', '>': 'gt', '"': 'quot' }[char]};`));
  return [
    value,
    encodeURIComponent(value),
    new URLSearchParams({ v: value }).toString().slice(2),
    entities(value, '&#39;'),
    entities(value, '&apos;'),
    entities(value, '&#x27;'),
    ...[js, go, python].flatMap((json) => [json, json.replaceAll('/', '\\/')]),
  ];
}

/**
 * Bytes as a string of one character each, U+0000 to U+00FF: what the
 * redaction scans, in any charset. Each byte widened to a UTF-16 unit and
 * decoded natively, a twentieth of the CPU `String.fromCharCode` takes;
 * never `latin1`, which WHATWG decodes as windows-1252 (0x80 is €).
 */
function binary(bytes: Uint8Array): string {
  return UTF16.decode(Uint16Array.from(bytes));
}

const LATIN1 = new TextDecoder('latin1');

/** A string of one character a byte, U+0000 to U+00FF, as its bytes: `binary`'s inverse. */
function binaryBytes(text: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(text.length);
  for (let at = 0; at < text.length; at++) bytes[at] = text.charCodeAt(at);
  return bytes;
}

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * A streamed upload, as it passes: a handle anywhere in it, a chunk
 * boundary included, a length other than the one it declared, or, with
 * `digest`, bytes whose SHA-256 is not that one, and it stops, so the
 * upstream gets a broken request and stores nothing: the length goes with
 * it, and it never gets all of it. What a handle could still begin, and the
 * last byte at least, wait until that is known. On Workers, its declared
 * length goes with it (`FixedLengthStream`); Node's fetch sends the header
 * as given. `refused` says why it stopped, once it has.
 */
function scanned(body: ReadableStream<Uint8Array>, length: number, secret: Sending['secret'], digest: string | null): { body: ReadableStream<Uint8Array>; refused: () => string | null } {
  // The last bytes seen, held back: what a handle (or session token) could still be the start of, and the end, sent only once it is the length declared, and its digest.
  let held = new Uint8Array(0);
  const declared = declaredBody(length, digest);
  let refusal: string | null = null;
  const refuse = (why: string): never => {
    refusal = why;
    throw new Error(why);
  };
  const keep = Math.max(1, (secret?.length ?? 0) - 1);
  const checked = body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, out) {
        const past = declared.take(chunk);
        if (past !== null) refuse(past);
        const window = new Uint8Array(held.length + chunk.length);
        window.set(held);
        window.set(chunk, held.length);
        // Decoded natively, a tenth of the CPU `binary` takes: no byte past ASCII decodes to an ASCII character a secret holds.
        if (secret?.pattern.test(LATIN1.decode(window))) refuse(`${secret.what} is in the body`);
        const kept = Math.min(window.length, keep);
        if (window.length > kept) out.enqueue(window.slice(0, window.length - kept));
        held = window.slice(window.length - kept);
      },
      flush(out) {
        const ended = declared.end();
        if (ended !== null) refuse(ended);
        if (held.length > 0) out.enqueue(held);
      },
    }),
  );
  const Fixed = (globalThis as { FixedLengthStream?: new (length: number) => TransformStream<Uint8Array, Uint8Array> }).FixedLengthStream;
  return { body: Fixed === undefined ? checked : checked.pipeThrough(new Fixed(length)), refused: () => refusal };
}

/**
 * A body held to the length it declared and, with `digest`, to the SHA-256 its `Content-Digest` declares, as its parts
 * pass: `take` each, then `end`; each says why the body stops there, or null. A streamed body's through a credential
 * (`scanned`), and a raw message's (`fed`).
 */
function declaredBody(length: number, digest: string | null): { take(part: Uint8Array): string | null; end(): string | null } {
  let seen = 0;
  const hash = digest === null ? null : createHash('sha256');
  return {
    take: (part) => {
      seen += part.length;
      if (seen > length) return 'the body ran past the length it declared';
      hash?.update(part);
      return null;
    },
    end: () => (seen !== length ? 'the body ended short of the length it declared' : hash !== null && hash.digest('hex') !== digest ? 'the body is not what its Content-Digest says' : null),
  };
}

/** Whether a header's value carries what `pattern` finds, a handle say: as it is, or inside Basic authentication's base64. */
function carries(value: string, pattern: RegExp = HANDLE): boolean {
  if (pattern.test(value)) return true;
  const basic = /^Basic\s+(\S+)$/i.exec(value);
  if (basic === null) return false;
  try {
    return pattern.test(atob(basic[1]!));
  } catch {
    return false;
  }
}

/**
 * A URL with each `%XX` as its byte, one character each: what the handle,
 * which is ASCII, is looked for in. It never fails, as decoding the whole
 * as UTF-8 does on a `%FF`, which would leave `coffre%5Fuse_…` unseen.
 */
function bytesOf(text: string): string {
  return text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));
}

/**
 * The credential's values for a handle, opened now: one use, which the
 * vault decides and logs, naming the credential. Nothing is kept here; the
 * vault's memory (`memorySeconds`) is the only one, and through an outage
 * of the database, the rows it last answered this same ask from
 * (`outageSeconds`, D238).
 */
async function valuesFor(coffre: PluginContext, proxy: Proxy, handle: string, path: string, credential: Resolved): Promise<Opened> {
  const used = await coffre.use(handle, { path: readOf(proxy, path), keys: credential.keys, purpose: 'use', upstream: credential.name });
  return { values: used.values, plain: used.plain };
}

/**
 * The handle, where the app sends it: `x-coffre-handle` (the `credential(name)` helper), or where the credential takes
 * its key, a form or JSON rule's `field`, a path rule's segment in `relative`, the path under the upstream (null for none).
 */
function handleIn(request: Request, credential: Resolved, target: URL, relative: string | null, field: string | null = null): string | null {
  const explicit = request.headers.get('x-coffre-handle');
  if (explicit !== null) return HANDLE.exec(explicit)?.[0] ?? null;
  const inject = credential.inject;
  let slot: string | null = null;
  if (inject.kind === 'header') slot = request.headers.get(inject.name);
  if (inject.kind === 'query') slot = target.searchParams.get(inject.name);
  if (inject.kind === 'form' || inject.kind === 'json') slot = field;
  if (inject.kind === 'path') slot = relative === null ? null : appSegment(credential, relative);
  // The SDK's `Credential=<access key id>/…`: the handle, as the access key it signed with.
  if (inject.kind === 'sigv4') slot = /Credential=([^/,\s]+)\//.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
  if (inject.kind === 'basic') {
    const basic = /^Basic\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
    try {
      slot = basic === null ? null : atob(basic[1]!);
    } catch {
      slot = null;
    }
  }
  return slot === null ? null : handleOf(credential, slot);
}

/** The handle in what the app put where the credential takes its key: a shaped placeholder's slot is that shape exactly; the handle alone is found wherever the rule frames it. */
function handleOf(credential: Resolved, slot: string): string | null {
  return credential.shape === undefined ? (HANDLE.exec(slot)?.[0] ?? null) : (credential.shape.exec(slot)?.[1] ?? null);
}

/** The segment a credential's `path()` rule takes its key in, as the app sent it under the upstream (`relative`), decoded once: `botcoffre_use_…`; null for none. */
function appSegment(credential: Resolved, relative: string): string | null {
  const at = credential.framed === undefined ? -1 : pathSlot(credential.framed, relative);
  return at === -1 ? null : bytesOf(relative.split('/')[at]!);
}

function bearer(request: Request): string | null {
  return /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
}

/** A rule that fills a field of the body, a form's or a JSON object's. */
type BodyRule = Extract<Inject, { kind: 'form' | 'json' }>;

function inBody(inject: Inject): inject is BodyRule {
  return inject.kind === 'form' || inject.kind === 'json';
}

/**
 * A form or JSON rule's field in the request's body: what the app put there,
 * decoded; every other name and value in the body, decoded, a line each,
 * which nothing that authenticated the request may be in; and the body with
 * a value in the field's place, every other byte as it was.
 */
type Field = { value: string; rest: string; fill: (value: string) => Uint8Array<ArrayBuffer> };

/**
 * The field a form or JSON rule fills, in a body of the type it names, in
 * UTF-8 and not compressed, or the refusal: no field, the field twice,
 * which upstreams read differently, or a JSON field that holds no string.
 * Nothing of the body is quoted: the handle, or another secret, may be in it.
 */
function fieldIn(request: Request, body: Uint8Array | undefined, name: string, inject: BodyRule): Field | Response {
  const type = inject.kind === 'form' ? 'application/x-www-form-urlencoded' : 'application/json';
  if (body === undefined || body.length === 0) return failure(400, `${name} takes its key in the ${inject.name} field of the body: send one, ${type}, with a POST or the like`);
  const [media, ...parameters] = (request.headers.get('content-type') ?? '').split(';').map((part) => part.trim().toLowerCase());
  const charset = parameters.find((parameter) => parameter.startsWith('charset='))?.slice('charset='.length).replace(/^"(.*)"$/, '$1');
  if (media !== type || (charset !== undefined && charset !== 'utf-8') || !/^(identity)?$/i.test(request.headers.get('content-encoding') ?? '')) {
    return failure(415, `${name} takes its key in the ${inject.name} field of an ${type} body, UTF-8 and not compressed`);
  }
  const found = (inject.kind === 'form' ? formField : jsonField)(body, inject.name);
  return typeof found === 'string' ? failure(400, `the body ${found}, where ${name} takes its key`) : found;
}

/**
 * A field's name as some upstream's parser may read it, the same as
 * another's: up to a `[` (PHP's and qs's arrays, `refresh_token[0]`),
 * case folded (Go's JSON, `SECRET` and `ſecret`), and its letters and
 * digits alone (PHP's `.` and space, `refresh.token`). Another name alike
 * the field's is the field twice, which upstreams read differently.
 */
function alike(name: string): string {
  return name.split('[', 1)[0]!.toUpperCase().toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * A form's field, as WHATWG's parser reads one: `&`-separated pairs, the
 * name up to the first `=`, `+` a space and `%XX` a byte. Filled, the pair
 * keeps its name as written and takes the value form-encoded. Scanned as
 * bytes, one character each, so every other byte goes on as it came.
 */
function formField(bytes: Uint8Array, name: string): Field | string {
  const pairs = binary(bytes).split('&', MAX_FIELDS + 1);
  if (pairs.length > MAX_FIELDS) return `has more than ${MAX_FIELDS} fields`;
  const decoded = (part: string) => bytesOf(part.replace(/\+/g, ' '));
  // A name is the field's as written, or once decoded, where it has anything to decode; one `alike` it makes it twice.
  const names = pairs.map((pair) => {
    const equals = pair.indexOf('=');
    const key = equals === -1 ? pair : pair.slice(0, equals);
    return /[%+]/.test(key) ? decoded(key) : key;
  });
  const at = names.flatMap((key, index) => (key === name ? [index] : []));
  if (at.length === 0) return `has no ${name} field`;
  const as = alike(name);
  if (at.length > 1) return `has the ${name} field more than once`;
  if (names.filter((key) => alike(key) === as).length > 1) return `has a name alike ${name}, which some upstreams read as it`;
  const index = at[0]!;
  const pair = pairs[index]!;
  const equals = pair.indexOf('=');
  const written = equals === -1 ? pair : pair.slice(0, equals);
  const value = new TextDecoder().decode(binaryBytes(decoded(equals === -1 ? '' : pair.slice(equals + 1))));
  return {
    value,
    rest: decoded(pairs.filter((_, other) => other !== index).join('\n')),
    fill: (filled) => binaryBytes(pairs.map((other, at) => (at === index ? `${written}=${new URLSearchParams([['', filled]]).toString().slice(1)}` : other)).join('&')),
  };
}

/**
 * A JSON object's field, at its top, whose value is a string. Each string
 * in the document is found in order, keys included, with how deep it lies:
 * in valid JSON, a quote outside a string opens one. The scan stops at
 * `MAX_FIELDS` and `MAX_DEPTH`, before `JSON.parse` holds it to JSON at
 * all. Filled, the value's string is replaced, and nothing else is written
 * again: a number too long for a double keeps every digit.
 */
function jsonField(bytes: Uint8Array, name: string): Field | string {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return 'is no JSON';
  }
  let depth = 0;
  let from = 0;
  let strings = 0;
  // Whether the last string was the field's name, its value next; and where that value lies.
  let named = false;
  let found: { start: number; end: number; value: string } | null = null;
  const rest: string[] = [];
  const as = alike(name);
  const colon = /\s*:/y;
  /** Whether what lies between two strings takes the document past `MAX_DEPTH`. */
  const deeper = (gap: string): boolean => {
    for (const char of gap) {
      depth += char === '{' || char === '[' ? 1 : char === '}' || char === ']' ? -1 : 0;
      if (depth > MAX_DEPTH) return true;
    }
    return false;
  };
  let parsed: unknown;
  try {
    for (const match of text.matchAll(/"[^"\\]*(?:\\.[^"\\]*)*"/g)) {
      const gap = text.slice(from, match.index);
      if (deeper(gap)) return `nests deeper than ${MAX_DEPTH}`;
      // A name and a value each.
      if (++strings > 2 * MAX_FIELDS) return `has more than ${MAX_FIELDS} fields`;
      from = match.index + match[0].length;
      const string = match[0].includes('\\') ? (JSON.parse(match[0]) as string) : match[0].slice(1, -1);
      if (named) {
        if (!/^\s*:\s*$/.test(gap)) return `gives ${name} as no string`;
        found = { start: match.index, end: from, value: string };
        named = false;
      } else if (depth === 1 && ((colon.lastIndex = from), colon.test(text))) {
        // A name at the top: the field's, once; any other `alike` it makes it twice.
        if (string === name && found === null) named = true;
        else if (alike(string) === as) return string === name ? `has the ${name} field more than once` : `has a name alike ${name}, which some upstreams read as it`;
        else rest.push(string);
      } else rest.push(string);
    }
    if (deeper(text.slice(from))) return `nests deeper than ${MAX_DEPTH}`;
    // A byte order mark, which JSON.parse refuses and a parser of the web skips, kept where it is.
    parsed = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch {
    return 'is no JSON';
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return 'is no JSON object';
  if (named) return `gives ${name} as no string`;
  if (found === null) return `has no ${name} field at its top`;
  const { start, end, value } = found;
  return { value, rest: rest.join('\n'), fill: (filled) => new TextEncoder().encode(`${text.slice(0, start)}${JSON.stringify(filled)}${text.slice(end)}`) };
}

/** A form or JSON rule's body, read whole, and its field in it. */
type Fillable = { content: Carried; field: Field };

async function fillable(request: Request, credential: Resolved, inject: BodyRule): Promise<Fillable | Response> {
  const content = await carried(request, credential);
  if (content instanceof Response) return content;
  const field = fieldIn(request, content.body, credential.name, inject);
  return field instanceof Response ? field : { content, field };
}

/**
 * A form or JSON rule's body and field, or its refusal of the body, for the
 * stable URL, which needs the handle before it knows the route: read from a
 * copy, which the route sends if it goes through this credential. A route
 * through one that was not peeked, a header rule's, reads the request itself.
 * Null for any other rule.
 */
async function peekField(request: Request, credential: Resolved): Promise<Fillable | Response | null> {
  const inject = credential.inject;
  if (!inBody(inject)) return null;
  const copy = request.clone();
  try {
    return await fillable(copy, credential, inject);
  } finally {
    // A copy left unread would keep every byte the request's own body is read for: cancelled, and not waited for, as `boundedBody` does.
    if (!copy.bodyUsed) void copy.body?.cancel().catch(() => undefined);
  }
}

/** The body, read whole up to `max` bytes, and no further: null past it, the rest left unread. */
async function boundedBody(request: Request, max = MAX_BODY_BYTES): Promise<Uint8Array<ArrayBuffer> | undefined | null> {
  if (Number(request.headers.get('content-length') ?? '0') > max) return null;
  if (request.body === null) return undefined;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      // Not waited for: a copy's (`peekField`) settles only once the request's own body is done with too.
      void reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    body.set(chunk, at);
    at += chunk.byteLength;
  }
  return body;
}

/** `{KEY}` in a template, each the environment's value. */
function render(template: string, values: Record<string, string>): string {
  return template.replace(TEMPLATE_KEY, (_, key: string) => values[key]!);
}

/**
 * The upstream's answer, with each value the request carried replaced
 * wherever it shows: in headers, the reason phrase and a text body,
 * streamed, as bytes, holding back what a longer value could still
 * complete, so that one split across chunks, or one that begins another,
 * is caught too. A binary body passes as it is. Cookies stay with the upstream: one
 * set on coffre's origin could stand in for coffre's own. `location`, a
 * redirect's, is already the proxy's own URL for it.
 */
/** What redacts the forms of what a request carried (`echoed`): a whole string, or part of a stream (`scrub`). */
type Redactor = { scrub: (text: string, final: boolean) => { done: string; rest: string }; whole: (text: string) => string; any: boolean };

function redactor(values: string[]): Redactor {
  // Each form as the bytes an answer carries it in, UTF-8 or Latin-1, scanned as binary strings: lossless in any charset.
  const forms = values.filter((value) => value.length >= MIN_REDACTED).flatMap((value) => {
    const utf8 = binary(new TextEncoder().encode(value));
    return /^[\u0000-\u00ff]*$/.test(value) && value !== utf8 ? [utf8, value] : [utf8];
  });
  const secrets = [...new Set(forms)].sort((a, b) => b.length - a.length);
  // Leftmost, then longest: a value that begins another is replaced only once the longer one cannot match there.
  const pattern = secrets.length === 0 ? null : new RegExp(secrets.map((secret) => secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g');
  const longest = secrets[0]?.length ?? 0;
  /**
   * `text` with each value replaced, up to where the next part could still
   * change what matches: a match must start where the longest value, from
   * there, would lie whole in `text`, unless `final`. What follows is
   * returned unread, for the next part to complete.
   */
  const scrub = (text: string, final: boolean): { done: string; rest: string } => {
    if (pattern === null) return { done: text, rest: '' };
    const settled = final ? text.length : Math.max(0, text.length - longest + 1);
    let done = '';
    let from = 0;
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match !== null && match.index < settled; match = pattern.exec(text)) {
      done += text.slice(from, match.index) + REDACTED;
      from = match.index + match[0].length;
    }
    const cut = Math.max(from, settled);
    if (final) return { done: done + text.slice(from), rest: '' };
    // Of the rest, hold back only from where a value could still begin: a partial match, or a whole one a longer could extend.
    let hold = cut;
    while (hold < text.length && !secrets.some((secret) => secret.startsWith(text.slice(hold)) || text.startsWith(secret, hold))) hold += 1;
    return { done: done + text.slice(from, hold), rest: text.slice(hold) };
  };
  // A header's value and the reason phrase are already bytes, one character each, as fetch gives them.
  return { scrub, whole: (text) => scrub(text, true).done, any: pattern !== null };
}

function redacted(upstream: Response, { scrub, whole, any }: Redactor, location: string | null): Response {
  const headers = new Headers();
  for (const [name, value] of upstream.headers) if (!DROPPED_ANSWER.has(name)) headers.set(name, whole(value));
  if (location !== null) headers.set('location', location);
  // Never kept by a cache on the way: the next caller, with another handle or none, would get it without coffre's checks.
  for (const name of ['expires', 'pragma', 'age', 'surrogate-control', 'cdn-cache-control', 'cloudflare-cdn-cache-control']) headers.delete(name);
  headers.set('cache-control', 'no-store');
  // The upstream's document, on coffre's origin, runs nothing and reaches nothing: a sandbox is an origin of its own,
  // with no cookie of coffre's, and `setSecurityHeaders` keeps a policy that only narrows.
  headers.set('content-security-policy', "sandbox; default-src 'none'; frame-ancestors 'none'");
  headers.set('x-content-type-options', 'nosniff');
  const init = { status: upstream.status, statusText: whole(upstream.statusText), headers };
  const type = upstream.headers.get('content-type') ?? '';
  const text = /^text\/|json|xml|javascript|x-www-form-urlencoded|event-stream/i.test(type);
  if (upstream.body === null || !text || !any) return new Response(upstream.body, init);
  let carry = '';
  const bytes = (part: string) => Uint8Array.from(part, (char) => char.charCodeAt(0));
  const body = upstream.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, out) {
        const { done, rest } = scrub(carry + binary(chunk), false);
        carry = rest;
        if (done.length > 0) out.enqueue(bytes(done));
      },
      flush(out) {
        const last = whole(carry);
        if (last.length > 0) out.enqueue(bytes(last));
      },
    }),
  );
  return new Response(body, init);
}

function resolve(name: string, credential: Credential, insecure: boolean): Resolved {
  if (!NAME.test(name)) throw new Error(`credentialProxy: a credential's name is lowercase letters, digits and dashes; got ${JSON.stringify(name)}`);
  let base: URL;
  try {
    base = new URL(credential.upstream);
  } catch {
    throw new Error(`credentialProxy: ${name}'s upstream is a URL, https://api.example.com/v1; got ${JSON.stringify(credential.upstream)}`);
  }
  if (base.search !== '' || base.hash !== '' || base.username !== '' || base.password !== '') throw new Error(`credentialProxy: ${name}'s upstream is an origin and a path, with no query, fragment or user`);
  if (base.protocol !== 'https:' && !(insecure && base.protocol === 'http:')) {
    throw new Error(`credentialProxy: ${name}'s upstream is HTTPS${insecure ? ' or HTTP' : ': plain HTTP only with insecureUpstreams, for a local fake'}`);
  }
  if (!insecure && privateHost(base.hostname)) throw new Error(`credentialProxy: ${name}'s upstream ${base.hostname} is a private address, which only insecureUpstreams, for a local fake, reaches`);
  const inject = credential.inject;
  const templates = inject.kind === 'basic' ? [inject.user, inject.password]
    : inject.kind === 'sigv4' ? [inject.accessKeyId, inject.secretAccessKey, ...(inject.sessionToken === undefined ? [] : [inject.sessionToken])]
    : [inject.template];
  if ((inject.kind === 'header' || inject.kind === 'query') && !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(inject.name)) throw new Error(`credentialProxy: ${name} injects into ${JSON.stringify(inject.name)}, which is no header or parameter name`);
  if (inBody(inject) && !/^(?=.*[A-Za-z0-9])[A-Za-z0-9_.-]{1,128}$/.test(inject.name)) throw new Error(`credentialProxy: ${name} fills the field ${JSON.stringify(inject.name)}, which is no field name: letters, digits and _.-, a letter or digit among them, at the top of the body`);
  const framed = inject.kind === 'path' ? (typeof inject.template === 'string' ? PATH_TEMPLATE.exec(inject.template) : null) : undefined;
  if (framed === null) throw new Error(`credentialProxy: ${name}'s path() is one segment naming one key once, path('bot{TELEGRAM_BOT_TOKEN}'), the text around it letters, digits and -._~!$&'()*+,=:@; got ${JSON.stringify((inject as { template: unknown }).template)}`);
  // It may shape the path's one segment, which a slash would make two.
  if (framed !== undefined && credential.placeholder?.kind === 'prefix' && credential.placeholder.prefix.includes('/')) throw new Error(`credentialProxy: ${name}'s prefix() has a /, and its path() rule takes the placeholder in one segment`);
  if (inject.kind === 'sigv4' && (!/^[a-z0-9-]{1,32}$/.test(inject.region) || !/^[a-z0-9-]{1,32}$/.test(inject.service))) throw new Error(`credentialProxy: ${name} signs for a region and a service, eu-west-3 and s3`);
  const keys = [...new Set(templates.flatMap((template) => [...template.matchAll(TEMPLATE_KEY)].map((match) => match[1]!)))];
  if (keys.length === 0) throw new Error(`credentialProxy: ${name}'s rule names no key: write it as {KEY}, as header('x-api-key', '{SCHUMANN_API_KEY}')`);
  if (credential.baseUrl !== undefined) {
    throw new Error(`credentialProxy: ${name}'s baseUrl is gone in 0.9, and \`coffre run\` no longer sets ${String(credential.baseUrl)}: point the app's own config at the proxy's stable URL for ${name}, <publicUrl>/use/${name}, the same for every environment`);
  }
  if (credential.standIn !== undefined) throw new Error(`credentialProxy: ${name}'s standIn is called placeholder in 0.10: rename it`);
  if (credential.identifiers !== undefined) {
    throw new Error(`credentialProxy: ${name}'s identifiers are gone in 0.10: mark each key plain instead, coffre set <env>/<KEY> <value> --plain, and remove identifiers`);
  }
  // A binding the Worker lacks is `undefined`, the key still there: refused, never the global fetch in its place.
  if ('egress' in credential && typeof credential.egress?.fetch !== 'function') {
    throw new Error(credential.egress === undefined
      ? `credentialProxy: ${name}'s egress is undefined, as a Worker's binding is when wrangler.jsonc lacks it: add the binding, or remove egress. ${name}'s requests never leave without it`
      : `credentialProxy: ${name}'s egress has no fetch method: give it a VPC Service binding, a service binding, or { fetch(url, init) }`);
  }
  const methods = credential.methods?.map((method) => method.toUpperCase());
  if (credential.paths !== undefined && credential.paths.some((path) => !path.startsWith('/'))) throw new Error(`credentialProxy: ${name}'s paths start with /`);
  const shape = credential.placeholder === undefined && framed === undefined ? undefined : placeholderShape(name, credential.placeholder, inject);
  limited(name, credential.limit);
  return { ...credential, ...(methods === undefined ? {} : { methods }), ...(shape === undefined ? {} : { shape }), ...(framed === undefined ? {} : { framed: { before: framed[1]!, after: framed[3]! } }), name, base, keys };
}

/**
 * The slot a shaped placeholder fills, as a pattern: the rule's template, the
 * placeholder where its key goes, the handle its one group. Only a header, a
 * query parameter, a body's field or a path's segment that carries one key, once, takes a shaped placeholder:
 * Basic's pair, and an AWS key pair, are no one token to shape. A path rule's slot is always one exactly, the bare
 * handle where no placeholder shapes it (`undefined`).
 */
function placeholderShape(name: string, placeholder: Placeholder | undefined, inject: Inject): RegExp {
  if (placeholder !== undefined && placeholder.kind !== 'jwt' && placeholder.kind !== 'prefix') throw new Error(`credentialProxy: ${name}'s placeholder is jwt(…) or prefix(…)`);
  if (inject.kind === 'basic' || inject.kind === 'sigv4' || [...inject.template.matchAll(TEMPLATE_KEY)].length !== 1) {
    throw new Error(`credentialProxy: ${name}'s placeholder shapes the one key a header, query, form, JSON or path rule carries, header('authorization', 'Bearer {TOKEN}'), not a ${inject.kind === 'basic' || inject.kind === 'sigv4' ? `${inject.kind}() rule` : 'template with several keys, or one twice'}`);
  }
  if (placeholder?.kind === 'jwt' && (!Array.isArray(placeholder.claims) || placeholder.claims.some((claim) => typeof claim !== 'string' || claim === '' || claim === 'exp'))) {
    throw new Error(`credentialProxy: ${name}'s jwt() names the claims it copies from the real token, each a string; exp is the handle's end, never copied`);
  }
  if (placeholder?.kind === 'prefix' && !/^[A-Za-z0-9._~+/:=-]{1,64}$/.test(placeholder.prefix)) throw new Error(`credentialProxy: ${name}'s prefix() is up to 64 letters, digits and ._~+/:=-, sk_test_; got ${JSON.stringify(placeholder.prefix)}`);
  const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const handle = `(${HANDLE.source})`;
  const token = placeholder === undefined ? handle : placeholder.kind === 'jwt' ? `[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.${handle}` : `${escape(placeholder.prefix)}${handle}`;
  const [before, after] = inject.template.split(TEMPLATE_KEY).filter((_, at) => at % 2 === 0);
  return new RegExp(`^${escape(before!)}${token}${escape(after!)}$`);
}

function checkTunnel(name: string, tunnel: Tunnel, credentials: Map<string, Resolved>, insecure: boolean): Tunnel {
  if (!NAME.test(name)) throw new Error(`credentialProxy: a tunnel's name is lowercase letters, digits and dashes; got ${JSON.stringify(name)}`);
  if (credentials.has(name)) throw new Error(`credentialProxy: ${name} names a credential and a tunnel`);
  if (tunnel.kind !== 'postgres') throw new Error(`credentialProxy: tunnel ${name} is postgres(…), the only kind there is`);
  if (!KEY.test(tunnel.key)) throw new Error(`credentialProxy: tunnel ${name} names the key that holds its URL, DATABASE_URL`);
  // A binding the Worker lacks is `undefined`, the key still there: refused, never the platform's TCP in its place.
  if ('connect' in tunnel && typeof tunnel.connect?.connect !== 'function') {
    throw new Error(tunnel.connect === undefined
      ? `credentialProxy: tunnel ${name}'s connect is undefined, as a Worker's binding is when wrangler.jsonc lacks it: add the binding, or remove connect. ${name} never dials without it`
      : `credentialProxy: tunnel ${name}'s connect has no connect method: give it a VPC Network binding`);
  }
  // A network binding reaches a whole private network: the tunnel names the hosts in it the URL may name.
  if (tunnel.connect !== undefined && (tunnel.hosts ?? []).length === 0) throw new Error(`credentialProxy: tunnel ${name} dials through a network binding, and names the hosts it reaches there: hosts: ['10.0.1.5']`);
  // Each as it is dialled, 127.1 as 127.0.0.1, db.acme.example. as db.acme.example: what the URL's host is held to.
  const hosts = tunnel.hosts?.map((host) => canonicalHost(new URL(`http://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}`).hostname));
  if (!insecure && tunnel.connect === undefined && hosts?.some(privateHost)) throw new Error(`credentialProxy: tunnel ${name} names a private host, which only insecureUpstreams, or a network binding (connect), reaches`);
  return { ...tunnel, ...(hosts === undefined ? {} : { hosts }) };
}

function checkSigner<T extends Signer | Cipher>(name: string, signer: T, credentials: Map<string, Resolved>, tunnels: Map<string, Tunnel>, signers: Map<string, Signer>, what: 'signer' | 'verifier' | 'cipher', verifiers: Map<string, Hmac> = new Map()): T {
  if (!NAME.test(name)) throw new Error(`credentialProxy: a ${what}'s name is lowercase letters, digits and dashes; got ${JSON.stringify(name)}`);
  const taken = credentials.has(name) ? 'credential' : tunnels.has(name) ? 'tunnel' : signers.has(name) ? 'signer' : verifiers.has(name) ? 'verifier' : null;
  if (taken !== null) throw new Error(`credentialProxy: ${name} names a ${taken} and a ${what}`);
  const kinds = { signer: ['private-key', 'hmac'], verifier: ['hmac'], cipher: ['aes-gcm'] }[what];
  if (!kinds.includes(signer.kind)) throw new Error(`credentialProxy: ${what} ${name} is ${{ signer: 'privateKey(…) or hmac(…)', verifier: 'hmac(…), the only kind there is', cipher: 'aesGcm(…), the only kind there is' }[what]}`);
  if (!KEY.test(signer.key)) throw new Error(`credentialProxy: ${what} ${name} names the key that holds its ${{ hmac: 'secret, YOUSIGN_WEBHOOK_SECRET', 'private-key': 'private key, DFNS_PRIVATE_KEY', 'aes-gcm': 'key, BILLING_TOKEN_KEY' }[signer.kind]}`);
  if (signer.kind === 'aes-gcm') {
    // AES-256-GCM alone, a 12-byte IV and a 16-byte tag: an option it does not know is refused, never ignored.
    const unknown = Object.keys(signer).find((option) => !['kind', 'key', 'keyEncoding', 'maxBytes', 'limit'].includes(option));
    if (unknown !== undefined) throw new Error(`credentialProxy: cipher ${name}'s aesGcm() takes keyEncoding, maxBytes and limit, and is AES-256-GCM alone; got ${unknown}`);
    if (signer.keyEncoding !== 'hex' && signer.keyEncoding !== 'base64' && signer.keyEncoding !== 'base64url') throw new Error(`credentialProxy: cipher ${name}'s aesGcm() reads its key's 32 bytes as hex, base64 or base64url: keyEncoding`);
    if (signer.maxBytes !== undefined && !(Number.isInteger(signer.maxBytes) && signer.maxBytes >= 1 && signer.maxBytes <= MAX_MESSAGE_BYTES)) throw new Error(`credentialProxy: cipher ${name}'s maxBytes is a whole number of bytes, ${sized(MAX_MESSAGE_BYTES)} at most`);
  }
  if (signer.kind === 'hmac') {
    // HMAC-SHA256 alone, written as these schemes write it: a key it does not know is refused, never ignored.
    const unknown = Object.keys(signer).find((option) => !['kind', 'key', 'encoding', 'prefix', 'keyEncoding', 'maxBytes', 'limit'].includes(option));
    if (unknown !== undefined) throw new Error(`credentialProxy: ${what} ${name}'s hmac() takes encoding, prefix, keyEncoding, maxBytes and limit, and signs with SHA-256 alone; got ${unknown}`);
    // A signer's message past 1 MiB goes raw; a verifier's is JSON alone.
    const most = what === 'signer' ? MAX_RAW_MESSAGE_BYTES : MAX_MESSAGE_BYTES;
    if (signer.maxBytes !== undefined && !(Number.isInteger(signer.maxBytes) && signer.maxBytes >= 1 && signer.maxBytes <= most)) throw new Error(`credentialProxy: ${what} ${name}'s maxBytes is a whole number of bytes, ${sized(most)} at most`);
    if (signer.encoding !== 'hex' && signer.encoding !== 'base64' && signer.encoding !== 'base64url') throw new Error(`credentialProxy: ${what} ${name}'s hmac() writes its signatures in hex, base64 or base64url`);
    if (signer.keyEncoding !== undefined && signer.keyEncoding !== 'hex' && signer.keyEncoding !== 'base64' && signer.keyEncoding !== 'base64url') throw new Error(`credentialProxy: ${what} ${name}'s hmac() reads its key's value as hex, base64 or base64url, or as its UTF-8 bytes without keyEncoding`);
    if (signer.prefix !== undefined && (typeof signer.prefix !== 'string' || !/^[\x21-\x7e]{1,32}$/.test(signer.prefix))) throw new Error(`credentialProxy: ${what} ${name}'s prefix is up to 32 printable characters, sha256=`);
  }
  limited(name, signer.limit);
  // The app holds one value for a key, and a signer's is the handle as it is.
  const shaped = [...credentials.values()].find((credential) => credential.placeholder !== undefined && credential.keys.includes(signer.key));
  if (shaped !== undefined) throw new Error(`credentialProxy: ${shaped.name} and ${name} read ${signer.key} with different placeholders, and the app holds one value for it`);
  return signer;
}

function checkListed(option: 'generate', listed: Record<string, 'all' | readonly string[]>): Map<string, 'all' | readonly string[]> {
  for (const [path, keys] of Object.entries(listed)) {
    if (!/^[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/.test(path)) throw new Error(`credentialProxy: ${option} names environments by path, market/local; got ${JSON.stringify(path)}`);
    if (keys !== 'all' && (!Array.isArray(keys) || keys.some((key) => !KEY.test(key)))) throw new Error(`credentialProxy: ${option}['${path}'] is 'all' or a list of keys`);
  }
  return new Map(Object.entries(listed));
}

/**
 * A host as a URL parsed it (every caller's has been: 127.1 and 2130706433
 * are 127.0.0.1 there, [0:0::1] is ::1), without brackets or trailing dots,
 * which the parser keeps on a name: `localhost.` is localhost.
 */
function canonicalHost(host: string): string {
  return host.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.+$/, '');
}

/** Whether a host is an IP address, not a name a resolver could point anywhere. */
function address(host: string): boolean {
  const name = canonicalHost(host);
  return name.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(name);
}

/** Whether a host is a private, loopback or link-local address, or localhost, however it is written. */
function privateHost(host: string): boolean {
  const name = canonicalHost(host);
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(name);
  if (v4 !== null) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
  }
  if (!name.includes(':')) return false;
  // 6to4 carries an IPv4 address in its next 32 bits: 2002:a00:1:: is 10.0.0.1's.
  const [first, high, low] = hextets(name);
  if (first === 0x2002) return privateHost(`${high! >> 8}.${high! & 255}.${low! >> 8}.${low! & 255}`);
  // ::/16 holds loopback, the unspecified address and IPv4 written as IPv6 (::ffff:a00:1, ::7f00:1); 64:ff9b:: is NAT64's; fe80::/10 is link-local, fec0::/10 site-local.
  return /^(?:::|0:)/.test(name) || /^f[cd]/.test(name) || /^fe[89a-f]/.test(name) || name.startsWith('64:ff9b:');
}

/** An IPv6 address as a URL writes it (hex groups, `::` once at most), as its eight groups. */
function hextets(address: string): number[] {
  const [head, tail] = address.split('::').map((part) => (part === '' ? [] : part.split(':')));
  const groups = tail === undefined ? head! : [...head!, ...Array<string>(8 - head!.length - tail.length).fill('0'), ...tail];
  return groups.map((group) => parseInt(group, 16));
}

function answer(body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

/** coffre's own refusal, told apart from the upstream's by its header. */
function failure(status: number, message: string, reason?: string): Response {
  return new Response(JSON.stringify({ error: 'credential_proxy', message, ...(reason === undefined ? {} : { reason }) }), {
    status,
    headers: {
      'content-type': 'application/json', 'cache-control': 'no-store', 'coffre-proxy': 'refused',
      // coffre could not answer for a moment (`errorResponse`): the app's client hears when to ask again.
      ...(status === 503 && reason === 'unavailable' ? { 'retry-after': UNAVAILABLE_RETRY_AFTER } : {}),
    },
  });
}

/**
 * A credential's or signer's limit as the gate counts it, per workload
 * (section 8.1): `stripe per minute` and `stripe per day`, made for the
 * service once authentication says which, when the limit is a function.
 */
function countsOf(name: string, limit: Limits | undefined): Pick<WorkloadAt, 'counts'> {
  if (limit === undefined) return {};
  const counts = (given: Limit | undefined) => {
    const checked = checkLimit(name, given);
    return [
      ...(checked.perMinute === undefined ? [] : [{ key: `${name} per minute`, windowMs: 60_000, most: checked.perMinute }]),
      ...(checked.perDay === undefined ? [] : [{ key: `${name} per day`, windowMs: 86_400_000, most: checked.perDay }]),
    ];
  };
  return { counts: typeof limit === 'function' ? (service: string) => counts(limit(service)) : counts(limit) };
}

/** A limit as configured, or as its function gave it for a service: whole numbers of uses, at least 1, or none. */
function checkLimit(name: string, limit: Limit | undefined): Limit {
  if (limit === undefined) return {};
  const whole = (value: unknown) => value === undefined || (typeof value === 'number' && Number.isInteger(value) && value >= 1);
  if (typeof limit !== 'object' || limit === null || Object.keys(limit).some((key) => key !== 'perMinute' && key !== 'perDay') || !whole(limit.perMinute) || !whole(limit.perDay)) {
    throw new Error(`credentialProxy: ${name}'s limit is { perMinute?, perDay? }, each a whole number of uses, at least 1`);
  }
  return limit;
}

/** A limit as configured: one checked now, or a function, whose answers are checked as it gives them. */
function limited(name: string, limit: Limits | undefined): void {
  if (typeof limit !== 'function') checkLimit(name, limit);
}

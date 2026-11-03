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
 * redacted from its answer. A handle opens values for its person as a read
 * does, by their grants and its scope, logged once per credential about
 * every 45 seconds while used (`cacheSeconds`), never handed back. The app holds as they are the
 * values its person may read, plain and secret ones, never a sensitive one
 * (docs/design/credential-proxy.md, section 2).
 */
import { createHash } from 'node:crypto';

import { CoffreError } from '@coffre/client';
import { bodyDigest, bodyLine, contentDigest, declaredDigest, MAX_DIGESTED_BODY, UNSIGNED_BODY } from '@coffre/client/dpop';
import { constraintsAllow, CREDENTIAL_NAME, type GateCount } from '@coffre/core/identity';
import { recipeProblem } from '@coffre/core/recipe';
import { isUnavailable } from '@coffre/db/dialect';

import type { ProxyAllow, ProxyDefinition, ProxyHmac, ProxyInject, ProxyLimit, ProxyMethod } from '@coffre/core/vault';
import { withProxyCode, type ProxyCodeItem } from '../proxy-code.ts';
import { UNAVAILABLE_RETRY_AFTER } from '../api/errors.ts';
import { WorkloadRefused, type CoffrePlugin, type Connect, type PickKeys, type PluginContext, type PluginCounts, type RouteAsked, type RouteUsed, type SocketSession, type Used, type WorkloadAt, type WorkloadUse } from '../plugins.ts';
import { definitionKeys, TEMPLATE_KEY as SHARED_TEMPLATE_KEY, USE_DEADLINE_MS, type DecidedItem, type ProxyRoute } from '@coffre/core/vault';
import { database, tunnel as tunnelPostgres, type Database } from './postgres-tunnel.ts';
import { hmacSign, hmacVerify, type Encoding } from './hmac.ts';
import { signWith, SigningKeyError } from './sign.ts';
import { presignV4, signV4 } from './sigv4.ts';
import { type AllowEntry, alike, allows, bytesOf, climbs, FIELD_NAME, HANDLE_CLAIM, MAX_MESSAGE_BYTES, methodsFor, PARAMETER_NAME, PLACEHOLDER_PREFIX, readPattern, requestSegments, SIGNATURE_PREFIX } from '@coffre/core/proxy-match';
import { workersSocket, type WorkersSocket } from '../workers-socket.ts';
import { logged } from '../logged.ts';

/** How a credential's values reach its upstream: in a header, a query parameter, a field of a form or JSON body, Basic authentication, or an AWS signature. */
export type Inject =
  | { kind: 'header'; name: string; template: string }
  | { kind: 'query'; name: string; template: string }
  | { kind: 'form' | 'json'; name: string; template: string }
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

/**
 * Which requests a credential takes: these methods, on this path under its
 * upstream, each any unless set, and at least one set. An entry's empty
 * `methods` is any method, as the Proxy tab's, unlike the legacy
 * `methods: []` beside `paths`, which takes none. A plain path is
 * a prefix by segments, `/companies` for `/companies/42` and never
 * `/companiesX`; `*` stands for exactly one segment, `/files/*`, and `**`,
 * last, for the rest of the path, `/files/**`; a trailing slash, a segment
 * below that a server reads as one, `/files/` for `/files/a` and never
 * `/files/` or `/files/...`. Each segment is matched decoded: `docu%6Dents`
 * is `documents`. No regexes.
 */
export type Allow = { methods?: readonly string[]; path?: string };

/** One credential: its upstream, how its keys reach it, and what of it a caller may ask. */
export type Credential = {
  /** Where its requests go, `https://api.schumann.example/v1`: `/use/<name>/<path>` goes to `<upstream>/<path>`, and nowhere else. */
  upstream: string;
  /**
   * How its keys reach the upstream: one rule, or several, applied in
   * order: `[header('authorization', 'Bearer {STRIPE_KEY}'), header('stripe-account', '{STRIPE_ACCOUNT}')]`.
   * One rule per header, parameter or field; one `basic()` at most, and
   * none beside a rule setting `authorization`; one `sigv4()` at most, last,
   * which signs the headers the rules before it set, and beside no rule
   * setting `authorization`, an `x-amz-` header or a field of the body.
   */
  inject: Inject | readonly Inject[];
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
  /** The shape of what the app holds for its key, `jwt(…)` or `prefix(…)`, where a header, query, form or JSON rule carries that one key: the handle as it is, unless set. */
  placeholder?: Placeholder;
  /**
   * Which requests it takes, each entry its methods and path (`Allow`):
   * `[{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }]`.
   * A request any entry allows goes; any, unless set. Not beside `methods`
   * and `paths`, which say the same in one entry per path.
   */
  allow?: readonly Allow[];
  /** The methods it may be used with, `['GET', 'POST']`; any, unless set. Read as `allow`'s entries' methods. */
  methods?: readonly string[];
  /** The paths under `upstream` it may be used on, each as an `allow` entry's path, `['/companies']`; any, unless set. A trailing slash, `/companies/`, takes what is below it and not `/companies` itself; a `*` is itself, as before 0.16, never a glob. */
  paths?: readonly string[];
  /** The environments it serves, by path, `['market/prod']`; every one, unless set. Its name is the deployment's in every environment all the same. */
  environments?: readonly string[];
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

/** A database the proxy tunnels to: the key that holds its URL, the hosts that URL may name, what it dials through, and the environments it serves (every one, unless set). */
export type Tunnel = { kind: 'postgres'; key: string; hosts?: readonly string[]; connect?: Network; environments?: readonly string[] };

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
export function postgres(key: string, options: { hosts?: readonly string[]; connect?: Network; environments?: readonly string[] } = {}): Tunnel {
  return { kind: 'postgres', key, ...options };
}

/** A key coffre signs with for the app, which never holds it: a private key, `privateKey(…)`, or an HMAC secret, `hmac(…)`. */
export type Signer = { kind: 'private-key'; key: string; limit?: Limits; environments?: readonly string[] } | Hmac;

/**
 * A private key the app signs with through coffre, `credential(name).sign(message)`:
 * `privateKey('DFNS_PRIVATE_KEY')`. The environment's value is a PKCS#8
 * PEM, Ed25519, P-256 or RSA; the app holds the handle where it was, and
 * each signature is one use in the log. `limit`, as a credential's, counts
 * a workload's signatures: `privateKey('DFNS_PRIVATE_KEY', { limit: { perMinute: 10 } })`.
 */
export function privateKey(key: string, options: { limit?: Limits; environments?: readonly string[] } = {}): Signer {
  return { kind: 'private-key', key, ...options };
}

export type { Encoding };

/** An HMAC-SHA256 secret coffre signs or checks signatures with for the app: the key that holds it, how its signatures are written, and how often a workload may use it. */
export type Hmac = { kind: 'hmac'; key: string; encoding: Encoding; prefix?: string; maxBytes?: number; limit?: Limits; environments?: readonly string[] };

/**
 * An HMAC-SHA256 secret the app never holds: an inbound webhook's, among
 * `verifiers`, which the app asks whether a signature is the secret's
 * (`credential(name).verify(body, signature)`), or a key of the app's own
 * among `signers`, which also signs (`credential(name).sign(message)`).
 * The key is the environment's value, as its UTF-8 bytes; the signature
 * is written in `encoding`, `hex`, `base64` or `base64url`, after
 * `prefix`: `hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' })`
 * checks Yousign's `x-yousign-signature-256`. `maxBytes` is the longest
 * message it signs or checks, 64 KiB unless set, 1 MiB at most: such a
 * body costs about 5 ms of CPU, of a Worker's 10 ms on the Free plan.
 * `limit` and `environments`, as a credential's.
 */
export function hmac(key: string, options: { encoding: Encoding; prefix?: string; maxBytes?: number; limit?: Limits; environments?: readonly string[] }): Hmac {
  return { kind: 'hmac', key, ...options };
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
  /**
   * How often an open tunnel checks its handle still stands, ending when it
   * does not: 60 seconds unless set. A workload's tunnel stops within 15
   * seconds of a freeze or a revocation, or this if it is less.
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
   * Whether Owners, and whoever a role gives `proxy.edit`, may write this
   * deployment's proxy definitions per environment in the UI (0.16,
   * docs/design/proxy-ui.md): off unless set. Code's definitions win a name
   * both use, in every environment.
   */
  editable?: boolean;
  /**
   * How long a credential's values, once opened for a handle, serve its
   * next requests from this process's memory: 60 seconds unless set, 0 for
   * a read per request. Each opening is one entry in the log; a revoked
   * handle's values serve no longer than this. In its last quarter (15
   * seconds at most), one request at a time opens them again while the
   * others are served, so a lapse does not become a vault call per request.
   */
  cacheSeconds?: number;
};

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/**
 * A key a rule's template names, `{SCHUMANN_API_KEY}`: core's one reading of templates, which the vault's save stores
 * beside each UI item, so that the proxy's startup check, a UI route's use and the log's replay read one key list.
 */
const TEMPLATE_KEY = SHARED_TEMPLATE_KEY;
/** A handle, wherever the app put it: alone, or inside a header the upstream's own scheme frames. */
const HANDLE = /coffre_use_[A-Za-z0-9_-]{43}/;
const HANDLES = new RegExp(HANDLE.source, 'g');
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

/** One rule of a credential's, read: the keys it names, and, with a placeholder, what its slot must be, the handle its one group. */
type Rule = Inject & { keys: readonly string[]; shape?: RegExp };

/** A rule that fills a field of the body, a form's or a JSON object's. */
type BodyRule = Extract<Rule, { kind: 'form' | 'json' }>;

type SigV4Rule = Extract<Rule, { kind: 'sigv4' }>;

/**
 * A credential as the proxy reads it: its rules in order, the body's among
 * them and its SigV4 one apart; its allow list (null: everything); every
 * key it names.
 */
type Resolved = Omit<Credential, 'inject' | 'allow'> & {
  name: string;
  base: URL;
  keys: string[];
  rules: readonly Rule[];
  body: readonly BodyRule[];
  sigv4: SigV4Rule | undefined;
  allowed: readonly AllowEntry[] | null;
};

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
  const messageBytes = Math.max(...[...signers.values(), ...verifiers.values()].map(longest), MESSAGE_BYTES);
  const recheckMs = (options.recheckSeconds ?? 60) * 1000;
  if (!(recheckMs > 0 && recheckMs <= 3_600_000)) throw new Error('credentialProxy: recheckSeconds is above 0, an hour at most');
  const cacheMs = (options.cacheSeconds ?? 60) * 1000;
  if (!Number.isFinite(cacheMs) || cacheMs < 0 || cacheMs > 3_600_000) throw new Error('credentialProxy: cacheSeconds is between 0 and 3600');
  // Values a handle opened, by handle, environment and credential: settled values only, never a pending read (AGENTS.md, "What an isolate keeps").
  const cache = new Map<string, Kept>();
  const handles = new Map<string, { paths: readonly (string | null)[] | null; until: number }>();
  const groups = new Map<string, Group>();
  const editable = options.editable === true;
  const ui: UiState = { items: new Map(), last: new Map(), kept: new Map() };
  return withProxyCode({
    name: 'credential-proxy',
    routes: {
      prefix: '/use',
      fetch: async (request, coffre) => {
        try {
          return await serve(request, coffre, { credentials, groups, tunnels, signers, verifiers, messageBytes, insecure: options.insecureUpstreams === true, recheckMs, generate, cacheMs, cache, handles, editable, ui });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code, error.retryAfter);
          throw error;
        }
      },
      socket: async (request, coffre) => {
        try {
          return await open(request, coffre, { credentials, groups, tunnels, signers, verifiers, messageBytes, insecure: options.insecureUpstreams === true, recheckMs, generate, cacheMs, cache, handles, editable, ui });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code, error.retryAfter);
          throw error;
        }
      },
    },
  }, {
    editable: options.editable === true,
    insecureUpstreams: options.insecureUpstreams === true,
    names: [...new Set([...credentials.keys(), ...tunnels.keys(), ...signers.keys(), ...verifiers.keys()])].sort(),
    items: codeItems(options.credentials, tunnels, signers, verifiers),
    cacheSeconds: cacheMs / 1000,
  });
}

/** A group of tunnel sessions: how to end each, its last answer (settled, never pending), and its timers: its checks', the one its bytes stop by, and its end's. */
type Group = {
  ends: Set<() => void>;
  stands: boolean;
  timers: ReturnType<typeof setInterval>[];
  watchdog: ReturnType<typeof setTimeout> | undefined;
  expiry: ReturnType<typeof setTimeout> | undefined;
};

/** How long a group's check of the vault may take before it counts as a no: the vault has that long to answer. */
const RECHECK_DEADLINE_MS = 10_000;
/** How long a workload's tunnel runs past a freeze or a revocation at most (section 8.2): its statement is asked again within it. */
const WORKLOAD_RECHECK_MS = 15_000;

type Proxy = {
  credentials: Map<string, Resolved>;
  /** The open tunnel sessions, by handle or session, environment and tunnel, each group checked as one (`watch`). */
  groups: Map<string, Group>;
  tunnels: Map<string, Tunnel>;
  signers: Map<string, Signer>;
  /** HMAC secrets that check signatures and make none. */
  verifiers: Map<string, Hmac>;
  /** The longest message any signer or verifier takes. */
  messageBytes: number;
  insecure: boolean;
  recheckMs: number;
  generate: Map<string, 'all' | readonly string[]>;
  cacheMs: number;
  cache: Map<string, Kept>;
  /** The environments each handle was made for, by path, kept for `cacheSeconds` as its values are (`madeFor`). A workload's are its statement's to say. */
  handles: Map<string, { paths: readonly (string | null)[] | null; until: number }>;
  /** Whether the environments' UI definitions serve the names code lacks (`editable`), and this isolate's copies of them. */
  editable: boolean;
  ui: UiState;
};

/**
 * This isolate's UI definitions (0.16, T186 PR C; docs/design/proxy-ui.md, sections 3 and 4): each item a vault answer
 * brought, by its digest, and read as a code credential is (`resolve`), once; the digest each reading last answered,
 * and when (the copy, which only saves the item's bytes: CopyFromVault); and the values each caller's use opened, by
 * caller and the reading the vault took (`keptAt`), each kept with the item it was decided on, which a cache hit sends by
 * (BoundToDefinition). Settled
 * values only, bounded.
 */
type UiState = {
  items: Map<string, { definition: ProxyDefinition; resolved: Resolved | string | null }>;
  last: Map<string, { digest: string; confirmed: number }>;
  kept: Map<string, UiKept>;
};

/** A UI use's values, kept: until when, the item they were decided on (its digest), the reading and the place it was at. */
type UiKept = Opened & { until: number; digest: string; definition: ProxyDefinition; reading: RouteUsed['reading']; path: string };

/** The most of each that an isolate keeps: past it, a map starts over. */
const UI_KEPT = 10_000;

/** A credential's values, opened, and which keys of it are plain, no secret: what the answer's redaction leaves as it is. */
type Opened = { values: Record<string, string>; plain: readonly string[] };

/**
 * Opened values as the cache keeps them: until when they serve, from when
 * they are asked for again (`refreshFrom`), and until when no other
 * request asks (`hold`), a time, never the pending read: one asking that
 * never answers, its caller gone, holds no one off for long.
 */
type Kept = Opened & { until: number; refreshFrom: number; hold?: number };

/**
 * How long before its values stop serving a cache entry is asked for
 * again, by one request at a time while the others are served it: a
 * quarter of `cacheSeconds`, 15 s at most.
 */
function refreshWindow(cacheMs: number): number {
  return Math.min(cacheMs / 4, 15_000);
}

/** How long one request asking again holds the others off, at most: a slow or abandoned one is followed by another before the entry ends. */
const REFRESH_ATTEMPT_MS = 5000;

/** How soon after a refresh the vault did not answer another request asks. */
const REFRESH_RETRY_MS = 1000;

/** What the vault says when it refuses, which ends an entry; anything else, it did not answer. */
const REFUSED = new Set([401, 403, 404, 409]);

async function serve(request: Request, coffre: PluginContext, proxy: Proxy): Promise<Response> {
  const url = new URL(request.url);
  // The raw segments after `/use`: the place and credential decoded, the rest sent on as the app wrote it.
  const raw = url.pathname.slice('/use'.length).split('/').slice(1);
  if (raw.length === 0 || (raw.length === 1 && raw[0] === '')) {
    // What `coffre run` asks first: whether this instance has the proxy. It holds no secret.
    if (request.method === 'GET') return answer({ proxy: 'coffre', credentials: [...proxy.credentials.keys()] });
    // A workload that reaches one environment presigns and signs without naming it.
    return request.method === 'POST' ? compute(request, coffre, proxy, null) : failure(405, 'GET only');
  }
  let place: string[];
  try {
    place = raw.slice(0, 3).map(decodeURIComponent);
  } catch {
    return failure(400, 'the path is not valid percent-encoding');
  }
  const stable = proxy.credentials.get(place[0]!);
  // Whether a name may be a handle's UI route for this request: under `editable`, of a handle's request (no session, no
  // service binding, whose calls `uiWorkloadForward` takes), and a name code lacks (R66).
  const uiServes = (name: string | undefined) => proxy.editable && coffre.useRoute !== undefined && !coffre.binding && sessionToken(request) === null
    && name !== undefined && CREDENTIAL_NAME.test(name) && !coded(proxy, name);
  // A workload's: `/use/<credential>/<path>` whenever `<credential>` is one, for the one environment it reaches, and
  // `/use/<project>/<env>/<credential>/<path>` otherwise. Nothing tells a session's environments by name before its
  // one statement, so the URL alone decides; a handle's are below.
  const named = stable === undefined && raw.length >= 3 ? proxy.credentials.get(place[2]!) : undefined;
  if (stable !== undefined || named !== undefined) {
    const used = await workloadForward(request, coffre, proxy, stable !== undefined ? null : `${place[0]}/${place[1]}`, (stable ?? named)!, raw.slice(stable !== undefined ? 1 : 3), url.search);
    if (used !== null) return used;
  }
  // A name code lacks, of a workload's request (a session's or a service binding's call): the environment's UI route,
  // under `editable` (T186 PR C2b). `/use/<a>/<b>` stays the plan or compute for a workload, as before.
  if (proxy.editable && coffre.useRoute !== undefined && stable === undefined && named === undefined && raw.length !== 2) {
    const used = await uiWorkloadForward(request, coffre, proxy, raw, place, url);
    if (used !== null) return used;
  }
  // A name code lacks, of a handle's request: the environment's UI definitions, under `editable` (T186 PR C). Code wins
  // a name it holds (R66): only a URL whose name code lacks gets here, its readings as section 6's table says. Never a
  // service binding's call, which carries no handle, before any copy kept for a handle is looked at (review r2 of #467).
  if (proxy.editable && coffre.useRoute !== undefined && stable === undefined && sessionToken(request) === null && !coffre.binding) {
    if (raw.length === 1 || (raw.length >= 3 && !coded(proxy, place[2]!))) return uiForward(request, coffre, proxy, raw, place, url, true);
    // `/use/<a>/<b>`, the plan or compute, and `/use/<a>/<b>/<code's name>/…`, code's credential, when the handle was
    // made for `<a>/<b>`; otherwise route `<a>` at `/<b>…` (section 6). The handle's made-for list decides, the handle
    // found outside the body or in it.
    if (!coded(proxy, place[0]!)) {
      const handle = await uiHandle(request, url);
      if (handle instanceof Response) return handle;
      const paths = handle === null ? null : await madeFor(coffre, proxy, handle);
      if (handle !== null && !(paths ?? []).includes(`${place[0]}/${place[1]}`)) return uiForward(request, coffre, proxy, raw, place, url, false, handle);
    }
  }

  // A form or JSON rule's body, as the stable URL read it to find the handle: what the route then sends, read once.
  const peeked = new Map<Resolved, Fillable>();
  // `/use/<credential>/<path>`, the stable URL, for the environment the handle was made for; unless `<a>/<b>` is an
  // environment the handle was made for, which `/use/<project>/<env>/…` names below. Never a guess: the URL and the handle decide.
  if (stable !== undefined) {
    const named = place[2] === undefined ? undefined : proxy.credentials.get(place[2]);
    // A form or JSON rule's refusal of the body, which says more than that no handle came: the named credential's, if both refuse.
    let refused: Response | null = null;
    const found = async (credential: Resolved) => {
      const read = await peekField(request, credential);
      if (read instanceof Response) refused = read;
      else if (read !== null) peeked.set(credential, read);
      return handleIn(request, credential, url, read instanceof Response ? [] : read?.fields.values);
    };
    const first = await found(stable);
    if (first instanceof Response) return first;
    const second = first ?? (named === undefined ? null : await found(named));
    if (second instanceof Response) return second;
    // Where code's credential takes no handle, a URL whose third segment may name the handle's environment's UI route:
    // the handle wherever that route's item may take it, `x-openai-key` say, which the made-for list below then weighs
    // (review r3 of #467).
    const third = place[2];
    const outside = second ?? HANDLE.exec(bearer(request) ?? '')?.[0] ?? (raw.length >= 3 && uiServes(third) ? await uiHandle(request, url) : null);
    if (outside instanceof Response) return outside;
    const handle = outside;
    if (handle === null) return refused ?? failure(401, `send the handle \`coffre run\` gave your app where ${stable.name} takes its key, or as x-coffre-handle`);
    // The environment the handle was made for, the URL's: null where the URL names one of the handle's instead.
    const routed = async (): Promise<string | Response | null> => {
      const paths = await madeFor(coffre, proxy, handle);
      if (raw.length !== 1 && (paths ?? []).includes(`${place[0]}/${place[1]}`)) return null;
      if (paths === null) return failure(409, `this handle was made before coffre 0.9 and names no environment: run the app with \`coffre run\` again, or name the environment, ${coffre.publicUrl}/use/<project>/<environment>/${stable.name}`);
      // As many as it was made for, a deleted one too: what the handle names decides, never what is left of it.
      const live = paths.filter((path) => path !== null);
      if (paths.length > 1) {
        const urls = live.map((path) => `${coffre.publicUrl}/use/${path}/${stable.name}`).join(' or ');
        return failure(409, `this handle stands in for ${paths.length} environments, and the stable URL is for a run of one: name it${live.length === 0 ? '' : `, ${urls}`}`);
      }
      if (live.length === 0) return failure(409, 'the environment this handle was made for is gone');
      return live[0]!;
    };
    // With no cache, and a URL whose third segment names nothing of the proxy's, so that it is the stable URL whatever
    // the handle was made for, unless `<a>/<b>` is that environment: its one key in the vault's one call, which finds
    // the environment itself (T145). Anything else it serves not so, as below.
    // The handle's environment named, its credential one code lacks: the environment's UI route, or none. Its body still
    // to read: code's credential read a copy (reviews r3 and r4 of #467).
    const placed = () => (uiServes(third) ? uiForward(request, coffre, proxy, raw, place, url, true, handle) : noCredential(third!));
    const direct = proxy.cacheMs === 0 && coffre.useMadeFor !== undefined && stable.keys.length === 1
      && (raw.length === 1 || (third !== undefined && !proxy.credentials.has(third) && !proxy.signers.has(third) && !proxy.verifiers.has(third)));
    if (direct) {
      const unless = [...(raw.length === 1 ? [] : [`${place[0]}/${place[1]}`]), ...proxy.generate.keys()];
      return forward(request, coffre, proxy, { unless, routed: async () => (await routed()) ?? placed() }, stable, raw.slice(1), url.search, peeked.get(stable));
    }
    const route = await routed();
    if (route instanceof Response) return route;
    if (route !== null) return forward(request, coffre, proxy, route, stable, raw.slice(1), url.search, peeked.get(stable));
    // `<a>/<b>` is the handle's environment, and `<a>` only happens to name code's credential: the third segment is the
    // credential, code's (below) or the environment's UI route (review r2 of #467).
    if (uiServes(third)) return uiForward(request, coffre, proxy, raw, place, url, true, handle);
  }
  if (raw.length === 2) {
    if (request.method === 'POST') return compute(request, coffre, proxy, `${place[0]}/${place[1]}`);
    if (request.method !== 'GET') return failure(405, 'GET for the plan, POST to presign or sign');
    return plan(request, coffre, proxy, `${place[0]}/${place[1]}`);
  }
  if (raw.length < 3) return failure(404, 'name /use/<credential>/<path>, or /use/<project>/<environment>/<credential>/<path>');
  const credential = proxy.credentials.get(place[2]!);
  if (credential === undefined && proxy.signers.has(place[2]!)) return failure(404, `${place[2]} is a signer, which reaches no upstream: credential(${JSON.stringify(place[2])}).sign(message)`);
  if (credential === undefined && proxy.verifiers.has(place[2]!)) return failure(404, `${place[2]} is a verifier, which reaches no upstream: credential(${JSON.stringify(place[2])}).verify(message, signature)`);
  if (credential === undefined) return noCredential(place[2]!);
  return forward(request, coffre, proxy, `${place[0]}/${place[1]}`, credential, raw.slice(3), url.search, peeked.get(credential));
}

/** Whether code defines `name`, of any kind: a name code holds is never a UI item's (R66). */
function coded(proxy: Proxy, name: string): boolean {
  return proxy.credentials.has(name) || proxy.signers.has(name) || proxy.verifiers.has(name) || proxy.tunnels.has(name);
}

/**
 * The one handle a request carries for a UI route, before any item says where it rides: by its shape outside the body
 * (`handlesOutside`), else in the body, read from a copy (64 KiB at most), which leaves the request's own unread. Two
 * different handles: 400.
 */
async function uiHandle(request: Request, url: URL): Promise<string | null | Response> {
  const outside = handlesOutside(request, url);
  if (outside.size > 1) return failure(400, 'the request carries two different handles: a route takes one');
  if (outside.size === 1) return outside.values().next().value!;
  if (request.body === null || request.method === 'GET' || request.method === 'HEAD') return null;
  const copy = request.clone();
  try {
    const bytes = await boundedBody(copy, MAX_FIELD_BODY);
    const inside = bytes == null ? new Set<string>() : handlesInBody(bytes, bodyKind(request));
    if (inside.size > 1) return failure(400, 'the request carries two different handles: a route takes one');
    return inside.values().next().value ?? null;
  } finally {
    if (!copy.bodyUsed) void copy.body?.cancel().catch(() => undefined);
  }
}

/**
 * The handles a request carries outside its body, found by their shape before any definition says where one rides:
 * in any header (a custom one such as `x-api-key`, SigV4's `Credential=`, Basic's pair decoded) or the query. The
 * item the use decides on then checks that the handle sits where it takes its key (`sendAs`).
 */
function handlesOutside(request: Request, url: URL): Set<string> {
  // As sent and as decoded: `?key=coffre%5Fuse_…` is the handle `handleIn` reads from `searchParams` (review r7 of #467).
  const found = new Set<string>(url.search.match(HANDLES) ?? []);
  for (const [name, value] of url.searchParams) for (const handle of `${name}\n${value}`.match(HANDLES) ?? []) found.add(handle);
  for (const [name, value] of request.headers) {
    for (const handle of value.match(HANDLES) ?? []) found.add(handle);
    if (name !== 'authorization') continue;
    // Each Basic pair, where `Headers` joined two Authorization headers (base64 has no comma).
    for (const part of value.split(',')) {
      const basic = /^\s*Basic\s+(\S+)\s*$/i.exec(part);
      if (basic === null) continue;
      try {
        for (const handle of atob(basic[1]!).match(HANDLES) ?? []) found.add(handle);
      } catch {
        // Not base64: no pair, no handle.
      }
    }
  }
  return found;
}

/**
 * The handles a body carries: its bytes as sent, and the body as the one rule kind its Content-Type lets read it
 * (`bodyKind`, as `fieldsIn` does) decodes it (review r7 of #467): a form's pairs (`client_secret=coffre%5Fuse_…`),
 * or each JSON string with its escapes undone (`"coffre\u005fuse_…"`). Never the other kind's: a JSON note holding
 * `coffre%5Fuse_…` is text, which `handleIn` reads as text, not a second handle (review r8 of #467).
 */
function handlesInBody(bytes: Uint8Array, kind: BodyRule['kind'] | null): Set<string> {
  const found = new Set<string>(LATIN1.decode(bytes).match(HANDLES) ?? []);
  if (kind === null) return found;
  const text = new TextDecoder().decode(bytes);
  if (kind === 'form') {
    for (const [name, value] of new URLSearchParams(text)) for (const handle of `${name}\n${value}`.match(HANDLES) ?? []) found.add(handle);
    return found;
  }
  for (const { raw } of jsonStrings(text)) {
    if (!raw.includes('\\')) continue;
    try {
      for (const handle of (JSON.parse(raw) as string).match(HANDLES) ?? []) found.add(handle);
    } catch {
      // No JSON string: its bytes counted as sent.
    }
  }
  return found;
}

/**
 * A UI route's request, a handle's (T186 PR C; docs/design/proxy-ui.md, sections 3 and 6): the handle found by its
 * shape outside the body (`handlesOutside`), else in the body (read from a copy, 64 KiB at most), before anything
 * else, as no definition is needed for it; then the route use, the vault's one call, which reads the URL both
 * ways and answers the values with the item they were decided on (SentAsDecided); or the values this caller's use kept
 * for this URL, with the item they were decided on (BoundToDefinition). Every check a code credential's request takes
 * runs on that item, the target rebuilt from its upstream, and the handle must sit where it takes its key.
 *
 *   Bo's handle, `GET /use/openai/models`, openai saved in market/dev's Proxy tab   the vault's call, then api.openai.com/v1/models
 *   the same within cacheSeconds, an Owner having pointed openai elsewhere since      no call: api.openai.com still, its values' item
 */
async function uiForward(request: Request, coffre: PluginContext, proxy: Proxy, raw: readonly string[], place: readonly string[], url: URL, placeReading: boolean, found?: string): Promise<Response> {
  // Only a reading whose name can be a UI route's: `/use/s3/bucket/report.csv` is `s3` at `/bucket/report.csv`, never a
  // route `report.csv` at `s3/bucket`; and never a name code holds (R66).
  const named = placeReading && raw.length >= 3 && CREDENTIAL_NAME.test(place[2]!) && !coded(proxy, place[2]!) ? { path: `${place[0]}/${place[1]}`, route: place[2]! } : null;
  const stable = CREDENTIAL_NAME.test(place[0]!) && !coded(proxy, place[0]!) ? place[0]! : null;
  if (named === null && stable === null) return noCredential(place[0]!);
  const handle = found ?? (await uiHandle(request, url));
  if (handle instanceof Response) return handle;
  if (handle === null) return failure(401, `send the handle \`coffre run\` gave your app where ${named?.route ?? stable} takes its key, or as x-coffre-handle`);
  // An upstream an Owner typed goes out through the runtime's public fetch, which on Node dials no private address
  // whatever the name resolves to (section 5; review r2 of #467); `insecureUpstreams`, for local fakes, through the
  // global one. A runtime without it sends none, asked before the use, so no use is logged for nothing.
  let through: Egress | undefined;
  if (!proxy.insecure) {
    if (coffre.publicFetch === undefined) return failure(503, `${named?.route ?? stable}: this runtime has no fetch that checks where an upstream resolves, which a route saved in the Proxy tab is sent through`, 'unavailable', '60');
    through = { fetch: coffre.publicFetch };
  }
  const now = Date.now();
  // When the values may be sent by at the latest: kept, until they lapse; decided now, within the use's deadline, as
  // the vault decided them for a request sent then. A body that comes later is sent with none (P1, review r1 of #467).
  let sendBy: number;
  let kept = keptFor(proxy, handle, named, stable, now);
  if (kept === undefined) {
    // The copies this isolate holds for either reading, by digest: the answer leaves out an item that is one of them.
    const readings = [...(named === null ? [] : [`n\n${named.path}\n${named.route}`]), ...(stable === null ? [] : [`s\n${handle}\n${stable}`])];
    // What a copy confirmed within `cacheSeconds` refuses (its upstream, path and method) stands, no call made; an older
    // copy's refusal does not: the use's answer decides (docs/design/proxy-ui.md, section 3, "The app's checks"). Only the
    // copy of the reading the vault would take: the place reading where the handle's kept made-for list names `<a>/<b>`,
    // else the stable one (section 6); none when that list is not kept, as another handle's place copy says nothing of
    // this one's URL, nor of whether it is a handle at all: only this handle's own copy, or a place copy its checked
    // made-for list chose, refuses before the vault has seen it (review r2 of #467).
    const known = proxy.handles.get(handle);
    const paths = known !== undefined && known.until > now ? known.paths : undefined;
    const reading = paths === undefined
      ? (named === null ? 1 : null)
      : named !== null && (paths ?? []).includes(named.path) ? 0 : stable !== null ? 1 : null;
    const last = reading === null ? undefined : proxy.ui.last.get(readings[named === null ? 0 : reading]!);
    const copy = last === undefined ? undefined : proxy.ui.items.get(last.digest);
    if (last !== undefined && copy !== undefined && copy.definition.kind === 'route' && now - last.confirmed < proxy.cacheMs) {
      const read = uiCredential(proxy, last.digest, copy.definition);
      if (typeof read !== 'string') {
        const aimed = aim(request, read, raw.slice(reading === 0 ? 3 : 1), url.search);
        if (aimed instanceof Response) return aimed;
      }
    }
    const digests = readings.flatMap((key) => {
      const last = proxy.ui.last.get(key);
      return last === undefined || !proxy.ui.items.has(last.digest) ? [] : [last.digest];
    });
    const used = await coffre.useRoute!(handle, { named, stable, digests, logged: { ui: true }, refuses: (item) => {
      const definition = itemOf(proxy, item);
      return definition === null ? null : unrouted(definition);
    } });
    const definition = itemOf(proxy, used.item);
    if (definition === null) return failure(503, `${used.item.name}: this isolate's copy of its definition is gone; ask again`, 'moved', '1');
    remember(proxy.ui.last, used.reading === 'named' ? readings[0]! : `s\n${handle}\n${stable!}`, { digest: used.item.digest, confirmed: now });
    kept = { values: used.values, plain: used.plain, digest: used.item.digest, definition, reading: used.reading, path: used.environment.path, until: Math.min(now + proxy.cacheMs, Date.parse(used.expiresAt)) };
    if (proxy.cacheMs > 0) remember(proxy.ui.kept, keptAt(handle, used.reading === 'named' ? { named: named! } : { stable: stable! }), kept);
    sendBy = Math.min(now + Math.max(proxy.cacheMs, USE_DEADLINE_MS), Date.parse(used.expiresAt));
  } else {
    sendBy = kept.until;
  }
  // Refused before its use opened anything (`refuses`): no item kept is any other kind.
  if (kept.definition.kind !== 'route') return failure(404, unrouted(kept.definition)!);
  const credential = uiCredential(proxy, kept.digest, kept.definition);
  if (typeof credential === 'string') return failure(503, credential, 'unavailable', '1');
  const rest = kept.reading === 'named' ? raw.slice(3) : raw.slice(1);
  return sendAs(request, coffre, credential, [...rest], url.search, handle, { values: kept.values, plain: kept.plain }, `${kept.path}/${credential.name}`, sendBy, through);
}

/**
 * Why a UI item serves no request at `/use`, or null for a route: a signer, verifier or tunnel reaches no upstream.
 *
 *   signer `signing`   signing is a signer, which reaches no upstream: credential("signing").sign(message)
 */
function unrouted(definition: ProxyDefinition): string | null {
  const { kind, name } = definition;
  if (kind === 'route') return null;
  return `${name} is a ${kind}, which reaches no upstream${kind === 'tunnel' ? ': `coffre run` tunnels to it' : `: credential(${JSON.stringify(name)}).${kind === 'signer' ? 'sign(message)' : 'verify(message, signature)'}`}`;
}

/**
 * Where a handle's kept values are, by the reading the vault took, never by the URL: the place reading's by place and
 * route, the stable one's by route, so every path under a route finds them (review r4 of #467).
 */
function keptAt(handle: string, reading: { named: { path: string; route: string } } | { stable: string }): string {
  return 'named' in reading ? `${handle}\nn\n${reading.named.path}/${reading.named.route}` : `${handle}\ns\n${reading.stable}`;
}

/**
 * The values this handle's use kept for the reading the vault would take of this URL (section 6's table), unlapsed:
 * the place reading's where it has them; else the stable one's, which only a handle of one environment has (several
 * get 409), and which stands for every URL whose `<a>/<b>` is not that environment, the place reading's there.
 *
 *   market/dev's handle, kept stable `openai`   /use/openai/models/gpt-a, /use/openai/models/gpt-b: that one copy
 *                                               /use/market/dev/openai/models: not it (the place reading)
 */
function keptFor(proxy: Proxy, handle: string, named: { path: string; route: string } | null, stable: string | null, now: number): UiKept | undefined {
  const fresh = (at: string): UiKept | undefined => {
    const kept = proxy.ui.kept.get(at);
    if (kept === undefined || kept.until > now) return kept;
    proxy.ui.kept.delete(at);
    return undefined;
  };
  const place = named === null ? undefined : fresh(keptAt(handle, { named }));
  if (place !== undefined) return place;
  const copy = stable === null ? undefined : fresh(keptAt(handle, { stable }));
  return copy !== undefined && copy.path !== named?.path ? copy : undefined;
}

/** The definition of an item a use decided on: the answer's, or this isolate's copy of that digest, which the answer left out. */
function itemOf(proxy: Proxy, item: DecidedItem): ProxyDefinition | null {
  if (item.definition !== null) {
    remember(proxy.ui.items, item.digest, { definition: item.definition, resolved: null });
    return item.definition;
  }
  return proxy.ui.items.get(item.digest)?.definition ?? null;
}

/**
 * A UI route's definition as the proxy reads a code credential (`resolve`), once per digest: its rules, allow list and
 * placeholder as code would write them. An egress is a binding only code declares, none yet (PR C keeps them for
 * later): a route naming one answers 503, never a direct fetch in its place.
 */
function uiCredential(proxy: Proxy, digest: string, definition: ProxyRoute): Resolved | string {
  const held = proxy.ui.items.get(digest);
  if (held?.resolved != null) return held.resolved;
  let resolved: Resolved | string;
  if (definition.egress !== null) {
    resolved = `${definition.name} leaves through the egress ${definition.egress}, which this deployment's code does not declare`;
  } else {
    try {
      resolved = resolve(definition.name, credentialOf(definition), proxy.insecure);
    } catch (error) {
      resolved = `${definition.name}: its definition is not one this proxy takes (${(error as Error).message})`;
    }
  }
  remember(proxy.ui.items, digest, { definition, resolved });
  return resolved;
}

/** A UI route, written as code writes a credential: the same rules, allow list, placeholder and limit. */
function credentialOf(route: ProxyRoute): Credential {
  const inject = route.inject.map((rule): Inject => {
    switch (rule.kind) {
      case 'basic': return basic(rule.user, rule.password);
      case 'sigv4': return sigv4({ accessKeyId: rule.accessKeyId, secretAccessKey: rule.secretAccessKey, ...(rule.sessionToken === null ? {} : { sessionToken: rule.sessionToken }), region: rule.region, service: rule.service });
      case 'header': return header(rule.name, rule.template);
      default: return { kind: rule.kind, name: rule.name, template: rule.template };
    }
  });
  const limit: Limit = { ...(route.limit.perMinute === null ? {} : { perMinute: route.limit.perMinute }), ...(route.limit.perDay === null ? {} : { perDay: route.limit.perDay }) };
  return {
    upstream: route.upstream, inject,
    ...(route.allow === null ? {} : { allow: route.allow.map((entry) => ({ ...(entry.methods.length === 0 ? {} : { methods: entry.methods }), path: entry.path })) }),
    ...(route.placeholder === null ? {} : { placeholder: route.placeholder.kind === 'jwt' ? jwt({ claims: route.placeholder.claims }) : prefix(route.placeholder.prefix) }),
    ...(Object.keys(limit).length === 0 ? {} : { limit }),
  };
}

/** `map` holding `value` at `key`, a map starting over past `UI_KEPT` entries. */
function remember<T>(map: Map<string, T>, key: string, value: T): void {
  if (map.size >= UI_KEPT && !map.has(key)) map.clear();
  map.set(key, value);
}

/** A credential the URL names that the deployment's proxy has not. */
const noCredential = (name: string) => failure(404, `this instance has no credential ${JSON.stringify(name)}: its deployment's credentialProxy names them`);

/**
 * The environments `handle` was made for, by path as they are named now,
 * null for one deleted: asked of coffre, and kept for `cacheSeconds`, as
 * the values they open are, so a rename reaches the stable URL within the
 * minute. Null for a handle of 0.8.
 */
async function madeFor(coffre: PluginContext, proxy: Proxy, handle: string): Promise<readonly (string | null)[] | null> {
  const now = Date.now();
  const kept = proxy.handles.get(handle);
  if (kept !== undefined && kept.until > now) return kept.paths;
  const { paths, expiresAt } = await coffre.handle(handle);
  if (proxy.cacheMs > 0) {
    // A handful of handles in a dev loop: past a thousand, the oldest go.
    if (proxy.handles.size >= 1000) for (const [old, entry] of proxy.handles) if (entry.until <= now || proxy.handles.size >= 1000) proxy.handles.delete(old);
    proxy.handles.set(handle, { paths, until: Math.min(now + proxy.cacheMs, Date.parse(expiresAt)) });
  }
  return paths;
}

/** The signers and verifiers, by name: each a key the app holds the handle for, which coffre computes with. */
function keyed(proxy: Proxy): [string, Signer][] {
  return [...proxy.signers, ...proxy.verifiers];
}

/**
 * What `coffre run` gives the app for an environment: each credential whose
 * keys it holds, its keys as the handle; the values its person may read,
 * plain ones and secrets, as they are, never a sensitive one; and what the
 * app reads for `credential(name)`. Each key the environment holds that none
 * of these covers, a sensitive one the proxy does not use, is named in
 * `left`, for `coffre run` to say.
 */
async function plan(request: Request, coffre: PluginContext, proxy: Proxy, path: string): Promise<Response> {
  // A workload's proof signs the request's content as every request under /use does: here, no body.
  const caller = await workloadOf(request, coffre, { place: path, credential: null, body: await bodyDigest(new Uint8Array(0)) });
  if (caller instanceof Response) return caller;
  if (caller !== null) return answering(caller, () => workloadPlan(coffre, proxy, caller, caller.path ?? path));
  const handle = bearer(request);
  if (handle === null) return failure(401, 'send the handle `coffre run` made as a bearer token');
  // The place's UI items, before the read that picks what the app is given: their keys are the handle too. Asked of the
  // environment; the read below says whether it reads the person's personal config instead (`generate`'s `@me`), which
  // serves none: decided on the read's own answer, so no config made between the two calls gets the base environment's
  // routes (review r5 of #467). On each attempt's answer: a read the vault retries (`AccessChanged`) may resolve the base
  // environment after a personal config, deleted between the two, and its items are the base's again (review r6).
  const items = await uiPlanItems(coffre, proxy, handle, path);
  const none = { routes: [], held: new Set<string>() };
  let ui = items;
  // The credentials the environment holds every key of, of those that serve it, code's and the UI's routes: their keys
  // are placeholders, whoever may read them.
  const covering = (keys: readonly string[]) => [...[...proxy.credentials.values()].filter((credential) => serves(credential, path)), ...ui.routes]
    .filter((credential) => credential.keys.every((key) => keys.includes(key)));
  const tunnels = [...proxy.tunnels].filter(([, tunnel]) => serves(tunnel, path));
  const signers = keyed(proxy).filter(([, signer]) => serves(signer, path));
  // What the read resolved, for what `coffre run` generates below.
  let resolved: Parameters<PickKeys>[1] = [];
  let personal = false;
  // Its plain keys, which say where each credential's handle rides (`riding`).
  let plainKeys: ReadonlySet<string> = new Set();
  // One read, which opens what the app holds as it is, chosen from the rows it opens: a sensitive value is never one,
  // and the vault refuses the read if it were.
  const held = await coffre.use(handle, {
    path: readOf(proxy, path),
    purpose: 'expose',
    logged: { plan: true },
    keys: (environment, rows) => {
      resolved = rows;
      personal = environment.personal;
      ui = personal ? none : items;
      const using = covering(rows.map((row) => row.key));
      const covered = new Set([...using.flatMap((credential) => credential.keys), ...tunnels.map(([, tunnel]) => tunnel.key), ...signers.map(([, signer]) => signer.key), ...ui.held]);
      // What the proxy fills in itself, a tunnel's URL or a signer's or verifier's handle, never the value the environment holds; and a
      // credential's plain keys where giving them would leave the handle nowhere the proxy finds it: S3's access key id,
      // which the SDK sends as `Credential=`, or every key of a header's. Those stay placeholders, as secrets do.
      const asTheyAre = new Set(rows.filter((row) => row.plain).map((row) => row.key));
      plainKeys = asTheyAre;
      const filled = new Set([
        ...tunnels.map(([, tunnel]) => tunnel.key),
        ...signers.map(([, signer]) => signer.key),
        ...ui.held,
        ...using.filter((credential) => !carriesHandle(credential.rules, asTheyAre)).flatMap((credential) => credential.keys),
      ]);
      return rows
        // A plain value is no secret, wherever it is held; a secret the proxy does not use, its person reads where it is held.
        .filter((row) => (row.plain && !filled.has(row.key)) || (!covered.has(row.key) && !row.sensitive && row.reads))
        .map((row) => row.key);
    },
  });
  const env: Record<string, string> = Object.create(null);
  const credentials: Record<string, string> = {};
  const covered = new Set<string>();
  const using = covering(held.keys);
  // Two that read one key with different placeholders, as startup refuses of code's alone: the app holds one value for
  // it, which one of them would refuse. Code's and the UI's routes together, as this environment serves them (review r2
  // of #467).
  for (const one of using) {
    const other = using.find((two) => two !== one && two.keys.some((key) => one.keys.includes(key)) && JSON.stringify(two.placeholder) !== JSON.stringify(one.placeholder));
    if (other !== undefined) {
      throw new CoffreError(409, 'conflict', `${one.name} and ${other.name} read ${one.keys.find((key) => other.keys.includes(key))} with different placeholders in ${held.environment.path}, and the app holds one value for it: give them the same placeholder, in the Proxy tab or the deployment's code`);
    }
    // And a signer's or verifier's key, whose value is the handle as it is (`checkSigner`'s rule for code's): a shaped
    // route reading it would be given the bare handle below, and refuse it (review r3 of #467).
    const signer = one.placeholder === undefined ? undefined : signers.find(([, two]) => one.keys.includes(two.key));
    if (signer !== undefined) {
      throw new CoffreError(409, 'conflict', `${one.name} and ${signer[0]} read ${signer[1].key} with different placeholders in ${held.environment.path}, and the app holds one value for it: a signer's is the handle as it is, so drop ${one.name}'s placeholder`);
    }
  }
  for (const credential of using) {
    // The environment's URL, which a run of several environments tells apart, and which `presign()` derives the environment's from.
    credentials[credential.name] = `${coffre.publicUrl}/use/${path}/${credential.name}`;
    // Every key the placeholder, and a plain value given as it is below. A shaped one shapes the one rule the handle rides in.
    let placeholder = handle;
    if (credential.placeholder !== undefined) {
      const ride = riding(credential, (key) => plainKeys.has(key));
      const rule = ride.length === 1 ? ride[0] : undefined;
      if (rule !== undefined && rule.shape === undefined) {
        throw new CoffreError(409, 'conflict', `${credential.name}'s placeholder shapes the one key a header, query, form or JSON rule carries, and in ${held.environment.path} the handle rides in its ${rule.kind}() rule, which no placeholder shapes: drop the placeholder, or mark that rule's keys plain`);
      }
      if (rule === undefined) {
        throw new CoffreError(409, 'conflict', `${credential.name}'s placeholder shapes the one key a header, query, form or JSON rule carries, and ${held.environment.path}'s keys that are no plain ones sit in ${ride.length} of its rules: mark the others plain, or drop the placeholder`);
      }
      placeholder = await shaped(coffre, credential, rule.keys[0]!, handle, readOf(proxy, path), ui.routes.includes(credential) ? resolved : null);
    }
    for (const key of credential.keys) {
      env[key] = placeholder;
      covered.add(key);
    }
  }
  for (const [key, value] of Object.entries(held.values)) {
    env[key] = value;
    covered.add(key);
  }
  // The keys of a UI item this release serves no request of yet (a signer, verifier or tunnel), or of a route this proxy
  // cannot read: the handle, never the value, and no URL of it.
  for (const key of ui.held) {
    if (!held.keys.includes(key) || covered.has(key)) continue;
    env[key] = handle;
    covered.add(key);
  }
  // A signer's or verifier's key the handle, and its name where `credential(name)` finds it: the key never leaves coffre.
  for (const [name, signer] of signers) {
    if (!held.keys.includes(signer.key)) continue;
    credentials[name] = `${coffre.publicUrl}/use/${path}/${name}`;
    env[signer.key] = handle;
    covered.add(signer.key);
  }
  // A database's URL is `coffre run`'s to make, its listener's, with the handle as the password: never the real one.
  const dialled: Record<string, { key: string; url: string }> = {};
  for (const [name, tunnel] of tunnels) {
    if (!held.keys.includes(tunnel.key)) continue;
    dialled[name] = { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` };
    delete env[tunnel.key];
    covered.add(tunnel.key);
  }
  // What the app would go without and a recipe made, in an environment the deployment generates for: `coffre run`
  // makes each a value of the person's own, in their personal config, replacing the version read here, so that of
  // two runs at once one writes and the other reads what it wrote. Each is written a secret, which the app is given: saying
  // nothing, an override takes the level of the key it overrides, sensitive here (decision 27).
  const making = proxy.generate.get(path.replace(/@me$/, ''));
  const generate: Record<string, { recipe: string; replaces: string; sensitivity: 'secret' }> = {};
  const generates = (key: string) => making === 'all' || (making?.includes(key) ?? false);
  for (const row of making === undefined ? [] : resolved) {
    if (covered.has(row.key) || row.recipe === null || row.versionId === null || recipeProblem(row.recipe) !== null || !generates(row.key)) continue;
    // The person's own value, made sensitive: theirs, which the app goes without, never made again over it (R18).
    if (personal && !row.inherited && row.sensitive) continue;
    generate[row.key] = { recipe: row.recipe, replaces: row.versionId, sensitivity: 'secret' };
  }
  return answer({
    environment: held.environment.path,
    env: { ...env },
    credentials,
    tunnels: dialled,
    left: held.keys.filter((key) => !covered.has(key)),
    ...(making === undefined ? {} : { generate }),
  });
}

/**
 * The UI items a handle's plan shapes (T186 PR C; docs/design/proxy-ui.md, section 6, "The plan shapes UI items as it
 * shapes code's"): one `proxyItem` call with no name, as the handle, which answers every item the place serves, fork
 * chain included, each checked as a use checks it. Its routes, read as code's (`resolve`), join the covering set; every
 * other key an item sends (a signer's, verifier's or tunnel's, which this release serves no request of yet, or a
 * route's this proxy cannot read) is the handle too, so that no UI item's value reaches the app. A name code holds is
 * left out, as no use reaches it. Nothing here is kept as a copy to send by: only a use's answer is (`CopyFromVault`).
 * Fails closed: a level a writer changed answers 503, never a plan shaped from code alone, which would hand the app the
 * values of the forged route's keys. A personal config serves no UI item (decision 7): none.
 *
 *   market/dev, UI route `openai` sending {OPENAI_API_KEY}, which its person reads   OPENAI_API_KEY=<the handle>
 *   the same, one of the 256 items forged                                            503, no environment
 */
async function uiPlanItems(coffre: PluginContext, proxy: Proxy, handle: string, path: string): Promise<{ routes: Resolved[]; held: Set<string> }> {
  const none = { routes: [], held: new Set<string>() };
  if (!proxy.editable || coffre.proxyItem === undefined) return none;
  const found = await coffre.proxyItem(handle, { place: path, name: null });
  const forged = (fault: string) => new CoffreError(503, 'unavailable', `${path}'s proxy definitions are not as the vault sealed them (${fault}): an Owner saves them again; until then no plan is given`, fault, '1');
  if (found.fault !== null) throw forged(found.fault);
  // A personal config serves no UI item, and the vault reads none there (decision 7).
  if (found.personal) return none;
  if (found.items === null || found.items.some((item) => item.definition === null)) throw forged('incomplete');
  const routes: Resolved[] = [];
  const held = new Set<string>();
  for (const { definition } of found.items) {
    if (definition === null || coded(proxy, definition.name)) continue;
    if (definition.kind === 'route') {
      try {
        routes.push(resolve(definition.name, credentialOf(definition), proxy.insecure));
        continue;
      } catch {
        // Saved, yet not a route this proxy sends (its upstream, say): its keys are the handle all the same, below.
      }
    }
    for (const key of definitionKeys(definition)) held.add(key);
  }
  return { routes, held };
}

/**
 * What a workload's environment holds for it (docs/design/workload-access.md,
 * section 6.2): the values it reads, plain ones and those its binding lists
 * in `reads`; the names of the credentials and signers it uses through
 * coffre, and its tunnels, each with the key whose URL the local listener
 * stands in for, as a handle's plan has them; and every key it holds but
 * does not read, `useOnly`. No placeholder: its requests carry its proof,
 * never a value in a slot. Its environment's UI routes too (T186 PR C2b):
 * one `proxyItem` call as the workload, failing closed as a handle's plan
 * does (a level a writer changed: 503, no plan).
 */
async function workloadPlan(coffre: PluginContext, proxy: Proxy, caller: WorkloadUse, path: string): Promise<Response> {
  const routes = await uiRoutesOf(coffre, proxy, caller, path);
  const held = await coffre.use(caller, { path, purpose: 'expose', logged: { plan: true }, keys: (_, rows) => rows.filter((row) => row.plain || row.reads).map((row) => row.key) });
  // The items that serve its environment, whose keys it holds every one of.
  const holds = (item: { environments?: readonly string[] }, keys: readonly string[]) => serves(item, path) && keys.every((key) => held.keys.includes(key));
  return answer({
    environment: held.environment.path,
    values: { ...held.values },
    credentials: [
      ...[...proxy.credentials.values()].filter((credential) => holds(credential, credential.keys)).map((credential) => credential.name),
      ...keyed(proxy).filter(([, signer]) => holds(signer, [signer.key])).map(([name]) => name),
      ...routes.filter((route) => holds({}, definitionKeys(route))).map((route) => route.name),
    ],
    tunnels: Object.fromEntries([...proxy.tunnels].filter(([, tunnel]) => holds(tunnel, [tunnel.key])).map(([name, tunnel]) => [name, { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` }])),
    useOnly: held.keys.filter((key) => !Object.hasOwn(held.values, key)),
    mints: [],
  });
}

/**
 * A workload's environment's UI routes, as its plan lists them: one `proxyItem` call with no name, as the workload, at
 * the place its statement checked; a name code holds left out. A level a writer changed, or an item answered without
 * its definition, is 503, as a handle's plan (`uiPlanItems`).
 */
async function uiRoutesOf(coffre: PluginContext, proxy: Proxy, caller: WorkloadUse, path: string): Promise<ProxyRoute[]> {
  if (!proxy.editable || coffre.proxyItem === undefined) return [];
  const found = await coffre.proxyItem(caller, { place: null, name: null });
  const forged = (fault: string) => new CoffreError(503, 'unavailable', `${path}'s proxy definitions are not as the vault sealed them (${fault}): an Owner saves them again; until then no plan is given`, fault, '1');
  if (found.fault !== null) throw forged(found.fault);
  if (found.items === null || found.items.some((item) => item.definition === null)) throw forged('incomplete');
  return found.items.flatMap(({ definition }) => (definition !== null && definition.kind === 'route' && !coded(proxy, definition.name) ? [definition] : []));
}

/**
 * A credential's placeholder in the shape its client checks: the handle behind
 * a prefix, or a JWT of the real token's named claims, which go no further than
 * those. Code's are opened as a use of the credential, logged: the deployment's
 * code chose those claims. A UI route's (`ui`, the plan read's rows) are opened
 * for the caller alone, purpose `expose` (docs/design/proxy-ui.md, section 3,
 * "The plan's placeholder shaping is not a route use"): an editor's choice of
 * claims shows the caller nothing they may not read (review r5 of #467).
 *
 *   code's jwt() on a sensitive DFNS_AUTH_TOKEN, a Developer's plan    its claims, as ever
 *   a UI route's, the same key                                         403, nothing of it opened
 *   a UI route's on a secret, a Contributor's plan (uses, never reads) 403, nothing of it opened
 */
async function shaped(coffre: PluginContext, credential: Resolved, key: string, handle: string, path: string, ui: Parameters<PickKeys>[1] | null): Promise<string> {
  const placeholder = credential.placeholder!;
  if (placeholder.kind === 'prefix') return `${placeholder.prefix}${handle}`;
  if (ui !== null) {
    // What the plan's read found of it: refused here, with a reason, rather than by the vault's `expose` below alone.
    const row = ui.find((one) => one.key === key);
    if (row === undefined || !row.reads || row.sensitive) {
      throw new CoffreError(403, 'forbidden', `${credential.name}'s placeholder copies claims of ${key}, which you may not read in ${path}: a route saved in the Proxy tab shows its caller only what they read, so an Owner drops its placeholder, or gives you ${key} to read`, 'placeholder_unread');
    }
  }
  const used = await coffre.use(handle, { path, keys: [key], purpose: ui === null ? 'use' : 'expose', only: true, logged: { credential: credential.name, placeholder: { claims: placeholder.claims } } });
  const real = claimsOf(used.values[key]);
  if (real === null) throw new CoffreError(409, 'conflict', `${used.environment.path}'s ${key} is no JWT, which ${credential.name}'s placeholder copies its claims from`);
  const claims = Object.fromEntries(placeholder.claims.filter((claim) => Object.hasOwn(real, claim)).map((claim) => [claim, real[claim]]));
  return `${UNSIGNED}.${base64url(new TextEncoder().encode(JSON.stringify({ ...claims, exp: Math.floor(Date.parse(used.expiresAt) / 1000) })))}.${handle}`;
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

function base64url(bytes: Uint8Array): string {
  return btoa(binary(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * What a person's use of `path` reads: their personal config of it, or the
 * environment while they have none, where the deployment generates values
 * for it; the environment itself anywhere else.
 */
function readOf(proxy: Proxy, path: string, user: User = ''): string {
  return typeof user === 'string' && proxy.generate.has(path) ? `${path}@me` : path;
}

/**
 * A tunnel asked for, `/use/<project>/<env>/<name>` as a WebSocket, by
 * `coffre run`'s listener with the handle as its bearer token, or by a
 * workload with its session and a proof (`htm` GET, `htu` the URL's https
 * form): the database's URL opened (or remembered) as a credential's values
 * are, checked against the tunnel's hosts, and the session that logs in with
 * it. Each connection asks again: a cancel request comes on one of its own.
 */
async function open(request: Request, coffre: PluginContext, proxy: Proxy): Promise<Response | SocketSession> {
  const raw = new URL(request.url).pathname.slice('/use/'.length).split('/');
  if (raw.length !== 3) return failure(404, 'a tunnel is /use/<project>/<environment>/<name>');
  let place: string[];
  try {
    place = raw.map(decodeURIComponent);
  } catch {
    return failure(400, 'the path is not valid percent-encoding');
  }
  const name = place[2]!;
  const tunnel = proxy.tunnels.get(name);
  if (tunnel === undefined) return failure(404, `this instance has no tunnel ${JSON.stringify(name)}: its deployment's credentialProxy names them`);
  const path = `${place[0]}/${place[1]}`;
  if (!serves(tunnel, path)) return notServed(name, path);
  const caller = await workloadOf(request, coffre, { place: path, credential: name });
  if (caller instanceof Response) return caller;
  if (caller !== null) return workloadTunnel(request, coffre, proxy, caller, name, tunnel);
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  // A connection is no request that the cache's minute may serve: each checks the handle stands, opening nothing.
  const { expiresAt } = await coffre.handle(handle);
  let fresh = false;
  const { values } = await valuesFor(coffre, proxy, handle, path, { name, keys: [tunnel.key] }, { tunnel: true }, () => (fresh = true));
  const db = dialled(proxy, path, name, tunnel, values[tunnel.key]!);
  if (db instanceof Response) return db;
  const key = cacheKey(handle, path, name);
  const deadline = Math.min(proxy.recheckMs, RECHECK_DEADLINE_MS);
  // Every `recheckSeconds`, the database's URL opened again for the handle's sessions, as the vault decides it (a revoked handle, a lost grant), logged as a use.
  const check: Check = {
    every: proxy.recheckMs,
    deadline,
    arms: true,
    now: !fresh,
    run: () => coffre.use(handle, { path: readOf(proxy, path, handle), keys: [tunnel.key], purpose: 'use', only: true, logged: { credential: name, tunnel: true, recheck: true } }).then((used) => Object.hasOwn(used.values, tunnel.key)),
  };
  return session(tunnel, {
    handle,
    group: key,
    database: db,
    // Just before a login: the handle afresh, opening nothing, and the group's last word on its person's access.
    stands: async () => (await coffre.handle(handle).then(() => true, () => false)) && (proxy.groups.get(key)?.stands ?? true),
    watch: (end) => watch(proxy, key, { checks: [check], bound: proxy.recheckMs + deadline, until: Date.parse(expiresAt) }, end),
  });
}

/**
 * A workload's tunnel (docs/design/workload-access.md, section 7.1): its
 * Durable Object named by its session (`forwardSocket`), the database's URL
 * opened for the session as a credential's values are, and the app's login
 * asked for no password: the signed upgrade authenticated it (section 9.3).
 * It carries bytes while its last good check is less than `recheckSeconds`
 * old, 15 at most (section 8.2): every two thirds of that, section 5.3's
 * statement again, revocation and every freeze included, with a third of it
 * to answer; so a freeze or a revocation ends it within one. Every
 * `recheckSeconds`, the vault's decision afresh too, which a lost grant
 * changes.
 */
async function workloadTunnel(request: Request, coffre: PluginContext, proxy: Proxy, caller: WorkloadUse, name: string, tunnel: Tunnel): Promise<Response | SocketSession> {
  if (sessionToken(request) === null || caller.path === null) return nonced(failure(403, 'a tunnel is a session\'s, which names its environment'), caller);
  const path = caller.path;
  if (!serves(tunnel, path)) return nonced(notServed(name, path), caller);
  if (!constraintsAllow(caller.constraints, { place: path, credential: name })) return nonced(failure(403, `this narrowed session may not open ${name}`, 'narrowed'), caller);
  let fresh = false;
  let opened: Opened;
  try {
    opened = await valuesFor(coffre, proxy, caller, path, { name, keys: [tunnel.key] }, { tunnel: true }, () => (fresh = true));
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return nonced(failure(error.status, error.message, error.reason ?? error.code, error.retryAfter), caller);
  }
  const db = dialled(proxy, path, name, tunnel, opened.values[tunnel.key]!);
  if (db instanceof Response) return nonced(db, caller);
  const key = cacheKey(caller, path, name);
  const bound = Math.min(proxy.recheckMs, WORKLOAD_RECHECK_MS);
  const checks: Check[] = [
    { every: (bound * 2) / 3, deadline: bound / 3, arms: true, now: false, run: () => coffre.recheck(caller) },
    {
      every: proxy.recheckMs,
      deadline: Math.min(proxy.recheckMs, RECHECK_DEADLINE_MS),
      arms: false,
      now: !fresh,
      run: () => coffre.use(caller, { path, keys: [tunnel.key], purpose: 'use', only: true, logged: { credential: name, tunnel: true, recheck: true } }).then((used) => Object.hasOwn(used.values, tunnel.key)),
    },
  ];
  return session(tunnel, {
    handle: null,
    group: key,
    database: db,
    stands: async () => (await coffre.recheck(caller)) && (proxy.groups.get(key)?.stands ?? true),
    watch: (end) => watch(proxy, key, { checks, bound, until: null }, end),
  });
}

/** The database a tunnel's URL names, as it is dialled, or why it is not: its hosts, TLS and private addresses as the tunnel allows. */
function dialled(proxy: Proxy, path: string, name: string, tunnel: Tunnel, url: string): Database | Response {
  let db: Database;
  try {
    db = database(url);
  } catch {
    // The value is a secret: what is wrong with it is said, never what it is.
    return failure(409, `${path}'s ${tunnel.key} is no postgres:// URL`);
  }
  if (tunnel.hosts !== undefined && !tunnel.hosts.includes(canonicalHost(db.host))) return failure(403, `${path}'s ${tunnel.key} names a host the tunnel ${name} does not reach`);
  if (tunnel.connect !== undefined) {
    // Inside the binding's private network, plaintext: TLS through it is no option yet.
    if (db.tls !== 'disable') return failure(409, `${path}'s ${tunnel.key} asks for TLS, which the tunnel ${name}'s network binding does not carry: sslmode=disable, for a database inside that network`);
  } else if (!proxy.insecure && (privateHost(db.host) || db.tls === 'disable')) {
    return failure(403, `${path}'s ${tunnel.key} names a private address or turns TLS off, which only insecureUpstreams, for a local database, or the tunnel's network binding (connect), allows`);
  } else if (!proxy.insecure && tunnel.hosts === undefined && !address(db.host)) {
    // Whoever writes the value picks the name, and a name may resolve to a private address: only the deployment's are dialled by name.
    return failure(403, `${path}'s ${tunnel.key} names its host by name, which the tunnel ${name} dials only when its hosts list it: a name may resolve to a private address`);
  }
  return db;
}

/** The session a tunnel's connection runs: through its network binding, if it has one, or the platform's TCP. */
function session(tunnel: Tunnel, given: Omit<Parameters<typeof tunnelPostgres>[1], 'connect'>): SocketSession {
  const network = tunnel.connect;
  return (client, connect) => tunnelPostgres(client, { ...given, connect: network === undefined ? connect : through(network) });
}

/**
 * One check of a tunnel group's: how often it runs, how long it may take
 * before it counts as a no, whether its yes keeps the group's bytes flowing
 * (`arms`), whether it runs at once, and what it asks.
 */
type Check = { every: number; deadline: number; arms: boolean; now: boolean; run: () => Promise<boolean> };

/**
 * A tunnel's sessions of one caller, environment and tunnel, as one: each
 * of its checks on its own timer, and the first answer that is no ends
 * every session at once, as does `until`, the handle's end. The group's
 * bytes flow only while its last good arming check is under `bound` old,
 * even if no check ran since (formal/Workload.tla, `TunnelByte`): a
 * check that never comes back keeps nothing open. It lives as long as its
 * sessions, and goes with the last.
 */
function watch(proxy: Proxy, key: string, tunnel: { checks: readonly Check[]; bound: number; until: number | null }, end: () => void): () => void {
  let group = proxy.groups.get(key);
  if (group === undefined) {
    const made: Group = { ends: new Set(), stands: true, timers: [], watchdog: undefined, expiry: undefined };
    /** The sessions end, and the URL the values' cache holds goes with them, so no new one is let in on it. */
    const close = () => {
      made.stands = false;
      proxy.cache.delete(key);
      for (const ending of [...made.ends]) ending();
    };
    const arm = (from: number) => {
      clearTimeout(made.watchdog);
      made.watchdog = setTimeout(close, Math.max(0, from + tunnel.bound - Date.now()));
    };
    for (const check of tunnel.checks) {
      // One at a time for the group, however many sessions it holds; one that has not answered in time is a no.
      let checking = false;
      const recheck = async () => {
        if (checking || !made.stands) return;
        checking = true;
        const started = Date.now();
        let late: ReturnType<typeof setTimeout> | undefined;
        const stands = await Promise.race([check.run().catch(() => false), new Promise<boolean>((resolve) => (late = setTimeout(() => resolve(false), check.deadline)))]);
        clearTimeout(late);
        checking = false;
        if (!made.stands) return;
        if (!stands) return close();
        // A group its last session has left arms nothing: its watchdog would close it later, dropping a newer group's cache.
        if (check.arms && proxy.groups.get(key) === made) arm(started);
      };
      made.timers.push(setInterval(() => void recheck(), check.every));
      // A new group let in on the cache's values decides now: its first interval starts from an answer of its own.
      if (check.now) void recheck();
    }
    // Let in just now, on a check of the admission's own.
    arm(Date.now());
    if (tunnel.until !== null) made.expiry = setTimeout(close, Math.max(0, tunnel.until - Date.now()));
    group = made;
    proxy.groups.set(key, group);
  }
  const mine = group;
  mine.ends.add(end);
  return () => {
    mine.ends.delete(end);
    if (mine.ends.size > 0) return;
    for (const timer of mine.timers) clearInterval(timer);
    clearTimeout(mine.watchdog);
    clearTimeout(mine.expiry);
    if (proxy.groups.get(key) === mine) proxy.groups.delete(key);
  };
}

/**
 * What a caller asks coffre to make with an environment's values, which it
 * never hands back: `POST /use/<project>/<env>`, or `POST /use` for a
 * workload that reaches one environment, with `{ presign: {…} }` for a
 * presigned URL, `{ sign: {…} }` for a signature, or `{ verify: {…} }`
 * for whether a signature is a verifier's. A handle's holder sends it as a
 * bearer token; a workload's proof signs the body, so nobody on the way
 * can change what is signed or checked. PR 7 adds `mint` beside them,
 * naming the credential it uses, as these do.
 */
async function compute(request: Request, coffre: PluginContext, proxy: Proxy, path: string | null): Promise<Response> {
  // Read up to what the longest message takes, as base64url in JSON beside the rest: under `editable`, what an HMAC saved
  // in the Proxy tab may take, 1 MiB.
  const ui = proxy.editable && coffre.useRoute !== undefined;
  const most = ui ? Math.max(proxy.messageBytes, MAX_MESSAGE_BYTES) : proxy.messageBytes;
  const raw = await boundedBody(request, Math.ceil(most / 3) * 4 + 4096);
  if (raw === null) return failure(413, `a message to sign or verify is at most ${sized(most)} here: an hmac()'s maxBytes takes a longer one`);
  type Asked = { presign?: Record<string, unknown>; sign?: Record<string, unknown>; verify?: Record<string, unknown> };
  let asked: Asked | null = null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(raw ?? new Uint8Array(0)));
    if (typeof parsed === 'object' && parsed !== null) asked = parsed as Asked;
  } catch {
    asked = null;
  }
  // What it asks for, and the credential or signer it uses, which a workload's `credential:` freeze and limits name.
  const operation = asked?.presign !== undefined ? 'presign' : asked?.sign !== undefined ? 'sign' : asked?.verify !== undefined ? 'verify' : null;
  if (asked === null || operation === null) {
    return failure(400, `send { presign: { credential, path, method, expiresIn } }, { sign: { credential, message } } or { verify: { credential, message, signature } } as JSON`);
  }
  const given = asked[operation] ?? {};
  const name = typeof given.credential === 'string' ? given.credential : '';
  // A name code lacks, of any kind (R66): the environment's item saved in the Proxy tab (C2b2).
  if (ui && CREDENTIAL_NAME.test(name) && !coded(proxy, name)) return uiCompute(request, coffre, proxy, path, operation, name, given, raw);
  // A verifier verifies, and an HMAC signer too, which could check a signature by making it: a private key's is no HMAC.
  const signer = operation === 'sign' ? proxy.signers.get(name) : operation === 'verify' ? (proxy.verifiers.get(name) ?? proxy.signers.get(name)) : undefined;
  const credential = operation === 'presign' ? proxy.credentials.get(name) : undefined;
  if (operation === 'sign' && signer === undefined) {
    return failure(404, `sign names a signer of this instance's: its deployment's credentialProxy names them, signers: { … }${proxy.verifiers.has(name) ? `; ${name} is a verifier, which checks signatures and makes none` : ''}`);
  }
  if (operation === 'verify' && signer?.kind !== 'hmac') return failure(404, 'verify names a verifier of this instance\'s, or a signer of its that is hmac(…): its deployment\'s credentialProxy names them, verifiers: { … }');
  // A presigned URL carries the signature alone: a credential of any other rule, or of more than SigV4, signs none.
  if (operation === 'presign' && !(credential?.rules.length === 1 && credential.sigv4 !== undefined)) return failure(404, 'presign names a credential of this instance\'s that signs with sigv4() alone');
  const caller = await workloadOf(request, coffre, { place: path, credential: name, body: await bodyDigest(raw ?? new Uint8Array(0)), ...countsOf(name, (signer ?? credential!).limit) });
  if (caller instanceof Response) return caller;
  const run = (who: User, at: string) => (!serves((signer ?? credential)!, at) ? notServed(name, at) : operation === 'presign' ? presign(coffre, proxy, at, who, credential!, given, sessionToken(request)) : operation === 'sign' ? sign(coffre, proxy, at, who, name, signer!, given) : verify(coffre, proxy, at, who, name, signer as Hmac, given));
  if (caller !== null) return answering(caller, async () => (caller.path === null ? failure(409, 'name the environment, POST /use/<project>/<environment>: this session reaches none, or several, or one gone') : run(caller, caller.path)));
  if (path === null) return failure(405, 'GET only: a handle names its environment, POST /use/<project>/<environment>');
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  return run(handle, path);
}

/** What `POST /use/<project>/<env>` makes with an item's values. */
type Operation = 'presign' | 'sign' | 'verify';

/** Who asks a UI item's compute, and where its copy, its kept values and its use are: a handle's place reading, or a workload's place. */
type Computing = {
  who: User;
  /** The environment's path, which a narrowed session's constraints name. */
  at: string;
  /** Where its values are kept (`proxy.ui.kept`), and its copy (`proxy.ui.last`), as a route use of the same name keeps them. */
  kept: string;
  reading: string;
  asked: Pick<RouteAsked, 'named' | 'stable'>;
  /** The session token the request carries, which no presigned URL may hold; null for a handle's or a binding's request. */
  token: string | null;
};

/**
 * A sign, verify or presign of an item saved in the Proxy tab, a name code lacks (T186 PR C2b2; docs/design/proxy-ui.md,
 * section 3, "Signers and verifiers" and "Presign"). One route use decides the item and its keys, for the caller and
 * for the item's editor, as a route's are; then everything the request asks is checked again on the decided item, and
 * the signature, the check or the URL is made by it alone, never by this isolate's copy (`SentAsDecided`). A copy's
 * refusal before the use stands only when the vault confirmed the copy within `cacheSeconds`, and for a handle only on
 * a place its checked made-for list names; a request such a copy admitted and the decided item refuses is 503 `moved`,
 * nothing made. An HMAC's values are kept for `cacheSeconds` with the item they were decided on, whose `encoding`,
 * `prefix` and `maxBytes` a kept sign or verify takes, never a newer copy's (`BoundToDefinition`). A private key's sign
 * and a presign are each a use of their own, never kept, as code's are.
 *
 *   workload, cold   proxyItem (the item's limit, counted before the gate), then the use: 2 calls
 *   workload, warm   the use: 1 call; an HMAC kept: none
 *   handle           the use: 1 call; an HMAC kept: none
 */
async function uiCompute(request: Request, coffre: PluginContext, proxy: Proxy, path: string | null, operation: Operation, name: string, given: Record<string, unknown>, raw: Uint8Array | undefined): Promise<Response> {
  const item = itemCounts(proxy);
  const caller = await workloadOf(request, coffre, { place: path, credential: name, body: await bodyDigest(raw ?? new Uint8Array(0)), counts: item.counts });
  if (caller instanceof Response) return limitRefused(caller, item);
  if (caller !== null) {
    return answering(caller, async () => {
      if (caller.path === null || caller.place === null) return failure(409, 'name the environment, POST /use/<project>/<environment>: this session reaches none, or several, or one gone');
      const copy = item.copy();
      if (copy instanceof CoffreError) throw copy;
      const computing = { who: caller, at: caller.path, kept: `w\n${caller.credentialId}\n${caller.place}\n${name}`, reading: `w\n${caller.place}\n${name}`, asked: { named: null, stable: name }, token: sessionToken(request) };
      return uiMade(coffre, proxy, computing, operation, name, given, copy);
    });
  }
  if (path === null) return failure(405, 'GET only: a handle names its environment, POST /use/<project>/<environment>');
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  // The place reading's copy, which any handle's use of the place brings: its refusals stand only for a handle whose
  // checked made-for list names the place, never a stranger's token (review r2 of #467).
  const now = Date.now();
  const reading = `n\n${path}\n${name}`;
  const last = proxy.ui.last.get(reading);
  const held = last === undefined ? undefined : proxy.ui.items.get(last.digest);
  const known = proxy.handles.get(handle);
  const vouched = known !== undefined && known.until > now && (known.paths ?? []).includes(path);
  const copy = last === undefined || held === undefined ? null : { digest: last.digest, definition: held.definition, fresh: vouched && now - last.confirmed < proxy.cacheMs };
  const named = { path, route: name };
  return uiMade(coffre, proxy, { who: handle, at: path, kept: keptAt(handle, { named }), reading, asked: { named, stable: null }, token: null }, operation, name, given, copy);
}

/** Whether an item is of a kind `operation` takes: a signer signs, an HMAC (a verifier's, or a signer's) verifies, a route presigns. */
function takes(definition: ProxyDefinition, operation: Operation): boolean {
  if (operation === 'presign') return definition.kind === 'route';
  if (operation === 'sign') return definition.kind === 'signer';
  return hmacOf(definition) !== null;
}

/** The HMAC an item signs or checks with: a verifier's, or an HMAC signer's; null for any other. */
function hmacOf(definition: ProxyDefinition): ProxyHmac | null {
  if (definition.kind === 'verifier') return definition.hmac;
  if (definition.kind === 'signer' && definition.signer.kind === 'hmac') return definition.signer;
  return null;
}

/**
 * Why an item takes no such request, or null: its kind, a message longer than it takes, a presign of a route whose one
 * inject rule is not SigV4. Nothing here reads a value, so the decided item's is asked before the read opens any
 * (`RouteAsked.refuses`).
 */
function unfit(definition: ProxyDefinition, operation: Operation, bytes: number): CoffreError | null {
  const { name, kind } = definition;
  if (!takes(definition, operation)) {
    const what = operation === 'presign' ? 'presigns no URL: a route saved with sigv4 as its one inject rule does' : operation === 'sign' ? 'signs nothing: a signer does' : 'checks no signature: a verifier, or an HMAC signer, does';
    return new CoffreError(404, 'not_found', `${name} is a ${definition.kind === 'signer' ? (definition.signer.kind === 'hmac' ? 'HMAC signer' : 'private-key signer') : kind}, which ${what}`);
  }
  if (definition.kind === 'route') {
    if (definition.inject.length !== 1 || definition.inject[0]!.kind !== 'sigv4') return new CoffreError(400, 'bad_request', `${name} presigns no URL: a presigned URL carries a SigV4 signature alone, and ${name} sends ${definition.inject.length === 1 ? `a ${definition.inject[0]!.kind} rule` : `${definition.inject.length} inject rules`}`);
    return null;
  }
  const most = hmacOf(definition)?.maxBytes ?? MESSAGE_BYTES;
  if (bytes > most) return new CoffreError(413, 'too_large', `${name} ${operation === 'sign' ? 'signs' : 'checks'} a message of ${sized(most)} at most`);
  return null;
}

/** 503 `moved`: the item changed between the copy that admitted a request and the use that decided it; nothing made. */
const movedItem = (name: string) => new CoffreError(503, 'unavailable', `${name} changed since this isolate's copy admitted the request, and nothing was made with it: send it again`, 'moved', '1');

/** A UI item's compute once its caller is known (`uiCompute`): the request's own checks, the kept values or the copy, the use, then the decided item's. */
async function uiMade(coffre: PluginContext, proxy: Proxy, computing: Computing, operation: Operation, name: string, given: Record<string, unknown>, copy: ItemCopy | null): Promise<Response> {
  const { who, at } = computing;
  // The request's own checks, which no item changes, before anything is used.
  let message: Uint8Array<ArrayBuffer> | null = null;
  let asked: PresignAsked | null = null;
  if (operation === 'presign') {
    const read = presignAsked(given);
    if (read instanceof Response) return read;
    asked = read;
  } else {
    message = messageOf(given.message);
    if (message === null) return failure(400, operation === 'sign' ? 'sign a message given as base64url' : 'verify a message given as base64url: the body as it came, byte for byte');
    if (operation === 'verify' && typeof given.signature !== 'string') return failure(400, 'verify a signature given as a string, as its header carried it');
    // A narrowed session's signers are named, and one limited to methods or paths signs nothing: no request to check them on.
    if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: at, credential: name })) return failure(403, `this narrowed session may not ${operation} with ${name}`, 'narrowed');
  }
  const bytes = message?.byteLength ?? 0;
  const now = Date.now();
  // An HMAC's values kept: the item they were decided on says how to sign or check, never the copy.
  if (message !== null) {
    const kept = proxy.ui.kept.get(computing.kept);
    if (kept !== undefined && kept.until <= now) proxy.ui.kept.delete(computing.kept);
    else if (kept !== undefined) {
      const refused = unfit(kept.definition, operation, bytes);
      if (refused !== null) throw refused;
      const hmac = hmacOf(kept.definition);
      if (hmac !== null) return hmacMade(kept.path, name, hmac, kept.values, operation, message, given.signature, kept.until);
    }
  }
  // A fresh copy's refusals stand; a copy it admitted makes the decided item's refusal a move.
  let admitted: string | null = null;
  if (copy !== null && copy.fresh) {
    const refused = unfit(copy.definition, operation, bytes);
    if (refused !== null) throw refused;
    if (asked !== null) {
      const resolved = uiCredential(proxy, copy.digest, copy.definition as ProxyRoute);
      if (typeof resolved !== 'string') {
        const aimed = presignTarget(resolved, asked, computing.token);
        if (aimed instanceof Response) return aimed;
      }
    }
    admitted = copy.digest;
  }
  const sha256 = operation === 'sign' ? hex(await crypto.subtle.digest('SHA-256', message!)) : null;
  // The entry records what was asked of the item the vault decided on: a private key's sign the message's SHA-256, a
  // presign the decided upstream's host, never the copy's (section 3, "Presign").
  const logged = (decided: DecidedItem | null): Record<string, unknown> => {
    const definition = decided === null ? null : itemOf(proxy, decided);
    if (asked !== null) {
      const resolved = definition?.kind === 'route' ? uiCredential(proxy, decided!.digest, definition) : null;
      const host = resolved === null || typeof resolved === 'string' ? undefined : resolved.base.host;
      return { ui: true, ...(host === undefined ? {} : { host }), presign: { method: asked.method, path: `/${asked.segments.join('/')}`, expiresIn: asked.expiresIn } };
    }
    return { ui: true, ...(definition?.kind === 'signer' && definition.signer.kind === 'private-key' ? { sign: { sha256 } } : {}) };
  };
  const used = await coffre.useRoute!(who, { ...computing.asked, digests: copy === null ? [] : [copy.digest], logged, refuses: (decided) => {
    const definition = itemOf(proxy, decided);
    if (definition === null) return null;
    // The vault's item is this isolate's copy now (`CopyFromVault`), whatever is made of it.
    remember(proxy.ui.last, computing.reading, { digest: decided.digest, confirmed: Date.now() });
    const refused = unfit(definition, operation, bytes);
    return refused === null ? null : admitted !== null && admitted !== decided.digest ? movedItem(name) : refused;
  } });
  const definition = itemOf(proxy, used.item);
  if (definition === null) return failure(503, `${used.item.name}: this isolate's copy of its definition is gone; ask again`, 'moved', '1');
  // What is made with values decided now answers within the use's window, as a route's request is sent in it
  // (`WithinWindow`): a signature made later, a slow key's or a stalled isolate's, answers 503 `late` (review r1 of #480).
  const answerBy = Math.min(now + Math.max(proxy.cacheMs, USE_DEADLINE_MS), Date.parse(used.expiresAt));
  // Refused before its use opened anything (`refuses`): the item takes the request.
  if (definition.kind === 'route') {
    const resolved = uiCredential(proxy, used.item.digest, definition);
    if (typeof resolved === 'string') return failure(503, resolved, 'unavailable', '1');
    const aimed = presignTarget(resolved, asked!, computing.token);
    if (aimed instanceof Response) {
      if (admitted !== null && admitted !== used.item.digest) throw movedItem(name);
      return aimed;
    }
    if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: at, credential: name, request: { method: asked!.method, url: aimed.target } })) {
      return failure(403, `this narrowed session may not presign ${asked!.method} ${aimed.relative} through ${name}`, 'narrowed');
    }
    if (resolved.keys.some((key) => !Object.hasOwn(used.values, key))) return failure(409, `${used.environment.path} holds no key ${name} signs with`);
    return presigned(resolved.sigv4!, asked!, aimed.target, used.values, used.expiresAt, who, name, answerBy);
  }
  if (definition.kind === 'signer' && definition.signer.kind === 'private-key') {
    const pem = used.values[definition.signer.key];
    if (pem === undefined) return failure(409, `${used.environment.path} holds no ${definition.signer.key}, which ${name} signs with`);
    try {
      const signature = base64url(await signWith(pem, message!));
      return Date.now() > answerBy ? lateMade(name) : answer({ signature });
    } catch (error) {
      // What is wrong with the key is said, never the key: neither the platform's error nor its message goes anywhere.
      return failure(409, `${used.environment.path}'s ${definition.signer.key} ${error instanceof SigningKeyError ? error.message : 'signs nothing'}`);
    }
  }
  const hmac = hmacOf(definition)!;
  if (proxy.cacheMs > 0) {
    remember(proxy.ui.kept, computing.kept, { values: used.values, plain: used.plain, digest: used.item.digest, definition, reading: used.reading, path: used.environment.path, until: Math.min(now + proxy.cacheMs, Date.parse(used.expiresAt)) });
  }
  return hmacMade(used.environment.path, name, hmac, used.values, operation, message!, given.signature, answerBy);
}

/** 503 `late`: what a UI item made was ready after its values' window closed, and goes nowhere (`WithinWindow`). */
const lateMade = (name: string) => failure(503, `${name}: what it made was ready after its values may be used; send it again`, 'late', '1');

/** An HMAC's sign or check with its values, by `hmac`, the item they were decided on, answered by `answerBy` or 503 `late`. */
async function hmacMade(path: string, name: string, hmac: ProxyHmac, values: Record<string, string>, operation: Operation, message: Uint8Array<ArrayBuffer>, signature: unknown, answerBy: number): Promise<Response> {
  const secret = values[hmac.key];
  if (secret === undefined) return failure(409, `${path} holds no ${hmac.key}, which ${name} ${operation === 'sign' ? 'signs' : 'checks'} with`);
  // WebCrypto takes no empty HMAC key: said as what is wrong with the value, not the platform's error.
  if (secret === '') return failure(409, `${path}'s ${hmac.key} is empty, and ${name} signs and checks nothing with an empty secret`);
  const scheme = { encoding: hmac.encoding, prefix: hmac.prefix };
  const made = operation === 'sign' ? { signature: await hmacSign(secret, message, scheme) } : { valid: await hmacVerify(secret, message, signature as string, scheme) };
  return Date.now() > answerBy ? lateMade(name) : answer(made);
}

/**
 * A signature by a signer's key, for the app that holds the handle, or the
 * workload: `{ sign: { credential, message } }`, the message base64url.
 * The key never leaves coffre. A private key signs as Node's
 * `crypto.sign(undefined, message, key)` does (`signWith`), and answers
 * `{ signature }`, base64url: each signature one use in the log, naming the
 * message by its SHA-256, never served from the cache. An HMAC secret
 * answers the signature as its scheme writes it (`hmacSign`), opened as a
 * credential's values are: logged once a minute, on a request's path.
 */
async function sign(coffre: PluginContext, proxy: Proxy, path: string, who: User, name: string, signer: Signer, asked: { message?: unknown }): Promise<Response> {
  const message = messageOf(asked.message);
  if (message === null) return failure(400, 'sign a message given as base64url');
  if (message.byteLength > longest(signer)) return failure(413, `${name} signs a message of ${sized(longest(signer))} at most${signer.kind === 'hmac' ? ': its hmac()\'s maxBytes takes a longer one' : ''}`);
  // A narrowed session's signers are named, and one limited to methods or paths signs nothing: no request to check them on.
  if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: path, credential: name })) return failure(403, `this narrowed session may not sign with ${name}`, 'narrowed');
  if (signer.kind === 'hmac') {
    const secret = await hmacSecret(coffre, proxy, path, who, name, signer);
    return answer({ signature: await hmacSign(secret, message, { encoding: signer.encoding, prefix: signer.prefix ?? '' }) });
  }
  const sha256 = hex(await crypto.subtle.digest('SHA-256', message));
  const used = await coffre.use(who, { path: readOf(proxy, path, who), keys: [signer.key], purpose: 'use', only: true, logged: { credential: name, sign: { sha256 } } });
  const pem = used.values[signer.key];
  if (pem === undefined) return failure(409, `${used.environment.path} holds no ${signer.key}, which ${name} signs with`);
  try {
    return answer({ signature: base64url(await signWith(pem, message)) });
  } catch (error) {
    // What is wrong with the key is said, never the key: neither the platform's error nor its message goes anywhere.
    return failure(409, `${used.environment.path}'s ${signer.key} ${error instanceof SigningKeyError ? error.message : 'signs nothing'}`);
  }
}

/**
 * Whether a signature is an HMAC secret's, for the app that holds the
 * handle, or the workload: `{ verify: { credential, message, signature } }`,
 * the message base64url, an inbound webhook's body as it came, byte for
 * byte, and the signature as its header carried it, `sha256=…`. coffre
 * opens the secret as a credential's values are, logged once a minute, and
 * answers `{ valid }`, compared in constant time (`hmacVerify`): no more,
 * whatever is wrong with the signature. The secret never leaves coffre.
 */
async function verify(coffre: PluginContext, proxy: Proxy, path: string, who: User, name: string, verifier: Hmac, asked: { message?: unknown; signature?: unknown }): Promise<Response> {
  const message = messageOf(asked.message);
  if (message === null) return failure(400, 'verify a message given as base64url: the body as it came, byte for byte');
  if (message.byteLength > longest(verifier)) return failure(413, `${name} checks a message of ${sized(longest(verifier))} at most: its hmac()'s maxBytes takes a longer one`);
  if (typeof asked.signature !== 'string') return failure(400, 'verify a signature given as a string, as its header carried it');
  if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: path, credential: name })) return failure(403, `this narrowed session may not verify with ${name}`, 'narrowed');
  const secret = await hmacSecret(coffre, proxy, path, who, name, verifier);
  return answer({ valid: await hmacVerify(secret, message, asked.signature, { encoding: verifier.encoding, prefix: verifier.prefix ?? '' }) });
}

/** The longest message a signer or verifier takes. */
function longest(signer: Signer): number {
  return signer.kind === 'hmac' ? (signer.maxBytes ?? MESSAGE_BYTES) : MESSAGE_BYTES;
}

const sized = (bytes: number) => (bytes % 1024 ** 2 === 0 ? `${bytes / 1024 ** 2} MiB` : bytes % 1024 === 0 ? `${bytes / 1024} KiB` : `${bytes} bytes`);

/** A message given as base64url, as its bytes: null for anything else. Buffer's decoder, several times faster than atob's string. */
function messageOf(given: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof given !== 'string' || !/^[A-Za-z0-9_-]*$/.test(given) || given.length % 4 === 1) return null;
  return Buffer.from(given, 'base64url');
}

/** An HMAC signer's or verifier's secret, opened for the caller as a credential's values are: remembered for `cacheSeconds`, logged as one use when opened. */
async function hmacSecret(coffre: PluginContext, proxy: Proxy, path: string, who: User, name: string, hmac: Hmac): Promise<string> {
  const { values } = await valuesFor(coffre, proxy, who, path, { name, keys: [hmac.key] }, { hmac: true });
  // WebCrypto takes no empty HMAC key: said as what is wrong with the value, not the platform's error.
  if (values[hmac.key] === '') throw new CoffreError(409, 'conflict', `${path}'s ${hmac.key} is empty, and ${name} signs and checks nothing with an empty secret`);
  return values[hmac.key]!;
}

/**
 * A presigned URL, for an AWS-signed credential: `{ presign: { credential,
 * path, method?, query?, expiresIn? } }`. coffre signs a GET (or HEAD) of
 * `path` under the credential's upstream with the real key pair, for at most
 * an hour and never past the handle or session, and answers `{ url,
 * expiresAt }`: a URL of the upstream's, which whoever holds it may use
 * until then, and which holds the access key's id and a signature, never
 * the secret. Each is one use in the log, naming the path and how long it
 * lasts, never served from the cache. A narrowed session's methods and
 * paths are held to the presigned request's.
 */
async function presign(coffre: PluginContext, proxy: Proxy, path: string, who: User, credential: Resolved, given: PresignGiven, token: string | null): Promise<Response> {
  const inject = credential.sigv4!;
  const method = given.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') return failure(400, 'a presigned URL is for GET or HEAD: an upload goes through the proxy');
  // Legacy `methods` answer before the other arguments are read, as before 0.16: `methods: ['POST']` is a 405 to any presign,
  // a malformed one included. `allow` never sets them (the two do not mix), and its methods answer with its paths, below.
  if (credential.methods !== undefined && !credential.methods.some((taken) => taken.toUpperCase() === method)) {
    return failure(405, credential.methods.length === 0 ? `${credential.name} takes no method` : `${credential.name} takes ${credential.methods.map((taken) => taken.toUpperCase()).join(', ')}`);
  }
  const asked = presignAsked(given);
  if (asked instanceof Response) return asked;
  const aimed = presignTarget(credential, asked, token);
  if (aimed instanceof Response) return aimed;
  const { target, relative } = aimed;
  if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: path, credential: credential.name, request: { method, url: target } })) {
    return failure(403, `this narrowed session may not presign ${method} ${relative} through ${credential.name}`, 'narrowed');
  }
  // Every URL is one use in the log, opened now: a URL outlives the request, and whoever holds it may use it.
  const used = await coffre.use(who, { path: readOf(proxy, path, who), keys: credential.keys, purpose: 'use', only: true, logged: { credential: credential.name, host: target.host, presign: { method, path: relative, expiresIn: asked.expiresIn } } });
  if (credential.keys.some((key) => !Object.hasOwn(used.values, key))) return failure(409, `${used.environment.path} holds no key ${credential.name} signs with`);
  return presigned(inject, asked, target, used.values, used.expiresAt, who, credential.name);
}

/** What a presign asks for, as its JSON gave it. */
type PresignGiven = { path?: unknown; method?: unknown; query?: unknown; expiresIn?: unknown };

/** A presign's arguments, checked as nothing of the credential's needs: the method, how long, the path, the query. */
type PresignAsked = { method: 'GET' | 'HEAD'; expiresIn: number; segments: string[]; query: Record<string, string> };

/** What a presign asks, checked before any credential's rules are: the URL is for GET or HEAD, an hour at most, a path that climbs nowhere. */
function presignAsked(given: PresignGiven): PresignAsked | Response {
  const method = given.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') return failure(400, 'a presigned URL is for GET or HEAD: an upload goes through the proxy');
  const expiresIn = given.expiresIn ?? 900;
  if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn < 1 || expiresIn > 3600) return failure(400, 'a presigned URL lasts between a second and an hour: expiresIn, in seconds');
  // No control character either: a URL drops a tab or a line break, which could join what the checks below saw apart.
  if (typeof given.path !== 'string' || !given.path.startsWith('/') || /[?#\u0000-\u001F\u007F]/.test(given.path)) return failure(400, 'presign a path under the credential as a URL has it, /bucket/key, each segment encoded: the query goes in query');
  const query = given.query ?? {};
  if (typeof query !== 'object' || query === null || Object.values(query).some((value) => typeof value !== 'string')) return failure(400, 'query is a map of strings, response-content-disposition and the like');
  // The same rules as a request through it: no segment that climbs, decoded however often, a slash, a control byte or a
  // dot segment (`..;`, `%252e%252e`), since a server behind may decode it again.
  const segments = given.path.slice(1).split('/');
  if (segments.some(climbs)) return failure(400, 'the path may not climb out of the credential\'s upstream');
  for (const name of Object.keys(query)) if (name.toLowerCase().startsWith('x-amz-')) return failure(400, 'the X-Amz- parameters are the signature\'s own');
  return { method, expiresIn, segments, query: query as Record<string, string> };
}

/**
 * The URL a presign signs, under `credential`'s upstream, or the refusal: its allow list, as for a request through it,
 * and neither a handle nor the request's session `token` in any of it. A UI route's is built again from the item the
 * use decided on, before anything is signed.
 */
function presignTarget(credential: Resolved, asked: PresignAsked, token: string | null): { target: URL; relative: string } | Response {
  const target = new URL(`${credential.base.href.replace(/\/$/, '')}/${asked.segments.join('/')}`);
  for (const [name, value] of Object.entries(asked.query)) target.searchParams.set(name, value);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  // And again on the path as the URL made it, which is the one signed: the same rule, `climbs`, on what URL parsing left.
  if (target.pathname.split('/').some(climbs)) return failure(400, 'the path may not climb out of the credential\'s upstream');
  const relative = target.pathname.slice(under.length) || '/';
  // Its allow list, as for a request through it: the URL is one.
  const refused = allowed(credential, asked.method, relative);
  if (refused !== null) return refused;
  // A URL is for sharing: neither the handle nor the session's token goes in it, its path or its query, as it is or
  // decoded however often a server behind may decode it (review r1 of #480: `query: { trace: <token> }`).
  const readings = decodings(target.href);
  // A URL still decoding after `climbs`'s 8 passes may hold anything a ninth would show: refused, as `climbs` refuses
  // such a segment (review r2 of #480: a token's `_` encoded 8 times over, which `searchParams` encodes a ninth).
  if (readings === null) return failure(400, 'the URL is encoded too many times over to check');
  if (readings.some((text) => HANDLE.test(text))) return failure(400, 'the handle goes in no presigned URL');
  if (token !== null && readings.some((text) => text.includes(token))) return failure(400, 'the session token goes in no presigned URL');
  return { target, relative };
}

/**
 * A URL as it is, then decoded as often as it changes: each reading a server behind may see; or null when it still
 * changes after `climbs`'s 8 decodings, whose further readings go unchecked.
 */
function decodings(href: string): string[] | null {
  const readings = [href];
  for (let depth = 0; depth < 8; depth += 1) {
    const next = bytesOf(readings.at(-1)!);
    if (next === readings.at(-1)) return readings;
    readings.push(next);
  }
  return bytesOf(readings.at(-1)!) === readings.at(-1) ? readings : null;
}

/**
 * The presigned URL, signed with `values` for at most what was asked, and never past the handle's or the session's own
 * end; a UI route's answered by `answerBy`, its values' window, or 503 `late`.
 */
async function presigned(inject: SigV4Rule, asked: PresignAsked, target: URL, values: Record<string, string>, expiresAt: string, who: User, name: string, answerBy?: number): Promise<Response> {
  const lasts = Math.min(asked.expiresIn, Math.floor((Date.parse(expiresAt) - Date.now()) / 1000));
  if (lasts < 1) return failure(401, typeof who === 'string' ? 'the handle ends now: run the app with `coffre run` again' : 'the session ends now: renew it');
  let url: URL;
  try {
    url = await presignV4(asked.method, target, {
      accessKeyId: render(inject.accessKeyId, values),
      secretAccessKey: render(inject.secretAccessKey, values),
      ...(inject.sessionToken === undefined ? {} : { sessionToken: render(inject.sessionToken, values) }),
    }, inject, lasts);
  } catch {
    return failure(409, `${name}'s values sign no URL`);
  }
  if (answerBy !== undefined && Date.now() > answerBy) return lateMade(name);
  return answer({ url: url.href, expiresAt: new Date(Date.now() + lasts * 1000).toISOString() });
}

/** Where a request through a credential goes, under its upstream, once its path is checked: the URL, the upstream's own path, and the request's within it. */
type Aim = { target: URL; under: string; relative: string };

/**
 * The upstream URL a request through `credential` goes to, or the refusal:
 * nothing the app writes leaves the credential's upstream, and its methods
 * and paths hold. Whoever sends it, a handle's holder or a workload.
 */
function aim(request: Request, credential: Resolved, rest: string[], search: string): Aim | Response {
  // Nothing the app writes leaves the credential's upstream: no slash or backslash smuggled in a segment, and no dot
  // segment as a server reads one, decoded, with its `;` parameters dropped as Tomcat and Spring drop them (`..;`).
  // Decoded as often as it changes, up to 8 times and refused past, since a server behind another decodes twice: `%252e%252e` is `..` to it. No control
  // byte either, which a server may cut a segment at (`..%00`), nor an overlong lead byte, which an old one decodes to a
  // dot (`%c0%ae`); and a dot segment is one with trailing blanks too (`..%20`). (`climbs`, @coffre/core/proxy-match.)
  if (rest.some(climbs)) return failure(400, 'the path may not climb out of the credential\'s upstream');
  // The credential's own URL, as the app asked for it: `…/schumann` is the upstream itself, `…/schumann/` the upstream and a slash.
  const target = new URL(`${rest.length === 0 ? credential.base.href : `${credential.base.href.replace(/\/$/, '')}/${rest.join('/')}`}${search}`);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) {
    return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  }
  const relative = target.pathname.slice(under.length) || '/';
  const refused = allowed(credential, request.method, relative);
  if (refused !== null) return refused;
  if (credential.sigv4 !== undefined) {
    if (target.searchParams.has('X-Amz-Signature') || target.searchParams.has('X-Amz-Credential')) return failure(400, `a presigned URL signs with the real key: ${credential.name} takes requests the SDK signs in their headers`);
    const hash = request.headers.get('x-amz-content-sha256') ?? '';
    if (hash.startsWith('STREAMING-') || /aws-chunked/i.test(request.headers.get('content-encoding') ?? '')) {
      return failure(400, `aws-chunked uploads chain their chunks' signatures from the real key: set requestChecksumCalculation: 'WHEN_REQUIRED' in the SDK, for UNSIGNED-PAYLOAD or a literal hash`);
    }
    if (hash !== '' && hash !== 'UNSIGNED-PAYLOAD' && !/^[0-9a-f]{64}$/.test(hash)) return failure(400, 'x-amz-content-sha256 is a SHA-256, hex, or UNSIGNED-PAYLOAD');
  }
  return { target, under, relative };
}

/**
 * The refusal of a request its credential's allow list does not take, or
 * null: 405 when no entry takes its method, on its path or on any; 403 when
 * it is its path no entry takes, or there is no entry. `relative` is the
 * path under the upstream as it goes, each segment matched decoded once
 * against an allow list, as written against legacy paths (@coffre/core/proxy-match). A `*` takes no empty segment (`//`) and none of `;`
 * parameters, spaces or dots alone, which a server may read as none, nor
 * does an `allow` path's trailing slash count one as what is below it; a
 * prefix, a `**`, a trailing slash past a segment a server reads as one, or
 * an entry of methods alone takes them, as S3's keys may hold `//`.
 */
function allowed(credential: Resolved, method: string, relative: string): Response | null {
  if (credential.allowed === null) return null;
  if (credential.allowed.length === 0) return failure(403, `${credential.name}'s allow list is empty: it takes no request`);
  // Legacy paths (`written`) and an allow list's never mix: the request's segments as the one kind or the other compares them.
  const segments = credential.allowed.some((entry) => entry.path !== null) ? requestSegments(relative, credential.allowed.some((entry) => entry.path?.written === true)) : [];
  const verdict = allows(credential.allowed, method, segments);
  if (verdict === 'allowed') return null;
  if (verdict === 'path') return failure(403, `${credential.name} is not for ${relative}`);
  // The methods taken on this path, if an entry takes it, else on any: one list, as `methods` gives it, says no more than that.
  const any = methodsFor(credential.allowed, null);
  const here = methodsFor(credential.allowed, segments);
  if (any.length === 0) return failure(405, `${credential.name} takes no method`);
  return failure(405, here.length === 0 || here.length === any.length ? `${credential.name} takes ${any.join(', ')}` : `${credential.name} takes ${here.join(', ')} on ${relative}`);
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
  return carriedAs(request, credential.name, { field: credential.body.length > 0, sigv4: credential.sigv4 !== undefined });
}

/**
 * `carried`, by what the credential does with a body: `field`, a form or JSON rule's, which fills a field of it;
 * `sigv4`, whose `x-amz-content-sha256` binds it. A UI route's workload request, whose item comes after its proof,
 * is carried by its headers alone (`sigv4` whatever it is, no field: the client's rule, `bodyLine`), and the decided
 * item then takes it or refuses it (`uiCarried`).
 */
async function carriedAs(request: Request, name: string, { field, sigv4 }: { field: boolean; sigv4: boolean }): Promise<Carried | Response> {
  const declared = request.headers.get('content-length') ?? '';
  // A body whose field coffre fills is read whole, and small: it is parsed, and changed.
  const amz = sigv4 && request.headers.has('x-amz-content-sha256');
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
  if (body === null && field) return failure(413, `${name} fills a field of a body read whole, ${MAX_FIELD_BODY / 1024} KiB at most`);
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
/**
 * The stable URL's environment, when the vault's one call finds it (`PluginContext.useMadeFor`): not one of `unless`;
 * where it finds none so, the one `routed` says, or its refusal.
 */
type MadeFor = { unless: readonly string[]; routed: () => Promise<string | Response> };

async function forward(request: Request, coffre: PluginContext, proxy: Proxy, path: string | MadeFor, credential: Resolved, rest: string[], search: string, peeked?: Fillable): Promise<Response> {
  // The stable URL's environment, as `routed` finds it, once: and its refusal before any of the request's own, as when
  // the route was found first (review r2 of #412).
  let routing: Promise<string | Response> | undefined;
  const routed = (made: MadeFor) => (routing ??= made.routed());
  // The body as this credential reads it: under the stable URL, from a copy, so that the request is whole for another
  // reading of the URL, whatever this one made of its body, a refusal's included (review r4 of #467). A streamed body
  // is read from neither: `send` streams the request's own.
  const body = <T>(reading: (from: Request) => Promise<T>): Promise<T> => (typeof path === 'string' ? reading(request) : fromCopy(request, reading));
  const refuse = async (response: Response): Promise<Response> => {
    if (typeof path === 'string') return response;
    const route = await routed(path);
    return route instanceof Response ? route : response;
  };
  // The body, read: a read that throws (a stream that breaks) after the route's refusal, if it has one (review r3).
  const read = async <T>(reading: () => Promise<T>): Promise<T | Response> => {
    try {
      return await reading();
    } catch (error) {
      if (typeof path !== 'string') {
        const route = await routed(path);
        if (route instanceof Response) return route;
      }
      throw error;
    }
  };
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return refuse(aimed);
  // An environment the URL names, which a code item may not serve: before the body is read, or anything opened.
  if (typeof path === 'string' && !serves(credential, path)) return notServed(credential.name, path);
  const { target } = aimed;
  // A form or JSON rule's handle is in the body's field: the body read whole first, and the fields found.
  const early = peeked ?? (credential.body.length > 0 ? await read(() => body((from) => fillable(from, credential))) : null);
  if (early instanceof Response) return refuse(early);
  const fields = early?.fields ?? null;
  const handle = handleIn(request, credential, target, fields?.values);
  if (handle instanceof Response) return refuse(handle);
  if (handle === null) return refuse(failure(401, `send what \`coffre run\` gave your app for its key where ${credential.name} takes it, or the handle as x-coffre-handle`));
  // Each query rule's parameter as the app sent it, if it stands in for this handle, its shape and all: what a redirect
  // under the upstream gives back. Otherwise the placeholder's shape around the handle, which the proxy reads as the app's own
  // (`e30` is `{}`: the proxy reads no claim).
  const back = backOf(credential, target, handle);
  // Read whole first, however long it takes to come, so the handle is checked, and the values opened, as the request goes out.
  const content = early?.content ?? (await read(() => body((from) => carried(from, credential))));
  if (content instanceof Response) return refuse(content);
  const through = { host: target.host };
  let route: string;
  let opened: Opened;
  if (typeof path === 'string') {
    route = path;
    opened = await valuesFor(coffre, proxy, handle, route, credential, through);
  } else {
    const logged = { credential: credential.name, ...through, ...(credential.egress === undefined ? {} : { egress: true }) };
    const made = await coffre.useMadeFor!(handle, { keys: [credential.keys[0]!], purpose: 'use', logged, unless: path.unless });
    if (made === null) {
      const found = await routed(path);
      if (found instanceof Response) return found;
      route = found;
      // Not by name (a SQLite vault's, or an environment `unless` names): the environment, found, is held to the scope all the same.
      if (!serves(credential, route)) return notServed(credential.name, route);
      opened = await valuesFor(coffre, proxy, handle, route, credential, through);
    } else {
      route = made.environment.path;
      // The vault found the environment in the same call: one the credential does not serve gets nothing of it.
      if (!serves(credential, route)) return notServed(credential.name, route);
      if (!Object.hasOwn(made.values, credential.keys[0]!)) throw new CoffreError(409, 'conflict', `${route} holds no ${credential.keys[0]}, which ${credential.name} needs`);
      opened = { values: made.values, plain: made.plain };
    }
  }
  // Each field the handle rides in, as the plan gave it, holds the handle the request is let in on, x-coffre-handle's
  // too: a value goes into no field the app did not put the handle in. A field of plain keys alone holds what the app put.
  if (fields !== null) {
    const ride = riding(credential, (key) => opened.plain.includes(key));
    if (credential.body.some((rule, at) => ride.includes(rule) && handleOf(rule, fields.values[at]!) !== handle)) return failure(400, `the handle is not in the field where ${credential.name} takes its key`);
  }
  const headers = new Headers();
  for (const [name, value] of request.headers) if (sent(name)) headers.set(name, value);
  // Where its redirects stay: the environment's URL, the stable one's included. Under the stable URL, a path that begins
  // with an environment of the handle's would name that environment, and another credential (`/use/schumann/dev/maps/…`).
  return send(request, credential, { ...aimed, ...content, opened, headers, proxied: `${coffre.publicUrl}/use/${route}/${credential.name}`, back, fields, secret: { pattern: HANDLE, length: HANDLE_LENGTH, what: 'the handle' } });
}

/**
 * Each query rule's parameter as the app sent it, if it stands in for this handle, its shape and all: what a redirect
 * under the upstream gives back. Otherwise the placeholder's shape around the handle, which the proxy reads as the app's
 * own (`e30` is `{}`: the proxy reads no claim).
 */
function backOf(credential: Resolved, target: URL, handle: string): [string, string][] {
  return credential.rules.flatMap((rule): [string, string][] => {
    if (rule.kind !== 'query') return [];
    const given = target.searchParams.get(rule.name);
    if (given !== null && handleOf(rule, given) === handle) return [[rule.name, given]];
    const placeholder = credential.placeholder;
    return [[rule.name, placeholder === undefined || rule.shape === undefined ? handle : render(rule.template, { [rule.keys[0]!]: placeholder.kind === 'prefix' ? `${placeholder.prefix}${handle}` : `${UNSIGNED}.e30.${handle}` })]];
  });
}

/**
 * A UI route's request sent, by the item its values were decided on (T186 PR C): every check a code credential's
 * request takes, on that item (its upstream, allow list, body rules), and the handle the use was made on found where
 * the item takes its key, else nothing goes (a copy that let the request through only provisionally: `moved`).
 */
async function sendAs(request: Request, coffre: PluginContext, credential: Resolved, rest: string[], search: string, handle: string, opened: Opened, route: string, sendBy: number, through: Egress | undefined): Promise<Response> {
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return aimed;
  const { target } = aimed;
  const early = credential.body.length > 0 ? await fillable(request, credential) : null;
  if (early instanceof Response) return early;
  const fields = early?.fields ?? null;
  const found = handleIn(request, credential, target, fields?.values);
  if (found instanceof Response) return found;
  if (found !== handle) return failure(400, `send the handle where ${credential.name} takes its key, or as x-coffre-handle`);
  const back = backOf(credential, target, handle);
  const content = early?.content ?? (await carried(request, credential));
  if (content instanceof Response) return content;
  if (fields !== null) {
    const ride = riding(credential, (key) => opened.plain.includes(key));
    if (credential.body.some((rule, at) => ride.includes(rule) && handleOf(rule, fields.values[at]!) !== handle)) return failure(400, `the handle is not in the field where ${credential.name} takes its key`);
  }
  const headers = new Headers();
  for (const [name, value] of request.headers) if (sent(name)) headers.set(name, value);
  return send(request, credential, { ...aimed, ...content, opened, headers, proxied: `${coffre.publicUrl}/use/${route}`, back, fields, secret: { pattern: HANDLE, length: HANDLE_LENGTH, what: 'the handle' }, sendBy, ...(through === undefined ? {} : { through }) });
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
 * One request through a credential, a workload's (docs/design/workload-access.md,
 * section 7.1), or null when it is no workload's, which a handle's path
 * then takes, its body unread. The workload is its key-bound session, sent
 * as `Authorization: DPoP` with a proof, or a Cloudflare service binding's
 * caller. A session's proof signs the request whole (`req`): its path and
 * query, the headers it names (`hdr`), which alone go on, and its body, read
 * whole and hashed, or, through a sigv4 credential, bound by the payload
 * hash it declares, which coffre signs again and the upstream checks
 * against the bytes, so an upload streams; `UNSIGNED-PAYLOAD` there binds
 * nothing, and only a binding that says `unsignedUploads` takes it. Then a
 * `narrow` child's constraints, on the URL about to be sent; the
 * credential's `limit`, counted by the gate in the same call; and the
 * values, opened for the session, or remembered for `cacheSeconds`: the
 * session itself is checked on every request, so a
 * revocation or a freeze stops the next one, warm or not.
 */
async function workloadForward(request: Request, coffre: PluginContext, proxy: Proxy, path: string | null, credential: Resolved, rest: string[], search: string): Promise<Response | null> {
  const token = sessionToken(request);
  const at = { place: path, credential: credential.name, ...countsOf(credential.name, credential.limit) };
  // No session: a Cloudflare call's caller, or no workload at all, which costs nothing to learn and leaves the body unread.
  let caller = token === null ? await workloadOf(request, coffre, at) : null;
  if (caller instanceof Response) return caller;
  if (token === null && caller === null) return null;
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return nonced(aimed, caller);
  // An environment the URL names, which a code item may not serve: before the body is read or the gate asked, as `forward`.
  if (path !== null && !serves(credential, path)) return nonced(notServed(credential.name, path), caller);
  const content = await carried(request, credential);
  if (content instanceof Response) return nonced(content, caller);
  // The body's line in `req`, and the payload hash a sigv4 credential signs again: one value, so what goes out is what
  // the proof bound. A body of any bytes signs the SHA-256 its `Content-Digest` declares, which `carried` and `scanned`
  // hold the bytes to, streamed or not; through a sigv4 credential, the hash its `x-amz-content-sha256` declares, which
  // the upstream checks against them (any other value binds nothing); every other request, an empty body's included
  // whatever its header says, the bytes' own digest.
  // The header that chose the line must be one the proof signs, and a buffered body must be what it declares: neither is
  // left for a copier to pick.
  let payload: string | undefined;
  let declaring: 'content-digest' | 'x-amz-content-sha256' | null = null;
  if (token !== null) {
    // The rule the SDK signs by (`bodyLine`), from the body's length as coffre holds it: a stream's declared content-length,
    // which `scanned` keeps it to, or the bytes read.
    const amz = content.digest === null && credential.sigv4 !== undefined ? request.headers.get('x-amz-content-sha256') : null;
    const declared = content.digest ?? amz;
    const length = content.streamed ? Number(content.declared) : (content.body?.byteLength ?? 0);
    declaring = declared === null || length === 0 ? null : content.digest !== null ? 'content-digest' : 'x-amz-content-sha256';
    const body = await bodyLine({ declared, length, bytes: content.body ?? null });
    if (amz !== null && length !== 0 && !content.streamed && body !== UNSIGNED_BODY && body !== (await bodyDigest(content.body!))) return failure(400, 'the body is not what its x-amz-content-sha256 says');
    payload = body === UNSIGNED_BODY ? 'UNSIGNED-PAYLOAD' : body;
    caller = await workloadOf(request, coffre, { ...at, body });
    if (caller instanceof Response) return caller;
  }
  const workload = caller!;
  return answering(workload, async () => {
    if (declaring !== null && workload.hdr !== null && !workload.hdr.includes(declaring)) {
      return failure(400, `${declaring} says what binds the body, so the proof signs it: name it in hdr`);
    }
    if (workload.path === null) return failure(409, 'the environment this session reaches is gone');
    if (!serves(credential, workload.path)) return notServed(credential.name, workload.path);
    // A form or JSON rule's field, whatever the app put there, as a header rule's header: it holds no handle.
    const fields = credential.body.length > 0 ? fieldsIn(request, content.body, credential.name, credential.body) : null;
    if (fields instanceof Response) return fields;
    if (!constraintsAllow(workload.constraints, { place: workload.path, credential: credential.name, request: { method: request.method, url: aimed.target } })) {
      return failure(403, `this narrowed session may not ${request.method} ${aimed.relative} through ${credential.name}`, 'narrowed');
    }
    const opened = await valuesFor(coffre, proxy, workload, workload.path, credential, { host: aimed.target.host });
    // Only what the proof signs goes on, of what the app sent: a header added on the way, by a library or a proxy, is dropped.
    const headers = new Headers();
    for (const [name, value] of request.headers) if ((workload.hdr === null || workload.hdr.includes(name)) && sent(name)) headers.set(name, value);
    const proxied = `${coffre.publicUrl}/use/${path === null ? '' : `${path}/`}${credential.name}`;
    const secret = token === null ? null : { pattern: new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), length: token.length, what: 'the session token' };
    return send(request, credential, { ...aimed, ...content, opened, headers, proxied, back: [], fields, secret, ...(payload === undefined ? {} : { payload }) });
  });
}

/**
 * A UI route's request by a workload (T186 PR C2b; docs/design/proxy-ui.md, section 3, "Workloads"), or null when it
 * is no workload's: a key-bound session's, or a Cloudflare service binding's call, at the environment the workload's
 * statement checks. The URL is read as the workload's client writes it (`WorkloadAt.or`): `/use/<route>/…` at the one
 * environment it reaches, `/use/<project>/<environment>/<route>/…` when it reaches several, or that one is
 * `<project>/<environment>`. Its item comes after its proof, so in this order:
 * - the body, carried by its headers alone, and its line in `req` from them (`carriedAs`: a declared `Content-Digest`
 *   or `x-amz-content-sha256` streams, any other body is read whole);
 * - the proof, the session's standing and the gate, whose counts are the route's limit: this isolate's copy of the
 *   item, or, on a cold isolate, `coffre.proxyItem`'s, asked as the workload once its place is known (a refusal there
 *   answered after the gate);
 * - the copy's refusals (aim, allow list), provisional unless the copy is fresh, as a handle's are;
 * - the use: the kept values, each with the item they were decided on, or the vault's one route use, as the workload;
 * - every check again on the item the values were decided on, never the copy (`BoundToDefinition`): aim and allow
 *   list, the `narrow` constraints on the URL its upstream makes, and whether it takes the body as it was carried
 *   (`uiCarried`: else 503 `moved`, nothing sent); then the send, before the values' window ends.
 *
 *   market/prod's sidecar, GET /use/openai/v1/models, warm   statement + gate, no vault call: kept values, by their item
 *   the same, cold                                          proxyItem (its limit), then one route use
 *   the same, an Owner pointed openai elsewhere since       the new item's upstream, or 503 moved if it takes no such body
 */
async function uiWorkloadForward(request: Request, coffre: PluginContext, proxy: Proxy, raw: readonly string[], place: readonly string[], url: URL): Promise<Response | null> {
  const token = sessionToken(request);
  if (token === null && !coffre.binding) return null;
  const ui = (name: string | undefined): name is string => name !== undefined && CREDENTIAL_NAME.test(name) && !coded(proxy, name);
  // The readings: route `<a>` at the one environment, or route `<c>` at `<a>/<b>` (`WorkloadAt.or`).
  const placed = raw.length >= 3 && ui(place[2]) ? { place: `${place[0]}/${place[1]}`, credential: place[2]! } : null;
  const at: Pick<WorkloadAt, 'place' | 'credential' | 'or'> | null = ui(place[0])
    ? { place: null, credential: place[0]!, ...(placed === null ? {} : { or: placed }) }
    : placed === null ? null : { place: placed.place, credential: placed.credential };
  if (at === null) return null;
  let through: Egress | undefined;
  if (!proxy.insecure) {
    if (coffre.publicFetch === undefined) return failure(503, 'this runtime has no fetch that checks where an upstream resolves, which a route saved in the Proxy tab is sent through', 'unavailable', '60');
    through = { fetch: coffre.publicFetch };
  }
  // Its body, by its headers alone: the item that says how it goes is not known before the proof that binds it.
  const content = await carriedAs(request, at.credential!, { field: false, sigv4: true });
  if (content instanceof Response) return content;
  const amz = content.digest === null ? request.headers.get('x-amz-content-sha256') : null;
  const declared = content.digest ?? amz;
  const length = content.streamed ? Number(content.declared) : (content.body?.byteLength ?? 0);
  const declaring = declared === null || length === 0 ? null : content.digest !== null ? 'content-digest' : 'x-amz-content-sha256';
  let body: string | undefined;
  if (token !== null) {
    body = await bodyLine({ declared, length, bytes: content.body ?? null });
    if (amz !== null && length !== 0 && !content.streamed && body !== UNSIGNED_BODY && body !== (await bodyDigest(content.body!))) return failure(400, 'the body is not what its x-amz-content-sha256 says');
  }
  // The route's item, by this isolate's copy at the workload's place, or the vault's (`proxyItem`), as its counts need
  // it: a refusal of the item answered once the gate has counted the request.
  const item = itemCounts(proxy);
  const caller = await workloadOf(request, coffre, { ...at, ...(body === undefined ? {} : { body }), counts: item.counts });
  if (caller instanceof Response) return limitRefused(caller, item);
  // Its body read, it is no other caller's request now.
  if (caller === null) return failure(401, "a workload's request carries its session, Authorization: DPoP, with its proof");
  return answering(caller, async () => {
    if (declaring !== null && caller.hdr !== null && !caller.hdr.includes(declaring)) {
      return failure(400, `${declaring} says what binds the body, so the proof signs it: name it in hdr`);
    }
    if (caller.path === null || caller.place === null) return failure(409, 'the environment this session reaches is gone');
    // The reading the checks took: the place's, when the statement found the workload at `<a>/<b>`.
    const named = at.or !== undefined ? caller.path === at.or.place : at.place !== null;
    const name = named ? placed!.credential : at.credential!;
    const rest = raw.slice(named ? 3 : 1);
    const found = item.copy();
    if (found instanceof CoffreError) throw found;
    const keptAt = `w\n${caller.credentialId}\n${caller.place}\n${name}`;
    const nowAt = Date.now();
    let kept = proxy.ui.kept.get(keptAt);
    if (kept !== undefined && kept.until <= nowAt) {
      proxy.ui.kept.delete(keptAt);
      kept = undefined;
    }
    let sendBy: number;
    if (kept === undefined) {
      // No values kept: the copy's refusals before any use, standing when it is fresh (provisional otherwise: the use's
      // answer decides). Kept values answer to their own item alone, never to a newer copy another session's use
      // brought, which would hold the request to both versions' rules at once (P2, review r1 of #477).
      if (found !== null && found.fresh) {
        if (found.definition.kind !== 'route') return failure(404, unrouted(found.definition)!);
        const read = uiCredential(proxy, found.digest, found.definition);
        if (typeof read !== 'string') {
          const aimed = aim(request, read, [...rest], url.search);
          if (aimed instanceof Response) return aimed;
        }
      }
      const used = await coffre.useRoute!(caller, { named: null, stable: name, digests: found === null ? [] : [found.digest], logged: { ui: true }, refuses: (item) => {
        const definition = itemOf(proxy, item);
        return definition === null ? null : unrouted(definition);
      } });
      const definition = itemOf(proxy, used.item);
      if (definition === null) return failure(503, `${used.item.name}: this isolate's copy of its definition is gone; ask again`, 'moved', '1');
      remember(proxy.ui.last, `w\n${caller.place}\n${name}`, { digest: used.item.digest, confirmed: nowAt });
      kept = { values: used.values, plain: used.plain, digest: used.item.digest, definition, reading: 'stable', path: used.environment.path, until: Math.min(nowAt + proxy.cacheMs, Date.parse(used.expiresAt)) };
      if (proxy.cacheMs > 0) remember(proxy.ui.kept, keptAt, kept);
      sendBy = Math.min(nowAt + Math.max(proxy.cacheMs, USE_DEADLINE_MS), Date.parse(used.expiresAt));
    } else {
      sendBy = kept.until;
    }
    if (kept.definition.kind !== 'route') return failure(404, unrouted(kept.definition)!);
    // From here on, the item the values were decided on, never the copy.
    const credential = uiCredential(proxy, kept.digest, kept.definition);
    if (typeof credential === 'string') return failure(503, credential, 'unavailable', '1');
    const aimed = aim(request, credential, [...rest], url.search);
    if (aimed instanceof Response) return aimed;
    const carrying = await uiCarried(request, credential, content, declared);
    if (carrying instanceof Response) {
      if (carrying.status === 503) proxy.ui.kept.delete(keptAt);
      return carrying;
    }
    const fields = credential.body.length > 0 ? fieldsIn(request, carrying.body, credential.name, credential.body) : null;
    if (fields instanceof Response) return fields;
    if (!constraintsAllow(caller.constraints, { place: caller.path, credential: name, request: { method: request.method, url: aimed.target } })) {
      return failure(403, `this narrowed session may not ${request.method} ${aimed.relative} through ${name}`, 'narrowed');
    }
    const headers = new Headers();
    for (const [header, value] of request.headers) if ((caller.hdr === null || caller.hdr.includes(header)) && sent(header)) headers.set(header, value);
    const proxied = `${coffre.publicUrl}/use/${named ? `${caller.path}/` : ''}${name}`;
    const secret = token === null ? null : { pattern: new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), length: token.length, what: 'the session token' };
    const payload = body === undefined || credential.sigv4 === undefined ? undefined : body === UNSIGNED_BODY ? 'UNSIGNED-PAYLOAD' : body;
    return send(request, credential, {
      ...aimed, ...carrying, opened: { values: kept.values, plain: kept.plain }, headers, proxied, back: [], fields, secret,
      ...(payload === undefined ? {} : { payload }), ...(through === undefined ? {} : { through }), sendBy,
    });
  });
}

/**
 * A UI workload request's body as its headers carried it (`carriedAs`), as the decided item takes it: a hash declared
 * in `x-amz-content-sha256` binds it only through a `sigv4` item (another was decided on another copy: 503 `moved`,
 * nothing sent); a form or JSON item fills a field of a body read whole, 64 KiB at most, so a streamed one is read
 * whole now and still held to the digest the proof bound (docs/design/proxy-ui.md, section 3, "What is read before
 * the answer").
 */
async function uiCarried(request: Request, credential: Resolved, content: Carried, declared: string | null): Promise<Carried | Response> {
  if (declared !== null && content.digest === null && credential.sigv4 === undefined) {
    return failure(503, `${credential.name} no longer signs with sigv4(), which this request's x-amz-content-sha256 is for: send it again`, 'moved', '1');
  }
  if (credential.body.length === 0) return content;
  if (!content.streamed) {
    if ((content.body?.byteLength ?? 0) > MAX_FIELD_BODY) return failure(413, `${credential.name} fills a field of a body read whole, ${MAX_FIELD_BODY / 1024} KiB at most`);
    return content;
  }
  const whole = await boundedBody(request, MAX_FIELD_BODY);
  if (whole === null) return failure(413, `${credential.name} fills a field of a body read whole, ${MAX_FIELD_BODY / 1024} KiB at most`);
  if ((whole?.byteLength ?? 0) !== Number(content.declared) || (await bodyDigest(whole ?? new Uint8Array(0))) !== declared) return failure(400, 'the body is not what its digest says');
  return { body: whole, streamed: false, declared: String(whole?.byteLength ?? 0), digest: content.digest };
}

/** A UI item's limit as the gate counts it, under the names code's limit takes (`countsOf`). */
function limitCounts(name: string, given: ProxyLimit, service: string): readonly GateCount[] {
  const limit: Limit = { ...(given.perMinute === null ? {} : { perMinute: given.perMinute }), ...(given.perDay === null ? {} : { perDay: given.perDay }) };
  const made = countsOf(name, limit).counts;
  return made === undefined ? [] : typeof made === 'function' ? [] : made;
}

/** A copy of a UI item at a workload's place: this isolate's, `fresh` when the vault confirmed it within `cacheSeconds`. */
type ItemCopy = { digest: string; definition: ProxyDefinition; fresh: boolean };

/** What `itemCounts` makes: the counts, the copy they were made from (or the vault's refusal of it), and how to ask again. */
type ItemCounted = { counts: PluginCounts; copy: () => ItemCopy | CoffreError | null; refresh: () => (() => Promise<void>) | null };

/**
 * The counts of a workload's request to a UI item (C2b), and the copy they were made from: this isolate's at the
 * workload's place, or, on a cold isolate, the vault's (`proxyItem`, asked as the workload), whose refusal is answered
 * after the gate (`copy`). The request counts against the copy's limit whatever the item's kind and whatever it asks:
 * values kept for this session may still serve it after an Owner saved another kind under the name, which a limit taken
 * only from a kind that takes the request would leave uncounted (review r2 of #480: a kept HMAC signer's signs, under a
 * verifier with the same limit). `refresh`, when a kept copy made the counts, asks the vault for the item again
 * (`limitRefused`).
 */
function itemCounts(proxy: Proxy): ItemCounted {
  let copy: ItemCopy | CoffreError | null = null;
  // The vault's answer for the item, asked as the workload, kept as this isolate's copy (`CopyFromVault`).
  let asked: (() => Promise<void>) | null = null;
  const counts: PluginCounts = async ({ service, place: where, credential: name, item }) => {
    if (where === null || name === null) return [];
    const now = Date.now();
    const reading = `w\n${where}\n${name}`;
    const last = proxy.ui.last.get(reading);
    const held = last === undefined ? undefined : proxy.ui.items.get(last.digest);
    const ask = async () => {
      try {
        const found = await item(name);
        if (found.fault !== null) copy = new CoffreError(503, 'unavailable', `${name}: this environment's proxy definitions are not as the vault sealed them (${found.fault}): an Owner saves them again`, found.fault, '1');
        else if (found.item === null || found.item.definition === null) copy = new CoffreError(404, 'not_found', `this instance has no credential ${JSON.stringify(name)} here: neither its deployment's code nor this environment's definitions name it`);
        else {
          const definition = itemOf(proxy, found.item)!;
          remember(proxy.ui.last, reading, { digest: found.item.digest, confirmed: now });
          copy = { digest: found.item.digest, definition, fresh: true };
        }
      } catch (error) {
        if (!(error instanceof CoffreError)) throw error;
        copy = error;
      }
    };
    if (last !== undefined && held !== undefined) {
      copy = { digest: last.digest, definition: held.definition, fresh: now - last.confirmed < proxy.cacheMs };
      asked = ask;
    } else {
      await ask();
    }
    const found = copy as ItemCopy | CoffreError | null;
    const counted = found === null || found instanceof CoffreError || !('limit' in found.definition) ? null : found.definition.limit;
    return counted === null ? [] : limitCounts(name, counted, service);
  };
  return { counts, copy: () => copy, refresh: () => asked };
}

/**
 * A workload's refusal before its use: refused by a limit a kept copy said, the vault's item now, for the next request,
 * so that a limit an Owner raised since refuses one request more at most, never until its window ends (no use's answer
 * would bring the new item).
 */
async function limitRefused(refusal: Response, item: ItemCounted): Promise<Response> {
  const refresh = item.refresh();
  if (refusal.status === 429 && refresh !== null && (await refusal.clone().json().catch(() => ({})) as { reason?: string }).reason === 'limit') await refresh();
  return refusal;
}

/** What a workload's request answers, a refusal of coffre's included, with the gate's newest nonce on it. */
async function answering(caller: WorkloadUse, work: () => Promise<Response>): Promise<Response> {
  try {
    return nonced(await work(), caller);
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return nonced(failure(error.status, error.message, error.reason ?? error.code, error.retryAfter), caller);
  }
}

/** What `send` takes: where to, what is carried, the values, the headers going on, and what must not leak. */
type Sending = Aim & Carried & {
  opened: Opened;
  headers: Headers;
  /** The proxy's URL for the credential, which a redirect under the upstream is made into. */
  proxied: string;
  /** Each query rule's parameter, the app's placeholder, put back on a redirect to the proxy. */
  back: readonly [string, string][];
  /** The form or JSON rules' fields, which the body goes out with the values in. */
  fields: Fields | null;
  /** What authenticated the request to coffre and goes no further: the handle, a workload's session token; null for a Cloudflare call. */
  secret: { pattern: RegExp; length: number; what: string } | null;
  /** The payload hash a sigv4 credential signs, as a session's proof bound it (its body line); else the request's own, or its bytes'. */
  payload?: string;
  /** How a credential with no egress of its own goes out, a UI route's (`PluginContext.publicFetch`): else the global fetch. */
  through?: Egress;
  /**
   * When the values decided for a UI route's request may last go out (epoch ms): checked as the fetch starts, after the
   * body came and every signature was made, so a request that took longer sends none (review r1 and r3 of #467).
   */
  sendBy?: number;
};

/**
 * The request as it goes out, with the values injected, then the
 * upstream's answer, redacted: a redirect stays on the proxy, and what
 * authenticated the request to coffre goes nowhere upstream.
 */
async function send(request: Request, credential: Resolved, out: Sending): Promise<Response> {
  const { target, under, streamed, declared, digest, headers, opened: { values, plain }, secret } = out;
  let { body } = out;
  // A streamed body says its length itself, which S3 requires of a PutObject.
  if (streamed) headers.set('content-length', declared);
  // Each rule in order: the headers the rules before SigV4 set, which it signs too, so none is swapped on the way.
  const set: string[] = [];
  const filled: string[] = [];
  // What each rule made of its values, as it set it: a later step may drop the header (SigV4 drops host, a filled body
  // its digests), and the upstream may have seen it all the same, or echo what the app sent.
  const made: string[] = [];
  let filling: Rule['kind'] = credential.rules[0]!.kind;
  try {
    for (const rule of credential.rules) {
      filling = rule.kind;
      let assembled: string;
      if (rule.kind === 'header') {
        headers.set(rule.name, render(rule.template, values));
        assembled = headers.get(rule.name)!;
        set.push(rule.name);
      } else if (rule.kind === 'basic') {
        assembled = btoa(binary(new TextEncoder().encode(`${render(rule.user, values)}:${render(rule.password, values)}`)));
        headers.set('authorization', `Basic ${assembled}`);
        set.push('authorization');
      } else if (rule.kind === 'query') {
        assembled = render(rule.template, values);
        target.searchParams.set(rule.name, assembled);
      } else if (inBody(rule)) {
        assembled = render(rule.template, values);
        filled.push(assembled);
      } else {
        // The app's own signature and the headers it signed are its handle's: signed again, for the upstream's host and path.
        for (const name of ['authorization', 'x-amz-date', 'x-amz-security-token']) headers.delete(name);
        // The hash the session's proof bound; else the client's own, as a streamed upload declared it or as sent on, or as its
        // Content-Digest declares it; or the body's, an empty one's included, as SigV4 has it when no header says otherwise.
        const given = out.payload ?? (streamed ? request.headers.get('x-amz-content-sha256') : headers.get('x-amz-content-sha256')) ?? digest;
        const payload = given ?? hex(await crypto.subtle.digest('SHA-256', body ?? new Uint8Array(0)));
        await signV4(request.method, target, headers, payload, {
          accessKeyId: render(rule.accessKeyId, values),
          secretAccessKey: render(rule.secretAccessKey, values),
          ...(rule.sessionToken === undefined ? {} : { sessionToken: render(rule.sessionToken, values) }),
        }, rule, undefined, set);
        assembled = headers.get('authorization')!;
      }
      if (rule.keys.some((key) => !plain.includes(key))) made.push(assembled);
    }
    if (filled.length > 0) body = out.fields!.fill(filled);
  } catch {
    // The platform's error quotes the value it refused: neither it nor its message goes anywhere, a log included.
    return failure(409, `${credential.name}'s value is no valid ${filling === 'query' ? 'query parameter' : 'header value'}: a line break in it, say`);
  }
  // The body changed: a digest of it is made again, of what goes out, and Content-Length is fetch's.
  if (out.fields !== null) {
    for (const name of ['repr-digest', 'digest', 'content-md5']) headers.delete(name);
    if (headers.has('content-digest')) headers.set('content-digest', contentDigest(await bodyDigest(body!)));
  }
  // What authenticated the request goes no further than coffre: anywhere else the app put it, the request stops, as it is or in Basic's base64,
  // or, in a form or JSON body, decoded.
  if (secret !== null) {
    const leaked = [...headers].find(([, value]) => carries(value, secret.pattern)) ?? (carries(bytesOf(target.href), secret.pattern) ? ['URL'] : undefined)
      ?? ((body !== undefined && secret.pattern.test(LATIN1.decode(body))) || (out.fields !== null && secret.pattern.test(out.fields.rest)) ? ['body'] : undefined);
    if (leaked !== undefined) {
      return failure(400, `${secret.what} is somewhere ${credential.name} does not take its key: ${leaked[0] === 'URL' || leaked[0] === 'body' ? `the ${leaked[0]}` : `the ${leaked[0]} header`}`);
    }
  }

  // What the request carried: each secret value of every rule's, and what each rule made of them, a header's filled
  // template, Basic's base64, as stored and as they went out (`Headers` trims a value's surrounding whitespace), in each
  // form an honest upstream may echo it in (`echoed`). A plain value is no secret, and an upstream quotes an account's id
  // back as a matter of course: it stays, and so does what a rule made of plain values alone.
  const secrets = Object.entries(values).filter(([key]) => !plain.includes(key)).map(([, value]) => value);
  const redact = redactor([...secrets.flatMap((value) => [value, value.trim()]), ...made].flatMap(echoed));

  // A streamed body's refusal, once `scanned` stops it: the answer, whatever the upstream made of the broken request.
  // Values decided for a request sent within their window: one whose body, digest or signature came after it goes with none.
  if (out.sendBy !== undefined && Date.now() > out.sendBy) return failure(503, `${credential.name}: the request was ready after its values may be sent; send it again`, 'late', '1');
  const upload = streamed ? scanned(request.body!, Number(declared), secret, digest) : null;
  let upstream: Response;
  try {
    upstream = await (credential.egress ?? out.through ?? globalThis).fetch(target, {
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
  // Redacted as the bytes it came in, before a URL encodes them again.
  const raw = upstream.headers.get('location');
  const location = raw === null ? null : redact.whole(raw);
  let at: string | null = null;
  if (location !== null) {
    // A `Location` no URL reads, `//` say, is nowhere under the upstream.
    const to = URL.canParse(location, target) ? new URL(location, target) : null;
    const inside = to !== null && to.origin === credential.base.origin && (to.pathname === under || to.pathname.startsWith(`${under}/`));
    if (inside) {
      // The proxy's URL for it, and a query rule's parameter, kept or not, the app's placeholder, for it to follow and be let in.
      const moved = new URL(`${out.proxied}${to.pathname.slice(under.length)}${to.search}`);
      for (const [name, value] of out.back) moved.searchParams.set(name, value);
      at = moved.href;
    } else if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel();
      // Where to is the upstream's to say, and may hold anything: the refusal names only the credential.
      return failure(502, `the upstream redirected outside ${credential.name}'s, where its key does not go`);
    } else at = location;
  }
  const refused = upload?.refused() ?? null;
  if (refused !== null) {
    await upstream.body?.cancel();
    return failure(400, refused);
  }
  return redacted(upstream, redact, at);
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
  let seen = 0;
  let refusal: string | null = null;
  const refuse = (why: string): never => {
    refusal = why;
    throw new Error(why);
  };
  const hash = digest === null ? null : createHash('sha256');
  const keep = Math.max(1, (secret?.length ?? 0) - 1);
  const checked = body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, out) {
        seen += chunk.length;
        if (seen > length) refuse('the body ran past the length it declared');
        hash?.update(chunk);
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
        if (seen !== length) refuse('the body ended short of the length it declared');
        if (hash !== null && hash.digest('hex') !== digest) refuse('the body is not what its Content-Digest says');
        if (held.length > 0) out.enqueue(held);
      },
    }),
  );
  const Fixed = (globalThis as { FixedLengthStream?: new (length: number) => TransformStream<Uint8Array, Uint8Array> }).FixedLengthStream;
  return { body: Fixed === undefined ? checked : checked.pipeThrough(new Fixed(length)), refused: () => refusal };
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
 * Who uses a credential: a handle, or a workload `workload` authenticated
 * for this request. A workload's values are kept per session, environment
 * and credential, its session checked on every request before they are.
 */
type User = string | WorkloadUse;

/** What a caller's values are kept under, and its tunnel group: the handle, or the session (a Cloudflare call's binding), with the environment and credential. */
function cacheKey(user: User, path: string, name: string): string {
  if (typeof user === 'string') return `${user}\u0000${path}\u0000${name}`;
  return `\u0001${user.profile === 'cloudflare' ? `binding:${user.bindingId}` : user.credentialId}\u0000${user.place}\u0000${name}`;
}

/**
 * The credential's values for the handle or workload: remembered for
 * `cacheSeconds` from when the vault was asked, or opened now, logged as
 * one use. In the last `refreshWindow` of an entry, one request at a time
 * asks the vault again, for `REFRESH_ATTEMPT_MS` at most, and every other
 * is served the entry meanwhile, so a steady caller does not turn a lapse
 * into a call per request. The one asking is served the entry too should
 * the vault not answer, and a second later another asks; refused, the
 * entry goes. Nothing serves past `until`.
 */
async function valuesFor(
  coffre: PluginContext,
  proxy: Proxy,
  user: User,
  path: string,
  credential: { name: string; keys: readonly string[]; egress?: Egress },
  /** What the use is, for its entry in the log: the upstream's host, `{ tunnel: true }` or `{ hmac: true }`. */
  through: { host: string } | { tunnel: true } | { hmac: true },
  /** Told when the vault decided now, not the cache. */
  decided?: () => void,
): Promise<Opened> {
  const key = cacheKey(user, path, credential.name);
  const now = Date.now();
  const kept = proxy.cache.get(key);
  const live = kept !== undefined && kept.until > now ? kept : undefined;
  // Until when this request holds the others off, should it ask.
  const hold = now + Math.min(REFRESH_ATTEMPT_MS, refreshWindow(proxy.cacheMs) / 2);
  if (live !== undefined) {
    if (now < live.refreshFrom || (live.hold !== undefined && now < live.hold)) return live;
    live.hold = hold;
  }
  let used: Used;
  try {
    used = await coffre.use(user, { path: readOf(proxy, path, user), keys: credential.keys, purpose: 'use', only: true, logged: { credential: credential.name, ...through, ...(credential.egress === undefined ? {} : { egress: true }) } });
  } catch (error) {
    const held = proxy.cache.get(key);
    // Refused: whatever the key holds goes, an answer another request kept meanwhile included; at worst it asks again.
    if (error instanceof CoffreError && REFUSED.has(error.status)) {
      proxy.cache.delete(key);
      throw error;
    }
    // The vault, or the database, did not answer: the entry held now still serves, whichever request made it. Anything else is no answer of theirs.
    const unanswered = isUnavailable(error) || (error instanceof CoffreError && error.status === 503);
    if (live === undefined || !unanswered || held === undefined || held.until <= Date.now()) throw error;
    console.error("the proxy's cache asked the vault again, unanswered; serving what it holds", logged(error));
    // Another a second on, unless one already asks after it, whose hold stands.
    if (held === live && live.hold === hold) live.hold = Date.now() + REFRESH_RETRY_MS;
    return held;
  }
  const missing = credential.keys.filter((name) => !Object.hasOwn(used.values, name));
  if (missing.length > 0) {
    proxy.cache.delete(key);
    throw new CoffreError(409, 'conflict', `${used.environment.path} holds no ${missing.join(', ')}, which ${credential.name} needs`);
  }
  decided?.();
  // Kept only over the entry it set out from: an older answer replaces no newer one, brings back none a refusal ended, and none a tunnel's end removed.
  if (proxy.cacheMs > 0 && (live === undefined || proxy.cache.get(key) === live)) {
    // Its own entry out first, so that it goes last in line, and replacing it makes no room at another's cost.
    proxy.cache.delete(key);
    // A handful of handles in a dev loop: past a thousand, the oldest go.
    if (proxy.cache.size >= 1000) for (const [old, entry] of proxy.cache) if (entry.until <= now || proxy.cache.size >= 1000) proxy.cache.delete(old);
    // From when the vault was asked, not when it answered: a revoked handle serves no longer than `cacheSeconds`.
    const until = Math.min(now + proxy.cacheMs, Date.parse(used.expiresAt));
    // An answer that serves no longer than the last (the handle's or session's end) is not asked for again.
    const refreshFrom = live !== undefined && until <= live.until ? until : until - refreshWindow(proxy.cacheMs);
    proxy.cache.set(key, { values: used.values, plain: used.plain, until, refreshFrom });
  }
  return { values: used.values, plain: used.plain };
}

/** The templates of a rule's that the app's request carries the handle in, when a key in them is no plain one: SigV4's access key id alone, which the SDK sends. */
function handleSlots(rule: Rule): string[] {
  return rule.kind === 'basic' ? [rule.user, rule.password] : rule.kind === 'sigv4' ? [rule.accessKeyId] : [rule.template];
}

const namesSecret = (rule: Rule, plain: (key: string) => boolean) => handleSlots(rule).some((slot) => [...slot.matchAll(TEMPLATE_KEY)].some((match) => !plain(match[1]!)));

/**
 * Whether the app's request still carries the handle where the proxy looks
 * for it (`handleIn`) when the `plain` keys of its rules are given as they
 * are: a key that is no plain one in a header's or a parameter's template,
 * a field's, in Basic's user or password, or in SigV4's access key id.
 */
function carriesHandle(rules: readonly Rule[], plain: ReadonlySet<string>): boolean {
  return rules.some((rule) => namesSecret(rule, (key) => plain.has(key)));
}

/**
 * The rules whose slots the app's request carries the handle in, as the plan
 * gave it: those naming a key that is no plain one; every rule, where all
 * its keys are plain, which then stay placeholders.
 */
function riding(credential: Resolved, plain: (key: string) => boolean): readonly Rule[] {
  const secret = credential.rules.filter((rule) => namesSecret(rule, plain));
  return secret.length > 0 ? secret : credential.rules;
}

/**
 * The handle, where the app sends it: `x-coffre-handle` (the `credential(name)`
 * helper), or where any rule of the credential takes its key, a form or JSON
 * rule's in its field (`fields`, in the order of the body's rules); null for
 * none; a refusal for two different ones, which no app sends. Every handle
 * the request carries where the proxy looks counts against the one it takes,
 * whatever its shape: a parameter given twice (`?token=p_H1&token=H2`), a
 * header given twice, which `Headers` joins, two Basic pairs, or two handles
 * in one slot. Only one in a placeholder's shape, or in x-coffre-handle,
 * lets the request in.
 */
function handleIn(request: Request, credential: Resolved, target: URL, fields: readonly string[] = []): string | null | Response {
  const explicit = request.headers.get('x-coffre-handle');
  const taken = new Set(explicit?.match(HANDLES) ?? []);
  if (explicit !== null && taken.size === 0) return null;
  const seen = new Set(taken);
  const authorization = request.headers.get('authorization');
  let field = 0;
  for (const rule of credential.rules) {
    // Basic's and SigV4's Authorization header as sent: a handle in it outside the pair or the signature counts too.
    if ((rule.kind === 'basic' || rule.kind === 'sigv4') && authorization !== null) for (const handle of authorization.match(HANDLES) ?? []) seen.add(handle);
    for (const slot of slotsOf(request, rule, target, inBody(rule) ? (fields[field++] ?? null) : null)) {
      for (const handle of slot.match(HANDLES) ?? []) seen.add(handle);
      const handle = handleOf(rule, slot);
      if (handle !== null) taken.add(handle);
    }
  }
  if (seen.size > 1) return failure(400, `the request carries two different handles: ${credential.name} takes one`);
  return taken.values().next().value ?? null;
}

/** What the app put where a rule takes its key, each time it put it: a header, a parameter, a field (given), Basic's pair, or SigV4's access key id. */
function slotsOf(request: Request, rule: Rule, target: URL, field: string | null): string[] {
  if (rule.kind === 'header') return [request.headers.get(rule.name)].filter((slot) => slot !== null);
  if (rule.kind === 'query') return target.searchParams.getAll(rule.name);
  if (rule.kind === 'form' || rule.kind === 'json') return field === null ? [] : [field];
  const authorization = request.headers.get('authorization');
  if (authorization === null) return [];
  // The SDK's `Credential=<access key id>/…`: the handle, as the access key it signed with.
  if (rule.kind === 'sigv4') return [...authorization.matchAll(/Credential=([^/,\s]+)\//g)].map((match) => match[1]!);
  // Each pair, where `Headers` joined two Authorization headers (base64 has no comma).
  return authorization.split(',').flatMap((part) => {
    const basic = /^\s*Basic\s+(\S+)\s*$/i.exec(part);
    try {
      return basic === null ? [] : [atob(basic[1]!)];
    } catch {
      return [];
    }
  });
}

/** The handle in what the app put where a rule takes its key: a shaped placeholder's slot is that shape exactly; the handle alone is found wherever the rule frames it. */
function handleOf(rule: Rule, slot: string): string | null {
  return rule.shape === undefined ? (HANDLE.exec(slot)?.[0] ?? null) : (rule.shape.exec(slot)?.[1] ?? null);
}

function bearer(request: Request): string | null {
  return /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
}

function inBody<T extends Inject>(inject: T): inject is Extract<T, { kind: 'form' | 'json' }> {
  return inject.kind === 'form' || inject.kind === 'json';
}

/**
 * The fields a credential's form or JSON rules fill, in the request's body:
 * what the app put in each, decoded, in the rules' order; every other name
 * and value in the body, decoded, a line each, which nothing that
 * authenticated the request may be in; and the body with a value in each
 * field's place, every other byte as it was.
 */
type Fields = { values: readonly string[]; rest: string; fill: (values: readonly string[]) => Uint8Array<ArrayBuffer> };

/**
 * The fields a credential's form or JSON rules fill, in a body of the type
 * they name, in UTF-8 and not compressed, or the refusal: a field missing,
 * a field twice, which upstreams read differently, or a JSON field that
 * holds no string. Nothing of the body is quoted: the handle, or another
 * secret, may be in it.
 */
function fieldsIn(request: Request, body: Uint8Array | undefined, name: string, rules: readonly BodyRule[]): Fields | Response {
  const kind = rules[0]!.kind;
  const named = rules.map((rule) => rule.name);
  const said = named.join(' and ');
  const type = kind === 'form' ? 'application/x-www-form-urlencoded' : 'application/json';
  if (body === undefined || body.length === 0) return failure(400, `${name} takes its key in the ${said} field${named.length > 1 ? 's' : ''} of the body: send one, ${type}, with a POST or the like`);
  if (bodyKind(request) !== kind) {
    return failure(415, `${name} takes its key in the ${said} field${named.length > 1 ? 's' : ''} of an ${type} body, UTF-8 and not compressed`);
  }
  const found = (kind === 'form' ? formFields : jsonFields)(body, named);
  return typeof found === 'string' ? failure(400, `the body ${found}, where ${name} takes its key`) : found;
}

/**
 * The rule kind whose fields a body can hold, by its Content-Type: a form's or JSON's, in UTF-8 and not compressed;
 * else none, which `fieldsIn` refuses (415).
 */
function bodyKind(request: Request): BodyRule['kind'] | null {
  const [media, ...parameters] = (request.headers.get('content-type') ?? '').split(';').map((part) => part.trim().toLowerCase());
  const charset = parameters.find((parameter) => parameter.startsWith('charset='))?.slice('charset='.length).replace(/^"(.*)"$/, '$1');
  if ((charset !== undefined && charset !== 'utf-8') || !/^(identity)?$/i.test(request.headers.get('content-encoding') ?? '')) return null;
  return media === 'application/x-www-form-urlencoded' ? 'form' : media === 'application/json' ? 'json' : null;
}

/**
 * A form's field, as WHATWG's parser reads one: `&`-separated pairs, the
 * name up to the first `=`, `+` a space and `%XX` a byte. Filled, the pair
 * keeps its name as written and takes the value form-encoded. Scanned as
 * bytes, one character each, so every other byte goes on as it came.
 */
function formFields(bytes: Uint8Array, wanted: readonly string[]): Fields | string {
  const pairs = binary(bytes).split('&', MAX_FIELDS + 1);
  if (pairs.length > MAX_FIELDS) return `has more than ${MAX_FIELDS} fields`;
  const decoded = (part: string) => bytesOf(part.replace(/\+/g, ' '));
  // A name is the field's as written, or once decoded, where it has anything to decode; one `alike` it makes it twice.
  const names = pairs.map((pair) => {
    const equals = pair.indexOf('=');
    const key = equals === -1 ? pair : pair.slice(0, equals);
    return /[%+]/.test(key) ? decoded(key) : key;
  });
  const indexes: number[] = [];
  for (const name of wanted) {
    const at = names.flatMap((key, index) => (key === name ? [index] : []));
    if (at.length === 0) return `has no ${name} field`;
    const as = alike(name);
    if (at.length > 1) return `has the ${name} field more than once`;
    if (names.filter((key) => alike(key) === as).length > 1) return `has a name alike ${name}, which some upstreams read as it`;
    indexes.push(at[0]!);
  }
  const value = (pair: string) => {
    const equals = pair.indexOf('=');
    return new TextDecoder().decode(binaryBytes(decoded(equals === -1 ? '' : pair.slice(equals + 1))));
  };
  return {
    values: indexes.map((index) => value(pairs[index]!)),
    rest: decoded(pairs.filter((_, other) => !indexes.includes(other)).join('\n')),
    fill: (filled) => binaryBytes(pairs.map((pair, at) => {
      const field = indexes.indexOf(at);
      if (field === -1) return pair;
      const equals = pair.indexOf('=');
      return `${equals === -1 ? pair : pair.slice(0, equals)}=${new URLSearchParams([['', filled[field]!]]).toString().slice(1)}`;
    }).join('&')),
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
function jsonFields(bytes: Uint8Array, wanted: readonly string[]): Fields | string {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return 'is no JSON';
  }
  let depth = 0;
  let from = 0;
  let strings = 0;
  // Which field the last string named, its value next (-1: none); and where each field's value lies.
  let named = -1;
  const found: ({ start: number; end: number; value: string } | null)[] = wanted.map(() => null);
  const rest: string[] = [];
  const alikes = wanted.map(alike);
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
    for (const match of jsonStrings(text)) {
      const gap = text.slice(from, match.index);
      if (deeper(gap)) return `nests deeper than ${MAX_DEPTH}`;
      // A name and a value each.
      if (++strings > 2 * MAX_FIELDS) return `has more than ${MAX_FIELDS} fields`;
      from = match.index + match.raw.length;
      const string = match.raw.includes('\\') ? (JSON.parse(match.raw) as string) : match.raw.slice(1, -1);
      if (named !== -1) {
        if (!/^\s*:\s*$/.test(gap)) return `gives ${wanted[named]} as no string`;
        found[named] = { start: match.index, end: from, value: string };
        named = -1;
      } else if (depth === 1 && ((colon.lastIndex = from), colon.test(text))) {
        // A name at the top: a field's, once; any other `alike` one makes it twice.
        const field = wanted.indexOf(string);
        const like = alikes.indexOf(alike(string));
        if (field !== -1 && found[field] === null) named = field;
        else if (like !== -1) return string === wanted[like] ? `has the ${string} field more than once` : `has a name alike ${wanted[like]}, which some upstreams read as it`;
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
  if (named !== -1) return `gives ${wanted[named]} as no string`;
  const missing = found.findIndex((field) => field === null);
  if (missing !== -1) return `has no ${wanted[missing]} field at its top`;
  const places = found as { start: number; end: number; value: string }[];
  return {
    values: places.map((field) => field.value),
    rest: rest.join('\n'),
    fill: (filled) => {
      // Each value's string replaced, from the last in the document to the first, so the earlier places stand.
      let out = text;
      for (const at of places.map((_, index) => index).sort((x, y) => places[y]!.start - places[x]!.start)) out = `${out.slice(0, places[at]!.start)}${JSON.stringify(filled[at]!)}${out.slice(places[at]!.end)}`;
      return new TextEncoder().encode(out);
    },
  };
}

/**
 * Each string of a JSON document, in order, as written and where it starts: a quote outside a string opens one, a
 * backslash takes the character after it, and a string that never closes ends the scan. Each character is read once,
 * so 64 KiB of escaped quotes that never close (`"\"\"\"…`) cost their length; the regex this replaced, retried
 * from each quote, cost their square, seconds of CPU before any check (review r8 of #467).
 */
function* jsonStrings(text: string): Generator<{ index: number; raw: string }> {
  for (let at = text.indexOf('"'); at !== -1; ) {
    let end = at + 1;
    while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
    if (end >= text.length) return;
    yield { index: at, raw: text.slice(at, end + 1) };
    at = text.indexOf('"', end + 1);
  }
}

/** A form or JSON rule's body, read whole, and its fields in it. */
type Fillable = { content: Carried; fields: Fields };

async function fillable(request: Request, credential: Resolved): Promise<Fillable | Response> {
  const content = await carried(request, credential);
  if (content instanceof Response) return content;
  const fields = fieldsIn(request, content.body, credential.name, credential.body);
  return fields instanceof Response ? fields : { content, fields };
}

/**
 * A form or JSON rule's body and fields, or its refusal of the body, for the
 * stable URL, which needs the handle before it knows the route: read from a
 * copy, which the route sends if it goes through this credential. A route
 * through one that was not peeked, a header rule's, reads the request itself.
 * Null for a credential with no such rule.
 */
async function peekField(request: Request, credential: Resolved): Promise<Fillable | Response | null> {
  if (credential.body.length === 0) return null;
  return fromCopy(request, (copy) => fillable(copy, credential));
}

/** What `reading` makes of a copy of the request, whose own body is left unread. */
async function fromCopy<T>(request: Request, reading: (copy: Request) => Promise<T>): Promise<T> {
  const copy = request.clone();
  try {
    return await reading(copy);
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
  const given = (Array.isArray(credential.inject) ? credential.inject : [credential.inject]) as readonly Inject[];
  if (given.length === 0) throw new Error(`credentialProxy: ${name}'s inject is a rule or a list of them, header('x-api-key', '{SCHUMANN_API_KEY}')`);
  const rules = given.map((inject) => checkRule(name, inject));
  checkRules(name, rules);
  const keys = [...new Set(rules.flatMap((rule) => rule.keys))];
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
  if (credential.placeholder !== undefined) {
    const placeholder = credential.placeholder;
    checkPlaceholder(name, placeholder);
    // Each rule that carries one key, once, may be the one the placeholder shapes: which one, the environment's plain keys say (`riding`).
    for (const [at, rule] of rules.entries()) if (shapeable(rule)) rules[at] = { ...rule, shape: placeholderShape(placeholder, rule) };
    if (!rules.some((rule) => rule.shape !== undefined)) {
      const kinds = [...new Set(rules.map((rule) => (rule.kind === 'basic' || rule.kind === 'sigv4' ? `a ${rule.kind}() rule` : 'a template with several keys, or one twice')))];
      throw new Error(`credentialProxy: ${name}'s placeholder shapes the one key a header, query, form or JSON rule carries, header('authorization', 'Bearer {TOKEN}'), not ${kinds.join(' or ')}`);
    }
  }
  limited(name, credential.limit);
  const { inject: _inject, allow: _allow, ...rest } = credential;
  const body = rules.filter((rule): rule is BodyRule => inBody(rule));
  const sigv4 = rules.find((rule): rule is SigV4Rule => rule.kind === 'sigv4');
  return { ...rest, name, base, keys, rules, body, sigv4, allowed: allowList(name, credential), ...checkScope(name, 'credential', credential.environments) };
}

/** A rule as written, checked: its names and the keys its templates name, at least one. */
function checkRule(name: string, inject: Inject): Rule {
  if (typeof inject !== 'object' || inject === null || !['header', 'query', 'form', 'json', 'basic', 'sigv4'].includes(inject.kind)) {
    throw new Error(`credentialProxy: ${name}'s inject is header(…), query(…), form(…), json(…), basic(…) or sigv4(…), or a list of them`);
  }
  if ((inject.kind === 'header' || inject.kind === 'query') && !PARAMETER_NAME.test(inject.name)) throw new Error(`credentialProxy: ${name} injects into ${JSON.stringify(inject.name)}, which is no header or parameter name`);
  if (inBody(inject) && !FIELD_NAME.test(inject.name)) throw new Error(`credentialProxy: ${name} fills the field ${JSON.stringify(inject.name)}, which is no field name: letters, digits and _.-, a letter or digit among them, at the top of the body`);
  if (inject.kind === 'sigv4' && (!/^[a-z0-9-]{1,32}$/.test(inject.region) || !/^[a-z0-9-]{1,32}$/.test(inject.service))) throw new Error(`credentialProxy: ${name} signs for a region and a service, eu-west-3 and s3`);
  const keys = [...new Set(templatesOf(inject).flatMap((template) => [...template.matchAll(TEMPLATE_KEY)].map((match) => match[1]!)))];
  if (keys.length === 0) throw new Error(`credentialProxy: ${name}'s rule names no key: write it as {KEY}, as header('x-api-key', '{SCHUMANN_API_KEY}')`);
  // A header's name as `Headers` keeps it, which SigV4's signed headers and the checks below compare.
  return inject.kind === 'header' ? { ...inject, name: inject.name.toLowerCase(), keys } : { ...inject, keys };
}

/** A rule's templates: each a string with `{KEY}`s in it. */
function templatesOf(inject: Inject): string[] {
  if (inject.kind === 'basic') return [inject.user, inject.password];
  if (inject.kind === 'sigv4') return [inject.accessKeyId, inject.secretAccessKey, ...(inject.sessionToken === undefined ? [] : [inject.sessionToken])];
  return [inject.template];
}

/**
 * A credential's rules together (docs/design/proxy-ui.md, section 7): one
 * per header, parameter or field, so none undoes another; Basic's and
 * SigV4's `authorization` set by them alone; SigV4 last, over every header
 * the rules before it set, and with no field of the body, which it signs
 * the hash of; a body a form's or a JSON's.
 */
function checkRules(name: string, rules: readonly Rule[]): void {
  const seen = new Map<string, Rule>();
  for (const rule of rules) {
    const slot = rule.kind === 'header' ? `the header ${rule.name}` : rule.kind === 'query' ? `the parameter ${rule.name}` : inBody(rule) ? `the field ${rule.name}` : `${rule.kind}()`;
    // A field as an upstream's parser may read it (`alike`): `secret` and `SECRET` are one.
    const id = rule.kind === 'header' ? `header ${rule.name}` : rule.kind === 'query' ? `query ${alike(rule.name)}` : inBody(rule) ? `field ${alike(rule.name)}` : rule.kind;
    if (seen.has(id)) throw new Error(`credentialProxy: ${name} sets ${slot} twice: one rule each`);
    seen.set(id, rule);
  }
  const sigv4 = rules.findIndex((rule) => rule.kind === 'sigv4');
  const authorization = seen.has('header authorization');
  if (seen.has('basic') && authorization) throw new Error(`credentialProxy: ${name}'s basic() sets the authorization header, which another of its rules sets too`);
  if (rules.some(inBody) && rules.some((rule) => rule.kind === (rules.find(inBody)!.kind === 'form' ? 'json' : 'form'))) {
    throw new Error(`credentialProxy: ${name} fills fields of a form and of a JSON body, and a request's body is one or the other`);
  }
  if (sigv4 === -1) return;
  if (sigv4 !== rules.length - 1) throw new Error(`credentialProxy: ${name}'s sigv4() comes last, signing what the rules before it set`);
  const owned = rules.find((rule) => rule.kind === 'basic' || ((rule.kind === 'header' || rule.kind === 'query') && (rule.name.toLowerCase() === 'authorization' || rule.name.toLowerCase().startsWith('x-amz-'))));
  if (owned !== undefined) {
    throw new Error(`credentialProxy: ${name}'s sigv4() owns the authorization header and the x-amz- headers and parameters, which ${owned.kind === 'basic' ? 'basic()' : `its ${owned.kind} rule ${(owned as { name: string }).name}`} sets`);
  }
  if (rules.some(inBody)) throw new Error(`credentialProxy: ${name}'s sigv4() signs the body's hash, which a form or JSON rule would change after`);
}

/** Whether a placeholder may shape a rule's slot: a header, query, form or JSON rule that names one key, once. */
function shapeable(rule: Rule): rule is Extract<Rule, { template: string }> {
  return rule.kind !== 'basic' && rule.kind !== 'sigv4' && [...rule.template.matchAll(TEMPLATE_KEY)].length === 1;
}

/** An allow list as configured, read: `allow`'s entries, or `methods` and `paths` as one entry per path; null for none, which takes every request. */
function allowList(name: string, credential: Credential): readonly AllowEntry[] | null {
  const methods = (given: readonly string[] | undefined, legacy: boolean): ReadonlySet<string> | null => {
    if (given === undefined) return null;
    if (!Array.isArray(given) || given.some((method) => typeof method !== 'string' || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(method))) throw new Error(`credentialProxy: ${name}'s methods are a list of methods, ['GET', 'POST']`);
    // `allow`'s none is any, as the Proxy tab's; `methods: []`, as before 0.16, takes none.
    return given.length === 0 && !legacy ? null : new Set(given.map((method) => method.toUpperCase()));
  };
  const path = (given: string, from: 'legacy' | 'code') => {
    const read = readPattern(given, from);
    if ('problem' in read) throw new Error(`credentialProxy: ${name}'s path ${JSON.stringify(given)}: ${read.problem}`);
    if (read.warning !== undefined) console.warn(`credentialProxy: ${name}'s path ${read.warning}`);
    return read.pattern;
  };
  if (credential.allow !== undefined) {
    if (credential.methods !== undefined || credential.paths !== undefined) throw new Error(`credentialProxy: ${name} says which requests it takes in allow, or in methods and paths, not both`);
    if (!Array.isArray(credential.allow)) throw new Error(`credentialProxy: ${name}'s allow is a list of { methods, path }`);
    return credential.allow.map((entry) => {
      if (typeof entry !== 'object' || entry === null || Object.keys(entry).some((option) => option !== 'methods' && option !== 'path')) throw new Error(`credentialProxy: ${name}'s allow entries are { methods, path }`);
      const read = { methods: methods(entry.methods, false), path: entry.path === undefined ? null : path(entry.path, 'code') };
      // An entry of any method on any path, `{}` or `{ methods: [] }`, would take every request, whatever the others say: say so
      // with no allow at all. Checked as read, not as spelled: legacy `methods: []` took none, and carried into an entry it would take all.
      if (read.methods === null && read.path === null) throw new Error(`credentialProxy: ${name}'s allow entry ${JSON.stringify(entry)} takes every request: give it methods or a path, or leave allow out`);
      return read;
    });
  }
  if (credential.methods === undefined && credential.paths === undefined) return null;
  const taken = methods(credential.methods, true);
  if (credential.paths === undefined) return [{ methods: taken, path: null }];
  if (!Array.isArray(credential.paths)) throw new Error(`credentialProxy: ${name}'s paths are a list, ['/companies']`);
  // `paths: []` takes no path, but its methods still answer first, as before 0.16: `methods: ['POST'], paths: []` is a
  // 405 to a GET and a 403 to a POST. An entry whose path matches none keeps them; no entry at all would be a 403 to both.
  if (credential.paths.length === 0) return [{ methods: taken, path: { segments: [], tail: 'never', written: true } }];
  // A path of `paths` matches as it did before 0.16 (`readPattern`'s `legacy`): `*` itself, never a glob, and `//` or `;x` as written.
  return credential.paths.map((given) => {
    if (typeof given === 'string' && given.includes('*')) console.warn(`credentialProxy: ${name}'s path ${given} takes * as itself, as before 0.16: allow: [{ path }] reads * and ** as globs`);
    return { methods: taken, path: path(given, 'legacy') };
  });
}

/** The environments a code item serves, checked: full paths, `market/prod`, since a bare `prod` would be every project's. */
function checkScope(name: string, what: string, environments: readonly string[] | undefined): { environments?: readonly string[] } {
  if (environments === undefined) return {};
  if (!Array.isArray(environments) || environments.length === 0 || environments.some((path) => typeof path !== 'string' || !/^[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/.test(path))) {
    throw new Error(`credentialProxy: ${what} ${name}'s environments are the paths it serves, ['market/prod']: every one, unless set`);
  }
  return { environments: [...environments] };
}

/**
 * Code's items as the Proxy tab shows them, locked (docs/design/proxy-ui.md,
 * section 6): each in the shape of a UI definition, read from the config as
 * written, already checked. What has no field there is said apart: a limit
 * per service, and a binding (an egress, a network), which has no name.
 * Legacy `methods` and `paths` read as their allow entries.
 */
function codeItems(credentials: Record<string, Credential>, tunnels: ReadonlyMap<string, Tunnel>, signers: ReadonlyMap<string, Signer>, verifiers: ReadonlyMap<string, Hmac>): ProxyCodeItem[] {
  const scope = (item: { environments?: readonly string[] }) => (item.environments === undefined ? null : [...item.environments]);
  const limit = (given: Limits | undefined): { limit: ProxyLimit; limitPerService: boolean } =>
    typeof given === 'function' ? { limit: { perMinute: null, perDay: null }, limitPerService: true } : { limit: { perMinute: given?.perMinute ?? null, perDay: given?.perDay ?? null }, limitPerService: false };
  const hmacOf = (signer: Hmac): ProxyHmac => ({ key: signer.key, encoding: signer.encoding, prefix: signer.prefix ?? '', maxBytes: signer.maxBytes ?? null });
  const item = (definition: ProxyDefinition, from: { environments?: readonly string[] }, limitPerService = false, bound = false, allowAs: ProxyCodeItem['allowAs'] = null): ProxyCodeItem => ({ definition, environments: scope(from), limitPerService, bound, allowAs });
  return [
    ...Object.entries(credentials).map(([name, credential]) => {
      const rules = (Array.isArray(credential.inject) ? credential.inject : [credential.inject]) as readonly Inject[];
      const inject = rules.map((rule): ProxyInject => (rule.kind === 'sigv4'
        ? { kind: 'sigv4', accessKeyId: rule.accessKeyId, secretAccessKey: rule.secretAccessKey, sessionToken: rule.sessionToken ?? null, region: rule.region, service: rule.service }
        : rule.kind === 'basic' ? { kind: 'basic', user: rule.user, password: rule.password } : { kind: rule.kind, name: rule.name, template: rule.template }));
      // Code takes any HTTP method (`PROPFIND`), the tab's own items only its seven: a code item's methods go out as code wrote
      // them, upper-cased, and the tab reads a code item's as strings (`MethodsMenu`, the sample call), never as its seven.
      const methods = (given: readonly string[] | undefined) => (given ?? []).map((method) => method.toUpperCase() as ProxyMethod);
      const allow: ProxyAllow[] | null = credential.allow !== undefined
        ? credential.allow.map((entry) => ({ methods: methods(entry.methods), path: entry.path ?? '/' }))
        : credential.paths !== undefined ? credential.paths.map((path) => ({ methods: methods(credential.methods), path }))
        : credential.methods !== undefined ? [{ methods: methods(credential.methods), path: '/' }] : null;
      const { limit: limited, limitPerService } = limit(credential.limit);
      const placeholder = credential.placeholder === undefined ? null : credential.placeholder.kind === 'jwt' ? { kind: 'jwt' as const, claims: [...credential.placeholder.claims] } : { kind: 'prefix' as const, prefix: credential.placeholder.prefix };
      // Matched as code matches it, which the tab's preview follows: `paths` as before 0.16, and its `methods` as written,
      // `[]` taking none, and still there when `paths: []` leaves no entry to hold them (`methods: ['POST'], paths: []`).
      const allowAs: ProxyCodeItem['allowAs'] = credential.allow !== undefined ? { from: 'code', methods: null } : allow !== null ? { from: 'legacy', methods: credential.methods === undefined ? null : methods(credential.methods) } : null;
      return item({ kind: 'route', name, upstream: credential.upstream, inject, allow, limit: limited, placeholder, egress: null }, credential, limitPerService, credential.egress !== undefined, allowAs);
    }),
    ...[...signers].map(([name, signer]) => {
      const { limit: limited, limitPerService } = limit(signer.limit);
      return item({ kind: 'signer', name, signer: signer.kind === 'hmac' ? { kind: 'hmac', ...hmacOf(signer) } : { kind: 'private-key', key: signer.key }, limit: limited }, signer, limitPerService);
    }),
    ...[...verifiers].map(([name, verifier]) => {
      const { limit: limited, limitPerService } = limit(verifier.limit);
      return item({ kind: 'verifier', name, hmac: hmacOf(verifier), limit: limited }, verifier, limitPerService);
    }),
    ...[...tunnels].map(([name, tunnel]) => item({ kind: 'tunnel', name, key: tunnel.key, hosts: [...(tunnel.hosts ?? [])], network: null }, tunnel, false, tunnel.connect !== undefined)),
  ].sort((a, b) => a.definition.name.localeCompare(b.definition.name));
}

/** Whether a code item serves an environment, by its path now (a personal config, `<env>@me`, its environment's). */
function serves(item: { environments?: readonly string[] }, path: string): boolean {
  return item.environments === undefined || item.environments.includes(path.replace(/@me$/, ''));
}

/** A code item's refusal in an environment it does not serve. */
const notServed = (name: string, path: string) => failure(404, `${name} does not serve ${path}: its deployment's credentialProxy names the environments it serves`);

/** A placeholder as configured, checked: `jwt(…)` naming the claims it copies, or `prefix(…)`. */
function checkPlaceholder(name: string, placeholder: Placeholder): void {
  if (placeholder.kind !== 'jwt' && placeholder.kind !== 'prefix') throw new Error(`credentialProxy: ${name}'s placeholder is jwt(…) or prefix(…)`);
  if (placeholder.kind === 'jwt' && (!Array.isArray(placeholder.claims) || placeholder.claims.some((claim) => typeof claim !== 'string' || claim === '' || claim === HANDLE_CLAIM))) {
    throw new Error(`credentialProxy: ${name}'s jwt() names the claims it copies from the real token, each a string; exp is the handle's end, never copied`);
  }
  if (placeholder.kind === 'prefix' && !PLACEHOLDER_PREFIX.test(placeholder.prefix)) throw new Error(`credentialProxy: ${name}'s prefix() is up to 64 letters, digits and ._~+/:=-, sk_test_; got ${JSON.stringify(placeholder.prefix)}`);
}

/**
 * The slot a shaped placeholder fills, as a pattern: the rule's template, the
 * placeholder where its key goes, the handle its one group. Only a header, a
 * query parameter or a body's field that carries one key, once, takes a shaped placeholder:
 * Basic's pair, and an AWS key pair, are no one token to shape.
 */
function placeholderShape(placeholder: Placeholder, rule: Extract<Rule, { template: string }>): RegExp {
  const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const handle = `(${HANDLE.source})`;
  const token = placeholder.kind === 'jwt' ? `[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.${handle}` : `${escape(placeholder.prefix)}${handle}`;
  const [before, after] = rule.template.split(TEMPLATE_KEY).filter((_, at) => at % 2 === 0);
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
  return { ...tunnel, ...(hosts === undefined ? {} : { hosts }), ...checkScope(name, 'tunnel', tunnel.environments) };
}

/** TCP out through a tunnel's network binding, to the host and port its URL names. */
function through(network: Network): Connect {
  return async (host, port, signal) => {
    if (signal?.aborted) throw new Error('the session ended');
    // Not awaited here: a dial the binding has not answered when the session ends is given up, and closed if it comes.
    return workersSocket(network.connect(`${host.includes(':') ? `[${host}]` : host}:${port}`), signal);
  };
}

function checkSigner(name: string, signer: Signer, credentials: Map<string, Resolved>, tunnels: Map<string, Tunnel>, signers: Map<string, Signer>, what: 'signer' | 'verifier'): Signer {
  if (!NAME.test(name)) throw new Error(`credentialProxy: a ${what}'s name is lowercase letters, digits and dashes; got ${JSON.stringify(name)}`);
  const taken = credentials.has(name) ? 'credential' : tunnels.has(name) ? 'tunnel' : signers.has(name) ? 'signer' : null;
  if (taken !== null) throw new Error(`credentialProxy: ${name} names a ${taken} and a ${what}`);
  if (what === 'verifier' ? signer.kind !== 'hmac' : signer.kind !== 'private-key' && signer.kind !== 'hmac') {
    throw new Error(`credentialProxy: ${what} ${name} is ${what === 'verifier' ? 'hmac(…), the only kind there is' : 'privateKey(…) or hmac(…)'}`);
  }
  if (!KEY.test(signer.key)) throw new Error(`credentialProxy: ${what} ${name} names the key that holds its ${signer.kind === 'hmac' ? 'secret, YOUSIGN_WEBHOOK_SECRET' : 'private key, DFNS_PRIVATE_KEY'}`);
  if (signer.kind === 'hmac') {
    // HMAC-SHA256 alone, written as these schemes write it: a key it does not know is refused, never ignored.
    const unknown = Object.keys(signer).find((option) => !['kind', 'key', 'encoding', 'prefix', 'maxBytes', 'limit', 'environments'].includes(option));
    if (unknown !== undefined) throw new Error(`credentialProxy: ${what} ${name}'s hmac() takes encoding, prefix, maxBytes, limit and environments, and signs with SHA-256 alone; got ${unknown}`);
    if (signer.maxBytes !== undefined && !(Number.isInteger(signer.maxBytes) && signer.maxBytes >= 1 && signer.maxBytes <= MAX_MESSAGE_BYTES)) throw new Error(`credentialProxy: ${what} ${name}'s maxBytes is a whole number of bytes, 1 MiB at most`);
    if (signer.encoding !== 'hex' && signer.encoding !== 'base64' && signer.encoding !== 'base64url') throw new Error(`credentialProxy: ${what} ${name}'s hmac() writes its signatures in hex, base64 or base64url`);
    if (signer.prefix !== undefined && (typeof signer.prefix !== 'string' || !SIGNATURE_PREFIX.test(signer.prefix))) throw new Error(`credentialProxy: ${what} ${name}'s prefix is up to 32 printable characters, sha256=`);
  }
  limited(name, signer.limit);
  // The app holds one value for a key, and a signer's is the handle as it is.
  const shaped = [...credentials.values()].find((credential) => credential.placeholder !== undefined && credential.keys.includes(signer.key));
  if (shaped !== undefined) throw new Error(`credentialProxy: ${shaped.name} and ${name} read ${signer.key} with different placeholders, and the app holds one value for it`);
  return { ...signer, ...checkScope(name, what, signer.environments) };
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
function failure(status: number, message: string, reason?: string, retryAfter?: string): Response {
  return new Response(JSON.stringify({ error: 'credential_proxy', message, ...(reason === undefined ? {} : { reason }) }), {
    status,
    headers: {
      'content-type': 'application/json', 'cache-control': 'no-store', 'coffre-proxy': 'refused',
      // coffre could not answer for a moment (`errorResponse`), or said when to ask again (a busy use): the app's client hears when.
      ...(status === 503 && (reason === 'unavailable' || retryAfter !== undefined) ? { 'retry-after': retryAfter ?? UNAVAILABLE_RETRY_AFTER } : {}),
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
  return { counts: typeof limit === 'function' ? ({ service }) => counts(limit(service)) : counts(limit) };
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

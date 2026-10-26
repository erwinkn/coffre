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
import { bodyDigest, bodyLine, declaredDigest, MAX_DIGESTED_BODY, UNSIGNED_BODY } from '@coffre/client/dpop';
import { constraintsAllow } from '@coffre/core/identity';
import { recipeProblem } from '@coffre/core/recipe';
import { isUnavailable } from '@coffre/db/dialect';

import { UNAVAILABLE_RETRY_AFTER } from '../api/errors.ts';
import { WorkloadRefused, type CoffrePlugin, type Connect, type PickKeys, type PluginContext, type SocketSession, type Used, type WorkloadAt, type WorkloadUse } from '../plugins.ts';
import { database, tunnel as tunnelPostgres, type Database } from './postgres-tunnel.ts';
import { hmacSign, hmacVerify, type Encoding } from './hmac.ts';
import { signWith, SigningKeyError } from './sign.ts';
import { presignV4, signV4 } from './sigv4.ts';
import { workersSocket, type WorkersSocket } from '../workers-socket.ts';
import { logged } from '../logged.ts';

/** How a credential's values reach its upstream: in a header, a query parameter, Basic authentication, or an AWS signature. */
export type Inject =
  | { kind: 'header'; name: string; template: string }
  | { kind: 'query'; name: string; template: string }
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
  /** The shape of what the app holds for its key, `jwt(…)` or `prefix(…)`, where a header or query rule carries that one key: the handle as it is, unless set. */
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
export type Hmac = { kind: 'hmac'; key: string; encoding: Encoding; prefix?: string; maxBytes?: number; limit?: Limits };

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
 * `limit`, as a credential's.
 */
export function hmac(key: string, options: { encoding: Encoding; prefix?: string; maxBytes?: number; limit?: Limits }): Hmac {
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
/** A key a rule's template names, `{SCHUMANN_API_KEY}`. */
const TEMPLATE_KEY = /\{([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;
/** A handle, wherever the app put it: alone, or inside a header the upstream's own scheme frames. */
const HANDLE = /coffre_use_[A-Za-z0-9_-]{43}/;
/** A request's body that declares no digest is read whole before it is sent on: an API call's, not an upload's. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;
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

/** `shape`: what a shaped placeholder's slot must be, the handle its one group. */
type Resolved = Credential & { name: string; base: URL; keys: string[]; shape?: RegExp };

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
  return {
    name: 'credential-proxy',
    routes: {
      prefix: '/use',
      fetch: async (request, coffre) => {
        try {
          return await serve(request, coffre, { credentials, groups, tunnels, signers, verifiers, messageBytes, insecure: options.insecureUpstreams === true, recheckMs, generate, cacheMs, cache, handles });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code);
          throw error;
        }
      },
      socket: async (request, coffre) => {
        try {
          return await open(request, coffre, { credentials, groups, tunnels, signers, verifiers, messageBytes, insecure: options.insecureUpstreams === true, recheckMs, generate, cacheMs, cache, handles });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code);
          throw error;
        }
      },
    },
  };
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
};

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
  // A workload's: `/use/<credential>/<path>` whenever `<credential>` is one, for the one environment it reaches, and
  // `/use/<project>/<env>/<credential>/<path>` otherwise. Nothing tells a session's environments by name before its
  // one statement, so the URL alone decides; a handle's are below.
  const named = stable === undefined && raw.length >= 3 ? proxy.credentials.get(place[2]!) : undefined;
  if (stable !== undefined || named !== undefined) {
    const used = await workloadForward(request, coffre, proxy, stable !== undefined ? null : `${place[0]}/${place[1]}`, (stable ?? named)!, raw.slice(stable !== undefined ? 1 : 3), url.search);
    if (used !== null) return used;
  }
  // `/use/<credential>/<path>`, the stable URL, for the environment the handle was made for; unless `<a>/<b>` is an
  // environment the handle was made for, which `/use/<project>/<env>/…` names below. Never a guess: the URL and the handle decide.
  if (stable !== undefined) {
    const named = place[2] === undefined ? undefined : proxy.credentials.get(place[2]);
    const handle = handleIn(request, stable, url) ?? (named === undefined ? null : handleIn(request, named, url)) ?? HANDLE.exec(bearer(request) ?? '')?.[0] ?? null;
    if (handle === null) return failure(401, `send the handle \`coffre run\` gave your app where ${stable.name} takes its key, or as x-coffre-handle`);
    const paths = await madeFor(coffre, proxy, handle);
    if (raw.length === 1 || !(paths ?? []).includes(`${place[0]}/${place[1]}`)) {
      if (paths === null) return failure(409, `this handle was made before coffre 0.9 and names no environment: run the app with \`coffre run\` again, or name the environment, ${coffre.publicUrl}/use/<project>/<environment>/${stable.name}`);
      // As many as it was made for, a deleted one too: what the handle names decides, never what is left of it.
      const live = paths.filter((path) => path !== null);
      if (paths.length > 1) {
        const urls = live.map((path) => `${coffre.publicUrl}/use/${path}/${stable.name}`).join(' or ');
        return failure(409, `this handle stands in for ${paths.length} environments, and the stable URL is for a run of one: name it${live.length === 0 ? '' : `, ${urls}`}`);
      }
      if (live.length === 0) return failure(409, 'the environment this handle was made for is gone');
      return forward(request, coffre, proxy, live[0]!, stable, raw.slice(1), url.search);
    }
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
  if (credential === undefined) return failure(404, `this instance has no credential ${JSON.stringify(place[2])}: its deployment's credentialProxy names them`);
  return forward(request, coffre, proxy, `${place[0]}/${place[1]}`, credential, raw.slice(3), url.search);
}

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
  // The credentials the environment holds every key of: their keys are placeholders, whoever may read them.
  const covering = (keys: readonly string[]) => [...proxy.credentials.values()].filter((credential) => credential.keys.every((key) => keys.includes(key)));
  // What the read resolved, for what `coffre run` generates below.
  let resolved: Parameters<PickKeys>[1] = [];
  let personal = false;
  // One read, which opens what the app holds as it is, chosen from the rows it opens: a sensitive value is never one,
  // and the vault refuses the read if it were.
  const held = await coffre.use(handle, {
    path: readOf(proxy, path),
    purpose: 'expose',
    logged: { plan: true },
    keys: (environment, rows) => {
      resolved = rows;
      personal = environment.personal;
      const using = covering(rows.map((row) => row.key));
      const covered = new Set([...using.flatMap((credential) => credential.keys), ...[...proxy.tunnels.values()].map((tunnel) => tunnel.key), ...keyed(proxy).map(([, signer]) => signer.key)]);
      // What the proxy fills in itself, a tunnel's URL or a signer's or verifier's handle, never the value the environment holds; and a
      // credential's plain keys where giving them would leave the handle nowhere the proxy finds it: S3's access key id,
      // which the SDK sends as `Credential=`, or every key of a header's. Those stay placeholders, as secrets do.
      const asTheyAre = new Set(rows.filter((row) => row.plain).map((row) => row.key));
      const filled = new Set([
        ...[...proxy.tunnels.values()].map((tunnel) => tunnel.key),
        ...keyed(proxy).map(([, signer]) => signer.key),
        ...using.filter((credential) => !carriesHandle(credential.inject, asTheyAre)).flatMap((credential) => credential.keys),
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
  for (const credential of covering(held.keys)) {
    // The environment's URL, which a run of several environments tells apart, and which `presign()` derives the environment's from.
    credentials[credential.name] = `${coffre.publicUrl}/use/${path}/${credential.name}`;
    // Every key the placeholder, and a plain value given as it is below.
    const placeholder = credential.placeholder === undefined ? handle : await shaped(coffre, credential, handle, readOf(proxy, path));
    for (const key of credential.keys) {
      env[key] = placeholder;
      covered.add(key);
    }
  }
  for (const [key, value] of Object.entries(held.values)) {
    env[key] = value;
    covered.add(key);
  }
  // A signer's or verifier's key the handle, and its name where `credential(name)` finds it: the key never leaves coffre.
  for (const [name, signer] of keyed(proxy)) {
    if (!held.keys.includes(signer.key)) continue;
    credentials[name] = `${coffre.publicUrl}/use/${path}/${name}`;
    env[signer.key] = handle;
    covered.add(signer.key);
  }
  // A database's URL is `coffre run`'s to make, its listener's, with the handle as the password: never the real one.
  const tunnels: Record<string, { key: string; url: string }> = {};
  for (const [name, tunnel] of proxy.tunnels) {
    if (!held.keys.includes(tunnel.key)) continue;
    tunnels[name] = { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` };
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
    tunnels,
    left: held.keys.filter((key) => !covered.has(key)),
    ...(making === undefined ? {} : { generate }),
  });
}

/**
 * What a workload's environment holds for it (docs/design/workload-access.md,
 * section 6.2): the values it reads, plain ones and those its binding lists
 * in `reads`; the names of the credentials and signers it uses through
 * coffre, and its tunnels, each with the key whose URL the local listener
 * stands in for, as a handle's plan has them; and every key it holds but
 * does not read, `useOnly`. No placeholder: its requests carry its proof,
 * never a value in a slot.
 */
async function workloadPlan(coffre: PluginContext, proxy: Proxy, caller: WorkloadUse, path: string): Promise<Response> {
  const held = await coffre.use(caller, { path, purpose: 'expose', logged: { plan: true }, keys: (_, rows) => rows.filter((row) => row.plain || row.reads).map((row) => row.key) });
  const holds = (keys: readonly string[]) => keys.every((key) => held.keys.includes(key));
  return answer({
    environment: held.environment.path,
    values: { ...held.values },
    credentials: [...[...proxy.credentials.values()].filter((credential) => holds(credential.keys)).map((credential) => credential.name), ...keyed(proxy).filter(([, signer]) => holds([signer.key])).map(([name]) => name)],
    tunnels: Object.fromEntries([...proxy.tunnels].filter(([, tunnel]) => holds([tunnel.key])).map(([name, tunnel]) => [name, { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` }])),
    useOnly: held.keys.filter((key) => !Object.hasOwn(held.values, key)),
    mints: [],
  });
}

/**
 * A credential's placeholder in the shape its client checks: the handle behind
 * a prefix, or a JWT of the real token's named claims, which are opened for
 * it as a use of the credential, logged, and go no further than those.
 */
async function shaped(coffre: PluginContext, credential: Resolved, handle: string, path: string): Promise<string> {
  const placeholder = credential.placeholder!;
  if (placeholder.kind === 'prefix') return `${placeholder.prefix}${handle}`;
  const key = credential.keys[0]!;
  const used = await coffre.use(handle, { path, keys: [key], purpose: 'use', logged: { credential: credential.name, placeholder: { claims: placeholder.claims } } });
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
    run: () => coffre.use(handle, { path: readOf(proxy, path, handle), keys: [tunnel.key], purpose: 'use', logged: { credential: name, tunnel: true, recheck: true } }).then((used) => Object.hasOwn(used.values, tunnel.key)),
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
  if (!constraintsAllow(caller.constraints, { place: path, credential: name })) return nonced(failure(403, `this narrowed session may not open ${name}`, 'narrowed'), caller);
  let fresh = false;
  let opened: Opened;
  try {
    opened = await valuesFor(coffre, proxy, caller, path, { name, keys: [tunnel.key] }, { tunnel: true }, () => (fresh = true));
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return nonced(failure(error.status, error.message, error.reason ?? error.code), caller);
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
      run: () => coffre.use(caller, { path, keys: [tunnel.key], purpose: 'use', logged: { credential: name, tunnel: true, recheck: true } }).then((used) => Object.hasOwn(used.values, tunnel.key)),
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
        if (check.arms) arm(started);
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
  // Read up to what the longest message takes, as base64url in JSON beside the rest.
  const raw = await boundedBody(request, Math.ceil(proxy.messageBytes / 3) * 4 + 4096);
  if (raw === null) return failure(413, `a message to sign or verify is at most ${sized(proxy.messageBytes)} here: an hmac()'s maxBytes takes a longer one`);
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
  // A verifier verifies, and an HMAC signer too, which could check a signature by making it: a private key's is no HMAC.
  const signer = operation === 'sign' ? proxy.signers.get(name) : operation === 'verify' ? (proxy.verifiers.get(name) ?? proxy.signers.get(name)) : undefined;
  const credential = operation === 'presign' ? proxy.credentials.get(name) : undefined;
  if (operation === 'sign' && signer === undefined) {
    return failure(404, `sign names a signer of this instance's: its deployment's credentialProxy names them, signers: { … }${proxy.verifiers.has(name) ? `; ${name} is a verifier, which checks signatures and makes none` : ''}`);
  }
  if (operation === 'verify' && signer?.kind !== 'hmac') return failure(404, 'verify names a verifier of this instance\'s, or a signer of its that is hmac(…): its deployment\'s credentialProxy names them, verifiers: { … }');
  if (operation === 'presign' && credential?.inject.kind !== 'sigv4') return failure(404, 'presign names a credential of this instance\'s that signs with sigv4()');
  const caller = await workloadOf(request, coffre, { place: path, credential: name, body: await bodyDigest(raw ?? new Uint8Array(0)), ...countsOf(name, (signer ?? credential!).limit) });
  if (caller instanceof Response) return caller;
  const run = (who: User, at: string) => (operation === 'presign' ? presign(coffre, proxy, at, who, credential!, given) : operation === 'sign' ? sign(coffre, proxy, at, who, name, signer!, given) : verify(coffre, proxy, at, who, name, signer as Hmac, given));
  if (caller !== null) return answering(caller, async () => (caller.path === null ? failure(409, 'name the environment, POST /use/<project>/<environment>: this session reaches none, or several, or one gone') : run(caller, caller.path)));
  if (path === null) return failure(405, 'GET only: a handle names its environment, POST /use/<project>/<environment>');
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  return run(handle, path);
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
  const used = await coffre.use(who, { path: readOf(proxy, path, who), keys: [signer.key], purpose: 'use', logged: { credential: name, sign: { sha256 } } });
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
async function presign(coffre: PluginContext, proxy: Proxy, path: string, who: User, credential: Resolved, asked: { path?: unknown; method?: unknown; query?: unknown; expiresIn?: unknown }): Promise<Response> {
  const inject = credential.inject as { kind: 'sigv4' } & SigV4;
  const method = asked.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') return failure(400, 'a presigned URL is for GET or HEAD: an upload goes through the proxy');
  if (credential.methods !== undefined && !credential.methods.includes(method)) return failure(405, `${credential.name} takes ${credential.methods.join(', ')}`);
  const expiresIn = asked.expiresIn ?? 900;
  if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn < 1 || expiresIn > 3600) return failure(400, 'a presigned URL lasts between a second and an hour: expiresIn, in seconds');
  // No control character either: a URL drops a tab or a line break, which could join what the checks below saw apart.
  if (typeof asked.path !== 'string' || !asked.path.startsWith('/') || /[?#\u0000-\u001F\u007F]/.test(asked.path)) return failure(400, 'presign a path under the credential as a URL has it, /bucket/key, each segment encoded: the query goes in query');
  const query = asked.query ?? {};
  if (typeof query !== 'object' || query === null || Object.values(query).some((value) => typeof value !== 'string')) return failure(400, 'query is a map of strings, response-content-disposition and the like');
  // The same rules as a request through it: under the upstream, its paths, no dot segment and no slash smuggled in a segment.
  const segments = asked.path.slice(1).split('/');
  if (segments.some((segment) => /^(\.|%2e){1,2}$/i.test(segment) || /%2f|%5c|\\/i.test(segment))) return failure(400, 'the path may not climb out of the credential\'s upstream');
  const target = new URL(`${credential.base.href.replace(/\/$/, '')}/${segments.join('/')}`);
  for (const [name, value] of Object.entries(query as Record<string, string>)) {
    if (name.toLowerCase().startsWith('x-amz-')) return failure(400, 'the X-Amz- parameters are the signature\'s own');
    target.searchParams.set(name, value);
  }
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  // And again on the path as the URL made it, which is the one signed: no dot segment, no slash or backslash in a segment.
  if (target.pathname.split('/').some((segment) => /^(\.|%2e){1,2}$/i.test(segment) || /%2f|%5c|\\/i.test(segment))) return failure(400, 'the path may not climb out of the credential\'s upstream');
  const relative = target.pathname.slice(under.length) || '/';
  if (credential.paths !== undefined && !credential.paths.some((prefix) => relative === prefix || relative.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) {
    return failure(403, `${credential.name} is not for ${relative}`);
  }
  // A URL is for sharing: the handle goes in none, its path or its query, encoded or not.
  if (HANDLE.test(bytesOf(target.href)) || HANDLE.test(target.href)) return failure(400, 'the handle goes in no presigned URL');
  if (typeof who !== 'string' && !constraintsAllow(who.constraints, { place: path, credential: credential.name, request: { method, url: target } })) {
    return failure(403, `this narrowed session may not presign ${method} ${relative} through ${credential.name}`, 'narrowed');
  }
  // Every URL is one use in the log, opened now: a URL outlives the request, and whoever holds it may use it.
  const used = await coffre.use(who, { path: readOf(proxy, path, who), keys: credential.keys, purpose: 'use', logged: { credential: credential.name, host: target.host, presign: { method, path: relative, expiresIn } } });
  if (credential.keys.some((key) => !Object.hasOwn(used.values, key))) return failure(409, `${used.environment.path} holds no key ${credential.name} signs with`);
  // Never past the handle's or the session's own end.
  const lasts = Math.min(expiresIn, Math.floor((Date.parse(used.expiresAt) - Date.now()) / 1000));
  if (lasts < 1) return failure(401, typeof who === 'string' ? 'the handle ends now: run the app with `coffre run` again' : 'the session ends now: renew it');
  let url: URL;
  try {
    url = await presignV4(method, target, {
      accessKeyId: render(inject.accessKeyId, used.values),
      secretAccessKey: render(inject.secretAccessKey, used.values),
      ...(inject.sessionToken === undefined ? {} : { sessionToken: render(inject.sessionToken, used.values) }),
    }, inject, lasts);
  } catch {
    return failure(409, `${credential.name}'s values sign no URL`);
  }
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
  // Decoded as often as it changes, since a server behind another decodes twice: `%252e%252e` is `..` to it. No control
  // byte either, which a server may cut a segment at (`..%00`), nor an overlong lead byte, which an old one decodes to a
  // dot (`%c0%ae`); and a dot segment is one with trailing blanks too (`..%20`).
  const climbs = (segment: string): boolean => {
    const read = bytesOf(segment);
    return /[/\\\x00-\x1f\x7f\xc0\xc1]/.test(read) || /^\.{1,2}[ \t]*$/.test(read.split(';')[0]!) || (read !== segment && climbs(read));
  };
  if (rest.some(climbs)) return failure(400, 'the path may not climb out of the credential\'s upstream');
  // The credential's own URL, as the app asked for it: `…/schumann` is the upstream itself, `…/schumann/` the upstream and a slash.
  const target = new URL(`${rest.length === 0 ? credential.base.href : `${credential.base.href.replace(/\/$/, '')}/${rest.join('/')}`}${search}`);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) {
    return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  }
  const relative = target.pathname.slice(under.length) || '/';
  if (credential.methods !== undefined && !credential.methods.includes(request.method)) return failure(405, `${credential.name} takes ${credential.methods.join(', ')}`);
  if (credential.paths !== undefined && !credential.paths.some((prefix) => relative === prefix || relative.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) {
    return failure(403, `${credential.name} is not for ${relative}`);
  }
  if (credential.inject.kind === 'sigv4') {
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
  const amz = credential.inject.kind === 'sigv4' && request.headers.has('x-amz-content-sha256');
  let digest: string | null = null;
  try {
    digest = amz ? null : declaredDigest(request.headers.get('content-digest') ?? '');
  } catch (error) {
    return failure(400, (error as Error).message);
  }
  // An empty body is checked before anything goes: with no last byte to hold back, its request is whole once its headers are.
  const streamed = (amz || (digest !== null && Number(declared) > 0)) && request.body !== null && /^\d+$/.test(declared);
  if (streamed && amz && Number(declared) > MAX_STREAM_BYTES) return failure(413, `an upload through the proxy carries at most ${MAX_STREAM_BYTES / 1024 ** 3} GiB: send a larger one in parts`);
  if (streamed && !amz && Number(declared) > MAX_DIGESTED_BODY) {
    return failure(413, `a body that declares its digest streams through the proxy up to ${MAX_DIGESTED_BODY / 1024 / 1024} MiB, under the 100 MB a Cloudflare zone takes: send a larger one in parts`);
  }
  const body = request.method === 'GET' || request.method === 'HEAD' || streamed ? undefined : await boundedBody(request);
  if (body === null) {
    return failure(413, `a request through the proxy carries at most ${MAX_BODY_BYTES / 1024 / 1024} MiB read whole; one that says its length and declares its SHA-256 streams, up to ${MAX_DIGESTED_BODY / 1024 / 1024} MiB: Content-Digest: sha-256=:<base64>:, as coffre serve and @coffre/client/workload send it, or x-amz-content-sha256 through an AWS-signed credential`);
  }
  if (digest !== null && !streamed && (await bodyDigest(body ?? new Uint8Array(0))) !== digest) return failure(400, 'the body is not what its Content-Digest says');
  // As a number writes it: `00` is the 0 it says, as it goes on and as the body's line reads it.
  return { body, streamed, declared: streamed ? String(Number(declared)) : declared, digest };
}

/** One request through a credential, a handle's: the handle checked, its values opened (or remembered), the request sent on with them. */
async function forward(request: Request, coffre: PluginContext, proxy: Proxy, path: string, credential: Resolved, rest: string[], search: string): Promise<Response> {
  const aimed = aim(request, credential, rest, search);
  if (aimed instanceof Response) return aimed;
  const { target } = aimed;
  const inject = credential.inject;
  const handle = handleIn(request, credential, target);
  if (handle === null) return failure(401, `send what \`coffre run\` gave your app for its key where ${credential.name} takes it, or the handle as x-coffre-handle`);
  // A query rule's parameter as the app sent it, if it stands in for this handle, its shape and all: what a redirect
  // under the upstream gives back. Otherwise the placeholder's shape around the handle, which the proxy reads as the app's own
  // (`e30` is `{}`: the proxy reads no claim).
  const given = inject.kind === 'query' ? target.searchParams.get(inject.name) : null;
  const back = inject.kind !== 'query' ? null : given !== null && handleOf(credential, given) === handle ? given
    : credential.placeholder === undefined ? handle : render(inject.template, { [credential.keys[0]!]: credential.placeholder.kind === 'prefix' ? `${credential.placeholder.prefix}${handle}` : `${UNSIGNED}.e30.${handle}` });
  // Read whole first, however long it takes to come, so the handle is checked, and the values opened, as the request goes out.
  const content = await carried(request, credential);
  if (content instanceof Response) return content;
  const opened = await valuesFor(coffre, proxy, handle, path, credential, { host: target.host });
  const headers = new Headers();
  for (const [name, value] of request.headers) if (sent(name)) headers.set(name, value);
  // Where its redirects stay: the environment's URL, the stable one's included. Under the stable URL, a path that begins
  // with an environment of the handle's would name that environment, and another credential (`/use/schumann/dev/maps/…`).
  return send(request, credential, { ...aimed, ...content, opened, headers, proxied: `${coffre.publicUrl}/use/${path}/${credential.name}`, back, secret: { pattern: HANDLE, length: HANDLE_LENGTH, what: 'the handle' } });
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
    const amz = content.digest === null && credential.inject.kind === 'sigv4' ? request.headers.get('x-amz-content-sha256') : null;
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
    if (!constraintsAllow(workload.constraints, { place: workload.path, credential: credential.name, request: { method: request.method, url: aimed.target } })) {
      return failure(403, `this narrowed session may not ${request.method} ${aimed.relative} through ${credential.name}`, 'narrowed');
    }
    const opened = await valuesFor(coffre, proxy, workload, workload.path, credential, { host: aimed.target.host });
    // Only what the proof signs goes on, of what the app sent: a header added on the way, by a library or a proxy, is dropped.
    const headers = new Headers();
    for (const [name, value] of request.headers) if ((workload.hdr === null || workload.hdr.includes(name)) && sent(name)) headers.set(name, value);
    const proxied = `${coffre.publicUrl}/use/${path === null ? '' : `${path}/`}${credential.name}`;
    const secret = token === null ? null : { pattern: new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), length: token.length, what: 'the session token' };
    return send(request, credential, { ...aimed, ...content, opened, headers, proxied, back: null, secret, ...(payload === undefined ? {} : { payload }) });
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
  const { target, under, body, streamed, declared, digest, headers, opened: { values, plain }, secret } = out;
  const inject = credential.inject;
  // A streamed body says its length itself, which S3 requires of a PutObject.
  if (streamed) headers.set('content-length', declared);
  try {
    if (inject.kind === 'header') headers.set(inject.name, render(inject.template, values));
    if (inject.kind === 'basic') headers.set('authorization', `Basic ${btoa(binary(new TextEncoder().encode(`${render(inject.user, values)}:${render(inject.password, values)}`)))}`);
    if (inject.kind === 'query') target.searchParams.set(inject.name, render(inject.template, values));
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
  // What authenticated the request goes no further than coffre: anywhere else the app put it, the request stops, as it is or in Basic's base64.
  if (secret !== null) {
    const leaked = [...headers].find(([, value]) => carries(value, secret.pattern)) ?? (carries(bytesOf(target.href), secret.pattern) ? ['URL'] : undefined)
      ?? (body !== undefined && secret.pattern.test(LATIN1.decode(body)) ? ['body'] : undefined);
    if (leaked !== undefined) {
      return failure(400, `${secret.what} is somewhere ${credential.name} does not take its key: ${leaked[0] === 'URL' || leaked[0] === 'body' ? `the ${leaked[0]}` : `the ${leaked[0]} header`}`);
    }
  }

  // What the request carried: each secret value, and what the rule made of them, Basic's base64, as stored and as they went
  // out (`Headers` trims a value's surrounding whitespace), in each form an honest upstream may echo it in (`echoed`). A plain
  // value is no secret, and an upstream quotes an account's id back as a matter of course: it stays.
  const injected = inject.kind === 'header' ? headers.get(inject.name)! : inject.kind === 'basic' ? headers.get('authorization')!.slice('Basic '.length)
    : inject.kind === 'sigv4' ? headers.get('authorization')! : target.searchParams.get(inject.name)!;
  const secrets = Object.entries(values).filter(([key]) => !plain.includes(key)).map(([, value]) => value);
  // What the rule made of them too, unless it is made of plain values alone: an account's id in a header is quoted back.
  const made = credential.keys.some((key) => !plain.includes(key)) ? [injected] : [];
  const redact = redactor([...secrets.flatMap((value) => [value, value.trim()]), ...made].flatMap(echoed));

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
      if (inject.kind === 'query' && out.back !== null) moved.searchParams.set(inject.name, out.back);
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

/** Bytes as a string of one character each, U+0000 to U+00FF: what the redaction scans, in any charset. */
function binary(bytes: Uint8Array): string {
  let text = '';
  for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return text;
}

const LATIN1 = new TextDecoder('latin1');

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
 * A URL with each `%XX` as its byte, one character each: what the handle,
 * which is ASCII, is looked for in. It never fails, as decoding the whole
 * as UTF-8 does on a `%FF`, which would leave `coffre%5Fuse_…` unseen.
 */
function bytesOf(text: string): string {
  return text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));
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
    used = await coffre.use(user, { path: readOf(proxy, path, user), keys: credential.keys, purpose: 'use', logged: { credential: credential.name, ...through, ...(credential.egress === undefined ? {} : { egress: true }) } });
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

/**
 * Whether the app's request still carries the handle where the proxy looks
 * for it (`handleIn`) when the `plain` keys of its rule are given as they
 * are: a key that is no plain one in the header's or the parameter's
 * template, in Basic's user or password, or in SigV4's access key id.
 */
function carriesHandle(inject: Inject, plain: ReadonlySet<string>): boolean {
  const slots = inject.kind === 'basic' ? [inject.user, inject.password] : inject.kind === 'sigv4' ? [inject.accessKeyId] : [inject.template];
  return slots.some((slot) => [...slot.matchAll(TEMPLATE_KEY)].some((match) => !plain.has(match[1]!)));
}

/** The handle, where the app sends it: `x-coffre-handle` (the `credential(name)` helper), or where the credential takes its key. */
function handleIn(request: Request, credential: Resolved, target: URL): string | null {
  const explicit = request.headers.get('x-coffre-handle');
  if (explicit !== null) return HANDLE.exec(explicit)?.[0] ?? null;
  const inject = credential.inject;
  let slot: string | null = null;
  if (inject.kind === 'header') slot = request.headers.get(inject.name);
  if (inject.kind === 'query') slot = target.searchParams.get(inject.name);
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

function bearer(request: Request): string | null {
  return /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
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
      await reader.cancel();
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
  const shape = credential.placeholder === undefined ? undefined : placeholderShape(name, credential.placeholder, inject);
  limited(name, credential.limit);
  return { ...credential, ...(methods === undefined ? {} : { methods }), ...(shape === undefined ? {} : { shape }), name, base, keys };
}

/**
 * The slot a shaped placeholder fills, as a pattern: the rule's template, the
 * placeholder where its key goes, the handle its one group. Only a header or
 * a query parameter that carries one key, once, takes a shaped placeholder:
 * Basic's pair, and an AWS key pair, are no one token to shape.
 */
function placeholderShape(name: string, placeholder: Placeholder, inject: Inject): RegExp {
  if (placeholder.kind !== 'jwt' && placeholder.kind !== 'prefix') throw new Error(`credentialProxy: ${name}'s placeholder is jwt(…) or prefix(…)`);
  if ((inject.kind !== 'header' && inject.kind !== 'query') || [...inject.template.matchAll(TEMPLATE_KEY)].length !== 1) {
    throw new Error(`credentialProxy: ${name}'s placeholder shapes the one key a header or query rule carries, header('authorization', 'Bearer {TOKEN}'), not a ${inject.kind === 'basic' || inject.kind === 'sigv4' ? `${inject.kind}() rule` : 'template with several keys, or one twice'}`);
  }
  if (placeholder.kind === 'jwt' && (!Array.isArray(placeholder.claims) || placeholder.claims.some((claim) => typeof claim !== 'string' || claim === '' || claim === 'exp'))) {
    throw new Error(`credentialProxy: ${name}'s jwt() names the claims it copies from the real token, each a string; exp is the handle's end, never copied`);
  }
  if (placeholder.kind === 'prefix' && !/^[A-Za-z0-9._~+/:=-]{1,64}$/.test(placeholder.prefix)) throw new Error(`credentialProxy: ${name}'s prefix() is up to 64 letters, digits and ._~+/:=-, sk_test_; got ${JSON.stringify(placeholder.prefix)}`);
  const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const handle = `(${HANDLE.source})`;
  const token = placeholder.kind === 'jwt' ? `[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.${handle}` : `${escape(placeholder.prefix)}${handle}`;
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
    const unknown = Object.keys(signer).find((option) => !['kind', 'key', 'encoding', 'prefix', 'maxBytes', 'limit'].includes(option));
    if (unknown !== undefined) throw new Error(`credentialProxy: ${what} ${name}'s hmac() takes encoding, prefix, maxBytes and limit, and signs with SHA-256 alone; got ${unknown}`);
    if (signer.maxBytes !== undefined && !(Number.isInteger(signer.maxBytes) && signer.maxBytes >= 1 && signer.maxBytes <= MAX_MESSAGE_BYTES)) throw new Error(`credentialProxy: ${what} ${name}'s maxBytes is a whole number of bytes, 1 MiB at most`);
    if (signer.encoding !== 'hex' && signer.encoding !== 'base64' && signer.encoding !== 'base64url') throw new Error(`credentialProxy: ${what} ${name}'s hmac() writes its signatures in hex, base64 or base64url`);
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

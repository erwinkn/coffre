/**
 * The credential proxy (docs/design/credential-proxy.md): a person's app,
 * an agent's included, uses secrets without ever holding them. `coffre run`
 * gives it a stand-in for each, a handle (`coffre_use_…`) that reaches
 * nothing but this proxy, and points its base URL here; the proxy swaps in
 * the real value at the edge, for the credential's own upstream only. In
 * the deployment's configuration:
 *
 *   import { credentialProxy, header, sigv4 } from '@coffre/server/plugins/credential-proxy';
 *   plugins: [credentialProxy({
 *     credentials: {
 *       schumann: { upstream: 'https://api.schumann.example/v1', inject: header('x-api-key', '{SCHUMANN_API_KEY}'), baseUrl: 'SCHUMANN_BASE_URL' },
 *       s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }), baseUrl: 'AWS_ENDPOINT_URL_S3' },
 *     },
 *     expose: { 'market/local': 'all' },
 *   })],
 *
 * and its app's route, `routes/use.$.ts`, `createFileRoute('/use/$')({ ...plugin })`.
 * Then, for a person's `coffre run market/dev`:
 *
 *   GET /use/market/dev                     what the app's environment holds: stand-ins, base URLs, exposed values
 *   ANY /use/market/dev/schumann/<path>     the request, sent to https://api.schumann.example/v1/<path> with the key
 *
 * Each credential names the keys its rule reads, from the environment the
 * request names, and one upstream: the request goes there or nowhere, over
 * HTTPS, its redirects never followed, and a value the upstream echoes is
 * redacted from its answer. A handle opens values for its person as a read
 * does, by their grants and its scope, logged once per credential a minute
 * (`cacheSeconds`), never handed back. `expose` names the few values an
 * environment's apps may hold as they are, by its exact path.
 */
import { CoffreError } from '@coffre/client';

import type { CoffrePlugin, PluginContext, SocketSession } from '../plugins.ts';
import { database, tunnel as tunnelPostgres, type Database } from './postgres-tunnel.ts';
import { presignV4, signV4 } from './sigv4.ts';

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

/** One credential: its upstream, how its keys reach it, and what of it a caller may ask. */
export type Credential = {
  /** Where its requests go, `https://api.schumann.example/v1`: `/use/<project>/<env>/<name>/<path>` goes to `<upstream>/<path>`, and nowhere else. */
  upstream: string;
  inject: Inject;
  /** The key the app reads the upstream's address from, `SCHUMANN_BASE_URL`: `coffre run` sets it to this proxy's URL for the credential. */
  baseUrl?: string;
  /**
   * Keys the rule reads that are no secret, and that the app needs as they
   * are: an account's id it puts in its URLs, Twilio's `TWILIO_SID` in
   * `/Accounts/{sid}/Messages.json`. `coffre run` gives the app their
   * values, each opened to `expose`, and the handle stands in for the rest.
   * Held to `expose`'s limits: configuration only, and only an
   * environment's own value, never one a fork inherits or a personal
   * config's, which get the handle like the rest.
   */
  identifiers?: readonly string[];
  /** The methods it may be used with, `['GET', 'POST']`; any, unless set. */
  methods?: readonly string[];
  /** The paths under `upstream` it may be used on, by prefix, `['/companies']`; any, unless set. */
  paths?: readonly string[];
};

/** A database the proxy tunnels to: the key that holds its URL, and the hosts that URL may name. */
export type Tunnel = { kind: 'postgres'; key: string; hosts?: readonly string[] };

/**
 * A Postgres database, reached through `coffre run`'s local listener and
 * coffre's tunnel: `postgres('DATABASE_URL', { hosts: ['db.acme.example'] })`.
 * The environment's `DATABASE_URL` is the real one, `postgres://…`, which
 * coffre logs in with; the app's is the listener's, with the handle as its
 * password. `hosts`, when set, are the only ones the URL may name.
 */
export function postgres(key: string, options: { hosts?: readonly string[] } = {}): Tunnel {
  return { kind: 'postgres', key, ...options };
}

export type CredentialProxyOptions = {
  /** By name, as the proxy's URLs say it: lowercase letters, digits and dashes. */
  credentials: Record<string, Credential>;
  /** Databases, by name as credentials are, which `coffre run` tunnels to: `{ db: postgres('DATABASE_URL') }`. */
  tunnels?: Record<string, Tunnel>;
  /** How often an open tunnel checks its handle still stands, ending when it does not: 60 seconds unless set. */
  recheckSeconds?: number;
  /**
   * The values an environment's apps may hold as they are, by the exact
   * path of the environment a read resolves to: `{ 'market/local': 'all',
   * 'market/dev': ['CHAIN_SIGNER_KEY'] }`. Never a fork's parent, nor a
   * personal config, unless named itself. Only what cannot be used through
   * the proxy belongs here, and better a local-only value than a real one.
   */
  expose?: Record<string, 'all' | readonly string[]>;
  /** Upstreams over plain HTTP, and at private, loopback or link-local addresses: for local fakes in development, never in production. */
  insecureUpstreams?: boolean;
  /**
   * How long a credential's values, once opened for a handle, serve its
   * next requests from this process's memory: 60 seconds unless set, 0 for
   * a read per request. Each opening is one entry in the log; a revoked
   * handle's values serve no longer than this.
   */
  cacheSeconds?: number;
};

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;
/** A handle, wherever the app put it: alone, or inside a header the upstream's own scheme frames. */
const HANDLE = /coffre_use_[A-Za-z0-9_-]{43}/;
/** A request's body is read whole before it is sent on: an API call's, not an upload's. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;
/** An AWS-signed upload streams through, up to S3's own limit for one request; past it, a multipart upload's parts each pass. */
const MAX_STREAM_BYTES = 5 * 1024 ** 3;
const HANDLE_LENGTH = 'coffre_use_'.length + 43;
/** Values shorter than this are not redacted from answers: too short to tell from the text around them. */
const MIN_REDACTED = 8;
const REDACTED = '[redacted by coffre]';
/** Headers about one hop, and those that would tell the upstream about coffre's caller, its cookies or its handle. */
const DROPPED = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'cookie', 'content-length', 'expect', 'x-coffre-handle', 'forwarded', 'x-real-ip', 'cdn-loop', 'true-client-ip',
]);
const DROPPED_ANSWER = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'set-cookie', 'content-length', 'content-encoding', 'trailer']);

type Resolved = Credential & { name: string; base: URL; keys: string[] };

/** The credential proxy, as a plugin of the deployment's (`plugins: [credentialProxy({…})]`). */
export function credentialProxy(options: CredentialProxyOptions): CoffrePlugin {
  const credentials = new Map(Object.entries(options.credentials).map(([name, credential]) => [name, resolve(name, credential, options.insecureUpstreams === true)]));
  const expose = checkExpose(options.expose ?? {});
  const tunnels = new Map(Object.entries(options.tunnels ?? {}).map(([name, tunnel]) => [name, checkTunnel(name, tunnel, credentials, options.insecureUpstreams === true)]));
  const recheckMs = (options.recheckSeconds ?? 60) * 1000;
  if (!(recheckMs > 0 && recheckMs <= 3_600_000)) throw new Error('credentialProxy: recheckSeconds is above 0, an hour at most');
  const cacheMs = (options.cacheSeconds ?? 60) * 1000;
  if (!Number.isFinite(cacheMs) || cacheMs < 0 || cacheMs > 3_600_000) throw new Error('credentialProxy: cacheSeconds is between 0 and 3600');
  // Values a handle opened, by handle, environment and credential: settled values only, never a pending read (AGENTS.md, "What an isolate keeps").
  const cache = new Map<string, { values: Record<string, string>; until: number }>();
  const groups = new Map<string, Group>();
  return {
    name: 'credential-proxy',
    routes: {
      prefix: '/use',
      fetch: async (request, coffre) => {
        try {
          return await serve(request, coffre, { credentials, groups, tunnels, insecure: options.insecureUpstreams === true, recheckMs, expose, cacheMs, cache });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code);
          throw error;
        }
      },
      socket: async (request, coffre) => {
        try {
          return await open(request, coffre, { credentials, groups, tunnels, insecure: options.insecureUpstreams === true, recheckMs, expose, cacheMs, cache });
        } catch (error) {
          if (error instanceof CoffreError) return failure(error.status, error.message, error.reason ?? error.code);
          throw error;
        }
      },
    },
  };
}

/** A group of tunnel sessions: how to end each, its last answer (settled, never pending), and its timer. */
type Group = { ends: Set<() => void>; stands: boolean; checking: boolean; timer: ReturnType<typeof setInterval>; expiry: ReturnType<typeof setTimeout> };

/** How long a group's check may take before it counts as a no: the vault has that long to answer. */
const RECHECK_DEADLINE_MS = 10_000;

type Proxy = {
  credentials: Map<string, Resolved>;
  /** The open tunnel sessions, by handle, environment and tunnel, each group checked as one (`watch`). */
  groups: Map<string, Group>;
  tunnels: Map<string, Tunnel>;
  insecure: boolean;
  recheckMs: number;
  expose: Map<string, 'all' | readonly string[]>;
  cacheMs: number;
  cache: Map<string, { values: Record<string, string>; until: number }>;
};

async function serve(request: Request, coffre: PluginContext, proxy: Proxy): Promise<Response> {
  const url = new URL(request.url);
  // The raw segments after `/use`: the place and credential decoded, the rest sent on as the app wrote it.
  const raw = url.pathname.slice('/use'.length).split('/').slice(1);
  if (raw.length === 0 || (raw.length === 1 && raw[0] === '')) {
    // What `coffre run` asks first: whether this instance has the proxy. It holds no secret.
    return request.method === 'GET' ? answer({ proxy: 'coffre', credentials: [...proxy.credentials.keys()] }) : failure(405, 'GET only');
  }
  let place: string[];
  try {
    place = raw.slice(0, 3).map(decodeURIComponent);
  } catch {
    return failure(400, 'the path is not valid percent-encoding');
  }
  if (raw.length === 2) {
    if (request.method === 'POST') return presign(request, coffre, proxy, `${place[0]}/${place[1]}`);
    if (request.method !== 'GET') return failure(405, 'GET for the plan, POST to presign');
    return plan(request, coffre, proxy, `${place[0]}/${place[1]}`);
  }
  if (raw.length < 3) return failure(404, 'name /use/<project>/<environment>/<credential>/<path>');
  const credential = proxy.credentials.get(place[2]!);
  if (credential === undefined) return failure(404, `this instance has no credential ${JSON.stringify(place[2])}: its deployment's credentialProxy names them`);
  return forward(request, coffre, proxy, `${place[0]}/${place[1]}`, credential, raw.slice(3), url.search);
}

/**
 * What `coffre run` gives the app for an environment: each credential whose
 * keys it holds, its keys as the handle and its base URL as the proxy's;
 * the values `expose` lets it hold as they are; and what the app reads for
 * `credential(name)`. Each key the environment holds that none of these
 * covers is named in `left`, for `coffre run` to say.
 */
async function plan(request: Request, coffre: PluginContext, proxy: Proxy, path: string): Promise<Response> {
  const handle = bearer(request);
  if (handle === null) return failure(401, 'send the handle `coffre run` made as a bearer token');
  // The credentials the environment holds every key of: their keys are stand-ins, never exposed.
  const covering = (keys: readonly string[]) => [...proxy.credentials.values()].filter((credential) => credential.keys.every((key) => keys.includes(key)));
  // One read, which opens what the exact environment exposes, never through a parent; and a personal config's own
  // values, which only its owner writes, so they hand back nothing they did not write. Chosen from the rows it opens.
  const held = await coffre.use(handle, {
    path,
    purpose: 'expose',
    logged: { plan: true },
    keys: (environment, rows) => {
      const using = covering(rows.map((row) => row.key));
      const identifiers = new Set(using.flatMap((credential) => credential.identifiers ?? []));
      const covered = new Set([
        ...using.flatMap((credential) => [...credential.keys, ...(credential.baseUrl === undefined ? [] : [credential.baseUrl])]),
        ...[...proxy.tunnels.values()].map((tunnel) => tunnel.key),
      ]);
      const listed = environment.personal ? undefined : proxy.expose.get(environment.path);
      return rows
        // An identifier as `expose` is: the environment's own value, never a parent's, never a personal config's.
        .filter((row) => (identifiers.has(row.key) && !row.inherited && !environment.personal) || (!covered.has(row.key) && (environment.personal ? !row.inherited : listed === 'all' || (listed?.includes(row.key) ?? false))))
        .map((row) => row.key);
    },
  });
  const env: Record<string, string> = Object.create(null);
  const credentials: Record<string, string> = {};
  const covered = new Set<string>();
  for (const credential of covering(held.keys)) {
    const at = `${coffre.publicUrl}/use/${path}/${credential.name}`;
    credentials[credential.name] = at;
    // Every key the handle, and an identifier given as it is below, where its environment holds it itself.
    for (const key of credential.keys) {
      env[key] = handle;
      covered.add(key);
    }
    if (credential.baseUrl !== undefined) {
      env[credential.baseUrl] = at;
      covered.add(credential.baseUrl);
    }
  }
  for (const [key, value] of Object.entries(held.values)) {
    env[key] = value;
    covered.add(key);
  }
  // A database's URL is `coffre run`'s to make, its listener's, with the handle as the password: never the real one.
  const tunnels: Record<string, { key: string; url: string }> = {};
  for (const [name, tunnel] of proxy.tunnels) {
    if (!held.keys.includes(tunnel.key)) continue;
    tunnels[name] = { key: tunnel.key, url: `${coffre.publicUrl.replace(/^http/, 'ws')}/use/${path}/${name}` };
    delete env[tunnel.key];
    covered.add(tunnel.key);
  }
  return answer({
    environment: held.environment.path,
    env: { ...env },
    credentials,
    tunnels,
    left: held.keys.filter((key) => !covered.has(key)),
  });
}

/**
 * A tunnel asked for, `/use/<project>/<env>/<name>` as a WebSocket, by
 * `coffre run`'s listener with the handle as its bearer token: the
 * database's URL opened (or remembered) as a credential's values are,
 * checked against the tunnel's hosts, and the session that logs in with it.
 * Each connection asks again: a cancel request comes on one of its own.
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
  const tunnel = proxy.tunnels.get(place[2]!);
  if (tunnel === undefined) return failure(404, `this instance has no tunnel ${JSON.stringify(place[2])}: its deployment's credentialProxy names them`);
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  const path = `${place[0]}/${place[1]}`;
  // A connection is no request that the cache's minute may serve: each checks the handle stands, opening nothing.
  const { expiresAt } = await coffre.handle(handle);
  let fresh = false;
  const values = await valuesFor(coffre, proxy, handle, path, { name: place[2]!, keys: [tunnel.key] }, null, () => (fresh = true));
  let db: Database;
  try {
    db = database(values[tunnel.key]!);
  } catch {
    // The value is a secret: what is wrong with it is said, never what it is.
    return failure(409, `${path}'s ${tunnel.key} is no postgres:// URL`);
  }
  if (tunnel.hosts !== undefined && !tunnel.hosts.includes(db.host)) return failure(403, `${path}'s ${tunnel.key} names a host the tunnel ${place[2]} does not reach`);
  if (!proxy.insecure && (privateHost(db.host) || db.tls === 'disable')) {
    return failure(403, `${path}'s ${tunnel.key} names a private address or turns TLS off, which only insecureUpstreams, for a local database, allows`);
  }
  const key = `${handle}\u0000${path}\u0000${place[2]!}`;
  return (client, connect) =>
    tunnelPostgres(client, {
      handle,
      database: db,
      connect,
      // Just before a login: the handle afresh, opening nothing, and the group's last word on its person's access.
      stands: async () => (await coffre.handle(handle).then(() => true, () => false)) && (proxy.groups.get(key)?.stands ?? true),
      watch: (end) => watch(coffre, proxy, key, { path, handle, name: place[2]!, key: tunnel.key, expiresAt, fresh }, end),
    });
}

/**
 * A tunnel's sessions of one handle, environment and tunnel, as one: one
 * timer, which every `recheckSeconds` opens the database's URL again for
 * all of them, as the vault decides it (a revoked handle, a lost grant),
 * logged as a use; and the first answer that is no ends every one of them
 * at once. It lives as long as its sessions, and goes with the last.
 */
function watch(
  coffre: PluginContext,
  proxy: Proxy,
  key: string,
  /** `fresh`: the session was let in on the vault's answer just now, not the cache's. */
  tunnel: { path: string; handle: string; name: string; key: string; expiresAt: string; fresh: boolean },
  end: () => void,
): () => void {
  let group = proxy.groups.get(key);
  if (group === undefined) {
    const made: Group = {
      ends: new Set(),
      stands: true,
      checking: false,
      timer: setInterval(() => void recheck(made), proxy.recheckMs),
      // The handle's end, whatever any check is doing: the sessions end with it.
      expiry: setTimeout(() => close(made), Math.max(0, Date.parse(tunnel.expiresAt) - Date.now())),
    };
    /** The sessions end, and the URL the values' cache holds goes with them, so no new one is let in on it. */
    const close = (closing: Group) => {
      closing.stands = false;
      proxy.cache.delete(key);
      for (const ending of [...closing.ends]) ending();
    };
    const recheck = async (checked: Group) => {
      // One check at a time for the group, however many sessions it holds; one that has not answered in time is a no.
      if (checked.checking) return;
      checked.checking = true;
      let late: ReturnType<typeof setTimeout> | undefined;
      const stands = await Promise.race([
        coffre.use(tunnel.handle, { path: tunnel.path, keys: [tunnel.key], purpose: 'use', logged: { credential: tunnel.name, tunnel: true, recheck: true } }).then(
          (used) => Object.hasOwn(used.values, tunnel.key),
          () => false,
        ),
        new Promise<boolean>((resolve) => (late = setTimeout(() => resolve(false), Math.min(proxy.recheckMs, RECHECK_DEADLINE_MS)))),
      ]);
      clearTimeout(late);
      checked.checking = false;
      checked.stands = stands;
      if (!stands) close(checked);
    };
    group = made;
    proxy.groups.set(key, group);
    // A new group let in on the cache's URL decides now, through the vault: its first interval starts from an answer of its own.
    if (!tunnel.fresh) void recheck(made);
  }
  const mine = group;
  mine.ends.add(end);
  return () => {
    mine.ends.delete(end);
    if (mine.ends.size > 0) return;
    clearInterval(mine.timer);
    clearTimeout(mine.expiry);
    if (proxy.groups.get(key) === mine) proxy.groups.delete(key);
  };
}

/**
 * A presigned URL, for an AWS-signed credential: `POST /use/<project>/<env>`
 * with `{ presign: { credential, path, method?, query?, expiresIn? } }`, the
 * handle as a bearer token. coffre signs a GET (or HEAD) of `path` under
 * the credential's upstream with the real key pair, for at most an hour and
 * never past the handle, and answers `{ url, expiresAt }`: a URL of the
 * upstream's, which whoever holds it may use until then, and which holds
 * the access key's id and a signature, never the secret. Each is one use in
 * the log, naming the path and how long it lasts, never served from the
 * cache.
 */
async function presign(request: Request, coffre: PluginContext, proxy: Proxy, path: string): Promise<Response> {
  const handle = bearer(request);
  if (handle === null || !HANDLE.test(handle)) return failure(401, 'send the handle `coffre run` made as a bearer token');
  const raw = await boundedText(request, 8192);
  let asked: { credential?: unknown; path?: unknown; method?: unknown; query?: unknown; expiresIn?: unknown };
  try {
    asked = (JSON.parse(raw ?? '') as { presign?: typeof asked }).presign ?? {};
  } catch {
    return failure(400, 'send { presign: { credential, path, method, expiresIn } } as JSON');
  }
  const credential = typeof asked.credential === 'string' ? proxy.credentials.get(asked.credential) : undefined;
  if (credential === undefined || credential.inject.kind !== 'sigv4') return failure(404, 'presign names a credential of this instance\'s that signs with sigv4()');
  const inject = credential.inject;
  const method = asked.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') return failure(400, 'a presigned URL is for GET or HEAD: an upload goes through the proxy');
  if (credential.methods !== undefined && !credential.methods.includes(method)) return failure(405, `${credential.name} takes ${credential.methods.join(', ')}`);
  const expiresIn = asked.expiresIn ?? 900;
  if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn < 1 || expiresIn > 3600) return failure(400, 'a presigned URL lasts between a second and an hour: expiresIn, in seconds');
  if (typeof asked.path !== 'string' || !asked.path.startsWith('/') || /[?#]/.test(asked.path)) return failure(400, 'presign a path under the credential as a URL has it, /bucket/key, each segment encoded: the query goes in query');
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
  const relative = target.pathname.slice(under.length) || '/';
  if (credential.paths !== undefined && !credential.paths.some((prefix) => relative === prefix || relative.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) {
    return failure(403, `${credential.name} is not for ${relative}`);
  }
  // Every URL is one use in the log, opened now: a URL outlives the request, and whoever holds it may use it.
  const used = await coffre.use(handle, { path, keys: credential.keys, purpose: 'use', logged: { credential: credential.name, host: target.host, presign: { method, path: relative, expiresIn } } });
  if (credential.keys.some((key) => !Object.hasOwn(used.values, key))) return failure(409, `${used.environment.path} holds no key ${credential.name} signs with`);
  // Never past the handle's own end.
  const lasts = Math.min(expiresIn, Math.floor((Date.parse(used.expiresAt) - Date.now()) / 1000));
  if (lasts < 1) return failure(401, 'the handle ends now: run the app with `coffre run` again');
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

/** A small body, as text, read no further than `max` bytes: null past it. */
async function boundedText(request: Request, max: number): Promise<string | null> {
  if (request.body === null) return '';
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (let part = await reader.read(); !part.done; part = await reader.read()) {
    size += part.value.length;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    parts.push(part.value);
  }
  const decoder = new TextDecoder();
  return parts.map((part) => decoder.decode(part, { stream: true })).join('') + decoder.decode();
}

/** One request through a credential: the handle checked, its values opened (or remembered), the request sent on with them. */
async function forward(request: Request, coffre: PluginContext, proxy: Proxy, path: string, credential: Resolved, rest: string[], search: string): Promise<Response> {
  // Nothing the app writes leaves the credential's upstream: no dot segment, no slash or backslash smuggled in a segment.
  if (rest.some((segment) => /^(\.|%2e){1,2}$/i.test(segment) || /%2f|%5c|\\/i.test(segment))) return failure(400, 'the path may not climb out of the credential\'s upstream');
  // The credential's own URL, as the app asked for it: `…/schumann` is the upstream itself, `…/schumann/` the upstream and a slash.
  const target = new URL(`${rest.length === 0 ? credential.base.href : `${credential.base.href.replace(/\/$/, '')}/${rest.join('/')}`}${search}`);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) {
    return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  }
  const relative = target.pathname.slice(under.length) || '/';
  const proxied = `${coffre.publicUrl}/use/${path}/${credential.name}`;
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
  const inject = credential.inject;
  const handle = handleIn(request, credential, target);
  if (handle === null) return failure(401, `send the handle \`coffre run\` gave your app where ${credential.name} takes its key, or as x-coffre-handle`);
  // An AWS-signed upload that says its payload's hash and length streams through, never held whole: an S3 object may be
  // gigabytes, and its signature needs no byte of it. Anything else is read whole first, however long it takes to come,
  // so the handle is checked, and the values opened, as the request goes out.
  const declared = request.headers.get('content-length') ?? '';
  const streamed = inject.kind === 'sigv4' && request.body !== null && request.headers.has('x-amz-content-sha256') && /^\d+$/.test(declared);
  if (streamed && Number(declared) > MAX_STREAM_BYTES) return failure(413, `an upload through the proxy carries at most ${MAX_STREAM_BYTES / 1024 ** 3} GiB: send a larger one in parts`);
  const body = request.method === 'GET' || request.method === 'HEAD' || streamed ? undefined : await boundedBody(request);
  if (body === null) return failure(413, `a request through the proxy carries at most ${MAX_BODY_BYTES / 1024 / 1024} MiB, unless it is AWS-signed with its payload's hash and length, which streams`);
  const values = await valuesFor(coffre, proxy, handle, path, credential, target.host);

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!DROPPED.has(name) && !name.startsWith('cf-') && !name.startsWith('x-forwarded-')) headers.set(name, value);
  }
  // A streamed body says its length itself, which S3 requires of a PutObject.
  if (streamed) headers.set('content-length', declared);
  try {
    if (inject.kind === 'header') headers.set(inject.name, render(inject.template, values));
    if (inject.kind === 'basic') headers.set('authorization', `Basic ${btoa(binary(new TextEncoder().encode(`${render(inject.user, values)}:${render(inject.password, values)}`)))}`);
    if (inject.kind === 'query') target.searchParams.set(inject.name, render(inject.template, values));
    if (inject.kind === 'sigv4') {
      // The app's own signature and the headers it signed are its handle's: signed again, for the upstream's host and path.
      for (const name of ['authorization', 'x-amz-date', 'x-amz-security-token']) headers.delete(name);
      const given = request.headers.get('x-amz-content-sha256');
      // The client's own hash, or the body's, an empty one's included, as SigV4 has it when no header says otherwise.
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
  // The handle goes no further than coffre: anywhere else the app put it, the request stops, as it is or in Basic's base64.
  const leaked = [...headers].find(([, value]) => carries(value)) ?? (carries(safeDecode(target.href)) ? ['URL'] : undefined)
    ?? (body !== undefined && HANDLE.test(new TextDecoder('latin1').decode(body)) ? ['body'] : undefined);
  if (leaked !== undefined) {
    return failure(400, `the handle is somewhere ${credential.name} does not take its key: ${leaked[0] === 'URL' || leaked[0] === 'body' ? `the ${leaked[0]}` : `the ${leaked[0]} header`}`);
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers,
      body: streamed ? scanned(request.body!, Number(declared)) : body,
      redirect: 'manual',
      ...(streamed ? { duplex: 'half' } : {}),
    } as RequestInit);
  } catch (error) {
    return failure(502, `${target.host} did not answer: ${error instanceof Error ? error.message : String(error)}`);
  }
  // What the request carried: each value, and what the rule made of them, Basic's base64, as stored and as they went out
  // (`Headers` trims a value's surrounding whitespace), in each form an honest upstream may echo it in (`echoed`).
  const injected = inject.kind === 'header' ? headers.get(inject.name)! : inject.kind === 'basic' ? headers.get('authorization')!.slice('Basic '.length)
    : inject.kind === 'sigv4' ? headers.get('authorization')! : target.searchParams.get(inject.name)!;
  const redact = redactor([...Object.values(values).flatMap((value) => [value, value.trim()]), injected].flatMap(echoed));
  // A redirect stays on the proxy: under the upstream, it is the proxy's URL for it; anywhere else, the app never learns of it.
  // Redacted as the bytes it came in, before a URL encodes them again.
  const raw = upstream.headers.get('location');
  const location = raw === null ? null : redact.whole(raw);
  let at: string | null = null;
  if (location !== null) {
    const to = new URL(location, target);
    const inside = to.origin === credential.base.origin && (to.pathname === under || to.pathname.startsWith(`${under}/`));
    if (inside) {
      // The proxy's URL for it, and a query rule's parameter, kept or not, the handle, for the app to follow and be let in.
      const back = new URL(`${proxied}${to.pathname.slice(under.length)}${to.search}`);
      if (inject.kind === 'query') back.searchParams.set(inject.name, handle);
      at = back.href;
    } else if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel();
      // Where to is the upstream's to say, and may hold anything: the refusal names only the credential.
      return failure(502, `the upstream redirected outside ${credential.name}'s, where its key does not go`);
    } else at = location;
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

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * A streamed upload, as it passes: a handle anywhere in it, a chunk
 * boundary included, or a byte past the length it declared, and it stops,
 * so the upstream gets a broken request and stores nothing. On Workers,
 * its declared length goes with it (`FixedLengthStream`); Node's fetch
 * sends the header as given.
 */
function scanned(body: ReadableStream<Uint8Array>, length: number): ReadableStream<Uint8Array> {
  let tail = '';
  let seen = 0;
  const checked = body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, out) {
        seen += chunk.length;
        if (seen > length) throw new Error('the upload ran past the length it declared');
        const text = tail + binary(chunk);
        if (HANDLE.test(text)) throw new Error('the handle is in the upload');
        // As much as a handle's length less one: the start of one the next chunk would finish.
        tail = text.slice(-(HANDLE_LENGTH - 1));
        out.enqueue(chunk);
      },
    }),
  );
  const Fixed = (globalThis as { FixedLengthStream?: new (length: number) => TransformStream<Uint8Array, Uint8Array> }).FixedLengthStream;
  return Fixed === undefined ? checked : checked.pipeThrough(new Fixed(length));
}

/** Whether a header's value carries a handle: as it is, or inside Basic authentication's base64. */
function carries(value: string): boolean {
  if (HANDLE.test(value)) return true;
  const basic = /^Basic\s+(\S+)$/i.exec(value);
  if (basic === null) return false;
  try {
    return HANDLE.test(atob(basic[1]!));
  } catch {
    return false;
  }
}

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

/** The credential's values for the handle: remembered for `cacheSeconds`, or opened now, logged as one use. */
async function valuesFor(
  coffre: PluginContext,
  proxy: Proxy,
  handle: string,
  path: string,
  credential: { name: string; keys: readonly string[] },
  host: string | null,
  /** Told when the vault decided now, not the cache. */
  decided?: () => void,
): Promise<Record<string, string>> {
  const key = `${handle}\u0000${path}\u0000${credential.name}`;
  const now = Date.now();
  const kept = proxy.cache.get(key);
  if (kept !== undefined && kept.until > now) return kept.values;
  const used = await coffre.use(handle, { path, keys: credential.keys, purpose: 'use', logged: { credential: credential.name, ...(host === null ? { tunnel: true } : { host }) } });
  const missing = credential.keys.filter((name) => !Object.hasOwn(used.values, name));
  if (missing.length > 0) throw new CoffreError(409, 'conflict', `${used.environment.path} holds no ${missing.join(', ')}, which ${credential.name} needs`);
  decided?.();
  if (proxy.cacheMs > 0) {
    // A handful of handles in a dev loop: past a thousand, the oldest go.
    if (proxy.cache.size >= 1000) for (const [old, entry] of proxy.cache) if (entry.until <= now || proxy.cache.size >= 1000) proxy.cache.delete(old);
    proxy.cache.set(key, { values: used.values, until: Math.min(now + proxy.cacheMs, Date.parse(used.expiresAt)) });
  }
  return used.values;
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
  return slot === null ? null : (HANDLE.exec(slot)?.[0] ?? null);
}

function bearer(request: Request): string | null {
  return /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
}

/** The body, read whole up to the limit, and no further: null past it, the rest left unread. */
async function boundedBody(request: Request): Promise<Uint8Array<ArrayBuffer> | undefined | null> {
  if (Number(request.headers.get('content-length') ?? '0') > MAX_BODY_BYTES) return null;
  if (request.body === null) return undefined;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
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
  return template.replace(PLACEHOLDER, (_, key: string) => values[key]!);
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
  const keys = [...new Set(templates.flatMap((template) => [...template.matchAll(PLACEHOLDER)].map((match) => match[1]!)))];
  if (keys.length === 0) throw new Error(`credentialProxy: ${name}'s rule names no key: write it as {KEY}, as header('x-api-key', '{SCHUMANN_API_KEY}')`);
  if (credential.baseUrl !== undefined && (!KEY.test(credential.baseUrl) || keys.includes(credential.baseUrl))) throw new Error(`credentialProxy: ${name}'s baseUrl is the key the app reads its address from, and none of its rule's`);
  if (credential.identifiers?.some((key) => !keys.includes(key))) throw new Error(`credentialProxy: ${name}'s identifiers are keys its rule reads`);
  if (credential.identifiers !== undefined && keys.every((key) => credential.identifiers!.includes(key))) throw new Error(`credentialProxy: ${name}'s rule needs a key that is no identifier, for the handle to stand in for`);
  const methods = credential.methods?.map((method) => method.toUpperCase());
  if (credential.paths !== undefined && credential.paths.some((path) => !path.startsWith('/'))) throw new Error(`credentialProxy: ${name}'s paths start with /`);
  return { ...credential, ...(methods === undefined ? {} : { methods }), name, base, keys };
}

function checkTunnel(name: string, tunnel: Tunnel, credentials: Map<string, Resolved>, insecure: boolean): Tunnel {
  if (!NAME.test(name)) throw new Error(`credentialProxy: a tunnel's name is lowercase letters, digits and dashes; got ${JSON.stringify(name)}`);
  if (credentials.has(name)) throw new Error(`credentialProxy: ${name} names a credential and a tunnel`);
  if (tunnel.kind !== 'postgres') throw new Error(`credentialProxy: tunnel ${name} is postgres(…), the only kind there is`);
  if (!KEY.test(tunnel.key)) throw new Error(`credentialProxy: tunnel ${name} names the key that holds its URL, DATABASE_URL`);
  // Each as it is dialled, 127.1 as 127.0.0.1: what the URL's host is held to.
  const hosts = tunnel.hosts?.map((host) => new URL(`http://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}`).hostname.replace(/^\[|\]$/g, ''));
  if (!insecure && hosts?.some(privateHost)) throw new Error(`credentialProxy: tunnel ${name} names a private host, which only insecureUpstreams reaches`);
  return { ...tunnel, ...(hosts === undefined ? {} : { hosts }) };
}

function checkExpose(expose: Record<string, 'all' | readonly string[]>): Map<string, 'all' | readonly string[]> {
  for (const [path, keys] of Object.entries(expose)) {
    if (!/^[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/.test(path)) throw new Error(`credentialProxy: expose names environments by path, market/local; got ${JSON.stringify(path)}`);
    if (keys !== 'all' && (!Array.isArray(keys) || keys.some((key) => !KEY.test(key)))) throw new Error(`credentialProxy: expose['${path}'] is 'all' or a list of keys`);
  }
  return new Map(Object.entries(expose));
}

/** Whether a host is a literal private, loopback or link-local address, or localhost. */
function privateHost(host: string): boolean {
  const name = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(name);
  if (v4 !== null) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (name.includes(':')) return name === '::1' || name === '::' || /^f[cd]/.test(name) || /^fe[89ab]/.test(name) || name.startsWith('::ffff:');
  return false;
}

function answer(body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

/** coffre's own refusal, told apart from the upstream's by its header. */
function failure(status: number, message: string, reason?: string): Response {
  return new Response(JSON.stringify({ error: 'credential_proxy', message, ...(reason === undefined ? {} : { reason }) }), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'coffre-proxy': 'refused' },
  });
}

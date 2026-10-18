/**
 * The credential proxy (docs/design/credential-proxy.md): a person's app,
 * an agent's included, uses secrets without ever holding them. `coffre run`
 * gives it a stand-in for each, a handle (`coffre_use_…`) that reaches
 * nothing but this proxy, and points its base URL here; the proxy swaps in
 * the real value at the edge, for the credential's own upstream only. In
 * the deployment's configuration:
 *
 *   import { credentialProxy, header } from '@coffre/server/plugins/credential-proxy';
 *   plugins: [credentialProxy({
 *     credentials: {
 *       schumann: { upstream: 'https://api.schumann.example/v1', inject: header('x-api-key', '{SCHUMANN_API_KEY}'), baseUrl: 'SCHUMANN_BASE_URL' },
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

import type { CoffrePlugin, PluginContext } from '../plugins.ts';

/** How a credential's values reach its upstream: in a header, a query parameter, or Basic authentication. */
export type Inject =
  | { kind: 'header'; name: string; template: string }
  | { kind: 'query'; name: string; template: string }
  | { kind: 'basic'; user: string; password: string };

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

/** One credential: its upstream, how its keys reach it, and what of it a caller may ask. */
export type Credential = {
  /** Where its requests go, `https://api.schumann.example/v1`: `/use/<project>/<env>/<name>/<path>` goes to `<upstream>/<path>`, and nowhere else. */
  upstream: string;
  inject: Inject;
  /** The key the app reads the upstream's address from, `SCHUMANN_BASE_URL`: `coffre run` sets it to this proxy's URL for the credential. */
  baseUrl?: string;
  /** The methods it may be used with, `['GET', 'POST']`; any, unless set. */
  methods?: readonly string[];
  /** The paths under `upstream` it may be used on, by prefix, `['/companies']`; any, unless set. */
  paths?: readonly string[];
};

export type CredentialProxyOptions = {
  /** By name, as the proxy's URLs say it: lowercase letters, digits and dashes. */
  credentials: Record<string, Credential>;
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
/** Values shorter than this are not redacted from answers: too short to tell from the text around them. */
const MIN_REDACTED = 8;
const REDACTED = '[redacted by coffre]';
/** Headers about one hop, and those that would tell the upstream about coffre's caller, its cookies or its handle. */
const DROPPED = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'cookie', 'content-length', 'x-coffre-handle', 'forwarded', 'x-real-ip', 'cdn-loop', 'true-client-ip',
]);
const DROPPED_ANSWER = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'set-cookie', 'content-length', 'content-encoding', 'trailer']);

type Resolved = Credential & { name: string; base: URL; keys: string[] };

/** The credential proxy, as a plugin of the deployment's (`plugins: [credentialProxy({…})]`). */
export function credentialProxy(options: CredentialProxyOptions): CoffrePlugin {
  const credentials = new Map(Object.entries(options.credentials).map(([name, credential]) => [name, resolve(name, credential, options.insecureUpstreams === true)]));
  const expose = checkExpose(options.expose ?? {});
  const cacheMs = (options.cacheSeconds ?? 60) * 1000;
  if (!Number.isFinite(cacheMs) || cacheMs < 0 || cacheMs > 3_600_000) throw new Error('credentialProxy: cacheSeconds is between 0 and 3600');
  // Values a handle opened, by handle, environment and credential: settled values only, never a pending read (AGENTS.md, "What an isolate keeps").
  const cache = new Map<string, { values: Record<string, string>; until: number }>();
  return {
    name: 'credential-proxy',
    routes: {
      prefix: '/use',
      fetch: async (request, coffre) => {
        try {
          return await serve(request, coffre, { credentials, expose, cacheMs, cache });
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
    if (request.method !== 'GET') return failure(405, 'GET only');
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
  // One read of what the environment holds, opening only what it exposes: logged as one use, of those values.
  const held = await coffre.use(handle, { path, keys: [], purpose: 'expose', logged: { plan: true } });
  const exposedHere = proxy.expose.get(held.environment.personal ? '' : held.environment.path);
  const exposed = held.keys.filter((key) => exposedHere === 'all' || (exposedHere?.includes(key) ?? false));
  const opened = exposed.length === 0 ? {} : (await coffre.use(handle, { path, keys: exposed, purpose: 'expose', logged: { exposed: true } })).values;
  const env: Record<string, string> = Object.create(null);
  const credentials: Record<string, string> = {};
  const covered = new Set(exposed);
  for (const credential of proxy.credentials.values()) {
    if (!credential.keys.every((key) => held.keys.includes(key))) continue;
    const at = `${coffre.publicUrl}/use/${path}/${credential.name}`;
    credentials[credential.name] = at;
    for (const key of credential.keys) {
      env[key] = handle;
      covered.add(key);
    }
    if (credential.baseUrl !== undefined) {
      env[credential.baseUrl] = at;
      covered.add(credential.baseUrl);
    }
  }
  for (const key of exposed) if (opened[key] !== undefined) env[key] = opened[key];
  return answer({
    environment: held.environment.path,
    env: { ...env },
    credentials,
    left: held.keys.filter((key) => !covered.has(key)),
  });
}

/** One request through a credential: the handle checked, its values opened (or remembered), the request sent on with them. */
async function forward(request: Request, coffre: PluginContext, proxy: Proxy, path: string, credential: Resolved, rest: string[], search: string): Promise<Response> {
  // Nothing the app writes leaves the credential's upstream: no dot segment, no slash or backslash smuggled in a segment.
  if (rest.some((segment) => /^(\.|%2e){1,2}$/i.test(segment) || /%2f|%5c|\\/i.test(segment))) return failure(400, 'the path may not climb out of the credential\'s upstream');
  const target = new URL(`${credential.base.href.replace(/\/$/, '')}/${rest.join('/')}${search}`);
  const under = credential.base.pathname.replace(/\/$/, '');
  if (target.origin !== credential.base.origin || (target.pathname !== under && !target.pathname.startsWith(`${under}/`))) {
    return failure(400, `${credential.name} reaches ${credential.base.href} only`);
  }
  const relative = target.pathname.slice(under.length) || '/';
  if (credential.methods !== undefined && !credential.methods.includes(request.method)) return failure(405, `${credential.name} takes ${credential.methods.join(', ')}`);
  if (credential.paths !== undefined && !credential.paths.some((prefix) => relative === prefix || relative.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) {
    return failure(403, `${credential.name} is not for ${relative}`);
  }

  const handle = handleIn(request, credential, target);
  if (handle === null) return failure(401, `send the handle \`coffre run\` gave your app where ${credential.name} takes its key, or as x-coffre-handle`);
  const values = await valuesFor(coffre, proxy, handle, path, credential, target.host);

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!DROPPED.has(name) && !name.startsWith('cf-') && !name.startsWith('x-forwarded-')) headers.set(name, value);
  }
  const inject = credential.inject;
  if (inject.kind === 'header') headers.set(inject.name, render(inject.template, values));
  if (inject.kind === 'basic') headers.set('authorization', `Basic ${btoa(`${render(inject.user, values)}:${render(inject.password, values)}`)}`);
  if (inject.kind === 'query') target.searchParams.set(inject.name, render(inject.template, values));
  // The handle goes no further than coffre: anywhere else the app put it, the request stops.
  const leaked = [...headers].find(([, value]) => HANDLE.test(value));
  if (leaked !== undefined || HANDLE.test(target.href)) {
    return failure(400, `the handle is somewhere ${credential.name} does not take its key${leaked === undefined ? '' : `: the ${leaked[0]} header`}`);
  }

  const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await boundedBody(request);
  if (body === null) return failure(413, `a request through the proxy carries at most ${MAX_BODY_BYTES / 1024 / 1024} MiB`);
  let upstream: Response;
  try {
    upstream = await fetch(target, { method: request.method, headers, body, redirect: 'manual' });
  } catch (error) {
    return failure(502, `${target.host} did not answer: ${error instanceof Error ? error.message : String(error)}`);
  }
  return redacted(upstream, Object.values(values));
}

/** The credential's values for the handle: remembered for `cacheSeconds`, or opened now, logged as one use. */
async function valuesFor(coffre: PluginContext, proxy: Proxy, handle: string, path: string, credential: Resolved, host: string): Promise<Record<string, string>> {
  const key = `${handle}\u0000${path}\u0000${credential.name}`;
  const now = Date.now();
  const kept = proxy.cache.get(key);
  if (kept !== undefined && kept.until > now) return kept.values;
  const used = await coffre.use(handle, { path, keys: credential.keys, purpose: 'use', logged: { credential: credential.name, host } });
  const missing = credential.keys.filter((name) => used.values[name] === undefined);
  if (missing.length > 0) throw new CoffreError(409, 'conflict', `${used.environment.path} holds no ${missing.join(', ')}, which ${credential.name} needs`);
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

/** The body, read whole up to the limit: null past it. */
async function boundedBody(request: Request): Promise<ArrayBuffer | null> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) return null;
  const body = await request.arrayBuffer();
  return body.byteLength > MAX_BODY_BYTES ? null : body;
}

/** `{KEY}` in a template, each the environment's value. */
function render(template: string, values: Record<string, string>): string {
  return template.replace(PLACEHOLDER, (_, key: string) => values[key]!);
}

/**
 * The upstream's answer, with each value the request carried replaced
 * wherever it shows: in headers, and in a text body, streamed, holding back
 * as much as the longest value so that one split across chunks is caught
 * too. A binary body passes as it is. Cookies stay with the upstream: one
 * set on coffre's origin could stand in for coffre's own.
 */
function redacted(upstream: Response, values: string[]): Response {
  const secrets = values.filter((value) => value.length >= MIN_REDACTED).sort((a, b) => b.length - a.length);
  const scrub = (text: string) => secrets.reduce((out, secret) => out.split(secret).join(REDACTED), text);
  const headers = new Headers();
  for (const [name, value] of upstream.headers) if (!DROPPED_ANSWER.has(name)) headers.set(name, scrub(value));
  headers.set('cache-control', upstream.headers.get('cache-control') ?? 'no-store');
  const type = upstream.headers.get('content-type') ?? '';
  const text = /^text\/|json|xml|javascript|x-www-form-urlencoded|event-stream/i.test(type);
  if (upstream.body === null || !text || secrets.length === 0) return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers });
  const hold = secrets[0]!.length - 1;
  let carry = '';
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const body = upstream.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, out) {
        const all = scrub(carry + decoder.decode(chunk, { stream: true }));
        // Hold back what could be the start of a value the next chunk ends.
        const cut = Math.max(0, all.length - hold);
        carry = all.slice(cut);
        if (cut > 0) out.enqueue(encoder.encode(all.slice(0, cut)));
      },
      flush(out) {
        const last = scrub(carry + decoder.decode());
        if (last.length > 0) out.enqueue(encoder.encode(last));
      },
    }),
  );
  return new Response(body, { status: upstream.status, statusText: upstream.statusText, headers });
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
  const templates = credential.inject.kind === 'basic' ? [credential.inject.user, credential.inject.password] : [credential.inject.template];
  if (credential.inject.kind !== 'basic' && !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(credential.inject.name)) throw new Error(`credentialProxy: ${name} injects into ${JSON.stringify(credential.inject.name)}, which is no header or parameter name`);
  const keys = [...new Set(templates.flatMap((template) => [...template.matchAll(PLACEHOLDER)].map((match) => match[1]!)))];
  if (keys.length === 0) throw new Error(`credentialProxy: ${name}'s rule names no key: write it as {KEY}, as header('x-api-key', '{SCHUMANN_API_KEY}')`);
  if (credential.baseUrl !== undefined && (!KEY.test(credential.baseUrl) || keys.includes(credential.baseUrl))) throw new Error(`credentialProxy: ${name}'s baseUrl is the key the app reads its address from, and none of its rule's`);
  const methods = credential.methods?.map((method) => method.toUpperCase());
  if (credential.paths !== undefined && credential.paths.some((path) => !path.startsWith('/'))) throw new Error(`credentialProxy: ${name}'s paths start with /`);
  return { ...credential, ...(methods === undefined ? {} : { methods }), name, base, keys };
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

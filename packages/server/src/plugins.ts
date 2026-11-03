// Plugins (docs/design/plugins.md): what a deployment adds to coffre in its
// configuration, `plugins: [vaultKv({ mount: 'secret' })]`. A plugin holds no
// authority of its own. It answers paths of its own, and reaches coffre only
// as whoever a request's credential names, through the API: the same route
// table, checks, vault and audit log as the CLI.
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import { USE_DEADLINE_MS, type Access, type DecidedItem, type RouteCaller, type RouteFound, type RouteUseOutcome, type Vault } from '@coffre/core/vault';
import type { CredentialScope } from '@coffre/core/access';
import { ACCESS_JWT_HEADER, CREDENTIAL_NAME, hashToken, tokenKind, type BindingPolicy, type Constraints, type GateCount, type WorkloadCaller } from '@coffre/core/identity';

import { AccessChanged, accessFor, type Recalled } from './accesses.ts';
import { authenticateRequest, type AuthenticatedIdentity } from './auth.ts';
import { exchangeWorkloadToken, logout } from './auth-routes.ts';
import { callerFrom, withRecalled } from './api/caller.ts';
import { ApiError } from './api/errors.ts';
import { parsePath, type Path } from './api/paths.ts';
import { readScope } from './api/services.ts';
import { environmentsOf } from './api/workloads.ts';
import { checkAuthRow } from './auth-rows.ts';
import { environmentPaths, places as placeRows, type BindingRow, type CredentialRead } from './db/queries.ts';
import { namedManyAhead, readAhead, type ReadAhead } from './db/read-ahead.ts';
import { uses015 } from './api/changes.ts';
import { callBindings, frozenTargets } from './db/workloads.ts';
import { reveal, type PickKeys } from './api/secrets.ts';
import { refusedUse } from './api/keys.ts';
import { fetchApi } from './fetch-api.ts';
import { acceptance, useByName, useManyByName, useRouteByName } from './named-use.ts';
import { errorResponse } from './http.ts';
import { limitAlert, raiseAlert } from './alerts.ts';
import { logged } from './logged.ts';
import { proxyCodeOf } from './proxy-code.ts';
import { gateProxy } from './proxy-gate.ts';
import { apiContext, type CoffreRuntime } from './runtime.ts';
import { dpopToken, gateOf, namedPlace, OtherReading, SessionRefused, sessionScope, sessionStands, standingSession, type CountsAt, type GateCounts, type StandingSession } from './workload-sessions.ts';

export type { PickKeys };

/** One plugin, as its constructor returns it: `vaultKv({ mount: 'secret' })`. */
export type CoffrePlugin = {
  /** What names it in errors: lowercase, `vault-kv`. Unique among a deployment's plugins. */
  name: string;
  /**
   * The paths it answers: `prefix`, `/v1`, and every path under it, whatever
   * the method. The deployment's app routes them to coffre with a file
   * route of their own, `routes/v1.$.ts` (`plugin`, in `@coffre/server/routes`).
   */
  routes?: {
    prefix: string;
    fetch: (request: Request, coffre: PluginContext) => Promise<Response>;
    /**
     * A WebSocket asked for under `prefix`: a refusal, or what carries the
     * connection's bytes once it is open (`SocketSession`). On Node, the
     * server's `upgrade` events reach it (`createCoffre(…).upgrade`); on
     * Workers, a Durable Object per bearer and path hosts it, and its
     * client paces the bytes by credit, as `coffre run`'s listener does
     * (`cloudflare-sockets.ts`): a socket's client is coffre's own. A
     * browser's WebSocket can neither ask for that nor count, and is
     * refused there.
     */
    socket?: (request: Request, coffre: PluginContext) => Promise<Response | SocketSession>;
  };
};

/** A connection's bytes both ways, a WebSocket's or a TCP socket's, and when it ends, whichever side ends it. */
export type Pipe = { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array>; close(): void; closed: Promise<void> };

/** An outbound TCP connection, which can turn to TLS once the protocol on it says it will. */
export type Socket = Pipe & { startTls(servername: string): Promise<Pipe> };

/** TCP out, as the platform opens it; `signal` gives up a dial still under way. */
export type Connect = (host: string, port: number, signal?: AbortSignal) => Promise<Socket>;

/** What runs a plugin's WebSocket once it is open: its bytes, and TCP out. Ends when the connection does. */
export type SocketSession = (client: Pipe, connect: Connect) => Promise<void>;

/** What a plugin's route answers with: where coffre is, and its API as a credential's holder. */
export type PluginContext = {
  publicUrl: string;
  /**
   * Whether the request came through a Cloudflare service binding
   * (`bindingRoute`): its service's call, carrying no handle, token or
   * session, which `workload` answers for. Which service is coffre's to
   * know, never the plugin's.
   */
  binding: boolean;
  /**
   * A request to a host an Owner typed in a web page, a UI route's upstream:
   * on Node, one that dials only public addresses, whatever the name
   * resolves to; on Workers, the platform's fetch. Absent, the plugin sends
   * none (docs/design/proxy-ui.md, section 5).
   */
  publicFetch?: (url: URL, init: RequestInit) => Promise<Response>;
  /**
   * TCP out to a host an Owner typed in a web page, a UI tunnel's database:
   * on Node, one that dials only public addresses, whatever the name
   * resolves to; on Workers, the platform's `connect()`. Absent, the plugin
   * dials none (docs/design/proxy-ui.md, section 5).
   */
  publicConnect?: Connect;
  /**
   * The API as whoever `token` names, which the plugin read from its
   * request: a service, personal or CLI token with coffre's sign-in, Access's
   * assertion behind Cloudflare Access; never a cookie, which coffre alone
   * reads. The token is checked at the first call, once for all of them; a
   * refusal, the token's included, throws a `CoffreError`.
   */
  api(token: string): CoffreClient;
  /**
   * The request as a workload's sign-in: its body, a workload's ID token,
   * for a credential of the service account it names that lasts five
   * minutes, through that account's trust bindings. This is `POST
   * /api/auth/oidc` on the plugin's own request, in process: its limits
   * first, then the body, read only to its limit, then the token spent so
   * that it signs in once, and its audit. `asked` says what the body asks
   * for, `{ service, token }`, in the plugin's words. A refusal throws a
   * `CoffreError`, a body that does not say 400.
   */
  exchange(asked: (body: unknown) => { service: unknown; token: unknown }): Promise<{ token: string; expiresAt: string }>;
  /** End the credential `token` is, as `POST /api/auth/logout` with it does. A refusal throws a `CoffreError`. */
  signOut(token: string): Promise<void>;
  /**
   * Values of the environment `path` names, `market/dev`, for whoever
   * `handle` (`coffre_use_…`) stands in for: opened to `use` them for its
   * person, in a request the plugin sends for them, or to `expose` them,
   * handed to their app (docs/design/credential-proxy.md). The API's read,
   * in process and nowhere else: the same checks, its person's grants and
   * the handle's scope, one vault entry naming the keys, and one
   * `credential.use` entry, with `logged` in it, which the vault appends
   * beside it (an older vault: the app, under the head). Only the keys
   * asked for, or chosen, those the environment holds; `environment` is the
   * one the read resolved to (`market/dev@me` may be a personal config). A
   * refusal throws a `CoffreError`. In place of a handle, the workload
   * `workload` returned for this request: its service's grants within its
   * scope, which reads only plain keys and those its binding lists
   * (docs/design/workload-access.md, section 6.1).
   */
  use(handle: string | WorkloadUse, asked: UseAsked): Promise<Used>;
  /**
   * `use` of a handle's one key at the environment it was made for, the credential proxy's stable URL, in the vault's
   * one call (T145): unless that environment is one of `unless` (`market/dev`), which the request does not mean. Null
   * where the vault serves it not so (a handle of several environments, of none, of 0.8, a fork or a personal config,
   * one of `unless`, an older vault): nothing was used, and `handle` then `use` answer it, as ever.
   */
  useMadeFor?(handle: string, asked: Omit<UseAsked, 'path' | 'keys' | 'only'> & { keys: readonly [string]; unless: readonly string[] }): Promise<Used | null>;
  /**
   * Whether `handle` still stands, opening nothing and logging nothing:
   * when it ends, and the environments it was made for, each by path as it
   * is named now (`market/dev@me`), or null where it was deleted; null for
   * a handle of 0.8, which kept none. A refusal throws a `CoffreError`.
   */
  handle(handle: string): Promise<{ expiresAt: string; paths: readonly (string | null)[] | null }>;
  /**
   * The request as a workload's (docs/design/workload-access.md, section
   * 5.3), never answered from a cache: its key-bound session, `Authorization:
   * DPoP coffre_wl_…`, in one statement with its binding, its ancestors and
   * every freeze that names it, the credential it uses at `place` among
   * them; its proof, for this request and, with `body`, the content coffre
   * forwards; then its gate, the proof once and `counts` in the same call.
   * No vault call. A `narrow` child is a workload too, with its
   * `constraints`. Through a Cloudflare service binding (`bindingRoute`),
   * the caller its binding's `props` name, with no proof and no session.
   *
   * `place` is an environment's ID or path (`market/prod`); null with a
   * `credential` means the one environment the session reaches
   * (`/use/<credential>`). A refusal throws a `WorkloadRefused`, whose
   * `response` is the answer to forward as it is; a count's first refusal
   * in its window has written its `workload.alert` already. What it returns
   * is what `use` takes in place of a handle. Null for a request that is no
   * workload's, which carries no `Authorization: DPoP`: a handle's, say.
   */
  workload(request: Request, at: WorkloadAt): Promise<WorkloadUse | null>;
  /**
   * Whether a workload this context's `workload` returned still stands, as
   * section 5.3's statement says now, freezes and the credential it used
   * included, without its proof or its gate: what an open tunnel's rechecks
   * ask, its socket authenticated already (section 7.1). No vault call.
   * False for a caller this context did not make.
   */
  recheck(caller: WorkloadUse): Promise<boolean>;
  /**
   * A UI definition's use (0.16, T186 PR C; docs/design/proxy-ui.md, section 3): the vault's one call finds the item
   * `asked` names at the place, a handle's URL read the way section 6 says (`named`, the place reading, taken when the
   * handle was made for that environment; `stable`, the route at the handle's one environment), and uses every key it
   * sends, each decided for the caller and for the item's editor. It answers the values
   * and the item they were decided on (its definition left out where `digests` names its digest: the copy's), which
   * the proxy sends by, never by a copy of its own. Refused: a `CoffreError` (404 no such item, 409 a personal config,
   * 403 a key its editor may not route, 503 an item a writer changed). The app's `credential.use` entry records it, with
   * `logged`, as `use`'s does, under the name of the route the vault's reading took (review r4 of #467). In place of
   * a handle, the workload `workload` returned for this request (C2b): its route `stable`, at the place its statement
   * checked, decided for it as the vault decides its standing there, in the same one call.
   */
  useRoute?(caller: string | WorkloadUse, asked: RouteAsked): Promise<RouteUsed>;
  /**
   * A handle's `useRoute` of a URL that may name the place itself (T186 PR C2b4; section 6, "URLs of one or two
   * segments"): `/use/<a>/<b>`, the plan or compute where the handle was made for `<a>/<b>`, else route `<a>` at `/<b>`;
   * and `/use/<a>/<b>/<code's name>/…` the same, code's credential at `<a>/<b>`. Both readings go in the one call,
   * which picks one from the caller's rows: the stable one is `useRoute`'s answer, `stable` at the handle's one
   * environment; the place's is null, nothing used or opened, and the proxy serves the URL as the place's, in calls of
   * its own, as it did after the handle's made-for list.
   */
  useRouteOrPlace?(handle: string, asked: Omit<RouteAsked, 'named' | 'stable'> & { place: string; stable: string }): Promise<RouteUsed | null>;
  /**
   * A place's UI items as a use would find them, using nothing (section 3, `proxyItem`): the caller checked first, then
   * `name`'s item, or, with none, every item the place serves. `place`, a handle's by path, null for its own; a
   * workload's is always its own, the one its statement checked. Refused: a `CoffreError`.
   */
  proxyItem?(caller: string | WorkloadUse, asked: { place: string | null; name: string | null }): Promise<ItemsFound>;
};

/** What a UI route's use names (`PluginContext.useRoute`). */
export type RouteAsked = {
  named: { path: string; route: string } | null;
  stable: string | null;
  digests: readonly string[];
  /**
   * What the app's `credential.use` entry records beside the route, or how the item the vault decided on says it (a
   * presigned URL's host, C2b2), asked once the vault has decided, before the read: so a private key's sign hashes its
   * message only for a caller the vault knows, whose item signs with a private key (Fable's review of #480).
   */
  logged: Record<string, unknown> | ((item: DecidedItem | null) => Record<string, unknown> | Promise<Record<string, unknown>>);
  /**
   * Why the proxy would serve no request on the item the vault found, or null: `GET /use/signing/x`, a signer, reaches
   * no upstream. Asked before the read opens what the vault answered, so the app reads no value of it and keeps none
   * (404 for a reason alone; Fable's review of #467), and only of a use the vault allowed: a key the caller may not use
   * is the read's one "no" whatever the item's kind (review r10). A `CoffreError` is answered as it is: a sign, verify or
   * presign whose decided item takes it otherwise than the copy that admitted it (503 `moved`, C2b2). The vault's call
   * has logged its use already.
   */
  refuses?: (item: DecidedItem) => string | CoffreError | null;
};

/** A UI route's use, answered: the values, by key, and those of them plain; the item they were decided on; where. */
export type RouteUsed = {
  values: Record<string, string>; plain: string[]; keys: string[];
  item: DecidedItem; seals: string[]; reading: 'named' | 'stable';
  environment: { path: string }; expiresAt: string;
};

/** A place's UI items as `proxyItem` found them: one, or every one, each with its digest; or a level a writer changed. */
export type ItemsFound = {
  fault: 'tampered' | 'stale' | null; personal: boolean;
  item: (DecidedItem & { level: number }) | null; items: (DecidedItem & { level: number })[] | null;
};

/** What a workload's request uses (`PluginContext.workload`): where and which credential, the body line `req` signs, and the counts its limits take. */
export type WorkloadAt = {
  /** An environment's ID or its path, `market/prod`. */
  place: string | null;
  credential: string | null;
  /**
   * With `place` null, the URL's other reading (`/use/<a>/<b>/<c>/…`, a UI route's; T186 PR C2b), as a workload's
   * client writes its URLs: `credential` at the one environment the workload reaches, unless it reaches several, or
   * none, or that one is at `or.place`'s path, when `or` is the request, at that path. Decided before the gate: the
   * proof is spent once, by the reading taken, which the caller's `path` says.
   */
  or?: { place: string; credential: string };
  /**
   * `bodyDigest(bytes)` of a buffered body, a sigv4 upload's declared
   * digest, or `UNSIGNED_BODY`, which only a binding that says
   * `unsignedUploads` takes: for a request whose proof signs its content.
   * Left out for one that signs none.
   */
  body?: string;
  /**
   * The counts, or how to make them once authentication says who sends the request and where: the service,
   * `token:<name>` (a limit per workload), and the place by ID, whose UI item `item` finds as this workload, using
   * nothing (`PluginContext.proxyItem`), for a UI route's limit (T186 PR C2b). Made only when the gate is about to
   * take them; a function that throws fails the request.
   */
  counts?: PluginCounts;
};

/** A workload request's counts as a plugin gives them (`WorkloadAt.counts`). */
export type PluginCounts = readonly GateCount[] | ((at: { service: string; place: string | null; credential: string | null; item: (name: string) => Promise<ItemsFound> }) => readonly GateCount[] | Promise<readonly GateCount[]>);

/**
 * A workload, authenticated for one request: the caller the proxy sees, the
 * gate's nonce to send back (`DPoP-Nonce`; null for a Cloudflare call), the
 * environments it reaches by ID, and the one this request uses, by ID and
 * by its path as named now (what `use` and `constraintsAllow` take).
 */
export type WorkloadUse = WorkloadCaller & { readonly nonce: string | null; readonly places: readonly string[]; readonly place: string | null; readonly path: string | null };

/** A workload's request refused: `response` is its answer, the headers RFC 9449 asks for included; `limit`, a count the gate refused. */
export class WorkloadRefused extends CoffreError {
  readonly response: Response;
  readonly limit: { key: string; retryAfterMs: number; first: boolean } | null;
  constructor(status: number, code: string, message: string, reason: string | undefined, response: Response, limit: WorkloadRefused['limit'] = null) {
    super(status, code, message, reason);
    this.name = 'WorkloadRefused';
    this.response = response;
    this.limit = limit;
  }
}

/**
 * What a workload caller stands on, kept beside it by the context of the
 * request it was made for: `use` takes back only those, so one kept from
 * an earlier request, checked before a revocation or a freeze, is no one.
 */
type Standing = { kind: 'session'; session: StandingSession; credential: string | null } | { kind: 'binding'; binding: BindingRow; policy: BindingPolicy; policySeq: bigint | null; credential: string | null };
type Standings = WeakMap<WorkloadUse, Standing>;

/**
 * What a plugin opens values for (`PluginContext.use`): `keys` by name, or
 * chosen from what the read resolved (`PickKeys`), so that a choice about
 * an environment's rows is made on the rows that are opened. `only`, with
 * keys by name: the read reads those keys' rows and no other, and `Used.keys`
 * lists those of them the environment holds, not every key it holds: for a
 * caller that never reads that list (the credential proxy's uses).
 */
export type UseAsked = { path: string; keys: readonly string[] | PickKeys; purpose: 'use' | 'expose'; logged: Record<string, unknown>; only?: boolean };

/** A UI item's lookup refused: none at the place (404), or a level a writer changed, which serves nothing (503). */
function foundRefusal(found: RouteFound, name: string): CoffreError | null {
  if (found.found) return null;
  if (found.fault === null) return new CoffreError(404, 'not_found', `this instance has no credential ${JSON.stringify(name)} here: neither its deployment's code nor this environment's definitions name it`);
  return new CoffreError(503, 'unavailable', `${name}: this environment's proxy definitions are not as the vault sealed them (${found.fault}): an Owner saves them again`, found.fault, '1');
}

/** A route use's answer as the proxy takes it: the values the read opened, the item, and where. */
/** What a route use's `credential.use` entry records beside the route: the proxy's, or what it says of the item the vault decided on. */
async function loggedOf(answered: Extract<RouteUseOutcome, { route: 'name' }>, asked: RouteAsked): Promise<Record<string, unknown>> {
  if (typeof asked.logged !== 'function') return asked.logged;
  return await asked.logged(answered.found?.found === true ? answered.found.item : null);
}

/** The proxy's refusal of the item a use decided on (`RouteAsked.refuses`): a reason alone is a 404. */
function unservedError(unserved: string | CoffreError): CoffreError {
  return typeof unserved === 'string' ? new CoffreError(404, 'not_found', unserved) : unserved;
}

function routeUsed(answered: Extract<RouteUseOutcome, { route: 'name' }>, read: { values: Record<string, string>; plain: string[]; keys: string[]; environment: { path: string } }, expiresAt: string): RouteUsed {
  const found = answered.found;
  if (found === null || !found.found) throw new Error('a route use answered values with no item');
  // Every key the vault decided on, an own value of the read: one archived between the two leaves nothing, and a key
  // named `toString` or `constructor` would otherwise read the object's prototype as its value (review r3 of #480).
  const missing = answered.keys.map((key) => key.key).filter((key) => !Object.hasOwn(read.values, key));
  if (missing.length > 0) throw new CoffreError(409, 'conflict', `${read.environment.path} holds no ${missing.join(', ')}, which ${found.item.name} needs`);
  return { values: read.values, plain: read.plain, keys: read.keys, item: found.item, seals: found.seals, reading: answered.reading, environment: { path: read.environment.path }, expiresAt };
}

/** A refusal as a plugin throws it, its response kept to forward. */
async function workloadRefused(response: Response, limit: WorkloadRefused['limit'] = null): Promise<WorkloadRefused> {
  const body = (await response.clone().json()) as { error?: string; message?: string; reason?: string };
  return new WorkloadRefused(response.status, body.error ?? 'error', body.message ?? response.statusText, body.reason, response, limit);
}

/** Why a workload's request is refused, as `refuse` makes it: an `ApiError`'s answer. */
async function refusedWith(error: ApiError, headers: HeadersInit = {}): Promise<WorkloadRefused> {
  return workloadRefused(errorResponse(error, headers));
}

/**
 * Values a plugin opened, and which of them are plain, no secret; every key
 * the environment holds, the environment they came from, and when the
 * handle that opened them ends.
 */
/** A use's answer: `keys`, every key the environment holds, or with `only`, those of the asked ones it holds. */
export type Used = { values: Record<string, string>; plain: string[]; keys: string[]; environment: { path: string; personal: boolean }; expiresAt: string };

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const PREFIX = /^(\/[a-z0-9][a-z0-9._-]*)+$/;
/** What coffre answers itself, and no plugin may take. */
const COFFRE_PATHS = ['/api', '/auth', '/mcp', '/.well-known', '/livez', '/readyz'];

/** Whether `pathname` is `prefix` or under it. */
const under = (pathname: string, prefix: string) => pathname === prefix || pathname.startsWith(`${prefix}/`);

/** Check a deployment's plugins, failing on the first problem: a bad name, or paths two would answer. */
export function checkPlugins(plugins: readonly CoffrePlugin[]): readonly CoffrePlugin[] {
  const names = new Set<string>();
  const prefixes: string[] = [...COFFRE_PATHS];
  for (const plugin of plugins) {
    if (typeof plugin.name !== 'string' || !NAME.test(plugin.name)) throw new Error(`a plugin's name is lowercase letters, digits and dashes; got ${JSON.stringify(plugin.name)}`);
    if (names.has(plugin.name)) throw new Error(`two plugins are named ${plugin.name}`);
    names.add(plugin.name);
    if (plugin.routes === undefined) continue;
    const { prefix } = plugin.routes;
    if (!PREFIX.test(prefix)) throw new Error(`plugin ${plugin.name}: its prefix is a path such as /v1, without a trailing slash; got ${JSON.stringify(prefix)}`);
    const taken = prefixes.find((other) => under(prefix, other) || under(other, prefix));
    if (taken !== undefined) throw new Error(`plugin ${plugin.name}: ${prefix} overlaps ${taken}, which ${COFFRE_PATHS.includes(taken) ? 'coffre answers' : 'another plugin takes'}`);
    prefixes.push(prefix);
  }
  return plugins;
}

/** The plugin's answer to a request under its prefix; null when no plugin takes the path. */
export function pluginRoute(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> | null {
  const plugin = pluginFor(request, runtime);
  return plugin === undefined ? null : gated(runtime, plugin, (ui) => plugin.routes!.fetch(request, pluginContext(request, runtime, sourceIp, null, ui)));
}

/**
 * A plugin's route, behind the proxy's gate when the plugin is the credential proxy (proxy-gate.ts; T186 PR C): its
 * code's names reserved before its first request in this isolate, every request of it, `GET /use` and the plan among
 * them, and its WebSockets: nothing it serves or shows gets past it. A gate that fails answers the request itself.
 */
async function gated<T>(runtime: CoffreRuntime, plugin: CoffrePlugin, serve: (ui: boolean) => Promise<T>): Promise<T | Response> {
  const code = proxyCodeOf([plugin]);
  let ui = false;
  try {
    await gateProxy(runtime.vault, code);
    // Whether the vault serves UI items at all (`servesUi`): asked of the proxy alone, once per vault, kept settled.
    ui = code !== null && (await servesUi(runtime.vault));
  } catch (error) {
    // Not passed: 503, `deploying` or `unavailable` with Retry-After, the plugin never asked; the next request asks again.
    return errorResponse(error);
  }
  return serve(ui);
}

/**
 * Whether the vault decides UI items (`useRoute`, `proxyItem`): only on 0.15's uses, its log and the hot path's login.
 * A vault of 0.14's log, a deployment's supported mode, holds no proxy definitions and throws on either call; the proxy
 * is then given neither, and serves code's items as ever (review r5 of #467).
 *
 *   log '0.15', hotDatabase set    useRoute, proxyItem given: the plan asks the place's UI items
 *   log '0.14'                     neither: `GET /use/market/dev` is code's plan, no vault call for UI items
 */
async function servesUi(vault: Vault): Promise<boolean> {
  return vault.useRoute !== undefined && vault.proxyItem !== undefined && (await uses015(vault));
}

/**
 * A plugin's answer to a call another Worker of the account made through a
 * Cloudflare service binding (docs/design/workload-access.md, section 9.2),
 * as the service `principal` its binding's `props` name, `token:<name>`;
 * null when no plugin takes the path. Its context's `workload` answers from
 * the service's `cloudflare` binding (`workloadFromBinding`), and takes no
 * session or handle: nothing but coffre's own entrypoint names the
 * principal, and no plugin can ask for one.
 */
export function bindingRoute(request: Request, runtime: CoffreRuntime, principal: string): Promise<Response> | null {
  const plugin = pluginFor(request, runtime);
  return plugin === undefined ? null : gated(runtime, plugin, (ui) => plugin.routes!.fetch(request, pluginContext(request, runtime, null, principal, ui)));
}

/**
 * A Cloudflare call's caller (section 9.2): the service's oldest live
 * binding of profile `cloudflare`, its MAC, revocation and tombstone, its
 * member's generation, and the freezes of the instance, the service, the
 * binding and the credential it uses, in one statement; then the gate's
 * counts, with no proof. The same `WorkloadUse` a session's request makes,
 * `credentialId` `binding:<id>`, so the proxy sees one kind of caller.
 * Throws `WorkloadRefused`.
 */
export function workloadFromBinding(runtime: CoffreRuntime, principal: string, at: WorkloadAsk): Promise<WorkloadUse> {
  return bindingWorkload(runtime, principal, at, new WeakMap());
}

/** What a workload's request asks, as the checks take it: a plugin's `WorkloadAt`, its counts made for the caller (`GateCounts`). */
type WorkloadAsk = Omit<WorkloadAt, 'counts'> & { counts?: GateCounts };

async function bindingWorkload(runtime: CoffreRuntime, principal: string, at: WorkloadAsk, standings: Standings): Promise<WorkloadUse> {
  const workloads = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads : null;
  const unbound = () => refusedWith(new ApiError('unauthenticated', `no live cloudflare binding of ${principal} takes this call`));
  if (workloads === null || !/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(principal)) throw await unbound();
  const named = at.place === null ? null : namedPlace(at.place);
  if ((at.place !== null && named === null) || (at.credential !== null && !CREDENTIAL_NAME.test(at.credential))) {
    throw await refusedWith(new ApiError('bad_request', 'an environment is named by its ID or its path, and a credential by its name in the configuration'));
  }
  let rows: Awaited<ReturnType<typeof callBindings>>;
  try {
    rows = await callBindings(runtime.db, principal, { place: named, credential: at.credential });
  } catch (error) {
    console.error('checking a cloudflare binding failed', logged(error));
    throw await refusedWith(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
  const found = rows.find((row) => !row.tombstoned && row.binding.policy !== null && row.memberStatus === 'active'
    && row.memberGeneration === row.binding.generation && checkAuthRow(runtime.chainKey, 'service_bindings', row.binding));
  if (found === undefined) throw await unbound();
  const { binding } = found;
  const policy = JSON.parse(binding.policy!) as BindingPolicy;
  if (workloads.noReads && policy.reads !== undefined) {
    throw await refusedWith(new ApiError('forbidden', 'this instance lets no binding list reads (noReads): bind the workload again without them', 'no_reads'));
  }
  // The place it names, as the statement found it.
  const asked = at.place === null ? null : found.place;
  if (at.place !== null && asked === null) throw await refusedWith(new ApiError('not_found', `${at.place} names no environment`));
  // Where it reaches, by ID: its scope's environments, or a project's, read only when it names one.
  const scope = readScope(binding.scope) ?? [];
  const reached = scope.every((grant) => grant.environmentId !== null)
    ? [...new Set(scope.map((grant) => grant.environmentId!))]
    : environmentsOf(scope, await placeRows(runtime.db)).map((environment) => environment.id);
  const place = asked ?? (reached.length === 1 ? reached[0]! : null);
  // Its path: the statement's for a place named, else the one it reaches, read by its ID.
  const path = asked !== null ? found.placePath : place === null ? null : ((await environmentPaths(runtime.db, [place])).get(place) ?? null);
  // The URL's other reading (`WorkloadAt.or`): the environment it reaches is the one the URL names, or there is not one.
  if (at.or !== undefined && at.place === null && (place === null || path === at.or.place)) {
    const { or, ...rest } = at;
    return bindingWorkload(runtime, principal, { ...rest, place: or.place, credential: or.credential }, standings);
  }
  if (at.credential !== null && place === null) {
    throw await refusedWith(new ApiError('bad_request', 'name the environment it uses, /use/<project>/<environment>/<credential>: this service reaches none, or several'));
  }
  // The credential's freeze, when the call named no environment and the statement could not know which.
  const frozen = found.frozen.instance || found.frozen.service || found.frozen.binding || found.frozen.credential
    || (asked === null && place !== null && at.credential !== null && (await frozenTargets(runtime.db, [`credential:${place}/${at.credential}`])).length > 0);
  if (frozen) throw await refusedWith(new ApiError('forbidden', 'frozen: a manager stopped this use; nothing passes until they lift it', 'frozen'));
  const counts = typeof at.counts === 'function' ? await at.counts({ service: principal, place, name: at.credential, credential: binding.id, way: 'binding' }) : at.counts;
  if (counts !== undefined && counts.length > 0) {
    let admitted;
    try {
      admitted = await gateOf(runtime, principal).admit({ counts });
    } catch (error) {
      if (error instanceof SessionRefused) throw await workloadRefused(error.response);
      console.error('the workload gate failed', logged(error));
      throw await refusedWith(new ApiError('unavailable', 'coffre cannot count this call right now'));
    }
    if (!admitted.ok) {
      if (admitted.reason === 'limit') {
        const limit = { key: admitted.key, retryAfterMs: admitted.retryAfterMs, first: admitted.first };
        if (admitted.first) await raiseAlert(runtime, limitAlert({ principal, bindingId: binding.id, session: null, sourceIp: null }, admitted), { credential: at.credential, count: admitted.key, retryAfterMs: admitted.retryAfterMs }, place);
        throw await workloadRefused(errorResponse(new ApiError('too_many_requests', `past this workload's limit for ${admitted.key}`, 'limit'), { 'retry-after': String(Math.ceil(admitted.retryAfterMs / 1000)) }), limit);
      }
      throw await refusedWith(new ApiError('too_many_requests', 'this workload sends more calls than its gate takes: try again shortly', 'overloaded'), { 'retry-after': '1' });
    }
  }
  const caller: WorkloadUse = {
    kind: 'workload',
    principal,
    credentialId: `binding:${binding.id}`,
    bindingId: binding.id,
    profile: 'cloudflare',
    constraints: null,
    hdr: null,
    sourceIp: null,
    nonce: null,
    places: reached,
    place,
    path,
  };
  standings.set(caller, { kind: 'binding', binding, policy, policySeq: found.policySeq === null ? null : BigInt(found.policySeq), credential: at.credential });
  return caller;
}

/** A workload's session for a plugin's request (`PluginContext.workload`), as `standingSession` checks it. */
async function sessionWorkload(request: Request, runtime: CoffreRuntime, sourceIp: string | null, at: WorkloadAsk, standings: Standings): Promise<WorkloadUse | null> {
  const token = dpopToken(request);
  if (token === null) return null;
  let session: StandingSession;
  // The fields a plugin may ask, each by name: nothing it adds reaches the checks (a `freezes`, say).
  const asking = (where: { place: string | null; credential: string | null; unless?: string }) => standingSession(request, runtime, token, sourceIp, {
    ...where,
    ...(at.body === undefined ? {} : { body: at.body }),
    ...(at.counts === undefined ? {} : { counts: at.counts }),
    children: true,
  });
  let credential = at.credential;
  try {
    try {
      session = await asking(at.or === undefined || at.place !== null ? { place: at.place, credential: at.credential } : { place: null, credential: at.credential, unless: at.or.place });
    } catch (error) {
      // The URL's other reading (`WorkloadAt.or`), refused before its gate: asked again by that one.
      if (!(error instanceof OtherReading) || at.or === undefined) throw error;
      credential = at.or.credential;
      session = await asking({ place: at.or.place, credential });
    }
  } catch (error) {
    if (error instanceof SessionRefused) throw await workloadRefused(error.response, error.limit);
    throw error;
  }
  const caller: WorkloadUse = { ...session.caller, nonce: session.nonce, places: session.places, place: session.place, path: session.path };
  standings.set(caller, { kind: 'session', session, credential });
  return caller;
}

/**
 * Whether a caller `workload` made still stands (`PluginContext.recheck`):
 * a session's statement again, every clause but the proof and the gate; a
 * Cloudflare call's binding, as `workloadFromBinding` holds it.
 */
async function rechecked(runtime: CoffreRuntime, caller: WorkloadUse, standings: Standings): Promise<boolean> {
  const standing = standings.get(caller);
  if (standing === undefined) return false;
  if (standing.kind === 'session') return sessionStands(runtime, standing.session, { place: caller.place, credential: standing.credential, children: true });
  return bindingWorkload(runtime, caller.principal, { place: caller.place, credential: standing.credential }, new WeakMap()).then(
    (again) => again.bindingId === caller.bindingId,
    (error: unknown) => {
      if (error instanceof WorkloadRefused) return false;
      throw error;
    },
  );
}

/**
 * The identity a workload caller reads as, through the API's read: the
 * vault's answer about its service, once, and the scope it holds, each
 * grant with its binding's `reads` (`sessionScope`). Null for a caller
 * coffre did not make.
 */
async function workloadIdentity(
  runtime: CoffreRuntime,
  caller: WorkloadUse,
  sourceIp: string | null,
  standings: Standings,
  /** Its read may decide on the vault's answer kept from an earlier request, which the vault checks (`accessFor`). */
  recall = false,
  /** The vault's answer about its service in the call that used the values (a route use's `standing`): nothing asked. */
  given?: Access,
): Promise<{ identity: AuthenticatedIdentity; expiresAt: string; constraints: Constraints | null } | null> {
  const standing = standings.get(caller);
  if (standing === undefined) return null;
  const { row, binding, policy, policySeq } = standing.kind === 'session' ? standing.session : { ...standing, row: null };
  const scope: CredentialScope = sessionScope(row ?? { scope: null }, binding, policy);
  const generation = row?.generation ?? binding.generation;
  const { access, recalled } = given !== undefined ? { access: given, recalled: null } : await accessFor(runtime, caller.principal, recall && { generation });
  const id = caller.principal.slice('token:'.length);
  const callerOf = withRecalled(callerFrom({ type: 'service', id }, access, policySeq, scope, 'workload'), recalled);
  if (callerOf.generation !== generation) return null;
  return {
    constraints: standing.kind === 'session' ? standing.session.caller.constraints : null,
    expiresAt: (row?.expiresAt ?? new Date(Date.now() + 60_000)).toISOString(),
    identity: {
      principal: { type: 'service', id, commonName: id },
      registered: callerOf.registered,
      caller: callerOf,
      requestId: crypto.randomUUID(),
      sourceIp,
      // A binding's call has no credentials row: its entries name the binding, `binding:<id>`, and its fence checks the binding.
      credentialId: standing.kind === 'session' ? caller.credentialId : null,
      bindingId: standing.kind === 'binding' ? binding.id : null,
      credentialExpiresAt: row?.expiresAt.toISOString() ?? null,
      passkeyId: null,
      provenance: caller.credentialId,
      personalToken: null,
      handlePlaces: null,
      via: null,
      workload: standing.kind === 'session' ? standing.session : null,
    },
  };
}

/** A plugin's answer to a WebSocket asked for under its prefix; null when no plugin takes it. */
export function pluginSocket(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response | SocketSession> | null {
  const plugin = pluginFor(request, runtime);
  const socket = plugin?.routes?.socket;
  return socket === undefined ? null : gated(runtime, plugin!, (ui) => socket(request, pluginContext(request, runtime, sourceIp, null, ui)));
}

/** Whether a plugin takes WebSockets at `request`'s path, deciding nothing about the request itself. */
export function takesSocket(request: Request, plugins: readonly CoffrePlugin[]): boolean {
  return pluginFor(request, { plugins })?.routes?.socket !== undefined;
}

/** A use's path, `market/dev`, as `use` parses it; undefined for one it would refuse. */
function parsedPlace(path: string): Path | undefined {
  try {
    return parsePath(path, [2]);
  } catch {
    return undefined;
  }
}

function pluginFor(request: Request, runtime: Pick<CoffreRuntime, 'plugins'>): CoffrePlugin | undefined {
  const { pathname } = new URL(request.url);
  return runtime.plugins.find((plugin) => plugin.routes !== undefined && under(pathname, plugin.routes.prefix));
}

function pluginContext(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  binding: string | null = null,
  ui = false,
): PluginContext {
  // The token where the API looks for it in this instance's mode: a header either way, so never ambient.
  const carrying = (token: string): Record<string, string> => (runtime.auth.mode === 'cloudflare' ? { [ACCESS_JWT_HEADER]: token } : { authorization: `Bearer ${token}` });
  // One of coffre's own routes outside the API's, in process: its answer, or its refusal as the client throws one.
  const answer = async (response: Response): Promise<unknown> => {
    const body = (await response.json()) as { error?: string; message?: string; reason?: string };
    if (!response.ok) throw new CoffreError(response.status, body.error ?? 'error', body.message ?? response.statusText, body.reason);
    return body;
  };
  const proxyHandle = async (handle: string, recall = false, ahead?: CredentialRead | null): Promise<AuthenticatedIdentity> => {
    // A call through a service binding is its service's alone: it carries no handle, token or session.
    if (binding !== null) throw new CoffreError(403, 'forbidden', 'a call through a service binding is its service\'s, and takes no other credential', 'binding');
    const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), handle, sourceIp, { handle: true, recall, ...(ahead === undefined ? {} : { ahead }) });
    if (identity instanceof Response) await answer(identity);
    return identity as AuthenticatedIdentity;
  };
  /**
   * With 0.15's uses, what a handle's read reads before anything else, in one call (db/read-ahead.ts): its
   * credential, and, for `path`, the place and the `keys` it names. Null without them, and each is read as ever.
   */
  const readFor = async (handle: string, path?: string, keys?: UseAsked['keys']): Promise<ReadAhead | null> => {
    // No read for what is no handle: a request with anything else is refused on its kind alone.
    if (binding !== null || tokenKind(handle) !== 'handle' || !(await uses015(runtime.vault))) return null;
    try {
      // A path that names no environment reads none ahead: the handle is checked before the read refuses it.
      const named = path === undefined ? undefined : parsedPlace(path);
      const place = named?.environment === undefined ? undefined : { project: named.project, environment: named.environment };
      return await readAhead(runtime.db, { tokenHash: hashToken(handle), path: place, keys: Array.isArray(keys) ? keys : undefined });
    } catch (error) {
      // As a credential's own read that fails (`authenticateRequest`): an outage, not a refusal.
      console.error('checking a credential failed', { error: logged(error) });
      throw new CoffreError(503, 'unavailable', 'coffre cannot check who you are right now');
    }
  };
  /**
   * 0.15's use by name, the vault's one call (`useByName`): a handle's one key, or none (`key` null: its standing at the
   * place alone). Null where the vault serves none so: the use goes as ever.
   */
  const namedFor = async (handle: string, place: { project: string; environment: string } | null, key: string | null, purpose: 'use' | 'expose' = 'use', unless?: readonly string[]) => {
    if (binding !== null) return null;
    const others = unless?.flatMap((path) => {
      const [project, environment] = path.split('/');
      return project === undefined || environment === undefined ? [] : [{ project, environment }];
    });
    const used = await useByName(runtime, request, sourceIp, handle, { kinds: ['handle'], place, key, purpose, ...(others === undefined ? {} : { unless: others }) });
    if (used === null) return null;
    if (used.identity instanceof Response) await answer(used.identity);
    return { ...used, identity: used.identity as AuthenticatedIdentity };
  };
  /** An API error, as a plugin sees it. */
  const rethrown = (error: unknown): never => {
    if (!(error instanceof ApiError)) throw error;
    throw new CoffreError(error.status, error.code, error.message, error.reason, error.retryAfter);
  };
  /**
   * A handle's use of one key by name (`namedFor`), and the read on what it answered; null where the vault serves none
   * so. `asked.path` null: at the environment the handle was made for, unless it is one of `unless`.
   */
  const byName = async (handle: string, asked: Omit<UseAsked, 'path'> & { path: string | null }, unless?: readonly string[]) => {
    let place: { project: string; environment: string } | null = null;
    if (asked.path !== null) {
      const named = parsedPlace(asked.path);
      // A fork, and `dev@me`, its caller's personal config of dev or dev, by name too (T165).
      if (named?.environment === undefined) return null;
      place = { project: named.project, environment: named.environment };
    }
    try {
      const used = await namedFor(handle, place, (asked.keys as readonly string[])[0]!, asked.purpose === 'expose' ? 'expose' : 'use', unless);
      if (used === null || used.place === null) return null;
      const read = await reveal(apiContext(runtime, used.identity), { project: used.place.project, environment: used.place.environment }, {
        purpose: asked.purpose, keys: asked.keys, logged: asked.logged, only: true, decided: used.decided, ...(used.ahead == null ? {} : { ahead: used.ahead }),
      });
      return { values: read.values, plain: read.plain, keys: read.keys, environment: { path: read.environment.path, personal: read.environment.personal }, expiresAt: used.identity.credentialExpiresAt! };
    } catch (error) {
      return rethrown(error);
    }
  };
  /**
   * A handle's use of several keys by name, the vault's one call (`useManyByName`, T165), and the read on what it
   * answered; null where the vault serves none so. Its keys only (`UseAsked.only`), each once.
   */
  const byNameMany = async (handle: string, asked: UseAsked & { keys: readonly string[] }) => {
    if (binding !== null) return null;
    const named = parsedPlace(asked.path);
    // A fork, and `dev@me`, its caller's personal config of dev or dev, by name too.
    if (named?.environment === undefined) return null;
    const place = { project: named.project, environment: named.environment };
    try {
      const used = await useManyByName(runtime, request, sourceIp, handle, {
        kinds: ['handle'], place, keys: [...new Set(asked.keys)], purpose: asked.purpose === 'expose' ? 'expose' : 'use', leavesSensitive: false,
      });
      if (used === null) return null;
      if (used.identity instanceof Response) await answer(used.identity);
      const identity = used.identity as AuthenticatedIdentity;
      const read = await reveal(apiContext(runtime, identity), place, {
        purpose: asked.purpose, keys: asked.keys, logged: asked.logged, only: true, decided: used.decided, ...(used.ahead == null ? {} : { ahead: used.ahead }),
      });
      return { values: read.values, plain: read.plain, keys: read.keys, environment: { path: read.environment.path, personal: read.environment.personal }, expiresAt: identity.credentialExpiresAt! };
    } catch (error) {
      return rethrown(error);
    }
  };
  const noCredential = () => new CoffreError(403, 'forbidden', 'a call through a service binding is its service\'s, and takes no other credential', 'binding');
  // The workload callers this request's context made: the only ones its `use` takes.
  const standings: Standings = new WeakMap();
  // One read for the proxy, as `use` asks it, on the caller's access recalled or asked for (`accessFor`).
  const use = async (handle: Parameters<PluginContext['use']>[0], asked: Parameters<PluginContext['use']>[1], recall: boolean) => {
    let recalled: Recalled | undefined;
    try {
      let caller: AuthenticatedIdentity;
      let ahead: ReadAhead | null | undefined;
      let expiresAt: string;
      // The credential `handle()` read, for this use alone, the one that follows it: any other use goes first, and it lapses.
      if (typeof handle === 'string') {
        ahead = await readFor(handle, asked.path, asked.only === true ? asked.keys : undefined);
        caller = await proxyHandle(handle, recall, ahead?.credential);
        if (!caller.registered) throw new ApiError('registration_required', 'the person this handle stands in for is no member here');
        expiresAt = caller.credentialExpiresAt!;
      } else {
        // A workload caller `workload` made for this request, and no other: one a plugin built itself is no one.
        const made = await workloadIdentity(runtime, handle, sourceIp, standings, recall);
        if (made === null || !made.identity.registered) throw new ApiError('unauthenticated', 'that workload is no caller coffre authenticated');
        // A `narrow` child never reads (section 8.4): it uses, and is handed nothing back. Decided on what coffre kept, not on what the plugin holds.
        if (made.constraints !== null && asked.purpose !== 'use') throw new ApiError('forbidden', 'a narrowed session uses values, and reads none', 'narrowed');
        ({ identity: caller, expiresAt } = made);
      }
      recalled = caller.caller.recalled;
      // A workload uses the environment its statement checked, freezes and all: a path renamed onto another since reads nothing.
      const place = typeof handle !== 'string' && handle.place !== null ? { environmentId: handle.place } : {};
      const read = await reveal(apiContext(runtime, caller), parsePath(asked.path, [2]), { purpose: asked.purpose, keys: asked.keys, logged: asked.logged, only: asked.only === true, ...place, ...(ahead == null ? {} : { ahead }) });
      return { values: read.values, plain: read.plain, keys: read.keys, environment: { path: read.environment.path, personal: read.environment.personal }, expiresAt };
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      // Nothing goes back on a kept answer the vault has not vouched for this request, a refusal included (`fetchApi`).
      await recalled?.confirm();
      throw new CoffreError(error.status, error.code, error.message, error.reason, error.retryAfter);
    }
  };
  /** The route the vault's reading looked up: `/use/openai/models/gpt`'s stable reading is `openai`, never `gpt`. */
  const readName = (answered: Extract<RouteUseOutcome, { route: 'name' }>, asked: RouteAsked): string => (answered.reading === 'named' ? asked.named?.route : asked.stable) ?? '';
  /**
   * A UI route's answer refused before any value is opened: a personal config, no such item or one a writer changed,
   * or a key its editor no longer routes (`route_not_cleared`, decision 5: 403 naming who must save again, as the
   * caller may read the key and only the route may not send it). Null otherwise: allowed, or refused by the caller's
   * own standing, which the read answers as every read does (D153). `name` is the route the vault's reading looked up.
   */
  const routeRefusal = (answered: Extract<RouteUseOutcome, { route: 'name' }>, asked: RouteAsked): CoffreError | null => {
    const name = readName(answered, asked);
    if (answered.personal) {
      return new CoffreError(409, 'conflict', `${name} is defined in the UI, and a personal config serves no UI definition: name its environment${answered.place === null ? '' : `, ${answered.place.project}/${answered.place.environment.replace(/@me$/, '')}`}`, 'route_not_personal');
    }
    if (!answered.stands || answered.found === null) return null;
    const missing = foundRefusal(answered.found, name);
    if (missing !== null) return missing;
    const { outcome } = answered;
    if (!outcome.ok && 'code' in outcome && outcome.code === 'route_not_cleared') {
      return new CoffreError(403, 'forbidden', `${name} is defined in the UI, and ${outcome.why ?? 'its editor no longer holds a key it sends'}: someone who reads its keys saves it again`, 'route_not_cleared');
    }
    return null;
  };
  /**
   * A handle's UI route use: the vault's call, the read on what it decided, and the item the values go by; null where
   * the vault took the place reading of no route (`route` null: the place itself, C2b4), nothing used.
   */
  const handleRouteUse = async (handle: string, asked: RouteAsked, place: { path: string; route: null } | null = null): Promise<RouteUsed | null> => {
    const reading = place ?? asked.named;
    const name = asked.named?.route ?? asked.stable ?? '';
    const named = reading === null ? null : (() => {
      const [project, environment] = reading.path.split('/');
      return { place: { project: project!, environment: environment! }, route: reading.route };
    })();
    try {
      if (binding !== null) throw noCredential();
      const used = await useRouteByName(runtime, request, sourceIp, handle, { named, stable: asked.stable, digests: asked.digests });
      if (used === null) throw new CoffreError(409, 'conflict', `this handle stands in for several environments, or none, and the stable URL is for a run of one: name it, ${runtime.publicUrl}/use/<project>/<environment>/${name}`, 'no_environment');
      if (used.identity instanceof Response) await answer(used.identity);
      const identity = used.identity as AuthenticatedIdentity;
      if (used.credential) throw new CoffreError(401, 'unauthenticated', 'that handle is unknown, expired or revoked');
      const { answered } = used;
      // The place itself: the URL is the place's (the plan, compute, code's credential), which serves it as it says.
      if (answered.reading === 'named' && place !== null) return null;
      const refused = routeRefusal(answered, asked);
      if (refused !== null) throw refused;
      if (answered.place === null) throw new CoffreError(404, 'not_found', `${name}: no such place`);
      // Only an allowed use's item is asked: a refusal of the caller's own (a key they may not use, busy, the bulk limit)
      // is the read's to answer, as every read's is, whatever kind the item is (review r10 of #467).
      const unserved = answered.found?.found === true && answered.outcome.ok ? asked.refuses?.(answered.found.item) ?? null : null;
      if (unserved !== null) throw unservedError(unserved);
      const read = await reveal(apiContext(runtime, identity), answered.place, {
        purpose: 'use', keys: answered.keys.map((key) => key.key), logged: { ...(await loggedOf(answered, asked)), credential: readName(answered, asked) }, only: true, decided: used.decided, ...(used.ahead == null ? {} : { ahead: used.ahead }),
      });
      return routeUsed(answered, read, identity.credentialExpiresAt!);
    } catch (error) {
      return rethrown(error);
    }
  };
  /**
   * A workload caller as the vault's route use names it (`RouteCaller`): its session's credential, or its Cloudflare
   * binding, at the place its statement checked, by ID. Only one this context's `workload` made, as `use` takes.
   */
  const workloadCaller = (caller: WorkloadUse): RouteCaller => {
    const standing = standings.get(caller);
    if (standing === undefined) throw new CoffreError(401, 'unauthenticated', 'that workload is no caller coffre authenticated');
    if (caller.place === null) throw new CoffreError(409, 'conflict', 'the environment this session reaches is gone, or it reaches several: name it, /use/<project>/<environment>/<credential>');
    return standing.kind === 'binding'
      ? { kind: 'workload', credential: standing.binding.id, way: 'binding', place: caller.place }
      : { kind: 'workload', credential: caller.credentialId, place: caller.place };
  };
  /**
   * A workload's UI route use (C2b; docs/design/proxy-ui.md, section 3, "Workloads"): the vault's one call decides the
   * route at the place its statement checked, the workload's standing there with it (`standing`), so the read asks the
   * vault nothing more; the read is at that place by ID, as every workload's use is (a path renamed onto another since
   * reads nothing).
   */
  const workloadRouteUse = async (caller: WorkloadUse, asked: RouteAsked): Promise<RouteUsed> => {
    try {
      if (asked.named !== null || asked.stable === null) throw new Error("a workload's route use names its route as stable, at its place");
      const at = Date.now();
      const answered = await runtime.vault.useRoute({ caller: workloadCaller(caller), named: null, stable: asked.stable, digests: asked.digests, purpose: 'use', at, deadline: at + USE_DEADLINE_MS });
      if (!answered.served) throw new CoffreError(404, 'not_found', `${asked.stable}: the environment this workload uses is gone`);
      if (answered.route !== 'name') throw refusedUse(answered.outcome);
      const refused = routeRefusal(answered, asked);
      if (refused !== null) throw refused;
      const unserved = answered.found?.found === true && answered.outcome.ok ? asked.refuses?.(answered.found.item) ?? null : null;
      if (unserved !== null) throw unservedError(unserved);
      const made = await workloadIdentity(runtime, caller, sourceIp, standings, false, answered.standing);
      if (made === null || !made.identity.registered) throw new ApiError('unauthenticated', 'that workload is no caller coffre authenticated');
      const ahead = namedManyAhead(runtime.db, answered.app, answered.stands ? answered.keys : null, { personal: false });
      const read = await reveal(apiContext(runtime, made.identity), parsePath(caller.path!, [2]), {
        purpose: 'use', keys: answered.keys.map((key) => key.key), logged: { ...(await loggedOf(answered, asked)), credential: asked.stable }, only: true, environmentId: caller.place!,
        decided: { keys: answered.keys, stands: answered.stands, outcome: answered.outcome, at: answered.at }, ...(ahead == null ? {} : { ahead }),
      });
      return routeUsed(answered, read, made.expiresAt);
    } catch (error) {
      return rethrown(error);
    }
  };
  const routeUse: PluginContext['useRoute'] & {} = async (caller, asked) => {
    if (typeof caller !== 'string') return workloadRouteUse(caller, asked);
    const used = await handleRouteUse(caller, asked);
    if (used === null) throw new Error('a route use of a route answered the place');
    return used;
  };
  const routeOrPlace: PluginContext['useRouteOrPlace'] & {} = (handle, asked) => handleRouteUse(handle, { ...asked, named: null }, { path: asked.place, route: null });
  /** `proxyItem`'s call as `caller`, refused as a use is. */
  const itemsAs = async (caller: RouteCaller, place: { project: string; environment: string } | null, name: string | null): Promise<ItemsFound> => {
    const at = Date.now();
    const found = await runtime.vault.proxyItem({ caller, place, name, at, deadline: at + USE_DEADLINE_MS });
    if (!found.ok && 'busy' in found && found.busy !== undefined) throw refusedUse(found as never);
    if (!found.ok) {
      const code = (found as { code: string }).code;
      if (code === 'credential') throw new CoffreError(401, 'unauthenticated', 'that credential is unknown, expired or revoked');
      throw refusedUse({ ok: false, code: code as never, number: null });
    }
    return { fault: found.fault, personal: found.personal, item: found.item, items: found.items };
  };
  const proxyItem: PluginContext['proxyItem'] & {} = async (caller, asked) => {
    try {
      if (typeof caller !== 'string') {
        if (asked.place !== null) throw new Error("a workload's items are at the place its statement checked");
        return await itemsAs(workloadCaller(caller), null, asked.name);
      }
      if (binding !== null) throw noCredential();
      if (tokenKind(caller) !== 'handle') throw new CoffreError(401, 'unauthenticated', 'send the handle `coffre run` gave your app');
      const place = asked.place === null ? null : (() => {
        const [project, environment] = asked.place.split('/');
        return { project: project!, environment: environment! };
      })();
      return await itemsAs({ kind: 'handle', tokenHash: hashToken(caller).toString('base64'), accepts: acceptance(runtime) }, place, asked.name);
    } catch (error) {
      return rethrown(error);
    }
  };
  /**
   * A plugin's counts as the checks make them (`GateCounts`): a function's, with `item` asking the vault, as the caller
   * the statement found, for its place's UI item. No UI item without `servesUi`.
   */
  const counted = (counts: PluginCounts | undefined): GateCounts | undefined => {
    if (typeof counts !== 'function') return counts;
    return (made: CountsAt) => counts({
      service: made.service,
      place: made.place,
      credential: made.name,
      item: async (name) => {
        try {
          if (!ui || made.place === null) throw new CoffreError(404, 'not_found', `${name}: this instance serves no item defined in the UI here`);
          return await itemsAs({ kind: 'workload', credential: made.credential, ...(made.way === undefined ? {} : { way: made.way }), place: made.place }, null, name);
        } catch (error) {
          return rethrown(error);
        }
      },
    });
  };
  return {
    // A vault that decides no UI item (`servesUi`): neither, and the proxy serves code's items alone.
    ...(ui ? { useRoute: routeUse, useRouteOrPlace: routeOrPlace, proxyItem } : {}),
    publicUrl: runtime.publicUrl,
    binding: binding !== null,
    ...(runtime.publicFetch === undefined ? {} : { publicFetch: runtime.publicFetch }),
    ...(runtime.publicConnect === undefined ? {} : { publicConnect: runtime.publicConnect }),
    workload: (asked, at) => {
      const { counts, ...rest } = at;
      const checked: WorkloadAsk = { ...rest, ...(counts === undefined ? {} : { counts: counted(counts)! }) };
      return binding === null ? sessionWorkload(asked, runtime, sourceIp, checked, standings) : bindingWorkload(runtime, binding, checked, standings);
    },
    recheck: (caller) => rechecked(runtime, caller, standings),
    handle: async (handle) => {
      // A handle of one environment: its person's standing there, decided by the vault's one named call on the sealed
      // rows, nothing asked of `access` (T145). Refused, it names no environment.
      const standing = await namedFor(handle, null, null).catch(rethrown);
      if (standing !== null) {
        // Whether the handle stands, and where: what its person may do there is the use's to decide, and to log (review r1).
        const { credentialExpiresAt, handlePlaces: places } = standing.identity;
        if (places === null) return { expiresAt: credentialExpiresAt!, paths: null };
        const place = standing.ahead?.place;
        const live = (slug: string) => !slug.includes('~');
        const paths = place != null && place.environment !== null
          ? [live(place.project.slug) && live(place.environment.slug) ? `${place.project.slug}/${place.environment.slug}` : null]
          : await (async () => {
            const found = await environmentPaths(runtime.db, places.map((one) => one.environmentId));
            return places.map(({ environmentId, personal }) => (found.has(environmentId) ? `${found.get(environmentId)}${personal ? '@me' : ''}` : null));
          })();
        return { expiresAt: credentialExpiresAt!, paths };
      }
      // Asking the vault about the person, as ever; with 0.15's uses, its credential read ahead. A use that follows reads
      // it again, with its place and keys, in the one call it makes anyway, and decides on the answer kept here.
      const identity = await proxyHandle(handle, false, (await readFor(handle))?.credential);
      const { credentialExpiresAt, handlePlaces: places } = identity;
      if (places === null) return { expiresAt: credentialExpiresAt!, paths: null };
      const named = await environmentPaths(runtime.db, places.map((place) => place.environmentId));
      const paths = places.map(({ environmentId, personal }) => (named.has(environmentId) ? `${named.get(environmentId)}${personal ? '@me' : ''}` : null));
      return { expiresAt: credentialExpiresAt!, paths };
    },
    exchange: async (asked) => {
      if (binding !== null) throw noCredential();
      return (await answer(await exchangeWorkloadToken(request, runtime, sourceIp, asked))) as { token: string; expiresAt: string };
    },
    signOut: async (token) => {
      if (binding !== null) throw noCredential();
      await answer(await logout(new Request(`${runtime.publicUrl}/api/auth/logout`, { method: 'POST', headers: carrying(token) }), runtime, sourceIp));
    },
    use: async (handle, asked) => {
      // One key, a handle's: the vault's one named call, which decides on the caller as it is (T145). Several, the same
      // call of all of them (T165). Keys the proxy chooses from what the read resolves (`PickKeys`), a workload's, or
      // anything the vault does not serve by name, as below.
      if (typeof handle === 'string' && asked.only === true && Array.isArray(asked.keys) && asked.keys.length > 0) {
        const keys = asked.keys as readonly string[];
        const used = new Set(keys).size === 1 ? await byName(handle, asked) : await byNameMany(handle, { ...asked, keys });
        if (used !== null) return used;
      }
      // On the vault's answer about the caller kept from an earlier request, which the vault checks as it opens the
      // values: one call. One that is not the vault's now read and logged nothing, and the read goes again, asking.
      try {
        return await use(handle, asked, true);
      } catch (error) {
        if (!(error instanceof AccessChanged)) throw error;
      }
      return use(handle, asked, false);
    },
    useMadeFor: (handle, asked) => byName(handle, { ...asked, path: null, only: true }, asked.unless),
    api: (token) => {
      if (binding !== null) throw noCredential();
      let checked: Promise<AuthenticatedIdentity | Response> | undefined;
      return createClient({
        url: runtime.publicUrl,
        headers: () => carrying(token),
        // In process, as a page's render calls it (`pageClient`): one check of the token for every call.
        transport: (inner) =>
          fetchApi(inner, runtime, {
            sourceIp,
            authenticate: async () => {
              checked ??= authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp);
              const identity = await checked;
              // A refusal's body is read once: each call answers with its own copy.
              return identity instanceof Response ? identity.clone() : identity;
            },
          }),
      });
    },
  };
}

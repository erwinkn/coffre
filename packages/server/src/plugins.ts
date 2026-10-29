// Plugins (docs/design/plugins.md): what a deployment adds to coffre in its
// configuration, `plugins: [vaultKv({ mount: 'secret' })]`. A plugin holds no
// authority of its own. It answers paths of its own, and reaches coffre only
// as whoever a request's credential names, through the API: the same route
// table, checks, vault and audit log as the CLI.
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import type { CredentialScope } from '@coffre/core/access';
import { ACCESS_JWT_HEADER, CREDENTIAL_NAME, hashToken, tokenKind, type BindingPolicy, type Constraints, type WorkloadCaller } from '@coffre/core/identity';
import { personalOf } from '@coffre/core/schemas';

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
import { readAhead, type ReadAhead } from './db/read-ahead.ts';
import { uses015 } from './api/changes.ts';
import { callBindings, frozenTargets } from './db/workloads.ts';
import { reveal, type PickKeys } from './api/secrets.ts';
import { fetchApi } from './fetch-api.ts';
import { useByName } from './named-use.ts';
import { errorResponse } from './http.ts';
import { limitAlert, raiseAlert } from './alerts.ts';
import { logged } from './logged.ts';
import { apiContext, type CoffreRuntime } from './runtime.ts';
import { dpopToken, gateOf, namedPlace, SessionRefused, sessionScope, sessionStands, standingSession, type GateCounts, type StandingSession } from './workload-sessions.ts';

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
};

/** What a workload's request uses (`PluginContext.workload`): where and which credential, the body line `req` signs, and the counts its limits take. */
export type WorkloadAt = {
  /** An environment's ID or its path, `market/prod`. */
  place: string | null;
  credential: string | null;
  /**
   * `bodyDigest(bytes)` of a buffered body, a sigv4 upload's declared
   * digest, or `UNSIGNED_BODY`, which only a binding that says
   * `unsignedUploads` takes: for a request whose proof signs its content.
   * Left out for one that signs none.
   */
  body?: string;
  /** The counts, or how to make them for the service, `token:<name>`, which only authentication tells (a limit per workload). */
  counts?: GateCounts;
};

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
  const routes = routesFor(request, runtime);
  return routes === undefined ? null : routes.fetch(request, pluginContext(request, runtime, sourceIp));
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
  const routes = routesFor(request, runtime);
  return routes === undefined ? null : routes.fetch(request, pluginContext(request, runtime, null, principal));
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
export function workloadFromBinding(runtime: CoffreRuntime, principal: string, at: WorkloadAt): Promise<WorkloadUse> {
  return bindingWorkload(runtime, principal, at, new WeakMap());
}

async function bindingWorkload(runtime: CoffreRuntime, principal: string, at: WorkloadAt, standings: Standings): Promise<WorkloadUse> {
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
  if (at.credential !== null && place === null) {
    throw await refusedWith(new ApiError('bad_request', 'name the environment it uses, /use/<project>/<environment>/<credential>: this service reaches none, or several'));
  }
  // The credential's freeze, when the call named no environment and the statement could not know which.
  const frozen = found.frozen.instance || found.frozen.service || found.frozen.binding || found.frozen.credential
    || (asked === null && place !== null && at.credential !== null && (await frozenTargets(runtime.db, [`credential:${place}/${at.credential}`])).length > 0);
  if (frozen) throw await refusedWith(new ApiError('forbidden', 'frozen: a manager stopped this use; nothing passes until they lift it', 'frozen'));
  const counts = typeof at.counts === 'function' ? at.counts(principal) : at.counts;
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
async function sessionWorkload(request: Request, runtime: CoffreRuntime, sourceIp: string | null, at: WorkloadAt, standings: Standings): Promise<WorkloadUse | null> {
  const token = dpopToken(request);
  if (token === null) return null;
  let session: StandingSession;
  try {
    // The fields a plugin may ask, each by name: nothing it adds reaches the checks (a `freezes`, say).
    session = await standingSession(request, runtime, token, sourceIp, {
      place: at.place,
      credential: at.credential,
      ...(at.body === undefined ? {} : { body: at.body }),
      ...(at.counts === undefined ? {} : { counts: at.counts }),
      children: true,
    });
  } catch (error) {
    if (error instanceof SessionRefused) throw await workloadRefused(error.response, error.limit);
    throw error;
  }
  const caller: WorkloadUse = { ...session.caller, nonce: session.nonce, places: session.places, place: session.place, path: session.path };
  standings.set(caller, { kind: 'session', session, credential: at.credential });
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
): Promise<{ identity: AuthenticatedIdentity; expiresAt: string; constraints: Constraints | null } | null> {
  const standing = standings.get(caller);
  if (standing === undefined) return null;
  const { row, binding, policy, policySeq } = standing.kind === 'session' ? standing.session : { ...standing, row: null };
  const scope: CredentialScope = sessionScope(row ?? { scope: null }, binding, policy);
  const generation = row?.generation ?? binding.generation;
  const { access, recalled } = await accessFor(runtime, caller.principal, recall && { generation });
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
  const routes = routesFor(request, runtime);
  return routes?.socket === undefined ? null : routes.socket(request, pluginContext(request, runtime, sourceIp));
}

/** Whether a plugin takes WebSockets at `request`'s path, deciding nothing about the request itself. */
export function takesSocket(request: Request, plugins: readonly CoffrePlugin[]): boolean {
  return routesFor(request, { plugins })?.socket !== undefined;
}

/** A use's path, `market/dev`, as `use` parses it; undefined for one it would refuse. */
function parsedPlace(path: string): Path | undefined {
  try {
    return parsePath(path, [2]);
  } catch {
    return undefined;
  }
}

function routesFor(request: Request, runtime: Pick<CoffreRuntime, 'plugins'>) {
  const { pathname } = new URL(request.url);
  return runtime.plugins.find((plugin) => plugin.routes !== undefined && under(pathname, plugin.routes.prefix))?.routes;
}

function pluginContext(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  binding: string | null = null,
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
      // A personal config (`dev@me`) is read by its owner: as ever.
      if (named?.environment === undefined || personalOf(named.environment) !== null) return null;
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
  return {
    publicUrl: runtime.publicUrl,
    workload: (asked, at) => (binding === null ? sessionWorkload(asked, runtime, sourceIp, at, standings) : bindingWorkload(runtime, binding, at, standings)),
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
      // One key, a handle's: the vault's one named call, which decides on the caller as it is (T145). Several, or anything
      // the vault does not serve by name, as below until PR B2.
      if (typeof handle === 'string' && asked.only === true && Array.isArray(asked.keys) && asked.keys.length === 1) {
        const used = await byName(handle, asked);
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

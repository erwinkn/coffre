// Plugins (docs/design/plugins.md): what a deployment adds to coffre in its
// configuration, `plugins: [vaultKv({ mount: 'secret' })]`. A plugin holds no
// authority of its own. It answers paths of its own, and reaches coffre only
// as whoever a request's credential names, through the API: the same route
// table, checks, vault and audit log as the CLI.
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import type { CredentialScope } from '@coffre/core/access';
import { ACCESS_JWT_HEADER, CREDENTIAL_NAME, type BindingPolicy, type Constraints, type GateCount, type WorkloadCaller } from '@coffre/core/identity';

import { authenticateRequest, type AuthenticatedIdentity } from './auth.ts';
import { exchangeWorkloadToken, logout } from './auth-routes.ts';
import { callerFrom } from './api/caller.ts';
import { ApiError } from './api/errors.ts';
import { parsePath } from './api/paths.ts';
import { readScope } from './api/services.ts';
import { environmentsOf } from './api/workloads.ts';
import { checkAuthRow } from './auth-rows.ts';
import { environmentPaths, places as placeRows, type BindingRow } from './db/queries.ts';
import { callBindings, frozenTargets } from './db/workloads.ts';
import { reveal, type PickKeys } from './api/secrets.ts';
import { fetchApi } from './fetch-api.ts';
import { errorResponse } from './http.ts';
import { logged } from './logged.ts';
import { apiContext, type CoffreRuntime } from './runtime.ts';
import { dpopToken, gateOf, SessionRefused, sessionScope, standingSession, UUID, type StandingSession } from './workload-sessions.ts';

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
   * `credential.use` entry of the app's, with `logged` in it. Only the keys
   * asked for, or chosen, those the environment holds; `environment` is the
   * one the read resolved to (`market/dev@me` may be a personal config). A
   * refusal throws a `CoffreError`. In place of a handle, the workload
   * `workload` returned for this request: its service's grants within its
   * scope, which reads only plain keys and those its binding lists
   * (docs/design/workload-access.md, section 6.1).
   */
  use(handle: string | WorkloadUse, asked: UseAsked): Promise<Used>;
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
   * `place` is an environment's ID; null with a `credential` means the one
   * environment the session reaches (`/use/<credential>`). A refusal throws
   * a `WorkloadRefused`, whose `response` is the answer to forward as it is.
   * What it returns is what `use` takes in place of a handle. Null for a
   * request that is no workload's, which carries no `Authorization: DPoP`:
   * a handle's, say.
   */
  workload(request: Request, at: WorkloadAt): Promise<WorkloadUse | null>;
};

/** What a workload's request uses (`PluginContext.workload`): where and which credential, the body line `req` signs, and the counts its limits take. */
export type WorkloadAt = {
  place: string | null;
  credential: string | null;
  /** `bodyDigest(bytes)` of a buffered body, a sigv4 upload's declared digest, or `UNSIGNED_BODY`: for a request coffre forwards, whose proof signs its content. Left out for one that signs none. */
  body?: string;
  counts?: readonly GateCount[];
};

/**
 * A workload, authenticated for one request: the caller the proxy sees, the
 * gate's nonce to send back (`DPoP-Nonce`; null for a Cloudflare call), the
 * environments it reaches by ID, and the one this request uses.
 */
export type WorkloadUse = WorkloadCaller & { readonly nonce: string | null; readonly places: readonly string[]; readonly place: string | null };

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
type Standing = { kind: 'session'; session: StandingSession } | { kind: 'binding'; binding: BindingRow; policy: BindingPolicy; policySeq: bigint | null };
type Standings = WeakMap<WorkloadUse, Standing>;

/**
 * What a plugin opens values for (`PluginContext.use`): `keys` by name, or
 * chosen from what the read resolved (`PickKeys`), so that a choice about
 * an environment's rows is made on the rows that are opened.
 */
export type UseAsked = { path: string; keys: readonly string[] | PickKeys; purpose: 'use' | 'expose'; logged: Record<string, unknown> };

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
  if ((at.place !== null && !UUID.test(at.place)) || (at.credential !== null && !CREDENTIAL_NAME.test(at.credential))) {
    throw await refusedWith(new ApiError('bad_request', 'an environment is named by its ID, and a credential by its name in the configuration'));
  }
  const target = at.credential === null || at.place === null ? null : `credential:${at.place}/${at.credential}`;
  let rows: Awaited<ReturnType<typeof callBindings>>;
  try {
    rows = await callBindings(runtime.db, principal, target);
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
  // Where it reaches, by ID: its scope's environments, and a project's, read only when it names one.
  const scope = readScope(binding.scope) ?? [];
  const reached = scope.every((grant) => grant.environmentId !== null)
    ? [...new Set(scope.map((grant) => grant.environmentId!))]
    : environmentsOf(scope, await placeRows(runtime.db)).map((environment) => environment.id);
  const place = at.place ?? (reached.length === 1 ? reached[0]! : null);
  if (at.credential !== null && place === null) {
    throw await refusedWith(new ApiError('bad_request', 'name the environment it uses, /use/<project>/<environment>/<credential>: this service reaches none, or several'));
  }
  // The credential's freeze, when the call named no environment and the statement could not know which.
  const frozen = found.frozen.instance || found.frozen.service || found.frozen.binding || found.frozen.credential
    || (target === null && at.credential !== null && (await frozenTargets(runtime.db, [`credential:${place}/${at.credential}`])).length > 0);
  if (frozen) throw await refusedWith(new ApiError('forbidden', 'frozen: a manager stopped this use; nothing passes until they lift it', 'frozen'));
  if (at.counts !== undefined && at.counts.length > 0) {
    let admitted;
    try {
      admitted = await gateOf(runtime, principal).admit({ counts: at.counts });
    } catch (error) {
      if (error instanceof SessionRefused) throw await workloadRefused(error.response);
      console.error('the workload gate failed', logged(error));
      throw await refusedWith(new ApiError('unavailable', 'coffre cannot count this call right now'));
    }
    if (!admitted.ok) {
      if (admitted.reason === 'limit') {
        const limit = { key: admitted.key, retryAfterMs: admitted.retryAfterMs, first: admitted.first };
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
  };
  standings.set(caller, { kind: 'binding', binding, policy, policySeq: found.policySeq === null ? null : BigInt(found.policySeq) });
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
  const caller: WorkloadUse = { ...session.caller, nonce: session.nonce, places: session.places, place: session.place };
  standings.set(caller, { kind: 'session', session });
  return caller;
}

/**
 * The identity a workload caller reads as, through the API's read: the
 * vault's answer about its service, once, and the scope it holds, each
 * grant with its binding's `reads` (`sessionScope`). Null for a caller
 * coffre did not make.
 */
async function workloadIdentity(runtime: CoffreRuntime, caller: WorkloadUse, sourceIp: string | null, standings: Standings): Promise<{ identity: AuthenticatedIdentity; expiresAt: string; constraints: Constraints | null } | null> {
  const standing = standings.get(caller);
  if (standing === undefined) return null;
  const { row, binding, policy, policySeq } = standing.kind === 'session' ? standing.session : { ...standing, row: null };
  const scope: CredentialScope = sessionScope(row ?? { scope: null }, binding, policy);
  const access = await runtime.vault.access(caller.principal);
  const id = caller.principal.slice('token:'.length);
  const generation = row?.generation ?? binding.generation;
  const callerOf = callerFrom({ type: 'service', id }, access, policySeq, scope, 'workload');
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
      credentialId: caller.credentialId,
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

function routesFor(request: Request, runtime: Pick<CoffreRuntime, 'plugins'>) {
  const { pathname } = new URL(request.url);
  return runtime.plugins.find((plugin) => plugin.routes !== undefined && under(pathname, plugin.routes.prefix))?.routes;
}

function pluginContext(request: Request, runtime: CoffreRuntime, sourceIp: string | null, binding: string | null = null): PluginContext {
  // The token where the API looks for it in this instance's mode: a header either way, so never ambient.
  const carrying = (token: string): Record<string, string> => (runtime.auth.mode === 'cloudflare' ? { [ACCESS_JWT_HEADER]: token } : { authorization: `Bearer ${token}` });
  // One of coffre's own routes outside the API's, in process: its answer, or its refusal as the client throws one.
  const answer = async (response: Response): Promise<unknown> => {
    const body = (await response.json()) as { error?: string; message?: string; reason?: string };
    if (!response.ok) throw new CoffreError(response.status, body.error ?? 'error', body.message ?? response.statusText, body.reason);
    return body;
  };
  const proxyHandle = async (handle: string): Promise<AuthenticatedIdentity> => {
    // A call through a service binding is its service's alone: it carries no handle, token or session.
    if (binding !== null) throw new CoffreError(403, 'forbidden', 'a call through a service binding is its service\'s, and takes no other credential', 'binding');
    const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), handle, sourceIp, { handle: true });
    if (identity instanceof Response) await answer(identity);
    return identity as AuthenticatedIdentity;
  };
  const noCredential = () => new CoffreError(403, 'forbidden', 'a call through a service binding is its service\'s, and takes no other credential', 'binding');
  // The workload callers this request's context made: the only ones its `use` takes.
  const standings: Standings = new WeakMap();
  return {
    publicUrl: runtime.publicUrl,
    workload: (asked, at) => (binding === null ? sessionWorkload(asked, runtime, sourceIp, at, standings) : bindingWorkload(runtime, binding, at, standings)),
    handle: async (handle) => {
      const { credentialExpiresAt, handlePlaces: places } = await proxyHandle(handle);
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
      try {
        let caller: AuthenticatedIdentity;
        let expiresAt: string;
        if (typeof handle === 'string') {
          caller = await proxyHandle(handle);
          if (!caller.registered) throw new ApiError('registration_required', 'the person this handle stands in for is no member here');
          expiresAt = caller.credentialExpiresAt!;
        } else {
          // A workload caller `workload` made for this request, and no other: one a plugin built itself is no one.
          const made = await workloadIdentity(runtime, handle, sourceIp, standings);
          if (made === null || !made.identity.registered) throw new ApiError('unauthenticated', 'that workload is no caller coffre authenticated');
          // A `narrow` child never reads (section 8.4): it uses, and is handed nothing back. Decided on what coffre kept, not on what the plugin holds.
          if (made.constraints !== null && asked.purpose !== 'use') throw new ApiError('forbidden', 'a narrowed session uses values, and reads none', 'narrowed');
          ({ identity: caller, expiresAt } = made);
        }
        const read = await reveal(apiContext(runtime, caller), parsePath(asked.path, [2]), asked);
        return { values: read.values, plain: read.plain, keys: read.keys, environment: read.environment, expiresAt };
      } catch (error) {
        if (!(error instanceof ApiError)) throw error;
        throw new CoffreError(error.status, error.code, error.message, error.reason);
      }
    },
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

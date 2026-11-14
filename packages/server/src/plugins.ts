// Plugins (docs/design/plugins.md): what a deployment adds to coffre in its
// configuration, `plugins: [credentialProxy({ … })]`. A plugin holds no
// authority of its own. It answers paths of its own, and reaches values only
// as whoever a request's credential is, through the vault's `use`: the app
// reads the credential's row to find the place it uses and, for a workload's
// session, its gate (docs/design/0.16.md, "What the app reads of a workload,
// and decides nothing on"), and the vault decides on its own rows.
import { CoffreError } from '@coffre/client';
import { hashToken, type BindingPolicy, type Constraints, type GateCount } from '@coffre/core/identity';
import type { Peeked, Presented, Used as VaultUsed } from '@coffre/core/vault';
import { isUnreachable } from '@coffre/db/dialect';

import { ApiError, refusal, toErrorBody } from './api/errors.ts';
import { stopOf } from './api/routes/secrets.ts';
import { routedCredential, type RoutedCredential } from './db/queries/sessions.ts';
import type { CoffreRuntime } from './runtime.ts';
import { dpopToken, gated, SessionRefused, sessionProof, sessionStopped, unknown } from './sessions.ts';

/** One plugin, as its constructor returns it: `credentialProxy({ … })`. */
export type CoffrePlugin = {
  /** What names it in errors: lowercase, `credential-proxy`. Unique among a deployment's plugins. */
  name: string;
  /**
   * The paths it answers: `prefix`, `/use`, and every path under it, whatever
   * the method. The deployment's app routes them to coffre with a file
   * route of their own, `routes/use.$.ts` (`plugin`, in `@coffre/server/routes`).
   */
  routes?: {
    prefix: string;
    fetch: (request: Request, coffre: PluginContext) => Promise<Response>;
  };
};

/** A connection's bytes both ways, a WebSocket's or a TCP socket's, and when it ends, whichever side ends it. */
export type Pipe = { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array>; close(): void; closed: Promise<void> };

/** An outbound TCP connection, which can turn to TLS once the protocol on it says it will. */
export type Socket = Pipe & { startTls(servername: string): Promise<Pipe> };

/** TCP out, as the platform opens it; `signal` gives up a dial still under way. */
export type Connect = (host: string, port: number, signal?: AbortSignal) => Promise<Socket>;

/** What a plugin's route answers with: where coffre is, and the values a request's credential may use. */
export type PluginContext = {
  publicUrl: string;
  /**
   * Values of the environment `path` names, `market/dev` or `market/dev@me`,
   * for whoever `caller` is: a handle (`coffre_use_…`) the plugin read from
   * its request, or the workload `workload` returned for this request. One
   * call to the vault (`use`), which decides on its own rows and logs the
   * use, naming `upstream`; nothing is kept here, so a revocation stops the
   * next request. Every key asked for, or a `CoffreError`: a refusal of the
   * whole use or of one key, or a key the environment does not hold (409).
   */
  use(caller: string | WorkloadUse, asked: UseAsked): Promise<Used>;
  /**
   * What a handle may use at `path`, with nothing opened and nothing logged
   * (the vault's `peek`, decided as a use through the proxy is): each key
   * the environment holds, by the nature its rows say, or why the handle may
   * not use it. What `coffre run`'s plan chooses the keys it asks `expose`
   * for by, never what it places a value by; and, for what it generates,
   * each key's version id and recipe, whether it is the caller's own, and
   * whether the read found their personal config (`personal`). A
   * `CoffreError` for a refusal of the whole place.
   */
  held(caller: string, path: string): Promise<Pick<Peeked, 'personal' | 'items'>>;
  /**
   * Values handed back to the caller's own app (purpose `expose`): the keys
   * named, or every key with `null`. One call to the vault, which logs what
   * it gives. Both this and `held` read the vault's rows now, never its
   * memory: a plan follows the writes `coffre run` just made. Key by key, the values given, those of them that opened plain,
   * and why each other is not given (`sensitive`, `use_only`, …), which the
   * caller does without. A `CoffreError` for a refusal of the whole use.
   */
  expose(caller: string | WorkloadUse, asked: { path: string; keys: readonly string[] | null }): Promise<Exposed>;
  /**
   * The environments a handle was made for, by path as they are named now
   * (`market/dev@me`), or null where one was deleted, and when it ends: the
   * app's read of its row, unchecked, which only says where a request with
   * no environment in its URL goes. Whether the handle stands is the
   * vault's answer to the use. A `CoffreError` 401 for a token that is no
   * handle's.
   */
  handle(handle: string): Promise<{ expiresAt: string; paths: readonly (string | null)[] }>;
  /**
   * The request as a workload's session (`Authorization: DPoP coffre_wl_…`),
   * held to its proof before the vault is asked, cheapest first: the
   * proof's shape; the session's row, by its token's hash, for its service,
   * its key and its places; the proof, for this request and, with `body`,
   * its headers and content (`hdr`, `req`); then its service's gate, the
   * proof once and `counts` in the same call. No vault call. A refusal
   * throws a `WorkloadRefused`, whose `response` is the answer to forward as
   * it is. Null for a request that carries no session.
   *
   * `place` is an environment's path (`market/prod`); null means the one
   * environment the session was made for (`/use/<credential>`), and the
   * caller's `path` is null when it reaches none or several.
   */
  workload(request: Request, at: WorkloadAt): Promise<WorkloadUse | null>;
};

/** What a workload's request uses (`PluginContext.workload`): where, the body line `req` signs, and the counts its limits take. */
export type WorkloadAt = {
  /** An environment's path, `market/prod`, or null for the one its session was made for. */
  place: string | null;
  /**
   * `bodyDigest(bytes)` of a buffered body, a sigv4 upload's declared
   * digest, or `UNSIGNED_BODY`: for a request whose proof signs its
   * content. Left out for one that signs none.
   */
  body?: string;
  /** The counts, or how to make them for the service, `token:<name>`, which only its row tells (a limit per workload). */
  counts?: readonly GateCount[] | ((service: string) => readonly GateCount[]);
};

/**
 * A workload's session, held to its proof for one request: its service, the
 * headers its proof signs (which alone go on), the gate's nonce to send back
 * (`DPoP-Nonce`), and the environment this request uses, by path, null when
 * the session reaches none or several and the URL named none.
 */
export type WorkloadUse = { readonly principal: string; readonly hdr: readonly string[] | null; readonly nonce: string; readonly path: string | null };

/** A workload's request refused: `response` is its answer, the headers RFC 9449 asks for included. */
export class WorkloadRefused extends CoffreError {
  readonly response: Response;
  constructor(status: number, code: string, message: string, reason: string | undefined, response: Response) {
    super(status, code, message, reason);
    this.name = 'WorkloadRefused';
    this.response = response;
  }
}

/** What a plugin opens values for (`PluginContext.use`): the keys by name, why, and the name of what they are used for, which the log says. */
export type UseAsked = { path: string; keys: readonly string[]; purpose: 'use' | 'expose'; upstream: string };

/**
 * Values a plugin opened, by key; those that are plain, no secret, which an
 * upstream may echo; the environment they came from; and, for a workload's
 * session, what only the app can hold its request to: its binding's policy
 * (`unsignedUploads`) and a narrowed session's constraints.
 */
export type Used = {
  values: Record<string, string>;
  plain: string[];
  environment: { path: string; personal: boolean };
  workload: { policy: BindingPolicy; constraints: Constraints | null } | null;
};

/** What `expose` hands back: by key, the values given and those that opened plain, and why the others are not given. */
export type Exposed = { values: Record<string, string>; plain: string[]; refused: Record<string, string>; environment: { path: string; personal: boolean } };

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const PREFIX = /^(\/[a-z0-9][a-z0-9._-]*)+$/;
/** What coffre answers itself, and no plugin may take. */
const COFFRE_PATHS = ['/api', '/auth', '/mcp', '/.well-known', '/livez', '/readyz'];

/** Whether `pathname` is `prefix` or under it. */
const under = (pathname: string, prefix: string) => pathname === prefix || pathname.startsWith(`${prefix}/`);

/** Check a deployment's plugins, failing on the first problem: a bad name, or paths two would answer. */
export function checkPlugins(plugins: readonly CoffrePlugin[]): readonly CoffrePlugin[] {
  if (!Array.isArray(plugins)) throw new Error('plugins is a list, `plugins: [credentialProxy({ … })]`');
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
  const { pathname } = new URL(request.url);
  const routes = runtime.plugins.find((plugin) => plugin.routes !== undefined && under(pathname, plugin.routes.prefix))?.routes;
  return routes === undefined ? null : routes.fetch(request, pluginContext(request, runtime, sourceIp));
}

/** A refusal as a plugin throws it: the API's error, its status and words. */
function thrown(error: ApiError): CoffreError {
  return new CoffreError(toErrorBody(error).status, error.code, error.message, error.reason);
}

/** A session's refusal before the vault, as a plugin throws it: its response kept to forward. */
async function workloadRefused(response: Response): Promise<WorkloadRefused> {
  const body = (await response.clone().json()) as { error?: string; message?: string; reason?: string };
  return new WorkloadRefused(response.status, body.error ?? 'error', body.message ?? response.statusText, body.reason, response);
}

/**
 * What the proxy last routed each credential by, kept for an outage of the
 * database alone (D238): when the routing read cannot reach it, the row read
 * last for that token still says where the request goes, and the vault,
 * which answers a proxied use from the rows it last read for the same ask
 * (`outageSeconds`), decides as ever. The rows say only where to ask; none
 * decides anything, so one kept past a revocation gives nothing the vault
 * does not. Kept until the credential ends, an hour at most, a thousand at
 * most; a failure is remembered for two seconds, as the vault remembers
 * one, so the requests in them do not each wait for the database to fail.
 */
type Routes = { rows: Map<string, { row: RoutedCredential; until: number }>; downUntil: number };

const ROUTES_KEPT = 1000;
const ROUTE_MS = 3_600_000;
const DOWN_MS = 2000;

/** By the deployment's plugins, the configuration's own list: an isolate's or a process's, settled values only (AGENTS.md, "What an isolate keeps"). */
const routing = new WeakMap<readonly CoffrePlugin[], Routes>();

function routesOf(runtime: CoffreRuntime): Routes {
  let routes = routing.get(runtime.plugins);
  if (routes === undefined) routing.set(runtime.plugins, (routes = { rows: new Map(), downUntil: -Infinity }));
  return routes;
}

/** The credential `token` hashes to, as the app routes it (`routedCredential`): read, or through an outage, the row read last. */
export async function routed(runtime: CoffreRuntime, tokenHash: Buffer): Promise<RoutedCredential | null> {
  const routes = routesOf(runtime);
  const key = tokenHash.toString('hex');
  const kept = () => {
    const held = routes.rows.get(key);
    return held !== undefined && held.until > Date.now() ? held.row : undefined;
  };
  if (Date.now() < routes.downUntil) {
    const row = kept();
    if (row !== undefined) return row;
  }
  let row: RoutedCredential | null;
  try {
    row = await routedCredential(runtime.db, tokenHash);
  } catch (error) {
    if (!isUnreachable(error)) throw error;
    routes.downUntil = Date.now() + DOWN_MS;
    const held = kept();
    if (held === undefined) throw error;
    return held;
  }
  routes.rows.delete(key);
  if (row !== null) {
    if (routes.rows.size >= ROUTES_KEPT) routes.rows.delete(routes.rows.keys().next().value!);
    routes.rows.set(key, { row, until: Math.min(Date.now() + ROUTE_MS, row.expiresAt.getTime()) });
  }
  return row;
}

/** Where a path names: `market/dev@me` is `market`, `dev`, its person's own. Null for anything else. */
function placeOf(path: string): { project: string; environment: string; mine: boolean } | null {
  const match = /^([^/@]+)\/([^/@]+)(@me)?$/.exec(path);
  return match === null ? null : { project: match[1]!, environment: match[2]!, mine: match[3] !== undefined };
}

/** What a workload caller stands on, kept by the context of the request it was made for: `use` takes back only those. */
type Standing = { token: string; proof: string; sourceIp: string | null };

function pluginContext(request: Request, runtime: CoffreRuntime, sourceIp: string | null): PluginContext {
  // The workload callers this request's context made: the only ones its `use` takes.
  const standings = new WeakMap<WorkloadUse, Standing>();
  return {
    publicUrl: runtime.publicUrl,
    handle: async (handle) => {
      const row = await routed(runtime, hashToken(handle));
      if (row === null || row.kind !== 'handle') throw thrown(new ApiError('unauthenticated', 'that handle is unknown, expired or revoked'));
      return { expiresAt: row.expiresAt.toISOString(), paths: (row.places ?? []).map((place) => (place === null ? null : `${place.path}${place.personal ? '@me' : ''}`)) };
    },
    workload: async (asked, at) => {
      const token = dpopToken(asked);
      if (token === null) return null;
      try {
        const parsed = sessionProof(asked, runtime, token);
        const row = await routed(runtime, hashToken(token));
        if (row === null || row.kind !== 'workload' || row.jkt === null) throw unknown();
        const counts = typeof at.counts === 'function' ? at.counts(row.principal) : at.counts;
        const { proven, hdr } = await gated(asked, runtime, token, parsed, { id: row.id, principal: row.principal, jkt: row.jkt }, {
          ...(at.body === undefined ? {} : { content: { headers: asked.headers, body: at.body } }),
          ...(counts === undefined ? {} : { counts }),
        });
        const live = (row.places ?? []).filter((place) => place !== null);
        const path = at.place ?? (live.length === 1 && (row.places ?? []).length === 1 ? live[0]!.path : null);
        const caller: WorkloadUse = { principal: row.principal, hdr, nonce: proven.nonce, path };
        standings.set(caller, { token, proof: proven.proof, sourceIp });
        return caller;
      } catch (error) {
        if (error instanceof SessionRefused) throw await workloadRefused(error.response);
        throw error;
      }
    },
    use: async (caller, asked) => {
      const [place, shown] = askedAs(caller, asked.path);
      const answer = await runtime.vault.use({ ...shown, ...place, keys: [...asked.keys], purpose: asked.purpose, upstream: asked.upstream });
      const word = wording(caller);
      if ('refused' in answer) throw word(refusal(answer.refused, asked.path));
      return usedOf(answer, asked, place.mine, word);
    },
    held: async (caller, path) => {
      const [place, shown] = askedAs(caller, path);
      // Read now: a plan right after `coffre run` wrote the values it generated must see them (`UseInput.fresh`).
      const answer = await runtime.vault.peek({ ...shown, ...place, keys: null, purpose: 'use', upstream: null, fresh: true });
      if ('refused' in answer) throw wording(caller)(refusal(answer.refused, path));
      return { personal: answer.personal, items: answer.items };
    },
    expose: async (caller, asked) => {
      const [place, shown] = askedAs(caller, asked.path);
      const answer = await runtime.vault.use({ ...shown, ...place, keys: asked.keys === null ? null : [...asked.keys], purpose: 'expose', upstream: null, fresh: true });
      if ('refused' in answer) throw wording(caller)(refusal(answer.refused, asked.path));
      const exposed: Exposed = { values: Object.create(null), plain: [], refused: Object.create(null), environment: { path: asked.path.replace(/@me$/, ''), personal: place.mine } };
      for (const item of answer.values) {
        if ('refused' in item) exposed.refused[item.key] = item.refused;
        else {
          exposed.values[item.key] = item.value;
          if (item.nature === 'plain') exposed.plain.push(item.key);
        }
      }
      return exposed;
    },
  };

  /** Where `path` names and what the request shows the vault: a handle's hash, or a workload caller's this context made, and no other. */
  function askedAs(caller: string | WorkloadUse, path: string): [NonNullable<ReturnType<typeof placeOf>>, Presented] {
    const place = placeOf(path);
    if (place === null) throw thrown(new ApiError('bad_request', 'an environment is named by its path, project/environment'));
    if (typeof caller === 'string') return [place, { token: hashToken(caller).toString('hex'), proof: null, request: crypto.randomUUID(), ip: sourceIp }];
    // A workload caller `workload` made for this request, and no other: one a plugin built itself is no one.
    const standing = standings.get(caller);
    if (standing === undefined) throw thrown(new ApiError('unauthenticated', 'that workload is no caller coffre authenticated'));
    return [place, { token: hashToken(standing.token).toString('hex'), proof: standing.proof, request: crypto.randomUUID(), ip: standing.sourceIp }];
  }

  /** A workload's stop worded as 0.14.7 did (`sessionStopped`); any other refusal as the API words it. */
  function wording(caller: string | WorkloadUse): (error: ApiError) => CoffreError {
    return (error) => thrown((typeof caller === 'string' ? error : sessionStopped(error, sourceIp)) as ApiError);
  }
}

/** The vault's answer as a plugin takes it: every key asked for, or why not. */
function usedOf(answer: VaultUsed, asked: UseAsked, mine: boolean, word: (error: ApiError) => CoffreError): Used {
  const stop = stopOf(answer.values);
  if (stop !== undefined) throw word(refusal(stop.refused, `${asked.path}/${stop.key}`));
  const values: Record<string, string> = Object.create(null);
  const plain: string[] = [];
  const missing: string[] = [];
  for (const item of answer.values) {
    if ('refused' in item) {
      // What a person's read leaves out, a sensitive value handed back included, refuses this one use.
      if (item.refused === 'unknown_key' || item.refused === 'no_value') missing.push(item.key);
      else throw word(refusal(item.refused, `${asked.path}/${item.key}`));
      continue;
    }
    values[item.key] = item.value;
    if (item.nature === 'plain') plain.push(item.key);
  }
  if (missing.length > 0) throw thrown(new ApiError('conflict', `${asked.path} holds no ${missing.join(', ')}, which ${asked.upstream} needs`));
  return {
    values,
    plain,
    environment: { path: asked.path.replace(/@me$/, ''), personal: mine },
    workload: answer.workload === null ? null : { policy: answer.workload.policy, constraints: answer.workload.constraints },
  };
}

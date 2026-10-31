import type { CoffreClient } from '@coffre/client';

import { ApiError, badRequest, UNAVAILABLE } from './api/errors.ts';
import { narrowWorkload } from './api/narrow.ts';
import {
  finishSignin,
  logout,
  pollDevice,
  exchangeWorkloadSession,
  exchangeWorkloadToken,
  renewWorkloadSession,
  signOut,
  startDevice,
  startSignin,
} from './auth-routes.ts';
import { WORKLOAD_SIGN_IN_PATH } from '@coffre/core/identity';
import { preferencesIn, type Preferences } from '@coffre/core/pages';
import { isUnreachable } from '@coffre/db/dialect';
import { migrated } from '@coffre/db/schema-version';

import { auditHead, pruneSpentTokens } from './db/queries.ts';
import { anchorIsOwn } from './anchor.ts';
import { finishRotation, keyStateNow, rotateStep, type KeyState } from './key-rotation.ts';
import { CUTTING_OVER_NOW, cutoverReady, HOLD_MS, type CutoverHeld } from './cutover.ts';
import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { logged } from './logged.ts';
import { mcpEndpoint } from './mcp/endpoint.ts';
import { authorizationServer, oauthRegister, oauthRevoke, oauthToken, protectedResource } from './mcp/http.ts';
import { pluginRoute } from './plugins.ts';
import { ObjectMoved, vaultSaysSealing } from './api/changes.ts';
import { watchOf, type CoffreRuntime } from './runtime.ts';
import { cspNonce, setSecurityHeaders } from './security-headers.ts';


type Handler = (request: Request, runtime: CoffreRuntime, sourceIp: string | null) => Promise<Response>;

/** Exact paths outside the route table, and the one method each takes. */
const ROUTES: Record<string, { method: 'GET' | 'POST'; handler: Handler; browserForm?: true }> = {
  '/livez': { method: 'GET', handler: async () => jsonResponse({ ok: true }) },
  '/readyz': {
    method: 'GET',
    handler: async (_request, runtime) => {
      const readiness = await ready(runtime);
      return jsonResponse(readiness, readiness.ok ? 200 : 503);
    },
  },
  '/api/auth/device': { method: 'POST', handler: startDevice },
  '/api/auth/device/token': { method: 'POST', handler: pollDevice },
  '/api/auth/logout': { method: 'POST', handler: logout },
  '/api/auth/oidc': { method: 'POST', handler: exchangeWorkloadToken },
  // A workload's key-bound session (docs/design/workload-access.md): its sign-in, renewal, and a child with less.
  [WORKLOAD_SIGN_IN_PATH]: { method: 'POST', handler: exchangeWorkloadSession },
  '/api/auth/workload/renew': { method: 'POST', handler: renewWorkloadSession },
  '/api/auth/workload/narrow': { method: 'POST', handler: narrowWorkload },
  // MCP clients' OAuth (docs/design/mcp.md, section 4), and the endpoint its tokens are for.
  '/api/oauth/token': { method: 'POST', handler: oauthToken },
  '/api/oauth/register': { method: 'POST', handler: oauthRegister },
  '/api/oauth/revoke': { method: 'POST', handler: oauthRevoke },
  '/.well-known/oauth-protected-resource': { method: 'GET', handler: protectedResource },
  '/.well-known/oauth-protected-resource/mcp': { method: 'GET', handler: protectedResource },
  '/.well-known/oauth-authorization-server': { method: 'GET', handler: authorizationServer },
  '/mcp': { method: 'POST', handler: mcpEndpoint },
  // Posted by coffre's own pages, with the browser's cookies.
  '/auth/signout': { method: 'POST', handler: signOut, browserForm: true },
};

const PROVIDER_ROUTE = /^\/auth\/(signin|callback)\/([a-z0-9-]{1,32})$/;

/**
 * coffre's own paths, health, sign-in and the API, and its plugins'. Null
 * for any other, a page's, which the deployment's Start app renders.
 */
export async function coffreRoute(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response | null> {
  const { pathname } = new URL(request.url);

  const exact = ROUTES[pathname];
  if (exact !== undefined) {
    // HEAD is GET without the body, which the platform drops: what a monitor asks /livez and /readyz.
    const method = request.method === 'HEAD' && exact.method === 'GET' ? 'GET' : request.method;
    if (method !== exact.method) return methodNotAllowed([exact.method]);
    if (exact.browserForm && !isSameOrigin(request, runtime.publicUrl)) {
      return errorResponse(new ApiError('cross_origin', 'this must be sent from coffre itself'));
    }
    return exact.handler(request, runtime, sourceIp);
  }
  if (pathname === '/api' || pathname.startsWith('/api/')) return fetchApi(request, runtime, { sourceIp });

  const provider = PROVIDER_ROUTE.exec(pathname);
  if (provider !== null) {
    if (request.method !== 'GET') return methodNotAllowed(['GET']);
    const [, step, id] = provider;
    return step === 'signin'
      ? startSignin(request, runtime, sourceIp, id)
      : finishSignin(request, runtime, sourceIp, id);
  }
  return pluginRoute(request, runtime, sourceIp);
}

/** What a page renders with: this response's nonce, the API as the visitor, and how they have the pages drawn. */
export type PageContext = { cspNonce: string; client: CoffreClient; preferences: Preferences };

/**
 * One request, whatever answers it, a page or one of coffre's routes: it
 * gets a fresh nonce, the visitor's API client and their preferences to
 * render with, and coffre's security headers on whatever comes back.
 * `sourceIp` is the platform's to vouch for: Cloudflare's header on
 * Workers, the socket's address on Node.
 */
export async function respond(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  render: (context: PageContext) => Promise<Response>,
): Promise<Response> {
  const nonce = cspNonce();
  let response: Response;
  try {
    const { pathname } = new URL(request.url);
    const closed = SERVED_WHILE_MIGRATING.has(pathname) ? null : await door(runtime);
    response =
      closed === null
        ? await render({ cspNonce: nonce, client: pageClient(request, runtime, sourceIp), preferences: preferencesIn(request.headers.get('cookie')) })
        : closed(request);
  } catch (error) {
    response = errorResponse(error);
  }
  const auth = runtime.auth;
  const options = {
    nonce,
    publicUrl: runtime.publicUrl,
    // Access's logout form posts to Access itself.
    formOrigins: auth.mode === 'cloudflare' ? [auth.access.issuer] : [],
  };
  try {
    return setSecurityHeaders(response, options);
  } catch (error) {
    // A route's response that cannot take them: said in the log, and answered with one that can.
    return setSecurityHeaders(errorResponse(error), options);
  }
}

/** What answers below this version's migrations, or during a rotation: liveness, and readiness, which is red until they are done. */
const SERVED_WHILE_MIGRATING = new Set(['/livez', '/readyz']);

/**
 * What answers instead of the request, if anything does: below the
 * migrations, `migrating`; until the log is under the app's key, a step of
 * the rotation to it, then `rotating`, or `app_key` for a key the log
 * refuses (`keyReady`). Null: the request is served.
 */
async function door(runtime: CoffreRuntime): Promise<((request: Request) => Response) | null> {
  if (!(await schemaReady(runtime))) return migrating;
  const held = await keyReady(runtime);
  if (held !== null) return held.kind === 'rotating' || held.kind === 'stalled' ? rotating : held.kind === 'refused' ? wrongKey : unreachable;
  // Under 0.15's log, cut over from 0.14 before anything else: the first request does it, and waits.
  const cut = await cutoverReady(runtime);
  return cut === null ? null : cuttingOver(cut);
}

/**
 * The answer while 0.15's log is not cut over from 0.14 (cutover.ts): a
 * request of this isolate is cutting over, or the cutover was refused,
 * failed, or met 0.14 writing meanwhile, which the server's log says once.
 * A request tries again once the hold lapses. A question that did not
 * answer says only that: an instance made on 0.15, asking of its own
 * cutover's seal, moves nothing (T170).
 */
function cuttingOver(held: CutoverHeld): (request: Request) => Response {
  cutoverRefused(held.why);
  return () => errorResponse(new ApiError('unavailable', held.failed ? UNCHECKED : CUTTING_OVER), { 'retry-after': String(HOLD_MS / 1000) });
}

/** Why the cutover holds the door, said in the server's log once, and again if it changes: from a request or readiness alike. */
function cutoverRefused(why: string): void {
  if (why === CUTTING_OVER_NOW || refusals.get(cuts) === why) return;
  refusals.set(cuts, why);
  console.error({ event: 'cutover_refused', reason: why }, "coffre serves nothing until 0.15's log is cut over from 0.14");
}

const cuts = {};

const CUTTING_OVER = "coffre is moving its audit log to 0.15's, and serves once it has: the server's log says what holds it back";

const UNCHECKED = "coffre could not check that its audit log is cut over to 0.15's, and serves once it can: the server's log says why";

/**
 * Whether the database has every migration this version ships. Each
 * deployment migrates before it deploys (`coffre migrate`), so a new app
 * never serves on a schema it does not have: until then, everything but
 * health answers 503 `migrating`; a database never migrated has no ledger,
 * and is below them too. Asked until it holds, then known. A database that
 * cannot be reached lets the request through, to meet the outage as it would
 * anyway: a page shows its error state, the API answers 503. Hyperdrive's
 * pool full is one too, and may free before the request's own queries:
 * then, below the migrations, they run on the old schema. That is a gap
 * accepted, as it was for a database that came back mid-request: it needs
 * a deploy that skipped `coffre migrate`, and migrations only add. Any
 * other failure of the question fails the request.
 */
export async function schemaReady(runtime: CoffreRuntime): Promise<boolean> {
  if (!runtime.schema.migrated) {
    try {
      runtime.schema.migrated = await migrated(runtime.db);
    } catch (error) {
      if (isUnreachable(error)) return true;
      throw error;
    }
  }
  return runtime.schema.migrated;
}

const MIGRATING = "coffre's database lacks this version's migrations: an owner runs `coffre migrate`, as every deploy does first";

/** The answer below the migrations: the API's error, or for a browser's page, a page that says it in words. */
function migrating(request: Request): Response {
  if (!(request.headers.get('accept') ?? '').includes('text/html')) return errorResponse(new ApiError('migrating', MIGRATING), { 'retry-after': '30' });
  const page =
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>coffre is migrating</title>' +
    "<p>coffre's database lacks this version's migrations. An owner runs <code>coffre migrate</code>, as every deploy does first; this page works once it has.</p></html>";
  return new Response(page, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'retry-after': '30' } });
}

/** What holds the app back from serving under its key (`keyReady`). */
export type KeyHeld =
  | { kind: 'rotating' }
  /** Every row signed again, and the audit anchor's store could not be used: the rotation waits for it, as `rotating` to a request. */
  | { kind: 'stalled' }
  | { kind: 'refused'; reason: string }
  | { kind: 'unreachable' };

/**
 * Whether the log is under the app's key: null once it is, known from then
 * on, for the configuration's life. Until then, a step of the rotation to
 * it, each call one (key-rotation.ts), if no other start holds the log's
 * head (`wait` waits for it): rows signed again, or, once they all are,
 * the audit anchor sealed again and `key.rotate`. What still
 * holds the app back: the rotation; a key the log refuses, which only
 * another deployment of the app's keys changes; or, with keys it replaced
 * configured, a database that cannot be reached, as nothing may be
 * checked under a key the log has not settled while a rotation may be due.
 * Without them there is none to be due, and a database that cannot be
 * reached lets the request through, as `schemaReady` does, to meet the
 * outage as it would anyway.
 */
export async function keyReady(runtime: CoffreRuntime, { wait = false }: { wait?: boolean } = {}): Promise<KeyHeld | null> {
  if (runtime.appKey.settled) return null;
  let state: KeyState;
  try {
    state = await keyStateNow(runtime.db, runtime);
    // With 0.15's log, a step that other starts' steps kept coming between, past its tries, leaves the rotation to them.
    const read = state;
    if (read.kind === 'rotating') state = await rotateStep(runtime.db, runtime, { wait, vault: runtime.vault }).catch((error: unknown) => {
      if (error instanceof ObjectMoved) return read;
      throw error;
    });
    if (state.kind === 'sealing') {
      // A store that cannot be used holds the rotation back, and says so: the next step tries again.
      const sealed = await resealAnchor(runtime, state.from).then(() => true, (error: unknown) => {
        console.error('the audit anchor could not be sealed again under the new app key: the rotation waits for it', logged(error));
        return false;
      });
      if (!sealed) return { kind: 'stalled' };
      state = await finishRotation(runtime.db, runtime, { wait, vault: runtime.vault });
    }
  } catch (error) {
    if (!isUnreachable(error)) throw error;
    return runtime.previousChainKeys.length === 0 ? null : { kind: 'unreachable' };
  }
  if (state.kind === 'refused') refusedKey(runtime, state.reason);
  if (state.kind === 'refused') return state;
  if (state.kind !== 'settled') return { kind: 'rotating' };
  runtime.appKey.settled = true;
  return null;
}

/**
 * The rotation stepped to its end, or until the log refuses the key or
 * the anchor's store cannot be used, once the database is migrated: what a
 * Node process runs as it starts, beside the requests, whose door steps it
 * too. A failure is said, and each request's door steps again.
 */
export async function settleKey(runtime: CoffreRuntime): Promise<void> {
  try {
    if (!(await schemaReady(runtime))) return;
    while ((await keyReady(runtime, { wait: true }))?.kind === 'rotating');
  } catch (error) {
    console.error('the rotation to the app key could not go on: each request tries again', logged(error));
  }
}

/**
 * The audit anchor sealed again under the app's key, from the key the
 * rotation moves from, by the audit watch if there is one: before
 * `key.rotate`, after which the old key vouches for nothing, the anchor
 * included. A store that cannot be used holds the rotation back, and the
 * next step tries again.
 */
async function resealAnchor(runtime: CoffreRuntime, from: Buffer): Promise<void> {
  const watch = watchOf(runtime);
  if (watch === null) return;
  await watch.hooks.reseal(watch.context(), (anchor) => anchorIsOwn(from, anchor));
}

const ROTATING = 'coffre is moving to its new app key, signing its rows again under it: each request takes it a step further';

/** The answer during a rotation, for a moment: the API's error, or for a browser's page, a page that comes back. */
function rotating(request: Request): Response {
  if (!(request.headers.get('accept') ?? '').includes('text/html')) return errorResponse(new ApiError('rotating', ROTATING), { 'retry-after': '1' });
  const page =
    '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="1"><title>coffre is moving to its new key</title>' +
    "<p>coffre is moving to its new app key, signing its rows again under it. This page comes back once it has: everyone signs in again then.</p></html>";
  return new Response(page, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'retry-after': '1' } });
}

const WRONG_KEY = "coffre's audit log is under an app key this deployment does not hold, or has moved on from its own: the server's log says which, and an operator fixes auditChainKey or previousAuditChainKeys";

/** The answer to every request while the log refuses the app's key. Which keys, the server's log says, not the visitor. */
function wrongKey(request: Request): Response {
  if (!(request.headers.get('accept') ?? '').includes('text/html')) return errorResponse(new ApiError('app_key', WRONG_KEY), { 'retry-after': '30' });
  const page = `<!doctype html><html lang="en"><meta charset="utf-8"><title>coffre's app key</title><p>${WRONG_KEY}.</p></html>`;
  return new Response(page, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'retry-after': '30' } });
}

/** The answer while the database cannot say where the app's key stands: nothing is checked under a key it has not settled. */
function unreachable(): Response {
  // A moment's 503, which says when to ask again (`errorResponse`).
  return errorResponse(new ApiError('unavailable', UNAVAILABLE));
}

const refusals = new WeakMap<object, string>();

/** Why the log refuses the app's key, said in the server's log once a configuration, and again if it changes. */
function refusedKey(runtime: CoffreRuntime, reason: string): void {
  if (refusals.get(runtime.appKey) === reason) return;
  refusals.set(runtime.appKey, reason);
  console.error({ event: 'app_key_refused', reason }, "coffre serves nothing under this app key");
}

/**
 * Spent tokens forgotten a beat: a beat every five minutes forgets up to
 * 60,000 an hour, where one binding's exchanges spend at most 3,600.
 */
export const SPENT_TOKENS_PER_BEAT = 5000;

/**
 * Readiness: the database migrated, and, with an audit watch, what it says
 * (plugins/audit-watch.ts). Without one, nothing more, and `watched: false`
 * says so: the log is verified only when someone asks (`coffre verify log`).
 */
async function ready(runtime: CoffreRuntime): Promise<{ ok: boolean } & Record<string, unknown>> {
  const watch = watchOf(runtime);
  try {
    if (!(await migrated(runtime.db))) return watch === null ? { ok: false, watched: false } : { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false };
  } catch {
    return watch === null ? { ok: false, watched: false } : { ok: false };
  }
  // Below its key, each ask a step of the rotation: a deploy that waits on readiness takes it to its end.
  const held = await keyReady(runtime).catch((error: unknown) => {
    console.error('the rotation to the app key could not go on', logged(error));
    return 'error' as const;
  });
  if (held === 'error') return { ok: false, appKey: 'error' };
  if (held !== null) return { ok: false, ...(held.kind === 'rotating' || held.kind === 'stalled' ? { rotating: true } : held.kind === 'refused' ? { appKey: false } : {}) };
  // Under 0.15's log, cut over from 0.14: a deploy that waits on readiness takes it there.
  const cut = await cutoverReady(runtime);
  if (cut !== null) {
    // A deploy that polls readiness alone reads why in the server's log (review r9).
    cutoverRefused(cut.why);
    return { ok: false, cutover: false };
  }
  // Under 0.15's log a change answers once sealed (R51): whether the checkpointer seals, red within seconds of a stall
  // and green again once it ticks (T169).
  const unsealed = await unsealing(runtime);
  if (unsealed !== null) return { ok: false, sealing: false };
  if (watch === null) return { ok: true, watched: false };
  const said = await watch.hooks.readiness(watch.context());
  return { ...said, ok: said.ok };
}

/** How long readiness waits on the vault's word on its checkpointer: past it, the checkpointer does not seal. */
const SEALING_ASKED_MS = 3000;

/** Why 0.15's checkpointer does not seal, said in the server's log once while it stands; null when it does (T169). */
async function unsealing(runtime: CoffreRuntime): Promise<string | null> {
  const { vault } = runtime;
  if (vault.sealing === undefined || !(await vaultSaysSealing(vault))) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const said = await Promise.race([
    vault.sealing().catch((error: unknown) => ({ ok: false as const, reason: error instanceof Error ? error.message : String(error) })),
    new Promise<{ ok: false; reason: string }>((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, reason: `the vault did not say within ${SEALING_ASKED_MS} ms` }), SEALING_ASKED_MS);
    }),
  ]).finally(() => clearTimeout(timer));
  const why = said.ok ? null : said.reason;
  if (why !== null && sealingSaid.get(runtime.vault) !== why) console.error('the audit checkpointer does not seal: changes answer 503 until it does', why);
  if (why === null) sealingSaid.delete(runtime.vault);
  else sealingSaid.set(runtime.vault, why);
  return why;
}

/** What readiness last said of the checkpointer, per vault: said again only once it changes. */
const sealingSaid = new WeakMap<object, string>();

/**
 * The scheduled run: the audit watch's beat, if the deployment added one;
 * the vault's checkpoint of the log, once, which the beat asked for if it
 * ran, and which keeps every verification a walk from the newest
 * checkpoint (R25); then spent tokens' upkeep. Throws so the scheduler
 * reports failures.
 */
export async function runScheduled(runtime: CoffreRuntime): Promise<void> {
  if (!(await schemaReady(runtime))) throw new Error(MIGRATING);
  const held = await keyReady(runtime);
  if (held !== null) {
    throw new Error(
      held.kind === 'rotating' || held.kind === 'stalled' ? `${ROTATING}: the scheduled job runs once it has` : held.kind === 'refused' ? held.reason : "coffre's database cannot be reached",
    );
  }
  // Under 0.15's log, cut over from 0.14 first, as a request's door and readiness have it: on Node, the job runs as the
  // server starts, before any request, and the vault decides nothing until then.
  const cut = await cutoverReady(runtime);
  if (cut !== null) {
    cutoverRefused(cut.why);
    throw new Error(`the scheduled job runs once 0.15's log is cut over: ${cut.why}`);
  }
  const watch = watchOf(runtime);
  if (watch === null) unwatched(runtime);
  const context = watch?.context();
  const watched = watch === null ? true : await watch.hooks.scheduled(context!);
  // Asked once a run: the watch's own call, when it made one, is this one.
  const signed = await (context?.vault.checkpoint() ?? runtime.vault.checkpoint()).then(
    (outcome) => (outcome.ok ? null : outcome.refusal.message),
    (error: Error) => error.message,
  );
  // After the beat, which a failed prune never holds back, and reported as the run's failure too.
  const pruned = await pruneSpentTokens(runtime.db, SPENT_TOKENS_PER_BEAT).then(() => null, (error: Error) => error);
  if (!watched) throw new Error('scheduled audit heartbeat failed');
  // An empty log has nothing to sign: no failure without a watch, whose beat is an entry.
  if (signed !== null && watch === null && !(await logIsEmpty(runtime))) throw new Error(`the vault did not checkpoint the audit log: ${signed}`);
  if (pruned !== null) throw new Error(`spent tokens could not be pruned: ${pruned.message}`);
}

const told = new WeakSet<object>();

/**
 * Said once a configuration, the isolate's or the process's: a deployment
 * that left the audit watch out, or upgraded without adding it, sees that
 * nothing watches the log.
 */
function unwatched(runtime: CoffreRuntime): void {
  if (told.has(runtime.plugins)) return;
  told.add(runtime.plugins);
  console.warn('no audit watch: the audit log is verified only when someone asks (coffre verify log), and /readyz says only that the database is migrated. Add auditWatch to plugins (docs/deploy.md, "The audit watch").');
}

/** Whether the log holds no entry yet; a database that cannot say, no. */
async function logIsEmpty(runtime: CoffreRuntime): Promise<boolean> {
  return auditHead(runtime.db).then((head) => (head?.nextSeq ?? 0n) === 0n, () => false);
}

/**
 * More of the audit watch's backlog walked, a walk after another, up to
 * `walks`, and none begun after `until` (ms since the epoch): what Node's
 * scheduled job runs after each run (on Workers, the anchor's Durable
 * Object's alarm). Whether more is left.
 */
export async function walkAuditBacklog(runtime: CoffreRuntime, walks: number, until = Infinity): Promise<boolean> {
  const watch = watchOf(runtime);
  if (watch === null) return false;
  for (let i = 0; i < walks; i++) {
    if (Date.now() >= until) return true;
    if (!(await watch.hooks.walkOn(watch.context()))) return false;
  }
  return true;
}

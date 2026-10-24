import type { CoffreClient } from '@coffre/client';

import { ApiError, badRequest } from './api/errors.ts';
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
import { preferencesIn, type Preferences } from '@coffre/core/pages';
import { isUnreachable } from '@coffre/db/dialect';
import { migrated } from '@coffre/db/schema-version';

import { pruneSpentTokens } from './db/queries.ts';
import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { logged } from './logged.ts';
import { mcpEndpoint } from './mcp/endpoint.ts';
import { authorizationServer, oauthRegister, oauthRevoke, oauthToken, protectedResource } from './mcp/http.ts';
import { pluginRoute } from './plugins.ts';
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
  '/api/auth/workload': { method: 'POST', handler: exchangeWorkloadSession },
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
    response =
      SERVED_WHILE_MIGRATING.has(pathname) || (await schemaReady(runtime))
        ? await render({ cspNonce: nonce, client: pageClient(request, runtime, sourceIp), preferences: preferencesIn(request.headers.get('cookie')) })
        : migrating(request);
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

/** What answers below this version's migrations: liveness, and readiness, which is red until they run. */
const SERVED_WHILE_MIGRATING = new Set(['/livez', '/readyz']);

/**
 * Whether the database has every migration this version ships. Each
 * deployment migrates before it deploys (`coffre migrate`), so a new app
 * never serves on a schema it does not have: until then, everything but
 * health answers 503 `migrating`; a database never migrated has no ledger,
 * and is below them too. Asked until it holds, then known. A database that
 * cannot be reached lets the request through, to meet the outage as it would
 * anyway: a page shows its error state, the API answers 503. Any other
 * failure of the question fails the request.
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

/**
 * Spent tokens forgotten a beat: a beat every five minutes forgets up to
 * 60,000 an hour, where one binding's exchanges spend at most 3,600.
 */
export const SPENT_TOKENS_PER_BEAT = 5000;

/**
 * Readiness: the database migrated, and, with an audit watch, what it says
 * (plugins/audit-watch.ts). Without one, nothing more: the log is
 * verified only when someone asks (`coffre verify log`).
 */
async function ready(runtime: CoffreRuntime): Promise<{ ok: boolean } & Record<string, unknown>> {
  const watch = watchOf(runtime);
  try {
    if (!(await migrated(runtime.db))) return watch === null ? { ok: false } : { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false };
  } catch {
    return { ok: false };
  }
  if (watch === null) return { ok: true };
  const said = await watch.hooks.readiness(watch.context());
  return { ...said, ok: said.ok };
}

/**
 * The scheduled run: the audit watch's beat, if the deployment added one;
 * the vault's checkpoint of the log, once, which the beat asked for if it
 * ran, and which keeps every verification a walk from the newest
 * checkpoint (R25); then spent tokens' upkeep. Throws so the scheduler
 * reports failures.
 */
export async function runScheduled(runtime: CoffreRuntime): Promise<void> {
  if (!(await schemaReady(runtime))) throw new Error(MIGRATING);
  const watch = watchOf(runtime);
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
  if (signed !== null && watch === null && signed !== 'the log is empty') throw new Error(`the vault did not checkpoint the audit log: ${signed}`);
  if (pruned !== null) throw new Error(`spent tokens could not be pruned: ${pruned.message}`);
}

/**
 * More of the audit watch's backlog walked, a walk after another, up to
 * `walks`: what Node's scheduled job runs after each run (on Workers, the
 * anchor's Durable Object's alarm). Whether more is left.
 */
export async function walkAuditBacklog(runtime: CoffreRuntime, walks: number): Promise<boolean> {
  const watch = watchOf(runtime);
  if (watch === null) return false;
  for (let i = 0; i < walks; i++) if (!(await watch.hooks.walkOn(watch.context()))) return false;
  return true;
}

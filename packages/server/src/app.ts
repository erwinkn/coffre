import type { CoffreClient } from '@coffre/client';

import { ApiError, badRequest } from './api/errors.ts';
import {
  finishSignin,
  logout,
  pollDevice,
  exchangeWorkloadToken,
  signOut,
  startDevice,
  startSignin,
} from './auth-routes.ts';
import { preferencesIn, type Preferences } from '@coffre/core/pages';
import { isUnreachable } from '@coffre/db/dialect';
import { migrated } from '@coffre/db/schema-version';

import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { auditReadiness, writeAuditHeartbeat } from './heartbeat.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { logged } from './logged.ts';
import { mcpEndpoint } from './mcp/endpoint.ts';
import { authorizationServer, oauthRegister, oauthRevoke, oauthToken, protectedResource } from './mcp/http.ts';
import type { CoffreRuntime } from './runtime.ts';
import { cspNonce, setSecurityHeaders } from './security-headers.ts';


type Handler = (request: Request, runtime: CoffreRuntime, sourceIp: string | null) => Promise<Response>;

/** Exact paths outside the route table, and the one method each takes. */
const ROUTES: Record<string, { method: 'GET' | 'POST'; handler: Handler; browserForm?: true }> = {
  '/livez': { method: 'GET', handler: async () => jsonResponse({ ok: true }) },
  '/readyz': {
    method: 'GET',
    handler: async (_request, runtime) => {
      const readiness = await auditReadiness(runtime.db, runtime.vault);
      return jsonResponse(readiness, readiness.ok ? 200 : 503);
    },
  },
  '/api/auth/device': { method: 'POST', handler: startDevice },
  '/api/auth/device/token': { method: 'POST', handler: pollDevice },
  '/api/auth/logout': { method: 'POST', handler: logout },
  '/api/auth/oidc': { method: 'POST', handler: exchangeWorkloadToken },
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
 * coffre's own paths: health, sign-in and the API. Null for any other, a
 * page's, which the deployment's Start app renders.
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
  return null;
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
async function schemaReady(runtime: CoffreRuntime): Promise<boolean> {
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

/** The scheduled audit heartbeat and checkpoint. Throws so the scheduler reports failures. */
export async function runScheduled(runtime: CoffreRuntime): Promise<void> {
  if (!(await schemaReady(runtime))) throw new Error(MIGRATING);
  const ok = await writeAuditHeartbeat(runtime.db, runtime.chainKey, runtime.vault, {
    warn: (value, message) => console.warn(message, value),
  });
  if (!ok) throw new Error('scheduled audit heartbeat failed');
}

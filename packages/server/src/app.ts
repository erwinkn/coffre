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
import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { auditReadiness, writeAuditHeartbeat } from './heartbeat.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
import { cspNonce, withSecurityHeaders } from './security-headers.ts';


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
    if (request.method !== exact.method) return methodNotAllowed([exact.method]);
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

/** What a page renders with: this response's nonce, and the API as the visitor. */
export type PageContext = { cspNonce: string; client: CoffreClient };

/**
 * One request, whatever answers it, a page or one of coffre's routes: it
 * gets a fresh nonce and the visitor's API client to render with, and
 * coffre's security headers on whatever comes back. A page whose render
 * failed because the API answered it 503, the vault or the database out of
 * reach, is an outage, not a bug: it answers 503, as the API did, with the
 * page the UI rendered for the failure, and a moment to wait before trying
 * again. `sourceIp` is the adapter's to vouch for: Cloudflare's header on
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
    // Next.js's internal header, which has let requests skip middleware
    // elsewhere; nothing legitimate sends it here.
    if (request.headers.has('x-middleware-subrequest')) {
      response = errorResponse(badRequest('x-middleware-subrequest is not accepted'));
    } else {
      let unavailable = false;
      const client = pageClient(request, runtime, sourceIp, (status) => (unavailable ||= status === 503));
      const rendered = await render({ cspNonce: nonce, client });
      response = rendered.status === 500 && unavailable ? retryLater(rendered) : rendered;
    }
  } catch (error) {
    response = errorResponse(error);
  }
  const auth = runtime.auth;
  return withSecurityHeaders(request, response, {
    nonce,
    // Access's logout form posts to Access itself.
    formOrigins: auth.mode === 'cloudflare' ? [auth.access.issuer] : [],
  });
}

function retryLater(rendered: Response): Response {
  const headers = new Headers(rendered.headers);
  headers.set('retry-after', '5');
  return new Response(rendered.body, { status: 503, statusText: 'Service Unavailable', headers });
}

/** The scheduled audit heartbeat and checkpoint. Throws so the scheduler reports failures. */
export async function runScheduled(runtime: CoffreRuntime): Promise<void> {
  const ok = await writeAuditHeartbeat(runtime.db, runtime.chainKey, runtime.vault, {
    warn: (value, message) => console.warn(message, value),
  });
  if (!ok) throw new Error('scheduled audit heartbeat failed');
}

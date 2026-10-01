import { ApiError, badRequest } from './api/errors.ts';
import {
  finishSignin,
  logout,
  pollDevice,
  signOut,
  startDevice,
  startSignin,
} from './auth-routes.ts';
import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { auditReadiness, writeAuditHeartbeat } from './heartbeat.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';
import { cspNonce, withSecurityHeaders } from './security-headers.ts';
import type { Ui } from './ui.ts';

export type { Ui };

type Handler = (request: Request, runtime: CoffreRuntime, sourceIp: string | null) => Promise<Response>;

/** Exact paths outside the route table, and the one method each takes. */
const ROUTES: Record<string, { method: 'GET' | 'POST'; handler: Handler; browserForm?: true }> = {
  '/livez': { method: 'GET', handler: async () => jsonResponse({ ok: true }) },
  '/readyz': {
    method: 'GET',
    handler: async (_request, runtime) => {
      const readiness = await auditReadiness(runtime.db);
      return jsonResponse(readiness, readiness.ok ? 200 : 503);
    },
  },
  '/api/auth/device': { method: 'POST', handler: startDevice },
  '/api/auth/device/token': { method: 'POST', handler: pollDevice },
  '/api/auth/logout': { method: 'POST', handler: logout },
  // Posted by coffre's own pages, with the browser's cookies.
  '/auth/signout': { method: 'POST', handler: signOut, browserForm: true },
};

const PROVIDER_ROUTE = /^\/auth\/(signin|callback)\/([a-z0-9-]{1,32})$/;

async function route(request: Request, runtime: CoffreRuntime, sourceIp: string | null, ui: Ui, nonce: string) {
  // Next.js's internal header, which has let requests skip middleware
  // elsewhere; nothing legitimate sends it here.
  if (request.headers.has('x-middleware-subrequest')) {
    return errorResponse(badRequest('x-middleware-subrequest is not accepted'));
  }
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

  if (request.method !== 'GET' && request.method !== 'HEAD') return methodNotAllowed(['GET']);
  return ui.fetch(request, { context: { cspNonce: nonce, client: pageClient(request, runtime, sourceIp) } });
}

/**
 * One request, on either runtime: health, sign-in, the API, then pages.
 * `sourceIp` is the adapter's to vouch for: Cloudflare's header on Workers,
 * the socket's address on Node.
 */
export async function handleRequest(
  request: Request,
  runtime: CoffreRuntime,
  ui: Ui,
  sourceIp: string | null,
): Promise<Response> {
  const nonce = cspNonce();
  let response: Response;
  try {
    response = await route(request, runtime, sourceIp, ui, nonce);
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

/**
 * The scheduled job, every few minutes: the audit heartbeat and checkpoint,
 * and syncs that are due. They are independent: a destination that is down
 * must not stop the heartbeat, and a failed heartbeat must not hold back
 * pending syncs. Throws when the heartbeat failed, so the scheduler reports it.
 */
export async function runScheduled(runtime: CoffreRuntime): Promise<void> {
  const [heartbeat, syncs] = await Promise.allSettled([
    writeAuditHeartbeat(runtime.db, runtime.chainKey, runtime.vault, {
      warn: (value, message) => console.warn(message, value),
    }),
    runtime.syncs.reconcile(),
  ]);
  if (syncs.status === 'rejected') console.error('scheduled syncs failed', syncs.reason);
  if (heartbeat.status === 'rejected' || !heartbeat.value) {
    throw new Error('scheduled audit heartbeat failed', {
      cause: heartbeat.status === 'rejected' ? heartbeat.reason : undefined,
    });
  }
}

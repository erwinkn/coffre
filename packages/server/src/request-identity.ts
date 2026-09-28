import { createMiddleware } from '@tanstack/react-start';

import { accessTokenForRequest, authenticateRequest, type AuthenticatedIdentity } from './auth.ts';
import { badRequest } from './api/errors.ts';
import { errorResponse } from './http.ts';
import { getRuntime } from './runtime.ts';

// `start.ts` imports this module, and the browser bundle gets `start.ts` too.
// Start strips the `.server()` body below from that bundle, and with it the
// only uses of `auth.ts` and `runtime.ts`, so they, and the database code they
// reach, stay on the server. Anything this module uses outside that body
// ships to the browser: keep it to plain functions like the path checks.
// `scripts/check-client-bundle.mjs` fails the build if the database leaks.

export const PUBLIC_HEALTH_PATHS = new Set(['/livez', '/readyz']);

type AnonymousRequestContext = {
  principal: null;
  registered: false;
  caller: null;
  requestId: string;
  sourceIp: string | null;
};

export type RequestIdentityContext =
  | AuthenticatedIdentity
  | AnonymousRequestContext;

const requestContexts = new WeakMap<Request, RequestIdentityContext>();

export function isPublicHealthPath(pathname: string): boolean {
  return PUBLIC_HEALTH_PATHS.has(pathname);
}

export function isApiPath(pathname: string): boolean {
  return pathname === '/api' || pathname.startsWith('/api/');
}

function anonymousContext(requestId = crypto.randomUUID()): AnonymousRequestContext {
  return { principal: null, registered: false, caller: null, requestId, sourceIp: null };
}

export function requestIdentityContextFor(
  request: Request,
): RequestIdentityContext | undefined {
  return requestContexts.get(request);
}

function remember(request: Request, context: RequestIdentityContext): void {
  requestContexts.set(request, context);
}

/**
 * Pages render signed out (the sign-in page itself), and sign-in, callback
 * and sign-out routes check whatever session they need themselves.
 */
export function allowsAnonymousTransport(
  request: Request,
  handlerType: 'serverFn' | 'router',
  pathname: string,
): boolean {
  if (handlerType === 'router' && pathname.startsWith('/auth/')) return true;
  return request.method === 'GET' || request.method === 'HEAD';
}

/**
 * Who is asking, for pages and sign-in routes. `/api` is not its business:
 * the API authenticates every call itself, from the page's own server render
 * too, so it has one front door; see `fetch-api.ts`.
 */
export const requestIdentityMiddleware = createMiddleware().server(
  async ({ request, pathname, handlerType, next }) => {
    if (request.headers.has('x-middleware-subrequest')) {
      return errorResponse(badRequest('x-middleware-subrequest is not accepted'));
    }

    if (isPublicHealthPath(pathname) || isApiPath(pathname)) {
      const context: RequestIdentityContext = anonymousContext();
      remember(request, context);
      return next({ context: { coffreRequest: context } });
    }

    const runtime = getRuntime();
    const token = accessTokenForRequest(request, runtime.auth);
    if (
      token === null &&
      allowsAnonymousTransport(request, handlerType, pathname)
    ) {
      const context: RequestIdentityContext = anonymousContext();
      remember(request, context);
      return next({ context: { coffreRequest: context } });
    }

    const result = await authenticateRequest(request, runtime, crypto.randomUUID(), token);
    if (result instanceof Response) {
      // An expired or revoked session on a page is someone to send to the
      // sign-in page, not a JSON error to show them.
      if (result.status === 401 && allowsAnonymousTransport(request, handlerType, pathname)) {
        const context: RequestIdentityContext = anonymousContext();
        remember(request, context);
        return next({ context: { coffreRequest: context } });
      }
      return result;
    }
    remember(request, result);
    return next({
      context: { coffreRequest: result as RequestIdentityContext },
    });
  },
);

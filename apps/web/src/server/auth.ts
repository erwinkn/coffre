import { createMiddleware } from '@tanstack/react-start';

import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { ACCESS_JWT_HEADER } from '../../../../packages/core/src/identity/types.ts';
import type { AuthConfig } from '../../../../packages/core/src/identity/auth-mode.ts';
import { loadCaller, type Caller } from './api/caller.ts';
import { ApiError, badRequest } from './api/errors.ts';
import { errorResponse } from './http.ts';
import { getRuntime, type CoffreRuntime } from './runtime.ts';

export const DEV_TOKEN_COOKIE = 'coffre_dev_token';
export const PUBLIC_HEALTH_PATHS = new Set(['/livez', '/readyz']);
/**
 * API endpoints a caller reaches before it has a credential: the CLI's
 * device-login start and poll.
 */
export const PUBLIC_API_PATHS = new Set(['/api/auth/device', '/api/auth/device/token']);

type AnonymousRequestContext = {
  principal: null;
  registered: false;
  caller: null;
  requestId: string;
  sourceIp: string | null;
};

/** A verified caller, loaded once with everything they hold. */
export type AuthenticatedIdentity = {
  principal: Principal;
  registered: boolean;
  caller: Caller;
  requestId: string;
  sourceIp: string | null;
  /** The coffre credential that authenticated this request, in signin mode. */
  credentialId: string | null;
};

export type RequestIdentityContext =
  | AuthenticatedIdentity
  | AnonymousRequestContext;

type AuthenticationRuntime = Pick<
  CoffreRuntime,
  'auth' | 'verifier' | 'db' | 'rootAdmins'
>;

const requestContexts = new WeakMap<Request, RequestIdentityContext>();

export function isPublicHealthPath(pathname: string): boolean {
  return PUBLIC_HEALTH_PATHS.has(pathname);
}

export function isApiPath(pathname: string): boolean {
  return pathname === '/api' || pathname.startsWith('/api/');
}

function cookieValue(request: Request, name: string): string | null {
  const raw = request.headers.get('cookie');
  if (raw === null) return null;
  for (const part of raw.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    const value = part.slice(separator + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * The browser session cookie in signin mode. Over HTTPS it carries the
 * `__Host-` prefix, which makes the browser refuse it unless it is Secure,
 * host-only and path-wide: no subdomain can plant or shadow it. Plain HTTP,
 * which config allows on loopback only, cannot use the prefix.
 */
export function sessionCookieName(auth: AuthConfig): string {
  return auth.mode === 'signin' && auth.signin.publicUrl.startsWith('https:')
    ? '__Host-coffre_session'
    : 'coffre_session';
}

export function readCookie(request: Request, name: string): string | null {
  return cookieValue(request, name);
}

export function bearerToken(request: Request): string | null {
  const match = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  return match === null ? null : match[1];
}

export function accessTokenForRequest(request: Request, auth: AuthConfig): string | null {
  if (auth.mode === 'cloudflare') {
    const token = request.headers.get(ACCESS_JWT_HEADER);
    return token === null || token.length === 0 ? null : token;
  }
  if (auth.mode === 'signin') return cookieValue(request, sessionCookieName(auth));
  return cookieValue(request, DEV_TOKEN_COOKIE);
}

/**
 * The API takes a header, the UI a cookie. In signin mode that header is a
 * standard bearer token; in dev mode it is the Access-shaped assertion the
 * dev IdP mints.
 */
export function accessTokenForBoundary(
  request: Request,
  auth: AuthConfig,
  pathname: string,
): string | null {
  if (auth.mode === 'signin' && isApiPath(pathname)) return bearerToken(request);
  if (auth.mode === 'dev' && isApiPath(pathname)) {
    const token = request.headers.get(ACCESS_JWT_HEADER);
    return token === null || token.length === 0 ? null : token;
  }
  return accessTokenForRequest(request, auth);
}

/**
 * The caller's address, from Cloudflare's own header. The edge overwrites
 * `cf-connecting-ip` on every request, so a client cannot choose it; in dev
 * mode nothing sits in front to vouch for it.
 */
export function trustedSourceIp(request: Request, auth: AuthConfig): string | null {
  if (auth.mode === 'dev') return null;
  const value = request.headers.get('cf-connecting-ip');
  if (value === null || value.length > 45) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255) ? value : null;
  }
  return /^[0-9a-f]+(?::[0-9a-f]*)+$/i.test(value) ? value : null;
}

function unauthenticated(auth: AuthConfig): Response {
  return errorResponse(
    new ApiError(
      'unauthenticated',
      auth.mode === 'cloudflare' ? 'sign in through Cloudflare Access first' : 'sign in first',
    ),
  );
}

const registrationRequired = () =>
  errorResponse(new ApiError('registration_required', 'you are signed in, but not a member here'));

function anonymousContext(requestId = crypto.randomUUID()): AnonymousRequestContext {
  return { principal: null, registered: false, caller: null, requestId, sourceIp: null };
}

export async function authenticateRequest(
  request: Request,
  runtime: AuthenticationRuntime,
  requestId = crypto.randomUUID(),
  token = accessTokenForRequest(request, runtime.auth),
): Promise<AuthenticatedIdentity | Response> {
  if (token === null) return unauthenticated(runtime.auth);

  const sourceIp = trustedSourceIp(request, runtime.auth);
  let principal: Principal;
  let credentialId: string | null = null;
  try {
    const verified = (await runtime.verifier.verify(token, { sourceIp })) as Principal & {
      credentialId?: string;
    };
    ({ credentialId = null, ...principal } = verified);
  } catch {
    return errorResponse(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'));
  }

  try {
    const caller = await loadCaller(runtime.db, principal, runtime.rootAdmins);
    return {
      principal,
      registered: caller.registered,
      caller,
      requestId,
      sourceIp,
      credentialId,
    };
  } catch {
    return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
}

export function requestIdentityContextFor(
  request: Request,
): RequestIdentityContext | undefined {
  return requestContexts.get(request);
}

// Routes receive their Request directly. Server functions use getRequest().
export const requestIdentityContext = requestIdentityContextFor;

function remember(request: Request, context: RequestIdentityContext): void {
  requestContexts.set(request, context);
}

export function allowsAnonymousTransport(
  request: Request,
  handlerType: 'serverFn' | 'router',
  pathname: string,
): boolean {
  if (handlerType === 'serverFn') return true;
  // Sign-in, callback and sign-out routes check whatever session they need
  // themselves; the device endpoints are how a CLI gets a credential at all.
  if (pathname.startsWith('/auth/') || PUBLIC_API_PATHS.has(pathname)) return true;
  return (
    (request.method === 'GET' || request.method === 'HEAD') &&
    !isApiPath(pathname)
  );
}

export const requestIdentityMiddleware = createMiddleware().server(
  async ({ request, pathname, handlerType, next }) => {
    if (request.headers.has('x-middleware-subrequest')) {
      return errorResponse(badRequest('x-middleware-subrequest is not accepted'));
    }

    if (isPublicHealthPath(pathname)) {
      const context: RequestIdentityContext = anonymousContext();
      remember(request, context);
      return next({ context: { coffreRequest: context } });
    }

    const runtime = getRuntime();
    const token = accessTokenForBoundary(request, runtime.auth, pathname);
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
    if (!result.registered && isApiPath(pathname)) {
      return registrationRequired();
    }
    remember(request, result);
    return next({
      context: { coffreRequest: result as RequestIdentityContext },
    });
  },
);

export const registeredIdentityMiddleware = createMiddleware({
  type: 'function',
}).server(async ({ next, context }) => {
  const runtime = getRuntime();
  const identity = (context as unknown as { coffreRequest?: RequestIdentityContext })
    .coffreRequest;
  if (
    identity?.principal !== null &&
    identity?.principal !== undefined &&
    identity.registered
  ) {
    return next();
  }
  throw identity?.principal === null || identity?.principal === undefined
    ? unauthenticated(runtime.auth)
    : registrationRequired();
});

import { createMiddleware } from '@tanstack/react-start';

import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { ACCESS_JWT_HEADER } from '../../../../packages/core/src/identity/types.ts';
import type { AuthConfig } from '../../../../packages/core/src/identity/auth-mode.ts';
import type { RequestContext } from './services/secrets.ts';
import { jsonResponse } from './http.ts';
import { getRuntime, type CoffreRuntime } from './runtime.ts';

export const DEV_TOKEN_COOKIE = 'coffre_dev_token';
export const PUBLIC_HEALTH_PATHS = new Set(['/livez', '/readyz']);

type AnonymousRequestContext = Omit<RequestContext, 'principal'> & {
  principal: null;
  registered: false;
};

type AuthenticatedRequestContext = RequestContext & {
  registered: boolean;
};

export type RequestIdentityContext =
  | AuthenticatedRequestContext
  | AnonymousRequestContext;

type AuthenticationRuntime = Pick<
  CoffreRuntime,
  'auth' | 'verifier' | 'pool' | 'rootAdmins'
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

export function accessTokenForRequest(request: Request, auth: AuthConfig): string | null {
  if (auth.mode === 'cloudflare') {
    const token = request.headers.get(ACCESS_JWT_HEADER);
    return token === null || token.length === 0 ? null : token;
  }
  return cookieValue(request, DEV_TOKEN_COOKIE);
}

/** Direct local CLI calls use the Access-shaped assertion; the UI uses its cookie. */
export function accessTokenForBoundary(
  request: Request,
  auth: AuthConfig,
  pathname: string,
): string | null {
  if (auth.mode === 'dev' && isApiPath(pathname)) {
    const token = request.headers.get(ACCESS_JWT_HEADER);
    return token === null || token.length === 0 ? null : token;
  }
  return accessTokenForRequest(request, auth);
}

function trustedSourceIp(request: Request, auth: AuthConfig): string | null {
  if (auth.mode !== 'cloudflare') return null;
  const value = request.headers.get('cf-connecting-ip');
  if (value === null || value.length > 45) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255) ? value : null;
  }
  return /^[0-9a-f]+(?::[0-9a-f]*)+$/i.test(value) ? value : null;
}

function isRootAdmin(principal: Principal, rootAdmins: readonly string[]): boolean {
  return principal.type === 'user' && rootAdmins.includes(principal.id);
}

async function isRegistered(
  runtime: AuthenticationRuntime,
  principal: Principal,
): Promise<boolean> {
  if (isRootAdmin(principal, runtime.rootAdmins)) return true;
  const result = await runtime.pool.query<{ active: boolean }>(
    `SELECT active
       FROM principals
      WHERE principal_type = $1
        AND principal_id = $2
      LIMIT 1`,
    [principal.type, principal.id],
  );
  return result.rows[0]?.active === true;
}

function unauthenticated(auth: AuthConfig): Response {
  return jsonResponse(
    {
      error:
        auth.mode === 'cloudflare' ? 'cloudflare_access_required' : 'unauthenticated',
    },
    401,
  );
}

function anonymousContext(requestId = crypto.randomUUID()): AnonymousRequestContext {
  return { principal: null, registered: false, requestId, sourceIp: null };
}

export async function authenticateRequest(
  request: Request,
  runtime: AuthenticationRuntime,
  requestId = crypto.randomUUID(),
  token = accessTokenForRequest(request, runtime.auth),
): Promise<AuthenticatedRequestContext | Response> {
  if (token === null) return unauthenticated(runtime.auth);

  let principal: Principal;
  try {
    principal = await runtime.verifier.verify(token);
  } catch {
    return jsonResponse({ error: 'unauthenticated' }, 401);
  }

  try {
    const registered = await isRegistered(runtime, principal);
    return {
      principal,
      registered,
      requestId,
      sourceIp: trustedSourceIp(request, runtime.auth),
    };
  } catch {
    return jsonResponse({ error: 'authentication_unavailable' }, 503);
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

function allowsAnonymousDevTransport(
  request: Request,
  handlerType: 'serverFn' | 'router',
  pathname: string,
): boolean {
  if (handlerType === 'serverFn') return true;
  return (
    (request.method === 'GET' || request.method === 'HEAD') &&
    !isApiPath(pathname)
  );
}

export const requestIdentityMiddleware = createMiddleware().server(
  async ({ request, pathname, handlerType, next }) => {
    if (request.headers.has('x-middleware-subrequest')) {
      return jsonResponse({ error: 'bad_request' }, 400);
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
      runtime.auth.mode === 'dev' &&
      allowsAnonymousDevTransport(request, handlerType, pathname)
    ) {
      const context: RequestIdentityContext = anonymousContext();
      remember(request, context);
      return next({ context: { coffreRequest: context } });
    }

    const result = await authenticateRequest(request, runtime, crypto.randomUUID(), token);
    if (result instanceof Response) return result;
    if (!result.registered && isApiPath(pathname)) {
      return jsonResponse({ error: 'registration_required' }, 403);
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
    : jsonResponse({ error: 'registration_required' }, 403);
});

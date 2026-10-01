import { createClient, type CoffreClient } from '@coffre/client';
import { ACCESS_JWT_HEADER, type AuthConfig, type SigninBrand } from '@coffre/core/identity';

import { ApiError } from './api/errors.ts';
import { serveApi } from './api/router.ts';
import {
  authenticateRequest,
  bearerToken,
  readCookie,
  registrationRequired,
  sessionCookieName,
  unauthenticated,
  type AuthenticatedIdentity,
} from './auth.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { apiContext, type CoffreRuntime } from './runtime.ts';
import { publicProviders } from './signin.ts';

/** The cookie Cloudflare Access keeps its session in, on the browser. */
const ACCESS_COOKIE = 'CF_Authorization';

/**
 * How a request proves who it is. A cookie is `ambient`: the browser attaches
 * it to every request to this origin, whichever site's page sent it. A header
 * is only there when the caller put it there.
 */
export type ApiCredential = { token: string; ambient: boolean };

const nonEmpty = (value: string | null) => (value === null || value.length === 0 ? null : value);

/**
 * The credential an API call carries. With coffre's sign-in, the CLI and
 * service tokens send a bearer token, and the browser the cookie its sign-in
 * set. Behind Cloudflare Access every request carries Access's assertion,
 * and the browser's carry Access's cookie as well, which is what gives them
 * away.
 */
export function apiCredential(request: Request, auth: AuthConfig): ApiCredential | null {
  if (auth.mode === 'cloudflare') {
    const token = nonEmpty(request.headers.get(ACCESS_JWT_HEADER));
    return token === null ? null : { token, ambient: readCookie(request, ACCESS_COOKIE) !== null };
  }
  const header = bearerToken(request);
  if (header !== null) return { token: header, ambient: false };
  const cookie = readCookie(request, sessionCookieName(auth));
  return cookie === null ? null : { token: cookie, ambient: true };
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Whether the browser vouches that a page of this origin sent the request.
 * Every current browser sends `Sec-Fetch-Site`; older ones at least send
 * `Origin` on a POST. A request with neither is not from a page we can
 * vouch for.
 */
export function isSameOrigin(request: Request, publicUrl: string): boolean {
  const site = request.headers.get('sec-fetch-site');
  if (site !== null) return site === 'same-origin';
  return request.headers.get('origin') === publicUrl;
}

/**
 * Who is calling the API, or the response that turns them away. A change
 * made with a cookie must come from one of coffre's own pages: otherwise any
 * site the person visits could make it in their name (CSRF). Headers need no
 * such check, since another site's page cannot make the browser send them.
 */
export async function apiCaller(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
): Promise<AuthenticatedIdentity | Response> {
  const credential = apiCredential(request, runtime.auth);
  if (credential === null) return unauthenticated(runtime.auth);
  if (credential.ambient && !SAFE_METHODS.has(request.method) && !isSameOrigin(request, runtime.publicUrl)) {
    return errorResponse(
      new ApiError('cross_origin', 'a change sent with a browser session must come from coffre itself'),
    );
  }
  return authenticateRequest(request, runtime, crypto.randomUUID(), credential.token, sourceIp);
}

/**
 * How this instance signs people in, which the sign-in page, the account
 * page and the CLI read rather than being told a mode. Exactly one is set.
 */
export type AuthInfo = {
  /** coffre's own sign-in: the page's heading, and a button per provider. */
  signin: {
    title: string;
    note: string | null;
    providers: { id: string; label: string; brand: SigninBrand }[];
  } | null;
  /** Cloudflare Access in front: whether it forwarded an assertion with this request. */
  access: { assertion: boolean } | null;
};

function authInfo(request: Request, runtime: CoffreRuntime): AuthInfo {
  const { signin } = runtime;
  return {
    signin:
      signin === null
        ? null
        : { title: signin.config.page.title, note: signin.config.page.note, providers: publicProviders(signin.config) },
    access:
      runtime.auth.mode === 'cloudflare' ? { assertion: nonEmpty(request.headers.get(ACCESS_JWT_HEADER)) !== null } : null,
  };
}

/**
 * The API: `/api/*` but sign-in's own routes. The browser reaches it over
 * HTTP, and a page's server render in process, through `pageClient`.
 * `/api/me` also answers someone signed in who is not a member, and
 * `/api/auth` anyone at all: the sign-in page needs it before there is anyone
 * to be.
 */
export async function fetchApi(
  request: Request,
  runtime: CoffreRuntime,
  options: { sourceIp: string | null },
): Promise<Response> {
  try {
    const { pathname } = new URL(request.url);
    if (pathname === '/api/auth') {
      return request.method === 'GET' ? jsonResponse(authInfo(request, runtime)) : methodNotAllowed(['GET']);
    }
    const identity = await apiCaller(request, runtime, options.sourceIp);
    if (identity instanceof Response) return identity;
    if (!identity.registered && !(request.method === 'GET' && pathname === '/api/me')) {
      return registrationRequired();
    }
    return await serveApi(request, apiContext(runtime, identity));
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * The page's credential, and nothing else of its request: the session
 * cookie, or Access's assertion behind Cloudflare. Every other cookie and
 * header stays behind.
 */
export function pageCredential(page: Request, auth: AuthConfig): Record<string, string> {
  if (auth.mode === 'cloudflare') {
    const token = nonEmpty(page.headers.get(ACCESS_JWT_HEADER));
    return token === null ? {} : { [ACCESS_JWT_HEADER]: token };
  }
  const name = sessionCookieName(auth);
  const token = readCookie(page, name);
  return token === null ? {} : { cookie: `${name}=${encodeURIComponent(token)}` };
}

/**
 * The client a page renders with on the server: each call goes straight to
 * `fetchApi`, in process, as the visitor. It forwards their credential as the
 * browser sent it, so a cookie stays a cookie: a change attempted during a
 * render has no origin to show and is refused, as from any other site. The
 * visitor's address rides alongside, not as a header, for the audit log and
 * the session's last-seen address.
 */
export function pageClient(page: Request, runtime: CoffreRuntime, sourceIp: string | null): CoffreClient {
  const credential = pageCredential(page, runtime.auth);
  return createClient({
    url: new URL(page.url).origin,
    headers: () => credential,
    transport: (request) => fetchApi(request, runtime, { sourceIp }),
  });
}

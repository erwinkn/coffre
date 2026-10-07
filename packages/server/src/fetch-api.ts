import { createClient, type CoffreClient } from '@coffre/client';
import { ACCESS_JWT_HEADER, tokenKind, type AuthConfig, type SigninBrand } from '@coffre/core/identity';

import { ApiError } from './api/errors.ts';
import { routeParts, serveApi } from './api/router.ts';
import {
  authenticateRequest,
  bearerToken,
  readCookie,
  accessTampered,
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
 * Reads only coffre's own pages make, which do work for the asking: the
 * consent page's describes a client, fetching its metadata document, and an
 * approval's reads what its change would replace, as the person. Asked
 * with a cookie, they take the same-origin rule a change does, so another
 * site's `<img>` cannot make coffre fetch a URL, or read, in a signed-in
 * person's name. By their route, as the router reads a path, `:id` any one
 * segment: `/api//oauth/authorizations/` is the same read.
 */
const PAGE_READS = ['oauth/authorizations', 'approvals/:id'].map((route) => route.split('/'));

/** Whether a request is to one of `routes`, by its path as the router reads it. */
function routeIn(request: Request, routes: readonly string[][]): boolean {
  let parts: string[];
  try {
    parts = routeParts(new URL(request.url).pathname);
  } catch {
    // A path that does not decode is no route: the router answers 400, and reads nothing.
    return false;
  }
  return routes.some((route) => route.length === parts.length && route.every((part, index) => part.startsWith(':') || part === parts[index]));
}

const isPageRead = (request: Request) => routeIn(request, PAGE_READS);

/**
 * Routes only the browser reaches: an approval is decided on coffre's page,
 * by its person, not by an app holding their CLI session. With
 * coffre's sign-in, the credential must be a browser session, which the
 * CLI never holds. Behind Cloudflare Access, it must come with Access's
 * cookie, which a client that is no browser can set too: there, this keeps
 * the honest CLI out, not a determined one.
 */
const BROWSER_ONLY = [['approvals', ':id']];

function isBrowser(credential: ApiCredential, auth: AuthConfig): boolean {
  return auth.mode === 'cloudflare' ? credential.ambient : tokenKind(credential.token) === 'browser';
}

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
 * The few reads that do work for the asking (`PAGE_READS`) take the rule
 * too. `authenticate` checks the credential; a page's render passes one that
 * checks it once for all its calls, and is `inProcess` (`pageClient`).
 */
export async function apiCaller(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  authenticate: Authenticate = (token) => authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp),
  inProcess = false,
): Promise<AuthenticatedIdentity | Response> {
  const credential = apiCredential(request, runtime.auth);
  if (credential === null) return unauthenticated(runtime.auth);
  // A change, always; a page's read, unless it is the page's own render, in process, which is coffre itself.
  const checked = !SAFE_METHODS.has(request.method) || (isPageRead(request) && !inProcess);
  if (credential.ambient && checked && !isSameOrigin(request, runtime.publicUrl)) {
    return errorResponse(
      new ApiError('cross_origin', SAFE_METHODS.has(request.method) ? 'this, asked with a browser session, must come from coffre itself' : 'a change sent with a browser session must come from coffre itself'),
    );
  }
  if (routeIn(request, BROWSER_ONLY) && !isBrowser(credential, runtime.auth)) {
    return errorResponse(new ApiError('forbidden', 'open this on coffre, signed in in your browser', 'browser_only'));
  }
  return authenticate(credential.token);
}

/** How a credential becomes its caller, or the response that turns them away. */
type Authenticate = (token: string) => Promise<AuthenticatedIdentity | Response>;

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
  /** `inProcess`: a page's render (`pageClient`), whose cookie the browser sent to coffre's own page. */
  options: { sourceIp: string | null; authenticate?: Authenticate; inProcess?: boolean },
): Promise<Response> {
  try {
    const { pathname } = new URL(request.url);
    if (pathname === '/api/auth') {
      return request.method === 'GET' ? jsonResponse(authInfo(request, runtime)) : methodNotAllowed(['GET']);
    }
    const identity = await apiCaller(request, runtime, options.sourceIp, options.authenticate, options.inProcess);
    if (identity instanceof Response) return identity;
    if (!identity.registered && !(request.method === 'GET' && pathname === '/api/me')) {
      return identity.caller.tampered ? accessTampered() : registrationRequired();
    }
    return await serveApi(request, apiContext(runtime, identity));
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * The page's credential, and nothing else of its request: the session
 * cookie, or Access's assertion and cookie behind Cloudflare. Every other
 * cookie and header stays behind.
 */
export function pageCredential(page: Request, auth: AuthConfig): Record<string, string> {
  if (auth.mode === 'cloudflare') {
    const token = nonEmpty(page.headers.get(ACCESS_JWT_HEADER));
    const cookie = readCookie(page, ACCESS_COOKIE);
    // Access's cookie too, when the browser sent it: what tells a browser's page from any other caller.
    return token === null ? {} : { [ACCESS_JWT_HEADER]: token, ...(cookie === null ? {} : { cookie: `${ACCESS_COOKIE}=${encodeURIComponent(cookie)}` }) };
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
 * the session's last-seen address. `answered` hears each answer's status.
 *
 * The render is one request: its calls carry one credential, which is
 * checked once, by one call to the vault, and its caller is every call's.
 * Each call still passes the checks of its own method.
 */
export function pageClient(
  page: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
): CoffreClient {
  const credential = pageCredential(page, runtime.auth);
  // A page is rendered for a top-level navigation, or for a caller that is no
  // browser. One embedded in another site, an iframe or an image, makes none
  // of the reads that do work for the asking, whatever its credential.
  const dest = page.headers.get('sec-fetch-dest');
  const embedded = dest !== null && dest !== 'document';
  let checked: Promise<AuthenticatedIdentity | Response> | undefined;
  const authenticate: Authenticate = async (token) => {
    checked ??= authenticateRequest(page, runtime, crypto.randomUUID(), token, sourceIp);
    const identity = await checked;
    // A refusal's body is read once: each call answers with its own copy.
    return identity instanceof Response ? identity.clone() : identity;
  };
  return createClient({
    url: new URL(page.url).origin,
    headers: () => credential,
    transport: async (request) =>
      embedded && isPageRead(request)
        ? errorResponse(new ApiError('cross_origin', 'this is read only by a page opened on its own, not one embedded in another site'))
        : fetchApi(request, runtime, { sourceIp, authenticate, inProcess: true }),
  });
}

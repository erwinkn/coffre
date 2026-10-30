import { createClient, type CoffreClient } from '@coffre/client';
import { ACCESS_JWT_HEADER, tokenKind, type AuthConfig, type SigninBrand, type TokenKind } from '@coffre/core/identity';
import { personalOf } from '@coffre/core/schemas';
import type { Purpose } from '@coffre/core/vault';

import { AccessChanged } from './accesses.ts';
import type { ApiContext } from './api/context.ts';
import { ApiError } from './api/errors.ts';
import { parsePath, type Path } from './api/paths.ts';
import { Render } from './api/render.ts';
import { API_BODY_BYTES, routeParts, serveApi } from './api/router.ts';
import { revealInput } from './api/routes.ts';
import {
  authenticateRequest,
  headerToken,
  readCookie,
  accessTampered,
  refusedByKind,
  registrationRequired,
  sessionCookie,
  sessionCookieName,
  unauthenticated,
  type AuthenticatedIdentity,
} from './auth.ts';
import { errorResponse, jsonResponse, methodNotAllowed, parseJsonBody, readLimitedBytes } from './http.ts';
import { useByName } from './named-use.ts';
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
  // A bearer token, or a workload's session with its key's proof (`Authorization: DPoP`).
  const header = headerToken(request);
  if (header !== null) return { token: header, ambient: false };
  const cookie = sessionCookie(request, auth);
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
 * The reads that decide on the vault's answer about their caller kept from
 * an earlier request, as the vault checks it when it opens their values:
 * one vault call, not two (`accessFor`).
 */
const RECALLING = [['reveals']];

/** The credentials whose reveal of one key the vault serves by name: a person's or a service's, never a workload's. */
const NAMED_KINDS: readonly TokenKind[] = ['browser', 'cli', 'personal', 'service'];

/**
 * The one key a reveal's body names, and where: its path's (`market/dev/API_KEY`, to reveal) or a list of one
 * (`market/dev`, `keys: ['API_KEY']`, as `coffre export --keys` runs it). Null for anything else, a personal config
 * included, or a body the route refuses: the request goes as ever.
 */
function namedReveal(body: Uint8Array): { place: { project: string; environment: string }; key: string; purpose: Purpose } | null {
  let input: unknown;
  try {
    // Decoded as the route decodes it (`readJson`).
    input = parseJsonBody(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
  const parsed = revealInput.safeParse(input);
  if (!parsed.success) return null;
  const { path: asked, keys } = parsed.data;
  let path: Path;
  try {
    path = parsePath(asked, [2, 3]);
  } catch {
    return null;
  }
  const key = keys === undefined ? path.key : path.key === undefined && keys.length === 1 ? keys[0] : undefined;
  if (key === undefined || path.environment === undefined || personalOf(path.environment) !== null) return null;
  return { place: { project: path.project, environment: path.environment }, key, purpose: path.key === undefined ? 'run' : 'reveal' };
}

/**
 * The reads that only show their caller, and decide nothing: who they
 * are, and what they hold where, to choose which places and buttons to
 * show. The app reads their caller from the vault's rows itself, asking
 * nothing of the vault (`answerShown`), and the caller is `unchecked`,
 * which no other route takes (`serveApi`): whatever it then asks for, the
 * vault decides. A page's render, an MCP connection or a plugin asks with
 * the caller it checked already, and its `me` shows that one.
 */
const SHOWING = [['me']];

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
  /**
   * `inProcess`: a page's render (`pageClient`), whose cookie the browser sent to coffre's own page.
   * `recall: false`: asked again, its caller asked of the vault (`RECALLING`).
   * `render`: the page's render it is one call of, whose calls read the instance's places once.
   */
  options: { sourceIp: string | null; authenticate?: Authenticate; inProcess?: boolean; recall?: false; render?: Render },
): Promise<Response> {
  const recall = options.recall !== false && options.authenticate === undefined && request.method === 'POST' && routeIn(request, RECALLING);
  const shows = options.authenticate === undefined && request.method === 'GET' && routeIn(request, SHOWING);
  // A request decided on a kept answer, which may start over: its body, read once within the API's bound, kept for that.
  let again: Request | null = null;
  try {
    const { pathname } = new URL(request.url);
    if (pathname === '/api/auth') {
      return request.method === 'GET' ? jsonResponse(authInfo(request, runtime)) : methodNotAllowed(['GET']);
    }
    // Its bytes, read once within the bound, not teed: a branch left unread would hold back the cancel of a body past it,
    // which then never answers. Decoded by the route, as any request's.
    const bytes = async (): Promise<Uint8Array<ArrayBuffer> | Response> => {
      try {
        return await readLimitedBytes(request, API_BODY_BYTES);
      } catch (error) {
        // A body refused is answered as for a request that asked who its caller is: its caller asked for now, first.
        const asked = await apiCaller(request, runtime, options.sourceIp, options.authenticate, options.inProcess);
        if (asked instanceof Response) return asked;
        if (!asked.registered) return asked.caller.tampered ? accessTampered() : registrationRequired();
        throw error;
      }
    };
    let authenticate: Authenticate | undefined = recall || shows
      ? (token) => authenticateRequest(request, runtime, crypto.randomUUID(), token, options.sourceIp, recall ? { recall: true } : { shows: 'caller' })
      : options.authenticate;
    // A reveal of one key, by its path or as a list of one, with a coffre credential: the vault's one call by name, which
    // decides on the caller as they are (`useByName`, T145, PR B). Its body is read first, to know the key; only for a
    // credential of a kind it serves by name and not refused for its kind alone, read before anything else is.
    let body: Uint8Array<ArrayBuffer> | null = null;
    let named: ApiContext['named'];
    const credential = recall && runtime.vault.useNamed !== undefined ? apiCredential(request, runtime.auth) : null;
    const kind = credential === null ? null : tokenKind(credential.token);
    if (credential !== null && kind !== null && NAMED_KINDS.includes(kind) && refusedByKind(runtime, credential.token) === null) {
      const read = await bytes();
      if (read instanceof Response) return read;
      body = read;
      const asked = namedReveal(body);
      const recalled = authenticate!;
      if (asked !== null) {
        authenticate = async (token) => {
          const used = await useByName(runtime, request, options.sourceIp, token, { kinds: NAMED_KINDS, ...asked });
          if (used === null) return recalled(token);
          named = { decided: used.decided, ahead: used.ahead };
          return used.identity;
        };
      }
    }
    const identity = await apiCaller(request, runtime, options.sourceIp, authenticate, options.inProcess);
    if (identity instanceof Response) return identity;
    if (!identity.registered && !(request.method === 'GET' && pathname === '/api/me')) {
      return identity.caller.tampered ? accessTampered() : registrationRequired();
    }
    let served = request;
    if (body === null && identity.caller.recalled !== undefined) {
      const read = await bytes();
      if (read instanceof Response) return read;
      body = read;
    }
    if (body !== null) {
      const sent = body;
      const replay = () => new Request(request.url, { method: request.method, headers: request.headers, body: sent });
      served = replay();
      if (identity.caller.recalled !== undefined) again = replay();
    }
    const response = await serveApi(served, { ...apiContext(runtime, identity, options.render), ...(named === undefined ? {} : { named }) });
    // Nothing goes back on a kept answer the vault has not vouched for this request.
    await identity.caller.recalled?.confirm();
    if (identity.workload == null) return response;
    // A workload's every answer carries the gate's current nonce, which its next proof signs (section 5.1): on a copy, whose headers are its own.
    const answered = new Response(response.body, response);
    answered.headers.set('dpop-nonce', identity.workload.nonce);
    return answered;
  } catch (error) {
    // Decided on a kept answer that is not the vault's now: nothing was read, logged or answered. Again, asking.
    if (error instanceof AccessChanged && again !== null) return fetchApi(again, runtime, { ...options, recall: false });
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
  const token = sessionCookie(page, auth);
  return token === null ? {} : { cookie: `${sessionCookieName(auth)}=${encodeURIComponent(token)}` };
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
 * checked once, by one call to the vault, and its caller is every call's;
 * and they read the places that caller reaches once (`Render`). Each call
 * still passes the checks of its own method.
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
  const render = new Render();
  const authenticate: Authenticate = async (token) => {
    // With the instance's settings, read with the credential, which its `me` shows.
    checked ??= authenticateRequest(page, runtime, crypto.randomUUID(), token, sourceIp, { shows: 'settings' });
    const identity = await checked;
    // A refusal's body is read once: each call answers with its own copy.
    return identity instanceof Response ? identity.clone() : identity;
  };
  return createClient({
    url: new URL(page.url).origin,
    headers: () => credential,
    transport: async (request) => {
      if (embedded && isPageRead(request)) return errorResponse(new ApiError('cross_origin', 'this is read only by a page opened on its own, not one embedded in another site'));
      if (SAFE_METHODS.has(request.method)) return fetchApi(request, runtime, { sourceIp, authenticate, inProcess: true, render });
      // A change, which a credential that is no cookie may make (an Access service token's): read afresh, and what the
      // render read before it is read afresh after it.
      const answered = await fetchApi(request, runtime, { sourceIp, authenticate, inProcess: true });
      render.forget();
      return answered;
    },
  });
}

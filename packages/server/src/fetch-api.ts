import { createClient, type CoffreClient } from '@coffre/client';
import { tokenKind, type AuthConfig } from '@coffre/core/identity';
import type { Called, Presented } from '@coffre/core/vault';

import { callerOf } from './api/context.ts';
import { ApiError } from './api/errors.ts';
import { serveApi } from './api/router.ts';
import { bearerToken, presented, sessionCookie, sessionCookieName } from './auth.ts';
import { BROWSERS_ONLY, machineCredential, unregisteredMe, type Admission } from './behind-access.ts';
import { errorResponse, jsonResponse } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';
import { dpopToken, provenSession, SessionRefused, sessionStopped } from './sessions.ts';

/**
 * How a request proves who it is. A cookie is `ambient`: the browser attaches
 * it to every request to this origin, whichever site's page sent it. A header
 * is only there when the caller put it there.
 */
export type ApiCredential = { token: string; ambient: boolean };

/**
 * The credential an API call carries: the CLI and service tokens send a
 * bearer token, and the browser the cookie its sign-in set. Behind Access,
 * only the browser's session the check admitted it with (`admit`): a bearer
 * token or a workload's DPoP session is refused, until the CLI and machines
 * are served there.
 */
export function apiCredential(request: Request, auth: AuthConfig, access?: Admission): ApiCredential | null {
  if (auth.mode === 'cloudflare') {
    if (machineCredential(request) !== null) throw new ApiError('unauthenticated', BROWSERS_ONLY);
    return access?.session == null ? null : { token: access.session, ambient: true };
  }
  const header = bearerToken(request);
  if (header !== null) return { token: header, ambient: false };
  const cookie = sessionCookie(request, auth);
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

/** How a call learns who its request is: of the vault, or of the page's render it is part of. */
type AskCaller = (shown: Presented) => Promise<Called>;

/**
 * The API: `/api/*`. The browser reaches it over HTTP, and a page's server
 * render in process, through `pageClient`.
 *
 * It reads the request's credential and hashes it, and that is all it does
 * about who is asking: the vault finds the credential by the hash. Three
 * things are the app's to hold, since only it sees the request. A change
 * made with a cookie must come from one of coffre's own pages: otherwise
 * any site the person visits could make it in their name (CSRF); a header
 * needs no such check, since another site's page cannot make the browser
 * send it. A workload's session comes with its key's proof, which the app
 * holds to the request and its service's gate takes once (`sessions.ts`);
 * every answer then carries the gate's nonce, for the next proof. And a
 * handle reaches the credential proxy alone.
 */
export async function fetchApi(request: Request, runtime: CoffreRuntime, options: { sourceIp: string | null; caller?: AskCaller; page?: Request; access?: Admission }): Promise<Response> {
  const { access } = options;
  let nonce: string | null = null;
  let response: Response;
  try {
    // Behind Access a workload's session is a machine's credential, which `apiCredential` refuses before its row is read or its gate asked.
    const session = runtime.auth.mode === 'cloudflare' ? null : dpopToken(request);
    let shown: Presented;
    let crossSite = false;
    if (session !== null) {
      const proven = await provenSession(request, runtime, session);
      nonce = proven.nonce;
      shown = presented(session, options.sourceIp, proven.proof);
    } else {
      const credential = apiCredential(request, runtime.auth, access);
      if (credential === null) {
        if (access?.unregistered == null) throw new ApiError('unauthenticated', access?.why ?? 'sign in first');
        if (request.method === 'GET' && new URL(request.url).pathname === '/api/me') return jsonResponse(unregisteredMe(access.unregistered));
        throw new ApiError('registration_required', access.why);
      }
      if (credential.ambient && !SAFE_METHODS.has(request.method) && !isSameOrigin(request, runtime.publicUrl)) {
        throw new ApiError('cross_origin', 'a change sent with a browser session must come from coffre itself');
      }
      const kind = tokenKind(credential.token);
      // A handle is a placeholder for secrets in a person's app: the vault would open values for one, so the API turns it away.
      if (kind === 'handle') {
        throw new ApiError('forbidden', "a handle stands in for secrets, and only coffre's credential proxy takes one: sign in to use the API", 'handle');
      }
      // An MCP client's tokens are good at `/mcp` and its token endpoint alone, as 0.14.7 held them.
      if (kind === 'mcp' || kind === 'mcp-refresh') throw new ApiError('unauthenticated', "an MCP client's token is good at /mcp alone");
      // The vault would refuse it anyway, without its proof; this says why.
      if (kind === 'workload') {
        throw new ApiError('unauthenticated', "a workload's session is sent with its key's proof, Authorization: DPoP, never as a bearer token", 'workload');
      }
      shown = presented(credential.token, options.sourceIp);
      crossSite = credential.ambient && !(options.page === undefined ? isSameOrigin(request, runtime.publicUrl) : topLevel(options.page));
    }
    const ask = options.caller ?? ((from) => callerOf(runtime.vault, from));
    // Asked once a request, by the handler that needs it. The promise is this request's alone.
    let asked: Promise<Called> | undefined;
    response = await serveApi(request, {
      db: runtime.db,
      vault: runtime.vault,
      shown,
      caller: () => (asked ??= ask(shown)),
      crossSite,
      auth: runtime.auth,
      rotateAfterDays: runtime.rotateAfterDays,
      transport: runtime.transport,
    });
  } catch (error) {
    // A session the gate took and the vault then stopped is answered as 0.14.7 answered its workload.
    response = error instanceof SessionRefused ? error.response : errorResponse(nonce === null ? error : sessionStopped(error, options.sourceIp));
  }
  if (nonce !== null) return withNonce(response, nonce);
  // Behind Access, a session the vault no longer finds: the browser signs in again on its next request.
  if (response.status === 401 && access?.session != null) access.ended();
  return response;
}

/** An answer to a workload, with the nonce its next proof signs: a response of its own, since another's headers may be immutable. */
function withNonce(response: Response, nonce: string): Response {
  const headers = new Headers(response.headers);
  headers.set('dpop-nonce', nonce);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Whether a page's request is the browser opening it, as a tab or a window:
 * a page another site embeds, as a frame or an image, is that site's doing,
 * not the person's. A browser that sends no `Sec-Fetch-Dest` says neither.
 */
function topLevel(page: Request): boolean {
  const dest = page.headers.get('sec-fetch-dest');
  return dest === null || dest === 'document';
}

/** The page's credential, and nothing else of its request: the session cookie. Every other cookie and header stays behind. */
export function pageCredential(page: Request, auth: AuthConfig): Record<string, string> {
  const token = sessionCookie(page, auth);
  return token === null ? {} : { cookie: `${sessionCookieName(auth)}=${encodeURIComponent(token)}` };
}

/**
 * The client a page renders with on the server: each call goes straight to
 * `fetchApi`, in process, as the visitor. It forwards their credential as the
 * browser sent it, so a cookie stays a cookie: a change attempted during a
 * render has no origin to show and is refused, as from any other site. The
 * visitor's address rides alongside, not as a header, for the log.
 *
 * The render is one request: the vault is asked who its caller is once, by
 * the first call that needs to know, and the answer is every call's.
 * Behind Access, its calls carry the session the page's request was
 * admitted with, as its own route would.
 */
export function pageClient(page: Request, runtime: CoffreRuntime, sourceIp: string | null, access?: Admission): CoffreClient {
  const credential = pageCredential(page, runtime.auth);
  let asked: Promise<Called> | undefined;
  const caller: AskCaller = (shown) => (asked ??= callerOf(runtime.vault, shown));
  return createClient({
    url: new URL(page.url).origin,
    headers: () => credential,
    transport: (request) => fetchApi(request, runtime, { sourceIp, caller, page, access }),
  });
}

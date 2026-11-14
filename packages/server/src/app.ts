import type { CoffreClient } from '@coffre/client';
import { preferencesIn, type Preferences } from '@coffre/core/pages';
import { isUnreachable } from '@coffre/db/dialect';
import { migrated } from '@coffre/db/schema-version';

import { ApiError } from './api/errors.ts';
import { admit, type Admission } from './behind-access.ts';
import { exchangeToken } from './exchange.ts';
import { fetchApi, isSameOrigin, pageClient } from './fetch-api.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from './http.ts';
import { mcpEndpoint } from './mcp/endpoint.ts';
import { authorizationServer, oauthRegister, oauthRevoke, oauthToken, protectedResource } from './mcp/http.ts';
import { pluginRoute } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';
import { cspNonce, setSecurityHeaders } from './security-headers.ts';
import { finishSignin, logout, pollDevice, PROVIDER_PATH, signOut, startDevice, startSignin } from './signin.ts';

/**
 * `track`: work the response must not cut short, which the platform keeps the request alive for (`requestScope`).
 * `access`: behind Cloudflare Access, the session the request was admitted with (`admit`).
 */
type Handler = (request: Request, runtime: CoffreRuntime, sourceIp: string | null, track: (work: Promise<unknown>) => void, access: Admission | undefined) => Promise<Response>;

/**
 * Exact paths outside the API's route table, and the one method each
 * takes. `browserForm`: a
 * form coffre's own pages post, with the browser's cookies, which must
 * come from one of them.
 */
const PATHS: Record<string, { method: 'GET' | 'POST'; handler: Handler; browserForm?: true }> = {
  '/livez': { method: 'GET', handler: async () => jsonResponse({ ok: true }) },
  '/readyz': {
    method: 'GET',
    handler: async (_request, runtime) => {
      const readiness = await ready(runtime);
      return jsonResponse(readiness, readiness.ok ? 200 : 503);
    },
  },
  // Sign-in (signin.ts): the device login's two calls, and signing out. What the sign-in page reads first, GET /api/auth,
  // is the API's (`fetchApi`), where a page's render reaches it too.
  '/api/auth/device': { method: 'POST', handler: startDevice },
  '/api/auth/device/token': { method: 'POST', handler: pollDevice },
  '/api/auth/logout': { method: 'POST', handler: logout },
  '/auth/signout': { method: 'POST', handler: signOut, browserForm: true },
  // A CI run's exchange (exchange.ts): its platform's ID token, for a five-minute token of its service.
  '/api/auth/oidc': { method: 'POST', handler: exchangeToken },
  // MCP's OAuth (mcp/http.ts): the metadata clients read first, then the token, registration and revocation endpoints;
  // and the endpoint its access tokens are for (mcp/endpoint.ts).
  '/.well-known/oauth-protected-resource': { method: 'GET', handler: protectedResource },
  '/.well-known/oauth-protected-resource/mcp': { method: 'GET', handler: protectedResource },
  '/.well-known/oauth-authorization-server': { method: 'GET', handler: authorizationServer },
  '/api/oauth/token': { method: 'POST', handler: oauthToken },
  '/api/oauth/register': { method: 'POST', handler: oauthRegister },
  '/api/oauth/revoke': { method: 'POST', handler: oauthRevoke },
  '/mcp': { method: 'POST', handler: mcpEndpoint },
};

/** What answers with no session, behind Access too: health, and how this instance signs people in, which tells whether Access sent an assertion. */
const UNCHECKED = new Set(['/livez', '/readyz', '/api/auth']);

/** Behind Access, whether a request to this path is checked against its assertion first (`admit`). */
export function checked(runtime: CoffreRuntime, pathname: string): boolean {
  return runtime.auth.mode === 'cloudflare' && !UNCHECKED.has(pathname);
}

/**
 * coffre's own paths: health, sign-in and the API. Null for any other, a page's,
 * which the deployment's Start app renders. `access`: the session `respond`
 * admitted the request with, behind Access. A route asked without it is
 * checked here, and its response sets the check's cookies.
 */
export async function coffreRoute(request: Request, runtime: CoffreRuntime, sourceIp: string | null, track: (work: Promise<unknown>) => void = () => {}, access?: Admission): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  if (access === undefined && checked(runtime, pathname)) {
    const admitted = await admit(request, runtime, sourceIp);
    const response = await coffreRoute(request, runtime, sourceIp, track, admitted);
    return response === null ? null : withCookies(response, admitted.cookies);
  }
  const exact = PATHS[pathname];
  if (exact !== undefined) {
    // HEAD is GET without the body, which the platform drops: what a monitor asks /livez and /readyz.
    const method = request.method === 'HEAD' && exact.method === 'GET' ? 'GET' : request.method;
    if (method !== exact.method) return methodNotAllowed([exact.method]);
    if (exact.browserForm && !isSameOrigin(request, runtime.publicUrl)) return errorResponse(new ApiError('cross_origin', 'this must be sent from coffre itself'));
    return exact.handler(request, runtime, sourceIp, track, access);
  }
  if (pathname === '/api' || pathname.startsWith('/api/')) return fetchApi(request, runtime, { sourceIp, access });
  // A provider's round trip: leaving for it, and back.
  const provider = PROVIDER_PATH.exec(pathname);
  if (provider !== null) {
    if (request.method !== 'GET') return methodNotAllowed(['GET']);
    const [, step, id] = provider as unknown as [string, 'signin' | 'callback', string];
    return step === 'signin' ? startSignin(request, runtime, id) : finishSignin(request, runtime, sourceIp, id);
  }
  // A plugin's paths, the credential proxy's `/use` among them.
  return pluginRoute(request, runtime, sourceIp);
}

/** What a page renders with: this response's nonce, the API as the visitor, and how they have the pages drawn. */
export type PageContext = { cspNonce: string; client: CoffreClient; preferences: Preferences };

/** A response with these cookies set on it: a copy, when the platform made its headers immutable. */
function withCookies(response: Response, cookies: readonly string[]): Response {
  if (cookies.length === 0) return response;
  let answer = response;
  try {
    for (const cookie of cookies) answer.headers.append('set-cookie', cookie);
  } catch {
    answer = new Response(response.body, response);
    for (const cookie of cookies) answer.headers.append('set-cookie', cookie);
  }
  return answer;
}

/**
 * One request, whatever answers it, a page or one of coffre's routes: it
 * gets a fresh nonce, the visitor's API client and their preferences to
 * render with, and coffre's security headers on whatever comes back.
 * `sourceIp` is the platform's to vouch for: Cloudflare's header on
 * Workers, the socket's address on Node. Behind Access, the request is
 * first checked against its assertion (`admit`), once: its page's client
 * and the route `render` asks (`access`) use the session it was admitted
 * with, and the response sets the check's cookies.
 */
export async function respond(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  render: (context: PageContext, access: Admission | undefined) => Promise<Response>,
): Promise<Response> {
  const nonce = cspNonce();
  let response: Response;
  let access: Admission | undefined;
  try {
    const { pathname } = new URL(request.url);
    const open = SERVED_WHILE_MIGRATING.has(pathname) || (await schemaReady(runtime));
    if (open && checked(runtime, pathname)) access = await admit(request, runtime, sourceIp);
    response = open
      ? await render({ cspNonce: nonce, client: pageClient(request, runtime, sourceIp, access), preferences: preferencesIn(request.headers.get('cookie')) }, access)
      : migrating(request);
  } catch (error) {
    response = errorResponse(error);
  }
  // Read once the render is done: a call of its may have found the session gone (`ended`).
  if (access !== undefined) response = withCookies(response, access.cookies);
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

/** What answers below this version's migrations: liveness, and readiness, which is red until they are done. */
const SERVED_WHILE_MIGRATING = new Set(['/livez', '/readyz']);

/**
 * Whether the database has every migration this version ships. Each
 * deployment migrates before it deploys (`coffre migrate`), so a new app
 * never serves on a schema it does not have: until then, everything but
 * health answers 503 `migrating`; a database never migrated has no ledger,
 * and is below them too. Asked until it holds, then known. A database that
 * cannot be reached lets the request through, to meet the outage as it would
 * anyway: a page shows its error state, the API answers 503. Hyperdrive's
 * pool full is one too, and may free before the request's own queries:
 * then, below the migrations, they run on the old schema. That is a gap
 * accepted, as it was for a database that came back mid-request: it needs
 * a deploy that skipped `coffre migrate`. Any other failure of the question
 * fails the request.
 */
export async function schemaReady(runtime: CoffreRuntime): Promise<boolean> {
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

/** Readiness: the database migrated. What the signer says of the log comes with the vault's `about`. */
async function ready(runtime: CoffreRuntime): Promise<{ ok: boolean }> {
  try {
    return { ok: await migrated(runtime.db) };
  } catch {
    return { ok: false };
  }
}

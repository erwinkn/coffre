import { ACCESS_JWT_HEADER, tokenKind, type AuthConfig, type Principal } from '@coffre/core/identity';
import type { CredentialScope } from '@coffre/core/access';
import type { Access } from '@coffre/core/vault';

import { callerFrom, newestPolicySeq, type Caller } from './api/caller.ts';
import { formatMember } from './api/paths.ts';
import { ApiError } from './api/errors.ts';
import type { McpVia } from './api/context.ts';
import { CredentialUncheckable, type HandlePlace, type PersonalToken } from './api/signin.ts';
import { errorResponse } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
import { dpopToken, SessionRefused, sessionScope, standingSession, type StandingSession } from './workload-sessions.ts';

/** A verified caller, loaded once with everything they hold. */
export type AuthenticatedIdentity = {
  principal: Principal;
  registered: boolean;
  caller: Caller;
  requestId: string;
  sourceIp: string | null;
  /** The coffre credential that authenticated this request, in signin mode. */
  credentialId: string | null;
  /** When that credential ends, ISO 8601; null without one. */
  credentialExpiresAt: string | null;
  /** That credential, when a trust binding issued it for a CI run, or it is a personal token: every entry the request writes names it. */
  provenance: string | null;
  /** The personal token the request came in on, which acts as its person within its scope; null for anything else. */
  personalToken: PersonalToken | null;
  /** The environments the handle it came in on was made for; null for anything else, or a handle of 0.8. */
  handlePlaces: readonly HandlePlace[] | null;
  /** The MCP connection a tool's call came through; null for every other request. */
  via: McpVia | null;
  /** The workload's key-bound session the request came in on, its proof checked and its nonce the gate's; none for anything else. */
  workload?: StandingSession | null;
};

type AuthenticationRuntime = Pick<
  CoffreRuntime,
  'auth' | 'verifier' | 'vault' | 'db' | 'chainKey' | 'publicUrl' | 'gates' | 'waitUntil'
>;

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

/**
 * The browser's session, from its cookie in signin mode. Never a personal
 * token: that is a bearer token, sent in a header, and what trusts the
 * cookie (pages, linking an account, approving a sign-in) trusts a person
 * at their browser, which a token planted in the cookie is not.
 */
export function sessionCookie(request: Request, auth: AuthConfig): string | null {
  const token = cookieValue(request, sessionCookieName(auth));
  return token === null || tokenKind(token) === 'personal' ? null : token;
}

export function bearerToken(request: Request): string | null {
  const match = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  return match === null ? null : match[1];
}

/** The token a request's `Authorization` carries: a bearer's, or a workload's session, sent with its key's proof (`DPoP`). */
export function headerToken(request: Request): string | null {
  return bearerToken(request) ?? dpopToken(request);
}

export function accessTokenForRequest(request: Request, auth: AuthConfig): string | null {
  if (auth.mode === 'signin') return sessionCookie(request, auth);
  const token = request.headers.get(ACCESS_JWT_HEADER);
  return token === null || token.length === 0 ? null : token;
}

/**
 * The caller's address on Workers, from Cloudflare's own header. The edge
 * overwrites `cf-connecting-ip` on every request, so a client cannot choose
 * it. On Node the address is the socket's, and this header means nothing.
 */
export function cloudflareSourceIp(request: Request): string | null {
  const value = request.headers.get('cf-connecting-ip');
  if (value === null || value.length > 45) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255) ? value : null;
  }
  return /^[0-9a-f]+(?::[0-9a-f]*)+$/i.test(value) ? value : null;
}

export function unauthenticated(auth: AuthConfig): Response {
  return errorResponse(
    new ApiError(
      'unauthenticated',
      auth.mode === 'cloudflare' ? 'sign in through Cloudflare Access first' : 'sign in first',
    ),
  );
}

export const registrationRequired = () =>
  errorResponse(new ApiError('registration_required', 'you are signed in, but not a member here'));

/** What a member whose record failed the vault's integrity check is told, wherever they ask. */
export const TAMPERED_MESSAGE =
  "your access record failed coffre's integrity check: it was changed outside coffre. An owner must remove you and add you again";

export const accessTampered = () => errorResponse(new ApiError('vault_refused', TAMPERED_MESSAGE, 'tampered'));

export async function authenticateRequest(
  request: Request,
  runtime: AuthenticationRuntime,
  requestId: string = crypto.randomUUID(),
  token = accessTokenForRequest(request, runtime.auth),
  sourceIp: string | null = null,
  /** `handle`: the credential proxy's, which takes a handle and nothing else; everything else takes anything but one. */
  options: { handle?: boolean } = {},
): Promise<AuthenticatedIdentity | Response> {
  if (token === null) return unauthenticated(runtime.auth);
  // A handle is a placeholder for secrets in a person's app: it reaches the credential proxy, never the API, a page or a plugin's API.
  const kind = tokenKind(token);
  const handle = kind === 'handle';
  if (handle && options.handle !== true) {
    return errorResponse(new ApiError('forbidden', "a handle stands in for secrets, and only coffre's credential proxy takes one: sign in to use the API", 'handle'));
  }
  if (!handle && options.handle === true) return errorResponse(new ApiError('unauthenticated', 'the credential proxy takes a handle (coffre_use_…), as `coffre run` gives your app one'));
  // An enrollment code buys a workload's session and is no credential; a session is used with its key's proof, never
  // as a bearer: its hash covers its prefix, so neither is ever looked up as one (docs/design/workload-access.md).
  if (kind === 'enrollment') return errorResponse(new ApiError('unauthenticated', 'an enrollment code is no credential: a workload exchanges it at /api/auth/workload', 'enrollment'));
  if (kind === 'workload') return authenticateWorkload(request, runtime, requestId, token, sourceIp);
  // A strict instance leaves services nothing but key-bound sessions (section 6.3): a bearer service token, kept or exchanged, reads nothing.
  if (kind === 'service' && runtime.auth.mode === 'signin' && runtime.auth.signin.workloads?.useOnly === true) {
    return errorResponse(new ApiError('unauthenticated', 'this instance takes no service token (useOnly): sign the service in at /api/auth/workload, with its key', 'use_only'));
  }

  let principal: Principal;
  let credentialId: string | null = null;
  let credentialExpiresAt: string | null = null;
  let credentialGeneration: number | undefined;
  let exchanged = false;
  let credentialScope: CredentialScope | null = null;
  let personalToken: PersonalToken | null = null;
  let handlePlaces: readonly HandlePlace[] | null = null;
  let checked: Access | undefined;
  // The newest policy change before the vault is asked: the policy it answers with is this one or newer (`policyStill`).
  // A coffre credential's verifier reads it with the credential, before it asks the vault; Access's asks nothing of the vault.
  let policySeq: bigint | null | undefined;
  try {
    const verified = (await runtime.verifier.verify(token, { sourceIp })) as Principal & {
      credentialId?: string;
      credentialGeneration?: number;
      access?: Access;
      exchanged?: boolean;
      credentialScope?: CredentialScope | null;
      personalToken?: PersonalToken | null;
      handlePlaces?: readonly HandlePlace[] | null;
      expiresAt?: string;
      policySeq?: bigint | null;
    };
    ({ credentialId = null, expiresAt: credentialExpiresAt = null, credentialGeneration, access: checked, exchanged = false, credentialScope = null, personalToken = null, handlePlaces = null, policySeq, ...principal } = verified);
  } catch (error) {
    // Only a credential checked and refused is a sign-out; one that could not be checked is an outage.
    if (error instanceof CredentialUncheckable) {
      // Logged with what failed, the database or the vault, as below.
      console.error('checking a credential failed', { requestId, error: logged(error.cause) });
      return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
    }
    return errorResponse(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'));
  }

  try {
    if (policySeq === undefined) policySeq = await newestPolicySeq(runtime.db);
  } catch (error) {
    console.error('checking a credential failed', { requestId, error: logged(error) });
    return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }

  try {
    // A coffre credential was checked against what the vault says of its member: that answer, not a second call.
    const caller = {
      ...callerFrom({ type: principal.type, id: principal.id }, checked ?? await runtime.vault.access(formatMember(principal)), policySeq, credentialScope),
      kind: principal.type === 'service' ? 'bearer' as const : 'person' as const,
    };
    // Removal may have raced the credential verification above.
    if (credentialGeneration !== undefined && caller.generation !== credentialGeneration) {
      return unauthenticated(runtime.auth);
    }
    return {
      principal,
      registered: caller.registered,
      caller,
      requestId,
      sourceIp,
      credentialId,
      credentialExpiresAt,
      provenance: exchanged || personalToken !== null || handle ? credentialId : null,
      personalToken,
      handlePlaces,
      via: null,
      workload: null,
    };
  } catch (error) {
    // Logged, so a bug of ours is not read as an outage of the vault or the database.
    console.error('checking who called failed', { requestId, error: logged(error) });
    return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
}

/**
 * A workload's session at the API (docs/design/workload-access.md, section
 * 5.3): its one statement, its proof and its gate (`standingSession`), then
 * the vault's answer about its service, as for any credential. It holds
 * what its scope and the account hold, each grant with its binding's
 * `reads` (`sessionScope`), and reaches the routes `WORKLOAD_ROUTES` lists;
 * a `narrow` child reaches none of them. Every entry it writes names it.
 */
async function authenticateWorkload(
  request: Request,
  runtime: AuthenticationRuntime,
  requestId: string,
  token: string,
  sourceIp: string | null,
  children = false,
): Promise<AuthenticatedIdentity | Response> {
  let session: StandingSession;
  try {
    session = await standingSession(request, runtime, token, sourceIp, { place: null, credential: null, children });
  } catch (error) {
    if (error instanceof SessionRefused) return error.response;
    console.error('checking a workload session failed', { requestId, error: logged(error) });
    return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
  const { row, binding, policy } = session;
  const id = row.principal.slice('token:'.length);
  try {
    const access = await runtime.vault.access(row.principal);
    const caller = { ...callerFrom({ type: 'service', id }, access, session.policySeq, sessionScope(row, binding, policy)), kind: 'workload' as const };
    // Removal may have raced the statement.
    if (caller.generation !== row.generation) return unauthenticated(runtime.auth);
    return {
      principal: { type: 'service', id, commonName: id },
      registered: caller.registered,
      caller,
      requestId,
      sourceIp,
      credentialId: row.id,
      credentialExpiresAt: row.expiresAt.toISOString(),
      provenance: row.id,
      personalToken: null,
      handlePlaces: null,
      via: null,
      workload: session,
    };
  } catch (error) {
    console.error('checking who called failed', { requestId, error: logged(error) });
    return errorResponse(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
}

/**
 * A workload's own sign-in routes (renew, narrow, logout): its session at
 * the API, a `narrow` child's included where the route takes one, or the
 * response that turns it away.
 */
export function authenticateSession(
  request: Request,
  runtime: AuthenticationRuntime,
  sourceIp: string | null,
  options: { children: boolean },
): Promise<AuthenticatedIdentity | Response> {
  const token = dpopToken(request);
  if (token === null || tokenKind(token) !== 'workload') {
    return Promise.resolve(errorResponse(new ApiError('unauthenticated', "this takes a workload's session, Authorization: DPoP coffre_wl_…, with its key's proof")));
  }
  return authenticateWorkload(request, runtime, crypto.randomUUID(), token, sourceIp, options.children);
}

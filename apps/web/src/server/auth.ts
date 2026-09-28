import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { ACCESS_JWT_HEADER } from '../../../../packages/core/src/identity/types.ts';
import type { AuthConfig } from '../../../../packages/core/src/identity/auth-mode.ts';
import { loadCaller, type Caller } from './api/caller.ts';
import { ApiError } from './api/errors.ts';
import { errorResponse } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';

export const DEV_TOKEN_COOKIE = 'coffre_dev_token';

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

type AuthenticationRuntime = Pick<
  CoffreRuntime,
  'auth' | 'verifier' | 'db' | 'rootAdmins'
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

export async function authenticateRequest(
  request: Request,
  runtime: AuthenticationRuntime,
  requestId = crypto.randomUUID(),
  token = accessTokenForRequest(request, runtime.auth),
  sourceIp = trustedSourceIp(request, runtime.auth),
): Promise<AuthenticatedIdentity | Response> {
  if (token === null) return unauthenticated(runtime.auth);

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

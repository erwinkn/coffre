import { hashToken, tokenKind, type AuthConfig } from '@coffre/core/identity';
import type { Presented } from '@coffre/core/vault';

/**
 * A request's credential, and what it showed (docs/design/0.16.md, "The
 * server"). The app reads the token and hashes it. It looks nothing up and
 * verifies nothing: the vault finds the credential by the hash, and decides.
 */

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
  return match === null ? null : match[1]!;
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

/**
 * What a request showed, which every call to the vault starts with: its
 * token by its SHA-256, an id for the log, and the address the platform
 * vouches for. No proof yet: a workload's session, which is its key's
 * alone, is refused until the app holds its proof to the request again.
 */
export function presented(token: string, sourceIp: string | null): Presented {
  return { token: hashToken(token).toString('hex'), proof: null, request: crypto.randomUUID(), ip: sourceIp };
}

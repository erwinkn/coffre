import { createHash } from 'node:crypto';

import {
  createSigninProvider,
  type SigninConfig,
  type SigninProvider,
  type SigninProviderConfig,
} from '../../core/src/identity/signin/index.ts';
import type { AuthConfig } from '../../core/src/identity/auth-mode.ts';

const providers = new Map<string, SigninProvider>();

/**
 * One provider object per configuration for the isolate's lifetime, so the
 * OIDC discovery document is fetched once rather than on every sign-in.
 */
export function signinProvider(config: SigninProviderConfig): SigninProvider {
  const key = createHash('sha256').update(JSON.stringify(config)).digest('base64url');
  let provider = providers.get(key);
  if (provider === undefined) {
    provider = createSigninProvider(config);
    providers.set(key, provider);
  }
  return provider;
}

export function callbackUrl(config: SigninConfig, providerId: string): string {
  return `${config.publicUrl}/auth/callback/${providerId}`;
}

function secure(auth: AuthConfig): boolean {
  return auth.mode === 'signin' && auth.signin.publicUrl.startsWith('https:');
}

export function pendingCookieName(auth: AuthConfig): string {
  return secure(auth) ? '__Host-coffre_signin' : 'coffre_signin';
}

export function cookieHeader(
  auth: AuthConfig,
  name: string,
  value: string,
  maxAgeSeconds: number,
): string {
  return [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    // Lax, not Strict: the provider's redirect back is a cross-site
    // top-level navigation, and it must carry the pending-state cookie.
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
    ...(secure(auth) ? ['Secure'] : []),
  ].join('; ');
}

export function clearCookieHeader(auth: AuthConfig, name: string): string {
  return cookieHeader(auth, name, '', 0);
}

/**
 * A path on this origin, or `/projects`. `next` arrives in a query string,
 * so anything that could leave the origin (`//evil`, `/\evil`, a full URL)
 * is refused rather than repaired.
 */
export function safeNext(raw: string | null, publicUrl: string): string {
  if (raw === null || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return '/projects';
  }
  try {
    const url = new URL(raw, publicUrl);
    if (url.origin !== new URL(publicUrl).origin) return '/projects';
    if (url.pathname === '/login' || url.pathname.startsWith('/auth/signin/')) return '/projects';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/projects';
  }
}

export function redirectResponse(location: string, cookies: string[] = [], status = 302): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status, headers });
}

/** "Firefox on macOS", from a User-Agent, for the session list. Best effort by design. */
export function describeUserAgent(userAgent: string | null): string | null {
  if (userAgent === null || userAgent === '') return null;
  const browser =
    /Edg\//.test(userAgent) ? 'Edge'
    : /Firefox\//.test(userAgent) ? 'Firefox'
    : /Chrome\//.test(userAgent) ? 'Chrome'
    : /Safari\//.test(userAgent) ? 'Safari'
    : null;
  const system =
    /Windows/.test(userAgent) ? 'Windows'
    : /iPhone|iPad/.test(userAgent) ? 'iOS'
    : /Mac OS X/.test(userAgent) ? 'macOS'
    : /Android/.test(userAgent) ? 'Android'
    : /Linux/.test(userAgent) ? 'Linux'
    : null;
  if (browser === null && system === null) return userAgent.slice(0, 60);
  return [browser ?? 'Browser', system].filter(Boolean).join(' on ');
}

/** Configured providers as the pages show them: no client ids, no secrets. */
export function publicProviders(config: SigninConfig) {
  return config.providers.map(({ id, label, brand }) => ({ id, label, brand }));
}

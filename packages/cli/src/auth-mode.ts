import type { AuthMode } from '../../core/src/identity/auth-mode.ts';

export function cloudflareApiUrl(raw: string | undefined): string {
  const value = raw?.trim();
  if (!value) {
    throw new Error(
      'COFFRE_API_URL must be an explicit HTTPS origin when COFFRE_AUTH_MODE=cloudflare',
    );
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      'COFFRE_API_URL must be an explicit HTTPS origin when COFFRE_AUTH_MODE=cloudflare',
    );
  }

  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(
      'COFFRE_API_URL must be an explicit HTTPS origin when COFFRE_AUTH_MODE=cloudflare',
    );
  }

  return url.origin;
}

export function isCloudflareAccessRedirect(mode: AuthMode, status: number): boolean {
  return mode === 'cloudflare' && status >= 300 && status < 400;
}

export function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(';', 1)[0].trim().toLowerCase();
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

/**
 * Dev talks directly to the API with an Access-shaped assertion. Production
 * talks to the Cloudflare edge with the user token; Access validates it and
 * forwards its own assertion header to the origin.
 */
export function cliAuthHeader(mode: AuthMode, token: string): Record<string, string> {
  return mode === 'cloudflare'
    ? { 'cf-access-token': token }
    : { 'cf-access-jwt-assertion': token };
}

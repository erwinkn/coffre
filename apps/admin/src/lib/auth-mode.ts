import type { AuthConfig } from '../../../../packages/core/src/identity/auth-mode.ts';

export type AvailableTokens = {
  forwardedAccessJwt?: string | null;
  devCookie?: string | null;
};

/**
 * Select exactly one identity transport for the configured mode.
 *
 * Cloudflare mode never observes the dev cookie. Dev mode never treats a
 * client-supplied Access-looking header as the local persona.
 */
export function selectAdminToken(
  auth: AuthConfig,
  tokens: AvailableTokens,
): string | null {
  const candidate =
    auth.mode === 'cloudflare' ? tokens.forwardedAccessJwt : tokens.devCookie;
  return candidate && candidate.length > 0 ? candidate : null;
}

export function missingIdentityMessage(auth: AuthConfig): string {
  return auth.mode === 'cloudflare'
    ? 'Cloudflare Access did not forward an identity assertion. Open coffre through its Access-protected hostname.'
    : 'You are not signed in.';
}

export function rejectedIdentityMessage(auth: AuthConfig): string {
  return auth.mode === 'cloudflare'
    ? 'Cloudflare Access authentication was not accepted. Reopen coffre through its Access-protected hostname.'
    : 'Your local development session has expired. Sign in again to continue.';
}

/**
 * The headers every response from the Worker carries, so that a browser
 * holds coffre's pages to the little they need: scripts only from coffre,
 * never framed, never sniffed, never cached.
 *
 * The inline scripts a page needs (the theme and sidebar boot scripts, and
 * the data TanStack streams in for hydration) carry a nonce minted for that
 * response, so an injected `<script>` has no way to run.
 */

/** A fresh nonce for one response's scripts: 128 random bits. */
export function cspNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

export type SecurityHeaderOptions = {
  /** This response's script nonce, from `cspNonce()`. */
  nonce: string;
  /**
   * Origins forms may post to besides coffre's own. Signing out behind
   * Cloudflare Access redirects to Access's logout, which may send the
   * browser on to the team domain, and browsers hold a form's redirects to
   * `form-action` too.
   */
  formOrigins?: readonly string[];
};

export function contentSecurityPolicy({ nonce, formOrigins = [] }: SecurityHeaderOptions): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    // React's `style` props and the toasts' injected stylesheet are inline.
    // An injected style cannot run code, and the directives below keep it
    // from loading anything from elsewhere, so this costs little.
    "style-src 'self' 'unsafe-inline'",
    // The favicon is a data: URL.
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    ["form-action 'self'", ...formOrigins].join(' '),
    "frame-ancestors 'none'",
  ].join('; ');
}

/**
 * `response` with the security headers set. A copy, because some responses,
 * such as `Response.redirect()`'s, have headers that cannot change.
 */
export function withSecurityHeaders(
  request: Request,
  response: Response,
  options: SecurityHeaderOptions,
): Response {
  const secured = new Response(response.body, response);
  const headers = secured.headers;

  // Enforced in development too, so a script that lacks the nonce fails
  // where it is written rather than once deployed.
  headers.set('content-security-policy', contentSecurityPolicy(options));
  // Frame protection for browsers that predate `frame-ancestors`.
  headers.set('x-frame-options', 'DENY');
  headers.set('x-content-type-options', 'nosniff');
  // Not `no-referrer`: under it, browsers send `Origin: null` on same-origin
  // POSTs, which the CSRF check rightly refuses.
  headers.set('referrer-policy', 'same-origin');
  // A page coffre opens, or that opens coffre, gets no handle on its window.
  headers.set('cross-origin-opener-policy', 'same-origin');
  // Another site cannot pull coffre's responses into its own page.
  headers.set('cross-origin-resource-policy', 'same-origin');
  // Only over HTTPS, where the browser honours it; plain HTTP is development.
  if (new URL(request.url).protocol === 'https:') {
    headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  }
  // Every page names secrets and who may read them, and another person can
  // change either at any moment: nothing is worth keeping.
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');

  return secured;
}

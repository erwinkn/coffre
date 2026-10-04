/**
 * The headers every response from the Worker carries, so that a browser
 * holds coffre's pages to the little they need: scripts only from coffre,
 * never framed, never sniffed, never cached.
 *
 * The inline scripts a page needs, the data TanStack streams in for
 * hydration, carry a nonce minted for that response, so an injected
 * `<script>` has no way to run.
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
   * coffre's public URL. Its scheme, not the request's, says whether
   * browsers reach coffre over HTTPS: behind a proxy that ends TLS, the
   * request itself arrives as plain HTTP.
   */
  publicUrl: string;
  /**
   * Origins forms may post to besides coffre's own. Signing out behind
   * Cloudflare Access redirects to Access's logout, which may send the
   * browser on to the team domain, and browsers hold a form's redirects to
   * `form-action` too.
   */
  formOrigins?: readonly string[];
};

export function contentSecurityPolicy({ nonce, formOrigins = [] }: Pick<SecurityHeaderOptions, 'nonce' | 'formOrigins'>): string {
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

/** What a route that answers with a response coffre cannot add its headers to hears. */
export const IMMUTABLE =
  'a route answered with a Response whose headers cannot change, as Response.redirect() and fetch() make them, ' +
  "and coffre sets its security headers on the response in place: return new Response(null, { status: 302, headers: { location } }) " +
  'for a redirect, or new Response(upstream.body, upstream) for a fetched response (docs/deploy.md, "Your own routes")';

/**
 * Set the security headers on `response`, in place: the response Start
 * goes on to handle stays the one the route or page made, a TanStack
 * redirect's marker and all. Its headers must be changeable, as those of a
 * `new Response(…)` are; `Response.redirect()`'s and `fetch()`'s are not,
 * and coffre makes neither.
 */
export function setSecurityHeaders(response: Response, options: SecurityHeaderOptions): Response {
  const headers = response.headers;
  // Enforced in development too, so a script that lacks the nonce fails
  // where it is written rather than once deployed. The first header set
  // finds out whether the response takes them.
  try {
    headers.set('content-security-policy', contentSecurityPolicy(options));
  } catch (error) {
    throw new Error(IMMUTABLE, { cause: error });
  }

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
  if (options.publicUrl.startsWith('https:')) {
    headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  }
  // Every page names secrets and who may read them, and another person can
  // change either at any moment: nothing is worth keeping.
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');

  return response;
}

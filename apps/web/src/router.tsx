import { createRouter as createTanStackRouter } from '@tanstack/react-router';
import { getGlobalStartContext } from '@tanstack/react-start';
import { routeTree } from './routeTree.gen';
import { NotFound, RouteError } from './components/route-states';

/**
 * The router factory. TanStack Start calls this once per request on the server
 * and once on the client.
 *
 * Note what is deliberately absent: any caching of loader data. Every screen in
 * this app reports authorisation state that another person can change from
 * another tab, so a stale project list or grant table is not a cosmetic
 * problem. `staleTime: 0` means a navigation back to a screen refetches it,
 * which is the behaviour the Next.js version got from `force-dynamic`.
 */
export function getRouter() {
  return createTanStackRouter({
    routeTree,
    defaultPreload: 'intent',
    defaultStaleTime: 0,
    scrollRestoration: true,
    defaultNotFoundComponent: NotFound,
    defaultErrorComponent: RouteError,
    ssr: { nonce: cspNonce() },
  });
}

/**
 * The nonce the Worker minted for this response's Content-Security-Policy,
 * which the router puts on every script it renders. The client has none to
 * give: hydration reads it back from the page. A router built only to
 * resolve a redirect runs outside the request's context and renders nothing.
 */
function cspNonce(): string | undefined {
  try {
    return getGlobalStartContext()?.cspNonce;
  } catch {
    return undefined;
  }
}

/** What worker.ts hands every request. */
type RequestContext = { cspNonce: string };

// Start's server entry reads this `Register`, and its context helpers the
// one below: the two do not merge, so each hears of the request context.
declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>;
    server: { requestContext: RequestContext };
  }
}

declare module '@tanstack/react-start' {
  interface Register {
    server: { requestContext: RequestContext };
  }
}

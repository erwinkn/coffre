import { createClient, type CoffreClient } from '@coffre/client';
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
    context: { client: requestClient() },
  });
}

/**
 * The API as this visitor, which every loader reads through:
 * `context.client.secrets.list('market/dev')`. On the server `@coffre/server`
 * builds it per request, calling the API in process with the visitor's
 * credential (`server/fetch-api.ts`); the UI only uses it. In the browser it
 * is plain `fetch` to `/api`, which sends the session cookie itself.
 */
function requestClient(): CoffreClient {
  if (typeof window !== 'undefined') return createClient({ url: window.location.origin });
  try {
    const client = getGlobalStartContext()?.client;
    if (client !== undefined) return client;
  } catch {
    // As for the nonce, below: outside a request there is no one to ask as.
  }
  return createClient({
    url: 'http://coffre.invalid',
    transport: () => Promise.reject(new Error('no request to call the API for')),
  });
}

/**
 * The nonce the server minted for this response's Content-Security-Policy,
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

/** What `@coffre/server` hands every request; see `types.ts`. */
type RequestContext = { cspNonce: string; client: CoffreClient };

/** What every loader and component can reach through the router. */
export type RouterContext = { client: CoffreClient };

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

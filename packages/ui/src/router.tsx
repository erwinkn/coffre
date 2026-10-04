import { createClient, type CoffreClient } from '@coffre/client';
import { createRouter as createTanStackRouter, type AnyRoute } from '@tanstack/react-router';
import { setupRouterSsrQueryIntegration } from '@tanstack/react-router-ssr-query';
import { NotFound, RouteError } from './components/route-states';
import { createQueryClient } from './lib/queries';
import { DEFAULT_PREFERENCES, requestPage } from './lib/page-context';
import { browserPreferences, type Preferences } from './lib/preferences';
import type { CoffreContext } from './options';

/**
 * The deployment's router, around its route tree, which holds coffre's
 * routes: `export const getRouter = () => createRouter(routeTree)`. It gives
 * the routes coffre's context (`CoffreContext`). TanStack
 * Start calls it once per request on the server and once on the client, so
 * each gets a query cache of its own: a request's reads are never another
 * visitor's. The server's reads travel with the page, so the browser starts
 * from them rather than asking again.
 *
 * Loaders read through the query cache (`lib/queries.ts`, which says how
 * fresh it keeps a page), so the router keeps no copy of its own: it runs a
 * route's loader on every navigation and every hover, and the cache answers
 * whatever it already holds. A hover is then a read the click reuses.
 */
export function createRouter<TRouteTree extends AnyRoute>(routeTree: TRouteTree) {
  const queryClient = createQueryClient();
  const page = typeof window === 'undefined' ? requestPage() : undefined;
  const context: RouterContext = {
    coffre: page?.client ?? browserClient(),
    queryClient,
    preferences: page?.preferences ?? (typeof window === 'undefined' ? DEFAULT_PREFERENCES : browserPreferences()),
  };
  const router = createTanStackRouter({
    routeTree,
    defaultPreload: 'intent',
    defaultStaleTime: 0,
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
    defaultNotFoundComponent: NotFound,
    defaultErrorComponent: RouteError,
    // The nonce coffre's middleware minted for this response's policy, which
    // the router puts on every script it renders. The browser has none to
    // give: hydration reads it back from the page.
    ssr: { nonce: page?.cspNonce },
    context,
  });
  setupRouterSsrQueryIntegration({ router, queryClient });
  return router;
}

/** What the router gives every route: coffre's context, and how the visitor has the pages drawn, for `<CoffreProvider>`. */
export type RouterContext = CoffreContext & { preferences: Preferences };

/**
 * The API as this visitor in the browser, which every loader reads through
 * (`context.coffre.secrets.list('market/dev')`): plain `fetch` to `/api`,
 * which sends the session cookie itself. On the server, coffre's
 * middleware builds it per request; outside one, nothing calls it.
 */
function browserClient(): CoffreClient {
  return createClient({ url: typeof window === 'undefined' ? 'http://coffre.invalid' : window.location.origin });
}

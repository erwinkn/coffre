import { createClient, type CoffreClient } from '@coffre/client';
import { createRouter as createTanStackRouter, type AnyRoute } from '@tanstack/react-router';
import { setupRouterSsrQueryIntegration } from '@tanstack/react-router-ssr-query';
import { getGlobalStartContext } from '@tanstack/react-start';
import { NotFound, RouteError } from './components/route-states';
import { createQueryClient } from './lib/queries';
import type { CoffreContext } from './routes';

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
  const router = createTanStackRouter({
    routeTree,
    defaultPreload: 'intent',
    defaultStaleTime: 0,
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
    defaultNotFoundComponent: NotFound,
    defaultErrorComponent: RouteError,
    ssr: { nonce: cspNonce() },
    context: { coffre: requestClient(), queryClient } satisfies CoffreContext,
  });
  setupRouterSsrQueryIntegration({ router, queryClient });
  return router;
}

/** What coffre's middleware hands each request's render (`@coffre/server/start`). */
type PageContext = { cspNonce?: string; client?: CoffreClient };

function pageContext(): PageContext | undefined {
  try {
    return getGlobalStartContext() as PageContext | undefined;
  } catch {
    // Outside a request: a router built only to resolve a redirect renders nothing.
    return undefined;
  }
}

/**
 * The API as this visitor, which every loader reads through:
 * `context.coffre.secrets.list('market/dev')`. On the server coffre's
 * middleware builds it per request, calling the API in process with the
 * visitor's credential; the pages only use it. In the browser it is plain
 * `fetch` to `/api`, which sends the session cookie itself.
 */
function requestClient(): CoffreClient {
  if (typeof window !== 'undefined') return createClient({ url: window.location.origin });
  const client = pageContext()?.client;
  if (client !== undefined) return client;
  return createClient({
    url: 'http://coffre.invalid',
    transport: () =>
      Promise.reject(
        new Error(
          "coffre's request middleware is not installed: add coffreMiddleware, from @coffre/server/start, to " +
            "createStart(() => ({ requestMiddleware: [coffreMiddleware] })) in the app's src/start.ts",
        ),
      ),
  });
}

/**
 * The nonce coffre's middleware minted for this response's
 * Content-Security-Policy, which the router puts on every script it renders.
 * The client has none to give: hydration reads it back from the page.
 */
function cspNonce(): string | undefined {
  return pageContext()?.cspNonce;
}

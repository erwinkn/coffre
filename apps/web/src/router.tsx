import { createRouter as createTanStackRouter } from '@tanstack/react-router';
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
  });
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}

/**
 * coffre's server routes, for the deployment's route tree, beside its pages:
 *
 *   import { coffreServerRoutes } from '@coffre/server/routes';
 *   export const routeTree = root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)]);
 *
 * or one at a time, `api(root)`, `auth(root)`, `livez(root)`, `readyz(root)`.
 * `/api/$` is the whole API, which the pages and the CLI need all of. A
 * route at a more specific path, `/api/hello`, would win over it, and take
 * a path of coffre's: a deployment's own go elsewhere. Each reaches coffre through the request's context, which the server
 * entry sets: this file runs in the browser's bundle too, and imports
 * nothing of the server.
 */
import { createRoute, type AnyRoute } from '@tanstack/react-router';
import type {} from '@tanstack/react-start';

import { coffreOf, requireMiddleware } from './wiring.ts';

/** Every method, to coffre: it answers 405 for a method a path does not take. */
const handlers = {
  ANY: ({ request, context }: { request: Request; context: unknown }) => {
    requireMiddleware(context);
    return coffreOf(context).route(request);
  },
};

const serverRoute = <TPath extends string>(path: TPath) =>
  <TParent extends AnyRoute>(parent: TParent) =>
    createRoute({ getParentRoute: () => parent, path, server: { handlers } });

/** The API, all of it: `/api` and everything under it. */
export const api = serverRoute('/api/$');
/** Sign-in with a provider, its callback, and signing out. `/auth/device` is a page, which this leaves to the pages. */
export const auth = serverRoute('/auth/$');
/** Whether the process answers. */
export const livez = serverRoute('/livez');
/** Whether coffre can take writes: the audit log's heartbeat and checkpoint. */
export const readyz = serverRoute('/readyz');

/** All of coffre's server routes, under `parent`, the root. */
export function coffreServerRoutes<TParent extends AnyRoute>(parent: TParent) {
  return [api(parent), auth(parent), livez(parent), readyz(parent)] as const;
}

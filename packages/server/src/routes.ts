/**
 * coffre's server routes: its API, sign-in and health, which coffre's
 * server answers. As route options, for the deployment's file routes,
 *
 *   // src/routes/api.$.ts
 *   export const Route = createFileRoute('/api/$')({ ...api });
 *
 * or in code, `coffreServerRoutes(root)`, or one at a time, `apiRoute(root)`.
 * `/api/$` is the whole API, which the pages and the CLI need all of. A
 * route at a more specific path, `/api/hello`, would win over it, and take
 * a path of coffre's: a deployment's own go elsewhere. Each reaches coffre
 * through the request's context, which the server entry sets: this file
 * runs in the browser's bundle too, when its routes are code, and imports
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

/** Any of coffre's server routes: every method of it, to coffre's server. */
const route = { server: { handlers } };

/** `/api/$`: the API, all of it. */
export const api = route;
/** `/auth/$`: sign-in with a provider, its callback, and signing out. `/auth/device` is a page, which this leaves to the pages. */
export const auth = route;
/** `/livez`: whether the process answers. */
export const livez = route;
/** `/readyz`: whether coffre can take writes, the audit log's heartbeat and checkpoint. */
export const readyz = route;

export const apiRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/api/$', ...api });
export const authRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/auth/$', ...auth });
export const livezRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/livez', ...livez });
export const readyzRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/readyz', ...readyz });

/** All of coffre's server routes, under `parent`, the root. */
export function coffreServerRoutes<TParent extends AnyRoute>(parent: TParent) {
  return [apiRoute(parent), authRoute(parent), livezRoute(parent), readyzRoute(parent)] as const;
}

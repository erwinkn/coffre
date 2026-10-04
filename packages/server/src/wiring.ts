// How coffreMiddleware and coffre's server routes find coffre in a request's
// context, and what they say when the deployment's app did not put it there.
// Imports nothing of the server: these run in files the browser loads too.
import type { CoffreRequest } from './scope.ts';

export const NO_COFFRE =
  "coffre is not in this request's context: the app's server entry hands it to Start with each request, " +
  '`handler.fetch(request, { context: coffre.request(env, ctx) })` in src/server.ts on Workers, `serve({ app, coffre })` on Node';

export const NO_MIDDLEWARE =
  "coffre's request middleware is not installed: add coffreMiddleware, from @coffre/server/start, to " +
  "createStart(() => ({ requestMiddleware: [coffreMiddleware] })) in the app's src/start.ts";

/** coffre's part of the request, from Start's context. */
export function coffreOf(context: unknown): CoffreRequest {
  const coffre = (context as { coffre?: CoffreRequest } | undefined)?.coffre;
  if (coffre === undefined || typeof coffre.route !== 'function') throw new Error(NO_COFFRE);
  return coffre;
}

/** That coffreMiddleware ran for this request: it marks the context it hands on. */
export function requireMiddleware(context: unknown): void {
  if ((context as { coffreMiddleware?: unknown } | undefined)?.coffreMiddleware !== true) throw new Error(NO_MIDDLEWARE);
}

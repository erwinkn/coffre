// coffre's part of one request, as a deployment's Start app reaches it: its
// server entry hands Start `{ coffre }` as the request's context, which
// coffreMiddleware (`@coffre/server/start`) and coffre's server routes
// (`@coffre/server/routes`) read. Neither imports any of this: they run in
// files the browser loads too, and reach the server only through here.
import type { Preferences } from '@coffre/core/pages';

import { coffreRoute, respond, type PageContext } from './app.ts';
import { ApiError } from './api/errors.ts';
import { errorResponse } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';

export type { PageContext, Preferences };

/** coffre's part of one request. */
export type CoffreRequest = {
  /** coffre's own paths, health, sign-in and the API; not found for any other. */
  route(request: Request): Promise<Response>;
  /** A response, a page's or a route's, made with this request's nonce and client, and secured with coffre's headers. */
  respond(request: Request, render: (context: PageContext) => Promise<Response>): Promise<Response>;
};

/** What the deployment's server entry hands Start for each request. */
export type CoffreContext = { coffre: CoffreRequest };

/**
 * One request's coffre, on `runtime`. `sourceIp` reads the caller's address
 * from the request as the platform gives it; `track` is told of each piece of
 * work coffre does for it, for a platform that must keep the request's
 * database open until that work is done.
 */
export function requestScope(
  runtime: CoffreRuntime,
  sourceIp: (request: Request) => string | null,
  track: (work: Promise<unknown>) => void = () => {},
): CoffreRequest {
  const tracked = <T>(work: Promise<T>): Promise<T> => {
    track(work);
    return work;
  };
  return {
    route: (request) =>
      tracked(
        (async () => {
          try {
            return (await coffreRoute(request, runtime, sourceIp(request))) ?? errorResponse(new ApiError('not_found', 'no such path'));
          } catch (error) {
            return errorResponse(error);
          }
        })(),
      ),
    respond: (request, render) => tracked(respond(request, runtime, sourceIp(request), render)),
  };
}


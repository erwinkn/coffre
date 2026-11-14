// coffre's part of one request, as a deployment's Start app reaches it: its
// server entry hands Start `{ coffre }` as the request's context, which
// coffreMiddleware (`@coffre/server/start`) and coffre's server routes
// (`@coffre/server/routes`) read. Neither imports any of this: they run in
// files the browser loads too, and reach the server only through here.
import type { Preferences } from '@coffre/core/pages';

import { coffreRoute, respond, type PageContext as Rendered } from './app.ts';
import type { Admission } from './behind-access.ts';
import { ApiError } from './api/errors.ts';
import { errorResponse } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';

export type { Preferences };

/**
 * What a response is rendered with: its nonce, the API as the visitor, their
 * preferences, and coffre for the route it may be, which answers as the
 * visitor was admitted (behind Access, the session `respond` checked).
 * Start hands it on in the request's context, where coffre's routes find it.
 */
export type PageContext = Rendered & CoffreContext;

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
  const route = (request: Request, access?: Admission) =>
    tracked(
      (async () => {
        try {
          return (await coffreRoute(request, runtime, sourceIp(request), track, access)) ?? errorResponse(new ApiError('not_found', 'no such path'));
        } catch (error) {
          return errorResponse(error);
        }
      })(),
    );
  const scope: CoffreRequest = {
    route: (request) => route(request),
    respond: (request, render) =>
      tracked(respond(request, runtime, sourceIp(request), (page, access) => render({ ...page, coffre: { ...scope, route: (inner) => route(inner, access) } }))),
  };
  return scope;
}


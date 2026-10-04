/**
 * coffre's request middleware, for the deployment's Start app:
 *
 *   // src/start.ts
 *   import { createStart } from '@tanstack/react-start';
 *   import { coffreMiddleware } from '@coffre/server/start';
 *
 *   export const startInstance = createStart(() => ({ requestMiddleware: [coffreMiddleware] }));
 *
 * Every request Start answers, a page, one of coffre's routes or one of the
 * deployment's own, gets a fresh CSP nonce and the visitor's API client,
 * which the pages render with, and coffre's security headers on its
 * response. It reaches coffre through the request's context, which the
 * server entry sets: this file runs in the browser's bundle too, and imports
 * nothing of the server.
 */
import { createMiddleware } from '@tanstack/react-start';

import { coffreOf } from './wiring.ts';

export const coffreMiddleware = createMiddleware({ type: 'request' }).server(async ({ request, context, next }) => {
  const coffre = coffreOf(context);
  let result: Awaited<ReturnType<typeof next>> | undefined;
  const response = await coffre.respond(request, async (page) => {
    result = await next({ context: { ...page, coffreMiddleware: true } });
    return result.response;
  });
  return { ...result, response } as Awaited<ReturnType<typeof next>>;
});

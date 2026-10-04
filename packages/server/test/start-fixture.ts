import { coffreRoute, respond, type PageContext } from '../src/app.ts';
import { methodNotAllowed } from '../src/http.ts';
import type { CoffreRuntime } from '../src/runtime.ts';

/** A stand-in for the deployment's pages, which Start renders. */
export type Pages = { fetch(request: Request, init: { context: PageContext }): Response | Promise<Response> };

/**
 * One request as a deployment's Start app answers it: coffre's middleware
 * around coffre's server routes, then a page for a GET or HEAD.
 */
export function answer(request: Request, runtime: CoffreRuntime, pages: Pages, sourceIp: string | null): Promise<Response> {
  return respond(request, runtime, sourceIp, async (context) => {
    const own = await coffreRoute(request, runtime, sourceIp);
    if (own !== null) return own;
    if (request.method !== 'GET' && request.method !== 'HEAD') return methodNotAllowed(['GET']);
    return pages.fetch(request, { context });
  });
}

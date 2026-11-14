import type { z } from 'zod';

import { errorResponse, jsonResponse, readJson } from '../http.ts';
import type { ApiContext } from './context.ts';
import { ApiError, badRequest, notFound, noteTampered } from './errors.ts';
import { PARAMS, type Route } from './route.ts';
import { routes } from './routes.ts';

/**
 * The most an API request body may be, read as it streams and abandoned
 * past this: a control-plane request, a bulk secret write its largest,
 * which is also the most the vault takes of one write.
 */
export const API_BODY_BYTES = 1024 * 1024;

/**
 * The most top-level entries a request body may name, refused before it is
 * validated: a bulk write is an object keyed by name, and validation does
 * work per entry. The most keys the vault takes of one write.
 */
const MAX_BODY_KEYS = 2000;

type AnyRoute = Route<string, z.ZodType | undefined, unknown, z.ZodType | undefined>;

type Compiled = {
  /** `METHOD /route`, as the table names it. */
  key: string;
  method: string;
  segments: ({ literal: string } | { param: string })[];
  def: AnyRoute;
};

const compiled: Compiled[] = Object.entries(routes).map(([key, def]) => {
  const [method, shape] = key.split(' ') as [string, string];
  return {
    key,
    method,
    segments: shape
      .split('/')
      .slice(1)
      .map((part) => (part.startsWith(':') ? { param: part.slice(1) } : { literal: part })),
    def: def as AnyRoute,
  };
});

/**
 * The route a request means: of the shapes that fit the path and take its
 * method, the most specific, where at the first segment two shapes differ,
 * a literal beats a parameter. When no shape takes the method, `allowed`
 * lists the methods the path does take.
 */
function match(parts: string[], method: string): { route: Compiled; params: Record<string, string> } | { allowed: string[] } | null {
  let best: { route: Compiled; params: Record<string, string> } | null = null;
  const allowed = new Set<string>();
  for (const route of compiled) {
    if (route.segments.length !== parts.length) continue;
    const params: Record<string, string> = {};
    const fits = route.segments.every((segment, index) => {
      if ('literal' in segment) return segment.literal === parts[index];
      params[segment.param] = parts[index]!;
      return true;
    });
    if (!fits) continue;
    allowed.add(route.method);
    if (route.method !== method) continue;
    if (best === null || moreSpecific(route, best.route)) best = { route, params };
  }
  if (best !== null) return best;
  return allowed.size === 0 ? null : { allowed: [...allowed] };
}

function moreSpecific(a: Compiled, b: Compiled): boolean {
  for (let index = 0; index < a.segments.length; index += 1) {
    const aLiteral = 'literal' in a.segments[index]!;
    const bLiteral = 'literal' in b.segments[index]!;
    if (aLiteral !== bLiteral) return aLiteral;
  }
  return false;
}

/**
 * A path's segments as the router matches them: after `/api`, empty ones
 * dropped, each percent-decoded. Throws on percent-encoding that does not
 * decode, which no route matches.
 */
export function routeParts(pathname: string): string[] {
  return pathname.replace(/^\/api/, '').split('/').filter(Boolean).map(decodeURIComponent);
}

/**
 * Serve one API request (docs/design/0.16.md, "The server"):
 *
 *   1. match `METHOD /route`; no route is 404, a route without this method 405
 *   2. check the path's segments and parse the input (a GET's query, or the
 *      body and any flags in the query string)
 *   3. run the handler
 *
 * Nothing is looked up and no permission checked before the handler: who
 * may do what is the vault's to decide, in the handler's one call to it.
 */
export async function serveApi(request: Request, ctx: ApiContext): Promise<Response> {
  const url = new URL(request.url);
  let parts: string[];
  try {
    parts = routeParts(url.pathname);
  } catch {
    throw badRequest('the path is not valid percent-encoding');
  }
  const found = match(parts, request.method);
  if (found === null) throw notFound(`no route for ${url.pathname}`);
  if ('allowed' in found) {
    return errorResponse(new ApiError('method_not_allowed', `use ${found.allowed.join(' or ')}`), { allow: found.allowed.join(', ') });
  }
  const { def, key } = found.route;
  try {
    return await serveRoute(request, url, def, found.params, ctx);
  } catch (error) {
    noteTampered(error, key, ctx.shown.request);
    throw error;
  }
}

/** Steps 2 and 3: the path's segments and the input checked, then the handler. */
async function serveRoute(request: Request, url: URL, def: AnyRoute, params: Record<string, string>, ctx: ApiContext): Promise<Response> {
  for (const [name, value] of Object.entries(params)) {
    if (PARAMS[name] === undefined) continue;
    const parsed = PARAMS[name].safeParse(value);
    if (!parsed.success) throw badRequest(`"${value}" is not a valid ${name}`);
    // As its schema writes it: an id in lowercase, as the vault takes one.
    params[name] = parsed.data;
  }
  const raw = request.method === 'GET' ? Object.fromEntries(url.searchParams) : await readJson(request, API_BODY_BYTES, {});
  // An object body naming more than the cap is refused before validation walks every entry.
  if (raw !== null && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length > MAX_BODY_KEYS) {
    throw badRequest(`the body names more than ${MAX_BODY_KEYS} entries`);
  }
  const input = def.input === undefined ? undefined : def.input.parse(raw);
  const query = request.method === 'GET' || def.query === undefined ? undefined : def.query.parse(Object.fromEntries(url.searchParams));
  return jsonResponse(await def.run(ctx, { params, input, query } as never));
}

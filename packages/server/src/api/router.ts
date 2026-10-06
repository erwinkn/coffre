import { MCP_SCOPE_INFO, scopeString } from '@coffre/core/mcp';
import { folderName, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { resolvePath, type ResolvedPath } from '../db/queries.ts';
import { errorResponse, jsonResponse, readJson } from '../http.ts';
import { can, placeOf } from './caller.ts';
import { denied, missing, refuse, Refusal, type ApiContext } from './context.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatPath } from './paths.ts';
import { challengeScopes, ROUTE_SCOPES } from '../mcp/scopes.ts';
import { routes, type Check, type Route } from './routes.ts';

type AnyRoute = Route<string, z.ZodType | undefined, unknown, z.ZodType | undefined>;

type Compiled = {
  method: string;
  /** The route without its method, e.g. `/secrets/:project/:environment`. */
  shape: string;
  segments: ({ literal: string } | { param: string })[];
  def: AnyRoute;
};

const compiled: Compiled[] = Object.entries(routes).map(([key, def]) => {
  const [method, shape] = key.split(' ');
  return {
    method,
    shape,
    segments: shape
      .split('/')
      .slice(1)
      .map((part) => (part.startsWith(':') ? { param: part.slice(1) } : { literal: part })),
    def: def as AnyRoute,
  };
});

/** What each named segment may hold. */
const PARAMS: Record<string, z.ZodType<string>> = {
  project: slug,
  environment: slug,
  key: secretKey,
  member: z.string().min(3).max(330),
  id: z.string().uuid(),
  code: z.string().min(1).max(16),
  folder: folderName,
};

/**
 * The route a request means: of the shapes that fit the path and take its
 * method, the most specific, where at the first segment two shapes differ,
 * a literal beats a parameter. When no shape takes the method,
 * `allowed` lists the methods
 * the path does take.
 */
function match(
  parts: string[],
  method: string,
): { route: Compiled; params: Record<string, string> } | { allowed: string[] } | null {
  let best: { route: Compiled; params: Record<string, string> } | null = null;
  const allowed = new Set<string>();
  for (const route of compiled) {
    if (route.segments.length !== parts.length) continue;
    const params: Record<string, string> = {};
    const fits = route.segments.every((segment, index) => {
      if ('literal' in segment) return segment.literal === parts[index];
      params[segment.param] = parts[index];
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
    const aLiteral = 'literal' in a.segments[index];
    const bLiteral = 'literal' in b.segments[index];
    if (aLiteral !== bLiteral) return aLiteral;
  }
  return false;
}

function checks(def: AnyRoute, input: unknown, query: unknown): readonly Check[] {
  if (def.needs === undefined) return [];
  if (typeof def.needs === 'function') return def.needs(input as never, query as never);
  return typeof def.needs === 'string' || !Array.isArray(def.needs) ? [def.needs as Check] : def.needs;
}

async function locate(
  ctx: ApiContext,
  def: AnyRoute,
  params: Record<string, string>,
): Promise<ResolvedPath | null> {
  if (params.project === undefined) return null;
  const path = { project: params.project, environment: params.environment, key: params.key };
  const last = params.key !== undefined ? 'key' : params.environment !== undefined ? 'environment' : 'project';
  const place = await resolvePath(ctx.db, path);
  if (place === null) {
    if (def.creates && last === 'project') return null;
    throw notFound(`no project "${params.project}"`);
  }
  if (params.environment !== undefined && place.environment === null && !(def.creates && last === 'environment')) {
    throw notFound(`no environment "${formatPath(path).split('/').slice(0, 2).join('/')}"`);
  }
  if (params.key !== undefined && place.secret === null && !def.creates) {
    throw notFound(`no secret "${formatPath(path)}"`);
  }
  return place;
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
 * Serve one API request for an authenticated caller:
 *
 *   1. match `METHOD /route`; no route is 404, a route without this method 405
 *   2. check the path's segments and parse the input (a GET's query, or the body
 *      and any flags in the query string)
 *   3. resolve the path in one query; a missing place is 404, not logged
 *   4. check the route's permissions against the caller; a refusal is logged
 *   5. run the handler
 */
export async function serveApi(request: Request, ctx: ApiContext): Promise<Response> {
  try {
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
      return errorResponse(new ApiError('method_not_allowed', `use ${found.allowed.join(' or ')}`), {
        allow: found.allowed.join(', '),
      });
    }
    const { route } = found;
    const { def } = route;
    if (ctx.via !== null) {
      // Through MCP, a route is the connection's only within its scopes, whatever the person may do.
      const needed = ROUTE_SCOPES[`${route.method} ${route.shape}` as keyof typeof ROUTE_SCOPES];
      if (needed === null || needed === undefined) throw new ApiError('forbidden', 'apps connected through MCP cannot do this: it is for people, in coffre itself');
      if (!ctx.via.scopes.includes(needed)) {
        throw new ApiError('insufficient_scope', `this needs the ${MCP_SCOPE_INFO[needed].label} scope: connect the app again with it (${scopeString(challengeScopes(ctx.via.scopes, needed))})`, needed);
      }
    }

    for (const [name, value] of Object.entries(found.params)) {
      if (PARAMS[name] !== undefined && !PARAMS[name].safeParse(value).success) {
        throw badRequest(`"${value}" is not a valid ${name}`);
      }
    }
    const raw = request.method === 'GET' ? Object.fromEntries(url.searchParams) : await readJson(request, {});
    const input = def.input === undefined ? undefined : def.input.parse(raw);
    const query =
      request.method === 'GET' || def.query === undefined
        ? undefined
        : def.query.parse(Object.fromEntries(url.searchParams));

    const place = await locate(ctx, def, found.params);
    for (const check of checks(def, input, query)) {
      const permission = typeof check === 'string' ? check : check.permission;
      const scope = placeOf(place!.project, typeof check === 'string' ? place!.environment : null);
      if (can(ctx.caller, permission, scope)) continue;
      const path = formatPath({ project: found.params.project, environment: found.params.environment, key: found.params.key });
      await refuse(
        ctx,
        new Refusal(
          forbidden(`you need ${permission} on ${typeof check === 'string' ? path : found.params.project}`),
          denied(ctx, def.action ?? `${route.method} ${route.shape}`, missing(permission), {
            projectId: place!.project.id,
            environmentId: place!.environment?.id ?? null,
            secretId: place!.secret?.id ?? null,
            metadata: { path },
          }),
        ),
      );
    }

    return jsonResponse(await def.run(ctx, { params: found.params, place, input, query } as never));
  } catch (error) {
    return errorResponse(error);
  }
}

import { z } from 'zod';

import { secretKey, slug } from '../../shared/schemas.ts';
import { errorResponse, jsonResponse, readJson } from '../http.ts';
import { can } from './caller.ts';
import { denied, missing, refuse, Refusal, type ApiContext } from './context.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatPath, resolvePath, type ResolvedPath } from './paths.ts';
import { routes, type Check, type Route } from './routes.ts';

type AnyRoute = Route<string, z.ZodType | undefined, unknown>;

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
};

/**
 * The routes a path could mean, most specific first: at the first segment
 * where two shapes differ, a literal beats a parameter. So
 * `/syncs/by-id/…` never reads as a project named `by-id`.
 */
function match(parts: string[]): { shape: string; params: Record<string, string> } | null {
  let best: { route: Compiled; params: Record<string, string> } | null = null;
  for (const route of compiled) {
    if (route.segments.length !== parts.length) continue;
    const params: Record<string, string> = {};
    const fits = route.segments.every((segment, index) => {
      if ('literal' in segment) return segment.literal === parts[index];
      params[segment.param] = parts[index];
      return true;
    });
    if (!fits) continue;
    if (best === null || moreSpecific(route, best.route)) best = { route, params };
  }
  return best === null ? null : { shape: best.route.shape, params: best.params };
}

function moreSpecific(a: Compiled, b: Compiled): boolean {
  for (let index = 0; index < a.segments.length; index += 1) {
    const aLiteral = 'literal' in a.segments[index];
    const bLiteral = 'literal' in b.segments[index];
    if (aLiteral !== bLiteral) return aLiteral;
  }
  return false;
}

function checks(def: AnyRoute, input: unknown): readonly Check[] {
  if (def.needs === undefined) return [];
  if (typeof def.needs === 'function') return def.needs(input as never);
  return typeof def.needs === 'string' || !Array.isArray(def.needs) ? [def.needs as Check] : def.needs;
}

async function locate(
  ctx: ApiContext,
  def: AnyRoute,
  params: Record<string, string>,
): Promise<ResolvedPath | null> {
  if (params.project === undefined) return null;
  const path = { project: params.project, environment: params.environment, key: params.key };
  const place = await resolvePath(ctx.db, path);
  if (place === null) throw notFound(`no project "${params.project}"`);
  const last = params.key !== undefined ? 'key' : params.environment !== undefined ? 'environment' : 'project';
  if (params.environment !== undefined && place.environment === null && !(def.creates && last === 'environment')) {
    throw notFound(`no environment "${formatPath(path).split('/').slice(0, 2).join('/')}"`);
  }
  if (params.key !== undefined && place.secret === null && !def.creates) {
    throw notFound(`no secret "${formatPath(path)}"`);
  }
  return place;
}

/**
 * Serve one API request for an authenticated caller:
 *
 *   1. match `METHOD /route`; no route is 404, a route without this method 405
 *   2. check the path's segments and parse the input (a GET's query, or the body)
 *   3. resolve the path in one query; a missing place is 404, not logged
 *   4. check the route's permissions against the caller; a refusal is logged
 *   5. run the handler
 */
export async function serveApi(request: Request, ctx: ApiContext): Promise<Response> {
  try {
    const url = new URL(request.url);
    let parts: string[];
    try {
      parts = url.pathname.replace(/^\/api/, '').split('/').filter(Boolean).map(decodeURIComponent);
    } catch {
      throw badRequest('the path is not valid percent-encoding');
    }
    const found = match(parts);
    if (found === null) throw notFound(`no route for ${url.pathname}`);
    const route = compiled.find((candidate) => candidate.shape === found.shape && candidate.method === request.method);
    if (route === undefined) {
      const allowed = compiled.filter((candidate) => candidate.shape === found.shape).map((candidate) => candidate.method);
      return errorResponse(new ApiError('method_not_allowed', `use ${allowed.join(' or ')}`), {
        allow: allowed.join(', '),
      });
    }
    const { def } = route;

    for (const [name, value] of Object.entries(found.params)) {
      if (PARAMS[name] !== undefined && !PARAMS[name].safeParse(value).success) {
        throw badRequest(`"${value}" is not a valid ${name}`);
      }
    }
    const raw = request.method === 'GET' ? Object.fromEntries(url.searchParams) : await readJson(request, {});
    const input = def.input === undefined ? undefined : def.input.parse(raw);

    const place = await locate(ctx, def, found.params);
    for (const check of checks(def, input)) {
      const permission = typeof check === 'string' ? check : check.permission;
      const scope = {
        projectId: place!.project.id,
        environmentId: typeof check === 'string' ? (place!.environment?.id ?? null) : null,
      };
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

    return jsonResponse(await def.run(ctx, { params: found.params, place, input } as never));
  } catch (error) {
    return errorResponse(error);
  }
}

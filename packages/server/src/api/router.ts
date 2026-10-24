import { MCP_SCOPE_INFO, scopeString } from '@coffre/core/mcp';
import { environmentPath, folderName, roleId, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { resolvePath, type ResolvedPath } from '../db/queries.ts';
import { errorResponse, jsonResponse, readJson } from '../http.ts';
import { can, placeOf } from './caller.ts';
import { denied, missing, refuse, Refusal, type ApiContext } from './context.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatPath } from './paths.ts';
import { makePersonal, ownerOf, resolveRead } from './personal.ts';
import { challengeScopes, ROUTE_SCOPES } from '../mcp/scopes.ts';
import { PERSONAL_TOKEN_ROUTES } from './personal-tokens.ts';
import { ISSUING_ROUTES, WORKLOAD_ROUTES } from './workload-routes.ts';
import { routes, type Check, type Route } from './routes.ts';

/**
 * The most an API request body may be, read as it streams and abandoned
 * past this: a control-plane request, a bulk secret write its largest. Well
 * above anything the CLI or UI sends for a typical change, though a very
 * large `.env` import (over this, or over `MAX_BODY_KEYS`) is refused with a
 * 400 and must be split. Bounded so no request buffers an unbounded body;
 * the body's value count is held to `MAX_BODY_NODES` in `readJson` before
 * validation, which is what keeps a parse within R27's budget.
 */
const API_BODY_BYTES = 1024 * 1024;

/**
 * The most top-level entries a request body may name, refused before it is
 * validated. A bulk write, a dismissal map and an access patch are objects
 * keyed by name, and validation does work (sometimes an error) per entry, so
 * the count is held here, before the schema walks every one. Above the
 * vault's 1000-key bulk-read cap, so a write may name more keys than one read
 * returns, as a large environment does; above any real one. Nested
 * collections (a scope, a binding's claims) are bounded by the body's total
 * value count (`MAX_BODY_NODES`); this bounds the top-level maps that would
 * otherwise drive a costly per-entry union before any key cap applied.
 */
const MAX_BODY_KEYS = 2000;

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
  // A slug, or `<slug>@me` for the caller's personal config of it.
  environment: environmentPath,
  key: secretKey,
  member: z.string().min(3).max(330),
  id: z.string().uuid(),
  enrollment: z.string().uuid(),
  code: z.string().min(1).max(16),
  folder: folderName,
  role: roleId,
  // A freeze's target, as `freezeTarget` spells it: `credential:<environment id>/<name>` sent with its `/` escaped.
  target: z.string().min(1).max(400),
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
  query: unknown,
): Promise<ResolvedPath | null> {
  if (params.project === undefined) return null;
  const path = { project: params.project, environment: params.environment, key: params.key };
  const last = params.key !== undefined ? 'key' : params.environment !== undefined ? 'environment' : 'project';
  let place = await resolvePath(ctx.db, path, { owner: ownerOf(ctx) });
  // `dev@me` while the caller has no personal config of dev: a read is of dev, a write that may make one makes it
  // (a dry run makes nothing), and anything else finds none.
  if (place?.personal !== undefined && place.environment === null) {
    const dryRun = (query as { dryRun?: string } | undefined)?.dryRun !== undefined;
    if (def.personal === 'falls back') place = await resolveRead(ctx, path);
    else if (def.personal === 'makes' && !dryRun) place = (await makePersonal(ctx, place, def.action ?? 'environment.create')).place;
    else if (def.personal === 'handles') return place;
    else throw notFound(`you have no personal config of ${params.project}/${place.personal.of.slug}: a write to ${params.project}/${params.environment} makes one`);
  }
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
 *   1. match `METHOD /route`; no route is 404, a route without this method 405;
 *      a route an MCP connection's scopes or a personal token do not reach is refused
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
      if (needed === null || needed === undefined) throw new ApiError('forbidden', 'apps connected through MCP cannot do this: only people can, in coffre itself');
      if (!ctx.via.scopes.includes(needed)) {
        throw new ApiError('insufficient_scope', `this needs the ${MCP_SCOPE_INFO[needed].label} scope: connect the app again with it (${scopeString(challengeScopes(ctx.via.scopes, needed))})`, needed);
      }
    }
    if (ctx.personalToken !== null && !PERSONAL_TOKEN_ROUTES[`${route.method} ${route.shape}` as keyof typeof PERSONAL_TOKEN_ROUTES]) {
      // A token reaches its person's secrets and places, never their access or sign-in: logged, as a token tried it.
      await refuse(
        ctx,
        new Refusal(
          forbidden('a personal token cannot do this: only its person can, signed in as themselves'),
          denied(ctx, 'token.use', 'personal_token', { metadata: { route: `${route.method} ${route.shape}` } }),
        ),
      );
    }

    const key = `${route.method} ${route.shape}` as keyof typeof WORKLOAD_ROUTES;
    if (ctx.caller.kind === 'workload' && !WORKLOAD_ROUTES[key]) {
      // A workload's session reaches what a service token does, but what only a person does, and issues nothing (docs/design/workload-access.md, section 6.1).
      const issues = ISSUING_ROUTES.has(key);
      const reason = issues ? 'workload_cannot_issue' : 'workload';
      await refuse(ctx, new Refusal(
        new ApiError('forbidden', issues ? "a workload's session issues no credential and changes no one's access" : "a workload's session cannot do this: only a person can", reason),
        denied(ctx, 'token.use', reason, { metadata: { route: key } }),
      ));
    }

    for (const [name, value] of Object.entries(found.params)) {
      if (PARAMS[name] !== undefined && !PARAMS[name].safeParse(value).success) {
        throw badRequest(`"${value}" is not a valid ${name}`);
      }
    }
    const raw = request.method === 'GET' ? Object.fromEntries(url.searchParams) : await readJson(request, API_BODY_BYTES, {});
    // An object body naming more than the cap is refused before validation walks every entry (R27): no route's body
    // carries more top-level entries, and a larger one drives per-entry work a key cap would only catch after the fact.
    if (raw !== null && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length > MAX_BODY_KEYS) {
      throw badRequest(`the body names more than ${MAX_BODY_KEYS} entries`);
    }
    const input = def.input === undefined ? undefined : def.input.parse(raw);
    const query =
      request.method === 'GET' || def.query === undefined
        ? undefined
        : def.query.parse(Object.fromEntries(url.searchParams));

    const place = await locate(ctx, def, found.params, query);
    // `dev@me` for a route that handles it, made or not: its handler checks what that takes.
    const handled = place?.personal !== undefined && def.personal === 'handles';
    for (const check of handled ? [] : checks(def, input, query)) {
      const anyOf = typeof check === 'string' ? [check] : 'anyOf' in check ? check.anyOf : [check.permission];
      const onProject = typeof check === 'object' && 'on' in check;
      const scope = placeOf(place!.project, onProject ? null : place!.environment);
      if (anyOf.some((permission) => can(ctx.caller, permission, scope))) continue;
      const permission = anyOf[0]!;
      const path = formatPath({ project: found.params.project, environment: found.params.environment, key: found.params.key });
      await refuse(
        ctx,
        new Refusal(
          forbidden(`you need ${anyOf.join(' or ')} on ${onProject ? found.params.project : path}`),
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

import { randomUUID } from 'node:crypto';

import { ownsInstance, ownsProject } from '@coffre/core/access';
import type { ProxyDefinition, ProxyView, Refusal as VaultRefusal } from '@coffre/core/vault';

import type { ResolvedPath } from '../db/queries.ts';
import { can, placeOf } from './caller.ts';
import { denied, Refusal, through, vaultCredential, withRefusals, type ApiContext } from './context.ts';
import { ApiError, badRequest, conflict, forbidden, vaultRefused } from './errors.ts';
import { formatMember } from './paths.ts';
import type { ProxyCodeItem } from '../proxy-code.ts';
import { gateProxy } from '../proxy-gate.ts';

/**
 * An environment's proxy definitions written in the UI (0.16, T186;
 * docs/design/proxy-ui.md), the Proxy tab's API. Every read and write is a
 * vault call: the vault seals the definitions, checks them on every read
 * (a forged object shows as `tampered`), and decides every save on its own
 * sealed objects. The checks here, the deployment's code first, are for the
 * page; the vault's are the guarantee.
 *
 *   GET /api/projects/market/dev/proxy                       anyone who lists market/dev
 *   PUT /api/projects/market/dev/proxy                       a person holding proxy.edit there
 *     { seal, items: { openai: { kind: 'route', … }, maps: null } }
 *   PUT /api/proxy/reserved { release: 'maps' }               an Owner of the whole instance
 */

/**
 * The tab's view: the environment's items as its sealed object holds them,
 * the names code reserved, whether this caller may save here now and why
 * not, and the items this deployment's code defines, whose rows show locked
 * with code's values (R66).
 *
 *   { items: [{ definition: { kind: 'route', name: 'openai', … }, savedBy: 'user:ada@acme.example', … }],
 *     editable: false, readOnly: { reason: 'missing_proxy_edit', message: '…' },
 *     code: [{ definition: { kind: 'route', name: 'maps', … }, environments: null, … }],
 *     routesSensitive: false, releases: false, useUrl: 'https://secrets.acme.example/use' }
 */
export type ProxyPage = ProxyView & {
  editable: boolean;
  /** Why this caller may not save here now, as the page says it; null when they may. */
  readOnly: { reason: string; message: string } | null;
  code: ProxyCodeItem[];
  /** Whether this caller's save routes the place's sensitive keys: an Owner of its project (R66), audited. */
  routesSensitive: boolean;
  /** Whether this caller releases a reserved name: an Owner of the whole instance, signed in as themselves. */
  releases: boolean;
  /** Where the proxy answers, `<publicUrl>/use`: each route at `/use/<name>`. */
  useUrl: string;
  /**
   * How long after a save values decided before it may still reach the old
   * upstream, in seconds: the proxy's `cacheSeconds`, or its 3 s deadline
   * with no cache (docs/design/proxy-ui.md, decision 4). The save says so.
   */
  windowSeconds: number;
  /** Whether a definition may reach plain HTTP and private addresses: the proxy's `insecureUpstreams`, for local fakes. */
  insecureUpstreams: boolean;
};

/** A save: the seal the page loaded (null for none yet), each item changed by name, the item or null, and whether every other one goes. */
export type ProxySave = { seal: string | null; items: Record<string, ProxyDefinition | null>; replace?: boolean };

export async function proxyPage(ctx: ApiContext, place: ResolvedPath): Promise<ProxyPage> {
  const environment = place.environment!;
  // Code's names reserved first (the gate), so that the page never shows a UI item code shadows (CodeGate).
  await gateProxy(ctx.vault, ctx.proxy ?? null);
  const view = await ctx.vault.proxy({ projectId: place.project.id, environmentId: environment.id });
  return pageOf(ctx, place, view);
}

/** The vault's view, with what the page says of this caller and this deployment's code. */
function pageOf(ctx: ApiContext, place: ResolvedPath, view: ProxyView): ProxyPage {
  const cannot = mayEdit(ctx, place);
  return {
    ...view,
    editable: cannot === null,
    readOnly: cannot === null ? null : { reason: cannot.reason, message: cannot.error.message },
    code: [...(ctx.proxy?.items ?? [])],
    routesSensitive: ownsProject(ctx.caller, place.project.id),
    releases: mayRelease(ctx),
    useUrl: `${(ctx.publicUrl ?? '').replace(/\/+$/, '')}/use`,
    windowSeconds: Math.max(ctx.proxy?.cacheSeconds ?? DEFAULT_CACHE_SECONDS, USE_DEADLINE_SECONDS),
    insecureUpstreams: ctx.proxy?.insecureUpstreams === true,
  };
}

/** The proxy's `cacheSeconds` unless set, and the deadline a use's values are sent by (R53), the window with no cache. */
const DEFAULT_CACHE_SECONDS = 60;
const USE_DEADLINE_SECONDS = 3;

/** Whether the caller releases a reserved name: an Owner of the whole instance, a person signed in as themselves. */
function mayRelease(ctx: ApiContext): boolean {
  return ctx.caller.principal.type === 'user' && ctx.caller.credentialScope === null && ownsInstance(ctx.caller);
}

/**
 * Why the caller may not save this environment's definitions, as the page
 * says it, or null: the deployment lets the tab write (`editable`), a person
 * signed in as themselves asks, at an environment that is no personal
 * config, holding `proxy.edit` there.
 */
function mayEdit(ctx: ApiContext, place: ResolvedPath): { error: ApiError; reason: string } | null {
  if (ctx.proxy?.editable !== true) return { error: conflict("this deployment's code keeps its proxy definitions: credentialProxy({ editable: true }) lets the UI write them"), reason: 'not_editable' };
  if (ctx.caller.principal.type !== 'user' || ctx.caller.credentialScope !== null) return { error: forbidden('a person edits proxy definitions, signed in as themselves'), reason: 'not_a_person' };
  if (place.environment!.owner !== null) return { error: conflict("a personal config takes no proxy definitions of its own: they are its environment's"), reason: 'route_not_personal' };
  if (!can(ctx.caller, 'proxy.edit', placeOf(place.project, place.environment))) return { error: forbidden('editing proxy definitions takes proxy.edit here: Owners hold it'), reason: 'missing_proxy_edit' };
  return null;
}

export async function saveProxy(ctx: ApiContext, place: ResolvedPath, input: ProxySave): Promise<ProxyPage> {
  const environment = place.environment!;
  const where = { projectId: place.project.id, environmentId: environment.id };
  await gateProxy(ctx.vault, ctx.proxy ?? null);
  return withRefusals(ctx, async () => {
    const refused = (error: ApiError, reason: string, metadata: Record<string, unknown> = {}) =>
      new Refusal(error, denied(ctx, 'proxy.save', reason, { ...where, metadata: { names: Object.keys(input.items), ...metadata } }));
    const cannot = mayEdit(ctx, place);
    if (cannot !== null) throw refused(cannot.error, cannot.reason);
    const code = ctx.proxy!;
    // What needs this deployment's code, which the vault cannot see: a name code defines, and an egress or a network it
    // declares. A courtesy to the editor: the guarantee is the check at use, on the code of the isolate that sends.
    const taken = Object.keys(input.items).find((name) => input.items[name] !== null && code.names.includes(name));
    if (taken !== undefined) throw refused(conflict(`${taken} is defined in this deployment's code, which wins the name in every environment`), 'reserved', { name: taken });
    for (const definition of Object.values(input.items)) {
      const transport = definition?.kind === 'route' ? definition.egress : definition?.kind === 'tunnel' ? definition.network : null;
      if (transport != null) throw badRequest(`${definition!.name}: this deployment's code declares no ${definition!.kind === 'route' ? 'egress' : 'network'} named ${transport}`);
    }
    const saved = await ctx.vault.saveProxy({
      actor: formatMember(ctx.caller.principal),
      ...where,
      seal: input.seal,
      items: input.items,
      ...(input.replace === undefined ? {} : { replace: input.replace }),
      insecureUpstreams: code.insecureUpstreams,
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: vaultCredential(ctx),
      ...through(ctx.caller),
    });
    if (!saved.ok) throw proxyRefused(saved.refusal);
    return pageOf(ctx, place, saved.view);
  });
}

/**
 * A reserved name freed, instance-wide: an Owner of the whole instance, signed
 * in as themselves, and never a name this deployment's code still defines.
 * Whether an older deployment still serving defines it, nothing can check:
 * the page says so before it asks.
 */
export async function releaseReserved(ctx: ApiContext, input: { release: string }): Promise<{ reserved: string[] }> {
  await gateProxy(ctx.vault, ctx.proxy ?? null);
  return withRefusals(ctx, async () => {
    const refused = (error: ApiError, reason: string) => new Refusal(error, denied(ctx, 'proxy.release', reason, { metadata: { name: input.release } }));
    if (!mayRelease(ctx)) {
      throw refused(forbidden('a released name is free in every project: only an Owner of the whole instance, signed in as themselves, releases one'), 'requires_instance_owner');
    }
    if (ctx.proxy?.names.includes(input.release) === true) throw refused(conflict(`${input.release} is defined in this deployment's code: it stays reserved while code defines it`), 'defined_in_code');
    const released = await ctx.vault.releaseProxy({
      actor: formatMember(ctx.caller.principal),
      name: input.release,
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: vaultCredential(ctx),
      ...through(ctx.caller),
    });
    if (!released.ok) throw proxyRefused(released.refusal);
    return { reserved: released.reserved };
  });
}

/**
 * The vault's refusal of a proxy change: a page behind another's save, a
 * reserved name, or a forged object to replace whole, a conflict (409);
 * a definition the rules refuse, a bad request; a key its editor may not
 * route, or no permission, the vault's refusal (403).
 */
function proxyRefused(refusal: VaultRefusal): ApiError {
  if (refusal.code === 'proxy_changed' || refusal.code === 'reserved' || refusal.code === 'tampered') return new ApiError('conflict', refusal.message, refusal.code);
  if (refusal.code === 'invalid') return new ApiError('bad_request', refusal.message, refusal.code);
  return vaultRefused(refusal);
}

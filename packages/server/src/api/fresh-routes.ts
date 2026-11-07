// Which API routes take a fresh check (docs/design/passkeys.md, section 4):
// a session a passkey touch confirmed in the last five minutes. The rule: it
// guards what widens someone's reach, mints a credential, or cannot be
// undone. Removing access, revoking, freezing and protecting never take one:
// in an incident they must be quick. Typed over the route table, as
// `PERSONAL_TOKEN_ROUTES` is, so a route added to the API fails the
// typecheck here until it says.
import { personalOf } from '@coffre/core/schemas';
import type { Confirmation } from '@coffre/core/vault';
import type { z } from 'zod';

import type { ApiContext } from './context.ts';
import { callerName, FreshCheckRequired } from './errors.ts';
import type { Params, RouteKey, Routes } from './routes.ts';

/**
 * What a route takes:
 *
 *   always    a fresh session; a person with no passkey yet, under `optional`, adds one first
 *   holder    a fresh session if the person holds a passkey; nothing otherwise
 *   ceremony  a touch of its own, for that act alone, which its handler asks (`403 touch_required`, section 4.2)
 *   handler   its handler decides, from what it reads anyway, before it writes (`requireFresh`)
 *   never
 *
 * Under `off`, and for a service, nothing is ever asked.
 */
export type Fresh = 'always' | 'holder' | 'ceremony' | 'handler' | 'never';

type Parsed<S> = [S] extends [never] ? undefined : S extends z.ZodType ? z.output<S> : undefined;
type BodyOf<K extends RouteKey> = Parsed<NonNullable<Routes[K]['input']>>;
type QueryOf<K extends RouteKey> = Parsed<NonNullable<Routes[K]['query']>>;

/** What a route's handler gets, typed per route: its path's parameters, its parsed body and its parsed query. */
export type Asked<K extends RouteKey> = { params: Params<K>; input: BodyOf<K>; query: QueryOf<K> };

/** What an answer may weigh beside the request: the session it came in on, a browser's or a terminal's. */
export type Asking = Pick<ApiContext, 'session'>;

type Answer<K extends RouteKey> = Fresh | ((asked: Asked<K>, ctx: Asking) => Fresh);

/** `?dryRun=1` makes nothing, so it needs no check, on the routes that take it, and only when the parsed query says so. */
const unlessDry = (fresh: Fresh) => ({ query }: { query: { dryRun?: string } }): Fresh => (query.dryRun === undefined ? fresh : 'never');

export const FRESH_ROUTES: { [K in RouteKey]: Answer<K> } = {
  'GET /me': 'never',
  'GET /projects': 'never',
  'PUT /projects/:project': 'never',
  'PATCH /projects/:project': 'never',
  // Erasing for good; its `?dryRun=1` says what it would erase.
  'DELETE /projects/:project': unlessDry('always'),
  'PUT /projects/:project/:environment': 'never',
  // Unprotecting lets every role's reach in again; protecting, as any other edit, is quick.
  'PATCH /projects/:project/:environment': ({ input }) => (input.protected === false ? 'always' : 'never'),
  // Erasing an environment for good; but a person's own personal config (`dev@me`) holds only what they wrote there,
  // and erasing it widens nobody's reach.
  'DELETE /projects/:project/:environment': ({ params, query }) =>
    query.dryRun !== undefined || personalOf(params.environment) !== null ? 'never' : 'always',
  'GET /personal/:project': 'never',
  'GET /projects/:project/:environment/missing': 'never',
  'GET /projects/:project/:environment/version': 'never',
  'GET /projects/:project/:environment/proxy': 'never',
  'PUT /projects/:project/:environment/proxy': 'never',
  'PATCH /projects/:project/:environment/dismissals': 'never',
  'GET /secrets/:project/:environment': 'never',
  // A sensitive value made a secret in place (R30), which people could not read and now can, is decided where the
  // write reads each key's level (`marking`); a write that keeps or tightens a level, or writes a value again, needs nothing.
  'PATCH /secrets/:project/:environment': 'handler',
  'PATCH /secrets/:project/:environment/:key': 'never',
  'GET /secrets/:project/:environment/:key/versions': 'never',
  // An old version comes back no looser than it was (`restoreVersion`).
  'POST /secrets/:project/:environment/:key/restore': 'never',
  'DELETE /secrets/:project/:environment/:key/reference': 'never',
  'PATCH /folders/:folder': 'never',
  'DELETE /folders/:folder': 'never',
  'PATCH /folders/:project/:environment/:folder': 'never',
  'DELETE /folders/:project/:environment/:folder': 'never',
  'GET /references': 'never',
  // Reads take no touch, in a protected environment or any other (section 4.3).
  'POST /reveals': 'never',
  'GET /members': 'never',
  'GET /members/:member': 'never',
  'GET /members/:member/access': 'never',
  // A member added or restored with a role, scope and grants.
  'PUT /members/:member': 'always',
  // Removing an Owner is the other way to demote one, and removing every other Owner a takeover's step.
  'DELETE /members/:member': 'always',
  'GET /members/:member/tokens': 'never',
  // A service's token; a person's own from a browser, which outlives its 12 hours, if they hold a passkey; from a
  // terminal, nothing: it holds at most what the terminal's session does, which its approval's touch confirmed.
  'POST /members/:member/tokens': ({ params, query }, ctx) =>
    query.dryRun !== undefined ? 'never' : !params.member.startsWith('user:') ? 'always' : ctx.session?.kind === 'browser' ? 'holder' : 'never',
  'POST /handles': 'never',
  'DELETE /handles/:id': 'never',
  'DELETE /members/:member/tokens/:id': 'never',
  'GET /members/:member/passkeys': 'never',
  // Another passkey, from a session a touch confirmed in the last five minutes; a person with none adds a first at sign-in (`add_passkey`).
  'POST /members/:member/passkeys/options': 'always',
  'POST /members/:member/passkeys': 'always',
  // A name grants nothing (section 3.6).
  'PATCH /members/:member/passkeys/:id': 'never',
  // Resetting someone's passkeys (section 3.7).
  'DELETE /members/:member/passkeys': 'always',
  'GET /members/:member/bindings': 'never',
  // A trust binding, and the keys it trusts: what a CI run or a workload signs in with.
  'POST /members/:member/bindings': unlessDry('always'),
  'POST /members/:member/bindings/keys': unlessDry('always'),
  'GET /workloads/lookup': 'never',
  'GET /workloads/repositories': 'never',
  'DELETE /members/:member/bindings/:id': 'never',
  'GET /members/:member/bindings/:id/enrollments': 'never',
  // An enrollment code, and making one current.
  'POST /members/:member/bindings/:id/enrollments': 'always',
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': 'always',
  // A workload's session waiting for a person.
  'POST /members/:member/tokens/:id/approve': 'always',
  'GET /freezes': 'never',
  'POST /freezes': 'never',
  // Lifting a freeze lets its uses through again.
  'DELETE /freezes/:target': 'always',
  'GET /roles': 'never',
  // What every holder of a role may do; its `?dryRun=1` weighs the change.
  'PUT /roles/:role': unlessDry('always'),
  'DELETE /roles/:role': unlessDry('always'),
  'PUT /instance-roles/:role': unlessDry('always'),
  'DELETE /instance-roles/:role': unlessDry('always'),
  'PUT /proxy/reserved': 'never',
  'GET /settings': 'never',
  // Where people may set up service accounts.
  'PUT /settings': 'always',
  // Grants, an instance role, an Owner's promotion and demotion. It takes no `dryRun`: a `?dryRun=1` on it is ignored
  // and the change made, so it is checked like any other request.
  'PATCH /access/:member': 'always',
  'GET /sessions': 'never',
  'DELETE /sessions/:id': 'never',
  'GET /identities': 'never',
  'DELETE /identities/:id': 'never',
  'GET /device-logins/:code': 'never',
  // A 30-day terminal, a connected client, an MCP client's change: a touch of their own, for that one act (section 4.2).
  'POST /device-logins/:code': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'GET /oauth/authorizations': 'never',
  'POST /oauth/authorizations': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'GET /approvals/:id': 'never',
  'POST /approvals/:id': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'GET /apps': 'never',
  'DELETE /apps/:id': 'never',
  'GET /audit': 'never',
  'GET /audit/verification': 'never',
  'GET /audit/trees': 'never',
  'GET /audit/reads': 'never',
  'GET /audit/keys': 'never',
  // Accepting lost entries for good.
  'POST /audit/loss': 'always',
};

/** How long a touch keeps its session fresh: Erwin's five minutes (D170, open question 1). */
export const FRESH_MS = 5 * 60 * 1000;

/**
 * Where a request stands for a fresh check:
 *
 *   exempt  nothing is asked: the policy is `off`, or the caller is no person (a service, a workload, the shown caller)
 *   fresh   a browser or terminal session a touch confirmed in the last five minutes, or an MCP client's change its
 *           person approved with a touch of its own (`McpVia.touched`), which stands for the change's check (section 4.4)
 *   stale   a person who holds a passkey, on anything else: an older session, a personal token, an MCP connection
 *   none    a person who holds none, under `optional`: their credential names none, which the request's own check
 *           (`passkeyStands`) takes only while they hold no live one
 */
export type Freshness = 'exempt' | 'fresh' | 'stale' | 'none';

export function freshness(ctx: Pick<ApiContext, 'signin' | 'caller' | 'session' | 'via' | 'personalToken' | 'passkeyId'>, now = Date.now()): Freshness {
  if (ctx.signin === null || ctx.signin.config.passkeys.policy === 'off' || ctx.caller.principal.type !== 'user') return 'exempt';
  if (ctx.via != null) {
    if (ctx.via.approvalId !== undefined && ctx.via.touched !== undefined) return 'fresh';
  } else if (ctx.personalToken === null && ctx.session?.confirmedAt != null) {
    const age = now - ctx.session.confirmedAt.getTime();
    // A confirmation ahead of this clock is no older than now: a clock behind the one that wrote it.
    if (age < FRESH_MS) return 'fresh';
  }
  return ctx.passkeyId === null ? 'none' : 'stale';
}

/**
 * What confirmed a fresh request: the touch that approved its MCP change, or its session's, whose passkey the session
 * names (a touch issues the session it confirms, on the passkey touched: section 6.5).
 */
function confirmation(ctx: Pick<ApiContext, 'session' | 'via' | 'passkeyId'>): Confirmation | null {
  if (ctx.via?.touched !== undefined) return ctx.via.touched;
  const at = ctx.session?.confirmedAt;
  return at == null || ctx.passkeyId === null ? null : { by: ctx.passkeyId, at: at.toISOString() };
}

/** Whether a route's answer lets the request through as it stands; false: refused `fresh_check_required`. */
export function freshEnough(fresh: Fresh, stands: Freshness): boolean {
  if (fresh === 'always') return stands === 'exempt' || stands === 'fresh';
  if (fresh === 'holder') return stands !== 'stale';
  return true;
}

/** The answer of a route to this request. */
export function freshAnswer<K extends RouteKey>(key: K, asked: Asked<K>, ctx: Asking): Fresh {
  const answer = FRESH_ROUTES[key] as Answer<K>;
  return typeof answer === 'function' ? answer(asked, ctx) : answer;
}

/**
 * Whether a request is fresh enough for an answer, and if so what confirmed it: the touch, when one let it through, or
 * null when nothing needed to (`exempt`, or `holder` of a person with no passkey). Null for a request that is not.
 */
export function freshPass(
  ctx: Pick<ApiContext, 'signin' | 'caller' | 'session' | 'via' | 'personalToken' | 'passkeyId'>,
  fresh: Fresh,
): { stands: Freshness; confirmed: Confirmation | null } {
  const stands = freshness(ctx);
  const touched = freshEnough(fresh, stands) && stands === 'fresh' && (fresh === 'always' || fresh === 'holder');
  return { stands, confirmed: touched ? confirmation(ctx) : null };
}

/**
 * Hold a request to an answer, refusing it `fresh_check_required` if it is not fresh enough: the router's check, and a
 * `handler` route's own once it knows (`marking`). Let through on a touch, the request records what confirmed it
 * (`ApiContext.confirmed`), which every entry it writes names (section 11).
 */
export function requireFresh(
  ctx: Pick<ApiContext, 'signin' | 'caller' | 'session' | 'via' | 'personalToken' | 'passkeyId' | 'credentialId' | 'requestId' | 'confirmed'>,
  fresh: Fresh,
  route: string,
): void {
  const { stands, confirmed } = freshPass(ctx, fresh);
  if (freshEnough(fresh, stands)) {
    if (confirmed !== null) ctx.confirmed = confirmed;
    return;
  }
  console.warn('an act a fresh check guards was refused', { principal: `user:${ctx.caller.principal.id}`, route, credentialId: ctx.credentialId, requestId: ctx.requestId });
  throw new FreshCheckRequired(stands as 'stale' | 'none', callerName(ctx.caller.principal));
}

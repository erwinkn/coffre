import { isDeploying, isStackOverflow, isUnsealed } from '@coffre/core/vault';
import { z } from 'zod';

import { gaveUp, isUnavailable } from '@coffre/db/dialect';
import { KeyRetired } from '@coffre/db/log';

import { logged } from '../logged.ts';
import { Superseded } from '../watch.ts';

/**
 * Every API error has one shape, `{ "error": code, "message": sentence }`,
 * and the code decides the status:
 *
 *   400 bad_request        the input does not parse, or names nothing usable
 *   401 unauthenticated    no credential, or one that did not verify
 *   401 passkey_required   a credential no live passkey stands behind, while the person holds one or the policy is `required`
 *   403 forbidden          the caller lacks the permission
 *   403 registration_required  signed in, but not a member of this instance
 *   403 cross_origin       a change sent with a browser cookie, from another site
 *   403 vault_refused      the vault said no; `reason` is its code (`no_grant`, `removed`, ...)
 *   403 bulk_limit         the vault said no: too many secrets read in too short a time
 *   403 insufficient_scope a request through MCP whose connection lacks the scope the route needs
 *   403 touch_required     an act that takes a touch of the caller's passkey of its own (passkeys.md, section 4.2): `touch`
 *                          carries what to ask the authenticator, for this act and this session alone; send the act again with its answer
 *   403 touch_failed       that touch did not check: no live passkey of the caller's, a signature or flag that fails, or a replay
 *   403 fresh_check_required  an act that takes a session a passkey touch confirmed in the last five minutes (passkeys.md,
 *                          section 4): confirm at the step-up and send it again, with `caller` as its `coffre-caller`
 *                          header; `reason: 'add_passkey'` when the person holds none yet, who adds one first
 *   404 not_found          no such project, environment, secret or member
 *   404 not_available      a key a request named, by name, that it may not have: none such, or no access to it, alike (D153)
 *   405 method_not_allowed
 *   409 conflict           the request is valid but the current state refuses it; `reason: 'caller_changed'`: an act
 *                          sent again after its fresh check, by another person than the one who sent it first
 *   429 too_many_requests  too many sign-ins waiting; try again later
 *   501 not_implemented    a route this release declares and does not serve yet
 *   503 unavailable        something coffre needs is not answering: the vault, a platform, its database
 *   503 migrating          the database lacks this version's migrations: nothing is served until `coffre migrate`
 *   503 rotating           the app is moving to its new key: nothing is served until it has (key-rotation.ts)
 *   503 app_key            the log is under an app key this deployment does not hold, or has moved on from its own
 *   500 internal_error     a bug; the details are in the server log only
 *
 * The message is written for a person and is safe to show them.
 */
export const ERROR_STATUS = {
  bad_request: 400,
  unauthenticated: 401,
  passkey_required: 401,
  forbidden: 403,
  registration_required: 403,
  cross_origin: 403,
  vault_refused: 403,
  bulk_limit: 403,
  insufficient_scope: 403,
  touch_required: 403,
  touch_failed: 403,
  fresh_check_required: 403,
  not_found: 404,
  not_available: 404,
  method_not_allowed: 405,
  conflict: 409,
  too_many_requests: 429,
  not_implemented: 501,
  unavailable: 503,
  deploying: 503,
  migrating: 503,
  rotating: 503,
  app_key: 503,
  internal_error: 500,
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

export type ErrorBody = { error: ErrorCode; message: string; reason?: string; touch?: TouchAsked; caller?: string };

/** What a `403 touch_required` asks: `get()`'s options, in WebAuthn's JSON form, and the sealed state to send back with its answer. */
export type TouchAsked = { options: unknown; state: string };

export class ApiError extends Error {
  readonly code: ErrorCode;
  /** Why, as a code: the vault's own for `vault_refused` and `bulk_limit`, and the app's for a logged refusal, which its entry names too. */
  readonly reason: string | undefined;
  /** For a 503, when to ask again, in seconds (`Retry-After`), when it is not `UNAVAILABLE_RETRY_AFTER`: a busy use's, the vault's own. */
  readonly retryAfter: string | undefined;

  constructor(code: ErrorCode, message: string, reason?: string, retryAfter?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.reason = reason;
    this.retryAfter = retryAfter;
  }

  get status(): number {
    return ERROR_STATUS[this.code];
  }
}

/** An act refused until it carries a touch of its own (passkeys.md, section 4.2): a prompt, which writes no entry. */
export class TouchRequired extends ApiError {
  readonly touch: TouchAsked;

  constructor(message: string, touch: TouchAsked) {
    super('touch_required', message);
    this.name = 'TouchRequired';
    this.touch = touch;
  }
}

/**
 * An act refused for a fresh check (passkeys.md, section 4.5), before anything is written: a prompt, which writes no
 * entry, only a line in the process log (`requireFresh`). `caller` names who sent it, opaquely (`user:<id>`): a browser sends the act again, after the touch, saying
 * so (`coffre-caller`), and the act goes only if the same person sends it (`CALLER_HEADER`, `serveApi`).
 */
export class FreshCheckRequired extends ApiError {
  readonly caller: string;

  constructor(stands: 'stale' | 'none', caller: string) {
    super(
      'fresh_check_required',
      stands === 'none'
        ? 'this takes a passkey: add one, then try again'
        : 'this takes a fresh touch of your passkey: confirm it is you, then try again',
      stands === 'none' ? 'add_passkey' : undefined,
    );
    this.name = 'FreshCheckRequired';
    this.caller = caller;
  }
}

/**
 * The header an act sent again after its fresh check carries: the `caller` its refusal named. Another person's session
 * since (another tab signed in as them) refuses it, `409 caller_changed`, before anything is read or written: the touch
 * confirmed their session, and the act was asked by someone else.
 */
export const CALLER_HEADER = 'coffre-caller';

/** Who a request's caller is, as a fresh check's refusal names them and its act's second sending says. */
export function callerName(principal: { type: string; id: string }): string {
  return `${principal.type}:${principal.id}`;
}

/**
 * The vault's refusal of a use by ids it decided before writing anything (`number` null: its key would have taken
 * its principal's lock, which only a use the vault allowed takes; DecideBeforeLock, review r2 of D153). Answered as
 * the refusal it carries; the vault logged no request, so the app does, whoever asked (`withRefusals`), with `fields`:
 * where the use was, its key, its operation and its purpose.
 */
export class UnloggedRefusal extends ApiError {
  fields: { projectId?: string; environmentId?: string; secretId?: string; operationId?: string | null; metadata?: Record<string, unknown> };

  constructor(refusal: ApiError, fields: UnloggedRefusal['fields']) {
    super(refusal.code, refusal.message, refusal.reason, refusal.retryAfter);
    this.name = 'UnloggedRefusal';
    this.fields = fields;
  }
}

export const badRequest = (message: string) => new ApiError('bad_request', message);
export const forbidden = (message = 'you do not have permission to do that') =>
  new ApiError('forbidden', message);
export const notFound = (message = 'not found') => new ApiError('not_found', message);
export const conflict = (message: string) => new ApiError('conflict', message);
/**
 * A key a request named that it may not have, whatever the reason (D153): there is none of that name, the caller may
 * not use it, or read it, a reference it is has ended, a row of it was put back. One answer for all, so that nobody
 * learns a key is held from being refused it; the reason is the audit log's.
 */
export const notAvailable = () => new ApiError('not_available', 'not available: no such key, or no access to it');
/**
 * A route of docs/design/workload-access.md that is declared, in every map
 * that lists the API, before the change that serves it: its message names
 * that change.
 */
export const notBuilt = (what: string, change: string) =>
  new ApiError('not_implemented', `${what} is not served yet: docs/design/workload-access.md, ${change}, brings it`);

/** The vault's refusal, as the API answers it. */
export function vaultRefused(refusal: { code: string; message: string }): ApiError {
  if (refusal.code === 'bulk_limit') {
    return new ApiError('bulk_limit', 'too many secrets read in too short a time; try again later', refusal.code);
  }
  // A sensitive value, which no person is handed: not a refusal of their access, which the message says how to use.
  if (refusal.code === 'sensitive') return new ApiError('forbidden', refusal.message, refusal.code);
  // A sensitive value its credential's issuer could not hand a service account (R32): the message says who can.
  if (refusal.code === 'not_owner_issued') return new ApiError('forbidden', refusal.message, refusal.code);
  // Not the caller's doing: the instance is misconfigured, and stays unable to open any value until restarted.
  if (refusal.code === 'wrong_kek') return new ApiError('unavailable', refusal.message, refusal.code);
  // Valid, and refused only by who else owns the instance now: the message says what to do first.
  if (refusal.code === 'last_owner') return new ApiError('conflict', refusal.message, refusal.code);
  return new ApiError('vault_refused', `the vault refused: ${refusal.message}`, refusal.code);
}

/**
 * What a request is told when what coffre needs did not answer: its
 * database, mostly, but the same words come from the vault's RPC and from
 * a key service, which coffre cannot tell apart from here.
 */
export const UNAVAILABLE = 'coffre cannot reach what it depends on right now; try again in a moment';

/**
 * How long, in seconds, a 503 `unavailable` tells its caller to wait
 * (`Retry-After`): what it waited on, a lock or a connection, gives up
 * after 15 s, and a caller back sooner than a few seconds joins the same
 * queue it left.
 */
export const UNAVAILABLE_RETRY_AFTER = '5';

/**
 * What a change is told when it committed but its seal did not come in time
 * (T169; R51): it is in force, and nothing says so yet but the log.
 */
export const UNSEALED_MESSAGE = 'coffre made this change, but could not seal it in its audit log in time; it will once it can. Check before you make it again';

/**
 * What a refused key write or first add is told when the record of its refusal (T179 PR 6, refused.ts) committed but
 * its seal did not come in time: as `UNSEALED_MESSAGE`'s 503, but nothing was changed, so it says so (review r2).
 */
export const REFUSAL_UNSEALED_MESSAGE = 'coffre did not make this change, but could not seal its refusal in its audit log in time; it will once it can. Try again in a moment';

/**
 * What a request is told while the app and the vault run two releases, for
 * the seconds of a deploy (`Deploying`, docs/design/proxy-ui.md, section 3):
 * the vault ran nothing, and the same request a second later is served.
 */
export const DEPLOYING = 'coffre is deploying a new release: try again in a second';

/** How long a 503 `deploying` tells its caller to wait (`Retry-After`): a deploy moves both Workers within seconds. */
export const DEPLOYING_RETRY_AFTER = '1';

/** The status and body for anything a handler throws. */
/** A body nested deeper than coffre can walk, said once for every entry point. */
export const NESTED_TOO_DEEPLY = 'the body is nested too deeply to read: flatten it';

export function toErrorBody(error: unknown): { status: number; body: ErrorBody } {
  // The vault on another release than this app (`versioned`): it read and wrote nothing. Not logged: a deploy's seconds.
  if (isDeploying(error)) return { status: 503, body: { error: 'deploying', message: DEPLOYING } };
  if (error instanceof ApiError) {
    const body: ErrorBody = { error: error.code, message: error.message };
    if (error.reason !== undefined) body.reason = error.reason;
    if (error instanceof TouchRequired) body.touch = error.touch;
    if (error instanceof FreshCheckRequired) body.caller = error.caller;
    return { status: error.status, body };
  }
  // An instance still under a key the log moved on from, as for the seconds a deploy takes: refused, not a bug.
  if (error instanceof KeyRetired || error instanceof Superseded) {
    return { status: 503, body: { error: 'app_key', message: 'this instance runs under an app key the audit log has moved on from: a newer deployment replaces it' } };
  }
  // A body nested deeper than a walk of it holds (`STACK_OVERFLOW`): the caller's to fix, as any input that does not
  // read. Logged as well, so that a recursion of coffre's own, which looks the same, still shows.
  if (isStackOverflow(error)) {
    console.error('a request nested too deeply to read', logged(error));
    return { status: 400, body: { error: 'bad_request', message: NESTED_TOO_DEEPLY } };
  }
  if (error instanceof z.ZodError) {
    const issue = error.issues[0];
    const where = issue && issue.path.length > 0 ? `${issue.path.join('.')}: ` : '';
    return {
      status: 400,
      body: { error: 'bad_request', message: `${where}${issue?.message ?? 'invalid input'}` },
    };
  }
  // A change committed whose seal did not come in time (T169): the vault's checkpointer stalled or did not answer.
  if (isUnsealed(error)) {
    console.error('a change was not sealed in time', logged(error));
    return { status: 503, body: { error: 'unavailable', message: UNSEALED_MESSAGE } };
  }
  // The database not answering, the vault's behind its call, or a key service's: the request was fine, and may be
  // asked again; a write whose connection dropped may have committed, which a look at it says. A statement that gave
  // up waiting is logged apart: under a busy database it is an outage, but a transaction held too long, across a
  // vault call say, is a bug that looks the same.
  if (isUnavailable(error)) {
    console.error(gaveUp(error) ? 'a statement gave up waiting' : 'a dependency did not answer', logged(error));
    return { status: 503, body: { error: 'unavailable', message: UNAVAILABLE } };
  }
  console.error('unhandled API error', logged(error));
  return {
    status: 500,
    body: { error: 'internal_error', message: 'something went wrong; see the server log' },
  };
}

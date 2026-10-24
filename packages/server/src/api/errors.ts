import { z } from 'zod';

import { KeyRetired } from '@coffre/db/log';

import { logged } from '../logged.ts';

/**
 * Every API error has one shape, `{ "error": code, "message": sentence }`,
 * and the code decides the status:
 *
 *   400 bad_request        the input does not parse, or names nothing usable
 *   401 unauthenticated    no credential, or one that did not verify
 *   403 forbidden          the caller lacks the permission
 *   403 registration_required  signed in, but not a member of this instance
 *   403 cross_origin       a change sent with a browser cookie, from another site
 *   403 vault_refused      the vault said no; `reason` is its code (`no_grant`, `removed`, ...)
 *   403 bulk_limit         the vault said no: too many secrets read in too short a time
 *   403 insufficient_scope a request through MCP whose connection lacks the scope the route needs
 *   404 not_found          no such project, environment, secret or member
 *   405 method_not_allowed
 *   409 conflict           the request is valid but the current state refuses it
 *   429 too_many_requests  too many sign-ins waiting; try again later
 *   501 not_implemented    a route this release declares and does not serve yet
 *   503 unavailable        something coffre needs is not answering
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
  forbidden: 403,
  registration_required: 403,
  cross_origin: 403,
  vault_refused: 403,
  bulk_limit: 403,
  insufficient_scope: 403,
  not_found: 404,
  method_not_allowed: 405,
  conflict: 409,
  too_many_requests: 429,
  not_implemented: 501,
  unavailable: 503,
  migrating: 503,
  rotating: 503,
  app_key: 503,
  internal_error: 500,
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

export type ErrorBody = { error: ErrorCode; message: string; reason?: string };

export class ApiError extends Error {
  readonly code: ErrorCode;
  /** Why, as a code: the vault's own for `vault_refused` and `bulk_limit`, and the app's for a logged refusal, which its entry names too. */
  readonly reason: string | undefined;

  constructor(code: ErrorCode, message: string, reason?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.reason = reason;
  }

  get status(): number {
    return ERROR_STATUS[this.code];
  }
}

export const badRequest = (message: string) => new ApiError('bad_request', message);
export const forbidden = (message = 'you do not have permission to do that') =>
  new ApiError('forbidden', message);
export const notFound = (message = 'not found') => new ApiError('not_found', message);
export const conflict = (message: string) => new ApiError('conflict', message);
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

/** The status and body for anything a handler throws. */
export function toErrorBody(error: unknown): { status: number; body: ErrorBody } {
  if (error instanceof ApiError) {
    const body: ErrorBody = { error: error.code, message: error.message };
    if (error.reason !== undefined) body.reason = error.reason;
    return { status: error.status, body };
  }
  // An instance still under a key the log moved on from, as for the seconds a deploy takes: refused, not a bug.
  if (error instanceof KeyRetired) {
    return { status: 503, body: { error: 'app_key', message: 'this instance runs under an app key the audit log has moved on from: a newer deployment replaces it' } };
  }
  if (error instanceof z.ZodError) {
    const issue = error.issues[0];
    const where = issue && issue.path.length > 0 ? `${issue.path.join('.')}: ` : '';
    return {
      status: 400,
      body: { error: 'bad_request', message: `${where}${issue?.message ?? 'invalid input'}` },
    };
  }
  console.error('unhandled API error', logged(error));
  return {
    status: 500,
    body: { error: 'internal_error', message: 'something went wrong; see the server log' },
  };
}

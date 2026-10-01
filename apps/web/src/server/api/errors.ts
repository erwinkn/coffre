import { z } from 'zod';

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
 *   404 not_found          no such project, environment, secret, member or sync
 *   405 method_not_allowed
 *   409 conflict           the request is valid but the current state refuses it
 *   429 too_many_requests  too many sign-ins waiting; try again later
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
  not_found: 404,
  method_not_allowed: 405,
  conflict: 409,
  too_many_requests: 429,
  unavailable: 503,
  internal_error: 500,
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

export type ErrorBody = { error: ErrorCode; message: string; reason?: string };

export class ApiError extends Error {
  readonly code: ErrorCode;
  /** The vault's own code, for `vault_refused` and `bulk_limit`. */
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

/** The vault's refusal, as the API answers it. */
export function vaultRefused(refusal: { code: string; message: string }): ApiError {
  return refusal.code === 'bulk_limit'
    ? new ApiError('bulk_limit', 'too many secrets read in too short a time; try again later', refusal.code)
    : new ApiError('vault_refused', `the vault refused: ${refusal.message}`, refusal.code);
}

/** The status and body for anything a handler throws. */
export function toErrorBody(error: unknown): { status: number; body: ErrorBody } {
  if (error instanceof ApiError) {
    const body: ErrorBody = { error: error.code, message: error.message };
    if (error.reason !== undefined) body.reason = error.reason;
    return { status: error.status, body };
  }
  if (error instanceof z.ZodError) {
    const issue = error.issues[0];
    const where = issue && issue.path.length > 0 ? `${issue.path.join('.')}: ` : '';
    return {
      status: 400,
      body: { error: 'bad_request', message: `${where}${issue?.message ?? 'invalid input'}` },
    };
  }
  console.error('unhandled API error', error);
  return {
    status: 500,
    body: { error: 'internal_error', message: 'something went wrong; see the server log' },
  };
}

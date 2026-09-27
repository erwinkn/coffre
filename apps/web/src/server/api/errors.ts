import { z } from 'zod';

/**
 * Every API error has one shape, `{ "error": code, "message": sentence }`,
 * and the code decides the status:
 *
 *   400 bad_request        the input does not parse, or names nothing usable
 *   401 unauthenticated    no credential, or one that did not verify
 *   403 forbidden          the caller lacks the permission
 *   403 registration_required  signed in, but not a member of this instance
 *   404 not_found          no such project, environment, secret, member or sync
 *   405 method_not_allowed
 *   409 conflict           the request is valid but the current state refuses it
 *   500 internal_error     a bug; the details are in the server log only
 *
 * The message is written for a person and is safe to show them.
 */
export const ERROR_STATUS = {
  bad_request: 400,
  unauthenticated: 401,
  forbidden: 403,
  registration_required: 403,
  not_found: 404,
  method_not_allowed: 405,
  conflict: 409,
  unavailable: 503,
  internal_error: 500,
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

export type ErrorBody = { error: ErrorCode; message: string };

export class ApiError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
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

/** The status and body for anything a handler throws. */
export function toErrorBody(error: unknown): { status: number; body: ErrorBody } {
  if (error instanceof ApiError) {
    return { status: error.status, body: { error: error.code, message: error.message } };
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

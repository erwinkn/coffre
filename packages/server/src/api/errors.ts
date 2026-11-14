import { z } from 'zod';

import { gaveUp, isUnavailable } from '@coffre/db/dialect';

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
 *   403 vault_refused      the vault said no; `reason` is its word (`no_access`, ...)
 *   403 bulk_limit         the vault said no: too many secrets read in too short a time
 *   403 insufficient_scope a request through MCP whose connection lacks the scope the route needs
 *   404 not_found          no such project, environment, secret or member
 *   405 method_not_allowed
 *   409 conflict           the request is valid but the current state refuses it
 *   429 too_many_requests  too many sign-ins waiting; try again later
 *   501 not_implemented    a route this release declares and does not serve yet
 *   503 unavailable        something coffre needs is not answering: the vault, a platform, its database
 *   503 migrating          the database lacks this version's migrations: nothing is served until `coffre migrate`
 *   503 adopting           the vault has not taken the database over yet: nobody signs in until it has
 *   500 tampered           a row the vault read is not one it wrote: the operator reads which in the server log
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
  adopting: 503,
  tampered: 500,
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
 * The vault's refusals the API words itself, each with its code. Any other
 * is 403 `vault_refused`, the vault's word as its `reason`: an area's
 * operations add theirs here as they are served.
 */
const REFUSALS: Record<string, [ErrorCode, string]> = {
  unauthenticated: ['unauthenticated', 'that credential is unknown, expired or revoked'],
  // One answer for a place that is not there and one the caller holds nothing in: the vault says neither which.
  no_access: ['vault_refused', 'no such place, or nothing you may do this in'],
  bulk_limit: ['bulk_limit', 'too many secrets read in too short a time; try again later'],
  // Not a refusal of the caller's access: nobody is handed a sensitive value.
  sensitive: ['forbidden', 'a sensitive value is handed back to no person: an app uses it through the credential proxy, and a service account reads it'],
  not_owner_issued: ['forbidden', 'a service account reads a sensitive value only on a token or trust binding an Owner of its project issued'],
  use_only: ['forbidden', "this workload uses that value only through coffre: its binding's reads do not list it where it is held"],
  parent_unreadable: ['forbidden', 'that is inherited from an environment you cannot read'],
  unknown_key: ['not_found', 'unknown secret'],
  no_value: ['not_found', 'that secret holds no value'],
  unknown_version: ['not_found', 'that secret has no such version'],
  unreadable: ['conflict', 'that is a reference whose source cannot be read'],
  archived: ['conflict', 'that secret is archived: bring it back before writing it'],
  broken_chain: ['conflict', 'the environment inherits from one that is gone'],
  // Projects and environments (routes/places.ts).
  exists: ['conflict', 'that is there already: its slug is taken'],
  referenced: ['conflict', 'a reference held elsewhere reads a value in it, which this would stop or send through a second reference: break that reference first'],
  // References (routes/secrets.ts).
  reference_to_itself: ['conflict', 'a key cannot be a reference to itself'],
  reference_to_reference: ['conflict', 'that is itself a reference: a reference reads a value, so point at its source instead'],
  no_reference: ['not_found', 'that key is no reference'],
  // Folders of keys (routes/secrets.ts).
  no_folder: ['not_found', 'no key is filed in that folder there'],
  // A fork's key reset to what it inherits, or that undone (routes/secrets.ts).
  not_inherited: ['conflict', 'no environment it inherits from passes that key down: archive it, or bring it back, instead'],
  inherited: ['conflict', 'a fork inherits from it: archive the fork first'],
  parent_archived: ['conflict', 'it inherits from an environment that is archived or deleted: restore that first'],
  too_deep: ['conflict', 'that environment already inherits from three: fork one higher up'],
  workload_cannot_issue: ['forbidden', "a workload's session issues no credential and changes no one's access"],
  not_a_person: ['forbidden', 'a service account keeps no personal config: name the environment itself'],
  // Members and their grants (routes/members.ts): to whoever may manage them, as 0.14 answered.
  not_a_member: ['not_found', 'no such member'],
  removed: ['conflict', 'they were removed: add them again first'],
  last_owner: ['conflict', 'the instance keeps one Owner of all of it: make another one first'],
  configured_owner: ['conflict', "the deployment names them an Owner, which they stay while its configuration says so"],
  invalid: ['conflict', 'a role the instance does not have, one that holds what only a project has given on an environment, or an end that has passed'],
  // The instance's roles (routes/roles.ts), as 0.14.7 answered.
  role_granted: ['conflict', 'a grant names that role: revoke it first'],
  policy_changed: ['conflict', 'the role changed since this change was weighed: weigh it again'],
  // Any operation's: the vault refuses to decide on a row it did not write, and the operator must look (`noteTampered`).
  tampered: ['tampered', "a record coffre's vault reads failed its integrity check: whoever runs coffre has the details in its server log"],
  adopting: ['adopting', "coffre's vault has not taken over its database yet; try again in a moment"],
  // Sign-in (signin.ts, routes/signin.ts): as 0.14 answered.
  unknown_identity: ['not_found', 'unknown sign-in account'],
  unknown_code: ['not_found', 'that code is unknown or has expired'],
  // Tokens, handles and sessions (routes/tokens.ts): one answer for a credential that is not there, ended, or not the caller's to end.
  unknown_credential: ['not_found', 'unknown credential'],
  unknown_principal: ['not_found', 'no such service account'],
  no_grants: ['bad_request', 'a credential reaches only what its account holds when it is made: give the account a grant first'],
};

/** Refusals about the instance, not what was asked for: their words are the same whatever the request named. */
const UNNAMED = new Set(['tampered', 'adopting']);

/**
 * The vault's refusal, as the API answers it: `what` names what was asked
 * for, `market/prod/KEY`, but on a refusal about the instance itself
 * (`tampered`, `adopting`), whose words name no row.
 */
export function refusal(refused: string, what?: string): ApiError {
  const [code, message] = REFUSALS[refused] ?? ['vault_refused', `the vault refused: ${refused}`];
  return new ApiError(code, what === undefined || UNNAMED.has(refused) ? message : `${what}: ${message}`, refused);
}

/**
 * A refusal that says the vault read a row it did not write, said once in
 * the server's log: whoever runs coffre must find it, and the caller is
 * told nothing of which. `route` is the route's pattern and `request` the
 * request's id, never anything the caller typed.
 */
export function noteTampered(error: unknown, route: string, request: string | null): void {
  if (error instanceof ApiError && error.code === 'tampered') console.error('the vault refused a request on a row it did not write', { route, request });
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

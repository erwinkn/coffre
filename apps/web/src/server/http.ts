import type { AuthenticatedIdentity, RequestIdentityContext } from './auth.ts';
import { ApiError, badRequest, toErrorBody } from './api/errors.ts';

export function jsonResponse(
  payload: unknown,
  status = 200,
  headers: HeadersInit = {},
): Response {
  return Response.json(payload, {
    status,
    headers: { 'cache-control': 'no-store', ...headers },
  });
}

/** Anything thrown, as the API's one error shape: `{ error, message }`. */
export function errorResponse(error: unknown, headers: HeadersInit = {}): Response {
  const { status, body } = toErrorBody(error);
  return jsonResponse(body, status, headers);
}

export function methodNotAllowed(allowed: readonly string[]): Response {
  return errorResponse(
    new ApiError('method_not_allowed', `use ${allowed.join(' or ')}`),
    { allow: allowed.join(', ') },
  );
}

/** The identity established by the global TanStack request middleware. */
export function requestContext(context: unknown): AuthenticatedIdentity {
  const identity = (context as { coffreRequest?: RequestIdentityContext }).coffreRequest;
  if (identity === undefined || identity.principal === null) {
    throw new ApiError('unauthenticated', 'sign in first');
  }
  if (!identity.registered) {
    throw new ApiError('registration_required', 'you are signed in, but not a member here');
  }
  return identity;
}

/** A JSON body, or `fallback` when the body is empty. */
export async function readJson(request: Request, fallback?: unknown): Promise<unknown> {
  let text: string;
  try {
    text = await request.text();
  } catch {
    throw badRequest('the body could not be read');
  }
  if (text.length === 0 && fallback !== undefined) return fallback;
  try {
    return JSON.parse(text);
  } catch {
    throw badRequest('the body is not JSON');
  }
}

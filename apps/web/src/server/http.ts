import { z } from 'zod';

import type { RequestIdentityContext } from './auth.ts';
import type { RequestContext } from './services/secrets.ts';

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

export function apiErrorResponse(error: unknown): Response {
  const status =
    typeof error === 'object' && error !== null && 'statusCode' in error
      ? (error as { statusCode?: unknown }).statusCode
      : undefined;
  const code =
    typeof error === 'object' && error !== null && 'apiCode' in error
      ? (error as { apiCode?: unknown }).apiCode
      : undefined;

  if (status === 401) return jsonResponse({ error: 'unauthenticated' }, 401);
  if (status === 403 && code === 'registration_required') {
    return jsonResponse({ error: 'registration_required' }, 403);
  }
  if (status === 403) return jsonResponse({ error: 'forbidden' }, 403);
  if (status === 404) return jsonResponse({ error: 'not_found' }, 404);
  if (status === 409) {
    return jsonResponse(
      {
        error: 'conflict',
        message: error instanceof Error ? error.message : 'conflict',
      },
      409,
    );
  }
  if (status === 400 || (error instanceof Error && error.name === 'ZodError')) {
    // Errors marked `expose` carry a sentence written for the caller, such as
    // which field of a sync's destination is wrong.
    const expose =
      error instanceof Error && (error as { expose?: unknown }).expose === true;
    return jsonResponse(
      expose ? { error: 'bad_request', message: error.message } : { error: 'bad_request' },
      400,
    );
  }
  console.error('unhandled API error', error);
  return jsonResponse({ error: 'internal_error' }, 500);
}

/** Extract the identity established by the global TanStack request middleware. */
export function requestContext(context: unknown): RequestContext {
  const identity = (context as { coffreRequest?: RequestIdentityContext }).coffreRequest;
  if (identity === undefined || identity.principal === null) {
    throw Object.assign(new Error('unauthenticated'), { statusCode: 401 });
  }
  if (!identity.registered) {
    throw Object.assign(new Error('registration required'), {
      statusCode: 403,
      apiCode: 'registration_required',
    });
  }
  return identity;
}

/** Keep HTTP response and error translation at the route boundary. */
export async function apiResponse(
  operation: () => unknown | Promise<unknown>,
  status = 200,
): Promise<Response> {
  try {
    return jsonResponse(await operation(), status);
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export function methodNotAllowed(allowed: readonly string[]): Response {
  return jsonResponse(
    { error: 'method_not_allowed' },
    405,
    { allow: allowed.join(', ') },
  );
}

export async function parseJson<T>(
  request: Request,
  parse: (input: unknown) => T,
): Promise<T> {
  let input: unknown;
  try {
    input = await request.json();
  } catch {
    throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 });
  }
  return parse(input);
}

export async function parseOptionalJson<T>(
  request: Request,
  parse: (input: unknown) => T,
  fallback: unknown = {},
): Promise<T> {
  let text: string;
  try {
    text = await request.text();
  } catch {
    throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 });
  }
  if (text.length === 0) return parse(fallback);
  try {
    return parse(JSON.parse(text));
  } catch (error) {
    if (error instanceof z.ZodError) throw error;
    throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 });
  }
}

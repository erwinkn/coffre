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

/** A JSON body, or `fallback` when the body is empty. */
export async function readJson(request: Request, fallback?: unknown): Promise<unknown> {
  let text: string;
  try {
    text = await request.text();
  } catch {
    throw badRequest('the body could not be read');
  }
  if (text.length === 0 && fallback !== undefined) return fallback;
  // Validation would quietly drop a `__proto__` key (a secret named that,
  // say), so the write would succeed and store nothing: refuse it outright.
  let proto = false;
  let body: unknown;
  try {
    body = JSON.parse(text, (key, value: unknown) => {
      if (key === '__proto__') proto = true;
      return value;
    });
  } catch {
    throw badRequest('the body is not JSON');
  }
  if (proto) throw badRequest('__proto__ cannot be used as a key');
  return body;
}

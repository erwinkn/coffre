import { ApiError, badRequest, toErrorBody, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';

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

/** Anything thrown, as the API's one error shape: `{ error, message }`; a moment's 503 says when to ask again. */
export function errorResponse(error: unknown, headers: HeadersInit = {}): Response {
  const { status, body } = toErrorBody(error);
  const momentary = status === 503 && body.error === 'unavailable' && body.reason === undefined && !new Headers(headers).has('retry-after');
  const later = error instanceof ApiError && error.retryAfter !== undefined ? error.retryAfter : UNAVAILABLE_RETRY_AFTER;
  return jsonResponse(body, status, momentary ? { ...Object.fromEntries(new Headers(headers)), 'retry-after': later } : headers);
}

export function methodNotAllowed(allowed: readonly string[]): Response {
  return errorResponse(
    new ApiError('method_not_allowed', `use ${allowed.join(' or ')}`),
    { allow: allowed.join(', ') },
  );
}

/**
 * A body of at most `max` bytes, as UTF-8, read as it streams: past the
 * limit the rest is never read. For a route anyone may call.
 */
export async function readLimitedText(request: Request, max: number): Promise<string> {
  const bytes = await readLimitedBytes(request, max);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw badRequest('the body is not UTF-8');
  }
}

/** A body's bytes, no more than `max` of them: past it, its stream is cancelled and it is refused. */
export async function readLimitedBytes(request: Request, max: number): Promise<Uint8Array<ArrayBuffer>> {
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader !== undefined) {
    for (;;) {
      const { done, value } = await reader.read().catch(() => {
        throw badRequest('the body could not be read');
      });
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel().catch(() => {});
        throw new ApiError('bad_request', `the body is larger than ${max} bytes`);
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks);
}

/**
 * The most values a request body may hold, counted over the whole tree
 * (every object entry, array element and leaf). Validation builds work, and
 * sometimes an error, per value, so a body is held to this before it is
 * validated: well above the largest real one (a 1000-key bulk write of
 * generated values is about 11k), and far below what a megabyte of tiny
 * entries or array elements would reach, which cost seconds of CPU (R27).
 */
const MAX_BODY_NODES = 20000;

/**
 * Parse a JSON body, then walk it once under a node cap, refusing a
 * `__proto__` key anywhere. `JSON.parse` makes `__proto__` an own property,
 * not prototype pollution, but validation treats it inconsistently (a secret
 * named that would seem to write and store nothing), so it is refused. The
 * walk counts every value and stops the body — before validation — once it
 * is too large: a plain parse (not a per-node reviver) is bounded by the
 * byte cap, but validating a huge array or record is not, so the count is
 * what keeps a request within R27's CPU budget. The walk pushes a node's
 * children only while under the cap, so a 262k-element array is refused
 * after counting it, never after copying it.
 */
export function parseJsonBody(text: string): unknown {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw badRequest('the body is not JSON');
  }
  let nodes = 1;
  const stack: unknown[] = [body];
  while (stack.length > 0) {
    const value = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    if (Array.isArray(value)) {
      nodes += value.length;
      if (nodes > MAX_BODY_NODES) throw badRequest(`the body holds more than ${MAX_BODY_NODES} values`);
      for (const element of value) stack.push(element);
    } else {
      if (Object.prototype.hasOwnProperty.call(value, '__proto__')) throw badRequest('__proto__ cannot be used as a key');
      const keys = Object.keys(value);
      nodes += keys.length;
      if (nodes > MAX_BODY_NODES) throw badRequest(`the body holds more than ${MAX_BODY_NODES} values`);
      for (const key of keys) stack.push((value as Record<string, unknown>)[key]);
    }
  }
  return body;
}

/** A JSON body of at most `max` bytes, as `readLimitedText` reads it. */
export async function readLimitedJson(request: Request, max: number): Promise<unknown> {
  return parseJsonBody(await readLimitedText(request, max));
}

/**
 * A JSON body of at most `max` bytes, or `fallback` when the body is empty.
 * Every body is bounded: the stream is abandoned past the limit, so an
 * oversize or endless body never buffers (the heart of R27's CPU budget).
 */
export async function readJson(request: Request, max: number, fallback?: unknown): Promise<unknown> {
  const text = await readLimitedText(request, max);
  if (text.length === 0 && fallback !== undefined) return fallback;
  return parseJsonBody(text);
}

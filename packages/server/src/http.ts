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

/**
 * A body of at most `max` bytes, as UTF-8, read as it streams: past the
 * limit the rest is never read. For a route anyone may call.
 */
export async function readLimitedText(request: Request, max: number): Promise<string> {
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
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw badRequest('the body is not UTF-8');
  }
}

/**
 * Parse a JSON body, refusing a top-level `__proto__` key. `JSON.parse`
 * makes it an own property, not prototype pollution, but validation treats
 * it inconsistently (a secret named that would seem to write and store
 * nothing), so refuse it outright. Top-level is enough: a body's data keys
 * (secret names, paths) live there, and every nested object a route takes is
 * `.strict()`, so a `__proto__` deeper is already refused. A plain parse,
 * not a reviver that runs a function per node: the reviver cost is what let
 * a large body of many tiny entries burn CPU (R27).
 */
function parseJsonBody(text: string): unknown {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw badRequest('the body is not JSON');
  }
  if (body !== null && typeof body === 'object' && !Array.isArray(body) && Object.prototype.hasOwnProperty.call(body, '__proto__')) {
    throw badRequest('__proto__ cannot be used as a key');
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

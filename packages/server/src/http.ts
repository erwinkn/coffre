import { countValues, MAX_BODY_NODES } from '@coffre/core/schemas';
import { z } from 'zod';

import { ApiError, badRequest, DEPLOYING_RETRY_AFTER, toErrorBody, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';

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

/** Anything thrown, as the API's one error shape: `{ error, message }`; a moment's 503 says when to ask again, a deploy's in a second. */
export function errorResponse(error: unknown, headers: HeadersInit = {}): Response {
  const { status, body } = toErrorBody(error);
  // A moment's 503: what coffre could not reach (no reason), or one that says itself when to ask again (a busy use, the
  // vault's). Any other error only when it says so itself (a two-trip write's 409 `changed`, its tries spent).
  const own = error instanceof ApiError ? error.retryAfter : undefined;
  const later = new Headers(headers).has('retry-after') ? undefined
    : status !== 503 ? own
    : body.error === 'deploying' ? DEPLOYING_RETRY_AFTER
    : body.error !== 'unavailable' ? undefined : own ?? (body.reason === undefined ? UNAVAILABLE_RETRY_AFTER : undefined);
  return jsonResponse(body, status, later === undefined ? headers : { ...Object.fromEntries(new Headers(headers)), 'retry-after': later });
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

// The bounds every body is read to, and the count of its values, are core's, so that what decodes a body's strings
// (a workload token's parts) holds to the same: re-exported here, where the API reads its bodies.
export { API_BODY_BYTES, countValues, MAX_BODY_NODES, READ_CPU_US, REQUEST_CPU_US, VALUE_CPU_US } from '@coffre/core/schemas';


/**
 * A JSON body, its values counted first (`countValues`) and refused past
 * `MAX_BODY_NODES` before `JSON.parse` makes any of them: parsed, a
 * mebibyte of tiny entries or of nesting costs 35 to 40 ms of CPU and holds
 * 8 to 28 times its size (`scripts/body-cost.ts`), where the count costs a
 * pass over the text. Then a walk of what was parsed refuses a `__proto__`
 * key anywhere: `JSON.parse` makes it an own property, not prototype
 * pollution, but validation treats it inconsistently (a secret named that
 * would seem to write and store nothing).
 */
export function parseJsonBody(text: string): unknown {
  if (countValues(text, MAX_BODY_NODES) > MAX_BODY_NODES) throw badRequest(`the body holds more than ${MAX_BODY_NODES} values`);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw badRequest('the body is not JSON');
  }
  const stack: unknown[] = [body];
  while (stack.length > 0) {
    const value = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    if (Array.isArray(value)) {
      for (const element of value) stack.push(element);
    } else {
      if (Object.prototype.hasOwnProperty.call(value, '__proto__')) throw badRequest('__proto__ cannot be used as a key');
      for (const key of Object.keys(value)) stack.push((value as Record<string, unknown>)[key]);
    }
  }
  return body;
}

/** A nested issue's message, never shown: an answer names the first issue alone, whose own message it keeps. */
const QUIET: z.core.ParseContext<z.core.$ZodIssue> & { async: false } = { async: false, error: () => 'invalid' };

/**
 * `schema`'s reading of a body, as `safeParse` answers, but with the first
 * issue alone: what an answer names (`toErrorBody`). `safeParse` builds
 * every issue's message, and its error a JSON of them all, which for a body
 * of failing entries costs twice the walk itself (`VALUE_CPU_US`); here a
 * union's branches keep a message no one reads, and only the first issue is
 * finished, with zod's own message. The walk still visits every value, which
 * `MAX_BODY_NODES` bounds.
 */
export function check<S extends z.ZodType>(schema: S, value: unknown): z.ZodSafeParseResult<z.output<S>> {
  const result = schema._zod.run({ value, issues: [] }, QUIET);
  if (result instanceof Promise) throw new Error('a body schema is synchronous');
  if (result.issues.length === 0) return { success: true, data: result.value as z.output<S> };
  const [first] = result.issues;
  return { success: false, error: new z.ZodError([z.core.util.finalizeIssue(first!, {}, z.core.config())]) as z.ZodError<z.output<S>> };
}

/** `schema`'s reading of a body, or its first issue thrown, as a `ZodError` the API answers 400 (`toErrorBody`). */
export function validate<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = check(schema, value);
  if (!result.success) throw result.error;
  return result.data;
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

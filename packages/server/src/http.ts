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

/**
 * The most an API request body may be, read as it streams and abandoned
 * past this, at every route the app answers, sign-in's included (one bound
 * before sign-in, as after): a control-plane request, a bulk secret write
 * its largest. Workers gives an isolate 128 MB
 * (https://developers.cloudflare.com/workers/platform/limits/, "Memory"); a
 * body takes about 5 MiB of it while it is read, 4% at most: its chunks and
 * their one copy (2 MiB), its text (up to 2 MiB, two bytes a character past
 * Latin-1) and its parsed value, which `MAX_BODY_NODES` holds to about its
 * size (`scripts/body-cost.ts`: 1.0 times, where a mebibyte of tiny entries
 * or nesting, parsed, would hold 8 to 28). Uses carry no body, and an
 * isolate serves a few control-plane requests at once. An `.env` of a
 * thousand keys is a few dozen kilobytes.
 */
export const API_BODY_BYTES = 1024 * 1024;

/**
 * A request's CPU at p99, in microseconds: R27's 20 ms, under which every
 * request stays, so that a body, refused or not, costs no more before its
 * route runs.
 */
export const REQUEST_CPU_US = 20_000;

/**
 * Reading the largest body at worst, in microseconds: counting its values
 * (`countValues`), then `JSON.parse` of one that passes, a mebibyte of
 * strings its costliest, 2.6 to 3.9 ms; a body refused by the count costs
 * 0.1 ms (`scripts/body-cost.ts`, Node 24, the machine named below).
 */
export const READ_CPU_US = 4_000;

/**
 * Validation's CPU per body value, at worst, in microseconds: `check` with
 * every route's schema, on bodies of `MAX_BODY_NODES` values in the
 * costliest shapes, alone and under every field a route reads a map or a
 * list from (`scripts/body-cost.ts`: Node 24.22 on a 96-core Linux host at a
 * load of 15, the thread's own CPU, the median of five; with zod's eval-built
 * fast paths and without, as on Workers, which forbids eval). The worst is a
 * secret write whose every entry fails its six-way union, 7.7 to 9.4 µs a
 * value over six runs, taken as 10; every other route is under 5. Through
 * zod's own `safeParse`, which builds every issue's message and a JSON of
 * them all, the same body cost 18 to 21.
 */
export const VALUE_CPU_US = 10;

/**
 * The most values a request body may hold, counted over the whole tree
 * (every object entry, array element and leaf) before it is parsed: what is
 * left of a request's CPU once the largest body is read, at validation's
 * worst cost per value (1,600). A bulk write of plain values is one per key
 * and its root: an `.env` of 1,599 keys fits, a larger one is written in
 * parts. The CBOR a passkey's response carries in its strings decodes under
 * the same count, on its own (`CeremonyExpectation.values`).
 */
export const MAX_BODY_NODES = Math.floor((REQUEST_CPU_US - READ_CPU_US) / VALUE_CPU_US);

/**
 * How many values a JSON text holds, counted as `JSON.parse` would make
 * them but without making any: the root, each array element and each object
 * entry, a key and its value together (`{"a":[1,2]}` is 4). One pass over
 * the characters, strings skipped whole, and it stops once past `cap`. A
 * value starts at the first character after `[`, `{` or `,` that is not
 * space and does not close a container, whatever the container is, so no
 * stack is kept. Text that is not JSON may count otherwise; `JSON.parse`
 * refuses it after.
 */
export function countValues(text: string, cap = Infinity): number {
  let count = 1;
  let expecting = false;
  for (let i = 0; i < text.length && count <= cap; i += 1) {
    const c = text.charCodeAt(i);
    // Space, tab, line feed, carriage return: JSON's whitespace, which neither starts nor ends a value.
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) continue;
    if (expecting) {
      expecting = false;
      if (c !== 0x5d && c !== 0x7d) count += 1;
    }
    if (c === 0x5b || c === 0x7b || c === 0x2c) expecting = true;
    else if (c === 0x22) {
      for (i += 1; i < text.length; i += 1) {
        const d = text.charCodeAt(i);
        if (d === 0x5c) i += 1;
        else if (d === 0x22) break;
      }
    }
  }
  return count;
}

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

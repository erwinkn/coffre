import { SyncProviderError, type SyncContext, type SyncProviderErrorCode } from './types.ts';

/** Exported so tests can shrink the delays; nothing else should touch it. */
export const timing = {
  requestTimeoutMs: 15_000,
  baseBackoffMs: 500,
  // A rate limit that resets further out than this is reported, not waited
  // out: Cloudflare, for one, blocks for five whole minutes.
  maxRetryWaitMs: 10_000,
};

const MAX_RETRIES = 2;
const WRITE_CONCURRENCY = 4;

export type JsonRequest = {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  /** Some APIs signal rate limiting with more than a 429 (GitHub uses 403). */
  isRateLimited?: (response: Response) => boolean;
};

export type JsonResponse = { status: number; headers: Headers; body: unknown };

/**
 * One JSON request with a timeout, and up to two retries when the upstream is
 * rate limiting or failing. Always resolves with the final response, whatever
 * its status; callers decide what a status means for them. Only a network
 * failure, an abort or a redirect throws.
 */
export async function requestJson(ctx: SyncContext, request: JsonRequest): Promise<JsonResponse> {
  const doFetch = ctx.fetch ?? globalThis.fetch;
  const isRateLimited = request.isRateLimited ?? ((response: Response) => response.status === 429);

  for (let attempt = 0; ; attempt++) {
    const timeout = AbortSignal.timeout(timing.requestTimeoutMs);
    const signal = ctx.signal ? AbortSignal.any([ctx.signal, timeout]) : timeout;

    let response: Response;
    try {
      response = await doFetch(request.url, {
        method: request.method,
        redirect: 'manual',
        headers: {
          ...request.headers,
          ...(request.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        body: request.body === undefined ? undefined : JSON.stringify(request.body),
        signal,
      });
    } catch (error) {
      if (ctx.signal?.aborted) throw new SyncProviderError('The sync was cancelled', 'network');
      if (timeout.aborted) {
        throw new SyncProviderError(`No response within ${timing.requestTimeoutMs / 1000}s`, 'network');
      }
      // Transport errors are retried like a 503: nothing reached the upstream, or
      // every write we send is idempotent anyway.
      if (attempt < MAX_RETRIES) {
        await sleep(backoff(attempt), ctx.signal);
        continue;
      }
      // The underlying message comes from the runtime, never from our request,
      // so it cannot carry the token.
      const detail = error instanceof Error ? `: ${error.message}` : '';
      throw new SyncProviderError(`Could not reach ${new URL(request.url).host}${detail}`, 'network');
    }

    if (response.status >= 300 && response.status < 400) {
      // A redirect can forward custom credential headers and the entire body.
      const location = response.headers.get('location');
      let target = 'an unknown host';
      try {
        if (location !== null) target = new URL(location, request.url).host || target;
      } catch { /* A malformed Location is still a refused redirect. */ }
      await response.body?.cancel();
      throw new SyncProviderError(`Refused redirect to ${target} (HTTP ${response.status})`, 'upstream', response.status);
    }

    const retryable = isRateLimited(response) || response.status >= 500;
    if (retryable && attempt < MAX_RETRIES) {
      const wait = retryWait(response.headers) ?? backoff(attempt);
      if (wait <= timing.maxRetryWaitMs) {
        await response.body?.cancel();
        await sleep(wait, ctx.signal);
        continue;
      }
    }

    return { status: response.status, headers: response.headers, body: await readBody(response) };
  }
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** How long the upstream asked us to wait, in ms, if it said. */
function retryWait(headers: Headers): number | null {
  const retryAfter = headers.get('retry-after');
  if (retryAfter !== null) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
    const date = Date.parse(retryAfter);
    if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  }
  // GitHub's primary rate limit: remaining hits 0 and reset is an epoch second.
  if (headers.get('x-ratelimit-remaining') === '0') {
    const reset = Number(headers.get('x-ratelimit-reset'));
    if (Number.isFinite(reset) && reset > 1e9) return Math.max(0, reset * 1000 - Date.now());
  }
  return null;
}

function backoff(attempt: number): number {
  return timing.baseBackoffMs * 2 ** attempt * (0.5 + Math.random() / 2);
}

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new SyncProviderError('The sync was cancelled', 'network'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * The statuses that mean "this whole call is doomed", as opposed to "the
 * upstream refused this one key". Anything else (400, 409, 422) is per-key.
 */
export function wholeCallCode(status: number): SyncProviderErrorCode | null {
  if (status === 401) return 'unauthorized';
  if (status === 403) return 'forbidden';
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'upstream';
  return null;
}

export function isOk(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * Runs `task` over `items` with a few in flight at once, so a large plan does
 * not trip the upstream's abuse detection. A thrown error stops new tasks from
 * starting and is rethrown once the in-flight ones settle.
 */
export async function forEachLimited<T>(items: readonly T[], task: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let failure: { error: unknown } | null = null;

  async function worker() {
    while (failure === null && next < items.length) {
      const item = items[next++]!;
      try {
        await task(item);
      } catch (error) {
        failure ??= { error };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(WRITE_CONCURRENCY, items.length) }, worker));
  if (failure !== null) throw (failure as { error: unknown }).error;
}

/** A plain-English message from whatever error body an upstream returned. */
export function upstreamMessage(body: unknown, pick: (body: Record<string, unknown>) => unknown): string {
  if (typeof body === 'object' && body !== null) {
    const picked = pick(body as Record<string, unknown>);
    if (typeof picked === 'string' && picked) return picked;
  }
  if (typeof body === 'string' && body) return body;
  return 'no error message';
}

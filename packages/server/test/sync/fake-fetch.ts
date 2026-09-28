import assert from 'node:assert/strict';

import { timing } from '../../src/sync/http.ts';

// Retries would otherwise sleep for real between attempts.
timing.baseBackoffMs = 0;

export type RecordedRequest = {
  method: string;
  url: string;
  /** Header names lower-cased. */
  headers: Record<string, string>;
  body: unknown;
};

export type Reply = { status?: number; body?: unknown; headers?: Record<string, string> };

type Handler = (request: RecordedRequest) => Reply | Promise<Reply>;

/**
 * A fetch that never touches the network: every request is recorded, and
 * answered by the first route whose "METHOD url" key matches exactly. A
 * request no route expects fails the test.
 */
export function fakeFetch(routes: Record<string, Reply | Handler | (Reply | Handler)[]>) {
  const requests: RecordedRequest[] = [];
  const queues = new Map(
    Object.entries(routes).map(([route, reply]) => [route, Array.isArray(reply) ? [...reply] : reply]),
  );

  const fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const headers = Object.fromEntries(
      Object.entries((init.headers ?? {}) as Record<string, string>).map(([name, value]) => [name.toLowerCase(), value]),
    );
    const request: RecordedRequest = {
      method: init.method ?? 'GET',
      url: String(input),
      headers,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    requests.push(request);

    const route = `${request.method} ${request.url}`;
    const entry = queues.get(route);
    assert.ok(entry !== undefined, `unexpected request: ${route}`);
    // An array answers successive calls in order, then keeps repeating its last reply.
    const handler = Array.isArray(entry) ? (entry.length > 1 ? entry.shift()! : entry[0]!) : entry;
    const reply = typeof handler === 'function' ? await handler(request) : handler;

    const status = reply.status ?? 200;
    const body = reply.body === undefined ? null : typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body);
    return new Response(status === 204 ? null : body, { status, headers: reply.headers });
  };

  return { fetch: fetch as typeof globalThis.fetch, requests };
}

/** Asserts that nothing secret made it into any message the caller could see. */
export function assertNoLeak(text: string, secrets: readonly string[]): void {
  for (const secret of secrets) {
    assert.ok(!text.includes(secret), `leaked ${JSON.stringify(secret)} in: ${text}`);
  }
}

export async function rejection(promise: Promise<unknown>): Promise<Error & { code?: string; status?: number }> {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string; status?: number };
  }
  assert.fail('expected a rejection');
}

import { PUBLISHED_BYTES } from '@coffre/core/identity';

import type { Connect } from '../plugins.ts';

/**
 * How coffre fetches what an issuer publishes for its bindings: its
 * discovery document, then its keys (docs/design/oidc.md, section 4). One
 * transport for both, with the same limits whatever the runtime: one
 * deadline for everything from DNS to the last byte, no redirects, no
 * credentials, a 200 with JSON, and at most `MAX_BODY_BYTES` of it.
 *
 * On Workers it is the standard public `fetch`, which reaches only the
 * internet, never a private-network binding. On Node it is
 * `nodeTransport()`, whose resolver admits only public addresses.
 */
export type WorkloadTransport = {
  /**
   * GET a JSON document, or throw `FetchRefused` saying why. `cacheControl`, when given, is told the answer's
   * `Cache-Control` header, or null: what the issuer says of how long its keys may be kept (`workloads/keys.ts`).
   */
  json(url: URL, cacheControl?: (value: string | null) => void): Promise<unknown>;
  /**
   * A request to a host an Owner typed in a web page, a UI route's upstream (docs/design/proxy-ui.md, section 5): on
   * Node, one that dials only public addresses (`publicFetch`); on Workers, the platform's, whose network reaches no
   * private one. Absent, such a request is refused (`insecureUpstreams` aside), never sent through the global fetch.
   */
  fetch?(url: URL, init: RequestInit): Promise<Response>;
  /**
   * TCP out to a host an Owner typed in a web page, a UI tunnel's database (docs/design/proxy-ui.md, section 5): on
   * Node, one that dials only public addresses (`publicConnect`); on Workers, the platform's `connect()`, whose network
   * reaches no private one. Absent, such a tunnel is refused (`insecureUpstreams` aside), never dialled through the
   * platform's own.
   */
  connect?: Connect;
};

/** Everything, from DNS to the last byte. */
export const FETCH_DEADLINE_MS = 5_000;
/** Discovery documents and key sets are a few kilobytes: `PUBLISHED_BYTES`, sign-in's own bound on them, with its share of an isolate's memory. */
export const MAX_BODY_BYTES = PUBLISHED_BYTES;
/** GitHub's API refuses a request that names no client. */
export const USER_AGENT = 'coffre';

/**
 * A fetch that broke a limit, or failed: the message names the URL and why,
 * never a body. `status` is the one the host answered, when it answered.
 * `transient` when the host did not answer in time, or said it could not
 * answer now (408, 429, a 5xx): a moment later it may, where an answer it
 * did give (a 404, a page that is not JSON, too many keys) stands.
 */
export class FetchRefused extends Error {
  readonly status: number | null;
  readonly transient: boolean;
  constructor(url: URL, why: string, options?: { cause?: unknown; status?: number; transient?: boolean }) {
    super(`${url.href}: ${why}`, options);
    this.name = 'FetchRefused';
    this.status = options?.status ?? null;
    this.transient = options?.transient ?? false;
  }

  /** A host that answered anything but a 200. */
  static answered(url: URL, status: number): FetchRefused {
    return new FetchRefused(url, `answered ${status}`, { status, transient: status === 408 || status === 429 || status >= 500 });
  }

  /**
   * A host that could not be reached, or stopped sending: `cause` the
   * network's error, the deadline's included, said as such. Transient, but
   * for an address the transport refuses to dial (`ENOTPUBLIC`), which no
   * moment changes.
   *
   *   AbortSignal.timeout(5_000) fired        https://…/jwks: timed out after 5 s
   *   ECONNRESET while reading the body       https://…/jwks: could not be read
   */
  static unreached(url: URL, cause: unknown, why: 'could not be fetched' | 'could not be read' = 'could not be fetched'): FetchRefused {
    const said = timedOut(cause) ? `timed out after ${FETCH_DEADLINE_MS / 1000} s` : why;
    return new FetchRefused(url, said, { cause, transient: (cause as { code?: unknown } | null)?.code !== 'ENOTPUBLIC' });
  }
}

/** The deadline's abort: `TimeoutError` from fetch, an `AbortError` caused by one from Node's `http`. */
function timedOut(error: unknown): boolean {
  const name = (error as { name?: unknown } | null)?.name;
  return name === 'TimeoutError' || (name === 'AbortError' && (error as { cause?: { name?: unknown } }).cause?.name === 'TimeoutError');
}

/** The standard `fetch`, as on Workers. */
export function fetchTransport(fetchImpl: typeof fetch = fetch): WorkloadTransport {
  return {
    fetch: (url, init) => fetchImpl(url, init),
    async json(url, cacheControl) {
      let response: Response;
      try {
        response = await fetchImpl(url, {
          redirect: 'manual',
          signal: AbortSignal.timeout(FETCH_DEADLINE_MS),
          headers: { accept: 'application/json', 'user-agent': USER_AGENT },
        });
      } catch (error) {
        throw FetchRefused.unreached(url, error);
      }
      if (response.status !== 200) {
        await response.body?.cancel();
        throw FetchRefused.answered(url, response.status);
      }
      cacheControl?.(response.headers.get('cache-control'));
      return parsed(url, response.headers.get('content-type'), await capped(url, response.body));
    },
  };
}

/** A body, read to its end, or `FetchRefused` past `MAX_BODY_BYTES`. */
export async function capped(url: URL, body: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new FetchRefused(url, `is larger than ${MAX_BODY_BYTES} bytes`);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof FetchRefused) throw error;
    throw FetchRefused.unreached(url, error, 'could not be read');
  }
  return Buffer.concat(chunks);
}

/** A body as JSON, from a response that says it is. */
export function parsed(url: URL, contentType: string | null, body: Uint8Array): unknown {
  if (contentType === null || !/^application\/([a-z.+-]+\+)?json\b/i.test(contentType)) {
    throw new FetchRefused(url, 'is not JSON');
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw new FetchRefused(url, 'is not valid JSON');
  }
}

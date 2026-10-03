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
  /** GET a JSON document, or throw `FetchRefused` saying why. */
  json(url: URL): Promise<unknown>;
};

/** Everything, from DNS to the last byte. */
export const FETCH_DEADLINE_MS = 5_000;
/** Discovery documents and key sets are a few kilobytes. */
export const MAX_BODY_BYTES = 64 * 1024;

/** A fetch that broke a limit, or failed: the message names the URL and why, never a body. */
export class FetchRefused extends Error {
  constructor(url: URL, why: string, options?: { cause?: unknown }) {
    super(`${url.href}: ${why}`, options);
    this.name = 'FetchRefused';
  }
}

/** The standard `fetch`, as on Workers. */
export function fetchTransport(fetchImpl: typeof fetch = fetch): WorkloadTransport {
  return {
    async json(url) {
      let response: Response;
      try {
        response = await fetchImpl(url, {
          redirect: 'manual',
          signal: AbortSignal.timeout(FETCH_DEADLINE_MS),
          headers: { accept: 'application/json' },
        });
      } catch (error) {
        throw new FetchRefused(url, 'could not be fetched', { cause: error });
      }
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new FetchRefused(url, `answered ${response.status}`);
      }
      return parsed(url, response.headers.get('content-type'), await capped(url, response.body));
    },
  };
}

async function capped(url: URL, body: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
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
    throw new FetchRefused(url, 'could not be read', { cause: error });
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

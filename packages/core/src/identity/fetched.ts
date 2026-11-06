/**
 * The most bytes coffre reads of what an identity provider publishes: an
 * OpenID Connect discovery document, a key set (JWKS), a workload issuer's
 * own (`@coffre/server`'s workload transport). Each is a few kilobytes (a
 * discovery document 1 to 3 KB, a JWKS of two or three RSA keys about
 * 2 KB), so 64 KiB reads any of them with room for many more keys. Bounded
 * so a provider, or whoever answers for its host, cannot make an isolate
 * buffer an endless answer: Workers gives an isolate 128 MB
 * (https://developers.cloudflare.com/workers/platform/limits/, "Memory"),
 * and 64 KiB is 1/2,000 of it, so the few such fetches an isolate makes at
 * once (one per provider, its answer then cached) hold a negligible share.
 */
export const PUBLISHED_BYTES = 64 * 1024;

/** A provider's answer larger than `PUBLISHED_BYTES`. */
export class PublishedTooLarge extends Error {
  constructor(url: string, max: number) {
    super(`${url} answered more than ${max} bytes`);
    this.name = 'PublishedTooLarge';
  }
}

/**
 * `fetchImpl`, its answer read whole but no more than `max` bytes of it:
 * past that the stream is cancelled and the call throws
 * `PublishedTooLarge`. For a library that fetches and parses on its own
 * (jose's remote key set, oauth4webapi's discovery), as its `customFetch`:
 * what it reads is the bounded copy.
 */
export function boundedFetch(fetchImpl: typeof fetch = (input, init) => fetch(input, init), max = PUBLISHED_BYTES): typeof fetch {
  return async (input, init) => {
    const response = await fetchImpl(input, init);
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > max) {
      await response.body?.cancel().catch(() => {});
      throw new PublishedTooLarge(url, max);
    }
    if (response.body === null) return response;
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel().catch(() => {});
        throw new PublishedTooLarge(url, max);
      }
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let at = 0;
    for (const chunk of chunks) {
      body.set(chunk, at);
      at += chunk.byteLength;
    }
    // A status that carries no body (204, 304) takes none.
    const empty = response.status === 204 || response.status === 205 || response.status === 304;
    return new Response(empty ? null : body, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
}

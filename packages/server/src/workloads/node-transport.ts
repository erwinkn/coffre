import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';

import { Agent, fetch as undiciFetch } from 'undici';

import { isPublicAddress } from './addresses.ts';
import { FETCH_DEADLINE_MS, FetchRefused, MAX_BODY_BYTES, parsed, USER_AGENT, type WorkloadTransport } from './transport.ts';

/**
 * The transport on Node, where a fetch could reach the server's own network.
 * Its resolver admits only public addresses (`addresses.ts`), and refuses a
 * name with any other among its answers. It runs when connecting, for every
 * address the connection may use, so a name that resolves elsewhere a
 * moment later gains nothing; TLS still checks the certificate against the
 * name. Plain HTTP reaches only loopback, which the binding's own check
 * allows only for a deployment that says so (`checkFetchUrl` in core).
 */
export function nodeTransport(): WorkloadTransport {
  return {
    fetch: publicFetch(),
    json: (url, cacheControl) =>
      new Promise((resolve, reject) => {
        const loopback = url.protocol === 'http:';
        if (loopback && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
          reject(new FetchRefused(url, 'plain HTTP reaches only loopback'));
          return;
        }
        const literal = loopback ? null : literalRefusal(url.hostname);
        if (literal !== null) {
          reject(new FetchRefused(url, 'could not be fetched', { cause: literal }));
          return;
        }
        const request = (loopback ? httpRequest : httpsRequest)(
          url,
          {
            method: 'GET',
            agent: false,
            headers: { accept: 'application/json', 'accept-encoding': 'identity', 'user-agent': USER_AGENT },
            signal: AbortSignal.timeout(FETCH_DEADLINE_MS),
            ...(loopback ? {} : { lookup: publicLookup }),
          },
          (response) => {
            if (response.statusCode === 200) cacheControl?.(headerValue(response.headers['cache-control']));
            read(url, response).then(resolve, reject);
          },
        );
        request.on('error', (error) => reject(error instanceof FetchRefused ? error : FetchRefused.unreached(url, error)));
        request.end();
      }),
  };
}

/**
 * A fetch that dials only public addresses, for a host an Owner typed (a UI route's upstream; docs/design/proxy-ui.md,
 * section 5): undici's, whose connections resolve their name through `lookup` as they open, so a name that resolves to
 * `10.0.0.5` sends no byte, however it resolved a moment before, and a pooled connection is one to a checked address.
 * TLS still checks the certificate against the name.
 *
 *   https://api.openai.com/v1/models, resolving to 162.159.140.245    sent
 *   https://internal.acme.example/x, resolving to 10.0.0.5               refused before the SYN: ENOTPUBLIC
 */
export function publicFetch(lookup: LookupFunction = publicLookup, tls: { ca?: string } = {}): NonNullable<WorkloadTransport['fetch']> {
  // `tls.ca`, a test's own authority for its fake upstream: the system's roots otherwise, and the name is checked either way.
  const dispatcher = new Agent({ connect: { ...tls, lookup } });
  return async (url, init) => {
    // Node asks no resolver for an address written as one: `lookup` never sees `https://240.0.0.1` (review r3 of #467).
    const literal = literalRefusal(new URL(url).hostname);
    if (literal !== null) throw new TypeError('fetch failed', { cause: literal });
    return (await undiciFetch(url, { ...(init as Parameters<typeof undiciFetch>[1]), dispatcher })) as unknown as Response;
  };
}

/**
 * Why a host written as an IP address may not be dialled, or null: Node connects to an address as written, without
 * the lookup, so the address is checked here, as the lookup checks a name's answers. `publicFetch`'s URLs and
 * `publicConnect`'s tunnels both ask it.
 *
 *   162.159.140.245       null
 *   240.0.0.1             ENOTPUBLIC (reserved)
 *   [::ffff:a00:5]        ENOTPUBLIC (10.0.0.5, written as IPv6)
 *   api.openai.com        null: a name, checked by the lookup as the connection opens
 */
export function literalRefusal(host: string): Error | null {
  const address = host.replace(/^\[|\]$/g, '');
  if (isIP(address) === 0 || isPublicAddress(address)) return null;
  return Object.assign(new Error(`${address} is an address that is not public`), { code: 'ENOTPUBLIC' });
}

/** `dns.lookup`, refusing a name with any answer that is not public. */
export const publicLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { ...options, all: true }, (error, addresses: LookupAddress[]) => {
    if (error) {
      callback(error, '', 0);
      return;
    }
    const refused = addresses.find((answer) => !isPublicAddress(answer.address));
    if (refused !== undefined || addresses.length === 0) {
      callback(Object.assign(new Error(`${hostname} resolves to an address that is not public`), { code: 'ENOTPUBLIC' }), '', 0);
      return;
    }
    if (options.all) (callback as unknown as (error: null, addresses: LookupAddress[]) => void)(null, addresses);
    else callback(null, addresses[0]!.address, addresses[0]!.family);
  });
};

/** A header as one string, or null: Node gives a list for one it saw more than once. */
function headerValue(value: string | string[] | undefined): string | null {
  return value === undefined ? null : Array.isArray(value) ? value.join(', ') : value;
}

function read(url: URL, response: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (response.statusCode !== 200) {
      // Closed, not drained: its body would be read past every bound.
      response.destroy();
      reject(FetchRefused.answered(url, response.statusCode ?? 0));
      return;
    }
    const encoding = response.headers['content-encoding'];
    if (encoding !== undefined && encoding !== 'identity') {
      response.destroy();
      reject(new FetchRefused(url, `came ${encoding}-encoded, though asked for none`));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    response.on('data', (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > MAX_BODY_BYTES) {
        response.destroy();
        reject(new FetchRefused(url, `is larger than ${MAX_BODY_BYTES} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    response.on('error', (error) => reject(FetchRefused.unreached(url, error, 'could not be read')));
    response.on('end', () => {
      try {
        resolve(parsed(url, response.headers['content-type'] ?? null, Buffer.concat(chunks)));
      } catch (error) {
        reject(error);
      }
    });
  });
}

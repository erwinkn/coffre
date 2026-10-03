import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';

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
    json: (url) =>
      new Promise((resolve, reject) => {
        const loopback = url.protocol === 'http:';
        if (loopback && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
          reject(new FetchRefused(url, 'plain HTTP reaches only loopback'));
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
          (response) => read(url, response).then(resolve, reject),
        );
        request.on('error', (error) => reject(error instanceof FetchRefused ? error : new FetchRefused(url, 'could not be fetched', { cause: error })));
        request.end();
      }),
  };
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

function read(url: URL, response: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (response.statusCode !== 200) {
      response.resume();
      reject(new FetchRefused(url, `answered ${response.statusCode}`));
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
    response.on('error', (error) => reject(new FetchRefused(url, 'could not be read', { cause: error })));
    response.on('end', () => {
      try {
        resolve(parsed(url, response.headers['content-type'] ?? null, Buffer.concat(chunks)));
      } catch (error) {
        reject(error);
      }
    });
  });
}

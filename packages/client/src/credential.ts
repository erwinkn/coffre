/**
 * A credential through coffre's credential proxy, for an app `coffre run`
 * started with placeholders (docs/design/credential-proxy.md): where its
 * client takes no base URL to point at the proxy, or the code is new.
 *
 *   import { credential } from '@coffre/client/credential';
 *   const schumann = credential('schumann');
 *   const companies = await (await schumann.fetch('/companies?q=acme')).json();
 *
 * `coffre run` sets `COFFRE_CREDENTIALS`, each credential's URL on the
 * proxy by name, its environment's (`…/use/market/dev/schumann`), and
 * `COFFRE_HANDLE`, the handle that stands in for the environment's values;
 * the proxy injects the key, and the app never holds it.
 */
export type ProxiedCredential = {
  /** The credential's URL on the proxy: `<url>/<path>` is `<upstream>/<path>`. */
  url: string;
  /** `fetch`, at a path under the credential's upstream, with the handle the proxy takes. */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /**
   * A presigned GET (or HEAD) of `path` under an AWS-signed credential's
   * upstream, `/bucket/key` with each segment encoded as in a URL: coffre
   * signs it with the real key pair, for `expiresIn` seconds (15 minutes
   * unless set, an hour at most), and the URL is the upstream's own, for a
   * browser or anyone to use until then.
   */
  presign(path: string, options?: { method?: 'GET' | 'HEAD'; expiresIn?: number; query?: Record<string, string> }): Promise<{ url: string; expiresAt: string }>;
  /**
   * A signature of `message` (a string signs as its UTF-8) by a signer's
   * key, which stays in coffre: a private key's, what Node's
   * `crypto.sign(undefined, message, key)` gives, base64url, each one use
   * in coffre's log; an HMAC secret's, as its `hmac()` writes it.
   */
  sign(message: Uint8Array | string): Promise<string>;
  /**
   * Whether `signature`, as its header carried it (`sha256=…`), is a
   * verifier's HMAC of `message`: an inbound webhook's body, the bytes as
   * they came, never the JSON parsed and written again. The secret stays
   * in coffre, which compares in constant time and says only yes or no.
   */
  verify(message: Uint8Array | string, signature: string): Promise<boolean>;
};

type Env = Record<string, string | undefined>;

/** The credential `name`, as `coffre run` gave the app it; `env` and `fetcher` for tests and odd runtimes. */
export function credential(
  name: string,
  env: Env = (globalThis as { process?: { env: Env } }).process?.env ?? {},
  fetcher: (input: string, init?: RequestInit) => Promise<Response> = (input, init) => fetch(input, init),
): ProxiedCredential {
  let urls: Record<string, unknown>;
  try {
    urls = JSON.parse(env.COFFRE_CREDENTIALS ?? '{}') as Record<string, unknown>;
  } catch {
    throw new Error('COFFRE_CREDENTIALS is not what `coffre run` sets: run the app with `coffre run <project>/<environment> -- …`');
  }
  const url = urls[name];
  const handle = env.COFFRE_HANDLE;
  if (typeof url !== 'string' || handle === undefined) {
    throw new Error(`no credential ${name} here: \`coffre run\` gives the app the credentials its environment holds, which the deployment's proxy names`);
  }
  /** What the handle asks coffre to make with the environment's values, at the environment's own URL on the proxy, which the credential's is under. */
  const compute = async (asked: unknown) => {
    const answer = await fetcher(url.slice(0, url.lastIndexOf('/')), {
      method: 'POST',
      headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/json' },
      body: JSON.stringify(asked),
    });
    return { answer, body: (await answer.json()) as { url?: string; expiresAt?: string; signature?: string; valid?: boolean; message?: string } };
  };
  const bytesOf = (message: Uint8Array | string) => {
    const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return {
    url,
    fetch: (path, init = {}) => {
      const headers = new Headers(init.headers);
      headers.set('x-coffre-handle', handle);
      return fetcher(`${url}${path.startsWith('/') ? '' : '/'}${path}`, { ...init, headers });
    },
    presign: async (path, options = {}) => {
      const { answer, body } = await compute({ presign: { credential: name, path, ...options } });
      if (!answer.ok || body.url === undefined) throw new Error(`coffre presigned nothing: ${body.message ?? answer.status}`);
      return { url: body.url, expiresAt: body.expiresAt! };
    },
    sign: async (message) => {
      const { answer, body } = await compute({ sign: { credential: name, message: bytesOf(message) } });
      if (!answer.ok || body.signature === undefined) throw new Error(`coffre signed nothing: ${body.message ?? answer.status}`);
      return body.signature;
    },
    verify: async (message, signature) => {
      const { answer, body } = await compute({ verify: { credential: name, message: bytesOf(message), signature } });
      if (!answer.ok || typeof body.valid !== 'boolean') throw new Error(`coffre verified nothing: ${body.message ?? answer.status}`);
      return body.valid;
    },
  };
}

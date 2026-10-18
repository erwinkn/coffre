/**
 * A credential through coffre's credential proxy, for an app `coffre run`
 * started with stand-ins (docs/design/credential-proxy.md): where its
 * client takes no base URL to point at the proxy, or the code is new.
 *
 *   import { credential } from '@coffre/client/credential';
 *   const schumann = credential('schumann');
 *   const companies = await (await schumann.fetch('/companies?q=acme')).json();
 *
 * `coffre run` sets `COFFRE_CREDENTIALS`, each credential's URL on the
 * proxy by name, and `COFFRE_HANDLE`, the handle that stands in for the
 * environment's values; the proxy injects the key, and the app never holds it.
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
  return {
    url,
    fetch: (path, init = {}) => {
      const headers = new Headers(init.headers);
      headers.set('x-coffre-handle', handle);
      return fetcher(`${url}${path.startsWith('/') ? '' : '/'}${path}`, { ...init, headers });
    },
    presign: async (path, options = {}) => {
      // The environment's own URL on the proxy, which the credential's is under.
      const answer = await fetcher(url.slice(0, url.lastIndexOf('/')), {
        method: 'POST',
        headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/json' },
        body: JSON.stringify({ presign: { credential: name, path, ...options } }),
      });
      const body = (await answer.json()) as { url?: string; expiresAt?: string; message?: string };
      if (!answer.ok || body.url === undefined) throw new Error(`coffre presigned nothing: ${body.message ?? answer.status}`);
      return { url: body.url, expiresAt: body.expiresAt! };
    },
  };
}

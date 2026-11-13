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
import { fromBase64url, JSON_MESSAGE_BYTES } from './dpop.ts';

/** What a cipher's encrypt gives: the IV coffre drew, 12 bytes, the ciphertext, and the 16-byte tag, which the app stores in its own format. */
export type Sealed = { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array };

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
   * in coffre's log; an HMAC secret's, as its `hmac()` writes it. A message
   * past 1 MiB goes raw, its bytes as the request's body, which coffre
   * signs as they come, never held: an `hmac()` signer's whose `maxBytes`
   * takes it, SumSub's document upload say.
   */
  sign(message: Uint8Array | string): Promise<string>;
  /**
   * Whether `signature`, as its header carried it (`sha256=…`), is a
   * verifier's HMAC of `message`: an inbound webhook's body, the bytes as
   * they came, never the JSON parsed and written again. The secret stays
   * in coffre, which compares in constant time and says only yes or no.
   */
  verify(message: Uint8Array | string, signature: string): Promise<boolean>;
  /**
   * `plaintext` (a string as its UTF-8) encrypted with a cipher's AES-256-GCM key, which stays in coffre, under `aad`
   * if given: under an IV coffre draws for each, never the app's.
   */
  encrypt(plaintext: Uint8Array | string, aad?: Uint8Array | string): Promise<Sealed>;
  /** The plaintext `sealed` holds under the cipher's key and `aad`, or null when it does not decrypt: whatever part is wrong, coffre says no more. */
  decrypt(sealed: Sealed, aad?: Uint8Array | string): Promise<Uint8Array | null>;
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
    return { answer, body: (await answer.json()) as { url?: string; expiresAt?: string; signature?: string; valid?: boolean; iv?: string; ciphertext?: string; tag?: string; plaintext?: string | null; message?: string } };
  };
  /** A message past what JSON takes, signed raw: its bytes as the body, with the SHA-256 that `coffre serve` streams it by, and coffre checks. */
  const raw = async (bytes: Uint8Array) => {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
    const answer = await fetcher(`${url.slice(0, url.lastIndexOf('/'))}?sign=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/octet-stream', 'content-length': String(bytes.length), 'content-digest': `sha-256=:${btoa(String.fromCharCode(...digest))}:` },
      body: bytes as Uint8Array<ArrayBuffer>,
    });
    return { answer, body: (await answer.json()) as { signature?: string; message?: string } };
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
      const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
      const { answer, body } = bytes.length > JSON_MESSAGE_BYTES ? await raw(bytes) : await compute({ sign: { credential: name, message: bytesOf(bytes) } });
      if (!answer.ok || body.signature === undefined) throw new Error(`coffre signed nothing: ${body.message ?? answer.status}`);
      return body.signature;
    },
    verify: async (message, signature) => {
      const { answer, body } = await compute({ verify: { credential: name, message: bytesOf(message), signature } });
      if (!answer.ok || typeof body.valid !== 'boolean') throw new Error(`coffre verified nothing: ${body.message ?? answer.status}`);
      return body.valid;
    },
    encrypt: async (plaintext, aad) => {
      const { answer, body } = await compute({ encrypt: { credential: name, plaintext: bytesOf(plaintext), ...(aad === undefined ? {} : { aad: bytesOf(aad) }) } });
      const [iv, ciphertext, tag] = [body.iv, body.ciphertext, body.tag].map((part) => (typeof part === 'string' ? fromBase64url(part) : null));
      if (!answer.ok || !iv || !ciphertext || !tag) throw new Error(`coffre encrypted nothing: ${body.message ?? answer.status}`);
      return { iv, ciphertext, tag };
    },
    decrypt: async ({ iv, ciphertext, tag }, aad) => {
      const { answer, body } = await compute({ decrypt: { credential: name, iv: bytesOf(iv), ciphertext: bytesOf(ciphertext), tag: bytesOf(tag), ...(aad === undefined ? {} : { aad: bytesOf(aad) }) } });
      if (!answer.ok || (body.plaintext !== null && typeof body.plaintext !== 'string')) throw new Error(`coffre decrypted nothing: ${body.message ?? answer.status}`);
      return body.plaintext === null ? null : fromBase64url(body.plaintext);
    },
  };
}

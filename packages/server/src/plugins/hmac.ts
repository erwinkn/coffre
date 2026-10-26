/**
 * An HMAC-SHA256 with a secret the app never holds, in WebCrypto, so the
 * same on Workers: what an `hmac()` signer or verifier of the credential
 * proxy answers (docs/design/credential-proxy.md, section 5). The key is the
 * value's UTF-8 bytes, as Node's `createHmac('sha256', value)` takes a
 * string. A signature is written as its scheme says, a prefix and an
 * encoding, `sha256=` and hex for Yousign's:
 *
 *   hex         lowercase, read in either case
 *   base64      with its padding, read with or without it
 *   base64url   without padding, read with or without it
 *
 * A signature is decoded, then checked by WebCrypto's own `verify`, which
 * compares in constant time (BoringSSL's `CRYPTO_memcmp`, on Node and in
 * workerd): it is the bytes that count, so base64's last character may
 * carry bits no byte reads. One in another alphabet, without its prefix,
 * or of another length, is no match.
 */

export type Encoding = 'hex' | 'base64' | 'base64url';

export type Scheme = { encoding: Encoding; prefix: string };

/** An HMAC-SHA256's length: no signature longer than its 64 hex digits is one. */
const MAC_BYTES = 32;

/** The signature of `message`, as the scheme writes it. */
export async function hmacSign(secret: string, message: Uint8Array<ArrayBuffer>, scheme: Scheme): Promise<string> {
  const mac = await crypto.subtle.sign('HMAC', await keyOf(secret, 'sign'), message);
  return `${scheme.prefix}${Buffer.from(mac).toString(scheme.encoding)}`;
}

/** Whether `signature`, as received, is the scheme's for `message`. */
export async function hmacVerify(secret: string, message: Uint8Array<ArrayBuffer>, signature: string, scheme: Scheme): Promise<boolean> {
  if (!signature.startsWith(scheme.prefix)) return false;
  const mac = decode(signature.slice(scheme.prefix.length), scheme.encoding);
  return mac !== null && crypto.subtle.verify('HMAC', await keyOf(secret, 'verify'), mac, message);
}

function keyOf(secret: string, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
}

/** The bytes a signature's text says, or null for text its encoding does not write: Buffer's decoders skip what they do not read. */
function decode(text: string, encoding: Encoding): Uint8Array<ArrayBuffer> | null {
  if (text.length > 2 * MAC_BYTES) return null;
  const bare = text.replace(/=+$/, '');
  const written = encoding === 'hex' ? /^(?:[0-9a-f]{2})*$/i.test(text)
    : (encoding === 'base64' ? /^[A-Za-z0-9+/]*={0,2}$/ : /^[A-Za-z0-9_-]*={0,2}$/).test(text) && bare.length % 4 !== 1 && (text.length === bare.length || text.length % 4 === 0);
  return written ? Buffer.from(bare, encoding) : null;
}

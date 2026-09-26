import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const VERSION = 'v1';

/**
 * Derive a purpose-bound key from one of coffre's existing 32-byte secrets.
 *
 * HKDF with a distinct `info` string gives a key that is independent of the
 * source for every practical purpose, so the sign-in cookie needs no new
 * secret to provision and a leak of one derived key says nothing about the
 * others.
 */
export function deriveKey(secret: Uint8Array, purpose: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), `coffre/${purpose}`, 32));
}

/**
 * Encrypt a small JSON value for a round trip through the browser.
 *
 * AES-256-GCM authenticates as well as hides, so a tampered or forged value
 * fails to open rather than decoding into something else. The expiry sits
 * inside the ciphertext, which keeps an old cookie from being replayed past
 * it even by a client that ignores Max-Age.
 */
export function seal(key: Uint8Array, value: unknown, ttlSeconds: number, now = Date.now()): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(VERSION));
  const plaintext = Buffer.from(JSON.stringify({ exp: now + ttlSeconds * 1000, value }));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url')}`;
}

/** The sealed value, or null when it is malformed, forged, tampered with or expired. */
export function unseal<T>(key: Uint8Array, sealed: string | undefined | null, now = Date.now()): T | null {
  if (!sealed?.startsWith(`${VERSION}.`)) return null;
  const raw = Buffer.from(sealed.slice(VERSION.length + 1), 'base64url');
  if (raw.length <= IV_BYTES + TAG_BYTES) return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, IV_BYTES));
    decipher.setAAD(Buffer.from(VERSION));
    decipher.setAuthTag(raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
    const plaintext = Buffer.concat([
      decipher.update(raw.subarray(IV_BYTES + TAG_BYTES)),
      decipher.final(),
    ]);
    const parsed = JSON.parse(plaintext.toString('utf8')) as { exp?: unknown; value?: unknown };
    if (typeof parsed.exp !== 'number' || parsed.exp <= now) return null;
    return parsed.value as T;
  } catch {
    return null;
  }
}

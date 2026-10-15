/**
 * Values the browser makes for a secret: random strings, AES keys and EC key
 * pairs, from Web Crypto alone.
 *
 * Nothing here talks to the server. A value made here goes into the row's
 * field like a typed one, and leaves the page only when that row is saved.
 */
import { secretKeyProblem } from './validation.ts';

export type Encoding = 'base62' | 'hex' | 'base64' | 'base64url';
export type AesSize = 128 | 256;
export type Curve = 'P-256' | 'P-384' | 'P-521';
export type PairAlgorithm = 'ECDSA' | 'ECDH';

export type Recipe =
  | { kind: 'random'; encoding: Encoding; bytes: number }
  | { kind: 'aes'; size: AesSize }
  | { kind: 'pair'; algorithm: PairAlgorithm; curve: Curve };

/** A value for the row, and for a key pair the public key, which takes a row of its own. */
export type Generated = { value: string; publicKey?: string };

export const MIN_BYTES = 1;
export const MAX_BYTES = 256;
export const DEFAULT_RECIPE: Recipe = { kind: 'random', encoding: 'base62', bytes: 32 };

export const ENCODINGS: { id: Encoding; name: string }[] = [
  { id: 'base62', name: 'Letters and digits' },
  { id: 'hex', name: 'Hex' },
  { id: 'base64', name: 'Base64' },
  { id: 'base64url', name: 'Base64 URL' },
];

/** Strongest first, as a new key should be. */
export const PAIRS: { algorithm: PairAlgorithm; curve: Curve }[] = [
  { algorithm: 'ECDSA', curve: 'P-521' },
  { algorithm: 'ECDSA', curve: 'P-384' },
  { algorithm: 'ECDSA', curve: 'P-256' },
  { algorithm: 'ECDH', curve: 'P-521' },
  { algorithm: 'ECDH', curve: 'P-384' },
  { algorithm: 'ECDH', curve: 'P-256' },
];

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
/**
 * The largest multiple of 62 a byte reaches: 248. A byte below it is taken
 * modulo 62, and each of the 62 characters has four bytes that make it. The
 * eight bytes from 248 up are thrown away, as taking them would make the
 * first eight characters a little likelier than the rest.
 */
const BASE62_LIMIT = 256 - (256 % 62);

type RandomBytes = (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
const randomBytes: RandomBytes = (bytes) => crypto.getRandomValues(bytes);

/**
 * How many characters carry `bytes` of entropy. Hex and base64 encode the
 * bytes themselves; base62 draws whole characters, each worth log2(62) bits,
 * so it takes as many as reach the same number of bits: 43 for 32 bytes.
 * Base64 pads to a multiple of four; base64 URL leaves the padding off.
 */
export function encodedLength(encoding: Encoding, bytes: number): number {
  switch (encoding) {
    case 'hex':
      return bytes * 2;
    case 'base64':
      return Math.ceil(bytes / 3) * 4;
    case 'base64url':
      return Math.ceil((bytes * 8) / 6);
    case 'base62':
      return Math.ceil((bytes * 8) / Math.log2(62));
  }
}

/** `length` characters of base62, each drawn uniformly by rejecting the bytes 248 to 255. */
export function base62(length: number, random: RandomBytes = randomBytes): string {
  let out = '';
  while (out.length < length) {
    // About 3% of bytes are rejected, so a few spare bytes almost always finish it in one draw.
    for (const byte of random(new Uint8Array(length - out.length + 8))) {
      if (byte >= BASE62_LIMIT) continue;
      out += BASE62[byte % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

export function randomValue(encoding: Encoding, bytes: number, random: RandomBytes = randomBytes): string {
  if (encoding === 'base62') return base62(encodedLength('base62', bytes), random);
  const drawn = random(new Uint8Array(bytes));
  if (encoding === 'hex') return [...drawn].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const base64 = toBase64(drawn);
  return encoding === 'base64'
    ? base64
    : base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function generate(recipe: Recipe): Promise<Generated> {
  switch (recipe.kind) {
    case 'random':
      return { value: randomValue(recipe.encoding, recipe.bytes) };
    case 'aes': {
      const key = await subtle().generateKey({ name: 'AES-GCM', length: recipe.size }, true, [
        'encrypt',
        'decrypt',
      ]);
      return { value: toBase64(await subtle().exportKey('raw', key)) };
    }
    case 'pair': {
      const usages: KeyUsage[] = recipe.algorithm === 'ECDSA' ? ['sign', 'verify'] : ['deriveBits'];
      const pair = await subtle().generateKey(
        { name: recipe.algorithm, namedCurve: recipe.curve },
        true,
        usages,
      );
      return {
        value: toBase64(await subtle().exportKey('pkcs8', pair.privateKey)),
        publicKey: toBase64(await subtle().exportKey('raw', pair.publicKey)),
      };
    }
  }
}

/**
 * The name a key pair's public key gets beside its private key's:
 * `JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`, any other name gains `_PUBLIC`.
 */
export function publicKeyName(privateName: string): string {
  const name = privateName.trim();
  if (name === '') return '';
  if (/PRIVATE/.test(name)) return name.replace(/PRIVATE/g, 'PUBLIC');
  if (/private/.test(name)) return name.replace(/private/g, 'public');
  return `${name}_PUBLIC`;
}

/** What stops a key pair's two names from being saved, if anything. */
export function pairNameProblem(privateName: string, publicName: string): string | null {
  const names = [privateName.trim(), publicName.trim()];
  if (names.includes('')) return 'Give each key a name.';
  for (const name of names) {
    const problem = secretKeyProblem(name);
    if (problem !== null) return `${name}: ${problem}`;
  }
  return names[0] === names[1] ? 'The two keys need different names.' : null;
}

/** Web Crypto's keys need a secure context: HTTPS, or the machine's own address. */
function subtle(): SubtleCrypto {
  if (globalThis.crypto?.subtle === undefined) {
    throw new Error('This page is not served over HTTPS, so the browser makes no keys here.');
  }
  return globalThis.crypto.subtle;
}

function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

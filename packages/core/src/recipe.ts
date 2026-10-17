/**
 * How a secret's value is made, when a client makes it rather than a person
 * typing it: random strings, AES keys and EC key pairs, from Web Crypto
 * alone, the same in the browser and in the CLI.
 *
 * A recipe is short text, `bytes:32:hex`, which the CLI takes as
 * `--generate` and the server stores beside the version it made, so that
 * `coffre regenerate` and the page's Regenerate make the next one the same
 * way. The server checks a recipe's shape and never makes a value: a value
 * is made where it is sent from, and nothing here talks to the server.
 *
 * ```
 * bytes:<1-256>[:base62|hex|base64|base64url]   random bytes, base62 unless named
 * aes:<128|256>                                 an AES-GCM key: the raw key, base64
 * ecdsa:<p-256|p-384|p-521>                     a key pair: PKCS #8 private, SPKI public, base64
 * ecdh:<p-256|p-384|p-521>
 * ```
 */

export type Encoding = 'base62' | 'hex' | 'base64' | 'base64url';
export type AesSize = 128 | 256;
export type Curve = 'P-256' | 'P-384' | 'P-521';
export type PairAlgorithm = 'ECDSA' | 'ECDH';

export type Recipe =
  | { kind: 'random'; encoding: Encoding; bytes: number }
  | { kind: 'aes'; size: AesSize }
  | { kind: 'pair'; algorithm: PairAlgorithm; curve: Curve };

/** A value, and for a key pair its public key, which is saved as a secret of its own. */
export type Generated = { value: string; publicKey?: string };

/**
 * What a write says about how its value was made, and what a listing says
 * of a key's current value: its recipe, and for a key pair the two keys it
 * wrote together, which only a write of both at once makes.
 */
export type Generation = { recipe: string; pair?: KeyPairNames };
export type KeyPairNames = { private: string; public: string };

export const MIN_BYTES = 1;
export const MAX_BYTES = 256;
/** Longer than any recipe there is: `bytes:256:base64url` is 19. */
export const MAX_RECIPE_LENGTH = 32;
export const DEFAULT_RECIPE: Recipe = { kind: 'random', encoding: 'base62', bytes: 32 };

export const ENCODINGS: { id: Encoding; name: string }[] = [
  { id: 'base62', name: 'Letters and digits' },
  { id: 'hex', name: 'Hex' },
  { id: 'base64', name: 'Base64' },
  { id: 'base64url', name: 'Base64 URL' },
];

export const CURVES: readonly Curve[] = ['P-256', 'P-384', 'P-521'];

/** Strongest first, as a new key should be. */
export const PAIRS: { algorithm: PairAlgorithm; curve: Curve }[] = [
  { algorithm: 'ECDSA', curve: 'P-521' },
  { algorithm: 'ECDSA', curve: 'P-384' },
  { algorithm: 'ECDSA', curve: 'P-256' },
  { algorithm: 'ECDH', curve: 'P-521' },
  { algorithm: 'ECDH', curve: 'P-384' },
  { algorithm: 'ECDH', curve: 'P-256' },
];

export const RECIPE_SYNTAX = 'bytes:<1-256>[:base62|hex|base64|base64url], aes:<128|256>, ecdsa:<p-256|p-384|p-521> or ecdh:<curve>';

/**
 * The recipe a text names, in any case: `bytes:32` is `bytes:32:base62`,
 * `ECDSA:P-256` is `ecdsa:p-256`. Throws, saying what is wrong, for any
 * other text.
 */
export function parseRecipe(text: string): Recipe {
  const parts = text.trim().toLowerCase().split(':');
  const [kind, size, encoding, ...rest] = parts;
  const wrong = (what: string) => new Error(`${what}: a recipe is ${RECIPE_SYNTAX}`);
  if (text.length > MAX_RECIPE_LENGTH) throw wrong(`"${text.slice(0, MAX_RECIPE_LENGTH)}…" is too long`);
  switch (kind) {
    case 'bytes': {
      if (rest.length > 0) break;
      const bytes = wholeNumber(size);
      if (bytes === null || bytes < MIN_BYTES || bytes > MAX_BYTES) {
        throw wrong(`bytes takes a length from ${MIN_BYTES} to ${MAX_BYTES}, not "${size ?? ''}"`);
      }
      const named = encoding ?? 'base62';
      if (!ENCODINGS.some((each) => each.id === named)) {
        throw wrong(`bytes are written as base62, hex, base64 or base64url, not "${named}"`);
      }
      return { kind: 'random', bytes, encoding: named as Encoding };
    }
    case 'aes': {
      if (encoding !== undefined) break;
      if (size !== '128' && size !== '256') throw wrong(`an AES key is 128 or 256 bits, not "${size ?? ''}"`);
      return { kind: 'aes', size: Number(size) as AesSize };
    }
    case 'ecdsa':
    case 'ecdh': {
      if (encoding !== undefined) break;
      const curve = CURVES.find((each) => each.toLowerCase() === size);
      if (curve === undefined) throw wrong(`${kind} takes the curve p-256, p-384 or p-521, not "${size ?? ''}"`);
      return { kind: 'pair', algorithm: kind === 'ecdsa' ? 'ECDSA' : 'ECDH', curve };
    }
  }
  throw wrong(`"${text}" is no recipe`);
}

/** What is wrong with a recipe's text, or null for a recipe. */
export function recipeProblem(text: string): string | null {
  try {
    parseRecipe(text);
    return null;
  } catch (error) {
    return (error as Error).message;
  }
}

/** A recipe as it is stored and shown: lowercase, every part named. */
export function formatRecipe(recipe: Recipe): string {
  switch (recipe.kind) {
    case 'random':
      return `bytes:${recipe.bytes}:${recipe.encoding}`;
    case 'aes':
      return `aes:${recipe.size}`;
    case 'pair':
      return `${recipe.algorithm.toLowerCase()}:${recipe.curve.toLowerCase()}`;
  }
}

/** A recipe in words, for a confirmation or a listing: "32 random bytes, hex: 64 characters". */
export function describeRecipe(recipe: Recipe): string {
  switch (recipe.kind) {
    case 'random': {
      const name = ENCODINGS.find((each) => each.id === recipe.encoding)!.name;
      const lowered = recipe.encoding === 'base62' ? name.toLowerCase() : name;
      return `${recipe.bytes} random ${recipe.bytes === 1 ? 'byte' : 'bytes'}, ${lowered}: ${encodedLength(recipe.encoding, recipe.bytes)} characters`;
    }
    case 'aes':
      return `a ${recipe.size}-bit AES-GCM key, raw, base64`;
    case 'pair':
      return `an ${recipe.algorithm} ${recipe.curve} key pair: the private key PKCS #8, the public key SPKI, both base64`;
  }
}

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

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
/**
 * The largest multiple of 62 a byte reaches: 248. A byte below it is taken
 * modulo 62, and each of the 62 characters has four bytes that make it. The
 * eight bytes from 248 up are thrown away, as taking them would make the
 * first eight characters a little likelier than the rest.
 */
const BASE62_LIMIT = 256 - (256 % 62);

export type RandomBytes = (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
const randomBytes: RandomBytes = (bytes) => webCrypto().getRandomValues(bytes);

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

/** A value made by the recipe, with the platform's CSPRNG. */
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
        publicKey: toBase64(await subtle().exportKey('spki', pair.publicKey)),
      };
    }
  }
}

/** What a write of generated values sends, by key: each value with how it was made. */
export type GeneratedWrite = Record<string, { value: string; generated: Generation }>;

/**
 * A value made by the recipe for `key`, as a write sends it, and for a key
 * pair its public key beside it, under `publicKey` or the name that follows
 * from the private key's (`publicKeyName`). The two halves name each other.
 */
export async function generateWrite(key: string, recipe: Recipe, publicKey?: string): Promise<GeneratedWrite> {
  const text = formatRecipe(recipe);
  const made = await generate(recipe);
  if (recipe.kind !== 'pair') return { [key]: { value: made.value, generated: { recipe: text } } };
  const pair = { private: key, public: publicKey ?? publicKeyName(key) };
  return {
    [pair.private]: { value: made.value, generated: { recipe: text, pair } },
    [pair.public]: { value: made.publicKey!, generated: { recipe: text, pair } },
  };
}

/**
 * The next value of a key by the recipe its current one was made by, as a
 * listing says it: a key pair's either half makes the pair again, whole,
 * under the names its halves have now.
 */
export async function regenerateWrite(key: string, generated: Generation): Promise<GeneratedWrite> {
  const recipe = parseRecipe(generated.recipe);
  if (recipe.kind !== 'pair') return generateWrite(key, recipe);
  if (generated.pair === undefined) throw new Error(`${key}: ${generated.recipe} makes a key pair, and no pair is named`);
  return generateWrite(generated.pair.private, recipe, generated.pair.public);
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

function wholeNumber(text: string | undefined): number | null {
  return text !== undefined && /^\d{1,4}$/.test(text) ? Number(text) : null;
}

/** Web Crypto's keys need a secure context: HTTPS, or the machine's own address. */
function subtle(): SubtleCrypto {
  if (globalThis.crypto?.subtle === undefined) {
    throw new Error('This page is not served over HTTPS, so the browser makes no keys here.');
  }
  return globalThis.crypto.subtle;
}

function webCrypto(): Crypto {
  if (globalThis.crypto?.getRandomValues === undefined) throw new Error('This runtime has no Web Crypto to draw random bytes from.');
  return globalThis.crypto;
}

function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

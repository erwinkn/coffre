// libsodium's sealed box, `crypto_box_seal`, as GitHub takes an Actions
// secret: the value encrypted to the repository's public key, under a key
// pair made for it alone and dropped after, so that only GitHub opens it.
//
// Node has X25519, but not XSalsa20, Poly1305, nor BLAKE2b at the length a
// sealed box takes its nonce at: they are here, from their specifications,
// small enough to read whole. The CLI bundles nothing more for one call.
// A test opens what this seals with libsodium itself.
import { createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto';

/** Seal `message` to `recipient`, a 32-byte X25519 public key: the ephemeral public key, then the box. */
export function seal(message: Uint8Array, recipient: Uint8Array): Uint8Array {
  const ephemeral = generateKeyPairSync('x25519');
  const publicKey = Buffer.from(ephemeral.publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const shared = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(recipient).toString('base64url') }, format: 'jwk' }),
  });
  const nonce = blake2b(Buffer.concat([publicKey, recipient]), 24);
  // crypto_box: the shared secret through HSalsa20, then XSalsa20-Poly1305 under it.
  const box = secretbox(message, nonce, hsalsa20(shared, new Uint8Array(16)));
  return Buffer.concat([publicKey, box]);
}

/** crypto_secretbox_easy: XSalsa20's stream, its first 32 bytes the Poly1305 key; the tag, then the ciphertext. */
export function secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
  const subkey = hsalsa20(key, nonce.subarray(0, 16));
  const stream = salsa20Stream(subkey, nonce.subarray(16, 24), 32 + message.length);
  const ciphertext = message.map((byte, i) => byte ^ stream[32 + i]!);
  return Buffer.concat([poly1305(ciphertext, stream.subarray(0, 32)), ciphertext]);
}

// --- Salsa20 ----------------------------------------------------------------------

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

const rotl = (x: number, n: number) => (x << n) | (x >>> (32 - n));

/** Salsa20's state: the constants on the diagonal, the key around them, `input` in the middle. */
function state(key: Uint8Array, input: Uint8Array): Uint32Array {
  const k = new DataView(key.buffer, key.byteOffset, 32);
  const n = new DataView(input.buffer, input.byteOffset, 16);
  const word = (view: DataView, i: number) => view.getUint32(i * 4, true);
  return Uint32Array.from([
    SIGMA[0]!, word(k, 0), word(k, 1), word(k, 2),
    word(k, 3), SIGMA[1]!, word(n, 0), word(n, 1),
    word(n, 2), word(n, 3), SIGMA[2]!, word(k, 4),
    word(k, 5), word(k, 6), word(k, 7), SIGMA[3]!,
  ]);
}

/** Salsa20's 20 rounds, ten double rounds, on `x` in place. */
function rounds(x: Uint32Array): void {
  const quarter = (a: number, b: number, c: number, d: number) => {
    x[b]! ^= rotl((x[a]! + x[d]!) | 0, 7);
    x[c]! ^= rotl((x[b]! + x[a]!) | 0, 9);
    x[d]! ^= rotl((x[c]! + x[b]!) | 0, 13);
    x[a]! ^= rotl((x[d]! + x[c]!) | 0, 18);
  };
  for (let i = 0; i < 10; i++) {
    quarter(0, 4, 8, 12);
    quarter(5, 9, 13, 1);
    quarter(10, 14, 2, 6);
    quarter(15, 3, 7, 11);
    quarter(0, 1, 2, 3);
    quarter(5, 6, 7, 4);
    quarter(10, 11, 8, 9);
    quarter(15, 12, 13, 14);
  }
}

/** HSalsa20: a key and 16 bytes to a new key, the rounds' diagonal and middle, unmixed with the input. */
export function hsalsa20(key: Uint8Array, input: Uint8Array): Uint8Array {
  const x = state(key, input);
  rounds(x);
  const out = new DataView(new ArrayBuffer(32));
  [0, 5, 10, 15, 6, 7, 8, 9].forEach((word, i) => out.setUint32(i * 4, x[word]!, true));
  return new Uint8Array(out.buffer);
}

/** `length` bytes of Salsa20's stream, for an 8-byte nonce, its block counter from 0. */
function salsa20Stream(key: Uint8Array, nonce: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(Math.ceil(length / 64) * 64);
  const input = new Uint8Array(16);
  input.set(nonce);
  const counter = new DataView(input.buffer, 8, 8);
  for (let block = 0; block * 64 < length; block++) {
    counter.setBigUint64(0, BigInt(block), true);
    const initial = state(key, input);
    const x = initial.slice();
    rounds(x);
    const view = new DataView(out.buffer, block * 64, 64);
    for (let i = 0; i < 16; i++) view.setUint32(i * 4, (x[i]! + initial[i]!) >>> 0, true);
  }
  return out.subarray(0, length);
}

// --- Poly1305 -----------------------------------------------------------------------

/** A little-endian number from bytes. */
function le(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

/** Poly1305's 16-byte tag of `message` under a one-time 32-byte key. */
export function poly1305(message: Uint8Array, key: Uint8Array): Uint8Array {
  const p = (1n << 130n) - 5n;
  const r = le(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  let acc = 0n;
  for (let at = 0; at < message.length; at += 16) {
    const chunk = message.subarray(at, at + 16);
    acc = ((acc + le(chunk) + (1n << BigInt(8 * chunk.length))) * r) % p;
  }
  let tag = (acc + le(key.subarray(16, 32))) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++, tag >>= 8n) out[i] = Number(tag & 0xffn);
  return out;
}

// --- BLAKE2b (RFC 7693) -------------------------------------------------------------------

const MASK = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const PERMUTATIONS = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const rotr = (x: bigint, n: bigint) => ((x >> n) | (x << (64n - n))) & MASK;

/** BLAKE2b of `input`, `length` bytes long (1 to 64), unkeyed: the length is part of the hash, not a cut. */
export function blake2b(input: Uint8Array, length: number): Uint8Array {
  const h = IV.slice();
  h[0]! ^= 0x01010000n ^ BigInt(length);
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let b = 0; b < blocks; b++) {
    const block = new Uint8Array(128);
    block.set(input.subarray(b * 128, b * 128 + 128));
    const view = new DataView(block.buffer);
    const m = Array.from({ length: 16 }, (_, i) => view.getBigUint64(i * 8, true));
    const last = b === blocks - 1;
    const v = [...h, ...IV];
    v[12]! ^= BigInt(last ? input.length : (b + 1) * 128);
    if (last) v[14]! ^= MASK;
    const mix = (a: number, bb: number, c: number, d: number, x: bigint, y: bigint) => {
      v[a] = (v[a]! + v[bb]! + x) & MASK;
      v[d] = rotr(v[d]! ^ v[a]!, 32n);
      v[c] = (v[c]! + v[d]!) & MASK;
      v[bb] = rotr(v[bb]! ^ v[c]!, 24n);
      v[a] = (v[a]! + v[bb]! + y) & MASK;
      v[d] = rotr(v[d]! ^ v[a]!, 16n);
      v[c] = (v[c]! + v[d]!) & MASK;
      v[bb] = rotr(v[bb]! ^ v[c]!, 63n);
    };
    for (let round = 0; round < 12; round++) {
      const s = PERMUTATIONS[round % 10]!;
      const word = (i: number) => m[s[i]!]!;
      mix(0, 4, 8, 12, word(0), word(1));
      mix(1, 5, 9, 13, word(2), word(3));
      mix(2, 6, 10, 14, word(4), word(5));
      mix(3, 7, 11, 15, word(6), word(7));
      mix(0, 5, 10, 15, word(8), word(9));
      mix(1, 6, 11, 12, word(10), word(11));
      mix(2, 7, 8, 13, word(12), word(13));
      mix(3, 4, 9, 14, word(14), word(15));
    }
    for (let i = 0; i < 8; i++) h[i] = h[i]! ^ v[i]! ^ v[i + 8]!;
  }
  const out = new DataView(new ArrayBuffer(64));
  h.forEach((word, i) => out.setBigUint64(i * 8, word, true));
  return new Uint8Array(out.buffer, 0, length);
}

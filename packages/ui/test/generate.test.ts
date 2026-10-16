import test from 'node:test';
import assert from 'node:assert/strict';

import {
  base62,
  encodedLength,
  generate,
  MAX_BYTES,
  pairNameProblem,
  PAIRS,
  publicKeyName,
  randomValue,
  type Encoding,
} from '../src/lib/generate.ts';

const ALPHABETS: Record<Encoding, RegExp> = {
  base62: /^[0-9A-Za-z]*$/,
  hex: /^[0-9a-f]*$/,
  base64: /^[A-Za-z0-9+/]*={0,2}$/,
  base64url: /^[A-Za-z0-9_-]*$/,
};

/** A random source that hands out the given bytes in order, as many as asked each time. */
function scripted(bytes: number[]) {
  let next = 0;
  return (buffer: Uint8Array<ArrayBuffer>) => {
    for (let index = 0; index < buffer.length; index += 1) {
      if (next === bytes.length) throw new Error('the script ran out of bytes');
      buffer[index] = bytes[next++]!;
    }
    return buffer;
  };
}

test('32 bytes are 43 base62 characters, 64 hex, 44 base64 and 43 base64 URL', () => {
  assert.equal(encodedLength('base62', 32), 43);
  assert.equal(encodedLength('hex', 32), 64);
  assert.equal(encodedLength('base64', 32), 44);
  assert.equal(encodedLength('base64url', 32), 43);
});

test('base62 characters carry at least the entropy of the bytes asked for', () => {
  for (let bytes = 1; bytes <= MAX_BYTES; bytes += 1) {
    const length = encodedLength('base62', bytes);
    assert.ok(length * Math.log2(62) >= bytes * 8, `${bytes} bytes`);
    assert.ok((length - 1) * Math.log2(62) < bytes * 8, `${bytes} bytes, one character fewer`);
  }
});

test('each encoding gives its length, in its alphabet, at every size', () => {
  for (const encoding of Object.keys(ALPHABETS) as Encoding[]) {
    for (const bytes of [1, 2, 3, 31, 32, 33, 64, MAX_BYTES]) {
      const value = randomValue(encoding, bytes);
      assert.equal(value.length, encodedLength(encoding, bytes), `${encoding}, ${bytes} bytes`);
      assert.match(value, ALPHABETS[encoding], `${encoding}, ${bytes} bytes`);
    }
  }
});

test('hex and base64 encode the bytes drawn, and base64 URL leaves the padding off', () => {
  const bytes = [0xfb, 0xff, 0x00, 0x10];
  assert.equal(randomValue('hex', 4, scripted(bytes)), 'fbff0010');
  assert.equal(randomValue('base64', 4, scripted(bytes)), '+/8AEA==');
  assert.equal(randomValue('base64url', 4, scripted(bytes)), '-_8AEA');
});

test('base62 takes a byte below 248 modulo 62, and throws away the eight above', () => {
  // 0 → '0', 61 → 'z', 62 → '0' again, 247 = 3·62 + 61 → 'z'; 248 to 255 are skipped.
  const value = base62(4, scripted([248, 0, 255, 61, 250, 62, 252, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  assert.equal(value, '0z0z');
});

test('base62 draws again when every byte of a draw is thrown away', () => {
  const rejected = Array.from({ length: 2 + 8 }, () => 255);
  assert.equal(base62(2, scripted([...rejected, 10, 36, ...Array(8).fill(0)])), 'Aa');
});

test('each character of base62 is as likely as any other', () => {
  // Each of 62 characters is made by exactly four of the bytes kept, so
  // feeding every byte value once gives each character exactly four times.
  const every = Array.from({ length: 256 }, (_, byte) => byte);
  const value = base62(62 * 4, scripted([...every, ...Array(256).fill(0)]));
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  assert.equal(counts.size, 62);
  assert.deepEqual(new Set(counts.values()), new Set([4]));
});

test('an AES-GCM key is the raw key, base64, of its size, and imports back', async () => {
  for (const size of [128, 256] as const) {
    const { value, publicKey } = await generate({ kind: 'aes', size });
    assert.equal(publicKey, undefined);
    const raw = Buffer.from(value, 'base64');
    assert.equal(raw.length, size / 8);
    assert.equal(value.length, size === 256 ? 44 : 24);
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    assert.equal((key.algorithm as AesKeyAlgorithm).length, size);
  }
});

test('a key pair is its private key in PKCS #8 and its public key in SPKI, both base64, which work together', async () => {
  // A DER SubjectPublicKeyInfo: the uncompressed point (one byte, then x and y at the
  // curve's size) behind a header that names the algorithm and the curve.
  const spkiLength = { 'P-256': 91, 'P-384': 120, 'P-521': 158 };
  for (const { algorithm, curve } of PAIRS) {
    const { value, publicKey } = await generate({ kind: 'pair', algorithm, curve });
    assert.ok(publicKey !== undefined);
    const spki = Buffer.from(publicKey, 'base64');
    assert.equal(spki.length, spkiLength[curve], `${algorithm} ${curve}`);
    assert.equal(spki[0], 0x30);

    const params = { name: algorithm, namedCurve: curve };
    const privateUsages: KeyUsage[] = algorithm === 'ECDSA' ? ['sign'] : ['deriveBits'];
    const privateKey = await crypto.subtle.importKey('pkcs8', Buffer.from(value, 'base64'), params, false, privateUsages);
    const publicUsages: KeyUsage[] = algorithm === 'ECDSA' ? ['verify'] : [];
    const imported = await crypto.subtle.importKey('spki', spki, params, false, publicUsages);
    if (algorithm === 'ECDSA') {
      const signing = { name: 'ECDSA', hash: 'SHA-256' };
      const data = new TextEncoder().encode('coffre');
      const signature = await crypto.subtle.sign(signing, privateKey, data);
      assert.ok(await crypto.subtle.verify(signing, imported, signature, data), `${curve} verifies`);
    } else {
      // The two halves agree on a secret with a peer only if they belong together.
      const peer = await crypto.subtle.generateKey(params, false, ['deriveBits']);
      const ours = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer.publicKey }, privateKey, 128);
      const theirs = await crypto.subtle.deriveBits({ name: 'ECDH', public: imported }, peer.privateKey, 128);
      assert.deepEqual(Buffer.from(ours), Buffer.from(theirs), `${curve} agrees`);
    }
  }
});

test('two generated values differ', async () => {
  const first = await generate({ kind: 'random', encoding: 'base62', bytes: 32 });
  const second = await generate({ kind: 'random', encoding: 'base62', bytes: 32 });
  assert.notEqual(first.value, second.value);
});

test("a public key's name follows its private key's", () => {
  assert.equal(publicKeyName('JWT_PRIVATE_KEY'), 'JWT_PUBLIC_KEY');
  assert.equal(publicKeyName('signing_private'), 'signing_public');
  assert.equal(publicKeyName('SIGNING_KEY'), 'SIGNING_KEY_PUBLIC');
  assert.equal(publicKeyName('  '), '');
});

test("a key pair's two names are each a secret's name, and differ", () => {
  assert.equal(pairNameProblem('JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY'), null);
  assert.equal(pairNameProblem('', 'JWT_PUBLIC_KEY'), 'Give each key a name.');
  assert.equal(pairNameProblem('JWT', 'JWT'), 'The two keys need different names.');
  assert.equal(pairNameProblem('JWT', 'JWT-PUBLIC'), 'JWT-PUBLIC: Letters, digits and underscores only.');
});

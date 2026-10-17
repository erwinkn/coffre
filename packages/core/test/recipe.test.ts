import test from 'node:test';
import assert from 'node:assert/strict';

import {
  base62,
  describeRecipe,
  encodedLength,
  formatRecipe,
  generate,
  generateWrite,
  MAX_BYTES,
  PAIRS,
  parseRecipe,
  publicKeyName,
  randomValue,
  recipeProblem,
  regenerateWrite,
  type Encoding,
  type Recipe,
} from '../src/recipe.ts';

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

test('a recipe reads in any case, and is written lowercase with every part named', () => {
  const cases: [string, Recipe, string][] = [
    ['bytes:32', { kind: 'random', bytes: 32, encoding: 'base62' }, 'bytes:32:base62'],
    ['bytes:32:hex', { kind: 'random', bytes: 32, encoding: 'hex' }, 'bytes:32:hex'],
    ['BYTES:1:Base64URL', { kind: 'random', bytes: 1, encoding: 'base64url' }, 'bytes:1:base64url'],
    [' bytes:256:base64 ', { kind: 'random', bytes: 256, encoding: 'base64' }, 'bytes:256:base64'],
    ['aes:256', { kind: 'aes', size: 256 }, 'aes:256'],
    ['aes:128', { kind: 'aes', size: 128 }, 'aes:128'],
    ['ecdsa:P-256', { kind: 'pair', algorithm: 'ECDSA', curve: 'P-256' }, 'ecdsa:p-256'],
    ['ecdh:p-521', { kind: 'pair', algorithm: 'ECDH', curve: 'P-521' }, 'ecdh:p-521'],
  ];
  for (const [text, recipe, canonical] of cases) {
    assert.deepEqual(parseRecipe(text), recipe, text);
    assert.equal(formatRecipe(recipe), canonical, text);
    assert.deepEqual(parseRecipe(canonical), recipe, `${canonical} reads back`);
  }
});

test('every recipe the dialog offers is written and read back as itself', () => {
  const recipes: Recipe[] = [
    ...(['base62', 'hex', 'base64', 'base64url'] as const).flatMap((encoding) =>
      [1, 32, MAX_BYTES].map((bytes): Recipe => ({ kind: 'random', encoding, bytes }))),
    { kind: 'aes', size: 128 },
    { kind: 'aes', size: 256 },
    ...PAIRS.map((pair): Recipe => ({ kind: 'pair', ...pair })),
  ];
  for (const recipe of recipes) assert.deepEqual(parseRecipe(formatRecipe(recipe)), recipe, formatRecipe(recipe));
});

test('anything else is no recipe, and says what is wrong', () => {
  const cases: [string, RegExp][] = [
    ['', /"" is no recipe/],
    ['random:32', /"random:32" is no recipe/],
    ['bytes', /bytes takes a length from 1 to 256, not ""/],
    ['bytes:0', /bytes takes a length from 1 to 256, not "0"/],
    ['bytes:257', /not "257"/],
    ['bytes:3.5', /not "3.5"/],
    ['bytes:-1', /not "-1"/],
    ['bytes:32:base32', /base62, hex, base64 or base64url, not "base32"/],
    ['bytes:32:hex:x', /is no recipe/],
    ['aes:192', /128 or 256 bits, not "192"/],
    ['aes:256:raw', /is no recipe/],
    ['ecdsa:secp256k1', /p-256, p-384 or p-521, not "secp256k1"/],
    ['ed25519:x', /is no recipe/],
    [`bytes:${'1'.repeat(40)}`, /is too long/],
  ];
  for (const [text, problem] of cases) {
    assert.throws(() => parseRecipe(text), problem, text);
    assert.match(recipeProblem(text)!, /a recipe is bytes:<1-256>/, text);
  }
  assert.equal(recipeProblem('bytes:32:hex'), null);
});

test('a recipe in words says what it makes', () => {
  assert.equal(describeRecipe(parseRecipe('bytes:32')), '32 random bytes as 43 letters and digits');
  assert.equal(describeRecipe(parseRecipe('bytes:1:hex')), '1 random byte as 2 hex characters');
  assert.equal(describeRecipe(parseRecipe('bytes:16:base64url')), '16 random bytes as 22 base64 URL characters');
  assert.equal(describeRecipe(parseRecipe('aes:128')), 'a 128-bit AES-GCM key, raw, base64');
  assert.equal(describeRecipe(parseRecipe('ecdh:p-384')), 'an ECDH P-384 key pair: the private key PKCS #8, the public key SPKI, both base64');
});

test('a write of a generated value carries its recipe, and a key pair names both its keys on both', async () => {
  const single = await generateWrite('SESSION_SECRET', parseRecipe('bytes:32:hex'));
  assert.deepEqual(Object.keys(single), ['SESSION_SECRET']);
  assert.match(single.SESSION_SECRET!.value, /^[0-9a-f]{64}$/);
  assert.deepEqual(single.SESSION_SECRET!.generated, { recipe: 'bytes:32:hex' });

  const pair = await generateWrite('JWT_PRIVATE_KEY', parseRecipe('ECDSA:P-256'));
  const names = { private: 'JWT_PRIVATE_KEY', public: 'JWT_PUBLIC_KEY' };
  assert.deepEqual(Object.keys(pair), ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY']);
  for (const key of Object.keys(pair)) assert.deepEqual(pair[key]!.generated, { recipe: 'ecdsa:p-256', pair: names });
  // The private key is PKCS #8 and the public key SPKI, of the same pair.
  const params = { name: 'ECDSA', namedCurve: 'P-256' };
  const privateKey = await crypto.subtle.importKey('pkcs8', Buffer.from(pair.JWT_PRIVATE_KEY!.value, 'base64'), params, false, ['sign']);
  const publicKey = await crypto.subtle.importKey('spki', Buffer.from(pair.JWT_PUBLIC_KEY!.value, 'base64'), params, false, ['verify']);
  const data = new TextEncoder().encode('coffre');
  const signing = { name: 'ECDSA', hash: 'SHA-256' };
  assert.ok(await crypto.subtle.verify(signing, publicKey, await crypto.subtle.sign(signing, privateKey, data), data));

  const named = await generateWrite('SIGNER', parseRecipe('ecdh:p-384'), 'SIGNER_PEER');
  assert.deepEqual(Object.keys(named), ['SIGNER', 'SIGNER_PEER']);
});

test('regenerating either half of a key pair makes the pair again, under the names it has, replacing the versions listed', async () => {
  const generated = { recipe: 'ecdsa:p-384', pair: { private: 'SIGNING_KEY', public: 'SIGNING_KEY_PUB' } };
  const versions = new Map([['SIGNING_KEY', 'v-signing-4'], ['SIGNING_KEY_PUB', 'v-pub-3'], ['TOKEN', 'v-token-7'], ['__proto__', 'v-proto']]);
  const versionOf = (key: string) => versions.get(key) ?? null;
  for (const key of ['SIGNING_KEY', 'SIGNING_KEY_PUB']) {
    const write = await regenerateWrite(key, generated, versionOf);
    assert.deepEqual(Object.keys(write), ['SIGNING_KEY', 'SIGNING_KEY_PUB']);
    assert.deepEqual(write.SIGNING_KEY!.generated, generated);
    assert.deepEqual([write.SIGNING_KEY!.replaces, write.SIGNING_KEY_PUB!.replaces], ['v-signing-4', 'v-pub-3']);
  }
  const once = await regenerateWrite('TOKEN', { recipe: 'bytes:16:base64url' }, versionOf);
  assert.deepEqual(Object.keys(once), ['TOKEN']);
  assert.match(once.TOKEN!.value, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(once.TOKEN!.replaces, 'v-token-7');
  await assert.rejects(() => regenerateWrite('KEY', { recipe: 'ecdsa:p-256' }, versionOf), /no pair is named/);
  // A half not listed with a version of its own is no pair to regenerate.
  await assert.rejects(() => regenerateWrite('A', { recipe: 'ecdh:p-256', pair: { private: 'A', public: 'TOKEN' } }, versionOf), /A is not listed with a version/);
  // A key named __proto__ is a key like any other.
  assert.deepEqual(Object.keys(await regenerateWrite('__proto__', { recipe: 'aes:256' }, versionOf)), ['__proto__']);
});

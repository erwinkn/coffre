import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { deriveKey, seal, unseal } from '../src/identity/signin/sealed.ts';

const SECRET = randomBytes(32);
const KEY = deriveKey(SECRET, 'signin-state/v1');
const VALUE = { provider: 'github', state: 'st', next: '/projects', link: null };

test('deriveKey is stable per purpose and independent across purposes', () => {
  assert.equal(KEY.length, 32);
  assert.deepEqual(deriveKey(SECRET, 'signin-state/v1'), KEY);
  assert.notDeepEqual(deriveKey(SECRET, 'signin-state/v2'), KEY);
  assert.notDeepEqual(deriveKey(randomBytes(32), 'signin-state/v1'), KEY);
  assert.notDeepEqual(KEY, SECRET);
});

test('a sealed value opens with its key before it expires', () => {
  const sealed = seal(KEY, VALUE, 600);
  assert.match(sealed, /^v1\.[A-Za-z0-9_-]+$/);
  assert.equal(sealed.includes('github'), false, 'the value is encrypted, not just signed');
  assert.deepEqual(unseal(KEY, sealed), VALUE);
});

test('sealing the same value twice gives different ciphertexts', () => {
  assert.notEqual(seal(KEY, VALUE, 600), seal(KEY, VALUE, 600));
});

test('an expired value does not open, whatever the cookie lifetime said', () => {
  const now = Date.now();
  const sealed = seal(KEY, VALUE, 600, now);
  assert.deepEqual(unseal(KEY, sealed, now + 599_999), VALUE);
  assert.equal(unseal(KEY, sealed, now + 600_000), null);
  assert.equal(unseal(KEY, sealed, now + 3_600_000), null);
});

test('another key, a tampered byte or a malformed string opens to null', () => {
  const sealed = seal(KEY, VALUE, 600);
  assert.equal(unseal(deriveKey(SECRET, 'something-else'), sealed), null);

  const raw = Buffer.from(sealed.slice(3), 'base64url');
  for (const index of [0, 12, 28, raw.length - 1]) {
    const tampered = Buffer.from(raw);
    tampered[index] ^= 0x01;
    assert.equal(unseal(KEY, `v1.${tampered.toString('base64url')}`), null, `byte ${index}`);
  }

  assert.equal(unseal(KEY, `v2.${sealed.slice(3)}`), null, 'unknown version');
  assert.equal(unseal(KEY, 'v1.'), null);
  assert.equal(unseal(KEY, 'v1.AAAA'), null);
  assert.equal(unseal(KEY, `v1.${raw.subarray(0, 28).toString('base64url')}`), null, 'no ciphertext');
  assert.equal(unseal(KEY, 'not sealed at all'), null);
  assert.equal(unseal(KEY, ''), null);
  assert.equal(unseal(KEY, null), null);
  assert.equal(unseal(KEY, undefined), null);
});

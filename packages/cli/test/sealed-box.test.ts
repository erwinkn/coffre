// The sealed box GitHub takes Actions secrets in, held to libsodium itself:
// what this seals, libsodium opens, at every length around a block's.
import test from 'node:test';
import assert from 'node:assert/strict';

import sodium from 'libsodium-wrappers';

import { blake2b, seal } from '../src/sealed-box.ts';

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const LENGTHS = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000];

test('BLAKE2b is RFC 7693, and libsodium at the length a nonce takes', async () => {
  await sodium.ready;
  // RFC 7693, Appendix A.
  assert.equal(
    hex(blake2b(Buffer.from('abc'), 64)),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
  );
  for (const length of LENGTHS) {
    const input = sodium.randombytes_buf(length);
    assert.equal(hex(blake2b(input, 24)), hex(sodium.crypto_generichash(24, input, null)), `${length} bytes`);
  }
});

test('libsodium opens what seal seals, and only with the recipient key', async () => {
  await sodium.ready;
  const recipient = sodium.crypto_box_keypair();
  for (const length of LENGTHS) {
    const message = sodium.randombytes_buf(length);
    const sealed = seal(message, recipient.publicKey);
    assert.equal(sealed.length, 32 + 16 + length);
    assert.equal(hex(sodium.crypto_box_seal_open(sealed, recipient.publicKey, recipient.privateKey)), hex(message), `${length} bytes`);
  }
  // A key pair of its own each time: the same message never seals the same.
  const value = Buffer.from('postgresql://owner:hunter2@db.example.com/coffre');
  assert.notEqual(hex(seal(value, recipient.publicKey)), hex(seal(value, recipient.publicKey)));
  const other = sodium.crypto_box_keypair();
  assert.throws(() => sodium.crypto_box_seal_open(seal(value, recipient.publicKey), other.publicKey, other.privateKey));
  // A byte changed anywhere, and it does not open.
  const tampered = seal(value, recipient.publicKey);
  tampered[40]! ^= 1;
  assert.throws(() => sodium.crypto_box_seal_open(tampered, recipient.publicKey, recipient.privateKey));
});

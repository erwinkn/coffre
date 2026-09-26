import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';

import { sealedBox, sealNonce, sealWithEphemeralKey } from '../src/sealed-box.ts';
import { fromBase64, toBase64 } from '../src/base64.ts';

/** crypto_box_seal_open, written independently of the code under test. */
function sealOpen(sealed: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array | null {
  const recipientPublicKey = nacl.box.keyPair.fromSecretKey(recipientSecretKey).publicKey;
  const ephemeralPublicKey = sealed.subarray(0, 32);
  const nonce = sealNonce(ephemeralPublicKey, recipientPublicKey);
  return nacl.box.open(sealed.subarray(32), nonce, ephemeralPublicKey, recipientSecretKey);
}

const encode = (text: string) => new TextEncoder().encode(text);
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

// Fixed keys for the vectors below: the recipient secret key is bytes 0x01..0x20
// and the ephemeral secret key bytes 0xff..0xe0.
const recipientSecretKey = fromBase64('AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=');
const recipientPublicKey = fromBase64('B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=');
const ephemeralSecretKey = fromBase64('//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=');

test('a sealed box opens with the recipient secret key', () => {
  const recipient = nacl.box.keyPair();
  const message = encode('postgres://user:hunter2@db.internal/app');

  const sealed = sealedBox(message, recipient.publicKey);

  assert.equal(sealed.length, 32 + 16 + message.length);
  assert.equal(decode(sealOpen(sealed, recipient.secretKey)!), 'postgres://user:hunter2@db.internal/app');
});

test('every seal uses a fresh ephemeral key', () => {
  const recipient = nacl.box.keyPair();
  const a = sealedBox(encode('same'), recipient.publicKey);
  const b = sealedBox(encode('same'), recipient.publicKey);
  assert.notDeepEqual(a.subarray(0, 32), b.subarray(0, 32));
});

test('a sealed box does not open with another key, or once tampered with', () => {
  const recipient = nacl.box.keyPair();
  const sealed = sealedBox(encode('secret'), recipient.publicKey);

  assert.equal(sealOpen(sealed, nacl.box.keyPair().secretKey), null);

  const tampered = sealed.slice();
  tampered[tampered.length - 1]! ^= 1;
  assert.equal(sealOpen(tampered, recipient.secretKey), null);
});

test('an empty value seals to just the header', () => {
  const recipient = nacl.box.keyPair();
  const sealed = sealedBox(new Uint8Array(0), recipient.publicKey);
  assert.equal(sealed.length, 48);
  assert.deepEqual(sealOpen(sealed, recipient.secretKey), new Uint8Array(0));
});

test('matches a known-answer vector that libsodium opens', () => {
  // Produced by sealWithEphemeralKey with the fixed keys above, then opened with
  // PyNaCl 1.5.0 (libsodium): SealedBox(PrivateKey(rsk)).decrypt(sealed) returned
  // b'coffre sealed box vector'.
  const expected =
    'Pry2khSTRNxU5YFgz5C+2e6h3RToHI6R3lV699ev2RWD+N1XlE3Zioh7BO4PYcar7XRdQxGiEdSl+cWiZVnzNb2vww49xxqw';

  const sealed = sealWithEphemeralKey(encode('coffre sealed box vector'), recipientPublicKey, ephemeralSecretKey);

  assert.equal(toBase64(sealed), expected);
});

test('opens a box sealed by libsodium', () => {
  // Produced with PyNaCl 1.5.0 (libsodium):
  //   SealedBox(PrivateKey(rsk).public_key).encrypt(b'sealed by libsodium')
  // This pins the nonce derivation and the wire layout from the other direction.
  const sealed = fromBase64(
    'P1Do10itOybkRTlHd9M5sAZOTDtBAdclNxI9Vjc4tXWySwD09sOMCH6WTBeInNLAkheTlxQdfDrPGFE708Yneba5FA==',
  );
  assert.equal(decode(sealOpen(sealed, recipientSecretKey)!), 'sealed by libsodium');
});

test('rejects a recipient key of the wrong length', () => {
  assert.throws(() => sealedBox(encode('x'), new Uint8Array(31)), /32 bytes/);
});

test('base64 round-trips binary larger than one chunk', () => {
  const bytes = new Uint8Array(70_000).map((_, i) => (i * 131) & 0xff);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
});

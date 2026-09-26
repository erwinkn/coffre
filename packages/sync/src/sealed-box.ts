import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2.js';

const KEY_BYTES = nacl.box.publicKeyLength;

/**
 * libsodium's `crypto_box_seal`, which is what GitHub requires for Actions
 * secrets: an anonymous box from a throwaway key pair, so only the recipient
 * can open it and nothing identifies the sender.
 *
 * Built from tweetnacl's `crypto_box` rather than libsodium-wrappers because
 * the latter ships WASM, which is awkward to load in a Worker.
 */
export function sealedBox(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const ephemeralSecretKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  try {
    return sealWithEphemeralKey(message, recipientPublicKey, ephemeralSecretKey);
  } finally {
    ephemeralSecretKey.fill(0);
  }
}

/**
 * The deterministic core of `sealedBox`, exported only so the tests can pin a
 * known-answer vector. Reusing an ephemeral key breaks the construction.
 */
export function sealWithEphemeralKey(
  message: Uint8Array,
  recipientPublicKey: Uint8Array,
  ephemeralSecretKey: Uint8Array,
): Uint8Array {
  if (recipientPublicKey.length !== KEY_BYTES) {
    throw new Error(`recipient public key must be ${KEY_BYTES} bytes`);
  }

  const ephemeral = nacl.box.keyPair.fromSecretKey(ephemeralSecretKey);
  const nonce = sealNonce(ephemeral.publicKey, recipientPublicKey);
  const boxed = nacl.box(message, nonce, recipientPublicKey, ephemeral.secretKey);
  ephemeral.secretKey.fill(0);

  // Wire format: ephemeral_pk || MAC || ciphertext, exactly as libsodium lays it out.
  const sealed = new Uint8Array(KEY_BYTES + boxed.length);
  sealed.set(ephemeral.publicKey, 0);
  sealed.set(boxed, KEY_BYTES);
  return sealed;
}

/** libsodium derives the nonce instead of sending it: blake2b(epk || rpk), 24 bytes. */
export function sealNonce(ephemeralPublicKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const input = new Uint8Array(KEY_BYTES * 2);
  input.set(ephemeralPublicKey, 0);
  input.set(recipientPublicKey, KEY_BYTES);
  return blake2b(input, { dkLen: nacl.box.nonceLength });
}

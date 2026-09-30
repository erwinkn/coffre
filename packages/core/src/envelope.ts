import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretContext } from './context.ts';
import { encodeAad } from './context.ts';
import type { KekRegistry } from './kek/registry.ts';
import { DEK_BYTES } from './kek/types.ts';

export * from './context.ts';

const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Current envelope format version. Stored on every row so the format can change
 * without a bulk re-encryption.
 */
export const ENVELOPE_VERSION = 1;

/**
 * One sealed secret value, exactly as it is stored in `secret_versions`.
 *
 * The AAD binding is implemented here, in our own envelope layer, rather than
 * via a provider "encryption context" feature. That keeps the stored format
 * portable: moving to a different KMS changes only how `wrappedDek` is produced.
 */
export type Envelope = {
  envelopeVersion: number;
  kekProvider: string;
  kekId: string;
  kekVersion: string;
  wrappedDek: Buffer;
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
};

/** The part of an envelope the data key produces: everything but the wrapped key. */
export type Sealed = Pick<Envelope, 'envelopeVersion' | 'iv' | 'authTag' | 'ciphertext'>;

/** A fresh data key. One per version, so no key ever encrypts two values. */
export function freshDek(): Buffer {
  return randomBytes(DEK_BYTES);
}

/**
 * Encrypt a secret value under `dek`, bound to `ctx`. Whoever holds the key
 * encryption key wraps `dek` separately: the vault, in coffre.
 */
export function encrypt(plaintext: Buffer, ctx: SecretContext, dek: Buffer): Sealed {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', dek, iv);
  cipher.setAAD(encodeAad(ctx));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { envelopeVersion: ENVELOPE_VERSION, iv, authTag: cipher.getAuthTag(), ciphertext };
}

/**
 * Decrypt with an unwrapped `dek`. Throws if the envelope was sealed for a
 * different project, environment or secret than `ctx` describes, because
 * the AAD will not match. This is the property that makes relocating a
 * ciphertext across environments fail closed.
 */
export function decrypt(envelope: Sealed, ctx: SecretContext, dek: Buffer): Buffer {
  if (envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.envelopeVersion}`);
  }
  if (envelope.iv.length !== IV_BYTES) {
    throw new Error('envelope IV has the wrong length');
  }
  if (envelope.authTag.length !== TAG_BYTES) {
    throw new Error('envelope auth tag has the wrong length');
  }
  const decipher = createDecipheriv('aes-256-gcm', dek, envelope.iv);
  decipher.setAAD(encodeAad(ctx));
  decipher.setAuthTag(envelope.authTag);
  return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
}

/**
 * Encrypt a secret value under a fresh DEK, and wrap that DEK under the
 * registry's primary KEK: `encrypt` and the wrap in one, where both halves
 * are in one place.
 */
export async function seal(
  plaintext: Buffer,
  ctx: SecretContext,
  keks: KekRegistry,
): Promise<Envelope> {
  const dek = freshDek();
  try {
    const sealed = encrypt(plaintext, ctx, dek);
    const wrapped = await keks.wrap(dek, ctx);
    return {
      ...sealed,
      kekProvider: wrapped.kekProvider,
      kekId: wrapped.kekId,
      kekVersion: wrapped.kekVersion,
      wrappedDek: wrapped.bytes,
    };
  } finally {
    dek.fill(0);
  }
}

/** Unwrap the envelope's DEK under the registry and decrypt: `decrypt` and the unwrap in one. */
export async function open(
  envelope: Envelope,
  ctx: SecretContext,
  keks: KekRegistry,
): Promise<Buffer> {
  if (envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.envelopeVersion}`);
  }
  const dek = await keks.unwrap(
    {
      kekProvider: envelope.kekProvider,
      kekId: envelope.kekId,
      kekVersion: envelope.kekVersion,
      bytes: envelope.wrappedDek,
    },
    ctx,
  );
  try {
    return decrypt(envelope, ctx, dek);
  } finally {
    dek.fill(0);
  }
}

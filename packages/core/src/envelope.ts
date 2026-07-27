import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretContext } from './context.ts';
import { encodeAad } from './context.ts';
import type { KekRegistry } from './kek/registry.ts';
import { DEK_BYTES } from './kek/types.ts';

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

/**
 * Encrypt a secret value under a fresh DEK, and wrap that DEK under the
 * registry's primary KEK.
 *
 * A new DEK is generated per version. Versions are append-only, so a DEK is
 * never reused across two different plaintexts and the GCM IV-reuse hazard
 * cannot arise from normal operation.
 */
export async function seal(
  plaintext: Buffer,
  ctx: SecretContext,
  keks: KekRegistry,
): Promise<Envelope> {
  const aad = encodeAad(ctx);
  const dek = randomBytes(DEK_BYTES);

  try {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const wrapped = await keks.wrap(dek, ctx);

    return {
      envelopeVersion: ENVELOPE_VERSION,
      kekProvider: wrapped.kekProvider,
      kekId: wrapped.kekId,
      kekVersion: wrapped.kekVersion,
      wrappedDek: wrapped.bytes,
      iv,
      authTag,
      ciphertext,
    };
  } finally {
    dek.fill(0);
  }
}

/**
 * Decrypt a sealed secret value.
 *
 * Throws if the envelope was sealed for a different project, environment or
 * secret than `ctx` describes, because the AAD will not match. This is the
 * property that makes relocating a ciphertext across environments fail closed.
 */
export async function open(
  envelope: Envelope,
  ctx: SecretContext,
  keks: KekRegistry,
): Promise<Buffer> {
  if (envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.envelopeVersion}`);
  }
  if (envelope.iv.length !== IV_BYTES) {
    throw new Error('envelope IV has the wrong length');
  }
  if (envelope.authTag.length !== TAG_BYTES) {
    throw new Error('envelope auth tag has the wrong length');
  }

  const aad = encodeAad(ctx);
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
    const decipher = createDecipheriv('aes-256-gcm', dek, envelope.iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(envelope.authTag);
    return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
  } finally {
    dek.fill(0);
  }
}

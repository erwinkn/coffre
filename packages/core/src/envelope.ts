import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretContext } from './context.ts';
import { encodeAad } from './context.ts';
import type { KekRegistry } from './kek/registry.ts';
import { DEK_BYTES } from './kek/types.ts';

export * from './context.ts';

const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * The envelope's format, stored on every row so that it can change without a
 * bulk re-encryption. The two differ in what the wrap of a value's key
 * names (`SecretContext`). In 1, all 0.14 wrote, its secret, a personal
 * config's owner and whether it is sensitive. In 2 the version's number too:
 * without it, a database writer could copy a secret's old version over its
 * current one, and it would open. A row relabelled from one to the other
 * opens as neither.
 */
export const ENVELOPE_VERSION = 2;

/** Format 1: a wrap that names no version number. */
const UNNUMBERED = 1;

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
 * Encrypt a secret value under `dek`, bound to `ctx`'s ids. Whoever holds
 * the key encryption key wraps `dek` separately: the vault, in coffre, whose
 * wrap binds the owner and sensitivity too.
 */
export function encrypt(plaintext: Buffer, ctx: SecretIds, dek: Buffer): Sealed {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', dek, iv);
  cipher.setAAD(valueAad(ctx));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // The value's half is the same in both formats. `seal` says which the wrap is.
  return { envelopeVersion: UNNUMBERED, iv, authTag: cipher.getAuthTag(), ciphertext };
}

/**
 * Decrypt with an unwrapped `dek`. Throws if the envelope was sealed for a
 * different project, environment or secret than `ctx` describes, because
 * the AAD will not match. This is the property that makes relocating a
 * ciphertext across environments fail closed.
 */
export function decrypt(envelope: Sealed, ctx: SecretIds, dek: Buffer): Buffer {
  if (envelope.envelopeVersion !== UNNUMBERED && envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.envelopeVersion}`);
  }
  if (envelope.iv.length !== IV_BYTES) {
    throw new Error('envelope IV has the wrong length');
  }
  if (envelope.authTag.length !== TAG_BYTES) {
    throw new Error('envelope auth tag has the wrong length');
  }
  const decipher = createDecipheriv('aes-256-gcm', dek, envelope.iv);
  decipher.setAAD(valueAad(ctx));
  decipher.setAuthTag(envelope.authTag);
  return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
}

/** What a value's own ciphertext binds: the secret's ids, never its owner or sensitivity, which only the wrap of its key does. */
export type SecretIds = Pick<SecretContext, 'projectId' | 'environmentId' | 'secretId'>;

function valueAad(ctx: SecretIds): Buffer {
  return encodeAad({ projectId: ctx.projectId, environmentId: ctx.environmentId, secretId: ctx.secretId });
}

/**
 * Encrypt a secret value under a fresh DEK, and wrap that DEK under the
 * registry's primary KEK: `encrypt` and the wrap in one, where both halves
 * are in one place. The envelope is format 2 when `ctx` names the version's
 * number, which the vault's always does.
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
      envelopeVersion: ctx.version === undefined ? UNNUMBERED : ENVELOPE_VERSION,
      kekProvider: wrapped.kekProvider,
      kekId: wrapped.kekId,
      kekVersion: wrapped.kekVersion,
      wrappedDek: wrapped.bytes,
    };
  } finally {
    dek.fill(0);
  }
}

/**
 * Unwrap the envelope's DEK under the registry and decrypt: `decrypt` and
 * the unwrap in one. `ctx` is the version's as its rows give it, number
 * included; the envelope's format says whether its wrap names the number.
 */
export async function open(
  envelope: Envelope,
  ctx: SecretContext,
  keks: KekRegistry,
): Promise<Buffer> {
  if (envelope.envelopeVersion !== UNNUMBERED && envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.envelopeVersion}`);
  }
  if (envelope.envelopeVersion === UNNUMBERED) ctx = { ...ctx, version: undefined };
  else if (ctx.version === undefined) throw new Error('an envelope of format 2 opens under its version\'s number');
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

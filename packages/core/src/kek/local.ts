import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import type { SecretContext } from '../context.ts';
import { encodeAad } from '../context.ts';
import { DEK_BYTES, type KekProvider, type WrappedDek } from './types.ts';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEK_BYTES = 32;

/**
 * A KEK held in local process memory, loaded from configuration.
 *
 * This is the local-development implementation of `KekProvider`. It is a
 * different implementation of the same interface, not a branch that skips
 * wrapping: the envelope format, the context binding and the failure modes are
 * identical to what a remote KMS-backed provider will produce.
 */
export class LocalKekProvider implements KekProvider {
  readonly provider = 'local';
  readonly keyId: string;
  readonly keyVersion: string;

  readonly #kek: Buffer;

  constructor(kek: Buffer, keyId: string, keyVersion: string = '1') {
    if (kek.length !== KEK_BYTES) {
      throw new Error(`local KEK must be ${KEK_BYTES} bytes, got ${kek.length}`);
    }
    this.#kek = kek;
    this.keyId = keyId;
    this.keyVersion = keyVersion;
  }

  /** Build a provider from a base64-encoded 32-byte key, e.g. from an env var. */
  static fromBase64(encoded: string, keyId: string, keyVersion = '1'): LocalKekProvider {
    return new LocalKekProvider(Buffer.from(encoded, 'base64'), keyId, keyVersion);
  }

  /** Generate a fresh random KEK. Used by tests and by the dev seed script. */
  static generate(keyId: string, keyVersion = '1'): LocalKekProvider {
    return new LocalKekProvider(randomBytes(KEK_BYTES), keyId, keyVersion);
  }

  /**
   * AAD for the wrap operation.
   *
   * Binds the wrapped DEK both to the secret it belongs to and to the KEK
   * identity that produced it, so a wrapped DEK cannot be replayed against a
   * row claiming a different KEK.
   */
  #wrapAad(ctx: SecretContext): Buffer {
    return Buffer.concat([
      encodeAad(ctx),
      Buffer.from(`|${this.provider}|${this.keyId}|${this.keyVersion}`, 'utf8'),
    ]);
  }

  async wrap(dek: Buffer, ctx: SecretContext): Promise<WrappedDek> {
    if (dek.length !== DEK_BYTES) {
      throw new Error(`DEK must be ${DEK_BYTES} bytes, got ${dek.length}`);
    }

    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.#kek, iv);
    cipher.setAAD(this.#wrapAad(ctx));

    const body = Buffer.concat([cipher.update(dek), cipher.final()]);

    return {
      kekProvider: this.provider,
      kekId: this.keyId,
      kekVersion: this.keyVersion,
      bytes: Buffer.concat([iv, cipher.getAuthTag(), body]),
    };
  }

  async unwrap(wrapped: WrappedDek, ctx: SecretContext): Promise<Buffer> {
    if (wrapped.kekProvider !== this.provider || wrapped.kekId !== this.keyId) {
      throw new Error(
        `wrapped DEK is for ${wrapped.kekProvider}:${wrapped.kekId}, not ${this.provider}:${this.keyId}`,
      );
    }
    if (wrapped.bytes.length !== IV_BYTES + TAG_BYTES + DEK_BYTES) {
      throw new Error('wrapped DEK has the wrong length');
    }

    const iv = wrapped.bytes.subarray(0, IV_BYTES);
    const tag = wrapped.bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const body = wrapped.bytes.subarray(IV_BYTES + TAG_BYTES);

    const decipher = createDecipheriv('aes-256-gcm', this.#kek, iv);
    decipher.setAAD(this.#wrapAad(ctx));
    decipher.setAuthTag(tag);

    // GCM raises on a tag mismatch, which is what a relocated or tampered
    // wrapped DEK produces. The error is deliberately not specific.
    const dek = Buffer.concat([decipher.update(body), decipher.final()]);

    // Defensive: a 32-byte plaintext is the only shape we ever wrap.
    if (dek.length !== DEK_BYTES) {
      throw new Error('unwrapped DEK has the wrong length');
    }
    return dek;
  }
}

/** Constant-time buffer comparison, for tests and callers that need it. */
export function equalBytes(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

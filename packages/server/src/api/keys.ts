import { decrypt, encrypt, freshDek, type Envelope } from '../../../core/src/envelope.ts';
import type { Purpose, Refusal, SecretRef, Vault, WrappedKey } from '../../../vault/src/types.ts';

/**
 * The app's half of envelope encryption. It encrypts and decrypts values
 * with data keys, but never holds a key that wraps them: the vault wraps
 * each fresh data key, and unwraps one only for a principal it lets read.
 * One vault call per batch, so a `coffre run` of fifty keys is one decision.
 */

/** Who is asking the vault, and why. */
export type Asking = { principal: string; requestId: string | null };

export type Keyed<T> = { ok: true; values: T[] } | { ok: false; refusal: Refusal };

function wrappedKey(envelope: Envelope): WrappedKey {
  return {
    kekProvider: envelope.kekProvider,
    kekId: envelope.kekId,
    kekVersion: envelope.kekVersion,
    bytes: envelope.wrappedDek.toString('base64'),
  };
}

function withWrapped(sealed: Omit<Envelope, 'kekProvider' | 'kekId' | 'kekVersion' | 'wrappedDek'>, wrapped: WrappedKey): Envelope {
  return {
    ...sealed,
    kekProvider: wrapped.kekProvider,
    kekId: wrapped.kekId,
    kekVersion: wrapped.kekVersion,
    wrappedDek: Buffer.from(wrapped.bytes, 'base64'),
  };
}

/** Encrypt each value under a fresh data key, and have the vault wrap the keys. */
export async function sealValues(
  vault: Vault,
  asking: Asking,
  items: { secret: SecretRef; value: string }[],
): Promise<Keyed<Envelope>> {
  if (items.length === 0) return { ok: true, values: [] };
  const deks = items.map(() => freshDek());
  try {
    const sealed = items.map(({ secret, value }, i) => encrypt(Buffer.from(value, 'utf8'), secret, deks[i]));
    const result = await vault.wrap({
      ...asking,
      items: items.map(({ secret }, i) => ({ secret, key: deks[i].toString('base64') })),
    });
    if (!result.ok) return result;
    return { ok: true, values: sealed.map((parts, i) => withWrapped(parts, result.wrapped[i])) };
  } finally {
    for (const dek of deks) dek.fill(0);
  }
}

/** Have the vault unwrap each envelope's key, and decrypt. */
export async function openValues(
  vault: Vault,
  asking: Asking & { purpose: Purpose },
  items: { secret: SecretRef; envelope: Envelope }[],
): Promise<Keyed<string>> {
  if (items.length === 0) return { ok: true, values: [] };
  const result = await vault.unwrap({
    ...asking,
    items: items.map(({ secret, envelope }) => ({ secret, wrapped: wrappedKey(envelope) })),
  });
  if (!result.ok) return result;
  return {
    ok: true,
    values: items.map(({ secret, envelope }, i) => {
      const dek = Buffer.from(result.keys[i], 'base64');
      try {
        return decrypt(envelope, secret, dek).toString('utf8');
      } finally {
        dek.fill(0);
      }
    }),
  };
}

/**
 * An old version's value as a new version: the same ciphertext, its key
 * wrapped again by the vault under the current key encryption key. Needs a
 * write grant, not a read one: the value is never opened.
 */
export async function rewrapValue(
  vault: Vault,
  asking: Asking,
  secret: SecretRef,
  from: { version: number; envelope: Envelope },
): Promise<Keyed<Envelope>> {
  const result = await vault.rewrap({
    ...asking,
    items: [{ secret, from: from.version, wrapped: wrappedKey(from.envelope) }],
  });
  if (!result.ok) return result;
  return { ok: true, values: [withWrapped(from.envelope, result.wrapped[0])] };
}

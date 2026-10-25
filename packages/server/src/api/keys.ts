import { decrypt, encrypt, freshDek, type Envelope } from '@coffre/core/envelope';
import type { Purpose, Refusal, SecretRef, Through, Vault, Via, WrappedKey } from '@coffre/core/vault';

import { AccessChanged, type Recalled } from '../accesses.ts';
import { ApiError } from './errors.ts';

/**
 * The app's half of envelope encryption. It encrypts and decrypts values
 * with data keys, but never holds a key that wraps them: the vault wraps
 * each fresh data key, and unwraps one only for a principal it lets read.
 * One vault call per batch, so a `coffre run` of fifty keys is one decision.
 */

/** Who is asking the vault, and why: the operation id ties the vault's entries to the app's for the same action. */
export type Asking = Through & { principal: string; requestId: string | null; operationId: string | null; credentialId?: string | null };

export type Keyed<T> = { ok: true; values: T[] } | { ok: false; refusal: Refusal };

/** Keys the vault wrapped, and the seq of its `key.wrap` or `key.rewrap` entry for each. */
export type Wrapped = { ok: true; values: Envelope[]; seqs: number[] } | { ok: false; refusal: Refusal };

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
): Promise<Wrapped> {
  if (items.length === 0) return { ok: true, values: [], seqs: [] };
  const deks = items.map(() => freshDek());
  try {
    const sealed = items.map(({ secret, value }, i) => encrypt(Buffer.from(value, 'utf8'), secret, deks[i]));
    const result = await vault.wrap({
      ...asking,
      items: items.map(({ secret }, i) => ({ secret, key: deks[i].toString('base64') })),
    });
    if (!result.ok) return result;
    boundAsAsked(items, result);
    return { ok: true, values: sealed.map((parts, i) => withWrapped(parts, result.wrapped[i])), seqs: result.seqs };
  } finally {
    for (const dek of deks) dek.fill(0);
  }
}

/**
 * Throw unless the vault bound each key sensitive exactly where the write
 * asked: a vault older than 0.10 binds none, and answers no `sensitive`,
 * and a version stored sensitive over a key it wrapped as a secret would
 * open for nobody.
 */
function boundAsAsked(items: readonly { secret: SecretRef }[], result: { sensitive?: readonly boolean[] }): void {
  if (items.every(({ secret }, i) => (secret.sensitive === true) === (result.sensitive?.[i] === true))) return;
  throw new ApiError('unavailable', 'the vault binds no sensitive value: it is older than this app, so deploy it first, then write again', 'vault_outdated');
}

/**
 * Have the vault unwrap each envelope's key, and decrypt; `via` reads a
 * source through a reference, and `through` names the fork an inherited
 * value is read in. A plain value is no secret: it is its `plaintext`,
 * with no vault call and no `secret.read` of it, so placeholders and the bulk
 * limit pass it by. Each caller has checked the read itself, a parent's
 * included. A reference's is opened through the vault all the same, which
 * holds the reference to its rules.
 */
export async function openValues(
  vault: Vault,
  asking: Asking & { purpose: Purpose; keepsSensitive?: boolean },
  items: { secretVersionId: string; secret: SecretRef; envelope: Envelope; plaintext?: string | null; via?: Via; through?: string }[],
  /** The caller's, decided on a kept answer of the vault's: the vault checks it, and says so by naming it back. */
  recalled?: Recalled,
): Promise<Keyed<string>> {
  const sealed = items.filter((item) => !plain(item));
  if (sealed.length === 0) return { ok: true, values: items.map((item) => item.plaintext!) };
  const checks = recalled !== undefined && !recalled.confirmed ? recalled.revision : undefined;
  const result = await vault.unwrap({
    ...asking,
    ...(checks === undefined ? {} : { accessRevision: checks }),
    items: sealed.map(({ secretVersionId, via, through }) => ({
      secretVersionId,
      ...(via === undefined ? {} : { via }),
      ...(through === undefined ? {} : { through }),
    })),
  });
  if (!result.ok && result.refusal.code === 'access_changed') throw new AccessChanged();
  // A vault older than 0.14.1 names nothing back: it checked nothing, and the request asks before it answers.
  if (result.ok && checks !== undefined && result.accessRevision === checks) recalled!.vouched();
  if (!result.ok) return result;
  const opened = sealed.map(({ secret, envelope }, i) => {
    const dek = Buffer.from(result.keys[i], 'base64');
    try {
      return decrypt(envelope, secret, dek).toString('utf8');
    } finally {
      dek.fill(0);
    }
  });
  let next = 0;
  return { ok: true, values: items.map((item) => (plain(item) ? item.plaintext! : opened[next++]!)) };
}

/**
 * Whether an item's value is plain, and read as it is: its own, a
 * parent's, or a reference's to a plain source, which takes its nature
 * from its source and its readers from where it is held.
 */
export function plain(item: { plaintext?: string | null }): boolean {
  return item.plaintext != null;
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
  from: { id: string; envelope: Envelope },
): Promise<Wrapped> {
  return rewrapValues(vault, asking, [{ secret, from }]);
}

/** `rewrapValue` for several, all or none: a key made stricter, or an old value brought back. */
export async function rewrapValues(
  vault: Vault,
  asking: Asking,
  items: readonly { secret: SecretRef; from: { id: string; envelope: Envelope } }[],
): Promise<Wrapped> {
  if (items.length === 0) return { ok: true, values: [], seqs: [] };
  const result = await vault.rewrap({
    ...asking,
    items: items.map(({ secret, from }) => ({ secret, secretVersionId: from.id })),
  });
  if (!result.ok) return result;
  boundAsAsked(items, result);
  return { ok: true, values: items.map(({ from }, i) => withWrapped(from.envelope, result.wrapped[i]!)), seqs: result.seqs };
}

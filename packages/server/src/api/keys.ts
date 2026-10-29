import { decrypt, encrypt, freshDek, type Envelope } from '@coffre/core/envelope';
import {
  newUseRequestId,
  USE_DEADLINE_MS,
  USE_METADATA_LENGTH,
  useRefusalMessage,
  type NamedUseOutcome,
  type Purpose,
  type Refusal,
  type SecretRef,
  type Through,
  type UsedValue,
  type UseOutcome,
  type UseRecord,
  type Vault,
  type Via,
  type WrappedKey,
} from '@coffre/core/vault';

import { AccessChanged, type Recalled } from '../accesses.ts';
import type { AuditEntry } from '../db/audit.ts';
import { uses015 } from './changes.ts';
import { ApiError, UNAVAILABLE, vaultRefused } from './errors.ts';

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
  asking: Asking & {
    purpose: Purpose;
    keepsSensitive?: boolean;
    /**
     * The id of the credentials row the request came in on: with 0.15's uses on, each value is opened by a use on it
     * (`useValues`). Not `credentialId`, which names the request's provenance in the vault's entries, and is no row's.
     */
    credentialRow?: string | null;
  },
  items: OpenItem[],
  /** The caller's, decided on a kept answer of the vault's: the vault checks it, and says so by naming it back. */
  recalled?: Recalled,
  /**
   * The credential proxy's `credential.use` entry, for the vault to append
   * beside its reads (`UnwrapInput.use`): `used` says it did, and the app
   * appends nothing then. Plain values only ask no vault, and log no use.
   * With 0.15's uses, nothing appends it, however long: each use's entry is
   * the record, and `used` says so too.
   */
  use?: UseRecord,
  /**
   * The use of this request's one key the vault made already, by name (`Vault.useNamed`, T145): nothing is opened
   * again, and its outcome is the value's, a plain one's text included, which the vault decided as any.
   */
  decided?: Decided,
): Promise<Keyed<string> & { used?: true; stood?: true }> {
  if (decided !== undefined) return decidedValues(decided, items);
  const sealed = items.filter((item) => !plain(item));
  if (sealed.length === 0) return { ok: true, values: items.map((item) => item.plaintext!) };
  const { credentialRow, ...asked } = asking;
  if (credentialRow != null && (await uses015(vault))) {
    const opened = await useValues(vault, { credential: credentialRow, purpose: asking.purpose, keepsSensitive: asking.keepsSensitive === true }, sealed);
    // A use decides on the rows as they are, but only where its key is held: it vouches for a kept answer about the
    // caller when every value going back is a use's, each read where it is held. Not with a plain value beside, which
    // no use decided, nor one inherited in a fork, where the use checks no permission of the caller's: the app asks.
    if (recalled !== undefined && sealed.length === items.length && sealed.every((item) => item.through === undefined)) recalled.vouched();
    let next = 0;
    // `stood`: each use decided on `credentialRow` as it was then, revoked, ended or of a generation its account has moved
    // past, sealed (formal/Credentials.tla, Revoking015Folded): what `credentialStill` would read again.
    return { ok: true, values: items.map((item) => (plain(item) ? item.plaintext! : opened[next++]!)), used: true, stood: true };
  }
  const checks = recalled !== undefined && !recalled.confirmed ? recalled.revision : undefined;
  const result = await vault.unwrap({
    ...asked,
    ...(checks === undefined ? {} : { accessRevision: checks }),
    items: sealed.map(({ secretVersionId, via, through }) => ({
      secretVersionId,
      ...(via === undefined ? {} : { via }),
      ...(through === undefined ? {} : { through }),
    })),
    ...(use === undefined ? {} : { use }),
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
  // A vault older than 0.14.5 names nothing back: it appended no use, and the app does.
  return { ok: true, values: items.map((item) => (plain(item) ? item.plaintext! : opened[next++]!)), ...(use !== undefined && result.used === true ? { used: true as const } : {}) };
}

/**
 * A value to open: its version, as the app read it, and what it is bound
 * to; `holder`, for a reference, the key that holds it, which a use names
 * (the vault finds the source itself, as it reads it then).
 */
export type OpenItem = { secretVersionId: string; secret: SecretRef; envelope: Envelope; plaintext?: string | null; via?: Via; through?: string; holder?: string };

/** How many uses one request has in flight at once: a whole environment's read takes turns, and leaves the isolate's admission room for others (R44). */
export const USES_AT_ONCE = 4;

/**
 * 0.15's read (docs/design/0.15-plan.md, PR 5b): one use per value, each
 * `use_credential` call logged as its request and decided on the rows as
 * the call reads them (R53). What goes back is the version the app read,
 * opened from the use's envelope: a use that read another answers 409, so
 * that the rest of the answer (its version, its natures) is of the same.
 * All or nothing: the first refusal refuses the request, and no value of
 * it goes back. A use the vault could not decide (late, over its isolate's
 * calls in flight) answers 503 with `Retry-After` (R44).
 *
 *   Ada's `coffre run` of 9 keys      9 uses, 4 at a time     9 entries, the values
 *   her grant revoked after the 4th   the 5th refused         403, nothing handed back
 */
export async function useValues(
  vault: Vault,
  asked: { credential: string; purpose: Purpose; keepsSensitive: boolean },
  items: readonly OpenItem[],
): Promise<string[]> {
  const values: string[] = [];
  let failed: { error: unknown } | null = null;
  let next = 0;
  const turn = async () => {
    while (failed === null && next < items.length) {
      const i = next++;
      const item = items[i]!;
      const at = Date.now();
      try {
        const outcome = await vault.use!({
          credential: asked.credential,
          secretId: item.holder ?? item.secret.secretId,
          place: item.through ?? null,
          purpose: asked.purpose,
          ...(asked.keepsSensitive ? { keepsSensitive: true } : {}),
          requestId: newUseRequestId(),
          at,
          deadline: at + USE_DEADLINE_MS,
        });
        if (!outcome.ok) throw refusedUse(outcome);
        // Another version than the app read: what the rest of the answer says (its version, nature, what it left out)
        // would not be of this value. Asked again, the request reads both anew.
        if (outcome.value.versionId !== item.secretVersionId) throw changed();
        values[i] = openedValue(outcome.value);
      } catch (error) {
        failed ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(USES_AT_ONCE, items.length) }, turn));
  if (failed !== null) throw (failed as { error: unknown }).error;
  return values;
}

/** The value a use opened, decrypted with its key and bound to what the vault read: a reference's source's ids. */
function openedValue(value: UsedValue): string {
  const dek = Buffer.from(value.key, 'base64');
  try {
    const { envelope } = value;
    const sealed = { envelopeVersion: envelope.version, ciphertext: Buffer.from(envelope.ciphertext, 'base64'), iv: Buffer.from(envelope.iv, 'base64'), authTag: Buffer.from(envelope.authTag, 'base64') };
    return decrypt(sealed, value.context, dek).toString('utf8');
  } finally {
    dek.fill(0);
  }
}

/** A use of a request's one key the vault made already, by name (`Vault.useNamed`): the key's id, and its outcome. */
export type Decided = { secretId: string | null; outcome: Extract<NamedUseOutcome, { served: true }>['outcome'] };

/**
 * The values of a read the vault decided already, by name: at most its one key, whose outcome stands for it, a refusal
 * as `useValues` answers it. The use decided on the request's credential too, so nothing reads it again (`stood`);
 * `used` where its entry is the vault's, a sealed value's.
 */
function decidedValues({ secretId, outcome }: Decided, items: readonly OpenItem[]): Keyed<string> & { used?: true; stood: true } {
  // Nothing of it going back (a key the place does not hold, a person's sensitive value a list leaves out): its outcome,
  // logged as the vault decided it, refuses nothing more. The vault wrote no use of a key it does not hold: the app's
  // own entry records the request, as before (review r1).
  if (items.length === 0) return { ok: true, values: [], stood: true };
  if (!outcome.ok) throw refusedUse(outcome);
  const values = items.map((item) => {
    if ((item.holder ?? item.secret.secretId) !== secretId) throw new Error("a named use's read opens no key but the one the vault decided");
    if ('plain' in outcome) {
      if (outcome.versionId !== item.secretVersionId) throw changed();
      return outcome.plain;
    }
    if (outcome.value.versionId !== item.secretVersionId) throw changed();
    return openedValue(outcome.value);
  });
  // A plain value's use the vault decided writes no entry: the app's records it, as when it handed one back itself.
  return { ok: true, values, stood: true, ...('plain' in outcome ? {} : { used: true as const }) };
}

/** A key this read names, written or removed while it ran: 409, to ask again. */
const changed = () => new ApiError('conflict', 'a key this read names was changed while it ran: try again', 'changed');

/**
 * A use refused, as the API answers it: the rules' refusals as 0.14's
 * (`vaultRefused`); a credential ended, 401; a key gone since the app read
 * it, 409, to be asked again; no cap logged yet, or a use not decided
 * (busy), 503 with the vault's `Retry-After`.
 */
export function refusedUse(outcome: Exclude<UseOutcome, { ok: true }>): ApiError {
  if ('busy' in outcome) return new ApiError('unavailable', UNAVAILABLE, undefined, String(outcome.retryAfter));
  switch (outcome.code) {
    case 'credential':
      return new ApiError('unauthenticated', useRefusalMessage('credential'));
    case 'missing':
      return changed();
    case 'no_policy':
      return new ApiError('unavailable', UNAVAILABLE);
    default:
      return vaultRefused({ code: outcome.code, message: useRefusalMessage(outcome.code) });
  }
}

/**
 * The app's entry of a use, as the vault appends it (`UnwrapInput.use`): its
 * fields as `appendAudit` would write them. Undefined for one longer than
 * the vault takes (`USE_METADATA_LENGTH`), a use naming hundreds of keys,
 * which the app appends itself.
 */
export function useRecord(entry: AuditEntry): UseRecord | undefined {
  const metadata = JSON.stringify(entry.metadata ?? {});
  if (metadata.length > USE_METADATA_LENGTH) return undefined;
  return { projectId: entry.projectId ?? null, environmentId: entry.environmentId ?? null, sourceIp: entry.sourceIp ?? null, metadata };
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

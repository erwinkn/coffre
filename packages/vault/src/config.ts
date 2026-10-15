import { hkdfSync } from 'node:crypto';

import { KekRegistry, LocalKekProvider, type KekProvider } from '@coffre/core/kek';

/** At most `count` data keys unwrapped per principal in any `windowMs`. */
export type BulkLimit = { count: number; windowMs: number };

/**
 * 1000 keys in 15 minutes: twenty `coffre run`s of a 50-key environment
 * back to back, which no person or deploy pipeline does, while a script
 * pulling every secret it can reach stops within a few seconds.
 */
export const DEFAULT_BULK_LIMIT: BulkLimit = { count: 1000, windowMs: 15 * 60_000 };

/** The vault as it runs: keys decoded, emails checked. */
export type ResolvedVaultConfig = {
  keks: KekRegistry;
  /**
   * Emails, lowercased: who becomes an Owner of the whole instance when it
   * has none, signing in (`access` in vault.ts). Otherwise nothing.
   */
  bootstrapOwners: readonly string[];
  /**
   * Who the vault makes an Owner of the whole instance, though it has one,
   * and until when, in ms since the epoch: `recoverOwner`. Null when the
   * configuration names nobody.
   */
  recoverOwner: { email: string; until: number } | null;
  /**
   * The seeds of the vault's own keys, which MAC its log entries, seal member
   * rows and sign checkpoints: the first signs; every one verifies what it
   * signed, so a rotation leaves earlier records verifying.
   */
  signingKeys: readonly Uint8Array[];
  bulkLimit: BulkLimit;
};

/**
 * A key-encryption key: 32 random bytes, base64, and the id envelopes record
 * it under; or one a key service holds, such as `awsKms({ keyArn, … })`.
 */
export type Kek = { id: string; key: string } | KekProvider;

/**
 * What a deployment writes: every key coffre has, and who may claim the
 * instance while nobody owns it. The app holds none of it.
 *
 *   {
 *     kek: awsKms({ keyArn: env.KMS_KEY_ARN, credentials: { … } }),
 *     previousKeks: [{ id: 'vault-2025-01-10-k7q2xm', key: env.OLD_VAULT_KEY }],
 *     bootstrapOwners: ['admin@acme.example'],
 *     signingKey: env.SIGNING_KEY, // required with a key service; derived from a local KEK otherwise
 *     recoverOwner: { email: 'omar@acme.example', until: '2026-10-20' }, // only while every Owner is locked out
 *   }
 */
export type VaultConfig = {
  /** Wraps every new data key. */
  kek: Kek;
  /**
   * Older KEKs, still unwrapping what they wrapped until a rewrap moves it
   * on, and verifying what the vault wrote under them before the rotation.
   */
  previousKeks?: readonly Kek[];
  /**
   * 32 random bytes, base64: the seed of the vault's own keys, which MAC its
   * log entries, seal member rows and sign checkpoints. Leave it out with a
   * local KEK, and the vault derives it from the KEK. Required when a key
   * service holds the KEK, as AWS KMS does: the vault never sees that key.
   */
  signingKey?: string;
  /** At most `count` data keys unwrapped per principal in any `windowMinutes`; 1000 in 15 unless set. */
  bulkLimit?: { count: number; windowMinutes: number };
  /**
   * The way back in when the instance has Owners but none of them can sign
   * in any more: until `until`, an ISO 8601 date or time at most a week
   * ahead, each vault process makes `email` an Owner of the whole instance
   * at its first call, if they are not one, logged as the vault's
   * (`reason: 'recovery'`). Take it out once they are in.
   */
  recoverOwner?: { email: string; until: string };
} & BootstrapOwners;

/**
 * At least one email, who becomes an Owner of the whole instance by signing
 * in while it has none: the way into a fresh instance, and back into one
 * whose every Owner is gone. While it has one, the list does nothing.
 * `rootAdmins` is its name before 0.6, read for one release.
 */
type BootstrapOwners =
  | { bootstrapOwners: readonly string[]; rootAdmins?: never }
  | {
      /** @deprecated 0.5's name for `bootstrapOwners`, read until 0.7: a root admin is an Owner now. */
      rootAdmins: readonly string[];
      bootstrapOwners?: never;
    };

function key32(value: string, what: string): Buffer {
  const raw = Buffer.from(value, 'base64');
  if (raw.length !== 32) throw new Error(`${what} must be 32 bytes, base64; got ${raw.length} bytes`);
  return raw;
}

const KEK_ID = /^[A-Za-z0-9._-]{1,64}$/;
const KEK_PROVIDER = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Every row records it, and `provider:keyId` finds the KEK again: visible ASCII, bounded. */
const KEK_NAME = /^[\x21-\x7e]{1,255}$/;

/** The label no other use of a KEK shares: a local KEK is otherwise only ever an AES-256-GCM key. */
const SIGNING_KEY_LABEL = 'coffre.vault.signing-key.v1';

/** The signing key a local KEK stands for, when the vault is given none: HKDF-SHA-256 of the KEK. */
export function derivedSigningKey(kek: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', kek, new Uint8Array(0), SIGNING_KEY_LABEL, 32));
}

/** A KEK as the registry takes it, and the signing key it stands for when it is one the vault holds. */
function kek(entry: Kek): { provider: KekProvider; signingKey: Buffer | null } {
  if (!('wrap' in entry)) {
    const { id, key } = entry;
    if (!KEK_ID.test(id)) throw new Error(`the vault key's ID "${id}" (kek.id) must be 1-64 letters, digits, dots, dashes or underscores`);
    const raw = key32(key, `the vault key ${id}`);
    return { provider: new LocalKekProvider(raw, id), signingKey: derivedSigningKey(raw) };
  }
  const { provider, keyId, keyVersion } = entry;
  if (typeof provider !== 'string' || !KEK_PROVIDER.test(provider)) {
    throw new Error(`a key service's name (kek.provider) must be 1-32 lowercase letters, digits or dashes; got "${String(provider)}"`);
  }
  if (typeof keyId !== 'string' || !KEK_NAME.test(keyId) || typeof keyVersion !== 'string' || !KEK_NAME.test(keyVersion)) {
    throw new Error(`vault key ${provider}: keyId and keyVersion must be 1-255 visible ASCII characters`);
  }
  if (typeof entry.wrap !== 'function' || typeof entry.unwrap !== 'function') {
    throw new Error(`vault key ${provider}:${keyId} needs wrap() and unwrap()`);
  }
  return { provider: entry, signingKey: null };
}

/** Check a deployment's vault configuration, failing on the first problem. */
export function resolveVaultConfig(config: VaultConfig): ResolvedVaultConfig {
  const keks = [config.kek, ...(config.previousKeks ?? [])].map(kek);
  const [current, ...previous] = keks.map((entry) => entry.provider);
  const refs = [current, ...previous].map(({ provider, keyId }) => `${provider}:${keyId}`);
  const twice = refs.find((ref, i) => refs.indexOf(ref) !== i);
  if (twice !== undefined) throw new Error(`two vault keys share an id: ${twice}`);
  return {
    keks: new KekRegistry(current, previous),
    bootstrapOwners: checkBootstrapOwners(config.bootstrapOwners ?? config.rootAdmins ?? []),
    signingKeys: signingKeys(config.signingKey, keks),
    bulkLimit: config.bulkLimit === undefined ? DEFAULT_BULK_LIMIT : checkBulkLimit(config.bulkLimit),
    recoverOwner: config.recoverOwner === undefined ? null : checkRecoverOwner(config.recoverOwner, Date.now()),
  };
}

/**
 * The key the vault signs with, then every other it verifies with. It signs
 * with `signingKey` when it is given one, and otherwise with the key the
 * primary KEK stands for. It verifies with the keys every local KEK stands
 * for too, the previous ones included: a KEK rotation changes the derived
 * signing key, and what the old one signed before the rotation must still
 * verify, for as long as the old KEK stays configured. Nothing after it does
 * (`#settle` in vault.ts).
 */
function signingKeys(given: string | undefined, keks: { provider: KekProvider; signingKey: Buffer | null }[]): Buffer[] {
  const derived = keks.flatMap((entry) => (entry.signingKey === null ? [] : [entry.signingKey]));
  let signing: Buffer;
  if (given !== undefined) signing = key32(given, 'the signing key');
  else if (keks[0].signingKey !== null) signing = keks[0].signingKey;
  else {
    const { provider, keyId } = keks[0].provider;
    throw new Error(
      `signingKey is required with the ${provider} vault key ${keyId}: the vault derives its signing key only from a vault key it holds, ` +
        'and a key service never hands its key over. Set signingKey to 32 random bytes, base64 (openssl rand -base64 32), and keep it with the vault key.',
    );
  }
  return [signing, ...derived].filter((key, i, all) => all.findIndex((other) => other.equals(key)) === i);
}

function checkBulkLimit({ count, windowMinutes }: { count: number; windowMinutes: number }): BulkLimit {
  if (!Number.isInteger(count) || count < 1 || !(windowMinutes > 0)) {
    throw new Error('bulkLimit needs a whole count of at least 1 and a window above 0 minutes');
  }
  return { count, windowMs: windowMinutes * 60_000 };
}

/** How far ahead a recovery may end: long enough to deploy and sign in, too short to forget it is there. */
export const RECOVERY_WINDOW_MS = 7 * 24 * 60 * 60_000;

/**
 * The recovery as the vault applies it, refused when `until` is more than
 * a week after `now`: left in place, a recovery makes its person an Owner
 * again at each new process, after an Owner demoted them too, so it ends by
 * itself. One already over is kept, and does nothing.
 */
export function checkRecoverOwner({ email, until }: { email: string; until: string }, now: number): { email: string; until: number } {
  const trimmed = typeof email === 'string' ? email.trim() : '';
  if (!isHumanEmail(trimmed)) throw new Error(`recoverOwner.email must be a person's email; got "${String(email)}"`);
  const end = typeof until === 'string' && /^\d{4}-\d{2}-\d{2}/.test(until) ? Date.parse(until) : Number.NaN;
  if (Number.isNaN(end)) throw new Error(`recoverOwner.until must be an ISO 8601 date or time, such as 2026-10-20 or 2026-10-20T18:00:00Z; got "${String(until)}"`);
  if (end > now + RECOVERY_WINDOW_MS) {
    throw new Error(`recoverOwner.until must be at most a week ahead, so that a recovery left in place ends by itself; got ${until}`);
  }
  return { email: trimmed.toLowerCase(), until: end };
}

function isHumanEmail(value: string): boolean {
  if (value.length > 254) return false;

  const parts = value.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (
    local.length === 0 ||
    local.length > 64 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
  ) {
    return false;
  }

  const labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
  );
}

/**
 * The bootstrap Owners, lowercased the way they are compared. At least one,
 * in every mode: they are the only way into a fresh instance, and back into
 * one with no Owner left.
 */
export function checkBootstrapOwners(emails: readonly string[]): string[] {
  const owners = [...new Set(emails.map((entry) => entry.trim()).filter((entry) => entry.length > 0))];
  if (owners.length === 0) {
    throw new Error('bootstrapOwners must name at least one email, or nobody can manage coffre');
  }
  const invalid = owners.find((entry) => !isHumanEmail(entry));
  if (invalid) {
    throw new Error(`bootstrapOwners must be human email identities; invalid: ${invalid}`);
  }
  return owners.map((entry) => entry.toLowerCase());
}

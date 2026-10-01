import { LocalKekProvider } from '../../core/src/kek/local.ts';
import { KekRegistry } from '../../core/src/kek/registry.ts';

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
  /** Emails, lowercased: always active, always owners, never changed through the API. */
  rootAdmins: readonly string[];
  /** The Ed25519 seed checkpoints are signed with. */
  signingKey: Uint8Array;
  bulkLimit: BulkLimit;
};

/** A key-encryption key: 32 random bytes, base64, and the id envelopes record it under. */
export type Kek = { id: string; key: string };

/**
 * What a deployment writes: every key coffre has, and who may always get
 * in. The app holds none of it.
 *
 *   {
 *     kek: { id: 'kek-2026-09', key: env.KEK },
 *     previousKeks: [{ id: 'kek-2025-01', key: env.KEK_2025_01 }],
 *     rootAdmins: ['admin@acme.example'],
 *     signingKey: env.SIGNING_KEY,
 *   }
 */
export type VaultConfig = {
  /** Wraps every new data key. */
  kek: Kek;
  /** Older KEKs, still unwrapping what they wrapped until a rewrap moves it on. */
  previousKeks?: readonly Kek[];
  /** At least one email: the only way into a fresh instance, and the only members nobody can remove. */
  rootAdmins: readonly string[];
  /** 32 random bytes, base64: the Ed25519 seed audit checkpoints are signed with. */
  signingKey: string;
  /** At most `count` data keys unwrapped per principal in any `windowMinutes`; 1000 in 15 unless set. */
  bulkLimit?: { count: number; windowMinutes: number };
};

function key32(value: string, what: string): Buffer {
  const raw = Buffer.from(value, 'base64');
  if (raw.length !== 32) throw new Error(`${what} must be 32 bytes, base64; got ${raw.length} bytes`);
  return raw;
}

const KEK_ID = /^[A-Za-z0-9._-]{1,64}$/;

function kek({ id, key }: Kek): LocalKekProvider {
  if (!KEK_ID.test(id)) throw new Error(`KEK id "${id}" must be 1-64 letters, digits, dots, dashes or underscores`);
  return new LocalKekProvider(key32(key, `KEK ${id}`), id);
}

/** Check a deployment's vault configuration, failing on the first problem. */
export function resolveVaultConfig(config: VaultConfig): ResolvedVaultConfig {
  const keks = [config.kek, ...(config.previousKeks ?? [])];
  const ids = keks.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) throw new Error('two KEKs share an id');
  const [current, ...previous] = keks.map(kek);
  return {
    keks: new KekRegistry(current, previous),
    rootAdmins: checkRootAdmins(config.rootAdmins),
    signingKey: key32(config.signingKey, 'the signing key'),
    bulkLimit: config.bulkLimit === undefined ? DEFAULT_BULK_LIMIT : checkBulkLimit(config.bulkLimit),
  };
}

function checkBulkLimit({ count, windowMinutes }: { count: number; windowMinutes: number }): BulkLimit {
  if (!Number.isInteger(count) || count < 1 || !(windowMinutes > 0)) {
    throw new Error('bulkLimit needs a whole count of at least 1 and a window above 0 minutes');
  }
  return { count, windowMs: windowMinutes * 60_000 };
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
 * Root admins, lowercased the way they are compared. At least one, in every
 * mode: they are the only way into a fresh instance, and the only members
 * nobody can remove.
 */
export function checkRootAdmins(emails: readonly string[]): string[] {
  const rootAdmins = [...new Set(emails.map((entry) => entry.trim()).filter((entry) => entry.length > 0))];
  if (rootAdmins.length === 0) {
    throw new Error('rootAdmins must name at least one email, or nobody can manage coffre');
  }
  const invalid = rootAdmins.find((entry) => !isHumanEmail(entry));
  if (invalid) {
    throw new Error(`rootAdmins must be human email identities; invalid: ${invalid}`);
  }
  return rootAdmins.map((entry) => entry.toLowerCase());
}

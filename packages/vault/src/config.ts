import { LocalKekProvider } from '../../core/src/kek/local.ts';
import { KekRegistry } from '../../core/src/kek/registry.ts';

type Environment = Readonly<Record<string, string | undefined>>;

/** At most `count` data keys unwrapped per principal in any `windowMs`. */
export type BulkLimit = { count: number; windowMs: number };

/**
 * 1000 keys in 15 minutes: twenty `coffre run`s of a 50-key environment
 * back to back, which no person or deploy pipeline does, while a script
 * pulling every secret it can reach stops within a few seconds.
 */
export const DEFAULT_BULK_LIMIT: BulkLimit = { count: 1000, windowMs: 15 * 60_000 };

export type VaultConfig = {
  keks: KekRegistry;
  /** Emails, lowercased: always active, always owners, never changed through the API. */
  rootAdmins: readonly string[];
  /** The Ed25519 seed checkpoints are signed with. */
  signingKey: Uint8Array;
  bulkLimit: BulkLimit;
};

function required(env: Environment, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

function requiredKey(env: Environment, name: string): Buffer {
  const raw = Buffer.from(required(env, name), 'base64');
  if (raw.length !== 32) {
    throw new Error(`${name} must decode to exactly 32 bytes, got ${raw.length}`);
  }
  return raw;
}

/**
 * The vault's configuration: every key coffre has, and who may always get
 * in. The app has none of it.
 *
 *   COFFRE_KEK_LOCAL, COFFRE_KEK_ID    the primary KEK and its id
 *   COFFRE_KEK_LOCAL_PREVIOUS          older KEKs, `id:base64,...`, still unwrapping
 *   COFFRE_ROOT_ADMINS                 emails, comma-separated; at least one
 *   COFFRE_VAULT_SIGNING_KEY           a 32-byte Ed25519 seed, base64
 *   COFFRE_BULK_LIMIT                  `<count>/<window>`, e.g. `1000/15m`
 */
export function loadVaultConfig(env: Environment): VaultConfig {
  const primary = LocalKekProvider.fromBase64(
    required(env, 'COFFRE_KEK_LOCAL'),
    env.COFFRE_KEK_ID ?? 'local-dev-1',
  );

  const secondary = (env.COFFRE_KEK_LOCAL_PREVIOUS ?? '')
    .split(',')
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const separator = entry.indexOf(':');
      if (separator <= 0 || separator === entry.length - 1) {
        throw new Error(
          'COFFRE_KEK_LOCAL_PREVIOUS entries must use the form key-id:base64-material',
        );
      }
      return LocalKekProvider.fromBase64(
        entry.slice(separator + 1),
        entry.slice(0, separator),
      );
    });

  return {
    keks: new KekRegistry(primary, secondary),
    rootAdmins: parseRootAdmins(env.COFFRE_ROOT_ADMINS),
    signingKey: requiredKey(env, 'COFFRE_VAULT_SIGNING_KEY'),
    bulkLimit: env.COFFRE_BULK_LIMIT ? parseBulkLimit(env.COFFRE_BULK_LIMIT) : DEFAULT_BULK_LIMIT,
  };
}

/** `1000/15m`: a count, then a window in seconds, minutes or hours. */
export function parseBulkLimit(raw: string): BulkLimit {
  const match = /^\s*(\d+)\s*\/\s*(\d+)\s*([smh])\s*$/.exec(raw);
  const count = Number(match?.[1]);
  const windowMs = Number(match?.[2]) * { s: 1000, m: 60_000, h: 3_600_000 }[match?.[3] as 's' | 'm' | 'h'];
  if (!match || count < 1 || !(windowMs > 0)) {
    throw new Error(`COFFRE_BULK_LIMIT must look like 1000/15m, got: ${raw}`);
  }
  return { count, windowMs };
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
export function parseRootAdmins(raw: string | undefined): string[] {
  const rootAdmins = [
    ...new Set(
      (raw ?? '')
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0),
    ),
  ];
  if (rootAdmins.length === 0) {
    throw new Error('COFFRE_ROOT_ADMINS must name at least one email, or nobody can manage coffre');
  }
  const invalid = rootAdmins.find((entry) => !isHumanEmail(entry));
  if (invalid) {
    throw new Error(`COFFRE_ROOT_ADMINS entries must be human email identities; invalid: ${invalid}`);
  }
  return rootAdmins.map((entry) => entry.toLowerCase());
}

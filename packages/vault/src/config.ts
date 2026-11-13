import { derivedSigningKey, KekRegistry, LocalKekProvider, type KekProvider } from '@coffre/core/kek';

import type { Workloads } from './caller.ts';
import type { SignerAlert } from './signer-host.ts';

/** At most `count` distinct data keys unwrapped per principal in any `windowMs`. */
export type BulkLimit = { count: number; windowMs: number };

/**
 * 1000 different keys in 15 minutes, which no person or deploy pipeline
 * reads, while a script pulling every secret it can reach stops within a
 * few seconds. A key read again counts once: a 50-key `coffre run` is 50
 * however often it runs.
 */
export const DEFAULT_BULK_LIMIT: BulkLimit = { count: 1000, windowMs: 15 * 60_000 };

/**
 * The longest bulk limit window: a day. The releases a window counts are
 * kept a day and an hour (migration 0021's `prune_vault_releases`,
 * `RELEASES_KEPT_MS`), so every window up to it, and one widened
 * since, counts exactly.
 */
export const MAX_BULK_WINDOW_MINUTES = 24 * 60;

/** How long an instance remembers a use's rows unless told (`memorySeconds`): what a revocation waits at most. */
export const DEFAULT_MEMORY_SECONDS = 2;
/** The longest it remembers them: up to a thousand reads, each with the values it opened, sit in an isolate for as long. */
export const MAX_MEMORY_SECONDS = 600;

/** The vault as it runs: keys decoded, emails checked. */
export type ResolvedVaultConfig = {
  keks: KekRegistry;
  /**
   * Emails, lowercased: the Owners of the whole instance its deployment
   * names, made one at each start and at sign-in (`#declare` in vault.ts),
   * and never demoted or removed while named.
   */
  owners: readonly string[];
  /**
   * The seeds of the vault's own keys, which MAC its log entries, seal member
   * rows and sign checkpoints: the first signs; every one verifies what it
   * signed, so a rotation leaves earlier records verifying.
   */
  signingKeys: readonly Uint8Array[];
  bulkLimit: BulkLimit;
  memorySeconds: number;
  workloads: Workloads;
  /** How long the signer keeps a use, in days; null keeps every one. */
  keepUsesDays: number | null;
};

/**
 * A key-encryption key: 32 random bytes, base64, and the id envelopes record
 * it under; or one a key service holds, such as `awsKms({ keyArn, … })`.
 */
export type Kek = { id: string; key: string } | KekProvider;

/**
 * What a deployment writes: every key coffre has, and who owns the
 * instance whatever its database says. The app holds none of it.
 *
 *   {
 *     kek: awsKms({ keyArn: env.KMS_KEY_ARN, credentials: { … } }),
 *     previousKeks: [{ id: 'vault-2025-01-10-k7q2xm', key: env.OLD_VAULT_KEY }],
 *     owners: ['admin@acme.example'],
 *     signingKey: env.SIGNING_KEY, // required with a key service; derived from a local KEK otherwise
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
  /**
   * At most `count` distinct data keys unwrapped per principal in any `windowMinutes`; 1000 in 15 unless set. The
   * window is a day at most: the releases it counts are kept a day and an hour (`prune_vault_releases`).
   */
  bulkLimit?: { count: number; windowMinutes: number };
  /**
   * How long an instance remembers the rows a use read, and the values it
   * opened from them, in seconds: 2 unless set, 0 for never, ten minutes
   * at most. A revocation takes effect within it (docs/design/0.16.md, "The
   * vault's short memory").
   */
  memorySeconds?: number;
  /**
   * For a deployment with workloads, what the app's `workloads` says of
   * them, which the vault decides on: `noReads`, no binding lists values
   * its sessions are handed back; `useOnly`, a service account is a
   * key-bound session or nothing. Left out, the vault takes no workload's
   * session.
   */
  workloads?: { noReads?: boolean; useOnly?: boolean };
   * How long the log keeps a use, in days: 90 unless set, and `null` keeps
   * every one (docs/design/0.16.md, "How long the log is kept"). Changes are
   * kept for good.
   */
  log?: { keepUsesDays?: number | null };
  /**
   * Where the signer's alerts go: what it found in the database that the
   * vault did not write, or that it has stopped checking (docs/design/0.16.md,
   * "The signer"). `text` is ready to post:
   *
   *   alert: ({ text }) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text }) }).then(() => undefined)
   *
   * One that throws is called again with the same findings after the next
   * run. Without it, alerts go to the vault's own log.
   */
  alert?: (alert: SignerAlert) => void | Promise<void>;
  /**
   * @deprecated Gone in 0.10, and refused: each key says who sees it now. Mark
   * those no person may read sensitive (`coffre mark <env> sensitive`), and
   * give people read through their roles where they should see values.
   */
  people?: 'gone in 0.10: mark keys sensitive (coffre mark <env> sensitive), and let roles say who reads the rest';
} & Owners;

/**
 * At least one email, each an Owner of the whole instance: made one when
 * the vault starts, and when they sign in, whatever their row says, and
 * refused to anyone who would demote or remove them, themselves included.
 * The way into a fresh instance, and back into one whose Owners are all
 * locked out: add an email, deploy, sign in. Taking an email off makes
 * them an Owner like any other, whom an Owner may demote. `rootAdmins`, as
 * 0.5 named it, and `bootstrapOwners` are read until 0.7.
 */
type Owners =
  | { owners: readonly string[]; bootstrapOwners?: never; rootAdmins?: never }
  | {
      /** @deprecated `owners`, read until 0.7. */
      bootstrapOwners: readonly string[];
      owners?: never;
      rootAdmins?: never;
    }
  | {
      /** @deprecated 0.5's name for `owners`, read until 0.7: a root admin is an Owner now. */
      rootAdmins: readonly string[];
      owners?: never;
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

export { derivedSigningKey };

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
  if ('people' in config && config.people !== undefined) {
    throw new Error(
      `people is gone in 0.10 (it was ${JSON.stringify(config.people)}): each key says who sees it now. Remove people, mark the keys no person may read sensitive ` +
        '(coffre mark <env> sensitive, or coffre set <env>/<KEY> --sensitive), and let roles say who reads the rest (docs/design/credential-proxy.md)',
    );
  }
  const keks = [config.kek, ...(config.previousKeks ?? [])].map(kek);
  const [current, ...previous] = keks.map((entry) => entry.provider);
  const refs = [current, ...previous].map(({ provider, keyId }) => `${provider}:${keyId}`);
  const twice = refs.find((ref, i) => refs.indexOf(ref) !== i);
  if (twice !== undefined) throw new Error(`two vault keys share an id: ${twice}`);
  return {
    keks: new KekRegistry(current, previous),
    owners: checkOwners(config.owners ?? config.bootstrapOwners ?? config.rootAdmins ?? []),
    signingKeys: signingKeys(config.signingKey, keks),
    bulkLimit: config.bulkLimit === undefined ? DEFAULT_BULK_LIMIT : checkBulkLimit(config.bulkLimit),
    memorySeconds: checkMemory(config.memorySeconds ?? DEFAULT_MEMORY_SECONDS),
    workloads: config.workloads === undefined ? null : { noReads: config.workloads.noReads === true, useOnly: config.workloads.useOnly === true },
    keepUsesDays: checkKeepUsesDays(config.log?.keepUsesDays),
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


function checkKeepUsesDays(days: number | null | undefined): number | null {
  if (days === undefined) return 90;
  if (days !== null && !(Number.isFinite(days) && days > 0)) throw new Error(`log.keepUsesDays must be a number of days above 0, or null to keep every use; got ${String(days)}`);
  return days;
}

function checkBulkLimit({ count, windowMinutes }: { count: number; windowMinutes: number }): BulkLimit {
  if (!Number.isInteger(count) || count < 1 || !(windowMinutes > 0) || windowMinutes > MAX_BULK_WINDOW_MINUTES) {
    throw new Error(`bulkLimit needs a whole count of at least 1 and a window above 0 minutes, a day (${MAX_BULK_WINDOW_MINUTES}) at most`);
  }
  return { count, windowMs: windowMinutes * 60_000 };
}

function checkMemory(seconds: number): number {
  if (!(seconds >= 0 && seconds <= MAX_MEMORY_SECONDS)) throw new Error(`memorySeconds is 0 to ${MAX_MEMORY_SECONDS} seconds`);
  return seconds;
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
 * The Owners the deployment names, lowercased the way they are compared.
 * At least one, in every mode: they are the only way into a fresh
 * instance, and back into one whose Owners are locked out.
 */
export function checkOwners(emails: readonly string[]): string[] {
  const owners = [...new Set(emails.map((entry) => entry.trim()).filter((entry) => entry.length > 0))];
  if (owners.length === 0) {
    throw new Error('owners must name at least one email, or nobody can manage coffre');
  }
  const invalid = owners.find((entry) => !isHumanEmail(entry));
  if (invalid) {
    throw new Error(`owners must be human email identities; invalid: ${invalid}`);
  }
  return [...new Set(owners.map((entry) => entry.toLowerCase()))];
}

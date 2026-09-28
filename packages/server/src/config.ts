import type { Auth, AuthConfig } from '../../core/src/identity/auth-mode.ts';
import { publicOrigin } from '../../core/src/identity/signin/config.ts';
import type { Vault } from '../../vault/src/types.ts';
import type { SyncTiming } from './api/syncs.ts';

/**
 * What every deployment writes, on either runtime. The runtime adds where
 * the database is: `postgres(env.HYPERDRIVE)` on Workers, a URL on Node.
 */
export type CoffreConfig = {
  /** The origin people reach coffre at, e.g. `https://secrets.acme.example`. */
  publicUrl: string;
  /** Keys, grants and members: the vault Worker's binding, or a Node vault. */
  vault: Vault;
  /** `signin(…)`, `cloudflareAccess(…)`, or `devIdp(…)` locally. */
  auth: Auth;
  /**
   * 32 random bytes, base64: the key of the audit log's hash chain. It lives
   * outside the database, so whoever can write the database cannot rewrite
   * the log and fix up the chain.
   */
  auditChainKey: string;
  syncs?: SyncSettings;
};

/** When the scheduler runs syncs by itself. A change is pushed at once either way. */
export type SyncSettings = {
  /** How often an idle, healthy destination is checked for keys that went missing there. 60 unless set. */
  driftCheckMinutes?: number;
  /** How long a sync whose last run failed waits before the next try. 15 unless set. */
  retryAfterMinutes?: number;
};

export type ResolvedConfig = {
  publicUrl: string;
  auth: AuthConfig;
  auditChainKey: Buffer;
  syncs: SyncTiming;
};

function minutes(value: number | undefined, name: string, fallback: number): number {
  if (value === undefined) return fallback * 60_000;
  if (!Number.isFinite(value) || value < 1) throw new Error(`syncs.${name} must be at least 1`);
  return value * 60_000;
}

/** Check a deployment's configuration, failing on the first problem. */
export function resolveConfig(config: CoffreConfig): ResolvedConfig {
  const publicUrl = publicOrigin(config.publicUrl);
  const auditChainKey = Buffer.from(config.auditChainKey ?? '', 'base64');
  if (auditChainKey.length !== 32) {
    throw new Error(`auditChainKey must be 32 bytes, base64; got ${auditChainKey.length} bytes`);
  }
  if (config.vault === undefined || config.vault === null) throw new Error('vault is required');
  return {
    publicUrl,
    auth: config.auth.resolve(publicUrl),
    auditChainKey,
    syncs: {
      driftCheckMs: minutes(config.syncs?.driftCheckMinutes, 'driftCheckMinutes', 60),
      retryAfterMs: minutes(config.syncs?.retryAfterMinutes, 'retryAfterMinutes', 15),
    },
  };
}

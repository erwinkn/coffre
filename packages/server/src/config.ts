import { publicOrigin, type Auth, type AuthConfig } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';

import { checkPlugins, type CoffrePlugin } from './plugins.ts';

/**
 * What every deployment writes, on either runtime. The runtime adds where
 * the database is: `postgres(env.HYPERDRIVE)` on Workers, a URL on Node.
 */
export type CoffreConfig = {
  /** The origin people reach coffre at, e.g. `https://secrets.acme.example`. */
  publicUrl: string;
  /** Keys, grants and members: the vault Worker's binding, or a Node vault. */
  vault: Vault;
  /** `signin(…)`, or `cloudflareAccess(…)` behind Cloudflare Access. */
  auth: Auth;
  /**
   * 32 random bytes, base64: the key of the audit log's hash chain. It lives
   * outside the database, so whoever can write the database cannot rewrite
   * the log and fix up the chain.
   */
  auditChainKey: string;
  /**
   * Days a value may go unchanged before the web UI and `coffre list` flag
   * it for rotation: 365 if left out, `null` for no flag. A rename is no
   * change; a reference's value is its source's.
   */
  rotateAfterDays?: number | null;
  /**
   * What the deployment adds to coffre, each answering paths of its own as
   * whoever a request's credential names: `[vaultKv({ mount: 'secret' })]`
   * (docs/design/plugins.md). None if left out.
   */
  plugins?: readonly CoffrePlugin[];
};

export type ResolvedConfig = {
  publicUrl: string;
  auth: AuthConfig;
  auditChainKey: Buffer;
  rotateAfterDays: number | null;
  plugins: readonly CoffrePlugin[];
};

/** A year: what a value may go unchanged before it is flagged, unless the deployment says. */
const ROTATE_AFTER_DAYS = 365;

/** Check a deployment's configuration, failing on the first problem. */
export function resolveConfig(config: CoffreConfig): ResolvedConfig {
  const publicUrl = publicOrigin(config.publicUrl);
  const auditChainKey = Buffer.from(config.auditChainKey ?? '', 'base64');
  if (auditChainKey.length !== 32) {
    throw new Error(`auditChainKey must be 32 bytes, base64; got ${auditChainKey.length} bytes`);
  }
  if (config.vault === undefined || config.vault === null) throw new Error('vault is required');
  const rotateAfterDays = config.rotateAfterDays === undefined ? ROTATE_AFTER_DAYS : config.rotateAfterDays;
  if (rotateAfterDays !== null && !(Number.isSafeInteger(rotateAfterDays) && rotateAfterDays > 0)) {
    throw new Error(`rotateAfterDays must be a whole number of days, at least 1, or null for no flag; got ${String(rotateAfterDays)}`);
  }
  return {
    publicUrl,
    auth: config.auth.resolve(publicUrl),
    auditChainKey,
    rotateAfterDays,
    plugins: checkPlugins(config.plugins ?? []),
  };
}

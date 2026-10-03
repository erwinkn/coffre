import { publicOrigin, type Auth, type AuthConfig } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';

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
};

export type ResolvedConfig = {
  publicUrl: string;
  auth: AuthConfig;
  auditChainKey: Buffer;
};

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
  };
}

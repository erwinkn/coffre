import { resolveDeployment, type Deployment, type DeploymentOptions, type MovedSetting } from '@coffre/core/deployment';
import { publicOrigin, type Auth, type AuthConfig } from '@coffre/core/identity';
import type { VaultEntry } from '@coffre/core/vault';

import { checkPlugins, movedByPlugin, type CoffrePlugin } from './plugins.ts';

/**
 * What every deployment writes, on either runtime. The runtime adds where
 * the database is: `postgres(env.HYPERDRIVE)` on Workers, a URL on Node.
 */
export type CoffreConfig = {
  /** The origin people reach coffre at, e.g. `https://secrets.acme.example`. */
  publicUrl: string;
  /**
   * Keys, grants and members: the vault Worker's binding, or a Node vault
   * (`connectVault`, `localVault`). Its one entry, `call`, carries this
   * app's release on every call: a vault on another one, for the seconds of
   * a deploy, runs nothing, and the app answers 503 `deploying`.
   */
  vault: VaultEntry;
  /** `signin(…)`, or `cloudflareAccess(…)` behind Cloudflare Access. */
  auth: Auth;
  /**
   * 32 random bytes, base64: the key of the audit log's hash chain. It lives
   * outside the database, so whoever can write the database cannot rewrite
   * the log and fix up the chain.
   */
  auditChainKey: string;
  /**
   * The app keys `auditChainKey` replaced, in any order, each as it was
   * given: they verify the log's entries written before the app moved on
   * from them, and nothing else. The first start under a new key signs
   * every row that must survive again under it, signs everyone out, and
   * writes `key.rotate` (docs/deploy.md, "Rotating the app key"). One that
   * is `auditChainKey` itself, as before the new key is given, counts once.
   * None if left out.
   */
  previousAuditChainKeys?: readonly string[];
  /**
   * What the deployment chooses, its `deployment.ts`: `defineDeployment({…})`
   * from `@coffre/core/deployment`, the same object the vault is given. The
   * defaults if left out (docs/design/config.md).
   */
  deployment?: Deployment | DeploymentOptions;
  /** @deprecated In `deployment.ts` since 0.16, `values.rotateAfterDays`: read until 0.17, which refuses it here. */
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
  deployment: Deployment;
  auth: AuthConfig;
  auditChainKey: Buffer;
  previousAuditChainKeys: readonly Buffer[];
  rotateAfterDays: number | null;
  plugins: readonly CoffrePlugin[];
};

/** Check a deployment's configuration, failing on the first problem. */
export function resolveConfig(config: CoffreConfig): ResolvedConfig {
  const publicUrl = publicOrigin(config.publicUrl);
  const auditChainKey = appKey('auditChainKey', config.auditChainKey);
  const previous = config.previousAuditChainKeys ?? [];
  if (!Array.isArray(previous)) throw new Error('previousAuditChainKeys is a list of the app keys auditChainKey replaced');
  // Each key once: the current one, listed too while it is still the one in use, is the current one.
  const previousAuditChainKeys = previous
    .map((text, i) => appKey(`previousAuditChainKeys[${i}]`, text))
    .filter((key, i, keys) => !key.equals(auditChainKey) && keys.findIndex((other) => other.equals(key)) === i);
  if (config.vault === undefined || config.vault === null) throw new Error('vault is required');
  const plugins = checkPlugins(config.plugins ?? []);
  const moved: MovedSetting[] = [
    ...(config.rotateAfterDays === undefined ? [] : [{ old: 'createCoffre({ rotateAfterDays })', options: { values: { rotateAfterDays: config.rotateAfterDays } } }]),
    ...(config.auth.moved ?? []),
    ...plugins.flatMap(movedByPlugin),
  ];
  const deployment = resolveDeployment(config.deployment, moved);
  return {
    publicUrl,
    deployment,
    auth: config.auth.resolve(publicUrl, deployment),
    auditChainKey,
    previousAuditChainKeys,
    rotateAfterDays: deployment.values.rotateAfterDays,
    plugins,
  };
}

/** An app key as a deployment passes it: 32 bytes, base64. */
function appKey(name: string, text: string | undefined): Buffer {
  const key = Buffer.from(typeof text === 'string' ? text : '', 'base64');
  if (key.length !== 32) throw new Error(`${name} must be 32 bytes, base64; got ${key.length} bytes`);
  return key;
}

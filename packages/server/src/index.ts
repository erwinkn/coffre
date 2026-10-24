// What both runtimes share: the configuration's shape and its constructors.
// `@coffre/server/cloudflare` and `@coffre/server/node` re-export all of it.

export {
  cloudflareAccess,
  github,
  githubApp,
  google,
  microsoft,
  oidc,
  signin,
  SigninError,
  type Auth,
  type GitHubApp,
  type GitHubAppOptions,
  type PendingSignin,
  type RateLimiter,
  type WorkloadLimits,
  type WorkloadsOptions,
  type SigninBrand,
  type SigninErrorCode,
  type SigninOptions,
  type SigninProfile,
  type SigninProvider,
} from '@coffre/core/identity';
export type { Vault } from '@coffre/core/vault';
export { memoryAnchor, type AnchorStore, type AuditAnchor } from './anchor.ts';
export type { CoffreConfig } from './config.ts';
export type { CoffrePlugin, PluginContext } from './plugins.ts';

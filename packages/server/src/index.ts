// What both runtimes share: the configuration's shape and its constructors.
// `@coffre/server/cloudflare` and `@coffre/server/node` re-export all of it.

export {
  cloudflareAccess,
  github,
  google,
  microsoft,
  oidc,
  signin,
  SigninError,
  type Auth,
  type PendingSignin,
  type SigninBrand,
  type SigninErrorCode,
  type SigninOptions,
  type SigninProfile,
  type SigninProvider,
} from '@coffre/core/identity';
export type { Vault } from '@coffre/core/vault';
export type { CoffreConfig, SyncSettings } from './config.ts';
export {
  cloudflareWorkers,
  githubActions,
  railway,
  SyncConfigError,
  SyncProviderError,
  vercel,
  type SyncApplyResult,
  type SyncBrand,
  type SyncContext,
  type SyncField,
  type SyncPlan,
  type SyncProvider,
  type SyncProviderErrorCode,
  type SyncVariable,
} from './sync/index.ts';

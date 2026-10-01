// What both runtimes share: the configuration's shape and its constructors.
// `@coffre/server/cloudflare` and `@coffre/server/node` re-export all of it.

export {
  cloudflareAccess,
  devIdp,
  github,
  google,
  microsoft,
  oidc,
  signin,
  type Auth,
  type AuthMode,
  type SigninOptions,
  type SigninProviderConfig,
} from '@coffre/core/identity';
export type { Vault } from '@coffre/core/vault';
export type { CoffreConfig, SyncSettings } from './config.ts';

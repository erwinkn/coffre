// What both runtimes share: the configuration's shape and its constructors.
// `@coffre/server/cloudflare` and `@coffre/server/node` re-export all of it.

export {
  cloudflareAccess,
  devIdp,
  signin,
  type Auth,
  type AuthMode,
  type SigninOptions,
} from '../../core/src/identity/auth-mode.ts';
export { github, google, microsoft, oidc } from '../../core/src/identity/signin/config.ts';
export type { SigninProviderConfig } from '../../core/src/identity/signin/config.ts';
export type { CoffreConfig, SyncSettings } from './config.ts';
export type { Vault } from '../../vault/src/types.ts';

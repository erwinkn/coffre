import type { SigninProviderConfig } from './config.ts';
import { GitHubSigninProvider } from './github.ts';
import { OidcSigninProvider } from './oidc.ts';
import type { ProviderOptions, SigninProvider } from './types.ts';

export * from './config.ts';
export * from './types.ts';
export { deriveKey, seal, unseal } from './sealed.ts';

export function createSigninProvider(
  config: SigninProviderConfig,
  options: ProviderOptions = {},
): SigninProvider {
  return config.kind === 'github'
    ? new GitHubSigninProvider(config, options)
    : new OidcSigninProvider(config, options);
}

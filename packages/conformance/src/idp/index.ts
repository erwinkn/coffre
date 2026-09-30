// A stand-in for the identity providers coffre trusts: Cloudflare Access, an
// OpenID Connect provider and GitHub. The suite signs its personas in through
// it; the dev loop and the tests use it too.
export { DEFAULT_CLIENT, DevIdp, type DevIdpClient, type DevIdpOptions, type RegisteredClient } from './idp.ts';
export { PERSONAS, type GitHubAccount, type GitHubAccountPatch, type Persona } from './people.ts';

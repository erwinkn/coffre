/**
 * Standalone dev IdP.
 *
 * Stands in for Cloudflare Access locally. It is a different implementation of
 * the same interface the API already verifies against -- not a bypass. The API
 * runs identical verification code either way; only issuer, JWKS URL and
 * audience differ. It also serves an OpenID Connect provider and a fake GitHub
 * for coffre's own sign-in.
 */
import { DEFAULT_CLIENT, DevIdp } from './idp.ts';

if (process.env.COFFRE_AUTH_MODE !== 'dev') {
  throw new Error('dev-idp refuses to start unless COFFRE_AUTH_MODE=dev');
}

const idp = new DevIdp();
idp.listenPort = Number(process.env.COFFRE_DEV_IDP_PORT ?? 8081);
idp.defaultAudience = process.env.COFFRE_ACCESS_AUD ?? 'coffre-local-dev-aud';

await idp.start();

console.log(`dev-idp listening on   ${idp.origin}`);
console.log(`  issuer               ${idp.issuer}`);
console.log(`  jwks_uri             ${idp.jwksUrl}`);
console.log(`  audience             ${idp.defaultAudience}`);
console.log(`  mint a user token    ${idp.origin}/dev/mint?email=erwin@equisafe.io`);
console.log(`  mint a service token ${idp.origin}/dev/mint?common_name=ci-deploy.access`);
console.log(`OpenID Connect`);
console.log(`  discovery            ${idp.origin}/.well-known/openid-configuration`);
console.log(`  authorize            ${idp.origin}/oauth/authorize`);
console.log(`  token                ${idp.origin}/oauth/token`);
console.log(`  userinfo             ${idp.origin}/oauth/userinfo`);
console.log(`  client               ${DEFAULT_CLIENT.clientId} / ${DEFAULT_CLIENT.clientSecret} (any loopback redirect URI)`);
console.log(`Fake GitHub`);
console.log(`  web base URL         ${idp.origin}/github`);
console.log(`  api base URL         ${idp.origin}/github/api`);
console.log(`  authorize            ${idp.origin}/github/login/oauth/authorize`);
console.log(`  access token         ${idp.origin}/github/login/oauth/access_token`);
console.log(`  client               same as above`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void idp.stop().then(() => process.exit(0));
  });
}

/**
 * Standalone dev IdP, for `pnpm dev`: an OpenID Connect provider and a fake
 * GitHub for coffre's own sign-in, each with a persona page instead of a
 * password. It signs anyone in as anyone, so it listens on loopback only.
 */
import { DEFAULT_CLIENT, DevIdp } from '@coffre/conformance/idp';

const idp = new DevIdp();
idp.listenPort = Number(process.env.COFFRE_DEV_IDP_PORT ?? 8081);

await idp.start();

console.log(`dev-idp listening on   ${idp.origin}`);
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

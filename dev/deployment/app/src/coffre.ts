// coffre's configuration in `pnpm dev`: examples/workers' src/coffre.ts, with
// coffre's own sign-in page. The dev IdP stands in for GitHub and for an
// OpenID Connect provider, so both provider kinds run without a network.
//
// Every value is a local fixture; see wrangler.jsonc and .env.dev.
import { createCoffre, github, oidc, postgres, signin, type CoffreContext } from '@coffre/server/cloudflare';

import type { RateLimiter, Vault } from '@coffre/server/cloudflare';

export type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT: Vault;
  COFFRE_PUBLIC_URL: string;
  COFFRE_DEV_IDP_URL: string;
  COFFRE_APP_KEY: string;
  WORKLOADS_PER_SOURCE: RateLimiter;
  WORKLOADS_TOTAL: RateLimiter;
};

export const coffre = createCoffre((env: Env) => {
  const idp = env.COFFRE_DEV_IDP_URL;
  const local = { clientId: 'coffre-local', clientSecret: 'coffre-local-secret' };
  return {
    publicUrl: env.COFFRE_PUBLIC_URL,
    database: postgres(env.HYPERDRIVE),
    vault: env.VAULT,
    auth: signin({
      providers: [
        github({ ...local, webUrl: `${idp}/github`, apiUrl: `${idp}/github/api` }),
        oidc({ ...local, id: 'local', label: 'Dev IdP', issuer: idp }),
      ],
      note: 'Local development. Both buttons lead to the dev IdP.',
      // CI runs signing in as services; the dev IdP is plain HTTP on loopback.
      workloads: { limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL }, allowLoopbackIssuersForDevelopment: true },
    }),
    auditChainKey: env.COFFRE_APP_KEY,
  };
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

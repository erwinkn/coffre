// coffre's configuration in `pnpm dev`: examples/workers' src/coffre.ts, with
// coffre's own sign-in page. The dev IdP stands in for GitHub and for an
// OpenID Connect provider, so both provider kinds run without a network.
//
// Every value is a local fixture; see wrangler.jsonc and .env.dev.
import { createCoffre, github, githubApp, oidc, postgres, signin, type CoffreContext } from '@coffre/server/cloudflare';

import type { RateLimiter, Vault } from '@coffre/server/cloudflare';
import { vaultKv } from '@coffre/server/plugins/vault-kv';

export type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT: Vault;
  COFFRE_PUBLIC_URL: string;
  COFFRE_DEV_IDP_URL: string;
  COFFRE_APP_KEY: string;
  /** The dev IdP's GitHub App's private key, which dev/start.sh makes. */
  COFFRE_DEV_GITHUB_APP_KEY: string;
  WORKLOADS_PER_SOURCE: RateLimiter;
  WORKLOADS_TOTAL: RateLimiter;
  MCP_PER_SOURCE: RateLimiter;
  MCP_PER_CONNECTION: RateLimiter;
  MCP_TOTAL: RateLimiter;
};

export const coffre = createCoffre((env: Env) => {
  const idp = env.COFFRE_DEV_IDP_URL;
  const local = { clientId: 'coffre-local', clientSecret: 'coffre-local-secret' };
  // The dev IdP's GitHub App, installed on acme and octo-dev: one value, which signs people in through its own
  // client and lists those accounts' repositories (docs/github-app.md). Its client is a local fixture; its key
  // is the one dev/start.sh made.
  const app = githubApp({
    appId: '1001',
    privateKey: env.COFFRE_DEV_GITHUB_APP_KEY,
    clientId: 'Iv23li-coffre-dev',
    clientSecret: 'coffre-dev-app-secret',
    webUrl: `${idp}/github`,
    apiUrl: `${idp}/github/api`,
  });
  return {
    publicUrl: env.COFFRE_PUBLIC_URL,
    database: postgres(env.HYPERDRIVE),
    vault: env.VAULT,
    auth: signin({
      providers: [
        github({ app }),
        oidc({ ...local, id: 'local', label: 'Dev IdP', issuer: idp }),
      ],
      note: 'Local development. Both buttons lead to the dev IdP.',
      // CI runs signing in as services; the dev IdP is plain HTTP on loopback.
      workloads: {
        limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL },
        allowLoopbackIssuersForDevelopment: true,
        github: app,
      },
      // MCP clients at /mcp; a client's metadata document may be plain HTTP on loopback here.
      mcp: {
        limits: { perSource: env.MCP_PER_SOURCE, perConnection: env.MCP_PER_CONNECTION, total: env.MCP_TOTAL },
        allowLoopbackClientsForDevelopment: true,
      },
    }),
    auditChainKey: env.COFFRE_APP_KEY,
    // coffre as a Vault KV v2 mount, read only, at /v1 (routes/v1.$.ts): `VAULT_ADDR=http://127.0.0.1:3000
    // VAULT_TOKEN=<a service token> vault kv get secret/market/prod` (docs/design/plugins.md).
    plugins: [vaultKv()],
  };
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

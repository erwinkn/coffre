// coffre's configuration in `pnpm dev`: examples/workers' src/coffre.ts, with
// coffre's own sign-in page. The dev IdP stands in for GitHub and for an
// OpenID Connect provider, so both provider kinds run without a network.
//
// Every value is a local fixture; see wrangler.jsonc and .env.dev.
import { createCoffre, durableAnchor, github, githubApp, oidc, postgres, signin, type CoffreContext } from '@coffre/server/cloudflare';

import type { AnchorNamespace, GatesNamespace, RateLimiter, SocketsNamespace, Vault } from '@coffre/server/cloudflare';
import { credentialProxy, postgres as tunnel } from '@coffre/server/plugins/credential-proxy';
import { vaultKv } from '@coffre/server/plugins/vault-kv';
import { auditWatch } from '@coffre/server/plugins/audit-watch';

export type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT: Vault;
  COFFRE_PUBLIC_URL: string;
  /** The dev IdP on loopback, which this Worker calls. */
  COFFRE_DEV_IDP_URL: string;
  /** The dev IdP as a browser reaches it; the same unless a tunnel is in front (dev/start.sh). */
  COFFRE_DEV_IDP_PUBLIC_URL: string;
  COFFRE_APP_KEY: string;
  /** The dev IdP's GitHub App's private key, which dev/start.sh makes. */
  COFFRE_DEV_GITHUB_APP_KEY: string;
  WORKLOADS_PER_SOURCE: RateLimiter;
  WORKLOADS_TOTAL: RateLimiter;
  MCP_PER_SOURCE: RateLimiter;
  MCP_PER_CONNECTION: RateLimiter;
  MCP_TOTAL: RateLimiter;
  /** The Durable Object that hosts the tunnel's WebSockets, `CoffreSockets` (src/server.ts). */
  SOCKETS: SocketsNamespace;
  /** The Durable Object that holds each workload's gate, `CoffreGates` (src/server.ts). */
  GATES: GatesNamespace;
  /** The Durable Object that keeps the audit log's anchor, `CoffreAnchor` (src/server.ts). */
  ANCHOR: AnchorNamespace;
};

// Behind a tunnel, the dev IdP is known by its public URL, as its issuer and in
// every address it publishes, and that URL answers only a person's browser. So
// this Worker's own calls to it go to loopback instead.
let tunnelled = '';
function reachIdpOnLoopback(env: Env) {
  const pair = `${env.COFFRE_DEV_IDP_PUBLIC_URL} ${env.COFFRE_DEV_IDP_URL}`;
  if (tunnelled === pair || env.COFFRE_DEV_IDP_PUBLIC_URL === env.COFFRE_DEV_IDP_URL) return;
  tunnelled = pair;
  const publicOrigin = new URL(env.COFFRE_DEV_IDP_PUBLIC_URL).origin;
  const local = new URL(env.COFFRE_DEV_IDP_URL).origin;
  const upstream = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== publicOrigin) return upstream(input, init);
    const target = local + url.pathname + url.search;
    return upstream(input instanceof Request ? new Request(target, input) : target, init);
  };
}

export const coffre = createCoffre((env: Env) => {
  reachIdpOnLoopback(env);
  const idp = env.COFFRE_DEV_IDP_PUBLIC_URL;
  // Loopback issuers and MCP clients are for an instance on loopback; behind a tunnel, there are none.
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(env.COFFRE_PUBLIC_URL).hostname);
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
    // Only this Worker calls the API.
    apiUrl: `${env.COFFRE_DEV_IDP_URL}/github/api`,
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
        allowLoopbackIssuersForDevelopment: loopback,
        github: app,
      },
      // MCP clients at /mcp; a client's metadata document may be plain HTTP on loopback here.
      mcp: {
        limits: { perSource: env.MCP_PER_SOURCE, perConnection: env.MCP_PER_CONNECTION, total: env.MCP_TOTAL },
        allowLoopbackClientsForDevelopment: loopback,
      },
    }),
    auditChainKey: env.COFFRE_APP_KEY,
    // coffre as a Vault KV v2 mount, read only, at /v1 (routes/v1.$.ts): `VAULT_ADDR=http://127.0.0.1:3000
    // VAULT_TOKEN=<a service token> vault kv get secret/market/prod` (docs/design/plugins.md).
    // The credential proxy's database tunnel at /use (routes/use.$.ts), its WebSockets in the SOCKETS Durable Object:
    // `coffre run market/dev -- psql "$DATABASE_URL"`. Local databases are plain TCP on loopback, which only
    // insecureUpstreams reaches.
    plugins: [vaultKv(), credentialProxy({ credentials: {}, tunnels: { db: tunnel('DATABASE_URL') }, insecureUpstreams: true }), auditWatch({ anchor: durableAnchor(env.ANCHOR) })],
    sockets: env.SOCKETS,
    gates: env.GATES,
  };
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

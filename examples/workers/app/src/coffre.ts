// coffre's configuration, once, from the app Worker's env: read by
// src/server.ts, and so only on the server. The app reaches the database
// through Hyperdrive and the keys only through the vault Worker's service
// binding.
import { createCoffre, github, githubApp, postgres, signin, type CoffreContext, type GatesNamespace, type SocketsNamespace, type Vault } from '@coffre/server/cloudflare';

export type Env = {
  HYPERDRIVE: Hyperdrive;
  VAULT: Vault;
  PUBLIC_URL: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  /** Set for GitHub Enterprise Server; github.com otherwise. */
  GITHUB_URL?: string;
  GITHUB_API_URL?: string;
  APP_KEY: string;
  /** The GitHub App's ID, a var, and private key, a secret: with them, it lists your repositories too (docs/github-app.md). */
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  /** What every CI run's exchange passes first: app/wrangler.jsonc's rate-limiting bindings. */
  WORKLOADS_PER_SOURCE: RateLimit;
  WORKLOADS_TOTAL: RateLimit;
  /** Set by conformance only: a binding's issuer may then be plain HTTP on loopback. Refused unless PUBLIC_URL is loopback too. */
  ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT?: string;
  /** What MCP clients' OAuth requests pass first, and each connection's tool calls: the same file's bindings. */
  MCP_PER_SOURCE: RateLimit;
  MCP_PER_CONNECTION: RateLimit;
  MCP_TOTAL: RateLimit;
  /** The Durable Object that hosts plugins' WebSockets, `CoffreSockets` (src/server.ts): the credential proxy's database tunnel. */
  SOCKETS: SocketsNamespace;
  /** The Durable Object that holds each workload's gate, `CoffreGates` (src/server.ts). */
  GATES: GatesNamespace;
};

export const coffre = createCoffre((env: Env) => {
  const client = { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET, webUrl: env.GITHUB_URL, apiUrl: env.GITHUB_API_URL };
  // One GitHub App signs people in and, given its ID and private key, lists
  // your repositories where an owner trusts a workflow, private ones too
  // (docs/github-app.md). Without them, sign-in alone, and repositories typed.
  const app = env.GITHUB_APP_ID ? githubApp({ ...client, appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY ?? '' }) : undefined;
  return {
    publicUrl: env.PUBLIC_URL,
    database: postgres(env.HYPERDRIVE),
    vault: env.VAULT,
    auth: signin({
      providers: [app ? github({ app }) : github(client)],
      // CI runs and apps may sign in as services with their platform's proof,
      // through the trust bindings owners make (docs/design/oidc.md), into
      // key-bound sessions or, for now, bearer credentials; `useOnly: true`
      // leaves them key-bound sessions only (docs/design/workload-access.md,
      // section 6.3).
      workloads: {
        limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL },
        allowLoopbackIssuersForDevelopment: env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',
        github: app,
      },
      // MCP clients, Claude among them, may connect at <PUBLIC_URL>/mcp as the
      // people who approve them (docs/mcp.md). Remove this to turn it off.
      mcp: {
        limits: { perSource: env.MCP_PER_SOURCE, perConnection: env.MCP_PER_CONNECTION, total: env.MCP_TOTAL },
      },
    }),
    auditChainKey: env.APP_KEY,
    // Where plugins' WebSockets run, one object per `coffre run` and database: the
    // credential proxy's tunnel, once you add it (docs/design/credential-proxy.md).
    sockets: env.SOCKETS,
    // Each workload's gate: its sessions' proofs taken once, and its limits.
    gates: env.GATES,
  };
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

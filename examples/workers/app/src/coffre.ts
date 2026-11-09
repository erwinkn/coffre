// coffre's configuration, once, from the app Worker's env: read by
// src/server.ts, and so only on the server. The app reaches the database
// through Hyperdrive and the keys only through the vault Worker's service
// binding.
import { createCoffre, durableAnchor, github, githubApp, postgres, signin, type AnchorNamespace, type CoffreContext, type GatesNamespace, type PasskeyPolicy, type SocketsNamespace, type VaultEntry } from '@coffre/server/cloudflare';
import { auditWatch } from '@coffre/server/plugins/audit-watch';
import { credentialProxy } from '@coffre/server/plugins/credential-proxy';

import { deployment } from '../../deployment';

export type Env = {
  HYPERDRIVE: Hyperdrive;
  VAULT: VaultEntry;
  PUBLIC_URL: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  /** Set for GitHub Enterprise Server; github.com otherwise. */
  GITHUB_URL?: string;
  GITHUB_API_URL?: string;
  /** Only this GitHub organization's members sign in, when set: a var, which `coffre setup` asks for (docs/github-app.md). */
  GITHUB_ORGANIZATION?: string;
  APP_KEY: string;
  /** Who signs in with a passkey after GitHub: app/wrangler.jsonc's var (docs/deployment-auth.md, "Passkeys"). */
  PASSKEYS: PasskeyPolicy;
  /** The GitHub App's ID, a var, and private key, a secret: with them, it lists your repositories too (docs/github-app.md). */
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  /** What every sign-in that takes anyone passes first, a CI run's and an MCP client's: app/wrangler.jsonc's rate-limiting binding. */
  SIGN_IN_PER_SOURCE: RateLimit;
  /** Set by conformance only: a binding's issuer may then be plain HTTP on loopback. Refused unless PUBLIC_URL is loopback too. */
  ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT?: string;
  /** The Durable Object that hosts plugins' WebSockets, `CoffreSockets` (src/server.ts): the credential proxy's database tunnel. */
  SOCKETS: SocketsNamespace;
  /** The Durable Object that holds each workload's gate, `CoffreGates` (src/server.ts). */
  GATES: GatesNamespace;
  /** The Durable Object that keeps the audit watch's anchor, `CoffreAnchor` (src/server.ts). */
  ANCHOR: AnchorNamespace;
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
    // What this instance allows: ../../deployment.ts, which the vault reads too.
    deployment,
    auth: signin({
      // GITHUB_ORGANIZATION, when set, lets only its members sign in.
      providers: [github(app ? { app, organization: env.GITHUB_ORGANIZATION } : { ...client, organization: env.GITHUB_ORGANIZATION })],
      // A passkey after GitHub: `optional` asks it of whoever holds one, and
      // of every Owner; `required`, of everyone; `off`, of no one, the
      // recovery when the last Owner lost theirs (docs/deployment-auth.md).
      passkeys: env.PASSKEYS,
      // CI runs and apps may sign in as services with their platform's proof,
      // through the trust bindings owners make (docs/design/oidc.md), into
      // key-bound sessions or, for now, bearer credentials; deployment.ts's
      // `services.useOnly` leaves them key-bound sessions only
      // (docs/design/workload-access.md, section 6.3).
      workloads: {
        limits: { perSource: env.SIGN_IN_PER_SOURCE },
        allowLoopbackIssuersForDevelopment: env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',
        github: app,
      },
      // MCP clients, Claude among them, may connect at <PUBLIC_URL>/mcp as the
      // people who approve them (docs/mcp.md). Remove this to turn it off.
      mcp: {
        limits: { perSource: env.SIGN_IN_PER_SOURCE },
      },
    }),
    auditChainKey: env.APP_KEY,
    // The audit watch: every five minutes, the log walked from what it last
    // verified, which it keeps outside the database, in ANCHOR; /readyz red
    // on anything it finds. Remove it, and the log is checked only when
    // someone runs `coffre verify log` (docs/deploy.md, "The audit watch").
    // The credential proxy (docs/design/credential-proxy.md): apps run with
    // `coffre run` reach their APIs through <PUBLIC_URL>/use, with the keys
    // filled in, which they never hold. deployment.ts's `proxy.editable` lets
    // Owners write routes, signers, verifiers and databases per environment
    // in its Proxy tab; add your own to `credentials` (and `tunnels`,
    // `signers`, `verifiers`) to keep them in code, where they win the name
    // in every environment.
    plugins: [auditWatch({ anchor: durableAnchor(env.ANCHOR) }), credentialProxy({ credentials: {} })],
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

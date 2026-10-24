// coffre's configuration, once, from the server's environment (.env, which
// `pnpm start` reads): read by src/server.ts, and so only on the
// server. It holds no vault key: it asks the vault, a process of its own
// (src/vault.ts), over a Unix socket.
import { createCoffre, fileAnchor, github, githubApp, processLimits, signin, type CoffreContext } from '@coffre/server/node';
import { auditWatch } from '@coffre/server/plugins/audit-watch';
import { connectVault } from '@coffre/vault/node';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; see .env.example`);
  return value;
}

const client = {
  clientId: env('GITHUB_CLIENT_ID'),
  clientSecret: env('GITHUB_CLIENT_SECRET'),
  // Set for GitHub Enterprise Server; github.com otherwise.
  webUrl: process.env.GITHUB_URL,
  apiUrl: process.env.GITHUB_API_URL,
};
// One GitHub App signs people in and, given its ID and private key, lists
// your repositories where an owner trusts a workflow, private ones too
// (docs/github-app.md). Without them, sign-in alone, and repositories typed.
const app = process.env.GITHUB_APP_ID
  ? githubApp({ ...client, appId: process.env.GITHUB_APP_ID, privateKey: process.env.GITHUB_APP_PRIVATE_KEY ?? '' })
  : undefined;

export const coffre = createCoffre({
  publicUrl: env('PUBLIC_URL'),
  database: env('DATABASE_URL'),
  vault: connectVault(env('VAULT_SOCKET')),
  // For tests or local SQLite development only, the vault in this process:
  // vault: await localVault({ database: env('DATABASE_URL'), kek: …, owners: […] }),
  auth: signin({
    providers: [app ? github({ app }) : github(client)],
    // CI runs and apps may sign in as services with their platform's proof,
    // through the trust bindings owners make (docs/design/oidc.md), into
    // key-bound sessions or, for now, bearer credentials; `useOnly: true`
    // leaves them key-bound sessions only (docs/design/workload-access.md,
    // section 6.3). Each exchange passes
    // these limits first, and each session's requests its gate; both are
    // this process's, so run one.
    workloads: {
      limits: processLimits({ perSource: 30, total: 300 }),
      // Set by conformance only: a binding's issuer may then be plain HTTP on
      // loopback. Refused unless PUBLIC_URL is loopback too.
      allowLoopbackIssuersForDevelopment: process.env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',
      github: app,
    },
    // MCP clients, Claude among them, may connect at <PUBLIC_URL>/mcp as the
    // people who approve them (docs/mcp.md). Remove this to turn it off.
    mcp: { limits: processLimits({ perSource: 30, perConnection: 120, total: 300 }) },
  }),
  auditChainKey: env('APP_KEY'),
  // The audit watch: every five minutes, the log walked from what it last
  // verified, which it keeps outside the database, in a file. Put the file
  // on a volume that outlives the process: on a disk that goes with the
  // container, every restart walks the log whole again and alerts, and a
  // cut made while it was down goes unseen. More than one process wants a
  // store they share (docs/deploy.md, "The audit watch"). Remove it, and
  // the log is checked only when someone runs `coffre verify log`.
  plugins: [auditWatch({ anchor: fileAnchor(env('AUDIT_ANCHOR')) })],
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

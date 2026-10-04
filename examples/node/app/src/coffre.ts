// coffre's configuration, once, from the server's environment (server.env,
// which `pnpm start` reads): read by src/server.ts, and so only on the
// server. It holds no vault key: it asks the vault, a process of its own
// (src/vault.ts), over a Unix socket.
import { createCoffre, github, processLimits, signin, type CoffreContext } from '@coffre/server/node';
import { connectVault } from '@coffre/vault/node';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; see server.env.example`);
  return value;
}

export const coffre = createCoffre({
  publicUrl: env('PUBLIC_URL'),
  database: env('DATABASE_URL'),
  vault: connectVault(env('VAULT_SOCKET')),
  // For tests or local SQLite development only, the vault in this process:
  // vault: await localVault({ database: env('DATABASE_URL'), kek: …, rootAdmins: […] }),
  auth: signin({
    providers: [
      github({
        clientId: env('GITHUB_CLIENT_ID'),
        clientSecret: env('GITHUB_CLIENT_SECRET'),
        // Set for GitHub Enterprise Server; github.com otherwise.
        webUrl: process.env.GITHUB_URL,
        apiUrl: process.env.GITHUB_API_URL,
      }),
    ],
    // CI runs may sign in as services with their platform's ID token, through
    // the trust bindings owners make (docs/design/oidc.md). Each exchange
    // passes these first; they count in this process.
    workloads: {
      limits: processLimits({ perSource: 30, total: 300 }),
      // Set by conformance only: a binding's issuer may then be plain HTTP on
      // loopback. Refused unless PUBLIC_URL is loopback too.
      allowLoopbackIssuersForDevelopment: process.env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',
    },
  }),
  auditChainKey: env('APP_KEY'),
});

// What src/server.ts hands Start with each request, for Start's types.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: CoffreContext };
  }
}

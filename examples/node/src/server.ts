// coffre's server: the API, sign-in, pages and scheduled job, in one
// process. The pages are app/, a TanStack Start app built by Vite, with
// coffre's routes and middleware; this is coffre's configuration, which
// each of its requests is handed. It holds no vault key: it asks the vault,
// a process of its own (src/vault.ts), over a Unix socket. Settings come
// from server.env.
import { createCoffre, github, processLimits, serve, signin } from '@coffre/server/node';
import { connectVault } from '@coffre/vault/node';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; see server.env.example`);
  return value;
}

const coffre = createCoffre({
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

// app/, built by `vite build app`.
const server = await serve({ app: new URL('../app/dist/', import.meta.url), coffre, port: Number(env('PORT')) });
console.log(`coffre is listening on ${server.url}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => void server.close().then(() => process.exit(0)));
}

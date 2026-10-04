// coffre's server: the API, sign-in, pages and scheduled job, in one
// process. It holds no KEK: it asks the vault, a process of its own
// (src/vault.ts), over a Unix socket. Settings come from server.env.
import { github, serve, signin } from '@coffre/server/node';
import { connectVault } from '@coffre/vault/node';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; see server.env.example`);
  return value;
}

const server = await serve({
  port: Number(env('PORT')),
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
  }),
  auditChainKey: env('AUDIT_CHAIN_KEY'),
});
console.log(`coffre is listening on ${server.url}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => void server.close().then(() => process.exit(0)));
}

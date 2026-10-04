// The app Worker: coffre's API, sign-in, pages and scheduled job. It reaches
// the database through Hyperdrive and the keys only through the vault
// Worker's service binding.
import { coffre, github, postgres, signin, type Vault } from '@coffre/server/cloudflare';

type Env = {
  HYPERDRIVE: Hyperdrive;
  VAULT: Vault;
  PUBLIC_URL: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  /** Set for GitHub Enterprise Server; github.com otherwise. */
  GITHUB_URL?: string;
  GITHUB_API_URL?: string;
  AUDIT_CHAIN_KEY: string;
};

export default coffre((env: Env) => ({
  publicUrl: env.PUBLIC_URL,
  database: postgres(env.HYPERDRIVE),
  vault: env.VAULT,
  auth: signin({
    providers: [
      github({
        clientId: env.GITHUB_CLIENT_ID,
        clientSecret: env.GITHUB_CLIENT_SECRET,
        webUrl: env.GITHUB_URL,
        apiUrl: env.GITHUB_API_URL,
      }),
    ],
  }),
  auditChainKey: env.AUDIT_CHAIN_KEY,
}));

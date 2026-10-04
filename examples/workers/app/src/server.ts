// The app Worker: coffre's API, sign-in, pages and scheduled job. It reaches
// the database through Hyperdrive and the keys only through the vault
// Worker's service binding.
import pages from '@tanstack/react-start/server-entry';
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
  APP_KEY: string;
  /** What every CI run's exchange passes first: app/wrangler.jsonc's rate-limiting bindings. */
  WORKLOADS_PER_SOURCE: RateLimit;
  WORKLOADS_TOTAL: RateLimit;
  /** Set by conformance only: a binding's issuer may then be plain HTTP on loopback. Refused unless PUBLIC_URL is loopback too. */
  ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT?: string;
};

export default coffre((env: Env) => ({
  pages,
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
    // CI runs may sign in as services with their platform's ID token, through
    // the trust bindings owners make (docs/design/oidc.md).
    workloads: {
      limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL },
      allowLoopbackIssuersForDevelopment: env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',
    },
  }),
  auditChainKey: env.APP_KEY,
}));

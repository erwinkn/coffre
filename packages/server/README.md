# @coffre/server

coffre's API under `/api`, sign-in, syncs to other services, the audit log
and the scheduled job, on Cloudflare Workers or Node. A deployment
configures it in code:

```ts
import { coffre, github, postgres, signin } from '@coffre/server/cloudflare';

export default coffre((env) => ({
  publicUrl: env.PUBLIC_URL,
  database: postgres(env.HYPERDRIVE),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })] }),
  auditChainKey: env.AUDIT_CHAIN_KEY,
}));
```

On Node, `serve({ … })` from `@coffre/server/node`. `coffre-server migrate`
brings the database up to date. `npx @coffre/cli init --workers` or
`--node` writes a whole deployment.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its seven `@coffre/*` packages are
released together, at one version. MIT licensed.

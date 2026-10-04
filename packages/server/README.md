# @coffre/server

coffre's API under `/api`, sign-in, the audit log and the scheduled job, on
Cloudflare Workers or Node, in a deployment's own TanStack Start app. A
deployment configures it once, in code:

```ts
// app/src/coffre.ts
import { createCoffre, github, postgres, signin } from '@coffre/server/cloudflare';

export const coffre = createCoffre((env: Env) => ({
  publicUrl: env.PUBLIC_URL,
  database: postgres(env.HYPERDRIVE),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })] }),
  auditChainKey: env.APP_KEY,
}));
```

and mounts it: its server entry hands Start each request with
`coffre.request(env, ctx)` as its context, `coffreMiddleware`
(`@coffre/server/start`) secures every response, and
`coffreServerRoutes(root)` (`@coffre/server/routes`) puts `/api`, `/auth`,
`/livez` and `/readyz` in its route tree. On Node, `createCoffre({ … })`
and `serve({ app, coffre })` from `@coffre/server/node`. A deployment brings
the shared Postgres database up to date with its own CLI, `pnpm exec coffre
migrate`, as its owner, before it deploys; `coffre-server migrate` does the
same for local SQLite and tests. The server connects as `coffre_runtime`;
the vault connects to the same database as `coffre_vault_runtime`, with a
Hyperdrive config of its own on Workers. `npx @coffre/cli init --workers`
or `--node` writes a whole deployment.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.

# coffre on Cloudflare Workers

Two Workers, configured in code:

- `app/src/worker.ts`, the app: the API, sign-in, the pages and a Cron job
  every five minutes. It reaches Postgres through Hyperdrive, and the vault
  through a service binding.
- `vault/src/worker.ts`, the vault: the keys, and the members and grants,
  which it keeps in the same database through a login of its own. It has no
  URL of its own.

Settings that are not secret are `vars` in each `wrangler.jsonc`; secrets are
Worker secrets. Everything below runs from this directory.

## 1. Settings

- `app/wrangler.jsonc`: `PUBLIC_URL`, and `GITHUB_CLIENT_ID` from a GitHub
  OAuth app whose callback is `<PUBLIC_URL>/auth/callback/github`.
- `vault/wrangler.jsonc`: `ROOT_ADMINS`, the emails of the first people in.

## 2. The database

coffre wants a Postgres database with three logins: its owner, for
migrations; `coffre_runtime`, which the app runs as; and
`coffre_vault_runtime`, which the vault runs as. Create the two as plain
logins (`CREATE ROLE coffre_runtime LOGIN PASSWORD '…'`, and the same for
`coffre_vault_runtime`); the first migration grants each the rows it needs,
and nothing else. Only the vault's may write members and grants, and each
appends to the audit log only as itself.

```sh
pnpm install
pnpm migrate "postgres://owner:…@db.example.com:5432/coffre"
pnpm exec wrangler hyperdrive create coffre --caching-disabled \
  --connection-string="postgres://coffre_runtime:…@db.example.com:5432/coffre"
pnpm exec wrangler hyperdrive create coffre-vault --caching-disabled \
  --connection-string="postgres://coffre_vault_runtime:…@db.example.com:5432/coffre"
```

Keep `--caching-disabled`: Hyperdrive otherwise caches reads for up to a
minute, and a revoked token or a signed-out session could keep working that
long. `wrangler.jsonc` cannot set it, so for a config made another way,
check `caching` in `wrangler hyperdrive get <id>`.

Put the ids they print under `hyperdrive`, the first in
`app/wrangler.jsonc` and the second in `vault/wrangler.jsonc`. Run
`pnpm migrate` again after every upgrade of `@coffre/server`, before
deploying it.

## 3. Secrets

```sh
openssl rand -base64 32 | pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc
openssl rand -base64 32 | pnpm exec wrangler secret put SIGNING_KEY -c vault/wrangler.jsonc
openssl rand -base64 32 | pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep a copy of `KEK` somewhere safe and offline: without it, no secret stored
in coffre can be read again.

## 4. Deploy

```sh
pnpm run deploy
```

deploys the vault, then the app, which binds to it. Route the app to
`PUBLIC_URL` in the dashboard, or with `routes` in `app/wrangler.jsonc`, then
sign in there as a root admin, and from a terminal:

```sh
coffre login https://secrets.example.com
```

Everything coffre keeps is in the database: secrets, members, grants and
the audit log. Back it up as one, and restore it as one.

## Locally

`pnpm dev` runs both Workers with `wrangler dev`. Put local secrets in
`app/.dev.vars` and `vault/.dev.vars`, and point Hyperdrive at a local
database with `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`,
for the app's login, and
`CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE`, for the
vault's.
`pnpm typecheck` checks the configuration against coffre's types, and
`pnpm build` bundles both Workers without deploying them.

## Conformance

```sh
pnpm conformance \
  --postgres "postgres://owner:…@127.0.0.1:5432" \
  --runtime "postgres://coffre_runtime:…@127.0.0.1:5432" \
  --vault-runtime "postgres://coffre_vault_runtime:…@127.0.0.1:5432"
```

runs both Workers under `wrangler dev`, on a database of their own that it
creates on that Postgres and drops after, signs people in through a
stand-in GitHub, and checks what coffre must never do: show a value to
someone without access, act for another site with someone's cookie, keep a
removed member in, give a value it did not log. Run it after changing this
project, and before deploying the change.

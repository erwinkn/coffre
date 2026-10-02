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
- `vault/wrangler.jsonc`: `ROOT_ADMINS`, the emails of the first people in,
  and `KEK_ID`, which `coffre keys` gives you below.

## 2. The database

coffre wants a Postgres database with three logins: its owner, for
migrations; `coffre_runtime`, which the app runs as; and
`coffre_vault_runtime`, which the vault runs as. Create the two as plain
logins. As the database's administrator, connect with `psql` and run:

```sql
CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password coffre_runtime
\password coffre_vault_runtime
```

Each `\password` prompts for a different generated password. The owner
must be able to create and grant roles: the migration creates `coffre_app`
and `coffre_vault`, and grants each login its own group. Only the vault may
write members and grants, and each appends to the log only as itself.
URL-encode special characters in the passwords in these URLs:

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

## 3. Keys

```sh
coffre keys
```

Run it with the CLI you ran `coffre init` with, or as
`npx @coffre/cli keys`. It prints two keys and the KEK's id, once, and
keeps no copy. Save its output in your password manager, with the GitHub
client secret, before anything else. There is one key for each Worker, so
that the app, which faces the network, never holds what decrypts a value:

- `KEK`, the vault's, decrypts every value, and the vault derives from it the
  key it signs its records with. Lose it, and every value is lost.
- `AUDIT_CHAIN_KEY`, the app's, signs the app's log entries, sessions and
  tokens. Lose it, and everyone is signed out and the log stops verifying.

Put `KEK_ID` in `vault/wrangler.jsonc`, then set the secrets; each command
prompts for the saved value:

```sh
pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc
pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep older KEKs after a rotation, for good: what they wrapped still needs
them, and so does what the vault signed under them. With AWS KMS instead of
a key of your own, the vault also needs a `SIGNING_KEY`
([keys](https://github.com/erwinkn/coffre/blob/main/docs/keys.md#aws-kms)).

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

Point a monitor at `<PUBLIC_URL>/readyz`: it turns red when the audit log
stops taking writes or the vault stops checkpointing it.

Everything coffre keeps is in the database: secrets, members, grants and
the audit log. Back it up as one, keep the escrowed keys apart from it, and
follow the [restore runbook](https://github.com/erwinkn/coffre/blob/main/docs/restore.md) to bring it back.

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

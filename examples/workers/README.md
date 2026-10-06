# coffre on Cloudflare Workers

Two Workers, configured in code:

- `app/`, the app: the API, sign-in, the pages and a Cron job every five
  minutes. It is a TanStack Start app of its own, built by Vite
  (`app/vite.config.ts`). coffre is configured in `app/src/coffre.ts`;
  `app/src/server.ts`, the Worker, hands it each request; `app/src/start.ts`
  puts coffre's middleware in front of every response; and
  `app/src/routes/` holds its routes, the root and a file for each of
  coffre's pages, beside any of your own
  ([Your own routes](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#your-own-routes)).
  It reaches Postgres through Hyperdrive, and the vault through a service
  binding.
- `vault/src/worker.ts`, the vault: the keys, and the members and grants,
  which it keeps in the same database through a login of its own. It has no
  URL of its own.

Settings that are not secret are `vars` in each `wrangler.jsonc`; secrets are
Worker secrets. Everything below runs from this directory.

## 1. Settings

- `app/wrangler.jsonc`: `PUBLIC_URL`, and `GITHUB_CLIENT_ID` from a GitHub
  OAuth app whose callback is `<PUBLIC_URL>/auth/callback/github`.
- `vault/wrangler.jsonc`: `ROOT_ADMINS`, the emails of the first people in,
  and `VAULT_KEY_ID`, which `coffre setup` gives you below.

## 2. The database and keys

Make a Postgres database, then, from this directory:

```sh
pnpm exec coffre setup
```

That is the CLI this project pins, once `pnpm install` has run: it migrates
with the migrations of the `@coffre/server` beside it. It asks for the database
administrator's connection string at a hidden prompt. A script pipes it in;
never pass it as an argument. It
makes the two logins coffre runs as, `coffre_runtime` for the app and
`coffre_vault_runtime` for the vault, migrates the database, and checks that
each login holds only its rights.

Then it shows five values on a screen of their own, which leaves nothing
behind in your scrollback: the app key and the app's database URL, and the
vault ID, the vault key and the vault's database URL. Copy each into your
password manager with `c`, beside the GitHub client secret; `w` shows where
each one goes. Nothing keeps a copy. There is one key for each Worker, so
that the app, which faces the network, never holds what decrypts a value:

- `VAULT_KEY`, the vault key, decrypts every value, and the vault derives
  from it the key it signs its records with. Lose it, and every value is
  lost.
- `APP_KEY`, the app key, signs the app's log entries, sessions and tokens.
  Lose it, and everyone is signed out and the log stops verifying.
- `VAULT_KEY_ID`, the vault ID, names the vault key. It is not secret.

To do the same by hand, see
[deploy.md](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#appendix-the-database-by-hand).

On a terminal, setup then offers to do Cloudflare too: it signs you in, makes
the Hyperdrive configs and the GitHub App, fills in both `wrangler.jsonc`,
and deploys, with the keys as secrets. That is sections 1, 3 and 4 below,
and the database URLs then go straight to Hyperdrive, unshown
([deploy.md](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#setup-does-cloudflare-too)).

## 3. Hyperdrive and secrets

Run the two `wrangler hyperdrive create` commands from setup's screen: one
config per login, each `--caching-disabled`. Hyperdrive otherwise caches
reads for up to a minute, and a revoked token or a signed-out session could
keep working that long. `wrangler.jsonc` cannot set it, so for a config made
another way, check `caching` in `wrangler hyperdrive get <id>`.

Put the ids they print under `hyperdrive`, the first in
`app/wrangler.jsonc` and the second in `vault/wrangler.jsonc`, and
`VAULT_KEY_ID` in `vault/wrangler.jsonc`. Then set the secrets; each command
prompts for the saved value:

```sh
pnpm exec wrangler secret put VAULT_KEY -c vault/wrangler.jsonc
pnpm exec wrangler secret put APP_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep older vault keys after a rotation, for good: what they wrapped still
needs them, and so does what the vault signed under them before it. With AWS KMS
instead of a key of your own, the vault also needs a `SIGNING_KEY`
([keys](https://github.com/erwinkn/coffre/blob/main/docs/keys.md#aws-kms)).

## 4. Deploy

```sh
pnpm run deploy
```

deploys the vault, then builds the app with Vite and deploys what it
built, which binds to the vault. Wrangler uploads that build as it is
(`app/dist/server/wrangler.json`), without bundling it again. Route the app to
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

## Upgrading

Run `coffre update` here, then migrate and deploy. With Workers Builds,
commit and push: both Workers' builds start with `printenv
DATABASE_OWNER_URL | pnpm exec coffre migrate --yes`, the administrator's
URL being their secret build variable `DATABASE_OWNER_URL`. By hand, run
`pnpm exec coffre migrate`, then `pnpm run deploy`. Until the migration has
run, the new version answers 503, `migrating`
([upgrading](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#upgrading),
[Workers Builds](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#workers-builds)).

## Locally

`pnpm dev` runs both Workers under `vite dev`, the vault beside the app, and
reloads the app as you edit it. Put local secrets in `app/.dev.vars` and `vault/.dev.vars`, and point Hyperdrive at a local
database with `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`,
for the app's login, and
`CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE`, for the
vault's.
`pnpm typecheck` checks the configuration against coffre's types, and
`pnpm build` builds both Workers without deploying them.

The app's React, TanStack Router, Start, Query and Vite are this project's
own dependencies, pinned at the versions `@coffre/ui` is built with; its
build stops with what to change when one differs, and `coffre update` moves
them with coffre's packages.

## Conformance

```sh
pnpm conformance \
  --postgres "postgres://owner:…@127.0.0.1:5432" \
  --runtime "postgres://coffre_runtime:…@127.0.0.1:5432" \
  --vault-runtime "postgres://coffre_vault_runtime:…@127.0.0.1:5432"
```

builds the app, runs both Workers under `wrangler dev`, on a database of their own that it
creates on that Postgres and drops after, signs people in through a
stand-in GitHub, and checks what coffre must never do: show a value to
someone without access, act for another site with someone's cookie, keep a
removed member in, give a value it did not log. Run it after changing this
project, and before deploying the change.

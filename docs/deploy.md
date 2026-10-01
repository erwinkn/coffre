# Deploying coffre

A deployment is a small project that imports coffre's packages and configures
them in code. It runs an app and a vault, as two Workers or two Node
processes. Both use one Postgres database, each through its own login.

```sh
coffre init --workers acme-secrets   # two Workers, two Hyperdrive configs
coffre init --node acme-secrets      # two Node processes, one Unix socket
cd acme-secrets
pnpm install
```

These are [examples/workers](../examples/workers) and
[examples/node](../examples/node), with the project's name and the CLI's
package version. Until the packages are published, install from tarballs;
`pnpm test:consumer` exercises that path.

## The database, for either deployment

Provision a Postgres database, e.g. `coffre`, owned by a migration login.
The owner must be able to create roles and grant their membership as well
as create the schema. Runtime processes never get this login. On a managed
service, use its administrative connection for this setup and check that it
allows those operations.

Connect to that database as its administrator with `psql`:

```sh
psql "postgres://owner@db.example.com:5432/coffre?sslmode=require"
```

Create two plain logins. `\password` prompts for passwords without putting
them in SQL statements or shell history. Use different generated passwords
and keep them in your password manager. On PlanetScale Postgres, these logins
connect as `coffre_runtime.<branch id>` and `coffre_vault_runtime.<branch id>`;
use those names in the connection strings below.

```sql
CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password coffre_runtime
\password coffre_vault_runtime
\q
```

Then migrate as the owner. Read the URL from your password manager into
`DATABASE_URL`, including the password and the TLS settings your host requires:

```sh
pnpm migrate
```

`pnpm migrate` runs `coffre-server migrate`. It accepts the owner URL as an
argument too. URL-encode special characters in passwords. Run it again
after every package upgrade, before starting either component. Clear the
owner's `DATABASE_URL` from the shell afterwards (`unset DATABASE_URL`).

The migration creates two group roles and grants their membership:

| Login | Group | Rights |
|---|---|---|
| `coffre_runtime` | `coffre_app` | app data, sessions and syncs; app entries in the log; read-only access to members and grants |
| `coffre_vault_runtime` | `coffre_vault` | members and grants; read the secret context it decides on; vault entries in the log |

Neither login owns tables or may change or delete audit entries. Row-level
security permits each to append only as its own author. Do not run either
component as the owner or give the runtime logins additional roles.

## On Workers

```
acme-secrets/
  app/src/worker.ts      coffre(env => ({ publicUrl, database, vault, auth, auditChainKey }))
  app/wrangler.jsonc     HYPERDRIVE, VAULT service binding, Cron, UI assets
  vault/src/worker.ts    vault(env => ({ database, kek, rootAdmins, signingKey }))
  vault/wrangler.jsonc   VAULT_HYPERDRIVE; no public route
```

### 1. Settings

Set `PUBLIC_URL` and `GITHUB_CLIENT_ID` in `app/wrangler.jsonc`. The GitHub
OAuth app's callback is `<PUBLIC_URL>/auth/callback/github`. Set `KEK_ID`
and `ROOT_ADMINS` in `vault/wrangler.jsonc`. The latter names the first
people in, whom nobody can remove through the API.

For Cloudflare Access instead, replace `signin(…)` with `cloudflareAccess(…)`
([deployment-auth.md](deployment-auth.md)).

### 2. Two Hyperdrive configs

Create one config per runtime login, both pointing to the same database.
Substitute their passwords below, URL-encoded. Use the database's direct
Postgres endpoint (normally port 5432), rather than another connection pool.

```sh
pnpm exec wrangler hyperdrive create coffre --caching-disabled \
  --connection-string="postgres://coffre_runtime:…@db.example.com:5432/coffre"
pnpm exec wrangler hyperdrive create coffre-vault --caching-disabled \
  --connection-string="postgres://coffre_vault_runtime:…@db.example.com:5432/coffre"
```

Put the first id in `app/wrangler.jsonc`, under the `HYPERDRIVE` binding,
and the second in `vault/wrangler.jsonc`, under `VAULT_HYPERDRIVE`. The app's
`VAULT` service binding names the vault Worker. The vault has no public URL.

Keep `--caching-disabled` on **both** configs. A cached session or grant
could otherwise survive its revocation. `wrangler.jsonc` cannot set this:
check `caching` with `wrangler hyperdrive get <id>`. Fix an existing config
with `wrangler hyperdrive update <id> --caching-disabled`.

### 3. Keys and secrets

Generate three separate 32-byte keys with `openssl rand -base64 32`.
Save them in a password manager **before** uploading them. Escrow the KEK
with its `KEK_ID`, `SIGNING_KEY`, `AUDIT_CHAIN_KEY`, and the GitHub client
secret. Each command below prompts for the saved value:

```sh
pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc
pnpm exec wrangler secret put SIGNING_KEY -c vault/wrangler.jsonc
pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Only the vault gets the KEK and signing key; only the app gets the audit
key and OAuth secret. Without the KEK, stored values cannot be read.
Without the signing and audit keys, the existing log cannot be verified.
Keep old KEKs too: a new KEK does not rewrap existing data keys. Configure
older ones as `previousKeks`. For AWS KMS, see [keys.md](keys.md); recovery
needs access to every KMS key that still wraps stored data keys.

### 4. Deploy

`pnpm run deploy` deploys the vault, then the app. `pnpm build` bundles
both without deploying them. Route the app to `PUBLIC_URL`, sign in as a
root admin, then try the CLI:

```sh
coffre login https://secrets.example.com
```

## On Node

```
acme-secrets/
  src/server.ts          serve({ database, vault: connectVault(socket), … })
  src/vault.ts           serveVault({ socket, database, kek, rootAdmins, signingKey })
  server.env.example     app settings
  vault.env.example      vault settings
```

Use Node 24 or later. Set up the database above, then:

```sh
cp server.env.example server.env
cp vault.env.example vault.env
chmod 600 server.env vault.env
```

Fill in `PUBLIC_URL`, the GitHub OAuth settings, `ROOT_ADMINS` and the
three separately generated, escrowed keys. Set the two `DATABASE_URL`s to
one database, using different logins:

```dotenv
# server.env
DATABASE_URL=postgres://coffre_runtime:…@db.example.com:5432/coffre
# vault.env
DATABASE_URL=postgres://coffre_vault_runtime:…@db.example.com:5432/coffre
```

Include the TLS settings your database host requires. Run the processes as
two users sharing a group. Each env file belongs to its own process's user;
the app's user must not read `vault.env`. Set `VAULT_SOCKET` in both files
to the same absolute path in a directory they can access. The vault makes
the socket `0660`; its group must be the shared group.

```sh
pnpm vault    # first: creates the socket
pnpm start    # in the server's process
```

The server listens on `127.0.0.1:PORT`. Put a TLS-terminating proxy in front
of it and forward requests to that address. Its scheduled job runs in the
server process.

For tests and local development only, both URLs can name the same absolute
SQLite file (`file:/tmp/coffre-local.db`), migrated once with `pnpm migrate`
and that URL. SQLite has no per-login privileges. The deployed example
uses Postgres; Node conformance uses SQLite to exercise the local option.

## Backups, restores and monitoring

Back up the one database, and keep the escrowed keys apart from it: the
backup holds no key, and the keys hold no data. [restore.md](restore.md) is
the runbook, for PlanetScale Postgres and plain Postgres, with the checks to
run before reopening traffic.

Point an external monitor at `/readyz`, so that someone is paged when it
turns red: it does when the log stops taking writes, the vault stops
signing checkpoints, a checkpoint finds the log cut or rewritten, or the
vault finds its KEK wrong. `/livez` only says the process answers.

## Conformance

Before deploying a changed configuration, run its `pnpm conformance`.
Workers needs three local Postgres URLs: `--postgres` for the owner,
`--runtime` for the app and `--vault-runtime` for the vault. The harness
creates, migrates and drops its own database. Node uses a temporary SQLite
file shared by both processes. Both use test keys and a stand-in GitHub,
not your live credentials. [conformance.md](conformance.md) lists the checks
and the separate `probe` command for a live instance.

## Not configured by coffre

The environment variable names above belong to the examples. Packages take
typed configuration and read no deployment environment variables themselves.
The exceptions are the CLI's user settings and the `DATABASE_URL` fallback
for `coffre-server migrate` when no URL is given.

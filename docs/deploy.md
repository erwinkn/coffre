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
The migration login owns the database and has `CREATEROLE` and `CREATEDB`.
It does not need `SUPERUSER`. Use the same login to provision the runtime
roles and run migrations. Postgres 16 and later give a role creator
`ADMIN OPTION` on its new roles. If the group roles already exist, the
migration login needs `ADMIN OPTION` on them. Runtime processes never get
this login. On a managed service, use its administrative connection.

Connect to that database as its administrator with `psql`:

```sh
psql "postgres://owner@db.example.com:5432/coffre?sslmode=verify-full"
```

Create two plain logins. `\password` prompts for passwords without putting
them in SQL statements or shell history. Use different generated passwords
and keep them in your password manager. On PlanetScale Postgres, these logins
connect as `coffre_runtime.<branch id>` and `coffre_vault_runtime.<branch id>`;
use those names in the connection strings below.

```sql
CREATE ROLE coffre_runtime LOGIN INHERIT NOCREATEDB NOCREATEROLE;
CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOCREATEDB NOCREATEROLE;
\password coffre_runtime
\password coffre_vault_runtime
\q
```

New roles default to no superuser, replication or RLS-bypass rights. The
migration checks those rights and refuses unsafe roles. It hardens existing
groups without trying to alter their superuser-only attributes.

Then migrate as the owner. Read the URL from your password manager into
`DATABASE_URL`, including the password and the TLS settings your host requires:

```sh
pnpm migrate
```

`pnpm migrate` runs `coffre-server migrate`. It accepts the owner URL as an
argument too. URL-encode special characters in passwords. Run it again
after every package upgrade, before starting either component. Clear the
owner's `DATABASE_URL` from the shell afterwards (`unset DATABASE_URL`).

PlanetScale URLs include `sslrootcert=system`. The Node connections and
migrator use Node's default trusted CAs for that value. They require
`sslmode=verify-full`, or default to it when no mode is given. The connection
refuses an untrusted certificate or a hostname mismatch. Other
`sslrootcert` values remain certificate file paths.

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
  vault/src/worker.ts    vault(env => ({ database, kek, rootAdmins }))
  vault/wrangler.jsonc   VAULT_HYPERDRIVE; no public route
```

### 1. Settings

Set `PUBLIC_URL` and `GITHUB_CLIENT_ID` in `app/wrangler.jsonc`. The GitHub
OAuth app's callback is `<PUBLIC_URL>/auth/callback/github`. Set
`ROOT_ADMINS` in `vault/wrangler.jsonc`: the first people in, whom nobody can
remove through the API. `KEK_ID` comes with the keys, in step 3.

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

coffre needs two keys, one for each component, so that the app, which faces
the network, never holds what decrypts a value:

| Key | Held by | What it does | If it is lost |
|---|---|---|---|
| `KEK`, named by `KEK_ID` | the vault | decrypts every value; the vault also derives from it the key it signs its log entries, member rows and checkpoints with | every value is lost for good |
| `AUDIT_CHAIN_KEY` | the app | signs the app's log entries, sessions and tokens | everyone is signed out, and the log stops verifying |

The KEK matters most: with it and a copy of the database, anyone has every
value, so it never sits beside the backups. Make both, and the KEK's id, at
once:

```sh
coffre keys
```

It prints them once, as `NAME=value` lines, with a note on each, and keeps
no copy; it uploads nothing and writes no file. Save the output in your
password manager, with the GitHub client secret, **before** setting
anything. Then put `KEK_ID` under `vars` in `vault/wrangler.jsonc`, and set
the secrets; each command prompts for the saved value:

```sh
pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc
pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep old KEKs too: after a rotation, the old one stays in `previousKeks`,
and escrowed, for good. It still opens what it wrapped, and what the vault
signed under it verifies only while it is configured
([keys.md](keys.md#a-local-key)).

With AWS KMS instead of a key of your own, the vault never sees the KEK, so
it cannot derive its signing key from it, and needs a third key,
`SIGNING_KEY` ([keys.md](keys.md#aws-kms)).

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
  src/vault.ts           serveVault({ socket, database, kek, rootAdmins })
  server.env.example     app settings
  vault.env.example      vault settings
```

Use Node 24 or later. Set up the database above, then:

```sh
cp server.env.example server.env
cp vault.env.example vault.env
chmod 600 server.env vault.env
```

Fill in `PUBLIC_URL`, the GitHub OAuth settings and `ROOT_ADMINS`, and the
keys from `coffre keys`, saved in your password manager first
([step 3 above](#3-keys-and-secrets) says what each is for): `KEK_ID` and
`KEK` in `vault.env`, `AUDIT_CHAIN_KEY` in `server.env`. Set the
two `DATABASE_URL`s to one database, using different logins:

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

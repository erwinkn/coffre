# coffre on Node

Two processes, configured in code:

- `src/server.ts`, the server: the API, sign-in, the pages and a job every
  five minutes, on one port. Put a proxy that terminates TLS in front of it.
- `src/vault.ts`, the vault: the keys, and the members and grants, which it
  keeps in the server's database through a login of its own. It answers
  only the server, on a Unix socket.

Run them as two users that share a group, and the process facing the network
never holds the KEK. For local development, `server.ts` can run the vault
in its own process instead; see the comment there. Everything below runs
from this directory, on Node 24 or later.

## 1. Settings

```sh
pnpm install
cp server.env.example server.env
cp vault.env.example vault.env
```

Fill both in: `PUBLIC_URL`, a GitHub OAuth app whose callback is
`<PUBLIC_URL>/auth/callback/github`, `ROOT_ADMINS`, and the keys from

```sh
coffre keys
```

Run it with the CLI you ran `coffre init` with, or as
`npx @coffre/cli keys`. It prints two keys and the KEK's id, once, and
keeps no copy. Save its output in your password manager, with the OAuth
client secret, before anything else. `KEK_ID` and `KEK` go in `vault.env`,
and `AUDIT_CHAIN_KEY` in `server.env`: one key for each process, so that the
server, which faces the network, never holds what decrypts a value.

- `KEK`, the vault's, decrypts every value, and the vault derives from it the
  key it signs its records with. Lose it, and every value is lost.
- `AUDIT_CHAIN_KEY`, the server's, signs the server's log entries, sessions
  and tokens. Lose it, and everyone is signed out and the log stops
  verifying.

With AWS KMS instead of a key of your own, the vault also needs a
`SIGNING_KEY` ([keys](https://github.com/erwinkn/coffre/blob/main/docs/keys.md#aws-kms)).

## 2. The database

Use one Postgres database with three logins: its owner for migrations,
`coffre_runtime` for the server, and `coffre_vault_runtime` for the vault.
As an administrator, connect to the database with `psql` and create the
runtime logins. `\password` prompts for each password without putting it
in a SQL statement or shell history:

```sql
CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password coffre_runtime
\password coffre_vault_runtime
```

Migrate as the owner, who must also be able to create and grant roles:

```sh
pnpm migrate "postgres://owner:…@db.example.com:5432/coffre"
```

The migration creates the `coffre_app` and `coffre_vault` group roles and
grants each login only its group's rights. Only the vault writes members
and grants; each login appends to the audit log only as itself. Run the
migration again after every package upgrade, before starting either process.

Fill `DATABASE_URL` in each env file with the same host and database, using
`coffre_runtime` in `server.env` and `coffre_vault_runtime` in `vault.env`.
URL-encode special characters in passwords. Neither process gets the owner's
URL. Keep each env file readable only by its process's user (`chmod 600`).

For tests and local development only, both URLs may instead name the same
absolute SQLite file, e.g. `file:/tmp/coffre-local.db`; migrate that URL once.
SQLite has no database logins or separation of privileges.

## 3. Run

```sh
pnpm vault    # first: the server connects to its socket
pnpm start
```

Then sign in at `PUBLIC_URL` as a root admin, and from a terminal:

```sh
coffre login https://secrets.example.com
```

Point a monitor at `<PUBLIC_URL>/readyz`: it turns red when the audit log
stops taking writes or the vault stops checkpointing it.

Everything coffre keeps is in the database: secrets, members, grants and
the audit log. Back it up as one, keep the escrowed keys apart from it, and
follow the [restore runbook](https://github.com/erwinkn/coffre/blob/main/docs/restore.md) to bring it back.

`pnpm typecheck` checks the configuration against coffre's types.

## Conformance

`pnpm conformance` runs the vault and the server on SQLite in a temporary
directory, signs people in through a stand-in GitHub, and checks what coffre
must never do: show a value to someone without access, act for another site
with someone's cookie, keep a removed member in, give a value it did not
log. Run it after changing this project, and before deploying the change.

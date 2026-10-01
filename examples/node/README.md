# coffre on Node

Two processes, configured in code:

- `src/server.ts`, the server: the API, sign-in, the pages and a job every
  five minutes, on one port. Put a proxy that terminates TLS in front of it.
- `src/vault.ts`, the vault: the keys, and the members and grants, which it
  keeps in the server's database through a login of its own. It answers
  only the server, on a Unix socket.

Run them as two users that share a group, and the process facing the network
never holds a key. Where that matters less, `server.ts` can run the vault
in its own process instead; see the comment there. Everything below runs
from this directory, on Node 24 or later.

## 1. Settings

```sh
pnpm install
cp server.env.example server.env
cp vault.env.example vault.env
```

Fill both in: `PUBLIC_URL`, a GitHub OAuth app whose callback is
`<PUBLIC_URL>/auth/callback/github`, `ROOT_ADMINS`, and three keys from
`openssl rand -base64 32`. Keep a copy of `KEK` somewhere safe and offline:
without it, no secret stored in coffre can be read again.

## 2. The database

`DATABASE_URL` is a Postgres database for deployment. The example defaults
to a SQLite file for local development and tests. Bring the database up to
date now and after every upgrade of `@coffre/server`:

```sh
pnpm migrate file:coffre.db
```

On Postgres, migrate as the database's owner, after creating two plain
logins: `coffre_runtime` for the server and `coffre_vault_runtime` for the
vault (`CREATE ROLE coffre_runtime LOGIN PASSWORD '…'`, and the same for the
other). The first migration grants each the rows it needs, and nothing
else: only the vault's may write members and grants. `DATABASE_URL` names
the server's login in `server.env`, and the vault's in `vault.env`.

## 3. Run

```sh
pnpm vault    # first: the server connects to its socket
pnpm start
```

Then sign in at `PUBLIC_URL` as a root admin, and from a terminal:

```sh
coffre login https://secrets.example.com
```

Everything coffre keeps is in the database: secrets, members, grants and
the audit log. Back it up as one, and restore it as one.

`pnpm typecheck` checks the configuration against coffre's types.

## Conformance

`pnpm conformance` runs the vault and the server on SQLite in a temporary
directory, signs people in through a stand-in GitHub, and checks what coffre
must never do: show a value to someone without access, act for another site
with someone's cookie, keep a removed member in, give a value it did not
log. Run it after changing this project, and before deploying the change.

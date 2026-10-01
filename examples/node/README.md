# coffre on Node

Two processes, configured in code:

- `src/server.ts`, the server: the API, sign-in, the pages and a job every
  five minutes, on one port. Put a proxy that terminates TLS in front of it.
- `src/vault.ts`, the vault: the keys, grants and members, in a SQLite file
  of its own. It answers only the server, on a Unix socket.

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

`DATABASE_URL` is a SQLite file, or a Postgres or MySQL database. Bring it
up to date now and after every upgrade of `@coffre/server`:

```sh
pnpm migrate file:coffre.db
```

On Postgres, migrate as the database's owner, after creating a plain login
named `coffre_runtime` for the server (`CREATE ROLE coffre_runtime LOGIN
PASSWORD '…'`): the first migration grants it rows to read and write, and
nothing else. `DATABASE_URL` then names that login.

## 3. Run

```sh
pnpm vault    # first: the server connects to its socket
pnpm start
```

Then sign in at `PUBLIC_URL` as a root admin, and from a terminal:

```sh
coffre login https://secrets.example.com
```

Back up the database and `vault.db` together: the vault's grants and audit
checkpoints describe that database. Copy `vault.db` while the vault is
stopped, or with `sqlite3 vault.db ".backup vault-backup.db"` while it runs:
its newest writes wait in `vault.db-wal` until SQLite moves them over.

`pnpm typecheck` checks the configuration against coffre's types.

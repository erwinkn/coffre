# coffre on Node

Two processes, configured in code:

- `src/server.ts`, the server: the API, sign-in, the pages and a job every
  five minutes, on one port. Put a proxy that terminates TLS in front of it.
- `src/vault.ts`, the vault: the keys, and the members and grants, which it
  keeps in the server's database through a login of its own. It answers
  only the server, on a Unix socket.

Run them as two users that share a group, and the process facing the network
never holds the vault key. For local development, `server.ts` can run the vault
in its own process instead; see the comment there. Everything below runs
from this directory, on Node 24 or later.

## 1. Settings

```sh
pnpm install
cp server.env.example server.env
cp vault.env.example vault.env
chmod 600 server.env vault.env
```

Fill in `PUBLIC_URL`, a GitHub OAuth app whose callback is
`<PUBLIC_URL>/auth/callback/github`, and `ROOT_ADMINS`. Keep each env file
readable only by its process's user.

## 2. The database and keys

Make a Postgres database, then:

```sh
npx @coffre/cli setup
```

Run it with the CLI you ran `coffre init` with. It asks for the database
administrator's connection string at a hidden prompt. A script can pipe it
in, or set `COFFRE_SETUP_DATABASE_URL`; never pass it as an argument. It
makes the two logins coffre runs as, `coffre_runtime` for the server and
`coffre_vault_runtime` for the vault, migrates the database, and checks that
each login holds only its rights.

Then it shows five values on a screen of their own, which leaves nothing
behind in your scrollback. Copy each with `c` into your password manager,
beside the OAuth client secret, then into its file; `w` shows where each
goes. Nothing keeps a copy. There is one key for each process, so that the
server, which faces the network, never holds what decrypts a value.

- `server.env` takes the app key, `APP_KEY`, and the app's database URL, as
  `DATABASE_URL`. The app key signs the server's log entries, sessions and
  tokens. Lose it, and everyone is signed out and the log stops verifying.
- `vault.env` takes the vault ID, `VAULT_KEY_ID`, the vault key, `VAULT_KEY`,
  and the vault's database URL, as `DATABASE_URL`. The vault key decrypts
  every value, and the vault derives from it the key it signs its records
  with. Lose it, and every value is lost. The vault ID only names it.
- Both URLs are the same database, each through its process's own login.
  Neither process gets the administrator's URL.

With AWS KMS instead of a key of your own, the vault also needs a
`SIGNING_KEY` ([keys](https://github.com/erwinkn/coffre/blob/main/docs/keys.md#aws-kms)).
To do the same by hand, see
[deploy.md](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#appendix-the-database-by-hand).

To upgrade: `coffre update` here, restart both processes, then `coffre migrate`
([upgrading](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#upgrading)).
For automation, `pnpm migrate`, with the administrator's URL in
`DATABASE_URL`, does the last step.

For tests and local development only, both URLs may instead name the same
absolute SQLite file, e.g. `file:/tmp/coffre-local.db`; migrate that URL once
with `pnpm migrate`, and make the keys with `npx @coffre/cli keys`. SQLite
has no database logins or separation of privileges.

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

# Deploying coffre

A deployment is a small project of your own that imports coffre's packages
and configures them in code; [architecture.md](architecture.md) explains the
shape. `coffre init` writes one, and each comes with a README that walks
through the same steps as this page.

```sh
coffre init --workers acme-secrets   # two Workers, Postgres through Hyperdrive
coffre init --node acme-secrets      # two Node processes, on SQLite, Postgres or MySQL
```

What you get is [examples/workers](../examples/workers) or
[examples/node](../examples/node), file for file, with the project named
after its directory and coffre's packages pinned at the CLI's version. Until
the `@coffre` packages are on npm, copy an example and install them from
tarballs (`pnpm test:consumer` shows how).

## On Workers

```
acme-secrets/
  app/src/worker.ts      coffre(env => ({ publicUrl, database, vault, auth, auditChainKey }))
  app/wrangler.jsonc     Hyperdrive, the VAULT service binding, the Cron trigger, @coffre/ui's files
  vault/src/worker.ts    vault(env => ({ kek, rootAdmins, signingKey })), and its Durable Object
  vault/wrangler.jsonc   the Durable Object and its migration
  package.json           @coffre/server, @coffre/ui, @coffre/vault, wrangler; exact pins
  pnpm-workspace.yaml    tells pnpm 11 not to run esbuild's and workerd's install scripts
```

**1. Settings.** Values that are not secret are `vars` in each
`wrangler.jsonc`: `PUBLIC_URL` and `GITHUB_CLIENT_ID` for the app, from a
GitHub OAuth app whose callback is `<PUBLIC_URL>/auth/callback/github`;
`KEK_ID` and `ROOT_ADMINS` (the first people in) for the vault. The worker
files turn them into coffre's typed configuration, so a deployment behind
Cloudflare Access instead swaps `signin(…)` for `cloudflareAccess(…)`
([deployment-auth.md](deployment-auth.md)).

**2. The database.** A Postgres database with two logins: its owner, which
migrates, and `coffre_runtime`, which the app runs as. Create
`coffre_runtime` as a plain login; the first migration grants it rows to read
and write, and nothing else.

```sh
pnpm install
pnpm migrate "postgres://owner:…@db.example.com:5432/coffre"
pnpm exec wrangler hyperdrive create coffre \
  --connection-string="postgres://coffre_runtime:…@db.example.com:5432/coffre"
```

The id Hyperdrive prints goes in `app/wrangler.jsonc`. `pnpm migrate` is
`coffre-server migrate`, which ships with `@coffre/server` so the schema
always matches the server's version: run it after every upgrade, before
deploying.

**3. Secrets.** Each Worker declares the secrets it needs
(`secrets.required`), and gets no others:

```sh
openssl rand -base64 32 | pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc
openssl rand -base64 32 | pnpm exec wrangler secret put SIGNING_KEY -c vault/wrangler.jsonc
openssl rand -base64 32 | pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep a copy of `KEK` offline: without it, no stored secret can be read
again. To rotate it, add a new `kek` and move the old one to `previousKeks`
in `vault/src/worker.ts`; the vault unwraps with either and wraps with the
new one. To keep the KEK in AWS KMS instead, where it never leaves and
CloudTrail logs every use, see [keys.md](keys.md).

**4. Deploy.** `pnpm run deploy` deploys the vault, then the app, whose
`VAULT` binding names it. `pnpm build` is the same as a dry run. Route the
app to `PUBLIC_URL`, sign in there as a root admin, then:

```sh
coffre login https://secrets.example.com
```

**Backups.** The database holds ciphertext, the directory and the audit log;
the vault's Durable Object holds grants, members, unwrap counts, audit
checkpoints and its own log. Cloudflare can restore a Durable Object to any
point in the last 30 days (Point-in-Time Recovery), but keeps no copy
elsewhere, and nothing exports one yet. Restore the two to the same moment:
each log records the other's head at every checkpoint, so verification fails
while either is behind.

## On Node

```
acme-secrets/
  src/server.ts          serve({ port, publicUrl, database, vault: connectVault(socket), auth, auditChainKey })
  src/vault.ts           serveVault({ socket, store, kek, rootAdmins, signingKey })
  server.env.example     each process's settings, read with node --env-file
  vault.env.example
  package.json           @coffre/server, @coffre/vault; exact pins
```

```sh
pnpm install
cp server.env.example server.env && cp vault.env.example vault.env   # then fill them in
pnpm migrate file:coffre.db     # or postgres://…, mysql://…, as the owner
pnpm vault                      # first: the server connects to its socket
pnpm start
```

The server listens on `127.0.0.1:PORT`; put a proxy that terminates TLS in
front of it. The vault answers only on its Unix socket, made `0660`: run the
two as different users sharing a group, and the process facing the network
never holds a key. Where that matters less, `server.ts` can hold the vault
itself with `localVault(…)` (see the comment there). Back up the database
and the vault's store together.

## Not configured by coffre

coffre reads no environment variable of its own in a deployment. The names
above (`PUBLIC_URL`, `KEK`, …) are the examples', and yours to change. The
only ones coffre's code reads are the CLI's, for the person using it
(`COFFRE_API_URL`, `COFFRE_TOKEN`, the Access service-token pair,
`COFFRE_AUTH_MODE` for `coffre login`), and `DATABASE_URL` as a fallback for
`coffre-server migrate` when no URL is given.

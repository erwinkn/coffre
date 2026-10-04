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
package version. `coffre setup`, run in an empty directory, offers to make
one there too, and installs its packages. A clone of a new repository,
holding only `.git`, counts as empty, for both. Until the packages are published, install from tarballs;
`pnpm test:consumer` exercises that path.

## The database and its keys, for either deployment

Provision a Postgres database, e.g. `coffre`, and have its administrator's
connection string at hand: the login that owns it, with `CREATEROLE` and
`CREATEDB`, and not necessarily `SUPERUSER`. On a managed service, that is
its administrative connection, such as PlanetScale's default role. Give the
database's direct endpoint (normally port 5432), not a connection pool: the
logins' connection strings are made from it. Then, from the deployment's
directory:

```sh
npx @coffre/cli setup
```

Run it with the CLI you ran `coffre init` with: it migrates with the
migrations it was built with, which are those of the `@coffre/server` of the
same version. It asks for the connection string at a hidden prompt; a script
can pipe it in, or set `COFFRE_SETUP_DATABASE_URL`. It never takes it as an
argument, where the shell's history and other users could read it. Then:

1. It makes the two runtime logins, `coffre_runtime` for the app and
   `coffre_vault_runtime` for the vault, each with a fresh password that
   reaches the database only as a SCRAM verifier. On PlanetScale Postgres
   they log in as `coffre_runtime.<branch id>` and
   `coffre_vault_runtime.<branch id>`, the branch taken from the
   administrator's own login.
2. It migrates the database as the administrator, as `coffre migrate` does.
3. It connects as each login and checks the boundary, in transactions it
   rolls back: the app's login cannot write members, neither can delete log
   entries or create tables, and the vault's login can write members.
4. It shows five values on a screen of their own, the terminal's alternate
   screen, which leaves nothing in the scrollback. For the app, the app key
   and its database URL. For the vault, the vault ID, the vault key and its
   database URL. Each is masked until you reveal it with `r`, and `c` copies
   it; `w` shows where each goes, on Workers and on Node, with the commands
   to copy. When setup does Cloudflare too ([below](#setup-does-cloudflare-too)),
   the database URLs go straight to Hyperdrive, and the screen shows the
   three keys alone.

**Copy each value into your password manager before leaving the screen.**
They are shown once: coffre keeps no copy, and writes no file. A copy goes
through the system's clipboard, which setup clears again after 30 seconds,
or when you leave, if it still holds the value. Leaving asks first. The
main screen then shows only what was done, and the vault ID, which is not
secret.

Run again, setup changes nothing it need not. Logins that exist keep their
passwords, unless you agree to new ones at its prompt or pass
`--reset-passwords`. A migrated database stays as it is. Keys come only with
new passwords, and only for a database that holds no data yet; one that does
has its keys already. Without a terminal, setup refuses rather than print
the values; `--json` prints them to stdout for a script, with a warning on
stderr.

`coffre keys` makes the keys alone, on the same screen, for a rotation of
the vault key, or for a database set up by hand
([appendix](#appendix-the-database-by-hand)).

After every upgrade of coffre's packages, migrate the database, before
the deploy ([Upgrading](#upgrading)). The running components never migrate
it themselves.

PlanetScale URLs include `sslrootcert=system`. The Node connections and
migrator use Node's default trusted CAs for that value. They require
`sslmode=verify-full`, or default to it when no mode is given. The connection
refuses an untrusted certificate or a hostname mismatch. Other
`sslrootcert` values remain certificate file paths.

The migration creates two group roles and grants their membership:

| Login | Group | Rights |
|---|---|---|
| `coffre_runtime` | `coffre_app` | app data and sessions; app entries in the log; read-only access to members and grants |
| `coffre_vault_runtime` | `coffre_vault` | members and grants; read the secret context it decides on; vault entries in the log |

Neither login owns tables or may change or delete audit entries. Row-level
security permits each to append only as its own author. Do not run either
component as the owner or give the runtime logins additional roles.

## Upgrading

The database migrates before the deploy, in the deployment's own pipeline:
Workers Builds, CI, or a script before a restart. Every migration keeps the
previous release working, and every release runs on the schema before its
migrations ([expand, then contract](architecture.md#expand-then-contract)),
so either order works; migrating first means the new code never meets the
old schema.

1. **`coffre update`**, in the deployment's directory. It updates the CLI
   the way it was installed (an npm or pnpm global, as each lists its
   globals; npx needs nothing; when neither claims it, it says so and what
   each would run), moves
   the deployment's `@coffre/*` pins to the release and installs them, and
   ends with what the release asks of the database: "coffre 0.1.12 adds 1
   migration (0001_remove_syncs)". The deployment's `minimumReleaseAge`
   exempts `@coffre/*`, so a fix installs the day it is published; your
   other packages still wait a week. A deployment from before its CLI was one
   of its packages gains `@coffre/cli` among its devDependencies, pinned with
   the rest: its pipeline migrates with it.

   It moves the packages the app's Start app builds with to the versions
   the release's pages are built with, React, TanStack Start and Vite among
   them, showing each: they must be those exactly, and the app's build stops
   when one is not. A deployment from before 0.2 also becomes a Start app of
   its own ([Upgrading to 0.2](#upgrading-to-02)).

   It also pins the deployment's pnpm, `packageManager` in its package.json,
   to the one coffre installs with, as `coffre init` writes it: then your
   machine, CI and Workers Builds install with the same pnpm, and each holds
   `minimumReleaseAge` alike. Without it, Workers Builds picks a pnpm of its
   own, and a lockfile one pnpm wrote can fail another's check. Moving to
   another pnpm major makes pnpm rebuild `node_modules` from scratch, which
   `coffre update` lets it do without asking again.

   If pnpm holds a package back, as when a lockfile an older pnpm wrote has
   `pg-protocol@1.16.1`, a day old, `coffre update` first resolves the
   lockfile again: pnpm then picks the newest versions old enough, say
   `pg-protocol@1.16.0`, and nothing is let through. Any other package may
   move within its range too, so it lists every version that moved. Only
   when no version old enough fits does it say when each is old enough and
   offer two choices: wait, the deployment left as it was, or let those
   packages through by name, each until it is old enough, in
   `pnpm-workspace.yaml`. The first `coffre update` after that date removes
   them. With `--yes` it waits: it never lets a package through unasked.
   Whenever the install fails, it puts `package.json`, `pnpm-workspace.yaml`
   and `pnpm-lock.yaml` back as they were, and says so.
2. **Migrate, then deploy.** Commit and push: [Workers Builds](#workers-builds)
   does both. By hand, or in any other pipeline, in the deployment's
   directory:

   ```sh
   pnpm exec coffre migrate --yes   # COFFRE_MIGRATE_DATABASE_URL: the owner's URL
   pnpm run deploy                  # on Node: pnpm build, then restart both processes
   ```
3. **Check `/readyz`**, which passes once the new code's scheduled job has
   run on the new schema.

In a deployment's directory, `coffre migrate` migrates its database to the
schema of the version the deployment pins, with that version's own
migrations, which the deployment's CLI carries; `pnpm exec` runs that CLI.
It needs no session, and asks no instance: until the deploy, the instance
runs the previous version, by design. It stops unless:

- **the CLI is the version the deployment pins.** A global `coffre` of
  another version says to run `pnpm exec coffre migrate`, after `pnpm
  install`.
- **the database is not ahead of that version.** A database a newer coffre
  migrated, as after rolling a deployment back, is refused, each migration
  it does not know named by when it was made and its hash, and nothing is
  changed. Deploy that version, or restore the database from before it
  ([restore.md](restore.md)).

It reads the **database owner's direct Postgres URL** from
`COFFRE_MIGRATE_DATABASE_URL`, from stdin, or at a hidden prompt; never from
the command line, and never prints it. Use the login that owns the tables,
not `coffre_runtime` or `coffre_vault_runtime`, and not a Hyperdrive
connection. It shows what it will apply, and asks, on a terminal; without
one, it applies only with `--yes`. It applies it under the migration lock,
with the database's privileges reasserted, and writes plain lines to a CI
log: no colours, no spinner.

From a laptop, run it in the deployment's directory as well. Anywhere else,
`coffre migrate`, signed in as an owner or a root admin, works on an
instance instead: it asks the instance which version it runs and which of
that version's migrations its database lacks, stops unless the CLI is that
version, checks that the database lacks what the instance says it lacks, and
after applying, that the instance sees the new schema and `/readyz` passes.
`--url` picks an instance other than the current one.

Until the database is migrated, owners and root admins see "Database
migrations pending" above every page, and any CLI command they run against
the instance says so on stderr, once a day.

A script that asks for the URL itself:

```sh
read -rs -p 'Database owner URL: ' COFFRE_MIGRATE_DATABASE_URL
printf '\n'
export COFFRE_MIGRATE_DATABASE_URL
pnpm exec coffre migrate --yes
unset COFFRE_MIGRATE_DATABASE_URL
```

## On Workers

```
acme-secrets/
  app/src/coffre.ts      createCoffre(env => ({ publicUrl, database, vault, auth, auditChainKey }))
  app/src/server.ts      { fetch: Start's handler, coffre.request(env, ctx) its context; scheduled }
  app/src/start.ts       createStart(() => ({ requestMiddleware: [coffreMiddleware, createCsrfMiddleware(…)] }))
  app/src/router.tsx     the root, the document; coffre's server routes and pages under it
  app/vite.config.ts     cloudflare(…), tanstackStart(…), viteReact(), coffre()
  app/wrangler.jsonc     HYPERDRIVE, VAULT service binding, Cron
  vault/src/worker.ts    vault(env => ({ database, kek, rootAdmins }))
  vault/wrangler.jsonc   VAULT_HYPERDRIVE; no public route
```

The app is a TanStack Start app of its own, with coffre's routes and
middleware in it ([Your own routes](#your-own-routes), and
[the UI](architecture.md#the-ui)). `vite build app` builds it into
`app/dist`: the Worker and its `wrangler.json`, which `wrangler deploy -c
app/dist/server/wrangler.json` uploads as it is, and the pages' static files,
which become the Worker's assets. The vault is a plain Worker, which wrangler
builds itself. `pnpm dev` runs both under `vite dev`, the vault beside the
app.

### Workers Builds

Workers Builds builds and deploys both Workers on every push, the vault's
build migrating the database first. In each Worker's **Settings > Build**,
with the repository connected and the deployment's directory as the root:

| Worker | Build command | Deploy command | Build variables |
|---|---|---|---|
| the vault, `<name>-vault` | `pnpm exec coffre migrate --yes` | `npx wrangler deploy -c vault/wrangler.jsonc` | `COFFRE_MIGRATE_DATABASE_URL`, the database owner's direct URL, as a secret |
| the app, `<name>` | `pnpm exec vite build app` | `npx wrangler deploy -c app/dist/server/wrangler.json` | none |

The owner's URL is the one `coffre setup` asked for. It is a build variable,
which only the build sees; the Worker never does. A build that cannot
migrate fails before its deploy, and the vault keeps running the previous
version. The app may deploy before or after the vault's migration: each
release runs on the schema before and after its migrations.

### Upgrading to 0.2

Since 0.2 a deployment's app is a TanStack Start app of its own, built by
Vite, with coffre's routes and middleware in it, rather than a Worker or a
server that imports prebuilt pages. Move it with the 0.2 CLI, in the
deployment's directory:

```sh
npx @coffre/cli@0.2.0 update
```

It moves the files a release of 0.1 wrote, and only those. It recognises
each entry, `app/src/worker.ts` or `src/server.ts`, byte for byte, as one of
the versions 0.1 wrote, and writes its configuration in 0.2's shape as that
version had it: a deployment of 0.1.2 keeps its `AUDIT_CHAIN_KEY`, one of
0.1.15 gains no CI sign-in it did not have. It changes `app/wrangler.jsonc`'s
`main`, `assets` and `keep_names`, and `package.json`'s scripts, only from
the values 0.1 wrote. It shows each file it changes, line by line, and asks
once. It changes nothing, and names each file and what to do, when:

- the entry is not as 0.1 wrote it: its configuration is yours;
- a file 0.2 writes is already there, and is not what 0.2 writes there,
  such as a helper of yours at `app/src/server.ts`;
- `main`, `assets` or `keep_names` hold values of yours;
- a `dev`, `build` or `deploy` script is yours, even one that runs 0.1's:
  it would still build 0.1's app.

A `tsconfig.json` or `README.md` of yours stays as it is; it says what the
tsconfig then lacks. The entry changes last, so a move cut short is found
again, and finished, by the next run. An older CLI's `coffre update` moves
the pins but not the files, and the app then says, as it starts, to run
this one.

By hand, on Workers: `app/src/worker.ts` becomes `app/src/coffre.ts`, its
configuration unchanged but for its first and last lines, and Start's
server entry, `app/src/server.ts`, hands it to each request:

```diff
 // app/src/coffre.ts, was app/src/worker.ts
-import { coffre, github, postgres, signin, type Vault } from '@coffre/server/cloudflare';
+import { createCoffre, github, postgres, signin, type CoffreContext, type Vault } from '@coffre/server/cloudflare';

-type Env = {
+export type Env = {
   …
 };

-export default coffre((env: Env) => ({
+export const coffre = createCoffre((env: Env) => ({
   …
 }));
+
+// What src/server.ts hands Start with each request, for Start's types.
+declare module '@tanstack/react-router' {
+  interface Register {
+    server: { requestContext: CoffreContext };
+  }
+}
```

```diff
 // app/wrangler.jsonc
-  "main": "src/worker.ts",
+  "main": "src/server.ts",
-  "keep_names": false,
-  "assets": { "directory": "../node_modules/@coffre/ui/dist/client" }
```

```diff
 // package.json
-    "dev": "wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc",
+    "dev": "vite dev app",
-    "build": "wrangler deploy --dry-run -c vault/wrangler.jsonc && wrangler deploy --dry-run -c app/wrangler.jsonc",
+    "build": "wrangler deploy --dry-run -c vault/wrangler.jsonc && vite build app && wrangler deploy --dry-run -c app/dist/server/wrangler.json",
-    "deploy": "wrangler deploy -c vault/wrangler.jsonc && wrangler deploy -c app/wrangler.jsonc",
+    "deploy": "wrangler deploy -c vault/wrangler.jsonc && vite build app && wrangler deploy -c app/dist/server/wrangler.json",
```

Then copy [`app/src/server.ts`](../examples/workers/app/src/server.ts),
[`app/src/start.ts`](../examples/workers/app/src/start.ts),
[`app/src/router.tsx`](../examples/workers/app/src/router.tsx) and
[`app/vite.config.ts`](../examples/workers/app/vite.config.ts) from the
release's `coffre init --workers`; add `"jsx": "react-jsx"` to
`tsconfig.json`'s `compilerOptions`, and `dist` to `.gitignore`; and add
the dependencies the release's [package.json](../examples/workers/package.json)
has that yours lacks, React, TanStack Router, Start, Query, Vite and their
plugins, at exactly its versions.

By hand, on Node: `src/server.ts` configures coffre, then serves the app
with it:

```diff
 // src/server.ts
-import { github, processLimits, serve, signin } from '@coffre/server/node';
+import { createCoffre, github, processLimits, serve, signin } from '@coffre/server/node';
 …
-const server = await serve({
-  port: Number(env('PORT')),
+const coffre = createCoffre({
   publicUrl: env('PUBLIC_URL'),
   …
   auditChainKey: env('APP_KEY'),
 });
+
+// app/, built by `vite build app`.
+const server = await serve({ app: new URL('../app/dist/', import.meta.url), coffre, port: Number(env('PORT')) });
 console.log(`coffre is listening on ${server.url}`);
```

Then copy [`app/`](../examples/node/app/src/router.tsx) from the release's
`coffre init --node` (`app/vite.config.ts`, `app/src/start.ts` and
`app/src/router.tsx`); add `"build": "vite build app"` to `package.json`'s
scripts, and the dependencies its [package.json](../examples/node/package.json)
has that yours lacks, at exactly its versions; add `"jsx": "react-jsx"` to
`tsconfig.json`'s `compilerOptions` and `"app/src"` to its `include`, and
`dist` to `.gitignore`.

Then `pnpm typecheck`, and deploy: on Workers, set the app's build and
deploy commands as [Workers Builds](#workers-builds) says, or `pnpm run
deploy`; on Node, `pnpm build` and restart both processes.

### Upgrading to 0.1.12

Deploy the new code first, then migrate: `0001_remove_syncs`, from before
[expand, then contract](architecture.md#expand-then-contract), drops tables
0.1.11 still reads, so a pipeline that migrates first would break the
running 0.1.11. Version 0.1.12 works with both `0000` and
`0001_remove_syncs`: it ignores the old sync tables and refuses legacy sync
principals. `/readyz` accepts either schema prefix, subject to its usual
audit heartbeat and checkpoint checks. A database with no baseline still
fails readiness. Upgrade from 0.1.11 to 0.1.12 first, before setting the
vault's build command.

1. [Check for syncs](../CHANGELOG.md), including archived destinations, and
   move each destination into your deploy pipeline. Back up the database.
2. In the deployment's directory, run `coffre update`: it moves the
   deployment's coffre packages to 0.1.12 and installs them. Deploy the
   vault, then the app; the example's `pnpm deploy` does both in this
   order. With Workers Builds, wait until both deployments finish and the
   old versions have stopped receiving requests and scheduled events before
   dropping their tables.
3. Run `pnpm exec coffre migrate`, with the **database owner's direct
   Postgres URL** and its existing TLS parameters ([Upgrading](#upgrading)). If either sync table still has rows, it refuses
   without changing the schema: "syncs are removed: migrate destinations to
   service tokens, back up and clear syncs and sync_keys before upgrading".
   After moving the destinations and stopping old versions, have the owner
   clear `sync_keys`, then `syncs`, as described in the release notes, and
   run it again.
4. Check `/readyz` and verify the audit log. Past sync entries still verify
   and render on the audit page. After `0001` drops the tables, rolling back
   to code that still uses syncs requires restoring the pre-upgrade database.

### Setup does Cloudflare too

On a terminal, in a Workers deployment, `coffre setup` offers to do the rest
of this section itself. Say yes, and it:

1. signs in to Cloudflare through wrangler's browser login, and asks which
   account when there are several;
2. asks coffre's address, under one of the account's domains, and the root
   admins;
3. after the database steps, makes a Hyperdrive config for each login, with
   caching off, the password going only in the request to Cloudflare's API;
4. makes the GitHub App people sign in with, from a manifest: GitHub's page
   opens filled in, and the app's name, `coffre-` and the address, is yours
   to change there;
5. fills in both `wrangler.jsonc`: the account, the Hyperdrive ids, the
   address as a custom domain, GitHub's client ID, the root admins and the
   vault ID;
6. shows the keys on their screen, then deploys the vault and the app with
   them as secrets, on wrangler's stdin, and waits for the address to
   answer.

The database URLs are never shown: Hyperdrive has them, and nothing else
does. Nothing is written but the two `wrangler.jsonc`.

**On a machine your browser is not on**, such as a server over SSH, each
browser step ends at a localhost address the browser cannot reach. Paste
that address at setup's prompt, and setup finishes the step itself, on its
own machine. It only ever requests a pasted address on localhost. For
GitHub, open the `data:` address setup prints in that browser instead of
its local page. With no browser at all, set `CLOUDFLARE_API_TOKEN` to a
token that may edit Workers and Hyperdrive and read the account's zones.

**One account, several deployments.** A Worker or a Hyperdrive config is
this deployment's only when this directory says so: the Worker binds a
Hyperdrive config whose id is in this directory's `wrangler.jsonc`, or, the
vault, the vault ID setup wrote there; a config found by name points at
this run's database, the same host and database. Setup never deploys over
another deployment's Worker, nor touches its config. When one already holds
this deployment's names, setup says which, and asks for a name of its own,
offering `coffre-` and the address's first label: `coffre-secrets` for
`secrets.example.com`, and `coffre-try` for `coffre-try.example.com`. Both Workers, `<name>` and `<name>-vault`, both
Hyperdrive configs and the app's binding to its vault take it, and both
`wrangler.jsonc` record it.

**Run again**, setup finds what it made and keeps it: the Hyperdrive configs,
by the ids in `wrangler.jsonc`, or by the Workers' names on this run's
database; the GitHub App, by its client ID and the app Worker's secret;
each Worker's key. It never makes a key for a Worker that has one, and when
a Worker lacks its key but the database holds data, it stops before
changing anything. A run that failed partway carries on from where it
stopped. Keys shown by a run whose deploy failed never reached Cloudflare:
the next run makes new ones, and its screen says they replace them.

Native Windows keeps the steps below, since wrangler cannot read secrets
from `/dev/stdin` there; WSL works. So does saying no, for a deployment
you would rather set up by hand.

### 1. Settings

Set `PUBLIC_URL` and `GITHUB_CLIENT_ID` in `app/wrangler.jsonc`. The GitHub
OAuth app's callback is `<PUBLIC_URL>/auth/callback/github`. Set
`ROOT_ADMINS` in `vault/wrangler.jsonc`: the first people in, whom nobody can
remove through the API. `VAULT_KEY_ID` comes with the keys, in step 3.

For Cloudflare Access instead, replace `signin(…)` with `cloudflareAccess(…)`
([deployment-auth.md](deployment-auth.md)).

### 2. Two Hyperdrive configs

One config per runtime login, both pointing to the same database. Each
command reads its login's database URL at a silent prompt, so that the
password stays out of your shell's history: run it, paste the URL from
`coffre setup`'s screen, then press Enter. `coffre setup` shows both
commands, ready to copy.

```sh
read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive create coffre --caching-disabled --connection-string="${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL
read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive create coffre-vault --caching-disabled --connection-string="${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL
```

The first takes the app's database URL, the second the vault's. They drop
the URL's TLS parameters: Hyperdrive always connects over TLS, and checks
the certificate against public CAs. The Cloudflare dashboard's Hyperdrive
page makes the same configs, without a shell.

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
| The vault key, `VAULT_KEY`, named by the vault ID, `VAULT_KEY_ID` | the vault | decrypts every value; the vault also derives from it the key it signs its log entries, member rows and checkpoints with | every value is lost for good |
| The app key, `APP_KEY` | the app | signs the app's log entries, sessions and tokens | everyone is signed out, and the log stops verifying |

The vault key matters most: with it and a copy of the database, anyone has
every value, so it never sits beside the backups. `coffre setup` made both,
and the vault ID, and you saved them with the GitHub client secret. Put
`VAULT_KEY_ID` under `vars` in `vault/wrangler.jsonc`, and set the secrets;
each command prompts for the saved value:

```sh
pnpm exec wrangler secret put VAULT_KEY -c vault/wrangler.jsonc
pnpm exec wrangler secret put APP_KEY -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
```

Keep old vault keys too: after a rotation, the old one stays in `previousKeks`,
and escrowed, for good. It still opens what it wrapped, and what the vault
signed under it before the rotation verifies only while it is configured;
it vouches for nothing after ([keys.md](keys.md#a-local-key)).

With AWS KMS instead of a key of your own, the vault never sees its key, so
it cannot derive its signing key from it, and needs a third key,
`SIGNING_KEY` ([keys.md](keys.md#aws-kms)).

### 4. Deploy

`pnpm run deploy` deploys the vault, then builds the app with Vite and
deploys what it built. `pnpm build` builds both without deploying them. Route the app to `PUBLIC_URL`, sign in as a
root admin, then try the CLI:

```sh
coffre login https://secrets.example.com
```

## On Node

```
acme-secrets/
  src/server.ts          createCoffre({ database, vault: connectVault(socket), … }); serve({ app: app/dist, coffre })
  src/vault.ts           serveVault({ socket, database, kek, rootAdmins })
  app/src/start.ts       createStart(() => ({ requestMiddleware: [coffreMiddleware, createCsrfMiddleware(…)] }))
  app/src/router.tsx     the root, the document; coffre's server routes and pages under it
  app/vite.config.ts     tanstackStart(…), viteReact(), coffre()
  server.env.example     app settings
  vault.env.example      vault settings
```

The app, `app/`, is a TanStack Start app, as on Workers, which `pnpm build`
builds; `serve` runs what it built, each request carrying coffre.

Use Node 24 or later. Run `coffre setup` as above, then:

```sh
cp server.env.example server.env
cp vault.env.example vault.env
chmod 600 server.env vault.env
```

Fill in `PUBLIC_URL`, the GitHub OAuth settings and `ROOT_ADMINS`, then
the values from `coffre setup`'s screen ([step 3 above](#3-keys-and-secrets)
says what each key is for). `server.env` takes the app key, `APP_KEY`, and
the app's database URL, as `DATABASE_URL`. `vault.env` takes the vault ID,
`VAULT_KEY_ID`, the vault key, `VAULT_KEY`, and the vault's database URL.
Both URLs name one database, through different logins, with the TLS
settings the administrator's connection string had:

```dotenv
# server.env
DATABASE_URL=postgresql://coffre_runtime:…@db.example.com:5432/coffre?sslmode=verify-full
# vault.env
DATABASE_URL=postgresql://coffre_vault_runtime:…@db.example.com:5432/coffre?sslmode=verify-full
```

Run the processes as
two users sharing a group. Each env file belongs to its own process's user;
the app's user must not read `vault.env`. Set `VAULT_SOCKET` in both files
to the same absolute path in a directory they can access. The vault makes
the socket `0660`; its group must be the shared group.

```sh
pnpm build    # the pages, with Vite, into app/dist
pnpm vault    # first: creates the socket
pnpm start    # in the server's process
```

The server listens on `127.0.0.1:PORT`. Put a TLS-terminating proxy in front
of it and forward requests to that address. Its scheduled job runs in the
server process.

For tests and local development only, both URLs can name the same absolute
SQLite file (`file:/tmp/coffre-local.db`), migrated once with `pnpm exec
coffre-server migrate file:/tmp/coffre-local.db`. SQLite has no per-login privileges. The deployed example
uses Postgres; Node conformance uses SQLite to exercise the local option.

## Your own routes

The app's routes are its `app/src/router.tsx`, the same on Workers and on
Node. Its root is the app's: the document, `<html>` to `<body>`, with
coffre's entries in its head and `<CoffreProvider>`, which coffre's pages
need around them, in its body. Under it, what `coffre init` writes mounts
all of coffre's routes:

```tsx
export const root = createRootRouteWithContext<CoffreContext>()({
  head: () => coffreHead(),
  shellComponent: ({ children }) => (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <CoffreProvider>{children}</CoffreProvider>
        <Scripts />
      </body>
    </html>
  ),
});

export const routeTree = root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)]);
```

`coffreServerRoutes(root)` is `/api/$`, `/auth/$`, `/livez` and `/readyz`,
answered by coffre's server: mount all four. `coffreRoutes(root)` is coffre's
pages, and nothing more than its pieces, each a function of its parent;
mount them one by one to leave a page out or put one of the app's own at its
path. Here, the audit log is left out, and `/` is the app's own page, which
lists the projects the signed-in visitor can see:

```tsx
import { createRoute, Link } from '@tanstack/react-router';
import { api, auth, livez, readyz } from '@coffre/server/routes';
import { access, account, coffreShell, coffreSolo, deviceLogin, environment, login, project, projects, settings, token, tokens, unregistered, user, users } from '@coffre/ui';

const shell = coffreShell(root);
const solo = coffreSolo(root);

const home = createRoute({
  getParentRoute: () => shell,
  path: '/',
  // As the signed-in visitor, with their permissions: in process on the
  // server, fetch to /api in the browser. A component has it as useCoffre().
  loader: ({ context }) => context.coffre.projects.list(),
  component: function Home() {
    const { projects } = home.useLoaderData();
    return (
      <ul>
        {projects.map(({ slug }) => (
          <li key={slug}>
            <Link to="/projects/$project" params={{ project: slug }}>{slug}</Link>
          </li>
        ))}
      </ul>
    );
  },
});

export const routeTree = root.addChildren([
  api(root),
  auth(root),
  livez(root),
  readyz(root),
  solo.addChildren([login(solo), unregistered(solo), deviceLogin(solo)]),
  shell.addChildren([home, projects(shell), project(shell), environment(shell), access(shell), users(shell), user(shell), tokens(shell), token(shell), settings(shell), account(shell)]),
]);
```

- **Paths are fixed.** Each of coffre's pages is at its own path, as its
  links expect; there is no base path. Links, coffre's and the app's, are
  checked against the app's tree when it typechecks.
- **What is left out is not offered.** coffre's nav and its command palette
  show only the pages mounted, and a user or token named on a page links to
  theirs only if it is. Another link to a page left out, such as a
  project's, leads to the not-found page.
- **The shell signs people in.** `coffreShell` is coffre's nav, and lets in
  only signed-in, registered visitors, sending the rest to sign in; coffre's
  pages under it rely on that. A page of the app's own under the shell, as
  `home` above, gets both; under the root, it gets neither, and is public.
  `coffreSolo` is the bare frame of the sign-in pages.
- **The app's own server routes** go at paths of their own, not under
  `/api/` or `/auth/`, whose paths are coffre's. They get coffre's headers,
  as everything the app answers does, through its middleware. A route's
  code is in what the browser loads too: TanStack Start strips server code
  only from routes in files of their own, which coffre's are not. So a
  handler reaches the server as coffre's do, through what `src/server.ts`
  hands each request, and imports nothing of the server itself:

  ```ts
  // app/src/server.ts: fetch hands Start your part beside coffre's
  handler.fetch(request, { context: { ...coffre.request(env, ctx), hooks: hooks(env) } })
  // app/src/coffre.ts: requestContext: CoffreContext & { hooks: Hooks }
  // app/src/router.tsx
  const deployed = createRoute({
    getParentRoute: () => root,
    path: '/hooks/deployed',
    server: { handlers: { POST: ({ request, context }) => context.hooks.deployed(request) } },
  });
  ```

  coffre sets its headers on the response a route returns, in place, so a
  route returns one whose headers can change: `new Response(…)`, not
  `Response.redirect()` or a `fetch()`'s own. TanStack's `redirect()` is
  fine.
- **Server functions are checked for CSRF.** `src/start.ts` lists Start's
  `createCsrfMiddleware(…)` after coffre's: Start applies it by itself only
  to an app that sets no middleware of its own, and coffre's is one. It
  looks at server functions alone; coffre's `/api` and `/auth` judge their
  own requests.

## CI runs without a stored token

A service can be trusted to sign in with the ID token a CI platform signs
for each run, instead of a token kept in the CI's secrets
([design](design/oidc.md)). A deployment `coffre init` writes has it on,
and trusts no run until an owner makes a binding for it. An exchange always
passes two limits first, per source address and in total, which the
deployment provides. An older deployment adds them as below;
leaving `workloads` out turns it off. `ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT`,
in the examples, is for conformance: an instance whose public URL is not
loopback refuses to start with it set.

On Workers, two rate-limiting bindings in `app/wrangler.jsonc`:

```jsonc
"ratelimits": [
  { "name": "WORKLOADS_PER_SOURCE", "namespace_id": "1001", "simple": { "limit": 30, "period": 60 } },
  { "name": "WORKLOADS_TOTAL", "namespace_id": "1002", "simple": { "limit": 300, "period": 60 } }
],
```

and in `app/src/server.ts`:

```ts
auth: signin({
  providers: [/* … */],
  workloads: { limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL } },
}),
```

Cloudflare counts each limit per location, so a flood from many places can
reach the limit times the locations it comes through. On Node,
`processLimits()` from `@coffre/server/node` counts per process:

```ts
workloads: { limits: processLimits({ perSource: 30, total: 300 }) },
```

Then an owner trusts a workflow on a service's page, under "Trusted
workloads", or with `coffre trust`.

## Backups, restores and monitoring

Back up the one database, and keep the escrowed keys apart from it: the
backup holds no key, and the keys hold no data. [restore.md](restore.md) is
the runbook, for PlanetScale Postgres and plain Postgres, with the checks to
run before reopening traffic.

Point an external monitor at `/readyz`, so that someone is paged when it
turns red: it does when the log stops taking writes, the vault stops
signing checkpoints, a checkpoint finds the log cut or rewritten, or the
vault finds its key wrong. `/livez` only says the process answers.

## Conformance

Before deploying a changed configuration, run its `pnpm conformance`.
Workers needs three local Postgres URLs: `--postgres` for the owner,
`--runtime` for the app and `--vault-runtime` for the vault. The harness
creates, migrates and drops its own database. Node uses a temporary SQLite
file shared by both processes. Both use test keys and a stand-in GitHub,
not your live credentials. [conformance.md](conformance.md) lists the checks,
and what `coffre verify instance` checks of a live one.

## Appendix: the database by hand

What `coffre setup` does, step by step, for a host or a policy it does not
fit. Connect to the database as its administrator with `psql`:

```sh
psql "postgres://owner@db.example.com:5432/coffre?sslmode=verify-full"
```

Create two plain logins. `\password` prompts for passwords without putting
them in SQL statements or shell history. Use different generated passwords
and keep them in your password manager. On PlanetScale Postgres, these logins
connect as `coffre_runtime.<branch id>` and `coffre_vault_runtime.<branch id>`;
use those names in their connection strings.

```sql
CREATE ROLE coffre_runtime LOGIN INHERIT NOCREATEDB NOCREATEROLE;
CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOCREATEDB NOCREATEROLE;
\password coffre_runtime
\password coffre_vault_runtime
\q
```

New roles default to no superuser, replication or RLS-bypass rights. The
migration checks those rights and refuses unsafe roles. It hardens existing
groups without trying to alter their superuser-only attributes. Postgres 16
and later give a role creator `ADMIN OPTION` on its new roles; if the group
roles already exist, the migration login needs `ADMIN OPTION` on them.

Then migrate as the owner, in the deployment's directory, with its URL
including the password and the TLS settings your host requires, and
special characters in the password URL-encoded. It asks for it at a hidden
prompt:

```sh
pnpm exec coffre migrate
```

Make the keys with `coffre keys`, which shows them once, on a screen of
their own, and writes no file. Each login's connection string is the
owner's, with the login's name and password.

## Not configured by coffre

The environment variable names above belong to the examples. Packages take
typed configuration and read no deployment environment variables themselves.
The exceptions are the CLI's user settings, `COFFRE_SETUP_DATABASE_URL`
and `COFFRE_MIGRATE_DATABASE_URL` among them, and the `DATABASE_URL`
fallback for `coffre-server migrate`, which tests and local SQLite use, when
no URL is given.

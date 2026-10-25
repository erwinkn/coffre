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
pnpm exec coffre setup
```

`pnpm exec` runs the CLI the deployment pins, the version `coffre init`
wrote: it migrates with the migrations it was built with, which are those of
the deployment's `@coffre/server`. It asks for the connection string at a hidden prompt; a script
pipes it in, or redirects a file to it. It never takes it as an argument or a
flag, where the shell's history and other users could read it. Then:

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

The migrations create three group roles and grant their membership:

| Login | Group | Rights |
|---|---|---|
| `coffre_runtime` | `coffre_app` | app data and sessions; app entries in the log; read-only access to members and grants |
| `coffre_vault_runtime` | `coffre_vault` | members and grants; read the secret context it decides on; vault entries in the log |
| `coffre_backup_login`, optional | `coffre_backup` | read every row, the log's included, for `pg_dump` ([restore.md](restore.md#on-plain-postgres)); write nothing |

Neither runtime login owns tables or may change or delete audit entries.
Row-level security permits each to append only as its own author. Do not run
either component as the owner or give the runtime logins additional roles.

Every `coffre migrate` grants `coffre_backup_login` its group when that
login exists, so it may be made before or after migrating.

## Upgrading

0.4.0 is a clean break: a deployment of 0.3 or earlier is not upgraded, but
deployed afresh ([From a release before 0.4.0](#from-a-release-before-040)).
From 0.4.0 on:

The database migrates before the deploy, in the deployment's own pipeline:
its deploy workflow, Workers Builds, other CI, or a script before a restart. The new version never
serves on a schema it does not have: below its migrations, everything but
`/livez` and `/readyz` answers 503 `migrating`, and `/readyz` stays red.
The previous version keeps serving on the new schema until the deploy, as
every migration lets it ([expand, then contract](architecture.md#expand-then-contract)).

1. **`coffre update`**, in the deployment's directory. It updates the CLI
   the way it was installed (an npm or pnpm global, as each lists its
   globals; npx needs nothing; when neither claims it, it says so and what
   each would run), moves
   the deployment's `@coffre/*` pins to the release and installs them, and
   ends with what the release asks of the database: the migrations it adds,
   by name, to run before the deploy. The deployment's `minimumReleaseAge`
   exempts `@coffre/*`, so a fix installs the day it is published; your
   other packages still wait a week. A deployment pinned before 0.4.0 is
   left as it was, and told to deploy afresh
   ([From a release before 0.4.0](#from-a-release-before-040)).

   It moves the packages the app's Start app builds with to the versions
   the release's pages are built with, React, TanStack Start and Vite among
   them, showing each: they must be those exactly, and the app's build stops
   when one is not. It adds the page files a release adds, and removes those
   it retires, where they are as coffre wrote them, and then writes the
   route tree, `app/src/routeTree.gen.ts`, as the build does, so the diff
   to commit is whole.

   The pages and the versions are the release's own, as its CLI knows
   them. The deployment's own CLI, `pnpm exec coffre update`, is of the
   release before, so it asks the new release's CLI what to change, `coffre
   update --plan <dir>`. That runs the new release's code, so it asks you
   first, once (`--yes` answers for CI; without a terminal and without it,
   nothing runs), then makes the move as that CLI says, without asking
   again. It fetches that CLI as the deployment's install will: npm installs
   it in an empty directory of its own, with the deployment's `.npmrc`, so
   from its registry, never a copy a project or the global prefix has. It
   takes the plan only as a list of page files in `app/src/routes/`, each as
   the deployment has it now, the Start app's packages at exact versions,
   and an exact pnpm, and checks it all before it changes anything. When
   that CLI cannot say, nothing changes and the update fails.
   CLIs before 0.5.1 do not ask: they move a deployment with their own
   pages, so 0.4's CLI left out 0.5.0's `users.$user.apps.tsx`. From such a
   CLI, update with the new release's own: `npx @coffre/cli@latest update`.

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
2. **Migrate, then deploy.** Commit and push: the
   [deploy workflow](#deploys-on-every-push), or
   [Workers Builds](#workers-builds), does both. By hand, or in any other
   pipeline, in the deployment's directory:

   ```sh
   printenv DATABASE_OWNER_URL | pnpm exec coffre migrate --yes   # the owner's URL, piped in
   pnpm run deploy                  # on Node: pnpm build, then restart both processes
   ```
3. **Check `/readyz`**, which passes once the new code's scheduled job has
   run on the new schema.

In a deployment's directory, `coffre migrate` migrates its database to the
schema of the version the deployment pins, with that version's own
migrations, which the deployment's CLI carries; `pnpm exec` runs that CLI.
It needs no session, and asks no instance: until the deploy, the instance
runs the previous version, by design. It stops unless:

- **the database was made by coffre 0.4.0 or later.** One an earlier
  release made is refused: 0.4.0 began its schema again from one baseline
  ([From a release before 0.4.0](#from-a-release-before-040)).
- **the CLI is the version the deployment pins.** A global `coffre` of
  another version says to run `pnpm exec coffre migrate`, after `pnpm
  install`.
- **the login can change coffre's tables.** Migrations change the
  `drizzle` schema, and the tables and the functions coffre's migrations
  make, so the login must own them, or be a member of the role that does,
  one that inherits its privileges. Other tables in `public` are the
  database's own, whoever owns them. Otherwise it names that role, and
  whether the login is a member that does not inherit, and stops before
  it asks: migrate with that role's URL, or, as a role that administers
  it, `GRANT "<owner>" TO "<login>" WITH INHERIT TRUE` (before Postgres
  16, `GRANT "<owner>" TO "<login>"`, and `ALTER ROLE "<login>" INHERIT`
  for a NOINHERIT login). With nothing to apply, a login that can still
  read the tables gets only a warning: the next migration needs another
  login.
- **the database is not ahead of that version.** A database a newer coffre
  migrated, as after rolling a deployment back, is refused, each migration
  it does not know named by when it was made and its hash, and nothing is
  changed. Deploy that version, or restore the database from before it
  ([restore.md](restore.md)).

It asks for the **database owner's direct Postgres URL**, at a hidden
prompt, or reads it from stdin when that is no terminal; never from the
command line, and never prints it. Use the login that owns the tables,
not `coffre_runtime` or `coffre_vault_runtime`, and not a Hyperdrive
connection. It shows what it will apply, and asks, on a terminal; without
one, it applies only with `--yes`. It applies it under the migration lock,
with the database's privileges reasserted, and writes plain lines to a CI
log: no colours, no spinner.

From a laptop, run it in the deployment's directory as well: anywhere else,
it says where it runs, and asks for nothing.

A script that asks for the URL itself:

```sh
read -rs -p 'Database owner URL: ' owner_url
printf '\n'
printf '%s' "$owner_url" | pnpm exec coffre migrate --yes
unset owner_url
```

### From a release before 0.4.0

0.4.0 starts over: its schema is one migration per engine, which only a new
database takes, and it carries no code for the files, variables or data of
earlier releases. A deployment of 0.3 or earlier is not moved; make a new
one beside it, with `coffre init` and `coffre setup`, on a new database,
and bring over what you keep: `coffre export` reads an environment's values
from the old instance. On an old database, 0.4.0's `coffre migrate` says it
was made before 0.4.0 and changes nothing, and in an old deployment's
folder, `coffre update` says so too.

## On Workers

```
acme-secrets/
  app/src/coffre.ts            createCoffre(env => ({ publicUrl, database, vault, auth, auditChainKey }))
  app/src/server.ts            { fetch: Start's handler, coffre.request(env, ctx) its context; scheduled }
  app/src/start.ts             createStart(() => ({ requestMiddleware: [coffreMiddleware, createCsrfMiddleware(…)] }))
  app/src/router.tsx           createRouter(routeTree), the tree Start generates from src/routes
  app/src/routes/__root.tsx    the root, the document: coffre's stylesheet and icons, <CoffreProvider>
  app/src/routes/api.$.ts      coffre's server routes, { ...api }; also auth.$.ts, livez.ts, readyz.ts
  app/src/routes/_coffre.tsx   coffre's nav, { ...shell }; its pages in _coffre/
  app/src/routes/_solo.tsx     the sign-in pages' frame, { ...solo }; its pages in _solo/
  app/vite.config.ts           cloudflare(…), tanstackStart(), viteReact(), coffre()
  app/wrangler.jsonc           HYPERDRIVE, VAULT service binding, Cron
  vault/src/worker.ts          vault(env => ({ database, kek, owners }))
  vault/wrangler.jsonc         VAULT_HYPERDRIVE; no public route
```

The app is a TanStack Start app of its own, coffre's routes and pages among
its own route files ([Your own routes](#your-own-routes), and
[the UI](architecture.md#the-ui)). `vite build app` builds it into
`app/dist`: the Worker and its `wrangler.json`, which `wrangler deploy -c
app/dist/server/wrangler.json` uploads as it is, and the pages' static files,
which become the Worker's assets. The vault is a plain Worker, which wrangler
builds itself. `pnpm dev` runs both under `vite dev`, the vault beside the
app.

### Deploys on every push

`coffre init --workers` writes a GitHub Actions workflow,
[.github/workflows/deploy.yml](../examples/workers/.github/workflows/deploy.yml). In a GitHub
repository, it runs on every push to `main`, and on demand from the
repository's Actions tab. It installs the deployment exactly as
`pnpm-lock.yaml` says, so commit that file; migrates the database; then
runs `pnpm run deploy`, the vault first, then the app. A migration that
fails stops the run before anything deploys, and the Workers keep running
the previous version, which runs on the new schema too. Two runs never
overlap: a push during a deploy waits for it to end. Its actions are pinned
by commit, as coffre's own workflows pin them.

It reads three of the repository's Actions secrets:

| Secret | What it is |
|---|---|
| `CLOUDFLARE_API_TOKEN` | a Cloudflare API token that may deploy the two Workers, and little else |
| `CLOUDFLARE_ACCOUNT_ID` | the Cloudflare account's id |
| `DATABASE_OWNER_URL` | the database owner's direct URL, the one `coffre setup` asked for. Only the migrate step has it, and `printenv` hands it to the CLI on stdin |

The token needs, on the account, *Workers Scripts Edit*, *Account Settings
Read*, *Workers KV Storage Edit* and *Hyperdrive Read*; and on the zone
coffre's address is served through, *Workers Routes Edit*. An address
under `workers.dev` needs no zone.

**`coffre setup` sets all three** when the deployment's directory is a
clone of a GitHub repository, its `origin` on the GitHub its sign-in uses.
It does so after deploying ([Setup does Cloudflare too](#setup-does-cloudflare-too)):

- **The token.** Setup asks Cloudflare's API for one with exactly these
  permissions, named `coffre deploys: <owner>/<repository>`. wrangler's
  login has no scope for API tokens, so Cloudflare refuses it, unless
  `CLOUDFLARE_API_TOKEN` is set to a token with *API Tokens Edit*. Refused,
  setup says so, prints the dashboard's form for a new token with the
  permissions filled in, and asks for the token you make there, hidden as
  you paste it. The form cannot name the account and the zone itself:
  choose them there. Setup checks the token can read what each permission
  covers before it takes it, and says which one it lacks.
- **GitHub.** Setup signs in with gh's login (`gh auth token`) when gh is
  signed in to that GitHub and may set the repository's secrets. Otherwise
  it asks whether to set them now; yes prints GitHub's form for a
  fine-grained token that may set the repository's secrets and lasts a day,
  since setup needs it for that run alone. On the form, choose *Only select
  repositories*, then the repository.
- **The secrets.** Each is sealed to the repository's public key, as
  GitHub's API requires (libsodium's sealed box), and set through that API.
  None is shown, logged or written anywhere. A deployment from before
  `coffre init` wrote the workflow gets it, to commit.

Run again, setup keeps the repository's token, and sets the other two
again. `coffre setup --rotate-deploy-token` makes a new token and sets it;
the one it replaces is deleted when the login may delete tokens, and
otherwise left for you to delete on the dashboard.

**Without a GitHub remote**, setup skips this, and its summary says how to
wire it later: push the deployment to a GitHub repository, workflow
included, and run setup again; or set the three secrets yourself, on the
repository's *Settings > Secrets and variables > Actions*; or use Workers
Builds instead.

### Workers Builds

Instead of the workflow, Cloudflare's Workers Builds can build and deploy
both Workers on every push. Delete the deploy workflow then, or
each push deploys twice. Each build migrates the database first: whichever Worker deploys first, it finds its
schema. In each Worker's **Settings > Build**, with the repository connected
and the deployment's directory as the root:

| Worker | Build command | Deploy command | Build variables |
|---|---|---|---|
| the vault, `<name>-vault` | `printenv DATABASE_OWNER_URL \| pnpm exec coffre migrate --yes` | `npx wrangler deploy -c vault/wrangler.jsonc` | `DATABASE_OWNER_URL`, the database owner's direct URL, as a secret |
| the app, `<name>` | `printenv DATABASE_OWNER_URL \| pnpm exec coffre migrate --yes && pnpm exec vite build app` | `npx wrangler deploy -c app/dist/server/wrangler.json` | `DATABASE_OWNER_URL`, as for the vault |

The owner's URL is the one `coffre setup` asked for. It is a build variable,
which only the build sees; the Worker never does. Workers Builds hands it to
the build command in its environment, and `printenv` passes it to the CLI
on stdin, never as an argument; the CLI reads no variable itself. The two
builds migrate the same database; the second finds nothing left to do, as
the migration lock keeps one waiting for the other. A build that cannot
migrate fails before its deploy, and its Worker keeps running the previous
version, which runs on the new schema too.

### Setup does Cloudflare too

On a terminal, in a Workers deployment, `coffre setup` offers to do the rest
of this section itself. Say yes, and it:

1. signs in to Cloudflare through wrangler's browser login, and asks which
   account when there are several;
2. asks coffre's address and its first Owner's email. An address under one of the
   account's domains becomes the app's custom domain; one whose DNS is
   elsewhere is served through one of them
   ([below](#a-domain-whose-dns-is-elsewhere));
3. after the database steps, makes a Hyperdrive config for each login, with
   caching off, the password going only in the request to Cloudflare's API;
4. makes the GitHub App people sign in with, from a manifest: GitHub's page
   opens filled in, and the app's name, `coffre-` and the address, is yours
   to change there. Its logo is not: neither a manifest nor GitHub's API
   sets one. Setup prints the app's settings page and coffre's mark as a
   PNG, `node_modules/@coffre/cli/assets/github-app-logo.png`, to upload
   there under Display information;
5. fills in both `wrangler.jsonc`: the account, the Hyperdrive ids, the
   address and its route, GitHub's client ID, the Owner's email and the
   vault ID;
6. shows the keys on their screen, then deploys the vault and the app with
   them as secrets, on wrangler's stdin;
7. when the deployment is a GitHub repository, makes the Cloudflare token
   its deploys run under, and sets the repository's three Actions secrets
   ([Deploys on every push](#deploys-on-every-push));
8. waits for the address to answer.

The database URLs are never shown: Hyperdrive has them, and nothing else
does. Nothing is written but the two `wrangler.jsonc`, and the deploy
workflow, for a deployment that has none.

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
stopped. A Hyperdrive config deleted since is made again, its login
given a new password for it: Hyperdrive needs the password, and the
database keeps only its verifier. Setup lists the configs as it starts, so
one deleted while it runs is made again in that run when its login is
getting a new password anyway; otherwise that run stops, and says to run
setup again. Keys shown by a run whose deploy failed never reached
Cloudflare: the next run makes new ones, and its screen says they replace them.

### A domain whose DNS is elsewhere

A Worker answers only at an address Cloudflare serves: a CNAME from your
DNS provider to `*.workers.dev` does not reach it. So for an address whose
DNS is not on the Cloudflare account, `secrets.example.org` say, setup uses
[Cloudflare for SaaS](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/):
the address becomes a custom hostname of one of the account's domains, and
the app Worker serves it through a route on that domain
([Workers as your fallback origin](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/start/advanced-settings/worker-as-origin/)).
Cloudflare for SaaS is on the Free plan, the first 100 custom hostnames
free ([plans](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/plans/)).

**Enable Cloudflare for SaaS** first, on the domain it goes through, on
its dashboard page *SSL/TLS, Custom Hostnames*: only the dashboard can, and
it asks for a payment method, even on the Free plan. Setup says so, with
the link, when it is off.

**A token, when wrangler's login is refused.** wrangler's login has no scope
for DNS records, and may not manage custom hostnames. When Cloudflare
refuses it one of these calls, setup says which permissions a token needs
and asks for one, hidden as you paste it: make it at
[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
with Account: *Workers Scripts Edit*, *Hyperdrive Edit* and *Account
Settings Read*; and Zone, for that domain: *Zone Read*, *Workers Routes
Edit*, *SSL and Certificates Edit* and *DNS Edit*. Setup tries it at once,
asks again if Cloudflare refuses it too, and goes on under it for the rest
of the run: each wrangler it runs gets it as its `CLOUDFLARE_API_TOKEN`.
Setup never reads that variable itself, and leaves the wranglers' as it is
until you give it a token. A run that needs no refused call, such as one on
a domain whose fallback origin is set, asks for nothing.

Then setup, with several domains on the account, asks which one serves the
address. It keeps the domain's fallback origin when it has one, else makes
`coffre-fallback.<domain>`, a proxied `AAAA 100::` record that points
nowhere, for the Worker to stand behind. It makes the custom hostname, with
its certificate validated by TXT record, and shows what to add at your DNS
provider:

```
Add these records where secrets.example.org's DNS is:
  CNAME  secrets.example.org                      →  coffre-fallback.acme.com
  TXT    _cf-custom-hostname.secrets.example.org  "5e1f…"
  TXT    _acme-challenge.secrets.example.org      "Kq0w…"
```

Cloudflare validates the certificate over HTTP too, once the CNAME points
to the domain, even with TXT chosen: with the CNAME in, the `_acme-challenge`
record is optional, and the certificate's renewals need nothing from you.
The TXT records let it all go through before the CNAME moves traffic over.

The rest of setup carries on meanwhile. After the deploy, it shows the
records still missing and asks Cloudflare every 10 seconds until it has seen
them and issued the certificate, then waits for coffre to answer. Ctrl-C
stops the wait, with everything else done: run setup again once the records
are in, and it finds the custom hostname, asks nothing about the domain,
and waits for what is left. When Cloudflare gave up waiting for the
records, the hostname *moved* or its certificate timed out, a run after
asks it to validate again.

If the address's DNS is on another Cloudflare account, the CNAME there must
be DNS only, not proxied, for the custom hostname to get the traffic. And
if the address's own domain joins this account later, the next run makes
the address a custom domain, and leaves the custom hostname behind:
Cloudflare marks it *moved* once the CNAME goes, and deletes it a week
after.

`app/wrangler.jsonc` records the route, on the domain's zone by its id:

```jsonc
"routes": [{ "pattern": "secrets.example.org/*", "zone_id": "<the zone's id>" }]
```

**With no domain on the account**, setup explains the two ways on and takes
neither unless you choose it:

- **Add the domain to Cloudflare.** Setup adds it, then stops with the two
  nameservers to set at your registrar. Once Cloudflare sees them, often
  within the hour, run setup again: the address is under one of the
  account's domains then, as a custom domain. A run before that shows the
  nameservers again. Adding a domain needs Zone: *Zone Edit*, for all zones
  of the account, which wrangler's login may not have: refused, setup asks
  for a token that has it, or you stop there and add the domain on the
  dashboard.
- **Use the workers.dev address for now**, `<name>.<subdomain>.workers.dev`,
  once the account has a workers.dev subdomain. Run setup again with your
  own address later: it moves the app there, and says to change the GitHub
  App's callback.

Native Windows keeps the steps below, since wrangler cannot read secrets
from `/dev/stdin` there; WSL works. So does saying no, for a deployment
you would rather set up by hand.

### 1. Settings

Set `PUBLIC_URL` and `GITHUB_CLIENT_ID` in `app/wrangler.jsonc`, from a
GitHub App whose callback is `<PUBLIC_URL>/auth/callback/github`, with
read-only access to email addresses, as setup makes it, and, for its logo,
[coffre's mark](../packages/cli/assets/github-app-logo.png). An OAuth app
with that callback works too. Set
`OWNERS` in `vault/wrangler.jsonc`: the instance's Owners, made ones at
every deploy, and the way back in if every Owner is locked out
([deployment-auth.md](deployment-auth.md#the-owners-the-deployment-names)). `VAULT_KEY_ID` comes with the keys, in step 3.

For Cloudflare Access instead, replace `signin(…)` with `cloudflareAccess(…)`
([deployment-auth.md](deployment-auth.md)).

### 2. Two Hyperdrive configs

One config per runtime login, both pointing to the same database. Each
command reads its login's database URL at a silent prompt, so that the
password stays out of your shell's history: run it, paste the URL from
`coffre setup`'s screen, then press Enter. `coffre setup` shows both
commands, ready to copy.

```sh
read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive create coffre --caching-disabled --origin-connection-limit=20 --connection-string="${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL
read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive create coffre-vault --caching-disabled --origin-connection-limit=20 --connection-string="${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL
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

Keep both configs' connections under the database's. Hyperdrive opens
connections up to its `origin_connection_limit`, 60 by default on Paid,
before it makes a query wait (a soft limit, which a network failure can
briefly exceed), and the database refuses any past its
`max_connections`: a page's parallel reads then fail with "remaining
connection slots are reserved" (53300). `coffre setup` reads the database's
`max_connections`, less the slots it reserves for superusers, keeps 3 for
the administrator and `coffre migrate`, and gives each config half the rest,
at most 20; the commands it shows carry that number, here 20, for a
`max_connections` of 100 (47 each, capped at 20), and 9 for one of 25. Fix
an existing config with
`wrangler hyperdrive update <id> --origin-connection-limit=<n>`.

Keep each config at that number, not below it. Hyperdrive splits a
config's connections among its pool's shards, and a transaction holds one
from BEGIN to COMMIT, a wait for a lock included. At Hyperdrive's minimum,
5, a location may have five shards of one connection each: one vault call
waiting on the audit log's head then stops every query on its shard, and
under load the pool stays full ("Timed out while waiting for an open slot
in the pool"). Its share assumes the database serves coffre alone: keep
a config lower only when its database serves something else too, which
more connections would crowd out. So with Cloudflare access, setup never
raises a limit set below its share, which it cannot tell from one chosen
for such a database; it says so, and prints the commands that raise it.
Without, when it prints update commands, they set the share; check a
config it does not update with `wrangler hyperdrive get <id>`.

### 3. Keys and secrets

coffre needs two keys, one for each component, so that the app, which faces
the network, never holds what decrypts a value:

| Key | Held by | What it does | If it is lost |
|---|---|---|---|
| The vault key, `VAULT_KEY`, named by the vault ID, `VAULT_KEY_ID` | the vault | decrypts every value; the vault also derives from it the key it signs its log entries, member rows and checkpoints with | every value is lost for good |
| The app key, `APP_KEY` | the app | signs the app's log entries, sessions and tokens | everyone is signed out, every token and binding stops working, and the log stops verifying |

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
deploys what it built. `pnpm build` builds both without deploying them. Route the app to `PUBLIC_URL`, sign in as the
Owner, the first time, then try the CLI:

```sh
coffre login https://secrets.example.com
```

## On Node

```
acme-secrets/
  app/src/coffre.ts      createCoffre({ database, vault: connectVault(socket), … }), from .env
  app/src/server.ts      { fetch: Start's handler, coffre.request(request) its context }; coffre.schedule()
  app/src/routes/        the root and coffre's routes, as on Workers
  app/vite.config.ts     tanstackStart(), viteReact(), coffre()
  src/vault.ts           serveVault({ socket, database, kek, owners })
  .env.example           app settings
  vault.env.example      vault settings
```

The app, `app/`, is a TanStack Start app, as on Workers, which `pnpm build`
builds. `pnpm start` runs what it built under
[srvx](https://srvx.h3.dev), as TanStack Start documents for Node, with
the settings srvx reads from `.env`: the server's `fetch`, on `127.0.0.1`
and `PORT`, for a proxy in front to terminate TLS, and the client files,
which the server entry serves itself under `/_coffre/assets/`, kept for good
(each name holds its content's hash), never sniffed and same-origin. The
server runs coffre's scheduled job itself, every five minutes. The vault is
a process of its own.

Use Node 24 or later. Run `coffre setup` as above, then:

```sh
cp .env.example .env
cp vault.env.example vault.env
chmod 600 .env vault.env
```

Fill in `PUBLIC_URL`, the GitHub OAuth settings and `OWNERS`, then
the values from `coffre setup`'s screen ([step 3 above](#3-keys-and-secrets)
says what each key is for). `.env` takes the app key, `APP_KEY`, and
the app's database URL, as `DATABASE_URL`. `vault.env` takes the vault ID,
`VAULT_KEY_ID`, the vault key, `VAULT_KEY`, and the vault's database URL.
Both URLs name one database, through different logins, with the TLS
settings the administrator's connection string had:

```dotenv
# .env
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

The app's routes are Start's own, the same on Workers and on Node. Its
root, `app/src/routes/__root.tsx`, is the app's: the document, with
coffre's stylesheet and icons in its head and `<CoffreProvider>`, which
coffre's pages need around them, in its body. coffre gives each of its
routes as route options: what the route does, its loader, its search and
its redirects, but not where it goes. The app mounts them as Start's file
routes, which is what `coffre init` writes: one file per route, each
spreading coffre's options; a page's names its component, from its own
module:

```tsx
// app/src/routes/_coffre.tsx: coffre's nav, around the pages in _coffre/
export const Route = createFileRoute('/_coffre')({ ...shell });

// app/src/routes/_coffre/projects.index.tsx
import { projects } from '@coffre/ui';
import { ProjectsPage } from '@coffre/ui/pages/projects';

export const Route = createFileRoute('/_coffre/projects/')({ ...projects, component: ProjectsPage });

// app/src/routes/api.$.ts
import { api } from '@coffre/server/routes';

export const Route = createFileRoute('/api/$')({ ...api });
```

Start splits each page into a chunk of its own, which the page's first
load fetches beside the app's entry. To leave one of coffre's pages out,
delete its file; to change one, override in its file, `{ ...projects,
component: ProjectsPage, head: () => ({ meta: [{ title: 'Projects' }] }) }`.
The app's own pages are files beside them, as in any Start app:
`app/src/routes/reports.tsx` is public, under the root;
`app/src/routes/_coffre/reports.tsx` is under coffre's nav, for signed-in
visitors only. A release that adds a page to coffre adds its file to the
deployment, through `coffre update`, which shows it first.

An app that prefers its routes in code mounts the same options with
TanStack's own `createRoute({ getParentRoute, path, ...projects, component:
ProjectsPage })`; coffre has no helper of its own for it.

- **Paths are fixed.** Each of coffre's pages is at its own path, as its
  links expect; there is no base path. Links, coffre's and the app's, are
  checked against the app's tree when it typechecks. The types do not
  catch a page put at another path: its links would not reach it.
- **A page with tabs is a layout.** A project's, a user's, a service
  account's and your account's page is a layout route,
  `_coffre/projects.$project.tsx`, and each tab a file under it, its first
  the index, `_coffre/projects.$project.index.tsx`. An environment's page,
  `_coffre/projects.$project_.$environment.tsx`, is under the project's
  path but not its layout.
- **What is left out is not offered.** coffre's nav, its command palette
  and a page's tabs show only the pages mounted, and a user or token named
  on a page links to theirs only if it is. Another link to a page left out, such as a
  project's, leads to the not-found page.
- **The shell signs people in.** `shell` is coffre's nav, and lets in only
  signed-in, registered visitors, sending the rest to sign in; coffre's
  pages under it rely on that. `solo` is the bare frame of the sign-in
  pages.
- **A page of the app's own calls the API as the signed-in visitor**, with
  their permissions: `useCoffre()` in a component, `context.coffre` in a
  loader, `loader: ({ context }) => context.coffre.projects.list()`. In
  process on the server, `fetch` to `/api` in the browser.
- **The app's own server routes** go at paths of their own, not under
  `/api/` or `/auth/`, whose paths are coffre's, and get coffre's headers,
  as everything the app answers does, through its middleware. coffre sets
  them on the response a route returns, in place, so a route returns one
  whose headers can change: `new Response(…)`, not `Response.redirect()` or
  a `fetch()`'s own. TanStack's `redirect()` is fine.
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

and in `app/src/coffre.ts`:

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
workloads", or with `coffre trust`. A GitHub App of the deployment's own,
`workloads.github`, lets the pages list the repositories it is
installed on, private ones too, rather than have their IDs typed; the
same app can sign people in ([github-app.md](github-app.md)).

### Key-bound sessions and their gate

A workload's key-bound session sends a fresh proof with each request
([design](design/workload-access.md#52-the-gate-replay-nonces-live-counters)),
and each workload's gate takes each proof once and counts its limits. A
deployment `coffre init` writes has it. `workloads: { useOnly: true }`
leaves services nothing but those sessions
([section 6.3](design/workload-access.md#63-the-strict-instance-and-the-path-from-today));
`coffre init` writes it again once conformance and the Action sign
services in with a key.

On Workers, the gates are a Durable Object, one per workload, made where
its first request comes from. An older deployment adds, in
`app/wrangler.jsonc`, a binding beside `SOCKETS` and a migration after
its own:

```jsonc
"durable_objects": {
  "bindings": [
    { "name": "SOCKETS", "class_name": "CoffreSockets" },
    { "name": "GATES", "class_name": "CoffreGates" }
  ]
},
"migrations": [
  { "tag": "sockets", "new_sqlite_classes": ["CoffreSockets"] },
  { "tag": "gates", "new_sqlite_classes": ["CoffreGates"] }
],
```

`gates: env.GATES` in `app/src/coffre.ts`, and in `app/src/server.ts`:

```ts
export const CoffreGates = coffre.Gates;
```

Without the binding, Workers takes no key-bound session: nothing else
there can hold a proof to one use.

On Node, the gates live in the server's process, which needs nothing in
the configuration. Run one server process. Several, coffre on Kubernetes
with more than one replica included, would each hold gates of their own,
with nonces of their own: a client sent to each in turn would be asked
for a new nonce at every turn. That fails loudly, never unsafely. The
gate's counts also start over when the process does, a day's limit
included.

## The audit watch

coffre's audit log is tamper-evident on its own: every entry hashed into
one chain and MACed by its author, and the vault's signed checkpoint of it
every five minutes. Someone who can write the database without the keys
cannot change it unseen, but without the audit watch nothing looks until
someone verifies the log (`coffre verify log`, or the audit page from the
newest checkpoint), and `/readyz` says only that the database is migrated,
with `watched: false`; the scheduled job says so in the log once.

The audit watch, a plugin of coffre's own, looks for you: every five
minutes it writes a heartbeat, walks the log from what it last verified,
and keeps what it verified outside the database, where whoever writes the
database cannot reach it: the anchor ([architecture](architecture.md#one-log-two-authors)).
`/readyz` then turns red on anything it finds, within a beat. `coffre
init` writes it into both kinds of deployment; remove the line to go
without.

```ts
// Workers: app/src/coffre.ts
import { durableAnchor } from '@coffre/server/cloudflare';
import { auditWatch } from '@coffre/server/plugins/audit-watch';
plugins: [auditWatch({ anchor: durableAnchor(env.ANCHOR) })],

// Node: app/src/coffre.ts
import { fileAnchor } from '@coffre/server/node';
plugins: [auditWatch({ anchor: fileAnchor(env('AUDIT_ANCHOR')) })],
```

On Workers the anchor is a Durable Object, one for the instance, whose
alarm also walks a backlog between beats. An older deployment adds, in
`app/wrangler.jsonc`, a binding beside `GATES` and a migration after its
own:

```jsonc
"durable_objects": {
  "bindings": [
    { "name": "SOCKETS", "class_name": "CoffreSockets" },
    { "name": "GATES", "class_name": "CoffreGates" },
    { "name": "ANCHOR", "class_name": "CoffreAnchor" }
  ]
},
"migrations": [
  { "tag": "sockets", "new_sqlite_classes": ["CoffreSockets"] },
  { "tag": "gates", "new_sqlite_classes": ["CoffreGates"] },
  { "tag": "anchor", "new_sqlite_classes": ["CoffreAnchor"] }
],
```

and, in `app/src/server.ts`:

```ts
export const CoffreAnchor = coffre.Anchor;
```

Not Workers KV: a KV read may be a minute stale, and KV has no
compare-and-set, so two beats could each write over the other's record,
and an older record put back would go unseen for as long. A Durable
Object reads its own writes, and runs one request at a time between its
storage's read and write.

On Node the anchor is a file, written whole and renamed into place, mode
0600 (`AUDIT_ANCHOR` in the example's `.env`). **Put it on a persistent
volume** that only the server's user writes. On a disk that goes with the
container, every restart finds the store empty: the watch walks the log
whole again and alerts, and a cut made while it was down goes unseen.
One file suits one server process. Several, coffre on Kubernetes with
more than one replica included, want a store they share with a
compare-and-set of its own, any object with `read()` and `write(prev,
next)` (`AnchorStore`): an S3 object written with `If-Match` on the ETag
read before (`If-None-Match: *` for the first), a Redis key set by a
script that compares first, or a row in a small database coffre's own
logins cannot reach. A store's `write` refuses a record that moves the
checkpoint or the app's progress back (`admits`), whoever calls it.

**An empty store is re-anchored by itself.** The first beat after the
watch is added, and the first after its store was lost, find no anchor:
they walk the log whole, 10,000 entries a beat and, between beats, a
walk a second (the Durable Object's alarm on Workers, the scheduled job on
Node), with `/readyz` green meanwhile, since an empty store is no evidence
of tampering. A clean walk writes the anchor, logs `audit.reanchor` and
sends one alert on the deployment's alert channel (`signin({ workloads: {
alert } })`, as a workload's alerts), or, without one, a warning in the
process's log. A walk that finds the log broken
keeps that as a finding: red, and nothing anchored past it. A cut made
before the store emptied cannot be seen: the alert says when to look.

**A finding clears by itself once the entry it names verifies again**,
restored from a backup or after a verifier fix; each finding and each
clearing is logged. The one case it cannot is entries lost for good, a
tail cut with no backup: an Owner of the whole instance accepts the loss,

```sh
coffre audit accept-loss 9400 9411
```

a range that must hold the entry the finding names. It is logged in their
name with the finding, which stays in the log, and alerted; the watch goes
on past the range, and finds tampering anywhere else as before. Pick a
range with an entry after it where you can: with none, the watch goes on
from the entry before the range, and walks whatever the log holds from
there again. The acceptance is the watch's alone: where the lost entries
were cut from between others, a check of the log itself, `coffre verify
log` or the audit page, still finds the gap, since nothing erases what
was found.

If the store cannot be reached, the beat fails and readiness is red, and
both recover by themselves once it answers: what it holds was not lost.

**A rotation of `APP_KEY` seals the anchor again** under the new key
([below](#rotating-the-app-key)): the record names the key it is sealed
under, and the rotation seals what it says again under the new one,
before its `key.rotate`. Changing `APP_KEY` with the old key left out of
`previousAuditChainKeys` leaves the anchor under a key the app does not
hold: readiness is red, and the beat leaves the record alone. List the old
key if you still hold it, and the rotation seals the record again,
findings and all. Only for a key that is lost, empty its store; the next
beat then re-anchors, with its alert, and a cut made before then goes
unseen. To empty it, delete the file on
Node; on Workers, name a new object,
`durableAnchor(env.ANCHOR, { name: 'anchor-2' })`, and deploy.

## Rotating the app key

The app key, `APP_KEY` (`auditChainKey`), MACs the app's log entries and
every row that signs someone in: sessions, service and personal tokens,
handles, workloads' sessions, trust bindings, enrollment codes, device
logins, linked sign-in accounts, MCP clients and their connections. A
rotation moves all of it to a new key, as the vault's own rotation does
for the vault key ([keys.md](keys.md#a-local-key)).

1. **Upgrade first.** Deploy a release that knows `previousAuditChainKeys`
   under the old key, and let its deploy finish: an instance of an older
   release would go on writing under the old key during the rotation.
2. **Make a new key.** `coffre keys`, and take only the app key; or
   `openssl rand -base64 32`. Keep it in your password manager beside the
   old one.
3. **List the old key, then give the new one.** First, keep the key in use
   under a secret of its own too, and deploy the code that lists it; while
   it is also `APP_KEY`, it counts once, and nothing changes. A rotation
   adds to the list, and never replaces an entry: each key replaced stays
   listed, under its own secret.

   ```ts
   auditChainKey: env.APP_KEY,                                // the key in use, then the new one
   previousAuditChainKeys: [env.APP_KEY_2026_10],             // each key replaced, the one in use added now
   // a second rotation: [env.APP_KEY_2026_10, env.APP_KEY_2027_04]
   ```

   On Workers, `wrangler secret put APP_KEY_2026_10 -c app/wrangler.jsonc`
   with the key in use, then `pnpm run deploy`; on Node, the same in
   `.env`, then a restart. Previous keys can be listed in any order.
4. **Give the new key, then wait for readiness.** Set `APP_KEY` to the
   new key: `wrangler secret put APP_KEY -c app/wrangler.jsonc`, which
   deploys at once, or `.env` and a restart on Node. The first start under
   it signs every row the old key signed again under the new one, a step
   of 100 rows a request, seals the audit anchor again under it, and then
   writes `key.rotate`. Until then every request but `/livez` and `/readyz`
   answers 503 `rotating`, and each one, `/readyz` too, takes it a step
   further; a Node process also steps it to the end as it starts. Given
   the new key without the old one listed, the app runs under the new key
   alone, everyone signed out and every token and binding failing, until
   a deploy lists the old key and rotates. Wait on readiness:

   ```sh
   until curl -fsS https://secrets.example.com/readyz; do sleep 1; done
   ```

   Many rows take many steps: an instance with 20,000 credentials, most of
   them CI runs' spent ones, takes two hundred.
5. **Check.** The audit log shows the rotation's `key.reseal` steps, each
   naming how many rows it signed again, how many sessions and approved
   device logins it ended, how many another listed key signed, which its
   own rotation signs next, and any row no key listed had signed, which
   fails as it did before; then `key.rotate`. `coffre verify log` verifies
   the whole log; `coffre verify keys` takes the new key as the one the
   app signs with.

What it changes, and what it keeps:

- **Everyone signs in again.** Browser and CLI sessions are signed out,
  never honoured under the new key. Service tokens, personal tokens,
  handles, workloads' sessions (one awaiting approval included), trust
  bindings, enrollment codes and MCP connections go on. An MCP client's
  access token lasts minutes and is signed with the key, not stored: the
  client refreshes it once, with its connection's refresh token. A sign-in
  or an MCP approval under way when the rotation runs starts again, and a
  CLI login approved but not yet taken is used up: the CLI logs in again.
- **The old key writes nothing from the rotation's first step.** The step's
  `key.reseal` names it, and the log refuses an append under a key it names
  so: an instance still running the old key, as during the seconds a
  deploy takes, has its writes refused, and a change it made to a row in
  that window may be lost. Once `key.rotate` is written, the old key
  vouches for no row, and verifies only the log's entries from before the
  first step: an entry under it after that is a finding, the watch's and
  `coffre verify log`'s.
- **The anchor is sealed again** under the new key, before `key.rotate`:
  what it says is what it said ([the audit watch](#the-audit-watch)). After
  `key.rotate`, a record under the old key is foreign, as any other key's:
  a store the rotation cannot reach holds it back until it can.
- **A database that cannot be reached serves nothing** while
  `previousAuditChainKeys` is set, until the app knows its key stands:
  503 `unavailable`.
- **A key replaced stays replaced.** A start under a key the log moved on
  from, as a rollback of the deploy would be, answers 503 `app_key`, and
  the server's log says which keys; so does a start that lists the new
  key of a rotation under way to another key, or that is the new key of
  one whose old key was taken out of `previousAuditChainKeys` before it
  ended. A start that does not hold the new key of a rotation under way
  serves, as under any key the log does not know. To undo a rotation,
  rotate again to a new key. A key the log does not know, a lost one or
  the wrong one, is served under as before rotations: everyone signs in
  again, every token and binding fails, the log stops verifying, and the
  server's log names the key it lacks.
- **A crash, or several isolates at once, change nothing.** Each step is
  one transaction under the log's head: the next goes on from the one the
  log says came before, whichever process takes it.
- **A leaked key's window closes with the rotation.** An entry forged
  with the old key after the first step is a finding; a row forged with
  it before `key.rotate` is signed again with the rest, as a rotation
  cannot tell it from the instance's own. When the old key leaked, review
  after the rotation everything that grants access without a session,
  which signing everyone out does not end: each person's linked sign-in
  accounts (`coffre identities`, which they unlink with `coffre
  identities unlink`; one forged for an Owner signs its holder in as
  them), their MCP clients (`coffre apps`) and personal tokens (`coffre
  tokens`), and each service's tokens, bindings and enrollment codes
  (`coffre tokens <service>`, `coffre trust <service>`, `coffre enroll
  <service> --list`).
- **A key replaced without a rotation**, as before this release, is
  rotated from once it is listed in `previousAuditChainKeys`, like any
  other: the rows it signed are signed again, so the tokens and bindings
  that swap ended work again. Don't list one you replaced to end what it
  signed, because it leaked: leave it out, and its entries stay
  unverifiable, as they are now.

**When may the old key go?** Keep it in `previousAuditChainKeys` for as
long as the log holds entries written under it, which is for good: it
verifies them, and nothing else. The app serves without it once the
rotation is done, but the audit watch needs it until its anchor has
verified past `key.rotate` (readiness green after a beat or two), or it
finds the old key's entries it had still to walk; and a walk of the whole
log, `coffre verify log` included, stops at the first entry under a key it
does not hold. Escrow it with the vault keys.

## MCP clients

Claude and other MCP clients connect at `<PUBLIC_URL>/mcp` as the people
who approve them ([mcp.md](mcp.md), [design](design/mcp.md)). A deployment
`coffre init` writes has it on; leaving `mcp` out turns it off, and `/mcp`
and its metadata then answer 404. It needs coffre's own sign-in, and three
limits: OAuth's token and registration requests pass one per source address
and one in total before any work, as CI runs' exchanges do, and each
connection's calls pass one of their own. A deployment from before 0.4
gains MCP's route files from `coffre update`, and adds these itself.

On Workers, three more rate-limiting bindings in `app/wrangler.jsonc`:

```jsonc
{ "name": "MCP_PER_SOURCE", "namespace_id": "1003", "simple": { "limit": 30, "period": 60 } },
{ "name": "MCP_PER_CONNECTION", "namespace_id": "1004", "simple": { "limit": 120, "period": 60 } },
{ "name": "MCP_TOTAL", "namespace_id": "1005", "simple": { "limit": 300, "period": 60 } }
```

and in `app/src/coffre.ts`, beside `workloads`:

```ts
mcp: {
  limits: { perSource: env.MCP_PER_SOURCE, perConnection: env.MCP_PER_CONNECTION, total: env.MCP_TOTAL },
},
```

On Node:

```ts
mcp: { limits: processLimits({ perSource: 30, perConnection: 120, total: 300 }) },
```

claude.ai and Claude Desktop connect from Anthropic's servers, which must
reach the instance; Claude Code connects from the person's machine.

## The credential proxy's database tunnel

`coffre run` gives a person's app a database URL of its own, a listener on
127.0.0.1, and coffre logs in to the real database for it, with the real
password, which the app never holds
([design](design/credential-proxy.md#5-the-other-shapes)). The deployment
adds the proxy, `credentialProxy({ … tunnels: { db: postgres('DATABASE_URL',
{ hosts: ['db.acme.example'] }) } })` in its `plugins`, and its route,
`app/src/routes/use.$.ts` (without `hosts`, the URL must name its host by
address: a name, which whoever writes the value picks, may resolve to a
private address):

```ts
import { createFileRoute } from '@tanstack/react-router';
import { plugin } from '@coffre/server/routes';

export const Route = createFileRoute('/use/$')({ ...plugin });
```

On Workers, each `coffre run`'s connections to a database run in a
Durable Object of their own. A deployment `coffre init` writes from 0.11
has it already: the `SOCKETS` binding and its migration in
`app/wrangler.jsonc`, `sockets: env.SOCKETS` in `app/src/coffre.ts`, and in
`app/src/server.ts`:

```ts
export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => coffre.upgrade(request, env) ?? handler.fetch(request, { context: coffre.request(env, ctx) }),
  scheduled: coffre.scheduled,
};

/** The Durable Object `SOCKETS` binds (wrangler.jsonc). */
export const CoffreSockets = coffre.Sockets;
```

An older deployment adds these itself, with, in `app/wrangler.jsonc`:

```jsonc
"durable_objects": { "bindings": [{ "name": "SOCKETS", "class_name": "CoffreSockets" }] },
"migrations": [{ "tag": "sockets", "new_sqlite_classes": ["CoffreSockets"] }],
```

The tunnel needs the 0.11 CLI or later: an older one is refused with 426.

A database in a private network, a read replica with no public address,
is reached through a [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
whose connector runs in that network, and a
[VPC Network binding](https://developers.cloudflare.com/workers-vpc/configuration/vpc-networks/)
to it:

```jsonc
// app/wrangler.jsonc
"vpc_networks": [{ "binding": "REPLICA_NET", "tunnel_id": "<the tunnel's id>" }],
```

```ts
// app/src/coffre.ts
tunnels: { replica: postgres('REPLICA_URL', { hosts: ['10.0.1.5'], connect: env.REPLICA_NET }) },
```

The binding reaches the network, `hosts` the addresses in it the URL may
name, and the URL says `sslmode=disable`: the binding carries plaintext
TCP, so the last leg, from the connector to the database, stays inside
that network. A binding the Worker lacks fails the configuration.

What to expect of it on Cloudflare, measured with a database behind a
tunnel: about 20 MB/s each way for one connection (1 MiB uncounted at
most, each way, a round trip to the object at a time), a query's round
trip 50 to 80 ms from Europe, a run's first connection 2 to 3 seconds and
the next ones under one. A run may open 32 connections at once. A
Durable Object is reset now and then, and Cloudflare resets a connection
whose app has read nothing for two minutes: the app's driver sees the
connection drop, and a pool opens another. A run writes three entries to
the app's audit log as it starts (its handle, its plan, its first
connection's use), each under the log's one lock, so an instance admits a
burst of runs at the pace of its database: on that setup, about one and a
half runs a second. 64 runs started at once were all admitted within 45
seconds but a few; past that, some fail with 500 or 503 while the lock is
waited on, and a run started again gets in.

## Backups, restores and monitoring

Back up the one database, and keep the escrowed keys apart from it: the
backup holds no key, and the keys hold no data. [restore.md](restore.md) is
the runbook, for PlanetScale Postgres and plain Postgres, with the checks to
run before reopening traffic.

Point an external monitor at `/readyz`, so that someone is paged when it
turns red, with the audit watch: it does when the log stops taking
writes, the vault stops signing checkpoints, a beat finds the log cut or
rewritten, the vault finds its key wrong, or the anchor cannot be reached
([The audit watch](#the-audit-watch)). `/livez` only says the process answers.

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

To back up with `pg_dump`, make a third login, `coffre_backup_login`, the
same way, before or after migrating: every migration run grants it the
group that reads every row ([restore.md](restore.md#on-plain-postgres)).
Nothing checks that login's own rights: keep it as plain as the two above.
Every run grants the group to whichever role bears that name, so on a server
where others may create roles, make it before they can.

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
typed configuration and read no deployment environment variables themselves,
and the CLI reads none either: it takes flags, and secrets in the files they
name (`coffre help`). The exception is the `DATABASE_URL` fallback for
`coffre-server migrate`, which tests and local SQLite use, when no URL is
given.

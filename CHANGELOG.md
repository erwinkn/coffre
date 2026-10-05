# Release notes

## Unreleased

**A service account is an identity, not a token.** The CLI and the UI showed
a service as `token:deploy-slides`, so its OIDC trust bindings looked set
"on a token", though OIDC is the way to need no token at all. Now a service
account, a machine identity for CI and other machines, is
`service:<name>` wherever a person reads one: help, output, previews,
refusals, `coffre access`, `coffre audit`, the audit log's sentences and the
UI's pages. It signs in one of two ways, and they are named so: by OIDC (trust
bindings) or with bearer tokens.
- The UI's Tokens page is Service accounts, and a service account's page
  shows "Sign in with OIDC", its trust bindings, then "Bearer tokens".
- The CLI takes `service:<name>`, still takes `token:<name>`, and `--service`
  as before; `coffre admit service:deploy` needs no `--service`.
- The API, the vault and the audit log keep `token:<name>`: the log's signed
  entries hold it. Nothing is migrated, and nothing signed or verified
  changes; `@coffre/client` shows and takes the names at the edge
  (`shownMember`, `apiMember`).

**A sign-in error is said once, and a reload is a clean retry.** The page
coffre sends a refused sign-in back to, `/login?error=…`, renders the
error on the server, then takes it out of the address once its scripts
run, so a reload, or a link to the page, starts over. The same goes for
`/account?linked=…` and `/account?error=…`. Without scripts, a reload
still shows it.

**"Your email already signs in with a different account" names it.** It
now says "Your email already signs in with GitHub. Sign in with GitHub,
then link this account from your account page.", lists several when
there are, and says "another GitHub account" when the address signs in
with a different account at the same provider. Only the providers are
named, never another email or account name, and only to a visitor whose
provider has just verified that the address is theirs.

**Grants on every project.** A member or a service can hold a role on every
project, the ones created later too, or on one environment in every project:

```sh
coffre grant '*' ada@acme.example --role auditor            # every project
coffre grant '*' ci-deploy --role viewer --env dev --service  # dev in every project, never prod
coffre revoke '*' ci-deploy --env dev --service
coffre access '*'                                           # who holds them
```

- Only instance owners and root admins give or take them. They are grants
  like any other: roles (only those an environment can hold go on one
  environment's name), end dates, `access.grant` and `access.revoke` entries
  naming the place as `*` or `*/dev`, and offboarding, which revokes them
  with the rest and counts them in its preview.
- `*/dev` matches the environment's slug when it is used: a project that has
  no `dev` gains one when someone creates it, and renaming `staging` to `dev`
  brings it in. Making a project or an environment, or giving one a new slug,
  answers with who reaches it through them (`inherited`), and the CLI and
  the dialogs say so before you confirm.
- The member page shows "All projects · Developer" or "dev in every
  project · Developer", and a project's access list shows who reaches it
  through them.
- One migration, `0005_instance_grants`: a column on `vault_grants`, and its
  checks loosened to allow these. 0.3.0 runs on the new schema, and this
  release on the old one, where it answers 503 to a grant on every project
  until `coffre migrate` has run.
- **Revoke grants on every project before rolling back past this release.**
  An older vault does not know them, and refuses everyone who holds one, as
  a member whose record was changed around it, until an owner removes them
  ([deploy.md](docs/deploy.md#rolling-back-past-grants-on-every-project)).

**`coffre trust` from first use.**
- A binding matches one event, and trusting a workflow that also runs by
  hand or on a schedule took one `coffre trust` for each. Now `--event` (and
  GitLab's `--source`) takes several, `--event
  push,workflow_dispatch,schedule`, a binding each, in one go. `push` is
  still the only default.
- The preview says which events the bindings accept, and names the flag
  that adds the others the ref allows: "Accepts runs started by push. Not
  by workflow_dispatch or schedule: add them with --event, as --event
  push,workflow_dispatch,schedule."
- For a private repository, whose IDs coffre cannot look up, it said only
  "not found". Now it says why in a line, then gives the command that gets
  the IDs and the flags to add:
  `gh api repos/OWNER/REPO --jq '"--repository-id \(.id) --owner-id \(.owner.id)"'`,
  and `glab api … | jq …` for a GitLab project.
- `coffre trust` alone prints its usage and exits 0, as `coffre help` says
  it does. A test now holds every command's `--help`, `-h` and `help
  <command>` to exit 0.

`coffre update` and `coffre migrate` without a terminal and without `--yes`
now say "Not a terminal, so nothing to confirm on: pass --yes to update
without asking."

**`coffre untrust` shows what it would end, and ends it with `--apply`**, as
every other command that ends something for good does. The preview names
the binding, its claims, and the CI runs that would lose sign-in, in a
sentence: "GitHub Actions runs of acme/api's workflow deploy.yml, on
branch main, by push would no longer sign in as token:api-deploy, and the
credentials they hold would end at once." A script that ran `coffre
untrust <service> <id>` adds `--apply`.

**wrangler 4.142, and `wrangler dev` stays up.** The Workers deployment's
wrangler moves from 4.118.0 to 4.142.0, with Cloudflare's Vite plugin
(1.50.0 to 1.61.0, which pins it) and the Workers types (5.20260926.1).
Under `wrangler dev` before 4.131, one request that met an idle internal
connection as it closed, about five seconds after the last, or a client
gone mid-upload, ended the whole dev server with an empty `✘ [ERROR]`
(cloudflare/workers-sdk#15203 and #14641, fixed by #15252): a local run, or
`pnpm conformance`, would stop partway. `coffre update` now moves wrangler
and the Workers types with the plugin.

**Everything the API does, the CLI does.** The commands that were the
browser's alone:

```sh
coffre projects create market [--name …]       # rename, archive, unarchive
coffre environments create market/prod         # the same
coffre rename market/prod/DB_URL DATABASE_URL   # a secret's key, its versions with it
coffre archive market/prod/OLD_KEY              # unarchive brings it back
coffre admit ada@acme.example [--owner]         # a member; --no-owner ends ownership
coffre admit deploy-slides --service            # a service, for CI
coffre revoke market ada@acme.example --env prod
coffre tokens deploy-slides                     # a service's tokens
coffre tokens issue deploy-slides [--expires-in <days>] [--label …] [--output-file <path>]
coffre tokens revoke deploy-slides <id> [--apply]
coffre sessions                                 # sessions revoke <id> [--apply]
coffre identities                               # identities unlink <id> [--apply]
```

From nothing to a CI service: `coffre admit deploy-slides --service`, `coffre
grant deploy deploy-slides --role viewer --env prod --service`, then `coffre
trust deploy-slides --github … --apply`, or `coffre tokens issue
deploy-slides`. `grant` does not make a member: to one not yet admitted it
says `admit them first, coffre admit … --service`. `tokens issue` prints the
token once, on stdout, and on a terminal says that it will not be shown
again; `--output-file` writes it to a new file, 0600, never one already
there, and prints no token. What ends something for good, a token, a
session or a linked account, is shown first and done with `--apply`, as
`offboard` and `import` are. The lists take `--json`: `projects`, `list`,
`history`, `access` (which takes a place now, `access market/prod`),
`tokens`, `sessions`, `identities`, `audit` and `whoami`.

Approving a `coffre login` stays the browser's, which is what vouches for
the CLI. `packages/cli/src/commands.ts` maps every route of the API to its
commands, or to the browser with why; a route added with neither fails the
typecheck and the parity test, and the test runs every command's `--help`.

Also: `coffre --version` prints the version; `coffre <command> --help` and
`coffre help <command>` print its usage, for every command; a flag a command
does not take, or an argument too many, is refused in a line and its usage,
exit 2, never a stack trace.

**The CLI reads no environment variable, and takes no secret as a flag or an
argument.** `COFFRE_TOKEN`, `COFFRE_API_URL` and the rest used to override the
saved session where no one could see it, and a secret in a variable reaches
every process the shell starts. Now flags configure, and a command that
needs a secret asks for it: at a hidden prompt, with a label (`Database
owner URL`), or, when stdin is no terminal, from stdin, which is where a
pipeline pipes it and a file is redirected. A CI run signs in as a person
does, with `coffre login`, and the commands after it use the session it
saves:

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

The session flags, before the command, pick another instance than the
current one, `--url`, or sign one command in as a service by its ID token,
`--service`, which on GitHub Actions needs nothing else. A variable an
earlier CLI read, still set, stops the command that read it, in one line
saying what to do instead, rather than leaving the run to go elsewhere, or
as someone else, unseen:

```
coffre: COFFRE_TOKEN is no longer read: unset it; instead, run `coffre login <url> --token` and paste the token, or pipe it in
```

| Before | Now |
|---|---|
| `COFFRE_API_URL` | `--url <url>`, or `coffre login <url>` once |
| `COFFRE_TOKEN` | `coffre login <url> --token`, the token pasted or piped in |
| `COFFRE_ACCESS_CLIENT_ID`, `COFFRE_ACCESS_CLIENT_SECRET` | `coffre login <url> --access-client-id <id>`, the secret pasted or piped in |
| `COFFRE_SERVICE` | `--service <name>`; on GitHub Actions, still nothing else |
| `COFFRE_ID_TOKEN`, `COFFRE_ID_TOKEN_FILE` | `coffre login <url> --service <name> --id-token`, the ID token piped in |
| `COFFRE_AUTH_MODE` | `--auth-mode signin\|cloudflare` |
| `COFFRE_MIGRATE_DATABASE_URL` | `coffre migrate` asks, or the URL piped in: `printenv DATABASE_OWNER_URL \| coffre migrate --yes` |
| `COFFRE_SETUP_DATABASE_URL` | `coffre setup` asks, or the URL piped in |
| `COFFRE_VAULT_KEY`, `COFFRE_APP_KEY` | `coffre verify keys` asks, or both piped in, the vault key's line first |
| `COFFRE_VAULT_KEY_ID` | `coffre verify keys --vault-id <id>`, as before |
| `COFFRE_CONFORMANCE_CANARY` | `coffre verify instance --canary <path>` asks for the value, or it is piped in |
| `coffre set <path> <value>` | `coffre set <path>`, the value asked for or piped in |
| `coffre verify instance --canary <path>=<value>` | the same, the value asked for or piped in |
| `coffre migrate --url <url>` | `coffre --url <url> migrate` |

`coffre logout` forgets a service token's or an Access service token's
session there, and revokes nothing: the token is the service's. A machine
sign-in never replaces a person's session unseen: they sign out first, or
the run signs in from a home of its own. `coffre set` refuses an empty
value, which an unset variable piped in would be, and takes one as it is,
at the prompt or piped, less exactly one final line break. An empty
session flag, which is what an unset variable expands to, an instance named
both as an argument and as `--url`, a session flag after the command, and
one a command has no use for are refused. When the instance does not know
the session saved for it, as after it was reset at the same address, the
CLI says so and names `coffre login <url>`. The GitHub Action's inputs are
as they were; it pipes the token to `coffre login --token`, the CLI in a
home of the step's own, removed when the step ends. On Workers Builds, rename the vault's
build variable `COFFRE_MIGRATE_DATABASE_URL` to `DATABASE_OWNER_URL`, and
its build command to `printenv DATABASE_OWNER_URL | pnpm exec coffre migrate
--yes` ([Workers Builds](docs/deploy.md#workers-builds)). On GitLab, name the
ID token anything but `COFFRE_ID_TOKEN`, and pipe it to `coffre login
--service <name> --id-token` ([docs/ci.md](docs/ci.md#without-a-stored-token)).

**`coffre setup` on Workers takes an address whose DNS is elsewhere.** A
Worker answers only at an address Cloudflare serves, so setup makes it a
custom hostname of one of the account's domains, with Cloudflare for SaaS,
on the Free plan: it keeps or makes the domain's fallback origin, makes the
custom hostname, shows the CNAME and TXT records to add at the address's
DNS provider, and, after the deploy, waits for Cloudflare to see them. A
run stopped there picks up where it left off. With no domain on the
account, setup offers to add one, showing its nameservers, or the Worker's
workers.dev address for now. This needs Cloudflare for SaaS enabled on the
domain. When Cloudflare refuses wrangler's login a call this needs, setup
asks for an API token, hidden, saying which permissions it needs, and its
wranglers deploy under it ([deploy.md](docs/deploy.md#a-domain-whose-dns-is-elsewhere)).

**A deployment's app is a TanStack Start app of its own** (0.2.0), a
conventional one, and coffre is a set of pieces it mounts, as an auth SDK's
are. Vite builds the app once, and nothing bundles it again: on Workers,
`wrangler deploy` uploads what Vite built, so no second pass rewrites what
the pages send the browser, as wrangler's `keep_names` did in 0.1.17. On
Node, srvx runs the same build, as TanStack Start documents, and the
vault stays a process of its own. The app's files, as `coffre init` writes
them:

- `app/src/coffre.ts`: the configuration, once, `export const coffre =
  createCoffre(…)`;
- `app/src/server.ts`: Start's handler, each request carrying coffre,
  `handler.fetch(request, { context: coffre.request(…) })`, and coffre's
  scheduled job;
- `app/src/start.ts`: `createStart(() => ({ requestMiddleware: [coffreMiddleware,
  createCsrfMiddleware(…)] }))`. coffre's middleware gives every response
  coffre's security headers and a fresh CSP nonce, and the pages the
  visitor's API client. A server route or page rendered without it fails,
  saying how to add it. Start's CSRF check for server functions, which Start
  drops once an app sets middleware of its own, stays for the app's;
- `app/src/routes/`: Start's file routes. The root, the app's own
  document, with coffre's stylesheet and icons and `<CoffreProvider>`; and a
  file for each of coffre's server routes, layouts and pages, each spreading
  coffre's route options: `createFileRoute('/_coffre/projects/')({ ...projects,
  component: ProjectsPage })`. Start splits each page into a chunk of its
  own, with its preload hints. Delete a page's file to leave it out; add
  files for the app's own pages, under coffre's nav or not. coffre's nav
  offers only the pages there. A page of the app's own may call the API as
  the signed-in visitor, `useCoffre()` in a component or `context.coffre` in
  a loader. An app that prefers routes in code mounts the same options with
  TanStack's `createRoute` ([Your own routes](docs/deploy.md#your-own-routes));
- `app/src/router.tsx`: `createRouter(routeTree)`, Start's generated tree;
- `app/vite.config.ts`: `cloudflare(…)` on Workers, `tanstackStart()`,
  `viteReact()`, and `coffre()` from `@coffre/ui/vite`, which puts the
  pages' files under `/_coffre/assets/` and checks the versions below.

The theme and the folded sidebar are cookies now, `coffre-theme` and
`coffre-sidebar`, which the server reads, so a page is drawn as the visitor
left it from the first byte, with no script of coffre's own before it: a
theme chosen before 0.2, kept in the browser's storage, is chosen once more.
coffre's look is scoped to the element `<CoffreProvider>` renders; the
app's document keeps its own.

React, TanStack Router, Start, Query and Vite are the deployment's own
dependencies now, pinned at exactly the versions `@coffre/ui` is built with;
`coffre update` moves them with coffre's packages, and adds the file of a
page a release adds. On Workers, `pnpm dev` is
now `vite dev app`, the vault beside the app. A refusal no longer waits for
the request's body: nothing in coffre reads what a caller is still sending
before answering.

To upgrade, in the deployment's directory, with the 0.2 CLI:

```sh
npx @coffre/cli@0.2.0 update
```

It moves a deployment whose files are as a release of 0.1 wrote them, its
configuration kept as that release had it, and shows each file it changes
before asking once. It changes nothing when a file is the deployment's own,
or one is already where 0.2 puts its own: it names each, and
[Upgrading to 0.2](docs/deploy.md#upgrading-to-02) shows the move by hand.
A move cut short is finished by the next run. Then `pnpm typecheck`, and
deploy: on Workers Builds, the app's build command is now `pnpm exec vite
build app` and its deploy command `npx wrangler deploy -c
app/dist/server/wrangler.json`; `pnpm run deploy` does both. On Node,
`pnpm build`, then restart both processes.

**Workers deployments: signed-in pages no longer go blank.** wrangler bundles
with esbuild's `keep_names` on, which wraps functions in an `__name` helper
that only the Worker has; seroval, which streams a page's data, writes its own
functions into the page as source, and with them the `__name` calls: in the
browser, `ReferenceError: __name is not defined`, then a blank page.
`app/wrangler.jsonc` now sets `"keep_names": false`, as `coffre init` writes
it, and `coffre update` offers to set it in an existing deployment, showing the
lines it adds. Deploy the app after. Node deployments were not affected.

Conformance loads the pages in a real browser: signed in, `/projects`, a
project and `/audit`, in headless Chrome, with no console error. Without a
Chrome on the machine, the check is skipped and says so; `--browser <path>`
names one.

`coffre setup` in a fresh clone of a deployment, with no `node_modules`,
installs it first, as its lockfile says, before Cloudflare's sign-in runs the
deployment's own wrangler: it no longer fails with `spawn …/wrangler ENOENT`.
An install that fails says why in a sentence. `coffre update` installs such
a clone as it was before moving it, so that the migrations it says the
release adds are counted from the deployment's own.

`coffre update` recognizes a CLI installed globally with pnpm 11, which
keeps it in its store's `links/` directory, and updates it with `pnpm add -g`
instead of calling it a dependency of that directory. It asks npm and pnpm
where their globals are (`ls -g`), with pnpm's `PNPM_HOME` when pnpm can't
answer; when neither claims the CLI, it says so and prints what each manager
would run. Run in a deployment, `pnpm coffre update` now knows its CLI as
one of the deployment's packages.

`coffre update` moves a deployment from pnpm 10 to 11 without a terminal:
pnpm's question about removing `node_modules` no longer stops it. When a
lockfile another pnpm wrote holds a package too young for this one, it first
resolves again for versions old enough, and lists every version that moved;
only when no older version fits does it offer to wait or to let the package
through. An install that fails leaves `package.json`, `pnpm-workspace.yaml`
and `pnpm-lock.yaml` as they were, byte for byte, and says so.

Deployments pin pnpm: `coffre init` writes `"packageManager": "pnpm@11.8.0"`,
and `coffre update` adds it to a deployment that lacks it, so every
install, Workers Builds' included, holds `minimumReleaseAge` alike. When
pnpm holds a package back, `coffre update` says when it is old enough, and
offers to wait or to let it through by name until then, never silently.

`coffre update` and `coffre migrate` upgrade a deployment: update the CLI
and the deployment's coffre packages, deploy, then migrate the database
with the owner's URL, asked for at a hidden prompt. `coffre migrate` first
checks that the instance runs the CLI's own version, and shows what it will
apply. `/me` now tells owners and root admins the version an instance runs
and how many of its migrations the database has applied; owners see a
banner while some are pending, and the CLI says so once a day. `pnpm
migrate` stays, for automation. [Upgrading](docs/deploy.md#upgrading).

Syncs are removed; use a service token with `coffre run` or `coffre export`,
or the GitHub Action.

Before upgrading, **check for syncs**, including archived destinations:

```sql
SELECT id, provider, created_by, archived_at FROM syncs;
SELECT sync_id, key FROM sync_keys;
```

The migration refuses to run if either table has any rows, rather than
silently discard a configured destination. Move each destination to your
CI/deploy pipeline, which already has its platform's write credentials.
Back up the database, then deploy the new vault and app before migrating;
they work with the old schema. Once old versions have stopped receiving
requests and scheduled events, have the database owner clear `sync_keys`
and then `syncs` after the destinations have been migrated, and run
`pnpm migrate` with the owner URL. An old app can create new syncs; do not
restart it. [Workers upgrade steps](docs/deploy.md#upgrading-to-0112-with-workers-builds)
include the exact command and login.
Remove unneeded third-party tokens stored as ordinary coffre secrets and
revoke those tokens with their issuers. Removing a sync never revoked copies
of values already pushed to an external platform.

The new migration drops both sync tables and their references on Postgres
and SQLite. All old migration files remain immutable. Past `sync.*` audit
entries, checkpoints, sealed legacy members and grants remain unchanged:
the log still verifies and the audit page still renders its human sentences.
Legacy sync principals can no longer read values or acquire new grants.

# Release notes

## Unreleased

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
session there, and revokes nothing: the token is the service's. An empty
session flag, which is what an unset variable expands to, an instance named
both as an argument and as `--url`, a session flag after the command, and
one a command has no use for are refused. When the instance does not know
the session saved for it, as after it was reset at the same address, the
CLI says so and names `coffre login <url>`. The GitHub Action's inputs are
as they were; it pipes the token to `coffre login --token`, and forgets
that session when its step ends. On Workers Builds, rename the vault's
build variable `COFFRE_MIGRATE_DATABASE_URL` to `DATABASE_OWNER_URL`, and
its build command to `printenv DATABASE_OWNER_URL | pnpm exec coffre migrate
--yes` ([Workers Builds](docs/deploy.md#workers-builds)). On GitLab, name the
ID token anything but `COFFRE_ID_TOKEN`, and pipe it to `coffre login
--service <name> --id-token` ([docs/ci.md](docs/ci.md#without-a-stored-token)).

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

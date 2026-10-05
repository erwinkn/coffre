# AGENTS.md

`coffre` is a pnpm monorepo secrets manager, shipped as packages a deployment imports
and configures in code: `packages/server` (`@coffre/server`: `/api`, sign-in,
its queries in `src/db`; `/cloudflare` and `/node` entry
points), `packages/db` (`@coffre/db`: the Drizzle schemas for Postgres and SQLite, their
migrations and migrator, the dialect helpers, and the connections, Hyperdrive's
included), `packages/ui` (`@coffre/ui`: the TanStack
Start pages as a library, route options a deployment's own Start app mounts as file
routes, and `@coffre/ui/vite`, the Vite plugin its build adds), `packages/vault` (`@coffre/vault`: keys, grants, members, its
entries in the shared log), `packages/client` (the typed API client the CLI and UI call), `packages/cli`
(`coffre`, including `coffre init`), `packages/conformance` (`@coffre/conformance`:
`coffre-conformance`, which boots a deployment and holds it to what it must never do,
and the dev IdP, `@coffre/conformance/idp`, the local stand-in for Cloudflare Access,
GitHub and OIDC), and `packages/core` (`@coffre/core`: access rules, the audit chain,
envelope encryption, vault keys, identity and sign-in, and the contract between server and
vault in `src/vault.ts`). `examples/workers` and `examples/node` are deployments,
exactly what `coffre init` writes (a test diffs them); each one's `app/` is a
conventional TanStack Start app, built once by Vite, whose file routes
(`app/src/routes/`, and the generated `routeTree.gen.ts`, committed) mount coffre's
route options (`@coffre/ui`, `@coffre/server/routes`), whose `start.ts` adds coffre's
middleware (`@coffre/server/start`), and whose server entry hands each request coffre as
its context (`docs/architecture.md`, "The UI"); on Node, srvx runs the built app. `dev/` holds what only the dev
loop uses and nothing ships: `dev/start.sh` (`pnpm dev`), the deployment it runs, the
dev IdP's launcher (`dev/idp`) and the seed. `scripts/` holds what dev, tests and CI share. The root `README.md` and the
`package.json` scripts are the source of truth for commands; this file only adds what
they leave implicit.

## Packages

A package imports another only by name (`@coffre/core/vault`, never
`../../core/src/vault.ts`); the `coffre/package-imports` lint rule holds every
`src`, `test` and `scripts` to it, so each package builds, ships and can be
internalized into a deployment on its own. The `@coffre/*` dependencies are
`workspace:*` and every package carries one version: `pnpm bump <version>` moves
them all and the examples' pins, and says whether any dependency the release
pins is younger than the week deployments wait, for the release notes;
`pnpm check:pins` fails on any drift, including the examples' `packageManager`,
which must be the workspace's pnpm.

Every package's `exports` lists a `coffre:source` condition first, pointing at
`src/*.ts`. Inside the workspace, dev, tests and typecheck turn it on and read the
other packages' sources: `tsconfig.base.json` (`customConditions`), Node
(`--conditions=coffre:source`, in every test script and in `pnpm coffre`), and
`dev/deployment/app/vite.config.ts` (every Vite environment). Builds leave it off and read each
other's `dist/`, in pnpm's dependency order, as `dev/deployment` and the examples
do in their typecheck, like any deployment. Published, the condition is inert.
Running a package's `.ts` with plain `node` outside those scripts needs the flag.

## Setup

**Toolchain.** Node **>= 24** and pnpm 11.8.0 (via corepack). Node 24 is a hard requirement
for workspace source, not just an `engines` field: the CLI, dev IdP, migrations, and the
`node --test` suite all execute TypeScript source (`*.ts`) directly with plain `node`,
which relies on native type-stripping (default only in Node 23.6+/24). The
published CLI is bundled JavaScript targeting Node 20 and runs on Node >= 20;
this does not relax the workspace's or deployments' Node 24 requirement.
`pnpm install` itself is version-agnostic.

**Database.** Postgres runs in Docker via `docker compose` on **:55432** (owner
`coffre_owner`, restricted runtime logins `coffre_runtime` for the app and
`coffre_vault_runtime` for the vault). The running app and all the
DB-backed tests need it up. Export `COMPOSE_PROJECT_NAME=coffre` whenever you invoke
`docker compose` directly.

`scripts/ensure-postgres.sh` reuses a healthy or initializing container and
serializes cold starts across worktrees with the host's advisory lock
(`flock` on Linux, `lockf` on macOS), then starts with `--no-recreate`. CI reserves 55432 from Linux's outgoing port allocation before
package downloads; the port is inside the default outgoing range. The
reservation script is CI-only and does not change a developer's host.

**Run the stack.** `pnpm dev` brings up Postgres + dev IdP (:8081) + coffre (:3000) +
seed data. It runs `dev/deployment/`, shaped like `examples/workers` (`app/`, a
Start app, and `vault/`), under `vite dev`, with the vault as an auxiliary Worker
beside the app and no port of its own. Its routes are files, as the examples', and
its root renders the Agentation toolbar. `dev/deployment/app/vite.config.ts` resolves
every `@coffre/*` import, the config's own included, to its sources through
`coffre:source`, so an edit to any package, a page or a route hot-reloads without a
build. The vault keeps its members, grants and log entries in the same
Postgres database, through its own login and Hyperdrive binding, and the
seed starts them over with everything else. `COFFRE_DEV_PORT`, `COFFRE_DEV_IDP_PORT` and `COFFRE_DEV_DATABASE` run a
second stack beside the first (see `dev/start.sh`). Sign in at
`http://127.0.0.1:3000/login`, through either button (the dev IdP plays GitHub and
an OIDC provider), as `admin@acme.example` (root admin) or any of the seeded
personas; the seed signs in the same way. CLI: `pnpm coffre <cmd>` from the root;
`pnpm coffre login http://127.0.0.1:3000` once, a device login approved in the
browser, and its session is the default after.

**Config is code.** The packages read no environment variable of their own; a
deployment passes everything to `createCoffre(…)`, `vault(env => …)` or
`serveVault({…})`. The CLI reads none either. Flags configure: the session flags,
before the command (`coffre --url … --service … export …`), say which instance and,
for a CI run's ID token, which service. A secret is never a flag or an argument: the
command asks for it at a hidden prompt, or reads it from stdin when that is no
terminal (`packages/cli/src/secret.ts`); a CI run signs in with `coffre login <url>
--token` and the like, which save its session. A variable an earlier CLI read stops
the command that read it, saying what to do instead (`packages/cli/src/flags.ts`). The env vars left are `DATABASE_URL` for `coffre-server
migrate`, the platforms' own the CLI uses (GitHub's `ACTIONS_ID_TOKEN_REQUEST_*`,
`GITHUB_ENV`), and the dev and test tooling's (`COFFRE_DEV_*`, `COFFRE_STATE_DIR`,
`COFFRE_TEST_ENGINE`, `COFFRE_TEST_DATABASE`). Don't add another to a package or the
CLI.

**Migrations: expand, then contract.** A deployment runs `coffre migrate` in
its pipeline, before it deploys, so each migration first meets the previous
release's code, and must work with it as well as with the code it ships:
the old code on the new schema, and the new code on the old schema until it
runs. Then the order of migrating and deploying does not matter. So a
migration adds: tables, columns that are nullable or have a default,
indexes, grants. What removes or tightens (dropping or renaming a table or a
column, NOT NULL on an existing column, a narrower check or type, a unique
or foreign key the old code may break) ships one release after the code
stops using it. `pnpm test:compat` holds the newest release to this
checkout's schema, through that release's own conformance; it would have
caught `0001_remove_syncs`, which dropped tables 0.1.11 still read.

**Transactions and the vault.** No app database transaction may stay open across
any vault call. Prepare outside SQL; commit app writes and their audit together,
taking the audit head before application rows. Reads commit their app audit before
returning values. The integration fixture tracks transactions and rejects vault
calls made inside them, including errors swallowed by handlers or background jobs.

**What an isolate keeps.** On Workers, every call opens its own database
and its I/O belongs to it; the isolate keeps state between calls (the vault's
prepared state, config caches). Keep only settled values there, never a
pending promise: a call that awaits another call's in-flight work is
cancelled as hung on Cloudflare when that call goes, which local workerd
does not reproduce. Concurrent first calls each do their own reads
(`packages/vault/test/isolate.test.ts`).

**One connection per call.** On Workers, each app request and each vault
call has one Postgres client through Hyperdrive (`HyperdrivePool` in
`@coffre/db`), connected on its first query. Its queries take turns on it,
and a transaction holds it from BEGIN to COMMIT. So code inside a
transaction queries through its `tx`, never the database: a query on the
database would wait for the transaction, which waits for it. `createDatabase`
refuses one at once, on Node too, so the suites catch it: each transaction's
work runs in an `AsyncLocalStorage` naming it, and a query or a transaction
asked of its pool from there throws `QueryOutsideTransaction`. A call that
opened several Hyperdrive connections at once was now and then cancelled
as hung on Cloudflare (`packages/vault/test/workers.test.ts` counts them).
A request asks the vault about its caller once: a page's render checks its
credential once for all its API calls (`pageClient`).

**Tests / checks.**
`Validate` runs the full CI suite except for a proven, synchronized version
bump. `scripts/version-only.mjs` compares Git objects and rejects any edit
beyond package versions, example pins, their lockfile specifiers and the
Action's literal CLI pin. The detector and gate tests run even on that
fast path. Parse errors or an unsupported diff select full validation.

- `pnpm test` = lint + migrate a scratch template + `node --test --test-concurrency=4`.
  Each file gets a private Postgres clone or SQLite copy; cases within a file remain
  sequential and reset per test. Templates and clones are removed after the run.
  `COFFRE_TEST_DATABASE` sets the scratch name prefix; a random suffix isolates
  simultaneous runs and other checkouts sharing compose Postgres. `pnpm test:schema`
  still recreates the exact database it names. Needs Postgres.
- `pnpm test:sqlite` runs the same suite on SQLite (`COFFRE_TEST_ENGINE`);
  `pnpm test:all` runs Postgres and SQLite. SQLite needs nothing and is kept
  for tests and local development; deployed app databases use Postgres.
- `pnpm test:schema` verifies both runtime logins' privileges. It also runs the
  full migration as a non-superuser owner in a disposable Postgres cluster,
  checks TLS trust and hostname verification, and runs `coffre setup` against
  another disposable cluster (`scripts/test-setup.sh`), as its superuser and
  as such an owner: setup makes cluster-wide roles, so never on the shared
  one. Postgres only.
- `pnpm build` builds every package in dependency order (core and client first). The
  UI builds as a library, `vite build`, each page a module of its own
  (`@coffre/ui/pages/<name>`), which the examples' file routes name, and Start splits. Core and client build
  in a run of their own: core's tests use conformance's dev IdP, and
  conformance runs the CLI, which bundles core, so the graph has a cycle that
  pnpm would order as it likes. The CLI's build fails on an import it cannot
  resolve rather than ship it. Conformance, the examples' typecheck and
  `test:consumer` want it first.
- `pnpm conformance:workers` / `pnpm conformance:node` run an example's own
  `pnpm conformance` (`docs/conformance.md`), on ports 3082 to +2; add `--port <n>`
  for another three. Each first builds the example's app with its own Vite, as it
  deploys; Workers then runs `app/dist/server/wrangler.json`, which wrangler does not
  bundle again, behind an entry of the harness's own that reads an unread request
  body (locally, wrangler fails the next request otherwise; coffre never waits on one). Workers needs Postgres and makes its own
  `coffre_conformance_<hex>` database, dropped after; Node runs on SQLite in a temp
  dir, the built app under srvx, as its `pnpm start`. Each holds the build's client
  files to holding no server code (`packages/conformance/src/bundle.ts`): a deployment's
  own build no longer checks. A check that fails prints what it saw, then the processes'
  output.
- `pnpm test:compat [--kind workers|node] [--release <v>] [--schema <v>]` installs
  the newest release from npm as `init` writes it, has its own conformance
  migrate with this checkout's migrations, and requires it conformant; then
  requires a synthetic destructive migration to fail it. `--schema` applies a
  published version's migrations instead, to check past releases. It needs
  network and Postgres.
- `pnpm test:consumer [<dir>]` packs the eight packages, runs the packed CLI's
  `init` for both kinds outside the workspace, diffs them against the examples,
  installs the tarballs (pnpm overrides, no workspace links), then typechecks,
  builds and runs conformance on each. It needs network for third-party packages.
- `pnpm formal` model-checks the locking protocol, `formal/Coffre.tla`, with
  TLC (`docs/formal.md`): every scenario must hold, and each again without one
  of the code's protections must fail. It needs Java 11+, and downloads TLC's
  jar once, checked against its pinned SHA-256. A change to the locks a flow
  takes, or what it re-checks under the head, changes the model too.
- `pnpm lint`, `pnpm check:pins`, `pnpm check:contrast` and `pnpm check:docs`
  (every path, script and link the docs name exists) do not need Postgres.
- `scripts/restore-drill.sh` (after `pnpm build`) backs up a seeded Workers
  stack with `pg_dump`, restores it, and checks it came back, then the
  wrong-key case, on ports 3400 to 3402 and 8481 and databases `coffre_drill` and
  `coffre_drill_restored` (`COFFRE_DEV_PORT`, `COFFRE_DEV_IDP_PORT`,
  `COFFRE_DRILL_DATABASE`; `docs/restore.md`). It drops its databases and stops its
  processes however it ends.
- `pnpm typecheck` covers every package, `dev/deployment` and both examples. It does
  not need Postgres, but on a fresh checkout it fails until `pnpm build` has run:
  that writes the `dist/` the deployments typecheck against.
- Run an example's scripts from the root, `pnpm --filter coffre-workers <script>`, not
  with `--dir`: each example has its own `pnpm-workspace.yaml` (as `init` output
  needs), so pnpm would treat it as a separate, uninstalled workspace.

**Dependencies.** `pnpm install` enforces exact pins, `ignore-scripts`, and a 7-day
`minimumReleaseAge` (`pnpm-workspace.yaml`). Add deps with `pnpm run add:dep`
(`--save-exact`), never a bare `pnpm add` (it writes caret ranges).
The examples pin `@coffre/*` at the packages' version, and `linkWorkspacePackages` links
them to the workspace; `pnpm bump` keeps them in step. `@coffre/ui`'s peers (React, react-dom,
TanStack Router, Start, Query, its SSR integration, and Vite) are exact pins too, and
each example pins them at exactly those versions: `pnpm check:pins` fails on drift, as
does a deployment's own build (`@coffre/ui/vite`), and `coffre update` moves them with
coffre's packages. `@coffre/server` peers on the same TanStack, and both depend on
`@tanstack/router-core` at the version react-router does: their declarations import
it, and a copy of its types would lack react-router's additions (`check:pins`). The same `minimumReleaseAge`
is in each example's `pnpm-workspace.yaml`, so in every deployment `init` writes,
with `@coffre/*` exempt so that a coffre fix is not held back a week.

## Cursor

The Cloud Agent environment is defined in-repo by `.cursor/environment.json` and
`.cursor/Dockerfile` (Node 24 via nvm, pnpm 11.8.0 via corepack, and a Docker engine set
up for the nested VM). Two things worth knowing:

- **Docker and Postgres** come up each boot via `.cursor/start.sh`
  (`sudo service docker start`, then compose Postgres). PID 1 is tini, not
  systemd; the SysV script is what actually starts dockerd. Snapshot compose
  containers are dead until recreated. `/var/run` is not a symlink to `/run`
  here; snapshots and `service docker start` can leave it `0700`, so the
  script `chmod 755`s it *after* the daemon is up or `ubuntu` cannot see
  `docker.sock`. If `docker info` fails or `:55432` is down, re-run that
  script. Web and the dev IdP are started by `pnpm dev`, or by hand.
- **Node on PATH.** The Cloud runtime injects its own Node 22 ahead on `PATH`, so the
  image prepends the nvm-managed Node 24 in `~/.bashrc` (above the stock interactive-guard
  early return, since the runtime sources it for non-interactive shells too) and in
  `/etc/profile.d`. If `node -v` ever shows 22, that prepend did not run.

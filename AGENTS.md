# AGENTS.md

`coffre` is a pnpm monorepo secrets manager, shipped as packages a deployment imports
and configures in code (`packages/*`, listed in the README's "Layout"). `examples/workers`
and `examples/node` are deployments, exactly what `coffre init` writes (a test diffs them);
`docs/architecture.md`, "The UI", says how their Start apps mount coffre. `dev/` holds what
only the dev loop uses and nothing ships; `scripts/` holds what dev, tests and CI share.
The root `README.md` and the `package.json` scripts are the source of truth for commands;
this file only adds what they leave implicit.

## Writing code here

- A function takes at most 10 arguments, in SQL and in TypeScript. More needs a written reason at the function.
  Defaults, named notation, a session setting or a wrapper object that hides the count are not fewer arguments.
  `packages/db/test/collapse.test.ts` lists the SQL functions over the limit; the list only shrinks.
- No mode flags. A boolean or nullable argument that picks a code path means two functions.
- A rule lives once, in one language. No SQL copy of a TypeScript check.
- What a deployment's config fixes is not passed on each call.
- No code for a state that cannot exist. If the upgrade check, a constraint or a type rules it out, nothing handles it.
- Every lock, cache and special case names the failing test or the measurement that needs it. One with neither is deleted.
- Before adding a branch for an edge case, try to make the case impossible.
- Comments say what the code does now, in plain sentences. No worker, task, decision or review IDs, no history.
- Prefer the PR that deletes.
- A PR title and a commit subject say what changes. IDs go in the PR body only.

## Packages

A package imports another only by name (`@coffre/core/vault`, never
`../../core/src/vault.ts`); the `coffre/package-imports` lint rule holds every
`src`, `test` and `scripts` to it, so each package builds, ships and can be
internalized into a deployment on its own. The `@coffre/*` dependencies are
`workspace:*` and every package carries one version: `pnpm bump <version>` moves
them all (README, "Releasing"). A release is that bump, a commit and a PR, with
no `pnpm install` or hand edit.

Every package's `exports` lists a `coffre:source` condition first, pointing at
`src/*.ts`. Inside the workspace, dev, tests and typecheck turn it on and read the
other packages' sources: `tsconfig.base.json` (`customConditions`), Node
(`--conditions=coffre:source`, in every test script and in `pnpm coffre`), and
`dev/deployment/app/vite.config.ts`. Builds leave it off and read each
other's `dist/`, as `dev/deployment` and the examples do in their typecheck.
Running a package's `.ts` with plain `node` outside those scripts needs the flag.

## Setup

**Toolchain.** Node and pnpm are pinned by `.node-version` and `packageManager`.
Node 24 is the floor for workspace source: the CLI, dev IdP, migrations and the
`node --test` suite run `*.ts` directly with native type-stripping. The published CLI
and client target Node 20. A toolchain move picks the latest release of the latest major
(Node: its latest LTS line) with no known vulnerability and at least 7 days old.
In a Cursor Cloud Agent, see `.cursor/README.md` (Docker restart, Node on PATH).

**Database.** Postgres runs in Docker via `docker compose` on **:55432** (owner
`coffre_owner`; restricted logins `coffre_runtime`, `coffre_vault_runtime` and
`coffre_vault_hot`). The running app and all the DB-backed tests need it up
(`pnpm db:up`). Export `COMPOSE_PROJECT_NAME=coffre` whenever you invoke
`docker compose` directly. A Postgres of your own, beside the shared one, is a
project and a port of its own: `COMPOSE_PROJECT_NAME=coffre_mine
COFFRE_POSTGRES_PORT=56432 pnpm test` starts it, and every script, test and
fixture connects to that port; `ensure-postgres.sh` refuses a project already
up on another. If it refuses a container whose address routes off its bridge, give
the project its own `COFFRE_POSTGRES_SUBNET` and export it for every run.

**Run the stack.** `pnpm dev` runs `dev/deployment/` on the packages' sources, so an
edit anywhere hot-reloads. `COFFRE_DEV_PORT`, `COFFRE_DEV_IDP_PORT` and
`COFFRE_DEV_DATABASE` run a second stack beside the first (`dev/start.sh`). Sign in at
`http://localhost:3000/login`, not 127.0.0.1: browsers make passkeys for a name only.
CLI: `pnpm coffre <cmd>` from the root; `pnpm coffre login http://localhost:3000` once.

**Config is code.** The packages read no environment variable of their own; a
deployment passes everything to `createCoffre(…)`, `vault(env => …)` or
`serveVault({…})`. The CLI reads none either. Flags configure: the session flags,
before the command (`coffre --url … --service … export …`), say which instance and,
for a CI run's ID token, which service. A secret is never a flag or an argument: the
command asks for it at a hidden prompt, or reads it from stdin when that is no
terminal (`packages/cli/src/secret.ts`); a CI run signs in with `coffre login <url>
--token` and the like, which save its session. The env vars left are `DATABASE_URL` for `coffre-server
migrate`, the platforms' own the CLI uses (GitHub's `ACTIONS_ID_TOKEN_REQUEST_*`,
`GITHUB_ENV`), and the dev and test tooling's (`COFFRE_DEV_*`, `COFFRE_STATE_DIR`,
`COFFRE_TEST_DATABASE`, `COFFRE_TEST_RESTORED_DATABASE`, `COFFRE_TEST_SHARD`, `COFFRE_TEST_SHARD_REPORT`, `COFFRE_POSTGRES_PORT`, `COFFRE_CLIENT_NODES`, `COFFRE_SWEEP_SIZE`, `COFFRE_SWEEP_OUTCOMES`, `COFFRE_SWEEP_KEEP`). Don't add another to a package or the
CLI.

**Migrations: expand, then contract.** A deployment runs `coffre migrate` in
its pipeline, before it deploys, so each migration first meets the previous
release's code, and must work with it: the old code serves on the new schema
until the deploy. The new code never meets the old schema: below its migrations,
the app answers everything but `/livez` and `/readyz` with 503 `migrating`, at one
door (`respond` in `packages/server/src/app.ts`), so no code checks whether a
migration has run. So a migration adds: tables, columns that are nullable
or have a default, indexes, grants. A migration that makes a table grants
`SELECT` on it to `coffre_backup`, by name, as it grants `coffre_app`;
`pnpm test:schema` fails on a table the backup cannot read. What removes or tightens (dropping or
renaming a table or a column, NOT NULL on an existing column, a narrower
check or type, a unique or foreign key the old code may break) ships one
release after the code stops using it. `pnpm test:compat` holds the newest
release to this checkout's schema; it is off until 0.16.0 is tagged.
0.16.0 is a clean break: one offline upgrade from 0.15.0. Until the 0.16.0 tag a migration
may drop, rename and tighten, and keeps no overload, column or branch for 0.15.0's code.
Expand-then-contract applies again from 0.16.0 on.

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
(`packages/vault/test/isolate.test.ts`). The app's once-per-isolate asks
(the vault's `about()`, the proxy's gate) go through `packages/server/src/asked-once.ts`,
whose header says how.

**One connection per call.** On Workers, each app request and each vault call has
one Postgres client through Hyperdrive, and a call that opened several was cancelled
as hung. Code inside a transaction queries through its `tx`, never the database
(`QueryOutsideTransaction`). A transaction reads what it needs together
(`Promise.all`) and leaves the writes whose answer it does not need to `later`
(`@coffre/db`): two round trips, which `packages/server/test/change-cost.test.ts`
holds each change route to. A request asks the vault about its caller once.
`docs/architecture.md`, "One connection per call", has the rest.

**Tests / checks.** No pull request runs CI. A change merges on `pnpm validate`, run
by its author on its exact head, rebased on `main`. It runs what the diff against
`origin/main` can change (`scripts/affected.mjs --list` shows what and why); `--full`
runs everything, and before a tag a local `--full` is the growth sweep's only run.
When `main` moves after a gate and the rebase is mechanical (clean, or conflicting only
in a migration or `CHANGELOG.md`, `git range-diff` showing the patch unchanged), run
it again and put the summary and the `git range-diff` verdict on the PR; any other
conflict gets a scoped review too.
Node's conformance is off at the gates until 0.16.1: Node is built and typechecked, nothing more.

- `./scripts/test-suite.sh --files <file>...` runs some test files (`--serial` first:
  one at a time). `pnpm test` runs lint and the whole suite, then the files that hold a
  statement's work, pages or locks to a budget (`packages/*/test/*.alone.ts`) one at a
  time, since another test's migration in the same cluster would upset them. Needs Postgres.
- `pnpm test:matrices` outlasts its own timeout unsharded, so `pnpm test` leaves it out:
  `COFFRE_TEST_SHARD=<k>/<n>` runs one shard. A new matrix passes its cases through `shardOf`.
- `pnpm test:schema` runs `coffre setup`, which makes cluster-wide roles, against
  disposable clusters (`scripts/test-setup.sh`): never on the shared Postgres.
- `dev/deployment` and the examples typecheck against the `dist/` the build writes, so
  on a fresh checkout `pnpm typecheck` fails until `pnpm build` has run.
- `pnpm sweep:growth` logs every plan: run it on a Postgres of your own only.
- A change to the locks a flow takes, or what it re-checks under the head, changes
  `formal/Coffre.tla` too (`pnpm formal`). A change to the access rules, the vault's
  per-key decision, the AAD or the chain verifier changes `formal/lean` in the same
  pull request (`pnpm formal:lean`).
- Run an example's scripts from the root, `pnpm --filter coffre-workers <script>`, not
  with `--dir`: each example has its own `pnpm-workspace.yaml` (as `init` output
  needs), so pnpm would treat it as a separate, uninstalled workspace.

**Dependencies.** `pnpm install` enforces exact pins, no install script
unless `allowBuilds` names it `true` with its reason (none is), and a 7-day
`minimumReleaseAge`, which `check:pins` refuses to shorten. Each example carries the same
age gate, with `@coffre/*` exempt so a coffre fix is not held back a week. Add deps with
`pnpm run add:dep` (`--save-exact`), never a bare `pnpm add` (it writes caret ranges).
`@coffre/ui`'s peers (React, react-dom, TanStack Router, Start, Query, its SSR
integration, and Vite) are exact pins too, and each example pins them at exactly those
versions; `@coffre/server` peers on the same TanStack, and both depend on
`@tanstack/router-core` at the version react-router does, or a copy of its types would
lack react-router's additions. `pnpm check:pins` fails on drift.

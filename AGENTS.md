# AGENTS.md

`coffre` is a pnpm monorepo secrets manager, shipped as packages a deployment imports
and configures in code: `packages/server` (`@coffre/server`: `/api`, sign-in, syncs and
their providers in `src/sync`, the Drizzle schema, queries and migrations in `src/db`;
`/cloudflare` and `/node` entry points), `packages/ui` (`@coffre/ui`: the TanStack
Start pages, prebuilt), `packages/vault` (`@coffre/vault`: keys, grants, members, its
own log), `packages/client` (the typed API client the CLI and UI call), `packages/cli`
(`coffre`, including `coffre init`), `packages/conformance` (`@coffre/conformance`:
`coffre-conformance`, which boots a deployment and holds it to what it must never do,
and the dev IdP, `@coffre/conformance/idp`, the local stand-in for Cloudflare Access,
GitHub and OIDC), and `packages/core` (`@coffre/core`: access rules, the audit chain,
envelope encryption, KEKs, identity and sign-in, and the contract between server and
vault in `src/vault.ts`). `examples/workers` and `examples/node` are deployments,
exactly what `coffre init` writes (a test diffs them). `dev/` holds what only the dev
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
them all and the examples' pins, and `pnpm check:pins` fails on any drift.

Every package's `exports` lists a `coffre:source` condition first, pointing at
`src/*.ts`. Inside the workspace, dev, tests and typecheck turn it on and read the
other packages' sources: `tsconfig.base.json` (`customConditions`), Node
(`--conditions=coffre:source`, in every test script and in `pnpm coffre`), and
`dev/vite.config.ts` (every Vite environment). Builds leave it off and read each
other's `dist/`, in pnpm's dependency order, as `dev/deployment` and the examples
do in their typecheck, like any deployment. Published, the condition is inert.
Running a package's `.ts` with plain `node` outside those scripts needs the flag.

## Setup

**Toolchain.** Node **>= 24** and pnpm 11.8.0 (via corepack). Node 24 is a hard runtime
requirement, not just an `engines` field: the CLI, dev IdP, migrations, and the
`node --test` suite all execute TypeScript source (`*.ts`) directly with plain `node`,
which relies on native type-stripping (default only in Node 23.6+/24). `pnpm install`
itself is version-agnostic.

**Database.** Postgres runs in Docker via `docker compose` on **:55432** (owner
`coffre_owner`, restricted runtime login `coffre_runtime`). The running app and all the
DB-backed tests need it up. Export `COMPOSE_PROJECT_NAME=coffre` whenever you invoke
`docker compose` directly.

**Run the stack.** `pnpm dev` brings up Postgres + dev IdP (:8081) + coffre (:3000) +
seed data. It runs the deployment in `dev/deployment/` (`app.ts`, `vault.ts`, their
`wrangler.jsonc`) under `vite dev`, with the vault as an auxiliary Worker beside the
app and no port of its own. `dev/vite.config.ts` roots Vite in `packages/ui` (where
TanStack Start finds the routes) and resolves every `@coffre/*` import to its
sources through `coffre:source`, so an edit to any package hot-reloads without a
build. The vault keeps its Durable Object SQLite under
`dev/.wrangler/state` (or `$COFFRE_STATE_DIR`), which `pnpm dev` empties before it
seeds. `COFFRE_DEV_PORT`, `COFFRE_DEV_IDP_PORT` and `COFFRE_DEV_DATABASE` run a
second stack beside the first (see `dev/start.sh`). Sign in at
`http://127.0.0.1:3000/login`, through either button (the dev IdP plays GitHub and
an OIDC provider), as `admin@acme.example` (root admin) or any of the seeded
personas; the seed signs in the same way. CLI: `pnpm coffre <cmd>` (from the root,
against `.env.dev`); `pnpm coffre login` is a device login, approved in the browser.

**Config is code.** The packages read no environment variable of their own; a
deployment passes everything to `coffre(env => …)`, `serve({…})`, `vault(env => …)`
or `serveVault({…})`. The env vars left are the CLI's user-facing ones (`COFFRE_API_URL`,
`COFFRE_TOKEN`, …), `DATABASE_URL` for `coffre-server migrate`, and the dev and test
tooling's (`COFFRE_DEV_*`, `COFFRE_STATE_DIR`, `COFFRE_TEST_ENGINE`,
`COFFRE_TEST_DATABASE`). Don't add another to a package.

**Tests / checks.**
- `pnpm test` = lint + recreate `coffre_test` + `node --test --test-concurrency=1`
  (serial: the integration suite shares one DB and resets it per test). Needs Postgres.
  `COFFRE_TEST_DATABASE` names another database, for a second checkout sharing the
  compose Postgres (`pnpm test:schema` follows it too).
- `pnpm test:sqlite` runs the same suite on SQLite (`COFFRE_TEST_ENGINE`);
  `pnpm test:all` runs Postgres and SQLite. SQLite needs nothing and is kept
  for tests and local development; deployed app databases use Postgres.
- `pnpm test:schema` verifies the restricted runtime role's privileges. Postgres only,
  as is the runtime role itself.
- `pnpm build` builds every package in dependency order (core and client first, the
  UI before the server, whose build reads their `dist/`). Conformance, the
  examples' typecheck and `test:consumer` want it first.
- `pnpm conformance:workers` / `pnpm conformance:node` run an example's own
  `pnpm conformance` (`docs/conformance.md`), on ports 3082 to +2; add `--port <n>`
  for another three. Workers needs Postgres and makes its own
  `coffre_conformance_<hex>` database, dropped after; Node runs on SQLite in a temp
  dir. A check that fails prints what it saw, then the processes' output.
- `pnpm test:consumer [<dir>]` packs the seven packages, runs the packed CLI's
  `init` for both kinds outside the workspace, diffs them against the examples,
  installs the tarballs (pnpm overrides, no workspace links), then typechecks,
  builds and runs conformance on each. It needs network for third-party packages.
- `pnpm lint`, `pnpm check:pins`, `pnpm check:contrast` do not need Postgres.
- `pnpm typecheck` covers every package, `dev/deployment` and both examples. It does
  not need Postgres, but on a fresh checkout it fails until `pnpm build` has run:
  that writes `packages/ui/src/routeTree.gen.ts`, and the `dist/` the deployments
  typecheck against.
- Run an example's scripts from the root, `pnpm --filter coffre-workers <script>`, not
  with `--dir`: each example has its own `pnpm-workspace.yaml` (as `init` output
  needs), so pnpm would treat it as a separate, uninstalled workspace.

**Dependencies.** `pnpm install` enforces exact pins, `ignore-scripts`, and a 7-day
`minimumReleaseAge` (`pnpm-workspace.yaml`). Add deps with `pnpm run add:dep`
(`--save-exact`), never a bare `pnpm add` (it writes caret ranges).
`packages/ui/src/routeTree.gen.ts` is generated by `vite build`/`vite dev` and
gitignored, so it is absent on a fresh checkout (see the typecheck note above). The
examples pin `@coffre/*` at the packages' version, and `linkWorkspacePackages` links
them to the workspace; `pnpm bump` keeps them in step. The same `minimumReleaseAge`
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

# AGENTS.md

`coffre` is a pnpm monorepo secrets manager, shipped as packages a deployment imports
and configures in code: `packages/server` (`@coffre/server`: `/api`, sign-in, syncs,
migrations; `/cloudflare` and `/node` entry points), `packages/ui` (`@coffre/ui`: the
TanStack Start pages, prebuilt), `packages/vault` (`@coffre/vault`: keys, grants,
members, its own log), `packages/client` (the typed API client the CLI and UI call),
`packages/cli` (`coffre`, including `coffre init`), and the internal `packages/core`,
`packages/db`, `packages/sync`, bundled into them. `examples/workers` and
`examples/node` are deployments, exactly what `coffre init` writes (a test diffs
them). `dev/` holds what only the dev loop uses and nothing ships: `dev/start.sh`
(`pnpm dev`), the deployment it runs, the dev IdP (`dev/idp`, the local stand-in for
Cloudflare Access, GitHub and OIDC, which the smokes use too) and the seed.
`scripts/` holds what dev, tests and CI share.
The root `README.md` and the `package.json` scripts are the source of truth for
commands; this file only adds what they leave implicit.

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
TanStack Start finds the routes) and aliases `@coffre/server/cloudflare`,
`@coffre/vault/cloudflare` and `@coffre/ui` to their sources, so edits to any of them
hot-reload without a build. The vault keeps its Durable Object SQLite under
`dev/.wrangler/state` (or `$COFFRE_STATE_DIR`), which `pnpm dev` empties before it
seeds. `COFFRE_DEV_PORT`, `COFFRE_DEV_IDP_PORT` and `COFFRE_DEV_DATABASE` run a
second stack beside the first (see `dev/start.sh`). Sign in at
`http://127.0.0.1:3000/login` as `admin@acme.example` (root admin) or any of the
seeded personas. CLI: `node --env-file=.env.dev packages/cli/src/main.ts <cmd>`.

**Config is code.** The packages read no environment variable of their own; a
deployment passes everything to `coffre(env => …)`, `serve({…})`, `vault(env => …)`
or `serveVault({…})`. The env vars left are the CLI's user-facing ones (`COFFRE_API_URL`,
`COFFRE_TOKEN`, …), `DATABASE_URL` for `coffre-server migrate`, and the dev and test
tooling's (`COFFRE_AUTH_MODE` for the dev IdP and seed, `COFFRE_DEV_*`,
`COFFRE_STATE_DIR`, `COFFRE_TEST_ENGINE`, `SMOKE_PORT`). Don't add another to a package.

**Tests / checks.**
- `pnpm test` = lint + recreate `coffre_test` + `node --test --test-concurrency=1`
  (serial: the integration suite shares one DB and resets it per test). Needs Postgres.
- `pnpm test:sqlite` and `pnpm test:mysql` run the same suite on the other engines
  (`COFFRE_TEST_ENGINE`); `pnpm test:all` runs all three. SQLite needs nothing.
  MySQL uses whatever answers on **:53306**, else starts the compose `mysql`
  service (profile `mysql`, data on tmpfs) via `scripts/ensure-mysql.sh`.
- `pnpm test:schema` verifies the restricted runtime role's privileges. Postgres only,
  as is the runtime role itself.
- `pnpm build` builds every package in dependency order (the UI before the server,
  whose typecheck reads the UI's `dist/index.d.ts`). Most checks below want it first.
- `pnpm smoke:workers` / `pnpm smoke:node` run `scripts/smoke.mjs` against an example,
  on ports `SMOKE_PORT` (3082) to +2. Workers needs Postgres and uses its own
  `coffre_smoke` database, dropped after; Node runs on SQLite in a temp dir.
- `pnpm test:consumer [<dir>]` packs the five public packages, runs the packed CLI's
  `init` for both kinds outside the workspace, diffs them against the examples,
  installs the tarballs (pnpm overrides, no workspace links), then typechecks,
  builds and smokes each. It needs network for third-party packages.
- `pnpm lint`, `pnpm check:pins`, `pnpm check:contrast` do not need Postgres.
- `pnpm typecheck` covers every package and both examples. It does not need
  Postgres, but on a fresh checkout it fails until `pnpm build` has run: that writes
  `packages/ui/src/routeTree.gen.ts` and the `.d.ts` files the server and examples
  import.
- Run an example's scripts from the root, `pnpm --filter coffre-workers <script>`, not
  with `--dir`: `examples/workers` has its own `pnpm-workspace.yaml` (as `init`
  output needs), so pnpm would treat it as a separate, uninstalled workspace.

**Dependencies.** `pnpm install` enforces exact pins, `ignore-scripts`, and a 7-day
`minimumReleaseAge` (`pnpm-workspace.yaml`). Add deps with `pnpm run add:dep`
(`--save-exact`), never a bare `pnpm add` (it writes caret ranges).
`packages/ui/src/routeTree.gen.ts` is generated by `vite build`/`vite dev` and
gitignored, so it is absent on a fresh checkout (see the typecheck note above). The
examples pin `@coffre/*` at the packages' version, and `linkWorkspacePackages` links
them to the workspace; keep those versions in step when bumping.

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

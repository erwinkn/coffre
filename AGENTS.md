# AGENTS.md

`coffre` is a pnpm monorepo secrets manager, shipped as packages a deployment imports
and configures in code: `packages/server` (`@coffre/server`: `/api`, sign-in,
its queries in `src/db`; `/cloudflare` and `/node` entry
points; the optional plugins a deployment adds, in `src/plugins`,
`docs/design/plugins.md`), `packages/db` (`@coffre/db`: the Drizzle schema for Postgres, its
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

## Packages

A package imports another only by name (`@coffre/core/vault`, never
`../../core/src/vault.ts`); the `coffre/package-imports` lint rule holds every
`src`, `test` and `scripts` to it, so each package builds, ships and can be
internalized into a deployment on its own. The `@coffre/*` dependencies are
`workspace:*` and every package carries one version: `pnpm bump <version>` moves
them all, the examples' pins and their `pnpm-lock.yaml` specifiers, heads
`CHANGELOG.md`'s `## Unreleased` notes `## <version> (<date>)` under a new,
empty `## Unreleased`, and says whether any dependency the release pins is
younger than the week deployments wait, for the release notes. A release is
that bump, a commit and a PR, with no `pnpm install` or hand edit. Then the
order is bump, merge, Validate (and the Action test) green on the merge commit,
tag: the release refuses a tag whose commit has no green run of both
(`.github/workflows/release.yml`). `pnpm check:pins`
fails on any drift, including the examples' `packageManager`, which must be
the workspace's pnpm.

Every package's `exports` lists a `coffre:source` condition first, pointing at
`src/*.ts`. Inside the workspace, dev, tests and typecheck turn it on and read the
other packages' sources: `tsconfig.base.json` (`customConditions`), Node
(`--conditions=coffre:source`, in every test script and in `pnpm coffre`), and
`dev/deployment/app/vite.config.ts` (every Vite environment). Builds leave it off and read each
other's `dist/`, in pnpm's dependency order, as `dev/deployment` and the examples
do in their typecheck, like any deployment. Published, the condition is inert.
Running a package's `.ts` with plain `node` outside those scripts needs the flag.

## Setup

**Toolchain.** Node **26.13.0**, as `.node-version` pins it (CI's setup-node reads it),
and pnpm **12.17.0**, as `package.json`'s `packageManager` pins it: install any pnpm
(https://pnpm.io/installation), which switches itself to that release, checked against
npm's registry signature, once the release is past the 7-day `minimumReleaseAge` (a
younger pin only warns, and the pnpm you have runs). Each is the latest release of the
latest major (Node's, of its latest LTS line) with no known vulnerability and at least
7 days old; a move picks the same way. No Corepack, which Node drops: CI installs pnpm with
pnpm/action-setup (6.1 or later, which knows pnpm 12's native executable) and
`.cursor/Dockerfile` from npm's `@pnpm/exe.linux-<arch>` tarball by its SHA-256, and
`check:pins` rejects `corepack` anywhere. The examples pin the same two, as every
deployment `init` writes does, and `coffre update` moves them with coffre's packages.
Node 24 is the floor, and a hard requirement
for workspace source, not just an `engines` field: the CLI, dev IdP, migrations, and the
`node --test` suite all execute TypeScript source (`*.ts`) directly with plain `node`,
which relies on native type-stripping (default only in Node 23.6+/24). The
published CLI is bundled JavaScript targeting Node 20 and runs on Node >= 20, as
does the published client (built for Node 20, no dependency); this does not relax the
workspace's or deployments' Node 24 requirement.
`pnpm install` itself is version-agnostic. Docker Compose **>= 2.19** (`docker compose --progress`,
which `scripts/ensure-postgres.sh` passes so that it can read what compose says).

**Database.** Postgres runs in Docker via `docker compose` on **:55432** (owner
`coffre_owner`, restricted runtime logins `coffre_runtime` for the app,
`coffre_vault_runtime` for the vault and `coffre_vault_hot` for its hot path,
0.15's uses). The running app and all the
DB-backed tests need it up. Export `COMPOSE_PROJECT_NAME=coffre` whenever you invoke
`docker compose` directly. A Postgres of your own, beside the shared one, is a
project and a port of its own: `COMPOSE_PROJECT_NAME=coffre_mine
COFFRE_POSTGRES_PORT=56432 pnpm test` starts it, and every script, test and
fixture connects to that port; `ensure-postgres.sh` refuses a project already
up on another.

The image is Debian's `postgres:16.14` (glibc), not Alpine's: managed Postgres
behind Hyperdrive is glibc, and musl's malloc costs a use 2-3x the Postgres
CPU, so an Alpine benchmark answers for nobody. It is the reference rig for
every Postgres number. The clusters use `--locale=C`, which compares bytes
whatever the libc, so the old data would have mounted fine; the volume is
named for the image (`coffre-pgdata-v16-debian`) anyway, so that a recreated
container starts a cluster of its own. A container already running keeps its
image, and `pnpm db:up` (`ensure-postgres.sh`) reuses it, saying so. To move
one to Debian, once, when this is on `main`, the checkouts sharing it have
rebased (one still on the old compose file recreates it back as Alpine, on
the old volume) and none is using it:
`COMPOSE_PROJECT_NAME=coffre docker compose up -d --force-recreate postgres`.
It starts on the fresh volume and `pnpm dev` reseeds; `docker volume rm
<project>_coffre-pgdata-v16` reclaims the old one, after the rebases too. A Postgres of your own
(above) is cheaper to recreate.

`scripts/ensure-postgres.sh` reuses a healthy or initializing container and
serializes cold starts across worktrees with the host's advisory lock
(`flock` on Linux, `lockf` on macOS), then starts with `--no-recreate`. CI reserves 55432 from Linux's outgoing port allocation before
package downloads; the port is inside the default outgoing range. The
reservation script is CI-only and does not change a developer's host.

Before it reports ready it also asks Linux, with `ip route get`, where the
container's address goes, and refuses unless that is the project's own bridge:
Cloudflare WARP routes some hosts of 192.168.0.0/20 off the machine (Docker hands
that subnet out once its 172.17-172.31 pools are taken), and a connection to `127.0.0.1:<port>` is
forwarded to that address (docker-proxy or DNAT), so the first `psql` would send the dev password to a
stranger. A container it started is removed again (the volume stays); one it
reused is only reported. Docker's `default-address-pools` (restart the daemon)
is the fix that lasts. A project's own subnet (`COFFRE_POSTGRES_SUBNET=10.77.0.0/24`,
one no other Docker network uses, after a `docker compose down` of the project)
holds only while every run sets it, so export it in the shell profile or direnv:
a later `up` without it recreates the network on Docker's pick. Where `ip` or the bridge is missing (macOS, Docker Desktop), the check is skipped.

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
second stack beside the first, and `COFFRE_DEV_PUBLIC_URL` and `COFFRE_DEV_IDP_PUBLIC_URL`
sign in to it through a tunnel (see `dev/start.sh`). Sign in at
`http://localhost:3000/login` (localhost, not 127.0.0.1: browsers make passkeys
for a name only), through either button (the dev IdP plays GitHub and
an OIDC provider), as `admin@acme.example` (the Owner) or any of the seeded
personas; the seed signs in the same way. Passkeys are `optional`, as
deployments run them (`COFFRE_DEV_PASSKEYS`), so Owners sign in with one, and
the seed added `admin@acme.example`'s, a software key: `node dev/passkey.mjs
<DevTools WebSocket URL>` puts it in a Chrome you drive (`agent-browser
cdp-url` gives one) while it runs, or `COFFRE_DEV_PASSKEYS=off pnpm dev` signs
everyone in with the dev IdP alone. CLI: `pnpm coffre <cmd>` from the root;
`pnpm coffre login http://localhost:3000` once, a device login approved in the
browser, and its session is the default after.

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
its pipeline, before it deploys (with Workers Builds, both Workers' builds
do), so each migration first meets the previous release's code, and must
work with it: the old code serves on the new schema until the deploy. The
new code never meets the old schema: below its migrations, the app answers
everything but `/livez` and `/readyz` with 503 `migrating`, at one door
(`respond` in `packages/server/src/app.ts`), so no code checks whether a
migration has run. So a migration adds: tables, columns that are nullable
or have a default, indexes, grants. A migration that makes a table grants
`SELECT` on it to `coffre_backup`, by name, as it grants `coffre_app`;
`pnpm test:schema` fails on a table the backup cannot read. What removes or tightens (dropping or
renaming a table or a column, NOT NULL on an existing column, a narrower
check or type, a unique or foreign key the old code may break) ships one
release after the code stops using it. 0.4.0 is a clean break: one baseline,
for new databases only, and no code for earlier releases'
deployments or data. `pnpm test:compat` holds the newest release to this
checkout's schema, through that release's own conformance, in CI on every
change; it was off for 0.4.0, which had no earlier release on its schema.

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
(`packages/vault/test/isolate.test.ts`). The app's own asks, once per
isolate, of the vault's `about()` and the proxy's gate, are made by its
first request alone: the others join that call's attempt and poll, on
timers of their own, for its settled answer or failure, take over a call not
settled in 3 s, and answer 503 to ask again after 6 s of waiting in all,
however many take-overs came meanwhile, their own included: a request that
took a call over waits on it as on the one it joined, polling, under the
same deadline (`packages/server/src/asked-once.ts`, T201).

**One connection per call.** On Workers, each app request and each vault
call has one Postgres client through Hyperdrive (`HyperdrivePool` in
`@coffre/db`), connected on its first query. Its queries take turns on it,
and a transaction holds it from BEGIN to COMMIT; plain reads asked
together, the app's and the vault's, take one turn, under one Sync, one
round trip (`groupReads`), and fail together: a cold isolate's start asks
its first reads so (T206). A transaction's statements asked
together go under one Sync too, BEGIN with the first, in the order they
were started, and the writes
it leaves to `later` (`@coffre/db`) with its
COMMIT: a transaction that reads what it needs together (`Promise.all`)
and leaves the writes whose answer it does not need to `later` is two
round trips, which `packages/server/test/change-cost.test.ts` holds each
change route to (T179). So code inside a
transaction queries through its `tx`, never the database: a query on the
database would wait for the transaction, which waits for it. `createDatabase`
refuses one at once, on Node too, so the suites catch it: each transaction's
work runs in an `AsyncLocalStorage` naming it, and a query or a transaction
asked of its pool from there throws `QueryOutsideTransaction`. A call that
opened several Hyperdrive connections at once was now and then cancelled
as hung on Cloudflare (`packages/vault/test/workers.test.ts` counts them).
A request asks the vault about its caller once: a page's render checks its
credential once for all its API calls (`pageClient`), and a read of values
asks nothing first when the app kept the vault's last answer, which its
unwrap checks (`Accesses`). `GET /api/me` asks it nothing: it only shows its
caller, whom the app reads from the vault's rows, unchecked, and no other
route takes such a caller (`docs/architecture.md`, "The API").

**Tests / checks.**
No pull request runs CI (Erwin, 11-07). A change merges on `pnpm validate`, run by
its author on its exact head, rebased on `main`. It runs what the diff against
`origin/main` can change (`scripts/affected.mjs` decides, `--list` shows what and
why), side by side, each step logging to a file of its own and each that needs
Postgres on a container and ports of its own (never :55432), removed however the step
ends (but with `--keep-db`), the run's containers on one network of its own (one of Docker's subnets a run,
never `COFFRE_POSTGRES_SUBNET`'s), and prints the commit, its tree, the base and each
step's result, for the pull request. With a Postgres step, it first removes what runs
killed outright left on this host: the containers and networks of a `validate.mjs` of
this boot no longer alive (an earlier boot's are removed by hand). `--full` runs everything, as the
release's `Validate` does, but the image and the packed client on every Node CI
names (here, the Nodes `COFFRE_CLIENT_NODES` lists, or the current one), and the
growth sweep, which `Validate` has no job for: before a tag, a local `--full` is its
only run. What a diff runs:

- The test files that import, name by path or scan with a glob a changed file
  (a build's `dist/` stands for its sources), through the file graph of
  `scripts/graph.mjs`; every one when it touches the harness
  (`scripts/test-suite.sh`, what it runs, the migrations among them, the compose
  file); a package's own tests for a file of it that no test reaches.
- Lint on the changed files, the typecheck of the packages that read them, and the
  other checks and conformance runs on what each runs: Workers' conformance on what
  its deployment runs. Node's is off at both gates, and in the consumer's run, until
  0.16.1 (T270; `nodeConformance` in `scripts/affected.mjs`, which `validate.yml`
  follows): Node is built and typechecked, nothing more.
- The slow tier on its own inputs: the use matrices on the matrix files, their worlds
  and the vault's use path (not the core rules it calls, which the proofs and the
  suite hold); TLC on the scenarios whose configuration or module, or a
  module it extends or instantiates, changed (`scripts/formal.sh`'s own lines for a
  scenario count as its); Terraform on its provider and the routes it calls; the
  packed consumer on manifests, build configs and the examples. The growth sweep
  (`pnpm sweep:growth`) runs with `--full` alone.
- A lockfile, a manifest's fields beyond its scripts or the pinned Node: everything
  but the matrices, TLC and the sweep. A file no rule claims: everything but TLC
  and the sweep, so a miss fails safe. A deleted file: what reads or runs the
  files beside it. A docs-only diff: `pnpm check:docs` alone.

At most `--jobs` (4) heavy steps run at once; run it under the host's CPU cap if it
has one. When `main` moves after a gate and the rebase is mechanical (clean, or
conflicting only in a migration or `CHANGELOG.md`, with `git range-diff` showing the
patch unchanged), run it again on the new head; any other conflict gets a scoped
review of the changes too. The pull request's comment gives the summary of each run
and the range-diff verdict. `Validate` (`.github/workflows/validate.yml`) runs
everything when dispatched (`gh workflow run validate.yml --ref main`) and nightly
on `main`, TLC only when the model's inputs have no green run yet, and gates
releases: a tag's commit needs a green run of it and of the Action test. The Action
names no version: its CLI, `action/coffre.mjs`, is this checkout's, which a change
to the CLI or anything it bundles rebuilds (`pnpm build`, then `pnpm build:action`),
and `pnpm check:action` holds it to what the sources build.

- `pnpm test` = lint + migrate a scratch template + `node --test --test-concurrency=4`,
  then the files that run alone (`packages/*/test/*.alone.ts`), one at a time: those
  that hold a statement's work, pages or locks to a budget or to the same call by
  call, which another test's migration in the same cluster would upset (any commit
  of thousands of catalog changes resets every backend's caches). Each file gets a
  private Postgres clone, its cases sequential and reset per test; templates and
  clones are removed after the run. `COFFRE_TEST_DATABASE` sets the scratch prefix;
  a random suffix isolates simultaneous runs. `pnpm test:schema` still recreates the
  exact database it names. `./scripts/test-suite.sh --files <file>...` runs some
  files (`--serial` first: one at a time). Needs Postgres.
- `pnpm test:matrices` runs the generated matrices of 0.15's use by name (every
  `packages/*/test/*.matrix.ts`): every key a caller may not have answered alike,
  whatever the vault's map holds, each statement slowed. Unsharded, the server's
  outlasts its own 7,200 s timeout on Postgres, so `pnpm test` leaves them out and
  they run in shards: `COFFRE_TEST_SHARD=<k>/<n>` runs the k-th of n, case i in shard
  i mod n + 1 (`scripts/matrix-shard.ts`), and `COFFRE_TEST_SHARD_REPORT=<dir>`
  records which cases ran, which `scripts/matrix-coverage.mjs` holds to every case
  exactly once (CI's six Postgres shards, and `pnpm validate`'s, one at a time). A new
  matrix passes its cases through `shardOf`. The files run side by side on one
  Postgres, each within its share of the connections (`scripts/matrix-connections.ts`),
  and a failing cell ends every pool its cells opened
  (`packages/vault/test/matrix-cells.test.ts`).
- `pnpm test:schema` verifies both runtime logins' privileges, runs the full
  migration as a non-superuser owner in a disposable cluster, checks TLS trust and
  hostname verification, and runs `coffre setup` against another
  (`scripts/test-setup.sh`), as its superuser and as such an owner: setup makes
  cluster-wide roles, so never on the shared one. Postgres only.
- `pnpm build` builds every package in dependency order: core and client, then db,
  then the CLI, then the rest, each run free of the cycle core's tests make through
  conformance's dev IdP (`ERR_PNPM_TASK_CYCLE`). The UI builds as a library, each
  page a module (`@coffre/ui/pages/<name>`). The CLI's build fails on an import it
  cannot resolve. Conformance, the examples' typecheck and `test:consumer` want it.
- `pnpm typecheck` covers every package, `dev/deployment` and both examples, unsorted
  (`--no-sort`, for the same cycle); the deployments read the `dist/` the build
  writes, so on a fresh checkout it fails until `pnpm build` has run.
- `pnpm conformance:workers` / `pnpm conformance:node` run an example's own
  `pnpm conformance` (`docs/conformance.md`) on ports 3082 to +2, or `--port <n>`'s
  three. Each builds the example's app with its own Vite first, as it deploys;
  Workers then runs `app/dist/server/wrangler.json` behind an entry of the harness's
  own that reads an unread request body (locally, wrangler fails the next request
  otherwise); Node runs the built app under srvx. Each needs Postgres and makes its
  own `coffre_conformance_<hex>` database, dropped after. Each holds
  the build's client files to holding no server code
  (`packages/conformance/src/bundle.ts`), and a failing check prints what it saw,
  then the processes' output.
- `pnpm test:compat [--kind workers|node] [--release <v>] [--schema <v>]` installs
  the newest release from npm as `init` writes it, has its own conformance migrate
  with this checkout's migrations and requires it conformant, then requires a
  synthetic destructive migration to fail it. `--schema` applies a published
  version's migrations instead. Needs network and Postgres. Off, in `Validate` and
  `pnpm validate`, until 0.16.0 is tagged: 0.16 is a clean break (D197).
- `pnpm test:consumer [--port <n>] [<dir>]` builds and packs the eight packages
  (`--built` packs the `dist/` there is: `pnpm validate`'s, read by its other steps meanwhile), runs the packed
  CLI's `init` for both kinds outside the workspace, diffs them against the
  examples, installs the tarballs, then typechecks, builds and runs conformance on
  each (`--skip-conformance node`, as both gates pass until 0.16.1, leaves Node's out). It also loads and calls the packed client with each Node
  `COFFRE_CLIENT_NODES` lists (`scripts/client-smoke.cjs`; CI names 20, 22 and 24).
  Needs network.
- `pnpm test:image` builds the CLI's image (`packages/cli/Dockerfile`) from this
  revision's packed CLI for linux/amd64 and linux/arm64, then runs the native one:
  `--version`, its non-root user, and `coffre serve` on a read-only root
  (`packages/cli/scripts/image-smoke.ts`). Needs Docker on Linux. The release pushes
  the same Dockerfile, built from npm's tarball, to `ghcr.io/erwinkn/coffre-cli`.
- `pnpm bench:workers` / `pnpm bench:node` (after `pnpm build`) boot an example as
  conformance does, on ports 3182 to +2, and print the CPU each hot path costs, cold
  and warm, from Linux's per-thread counters (on Workers, the workerd that runs both
  Workers; on Node, the server and the vault apart). `--entries` and `--members` grow
  the instance first. Workers' Free plan gives an invocation 10 ms of CPU.
- `pnpm sweep:growth [--size <n>] [--out <dir>] [--write-known]` runs every GET
  route, the audit page's filters and the main writes and background jobs on a
  history of each shape `--size` long (2,000), then ten times that, and fails on a
  runtime statement that read twice the pages at the larger, or ran there alone,
  unless `scripts/growth-sweep-known.txt` lists it; a fix deletes its lines
  (`docs/growth-sweep.md`). On a Postgres of your own only (`COMPOSE_PROJECT_NAME`,
  `COFFRE_POSTGRES_PORT`), since it logs every plan; `pnpm validate --full` runs it
  on its step's, `pnpm test` never.
- `pnpm formal` model-checks the locking protocol, `formal/Coffre.tla`, and the
  protocols beside it with TLC (`docs/formal.md`): every scenario must hold, and each
  again without one of the code's protections must fail. Needs Java 11+; downloads
  TLC's jar once, checked against its pinned SHA-256. A change to the locks a flow
  takes, or what it re-checks under the head, changes the model too. CI runs it as
  thirteen shards (`scripts/formal.sh --shard`), skipped when the model's inputs
  have a green run (`scripts/formal-key.sh`).
- `pnpm formal:lean` checks the Lean proofs in `formal/lean` (`docs/formal.md`,
  "Proofs in Lean") and holds their model to `@coffre/core/access`, the vault's
  per-key decision (`packages/vault/src/decide.ts`), the AAD and the chain verifier
  on about 120,000 generated cases (`--long`, `--seed=<n>`). A change to those rules
  changes `formal/lean` in the same pull request.
- `pnpm test:terraform` (after `pnpm build`) checks the Terraform provider, a Go
  module in `terraform-provider/`: gofmt, `go vet`, its unit tests, then its
  acceptance tests on Terraform and OpenTofu 1.11 against the Node example on
  Postgres that `packages/conformance/scripts/terraform-fixture.ts` boots on ports 3482 and 3483
  (`scripts/terraform-provider.sh`; `--unit` for the first three alone). Go and both
  CLIs are pinned by version and SHA-256.
- `pnpm lint`, `pnpm check:pins`, `pnpm check:workflows`, `pnpm check:contrast` and
  `pnpm check:docs` (every path, script and link the docs name exists) need no
  Postgres. `check:pins` holds the manifests, and every tracked workflow, action,
  compose file, Dockerfile, shell script and `pnpm-workspace.yaml`, to the rules
  `scripts/pins.mjs`'s header lists: an action by its commit; an image by its
  digest; a Dockerfile's `ADD` of a URL with `--checksum`; every other download
  through `scripts/fetch.sh <url> <sha256> <file>` (curl and wget banned elsewhere,
  but a health check of this machine marked `# pins: local`); no package runner or
  install outside the lockfile, `pnpm install` with `--frozen-lockfile`; an action's
  `*-version` input exact; no `corepack`; pnpm's 7-day age gate and
  `strictDepBuilds`. A line no rule can hold carries `# unpinned: <reason>`.
  Anything else (an image `docker run` pulls, a fetch hidden from those names) is
  review's. `check:workflows` runs zizmor (`scripts/zizmor.sh`,
  `.github/zizmor.yml`), which with `GH_TOKEN` set also asks GitHub whether each
  pinned commit is its repository's.
- `scripts/restore-drill.sh` (after `pnpm build`) backs up a seeded Workers stack
  with `coffre backup`, restores it with `coffre restore --keys`, checks it came
  back, then the wrong-key cases, on ports 3400 to 3402 and 8481 (`docs/restore.md`).
  It drops its databases and stops its processes however it ends. `pg_dump` and
  `pg_restore` on `PATH` must be PostgreSQL 16's, the compose server's;
  `packages/cli/test/backup.test.ts` skips without them.
- Run an example's scripts from the root, `pnpm --filter coffre-workers <script>`, not
  with `--dir`: each example has its own `pnpm-workspace.yaml` (as `init` output
  needs), so pnpm would treat it as a separate, uninstalled workspace.

**Dependencies.** `pnpm install` enforces exact pins, no install script but
those `allowBuilds` names `true` with its reason (none: esbuild, Koffi and
workerd are named `false`, and `strictDepBuilds` fails an install on one
nobody named), and a 7-day `minimumReleaseAge` (`pnpm-workspace.yaml`), which
`check:pins` refuses to shorten. Add deps with `pnpm run add:dep`
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
`.cursor/Dockerfile` (Node 26.13.0 via nvm, pnpm 12.17.0's native executable from npm's tarball, and a Docker engine set
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
  image prepends the nvm-managed Node 26 in `~/.bashrc` (above the stock interactive-guard
  early return, since the runtime sources it for non-interactive shells too) and in
  `/etc/profile.d`. If `node -v` ever shows 22, that prepend did not run.

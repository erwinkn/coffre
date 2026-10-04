# Release notes

## Unreleased

**A deployment's app is a TanStack Start app of its own** (0.2.0). Vite
builds it once, with `@coffre/ui` and `@coffre/server` as libraries inside
it, and nothing bundles it again: on Workers, `wrangler deploy` uploads what
Vite built, so no second pass rewrites what the pages send the browser, as
wrangler's `keep_names` did in 0.1.17. The app's files:

- `app/vite.config.ts`: `cloudflare(…)` on Workers, `tanstackStart()`,
  `viteReact()`, and `coffre()` from `@coffre/ui/vite`, which puts the
  pages' files under `/_coffre/assets/`, checks the versions below, and
  fails the build if server code reaches what the browser loads;
- `app/src/router.tsx`: `export { getRouter } from '@coffre/ui'`, the pages;
- `app/src/server.ts` on Workers (was `app/src/worker.ts`): `coffre(env =>
  ({ pages, … }))`, `pages` being Start's handler, `import pages from
  '@tanstack/react-start/server-entry'`. On Node, `src/server.ts` passes
  `serve({ pages: new URL('../app/dist/', import.meta.url), … })`.

React, TanStack Router, Start, Query and Vite are the deployment's own
dependencies now, pinned at exactly the versions `@coffre/ui` is built with;
`coffre update` moves them with coffre's packages. `@coffre/ui` ships its
pages as ES modules, each route a chunk of its own, so a release that adds a
page needs no change in the deployment. `keep_names` is gone from
`app/wrangler.jsonc`: nothing bundles the app again for it to matter.

To upgrade, in the deployment's directory, with the 0.2 CLI:

```sh
npx @coffre/cli@0.2.0 update
```

It shows each file it changes and asks once; an older CLI's `coffre update`
moves the pins without the files, and the app then says its `pages` are
missing. Then `pnpm typecheck`, and deploy: on Workers Builds, the app's
build command is now `pnpm exec vite build app` and its deploy command `npx
wrangler deploy -c app/dist/server/wrangler.json`; `pnpm run deploy` does
both. On Node, `pnpm build`, then restart both processes.
[Upgrading to 0.2](docs/deploy.md#upgrading-to-02).

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

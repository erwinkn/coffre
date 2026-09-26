# Cloudflare Worker deployment

The application repository owns the Worker code, custom domain, runtime-only
secrets, Hyperdrive binding, observability, Smart Placement, and five-minute
Cron Trigger. The infrastructure repository owns PostgreSQL, its owner/runtime
credentials, the private network, connector, Workers VPC Service, Hyperdrive
configuration, and Cloudflare Access application.

This page is Equisafe's pipeline. [deploy.md](deploy.md) deploys a coffre
of your own by hand.

## Production boundary

`apps/web/wrangler.jsonc` describes coffre itself. Where Equisafe's copy runs,
its Worker name and custom domain, is
[`deploy/equisafe.jsonc`](../deploy/equisafe.jsonc), which the workflow passes
to the build as `COFFRE_INSTANCE`. It keeps coffre's default auth mode,
Cloudflare Access, and so the default list of required secrets below.

Hyperdrive's query cache must be off for coffre (`caching.disabled` in
Terraform, `--caching-disabled` in Wrangler). With it on, a repeated `SELECT`
can be answered from a copy up to a minute old, so a revoked grant, session
or person keeps working for that minute.

`apps/web/wrangler.jsonc` deliberately contains the sentinel
`__COFFRE_HYPERDRIVE_ID__`. A normal Wrangler deployment must never create a
second Hyperdrive configuration. `scripts/deploy-worker.mjs` replaces the
sentinel only in Vite's generated deployment configuration with Terraform's
`cloudflare_hyperdrive_id`, supplies required secrets atomically through
Wrangler's secrets file, deploys, and restores the generated file afterwards.
It never writes production values into the tracked Wrangler configuration.

The deploy reads the list of secrets from the built configuration and
refuses to start if any is missing. The `coffre-production` GitHub environment
must provide:

- variables: `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_HYPERDRIVE_ID`
- secrets: `CLOUDFLARE_API_TOKEN`, `COFFRE_ACCESS_ISSUER`,
  `COFFRE_ACCESS_JWKS_URL`, `COFFRE_ACCESS_AUD`, `COFFRE_ROOT_ADMINS`,
  `COFFRE_KEK_LOCAL`, `COFFRE_KEK_ID`, and `COFFRE_AUDIT_CHAIN_KEY`
- optional rotation secret: `COFFRE_KEK_LOCAL_PREVIOUS`

The separate `coffre-migrations` GitHub environment must provide:

- variables: `COFFRE_DATABASE_IP`, `COFFRE_DATABASE_PORT`, and
  `COFFRE_RUNTIME_ROLE`
- secrets: `COFFRE_DATABASE_CA_CERTIFICATE`, `COFFRE_OWNER_DATABASE_URL`, and
  `COFFRE_RUNTIME_PASSWORD`

Both environments must allow only `main`. Keep migration-owner secrets out of
`coffre-production`, and keep Worker deployment secrets out of
`coffre-migrations`.

Set `COFFRE_RUNTIME_ROLE` to the fixed role name `coffre_runtime`. The database
schema grants privileges to this exact role and the migration runner rejects a
different value.

Copy the application values only from Terraform's sensitive
`worker_runtime_environment` output. Copy the Hyperdrive ID from
`cloudflare_hyperdrive_id`. Never copy `migration_environment`, the database
owner URL, database CA, or runtime password into the Worker environment.

Deployments are manually dispatched. The workflow rejects all release refs
except `main`, then runs the complete local contract suite from
[`validate.yml`](../.github/workflows/validate.yml), the same checks every pull
request runs. Configure the
`coffre-production` and `coffre-migrations` GitHub environments to allow only
the selected branch `main`, and disable administrator bypass if the repository
plan supports it. These environment rules are the authoritative secret
boundary because workflow code on another branch is not trusted. The migration
job targets only the repository-scoped `coffre-migrations` self-hosted runner.
That runner shares the stateless Scaleway connector VM and reaches the database
through its Private Network attachment. The VM accepts no inbound traffic, and
its security group allows PostgreSQL only to the RDB private `/32` endpoint.

The runner registers with a one-hour GitHub token delivered through a temporary
Scaleway user-data key. The key is deleted after GitHub reports the runner
online. No GitHub administration credential is stored in Terraform, GitHub
Actions, or the VM.

The migration runs directly from CI, takes the PostgreSQL advisory lock, and
then connects as the runtime role to verify its identity, membership, lack of
owner/DDL/audit-mutation privileges, and ability to write the heartbeat. The
script removes its mode-`0600` database CA and derived URLs on every normal,
failed, or interrupted exit. A runner-level completion hook then clears the
checked-out repository. The Worker deploy job cannot start unless the
migration and runtime privilege verification succeed.

## Local Worker runtime

`pnpm dev` selects the Wrangler `development` environment and maps the
checked-in local runtime URL to
`CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`. The dev IdP and
local-only keys remain process inputs; they are exposed to workerd as the
declared development secrets.

`pnpm --dir apps/web smoke:production` builds and runs the real Worker bundle
against the isolated test database. It deliberately makes the audit heartbeat
stale, confirms `/readyz` returns `503`, invokes the scheduled handler, confirms
readiness recovers, and verifies unauthenticated API requests fail closed.

## Database migrations

Migrations remain a one-shot owner operation outside Workers and Hyperdrive.
They read migration files from disk, take a PostgreSQL advisory lock, validate
history hashes, apply Drizzle migrations, and verify the restricted runtime
grants. Never put the owner URL in Worker secrets, add a migration handler to
the Worker, or keep a migration process running.

`scripts/migrate-private-database.sh` first verifies that the configured private
database IP and port are reachable. It writes the database CA and derived URLs
only to a mode-`0700` temporary directory and removes those files on every exit.
The owner URL remains outside Worker and Hyperdrive configuration.

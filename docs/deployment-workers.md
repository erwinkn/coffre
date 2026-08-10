# Cloudflare Worker deployment

The application repository owns the Worker code, custom domain, runtime-only
secrets, Hyperdrive binding, observability, Smart Placement, and five-minute
Cron Trigger. The infrastructure repository owns PostgreSQL, its owner/runtime
credentials, the private network, connector, Workers VPC Service, Hyperdrive
configuration, and Cloudflare Access application.

## Production boundary

`apps/web/wrangler.jsonc` deliberately contains the sentinel
`__COFFRE_HYPERDRIVE_ID__`. A normal Wrangler deployment must never create a
second Hyperdrive configuration. `scripts/deploy-worker.mjs` replaces the
sentinel only in Vite's generated deployment configuration with Terraform's
`cloudflare_hyperdrive_id`, supplies required secrets atomically through
Wrangler's secrets file, deploys, and restores the generated file afterwards.
It never writes production values into the tracked Wrangler configuration.

The `coffre-production` GitHub environment must provide:

- variables: `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_HYPERDRIVE_ID`,
  `CLOUDFLARE_WARP_DEVICE_PROFILE_ID`, `CLOUDFLARE_WARP_ORGANIZATION`,
  `COFFRE_DATABASE_IP`, `COFFRE_DATABASE_PORT`, and `COFFRE_RUNTIME_ROLE`
- secrets: `CLOUDFLARE_API_TOKEN`, `COFFRE_ACCESS_ISSUER`,
  `COFFRE_ACCESS_JWKS_URL`, `COFFRE_ACCESS_AUD`, `COFFRE_ROOT_ADMINS`,
  `COFFRE_KEK_LOCAL`, `COFFRE_KEK_ID`, `COFFRE_AUDIT_CHAIN_KEY`,
  `CLOUDFLARE_WARP_CLIENT_ID`, `CLOUDFLARE_WARP_CLIENT_SECRET`,
  `COFFRE_DATABASE_CA_CERTIFICATE`, `COFFRE_OWNER_DATABASE_URL`, and
  `COFFRE_RUNTIME_PASSWORD`
- optional rotation secret: `COFFRE_KEK_LOCAL_PREVIOUS`

The separate `coffre-maintenance` GitHub environment must allow only `main`
without reviewer approval so its scheduled cleanup can run unattended. It
contains variables `CLOUDFLARE_ACCOUNT_ID`,
`CLOUDFLARE_WARP_DEVICE_PROFILE_ID`, and `CLOUDFLARE_WARP_ORGANIZATION`, plus
only the `CLOUDFLARE_ZERO_TRUST_API_TOKEN` secret. That token requires the
Cloudflare `Zero Trust Write` permission because Cloudflare does not expose a
narrower registration-deletion permission. Do not reuse the Worker deployment
token or copy database credentials into this environment.

Set `COFFRE_RUNTIME_ROLE` to the fixed role name `coffre_runtime`. The database
schema grants privileges to this exact role and the migration runner rejects a
different value.

Copy the application values only from Terraform's sensitive
`worker_runtime_environment` output. Copy the Hyperdrive ID from
`cloudflare_hyperdrive_id`. Never copy `migration_environment`, the database
owner URL, database CA, or runtime password into the Worker environment.

Deployments are manually dispatched. The workflow first runs the complete
local contract suite. It rejects all release refs except `main`. Configure the
`coffre-production` GitHub environment to allow only the selected branch
`main`, and disable administrator bypass if the repository plan supports it.
This environment rule is the authoritative secret boundary because workflow
code on another branch is not trusted. The workflow verifies Cloudflare's
package-signing key and installs a version-pinned Cloudflare One Client on its
ephemeral Ubuntu runner. A dedicated
service token enrols that runner into a device profile that routes only the
database private `/32` address. Gateway permits this non-identity profile to
reach only the PostgreSQL port. There is no public hostname or database
endpoint.

Before it starts the database migration, the job checks that
`warp-cli settings` reports the Terraform-managed profile ID and that the
private database IP and port are reachable through WARP.

The migration runs directly from CI, takes the PostgreSQL advisory lock, and
then connects as the runtime role to verify its identity, membership, lack of
owner/DDL/audit-mutation privileges, and ability to write the heartbeat. The
runner removes the MDM file and its WARP registration on every normal, failed,
or interrupted exit. The separate `cleanup-warp-registrations.yml` workflow
uses a `Zero Trust Write` API token to delete registrations from the exact
Coffre device profile when their last activity is more than six hours old.
This covers jobs that are terminated before local cleanup can run. The Worker
deploy job cannot start unless the migration and local deregistration succeed.

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

`scripts/migrate-over-warp.sh` verifies Cloudflare's package-signing key,
installs an exact WARP package version, writes the database CA and derived URLs
only to a mode-`0700` temporary directory, and removes those files on every
exit. The owner URL remains outside Worker and Hyperdrive configuration.

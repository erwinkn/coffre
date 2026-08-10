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
  `SCW_DEFAULT_PROJECT_ID`, `SCW_DEFAULT_ORGANIZATION_ID`,
  `SCW_DEFAULT_ZONE`, and `COFFRE_RUNTIME_ROLE`
- secrets: `CLOUDFLARE_API_TOKEN`, `COFFRE_ACCESS_ISSUER`,
  `COFFRE_ACCESS_JWKS_URL`, `COFFRE_ACCESS_AUD`, `COFFRE_ROOT_ADMINS`,
  `COFFRE_KEK_LOCAL`, `COFFRE_KEK_ID`, `COFFRE_AUDIT_CHAIN_KEY`,
  `SCW_ACCESS_KEY`, `SCW_SECRET_KEY`, `COFFRE_DATABASE_CA_CERTIFICATE`,
  `COFFRE_OWNER_DATABASE_URL`, and `COFFRE_RUNTIME_PASSWORD`
- optional rotation secret: `COFFRE_KEK_LOCAL_PREVIOUS`

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
code on another branch is not trusted. The workflow then creates a temporary
`DEV1-S` instance, attaches
it to Coffre's Scaleway Private Network, permits SSH only from that GitHub
runner's IPv4 address, and runs the owner migration image. A second container
connects as the runtime role and verifies its identity, membership, lack of
owner/DDL/audit-mutation privileges, and ability to write the heartbeat. The
runner generates the instance SSH host key and pins its public key before the
first connection. Thus, credentials are never sent to an unauthenticated host.
The workflow deletes the instance, root volume, public IP, security group, CA, and
owner environment whether the migration succeeds or fails. The Worker deploy
job cannot start unless this migration job succeeds.

The Scaleway IAM key should be limited to the Coffre project and only the
Instance, IP, security-group, and Private Network operations needed by the
ephemeral runner. The protected environment should require reviewer approval.
The runner resolves the exact `equisafe-coffre` Private Network inside the
configured project and fails on zero or multiple matches; no extra Terraform
output has to be copied for it.

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

`deploy/migration.Dockerfile` is a minimal, digest-pinned migration image. It
contains the migration files and production database dependencies, but no
credentials. `scripts/migrate-on-scaleway.sh` transfers credentials only to
the ephemeral host, mounts the root-only CA path into one-shot containers, and
removes the sensitive files before destroying the host.

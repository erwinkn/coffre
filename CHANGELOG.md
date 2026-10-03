# Release notes

## Unreleased

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

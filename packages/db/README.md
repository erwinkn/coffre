# @coffre/db

coffre's database: the Drizzle schemas for Postgres and for SQLite, which
coffre uses in tests and local development, their migrations and the
migrator, the helpers for what the two engines do differently, and the
connections, Hyperdrive's included.

A deployment does not import it. `@coffre/server` runs its migrations with
`coffre-server migrate`. The server and vault open the same database with
separate logins, `coffre_runtime` and `coffre_vault_runtime`. The migrations
grant each its own rights; only the owner runs migrations.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.

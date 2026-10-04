# @coffre/db

coffre's database: the Drizzle schemas for Postgres and for SQLite, which
coffre uses in tests and local development, their migrations and the
migrator, the helpers for what the two engines do differently, and the
connections, Hyperdrive's included.

A deployment does not import it. Its own CLI applies the migrations,
`pnpm exec coffre migrate`, before the deploy; `coffre-server migrate` does
the same for local SQLite and tests. The server and vault open the same database with
separate logins, `coffre_runtime` and `coffre_vault_runtime`. The migrations
grant each its own rights; only the owner runs migrations. The owner needs
`CREATEROLE` and `CREATEDB`, and `ADMIN OPTION` on existing group roles.
Superuser is not required.

Node connections accept `sslrootcert=system` with `sslmode=verify-full`
and use Node's default trusted CAs. They check both the certificate chain
and the database hostname.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.

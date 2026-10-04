# @coffre/conformance

Checks a coffre deployment from outside: what it must never do, whatever
code it runs. `coffre-conformance workers|node [<dir>]` boots the deployment
in `<dir>` on its own keys and a scratch database, takes a handful of people
through it, and checks, among others, that no value leaks into any page,
table or log, that every read has the vault's entry in the shared log, every stored
version has the app's entry naming its vault wrap, and that
tampering with either author's entries is caught. Workers takes
`--postgres <owner URL>`, `--runtime <coffre_runtime URL>` and
`--vault-runtime <coffre_vault_runtime URL>` on a local Postgres server;
it creates and drops its own database. Node uses one temporary SQLite file
for both processes. Neither run uses the deployment's real database or keys. A running
instance is checked from outside by the CLI, `coffre verify instance`
(`@coffre/cli`), which the run takes too; see
[Against a running instance](https://github.com/erwinkn/coffre/blob/main/docs/conformance.md#against-a-running-instance).

`@coffre/conformance/idp` is the stand-in identity provider it signs in
with, which plays GitHub, an OIDC provider and Cloudflare Access, and a CI
platform that signs ID tokens for its runs.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.

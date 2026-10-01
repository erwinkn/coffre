# @coffre/conformance

Checks a coffre deployment from outside: what it must never do, whatever
code it runs. `coffre-conformance workers|node [<dir>]` boots the deployment
in `<dir>` on its own keys and a scratch database, takes a handful of people
through it, and checks, among others, that no value leaks into any page,
table or log, that every read is audited in both logs, and that tampering
with either log is caught. `coffre-conformance probe <url>` checks a running
instance from outside, without changing it: as no one, and with a service
token that reads one canary (`--token`, `--canary`); see
[Against a running instance](https://github.com/erwinkn/coffre/blob/main/docs/conformance.md#against-a-running-instance).

`@coffre/conformance/idp` is the stand-in identity provider it signs in
with, which plays GitHub, an OIDC provider and Cloudflare Access.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its seven `@coffre/*` packages are
released together, at one version. MIT licensed.

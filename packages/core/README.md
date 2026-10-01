# @coffre/core

What coffre's other packages share: access rules, envelope encryption, the
key-encryption keys (a local key, or AWS KMS), the audit chain, identity and
sign-in, and `Vault`, the contract between the server and the vault.

A deployment does not import it. `@coffre/server` and `@coffre/vault`
re-export what a deployment needs from it.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its seven `@coffre/*` packages are
released together, at one version. MIT licensed.

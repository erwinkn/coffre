# @coffre/vault

coffre's vault: the keys and who holds what. It decides every read and
write of a key and appends to the shared audit log as `vault`. It runs as a
Worker beside the app's Worker, or as its own process on Node. Both use
one Postgres database, each through its own restricted login:

```ts
import { postgres, vault } from '@coffre/vault/cloudflare';

export default vault((env) => ({
  database: postgres(env.VAULT_HYPERDRIVE), // coffre_vault_runtime, caching disabled
  kek: { id: env.KEK_ID, key: env.KEK }, // or awsKms({ keyArn, credentials }), with a signingKey
  rootAdmins: env.ROOT_ADMINS.split(','),
}));
```

On Node, `serveVault({ socket, database, … })` from `@coffre/vault/node`,
with the vault's Postgres URL. Only `coffre_vault_runtime` may write members
and grants; the app uses `coffre_runtime`. See the
[deploy guide](https://github.com/erwinkn/coffre/blob/main/docs/deploy.md)
for the logins and both Hyperdrive configs.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.

# @coffre/vault

coffre's vault: the keys, who holds what, and a log of its own. It decides
every read and write of a key and the app never holds one. It runs as a
Durable Object beside the app's Worker, or as its own process on Node:

```ts
import { vault } from '@coffre/vault/cloudflare';

export default vault((env) => ({
  kek: { id: env.KEK_ID, key: env.KEK }, // or awsKms({ keyArn, credentials })
  rootAdmins: env.ROOT_ADMINS.split(','),
  signingKey: env.SIGNING_KEY,
}));
```

On Node, `serveVault({ … })` from `@coffre/vault/node`.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its seven `@coffre/*` packages are
released together, at one version. MIT licensed.

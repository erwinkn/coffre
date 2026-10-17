# Read coffre from tools that speak Vault

coffre can answer as a HashiCorp Vault KV v2 store. It is read only, and a
deployment opts in. Tools that read secrets from Vault can then read them
from coffre: External Secrets Operator (ESO), the `vault` CLI, vals and
helmfile, Terraform, and GitHub's vault-action. Each read is coffre's own
reveal, as the token's holder. The same access rules apply, the same vault
opens the value, and the audit log records the read under the token's
name. The design, and why each piece is as it is, is in
[design/plugins.md](design/plugins.md).

To run `coffre` itself in a pod instead, without ESO and without a stored
token, see [kubernetes.md](kubernetes.md).

## Turning it on

The adapter is a plugin, `vaultKv`. Add it to the deployment's
configuration, `app/src/coffre.ts`, beside what it holds already. On
Workers:

```ts
import { vaultKv } from '@coffre/server/plugins/vault-kv';

export const coffre = createCoffre((env: Env) => ({
  // …publicUrl, database, vault, auth, auditChainKey, as they are
  plugins: [vaultKv()],
}));
```

On Node, the same line in the configuration object:

```ts
export const coffre = createCoffre({
  // …publicUrl, database, vault, auth, auditChainKey, as they are
  plugins: [vaultKv()],
});
```

Then add one route, `app/src/routes/v1.$.ts`, which hands every request
under `/v1` to coffre, as `api.$.ts` does for `/api`:

```ts
import { createFileRoute } from '@tanstack/react-router';
import { plugin } from '@coffre/server/routes';

export const Route = createFileRoute('/v1/$')({ ...plugin });
```

Build and deploy. The mount is `secret`, as in Vault, and
`vaultKv({ mount: 'kv' })` changes it. The adapter needs coffre's own
sign-in. Behind Cloudflare Access, a Vault token would have to be Access's
own short-lived assertion, which these tools cannot get.

## Paths

A Vault path names a coffre environment, or one key in it:

| Vault path | coffre |
|---|---|
| `secret/data/market/prod` | every value of `market/prod`, as one map |
| `secret/data/market/prod/STRIPE_KEY` | `{ "STRIPE_KEY": "…" }` |

A fork that inherits reads its parent's values, as `coffre export` does,
and needs read on the parent. Folders are not part of the path.

## A token for each reader

Each tool reads as a coffre service account, with a token of its own. For
example, ESO in a cluster reading `market/prod`:

```sh
coffre admit eso --service --grant market/prod=viewer
coffre tokens issue eso --label external-secrets --expires-in 90 --output-file eso-token
tr -d '\n' < eso-token | kubectl create secret generic coffre-token -n apps --from-file=token=/dev/stdin
rm eso-token
```

The file ends with a newline. ESO hands the token to Vault's client as it
is, and the client refuses a token with a newline in it, so `tr` drops the
newline first.

The token reaches what the account held when it was issued, never more.
`vault token lookup` (Vault's `auth/token/lookup-self`) shows how long it
has left. ESO checks the same thing before it marks the store Ready. Issue
the next token before this one runs out. To end one early:
`coffre tokens revoke eso <id> --apply`.

A person can use the `vault` CLI as themselves. Their CLI session works, and
so does a personal token, which is the better choice for a script:
`coffre tokens issue --label vault-cli --scope market/staging=viewer`.

## External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: { name: coffre, namespace: apps }
spec:
  provider:
    vault:
      server: https://secrets.acme.example
      path: secret
      version: v2
      auth:
        tokenSecretRef: { name: coffre-token, key: token }
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: { name: market, namespace: apps }
spec:
  secretStoreRef: { name: coffre, kind: SecretStore }
  refreshInterval: 15m
  target: { name: market-env }
  dataFrom:
    - extract: { key: market/prod }          # every value, one key each
  data:
    - secretKey: stripe
      remoteRef: { key: market/prod, property: STRIPE_KEY }
```

The two entries are alternatives, shown together. `dataFrom` takes every
value, and `data` takes the ones it names. Each entry is a read of its own,
so this manifest reads `market/prod` twice per refresh. A read writes one
audit entry for each environment it opens values in, naming the keys:
one for a plain environment, plus one per parent for a fork that
inherits, and per source for references into another environment.

A secret that is not there answers 404. That happens for an environment or
a key that does not exist, or one that was archived or deleted. ESO reads a
404 as the secret gone, and with `deletionPolicy: Delete` it deletes its
target. A `property` the environment lacks is different: the read of
`market/prod` succeeds, and ESO reports that the property is missing and
keeps the target. To have a key's archiving remove it from the target,
read the key by its own path, so that its absence is the 404:

```yaml
  data:
    - secretKey: stripe
      remoteRef: { key: market/prod/STRIPE_KEY, property: STRIPE_KEY }
```

Nothing else answers 404. A wrong path, a query, or anything coffre
does not serve answers 400 or 405, and an outage answers 503, so ESO
reports an error and keeps what it has.

Not supported:

- `dataFrom.find`, which lists paths.
- `metadataPolicy: Fetch`.
- `remoteRef.version`.

### Without a stored token: Kubernetes auth

ESO can sign in with a token Kubernetes signs for a service account of the
cluster's, through the coffre service account's trust bindings, so the
cluster stores no coffre token.

1. Trust the cluster's service account, here `eso-reader` in namespace
   `apps`, as coffre's `eso`. This is [kubernetes.md](kubernetes.md)'s
   first step, with its keys uploaded:

   ```sh
   coffre admit eso --service --grant market/prod=viewer
   coffre trust eso --issuer "$ISSUER" --jwks-file cluster-jwks.json \
     --claim sub=system:serviceaccount:apps:eso-reader \
     --claim kubernetes.io.serviceaccount.uid="$UID_"
   ```

   This previews the binding: its issuer, its keys by `kid` and its claims.
   Check them, then run it again with `--apply` to save it.

2. Point the SecretStore's auth at it. The role is the coffre service
   account, and the audience is coffre's URL, which the binding expects:

   ```yaml
   auth:
     kubernetes:
       mountPath: kubernetes
       role: eso
       serviceAccountRef:
         name: eso-reader
         audiences: [https://secrets.acme.example]
   ```

   ESO's own service account needs RBAC to `create` `serviceaccounts/token`
   for `eso-reader`.

On each sign-in, ESO asks Kubernetes for a new ten-minute token for
`eso-reader` and sends it as `PUT /v1/auth/kubernetes/login`. coffre trades
it as `coffre login --service` would: it checks it against the bindings,
spends it, and issues a credential of five minutes. ESO reads with that
credential, then ends it with `revoke-self`.

The token is spent at its first sign-in, so give ESO `serviceAccountRef`,
which gets a new one each time. A `secretRef` or a mounted token signs in
once, and is then refused as `replayed`. Unless ESO runs with
`--enable-vault-token-cache`, each refresh signs in and out again, so the
audit log shows a `token.exchange` and a sign-out beside each read.

ESO's `jwt` auth sends the same login to its own mount:
`auth: { jwt: { path: jwt, role: eso, kubernetesServiceAccountToken: {
serviceAccountRef: { name: eso-reader }, audiences: [https://secrets.acme.example] } } }`.

## Other tools

**The `vault` CLI.**

```sh
export VAULT_ADDR=https://secrets.acme.example VAULT_TOKEN="$(cat token)"
vault kv get secret/market/prod
vault kv get -field=STRIPE_KEY secret/market/prod
```

`vault kv get` prints `custom_metadata.coffre_version`, the environment's
version, which changes whenever a read would. `-wrap-ttl`, `kv put`, `kv
list` and `kv metadata` are refused.

**vals and helmfile.** `ref+vault://secret/market/prod#/STRIPE_KEY`, with
`VAULT_ADDR` and `VAULT_TOKEN` set.

**Terraform.** Set `skip_child_token = true` on the provider. Without it,
the provider asks Vault for a child token, and coffre mints none.

```hcl
provider "vault" {
  address          = "https://secrets.acme.example"
  skip_child_token = true
}

data "vault_kv_secret_v2" "market" {
  mount = "secret"
  name  = "market/prod"
}
```

**GitHub's vault-action** (`hashicorp/vault-action`) with `method: token`.
It takes paths as Vault does, `data/` included. Its `secrets` input
separates entries with `;`:

```yaml
- uses: hashicorp/vault-action@v3
  with:
    url: https://secrets.acme.example
    method: token
    token: ${{ secrets.COFFRE_TOKEN }}
    secrets: |
      secret/data/market/prod STRIPE_KEY ;
      secret/data/market/prod DATABASE_URL
```
 In a GitHub workflow, coffre's own Action and its OIDC sign-in
need no stored token ([ci.md](ci.md)), which is the better choice there.
vault-action's `method: jwt`, with `role` the coffre service account and
`jwtGithubAudience` coffre's URL, signs in with the run's ID token through
the account's GitHub binding, as coffre's Action does.

**consul-template and envconsul.** Set `renew_token = false`: coffre's
tokens are not renewed.

**Not supported:** Vault Agent, which needs tokens it can renew, and
Vault's CSI provider, which signs in by Kubernetes auth only.

## Why GET reveals here

coffre's own API reveals a value only to a POST, so that a link, a prefetch
or another site's image cannot read a value with a person's browser cookie.
The Vault adapter answers GETs, as Vault does, and none of those risks
apply:

- Its token comes only from the `X-Vault-Token` header. It never reads a
  cookie, not even coffre's own session.
- Another site's page cannot set that header without asking the browser
  first (a CORS preflight), and coffre never says yes.
- Every answer is `cache-control: no-store`.

## Without the plugin: ESO's webhook provider

ESO can read coffre's own API with no plugin, through its generic
`webhook` provider. That provider is alpha in ESO and supports less:
`dataFrom.find` errors, and the token's Kubernetes Secret must carry the
label `external-secrets.io/type: webhook`.

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: { name: coffre-webhook, namespace: apps }
spec:
  provider:
    webhook:
      url: https://secrets.acme.example/api/reveals
      method: POST
      headers:
        Content-Type: application/json
        Authorization: "Bearer {{ .creds.token }}"
      body: '{"path":{{ .remoteRef.key | toJson }}}'
      result:
        jsonPath: "$.values"
      secrets:
        - name: creds
          secretRef: { name: coffre-token, key: token }   # labeled external-secrets.io/type: webhook
```

With it, `dataFrom: [{ extract: { key: market/prod } }]` reads every value.
For one key, template the path:
`result: { jsonPath: "$.values.{{ .remoteRef.property }}" }`.

## Checking it by hand

`dev/vault-kv/main.go` makes ESO's calls through HashiCorp's own Go client
against `pnpm dev`. It is a manual check, kept for when a client changes,
and the test suite does not run it. Its header comment says how to run it.
`packages/server/test/vault-kv.test.ts` sends the same requests in the
suite.

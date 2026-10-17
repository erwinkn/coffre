# Secrets in Kubernetes

A pod signs in as a service account by OIDC with the token Kubernetes signs
for its own service account, and stores no coffre secret. The cluster need
not be reachable from coffre: its keys are uploaded with the trust binding
([Issuers coffre cannot reach](ci.md#issuers-coffre-cannot-reach)), so a
private cluster works, such as a Scaleway Kapsule cluster whose issuer is a
`.local` name or an address on a private network.

To sync coffre's values into Kubernetes Secrets with External Secrets
Operator instead, see [vault.md](vault.md).

Say the pod runs as Kubernetes service account `deploy`, in namespace `ci`,
and reads `market/prod` as coffre's `service:api-deploy`.

## 1. Trust the cluster's service account

Read three things from the cluster: its issuer, exactly as its tokens name
it; its public keys; and the service account's UID.

```sh
ISSUER="$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)"
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
UID_="$(kubectl get serviceaccount deploy -n ci -o jsonpath='{.metadata.uid}')"
```

Then admit the service account and trust the pod's tokens:

```sh
coffre admit api-deploy --service --grant market/prod=viewer
coffre trust api-deploy --issuer "$ISSUER" --jwks-file cluster-jwks.json \
  --claim sub=system:serviceaccount:ci:deploy \
  --claim kubernetes.io.serviceaccount.uid="$UID_"
```

The preview shows the binding: the issuer, the keys by `kid`, and the
claims. `--apply` saves it. In the pages: the service account's page, "Trust
a workload", "Other issuer", with the keys pasted under Keys and the UID
claim on a line of its own.

`sub` names the account by namespace and name. A name can be used again:
delete `deploy` and make a new one, and the new account has the same `sub`.
`kubernetes.io.serviceaccount.uid` is a nested claim, named by its path. It
holds the account's UID, which no later account shares, so a binding that
names it trusts that one account only.

## 2. Give the pod a token for coffre

Project a service-account token whose audience is your instance's URL. The
kubelet writes it to a file and refreshes it before it expires:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: api, namespace: ci }
spec:
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: deploy
      containers:
        - name: api
          image: registry.acme.example/api:1.4.2
          command: ["sh", "-c"]
          args:
            - export HOME="$(mktemp -d)" &&
              coffre login https://secrets.acme.example --service api-deploy --id-token < /var/run/secrets/coffre/token &&
              exec coffre run market/prod -- ./start
          volumeMounts:
            - { name: coffre-token, mountPath: /var/run/secrets/coffre, readOnly: true }
      volumes:
        - name: coffre-token
          projected:
            sources:
              - serviceAccountToken:
                  audience: https://secrets.acme.example
                  expirationSeconds: 600
                  path: token
```

`coffre login --id-token` reads the token from stdin, trades it for a
credential that lasts five minutes, and saves it as the session.
`coffre run` then starts the app with the secrets in its environment.

Two limits shape the projection:

- **An hour at most.** A binding with uploaded keys refuses a token whose
  lifetime, `exp` minus `iat`, is over an hour, and every exchange refuses
  one issued over an hour ago. coffre cannot ask a private cluster whether a
  token still stands, so the hour bounds what a copied token is good for.
  `expirationSeconds` is at most 3600; 600 is the shortest Kubernetes allows.
- **Each token signs in once.** A container that restarts reads the same
  file, and its token is spent: the exchange is refused as `replayed` until
  the kubelet writes a new one, at 80% of the token's lifetime. With 600
  seconds, that is at most eight minutes; with 3600, 48. So the shorter
  projection is the better one. A process that needs coffre again later
  keeps what `coffre run` gave it rather than signing in again.

## 3. When the cluster rotates its keys

Kubernetes signs tokens with the key its API server is given, and serves
the public key at `/openid/v1/jwks`. To rotate, the cluster's operator (on
a managed cluster, the provider) adds the new key, serves both for a while,
then signs with the new one and drops the old. A binding verifies with the
keys uploaded with it, and nothing else. So a token signed by the new key is
refused, `unknown_key`, until coffre has that key too.

Upload the cluster's keys again as soon as the new one is served, while the
set holds both:

```sh
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
coffre trust api-deploy --issuer "$ISSUER" --replace-keys --jwks-file cluster-jwks.json
```

The preview names each binding of `service:api-deploy` on the issuer.
`--apply` replaces every one with a binding that is the same except for its
keys. A set of the old key and the new takes tokens signed by either, so
pods keep signing in across the rotation. Once the old key is gone from
`/openid/v1/jwks`, run the same two commands again to drop it from coffre.

Replacing a binding ends the credentials it issued, at most five minutes'
worth: a pod that signed in in the last few minutes signs in again with its
next token. Each coffre service account that trusts the cluster has its own
bindings, and its keys are replaced on their own: run `--replace-keys` for
each.

In the pages, open a binding's Claims, then Replace keys.

## What it does not do

- **No live revocation.** Deleting a pod or the service account does not
  revoke a token it was given: coffre verifies offline, with the uploaded
  keys, and does not ask the cluster (Kubernetes' TokenReview). A token
  stays good for its hour, once. To cut a pod off at once, remove the
  binding (`coffre untrust api-deploy <binding-id> --apply`) or the service
  account's grant.
- **No discovery.** coffre never fetches the issuer's keys, so it learns of
  a rotation only when you upload the new keys.

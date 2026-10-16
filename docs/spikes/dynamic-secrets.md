# Dynamic secrets: credentials coffre mints per job

> W108, 2026-10-16, on 0.6.0 (`2d49645e`). An experiment, not a plan of
> record: the prototype on branch
> `bb/w108-dynamic-secrets-credentials-coffre-mints-pe-thr_4grrnwduzn` is
> for judging the options and is not meant to merge as it is.

## The problem, with Equisafe's numbers

Equisafe's CI keeps the `equisafe-release` GitHub App's private key and six
R2 API tokens made by hand. Every job that can read `ci/prod` gets the App's
key itself, so it can mint a token for every repository the App reaches,
with every permission the App holds, for as long as the key lives. The R2
tokens are the same: each one is good until someone revokes it.

What they want instead:

- coffre holds the App's key, and a job that reads `infra/ci` gets
  `GITHUB_TOKEN`, an installation token for `equisafe/infra` with
  `contents: write`, which dies within the hour;
- coffre holds one parent R2 token, and a job gets R2 keys for one bucket
  and prefix, which die after 15 minutes.

Nobody, not even an Owner, reads the App's key or the parent token. People
and jobs can only mint from them.

## Facts that shape the design

**GitHub.** `POST /app/installations/{id}/access_tokens`, signed with a JWT
from the App's private key, takes `repositories` (at most 500, by name) and
`permissions` (each `read` or `write`, within the App's own). The token
always lasts one hour, and no request makes it shorter. Anyone holding the
token can revoke it early with `DELETE /installation/token`.

**R2.** A temporary R2 credential can be made two ways, and neither needs
permission to create API tokens:

- *Signed locally.* Build an HS256 JWT over `{bucket, scope, paths, sub:
  accountId, iss: parentAccessKeyId, aud: <account>.r2.cloudflarestorage.com,
  iat, exp}`, keyed by the parent token's secret access key. The access key
  ID is the parent's, the secret is the SHA-256 hex digest of the JWT, and
  the session token is `base64("jwt/" + jwt)`. No network call is made
  ([Cloudflare's example](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/)).
- *By API.* `POST /accounts/{id}/r2/temp-access-credentials` with
  `Authorization: Bearer <parent R2 token>` and `{bucket, parentAccessKeyId,
  permission, ttlSeconds ≤ 604800, prefixes?, objects?}`.

A temporary credential can't do more than its parent, and revoking the
parent ends every derived credential at once. So the root here is one R2
API token, made once by hand in the dashboard with Object Read & Write on
the buckets it may delegate.

**Error 9109** comes from making *account API tokens* (`/accounts/{id}/tokens`).
That needs the permission "Account API Tokens: Edit", made by a Super
Administrator or, since 2026-10-01, by a member with the "API Token
Provisioning" role. R2 doesn't need it. Only a future "mint a whole
Cloudflare API token" provider would.

**Where coffre stands today.** Two decisions point the other way, and both
change if we do this:

- `docs/github-app.md`: the App's key lives with the app Worker, not the
  vault, because "it opens no secret". A minting App's key opens a lot,
  so it belongs in the vault.
- `docs/roadmap.md`, Decided: "the deploy pipeline holds its platform's
  write credentials". Dynamic secrets are coffre holding the root of those
  credentials and handing the pipeline only short-lived ones.

## Three ways to model it

### A. Minted keys, declared in the vault's configuration (prototyped)

The deployment's vault code names the root and each key it mints. The
example below is the prototype's exact API:

```ts
const release = githubApp({ appId: env.RELEASE_APP_ID, privateKey: env.RELEASE_APP_KEY });
const assets = r2({ accountId: env.CF_ACCOUNT_ID, accessKeyId: env.R2_PARENT_ID, secretAccessKey: env.R2_PARENT_SECRET });

export default vault((env) => ({
  kek, owners,
  minted: [
    { at: 'infra/ci', keys: { token: 'GITHUB_TOKEN' },
      from: release.tokens({ account: 'equisafe', repositories: ['infra'], permissions: { contents: 'write' } }) },
    { at: 'web/prod', keys: { accessKeyId: 'R2_ACCESS_KEY_ID', secretAccessKey: 'R2_SECRET_ACCESS_KEY', sessionToken: 'R2_SESSION_TOKEN' },
      from: assets.credentials({ bucket: 'web-assets', scope: 'object-read-write', prefixes: ['releases/'], ttlSeconds: 900 }) },
  ],
}));
```

`RELEASE_APP_KEY` and `R2_PARENT_SECRET` are secrets of the vault Worker.
Cloudflare never shows a Worker secret back, and coffre stores neither in
its database.

Reading works as it does today:

- `coffre export --format github infra/ci` writes `NPM_TOKEN` (stored) and
  `GITHUB_TOKEN` (minted for this read), and masks both. The Action and the
  CLI don't change.
- `coffre run infra/ci -- ./release.sh` does the same.
- `coffre get infra/ci/GITHUB_TOKEN` mints one key.
- In the UI, the row would read `GITHUB_TOKEN · Minted · GitHub App 1001 ·
  contents:write on infra · 1 h`, and its button says "Mint one" instead
  of revealing. That button is logged like any read.

Access needs nothing new. Minting is reading, so it takes `secret.read` on
the environment, through a credential's scope like any read (`allows` in
`packages/core/src/access.ts`).

- A Viewer of `infra/ci` mints, but there is no value of the root to read,
  so "mint but never read the root" comes for free.
- An Admin, who sees no values, mints nothing.
- A Developer scoped to `dev` mints nothing in `prod`.
- R6 holds: the name `GITHUB_TOKEN` is visible across siblings, never a
  token.

Pros:

- The smallest change: one config field, one vault method, two log actions.
- No migration, no new role, no new UI form.
- Changing what a key mints is a reviewed change to the deployment's code,
  and no coffre user can widen it.

Cons:

- Changing a scope means a deploy.
- Places are named by slug, so a renamed project silently mints nothing
  until the config follows. The real version should say so at sign-in and
  on the page.

### B. Minted keys as rows, sealed by the vault (like references)

The root stays in the configuration as a named *source* with a ceiling:

```ts
sources: { release: release.source({ places: ['infra/*'], repositories: ['infra', 'deploy-actions'], permissions: { contents: 'write' } }) }
```

The recipe ("`infra/ci/GITHUB_TOKEN` = `release`, `infra` only, contents
write") becomes a row the app stores and a `mint.define` entry the vault
writes under its MAC. That entry *is* the recipe, the same way a
`reference.create` entry is a reference today. To write a recipe, you need
`secret.write` on the place. The vault refuses one that leaves the place or
goes past the ceiling.

In the UI, "New key › Minted from › release" opens a form with the
repository picker that already exists (`GET /workloads/repositories`).

Pros:

- Recipes are edited in coffre, without a deploy.
- Each environment narrows its own.

Cons:

- Two layers of policy: the config's ceiling and the row's recipe.
- A migration for the rows, a vault write path, and a form.
- More to audit and more to get wrong.

About twice A's work.

### C. Mint on request, like AWS STS

Sources plus a new `credential.mint` permission. The job asks for what it
needs:

```yaml
- uses: erwinkn/coffre/action@v0.7.0
  with: { url: …, service: token:infra-release, mint: 'github: infra contents=write' }
```

Pros:

- Least privilege picked per job.
- Familiar to AWS users.

Cons:

- A permission whose meaning depends on a cap ("up to contents:write on
  these repositories") doesn't fit `access.ts`, where a check is a lookup
  of constants.
- A new CLI command, Action input and UI page.
- Doesn't compose with `run`/`export`.
- Every workflow must spell out scopes it shouldn't need to know.

Most of the surface for the least gain at Equisafe's scale.

### Where the root lives, which is a separate choice

1. **The vault's configuration**, from the vault Worker's secrets (A, B
   and C alike; prototyped). It is handled the same way as the KEK.
   Rotating it is `wrangler secret put`, then a deploy, which coffre's log
   doesn't see.
2. **A write-only coffre secret.** It is stored like any value, but marked
   so the vault never releases its key to the app. The vault decrypts it
   itself, only to mint. Rotation then goes through coffre, logged, and
   the rotation work applies to roots as to any secret. The cost: the
   vault starts decrypting values itself (today it only unwraps data keys,
   and the app decrypts), and the "write-only" mark has to be the vault's
   own record, or a database owner could flip it.

## Where minting runs: the vault

It runs in the vault, not the app. If the App's key sat in the app Worker,
a compromised app could mint anything with no vault entry. In the vault,
every mint is a decision the vault made and logged under its MAC, as every
read is.

The vault already calls out to other services (AWS KMS), so outbound fetch
from a vault Worker isn't new. The prototype's `vault.mint` follows the
same intent/outcome pattern, without holding a transaction across the call:

1. The app calls `vault.mint` with no transaction open (AGENTS.md).
2. **Vault transaction 1:** lock the member, check `secret.read`, append a
   `credential.mint` intent per minted entry, commit.
3. **No transaction:** call each provider in parallel within 15 s. GitHub
   takes two requests: the repository's installation, then the token. R2
   makes none.
4. **Vault transaction 2:** check the member again, then append a
   `credential.minted` outcome per entry, naming its intent, and commit.
   - A member removed or narrowed meanwhile gets nothing, and the outcome
     reads `withheld` (tested).
   - A provider that failed fails the whole read with 503 `unavailable`,
     the same way an unreadable reference stops a read rather than running
     without it.
5. The values go back to the app, which merges them into the environment's
   values. A key that is both stored and minted is a 409.

Notes on running it:

- **Isolate state:** nothing new. `GitHubApp` keeps its imported key, a
  settled value. Tokens aren't cached across reads: each job gets its own,
  so attribution and revocation stay per job.
- **Latency:** two vault transactions, plus about two GitHub round trips
  (a few hundred ms on github.com) per read that mints. Caching the
  installation ID would save one.
- **Rate limits:** an App's request limits on GitHub run to thousands an
  hour, far above CI volume. I found no separate limit on making tokens;
  that still needs confirming. On coffre's side, the bulk limit counts only `secret.read` entries today,
  so mints should get their own cap, like the exchange's 60 a minute.
- **A vault that dies between the provider call and transaction 2** leaves
  an intent with no outcome: "minted, maybe". `key.intent` already has an
  accounting check that flags such orphans; mints should get the same.

## The audit trail

Each mint writes two vault entries, both carrying the run's `credentialId`.
The audit page already joins that ID to the run's `token.exchange` entry
(`run_id`, `sha`, `workflow_ref`, `repository`, …), and the prototype's test
checks that the page shows `run_id` on a mint.

```json
{ "action": "credential.minted", "actor": "token:infra-release", "relatedSeq": 412,
  "metadata": { "subject": "infra/ci", "keys": ["GITHUB_TOKEN"], "provider": "github-app",
    "scope": { "app": "1001", "account": "acme", "repositories": ["infra"], "permissions": { "contents": "write" } },
    "granted": { "permissions": { "contents": "write" }, "repositories": ["infra"] },
    "expiresAt": "2026-10-16T15:02:11.000Z", "fingerprints": { "GITHUB_TOKEN": "3f9c0a…" },
    "purpose": "run", "intent": "…", "credentialId": "…" } }
```

The fingerprint is the first 16 hex digits of the token's SHA-256. It isn't
enough to use the token, but it is enough to answer "this `ghs_…` turned up
in a build log: which job got it?". The test checks that no entry contains
a token.

Locally signed R2 credentials have nothing random in them: two mints in the
same second with the same scope are the same credential. Whether R2 accepts
a `jti` claim to tell them apart is an open question.

## Revocation and expiry

What happens when a binding or member is removed mid-job:

- **The job's coffre credential** is checked on every request, so its next
  read fails. Nothing new there.
- **A mint in flight** is withheld (step 4 above). GitHub has already made
  that token, though, and the prototype doesn't revoke it. The real version
  should, with `DELETE /installation/token`.
- **Credentials already handed out** live until they expire: up to 1 h for
  GitHub (fixed), and the configured TTL for R2 (15 min in the example).

There are three ways to go further:

1. **Short lifetimes only.** Accept "≤ 1 h" and say so on the page. This is
   what I recommend first.
2. **Leases.** The vault keeps each minted credential, sealed, until it
   expires. Removing a member or unbinding revokes their live ones. This
   works for GitHub, which revokes one token at a time. R2 can only revoke
   the parent, which ends everyone's. Postgres roles (below) *need* leases,
   since nothing else drops the role.
3. **The emergency brake.** Suspend the App's installation, or roll the R2
   parent token. Either ends everything at once.

## Providers

The interface (in `packages/core/src/mint.ts`), with the deployment passing
providers in code and no environment variables:

```ts
interface Minter {
  provider: string;                       // 'github-app', 'r2'
  fields: readonly string[];              // ['token'], ['accessKeyId', 'secretAccessKey', 'sessionToken']
  scope: Readonly<Record<string, unknown>>; // what it mints, logged with each mint
  mint(signal: AbortSignal): Promise<{ values: Record<string, string>; expiresAt: string; granted?: object }>;
  // Not yet: revoke?(minted): Promise<void>, for leases.
}
```

- **GitHub App** (prototyped): `githubApp(…).tokens({ account,
  repositories, permissions })`. Each mint makes two requests.
- **R2** (prototyped): `r2(…).credentials({ bucket, scope, prefixes?,
  objects?, ttlSeconds })`. It signs locally and makes no requests.
  It is checked against Cloudflare's published derivation, never against
  R2 itself.
- **AWS STS:** `AssumeRole` from an IAM user's keys, three fields like R2.
  Better still, `AssumeRoleWithWebIdentity` with coffre as the OIDC
  issuer. coffre would sign an ID token with a key only the vault holds,
  and AWS would trust coffre's issuer, so no AWS root key is stored at all.
- **Postgres roles:** `CREATE ROLE … LOGIN PASSWORD … VALID UNTIL …;
  GRANT app_reader TO …`. `VALID UNTIL` only stops new logins, so the role
  has to be dropped later. This is the one that needs `revoke` and a
  cleanup pass.
- **GCP:** the IAM Credentials API's `generateAccessToken` for a service
  account (1 h, OAuth scopes), from a key JSON, or from coffre as an OIDC
  issuer through workload identity federation.

The interface generalizes. What differs between providers is the number of
fields, whether they touch the network, and whether expiry is enforced by
the provider (GitHub, R2, STS, GCP) or by coffre (Postgres).

## Where this meets rotation

- **Rotating a root.** For the App key: generate a second key on GitHub,
  put it in, deploy, then delete the first. Tokens it already minted keep
  working until their hour is up (I believe so, but haven't confirmed
  it). For the R2 parent: make a new token, swap it in, wait one TTL,
  then revoke the old one. Revoking first ends every live credential.
- **If roots become write-only coffre secrets** (choice 2 above), rotating
  them is just rotating a secret, and the rotation design covers it.
- **Minted keys have no age.** The 0.6 "Rotate" tag should never show on
  them; the row says "minted per read".

## What the prototype leaves out

- `about()` doesn't list minted keys yet. The page and the `coffre missing`
  gate need that list, so the gate counts a minted key as present and the
  page draws its row. The reveal path also asks the vault on every
  environment read once anything is minted, instead of knowing beforehand.
- No UI.
- No `revoke`.
- No mint cap or bulk-limit share.
- No orphan-intent accounting.
- MCP tools mint like any reader. They should probably be refused minted
  keys at first.
- Forks and comparisons skip minted keys, which is right, but untested.
- The Workers RPC path compiles but is untested. Only the in-process
  transport is exercised.

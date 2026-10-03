# OIDC login for services

A proposal, written on 2026-10-03, for review before any code.

A CI job proves who it is with the ID token its platform signs for it, and
trades it for a coffre credential that lasts five minutes. That replaces the
service token kept for up to a year in the CI's secret store. Service tokens
stay as the fallback. This is for coffre's own sign-in; behind Cloudflare
Access, CI keeps Access service tokens.

Say `token:api-deploy` holds `viewer` on `market/prod`, and an owner binds it
to `deploy.yml` pushed to `main` of `acme/api`. The job holds no secret:

```yaml
permissions: { id-token: write, contents: read }
steps:
  - run: coffre run market/prod -- ./deploy.sh
    env: { COFFRE_API_URL: https://secrets.acme.example, COFFRE_SERVICE: token:api-deploy }
```

## 1. Trust bindings

A binding belongs to one service: an issuer, and claims a token must carry.

```json
{ "issuer": "https://token.actions.githubusercontent.com",
  "claims": { "repository_owner_id": "9919", "repository_id": "41532",
              "workflow_ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main",
              "event_name": "push" } }
```

A token matches when its `iss` is the issuer byte for byte and each claim is
a top-level string of exactly that value. Any one of a service's bindings is
enough: two branches are two bindings.

**What a binding must name.**
- At least one claim besides `iss`, `aud` and the times.
- For an issuer shared by every customer of a platform, the claim that names
  the customer: GitHub's `repository_owner_id`, GitLab.com's `namespace_id`,
  Buildkite's `organization_slug` or Google's `sub`. On GitHub, also a
  repository (`repository_id`) or a reusable workflow (`job_workflow_ref`),
  never a whole organization.
- CircleCI, Fly.io and Kubernetes issue from one URL per customer, so the
  issuer is enough there.

**No wildcards in v1.** Patterns are where claim confusion lives:
`repo:acme/api:*` also matches `repo:acme/api:pull_request`. Exact values
fail closed, so a pattern can come later if a real case needs one.

## 2. The exchange

`POST /api/auth/oidc {"service": "token:api-deploy", "token": "<JWT>"}`
answers `{"token": "coffre_svc_…", "expiresAt": "…"}`.

- **The caller names the service.** AWS's `AssumeRoleWithWebIdentity` names
  a role the same way. Only that service's bindings are read, so two
  services can't be confused, and the log shows what was asked.
- **It is an ordinary service credential,** with the member's generation and
  the binding that issued it. Each request asks the vault what its principal
  holds, so the credential carries exactly the service's grants.
- **It lasts five minutes.** It stays in the asking process, never in a file
  or a later step. `coffre run` needs it for seconds, to fetch before it
  starts the command. Asking again costs one request, so a longer life would
  only keep a leaked credential alive.
- **It is audited as the service.** A `token.exchange` entry, beside
  `token.create`, names the binding, the issuer, `sub`, `jti`, the bound
  claims and the run (GitHub's `run_id` and `sha`).
- **A refusal is a 401, with no audit entry,** like an unknown bearer token.
  Anyone can mint a genuine token from their own repository, so logged
  refusals would let anyone fill the log. The process log gets a line, and
  the answer says why: `expired`, `too_old`, `audience`, `replayed`, or
  `no_match`. `no_match` names the claims that differ, never the values
  expected. An unknown service and an unbound issuer answer the same.

## 3. Validation

Each step runs in order, and nothing is fetched before step 3.

1. **Shape.** A compact JWS of at most 8 KiB, decoded but not yet trusted.
2. **The service.** It is active, from the request's one `vault.access`. It
   holds a live binding of its current generation for the token's `iss`. So
   a stranger can only make coffre fetch URLs an owner set.
3. **The signature**, under the issuer's keys (section 4).
   - The algorithm is RS256 or ES256, as for Access assertions today; never
     `none` or HS\*.
   - No key or URL from the token's header (`jwk`, `jku`, `x5u`) is used.
   - RSA keys are at least 2048 bits.
4. **`aud`** is this instance's `publicUrl`, alone. So a token minted for
   another instance, or for another service as well, is refused. Platforms
   whose audience is fixed keep service tokens; Bitbucket's and Azure
   Pipelines' look fixed, and each preset will confirm.
5. **Times**, with 30 s of tolerance.
   - `exp` is in the future.
   - `nbf` and `iat` are not.
   - `iat` is at most an hour old. That fits tokens handed out at job start
     (GitLab's `id_tokens`, Kubernetes' projected tokens) and refuses
     day-old ones.
6. **The claims** match a binding that no `token.unbind` entry names
   (section 6).
7. **Single use.** The token's SHA-256 is stored with the credential it
   bought, under a unique index, so a token is spent once the job used it.
   This also works for issuers that send no `jti`. The rows go after two
   hours, past step 5's limit, and the audit entry stays.

The price is one credential per token. GitHub, CircleCI and Buildkite mint
tokens on demand, and the CLI asks each run. On GitLab, a job that runs
coffre twice declares two `id_tokens`, or wraps its steps in one `coffre run`.

## 4. Fetching keys, on Workers too

**Discovery runs once, when the binding is made.** coffre checks that the
document's `issuer` matches, and stores its `jwks_uri` in the binding, under
the MAC. The owner sees that URL before saving. An exchange fetches only that
URL. It never fetches a URL from a token, or a discovery document that
changed since. An issuer that moves its keys needs its bindings saved again.

**Every fetch is checked.**
- URLs are `https`, on port 443, with a host name. No IP literal, no user or
  password, no `localhost`, `.local` or `.internal`. On Workers, `fetch`
  reaches only the public internet. On Node, loopback, private, link-local
  (cloud metadata) and unique-local addresses are refused when connecting,
  so DNS rebinding can't slip past.
- A fetch has a 5 s timeout and follows no redirects. It needs a 200 with
  JSON, cut off past 64 KiB, and keeps at most 32 keys.
- The dev IdP's `http://127.0.0.1` is allowed only where the deployment
  allows it: in dev and conformance.

**The cache keeps settled values only,** per isolate: each key set by URL, with when it was
fetched. It never keeps a promise.
- Two first exchanges in one isolate each fetch, rather than one awaiting the other's request,
  which Cloudflare cancels as hung once the first ends (#57).
- Sets are kept ten minutes, for at most 64 URLs.
- An unknown `kid` refetches, at most once a minute per URL and isolate.

**When the issuer is down,** the answer is a 503 with `Retry-After`. coffre keeps no copy of
the keys in the database for this case, because an issuer that can't serve its keys can rarely
mint tokens. A job that must run anyway uses a service token.

## 5. Threats

- **The issuer is compromised.** Its key matches every binding on it, as at
  every cloud that trusts it: AWS, Google Cloud and Azure trust GitHub's
  tokens the same way. What bounds it:
  - each service holds only its own grants;
  - each exchange logs the run it claims, which the platform can confirm;
  - the bulk limit applies;
  - `coffre untrust --issuer <url>` drops every binding on an issuer.
- **Claim confusion.** GitHub presets bind single claims, never `sub`. An
  organization can change `sub`'s format, and a coarse one, such as owner
  only, matches every repository.
  - A `pull_request` run has a `ref` of `refs/pull/…/merge`.
  - A `pull_request_target` run has the base branch's `ref`, but another
    `workflow_ref` or `event_name`.
  - IDs, unlike names, can't be re-registered by someone else after a
    rename.
- **Another repository in the organization** matches no binding naming a
  repository. A reusable workflow is bound with the owner's ID, because
  anyone's repository can call a public one.
- **A token or credential in a job log.** The token is spent once used, and
  at most an hour old. The credential dies in five minutes, and keeps the
  `coffre_svc_` prefix that secret scanners know. The CLI prints neither,
  and the Action masks both.
- **SSRF and poisoned keys:** section 4.
- **A database owner adds or edits a binding:** it fails the app's MAC, and
  is refused as `auth_row_tampered`.

## 6. Where bindings live

**In the app, beside sign-in accounts.** A binding is to a service what an `identities` row is
to a person: "these runs are `token:api-deploy`" rather than "this GitHub user is
`user:ada@acme.example`". Both say who someone is. The app decides that; the vault decides what
they may decrypt.

**The table.** `service_bindings` keeps the principal, its generation, the issuer, the JWKS URL,
the claims and the revocation, under the app key's MAC like the sign-in rows. The label and
last use sit outside the MAC.
- Owners add and remove bindings, as `token.bind` and `token.unbind`.
- Removing a binding revokes its live credentials.
- A binding of an earlier generation is dead: removing the service ends it, and admitting the
  service again doesn't revive it.

**Why not in the vault?** The vault's sealed member record would add little.
- A compromised app already acts as any member.
- The app's MAC already refuses a forged or edited row.
- The one gap is a removed binding put back. A MAC proves a row genuine, not current, and a
  binding doesn't expire as a session does. So step 6 refuses a binding a `token.unbind` entry
  names, at the cost of one indexed lookup among rare entries. Deleting that entry breaks the
  chain, which the next checkpoint finds within five minutes, turning `/readyz` red.

The vault would refuse at once instead. It would cost bindings in `access`, two more vault calls,
and sign-in configuration in the vault. I don't think it's worth it, but it's the first call to
challenge.

## 7. UI, CLI and the Action

- **The UI.** A service's Tokens page gets a "Trusted workloads" list: issuer, claims, who added
  it, last use, and Remove.
  - Presets cover GitHub Actions, GitLab, CircleCI, Buildkite, Kubernetes and Google Cloud, plus
    any OIDC issuer.
  - The GitHub preset asks for repository, workflow, branch and event. It looks up the IDs of a
    public repository, or shows `gh api repos/acme/api --jq '.id, .owner.id'` for a private one.
  - Presets only fill in claims, shown in full before saving.
- **The CLI**, naming members as `coffre grant` does:
  ```sh
  coffre trust api-deploy                 # lists its bindings
  coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
  coffre trust api-deploy --issuer https://gitlab.com --claim namespace_id=12 --claim project_id=345 --claim ref=main
  coffre untrust api-deploy <binding-id>
  ```
- **In CI**, with `COFFRE_SERVICE` set and no `COFFRE_TOKEN`, the CLI exchanges a token itself.
  - It takes the token from `COFFRE_ID_TOKEN` or `COFFRE_ID_TOKEN_FILE` (a Kubernetes projected
    token).
  - On GitHub, it asks for one with the instance URL as audience.
  - It keeps the credential in memory, never in `~/.coffre`: a self-hosted runner's disk
    outlives the job.
- **The Action** needs `id-token: write`, and takes `service:` instead of `token:`. It calls
  `core.getIDToken(<instance URL>)`, exchanges the token, and masks both.

**Not in v1:**
- Cloudflare Access.
- Patterns, and claims that are nested or not strings.
- Issuers the internet can't reach: a binding with pasted keys would cover them, when asked.
- Narrower grants per binding: two needs mean two services.

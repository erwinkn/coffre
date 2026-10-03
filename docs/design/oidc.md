# OIDC login for services

A proposal, written on 2026-10-03 and revised the same day after an
independent review ([PR #90](https://github.com/erwinkn/coffre/pull/90)),
whose findings are answered at the end. There is no code yet.

A CI job proves who it is with the ID token its platform signs for it. It
trades that token for a coffre credential that lasts five minutes, instead of
keeping a service token for up to a year in the CI's secret store. Service
tokens stay as the fallback. This is for coffre's own sign-in; behind
Cloudflare Access, CI keeps Access service tokens.

Say `token:api-deploy` holds `viewer` on `market/prod`, and an owner binds it
to `deploy.yml` pushed to `main` of `acme/api`. The job holds no secret:

```yaml
permissions: { id-token: write, contents: read }
steps:
  - run: coffre run market/prod -- ./deploy.sh
    env: { COFFRE_API_URL: https://secrets.acme.example, COFFRE_SERVICE: token:api-deploy }
```

## 1. Trust bindings

A binding belongs to one service. It names a profile, an issuer, and the
claims a token must carry, each a top-level string matched exactly:

```json
{ "profile": "github", "issuer": "https://token.actions.githubusercontent.com",
  "claims": { "repository_owner_id": "9919", "repository_id": "41532",
              "workflow_ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main",
              "ref": "refs/heads/main", "event_name": "push" } }
```

**The server enforces each profile's minimum.** It checks every binding
against its profile, whether it comes from the UI, the CLI or the API, and
refuses one that lacks a required claim. A known issuer URL forces its
profile. A GitHub Enterprise Server or a self-managed GitLab picks its own.

| Profile | Required claims |
|---|---|
| `github`, a workflow of the repository | `repository_owner_id`, `repository_id`, `workflow_ref`, `ref`, `event_name` |
| `github`, a reusable workflow | `repository_owner_id`, `job_workflow_ref`, `job_workflow_sha`, `event_name`, and `repository_id` unless "any repository of the organization" is chosen explicitly |
| `gitlab` | `project_id`, `ref_type`, `ref`, `pipeline_source` |
| `buildkite` | `organization_id`, `pipeline_id`, `build_branch` |
| `circleci`, on the organization's own issuer | `oidc.circleci.com/project-id`, `oidc.circleci.com/vcs-ref` |
| `google`, a service account | `sub`, its unique ID |
| `custom`, any other issuer | `sub`, and the UI says the owner vouches for what it means |

Some rules within the profiles:
- **GitHub events.** `event_name` must be `push`, `workflow_dispatch`, `schedule` or
  `release`. Those events run only code that someone with write access put in the
  repository. `pull_request_target`, `workflow_run` and the like can run a stranger's
  code under the base branch's ref, so the server refuses them.
- **Reusable workflows.** A reusable workflow is trusted at one commit. Its path can be reused and
  its branch changed, so `job_workflow_sha` pins it. A new version needs a new
  binding. The caller's IDs say who may call it, not what it is.
- **GitLab.** `ref_type` tells branch `main` from tag `main`. `pipeline_source`, say `push`,
  keeps out merge-request pipelines, whose `project_id` names the source project.

**No wildcards.** Patterns are where claim confusion lives:
`repo:acme/api:*` also matches `repo:acme/api:pull_request`.

**Bindings are immutable.** Its profile, issuer, JWKS URL and claims never
change. Changing one revokes the binding and creates another, with a new ID
that is never reused, and both go in the log. Only the label and the time of
last use change in place.

## 2. The exchange

`POST /api/auth/oidc {"service": "token:api-deploy", "token": "<JWT>"}`
answers `{"token": "coffre_svc_…", "expiresAt": "…"}`. The caller names the
service, as AWS's `AssumeRoleWithWebIdentity` names a role, and only that
service's bindings are read. A stranger costs at most one indexed read:

1. **Admission.** The body is read as a stream and cut off at 16 KiB.
   Requests are limited per source address and per deployment before any
   database, crypto or network work, and answered 429 beyond. On Workers
   that's a rate-limiting binding in the deployment, which Cloudflare
   enforces per location. On Node, a limit per address and a bound on
   exchanges in flight, per process.
2. **Shape** (section 3).
3. **The binding.** One app query reads the service's live bindings for the
   token's `iss`, and checks each one's MAC. With none, the request is
   refused, with no vault call and no fetch.
4. **The token:** its signature, then audience, times and claims, and
   that it isn't spent yet, a read (section 3).
5. **The member.** One `vault.access`, outside any transaction, checks the
   service is active and at the binding's generation.
6. **Commit**, in one app transaction, as sign-in does:
   - take the audit head first;
   - check the member still stands at that generation (`memberStanding`);
   - read the binding again: its MAC holds, it isn't revoked, and no
     `token.unbind` names it;
   - check the times again, then consume the token, insert the
     credential and append `token.exchange`.

   Unbinding takes the same head, so an exchange and a removal can't cross.
   A binding issues at most 60 credentials a minute, counted here.

**The credential** is an ordinary service credential, plus its binding.
- It has kind `service` and the member's principal and generation, plus
  `binding_id`. All of them are under its MAC.
- The binding must belong to the same principal and generation, a link the
  database enforces as it does for an identity.
- Checking the credential, on every request, also reads its binding's row:
  its MAC must hold and it must not be revoked.
- It lasts five minutes, stays in the asking process, and carries exactly
  the service's grants. One `coffre run` needs it for seconds, and asking
  again costs one request.

**Audit and provenance.** `token.exchange` names the service as its actor.
It records the credential, the binding, the generation, the issuer, the
expiry, and the verified run claims (GitHub's `run_id`, `sha` and
`workflow_ref`), bounded in size. Those claims are what the issuer asserts,
not proof of which run sent the request.

Every entry written for a request made with that credential records the
credential's ID: the app's entries in their metadata, the vault's through a
new `credentialId` in the calls' correlation, which the vault copies and
never decides on. So a secret read leads back to its run in one join, after
the credential row is long gone.

**Refusals stay out of the audit log**: 401, 429 at admission, 503 when the
issuer can't be reached. The process log records them, sampled. The answer
gives a reason a CI user can act on: `expired`, `too_old`, `audience`,
`replayed`, or `no_match`, which names the claims that differ but never the
values expected. An unknown service and an unbound issuer answer the same.

## 3. The token

- **Shape.** A compact JWS, decoded but not yet trusted. `iss` and `sub` are
  nonempty strings. `exp` and `iat` are finite numbers, and so is `nbf` when
  present.
- **Signature.** jose verifies under the binding's keys.
  - RS256 or ES256 (P-256) only; never `none` or HS\*. RSA keys are at least 2048 bits.
  - No key or URL from the header (`jwk`, `jku`, `x5u`) is used, and an unknown `crit` is refused.
  - Neither the Access verifier's audience check nor its cached JWKS object is reused: this profile
    is stricter.
- **Audience.** Exactly `publicUrl`, as a string or a one-element array.
- **Times.** With t now and a tolerance of 30 s: `exp > t − 30`, `iat ≤ t + 30`,
  `nbf ≤ t + 30`, and `t − iat ≤ 3600`. They are checked again at commit.
- **Claims** match the binding's exactly.
- **Single use.** Commit consumes the SHA-256 of the token's signing input,
  `header.payload` as received. It sits in a table of its own, under a unique
  index across every service, and is kept two hours, past the acceptance
  window, whatever becomes of the credential.
  - Hashing the whole token would not do. An ES256 signature `(r, s)` has a
    twin, `(r, n − s)`, that verifies the same claims, so one token has two
    spellings. The signing input is what the signature covers, so it has
    only one.
  - A thief who redeems a token before its job does isn't stopped by this,
    but the job then fails loudly.
- **One token, one credential.** GitHub, Buildkite and CircleCI mint tokens
  on demand, and the CLI asks for one per run. GitLab issues one per
  `id_tokens` entry: a job that runs coffre twice declares two, or wraps its
  work in one `coffre run`. If the answer to a committed exchange is lost,
  that token is spent. The client asks for a fresh one, or on GitLab the job
  is retried.

## 4. Fetching keys

**Discovery runs once, when a binding is made.** Its `issuer` must match
exactly. The binding stores the `jwks_uri` under its MAC, and the owner sees
it before saving. An issuer that moves its keys needs a new binding.

**Discovery and key fetches share one transport.**
- `https` on port 443, host names only, with no credentials and no redirects.
- One 5 s deadline covers DNS, the connection, TLS and the body. The body
  is decompressed and cut off at 64 KiB, and at most 32 keys are kept.
- On Node, the connection's resolver admits only globally routable unicast
  addresses, IPv4 and IPv6, per IANA's special-purpose registries. That rules
  out loopback, private, shared (`100.64.0.0/10`), link-local, unique-local,
  documentation, IPv4-mapped and translation addresses. It checks each
  address it connects to and keeps the host name for TLS, so a DNS answer
  can't be swapped after the check.
- On Workers, the standard public `fetch`, never a private-network (VPC)
  binding.
- Loopback, for the dev IdP, is a deployment's setting, never a binding's.

**The cache keeps settled values only,** per isolate: never a pending fetch,
key import or failure. Two first exchanges each fetch.
- Key sets are kept ten minutes, for at most 64 URLs.
- After an unknown `kid` or a failed fetch, that isolate waits a minute
  before fetching that URL again, cold cache included. Until then such
  tokens get a 503.
- Admission is the deployment-wide bound.

**When the issuer is down,** the answer is a 503 with `Retry-After`. Fresh
cached keys work until they expire. No copy of the keys is kept in the
database: an issuer that can't serve its keys can rarely mint tokens.

## 5. Threats

- **The issuer is compromised.** Its key matches every binding on it, as at
  every cloud that trusts it. Each service holds only its own grants. The
  bulk limit applies. `coffre untrust --issuer <url>` drops every binding on
  an issuer at once. Its forged run claims prove nothing (section 2).
- **Claim confusion.**
  - GitHub's profiles never bind `sub`, whose format an organization can
    change. They bind the claims instead, with the events listed and the
    refs exact.
  - IDs can't be registered again by someone else after a rename, as names
    can, so profiles use IDs.
- **Another repository in the organization** matches nothing without the
  repository's ID. A binding open to the whole organization is an explicit,
  displayed choice, for a reusable workflow pinned to one commit.
- **The job's own code.** OIDC proves which job asked, not that everything
  it runs is safe. A compromised runner, a build step that runs untrusted
  code, or a reusable workflow that executes its caller's inputs reads what
  the service can. Bindings narrow which jobs; grants narrow what they read.
- **A token or credential in a log.** The token is spent once used, and
  never more than an hour old. The credential dies in five minutes and
  keeps the `coffre_svc_` prefix that secret scanners know. The CLI prints
  neither, and the Action masks both.
- **SSRF and poisoned keys:** section 4.
- **A database owner adds, edits or restores a binding:** section 6.

## 6. Where bindings live

In the app, beside sign-in accounts: a binding is to a service what an
`identities` row is to a person. Both say who someone is, which the app
decides; the vault decides what they may decrypt.

A row written without the app's key fails its MAC. The MAC covers:
- the ID, principal and generation;
- the profile, the issuer and the JWKS URL;
- the claims, as JSON with sorted keys;
- the revocation.

**Rollback is the accepted limit, as everywhere in coffre.**
- **An old binding put back.** Bindings are immutable, so every binding
  replaced or removed has a `token.unbind` entry, and both the exchange and
  its commit refuse any binding that one names. To get past that, the
  owner must delete or edit the entry. That is a change to the log, found
  the next time the log is checked ([Limits](../architecture.md#limits)).
  A credential row put back with its binding buys what is left of its five
  minutes.
- **The vault would close no gap.** Its sealed member record has the same
  gap, a row put back with the newer entry cut out. A rewind of the whole
  database gets past both.
- **Finding it doesn't stop it.** A red `/readyz` stops nothing by itself.
  Containment would be a design of its own, as for the rest of coffre.

## 7. UI, CLI and the Action

**The UI.** A service's Tokens page gets a "Trusted workloads" list: issuer,
claims, who added the binding, its last use, and Remove.
- Adding one offers the profiles above, and shows the exact claims before
  saving.
- The GitHub form asks for the repository, workflow, branch and event, or
  for a reusable workflow and its commit. It looks up the IDs of a public
  repository, or shows `gh api repos/acme/api --jq '.id, .owner.id'` for a
  private one.

**The CLI** names members as `coffre grant` does:
```sh
coffre trust api-deploy                 # lists its bindings
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --event push
coffre trust api-deploy --gitlab 345 --branch main --source push
coffre untrust api-deploy <binding-id>
```

**In CI**, with `COFFRE_SERVICE` set and no `COFFRE_TOKEN`, the CLI exchanges
a token itself.
- On GitHub, Buildkite and CircleCI, it asks the platform for a fresh token
  with the instance URL as audience (`circleci run oidc get`, not the
  default token, whose audience is the organization's).
- Elsewhere it reads `COFFRE_ID_TOKEN`.
- It keeps the credential in memory, never in `~/.coffre`, because a
  self-hosted runner's disk outlives the job.

**The Action** needs `id-token: write`, and takes `service:` instead of
`token:`. It calls `core.getIDToken(<instance URL>)`, exchanges the token,
and masks both.

**Not in v1:**
- Cloudflare Access deployments.
- Kubernetes. A name in `sub` can be reused, and the immutable UID is nested. A deleted account's
  tokens stay valid offline, without TokenReview. A projected token is read again on each call,
  which single use refuses. A later profile would need a typed UID path and TokenRequest.
- Bitbucket Pipelines and Fly.io: their audiences can be set, but their
  profiles wait until their untrusted triggers are checked.
- Azure Pipelines, whose documented flow fixes the audience.
- CircleCI's shared root issuer.
- Patterns; nested or non-string claims; narrower grants per binding.

## Review responses

| # | Finding | Response |
|---|---|---|
| 1 | ES256 twins defeat a whole-token hash | Accepted: the signing input's hash is consumed, in its own table; a test presents the twin (section 3). |
| 2 | Minimums accept unrelated workloads | Accepted: profiles enforced on the server, GitHub's events listed, the job's own code under threats (sections 1, 5). |
| 3 | A reusable workflow's name isn't its identity | Accepted: `job_workflow_sha` required; organization-wide trust only by explicit choice (section 1). |
| 4 | Anonymous requests reach the vault | Accepted, in the PM's order: admission first, the vault last; issuance bounded per binding; refusal logs sampled; fetch cooldowns (sections 2, 4). |
| 5 | An edited binding rolls back undetected | Accepted: bindings are immutable; a change is a new ID (sections 1, 6). |
| 6 | Exchange races unbinding | Accepted: sign-in's commit discipline; the credential's MAC and foreign key carry its binding, read on every check; races tested on both engines (section 2). |
| 7 | The public-address policy is undefined | Accepted: globally routable unicast, per address, in the resolver; the Workers transport named (section 4). |
| 8 | Kubernetes identity and revocation | Left out of v1 (section 7). |
| 9 | Projected tokens break single use | Moot without Kubernetes; GitLab's limit and a lost answer's recovery stated (section 3). |
| 10 | Platform facts, token profile | Accepted: Bitbucket corrected, then left out for another reason; CircleCI through `oidc get`; Buildkite by IDs; types and inequalities spelled out (sections 1, 3, 7). |
| 11 | Reads can't be traced to a run | Accepted: the credential's ID in every entry its requests write, the vault's through correlation (section 2). |
| 12 | Section 6 overstated the vault | Accepted, rewritten (section 6). Argued: a `token.unbind` refuses without its MAC being checked, since a forged one can only deny service, which a database owner can do anyway. |

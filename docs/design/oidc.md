# OIDC login for services

A proposal, written on 2026-10-03 and revised twice that day, after an
independent review and its re-review ([PR #90](https://github.com/erwinkn/coffre/pull/90)).
Both rounds' findings are answered at the end. There is no code yet. v1
supports GitHub Actions, GitLab and other issuers by their subject.

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
claims a token must carry, each a top-level string matched exactly. The
claim that says what started the run, `event_name` on GitHub and
`pipeline_source` on GitLab, may list several values, and a token matches
with any one of them:

```json
{ "profile": "github", "issuer": "https://token.actions.githubusercontent.com",
  "claims": { "repository_owner_id": "9919", "repository_id": "41532",
              "workflow_ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main",
              "ref": "refs/heads/main", "event_name": ["push", "workflow_dispatch"] } }
```

A list is stored once each, in the profile's order, and a single value as
a plain string, so a binding made before lists existed reads as a binding
of one event.

**The server enforces each profile's minimum.** It checks every binding
against its profile, whether it comes from the UI, the CLI or the API, and
refuses one that lacks a required claim. A known issuer URL forces its
profile. A GitHub Enterprise Server or a self-managed GitLab picks its own.

| Profile | Required claims |
|---|---|
| `github`, a workflow of the repository | `repository_owner_id`, `repository_id`, `workflow_ref`, `ref`, `event_name` |
| `github`, a reusable workflow | `repository_owner_id`, `ref` (the caller's), `event_name`, `job_workflow_ref`, `job_workflow_sha`, and `repository_id` unless "any repository of the organization" is chosen explicitly |
| `gitlab` | `namespace_id`, `project_id`, `ref_type`, `ref`, `pipeline_source` |
| `custom`, any other issuer | `sub`, and the UI says the owner vouches for what it means: a Google Cloud service account's unique ID, say |

Some rules within the profiles:
- **GitHub events.** `event_name` is one or more of `push`,
  `workflow_dispatch`, `schedule`, `release`, `pull_request` and
  `workflow_run`. The first four are triggered by someone with write
  access, at a ref the binding names exactly. They don't make everything
  the job runs safe (section 5). The ref must suit every event listed.
  - `push`: the branch or tag ref, and a tag `main` is not `refs/heads/main`.
  - `workflow_dispatch`: the ref the writer dispatches, whatever the default
    branch has.
  - `schedule`: the default branch, so a binding stops matching when that
    changes.
  - `release`: `refs/tags/<tag>`, exact, which fits a binding per release
    tag. It doesn't tell `published` from `edited`; the workflow restricts
    that.

  - `pull_request`: the branch the pull request merges into. Its run is at
    `refs/pull/<n>/merge`, so the exchange reads its `ref`, and the ref its
    `workflow_ref` ends in, as `refs/heads/<base_ref>`, for GitHub's
    profiles only. A merged pull request's run is at that branch already.
    The run executes the pull request's code and workflow file, unreviewed,
    so the binding trusts whoever can push a branch to the repository.
    Forks get no ID token: GitHub turns `id-token: write` off for their
    pull requests, and Dependabot's, unless an admin of a private
    repository sends write tokens to them.
  - `workflow_run`: the default branch, whose workflow it runs. A fork's
    pull request can start it, so it is safe only while it runs none of
    the triggering run's code or artifacts.

  The owner picks these two knowing that; the form, the CLI and the MCP
  approval page say what each exposes. The server refuses
  `pull_request_target` and every other event, even when their ref
  happens to match: they act on anyone's pull request with the base
  repository's tokens.
- **Reusable workflows.** A reusable workflow is trusted at one commit:
  `job_workflow_sha` pins it, since its path can be reused and its branch
  changed. A new version needs a new binding.
  - The caller is pinned too, by its `ref`. A feature branch's own caller
    can't borrow production's binding.
  - Every calling workflow at that ref is trusted, unless the binding also
    names `workflow_ref`.
- **GitLab.**
  - `namespace_id` beside `project_id`. A project keeps its ID when
    transferred to another owner's namespace, and the binding stops
    matching there.
  - `ref_type` tells branch `main` from tag `main`.
  - `pipeline_source` keeps merge-request pipelines out. With `push`,
    `project_id` and `namespace_id` name the job's own project, in every
    supported GitLab version.

**What a service holds is bounded.**
- A service holds at most 16 live bindings.
- A binding has at most 16 claims, each value at most 256 bytes.
- A service's bindings on one issuer share one JWKS URL. A binding made
  after the issuer moved its keys replaces the others, which would fail
  anyway.

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
service's bindings are read. In order:

1. **Admission.** The body is read as a stream and cut off at 16 KiB. Two
   limits apply before any database, crypto or network work, one per source
   address and one for all sources together, answered 429 beyond.
   - **The limits are approximate.** On Workers they are Cloudflare's
     rate-limiting binding, which counts per location and lets bursts
     through. On Node, they are counters per process, with a bound on
     exchanges in flight.
   - **So a flood scales with the deployment.** It can reach the limit times
     the number of locations or processes. What bounds the work behind each
     admitted request is the rest of this list: one query of at most 16
     rows, one signature check, at most one key fetch.
   - **The limiter is required.** Configuring the exchange without it is a
     configuration error, never a route without limits.
2. **Shape** (section 3).
3. **The binding.** One app query reads the service's live bindings for the
   token's `iss`, at most 16, sharing one JWKS URL. It checks each one's
   MAC. With none, the request is refused, with no vault call and no fetch.
4. **The token:** its signature, then audience, times and claims, and
   that it isn't spent yet, a read (section 3).
5. **The member.** One `vault.access`, outside any transaction, checks the
   service is active and at the binding's generation.
6. **Commit**, in one app transaction, as sign-in does:
   - take the audit head first;
   - check the member still stands at that generation (`memberStanding`);
   - read the binding again: its MAC holds, it isn't revoked, and it has
     no tombstone (section 6);
   - check the times again, then consume the token, insert the
     credential and append `token.exchange`.

   Unbinding takes the same head, so an exchange and a removal can't cross.
   A binding issues at most 60 credentials a minute, counted here. A refusal
   at this step rolls everything back, and the token stays unspent.

**The credential** is an ordinary service credential, plus its binding.
- It has kind `service` and the member's principal and generation, plus
  `binding_id`. All of them are under its MAC.
- The binding must belong to the same principal and generation, a link the
  database enforces as it does for an identity.
- Checking the credential, on every request, also checks its binding. In
  the same uncached query, the binding's MAC must hold, it must not be
  revoked, and it must have no tombstone.
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
- **One token, one credential.**
  - GitHub mints tokens on demand, and the CLI asks for one per run.
  - GitLab issues one per `id_tokens` entry. A job that runs coffre twice
    declares two, or wraps its work in one `coffre run`.
  - If the answer to a committed exchange is lost, that token is spent. On
    GitHub the client asks for a fresh one; on GitLab the job is retried.

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
- Each cold isolate has its own cache and cooldowns. Admission, approximate
  as section 2 says, is what bounds them together.

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
    change. They bind single claims instead, with the events listed and the
    refs exact.
  - IDs can't be registered again by someone else after a rename, as names
    can, so profiles use IDs.
- **Forks.**
  - On GitHub, a fork's runs come in through events the profile refuses.
  - On GitLab, they come in as merge-request pipelines, which
    `pipeline_source` keeps out.
  - CircleCI and Buildkite are out of v1 because their bindable claims
    can't always tell a fork's `main` from the repository's (section 7).
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
- **What makes a tombstone.** A binding's tombstone is an app entry
  `token.unbind` whose decision is `allow`, naming that binding's ID exactly.
  - A denied attempt is logged under the same action and never counts, so a
    non-owner who tries to unbind can't switch a binding off.
  - The check is an existence query over every such entry, through an index
    on the binding ID. It is never "the latest entry wins".
  - Tombstones are entries of the log, kept forever, whatever is cleaned up
    elsewhere.
  - Their MAC isn't checked, because a forged tombstone can only deny
    access, which the database's owner can do anyway. A tombstone never
    grants anything.
- **An old binding put back.** Bindings are immutable, so every binding
  replaced or removed has a tombstone. The exchange, its commit and every
  credential check refuse that binding, so an old binding or credential row
  put back buys nothing. To get past that, the owner must delete or edit
  the tombstone. That is a change to the log, found the next time the log is
  checked ([Limits](../architecture.md#limits)).
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
- The GitHub form asks for the repository, the workflow, the event and its
  exact ref, or for a reusable workflow, its commit and the caller's ref. It
  looks up the IDs of a public repository, or shows
  `gh api repos/acme/api --jq '.id, .owner.id'` for a private one.
- The GitLab form takes the project and looks up its project and namespace
  IDs.

**The CLI** names members as `coffre grant` does:
```sh
coffre trust api-deploy                 # lists its bindings
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --event push
coffre trust api-deploy --gitlab acme/api --branch main --source push
coffre untrust api-deploy <binding-id>
```

**In CI**, with `COFFRE_SERVICE` set and no `COFFRE_TOKEN`, the CLI exchanges
a token itself.
- On GitHub, it asks for a fresh token with the instance URL as audience.
- Elsewhere it reads `COFFRE_ID_TOKEN`: GitLab's `id_tokens`, or a custom
  issuer's token.
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
- CircleCI. A fork build can carry the same project and ref. A profile
  would require `oidc.circleci.com/vcs-origin`, and refuse tokens without
  it, with a fork case tested.
- Buildkite. With fork builds on and their branch prefix off, a fork's
  `main` matches. No signed claim tells a push from a pull request.
- Bitbucket Pipelines and Fly.io. Their audiences can be set, but their
  untrusted triggers aren't checked yet.
- Azure Pipelines, whose documented flow fixes the audience.
- Google Cloud as a profile of its own: `custom`, by the service account's
  unique `sub`, covers it.
- Patterns; nested or non-string claims; narrower grants per binding.

## Review responses

Rows 1 to 12 answer the review, and R1 to R6 its re-review.

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
| 10 | Platform facts, token profile | Accepted: Bitbucket corrected, then left out for another reason; types and inequalities spelled out (sections 3, 7). CircleCI and Buildkite are out since R1 and R2. |
| 11 | Reads can't be traced to a run | Accepted: the credential's ID in every entry its requests write, the vault's through correlation (section 2). |
| 12 | Section 6 overstated the vault | Accepted, rewritten (section 6). Argued: a `token.unbind` refuses without its MAC being checked, since a forged one can only deny service, which a database owner can do anyway. |
| R1 | CircleCI admits a fork's `main` | CircleCI is out of v1. It can return as a profile requiring `vcs-origin` (section 7). |
| R2 | Buildkite admits fork builds | Buildkite is out of v1 (section 7). |
| R3 | Reusable workflows trust every caller branch | Accepted: the caller's `ref` is required; `workflow_ref` narrows to one caller; the feature-branch caller is a test case (section 1). |
| R4 | GitLab follows a transferred project | Accepted: `namespace_id` is required, and the claim family is fixed by `pipeline_source`. A namespace-only change is a test case (section 1). |
| R5 | A denied unbind counts as a tombstone | Accepted: only an app `token.unbind` with decision `allow` and the exact ID counts, through an indexed existence check. It also applies to every credential check, which closes the credential-row rollback (section 6). |
| R6 | Admission isn't deployment-wide | Accepted: the limits are stated as approximate, per location or process, with the exposure they leave. The limiter is required configuration; rows, claims and JWKS URLs per exchange are capped (sections 1, 2). |

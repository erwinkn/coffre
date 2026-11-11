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

Say `token:api-deploy` holds `viewer` on `market/prod`, and someone who
manages it, an Admin or a person who holds `viewer` there
([instance-roles.md](instance-roles.md), "Setting up service accounts"), binds it
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
| `custom`, any other issuer | one or more claims of any name, each exact (`sub` until 0.17; section 9.1), and the UI says the owner vouches for what they mean: a Google Cloud service account's unique `sub`, say, or a Capy project's `project` |

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
- **GitHub environments.** A GitHub binding may name `environment`, the
  GitHub environment its job runs in, such as `production`. Then only jobs
  in that environment match, and only once its protection rules (required
  reviewers, the branches it deploys) let them run. GitHub changes `sub`
  for such a job, to `repo:acme/api:environment:production`, but no GitHub
  profile binds `sub`, so `ref`, `workflow_ref` and `job_workflow_ref`
  match as they would without it. A binding without `environment` takes
  jobs in any environment, or none.
  - The name matches whatever its case: GitHub's environment names are
    case-insensitive, so `Production` and `production` are one environment
    under the same rules. Every other claim matches exactly.
  - It is checked as GitHub takes a name: at most 255 characters, no
    control character, no space at either end.
  - Anyone who can push a workflow can name an environment, and GitHub
    makes it, unprotected, if it does not exist. Naming one adds what its
    protection rules enforce, nothing more.
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
- A binding's claims have no count or length of their own: the body that
  carries them is held to 1 MiB and 1,600 values (`API_BODY_BYTES`,
  `MAX_BODY_NODES`), and nothing else bounds them (R70).
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

1. **Admission.** The body is read as a stream and cut off at the bound of
   every body sent before sign-in, 128 KiB (`SIGN_IN_BODY_BYTES`, 413 past
   it), which bounds the token too. One limit applies before any database,
   crypto or network work: the requests one source address made to this
   entry point, 10,000 per 10 seconds by default (1,000 a second, R44's CI
   sign-in rate, which a fleet behind one NAT sends from one address),
   answered 429 beyond, with `Retry-After: 10`. No limit counts all sources
   together (W331, D177).
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
   Nothing counts a binding's credentials (W331, D177; 0.15 counted 60 a
   minute): each ID token buys one. A refusal at this step rolls
   everything back, and the token stays unspent. With 0.15's log, the
   vault's `sign_in` makes it in one statement, holding the binding's row
   shared with its other sign-ins (`FOR KEY SHARE`), so they run together,
   and an unbind's `FOR UPDATE` waits for them, or they for it
   (formal/Lifecycle.tla, `EndedBindingEndsCredentials`).

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
cached keys work until they expire. No copy of fetched keys is kept in the
database: an issuer that can't serve its keys can rarely mint tokens. Keys
uploaded with a binding are a different case, fetched never (section 8).

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
  0.7 serves it without a profile of its own: keys uploaded with a binding, and nested claims
  (section 8).
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
  Nested claims came in 0.7 (section 8); narrower grants per binding in 0.5.

## 8. Uploaded keys (0.7)

An issuer on a private network, a Kubernetes cluster's above all, has no
public `https` URL for its keys, so section 4's discovery cannot reach it.
A binding may carry its issuer's public keys instead, uploaded with it
(`coffre trust --jwks-file`, or pasted in the dialog). The general recipe is
in [ci.md](../ci.md#issuers-coffre-cannot-reach), and Kubernetes' in
[kubernetes.md](../kubernetes.md).

- **Nothing is fetched.** Not at bind time, not at an exchange. The issuer
  is then any string a token's `iss` holds, matched exactly, with no
  control character or space at either end, at most 1,670 bytes, what fits
  in the index entry it shares with its service (`MAX_ISSUER_BYTES`). github.com's
  and gitlab.com's issuers are refused: they rotate their keys, so coffre
  always fetches theirs.
- **The keys are checked at upload** (`uploadedKeys` in core): RSA of 2048
  bits or more for RS256, P-256 for ES256, at most 32. An RSA key's modulus
  must be odd and its exponent odd and at least 65537, each in its fewest
  bytes: jose takes an exponent of 1, under which a signature is its own
  message and anyone can forge one. Each key keeps `kty`, `kid`, `use`,
  `alg` and its public parameters, in a fixed order, and the keys are sorted
  by thumbprint, so one set has one digest however it is listed. A token
  that names no `kid` verifies under whichever key of the set signed it. Keys for
  encryption are left out, as from a fetched set. A private or symmetric key
  refuses the whole set.
- **Where they live.** A nullable `service_bindings.jwks` holds them, as that
  canonical JSON. `jwks_uri`, still `NOT NULL`, holds `sha256:<hex>` of it.
  So "a service's bindings on one issuer share one key source" (section 1)
  compares one column, whether the keys are fetched or uploaded. The MAC
  covers the keys as a tuple of its own kind, `uploaded_service_bindings`
  (section 6), so keys swapped in the database fail it. The column has no
  UPDATE grant: like the rest of the binding, they never change in place.
- **Rotation replaces bindings.** Bindings stay immutable. New keys for an
  issuer, `--replace-keys` or Replace keys in the pages, replace every live
  binding of the service on it, in one step, each by one the same but for
  its keys, its scope inherited as any replacement's. The old one's
  `token.unbind`, reason `keys_replaced`, is its tombstone. Its credentials
  end with it. A binding whose keys differ from its siblings' on the issuer
  is refused unless it replaces them, rather than replacing them silently
  as a moved key URL does. During the issuer's overlap, a set of old and new
  keys takes tokens of both. A token signed by a key the binding does not
  hold is a 401 `unknown_key` that says to replace the keys, never the
  fetch cooldown's 503.
- **An hour's lifetime.** With uploaded keys, coffre can ask nobody whether
  a token still stands, so a token whose `exp` is over an hour past its
  `iat` is refused, `too_long`, however recently it was issued. Every token
  keeps the age limit of section 3 and single use. Fetched issuers are not
  held to the lifetime: GitLab's `id_tokens` live as long as the job's
  timeout.
- **Nested claims.** A claim name may be a path, its keys joined by dots,
  for every profile. `kubernetes.io` holds a dot itself, so a name is read
  every way its dots split it, and matches only when exactly one reading
  reaches a value in the token. A top-level name with dots,
  `oidc.circleci.com/vcs-origin`, still reads as before.
- **Verification is one function.** `WorkloadService.verify(member, token)`
  is steps 2 to 4 of section 2 without the spend: the binding that matched
  and the verified claims, and, read with the bindings in one statement,
  whether the token was spent and the newest policy change. The exchange
  refuses a spent token on that, then commits. A plugin that signs a
  workload in another way calls it too.

Findings 8 and 9 of the review, for Kubernetes: the UID is a nested claim a
binding names; there is still no TokenReview, which the recipe says; and a
projected token signs in once, which the recipe answers with a short
projection, wrapping the work in one `coffre run`, and the kubelet's
refresh.

## 9. Any claims, recorded claims, one token for many runs (0.17)

Until 0.17 a `custom` binding pinned `sub`. That fits an issuer whose `sub`
names one workload. It does not fit one whose `sub` names one run. Capy
(capy.ai) signs a token for each machine of an agent's thread, an hour
long, written to a file and replaced about 15 minutes before it expires
([docs.capy.ai/cloud-credentials](https://docs.capy.ai/cloud-credentials)):

```json
{ "iss": "https://api.capy.ai/oidc/orgs/o_123", "aud": "https://secrets.acme.example",
  "sub": "org/o_123/project/p_7/thread/ENG-142",
  "org": "o_123", "project": "p_7", "thread": "ENG-142", "machine": "m_9", "user": "u_4",
  "jti": "…", "iat": 1794355200, "nbf": 1794355140, "exp": 1794358800 }
```

`sub` changes with every thread, so no binding could name it. Nothing here
is Capy's: it is the general case of an issuer whose identity is spread over
claims of its own names. Three changes serve it.

### 9.1 A custom binding pins any claims

- **One or more claims, of any name.** A `custom` binding no longer
  requires `sub`. It names at least one claim, and each is matched as
  every claim is (section 1): the token's value at that name (top level, or
  nested, section 8) must be a string equal to the binding's. No pattern,
  no prefix: `org/o_123/project/p_7/thread/*` stays impossible, and
  `project` is pinned instead.
- **Strings only, and typed.** A binding's values are nonempty strings, as
  before. A token whose claim is the number `7` or the boolean `true`
  matches no binding, not even one that says `"7"` or `"true"`. An issuer
  that sends an identifier as a number cannot be bound by it, which is the
  limit the old rule had too.
- **Refused:**
  - a binding that names no claim at all: it would trust every token its
    issuer signs;
  - the reserved names, as before (`iss`, `aud`, `exp`, `iat`, `nbf`,
    `jti`);
  - a binding whose every claim says how the token was issued, not to
    whom: OIDC Core's `acr`, `amr`, `auth_time`, `azp`, `nonce`,
    `at_hash`, `c_hash`, `sid`, `email_verified` and
    `phone_number_verified`. Each may narrow a binding beside a claim that
    says who, never alone. This catches the obvious mistakes only. Whether
    a claim names one workload is the issuer's to say, and the next point
    puts it in front of the Owner.
- **The exposure, in words.** The CLI's plan, the Trust dialog and the MCP
  approval page say who a custom binding lets in, as they say what
  `pull_request` exposes:

  > Anyone holding a token from https://api.capy.ai/oidc/orgs/o_123 that
  > says project=p_7 signs in as capy-agent. Coffre cannot tell whether
  > these claims name one workload: you vouch that this issuer gives such
  > a token to nobody else.

- **Nothing migrates.** Every custom binding made before pins `sub`, which
  is still allowed, and reads as it did.

**Capy, worked.** The org's issuer is its own, so the issuer already pins
the organization; `project` pins the project. A thread's agent runs
commands that use credentials, so the binding is a workload's, key-bound,
and reads nothing (section 9.4):

```sh
coffre trust capy-agent --issuer https://api.capy.ai/oidc/orgs/o_123 \
  --claim project=p_7 --record thread,user,machine --workload --apply
```

In the Capy project's cloud setup, the token's audience is the instance's
URL, `https://secrets.acme.example`. The agent then runs, as often as it
likes within the token's hour:

```sh
coffre --url https://secrets.acme.example --service capy-agent \
  run --proof oidc:"$CAPY_OIDC_TOKEN_FILE" market/dev -- pnpm test
```

Capy's keys, `https://api.capy.ai/oidc/jwks.json`, sign every
organization's tokens. What keeps another organization's token out is the
issuer, `…/orgs/o_123`, matched exactly against `iss`: it relies on Capy
naming the right organization there, as GitHub's binding relies on GitHub
naming the right repository.

**GitHub and Fly, for contrast.** Their issuers force their profiles
(section 1), so a `custom` binding on them is still refused. A GitHub
workflow is bound by its profile's five claims, never by `sub`:

```sh
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --apply
```

A Fly app is bound by its `fly` profile, whose tokens name the session's
key in their audience:

```sh
coffre trust api-prod --fly acme --org-id 29873298 --app-id 3671581 --apply
```

### 9.2 Fly and Vercel stay profiles

They could almost be `custom` bindings now: `{ org_id, app_id }` on
`https://oidc.fly.io/acme`. Collapsing them was weighed and left out, for
four reasons:

- **The profile is what knows which claims identify.** `fly` requires both
  `org_id` and `app_id`, and `vercel` requires `environment`, which keeps
  previews out. A custom binding would let an Owner pin `org_id` alone, so
  every app of the organization would sign in. Section 9.1 can only warn
  about that; the profile refuses it.
- **The audience must name the key.** Their callers choose the audience,
  so their bindings always set `keyAudience` (workload-access.md, section
  4.2), and `forcedProfiles` keeps a custom binding from dropping it on
  their issuers. A custom binding on Fly's issuer would need that rule
  anyway, under another name.
- **Stored bindings name their profile under the vault's seal.** Removing
  the profiles would need a contraction: either a migration that rewrites
  sealed objects, or code that still reads `fly` and `vercel` forever.
- **Little would go.** The profiles are about 25 lines of rules. The
  client's `fly()` and `vercel()` proofs, which fetch a token for the key,
  stay either way.

### 9.3 Recorded claims

Every sign-in records the run's claims that `runClaims` knows by name
(`sub`, `jti`, GitHub's `run_id`, `sha` and the rest; section 2, "Audit and
provenance"), in its entry under the entry's MAC. A custom issuer's own
names are not among them. So a binding may name up to 8 more,
`record: ["machine", "thread", "user"]`. A sign-in through it copies those
claims from the verified token into the same record, beside the others:
`signIn.run.user = "u_4"`.

- **Any ID token's profile** takes `record`: every profile but `aws`,
  `enrollment` and `cloudflare`, whose proof carries no claims. Each name
  is a claim name as section 1 takes it, nested ones included, each at
  most once. They are stored sorted.
- **What is recorded** is what `runClaims` records: a string, cut to 256
  characters, or a finite number. A boolean, an array, an object or a
  missing claim is left out, never an error: recording never refuses a
  sign-in.
- **It is part of the binding**, immutable like the rest of it: under the
  app's MAC (a tuple kind of its own, `recorded_…`, section 6) and the
  vault's seal (its object's `record`, present only when set, so every
  binding sealed before seals as it did). Where the vault checks the token
  itself, with uploaded keys, it reads the names from the sealed binding,
  never from the app.
- **The entry's size stays bounded.** `runClaims` keeps at most 23 claims,
  and a sign-in's record takes at most 32. Eight more fit. A recorded
  name is at most 64 characters, as a sign-in's record takes them.
- **Personal data.** A recorded claim lives as long as the log, which
  nothing rewrites. Record identifiers (`user: "u_4"`), not names or
  emails.

**Where it is stored.** A nullable `service_bindings.record`: canonical
JSON, the names sorted, null when none (never `[]`). Expand-only:

- the column is new and nullable, so the previous release never sees it;
- `change_bindings`, the vault's statement that makes a binding, gets an
  overload one argument longer, `p_record`. The old signature, which the
  previous release's vault calls, becomes a wrapper that passes null;
- `cutover_bindings`, which the vault reads a 0.14 instance's bindings
  through when it cuts its log over, gets a twin that reads `record` too,
  `cutover_bindings_recorded`: this release can make a recording binding
  before that cutover, under the app's MAC, and the cutover seals it
  whole. The old one stays for the previous release's vault;
- on SQLite, the column alone, since the vault's statement is TypeScript.

A rollback to 0.16 with recorded bindings fails closed: 0.16 checks their
MAC under the tuple kind without `record`, finds it wrong, and treats them
as no bindings, so they sign nobody in until 0.17 is back. A binding
without `record` is untouched either way.

**Why `/use` is untouched.** The use statement reads a binding's row only
for a Cloudflare service binding's call (`way = 'binding'`), to check its
seal. A `cloudflare` binding never has `record`, refused by the app and by
the vault, so its sealed object is the same without reading the column.

### 9.4 One token for many runs

A token is spent once (section 3). Capy writes one token per hour and its
agent runs `coffre run` many times in that hour. The second run's exchange
gets `replayed`, and nothing it can do gets it a fresh token sooner.

What existed did not cover it:

- `coffre login <url> --service <name> --id-token` exchanges once and
  saves the bearer credential, which lasts five minutes. Runs after those
  five minutes need a fresh token.
- `coffre login <url> --token` saves a bearer token a person issued: a
  stored secret, which is what OIDC removes.
- `coffre serve` holds a key-bound session and renews it for as long as it
  runs, but it is a process that must keep running. An agent's machine
  sleeps, and its commands are not served through a listener.

**The CLI keeps the session the token bought, sealed by the token.** For
`--proof oidc` (stdin) and `--proof oidc:<file>`, `coffre --service <name>
run` signs in key-bound as before, then keeps the session instead of
logging out, in `~/.coffre/sessions/`:

- **Its file** is named by `HMAC-SHA-256(token, "coffre.session.v1 name" ‖
  origin ‖ service)`. It holds the session's key, the private half as a
  JWK, its token, its places and times, encrypted with AES-256-GCM under a
  key derived from the token by HKDF-SHA-256, the name as associated data.
  In clear, only its end, so stale files can be pruned unread.
- **A later run** with the same token finds the file, opens it, and goes
  on with that session: it renews it by its key (`POST
  /api/auth/workload/renew`) once past half its life, as `coffre serve`
  does. A run with a new token, Capy's next, exchanges it and keeps that
  session instead.
- **It ends with the token.** A file is used only until the earlier of the
  session's `notAfter` and the token's own `exp`, read from its payload. A
  token with no `exp` is never kept; a fractional one, which the instance
  accepts, is read down to the millisecond. For a binding whose token does not
  name the key, which is every Capy binding, the session's `notAfter` is
  the token's `exp` already (workload-access.md, section 5.4).
- **Two runs at once** take a lock file beside it around the exchange, so
  one exchanges and the other waits for its file. The lock names the run
  holding it, which keeps it fresh while it waits on the instance (an
  approval can take minutes) and removes it only if it is still its own.
  A lock nobody kept fresh within 30 seconds of now, either way (one dated
  ahead is not waited on until then), is a dead run's, and is taken
  over. A run reads a lock's holder, freshness and identity (its inode)
  through one descriptor, never through a symbolic link, and removes one,
  to take it over or release it,
  only under a second lock file held for that one step (`<lock>.break`),
  after reading it again: the stale file it found and no other, its own and
  no other. That second file is read the same way. Either one a link,
  dangling or not, or unreadable, fails the run rather than be waited out. The instance still spends the token once, so a lock defeated
  anyway costs a `replayed` run, never a second session.
- **A session refused** (revoked, frozen, its binding removed) deletes its
  file. The token is spent, so the run says so and waits for none: the
  next token signs in again. A 401 that only asks for a fresh DPoP nonce,
  again after the one retry (the gate restarted meanwhile), refuses nothing:
  that run fails and the file stays, for the next.
- **No other proof is kept.** GitHub's, Google's, Fly's and Vercel's
  name the key and are fetched fresh for each run. Kubernetes' projected
  token is a long-running pod's, where `coffre serve` belongs.

**What it costs.** Before, the token was a bearer until its first use, and
the session lived in one process. Now:

- **The token is worth a session for its whole hour.** Whoever holds it
  and the file has what the token bought. A copy of the file without the
  token opens nothing.
- **Section 7's runner rule still holds.** "Never in `~/.coffre`, because
  a self-hosted runner's disk outlives the job." The file outlives the job
  too, but it is sealed by a token the next job does not have, and it is
  useless once that token expires.
- **The session outlives the command**, until the token's `exp`, at most
  an hour. Before, `coffre run` logged out at its end. Revoking the
  session or freezing the binding ends it sooner, as for any session.

Tokens stay single use at the server, which changes nothing here. Azure's
repeating tokens keep their own rule (workload-access.md, section 4.2).

### 9.5 Threats

- **An Owner pins a claim that names no one.** Say a binding on a
  company's IdP pins `{ "email_verified": "true" }`, or on Capy, `{ "org":
  "o_123" }` alone. The first is refused (section 9.1). The second is
  allowed, and the plan says it plainly: anyone with a token from that
  organization, in any project, signs in. Coffre cannot know what a
  custom issuer's claims mean, so it says what the binding trusts, in
  words, before it is saved.
- **Anyone who can start a thread in the bound Capy project acts as the
  service account**, and so does a prompt injection that steers an agent
  in one. The token is the machine's, and every command on the machine can
  read it. So a binding for agents should be a use-only account: a
  workload's binding with no `reads`, whose sessions use credentials
  through coffre's proxy and never hold a value (workload-access.md,
  section 6). Its credentials' own limits (section 8.1 there) bound what a
  steered agent can spend.
- **Several organizations, one key set.** As in section 9.1: the exact
  `iss` keeps another organization's tokens out.
- **A recorded claim is the issuer's word**, as every run claim is
  (section 2): it says which thread asked, not which one sent a request.

**The formal models.** The claims' match is not modelled
(formal/Lifecycle.tla, "Not modelled: … the proof's claims and the
binding's match"), and 0.17 needs no change there. The match is a pure
decision on one verified token and one sealed binding, made before the
sign-in's statement. It takes no lock, orders nothing and keeps no state,
so it is invisible to every property the models check. What they do check
is unchanged: the token is spent once (`SpentOnce`), the vault verifies it
against the binding it sealed (`SignInsOnValidTokens`), and a session is
renewed only by its key and never past its `notAfter` (Workload.tla,
`NotAfter`). The session kept on disk changes no protocol: the server sees
a renewal and requests signed by the session's key, as from `coffre serve`.
The Lean proofs cover access, the vault's per-key decision, the AAD and
the chain, none of them a binding's claims.

## Review responses

Rows 1 to 12 answer the review, and R1 to R6 its re-review.

| # | Finding | Response |
|---|---|---|
| 1 | ES256 twins defeat a whole-token hash | Accepted: the signing input's hash is consumed, in its own table; a test presents the twin (section 3). |
| 2 | Minimums accept unrelated workloads | Accepted: profiles enforced on the server, GitHub's events listed, the job's own code under threats (sections 1, 5). |
| 3 | A reusable workflow's name isn't its identity | Accepted: `job_workflow_sha` required; organization-wide trust only by explicit choice (section 1). |
| 4 | Anonymous requests reach the vault | Accepted, in the PM's order: admission first, the vault last; issuance bounded per binding (until W331: each ID token buys one); refusal logs sampled; fetch cooldowns (sections 2, 4). |
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

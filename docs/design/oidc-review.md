# Review of OIDC login for services

Reviewed on 2026-10-03 against `oidc-design` commit
`713ded387113b230ee73be354ec95d45660f6d2c`, proposed in
[PR #89](https://github.com/erwinkn/coffre/pull/89).

The proposal is worth pursuing, but needs changes before implementation.
The most consequential gaps are replay protection, the minimum scope of a
binding, unauthenticated resource consumption, and binding rollback. There
is no critical finding. Keeping authentication in the app is reasonable;
moving bindings into the vault would not, by itself, fix these problems.

This review covers [the proposal](oidc.md), the existing
[sign-in service](../../packages/server/src/api/signin.ts),
[authentication boundary](../../packages/server/src/auth.ts),
[authentication MACs](../../packages/server/src/auth-rows.ts),
[credential queries](../../packages/server/src/db/queries.ts), both
[Postgres](../../packages/db/src/schema.ts) and
[SQLite](../../packages/db/src/schema.sqlite.ts) schemas, the vault's access
checks, and the [architecture limits](../architecture.md#limits).
Platform statements below were checked against their public documentation.
Findings describe defects or missing guarantees in the proposed design,
not claims about an implementation that does not yet exist.

## Ranked findings

### 1. High: hashing the entire JWT does not make an assertion single use

Section 3, step 7, lines 100 to 103; section 5, leaked-token threat,
lines 159 to 162.

ES256 signatures are malleable. Given a valid P-256 signature `(r, s)`, a
holder can replace it with `(r, n - s)`, where `n` is the curve order,
without knowing the issuer's private key. Both signatures authenticate
exactly the same header and payload, but the compact JWT strings have
different SHA-256 hashes. A token stolen from a log after a successful
exchange can therefore buy another credential while its claims remain
valid. Canonical base64url encoding alone does not fix this.

I reproduced this with Node 24.21.0: Node's signature verifier, WebCrypto
and the repository's `jose` 6.2.3 all accepted both signatures; hashing the
complete JWT produced two distinct hashes. This checks the cryptography
and verifier library, not a deployed Worker.
[JWS replay guidance](https://www.rfc-editor.org/rfc/rfc7515.html#section-10.10)
places the replay identifier inside the authenticated content.

Change step 7 to consume an identity independent of signature bytes. Use a
unique, issuer-scoped `jti` where the issuer guarantees its semantics, or a
hash of the authenticated JWS signing input for the no-`jti` case. Verify
the signature before consuming either. Keep uniqueness global across
bindings and services. Insert the consumption record, credential and
exchange audit entry in one transaction. Credential revocation must not
remove consumption records before the acceptance window ends. Add the
two-signature scenario to the future conformance cases. Even correct
single-use enforcement cannot stop a thief redeeming an unspent bearer
assertion first; keep that separate limitation explicit.

### 2. High: the minimum binding rules accept unrelated workloads

Section 1, "What a binding must name," lines 36 to 44; section 5,
"Claim confusion," lines 148 to 158; section 7, presets and CLI,
lines 198 to 207.

Exact comparison only helps for claims a binding actually constrains. A
GitHub binding containing just the two required owner/repository IDs
accepts every token-bearing workflow in that repository, including an
untrusted same-repository branch. A CircleCI organization issuer plus a
shared claim still accepts unrelated projects. A Kubernetes cluster issuer
plus a generic claim accepts other namespaces' service accounts. The text
also contradicts itself about whether these issuers need any claim at all.

For GitHub, `pull_request_target` can execute the same workflow file at the
same base/default branch as a trusted event. `workflow_ref` does not
necessarily differ. The event restriction in the opening example is doing
essential work. Ordinary `pull_request` runs use merge refs, but merged-PR
events can use the base ref, so a branch check cannot replace an event
check. [GitHub's ref definitions](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
describe that distinction. Even an explicitly allowed event cannot make
a workflow safe if it executes attacker-controlled code before fetching secrets.
[GitHub's event security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
describes this failure mode.

Define and enforce a minimum workload scope per preset on the server,
including bindings submitted directly through the API. GitHub's ordinary
deployment preset should require owner ID, repository ID, workflow, ref
and event, defaulting to a trusted push. CircleCI should require
`oidc.circleci.com/project-id` and appropriate VCS restrictions. Kubernetes
should require the service account identity. GitLab should bind a project,
ref type/ref and pipeline source; the example's bare `ref=main` does not
distinguish a tag named `main`. Buildkite should bind a pipeline as well as
an organization. A tenant-wide policy should require an explicit choice,
with its scope shown, rather than emerge from an incomplete binding.

Add compromised runners, untrusted checkout/build steps, and reusable
workflow inputs that execute caller code to section 5. OIDC authenticates
the job's identity; it does not attest that all code the job runs is safe.

### 3. High: a reusable workflow's name is not its immutable identity

Section 1, GitHub reusable-workflow alternative, lines 40 to 42;
section 5, lines 154 to 158.

In a reusable job, `repository_owner_id` and `repository_id` identify the
caller. `job_workflow_ref` identifies the callee by a repository path and
ref. Binding the caller's owner ID does not establish the callee's owner
ID. For example, an organization allows all its repositories to use
`vendor/deploy/.github/workflows/release.yml@refs/heads/main`. If that
repository moves and its former path is reused, a caller can execute a
different workflow under the same bound string. Even without a rename,
whoever can change the callee's `main` can change the trusted code.
[GitHub documents the caller/callee distinction](https://docs.github.com/en/enterprise-cloud%40latest/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows).

Make the organization-wide reusable-workflow option explicit about trusting
every eligible caller in that organization. Constrain caller repository,
ref and event where that breadth is unnecessary. Require a reviewed,
immutable callee commit through a SHA-pinned `job_workflow_ref` or an exact
`job_workflow_sha`, and explain the update procedure. Do not describe the
caller's owner ID as protecting the reusable workflow from namespace reuse.
A reviewed callee must also avoid executing arbitrary caller input with
its OIDC permission or fetched secrets.

### 4. High: anonymous requests reach the vault before proving anything

Section 2, refusals, lines 68 to 73; section 3, ordered step 2,
lines 77 to 83; section 4, cache and failures, lines 128 to 137.

An attacker can send a small, syntactically valid JWT with arbitrary
claims and any service name. Step 2 calls `vault.access` before signature
verification. Today that call reads membership, grants, the database clock
and access-log state, and checks integrity. An unknown bearer token
normally stops at its credential lookup; this endpoint introduces a cheap
anonymous way to drive both app and vault databases. A known binding also
lets bogus tokens trigger JWKS requests across many cold isolates. The
per-isolate unknown-`kid` cooldown does not bound deployment-wide traffic,
and the vault's bulk limit only counts unwrapped data keys.

Put admission limits before database, crypto and network work, covering
both source addresses and total deployment capacity. On Workers this
needs an edge/shared mechanism if a deployment-wide limit is promised;
an isolate counter is not one. Specify the Node equivalent, bounded
concurrency and a `429` response. Cap the whole request while streaming,
not only the JWT after JSON parsing. Rate-limit or sample refusal process
logs too.

First select and MAC-check the service's configured binding with a bounded
app lookup. Reject unconfigured issuers without calling the vault. After
signature, audience, time and claim verification, ask the vault once for
current membership, outside SQL, then perform the commit checks described
below. Define cooldowns for failed/empty JWKS fetches and unknown keys,
including the cold-cache case, without caching pending promises. Bound
successful issuance as well: repeated valid exchanges can grow credential
rows and the permanent audit log without consuming the secret-read limit.

### 5. High: restoring an older edited binding bypasses the proposed rollback check

Section 4, saving bindings again, lines 111 to 115; section 6,
table and rollback argument, lines 174 to 188.

The revocation lookup addresses restoring a removed binding, but the
proposal also permits saving bindings again and does not define edits as
replacement. Suppose binding B once trusted a repository broadly, then
an owner narrows its claims. A database owner restores the old, correctly
MAC'd B row at the same member generation. No `token.unbind` names B, so
the old policy works indefinitely. Restoring an old JWKS URL after an
issuer move has the same problem. No audit entry needs to be deleted, so
checkpoint integrity does not detect this row rollback.

Make security-relevant binding contents immutable. Changing claims,
issuer or JWKS URL must atomically revoke the old binding ID and create a
fresh, never-reused ID, with both events audited. Alternatively, compare
a MAC'd revision against authenticated current state; checking only for
`token.unbind` is insufficient for mutable rows. Include the binding ID
itself in the MAC, and define deterministic claim serialization. Labels
and last-use timestamps can remain mutable and unauthenticated.

### 6. Medium: unbinding needs commit-time checks and credential-time enforcement

Section 3, steps 2, 6 and 7, lines 80 to 103; section 6,
"Removing a binding revokes its live credentials," lines 174 to 180.

The ordered exchange allows a check-then-issue race unless its transaction
boundary is defined. Exchange A verifies binding B; an owner removes B and
revokes the credentials that exist; A then inserts a new credential. B's
member is still active at the same generation, so the existing
`SigninService.#liveCredential` would accept that ordinary service
credential. A sweep alone also fails if a database owner restores an old
credential row: step 6 checks the binding's tombstone only during exchange.

Specify the same commit discipline as existing sign-in. After external
verification and `vault.access`, take the app audit head first, recheck
the member generation with `memberStanding`, and reread the binding's MAC,
generation and authenticated revocation state. Consume the assertion,
insert the credential and append `token.exchange` atomically. Unbinding
must use the same serialization point. Recheck time validity at commit if
the request has waited. Never hold this transaction over a vault call.

Extend the credential MAC with the binding ID, and constrain the link to
the same principal and generation, as the identities foreign key already
does. Every credential check must reject a missing, revoked or superseded
binding, including its durable tombstone; do not rely exclusively on the
revocation sweep. Preserve `CredentialUncheckable`'s distinction between
an authentication refusal and a database/vault outage. Test exchanges
racing unbind and member removal/re-admission on both database engines.

### 7. Medium: the Node fetch policy does not fully define public addresses

Section 4, "Every fetch is checked," lines 117 to 126.

The listed address categories leave room for a literal implementation that
blocks RFC 1918, loopback and link-local addresses but allows other
non-public destinations. A registered JWKS hostname could later resolve
to `100.64.0.1`, reachable through a Node deployment's private overlay.
That is shared address space, not RFC 1918 private space, and is explicitly
not globally reachable in the
[IANA registry](https://www.iana.org/assignments/iana-ipv4-special-registry/).
If that internal server has a certificate valid for the hostname, for
example a shared wildcard certificate, HTTPS does not prevent the request.

Define a public, globally routable unicast address policy for both IPv4
and IPv6, including IPv4-mapped addresses, shared space and applicable
transition-address handling. Enforce it in the actual connection resolver
for every connection candidate, preserving the original TLS hostname and
certificate verification. A preliminary DNS check followed by ordinary
`fetch` is insufficient. The five-second deadline must include DNS, TLS
and the bounded, decompressed response body. Apply this transport to both
discovery and JWKS, with no forwarded credentials or redirects.

For Workers, state that this uses standard global public `fetch` and cannot
be silently replaced by a private-network binding. Cloudflare separately
supports [VPC fetch bindings](https://developers.cloudflare.com/workers-vpc/api/).
That is not evidence that ordinary public `fetch` reaches a VPC; it is a
reason to name the transport assumption. Keep development loopback access
an explicit deployment capability, never something selected by a binding.

### 8. Medium: Kubernetes identity and revocation need an explicit exception or support

Section 1, lines 43 to 44; section 3, times, lines 92 to 97;
section 5, identity/leak threats; section 7, exclusions, lines 219 to 223.

Even after requiring `sub`, a Kubernetes subject such as
`system:serviceaccount:prod:deploy` contains reusable names. Delete that
service account and recreate it with the same name: a name-only binding
trusts the new identity. The immutable service-account UID is nested under
the `kubernetes.io` claim, which v1 explicitly cannot match. The
[documented projected-token schema](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)
shows this distinction.

There is also no online revocation check. Deleting a pod or service account
does not revoke a copied token for an external offline verifier; Kubernetes
recommends TokenReview when that behavior is needed.
[Kubernetes validation guidance](https://kubernetes.io/docs/concepts/security/service-accounts/#authenticating-service-account-credentials-in-your-own-code)
states the difference. A still-unspent token can remain exchangeable until
coffre's expiry/age limits, and its exchanged credential then lasts five
minutes. Coffre's own member removal still works, but does not learn about
the Kubernetes deletion.

Either support an exact typed path to the service-account UID in the
Kubernetes preset, or explicitly label v1 as trusting a reusable namespace
and account name. Record the offline revocation limit in section 5 and the
preset. If immediate Kubernetes revocation is promised, design a separate
TokenReview integration with its credentials, availability and network
requirements; do not imply JWKS verification provides it.

### 9. Medium: projected tokens are incompatible with repeated single-use exchanges

Section 2, "Asking again costs one request," lines 61 to 64;
section 3, single-use limitations, lines 100 to 107; section 7,
`COFFRE_ID_TOKEN_FILE`, lines 210 to 215.

A pod runs `coffre run` successfully, then invokes it again a minute later.
Reading the projected file again normally returns the same assertion, so
the second exchange is rejected as replayed even though the first
credential may already have left memory. Kubelet rotates according to
token age, not on each file read; its documented threshold is 80% of the
token lifetime or 24 hours. A token projected for two hours can also cross
coffre's one-hour age limit before rotation.
[Kubernetes token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#launch-a-pod-using-service-account-token-projection)
documents that lifecycle.

Preserve single use, but document the Kubernetes constraint beside the
GitLab constraint. For v1, support one exchange per projection value and
recommend wrapping all required work in one `coffre run`, with a projection
lifetime compatible with the age limit. If independent calls must work,
specify how each obtains a fresh TokenRequest assertion and the narrow RBAC
needed for it. Also define recovery after a response is lost following a
committed exchange: retrying a consumed assertion cannot recover the
random credential when only its hash is stored.

### 10. Medium: the platform support claims need correction and a concrete token profile

Section 3, audience, times and on-demand issuance, lines 88 to 107;
section 7, presets, lines 196 to 217.

Bitbucket's audience is no longer fixed according to its current public
documentation: pipelines can configure `oidc.audiences`. Excluding it for
that reason unnecessarily leaves users with long-lived tokens. CircleCI
supports custom audiences through `circleci run oidc get`, but its default
environment token has the organization ID as audience. It also supports a
shared root issuer, contradicting the unconditional per-customer-URL
description. A preset must choose the correct acquisition path and issuer.

The following table records the platform facts needed to finish the
presets. Claim names are case-sensitive. These are documented capabilities,
not a claim that live integration tests have passed.

| Platform | Custom audience | Relevant identity and context claims |
| --- | --- | --- |
| GitHub Actions | Yes, `core.getIDToken(audience)`. | `repository_owner_id`, `repository_id`, `workflow_ref`, `ref`, `event_name`; reusable jobs also expose `job_workflow_ref` and `job_workflow_sha`. [Reference](https://docs.github.com/en/actions/reference/security/oidc). |
| GitLab | Yes, job `id_tokens.<name>.aud`. | `namespace_id`, `project_id`, `ref`, `ref_type`, `pipeline_source`, `ref_protected`. In merge-request pipelines the older project/namespace claims describe the source project; `job_project_id` and `job_namespace_id`, introduced in 18.4, identify the job's project. Choose deliberately and account for self-hosted versions. [Reference](https://docs.gitlab.com/ci/secrets/id_token_authentication/). |
| CircleCI | Yes, `circleci run oidc get --claims '{"aud":"..."}'`; default tokens use the organization ID. | `oidc.circleci.com/project-id`, `oidc.circleci.com/vcs-origin`, `oidc.circleci.com/vcs-ref`; `context-ids` is an array and `ssh-rerun` a boolean, outside v1's string matcher. A shared root issuer needs `oidc.circleci.com/org-id`. [Claims](https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/), [custom tokens](https://circleci.com/docs/guides/permissions-authentication/oidc-tokens-with-custom-claims/). |
| Buildkite | Yes, `buildkite-agent oidc request-token --audience`. | `organization_id`, `pipeline_id`, `build_branch`, `build_tag`, `build_commit`, `step_key`. Use immutable IDs instead of the proposed `organization_slug` for identity. [Reference](https://buildkite.com/docs/agent/cli/reference/oidc). |
| Kubernetes | Yes, projected `serviceAccountToken.audience` or TokenRequest. | `sub` names namespace/account; the UID is nested. `aud` is an array, including for one audience. [Projection](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken). |
| Google Cloud service account | Yes, metadata identity endpoint or `generateIdToken`. | Bind `sub`, the service account's unique ID. `email` is not the immutable identity. [Acquisition](https://docs.cloud.google.com/docs/authentication/get-id-token), [claims](https://docs.cloud.google.com/docs/authentication/token-types). |
| Fly.io Machines | Yes, arbitrary audience strings. | Organization-specific issuer, plus `org_id`, `app_id`, `machine_id`; the issuer path and `sub` use names. Require IDs for the intended scope. [Platform description](https://fly.io/blog/oidc-cloud-roles/). |
| Bitbucket Pipelines | Yes, `oidc.audiences`, up to ten configured values. | `workspaceUuid`, `repositoryUuid`, `branchName`, `deploymentEnvironment`, `pipelineUuid`, `stepUuid`; the default `sub` also contains a step UUID. [Audience configuration](https://support.atlassian.com/bitbucket-cloud/docs/integrate-pipelines-with-resource-servers-using-oidc/), [claims](https://support.atlassian.com/bitbucket-cloud/docs/deploy-on-aws-using-bitbucket-pipelines-openid-connect/). |
| Azure Pipelines workload federation | The documented service-connection flow uses `api://AzureADTokenExchange`; no arbitrary coffre audience is documented there. | Its service-connection issuer/subject must be taken from that flow. Retaining the fallback for this flow is justified. [Microsoft configuration](https://learn.microsoft.com/en-us/azure/devops/pipelines/release/automate-service-connections?view=azure-devops). |

Correct the Bitbucket exclusion, specify CircleCI token acquisition and
root-issuer handling, and replace Buildkite slugs with IDs. Confirm the
actual emitted audience set for each preset, including whether a custom
audience replaces or supplements a default.

Define `aud` as either exactly `publicUrl` or a singleton array containing
it; reject additional audiences. Require nonempty string `iss` and `sub`,
finite numeric `exp` and `iat`, and validate numeric `nbf` when present.
CircleCI and Google do not document `nbf` as a required claim. State the
clock-skew inequalities and check expiry/age at issuance. Keep a maintained
JOSE verifier responsible for key/algorithm compatibility, ES256's P-256
curve, signature format and unsupported critical headers. Do not copy the
existing Access verifier's generic audience-membership check or cached
remote-JWKS object as a complete implementation of this stricter profile.

### 11. Medium: the exchange record cannot attribute later reads to a run

Section 2, audit entry, lines 65 to 67; section 3, two-hour row cleanup,
lines 100 to 103; section 5, issuer-compromise evidence, lines 141 to 147.

Two jobs exchange into `token:api-deploy` concurrently. Their exchange
entries name different runs, but both subsequent secret reads name the
same service. The proposed exchange fields omit `credentialId`; current
ordinary audit helpers do not persist it, and vault reads only carry
principal, request and operation IDs. Once the credential rows are
deleted, the permanent log cannot say which job read a secret. A successful
exchange record is not evidence that that run performed each later action.

Persist a correlation path from exchange to credential to subsequent
request/operation to vault read. At minimum, record credential ID,
binding ID/revision, member generation, issuance/expiry, issuer and bounded
verified run claims at exchange, and credential provenance on later
operations. For vault reads, pass provenance as audit metadata or commit
an app correlation entry tied to the vault's request/operation ID before
returning values. The vault can continue making authorization decisions
from the principal. Do not log either bearer token.

Keep unauthenticated refusals out of the append-only business audit, with
bounded operational metrics/logs instead. Record only verified claims as
authenticated provenance. Under signing-key compromise, a genuine run ID
can be copied into a forged token: describe these as issuer assertions,
not independent proof of which platform run sent the request.

### 12. Medium: section 6 overstates what moving bindings to the vault would guarantee

Section 6, rollback and vault comparison, lines 182 to 192.

A sealed vault record is still replayable. Today's vault also compares its
record's sequence with authenticated access events, which detects row-only
rollback while the newer event remains. If an attacker restores the old
row and deletes the newer event, the architecture explicitly documents a
window until checkpoint verification. That is the same class of attack
section 6 assigns only to app bindings. A whole-database rewind followed
by process restarts can survive verification altogether.

Nor does `/readyz` becoming red itself stop authentication or decryption.
The current health check reports the failure; request handling is not
gated by it. A database owner who deletes `token.unbind` and restores a
binding can therefore cause more than a guaranteed five-minute access
window if nothing acts on the health failure. Five minutes is the normal
checkpoint cadence, not an unconditional containment deadline.

Keep the app/vault division, but compare equivalent freshness mechanisms
and state the accepted rollback limit. Authenticate the app's revocation
entries before using them as authority, and define their retention/index
independently of short-lived credentials. Link to the
[existing limits](../architecture.md#limits), including whole-database
rewind. If automatic containment is a requirement, explicitly design its
failure signal, enforcement point and outage behavior. Moving a MAC'd row
to the vault alone is not that design.

## What should be kept

- Authentication remains in the app; grants, member generations and the
  secret-read bulk limit remain in the vault. Fresh credentials must not
  reset that principal-level limit or revive an earlier membership.
- Exact issuer and claim comparison, no wildcard matching, immutable
  platform IDs where available, an instance-specific sole audience, and
  a caller-named service checked against only its own bindings.
- Explicit RS256/ES256 allowlisting, a 2048-bit RSA minimum, refusal of
  token-supplied keys/URLs, and bounded expiry plus assertion age. The
  one-hour age limit makes a two-hour consumption retention period
  conservative, provided required time claims are enforced.
- Discovery at binding creation with exact issuer verification, a
  MAC-protected reviewed JWKS URL, no redirects, bounded network work,
  and explicit production/dev transport separation.
- Settled values only in isolate caches. Never retain a remote-JWKS
  resolver's in-flight fetch promise, pending key import, or pending
  failure. Concurrent requests must own their I/O. Keep cache size,
  freshness and unknown-key refresh bounds, supplemented by admission
  control. An unavailable issuer is a `503`, not a false bad-credential
  verdict; fresh cached keys remain usable until their defined expiry.
- Five-minute random coffre credentials, stored only as hashes on the
  server and kept in process memory by the CLI; existing token prefixes,
  output masking, and an explicit long-lived-token fallback. Binding
  removal must revoke derived access, and issuance plus its audit record
  must commit before returning a token.

Only this review document changes. No implementation or design edits are
included. The cryptographic reproduction used ephemeral local keys and
wrote no source files; platform checks used public documentation rather
than live CI accounts.

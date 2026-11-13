# Workload access: use-only, key-bound, on every platform

How a running service (a workload) signs in to coffre and uses its secrets
without holding them. User guide: [docs/workloads.md](../workloads.md).

**Built:** sign-in at `/api/auth/workload` with an `oidc` or `aws` proof;
key-bound sessions checked by DPoP (RFC 9449) on every request; the gate
(replay, nonces, limits); use-only access with its `reads` escape hatch,
`useOnly` and `noReads`; the proxy, `sign`, `verify`, `presign` and the
Postgres tunnel for workloads; `limit` and `unknown_key` alerts; the SDK
(`@coffre/client/workload`) and `coffre serve`.

**Not built yet**, and not planned for 0.16: enrollment codes (4.4),
freezes (8.2), `narrow` (8.4), the Cloudflare entrypoint (9.2) and minting
(7.2). Their routes and commands exist and answer 501 or refuse. Each
section says what of them the code already holds.

## 1. The goal, by example

Acme's `ingest` runs on ECS and calls OpenAI. With a bearer token, the
task's environment holds `OPENAI_API_KEY=sk-…`, and whoever copies it uses
the key from anywhere until someone rotates it. With workload access, the
app makes a non-exportable P-256 key pair at boot, signs an AWS
`GetCallerIdentity` with its task role, and gets a session bound to the key.
It calls `https://secrets.acme.example/use/openai/v1/chat/completions`, each
request signed by the key, and coffre checks the session live, injects the
real key and forwards the call. The environment holds nothing secret, a
session token copied from a log is useless without the key, and a request
captured in transit is accepted once, as signed.

The rule: **a workload holds no secret that works anywhere else, and every
use passes live coffre policy.** What an attacker can still do, they do
through coffre, under limits, and logged.

## 2. Four concepts

| Concept | What it is |
|---|---|
| **Workload** | A service account (`token:api-prod`) with at least one trust binding (`service_bindings`): how it proves who it is on one platform (a profile and claims), and a `policy`. |
| **Proof** | What a workload presents once, at sign-in: a platform's ID token (`oidc`) or a signed AWS `GetCallerIdentity` (`aws`). |
| **Session** | A `credentials` row of kind `workload`, bound to a public key's thumbprint (`jkt`). Every request carries a DPoP proof signed by the private key. |
| **Use** | Coffre performs the operation and the app never holds the value: the proxy (`/use/<credential>`), `sign`, `verify`, `presign` and the Postgres tunnel (section 7). |

"Read" is no key level or role: it is a list on the binding (`reads`,
section 6), because the risk of reading belongs to the platform the value
lands on, and the binding is that platform.

## 3. Threat model and guarantees

**Trust roots:** coffre's app and vault code and keys; the platform's
identity issuer (the Kubernetes API server's signing key, AWS STS, Google's
and Entra's token services, GitHub's OIDC); TLS; WebCrypto's non-extractable
keys, which hold against anything short of reading process memory.

**Attackers:** **A** copies the platform's variable store, a disk, an image
or a backup. **B** sees whole requests in transit (a TLS-terminating
middlebox, a header log), and can replay or race them. **C** reads the
app's or platform's logs. **D** runs code in the app's process (a malicious
dependency). **E** controls CI. **F** is root on the host. **G1** holds a
copy of coffre's database, without its key-encryption key. **G2** runs code
in coffre's app.

**Cells:** **none**, nothing usable. **use**, requests *through coffre*,
each checked live and counted against limits, stopped by revoking the
session or binding; never the value. **value**, values read. Only keys a
binding lists in `reads` turn **use** into **value**.

| Platform (proof) | A | B | C | D | E | F | G1 | G2 |
|---|---|---|---|---|---|---|---|---|
| Kubernetes (projected token, `oidc`) | **none** | **use** once, for an exchange it wins the race to, until `exp`; the pod's own then fails `replayed` | **use** once, for an unspent token (¹) | **use** | **use** | **use** | **none** | **value** |
| AWS: ECS, Lambda, EC2, EKS (`aws`) | **none** | **none**: the signed request names the key | **use**, until leaked role credentials expire (²) | **use** | **use** | **use** | **none** | **value** |
| Google Cloud, Fly, GitHub Actions (`oidc`, audience names the key) | **none** | **none** | **none**: the token works only with the key it names | **use** | **use** | **use** | **none** | **value** |
| Vercel (`oidc`, audience names the key) | **none** | **none** | **use**, with any key, if the function's own token leaks (³) | **use** | **use** | n/a | **none** | **value** |
| Azure managed identity (`oidc`, fixed audience) | **none** | **use**, with any key, until `exp` (up to 24 h) | the same, unless `sources` excludes the attacker (⁴) | **use** | **use** | **use** | **none** | **value** |
| GitLab CI (`oidc`) | **none** | **use** once, until `exp` (⁵) | **use** once, for an unspent token (⁵) | **use** | **use** | **use** | **none** | **value** |
| *A bearer service token* | **value** | **value** | **value** | **value** | **value** | **value** | **none** | **value** |

1. A projected token's audience cannot name the key, so it is spent once:
   one the pod already used is worthless in a log.
2. Lambda puts its role's session credentials in the function's
   environment, so an env dump lets the attacker sign a `GetCallerIdentity`
   until they expire (at most 12 hours). `sources` narrows this where the
   workload has dedicated NAT addresses.
3. A Vercel function's own token, whose audience Vercel fixes, rides every
   request's `x-vercel-oidc-token` header. Whoever holds it can exchange it
   at `https://oidc.vercel.com/~token` for a token naming their own key,
   until it expires. The token coffre receives names the key, so a copy of
   that one is useless.
4. A managed identity hands the same cached token to every replica and
   restart, so it cannot be spent once: it is a bearer until it expires.
5. GitLab fixes `id_tokens` audiences in the job's YAML. If the attacker
   spends the token first, the job's own exchange fails `replayed`, which is
   loud.

**No platform-side attacker ever reads a value.** The **use** cells under
D, E and F cannot be closed by any design: code that runs as the workload
*is* the workload. Limits (8.1) and alerts (8.3) bound them.

**G2 stays open.** At sign-in the vault checks the binding's seal, the
sign-in's DPoP proof and that the session's `jkt` is its key, and, for a
binding that carries its issuer's keys, the token itself (`#proven` in
`packages/vault/src/vault.ts`). But each request's proof is checked by the
app alone, so a taken-over app can still ask the vault to open values for a
session ([architecture.md, "What the vault stops"](../architecture.md#what-the-vault-stops)).

### What it relies on, and the honest limits

- **Non-extractable is not unreadable.** `generateKey(…, false, …)` stops
  `exportKey`, so a library cannot copy the key out. Root can still read
  process memory, and a dependency holding a reference to the key object
  can call `sign`. JavaScript isolates nothing within one process, so
  column D says **use**.
- **Coffre is on the request path**, its availability and latency the
  app's. Sessions last an hour and renew at half-life, so a short outage
  stops uses without ending sessions.
- **Whoever may mint the platform's proof *is* the workload:**
  `sts:AssumeRole` on the role, `iam.serviceAccounts.getOpenIdToken` on a
  Google service account, `kubectl create token` for the Kubernetes one. On
  a binding an Owner made, that includes the sensitive keys it lists (6.1).
- **Upstreams must accept only coffre**, or a copy of a key from an
  *earlier* exposure still works (7.3).
- **What an Owner's bindings cost, their own service's sign-ins pay.** A
  binding's label and claims have no length of their own; the API body that
  makes one is held to 1 MiB and 1,600 values. Its issuer is held to
  `MAX_ISSUER_BYTES` (1,670 bytes), what fits the log's index. Only an
  Owner makes a binding, and its size costs that service's sign-ins: the
  label is copied into each credential a sign-in makes; each candidate's
  claims and issuer are checked against its MAC and parsed; a claim name is
  matched by trying each split at its dots (`claimAt`), 2^d lookups for d
  dots. A stranger's sign-in is held apart: its body is at most
  `SIGN_IN_BODY_BYTES` (128 KiB), the most at which 32 key tries fit a
  request's CPU budget (`packages/core/src/schemas.ts` derives it).

## 4. Proofs and the exchange

### 4.1 The exchange

`POST /api/auth/workload` signs a workload in, beside `/api/auth/oidc`,
which issues bearer credentials until `useOnly` (6.3).

```http
POST /api/auth/workload
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7…

{ "service": "token:api-prod", "proof": { "oidc": "eyJhbGciOiJSUzI1NiIs…" } }

HTTP/1.1 200 OK
DPoP-Nonce: g1.7Hq2…

{ "token": "coffre_wl_…", "tokenType": "DPoP", "expiresAt": "…", "notAfter": "…", "places": ["market/prod"] }
```

- **The `DPoP` header is required:** its signature, `htm` (`POST`), `htu`
  (this URL) and `iat` (within 60 s, `EXCHANGE_SKEW_SECONDS`). No nonce and
  no `ath`: the platform proof is spent or names the key. The session's
  `jkt` is the thumbprint of the proof's `jwk`.
- **In order** (`exchangeWorkloadSession`, `WorkloadService.signIn`): a
  deployment with no gate takes no session (503 `no_gate`); the per-source
  limiter, at most
  32 exchanges in flight per process (429 `busy`), the body (413 past
  128 KiB); the proof by its kind (`PROOFS`), with one read of the service's
  live bindings of its profiles, checked outside any transaction; the
  binding's `noReads` and `sources`; then one vault call (`signIn`) that
  checks the binding's seal and the DPoP proof, spends the token where it is
  spent, weighs the account and binding under their rows' locks, and writes
  the session and its change, which records the run. A proof no binding
  takes costs the limiter and one read.
- **Refusals** stay out of the audit log, since nobody was authenticated:
  401 with a reason (`ExchangeReason`: `no_match`, `signature`, `expired`,
  `audience`, `replayed`, `dpop`, `source`, …), 429 `busy`, or 503
  `issuer_unavailable`.
- **What is spent:**

  | The proof | Spent | Why |
  |---|---|---|
  | Names the key: an ID token whose audience names it, or a signed `GetCallerIdentity` | never | Only that key can use it; presenting it again makes another session for the same key. |
  | `azure` (`REPEATING_PROFILES`) | never | Every replica and restart presents the same token. It is a bearer until it expires. |
  | Any other ID token (`kubernetes`, `gitlab`, `custom`) | once, in `spent_id_tokens` | It is a bearer, and single use bounds a copy. |
- **`places`** are the binding's environments. With exactly one, the stable
  URL `/use/<credential>` works; with several, the request names one
  (`/use/<project>/<env>/<credential>`).

**A workload binding is never a bearer binding.** Every binding for a
key-bound session has a non-null `policy`, `{}` at least. `/api/auth/oidc`,
whose credentials read values, matches only bindings with **no** policy, of
the five `BEARER_PROFILES` (`github`, `github-reusable`,
`github-reusable-organization`, `gitlab`, `custom`). So a leaked Kubernetes
or Azure token, or a GitHub run with a workload binding, never buys a
reading credential there.

### 4.2 Profiles: which platform claims bind

`oidc` proofs follow [oidc.md](oidc.md): exact claims, IDs over names,
immutable bindings, tombstones, spent tokens, fetched or uploaded keys. Each
profile requires the claims that pin one workload by a field the platform
never reuses (`REQUIRED_CLAIMS`):

| Profile | Issuer | Required claims | Audience |
|---|---|---|---|
| `kubernetes` | the cluster's; uploaded keys for a private cluster | `sub`, `kubernetes.io.serviceaccount.uid` | `publicUrl` |
| `gcp` | `https://accounts.google.com` | `sub` (the service account's numeric ID) | names the key |
| `azure` | `https://sts.windows.net/<tenant>/` (v1) or `https://login.microsoftonline.com/<tenant>/v2.0` (v2) | `tid`, `oid` | the binding's `policy.audience` |
| `fly` | `https://oidc.fly.io/<org>` | `org_id`, `app_id` | names the key |
| `vercel` | `https://oidc.vercel.com/<team>` or `https://oidc.vercel.com` | `owner_id`, `project_id`, `environment` | names the key, through `https://oidc.vercel.com/~token` |
| `github`, `github-reusable…` | GitHub's | as for bearer bindings | names the key |
| `gitlab`, `custom` | as for bearer bindings | as for bearer bindings | `publicUrl` |

- **The audience names the key wherever the caller picks it.** For the
  `KEY_NAMING_PROFILES` (GitHub's three, `gcp`, `fly`, `vercel`) the SDK
  asks for `<publicUrl>#jkt=<thumbprint>`, and the exchange takes that, or
  `<publicUrl>?jkt=<thumbprint>`, only when the thumbprint is the DPoP
  key's (`expectedAudiences`). `checkPolicy` sets `keyAudience` for these
  profiles and refuses it off; a `custom` binding may set it.

  Example: a GitHub run's token has audience
  `https://secrets.acme.example#jkt=NzbLsXh8…`. An attacker who copies it
  from a log and signs in with their own key sends a proof whose thumbprint
  is not `NzbLsXh8…`, and the exchange answers `audience`.
- **Only Azure takes `policy.audience`**, and requires it: Entra mints
  tokens only for a registered resource.
- **Azure's tokens repeat**, so they are never spent, their age limit is
  their own `exp` rather than an hour after `iat`, and the session one makes
  ends at that `exp` (5.4).
- **Issuers force their profiles** (`forcedProfiles`): GitHub's, GitLab's,
  Google's, Fly's, Vercel's and Entra's issuers take only their own, so a
  `custom` binding cannot drop the key-naming audience for them, or spend a
  token Azure repeats.

### 4.3 `aws`: a signed `GetCallerIdentity`

The IAM method of HashiCorp Vault and Teleport: EC2, ECS, Lambda and EKS
with no OIDC setup. The SDK signs with the workload's role credentials,
with a bare SigV4 signer (the AWS SDKs' STS clients add headers coffre
refuses), and sends coffre the URL, headers and body, never the credentials:

```
POST https://sts.<region>.amazonaws.com/
Action=GetCallerIdentity&Version=2011-06-15
signed headers: content-type, host, x-amz-date, x-amz-security-token (if any),
                x-coffre-audience: <publicUrl>, x-coffre-key: <jkt>
```

**What coffre checks** (`packages/server/src/workloads/aws.ts`): the URL
is exactly STS's global or a regional host of the commercial partition, and
the body exactly that one, so nothing else is ever fetched and the proof
offers no SSRF; only an allowlist of headers, every one signed, with
`x-coffre-audience` (`publicUrl`) and `x-coffre-key` (the DPoP key's
thumbprint) among them; `x-amz-date` within 5 minutes. STS's 4xx is 401
`signature`; a throttle, a 5xx or an unreadable answer is 503
`issuer_unavailable`. An account's root, a federated user and an IAM user
(`AIDA…`, a long-lived key on disk) are refused.

**The binding names a role by its unique ID**, the `AROA…` part of `UserId`:

```json
{ "profile": "aws", "issuer": "urn:coffre:aws", "claims": { "account": "671742253563", "role_id": "AROAZ3EXAMPLE7QXYZ" } }
```

A role deleted and made again under the same name gets a new `AROA…` ID, so
the old binding no longer matches. `coffre trust ingest --aws
arn:aws:iam::…:role/ingest-task` looks the ID up with the caller's AWS CLI.

**The key is under the signature**, so the proof works with this key only
and column B is **none**. STS keeps no memory of requests and answers the
same proof twice: the key, not spending, makes a copy useless. Leaked role
credentials can still sign a fresh proof (note 2 of section 3).

### 4.4 `enrollment`: platforms that sign nothing

**Not built yet, and not planned for 0.16.** Railway, Render, Heroku and a
bare VM give a process no identity a copy of it lacks. The design is a code
CI mints per deploy (`coffre_enr_…`), exchanged at boot for a key-bound
session. It cannot make a copy inert, only loud (an `enrolled` alert per
session), bounded (at most `2 × replicas` live sessions per code) and
narrowed (`sources`).

What exists: the exchange takes no `enrollment` proof (`PROOFS` holds
`oidc` and `aws`); the mint, list, promote and approve routes answer 501
(`packages/server/src/api/enrollments.ts`); `coffre enroll` and `coffre
approve` refuse. Already in code:

- `checkPolicy` takes an `enrollment` binding's policy: `replicas`
  (required, 1 to 64), `sessionDays` (1 to 90, 30 by default),
  `overlapMinutes` (15), `mintedBy`, `approve`, `onContention`, `reads`,
  `sources`, `unsignedUploads`. `mintedBy` may not name the binding's own
  service, or a session of it could mint codes for itself and outlive every
  deploy.
- The `enrollment_codes` table (11) and the `coffre_enr_` prefix, which is
  never taken as a credential.

## 5. Sessions: DPoP, the gate, renewal

### 5.1 The key and the proof

The SDK makes `crypto.subtle.generateKey({ name: 'ECDSA', namedCurve:
'P-256' }, false, ['sign'])` once per process and exports only the public
JWK. `jkt` is its RFC 7638 thumbprint, 43 base64url characters. Every
request carries the session token and a fresh proof:

```http
POST /use/stripe/v1/charges?expand[]=balance_transaction HTTP/1.1
Authorization: DPoP coffre_wl_7mQ4…
DPoP: <header>.<payload>.<signature>
Content-Type: application/x-www-form-urlencoded
Idempotency-Key: 5f1c…

{ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
{ "jti": "pA6p8w2Yb3fQe1kHn0S9qg", "htm": "POST", "htu": "https://secrets.acme.example/use/stripe/v1/charges",
  "iat": 1792805400, "ath": "fUHyO2r2…", "nonce": "g1.7Hq2…", "hdr": "content-type idempotency-key", "req": "kq9Vg0Zy…" }
```

**The proof signs the whole request, and coffre forwards exactly what it
signs.** RFC 9449's `htm`, `htu`, `ath` and `nonce` cover the method, the
URL without its query, and the token; alone they would leave the query,
headers and body to a copier who wins the race. Two claims of coffre's own
cover the rest (`packages/client/src/dpop.ts`, shared by the SDK and the
verifier):

- **`hdr`** names, lowercased, the headers to forward: every header the app
  set except `UNSIGNED_HEADERS` (those the transport owns or an
  intermediary may rewrite, such as `content-length` and `host`, and the
  request's own `authorization`, `dpop` and `cookie`). A header added on the
  way, by an HTTP library or a proxy, is dropped rather than refused.
- **`req`** is the SHA-256 of a canonical request (`canonicalRequest`): the
  path as sent, every slash and escape kept; the raw query; `name:value`
  for each header in `hdr`; and the body's line. `htu` signs the path as a
  Cloudflare zone normalizes it (`canonicalHtu`), `req` as it goes
  upstream, so `/use/s3/a/b` and `/use/s3/a//b`, two objects to S3, are two
  requests under one `htu`.

**The body's line** (`bodyLine`, one function both sides call): a buffered
body is hashed whole. A streamed one that declares a `Content-Digest` (RFC
9530) is bound by its `sha-256`, which coffre checks as the bytes pass,
holding back the last ones until it matches, up to 95 MiB. Through a
`sigv4` credential, a body signs the `x-amz-content-sha256` it declares,
which S3 checks; `UNSIGNED-PAYLOAD` binds nothing, so it is refused (403
`unsigned_upload`) unless the binding says `unsignedUploads`. No body signs
the empty body's digest. The header that declares a hash must be one `hdr`
names, so a copier cannot pick the form. One case cannot agree and fails
closed (401 `req`): an empty stream of no stated length, which coffre cannot
tell from no body.

**The verifier** (`packages/core/src/identity/dpop.ts`, whose header lists
its checks in order) takes a proof of at most 2 KiB, ES256 on P-256 only,
the thumbprint equal to the row's `jkt`, and `iat` within ±300 s; the nonce,
not the clock, makes a proof fresh. Two ES256 signatures of one payload,
`(r, s)` and `(r, n−s)`, both verify; they carry one `jti`, so the gate
takes only the first.

**Refusals** are 401 with `WWW-Authenticate: DPoP
error="invalid_dpop_proof"` and a JSON `reason`, or `use_dpop_nonce` with a
fresh `DPoP-Nonce`, which the SDK retries once. Every answer after
authentication carries the gate's current nonce, so the SDK holds the
newest and a streamed body it cannot resend rarely meets a stale one.

### 5.2 The gate: replay, nonces, live counters

Proofs must be single-use for column B to say **none**, which takes a
shared memory of every `jti` seen. The gate is that memory, **one per
workload** (`packages/server/src/gate.ts`): it sees every request of the
service account and holds its limits too.

- **On Workers**, a Durable Object, `CoffreGates`, bound as `GATES`, one per
  principal, with no location hint, so Cloudflare places it near its first
  caller, where the workload runs.
- **On Node**, an object in the app's process. A Node deployment runs one
  app process; with several, each gate has its own nonces and clients
  bouncing between them fail on nonces, loudly rather than unsafely.

**Nonces are epochs.** A gate draws a random nonce when it starts and a new
one every 2 minutes (`EPOCH_MS`), takes a proof only under the current or
the previous nonce, and remembers every `jti` it took under each. A `jti`
taken under either is refused under both, spent as soon as the gate sees
it, even if a count then refuses the request.

Example: a proof under nonce `g5`, current from 10:00 to 10:02, is taken
until about 10:04. A copy with the same `jti` sent at 10:01 is `replayed`;
one sent at 10:05 gets `use_dpop_nonce`, which its sender cannot answer
without the key.

- **A restart forgets nothing that matters.** A new gate has a new nonce, so
  every earlier proof is refused. No `jti` is stored, no clock is trusted,
  and a client pays one retry. A clock stepping back up to 10 s
  (`SKEW_MS`) keeps the epoch; further starts a new one.
- **Memory is bounded by the rate.** At 1,000 requests a second
  (`GATE_CEILING`, a Durable Object's documented soft limit), two epochs
  hold at most 240,000 `jti`s, about 20 MB. Past it, 429 `overloaded`.
  Several gates per workload, by session hash, would lift it; not built.
- **Counts** are fixed windows on the clock (a minute's starts on the
  minute, a day's at 00:00 UTC), so a burst across a boundary can take
  twice a limit. A request past any of its counts counts in none. A count
  of an hour or more is also written to the Durable Object's storage within
  10 s of changing (`FLUSH_MS`); shorter ones live in memory.

**The gate decides no one's access.** Revocations and grants are the
database's, read on each request (5.3). Losing a gate costs a nonce retry
and resets counts; it never lets anything through.

### 5.3 Every request, checked live

A workload's request is never authenticated from a cache (`standingSession`
in `packages/server/src/workload-sessions.ts`):

1. the proof's shape, with no I/O;
2. **one SQL statement** (`workloadSession`): the session's row and its
   ancestors' (a `narrow` child's, at most four), each with its member's
   status and generation, its binding and whether a tombstone names it, and
   the place the request uses, by ID or by path;
3. the row: kind `workload`, its MAC, not revoked or expired, not past
   `not_after`, its member active at the same generation, its binding live
   (not revoked, closed or tombstoned) with a policy and a good MAC, its
   ancestors live, and `approved_at` set where the binding says `approve`;
4. the proof against the request (5.1);
5. the client address within `sources`, and `noReads`;
6. the gate: nonce, `jti` and the request's counts, in one call.

The member's generation is read without the vault's MAC. That is safe in
this direction: removal only moves the generation on, so a stale read can
only refuse.

**What is cached.** The vault's decision (grants and opened values), as for
a person's handle, for at most `proxy.revokedWithinSeconds` (60 unless
set). So revocation, expiry, a binding's end and the member's removal take
effect on the next request, a lost grant within that bound. An open
Postgres tunnel reruns the statement without the proof, at most every 15 s
for a workload (`WORKLOAD_RECHECK_MS`).

### 5.4 Lifetime and renewal

- **`expiresAt`: one hour** (`SESSION_MS`). `POST /api/auth/workload/renew`,
  with the session's `Authorization` and a proof, moves it on, never past
  `notAfter`, in two steps since the app computes the row's MAC: read the
  database's clock, then update only if the expiry and MAC are as read, the
  row is not revoked, and it is more than 5 s from expiring on the
  database's clock (`renewSession`). A renewal that lost a race or came late
  updates nothing, so it never revives an ended session. The SDK renews at
  half-life; a dead process stops renewing, so live sessions mean live
  processes.
- **`notAfter`: the hard end.** For a proof that names the key, the
  binding's `sessionHours` (24 unless set, at most 168). For any other ID
  token, the earlier of that and the token's own `exp`, so a copy of a
  bearer proof buys no more than the platform gave it.
- **Re-proving.** Before `notAfter` the SDK exchanges a fresh platform proof
  with the *same* key and swaps sessions, so a deleted Kubernetes service
  account or IAM role stops working within `sessionHours` with no action in
  coffre.
- **Why an hour is fine.** A bearer token's lifetime is its exposure. A
  key-bound token is worthless without the key at any age; a stolen
  capability is bounded by the proof, accepted once, for one exact request,
  within one nonce epoch. Lifetime only bounds forgotten sessions.
- **Ending one.** `POST /api/auth/logout` with DPoP revokes the session; the
  SDK calls it on `close()` and on `SIGTERM`.

### 5.5 What the proof does not stop

An active man in the middle of TLS can hold the app's request and deliver it
later, within the nonce's two epochs (at most 4 minutes), but cannot change
what coffre forwards. A passive copy that wins the race is the app's own
request, delivered once; the original is then `replayed`. Either way the
operation is the one the app asked for, at most once. The winner does get
the *answer* (a presigned URL, a signature, a response body), which whoever
reads the traffic reads anyway.

## 6. Use-only, and the escape hatch

### 6.1 The rule

**A workload session reads no value, except a plain one or one its binding
lists in `reads`.** Everything else it uses through coffre. For a session
whose binding gives `viewer` on `market/prod`:

| The key in `market/prod` | Without `reads` | With `STRIPE_WEBHOOK_SECRET` in `reads` for `market/prod` |
|---|---|---|
| `TWILIO_SID`, plain | read | read |
| `STRIPE_SECRET_KEY`, secret | use | use |
| `STRIPE_WEBHOOK_SECRET`, secret | use | **read** |
| `DATABASE_URL`, sensitive | use (the tunnel) | read only if listed *and* an Owner of `market` made the binding |

**Enforced in the app and in the vault:**

- **The API a session reaches** is `WORKLOAD_ROUTES`
  (`packages/server/src/api/workload-routes.ts`), typed over the route
  table, so a new route must say. It is what a service token reaches (CI's
  writes, folders, archive, deploy-on-push, audit where granted), renew and
  logout, minus `ISSUING_ROUTES`: service tokens, bindings, enrollment
  codes, members, grants, roles and service-account settings answer 403
  `workload_cannot_issue`. A token, binding or code is scoped by role, not
  by key, so one a session made could read keys the session may only use.
  Any other route answers 403 `workload`.
- **Routes that answer values** (reveals, a version's value, the plan)
  answer only plain and listed keys, and name the rest (`useOnly`).
- **No laundering.** A session may not make a reference, fork or copy from
  a key it may not read, which would move a use-only value to a place whose
  keys it reads.
- **The vault.** The app sends a workload's scope with `reads` on its
  grants (`scopeWithReads` in `packages/core/src/access.ts`). The vault
  refuses every purpose but the proxy's use with `use_only`
  (`packages/vault/src/decide.ts`) unless the key is listed where it is
  held: a fork's parent for an inherited key, a reference's holder for a
  reference. Example: `market/dev/S`, a reference to
  `market/prod/STRIPE_SECRET_KEY`, is readable through `"*"` listed for
  `market/dev`, not through a list of `market/prod`'s keys. The vault trusts
  the scope the app sends, so column G2 is unchanged.

**The escape hatch is per binding, per place, per key, by ID.** The API
takes and shows `reads` by path and name, `{ "market/prod":
["STRIPE_WEBHOOK_SECRET"] }` or `"*"` (every key of the environment),
resolved in the binding's transaction and refused by name when absent. The
policy stores environment and key IDs, so a rename moves nothing: renaming
`STRIPE_SECRET_KEY` onto the listed name `STRIPE_WEBHOOK_SECRET` leaves the
listed ID with the key that was listed, and a key deleted and made again is
not listed. A listed key must exist, so a binding made before it lists it
only through a new binding (bindings are immutable). A sensitive key listed
still needs the binding's scope to say `sensitive` for its project, which
only an Owner of the project making the binding gives: no path through
`reads` hands a sensitive value to a session a non-Owner made.

**Why on the binding.** Reading puts a value where the platform can lose
it, so the exposure belongs to the platform. One service may run on
Kubernetes reading nothing, and as a job that must hold
`STRIPE_WEBHOOK_SECRET`; each binding states its own exposure. What usually
removes the need: `verify` for a webhook secret (7.2), `sign` for a signing
key, the tunnel for a database URL. `reads` is for SDKs that take nothing
but the raw key.

### 6.2 What a workload gets back from the plan

`GET /use/<project>/<env>` with DPoP answers as for a handle, without
placeholders:

```json
{ "environment": "market/prod", "values": { "TWILIO_SID": "AC012…" },
  "credentials": ["stripe", "openai"], "tunnels": { "db": { "key": "DATABASE_URL", "url": "wss://…" } },
  "useOnly": ["STRIPE_SECRET_KEY", "DATABASE_URL"], "mints": [] }
```

`credentials` names credentials and signers, `tunnels` each tunnel's key and
URL, `useOnly` every key held and not read. `coffre serve` reads it to know
which listeners to open; `workload.read(key)` reads one value through it.

### 6.3 The strict instance, and the path from today

```ts
// deployment.ts
defineDeployment({ services: { useOnly: true, noReads: false } })
```

**`useOnly: true`** leaves services only key-bound sessions: no service
token is issued, a `coffre_svc_` token is refused at use (`use_only`), and
`POST /api/auth/oidc` answers 410 naming `/api/auth/workload`. CI keeps the
API through its session (`WORKLOAD_ROUTES`) and what its binding lists,
such as an `NPM_TOKEN`. Whatever authenticates with a service token stops,
the Vault KV plugin included ([docs/vault.md](../vault.md)). People are
unchanged.

**`noReads: true`** is stricter: no binding may list `reads`. Making one is
refused, and so are the sign-ins and requests of one that exists. Services
then read plain values only.

Both are off unless set, and `coffre init` writes them commented out.
Without `useOnly`, bearer service tokens and `/api/auth/oidc` keep working.

**Moving a deployment to `useOnly`:** run CI through `coffre run --service`,
which signs in at `/api/auth/workload` when the instance answers it; list in
`reads` the keys each job truly reads; move each app to its platform's
proof; turn on `useOnly` once no bearer service token is live, and `noReads`
once no binding lists `reads`.

## 7. Use: what Coffre does for the workload

### 7.1 What exists, now for workloads too

The proxy (`/use/<credential>/<path>`), `sign`, `verify`, `presign` and the
Postgres tunnel work for a workload as for a handle, except:

- **Authentication** is `Authorization: DPoP` and its proof, never a value
  in the credential's slot. The proxy forwards only the headers `hdr` names,
  then injects the credential. A plugin authenticates through
  `PluginContext.workload(request, { place, credential, body, counts })`,
  which runs 5.3 and the gate's counts in one call; no plugin parses DPoP.
- **Routing.** Only `DPoP coffre_wl_…` is a session. `/use/<a>/…` is
  credential `<a>`'s stable URL whenever `<a>` names a credential, and
  `/use/<project>/<env>/<credential>/…` otherwise, so nothing is looked up
  before the one statement. A project named like a credential is reached
  through the stable URL only. The statement resolves a place named by path
  and says back its ID and current path; a use refuses (409) if a rename
  moved the path in between.
- **Every HTTP request under `/use` signs its content**: forwarding, the
  plan and `POST /use…`, so a copy that wins the race cannot change the
  message to sign.
- **A child's constraints** (8.4) apply to every operation, through
  `constraintsAllow`, against the URL about to be sent upstream.
- **The tunnel's WebSocket** carries `Authorization: DPoP` and a proof with
  `htm` `GET` and `htu` the `https` form of its URL. Its Durable Object is
  named by a digest of its path and session token, which names one session,
  so the Worker looks nothing up. The tunnel asks a workload for no
  password. A group's bytes flow only while its last good check is under
  the bound old.

### 7.2 New uses

**`verify`**, for inbound webhooks: `POST /use/<project>/<env>` with
`{ "verify": { "credential": "yousign", "message": "<base64url>",
"signature": "<as received>" } }` answers `{ "valid": true | false }`,
configured beside `signers`:

```ts
verifiers: { yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) }
```

HMAC-SHA256 of the raw body, compared in constant time
([credential-proxy.md](credential-proxy.md), section 5). A webhook secret no
longer has to be read.

**Minting: not built yet, and not planned for 0.16.** A credential whose
parent key issues short-lived children (AWS `AssumeRole`, a GitHub App
installation token) would keep the parent in the vault while coffre mints
the children, to use itself or to hand to a binding that lists the minter.
What exists: `reads` may list `mints` per environment, the plan answers
`mints: []`, and the SDK's `credential(…).mint()` and `fromCoffre` call
`POST /use` with `mint`, which no minter serves.

### 7.3 Upstreams that accept only Coffre

Use-only protects a value only if the upstream refuses it from anyone but
coffre. The playbook is in [docs/workloads.md, "Upstreams that accept only
coffre"](../workloads.md#upstreams-that-accept-only-coffre): pin coffre's
egress where the issuer can pin a source address; keep a key that cannot be
pinned vault-only and rotate it; admit a database role only from coffre's
address; read, listed, only the key a workload must hold.

## 8. Live policy

### 8.1 Limits per credential

```ts
credentials: { stripe: { upstream: 'https://api.stripe.com', inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}'),
                         limit: { perMinute: 120, perDay: 20_000 } } }
```

- The gate counts each (workload, credential) pair: per minute in memory,
  per day in the Durable Object's storage too on Workers. On Node a restart
  resets both.
- Past a limit: 429 `limit` with `Retry-After`, nothing forwarded, and one
  `workload.alert` of kind `limit` per workload, credential and window.
- A limit per workload is a function of the service:
  `limit: (service) => service === 'token:batch' ? { perDay: 200_000 } : { perDay: 20_000 }`.
  A signer takes one too: `privateKey(key, { limit })`.
- A person's handle is not counted.

### 8.2 Freeze

**Not built yet, and not planned for 0.16.** A freeze would stop every use
under a target (the instance, a service, a binding, a session, or one
credential of one environment) at the next request, keeping sessions and
bindings, so lifting it restores service without a redeploy.

What exists: `GET` and `POST /api/freezes` and `DELETE
/api/freezes/<target>` answer 501 (`packages/server/src/api/freezes.ts`);
`coffre freeze` and `coffre unfreeze` refuse; `freezeTarget` in core spells
a target one way (`instance`, `token:<name>`, `binding:<uuid>`,
`session:<uuid>`, `credential:<environment uuid>/<name>`). Nothing writes a
`workload.freeze` entry, and the per-request check (5.3) reads no freeze.

### 8.3 Alerts

`workload.alert` entries of the app's, `{ kind, service, binding, session,
ip, text }` (`WorkloadAlert`), go to the log, which the audit page filters,
and to the deployment's function, called after the response (`waitUntil` on
Workers):

```ts
auth: signin({ workloads: { limits, alert: (alert) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text: alert.text }) }) } })
```

Raised today (`packages/server/src/alerts.ts`): `limit`, at the gate's first
refusal of a count in its window (8.1); `unknown_key`, a sign-in whose token
names a key its binding's uploaded keys lack, most likely a cluster that
rotated its key, which locks out every workload of the service; and
`audit`, the audit watch's own. `enrolled`, `contention`, `expiring` and
`frozen` are declared for the unbuilt features.

**`unknown_key` follows a token nobody verified**, which anyone who knows a
service and its issuer can send, each with a `kid` of their own. So it is
capped per service, never per `kid`, once an hour across isolates: one
conditional write on `capped_alerts` (`claimAlert`) decides, outside any
transaction, and a capped-out one writes and locks nothing. Only a request
that a binding of the service takes as far as its keys counts.

A failed entry or delivery is logged once to the process log and never
changes the answer. The log entry is the record that counts.

### 8.4 `narrow()`: online attenuation

**Not built yet, and not planned for 0.16.** A workload would hand a part of
itself (an AI agent's tool sandbox, a job runner) a child session bound to
the recipient's key, whose credentials, methods and path prefixes are each a
subset of the parent's, and which ends with any ancestor. Online rather than
Biscuit or macaroons: every use already goes to coffre, so checking a child
is free, its revocation instant, and its rules a few fields.

What exists: `POST /api/auth/workload/narrow` answers 501
(`packages/server/src/api/narrow.ts`), and the SDK's `narrow` calls it. The
checks a child would meet are built:

- `ancestors` and `constraints` on its row (11); the per-request statement
  reads every ancestor, and each must be live (5.3). A child reaches only
  `/use`, narrow and logout.
- `constraintsAllow` (`packages/core/src/identity/constraints.ts`) matches
  paths by whole segments on the resolved upstream URL, base path included,
  after the WHATWG parser has applied dot segments. A child of
  `/v1/refunds` is allowed `/v1/refunds/re_1`, and refused `/v1/refundsX`,
  `/v1/refunds/%2e%2e/charges` (`/v1/charges` once parsed) and
  `/v1/refunds/..;/charges` (which Tomcat reads as `/v1/charges`). Any
  encoded `.`, `/` or `\`, `%25` or `;` is refused, so the upstream cannot
  read a segment differently from coffre.
- A child with `paths` or `methods` is refused `sign`, `verify`, `mint` and
  the tunnel, which have no request to check.

## 9. The SDK, the binding, the sidecar

### 9.1 `@coffre/client/workload`: Node, Bun, Deno

No dependencies, WebCrypto only, built for Node 20 like the rest of the
client (`packages/client/src/workload.ts`):

```ts
import { workload, aws } from '@coffre/client/workload';
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'ingest', proof: aws() });
const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
```

- **Proofs:** `kubernetes()`, `aws()`, `gcp()`, `azure({ audience })`,
  `fly()`, `vercel()`, `github()`, `oidc(token)`, `enrollment(code)`.
- **`Workload`:** `fetch` (signs requests under `<url>/use/`, passes the
  rest through), `url(name)`, `credential(name)` (`fetch`, `sign`,
  `verify`, `presign`, `mint`), `read(key)` (rejects with `use_only` for
  anything not readable), `narrow`, `close`.
- **Lifecycle:** exchange once, renew at half-life, re-prove before
  `notAfter`, retry `use_dpop_nonce` once. The token, key and nonce live
  only in `workload()`'s closure; nothing touches disk or `process.env`.
- `@coffre/client/workload/postgres`'s `connect(coffre, 'db')` is a
  `Duplex` over the tunnel that node-postgres takes as `stream`.

### 9.2 Cloudflare Workers: a service binding, nothing to prove

**Not built yet, and not planned for 0.16.** Coffre's Worker would export
an entrypoint, `CoffreWorkload`, that an app Worker of the same account
binds with `props` naming its service. The caller's deploy configuration
sets `ctx.props`, which its code cannot change, so the call is the proof,
with no session row. The trust root is whoever can deploy Workers to the
account, who could equally deploy coffre.

What exists: the `cloudflare` profile (no claims, a policy of `reads`
only), the entrypoint answering 501
(`packages/server/src/cloudflare-workload.ts`), and
`PluginContext.workloadFromBinding`, which returns the caller a DPoP request
would.

### 9.3 `coffre serve` and `coffre run`: any language, any container

`coffre serve` (`packages/cli/src/serve.ts`) is the sidecar: it signs in,
holds the session and its key, and listens locally.

```sh
coffre serve --url https://secrets.acme.example --service api-prod \
  --proof kubernetes:/var/run/secrets/coffre/token --listen 127.0.0.1:7300 --tunnel db=127.0.0.1:7432
```

- `http://127.0.0.1:7300/use/<credential>/<path>` is forwarded with DPoP,
  signing the request as the app sent it, so the app's config names that
  URL (`OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai`). Each `--tunnel`
  is a Postgres listener with an empty password.
- **The boundary is the network namespace.** Anything in the pod can reach
  the listener, as anything in a process can use the SDK's key. On a shared
  machine, `--listen unix:/run/coffre/api.sock` (mode `0600`) narrows it to
  one user.
- **`coffre run --service api-prod --proof … -- ./start`** does the same for
  one command, giving the child the plan's values and `COFFRE_CREDENTIALS`
  pointing at its listener.

### 9.4 Each platform in about ten lines

Per-platform recipes (Kubernetes with a native sidecar, ECS and Lambda,
Cloud Run, Azure, Fly, Vercel, GitHub Actions, GitLab CI, any language) are
in [docs/workloads.md, "Each platform"](../workloads.md#each-platform).

## 10. Cost per request

A warm workload request through the proxy costs one app SQL statement, one
gate call, one ES256 verify and no vault call;
`packages/server/test/request-cost.alone.ts` holds it there. Beside a
handle's warm request, which asks neither the database nor the vault, it
adds a round trip to each of the database and the gate, and in return sees
a revocation on the very next request. On Cloudflare the gate call measured
about 0.2 ms of CPU on the Worker's side and 0.2 ms in the object, almost
all of it the Durable Object call's own. Hashing a body costs about 2 ms of
CPU per MiB on Workers. `pnpm bench:workers` measures both, cold and warm.

## 11. Data model and migration

**`credentials`**, for kind `workload` (`packages/db/src/schema.ts`):

| Column | What |
|---|---|
| `jkt` | the key's thumbprint, required for kind `workload` by a check |
| `not_after` | the hard end (5.4) |
| `places` | the environments the session was made for |
| `ancestors`, `constraints` | a `narrow` child's ancestors' IDs, root first, and its limits, canonical JSON (8.4) |
| `enrollment_id` → `enrollment_codes(id)` | the code that made it (4.4) |
| `approved_at`, `approved_by` | for `approve` bindings (4.4) |

`created_by` is `binding:<id>`. A `workload` row has a MAC kind of its own,
`workload_credentials`, so its MAC never checks as another kind's. The
runtime login may update `expires_at` (renewal) and `approved_*`, never
`jkt`, `not_after`, `ancestors`, `constraints` or `enrollment_id`.

**`service_bindings.policy`**: canonical JSON, keys sorted, one spelling per
policy (`checkPolicy`). Each profile takes a fixed subset of the fields
(`POLICY_FIELDS`): `audience`, `keyAudience`, `reads`, `sources`,
`sessionHours`, `unsignedUploads`, and 4.4's. Null marks a bearer binding
(4.1). It is immutable with the rest of the binding; a binding with one adds
the prefix `policed_` to its MAC kind, with the policy as the last field.
For the profiles whose proof is no ID token, `issuer` and `jwks_uri` hold a
URN (`urn:coffre:aws`, `urn:coffre:enrollment`, `urn:coffre:cloudflare`),
which no token names.

**`enrollment_codes`** (4.4, unused until enrollment is built): `id`,
`auth_mac`, `binding_id`, `code_hash` (SHA-256 of the code, unique),
`code_hint`, `scope` (fixed at minting), `created_at`, `created_by`,
`created_with`, `expires_at`.

**Tokens** (`packages/core/src/identity/tokens.ts`): `coffre_wl_` is a
session, `coffre_enr_` an enrollment code, never a credential; 32 random
bytes each, so secret scanners match them by prefix. A sign-in's change in
the log records the run: its proof, issuer and claims.

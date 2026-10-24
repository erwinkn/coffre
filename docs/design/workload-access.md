# Workload access: use-only, key-bound, on every platform

A design written on 2026-10-24 (W151) from Erwin's R34. Nothing in it is built
yet. Section 12 splits the build into PRs that can proceed in parallel, each
with the files it owns and its tests. The decisions in section 13 were taken
on the recommended option while Erwin was away (R10). Each one is his to
revisit.

## 1. The goal, by example

On 2026-10-21 Railway disclosed that attackers had read customers' encrypted
environment variables, and decrypted some of them. Take Acme's `api`, which
runs on Railway and calls Stripe and OpenAI.

**Today.** CI runs `coffre export market/prod` and pushes the values into
Railway's variables. The attacker copies `STRIPE_SECRET_KEY=sk_live_…` and
`OPENAI_API_KEY=sk-…`. Both work from anywhere, for as long as nobody rotates
them. Coffre's log shows CI reading them on deploy day and nothing after.

**With this design.** Railway's variables hold one value:
`COFFRE_ENROLL=coffre_enr_…`. CI mints it for this deploy, and it has no use
outside Coffre. At boot, the app makes a P-256 key pair in memory that cannot
be exported. It proves its identity with the enrollment code and gets a
session bound to that key. From then on it calls
`https://secrets.acme.example/use/stripe/v1/charges`, and every request is
signed by the key. Coffre checks live policy, injects the real key and
forwards the call. Stripe's key never reaches Railway, the app's memory or its
logs. Here is what the attacker can do with the copy:

| The attacker | Gets |
|---|---|
| Uses `coffre_enr_…` from an address the binding's `sources` admits | A session, and an `enrolled` alert naming their address at once. The code admits up to twice `replicas` sessions, so that a deploy can overlap old and new instances. A tripwire freezes a code that stays over `replicas` for long, or churns (4.4). A careful thief can stay under it, and keeps using Stripe *through Coffre*, logged and under limits, until someone acts on the alert or the next deploy promotes a new code. They never get Stripe's key. |
| Uses it from an address outside `sources` | Refused. On Railway this narrows rather than proves: its outbound addresses may be shared with other customers. |
| Copies the session token from a log line or a crash dump | Nothing. The token is useless without the key, which never left the process. |
| Captures one signed request in transit | Nothing. Each proof is accepted once, and signs the request it came with: method, URL, query, the headers Coffre forwards, and the body. (The enrollment exchange itself carries the code, so whoever reads that request holds what a copy of the env holds.) |

On every platform with a workload identity of its own (Cloudflare, Kubernetes,
AWS, Google Cloud, Azure, Fly, Vercel, CI), the platform's store holds nothing
at all.

The whole design follows from one rule. **A workload holds no secret that
works anywhere else, and every use passes live Coffre policy.** Whatever a
platform breach copies (env, disk, image, logs, a token), it yields no value.
On a platform with an identity of its own it yields no standing credential
either. On one without, the enrollment code is the one credential a copy
holds, and section 4.4 makes using it loud and bounded. Whatever an
attacker can do, they do through Coffre, under limits, logged, and only
until a freeze or revocation stops them.

## 2. Four concepts

| Concept | What it is | New? |
|---|---|---|
| **Workload** | A service account (`token:api-prod`) with at least one trust binding. A binding names how the workload proves who it is on one platform. | No. It is a service account plus `service_bindings` ("Trusted workloads" already). Bindings gain profiles and a `policy`. |
| **Proof** | What a workload presents once, at sign-in: a platform's ID token (`oidc`), a signed AWS `GetCallerIdentity` (`aws`), or a Coffre enrollment code (`enrollment`). On Cloudflare, the service binding is the proof. | `oidc` exists (`POST /api/auth/oidc`). `aws`, `enrollment` and the Cloudflare entrypoint are new. |
| **Session** | A `credentials` row of a new kind, `workload`, bound to a public key's thumbprint (`jkt`). Every request carries a DPoP proof (RFC 9449) signed by the private key, which never leaves the process's memory. | The kind, the key binding and the gate (section 5) are new. |
| **Use** | Coffre performs the operation and the app never holds the value: the proxy (`/use/<credential>`), `sign`, `presign`, the Postgres tunnel, and minting (section 7). | Use exists for people's handles. Workloads now get it, and it becomes their default. Minting is new. |

Two things are deliberately **not** new concepts:

- **"Read" is a list on the binding**, not a new key level or role. The risk of
  reading belongs to the platform the value lands on, and the binding *is*
  that platform. So the binding is where the list lives and where the page
  flags it: "exposed if Railway is breached" (section 6).
- **Narrowing** creates another session of kind `workload` with a parent
  (section 8). It is not a token format of its own.

## 3. Threat model and guarantees

**Assets.** The values Coffre holds, and the authority to use them.

**Trust roots.** These are taken as given:
- Coffre's app and vault code, and their keys.
- The platform's identity issuer, for platforms that have one: the
  Kubernetes API server's signing key, AWS STS, Google's and Entra's token
  services, GitHub's OIDC, Cloudflare's control plane for the binding's
  `props`.
- TLS.
- WebCrypto's non-extractable keys, which hold against anything short of
  reading process memory.

**Attackers, one column each:**

- **A. Env or store copy.** Reads the platform's variable store, a disk or
  volume snapshot, an image or a backup. Railway's breach.
- **B. Token in transit.** Sees whole requests to Coffre: a TLS-terminating
  middlebox, a proxy's header log. Can replay, and can race the original.
- **C. Log leak.** Gets whatever the app or platform wrote to logs or crash
  reports: an env dump, a token, a request.
- **D. Malicious dependency.** Runs code inside the app's process.
- **E. CI compromise.** Controls the pipeline that builds and deploys the app.
- **F. Root on the host.** Reads any process's memory and any file on the
  machine or node.
- **G1. Coffre's database copied.** Holds ciphertext, but no key-encryption
  key (KEK).
- **G2. Coffre's app or vault taken over.** Runs code in the app or the vault.

**What each cell means:**

- **none**: the attacker gets nothing usable.
- **use**: the attacker can make requests *through Coffre*. While their access
  lasts, each request is checked live, counted against limits, and stopped
  by a freeze or revocation. The log records each session's use of each
  credential at least once a minute (the vault's opening), not every
  request. The attacker never gets the value.
- **value**: the attacker reads values.

Only keys that a binding lists in `reads` (section 6) ever turn a **use** cell
into **value**, and the page shows that per binding. A strict instance
(`useOnly`) has no such keys.

| Platform (proof) | A. env/store copy | B. in transit | C. log leak | D. dependency | E. CI | F. root on host | G1. DB copy | G2. Coffre taken over |
|---|---|---|---|---|---|---|---|---|
| Cloudflare Workers (service binding, `props`) | **none**: nothing secret exists | **none**: the call never leaves Cloudflare's runtime | **none** | **use** | **use**: a deployer, or a branch's preview build that keeps the binding (9.2), can run code that calls it | n/a (Cloudflare's runtime) | **none** | **value** |
| Kubernetes (projected token, `oidc`) | **none**: etcd holds no projected token | **use** once, for an exchange it wins the race to, until the token's `exp`; the pod's own exchange then fails `replayed` | **use** once, for an unspent token, until its `exp`: the pod spec's `expirationSeconds`, 600 at least (¹) | **use** | **use**: it can run a pod as the service account | **use**: reads fresh projected tokens | **none** | **value** |
| AWS: ECS, Lambda, EC2, EKS (`aws`) | **none**: role credentials are runtime-only | **none**: the signed request names the key, so a copy works for no other key | **use**, until the leaked role credentials expire (²) | **use** | **use** | **use** | **none** | **value** |
| Google Cloud, Fly, GitHub Actions (`oidc`, audience names the key) | **none** | **none** | **none**: the token works only with the key its audience names (4.2) | **use** | **use** | **use** | **none** | **value** |
| Vercel (`oidc`, audience names the key, by an exchange) | **none** | **none**: what reaches Coffre names the key | **use**, with any key, until the function's own token's `exp`, if that token leaks (⁵) | **use** | **use** | n/a (Vercel's runtime) | **none** | **value** |
| Azure managed identity (`oidc`, fixed audience) | **none** | **use**, with any key, until the token's `exp` (up to 24 hours) | **use**, the same, unless `sources` excludes the attacker (³) | **use** | **use** | **use** | **none** | **value** |
| GitLab CI (`oidc`) | **none** | **use** once, for an exchange it wins the race to, until the token's `exp` (⁴) | **use** once, for an unspent token, until its `exp` (⁴) | **use** | **use** (it *is* CI) | **use** (the runner) | **none** | **value** |
| Railway, Render, a VM (`enrollment`) | **use**, *detected, not prevented*: a copied code raises `enrolled` at once, and shares the code's `2 × replicas` slots with the deployment (all of them while it is down) until the next deploy promotes a new code or a person acts. A tripwire freezes the clumsy cases (4.4). `sources` narrows the addresses it works from. | as A, for the exchange that carries the code; **none** for every request after | as A | **use** | **use**: CI mints codes | **use** | **none** | **value** |
| *Today: a bearer service token* | **value**, for up to a year | **value** | **value** | **value** | **value** | **value** | **none** | **value** |

Notes:

1. A projected token in a log is spent if the pod used it. Its audience
   cannot name the key, so an unspent one works once.
2. Lambda puts its role's session credentials in the function's runtime
   environment. An env dump in a log therefore lets the attacker sign a
   `GetCallerIdentity` with them until they expire (at most 12 hours). A
   binding's `sources` narrows this to the VPC's NAT addresses where the
   workload has dedicated ones.
3. Managed identities cache their tokens, so two replicas on one identity,
   or a restart, present the same token. Its audience cannot name the key,
   so it cannot be spent once (4.2): it is a bearer until it expires. A NAT gateway's dedicated addresses in
   `sources` exclude an attacker outside the network.
4. GitLab's `id_tokens` audiences are fixed in the job's YAML, so they
   cannot name a key either. If the attacker spends the token first, the
   job's own exchange fails with `replayed`, which is loud.
5. A Vercel function holds a token whose audience Vercel fixes
   (`https://vercel.com/<team>`), on every request's `x-vercel-oidc-token`
   header. Anyone holding it can exchange it at
   `https://oidc.vercel.com/~token` for a token of any audience, the
   attacker's key included, until it expires. A request logged with its
   headers therefore leaks a bearer of the workload. The token Coffre
   receives names the key, so a copy of *that* is useless.

What the table says in one sentence: **no platform-side attacker ever reads
a value.** In every **use** cell, a freeze or a revocation stops the attacker
at their next request. What a copy can hold beyond the attacker's presence
is bounded per row: an unspent ID token's single use until its `exp`,
Azure's cached tokens, a Vercel function's own token and Lambda's role
credentials until they expire, and an enrollment code until the next deploy
promotes a new one.

The **use** cells under D, E and F cannot be closed by any design. Code that
runs as the workload *is* the workload. What Coffre can do about them is
bound them: per-credential limits, `narrow()` for the parts of an app that
need less, and alerts.

**G2 is the column the vault exists for, and it stays open here.** A
taken-over app authenticates whomever it likes and asks the vault to open
values for them. That is the existing limit ([architecture.md, "What the vault stops"](../architecture.md#what-the-vault-stops)).
Key-bound sessions are what close it later. If the vault verifies each
workload's proof itself, a taken-over app can only replay proofs it is
handed, one use each. That design is section 14's first item. It is not in
this build.

### What it relies on, and the honest limits

- **Non-extractable is not unreadable.** `crypto.subtle.generateKey(…,
  false, …)` stops `exportKey`, so a library cannot serialize the key and
  send it elsewhere. Root on the host can still read process memory, and a
  dependency inside the process can call `sign` with the key object if it
  gets hold of a reference. The SDK keeps the key in a closure and never
  passes it out (section 9), but JavaScript isolates nothing within one
  process. Column D says **use**, not **none**, for this reason.
- **The enrollment row is detection, not prevention.** A platform that signs
  no identity offers nothing a copy lacks, except where the copy runs from.
  Section 4.4 makes copying loud and pins the source where the platform has
  stable egress addresses. It cannot make a copy inert.
- **Coffre is now on the request path.** Use-only means an upstream call
  goes through Coffre: its availability becomes the app's, and so does its
  latency, one more hop. Sessions last an hour and renew at half-life, so a
  short Coffre outage stops uses but does not end sessions. Section 10 has
  the budget.
- **Who becomes the workload.** On every platform, whoever may mint the
  platform's proof for that identity *is* the workload: `sts:AssumeRole` on
  the role, `iam.serviceAccounts.getOpenIdToken` on a Google service
  account, `kubectl create token` for the Kubernetes service account,
  deploying to the Worker. On a binding an Owner made, they read its
  listed sensitive keys. Each binding's page names that permission, so the
  Owner knows whom R32 now covers.
- **Upstreams must accept only Coffre.** If Stripe accepts the same key from
  anywhere, a copy of it from any *earlier* exposure still works. Section 7's
  playbook covers each kind of credential.

## 4. Proofs and the exchange

### 4.1 The exchange

`POST /api/auth/workload` signs a workload in. It sits beside
`/api/auth/oidc`, which stays for bearer credentials until `useOnly`
(section 6.3).

```http
POST /api/auth/workload
Content-Type: application/json
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoi4oCmIiwieSI6IuKApiJ9fQ.…

{ "service": "token:api-prod", "proof": { "oidc": "eyJhbGciOiJSUzI1NiIs…" } }
{ "service": "token:api-prod", "proof": { "aws": { "url": "https://sts.eu-west-3.amazonaws.com/", "headers": { "authorization": "AWS4-HMAC-SHA256 Credential=ASIA…/20261024/eu-west-3/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key, Signature=…", "content-type": "application/x-www-form-urlencoded; charset=utf-8", "x-amz-date": "20261024T013000Z", "x-amz-security-token": "…", "x-coffre-audience": "https://secrets.acme.example", "x-coffre-key": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" }, "body": "Action=GetCallerIdentity&Version=2011-06-15" } } }
{ "service": "token:api-prod", "proof": { "enrollment": "coffre_enr_Qm9Y…" } }
```

```http
HTTP/1.1 200 OK
DPoP-Nonce: g1.7Hq2…
Cache-Control: no-store

{ "token": "coffre_wl_…", "tokenType": "DPoP", "expiresAt": "2026-10-24T02:30:00Z",
  "notAfter": "2026-10-25T01:30:00Z", "places": ["market/prod"] }
```

- **The `DPoP` header is required.** The exchange checks the proof's
  signature, its `htm` (`POST`) and `htu` (this URL), and its `iat` (within
  60 s). It takes no nonce and no `ath`. The exchange is not replayable
  anyway: the platform proof is spent, and the key is the caller's own. The
  session's `jkt` is the thumbprint of the proof's `jwk`.
- **Admission, then work, in the same order as the OIDC exchange
  ([oidc.md](oidc.md), section 2):**
  1. the two limiters (per source, and total);
  2. the body, at most 16 KiB;
  3. the shape;
  4. one read of the service's live bindings of the proof's profiles, by an
     explicit profile filter;
  5. the proof itself;
  6. `vault.access` for the member, outside any transaction;
  7. the commit, under the log head, deciding on database facts only (no
     gate or vault call inside it): re-check member and binding, spend the
     proof, the enrollment's capacity (section 4.4), insert the credential,
     append `token.exchange` with `{ kind: 'workload', jkt, proof: 'aws' | 'oidc' | 'enrollment', … }`.

  A proof no binding can take costs admission and one read, as today.
- **Refusals** are kept out of the audit log as today. They are 401s with
  the OIDC exchange's reasons plus `dpop` (the header is missing or bad),
  `source` (outside the binding's `sources`, or no client address to check),
  `superseded` (an older enrollment) and `frozen`. A full code is 429
  `full` with `Retry-After: 30` (4.4). A session awaiting approval is not a
  refusal: it answers 202 `pending` (4.4).
- **What is spent.** There are three cases, one rule each:

  | The proof | Spent | Why |
  |---|---|---|
  | Names the key: an ID token whose audience names it, or a signed `GetCallerIdentity` | never | Only that key can use it. The same key presenting a platform's cached token again, to re-prove, is harmless. |
  | `azure` | never | A managed identity hands the same cached token to every replica and restart. Spending it would refuse them. It is a bearer until it expires (4.2). |
  | Any other ID token (`kubernetes`, `gitlab`, `custom`) | once, as today, in `consumed_tokens` | It is a bearer, and single use is what bounds a copy. |
- **`places`** are the environments of the binding's scope, as a handle's
  `places`. With exactly one, the stable URL `/use/<credential>` works. With
  several, the SDK names the environment (`/use/<project>/<env>/<credential>`),
  as a handle of several environments must.

**A workload binding is never a bearer binding.** Every binding made under
this design carries a non-null `policy`: `{}` at least, and
`{ "keyAudience": true }` for `github`, `gcp`, `fly` and `vercel`. `/api/auth/oidc`,
which issues the bearer credentials that read values (R13), matches only
bindings with **no** policy, of today's five profiles (`BEARER_PROFILES`:
`github`, `github-reusable`, `github-reusable-organization`, `gitlab`,
`custom`). So a leaked Kubernetes, Azure or Vercel token, or a GitHub run
with a workload binding, can never buy a reading credential there, whatever
`reads` says. Bindings made before this design have no policy and keep
working at both exchanges, as today.

**Why a new route and not a header on `/api/auth/oidc`.** The AWS and
enrollment proofs are not OIDC, and the answer is a different kind of
credential with different routes. One route per credential kind keeps
`useOnly` a one-line switch: it turns off the old route.

### 4.2 Profiles: which platform claims bind

`oidc` proofs keep everything in [oidc.md](oidc.md): exact claims, IDs over
names, immutable bindings, tombstones, spent signing inputs, fetched or
uploaded keys. What changes is new profiles. Each profile requires the claims
that pin one workload, by a field the platform never reuses:

| Profile | Issuer | Required claims | Audience | Gets its token from |
|---|---|---|---|---|
| `kubernetes` | the cluster's (`kubectl get --raw /.well-known/openid-configuration`); uploaded keys for a private cluster | `sub`, `kubernetes.io.serviceaccount.uid` | `publicUrl` (the projected volume's `audience`) | the projected file, read again before each exchange |
| `gcp` | `https://accounts.google.com` | `sub` (the service account's unique numeric ID) | `publicUrl#jkt=<thumbprint>` | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=…&format=full`, header `Metadata-Flavor: Google` |
| `azure` | the binding's, exactly one of `https://sts.windows.net/<tenant>/` (v1) or `https://login.microsoftonline.com/<tenant>/v2.0` (v2), whichever the resource app's `accessTokenAcceptedVersion` makes Entra issue | `tid`, `oid` (the managed identity's object ID) | the binding's `audience`: Entra mints tokens only for a registered resource. A v1 token's is the resource as asked for, its application ID URI (`api://coffre-acme`); a v2 token's is always the API's application (client) ID, a GUID | IMDS `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=…` with `Metadata: true`; App Service and Functions use `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` |
| `fly` | `https://oidc.fly.io/<org>` | `org_id`, `app_id` | `publicUrl#jkt=<thumbprint>` | `POST /v1/tokens/oidc` on the machine's `/.fly/api` socket, `{"aud": …}` |
| `vercel` | `https://oidc.vercel.com/<team>` (team mode) or `https://oidc.vercel.com` (global mode), the binding's | `owner_id`, `project_id`, `environment` (`production` keeps previews out) | `publicUrl#jkt=<thumbprint>` | the function's token (the `x-vercel-oidc-token` header, `VERCEL_OIDC_TOKEN`), exchanged for that audience: `POST https://oidc.vercel.com/~token` `{ "token": …, "aud": … }`, as `@vercel/oidc`'s `getVercelOidcToken({ audience })` does |
| `github`, `github-reusable…`, `gitlab`, `custom` | as today | as today | `publicUrl#jkt=<thumbprint>` on GitHub; `publicUrl` elsewhere | as today |

- **The audience names the key wherever the platform allows it.** Where the
  caller picks the audience (GitHub, Google, Fly, Vercel), the SDK asks for
  `<publicUrl>#jkt=<thumbprint>`, and the exchange accepts that form only
  when the thumbprint equals the DPoP key's. A copied token is then useless
  to any other key, spent or not. Bindings of these profiles require
  that form (`policy.keyAudience`, on by default for them and refused off by
  the page, which says why). `kubernetes`, `gitlab` and `custom` keep plain
  `publicUrl`, since their audience is fixed in configuration.
- **Vercel picks it by an exchange.** Settled from `@vercel/oidc`'s source
  (4.0.3; since 3.7.0): `getVercelOidcToken({ audience })` POSTs the
  function's own token to `https://oidc.vercel.com/~token` and gets back
  one for that audience. Vercel fixes the first token's audience,
  `https://vercel.com/<team>`, and that token is a bearer for the exchange
  until its own `exp`: a thief who holds it mints a token naming their own
  key (note 5 of section 3). What reaches Coffre names the key, so only the
  function's own token is worth stealing, and it is the platform's.
- **`audience` in the policy.** Azure cannot mint for an arbitrary
  audience. Its binding names the exact audience, under its MAC. Every
  other profile refuses a policy `audience`.
- **Azure's tokens repeat.** A managed identity caches its tokens for up
  to 24 hours, so replicas and restarts on one identity present the same
  one.
  - **Such a token is never spent**, and its age limit is its own `exp`
    rather than oidc.md's hour after `iat`: a restart two hours after
    issuance presents a token two hours old.
  - **A leaked one is therefore a bearer until it expires**, for any key
    (columns B and C), and the session it makes ends at its `exp` (5.4). The
    binding's page says so. A NAT gateway's dedicated addresses in
    `sources` close it.
  - Unverified live: there is no Azure account tonight.
- **`forcedProfiles` grows.** Google's, Fly's, Vercel's and Entra's issuers
  force their profiles, as github.com's and gitlab.com's do today. A
  `custom` binding therefore cannot drop `keyAudience` for them, or spend a
  cached token.
- **Unverified facts**, to check on first live use:
  - **Google and Fly** may refuse a `#` in the audience string. If either
    does, the SDK falls back to `publicUrl?jkt=<thumbprint>`, which the
    exchange accepts the same way. Google's metadata server may cache
    identity tokens per audience, which is harmless: a key-naming token is
    never spent.
  - **Vercel**: whether `~token` takes a `#` in `aud` (the `?jkt=` form
    is the fallback, as for Google and Fly), and that the token it answers
    keeps the function's issuer and claims (`@vercel/oidc`'s own verifier
    takes both issuer forms, and one key set, for either token).
- **AWS can also use OIDC.** AWS's outbound identity federation
  (`sts:GetWebIdentityToken`) makes AWS an OIDC issuer for accounts that turn
  it on. A `custom` binding works for those. The `aws` proof below needs no
  setup at all, so it is the default.

### 4.3 `aws`: a signed `GetCallerIdentity`

This is the IAM method of HashiCorp Vault and Teleport, which covers EC2, ECS,
Lambda and EKS with no OIDC setup.

**Signing.** The SDK signs, with the workload's own role credentials (env,
the ECS container endpoint, or IMDSv2):

```
POST https://sts.<region>.amazonaws.com/
Action=GetCallerIdentity&Version=2011-06-15
signed headers: content-type: application/x-www-form-urlencoded; charset=utf-8,
                host, x-amz-date, x-amz-security-token (if any),
                x-coffre-audience: <publicUrl>, x-coffre-key: <jkt>
```

It sends Coffre the URL, headers and body, never the credentials.

**What Coffre checks:**

1. **The URL, method and body.** The URL must be exactly
   `https://sts.amazonaws.com/` or `https://sts.<region>.amazonaws.com/`,
   with `<region>` matching `^[a-z]{2}(-[a-z]+)+-\d$` and not containing
   `-gov-`: the commercial partition only, so GovCloud, China (a `.com.cn`
   host) and FIPS endpoints are refused. The
   method is `POST`, and the body exactly
   `Action=GetCallerIdentity&Version=2011-06-15`. Nothing else is ever
   fetched, so the proof offers no SSRF.
2. **The headers.** Coffre rebuilds the request from an allowlist:
   `authorization`, `content-length`, `content-type`, `host`, `x-amz-content-sha256`,
   `x-amz-date`, `x-amz-security-token`, `x-coffre-audience` and
   `x-coffre-key`, each named once, in any case. Any other header is
   refused.
   - `x-coffre-audience` must equal `publicUrl`, and `x-coffre-key` the DPoP
     key's thumbprint. Both must be among the `SignedHeaders`, with
     `content-type`, `host` and `x-amz-date`.
   - Every header sent is signed, so Coffre forwards nothing the key did not
     sign. `host` may be left out: it is the URL's, which the fetch sends.
     A signed `content-length` must be the body's, 43, which the fetch sends
     too, as the AWS SDKs' and Go's signers may sign it.
   - The credential's scope names the URL's region (`us-east-1` for the
     global host) and `x-amz-date`'s day. `content-type` is the form's, and
     `x-amz-content-sha256`, which an SDK may sign, the body's digest.
3. **The time.** `x-amz-date` must be within 5 minutes. STS refuses past 15.
4. **STS.** Coffre forwards the request with the same transport rules as
   JWKS fetches (`https` only, no redirects, a 5 s deadline, 64 KiB). It
   parses `<GetCallerIdentityResult>`: `Arn`, `Account` and `UserId`, each
   once, with no markup in them. An account's root
   (`arn:aws:iam::<account>:root`) and a federated user
   (`…:federated-user/…`) are refused.
   - A 4xx is STS refusing the proof: 401 `signature`, naming STS's error
     code (`SignatureDoesNotMatch`, `ExpiredToken`).
   - A redirect, a 5xx, an answer it cannot read, or none, is 503
     `issuer_unavailable`, as an unreachable issuer is.

**What the binding names.** A role, by its **unique ID**, the `AROA…` prefix
of `UserId` for an assumed role:

```json
{ "profile": "aws", "issuer": "urn:coffre:aws",
  "claims": { "account": "671742253563", "role_id": "AROAZ3EXAMPLE7QXYZ" } }
```

Deleting a role and making another of the same name gives a new
`AROA…` ID, as a Kubernetes UID does. `coffre trust api --aws
arn:aws:iam::671742253563:role/api-task` looks the ID up once with the
caller's own AWS CLI (`aws iam get-role --query Role.RoleId`) and shows it
before saving. An IAM user (`AIDA…`) is refused: it means a long-lived
access key on disk, which is exactly what column A says a workload does not
hold. EC2 without a role gets an instance profile.

**The key is under the signature.** `x-coffre-key` is signed, so this proof
works with this key only, and column B is **none**. So it is never spent
(4.1): replaying it can only make another session for the same key. A role's credentials
leaked through a log (note 2 of the table) can still sign a fresh proof. That
is the residual risk.

**Checked live** (PR 2, on Erwin's AWS account, `us-east-2`), with a signer
written apart from the SDK's:

- A proof signed with SSO credentials (an `AWSReservedSSO_…` role) and one
  signed by a throwaway Lambda's role both verify at the regional and global
  hosts, and match a binding by account and role ID. STS answers the same
  proof twice: it keeps no memory of requests, which is why the key, not
  spending, is what makes a copy useless.
- STS refuses a proof whose `x-coffre-key` or `x-coffre-audience` changed
  after signing (`SignatureDoesNotMatch`), one sent to another region's host
  ("Credential should be scoped to a valid region"), one 16 minutes old
  ("Signature expired"), and one without its session token
  (`InvalidClientTokenId`).
- A role deleted and made again under the same name keeps its ARN and gets a
  new `AROA…` ID: the Lambda's proof under the new role matches no binding
  of the old.

### 4.4 `enrollment`: platforms that sign nothing

Railway, Render, Heroku and a bare VM give a process no identity that a copy
of it lacks. An enrollment code is the least that works. The design spends
its effort on making a copy **loud**, **contained**, **short-lived** and,
where the platform allows, **narrowed to its addresses**. It does so with
rules over database facts alone, so they cannot drift from what is true.

**The binding:**

```sh
coffre trust api-prod --enrollment --replicas 2 --source 162.220.232.0/24 --minted-by deploy
```

```json
{ "profile": "enrollment", "issuer": "urn:coffre:enrollment", "claims": {},
  "policy": { "replicas": 2, "sources": ["162.220.232.0/24"], "mintedBy": "token:deploy",
              "sessionDays": 30, "overlapMinutes": 15, "approve": false, "onContention": "freeze" } }
```

**Minting a code is issuing a credential.**
`POST /api/members/token:api-prod/bindings/<id>/enrollments` answers
`{ "code": "coffre_enr_…", "id": "<uuid>", "expiresAt": …, "withheld": […] }`.

- **Who may mint.** These callers may mint:
  - the service's managers, as people (personal tokens refused, as for
    every service-account route);
  - the service that `mintedBy` names, on a workload session proven by
    `oidc` or `aws`. CI's own, in practice.
- **Who may not.** `checkPolicy` refuses a `mintedBy` that names the
  binding's own service. The mint and promote routes refuse a session proven
  by `enrollment`, and every `narrow` child. Otherwise, a thief inside the
  app could mint and promote codes of its own, and outlive every deploy.
- **The code's scope is fixed at minting**, as a token's is by
  `issuedScope`: the binding's scope intersected with what the minter holds
  at that moment.
  - Each place's `sensitive` is true only where the minter is an Owner of
    its project as a person, which R32 requires. A CI service minting is
    never one, so its codes read no sensitive value.
  - The scope is stored in the `enrollments` row under its MAC, every
    session the code makes carries it, and a binding's `reads` apply only
    within it.
  - So a Viewer who manages `api-prod` and mints a code gets sessions that
    hold at most a Viewer's rights, and never a sensitive value. `withheld`
    names the places whose sensitive values the code will not read, as
    token issuance does.
  - The cost is least privilege for CI: a CI minter must itself hold what
    its apps use (D12).

CI mints one code per deploy and sets it as the platform's variable for that
deploy:

```sh
railway variables --set "COFFRE_ENROLL=$(coffre enroll api-prod)" --service api --environment production
```

`expires_at` is `sessionDays` from minting, at most 90. At that point the
code's sessions end and a deploy must enroll again. The binding's page warns
3 days before.

**What a code allows, and what stops a copy:**

1. **Liveness is expiry.** An enrollment session lasts 90 seconds past its
   last renewal, and the SDK renews every 30 seconds.
   - Renewal runs on the database's statement clock (`statement_timestamp()`
     on Postgres, not `now()`, which is the transaction's start), in two
     steps, because the app computes the row's MAC. It reads the clock,
     computes the new `expires_at` and its MAC, then runs
     `UPDATE … SET expires_at = $new, auth_mac = $mac WHERE id = $1 AND expires_at = $old AND $old > statement_timestamp() + interval '5 seconds' AND revoked_at IS NULL`.
     A renewal that loses a race, or arrives within 5 seconds of expiry,
     updates nothing, so it never revives a session that the count, on the
     same clock, already saw as dead.
   - A crashed process stops renewing and is dead within 90 seconds. A
     graceful stop logs out at once.
   - Only *roots* count, sessions made by the exchange. A `narrow` child is
     never a slot (`ancestors IS NULL` in the count and its index).
2. **Admission allows a deploy's overlap.** A code admits up to
   `2 × replicas` live roots. Past that, the exchange answers `full` with
   `Retry-After: 30`. The count is a database fact, read inside the
   exchange's commit under the log head, so racing exchanges never exceed
   it. A zero-downtime redeploy that reuses the code (Railway's Redeploy
   button, a variable change, an auto-deploy on push) starts its new
   instances beside the old ones and is admitted. Nothing live is ever
   fenced.
3. **A tripwire, not a guarantee: contention.** Coffre cannot tell the
   deployment's own instances from a thief's, because nothing the platform
   gives either of them differs. So nothing in this design's guarantees
   rests on detecting a copy. What a copy is held to is listed under "What
   it cannot prevent" below: the capacity, the alerts, `sources` and the
   code's lifetime. The tripwire catches the clumsy thief cheaply, and is
   stated with its evasions.
   - **The rule.** Over the last hour, and only since the binding's newest
     `workload.unfreeze`, take the code's roots, live or ended, each counting
     from `created_at` to the earliest of `expires_at`, `revoked_at` and
     now. The code is *contended* when either holds:
     - the excess, the number of live roots beyond `replicas` summed over
       time, `∫ (live − replicas)⁺ dt`, passes `overlapMinutes × replicas`
       session-minutes (30 with the defaults);
     - more than `4 × replicas` roots were created.

     Counting from the last lift means a lift is not undone by the same
     hour's history. Counting the excess, not only whether there is one,
     means three extra sessions weigh three times one.
   - **How it runs.** It reads one bounded set of rows, through an index on
     the code's roots by `created_at` that keeps ended ones. It runs after
     each exchange and each renewal, outside their transactions, from the
     database alone: no gate, and no state that a restart could lose.
     Contention freezes the binding (`workload.freeze`,
     `reason: 'contention'`) and alerts. `onContention: 'alert'` only
     alerts.

   | What happens, `replicas: 2` | Contention? |
   |---|---|
   | A replica crashes and restarts | no: its session ends within 90 s |
   | Two same-code redeploys in an hour, each overlapping two extra sessions for 4 minutes | no: 16 session-minutes, 4 roots made |
   | A thief enrolls while both replicas are up, and stays | yes, after 30 minutes with one session, 15 with two |
   | A thief re-enrolls every few minutes to reset its age | yes: the time over still adds up, and the roots it makes count too |
   | The service is scaled to 3 with `replicas: 2` | yes, after 30 minutes. The alert says to raise `replicas`, which takes a new binding (policies are immutable), a new code and a deploy |
   | **A thief takes a slot the deployment leaves free**: fewer instances than `replicas`, or one down for long | **no**. This is the evasion, stated on the binding's page: set `replicas` to exactly what runs. |
   | **A thief who stays under both thresholds**, for instance live 14 minutes an hour beside full replicas | **no**. The `enrolled` alert of each of its sessions is the signal. |

   - **Many redeploys an hour on the same code** would trip it. The docs'
     recipe mints a code per deploy and promotes it (item 4), and a
     deployment that redeploys more often raises `overlapMinutes`.
4. **Supersession, on `promote` only.**
   `POST …/enrollments/<id>/promote` (`coffre enroll --promote`) makes a
   code the binding's current one. CI calls it after a deploy that
   succeeded. No count triggers it, because a thief with a fresh copy could
   reach any count.
   - **It is recorded, not recomputed.** One `enrollment.supersede` entry
     per older code, naming it, is appended in the same transaction. The
     exchange and renewal refuse a code that such an entry names, through an
     index, as a tombstone works.
   - **The old deployment drains.** Its sessions cannot renew, so they end
     within 90 seconds while it finishes its requests. `promote --now`
     revokes them at once (`token.revoke`, `reason: 'superseded'`); that is
     the recovery step below.
   - **A deploy that fails** is never promoted, so the running deployment
     keeps its code.
   - **A rollback** restores a superseded code, so a rollback job mints and
     promotes a new one. The docs' Railway recipe does.
   - **A code that is never promoted** lives until its `expires_at`. The
     binding's page lists live codes, so one forgotten in a failed deploy is
     visible.
5. **`sources` narrows.** These are CIDRs, checked at the exchange and on
   every request against the client's address.
   - **On Workers**, the address is the one Cloudflare vouches for
     (`CF-Connecting-IP`).
   - **On Node**, it is the deployment's `clientAddress(request)`, which must
     be configured for any binding with `sources`. Without it, Node sees only
     the socket's peer, which behind a load balancer is the balancer. A
     request with no address is refused with `source`.
   - **On Railway**, static outbound IPs are per service and region, and
     Railway does not promise they are dedicated: they "may be shared with
     other customers". There, `sources` shrinks who could use a copy to code
     running on Railway, in that region. **It is not an attestation.** It is
     one where the addresses are dedicated: a cloud NAT gateway, a VM's own
     static IP.
6. **Alerts on every enrollment.** Each new root is a `workload.alert`
   `{ kind: 'enrolled', ip, code: <the code's ID and hint, never the code> }`,
   delivered at once (8.3). A restart at 3 a.m. produces one quiet line. An
   enrollment from an unknown address is the one to look at.
7. **`approve: true`**, for workloads that rarely restart.
   - Each session starts `pending`: the exchange answers 202
     `{ "pending": "<session id>", "approve": "<page URL>" }`.
   - The SDK retries the exchange with the same key every 5 seconds for up
     to 10 minutes. Each retry with the same key and code returns the same
     pending session.
   - Pending sessions take no slot, and a code holds at most `replicas` of
     them. A manager approves on the page or with `coffre approve <id>`,
     which is audited and counts the slot then.

**Recovering from a copy.** The binding's page offers these steps as one
action, in order:

1. Mint a new code, or have CI mint one.
2. Promote it with `--now`. That supersedes the stolen code and revokes its
   sessions, the thief's included.
3. Deploy with the new code.
4. Lift the freeze.

Lifting first would let the thief's session back in, so the page lifts only
after the promote.

**What it cannot prevent, stated on the binding's page and in the docs:**

- **The code is a standing credential until it is superseded or expires.**
  A copy enrolls, and raises `enrolled` at once, naming its address. It
  shares the code's `2 × replicas` slots with the deployment, one key per
  session, and holds all of them while the deployment is down. The
  tripwire freezes it if it overlaps full replicas for long, or churns. A
  thief who uses slots the deployment leaves free, or stays under the
  tripwire, keeps using the code's credentials through Coffre until a
  person acts on the alert, or the next deploy promotes a new code. It never
  reads a value unless the binding lists it in `reads`.
- **A thief who keeps reading the platform's store** reads every new code
  too. "The next promote ends it" holds for a one-time copy. A standing
  breach of the store is answered by moving off it: a platform with an
  identity, or a code entered by hand.
- **A copy is an availability lever.** It can fill the slots, or trip the
  tripwire on purpose to freeze the binding. That is a denial of service,
  never a read, and the recovery steps above end it.

**Open, settled in PR 3's review.** The tripwire's numbers (the excess
integral, the thresholds, counting from the last lift) came from the fourth
review round and have not been reviewed again. PR 3's review settles them
against its tests and the model (D14).
- **An attacker running *inside* the service** has the D and F columns of
  every platform.
- **A compromised CI can mint codes for itself** (column E). The mint is
  logged as CI's own act, naming the run, and is bounded by CI's own rights.

## 5. Sessions: DPoP, the gate, renewal

### 5.1 The key and the proof

The SDK makes `crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])`
once per process. It exports only the public JWK. The key is never written,
logged, put in env or sent anywhere. **Thumbprint:** `jkt` is the
base64url SHA-256 of `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`, the
RFC 7638 form, 43 characters.

**Every request** carries the session token and a fresh proof:

```http
POST /use/stripe/v1/charges?expand[]=balance_transaction HTTP/1.1
Host: secrets.acme.example
Authorization: DPoP coffre_wl_7mQ4…
DPoP: <base64url(header)>.<base64url(payload)>.<base64url(r || s)>
Content-Type: application/x-www-form-urlencoded
Idempotency-Key: 5f1c…
Stripe-Account: acct_1Nv…

amount=2000&currency=eur&source=tok_visa
```

```json
{ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
{ "jti": "pA6p8w2Yb3fQe1kHn0S9qg", "htm": "POST", "htu": "https://secrets.acme.example/use/stripe/v1/charges",
  "iat": 1792805400, "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", "nonce": "g1.7Hq2…",
  "hdr": "content-type idempotency-key stripe-account",
  "req": "kq9Vg0ZyqH4tD4H7tq3cXb6vR3a1v0Q5yR2mJ8wK1sE" }
```

**The proof signs the whole request, and Coffre forwards exactly what it
signs.** RFC 9449's claims (`htm`, `htu`, `ath`, `nonce`) cover the method,
the URL without its query, and the token. Two claims of Coffre's own cover
the rest:

- **`hdr`** names, lowercased and space-separated, the request headers to
  forward upstream. The SDK lists every header the app set, except the
  ones in `UNSIGNED_HEADERS`, one constant in `client/src/dpop.ts` that the
  verifier refuses too: those the transport owns and an intermediary may
  rewrite (`accept-encoding`, `content-length`, `transfer-encoding`, `te`,
  `connection`, `keep-alive`, `upgrade`, `proxy-*`, `host`), and
  `authorization`, `dpop` and `cookie`. Coffre sets the transport's own on
  the way out. A header sent more than once is one line, its values joined by
  `, ` in the order received, as the Fetch API's `Headers` gives them.
- **`req`** is base64url(SHA-256) of a canonical request:

  ```
  <the path as sent, as the WHATWG parser writes it: every slash and escape kept>\n
  <the raw query string as sent, without "?", or empty>\n
  <name>:<value>\n   for each header in hdr, in order, its value as received
  <the body's SHA-256, hex | the declared payload hash, for a streamed SigV4 upload only, | UNSIGNED-PAYLOAD>
  ```

  `htu` signs the path as a zone normalizes it; the first line signs it as
  it goes upstream, so `/use/s3/a/b` and `/use/s3/a//b`, two objects to S3,
  are two requests under one `htu` (PR 0's review r2). A path a zone
  changed on the way fails closed.

  The declared form applies only to a credential injected by `sigv4`, and
  only when its `x-amz-content-sha256` is 64 hex characters, which S3
  checks against the bytes. Any other value (`UNSIGNED-PAYLOAD`,
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, every `STREAMING-*`) is unsigned.
  Every other credential's body is hashed whole.

Coffre recomputes `req` from what it received, and forwards upstream only
the headers `hdr` names, plus the credential's injection. A header added on
the way, by an HTTP library or a proxy, is dropped rather than refused, so
`user-agent` and `via` do no harm.

- **Bodies.** A buffered body (up to the proxy's 16 MiB) is hashed whole. A
  streamed SigV4 upload is bound by the payload hash it declares, which S3
  itself checks against the bytes. An unsigned streamed upload cannot be
  bound, and a workload may send one only
  through a credential that says `unsignedUploads: true`, whose page notes
  that column B is **use** for it.
- **Cost.** Hashing a body costs CPU in proportion to its size, about 2 ms
  per MiB on Workers. API calls are kilobytes. Large objects go through
  streamed SigV4 or delivered minting (7.2).

**The verifier** (`verifyProof` in core) checks, cheapest first:

1. **Shape.** The proof is at most 2 KiB. `typ` is exactly `dpop+jwt` and
   `alg` exactly `ES256`.
2. **The key.** `jwk` has exactly `kty`, `crv`, `x` and `y`, a point on the
   curve, and no `d`.
3. **The claims.** `jti` is 22 base64url characters (16 bytes). `iat` is an
   integer. `hdr` holds at most 32 names, none of them in
   `UNSIGNED_HEADERS`.
4. **The session.** The session row comes from the token's hash, as for any
   credential (one indexed read, shared with 5.3).
5. **Key and signature.** `thumbprint(jwk) === row.jkt`, then the signature
   over the JWS signing input.
6. **What was signed.**
   - `htm` equals the method.
   - `htu` equals the request's URL as `publicUrl` spells it: scheme and host
     lowercased, no default port, no query or fragment. Its path is
     normalized as Cloudflare's zones normalize incoming paths by default:
     unreserved characters decoded, every other escape's hex uppercased (RFC
     3986 section 6.2.2), `\` made `/`, and runs of `/` merged. Both sides
     sign that form, through `canonicalHtu` in `client/src/dpop.ts`. PR 1d
     checks it on a deployed zone. A mismatch fails closed.
   - `ath` equals base64url(SHA-256(token)).
   - `req` equals the recomputed digest. A buffered body is checked before
     anything is sent; a streamed one is bound by its declared hash, as
     above.
   - `iat` is within ±300 s. The nonce, not the clock, is what makes a proof
     fresh.
7. **The gate** checks the nonce and the `jti` (5.2).

Two ES256 signatures of one payload, `(r, s)` and `(r, n−s)`, both verify.
They carry one `jti`, so the gate refuses the second, and a property test
holds this (section 12, PR 0).

**Refusals** are `401` with
`WWW-Authenticate: DPoP error="invalid_dpop_proof"` and a JSON `reason`, or
`error="use_dpop_nonce"` with a fresh `DPoP-Nonce` header, as RFC 9449
section 9 has it.

- **`use_dpop_nonce`** is retried once with the new nonce. The SDK cannot
  resend a body it streamed, so it keeps its nonce fresh instead: every
  answer carries the gate's current nonce, and the SDK uses the newest.
  Only a gate restart in the middle of a streamed upload fails it, once, and
  the caller retries as for any network error.
- **Every other refusal is final.**

**Why DPoP and not a scheme of our own.** It is a standard with libraries
in every language, so a sidecar in Go or a client in Python can speak it.
`hdr` and `req` are two extra claims that a DPoP library passes through
untouched. HTTP Message Signatures (RFC 9421) would cover the same ground
with a larger surface, and no DPoP library implements it.

### 5.2 The gate: replay, nonces, live counters

Proofs must be single-use for column B to say **none**. That takes a shared
memory of every `jti` seen, and any shared store costs something on every
request. Section 13, D2, compares the options. The choice: **one gate per
workload**, an object that sees every request of that service account and
holds what must be both shared and fast.

- **On Workers**, a Durable Object, `CoffreGates`, named
  `gate:<principal>`. The deployment binds it as `GATES`, as it binds
  `SOCKETS`, and `coffre init` writes it. Its location hint is the
  database's region: every request already crosses there for its credential
  read, so the hop costs one round trip inside that region.
- **On Node**, an object in the app's process. A Node deployment runs one
  app process, as `examples/node` does. Several processes, Coffre itself as
  more than one replica on Kubernetes included, would each hold a gate of
  their own, with different nonces, and clients would bounce between them.
  The gate's nonce makes that fail loudly rather than unsafely (below). The
  docs say so wherever Coffre on Kubernetes is mentioned.

**Nonces are epochs.** A gate draws a random `epoch` when it starts and
rotates it every 2 minutes. Its nonce is `g<n>.<epoch>`, 16 random bytes in
base64url after the rotation's count `n`. It need not be secret: it only
names an epoch, and a proof must still be signed by the session's key. The
gate accepts proofs carrying the current or the previous nonce, and
remembers the `jti`s seen under each. Everything else answers
`use_dpop_nonce` with the current nonce.

- **A restart or an eviction forgets nothing that matters.** A new epoch
  means every proof made before it carries an unknown nonce and is refused,
  so no proof seen before the restart can pass again. No `jti` is persisted,
  no clock is trusted, and a client pays one retry.
- **Memory is bounded by the rate.** The `jti`s are kept in two `Set`s of
  their 22-character strings, one per epoch. A workload at the gate's
  ceiling of 1,000 requests a second (a Durable Object's documented soft
  limit) holds at most 240,000 of them, about 20 MB, within an object's
  128 MB. Past the ceiling the gate answers 429 `overloaded`. A deployment
  that needs more shards a workload's gates by session (D2).

**The gate's interface** is replay and generic counters. Limits (8.1) use
the counters, so PR 1b owns the gate whole. Enrollment needs no gate at all
(4.4):

```ts
interface Gate {
  /** The current nonce, for answers that admit no proof: the exchange's DPoP-Nonce. */
  nonce(): Promise<string>;
  /** Replay and nonce when there is a proof; then, in the same call, every count the request asks for. A Cloudflare call has counts only. */
  admit(request: {
    replay?: { session: string; jti: string; nonce: string };
    counts?: { key: string; windowMs: number; most: number }[];
  }): Promise<
    | { ok: true; nonce: string }
    | { ok: false; reason: 'use_dpop_nonce'; nonce: string }
    | { ok: false; reason: 'replayed' | 'overloaded' }
    | { ok: false; reason: 'limit'; key: string; retryAfterMs: number; first: boolean }  // first: the first refusal in this window, which alerts
  >;
}
```

A count with a window of a day lives in the object's storage, flushed by an
alarm every 10 seconds, so an eviction loses at most 10 seconds of counts. A
Durable Object has no eviction hook. Any shorter window lives in memory.

**The gate is not the source of truth for any decision a person made.**
Freezes, revocations and grants are in the database and the log, read on each
request (5.3). If the gate is lost, it costs a nonce retry and resets
counters. It never lets anything through.

### 5.3 Every request, checked live

A workload request's authentication is never answered from a cache. Per
request:

1. **The row.** The token's row: `kind = 'workload'`, not revoked or
   expired, `not_after` not past, its MAC, and `approved_at` set where its
   binding says `approve`. Its `generation` equals its member's in
   `vault_members`: read without the vault's MAC, which is safe in this
   direction, because removal only ever moves the generation on. Its binding
   stands: MAC, no revocation, no tombstone, as for an exchanged credential
   today. Its ancestors stand (8.4). Its client address is within `sources`.
   A superseded code's sessions are refused at renewal, so they drain within
   90 seconds (4.4).
2. **The proof** (5.1) and **the gate** (5.2).
3. **No freeze** names the instance, the service, the binding, the session
   or the credential being used (8.2).

Steps 1 and 3 are **one SQL statement** on the app's connection: the row,
its member's generation, its binding, its ancestors and the freezes, joined
through their indexes. It has these clauses from PR 1a on, `approved_at`
included, so no later PR edits it.

**Which credential.** The `credential:` freeze needs the environment and
credential being used before the statement runs. So the proxy authenticates
with `PluginContext.workload(request, { place, credential })` once it has
resolved them from the URL or, for `sign`, `verify`, `presign` and `mint`,
from the body. A plan names no credential and checks the others.

**What is cached, and for how long.** The vault's decision, meaning grants
and the opened values, is cached per session for `cacheSeconds` (60), as
the proxy caches a handle's today. So:

- **Revocation, freeze, expiry, an ancestor's end and the member's
  removal** take effect on the next request. Supersession takes effect
  within 90 seconds, the old deployment's drain.
- **A lost grant** takes effect within `cacheSeconds`, as for handles.
- **A warm request** therefore costs one SQL statement, one gate call and
  one ES256 verify, with no vault call. A cold one adds `vault.access` and
  the opening, through the vault's own connection: two Postgres
  connections, as a handle's cold request has today.
- **An open Postgres tunnel** ends at its next recheck, within
  `recheckSeconds`. For a workload the recheck runs this statement too, so
  it sees freezes.
- **Handles stay as they are.** Their warm path asks no database, so a
  `credential:` freeze reaches a person's handle within `cacheSeconds`,
  not at once. Workloads see it at once.

### 5.4 Lifetime and renewal

- **`expiresAt`: one hour; 90 seconds for an enrollment session.** Renewal
  proves possession of the key: `POST /api/auth/workload/renew` with the
  session's own `Authorization` and a proof. It answers `{ "expiresAt": … }`,
  never past `notAfter`, and updates the row's `expires_at` under its MAC.
  Renewal has no entry of its own: the session's last use shows it, through
  the same throttled `last_used_at` and `last_used_ip` write that
  credentials have today (at most every 5 minutes), kept outside 5.3's one
  statement.
  - The SDK renews at half-life, or every 30 seconds for an enrollment
    session, whose expiry is its liveness (4.4).
  - A process that died stops renewing, and its session ends, so "live
    sessions" means live processes.
- **`notAfter`: the hard end.**
  - A proof that names the key (an `aws` proof, or an ID token whose
    audience names it): the binding's `sessionHours`, 24 unless set, at
    most 168.
  - Any other ID token: the earlier of `sessionHours` and the token's own
    `exp`. A copy of a bearer proof then buys no more than the platform's
    own lifetime for it, and the workload re-proves with the next token it
    is given.
  - `enrollment`: the code's `expires_at`.
  - Before `notAfter`, the SDK **re-proves**. It exchanges a fresh platform
    proof (a new metadata token, a new signed `GetCallerIdentity`, or on
    Kubernetes the projected token the kubelet writes at 80% of the old
    one's life, read when the file changes) with the *same* key, and swaps
    sessions. Requests in
    flight finish on the old one. A deleted Kubernetes service account or IAM
    role therefore stops working within `sessionHours` even without any
    action in Coffre.
- **Why the token is long-lived when Erwin finds 5 minutes too long.** A
  bearer credential's lifetime is its exposure, so it must be short. A
  key-bound token's exposure is the key's, and a copied token is worthless at
  any age. What bounds a stolen *capability* here is the proof: accepted
  once, for one exact request, within one nonce epoch. Lifetime only bounds
  forgotten sessions.
- **Ending one.** `POST /api/auth/logout` with DPoP revokes the session. The
  SDK calls it on `SIGTERM`.

### 5.5 What the proof does not stop

Take an attacker who can block traffic between the app and Coffre, not only
read it: an active man in the middle of TLS. They can hold the app's request
and deliver it later, within the nonce's two epochs, at most 4 minutes. They
cannot change anything Coffre forwards, because the proof signs it. A
passive copy that wins the race to Coffre is the app's own request,
delivered once; the original is then refused as `replayed`. Either way, the
operation that happens is the one the app asked for, at most once. What the
winner of that race does get is the *answer*: a presigned URL, a signature,
an upstream's response body. An attacker who reads the traffic reads those
anyway.

## 6. Use-only, and the escape hatch

### 6.1 The rule

**A workload session reads no value, except a plain one or one its binding
lists in `reads`.** Everything else it uses through Coffre. Here is the
precedence, for a session whose binding gives `viewer` on `market/prod`:

| The key in `market/prod` | Without `reads` | With `STRIPE_WEBHOOK_SECRET` listed in `reads` for `market/prod` |
|---|---|---|
| `TWILIO_SID`, plain | read | read |
| `STRIPE_SECRET_KEY`, secret | use | use |
| `STRIPE_WEBHOOK_SECRET`, secret | use | **read**, flagged "exposed if Railway is breached" |
| `DATABASE_URL`, sensitive | use (the tunnel) | read only if listed *and* an Owner of `market` made the binding (R32, unchanged) |

- **Where it is enforced.** Both the app and the vault enforce it, as R16's
  sensitivity is.
  - **The API a session reaches** is `WORKLOAD_ROUTES`, typed over the
    route table as `PERSONAL_TOKEN_ROUTES` is, so a new route must say:
    - every route a service token reaches today (writes such as `coffre set`
      from CI, folders, archive, deploy-on-push, audit where granted);
    - `POST …/bindings/:id/enrollments` and `…/promote`, for the service a
      binding's `mintedBy` names;
    - renew, narrow and logout.

    Routes that answer values (`POST /reveals`, a version's value, the plan)
    answer only plain and listed keys. Every other key is refused, or left
    out and named, as a person's sensitive keys are. Any other route
    answers 403 `workload`.
    - **A child of `narrow`** reaches only `/use`, narrow (to depth 4) and
      logout. Renew is refused to it.
    - **No laundering.** A workload session may not make a reference, fork
      or copy whose source is a key it may not read (6.1's list): it could
      otherwise move a use-only value to a place whose keys it reads.
  - **The proxy's plan** gives the app only the plain keys and the listed
    ones.
  - **The vault** is told the caller's kind, and a workload's lists.
    - `Through` gains a required `caller: 'person' | 'bearer' | 'workload'`.
      A `workload` caller must come with a credential scope, or the vault
      refuses it outright.
    - The app always materializes a workload's scope into per-place grants,
      the binding's scope when the row holds none (`scopeWithReads`). Each
      environment's grant may carry `reads: readonly string[] | '*'` beside
      R32's `sensitive`; a project's grant carries none, since on it a list
      would read the whole project.
    - The vault refuses every purpose but the proxy's `use`, a copy kept
      sensitive included, unless the key is listed at the place where the
      value is held: a reference's source, a fork's parent for an inherited
      key. The code is `use_only`.
    - So `market/dev/S`, a reference to `market/prod/STRIPE_SECRET_KEY`, is
      not readable through a `"*"` listed for `market/dev`.
    - A `copy` for a workload caller is refused unless the source is
      readable, the rule above in the vault.
  - The vault trusts the app's scope as it trusts it today. Column G2 is
    unchanged.
- **The escape hatch is per binding, per place, per key, by ID.**
  - **Stored by ID.** `reads` is stored in the binding's policy by
    environment ID and key ID, and shown by name:
    `{ "reads": { "<environment uuid>": { "keys": ["<secret uuid>", …] } } }`.
    A rename therefore moves nothing. Renaming `STRIPE_SECRET_KEY` onto the
    listed name `STRIPE_WEBHOOK_SECRET` leaves the listed ID with the key
    that was listed. A key deleted and made again is a new ID, and not
    listed.
  - **`"*"`** means every key of the environment, the per-environment
    hatch, and the page shows it in red.
  - **Listing a key** needs the key to exist, so a binding made before the
    key lists it once it exists, by a new binding (bindings are immutable).
  - A sensitive key listed still needs the credential's scope to say
    `sensitive` for its project (R32): an Owner-issued binding for an OIDC or
    AWS session, and an Owner-minted code for an enrollment one (4.4).
  - So no path through `reads`, `narrow` (children never read) or delivered
    minting (a listed read, under the same rule) hands a sensitive value to
    a session that a non-Owner made.
- **Why on the binding.** Reading puts a value where the platform can lose it,
  so the exposure is a property of *that platform*. The same service may run
  on Cloudflare, reading nothing, and in a Railway worker that must hold
  `STRIPE_WEBHOOK_SECRET`. Each binding states its own exposure, and the page
  lists "values exposed on Railway: STRIPE_WEBHOOK_SECRET" beside it.
- **What usually removes the need to read.** A webhook secret becomes
  `credential('stripe-webhook').verify(payload, signature)` (section 7.2). A
  signing key becomes `sign()`. An encryption key becomes envelope
  encryption: `credential('root').unwrap(dek)` once per data key. A database
  URL becomes the tunnel or a minted login. The read list is for SDKs that
  take nothing but the raw key.

### 6.2 What a workload gets back from the plan

`GET /use/<project>/<env>` with DPoP answers as for a handle, with no
placeholders (the SDK sends DPoP, not a value in a slot):

```json
{ "environment": "market/prod",
  "values": { "TWILIO_SID": "AC012…", "STRIPE_WEBHOOK_SECRET": "whsec_…" },
  "credentials": ["stripe", "openai", "dfns-key"], "tunnels": ["db"], "mints": ["aws"] }
```

`coffre serve` reads it to know which local listeners to open (section 9).
`workload.read(key)` reads one value through it.

### 6.3 The strict instance, and the path from today

```ts
auth: signin({ workloads: { limits, useOnly: true } })
```

**`useOnly: true`** leaves services nothing but key-bound sessions, which
read only plain values and their binding's listed, flagged `reads`:

- **No bearer service credential.**
  - `POST /members/:member/tokens` refuses to issue a service token.
  - Existing `coffre_svc_` tokens are refused at use, with reason
    `use_only`.
  - `POST /api/auth/oidc` answers 410 and names `/api/auth/workload`.
- **CI keeps the API.** CI jobs reach it through their workload session
  (`WORKLOAD_ROUTES`, 6.1). They still write secrets and run deploy-on-push,
  and they still hold, for instance, an `NPM_TOKEN` their binding lists.
- **What stops working.** Whatever authenticates with a service token. That
  is the Vault KV plugin (`docs/vault.md`, External Secrets Operator), which
  syncs values into Kubernetes Secrets, the opposite of this design. The
  docs and the startup log name it.
- **People are unchanged.** Their sensitivity rules are R16's.

**`noReads: true`**, beside it, is the strictest instance. No binding may
list `reads`: creating one is refused, and one that exists is refused at
use. Services then read plain values only. It is for deployments whose every
app and job can live by use.

Without `useOnly`, nothing that exists today changes. Bearer service tokens
and `/api/auth/oidc` keep reading as R13 and R32 say. `coffre init` writes
`useOnly: true` for new deployments: that is the pit of success. It does not
write `noReads`. An existing
deployment turns it on when its last reading credential is gone.

**Equisafe's path, from what it does today.** Its CI service accounts export
values with bearer OIDC exchanges (R13, R16, R32), and some deploys push
values into platform stores.

1. **The CLI turns key-bound wherever it can.**
   `coffre run --service deploy -- ./x` exchanges at `/api/auth/workload`
   when the instance answers it, and keeps the session in memory. Its child
   gets what a person's child gets: the plan's values, and
   `COFFRE_CREDENTIALS` pointing at the CLI's local listener (section 9). Keys
   the child must read are the binding's `reads`. The CLI prints the difference
   at once: `coffre: market/prod: STRIPE_SECRET_KEY is used through coffre now;
   list it in the binding's reads if this job must hold it`.
2. **List what each job truly reads.** Every `secret.read` entry since the
   last deploy, by binding, is on the binding's page ("read by runs in the
   last 30 days"). The Owner moves those keys to `reads`, or moves the job to
   use.
3. **Stop pushing values into platform stores.** Each app moves to its
   platform's proof (section 9), and the platform holds an enrollment code or
   nothing.
4. **Turn on `useOnly`** once no bearer service token is live and nothing
   uses the Vault KV plugin. Then `noReads`, once the binding pages show no
   `reads`. Decision D8 records what to remove one release later (expand,
   then contract).

## 7. Use: what Coffre does for the workload

### 7.1 What exists, now for workloads too

The proxy (`/use/<credential>/<path>`), `sign`, `presign` and the Postgres
tunnel all work for a workload session as for a handle, with these
differences:

- **How the caller authenticates.** The workload is the
  `Authorization: DPoP` header and its proof, never a value in the
  credential's slot, so there are no placeholders. The proxy forwards only
  the headers the proof's `hdr` names (5.1), then fills the rule's slot as
  today. The check that refuses the handle anywhere else in the request now
  refuses the workload token anywhere else.
- **A child's constraints** (8.4) apply to every operation, by
  `constraintsAllow` in core:
  - **`credentials`** names the credentials, signers, verifiers, tunnels
    and minters it may reach. Anything not named is refused.
  - **`methods` and `paths`** are checked against the resolved upstream
    target, the URL the proxy is about to send, never the path as received.
    For `presign`, they are checked against the presigned request's method
    and path.
  - **A child with `paths` or `methods` set** is refused `sign`, `verify`,
    `mint` and the tunnel. Those have no path to check, and a constraint
    that cannot be checked refuses.
- **The plugin capability.** `PluginContext.use(caller, …)` takes either a
  handle or a `WorkloadCaller`, the result of
  `PluginContext.workload(request)`, which runs section 5.3. One function
  authenticates, so the proxy never parses DPoP itself.
- **The tunnel's WebSocket** carries `Authorization: DPoP` and a proof whose
  `htm` is `GET` and whose `htu` is the `https` form of its URL. Its
  Durable Object is named by the session's ID rather than the bearer token.
  Rechecks run 5.3 without the proof, because the socket is already
  authenticated.

### 7.2 New uses

**`verify`**, for inbound webhooks: `POST /use/<project>/<env>` with
`{ "verify": { "credential": "stripe-webhook", "message": "<base64url>", "signature": "<as received>" } }`
answers `{ "valid": true | false }`. It is configured beside `signers`:

```ts
verifiers: { 'stripe-webhook': hmac('STRIPE_WEBHOOK_SECRET', { hash: 'SHA-256', encoding: 'hex' }) }
```

The comparison runs in constant time. Stripe's own scheme, `t=…,v1=…` with
its tolerance, is `stripeSignature('STRIPE_WEBHOOK_SECRET')`, because that is
the webhook most apps verify. With `verify`, a webhook secret no longer has to
be read.

**Minting.** A credential that issues short-lived children keeps its parent
key in the vault, as R7 allows. Coffre mints the children itself:

```ts
credentialProxy({
  minters: {
    aws: assumeRole({ roleArn: '{AWS_ROLE_ARN}', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', seconds: 900 }),
    github: githubInstallation({ appId: '{GH_APP_ID}', privateKey: '{GH_APP_PRIVATE_KEY}', installationId: '{GH_INSTALLATION_ID}', permissions: { contents: 'read' } }),
    r2: r2Temporary({ accountId: '{CF_ACCOUNT_ID}', parentAccessKeyId: '{R2_PARENT_KEY_ID}', apiToken: '{CF_R2_TOKEN}', bucket: 'uploads', permission: 'object-read-write', seconds: 900 }),
  },
  credentials: {
    s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ minted: 'aws', region: 'eu-west-3', service: 's3' }) },
    gh: { upstream: 'https://api.github.com', inject: header('authorization', 'Bearer {mint:github}') },
  },
})
```

- **Used inside Coffre.** `{mint:github}` in a rule, or `sigv4({ minted })`,
  draws a child from the minter. Each isolate caches it until 60 s before it
  expires, as a settled value only. The app never sees it. This is the
  default.
- **Delivered**, the second tier, for traffic that should not pass through
  Coffre: S3 objects of gigabytes, a database's own wire protocol.
  `POST /use/<project>/<env>` with `{ "mint": { "credential": "aws" } }`
  answers the child (`{ accessKeyId, secretAccessKey, sessionToken, expiresAt }`
  for AWS, `{ token, expiresAt }` for GitHub). Only a binding whose `reads`
  lists the minter (`"mints": ["aws"]`) gets it, and the page flags it as a
  value with a lifetime, "exposed for 15 minutes at a time".
  - **It counts as reading the minter's keys.** A minter whose parent keys
    include a sensitive one delivers only where the session's scope says
    `sensitive` for that project (R32, 6.1).
- **What a child can do** is the minter's to narrow: a session policy on
  `AssumeRole`, an installation token's `permissions` and `repositories`, an
  R2 credential's bucket and prefix. Every mint is one `credential.mint`
  entry naming the minter, the child's lifetime and the session.
- **Databases.** A minted Postgres login is the W108 item: `CREATE ROLE …
  VALID UNTIL` with a role to inherit, then `pg_terminate_backend` and
  `DROP ROLE` when its session ends. It needs a sweeper, so it is a later PR
  (section 14).

### 7.3 Upstreams that accept only Coffre

Use-only protects a value only if the upstream refuses that value from
anyone but Coffre. Here is the playbook by kind of credential, which
`docs/workloads.md` will carry:

| The upstream's credential | Make it accept only Coffre by | Examples |
|---|---|---|
| Issues short-lived children from a parent | **Mint** (7.2). The parent stays in the vault and never leaves Coffre. The upstream sees only children. | AWS (`AssumeRole`), GitHub App installations, R2 temporary credentials, GCP service-account impersonation, Azure client credentials |
| A static key whose issuer can pin a source address | **Pin Coffre's egress.** On Workers, through a credential's `egress` (a VPC Service to a fixed-address host, or Cloudflare's dedicated egress where the account has it). Never Cloudflare's shared addresses, which would admit every Worker. | Stripe restricted keys (IP allowlist), AWS IAM users (`aws:SourceIp`), Cloudflare API tokens (client IP filtering), most banking APIs (Schuman) |
| A static key that cannot be pinned | **Vault-only.** Mark it sensitive, give no binding `reads` for it, and rotate it on a schedule through the provider's API, where R7 lets Coffre hold write access. A copy from an *earlier* exposure works until that rotation. | OpenAI project keys, most SaaS API keys |
| A database password | **The network.** `pg_hba.conf` or a firewall admits the role only from Coffre's address (credential-proxy.md, section 6). Later, minted logins. | Postgres |
| A key the workload must hold | **Read, listed, flagged.** This is the escape hatch. Prefer a key whose upstream can pin source addresses. | an SDK with no base URL |

## 8. Live policy

### 8.1 Limits per credential

```ts
credentials: { stripe: { upstream: 'https://api.stripe.com', inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}'),
                         limit: { perMinute: 120, perDay: 20_000 } } }
```

- **What is counted.** The gate counts each (workload, credential) pair:
  requests per minute in memory, and per day in the object's storage on
  Workers. On Node the daily count is in memory, and a restart resets it,
  which the docs say.
- **Past a limit:** `429 { reason: 'limit' }` with `Retry-After`, nothing is
  forwarded, and one `workload.alert { kind: 'limit' }` is written per
  workload, credential and window.
- **For a limit per workload,** the deployment passes a function:
  `limit: (service) => service === 'token:batch' ? { perDay: 200_000 } : { perDay: 20_000 }`.
- **People's handles** are not gated in this build.

### 8.2 Freeze

A freeze stops every use under a target **at the next request**, and keeps
the sessions, codes and bindings, so lifting it restores service without a
redeploy. That matters for enrollment, where revoking would need CI to mint a
new code. Targets:

| Target | Who may freeze | Who may lift |
|---|---|---|
| `instance`: every workload use | an Owner | an Owner |
| `token:api-prod`: one workload | its managers | its managers who hold all of its grants (as for giving them) |
| `binding:<id>`: one platform of a workload, which is what contention freezes | its managers | the same |
| `session:<id>` | its managers | the same |
| `credential:<project>/<env>/<name>`: one upstream credential, for every workload and handle | anyone with `secret.write` on the place | an Owner of the project |

- **The API.** `POST /api/freezes { "target": "token:api-prod", "reason": "…" }`
  freezes, and `DELETE /api/freezes/<target>` lifts. On the CLI:
  `coffre freeze token:api-prod` and `coffre unfreeze …`. On the pages, a red
  Freeze button on each service, binding, session and credential.
- **Derived from the log, never copied.** A target is frozen when its newest
  allowed `workload.freeze` or `workload.unfreeze` entry is a freeze.
  - **Targets have one spelling**, canonicalized by `freezeTarget` in core:
    `instance`, `token:<name>`, `binding:<uuid>`, `session:<uuid>`, and
    `credential:<environment uuid>/<name>`, by the environment's ID so a
    rename moves nothing.
  - **The per-request check** is an index lookup on
    `audit_log_freeze_idx ((metadata::jsonb->>'target'), seq DESC) WHERE author = 'app' AND action IN ('workload.freeze', 'workload.unfreeze') AND decision = 'allow'`.
  - **The log is the one place the state lives**, under its MACs and chain. A
    database owner who deletes a freeze entry breaks the chain, which the
    next verification finds, the same limit as a tombstone's.
- **Tunnels** end at their next recheck, within `recheckSeconds`, whose
  statement includes the freeze (5.3). Workload tunnels recheck every 15
  seconds, not 60.

### 8.3 Alerts

`workload.alert` app entries, each `{ kind, service, binding, session, ip, … }`:

| `kind` | When |
|---|---|
| `enrolled` | a session made from an enrollment code |
| `contention` | 4.4, beside the automatic freeze |
| `limit` | 8.1 |
| `expiring` | an enrollment code 3 days from its end |
| `frozen` | each freeze and lift, including automatic ones |

They go to the log, which the audit page filters, and to the deployment's own
function, called in the background after the response (`waitUntil` on
Workers):

```ts
auth: signin({ workloads: { limits, alert: (alert) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text: alert.text }) }) } })
```

`alert.text` is one human line:
`api-prod enrolled from 203.0.113.9 (railway, code minted by deploy run 7001)`.
A delivery that fails is logged to the process log once. The alert entry in
the audit log is the record that counts.

### 8.4 `narrow()`: online attenuation

A workload hands a part of itself less authority, typically to an AI agent's
tool sandbox or a job runner:

```ts
const refunds = await coffre.narrow({ credentials: ['stripe'], methods: ['POST'], paths: ['/v1/refunds'], expiresIn: 600, label: 'refund-agent', key: sandboxPublicJwk });
```

`POST /api/auth/workload/narrow` with the parent's DPoP:

```json
{ "key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }, "label": "refund-agent",
  "constraints": { "places": ["market/prod"], "credentials": ["stripe"], "methods": ["POST"], "paths": ["/v1/refunds"] },
  "expiresIn": 600 }
```

The answer is `{ "token": "coffre_wl_…", "expiresAt": … }`.

- **The child is another session.** It is a `workload` row bound to the
  *recipient's* key. The recipient makes its own key pair and sends the
  parent only the public half, so the parent never holds the child's key. If
  `key` is omitted, the SDK makes one in-process, for a child that stays in
  the same process.
- **Narrower by construction.** The child's constraints are the intersection
  with the parent's, computed at creation and stored under the row's MAC:
  places ⊆, credentials ⊆, methods ⊆, path prefixes each under one of the
  parent's. The child's `notAfter` is at most the parent's. A child cannot
  read (`reads` is never inherited), mint for delivery, narrow below depth 4,
  or renew.
- **Paths are matched on what is sent, by segments.** `constraintsAllow`
  takes the resolved upstream URL, after the WHATWG parser has applied every
  dot segment (`/v1/refunds/%2e%2e/charges` is `/v1/charges` by then). Each
  prefix matches whole segments: `/v1/refunds` admits `/v1/refunds` and
  `/v1/refunds/re_1`, and never `/v1/refundsX`. A narrowed session's request
  is also refused if its path holds an encoded `.`, `/` or `\`, a `%25`
  (double encoding) or a `;` (`/v1/refunds/..;/charges`, which Tomcat reads
  as `/v1/charges`), so the upstream cannot read a segment differently from
  Coffre. A Hegel property generates paths with every such encoding.
- **Revoked with its parent.** The row stores `ancestors`, the IDs from the
  root down. Every request checks that each ancestor is unrevoked, unexpired
  and unfrozen, in the same statement (5.3). A parent that ends, whether by
  revocation, expiry or its process's death, ends its children at their next
  request.
- **Why online, not Biscuit or macaroons.** Every use already goes to Coffre,
  because Coffre performs it. So checking a child online is free, its
  revocation is instant, and its rules are this design's own few fields, not
  a policy language whose evaluator is a new place for bugs. Offline
  attenuation pays when the verifier is *not* Coffre: an upstream checking
  Coffre-issued tokens itself, or a sidecar attenuating thousands of times a
  second without a round trip. Neither happens here. A child also costs one
  row, which shows up on the page as what it is, with a label, rather than a
  token nobody can list.

## 9. The SDK, the binding, the sidecar

### 9.1 `@coffre/client/workload`: Node, Bun, Deno

It has no dependencies and uses WebCrypto only, built for Node 20 like the
rest of the client.

```ts
export function workload(options: {
  url: string;                 // https://secrets.acme.example
  service: string;             // 'api-prod', or 'token:api-prod'
  proof: Proof;                // kubernetes(), aws(), gcp(), azure({ audience }), fly(), vercel(token), github(), gitlab(), enrollment(code), auto()
  place?: string;              // when the binding has several environments
  fetch?: typeof fetch;
}): Promise<Workload>;

export interface Workload {
  readonly service: string;
  readonly places: readonly string[];
  /** A fetch that signs requests under <url>/use/ (method, URL, query, every header it was given, the body) and passes anything else through: give it to any SDK that takes one. */
  readonly fetch: typeof fetch;
  /** <url>/use/<name>, or <url>/use/<project>/<env>/<name> with several places. */
  url(name: string): string;
  credential(name: string): UsedCredential;
  /** The escape hatch: a plain value, or one the binding lists in reads. Anything else rejects with use_only. */
  read(key: string): Promise<string>;
  narrow(options: NarrowOptions): Promise<Workload>;
  close(): Promise<void>;      // logout; also on SIGTERM
}

export interface UsedCredential {
  fetch(path: string, init?: RequestInit): Promise<Response>;
  sign(message: string | Uint8Array): Promise<string>;                        // base64url, as today
  verify(message: string | Uint8Array, signature: string): Promise<boolean>;
  presign(path: string, options?: { expiresIn?: number; method?: 'GET' | 'HEAD' }): Promise<{ url: string; expiresAt: string }>;
  mint<T = Record<string, string>>(): Promise<T & { expiresAt: string }>;     // delivered minting, where listed
}
```

- **Lifecycle.** Exchange once, renew at half-life, re-prove before
  `notAfter`, retry `use_dpop_nonce` once, and retry an enrollment's `full`
  for up to 5 minutes. On `replayed` from a Kubernetes token (a restarted
  sidecar or process re-reading a spent file), it waits for the kubelet to
  write the next token, watching the file for up to 10 minutes, and says so
  on stderr. The
  token, the key and the nonce live only in `workload()`'s closure. Nothing
  touches disk or `process.env`.
- **`enrollment(code)`** removes the code from `process.env` once it is used,
  so the app's own env dumps no longer show it. That does nothing for the
  platform's store, which still holds it.
- **AWS without the AWS SDK.** `aws()` reads credentials from the
  environment, the ECS endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI` or
  `…_RELATIVE_URI`) or IMDSv2, and signs with a 60-line SigV4. It also takes
  `aws({ credentials: fromNodeProviderChain() })`. `fromCoffre(coffre, 'aws')`
  is an AWS SDK credential provider over delivered minting.
- **Postgres from Node.** `@coffre/client/workload/postgres` exports
  `connect(coffre, 'db')`, which returns a `Duplex` over the tunnel's
  WebSocket. node-postgres takes it as `stream`, so no listener and no
  password are involved: `new pg.Pool({ stream: () => connect(coffre, 'db') })`.

### 9.2 Cloudflare Workers: a service binding, nothing to prove

Coffre's app Worker exports an entrypoint, and an app Worker in the same
account binds it with `props` naming its service:

```jsonc
// the app's wrangler.jsonc
"services": [{ "binding": "COFFRE", "service": "coffre", "entrypoint": "CoffreWorkload", "props": { "service": "edge-api" } }]
```

- **What Coffre trusts.** `ctx.props` is set by the caller's deploy
  configuration, and the caller's code cannot change it. Cloudflare delivers
  it to `CoffreWorkload` as `this.ctx.props`. Coffre accepts a call when the
  service named in props has a live binding of profile `cloudflare`
  (`issuer: 'urn:coffre:cloudflare'`, no claims), and checks freezes, the
  gate's limits and `vault.access` as for any request. The binding is opt-in
  per service, can be revoked, and is logged like every other binding. There
  is no session row: each call is authenticated by the platform, and the
  audit's `credentialId` is `binding:<id>`. PR 1a's
  `PluginContext.workloadFromBinding(principal, { place, credential })` returns the same
  `WorkloadCaller` as a DPoP request, from the binding and the freezes, so the
  proxy sees one kind of caller.
- **The trust root is whoever can deploy Workers to the account.** They can
  set any `props`, and they could equally deploy Coffre itself. An account
  whose Workers deployers should not reach Coffre's services needs Coffre in
  an account of its own. Then service bindings do not cross accounts, and
  its Workers use `enrollment`. The binding's page says this. As of
  2026-10, Cloudflare's API and Terraform may not carry `props` for service
  bindings: deploy with wrangler.
- **Preview builds keep the binding.** With Workers Builds, a branch's
  preview version runs with the Worker's bindings, so whoever can push a
  branch would run code with production's `props`. A Worker that binds
  Coffre turns off non-production branch builds, or gives previews a wrangler
  environment of their own, bound to a service with its own binding. `coffre
  init`'s docs and the binding's page say so. Whether a preview version
  keeps `props` is to be checked live in PR 6, and the docs say what it
  found.

```ts
// the app Worker: OpenAI's SDK through coffre, no key anywhere
const openai = new OpenAI({ apiKey: 'coffre', baseURL: 'https://coffre/use/openai', fetch: (input, init) => env.COFFRE.fetch(new Request(input, init)) });
const { signature } = await env.COFFRE.sign('dfns-key', challenge);   // RPC: sign, verify, presign, mint
```

The host in `baseURL` is ignored, because the binding is the route. The
proxy's code is the same; only the authentication differs. The binding
carries the `Request` as the app built it, inside Cloudflare's runtime, with
nobody in between. So there is no `hdr`, and the proxy forwards the request's
headers as for a handle today, minus the hop-by-hop ones.

### 9.3 `coffre serve` and `coffre run`: any language, any container

`coffre serve` is the sidecar: a CLI process that holds the session and
listens locally.

```sh
coffre serve --url https://secrets.acme.example --service api-prod --proof kubernetes:/var/run/secrets/coffre/token --listen 127.0.0.1:7300
```

- **HTTP.** `http://127.0.0.1:7300/use/<credential>/<path>` is forwarded with
  DPoP, the proof signing the request as the app sent it, so the app's
  config names that URL. R14 holds: the app chooses its
  own provider URLs, and coffre writes none. `POST /use/<project>/<env>`
  forwards `sign`, `verify`, `presign` and `mint` alike.
- **Postgres.** Each tunnel in the plan gets a listener on its own port
  (`--tunnel db=127.0.0.1:7432`), as `coffre run` opens one for people.
  Its password is empty, because the sidecar's boundary is the pod.
- **The boundary is the network namespace.** Anything in the pod, or the
  container, can reach `127.0.0.1:7300`, just as anything in the process can
  reach the SDK's key. On a shared VM, `--listen unix:/run/coffre/api.sock`
  (mode `0600`, owned by the service's user) narrows it to one user.
- **`coffre run --service api-prod --proof … -- ./start`** does the same for
  the life of one command. It sets `COFFRE_CREDENTIALS` to the listener's
  URLs, and gives the child the plan's values. In CI with `--service` and no
  `--proof`, the CLI picks GitHub's or GitLab's proof as it picks their ID
  tokens today.

### 9.4 Each platform in about ten lines

**Railway** (Node; the same on Render and a VM):

```ts
import { workload, enrollment } from '@coffre/client/workload';
export const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: enrollment(process.env.COFFRE_ENROLL) });
export const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
export const charge = (body: URLSearchParams) => coffre.credential('stripe').fetch('/v1/charges', { method: 'POST', body });
// CI, each deploy:  railway variables --set "COFFRE_ENROLL=$(coffre enroll api-prod)"
```

**Cloudflare Workers**: section 9.2.

**Kubernetes** (any language), with a native sidecar:

```yaml
spec:
  serviceAccountName: api
  initContainers:
    - name: coffre
      image: registry.acme.example/coffre-cli:0.12   # any image with the coffre CLI
      restartPolicy: Always            # a native sidecar: an app restart keeps the session
      args: [serve, --url, https://secrets.acme.example, --service, api-prod, --proof, 'kubernetes:/var/run/secrets/coffre/token', --listen, '127.0.0.1:7300']
      volumeMounts: [{ name: coffre-token, mountPath: /var/run/secrets/coffre, readOnly: true }]
  containers:
    - { name: api, image: registry.acme.example/api:1.4.2 }   # its config: OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai
  volumes:
    - { name: coffre-token, projected: { sources: [{ serviceAccountToken: { audience: https://secrets.acme.example, expirationSeconds: 600, path: token } }] } }
```

The sidecar outlives the app container's restarts, so the single-use
projected token is read once per pod and again only to re-prove.

**ECS or Lambda**:

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'ingest', proof: aws() });
const s3 = new S3Client({ region: 'eu-west-3', credentials: fromCoffre(coffre, 'aws') });   // delivered minting, listed
const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
// coffre trust ingest --aws arn:aws:iam::671742253563:role/ingest-task
```

On Lambda, `workload()` runs once per execution environment, outside the
handler, so a cold start pays one exchange.

**Google Cloud Run**:

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'web', proof: gcp() });
// coffre trust web --gcp 104729384756102938475   (the service account's unique ID)
```

**Azure Container Apps or App Service**:

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'web', proof: azure({ audience: 'api://coffre-acme' }) });
// coffre trust web --azure --tenant <tid> --object <managed identity's object id> --audience api://coffre-acme
```

**Any language without a sidecar**: wrap it,
`coffre run --service web --proof gcp -- ./server`.

## 10. Cost per request

R27's target is under 10 ms of CPU at p50. Today a warm handle request asks
neither the database nor the vault: its handle and values come from the
proxy's cache. A warm workload request asks the database once, and pays
these:

| Step | CPU (to be measured in PR 1b, `pnpm bench:workers`) |
|---|---|
| Parse the proof, SHA-256 the token for `ath`, recompute `req` for a body of kilobytes | ~30 µs |
| Import the `jwk` (cached per isolate by `jkt`, as a settled value) | ~50 µs cold, 0 warm |
| One ES256 verify (BoringSSL in workerd) | ~100–200 µs |
| The one SQL statement of 5.3 (row, member's generation, binding, ancestors, freezes) | ~100 µs of client work, plus a round trip through Hyperdrive |
| The gate's RPC, from the caller's side | ~10 µs, plus a round trip inside the database's region |
| A cold request: `vault.access` and the opening, through the vault's connection | as a handle's cold request today |

The budget is under 0.5 ms of CPU on a warm request, plus two round trips:
one to the database and one to the gate. Freezes and revocations are then
seen on every request. A body's hash adds about 2 ms per MiB. The bench
reports cold and warm. `request-cost.test.ts` gains a workload case that
holds a warm request to one app statement and no vault call.

## 11. Data model and migration

One migration, `0015_workload_access`, for both engines. It only **adds**
(AGENTS.md, "expand, then contract"), and the current release's code serves
on it unchanged. On SQLite, widening the two checks on `credentials` means
rebuilding the table (create, copy, swap, in one transaction), which PR 0's
migration does, and its test checks that every row and index survives.

**`credentials`:**

| Change | What |
|---|---|
| `credentials_kind_check` | widened with `'workload'` |
| `credentials_kind_matches_principal` | becomes `(kind IN ('service','workload')) = (principal LIKE 'token:%')`. It is only looser, so existing rows pass. |
| `jkt text NULL` | the key's thumbprint. A new check, `kind <> 'workload' OR jkt IS NOT NULL`, which no existing row or old writer can break. |
| `not_after timestamptz NULL` | the hard end (5.4) |
| `ancestors text NULL` | JSON array of credential IDs, root first (8.4) |
| `constraints text NULL` | canonical JSON of a child's limits (8.4) |
| `enrollment_id uuid NULL REFERENCES enrollments(id)` | the code that made it (4.4) |
| `approved_at timestamptz NULL`, `approved_by text NULL` | for `approve` bindings (4.4) |
| index `credentials_enrollment_roots_idx (enrollment_id, created_at) WHERE kind = 'workload' AND ancestors IS NULL` | the capacity count and the tripwire (4.4): roots only, ended ones kept, since the tripwire reads the last hour |

- **What each kind of workload row holds:**

  | Made by | `created_by` | `scope` | `enrollment_id` | `ancestors`, `constraints` |
  |---|---|---|---|---|
  | an `oidc` or `aws` exchange | `binding:<id>` | null, so it holds the binding's, as an exchanged credential does today | null | null |
  | an enrollment code | `binding:<id>` | the code's, from `enrollments.scope` | the code | null |
  | `narrow` | `binding:<id>` of its root | its parent's | its root's | set |

  A Cloudflare call has no row (9.2).
- **Grants.** The runtime login gets no `UPDATE` on `jkt`, `not_after`,
  `ancestors`, `constraints` or `enrollment_id`, as for `places`. It gets
  `UPDATE` on `expires_at` (renew) and `approved_*`.
- **MAC tuple.** A `workload` row has one kind of its own,
  `workload_credentials`, which composes with no other prefix. Its fields are
  today's credential fields, then `createdBy`, `scope`, `places`, `jkt`,
  `notAfter`, `ancestors`, `constraints`, `enrollmentId`, `approvedAt` and
  `approvedBy`, in that order, with null distinct as everywhere. `kindOf` picks it first,
  whenever `kind === 'workload'`.

**`service_bindings`:**

| Change | What |
|---|---|
| `WORKLOAD_PROFILES` (core; the database has no profile check) | gains `kubernetes`, `gcp`, `azure`, `fly`, `vercel`, `aws`, `enrollment`, `cloudflare` |
| `policy text NULL` | canonical JSON, keys sorted, of `{ audience?, keyAudience?, reads?, sources?, sessionHours?, replicas?, sessionDays?, overlapMinutes?, mintedBy?, approve?, onContention?, unsignedUploads? }`. Each profile allows a fixed subset, checked by `checkPolicy` in core. Every binding made under this design has one, `{}` at least (4.1), so `policy IS NULL` marks exactly the bearer bindings of before. It is immutable like the rest of the binding, with no `UPDATE` grant. |

- **MAC tuple.** A non-null `policy` adds the prefix `policed_` last, over
  whatever `kindOf` composes today, with `policy` appended as the last
  field. A private cluster's binding with a scope and a policy is
  `policed_scoped_uploaded_service_bindings`: today's fields, then `jwks`,
  `scope` and `policy`. A workload binding is always policed, so its MAC
  never checks as an OIDC binding's.
- **Issuer and keys.** For the non-OIDC profiles, `issuer` and `jwks_uri`
  hold their URN: `urn:coffre:aws`, `urn:coffre:enrollment` or
  `urn:coffre:cloudflare`. That satisfies `NOT NULL`, and keeps "one key
  source per issuer" a single-column comparison.
- **Filtered by profile.** `/api/auth/oidc` and `/api/auth/workload` read
  bindings by an explicit profile list (4.1), so a binding with no claims
  never matches a token.

**`enrollments`**, a new table:

```sql
CREATE TABLE enrollments (
  id uuid PRIMARY KEY,
  auth_mac bytea NOT NULL,               -- kind 'enrollments': id, binding_id, code_hash, scope, created_by, created_with, expires_at
  binding_id uuid NOT NULL REFERENCES service_bindings(id),
  code_hash bytea NOT NULL UNIQUE,       -- SHA-256 of coffre_enr_…
  code_hint text NOT NULL,
  scope text NOT NULL,                   -- the binding's scope ∩ the minter's holdings, R32's sensitive per place (4.4)
  created_at timestamptz NOT NULL,
  created_by text NOT NULL,              -- the principal who minted it
  created_with uuid,                     -- their credential: the CI run's session
  expires_at timestamptz NOT NULL
);
CREATE INDEX enrollments_binding_idx ON enrollments (binding_id, created_at DESC);
```

The runtime login gets `SELECT` and `INSERT`, and nothing else.

**Tokens.** `generateToken` gains two kinds. `coffre_wl_` is a workload
session, and `coffre_enr_` is an enrollment code, which is never a
credential: `authenticateRequest` refuses it everywhere. Both are 32 random
bytes, so secret scanners match them by prefix. The regex in `tokens.ts`
grows to `(web|cli|svc|pat|use|wl|enr)`.

**Audit.**

- **New app actions:** `workload.freeze`, `workload.unfreeze`,
  `workload.alert`, `enrollment.create`, `enrollment.supersede` and
  `credential.mint`.
- **Existing actions gain fields:**
  - `token.create` gains `kind: 'workload'`, with `parent` for a child.
  - `token.exchange` gains `proof`.
  - `token.revoke` gains `reason: 'superseded'`.
- **Indexes.** The migration adds `audit_log_freeze_idx` (8.2) and
  `audit_log_supersede_idx ((metadata::jsonb->>'enrollmentId')) WHERE author = 'app' AND action = 'enrollment.supersede' AND decision = 'allow'`,
  the same shape as the unbind tombstones' index. Superseding several codes
  writes one entry per code. On SQLite, both use `json_extract`.

**Nothing is removed or tightened.** The contract step, D8, would come one
release after `useOnly` has served everywhere: drop `/api/auth/oidc`, drop
the issuing of `coffre_svc_` tokens, and tighten nothing in the schema.

## 12. The build: PRs, owners, tests

**Order.**

1. **PR 0 goes first and fast**, because everyone else compiles against it.
2. **After it, in parallel:** PRs 1a, 1b, 1c, 2, 5, 6 and 8. PR 1d follows
   1a, since it builds on `PluginContext.workload`. PR 6 builds on 1a's
   `workloadFromBinding`, and writes its entrypoint against PR 0's types
   until then.
3. **Once 1a and 1d have merged:** PRs 3, 4 and 7. They plug into the
   exchange and the proxy.
4. **After PRs 3, 4 and 7:** PR 9, which needs their routes, and PR 6's
   second half, the RPC methods for `mint`.

**Ownership.** Each file has one owner. Where another PR needs to change
something in it, the owner leaves a named hook, and the other PR adds one
line of registration after the owner has merged:

- **Routes and commands are declared once, in PR 0.** The route table is
  exhaustive in several maps: `api/routes.ts`, `api/personal-tokens.ts`,
  `mcp/scopes.ts`, `client/src/routes.ts`, `ui/src/parity.ts`, and the new
  `WORKLOAD_ROUTES`. PR 0 adds every route of this design to each of them,
  pointing at a handler exported from the owning PR's own file, which PR 0
  creates as a stub that answers 501. It does the same for every CLI command
  in `cli/commands.ts` (`enroll`, `approve`, `freeze`, `unfreeze`, `serve`).
  Owners then edit only their own files.
- **Proofs plug into the exchange.** PR 1a's exchange dispatches by proof
  kind through `PROOFS` in `api/workloads.ts`:

  ```ts
  type ProofKind = {
    profiles: readonly WorkloadProfile[];
    verify(input, ctx): Promise<{ binding; claims; spentKey?: Buffer; notAfter?: Date } | Refusal>;   // before the transaction; notAfter: a bearer token's exp
    commit?(tx, verified): Promise<{ enrollmentId?: string; scope?: string; notAfter?: Date; pending?: true } | Refusal>;  // inside it: an enrollment's code scope and expiry
    after?(outcome, ctx): Promise<void>;                                             // after it: alerts, contention
    lifetimeMs: number;                                                              // 3_600_000, or 90_000 for enrollment
    renew?: {
      check(tx, session): Promise<Refusal | null>;                                   // inside renewal's update: a superseded code
      after(session, ctx): Promise<void>;                                            // after it: contention
    };
  };
  ```

  PR 1a registers `oidc`, and PRs 2 and 3 register theirs, one line each.
  The exchange stores `scope` from `commit` when it gives one (an
  enrollment's code scope, which `MinterBound` rests on), and sets the
  session's `notAfter` to the earliest of `sessionHours` and the `notAfter`s
  of `verify` and `commit`. `pending: true` makes the exchange answer 202.
- **Shared types and configuration are PR 0's.** PR 0 declares them; the
  PRs that use them implement them:
  - the `workload` kind of `Caller` (`api/caller.ts`) and `ScopeGrant.reads`
    by ID (`core/access.ts`): declared by PR 0, produced by 1a, enforced by
    1c;
  - `WorkloadsOptions` (`core/src/identity/signin/config.ts`) gaining
    `useOnly`, `noReads` and `alert`: declared by PR 0, used by 1a and 1d;
  - the Node config's `clientAddress(request)` (`server/src/node.ts`,
    `config.ts`): declared by PR 0, used by PR 3;
  - `coffre.Gates` and `coffre.Workload` in `server/src/cloudflare.ts`:
    declared by PR 0, implemented by 1b and PR 6.
- **PR 1b owns `gate.ts` whole**, the counters included. PR 1a owns
  binding creation: accepting `policy`, skipping discovery for the `urn:`
  issuers, and refusing a sensitive key in `reads` unless an Owner of its
  project makes the binding.

| PR | What | Owns | Tests |
|---|---|---|---|
| **0. Foundation** | Pure code, schema, types and declarations. The proof's signing half lives in the client, which ships with no dependency, so the SDK and the server run the same canonicalization: `packages/client/src/dpop.ts` (`createProof`, `canonicalHtu`, `canonicalRequest`, `thumbprint`). Core depends on `@coffre/client` for it (no cycle: the client depends on nothing) and adds `verifyProof`. Also: `constraintsAllow` and `intersect` (8.4); `freezeTarget`; `BindingPolicy`, `checkPolicy` (`mintedBy` ≠ the service) and the new `WORKLOAD_PROFILES` with their `REQUIRED_CLAIMS`; the token kinds; the `Gate` and `WorkloadCaller` types; `Through.caller`, optional here and made required by 1c; migration `0015_workload_access` for both engines, with SQLite's rebuild; the schema; the MAC kinds; every route and CLI command, declared with 501 stubs (above) | `packages/client/src/dpop.ts` (new), `packages/core/src/identity/dpop.ts` (new), `packages/core/src/identity/constraints.ts` (new), `…/identity/tokens.ts`, `…/identity/workloads.ts`, `packages/db/src/schema.ts`, `packages/db/src/migrations/*/0015_*`, `packages/db/src/grants.ts`, `packages/server/src/auth-rows.ts`, the route maps and `cli/commands.ts` named above, and each stub file it creates for its owner | Hegel properties: proofs round-trip, and every single-field mutation is refused (`req` included: a changed query, header or body byte); the `(r, n−s)` twin has the same `jti`; the thumbprint is canonical whatever the JSON order; `canonicalHtu` is idempotent and keeps percent-encoding; `checkPolicy` is canonical (one digest per policy); `intersect` ⊆ both arguments; `constraintsAllow` against a reference over generated paths with every dot-segment and percent-encoding. The migration applies on both engines, SQLite's rebuild keeps every row and index, and the newest published release passes on the new schema (`pnpm test:compat`). |
| **1a. Exchange and sessions** | `POST /api/auth/workload` with `PROOFS` and `oidc` (audience naming the key, 4.1's spending rule, `notAfter` capped by a bearer proof's `exp`, the explicit profile filter in both exchanges); renew (the two-step update on the database's clock, and `PROOFS`' `renew` hooks), logout; binding creation with `policy`; `authenticateRequest`'s DPoP path, `WORKLOAD_ROUTES`, and the one statement of 5.3 with every clause; `PluginContext.workload(request, { place, credential })` and `workloadFromBinding`; `useOnly` and `noReads`, including service-token issuance refused | `packages/server/src/api/workloads.ts`, `…/auth.ts`, `…/auth-routes.ts`, `…/api/signin.ts`, `…/api/members.ts`, `…/plugins.ts` (the context's new methods) | An exchange per proof shape; a token without its key is refused; refusal outside `WORKLOAD_ROUTES`; revocation, freeze and member removal on the next request; a late renewal revives nothing; a Kubernetes session ends at its token's `exp`; `useOnly` refuses `coffre_svc_` and answers 410 at `/api/auth/oidc`; `request-cost.test.ts` (one app statement, no vault call, warm). |
| **1b. The gate** | the Node gate and the `CoffreGates` Durable Object (nonces, `jti`, counters with `first`); the `GATES` wiring in `examples/*`, `dev/deployment` and `coffre init`, and `init` writing `useOnly: true` | `packages/server/src/gate.ts` (new), `…/cloudflare-gates.ts` (new), `…/cloudflare-handler.ts`, `examples/*/app/src/coffre.ts`, `examples/*/app/src/server.ts`, `examples/*/app/wrangler.jsonc`, `dev/deployment/*`, `packages/cli/src/init.ts` | A replayed proof refused, including across a gate restart (a new epoch); `use_dpop_nonce`, then success; 429 past the ceiling; a model-based Hegel test against a reference set; `bench:workers` numbers. |
| **1c. Vault and access** | `Through.caller` made required; scopes materialized with `reads`; the vault's `use_only` at the place where the value is held; no laundering through references, forks or copies; `reads` by ID | `packages/vault/src/vault.ts`, `packages/core/src/vault.ts`, `packages/core/src/access.ts`, `packages/server/src/api/caller.ts`, `…/api/context.ts`, `…/api/secrets.ts`, `…/api/references.ts`, `…/api/forks.ts` | The vault refuses `reveal` with `use_only` and lets listed keys through; a workload caller with no scope refused; a reference to an unlisted source refused; a copy from an unreadable source refused; renaming a key onto a listed name leaves it unreadable; `NoLaundering`'s cases. |
| **1d. The proxy's workload caller** | the proxy, `sign`, `presign` and the tunnel accepting a workload caller: forwarding only `hdr`, `req` checked, `constraintsAllow` on the resolved target, `limit`, sockets named by session, 15 s rechecks; alerts and `alert(…)` delivery | `packages/server/src/plugins/credential-proxy.ts`, `…/cloudflare-sockets.ts`, `…/alerts.ts` (new) | A header outside `hdr` is not forwarded; a changed query, header or body is refused; a streamed SigV4 upload is bound by its payload hash, and `UNSIGNED-PAYLOAD` refused without `unsignedUploads`; revocation despite a warm value cache; limits answer 429 with one alert per window; a tunnel ends within a recheck of a freeze. |
| **2. Proofs** | the `aws` verifier; the `kubernetes`, `gcp`, `azure`, `fly` and `vercel` profiles; every new `coffre trust` flag (`--aws`, `--kubernetes`, `--gcp`, `--azure`, `--fly`, `--vercel`, `--enrollment`, `--cloudflare`, `--reads`, `--source`, `--replicas`, `--minted-by`, `--approve`, `--session-days`, `--session-hours`, `--overlap-minutes`, `--on-contention`, `--unsigned-uploads`) | `packages/server/src/workloads/aws.ts` (new), `…/workloads/profiles.ts` (new), its `PROOFS` entry, `packages/cli/src/trust.ts` | A fake STS that checks SigV4 with `@smithy/signature-v4`; `x-coffre-key` not among `SignedHeaders` refused; another region host, a non-STS URL, another body, an extra header and a redirect each refused; root, federated and IAM users refused; the same signed request again, with the same key, makes a second session and is never `replayed`; fixture tokens per profile, each with a required claim missing refused; a recreated role (new `AROA…`) refused; an Azure token presented again, by the same key or another, makes a session each, ending at the token's `exp` (a Vercel token names the key, D15: another key's is refused `audience`); a Kubernetes token presented twice is `replayed`; whether `@vercel/oidc` lets the audience be chosen, settled from its source. **Live:** a `GetCallerIdentity` signed with the `erwinkn-mgmt` SSO credentials against real STS (no resources), and a throwaway Lambda's role (`coffre-ovn-<W#>`, deleted after). |
| **3. Enrollment** | the `enrollments` routes (mint with its scope, promote, the recovery action); `coffre enroll` and `coffre approve`; capacity, the tripwire, supersession and drain (through `PROOFS`' `renew` hooks), `sources` with `clientAddress`, `approve` | `packages/server/src/api/enrollments.ts` (new), `…/workloads/enrollment.ts` (new, its `PROOFS` entry), `packages/cli/src/enroll.ts` (new) | Concurrency: N exchanges racing on one code never leave more than `2 × replicas` live roots, on both engines, renewals racing included; a crash's restart and two same-code redeploys an hour never freeze; a thief overlapping full replicas for `overlapMinutes`, re-enrolling with gaps, freezes, and so does churn past `4 × replicas` roots an hour; children take no slot; supersession only on `promote`, the old sessions drain within 90 s, `--now` revokes them, and a failed deploy keeps the old code; recovery (mint, promote, lift) leaves the thief out; a Viewer-minted code holds a Viewer's scope and no sensitive value; `mintedBy` naming the service itself is refused, and so is minting from an enrollment session or a child; `sources` refused at the exchange and per request, and a null address is refused; `pending`, then approve, then use. **Live:** a throwaway Railway project (`coffre-ovn-<W#>`): enroll, restart, copy the code to a second service, watch it freeze. |
| **4. Freeze and narrow** | the freeze routes and `coffre freeze`/`unfreeze`; `narrow` | `packages/server/src/api/freezes.ts` (new), `…/api/narrow.ts` (new), `packages/cli/src/freeze.ts` (new) | Freeze, then the next request is refused on HTTP, and on a tunnel within one recheck; lift restores; who may freeze or lift each target; narrow ⊆ parent; a child dies with any ancestor; a child cannot read, mint or renew; `/v1/refunds/%2e%2e/charges`, `/v1/refunds/..;/charges` and `/v1/refundsX` refused for a child of `/v1/refunds`; such a child refused `sign` and the tunnel; a child of `credentials: ['stripe']` refused `sign('dfns-key')`. |
| **5. SDK and sidecar** | `@coffre/client/workload` and its proofs; `fromCoffre`; `…/workload/postgres`; `coffre serve`; `coffre run --service` in key-bound mode; the CLI's tunnel listener speaking DPoP | `packages/client/src/workload.ts` (new), `…/workload-proofs.ts` (new), `…/workload-postgres.ts` (new), `packages/client/package.json` (its exports), `packages/cli/src/serve.ts` (new), `packages/cli/src/workload.ts`, `packages/cli/src/tunnels.ts` | Against a fake server first (this doc's wire format), then the real one once PRs 1a and 1d land: renewal (hourly, and every 30 s for enrollment), re-proof before `notAfter`, the nonce retry and the freshest nonce, `full` retries, waiting out a spent projected token; `hdr` and `req` match what the server recomputes; OpenAI's SDK through `coffre.fetch`; `pg` through `connect`; the key is non-extractable (`exportKey` rejects); nothing written to disk or env. The packed client still loads on Node 20, 22 and 24 (`test:consumer`). **Live:** a GitHub Actions workflow in a scratch repository of erwinkn, and `kind` in Docker with the sidecar. |
| **6. Cloudflare** | `CoffreWorkload` (`WorkerEntrypoint` with `props`): `fetch` (the proxy) and the RPC methods `sign`, `verify` and `presign`; then, after PR 7, `mint`. No `narrow` over RPC: a Cloudflare caller has no session row to be a child's root. The `cloudflare` binding's server side; its example wiring, after 1b | `packages/server/src/cloudflare-workload.ts` (new); after 1b merges, the entrypoint's export lines in `examples/workers` and `init.ts` | A miniflare test with two Workers, props naming a service with and without a binding; each RPC method; freeze; limits. Conformance: a Worker with props for an unbound service gets nothing. **Live:** two throwaway Workers on Erwin's personal account (`d56cef42…`), `coffre-ovn-<W#>-*`, including whether a preview version keeps `props`; deleted and verified gone. |
| **7. Minting and `verify`** | `minters` (`assumeRole`, `githubInstallation`, `r2Temporary`); `{mint:…}` in rules; `sigv4({ minted })`; the `mint` and `verify` operations; `hmac` and `stripeSignature` | `packages/server/src/plugins/mint/*.ts` (new), `…/plugins/verify.ts` (new); after 1d, the `mint` and `verify` cases of `credential-proxy.ts`'s `compute` | A fake STS and a fake GitHub; caching until 60 s before expiry, settled values only; delivered mint refused unless listed, and refused for a sensitive parent without R32's flag; `credential.mint` entries; Stripe's own test vectors for `stripeSignature`. **Live:** `AssumeRole` into a throwaway role (`coffre-ovn-<W#>`), deleted after. |
| **8. Formal** | `formal/Workload.tla` and its configurations; `docs/formal.md`'s section | `formal/Workload*.tla`, `formal/Workload*.cfg`, `docs/formal.md` | Section 12.1: each invariant holds, and each fails without its protection. |
| **9. Pages** | the binding forms for the new profiles; `reads` flagged per platform; a service's sessions, with their last address; codes and their scope; the Freeze buttons; the alert filter | `packages/ui/src/pages/*` (the service page and its dialogs) | The UI suite. The page shows "exposed if <platform> is breached" for every listed key. |

**Docs.** Each PR updates the docs for what it builds. PR 5 writes
`docs/workloads.md`, the per-platform guide (9.4 and the playbook in 7.3).

### 12.1 Verification

**Model checking**, `formal/Workload.tla`, TLC as `pnpm formal` runs it. The
model has two workloads, two keys per workload, one attacker who learns
every token, proof, platform token and enrollment code that crosses any
channel, but no private key, gates that restart at any step, and an
enrollment's replicas that crash, restart and redeploy with overlap. Each
invariant must hold, and must fail with its named protection removed:

| Invariant | Holds because | Fails without |
|---|---|---|
| `CopyIsUseless`: every accepted request was signed by the holder of its session's key | the proof's signature and `jkt` | checking `jkt` against the row |
| `ForwardedIsSigned`: what Coffre forwards upstream (method, URL, query, headers, body) is what the key signed | `req` recomputed and only `hdr` forwarded | forwarding unlisted headers, or skipping `req` |
| `ProofOnce`: no `(jkt, jti)` is accepted twice, across gate restarts | nonce epochs | the epoch (a restart forgets `jti`s) |
| `FreezeBound`: no use is accepted after a freeze of its target commits, and no tunnel byte flows after commit + `Recheck` | the per-request statement, before any cache | the check before the value cache (a cached session) |
| `RevokeBound`: the same for revoking a session, an ancestor or a binding, and removing the member; a superseded code's sessions within 90 s | the same statement, with the member's generation; renewal refused under a tombstone | the generation in the statement; the tombstone at renewal |
| `Capacity`: live roots per code ≤ `2 × replicas`, under concurrent exchanges and renewals | the count under the log head; renewal conditional on the database's clock and the old expiry | the head lock, or an unconditional renewal (a late renewal revives a counted-dead session) |
| `NoFalseContention`: with no foreign holder of a code, crashes, restarts and up to two same-code redeploys an hour, each with under half the threshold's excess session-minutes, never freeze it | liveness by expiry (90 s); the tripwire's accumulated time and its count of roots; children are not roots | counting children, or r1's and r2's rules (fencing the oldest; a run of `busy`), which the model keeps as negative configurations |
| `TripwireFires`: a foreign holder whose excess beside full replicas passes `overlapMinutes × replicas` session-minutes since the last lift, in any number of sessions with any gaps, or who makes more than `4 × replicas` roots, causes a freeze | the tripwire's excess integral over every root, ended ones included | r3's rule (the age of the `(replicas + 1)`-th root), which a re-enrolling thief evades: a negative configuration. The model also states the evasions (a free slot, staying under both thresholds) as reachable, so nobody mistakes the tripwire for a guarantee. |
| `Superseded`: no session is made from a code once an `enrollment.supersede` names it, and none renews | the tombstone check at the exchange and at renewal | the renewal half |
| `MinterBound`: a code's sessions never hold more than its minter held at minting, and read a sensitive value only if the minter was an Owner; no session of an enrollment mints or promotes | the code's scope, fixed at minting under its MAC; the routes' refusal | intersecting with the binding's scope alone; `mintedBy` naming the service |
| `NoLaundering`: a workload reads a value only if `reads` lists the key, by ID, where the value is held, whatever it renames, references or copies | `reads` by environment and key ID; the vault's check at the source's place; references and copies refused from unreadable sources | checking `reads` at the place the request names, or by name (a rename onto a listed name) |
| `NarrowSubset`: a child's rights ⊆ its parent's, at every state, on the URL sent upstream | intersection at creation, `constraintsAllow` on the resolved target, ancestors checked live | the ancestor check (a parent ended), or matching the path as received |
| `NotAfter`: no session is usable, or renewed, past `notAfter` | the row's `not_after` under MAC | the renew bound |

**Property tests** (Hegel, `pnpm test:properties`):

- DPoP mutations and the signature twin;
- the thumbprint;
- `canonicalHtu` against a reference over generated URLs;
- policy canonicalization;
- CIDR membership against a reference over generated addresses, IPv4 and
  IPv6;
- narrow intersection ⊆, and `constraintsAllow` on resolved URLs, over random constraint sets and paths with every encoding;
- `canonicalRequest` against a reference, over generated queries, header lists and bodies;
- a model-based test of the gate: random sequences of admit, rotate and
  restart against a reference set, and the reference must agree.

**Live tests**, each throwaway and named `coffre-ovn-<W#>`, within $5 per
worker, deleted and then verified gone through the provider's API:

| Platform | Test | Covered by |
|---|---|---|
| Cloudflare | two Workers, a binding with `props`, an upstream call through the proxy, freeze | PR 6 |
| AWS | `GetCallerIdentity` from SSO credentials; a Lambda's role; `AssumeRole` minting | PRs 2, 7 |
| Railway | enrollment, restart, a copied code, contention freeze | PR 3 |
| Kubernetes | a `kind` cluster in Docker: a pod's projected token, checked against its binding, which `coffre trust --kubernetes` made with `kubectl` (PR 2, done: the token carries the claims the fixtures do, and a service account made again under its name gets a new UID); the sidecar (PR 5) | PRs 2, 5 |
| GitHub Actions | a workflow in a scratch repository of erwinkn, with `id-token: write` and the audience naming the key | PR 5 |
| Google Cloud, Azure, Fly, Vercel | **not live.** There is no account for them tonight, so they are covered by fixture tokens shaped from each platform's documentation. Their first real use should include a live check. Vercel's choice of audience is settled from `@vercel/oidc`'s source (4.2). | PR 2 |

## 13. Decisions taken (R10), each Erwin's to revisit

1. **Key-bound sessions with DPoP, not short bearer tokens.** A copied token
   is worthless at any age, so lifetime stops being the control. A one-hour
   session renewed by the key, plus re-proof every 24 hours, replaces "5 to
   15 minutes". *Alternative:* bearer tokens of a minute, which would still
   be usable from anywhere in that minute and cost an exchange each minute.
2. **One gate per workload, nonces as epochs.** Options for the replay
   memory:
   - (a) a database row per request: a write per request, and a table the
     runtime login cannot clean;
   - (b) memory per isolate: no guarantee across isolates;
   - (c) a Durable Object per session: the same cost as (d), but limits
     need a per-workload view anyway;
   - (d) **one object per workload**, which also holds the limits.

   (d) has a ceiling of about 1,000 requests a second per workload (a
   Durable Object's soft limit) before sharding. *Reversible:* a workload past it gets several gates, by session
   hash, with limits split.
3. **Workloads read only what their binding lists.** The list lives on the
   binding, because the exposure belongs to the platform. *Alternative:* a
   fourth key level, `sealed`, which would decide by key and not by where
   the value lands, and would not distinguish Cloudflare from Railway.
4. **Enrollment codes are multi-use, up to `2 × replicas` live roots, and
   detecting a copy is a tripwire, not a guarantee.** Single-use per boot
   turns every crash into an outage. Three reviews in turn found the
   detection rule either freezing ordinary operations (fencing the oldest
   session; a run of `busy`) or evadable (the age of one session), because a
   copy and an instance are indistinguishable by construction. So the
   guarantee is stated without detection: a copy gets at most a slot, every
   session alerts at once, `sources` narrows, and the next promote ends it.
   The tripwire (accumulated over-occupancy, and churn) freezes the clumsy
   cases. *Reversible:* `replicas: 1` with `approve: true` comes close to
   single-use, at the cost of a person per restart.
5. **Cloudflare through `props`.** The trust root is the account's Workers
   deployers. *Alternative:* enrollment for Workers too, which would put a
   secret where none is needed.
6. **`narrow()` is online.** See 8.4.
7. **Freeze state comes from the log**, the newest allowed entry per target.
   *Alternative:* a `freezes` table under MAC, one more place that holds the
   same fact.
8. **Bearer paths stay until `useOnly`.** `coffre init` writes
   `useOnly: true`. The contract step, removing `/api/auth/oidc` and the
   issuing of service tokens, is one release after Equisafe has run on
   `useOnly`. Erwin decides that release.
9. **Delivered minting is a listed read.** A child credential with a
   lifetime is still a value, so it is exposed and flagged as one.
10. **A Node deployment's gate is its process.** A multi-process Node
    deployment is unsupported for workloads until it brings a shared gate.
11. **A proof signs the whole request** (`hdr`, `req`), and Coffre forwards
    exactly what it signs. RFC 9449 alone leaves the query, headers and body
    open to a copier who wins the race. *Alternative:* RFC 9421 message
    signatures, with a larger surface and no DPoP library support.
12. **A code's scope is fixed at minting**, intersected with the minter's
    holdings, as for any issued credential. A code is therefore never a way
    around R32. The cost is least privilege for CI: a CI minter must itself
    hold what the apps it deploys use. *Alternative:* a code minted by a
    person only, which no unattended deploy could do.
13. **`useOnly` means no bearer service credential**, and keeps listed reads.
    `noReads` is the stricter switch. With one switch for both, `init`'s
    default would leave a new deployment's CI without its `NPM_TOKEN`.
14. **Open after review r4, settled in the PRs that build them.** Review r4's
    findings were fixed without a fifth round, per the coordinator's
    decision. These are settled in their PRs' own reviews:
    - the enrollment tripwire's numbers (4.4), in PR 3;
    - the `PROOFS` and `Gate` shapes as amended in r4 (`notAfter`, `scope`,
      `nonce()`, optional replay), in PRs 0, 1a and 1b;
    - the declared payload hash limited to `sigv4` credentials (5.1), in
      PRs 0 and 1d;
    - `/api/auth/oidc` taking policy-less bindings only (4.1), in PR 1a.
15. **Vercel's audience names the key** (PR 2). The design took it as fixed,
    which was wrong: `@vercel/oidc` exchanges a function's token for one of
    any audience (4.2). So `vercel` is a key-naming profile, never a
    repeating one: a token sent to Coffre is useless to another key, and is
    never spent. What stays is the function's own token, a bearer for that
    exchange until its `exp` (note 5 of section 3). *Alternative:* keep
    Vercel's fixed audience, which would leave every token Coffre receives a
    bearer for any key.

## 14. Later

- **The vault checks proofs (closing G2).** The vault would record each
  session's `jkt` at the exchange, verify the platform proof itself (the
  OIDC signature, the STS answer, the enrollment hash), and require each
  `unwrap` for a workload to carry that request's DPoP proof, its `jti`
  spent in the vault's own memory. A taken-over app could then use only the
  proofs workloads send it, once each, for the URL they name, and could no
  longer open a value for a workload on its own. This is the "requests
  signed by keys the principals hold themselves" that architecture.md
  foresaw. It moves workload sign-in into the vault, so it is a design of its
  own.
- **Minted Postgres logins** (W108), with a sweeper.
- **People's handles, key-bound.** `coffre run` would hold a key for its
  child and listen locally, as for workloads. Placeholders would then stop
  being bearers.
- **Railway, Render and Heroku profiles**, the day those platforms sign a
  workload identity. Each one replaces enrollment there.

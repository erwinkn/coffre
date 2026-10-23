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
| Uses `coffre_enr_…` from their laptop | Refused. The binding pins Railway's static egress addresses (`sources`). |
| Uses it from inside another Railway service of theirs (the egress pin allows Railway's addresses) | A session, which fences one of the app's live sessions. The app re-enrolls within seconds. Two holders fighting over one code is *contention*: Coffre freezes the binding and alerts. Every use is logged, and none returns Stripe's key. |
| Copies the session token from a log line or a crash dump | Nothing. The token is useless without the key, which never left the process. |
| Captures one signed request in transit | Nothing. Each proof is accepted once and names one method and URL. |

On every platform with a workload identity of its own (Cloudflare, Kubernetes,
AWS, Google Cloud, Azure, Fly, Vercel, CI), the platform's store holds nothing
at all.

The whole design follows from one rule. **A workload holds no secret that
works anywhere else, and every use passes live Coffre policy.** Whatever a
platform breach copies (env, disk, image, logs, a token), it yields no value
and no standing credential. What it can do, it does through Coffre, while the
attacker stays inside, under limits, logged, and only until a freeze or
revocation stops it.

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
  lasts, each request is checked live, counted against limits, logged, and
  stopped by a freeze or revocation. They never get the value.
- **value**: the attacker reads values.

Only keys that a binding lists in `reads` (section 6) ever turn a **use** cell
into **value**, and the page shows that per binding. A strict instance
(`useOnly`) has no such keys.

| Platform (proof) | A. env/store copy | B. in transit | C. log leak | D. dependency | E. CI | F. root on host | G1. DB copy | G2. Coffre taken over |
|---|---|---|---|---|---|---|---|---|
| Cloudflare Workers (service binding, `props`) | **none**: nothing secret exists | **none**: the call never leaves Cloudflare's runtime | **none** | **use** | **use**: a deployer can deploy code that calls the binding | n/a (Cloudflare's runtime) | **none** | **value** |
| Kubernetes (projected token, `oidc`) | **none**: etcd holds no projected token | **none** | **none** (¹) | **use** | **use**: it can run a pod as the service account | **use**: reads fresh projected tokens | **none** | **value** |
| AWS: ECS, Lambda, EC2, EKS (`aws`) | **none**: role credentials are runtime-only | **none**: the signed request names the key and is spent once | **use**, until the leaked role credentials expire (²) | **use** | **use** | **use** | **none** | **value** |
| Google Cloud: Cloud Run, GCE, GKE (`oidc`, `gcp`) | **none** | **none** | **none**: the ID token's audience names the key (section 4.3) | **use** | **use** | **use** | **none** | **value** |
| Azure, managed identity (`oidc`, `azure`) | **none** | **none** | **use**, at most once, within the token's hour (³) | **use** | **use** | **use** | **none** | **value** |
| Fly, Vercel (`oidc`) | **none** | **none** | Fly: **none** (audience names the key). Vercel: **use** once (³) | **use** | **use** | **use** | **none** | **value** |
| GitHub Actions, GitLab CI (`oidc`) | **none** | **none** | **none** on GitHub (audience names the key). GitLab: **use** once (³) | **use** | **use** (it *is* CI) | **use** (the runner) | **none** | **value** |
| Railway, Render, a VM (`enrollment`) | **use**, *detected*: an `enrolled` alert at once, contention freeze. **none** when `sources` pins an egress the attacker cannot run from. | **none** | as A | **use** | **use**: CI mints codes | **use** | **none** | **value** |
| *Today: a bearer service token* | **value**, for up to a year | **value** | **value** | **value** | **value** | **value** | **none** | **value** |

Notes:

1. A Kubernetes token that ends up in a log is spent if the pod used it. Its
   audience cannot name the key, so an unspent one works once, within its
   10 to 60 minutes.
2. Lambda puts its role's session credentials in the function's runtime
   environment. An env dump in a log therefore lets the attacker sign a
   `GetCallerIdentity` with them until they expire (at most 12 hours). A
   binding's `sources` closes this off when the attacker is outside the VPC's
   NAT addresses.
3. An ID token whose audience cannot name the key is a bearer for its single
   use. If the attacker spends it first, the workload's own exchange fails
   with `replayed`, which is loud.

What the table says in one sentence: **no platform-side attacker ever reads a
value, and none gets anything that outlives their presence.** In every
**use** cell, a freeze stops the attacker within one request, and a
revocation does too.

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
  4. one read of the service's live bindings of the proof's kind;
  5. the proof itself;
  6. `vault.access` for the member, outside any transaction;
  7. the commit, under the log head: re-check member and binding, spend the
     proof, the enrollment's fencing (section 4.4), insert the credential,
     append `token.exchange` with `{ kind: 'workload', jkt, proof: 'aws' | 'oidc' | 'enrollment', … }`.

  A proof no binding can take costs admission and one read, as today.
- **Refusals** are 401s, kept out of the audit log as today. Their `reason`
  is the OIDC exchange's set plus `dpop` (the header is missing or bad),
  `source` (outside the binding's `sources`), `superseded` (an older
  enrollment), `frozen` and `pending` (section 4.4).
- **`places`** are the environments of the binding's scope, as a handle's
  `places`. With exactly one, the stable URL `/use/<credential>` works. With
  several, the SDK names the environment (`/use/<project>/<env>/<credential>`),
  as a handle of several environments must.

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
| `azure` | `https://sts.windows.net/<tenant>/` | `tid`, `oid` (the managed identity's object ID) | the binding's `audience`, an Entra application ID URI (`api://coffre-acme`): Entra mints tokens only for a registered resource | IMDS `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=…` with `Metadata: true`; App Service and Functions use `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` |
| `fly` | `https://oidc.fly.io/<org>` | `org_id`, `app_id` | `publicUrl#jkt=<thumbprint>` | `POST /v1/tokens/oidc` on the machine's `/.fly/api` socket, `{"aud": …}` |
| `vercel` | `https://oidc.vercel.com/<team>` | `owner_id`, `project_id`, `environment` (`production` keeps previews out) | `https://vercel.com/<team>`, fixed by Vercel: the binding's `audience` | the `x-vercel-oidc-token` request header (functions), `VERCEL_OIDC_TOKEN` (builds) |
| `github`, `github-reusable…`, `gitlab`, `custom` | as today | as today | `publicUrl#jkt=<thumbprint>` on GitHub; `publicUrl` elsewhere | as today |

- **The audience may name the key.** Where the platform lets the caller pick
  the audience (GitHub, Google, Fly), the SDK asks for
  `<publicUrl>#jkt=<thumbprint>`. The exchange accepts that form only when
  the thumbprint equals the DPoP key's. A copied token is then useless to any
  other key, whether or not it is spent. Plain `publicUrl` is still
  accepted, so platforms with a fixed audience keep working. A binding may
  require the key-naming form with `policy.keyAudience: true`; GitHub
  bindings made from the page default to it.
- **`audience` in the policy.** Azure and Vercel cannot mint for an arbitrary
  URL. Their binding names the exact audience, under its MAC. Every other
  profile refuses a policy `audience`.
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
signed headers: host, x-amz-date, x-amz-security-token (if any),
                x-coffre-audience: <publicUrl>, x-coffre-key: <jkt>
```

It sends Coffre the URL, headers and body, never the credentials.

**What Coffre checks:**

1. **The URL.** It must be exactly `https://sts.amazonaws.com/` or
   `https://sts.<region>.amazonaws.com/`, with `<region>` matching
   `^[a-z]{2}(-[a-z]+)+-\d$`. Nothing else is ever fetched, so the URL offers
   no SSRF.
2. **The headers.** `x-coffre-audience` must equal `publicUrl`, and
   `x-coffre-key` must equal the DPoP key's thumbprint. Both must be among
   the `SignedHeaders`.
3. **The time.** `x-amz-date` must be within 5 minutes. STS refuses past 15.
4. **Unspent.** The SHA-256 of `"aws\n" + Signature` must not be in
   `consumed_tokens`, the table the OIDC exchange already uses, kept 2 hours.
5. **STS.** Coffre forwards the request with the same transport rules as
   JWKS fetches (`https` only, no redirects, a 5 s deadline, 64 KiB). It
   parses `<GetCallerIdentityResult>`: `Arn`, `Account` and `UserId`.

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
before saving. An IAM user's `AIDA…` ID is accepted too, for EC2 without a
role, and the page warns that it means a long-lived key.

**The key is under the signature.** `x-coffre-key` is signed, so this proof
works with this key only, and column B is **none**. A role's credentials
leaked through a log (note 2 of the table) can still sign a fresh proof. That
is the residual risk.

### 4.4 `enrollment`: platforms that sign nothing

Railway, Render, Heroku and a bare VM give a process no identity a copy lacks.
An enrollment code is the least that works, and the design spends its
effort on making a copy **loud**, **contained** and, where the platform
allows, **pinned**.

**The binding:**

```sh
coffre trust api-prod --enrollment --replicas 2 --source 162.220.232.0/24 --minted-by deploy
```

```json
{ "profile": "enrollment", "issuer": "urn:coffre:enrollment", "claims": {},
  "policy": { "replicas": 2, "sources": ["162.220.232.0/24"], "mintedBy": "token:deploy",
              "sessionDays": 30, "approve": false } }
```

**Minting a code.** `POST /api/members/token:api-prod/bindings/<id>/enrollments`
answers `{ "code": "coffre_enr_…", "expiresAt": … }`. These callers may mint:

- the service's managers, as people (personal tokens refused, as for every
  service-account route);
- the service named by `mintedBy`, on a workload session: CI's own,
  OIDC-proven.

CI mints one per deploy and sets it as the platform's variable for that
deploy:

```sh
railway variables --set "COFFRE_ENROLL=$(coffre enroll api-prod)" --service api --environment production
```

The code is a row in `enrollments` (section 11): its hash, its binding, who
minted it, and `expires_at` (`sessionDays`, at most 90). That date is when
its sessions end and a new deploy must enroll again. The binding's page
warns 3 days before.

**What a code allows, and what stops a copy:**

1. **Several sessions, at most `replicas` at once.** A code is not single-use,
   because Railway restarts a crashed container with the same variables, and
   a single-use code would turn every crash into an outage. Each use makes a
   session. If the code already has `replicas` live sessions, the oldest is
   *fenced*: it is revoked (`token.revoke`, `reason: 'fenced'`) in the same
   transaction, under the log head, so two racing exchanges never leave
   `replicas + 1` live sessions.
2. **Contention freezes.** A fenced session that the gate saw within the last
   2 minutes was alive. Someone else is using the code, so Coffre freezes the
   binding (`workload.freeze`, `reason: 'contention'`) and alerts. The SDK
   re-enrolls on `fenced` by itself. A thief who fences an idle replica
   therefore gets fenced back as soon as that replica next speaks, and that
   second fence is contention. **A freeze is the default answer to a copy:
   an outage is better than a silent thief.** It is lifted by hand (section
   8.2). Setting `onContention: 'alert'` keeps the service up and only alerts.
3. **Supersession.** The newest code of a binding fences every older code 2
   minutes after the newest code's first session. That gives a rolling deploy
   two minutes of overlap. After that, older codes enroll nothing and their
   sessions end. This is derived on each check: an older code is dead once a
   newer one has a session older than the overlap. No job runs and nothing is
   copied.
4. **`sources`.** CIDRs checked at the exchange and on every request, against
   the address Coffre's per-source limiter already reads. On Railway Pro,
   static outbound IPs per environment make this a real attestation: a thief
   must run code inside that Railway environment. Render's outbound
   addresses are shared per region, which narrows the risk but proves
   nothing.
5. **Alerts on every enrollment.** Each new session is a `workload.alert`
   `{ kind: 'enrolled', ip, code }`, delivered at once (section 8.3). A
   restart at 3 a.m. produces one quiet line. An enrollment from an unknown
   address is the one to look at.
6. **`approve: true`**, for workloads that rarely restart. Each session
   starts `pending`: the exchange answers 202
   `{ "pending": "<session id>", "approve": "<page URL>" }`. The SDK retries
   the exchange with the same key every 5 s for up to 10 minutes, and a
   manager approves on the page or with `coffre approve <id>`. Each approval
   is audited.

**What it cannot prevent, stated in the binding's page and the docs:**

- An attacker with the code who enrolls while every real replica is down and
  never makes a request that fences one. They get an `enrolled` alert from
  their own address, and `sources` stops them if it is set.
- An attacker running *inside* the service, the rows D and F of every
  platform.
- A compromised CI minting codes for itself (column E). The mint is logged as
  CI's own act, naming the run.

## 5. Sessions: DPoP, the gate, renewal

### 5.1 The key and the proof

The SDK makes `crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])`
once per process. It exports only the public JWK. The key is never written,
logged, put in env or sent anywhere. **Thumbprint:** `jkt` is the
base64url SHA-256 of `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`, the
RFC 7638 form, 43 characters.

**Every request** carries the session token and a fresh proof:

```http
POST /use/stripe/v1/charges HTTP/1.1
Host: secrets.acme.example
Authorization: DPoP coffre_wl_7mQ4…
DPoP: <base64url(header)>.<base64url(payload)>.<base64url(r || s)>
```

```json
{ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
{ "jti": "pA6p8w2Yb3fQe1kHn0S9qg", "htm": "POST", "htu": "https://secrets.acme.example/use/stripe/v1/charges",
  "iat": 1792805400, "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", "nonce": "g1.7Hq2…" }
```

**The verifier** (`verifyProof` in core) checks, cheapest first:

1. **Shape.** The proof is at most 1 KiB. `typ` is exactly `dpop+jwt` and
   `alg` exactly `ES256`.
2. **The key.** `jwk` has exactly `kty`, `crv`, `x` and `y`, a point on the
   curve, and no `d`.
3. **The claims.** `jti` is 22 base64url characters (16 bytes). `iat` is an
   integer.
4. **The session.** The session row comes from the token's hash, as for any
   credential (one indexed read, shared with the checks in 5.3).
5. **Key and signature.** `thumbprint(jwk) === row.jkt`, then the signature
   over the JWS signing input.
6. **What was signed.**
   - `htm` equals the method.
   - `htu` equals the request's URL as `publicUrl` spells it: scheme and host
     lowercased, no default port, no query or fragment, and the path as
     received, percent-encoding untouched.
   - `ath` equals base64url(SHA-256(token)).
   - `iat` is within ±300 s. The nonce, not the clock, is what makes a proof
     fresh.
7. **The gate** checks the nonce and the `jti` (5.2).

Two ES256 signatures of one payload, `(r, s)` and `(r, n−s)`, both verify.
They carry one `jti`, so the gate refuses the second, and a property test
holds this (section 12, PR 0).

**Refusals** are `401` with
`WWW-Authenticate: DPoP error="invalid_dpop_proof"` and a JSON `reason`, or
`error="use_dpop_nonce"` with a fresh `DPoP-Nonce` header, as RFC 9449
section 9 has it. The SDK retries `use_dpop_nonce` once with the new nonce,
and treats every other refusal as final.

**Why DPoP and not a scheme of our own.** It is a standard with libraries
in every language, so a sidecar in Go or a client in Python can speak it.
What it lacks, binding the body, is section 5.5's honest limit and not worth
a custom format.

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
  app process, as `examples/node` does. Several processes would each hold a
  gate of their own, with different nonces, and clients would bounce between
  them. The docs say so, and the gate's nonce makes it fail loudly rather
  than unsafely (below).

**Nonces are epochs.** A gate draws a random `epoch` when it starts and
rotates it every 5 minutes. Its nonce is `g<n>.<epoch>`, 16 random bytes in
base64url after the rotation's count `n`. It need not be secret: it only
names an epoch, and a proof must still be signed by the session's key. It accepts proofs carrying the current or the
previous nonce, and remembers the `jti`s seen under each, for at most 10
minutes of memory per workload. Everything else answers `use_dpop_nonce`
with the current nonce.

- **A restart or eviction forgets nothing that matters.** A new epoch means
  every proof made before it carries an unknown nonce and is refused, so no
  proof seen before the restart can ever pass again. No `jti` is persisted,
  no clock is trusted, and a client pays one retry.
- **Memory is bounded** by the rate: a workload at 1,000 requests a second
  holds at most 600,000 `jti`s of 16 bytes, about 10 MB, inside a Durable
  Object's 128 MB. The gate refuses with 429 past 2,000 requests a second per
  workload, a limit a deployment may raise.

**The gate's interface:**

```ts
interface Gate {
  admit(request: {
    session: string; jkt: string; jti: string; nonce: string;
    ip: string; credential?: { place: string; name: string };
  }): Promise<
    | { ok: true; nonce: string }
    | { ok: false; reason: 'use_dpop_nonce'; nonce: string }
    | { ok: false; reason: 'replayed' | 'limit' | 'busy' }
  >;
  seen(session: string, withinMs: number): Promise<boolean>;  // enrollment contention
}
```

**Live counters** (section 8.1) live in the same object, so one call does
both: replay and limits.

**The gate is not the source of truth for any decision a person made.**
Freezes, revocations and grants are in the database and the log, read on each
request (5.3). If the gate is lost, it costs a nonce retry and resets
counters. It never lets anything through.

### 5.3 Every request, checked live

A workload request is never answered from a cache of its authority. Per
request:

1. The token's row: `kind = 'workload'`, not revoked or expired, `not_after`
   not past, its MAC, and `approved_at` set where its binding says `approve`.
   Its binding stands: MAC, no revocation, no tombstone, as for an exchanged
   credential today. Its ancestors stand (section 8.4). Its enrollment is not
   superseded (4.4). Its source is within `sources`.
2. The proof (5.1) and the gate (5.2).
3. **No freeze** names the instance, the service, the binding, the session or
   the credential being used (section 8.2).
4. `vault.access(principal)`, as for every request today.

Steps 1 and 3 are one SQL statement: the row, its binding, its ancestors,
its enrollment's supersession and the freezes, joined through their indexes.
`request-cost.test.ts` holds a workload request to the same number of
statements as a handle's.

Only after that does the proxy look in its value cache. Keyed by session,
it holds an opened value for `cacheSeconds` (60), as it does for handles. So
a revocation, a freeze or a lost grant takes effect on the **next request**.
An open Postgres tunnel ends at its next recheck: at most `recheckSeconds`,
and the recheck now includes the freeze.

### 5.4 Lifetime and renewal

- **`expiresAt`: one hour.** Renewal proves possession of the key:
  `POST /api/auth/workload/renew` with the session's own `Authorization` and
  a proof. It answers `{ "expiresAt": … }`, an hour from now and never past
  `notAfter`, and updates the row's `expires_at` under its MAC. Renewal has no
  entry of its own: the gate counts it, and the session's last use shows it.
  The SDK renews at half-life. A process that died stops renewing, and its
  session ends within the hour, so "live sessions" means live processes.
- **`notAfter`: the hard end.**
  - `oidc` and `aws`: the binding's `sessionHours`, 24 unless set, at most
    168.
  - `enrollment`: the code's `expires_at`.
  - Before `notAfter`, the SDK **re-proves**. It exchanges a fresh platform
    proof (a re-read projected token, a new metadata token, a new signed
    `GetCallerIdentity`) with the *same* key, and swaps sessions. Requests in
    flight finish on the old one. A deleted Kubernetes service account or IAM
    role therefore stops working within `sessionHours` even without any
    action in Coffre.
- **Why the token is long-lived when Erwin finds 5 minutes too long.** A
  bearer credential's lifetime is its exposure, so it must be short. A
  key-bound token's exposure is the key's, and a copied token is worthless at
  any age. What bounds a stolen *capability* here is the proof: accepted
  once, for one method and URL, within one nonce epoch. Lifetime only bounds
  forgotten sessions.
- **Ending one.** `POST /api/auth/logout` with DPoP revokes the session. The
  SDK calls it on `SIGTERM`.

### 5.5 What the proof does not bind

DPoP binds the method and URL, not the query string or the body. Take an
attacker who can *modify* traffic between the app and Coffre, not only read
it. They can drop a request and send its proof with a different body or
query, once, within the nonce epoch. That is a man in the middle of TLS, and
with one they could equally make the app's own requests say whatever they
like. A passive copy is refused, because the original spends the `jti` first
(or the copy does, and the original's failure is loud). Binding the body
would break streaming uploads, so the design leaves it at that.

## 6. Use-only, and the escape hatch

### 6.1 The rule

**A workload session reads no value, except a plain one or one its binding
lists in `reads`.** Everything else it uses through Coffre. Here is the
precedence, for a session whose binding gives `viewer` on `market/prod`:

| The key in `market/prod` | Without `reads` | With `reads: { "market/prod": { "keys": ["STRIPE_WEBHOOK_SECRET"] } }` |
|---|---|---|
| `TWILIO_SID`, plain | read | read |
| `STRIPE_SECRET_KEY`, secret | use | use |
| `STRIPE_WEBHOOK_SECRET`, secret | use | **read**, flagged "exposed if Railway is breached" |
| `DATABASE_URL`, sensitive | use (the tunnel) | read only if listed *and* an Owner of `market` made the binding (R32, unchanged) |

- **Where it is enforced.** Both the app and the vault enforce it, as R16's
  sensitivity is.
  - The app refuses, at its routes, every credential of kind `workload`
    outside `WORKLOAD_ROUTES` (renew, narrow, logout and `GET /api/me`), with
    reason `workload`, as it refuses handles.
  - The proxy's plan gives the app only the plain keys and the listed ones.
  - The vault gets each place's `reads` in the credential scope it is passed
    already (`Through`), beside R32's `sensitive`. It refuses every purpose
    that hands a value back (`handsBack`) unless the key's name is listed, with
    code `use_only`.
  - The vault trusts the app's scope as it trusts it today. Column G2 is
    unchanged.
- **The escape hatch is per binding, per place, per key.** `keys` lists names
  exactly. `"*"` means every key of the place, the per-environment hatch,
  and the page shows it in red. A sensitive key listed still needs an
  Owner-issued binding.
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

**`useOnly: true`** makes a service unable to read anything but plain values:

- **No bearer service credential.** `POST /members/:member/tokens` refuses to
  issue a service token. Existing `coffre_svc_` tokens are refused at use,
  with reason `use_only`. `POST /api/auth/oidc` answers 410 and names
  `/api/auth/workload`.
- **No `reads`** on any binding: a binding that has some is refused at
  creation, and refused at use while `useOnly` is on.
- **People are unchanged.** Their sensitivity rules are R16's.

Without `useOnly`, nothing that exists today changes. Bearer service tokens
and `/api/auth/oidc` keep reading as R13 and R32 say. `coffre init` writes
`useOnly: true` for new deployments: that is the pit of success. An existing
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
4. **Turn on `useOnly`** once the binding pages show no `reads` and no bearer
   token is live. Decision D8 records what to remove one release later
   (expand, then contract).

## 7. Use: what Coffre does for the workload

### 7.1 What exists, now for workloads too

The proxy (`/use/<credential>/<path>`), `sign`, `presign`, shaped
placeholders and the Postgres tunnel all work for a workload session exactly
as for a handle, with three differences:

- **How the caller authenticates.** The workload is the
  `Authorization: DPoP` header and its proof, never a value in the
  credential's slot. The proxy drops `Authorization` and `DPoP` before
  forwarding, then fills the rule's slot as today. The check that refuses the
  handle anywhere else in the request now refuses the workload token
  anywhere else.
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
  allowed `workload.freeze` or `workload.unfreeze` entry is a freeze. The
  per-request check is an index lookup on
  `audit_log_freeze_idx (metadata->>'target', seq DESC) WHERE action IN (…) AND decision = 'allow'`.
  The log is the one place the state lives, under its MACs and chain. A
  database owner who deletes a freeze entry breaks the chain, which the next
  verification finds, the same limit as a tombstone's.
- **A freeze is also a push.** The route tells the workload's gate, which
  closes its open tunnels at once. Without the push they would end at their
  next recheck, within `recheckSeconds`.

### 8.3 Alerts

`workload.alert` app entries, each `{ kind, service, binding, session, ip, … }`:

| `kind` | When |
|---|---|
| `enrolled` | a session made from an enrollment code |
| `contention` | 4.4, beside the automatic freeze |
| `new_source` | a session of a long-lived workload (enrollment, or a binding with `sources`) used from an address it has not used before. Serverless platforms change addresses constantly, so other sessions do not alert. |
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
  /** A fetch that signs requests under <url>/use/ and passes anything else through: give it to any SDK that takes one. */
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
  `notAfter`, retry `use_dpop_nonce` once, and re-enroll on `fenced`. The
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
  audit's `credentialId` is `binding:<id>`.
- **The trust root is whoever can deploy Workers to the account.** They can
  set any `props`, and they could equally deploy Coffre itself. An account
  whose Workers deployers should not reach Coffre's services needs Coffre in
  an account of its own. Then service bindings do not cross accounts, and
  its Workers use `enrollment`. The binding's page says this. As of
  2026-10, Cloudflare's API and Terraform may not carry `props` for service
  bindings: deploy with wrangler.

```ts
// the app Worker: OpenAI's SDK through coffre, no key anywhere
const openai = new OpenAI({ apiKey: 'coffre', baseURL: 'https://coffre/use/openai', fetch: (input, init) => env.COFFRE.fetch(new Request(input, init)) });
const { signature } = await env.COFFRE.sign('dfns-key', challenge);   // RPC: sign, verify, presign, mint, narrow
```

The host in `baseURL` is ignored, because the binding is the route. The
proxy's code is the same; only the authentication differs.

### 9.3 `coffre serve` and `coffre run`: any language, any container

`coffre serve` is the sidecar: a CLI process that holds the session and
listens locally.

```sh
coffre serve --url https://secrets.acme.example --service api-prod --proof kubernetes:/var/run/secrets/coffre/token --listen 127.0.0.1:7300
```

- **HTTP.** `http://127.0.0.1:7300/use/<credential>/<path>` is forwarded with
  DPoP, so the app's config names that URL. R14 holds: the app chooses its
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

R27's target is under 10 ms of CPU at p50. A workload request adds this to a
handle's:

| Step | CPU (to be measured in PR 1, `pnpm bench:workers`) |
|---|---|
| Parse the proof, SHA-256 the token for `ath` | ~20 µs |
| Import the `jwk` (cached per isolate by `jkt`, as a settled value) | ~50 µs cold, 0 warm |
| One ES256 verify (BoringSSL in workerd) | ~100–200 µs |
| The gate's RPC, from the caller's side | ~10 µs |
| The freeze, ancestor and enrollment checks | folded into the credential's one statement |

So the budget is under 0.5 ms of CPU and one round trip to the gate, inside
the database's region. The bench reports both cold and warm, and
`request-cost.test.ts` adds a workload case.

## 11. Data model and migration

One migration, `0015_workload_access`, for both engines. It only **adds**
(AGENTS.md, "expand, then contract"), and code of 0.11 serves on it unchanged.

**`credentials`:**

| Change | What |
|---|---|
| `credentials_kind_check` | widened with `'workload'` |
| `credentials_kind_matches_principal` | becomes `(kind IN ('service','workload')) = (principal LIKE 'token:%')`. Only looser; existing rows pass. |
| `jkt text NULL` | the key's thumbprint. A new check, `kind <> 'workload' OR jkt IS NOT NULL`, which no existing row or old writer can break. |
| `not_after timestamptz NULL` | the hard end (5.4) |
| `ancestors text NULL` | JSON array of credential IDs, root first (8.4) |
| `constraints text NULL` | canonical JSON of a child's limits (8.4) |
| `enrollment_id uuid NULL REFERENCES enrollments(id)` | the code that made it (4.4) |
| `approved_at timestamptz NULL`, `approved_by text NULL` | for `approve` bindings (4.4) |
| index `credentials_enrollment_idx (enrollment_id, created_at) WHERE kind = 'workload'` | fencing and supersession |

- **Grants.** The runtime login gets no `UPDATE` on `jkt`, `not_after`,
  `ancestors`, `constraints` or `enrollment_id`, as for `places`. It gets
  `UPDATE` on `expires_at` (renew) and `approved_*`.
- **MAC tuple.** A new kind, `workload_credentials`, in `auth-rows.ts`. It
  covers the fields of today's tuple, plus `jkt`, `not_after`, `ancestors`,
  `constraints`, `enrollment_id` and `approved_at`.

**`service_bindings`:**

| Change | What |
|---|---|
| profile check | widened with `kubernetes`, `gcp`, `azure`, `fly`, `vercel`, `aws`, `enrollment`, `cloudflare` |
| `policy text NULL` | canonical JSON, keys sorted, of `{ audience?, keyAudience?, reads?, sources?, sessionHours?, replicas?, sessionDays?, mintedBy?, approve?, onContention? }`. Each profile allows a fixed subset, checked by `checkPolicy` in core. Immutable like the rest of the binding, with no `UPDATE` grant. |

The MAC tuple is a new kind, `policed_service_bindings`, chosen when
`policy` is non-null, as `uploaded_service_bindings` is for `jwks`. For the
non-OIDC profiles, `issuer` and `jwks_uri` hold their URN, `urn:coffre:aws`,
`urn:coffre:enrollment` or `urn:coffre:cloudflare`. That satisfies `NOT NULL`
and keeps "one key source per issuer" a single-column comparison.

**`enrollments`**, a new table:

```sql
CREATE TABLE enrollments (
  id uuid PRIMARY KEY,
  auth_mac bytea NOT NULL,               -- tuple 'enrollments': id, binding_id, code_hash, created_by, expires_at
  binding_id uuid NOT NULL REFERENCES service_bindings(id),
  code_hash bytea NOT NULL UNIQUE,       -- SHA-256 of coffre_enr_…
  code_hint text NOT NULL,
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

- New app actions: `workload.freeze`, `workload.unfreeze`, `workload.alert`
  and `credential.mint`.
- `token.create` gains `kind: 'workload'`, with `parent` for a child.
- `token.exchange` gains `proof`.
- `token.revoke` gains `reason: 'fenced'`.
- The migration adds `audit_log_freeze_idx` (8.2). On SQLite it is
  `json_extract(metadata, '$.target')`.

**Nothing is removed or tightened.** The contract step, D8, would come one
release after `useOnly` has served everywhere: drop `/api/auth/oidc`, drop
the issuing of `coffre_svc_` tokens, and tighten nothing in the schema.

## 12. The build: PRs, owners, tests

PR 0 goes first and fast, because everyone else compiles against it. After
it, PRs 1, 2, 5, 6 and 8 run in parallel. PRs 3, 4, 7 and 9 start once PR 1
has merged: they touch the exchange and the proxy that PR 1 reshapes. Each
PR owns its files, and a file another PR also needs is named under one owner
only, with the hook the other PR calls.

| PR | What | Owns | Tests |
|---|---|---|---|
| **0. Foundation** | `dpop.ts` in core (`createProof`, `verifyProof`, `thumbprint`, `canonicalHtu`); the token kinds; migration `0015_workload_access` for both engines and the schema; the MAC tuples; `BindingPolicy`, `checkPolicy` and the new profiles' `REQUIRED_CLAIMS`; the `Gate` interface type | `packages/core/src/identity/dpop.ts` (new), `…/identity/tokens.ts`, `…/identity/workloads.ts`, `packages/db/src/schema.ts`, `packages/db/src/migrations/*/0015_*`, `packages/db/src/grants.ts`, `packages/server/src/auth-rows.ts` | Hegel properties: proofs round-trip, and every single-field mutation is refused; the `(r, n−s)` twin has the same `jti`; the thumbprint is canonical whatever the JSON order; `canonicalHtu` is idempotent and keeps percent-encoding; `checkPolicy` is canonical (one digest per policy). The migration applies on both engines, and 0.11's suite passes on the new schema (`pnpm test:compat`). |
| **1. Sessions** | `POST /api/auth/workload` (`oidc` proof, with the audience naming the key), renew, logout; `authenticateRequest`'s DPoP path and `WORKLOAD_ROUTES`; the vault's `reads` and `use_only`; `PluginContext.workload` and `use(caller)`; the proxy, `sign`, `presign` and the tunnel accepting a workload caller; the Node gate and the `CoffreGates` Durable Object (nonces, `jti`); the one-statement check of 5.3 (freeze clause included, reading the index PR 0 made); `useOnly` | `packages/server/src/api/workloads.ts` (the exchange and its `verifyProof` dispatch), `…/auth.ts`, `…/auth-routes.ts`, `…/api/signin.ts`, `…/plugins.ts`, `…/plugins/credential-proxy.ts`, `…/gate.ts` (new), `…/cloudflare-gates.ts` (new), `packages/vault/src/vault.ts`, `packages/core/src/vault.ts`, `packages/core/src/access.ts` | An exchange per proof shape; a token without its key is refused; a replayed proof is refused, including across a gate restart (a new epoch); `use_dpop_nonce` then success; refusal outside `WORKLOAD_ROUTES`; the vault refuses `reveal` with `use_only`, and lets listed keys through; revocation takes effect on the next request despite a warm value cache; `request-cost.test.ts` statements; `bench:workers` numbers in the PR. |
| **2. Proofs** | the `aws` verifier; the `kubernetes`, `gcp`, `azure`, `fly` and `vercel` profiles; `coffre trust --aws/--kubernetes/--gcp/--azure/--fly/--vercel` | `packages/server/src/workloads/aws.ts` (new), `…/workloads/profiles.ts` (new; PR 1's dispatch calls `verifyAws`), `packages/cli/src/trust.ts` | A fake STS that checks SigV4 with `@smithy/signature-v4`; `x-coffre-key` not among `SignedHeaders` is refused; another region host, a non-STS URL and a redirect are each refused; the spent signature; fixture tokens per profile, each with a required claim missing refused; a recreated role (new `AROA…`) refused. **Live:** a GetCallerIdentity signed with the `erwinkn-mgmt` SSO credentials against real STS (no resources), and a throwaway Lambda's role (`coffre-ovn-<W#>`, deleted after). |
| **3. Enrollment** | the `enrollments` routes; `coffre enroll` and `coffre approve`; fencing, contention, supersession, `sources`, `approve` | `packages/server/src/api/enrollments.ts` (new), the `enrollment` branch of the dispatch (one function PR 1 leaves as a stub), `packages/cli/src/enroll.ts` (new) | Concurrency: N exchanges racing on one code never leave more than `replicas` live, on both engines; contention freezes and the next use is `frozen`; supersession after overlap; the overlap window works; `sources` refused at the exchange and per request; `pending` → approve → use. **Live:** a throwaway Railway project (`coffre-ovn-<W#>`): enroll, restart, copy the code to a second service, watch it freeze. |
| **4. Live policy** | the freeze routes and pages; `limit` in the gate; alerts and `alert(…)` delivery; `narrow` | `packages/server/src/api/freezes.ts` (new), `…/api/narrow.ts` (new), `…/alerts.ts` (new), the counters' half of `gate.ts` (after PR 1), `packages/cli/src/freeze.ts` (new) | Freeze then the next request refused, on HTTP and on a tunnel within one recheck (pushed: at once); lift restores; who may freeze or lift; narrow ⊆ parent (a Hegel property over random constraints); a child dies with any ancestor; a child cannot read, mint or renew; limits with 429 and one alert per window. |
| **5. SDK and sidecar** | `@coffre/client/workload` and its proofs; `fromCoffre`; `…/workload/postgres`; `coffre serve`; `coffre run --service` in key-bound mode | `packages/client/src/workload.ts` (new), `…/workload-proofs.ts` (new), `…/workload-postgres.ts` (new), `packages/cli/src/serve.ts` (new), the workload branch of `packages/cli/src/workload.ts` | Against a fake server first (the doc's wire format), then the real one once PR 1 lands: renew at half-life, re-prove before `notAfter`, the nonce retry, re-enroll on `fenced`; OpenAI's and Stripe's SDKs through `coffre.fetch`; `pg` through `connect`; the key is non-extractable (`exportKey` rejects); nothing written to disk or env. The packed client still loads on Node 20, 22 and 24 (`test:consumer`). |
| **6. Cloudflare** | `CoffreWorkload` (`WorkerEntrypoint` with `props`); the `cloudflare` binding; `coffre init` and the examples' wiring of `GATES` and the entrypoint | `packages/server/src/cloudflare-workload.ts` (new), `packages/server/src/cloudflare-handler.ts`, `examples/workers/*`, `packages/cli/src/init.ts` | A miniflare test with two Workers, props naming a service with and without a binding; freeze; limits. Conformance: a Worker with props for an unbound service gets nothing. **Live:** two throwaway Workers on Erwin's personal account (`d56cef42…`), `coffre-ovn-<W#>-*`, deleted and verified gone. |
| **7. Minting and `verify`** | `minters` (`assumeRole`, `githubInstallation`, `r2Temporary`); `{mint:…}` in rules; `sigv4({ minted })`; the `mint` and `verify` operations; `hmac` and `stripeSignature` | `packages/server/src/plugins/mint/*.ts` (new), `…/plugins/verify.ts` (new), the `mint` and `verify` cases of `credential-proxy.ts`'s `compute` (after PR 1) | A fake STS and a fake GitHub; caching until 60 s before expiry, settled values only; delivered mint refused unless listed; `credential.mint` entries; Stripe's own test vectors for `stripeSignature`. **Live:** `AssumeRole` into a throwaway role (`coffre-ovn-<W#>`), deleted after. |
| **8. Formal** | `formal/Workload.tla` and its configurations; `docs/formal.md`'s section | `formal/Workload*.tla`, `formal/Workload*.cfg`, `docs/formal.md` | Section 12.1: each invariant holds, and each fails without its protection. |
| **9. Pages** | the binding forms for the new profiles; `reads` flagged per platform; a service's sessions, with their last address; the Freeze buttons; the alert filter | `packages/ui/src/pages/*` (the service page and its dialogs) | The UI suite. The page shows "exposed if <platform> is breached" for every listed key. |

**Docs.** Each PR updates the docs for what it builds. PR 5 writes
`docs/workloads.md`, the per-platform guide (section 9.4 and the playbook,
7.3).

### 12.1 Verification

**Model checking**, `formal/Workload.tla`, TLC as `pnpm formal` runs it. The
model has two workloads, two keys per workload, one attacker who learns
every token, proof, platform token and enrollment code that crosses any
channel, but no private key, and gates that restart at any step. Each
invariant must hold, and must fail with its named protection removed:

| Invariant | Holds because | Fails without |
|---|---|---|
| `CopyIsUseless`: every accepted request was signed by the holder of its session's key | the proof's signature and `jkt` | checking `jkt` against the row |
| `ProofOnce`: no `(jkt, jti)` is accepted twice, across gate restarts | nonce epochs | the epoch (a restart forgets `jti`s) |
| `FreezeBound`: no use is accepted after a freeze of its target commits, and no tunnel byte flows after commit + `Recheck` | the per-request check, uncached | the check before the value cache (a cached session) |
| `RevokeBound`: the same for revoking a session, an ancestor, a binding or a member | the same | ancestors in the check |
| `Replicas`: live sessions per enrollment ≤ `replicas`, under concurrent exchanges | fencing under the log head | the head lock at the exchange's commit |
| `Superseded`: no session is made from, or used under, an older code once a newer code's session is older than the overlap | the derived check at exchange and per request | the per-request half |
| `NarrowSubset`: a child's rights ⊆ its parent's, at every state | intersection at creation, and ancestors checked live | the ancestor check (a parent narrowed by revocation) |
| `NotAfter`: no session is usable, or renewed, past `notAfter` | the row's `not_after` under MAC | the renew bound |

**Property tests** (Hegel, `pnpm test:properties`):

- DPoP mutations and the signature twin;
- the thumbprint;
- `canonicalHtu` against a reference over generated URLs;
- policy canonicalization;
- CIDR membership against a reference over generated addresses, IPv4 and
  IPv6;
- narrow intersection ⊆, over random constraint sets;
- a model-based test of the gate: random sequences of admit, rotate and
  restart against a reference set, and the reference must agree.

**Live tests**, each throwaway and named `coffre-ovn-<W#>`, within $5 per
worker, deleted and then verified gone through the provider's API:

| Platform | Test | Covered by |
|---|---|---|
| Cloudflare | two Workers, a binding with `props`, an upstream call through the proxy, freeze | PR 6 |
| AWS | `GetCallerIdentity` from SSO credentials; a Lambda's role; `AssumeRole` minting | PRs 2, 7 |
| Railway | enrollment, restart, a copied code, contention freeze | PR 3 |
| Kubernetes | a `kind` cluster in Docker with the sidecar | PRs 2, 5 |
| GitHub Actions | a workflow in a scratch repository of erwinkn, with `id-token: write` and the audience naming the key | PR 5 |
| Google Cloud, Azure, Fly, Vercel | **not live.** There is no account for them tonight, so they are covered by fixture tokens shaped from each platform's documentation. Their first real use should include a live check. | PR 2 |

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
   - (d) **one object per workload**, which also holds limits and liveness.

   (d) has a ceiling of about 2,000 requests a second per workload before
   sharding. *Reversible:* a workload past it gets several gates, by session
   hash, with limits split.
3. **Workloads read only what their binding lists.** The list lives on the
   binding, because the exposure belongs to the platform. *Alternative:* a
   fourth key level, `sealed`, which would decide by key and not by where
   the value lands, and would not distinguish Cloudflare from Railway.
4. **Enrollment codes are multi-use within `replicas`, with fencing and a
   contention freeze.** Single-use per boot turns every crash into an
   outage. *Reversible:* `replicas: 1` with `approve: true` comes close to
   single-use.
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
- **Body binding** for buffered requests, a `bh` claim, if a deployment
  needs it against an active man in the middle.
- **Railway, Render and Heroku profiles**, the day those platforms sign a
  workload identity. Each one replaces enrollment there.

# Workloads

A workload is an app or a job that uses coffre without a person: a server on
Railway, a pod, a Lambda, a CI run. It proves who it is with its platform's
own identity and gets a session bound to a key that never leaves its
process. The session is use-only. The app calls Stripe or OpenAI through
coffre, which adds the real key on the way out, so the app never holds it.
The platform's variable store holds nothing, or a single enrollment code on
a platform that has no identity to prove.

On Railway, with Node:

```ts
import { workload, enrollment } from '@coffre/client/workload';

const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: enrollment(process.env.COFFRE_ENROLL) });
const charge = await coffre.credential('stripe').fetch('/v1/charges', { method: 'POST', body: new URLSearchParams({ amount: '2000', currency: 'eur' }) });
```

Someone who copies Railway's variables gets `COFFRE_ENROLL`. It works only
through coffre, raises an alert the moment it is used, and stops working once
the next deploy promotes a new code. Stripe's key was never there to copy.

The design, its threat model and every rule behind this guide are in
[docs/design/workload-access.md](design/workload-access.md).

**What is built.** The SDK, `coffre serve` and key-bound `coffre run` are.
The server side lands in its own changes: the exchange and sessions, the new
`coffre trust` flags, enrollment codes (`coffre enroll`), freeze and
`narrow`, the Workers binding, minting and `verify`. Until an instance
answers the workload exchange, `coffre --service … run` falls back to the
bearer exchange [ci.md](ci.md) describes.

## The SDK: Node, Bun, Deno

`@coffre/client/workload` has no dependencies and runs on Node 20 and later,
Bun and Deno. The common case is two lines:

```ts
import { workload, kubernetes } from '@coffre/client/workload';

const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: kubernetes() });
```

| Option | What it is |
|---|---|
| `url` | The instance, `https://secrets.acme.example`. |
| `service` | The service account it signs in as, `api-prod` or `token:api-prod`. |
| `proof` | How it proves who it is: `kubernetes()`, `aws()`, `gcp()`, `azure({ audience })`, `fly()`, `vercel()`, `github()`, `oidc(token)` or `enrollment(code)`. |
| `place` | Which environment `url()`, `credential()` and `read()` mean when the binding reaches several: `market/prod`. |
| `fetch` | The `fetch` it sends with, for tests or odd runtimes. |
| `log` | Where it says what it is waiting for. Standard error unless set. |

`workload()` rejects with a `CoffreError` if the first exchange is refused.
The error carries the status and the server's reason, as `superseded` or
`source`.

### Any SDK that takes a base URL

```ts
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
```

`coffre.url('openai')` is `https://secrets.acme.example/use/openai`, or
`…/use/market/prod/openai` when the session reaches several environments.
`coffre.fetch` signs every request under `<url>/use/` (method, URL, query,
headers and body) and passes any other request through untouched. The
`apiKey` is only there because OpenAI's constructor wants one. `coffre.fetch`
replaces the `Authorization` header with the session's, and coffre's proxy
puts the real key in its place.

### One credential

```ts
const stripe = coffre.credential('stripe');
const refund = await stripe.fetch('/v1/refunds', { method: 'POST', body: new URLSearchParams({ charge: 'ch_1' }) });

const signature = await coffre.credential('dfns-key').sign(challenge);               // base64url; the private key stays in coffre
const valid = await coffre.credential('stripe-webhook').verify(rawBody, stripeSignature); // the webhook secret is never read
const { url } = await coffre.credential('s3').presign('/uploads/report.pdf', { expiresIn: 900 });
const { token } = await coffre.credential('github').mint<{ token: string }>();        // where the binding lists the minter
```

A credential's `fetch` reaches its own upstream only: a path that climbs out of
it (`/../stripe/…`, from an object key or a file name) is refused before
anything is sent. `presign` gives the upstream's own URL, usable by anyone
until `expiresAt`.
`mint` answers only where the binding's `reads` lists the minter.

### `read`: the escape hatch

```ts
const sid = await coffre.read('TWILIO_SID');
```

A workload reads plain values, and the secrets its binding lists in `reads`.
Anything else rejects with a `CoffreError` whose reason is `use_only`. For a
binding that gives `viewer` on `market/prod`:

| Key in `market/prod` | Without `reads` | With `STRIPE_WEBHOOK_SECRET` in `reads` |
|---|---|---|
| `TWILIO_SID`, plain | read | read |
| `STRIPE_SECRET_KEY`, secret | use | use |
| `STRIPE_WEBHOOK_SECRET`, secret | use | read, and the binding's page says "exposed if Railway is breached" |
| `DATABASE_URL`, sensitive | use, through the tunnel | read only if listed and an Owner of `market` made the binding |

`reads` belongs to a binding, so the same service can read nothing on
Cloudflare and hold one webhook secret on Railway. Most reads have a
use-only replacement: `verify`, `sign`, or the tunnel.

### The AWS SDK

```ts
import { S3Client } from '@aws-sdk/client-s3';
import { fromCoffre } from '@coffre/client/workload';

const s3 = new S3Client({ region: 'eu-west-3', credentials: fromCoffre(coffre, 'aws') });
```

`fromCoffre` mints a session from the `aws` minter and keeps it until a
minute before it expires. The parent keys stay in coffre, and the binding
must list the minter. For ordinary calls, prefer a credential coffre signs
with SigV4 itself, so nothing leaves. Delivered minting is for traffic that
should not pass through coffre, such as gigabyte S3 objects.

### Postgres

```ts
import pg from 'pg';
import { connect } from '@coffre/client/workload/postgres';

const pool = new pg.Pool({ stream: () => connect(coffre, 'db') });
```

`connect` gives node-postgres a stream over the tunnel's WebSocket, signed
by the session. There is no listener, no password and no database URL in
the app: coffre logs in to the database. It uses the runtime's own
`WebSocket` (Node 22 and later, Bun, Deno). Node 20 has none, so pass the
`ws` package's: `connect(coffre, 'db', { WebSocket })`. A coffre on Workers
paces the bytes both ways. One on Node does not, and only the `ws` package's
WebSocket can pause it while the app reads nothing, so pass that one there
for results larger than memory.

### `narrow`

A part of the app that needs less, such as an AI agent's tool sandbox, gets
a session with less:

```ts
const refunds = await coffre.narrow({ credentials: ['stripe'], methods: ['POST'], paths: ['/v1/refunds'], expiresIn: 600, label: 'refund-agent' });
await refunds.credential('stripe').fetch('/v1/refunds', { method: 'POST', body });
```

The child has a key of its own. It reaches only what both it and its parent
allow, matches `paths` by whole segments (`/v1/refunds` admits
`/v1/refunds/re_1`, never `/v1/refundsX`), cannot read, mint or renew, and
ends when its parent ends. For a child in another process, that process
makes the key and sends only its public half:
`coffre.narrow({ …, key: publicJwk })` answers `{ token, expiresAt }`, which
it uses with its own key.

`await coffre.close()` logs out, and the session's children end with it.

### What the SDK does on its own

- **Renews** at half-life, every 30 minutes for an hour-long session. An
  enrollment session lasts 90 seconds past its last renewal and renews every
  30 seconds, so a crashed process is gone from coffre within 90 seconds.
- **Proves again** with a fresh platform proof and the same key at 90% of
  the way to the session's hard end, `notAfter` (24 hours by default).
  Requests in flight finish on the old session.
- **Recovers a lost session.** If renewal is refused (revoked, frozen) or a
  process slept past expiry, as Lambda does between invocations, it proves
  again before the next request, with backoff from 1 second to a minute.
  A superseded enrollment code is final.
- **Signs with the newest nonce**, and sends a request once more if coffre
  asks for a fresh one. A stream cannot be sent twice, so it goes with a
  nonce under 100 seconds old.
- **Declares the body's digest.** A proof signs the body's SHA-256, so the
  SDK reads a body whole before it sends it, and sends its digest with it,
  `Content-Digest: sha-256=:<base64>:` (RFC 9530), and its length. Coffre
  then streams the body to the upstream instead of reading it whole, up to
  95 MiB (below). A stream that already declares both, as `coffre serve`
  sends one, goes as it is, never read here. A `Content-Digest` the app set
  itself stays as it is: a SHA-256 in it is the body's line, and one
  without (`sha-512` alone) declares nothing to coffre, so the body is read
  whole, up to 16 MiB.
- **Waits** for an enrollment code that is `full` (up to 5 minutes), for a
  person to approve a pending session (up to 10 minutes, every 5 seconds),
  and for the kubelet to write the next projected token when a restarted
  process finds the old one spent (up to 10 minutes). It says so once on
  standard error, or through `log`.
- **Follows redirects hop by hop**, signing each hop within coffre afresh,
  and sending a hop elsewhere with the app's own headers alone, never the
  session's, and, as fetch does, without the app's `Authorization` and
  `Cookie` once it leaves the origin. Its own calls to coffre, the
  exchange above all, follow no redirect.
- **Logs out on `SIGTERM`**, every session it proved, then lets the signal
  end the process if no other handler is listening. `close()` does the same
  on demand, waits at most 3 seconds for coffre to confirm, and rejects if
  it did not. A process that stops its own way passes `sigterm: false` and
  calls `close()` itself.

### What never happens

- The key is a P-256 key made with WebCrypto as non-extractable:
  `exportKey` rejects. The key, the session token and the nonce live in
  `workload()`'s closure and nowhere else.
- Nothing is written to disk or to the environment.
- No proof crosses plain HTTP: `workload()` takes an `https` URL, or an
  `http` one on this machine.
- `enrollment(code)` deletes the code from `process.env`, under whatever
  name held it, so the app's own environment dumps stop showing it. The
  platform's store still holds it.

## Each platform

Each section shows the app's side and the trust binding beside it. The
`coffre trust` flags here (`--aws`, `--kubernetes`, `--gcp`, `--azure`,
`--fly`, `--vercel`, `--cloudflare`, `--enrollment`) come with the
server-side proofs and enrollment changes. Today `coffre trust` takes
`--github`, `--gitlab` and `--issuer`. The binding pins the claims that
name one workload by IDs the platform never reuses, as
[section 4.2 of the design](design/workload-access.md#42-profiles-which-platform-claims-bind)
lists.

### Railway, Render, a VM

These platforms sign nothing, so CI mints an enrollment code for each
deploy, and the platform holds it.

```sh
coffre trust api-prod --enrollment --replicas 2 --source 162.220.232.0/24 --minted-by deploy
```

```sh
# CI, each deploy, as the service --minted-by names
railway variables --set "COFFRE_ENROLL=$(coffre enroll api-prod)" --service api --environment production
railway up --service api --environment production
coffre enroll api-prod --promote <code-id>    # once the deploy is healthy: the old code's sessions drain within 90 s
```

The app is the opening example. In another language, pipe the code to the
sidecar, which reads it from standard input and never from an argument:

```sh
printf %s "$COFFRE_ENROLL" | coffre serve --url https://secrets.acme.example --service api-prod --proof enrollment
```

Set `--replicas` to exactly what runs. A code admits twice that many
sessions, so a deploy can overlap old and new instances, and every new
session raises an `enrolled` alert naming its address. `--source` narrows
where a copy works from, but on Railway it is not proof of anything:
Railway's static outbound addresses may be shared with other customers. It
holds where the addresses are yours, such as a NAT gateway or a VM's static
IP. A coffre on Node needs `clientAddress(request)` configured for any
binding with sources. A rollback restores a superseded code, so the rollback
job mints and promotes a new one too.

### Cloudflare Workers

A Worker in the same account binds coffre's entrypoint, and its deploy
configuration names the service. There is nothing to prove and nothing to
store. This binding is built by a separate change (PR 6 in the design);
until it lands, the entrypoint answers 501.

```jsonc
// the app's wrangler.jsonc
"services": [{ "binding": "COFFRE", "service": "coffre", "entrypoint": "CoffreWorkload", "props": { "service": "edge-api" } }]
```

```ts
// the app Worker: OpenAI's SDK through coffre, no key anywhere
const openai = new OpenAI({ apiKey: 'coffre', baseURL: 'https://coffre/use/openai', fetch: (input, init) => env.COFFRE.fetch(new Request(input, init)) });
```

```sh
coffre trust edge-api --cloudflare
```

coffre's deployment exports the entrypoint,
`export const CoffreWorkload = coffre.Workload`, and the host in `baseURL`
is ignored. Whoever can deploy Workers to the account can set any `props`,
so keep coffre in an account of its own if those people should not reach its
services. Preview builds keep the Worker's bindings: turn off
non-production branch builds, or bind previews to a service of their own.
Deploy with wrangler, since Cloudflare's API and Terraform may not carry
`props` yet.

### Kubernetes

A native sidecar holds the session, so an app restart keeps it, and the
single-use projected token is read once per pod.

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

```sh
coffre trust api-prod --kubernetes …   # pins sub and kubernetes.io.serviceaccount.uid
```

For a private cluster, coffre takes the cluster's public keys with the
binding, as [kubernetes.md](kubernetes.md) does today. With the SDK
instead, mount the same volume in the app's container and use
`kubernetes()`, which reads `/var/run/secrets/coffre/token` unless given
another path. A restarted app finds that token spent and waits for the
kubelet's next one, which comes at 80% of the token's life (8 minutes with
600 seconds), so the sidecar suits apps that restart often.

### ECS, Lambda, EC2, EKS

```ts
import { workload, aws, fromCoffre } from '@coffre/client/workload';

const coffre = await workload({ url: 'https://secrets.acme.example', service: 'ingest', proof: aws() });
const s3 = new S3Client({ region: 'eu-west-3', credentials: fromCoffre(coffre, 'aws') });
```

```sh
coffre trust ingest --aws arn:aws:iam::671742253563:role/ingest-task
```

`aws()` signs an STS `GetCallerIdentity` with the role's credentials and
sends coffre the signed request, never the credentials. The signature covers
the session key, so the proof works for that key only. Credentials come from
the environment, the ECS endpoint or IMDSv2, or from an AWS SDK provider,
`aws({ credentials: fromNodeProviderChain() })`. The binding names the role
by its unique `AROA…` ID. IAM users are refused. On Lambda, call
`workload()` outside the handler, so a cold start pays one exchange.

### Google Cloud Run

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'web', proof: gcp() });
```

```sh
coffre trust web --gcp 104729384756102938475   # the service account's unique ID
```

`gcp()` asks the metadata server for an ID token of the default service
account, whose audience names the session key. A copied token is useless to
any other key. The same proof works on GKE and Compute Engine.

### Azure Container Apps, App Service, Functions

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'web', proof: azure({ audience: 'api://coffre-acme' }) });
```

```sh
coffre trust web --azure --tenant <tid> --object <managed identity's object id> --audience api://coffre-acme
```

`audience` is coffre's Entra application ID URI. Entra mints only for a
registered audience, so the token cannot name the key (see the limits).
`azure({ audience, clientId })` picks a user-assigned identity.

### Fly

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api', proof: fly() });
```

```sh
coffre trust api --fly …   # pins org_id and app_id
```

`fly()` asks the machine's `/.fly/api` socket for a token naming the key.

### Vercel

```ts
const coffre = await workload({ url: 'https://secrets.acme.example', service: 'web', proof: vercel() });
```

```sh
coffre trust web --vercel …   # pins owner_id, project_id and environment
```

Turn on OIDC federation for the project. `vercel()` takes the function's
token from `VERCEL_OIDC_TOKEN` and exchanges it at Vercel for one whose
audience names the session key. Where the runtime gives the token only in
the request's `x-vercel-oidc-token` header, pass a function that returns the
latest one: `vercel(() => latestToken)`. Pin `environment` to `production`
to keep preview deployments out.

### GitHub Actions

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/checkout@v4
  - run: coffre --url https://secrets.acme.example --service deploy run -- ./deploy.sh
```

In a GitHub Actions job, `coffre run` needs no `--proof`: it asks the runner
for an ID token naming the key. `--url` and `--service` go before the
command. `./deploy.sh` gets the plain values and the binding's `reads`,
`COFFRE_CREDENTIALS` with a local listener's URL for each credential, and a
local URL for each tunnel. A secret it may no longer read is named at once:

```text
coffre: market/prod: STRIPE_SECRET_KEY is used through coffre now; list it in the binding's reads if this job must hold it
```

In JavaScript, the proof is `github()`. The binding is the one
[ci.md](ci.md#github-actions) makes.

### GitLab CI

```yaml
deploy:
  id_tokens:
    COFFRE_ID_TOKEN:
      aud: https://secrets.acme.example
  script:
    - printf %s "$COFFRE_ID_TOKEN" | coffre --url https://secrets.acme.example --service api-deploy run --proof oidc -- ./deploy
```

`--proof oidc` reads the ID token from standard input. In JavaScript, the
proof is `oidc(process.env.COFFRE_ID_TOKEN)`. GitLab fixes the audience in the
job's YAML, so the token cannot name the key. It is spent once used, which
makes one session per job, ending at the token's own expiry. On an instance
without the workload exchange, keep the `coffre login --id-token` recipe in
[ci.md](ci.md).

### Any language

Run the sidecar beside the app, or wrap the app's command:

```sh
coffre serve --url https://secrets.acme.example --service web --proof gcp --listen 127.0.0.1:7300
coffre --url https://secrets.acme.example --service web run --proof gcp -- ./server
```

## The sidecar: `coffre serve`

```sh
coffre serve --url https://secrets.acme.example --service api-prod \
  --proof kubernetes:/var/run/secrets/coffre/token --listen 127.0.0.1:7300 --tunnel db=127.0.0.1:7432
```

| Flag | What it does |
|---|---|
| `--url` | The instance. |
| `--service` | The service account. |
| `--proof` | `kubernetes[:<file>]`, `aws`, `gcp`, `azure:<audience>`, `fly`, `vercel`, `github`, `enrollment` or `oidc`. The last two read their secret from standard input, never an argument or a variable. |
| `--listen` | Where the app reaches it: `127.0.0.1:7300` unless given, `[::1]:7300`, or `unix:<path>`. |
| `--tunnel` | `<name>=<host>:<port>`, a Postgres listener for the database tunnel `name`. Repeat it for each. |
| `--place` | Which environment the tunnels are in, `market/prod`, when the session reaches several. |

It signs in once, holds the session and its key in memory, and forwards each
request under `/use/` to coffre, signed, with its method, path, query,
headers and body as the app sent them. Anything else answers 404. It holds
no value, and writes no URL into the app's environment: the app's own
config names the listener.

**Bodies, and the sidecar's memory.** The proof signs the body's SHA-256
and goes out in the headers, so the sidecar reads a body whole before it
sends anything. It holds the body **in memory**, as the chunks it came in,
one copy, and hashes it as it comes. It never writes it to disk: a
signature or KYC document never lands on the pod's filesystem. It then
sends the chunks to coffre with the body's `Content-Digest` and length, and
coffre streams them to the upstream, checking the bytes against the digest
as they pass. A body is at most **95 MiB** (99,614,720 bytes), which the
sidecar refuses past with a 413 before sending anything. That is under the
100 MB (decimal) Cloudflare takes in one request on Free and Pro zones, so
a body near the limit gets coffre's answer, not the zone's. **Size the
sidecar's memory limit for the uploads you run at once**: the process's
own (about 120 MB at its peak in the test, signed in and idle), and up to
95 MiB more for each upload in flight. A 55 MB Yousign document raised the
sidecar's peak by 70 MB. An S3 upload, which
declares its own hash, streams through without being held, up to 5 GiB.

```sh
OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai
DATABASE_URL=postgres://app@127.0.0.1:7432/app?sslmode=disable
```

`POST /use/<project>/<env>` goes through the same way, which carries
`sign`, `verify`, `presign` and `mint`. A tunnel opens only for each
`--tunnel` named. Its password is empty: each WebSocket upgrade is signed by
the session instead.

Anything that can reach the listener uses the session, as anything in a
process can use the SDK's key. The boundary is the pod, or the container's
network namespace. On a shared machine, `--listen unix:/run/coffre/api.sock`
makes a socket of mode `0600`, which only the user running `coffre serve`
can open. `SIGTERM` or `SIGINT` logs out before the sidecar exits, so the
session ends with the pod.

`coffre --url <url> --service <name> run [--proof <proof>] [<project>/<env>…] -- <command>`
does the same for one command's life, on a port of its own, and the child
can use `credential(name)` from `@coffre/client/credential`.

## Upstreams that accept only coffre

Use-only protects a value only if its upstream refuses that value from
anyone but coffre. If Stripe accepts the same key from anywhere, a copy from
an earlier exposure still works. By kind of credential:

| The upstream's credential | Make it accept only coffre by | Examples |
|---|---|---|
| Issues short-lived children from a parent | Minting. The parent stays in coffre's vault, and the upstream sees only children. | AWS (`AssumeRole`), GitHub App installations, R2 temporary credentials, GCP service-account impersonation, Azure client credentials |
| A static key whose issuer can pin a source address | Pinning coffre's egress. On Workers, through a credential's `egress`: a VPC Service to a fixed-address host, or Cloudflare's dedicated egress where the account has it. Never Cloudflare's shared addresses, which would admit every Worker. | Stripe restricted keys (IP allowlist), AWS IAM users (`aws:SourceIp`), Cloudflare API tokens (client IP filtering), most banking APIs (Schuman) |
| A static key that cannot be pinned | Keeping it in the vault. Mark it sensitive, list it in no binding's `reads`, and rotate it on a schedule through the provider's API. A copy from an earlier exposure works until that rotation. | OpenAI project keys, most SaaS API keys |
| A database password | The network. `pg_hba.conf` or a firewall admits the role only from coffre's address ([credential-proxy.md, section 6](design/credential-proxy.md#6-security)). Minted logins come later. | Postgres |
| A key the workload must hold | Reading it: listed in `reads`, and flagged on the binding's page. Prefer a key whose upstream can pin source addresses. | An SDK with no base URL |

## Limits

- **Code inside the process is the workload.** A malicious dependency can
  call the key's `sign` through the SDK, and root on the host can read the
  process's memory or a fresh projected token. Non-extractable stops the key
  from being copied out, not from being used in place. What bounds these
  cases is use: per-credential limits, `narrow`, alerts and freezes. Neither
  reads a value the binding does not list.
- **An enrollment code is detection, not prevention.** A copy enrolls, and
  shares the code's slots until a person acts on the alert or the next
  deploy promotes a new code. A thief who keeps reading the platform's
  store reads every new code too: the answer is a platform with an identity.
  The [design's section 4.4](design/workload-access.md#44-enrollment-platforms-that-sign-nothing)
  lists what a copy can and cannot do.
- **coffre is on the request path.** Each upstream call is one more hop, and
  coffre's availability becomes the app's. A short outage stops uses but not
  sessions, which last an hour.
- **A streamed body is checked as it passes, not before.** Coffre sends a
  body with a `Content-Digest` on as it comes and holds back only its last
  bytes until the digest matches; one that does not, or ends short or runs
  long, is cut off before its last byte, so the upstream never gets a
  complete request, and the app gets coffre's 400. An upstream that acts on
  part of a request before it ends, a multipart part it stores as soon as
  it has read it, can still have done so. That takes a request whose bytes
  are not the ones its proof signed: from a client holding the session,
  which could sign those bytes anyway, or from someone who read a proof on
  its way to coffre and sent a copy first, with other bytes.
- **On Node, coffre runs as one process.** The replay gate lives in the app
  process. Several replicas would each hold their own nonces, and clients
  would bounce between them and fail. Run coffre on Node as a single
  process, or on Workers, where the gate is a Durable Object.
- **Azure's tokens repeat.** A managed identity hands the same cached token
  to every replica and restart for up to 24 hours, so coffre cannot spend it
  once. A leaked one works with any key until it expires. A NAT gateway's
  dedicated addresses in `sources` close that. Vercel's function token
  repeats too. `vercel()` exchanges it for one that names the key, so a
  token copied on its way to coffre is useless to another key, but a leaked
  function token can still be exchanged, for any key, until it expires.
- **Not yet checked live.** Google and Fly may refuse a `#` in the audience
  string (`https://secrets.acme.example#jkt=…`), which the SDK sends today.
  If either does, the fallback is `?jkt=`, which the exchange accepts the
  same way, and `gcp()` or `fly()` changes to send it. Vercel's token
  exchange has not been run against a real project yet. Whether a Workers
  preview version keeps `props` is checked when the binding lands.

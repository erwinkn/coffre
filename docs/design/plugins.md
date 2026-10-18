# Plugins, and coffre as a Vault KV store

A design for 0.7.0, written on 2026-10-17 (W119). The mechanism and the
Vault adapter are built, its sign-in included (PRs 1 and 2 of section 7). The decisions in section 6
were taken on the recommended option while Erwin was away (R10), and each
is his to revisit. User docs: [vault.md](../vault.md). Erwin asked for a read-only HashiCorp Vault KV v2 API, so that
off-the-shelf tools, External Secrets Operator (ESO) first, can pull
coffre's secrets. That API is optional: a deployment adds it in its
configuration. coffre has no plugin mechanism yet, so this proposes a
general one, with the Vault adapter as its first user.

## 1. What a deployment writes

The configuration, on Workers (on Node, the same `plugins` line in
`createCoffre({…})`):

```ts
// app/src/coffre.ts
import { vaultKv } from '@coffre/server/plugins/vault-kv';

export const coffre = createCoffre((env: Env) => ({
  publicUrl: env.PUBLIC_URL,
  // …database, vault, auth, auditChainKey, as today
  plugins: [vaultKv()],
}));
```

and one file route, which hands every request under `/v1` to coffre, as
`api.$.ts` does for `/api`:

```ts
// app/src/routes/v1.$.ts
import { createFileRoute } from '@tanstack/react-router';
import { plugin } from '@coffre/server/routes';

export const Route = createFileRoute('/v1/$')({ ...plugin });
```

An Owner makes a service account for the cluster, `token:eso`, gives it
Viewer on `market/prod`, and issues it a token. In Kubernetes:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: { name: coffre }
spec:
  provider:
    vault:
      server: https://secrets.acme.example
      path: secret
      version: v2
      auth:
        tokenSecretRef: { name: coffre-token, key: token }   # coffre_svc_…
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: { name: market }
spec:
  secretStoreRef: { name: coffre }
  refreshInterval: 15m
  target: { name: market-env }
  dataFrom:
    - extract: { key: market/prod }        # every value of market/prod
  data:
    - secretKey: stripe
      remoteRef: { key: market/prod, property: STRIPE_KEY }
```

What ESO then sends, and what coffre does for each request:

| ESO sends | coffre does |
|---|---|
| `GET /v1/auth/token/lookup-self` (once, to mark the store Ready) | Checks the token and answers who it is: `display_name: token:eso`, `type: service`, and the seconds it has left as `ttl` |
| `GET /v1/secret/data/market/prod` (every 15 min) | Runs the API's reveal of `market/prod` as `token:eso`: the same checks, the same vault call, one `secret.read` entry naming the keys it opened. It answers `{ data: { data: { DATABASE_URL: …, STRIPE_KEY: … } } }` |
| `GET /v1/secret/data/market/staging` | 403 `permission denied`, logged as a refusal, as `coffre export market/staging` would be |
| `GET /v1/secret/data/market/gone` | 404 `{"errors":[]}`, which ESO reads as the secret deleted |

The same token works with the `vault` CLI:

```sh
VAULT_ADDR=https://secrets.acme.example VAULT_TOKEN=coffre_svc_… vault kv get secret/market/prod
```

## 2. The plugin shape

A plugin is a plain object, which its constructor returns:

```ts
type CoffrePlugin = {
  /** `vault-kv`: names it in errors. Unique in a deployment. */
  name: string;
  /** The paths it answers: `prefix` and everything under it, every method. */
  routes?: { prefix: string; fetch(request: Request, coffre: PluginContext): Promise<Response> };
};

type PluginContext = {
  publicUrl: string;
  /** The API as whoever `token` names, checked once at the first call. */
  api(token: string): CoffreClient;
  /**
   * The request as a workload's sign-in, for a 5-minute credential: `POST
   * /api/auth/oidc` on it, in process. `asked` says what its body asks for,
   * `{ service, token }`, read once admission passed.
   */
  exchange(asked: (body: unknown) => { service: unknown; token: unknown }): Promise<{ token: string; expiresAt: string }>;
  /** End the credential `token` is: `POST /api/auth/logout`, in process. */
  signOut(token: string): Promise<void>;
};
```

The Vault adapter's login, for example, says `exchange((body) => ({ service:
'token:' + body.role, token: body.jwt }))`, with the checks left out. The
route admits the request first, then reads the body, so a caller past the
limits costs no read.

`exchange` and `signOut` run coffre's own routes in process, with their
limits and audit, as `api` runs the API. A plugin that signs a workload in
only passes its token on. It never sees a key, and never calls the
bindings' `verify` alone: spending the token and issuing the credential
are what make the exchange safe, and they stay in core.

That is the whole v1 mechanism, about 80 lines in
`packages/server/src/plugins.ts`. **A plugin holds no authority of its own.**
It reaches coffre only through `api(token)`: the typed client the CLI uses,
running in process against the same route table, permission checks, vault
and audit log. A plugin can do exactly what the token's holder could do with
the CLI, and nothing more. MCP tools already work this way
(`packages/server/src/mcp/tools.ts`), so plugins add no new kind of access.

**Lifecycle.**

1. The deployment calls the constructor inside its configuration. On
   Workers that runs once for each `env` the isolate sees, and on Node once
   per process. The result is a settled value, never a pending promise
   (AGENTS.md, "What an isolate keeps").
2. `resolveConfig` checks the list (`checkPlugins`). Names must be
   lowercase and unique. Prefixes must be paths such as `/v1`, and none may
   overlap coffre's own server paths (`/api`, `/auth`, `/mcp`,
   `/.well-known`, `/livez`, `/readyz`) or another plugin's. A bad list
   fails at startup, not at the first request.
3. Each request reaches `coffreRoute` through the deployment's file route.
   coffre's own paths are matched first and plugins last. The request
   already went through `respond`, so it gets the migration door (503
   `migrating` below the schema), coffre's security headers, and the
   per-request database the platform gives it.
4. The plugin's `fetch` answers in its own protocol. Each `api(token)` call
   is an ordinary API call, with one database connection per request and
   no transaction held across a vault call. The API already guarantees
   both.

**What a plugin may never do**, and how the design keeps it out:

| Never | Because |
|---|---|
| Act with authority of its own | It gets no database, vault or runtime, only `api(token)` |
| Read a cookie | `api` takes a token the plugin read from its own header, and coffre alone reads the session cookie. A cross-site page cannot set a header without a CORS preflight, which coffre never grants |
| Skip the audit log | Every value it reads is a reveal, which the vault logs |
| Own migrations | There is no hook for them. Expand-then-contract stays coffre's alone |
| Read an environment variable | Options are arguments to its constructor (config is code) |
| Take one of coffre's paths | `checkPlugins` refuses the configuration |

One honest limit: a plugin is code the deployment imports, running in the
same process. Nothing stops it from importing `@coffre/db` and opening the
database itself. The capability API keeps honest plugins inside the rules
and makes review short (a plugin that imports anything but
`@coffre/client` and the plugin types is wrong at a glance). It is not a
sandbox against a hostile one. A lint rule could hold first-party plugins
to that import list, as `coffre/package-imports` does for packages.

**Versioning.** First-party plugins ship as subpath exports of
`@coffre/server` (`@coffre/server/plugins/vault-kv`) and move with it.
`PluginContext` is the contract, and its only substantial member is the
public HTTP API, which the CLI already relies on across versions. A
third-party plugin, later, is a package that peer-depends on
`@coffre/server`. The peer range is the compatibility check, so nothing
else is needed.

**Added since, for the credential proxy** ([credential-proxy.md](credential-proxy.md)):

- `use(handle, …)`: an environment's values, for a handle's person, opened
  to be used for them or exposed to their app, in process only.
- `handle(handle)`: whether a handle still stands, opening nothing, and
  the environments it was made for, which the proxy's stable URL resolves to.
- `routes.socket`: a WebSocket under the plugin's prefix, its bytes and TCP
  out, on Node through `createCoffre(…).upgrade`.

**Capabilities to add later**, each when its first plugin needs it (none is
built):

- `events.committed()`: a wake-up after a commit that wrote audit entries.
  Change notifications need it (section 4).
- `scheduled(coffre)`: called from the scheduled job (every 5 minutes on
  Node, the Worker's cron on Workers). Rotation and notification retries
  need it.

## 3. Options considered

**A. Capabilities over the API (recommended, prototyped).** As above. Its
cost is one in-process API call per action, plus one token check per
request. It reuses the most-tested code coffre has, the API's checks, and
needs no new rules for plugin authors to learn.

**B. Give plugins the runtime: database, vault and `ApiContext`.** This is
more powerful, since a plugin could write its own queries. But every
invariant in AGENTS.md (transactions and the vault, one connection per
call, audit before rows) would become the plugin's job, and the internals
would turn into a public interface. Rejected.

**C. No mechanism: `vaultKv` as a built-in option, like `signin({ mcp })`.**
This is the simplest answer for one feature. But each later integration
(notifications, rotation) would add more core configuration and more code
in `app.ts`. The mechanism is about 80 lines, so it costs less than the
second integration would.

**D. No code: ESO's generic `webhook` provider against today's API.** ESO
can already `POST /api/reveals` with `{"path":"{{ .remoteRef.key }}"}` and a
bearer token, then pick `$.values`. It costs nothing and is worth a page in
the docs now. Its limits:

- The provider is **alpha**.
- It serves ESO only.
- `dataFrom.find` is unsupported.
- The token's Kubernetes Secret must carry the label
  `external-secrets.io/type: webhook`.
- `property` needs a templated `jsonPath`.

The Vault adapter covers the stable provider and every tool that speaks
Vault.

**E. A separate proxy service** that translates Vault requests into coffre
API calls over HTTP. It has the same security model as A, but adds another
thing to deploy, version and secure. A plugin is that proxy, running in
process.

**How a plugin's paths reach coffre.** Two options:

- **A file route per prefix (recommended).** `routes/v1.$.ts` follows
  TanStack's normal path and works like `mcp.ts` (MCP is on when both the
  config and the route exist). It costs the deployment one more file.
- **Intercept in `coffreMiddleware`, before Start routes.** No file is
  needed, but a path appears that the app's route tree never shows, and it
  could shadow a page.

## 4. How the likely plugins fit

| Candidate | Shape | Needs |
|---|---|---|
| Vault KV read adapter | Plugin | `routes` + `api` (built) |
| Kubernetes login for the adapter | Part of that plugin | `exchange`. The key handling stays core: trust bindings with uploaded key sets (#241) |
| Change notifications (webhooks) | Plugin | `events` + `scheduled` + `api` as its own service account (sketch below) |
| Rotation, short-lived credentials (GitHub App tokens, R2) | Plugin | `scheduled` + `api` as its own service account. The third-party credential it rotates with is a coffre secret that account reads (R7) |
| Uploaded JWKS for Kubernetes service accounts | **Core**, not a plugin | It decides who a workload is |
| Sign-in providers, `cloudflareAccess` | **Stay as they are** | They decide who someone is and issue sessions |
| Workload profiles (GitHub, GitLab, custom), `githubApp` | **Stay as they are** | Same: they issue credentials |
| MCP | **Stays as it is** | It issues OAuth tokens, and its approvals are core pages and tables |

**The rule of thumb:** whatever decides who a caller is, or issues them a
credential, belongs to coffre's trust core and stays in `signin({…})`. A
plugin either speaks another protocol to callers coffre already knows, or
reacts to what happened. Moving sign-in into plugins would mean handing
plugins session and credential internals, which is option B through the
back door.

### Sketch: change notifications

```ts
plugins: [
  notify({
    // A service account the deployment made for it: Auditor on market. Config is code.
    token: env.NOTIFY_TOKEN,
    // Signs each delivery (HMAC-SHA256), so a receiver can tell it came from this coffre.
    signingKey: env.NOTIFY_SIGNING_KEY,
    to: [{ url: 'https://hooks.slack.com/services/…', on: ['market/prod'], actions: ['secret.write', 'secret.archive'] }],
  }),
],
```

1. **Wake-up.** After any commit that wrote audit entries, coffre calls
   `events.committed()` in `waitUntil`. The call carries no data, only the
   fact that something committed.
2. **Read as itself.** The plugin calls `api(token).audit.list({ path:
   'market/prod' })` as its Auditor account and keeps what it has not sent.
   It learns only what that account may read: names, actors and versions,
   never a value. That is the same rule as everywhere else, and it derives
   from the log instead of keeping a second copy.
3. **Deliver.** It POSTs `{ id: <entry seq>, action, path, keys, actor, at }`,
   signed. The `id` is the entry's sequence number, so a receiver can drop
   duplicates.
4. **Catch up.** On `scheduled`, the plugin rereads the last 15 minutes and
   sends again. That gives at-least-once delivery with no plugin state: a
   receiver sees each change once or more, and misses one only when the
   receiver was down for longer than the window. Durable delivery with no
   window would need a cursor stored somewhere. If that is ever needed, it
   should be one core-owned table (`plugin_state`: plugin, key, value) that
   coffre migrates, never a plugin's own migration.

## 5. The Vault KV adapter

**What it serves** (`packages/server/src/plugins/vault-kv.ts`):

| Request | Answer |
|---|---|
| `GET /v1/<mount>/data/<project>/<env>` | Every value of the environment, as `data.data`. This is the API's reveal, purpose `run` |
| `GET /v1/<mount>/data/<project>/<env>/<KEY>` | `{ KEY: value }`. The API's reveal of one key, purpose `reveal` |
| `GET /v1/auth/token/lookup-self` | Who the token is: `type: "service"`, `ttl` the seconds it has left and `expire_time` when it ends, as `GET /api/me` says (both 0 and null behind Cloudflare Access), no `namespace_path` |
| `GET /v1/sys/internal/ui/mounts/<mount>[/…]` | The mount, KV version `"2"`. No token is needed: it holds no secret, and Vault's UI asks for it unauthenticated too |
| Any other method (PUT, POST, PATCH, DELETE) | 405 `coffre's Vault API is read only` |
| Any query on a read: `?version=N`, `?read_snapshot_id=…` | 400 before anything is read: coffre serves current values only |
| `?list=true`, on any path (HashiCorp's client sends LIST that way; ESO's `find` asks it of `secret/metadata/`) | 405: no listing (see decision 6) |
| `X-Vault-Wrap-TTL` (`vault kv get -wrap-ttl=5m`) | 400 before anything is read: the client expects a wrapping token, not values |
| A non-empty `X-Vault-Namespace` | 400. An empty one passes, since vault-action always sends one |
| A path naming no environment (`secret/data/market`) | 400, never 404, so that a typo in an ExternalSecret does not make ESO delete its target |
| Any other path: `secret/metadata/…`, another mount | 400 |

The mount is `secret` by default, as in Vault (`vaultKv({ mount: 'kv' })`
changes it). The metadata in a data response has `version: 0`: Vault's
version is a number, and coffre's environment version (T94, #240) is a hash
of what a read opens. That hash goes in `custom_metadata.coffre_version`,
Vault's map of strings, which `vault kv get` prints. A whole environment's
reveal answers it, so it costs nothing. A single key's read has none. Each
value's history stays in coffre.

A fork that inherits (#238) reads through the adapter as it does through
`coffre export`. The adapter calls the API's reveal, so inherited keys
resolve live from the parent and need read on the parent. A token that
reads only the fork gets 403, never a partial map. A test holds both.

**Errors.** One rule: **404 means only that the environment or key a read
names is not there**, because ESO reads a 404 as the secret deleted, and
with `deletionPolicy: Delete` it deletes its target. So the API's 404 on a
read becomes `404 {"errors":[]}`, and nothing else does. Whatever coffre
does not serve is a 400 or a 405: a path, a query, a header, a method. An
outage keeps its 503. coffre's 401 and 403 become Vault's `403 permission
denied`, with coffre's reason after it.

**Why a GET may reveal here.** coffre's own API reveals only to a POST, so
that a link, a prefetch or another site's `<img>` cannot trigger a read
with the browser's cookie. None of that can happen here:

- The credential comes only from the `X-Vault-Token` header, never from a
  cookie. A browser's session cookie, even sent from coffre's own origin,
  gets 403, and a test holds this.
- A cross-site page cannot set that header without a CORS preflight, which
  coffre never answers with an allow.
- A prefetch or an `<img>` carries no header.
- Every answer is `cache-control: no-store`, carries coffre's security
  headers, and passes the migration door.

**Audit volume.** Each poll is one reveal, which the vault logs as one
`secret.read` for each environment it opens values in, naming the keys
(#242). That is one for a plain environment, plus one per parent for a fork
that inherits, and per source for references into another environment.
Take ESO polling 10 plain environments, one fetch each, every 15 minutes:
that is 40 entries an hour, about 1,000 a day, the same as `coffre export`
in a 15-minute cron.
Don't optimize it here. And if a poll ever needs to know whether anything
changed without reading values, coffre's environment version (T94,
`GET /api/projects/<p>/<e>/version`) is the tool, not change detection of
the adapter's own.

**Which tools this buys.** Requests were taken from each tool's source
(ESO v2.13.0, `hashicorp/vault/api` v1.22.0, Vault v2.2.0, Terraform
provider v5.13.0, vals v0.47.0). "Ran" means exercised against `pnpm dev`
with the real client.

| Tool | Works? | What it needs |
|---|---|---|
| ESO, `tokenSecretRef` | **Yes (ran)**: HashiCorp's Go client, ESO's exact calls | lookup-self + data |
| `vault kv get`, `vault token lookup` | **Yes (ran)**: Vault CLI 1.21 | ui/mounts + data |
| vals / helmfile `ref+vault://` | Yes | ui/mounts + data. vals fails outright on a 403 from ui/mounts, so that path must not need a token |
| Terraform `vault_kv_secret_v2` | Yes, with `skip_child_token = true` | lookup-self. Without that flag the provider mints a child token through `auth/token/create`, which a read-only API should not serve |
| Terraform `vault_generic_secret` | Yes | Falls back on its own |
| hashicorp/vault-action (GitHub) | Yes, token auth | Data. It sends an empty namespace |
| argocd-vault-plugin | Yes, token auth | Data |
| consul-template, envconsul | Yes, with `renew_token = false` | Data. `renewable: false` stops lease renewal |
| ESO `kubernetes` / `jwt` auth | Yes, with `serviceAccountRef` | `auth/<mount>/login` and `revoke-self` (below) |
| ESO `dataFrom.find`, `metadataPolicy: Fetch` | No | LIST and metadata (decision 6) |
| Vault Agent | No | Renewable tokens and `renew-self` |
| Vault CSI provider | No | Kubernetes auth only |
| Spring Cloud Vault | Probably | ui/mounts + data. Its startup calls are unconfirmed |

**Kubernetes login (PR 2).** ESO's Kubernetes auth sends
`PUT /v1/auth/kubernetes/login` with `{ "role": "eso", "jwt": "<service
account token>" }`. It reads `auth.client_token`, and on cleanup calls
lookup-self and then `PUT /v1/auth/token/revoke-self`.

1. The plugin calls `coffre.exchange({ service: 'token:eso', token: jwt })`.
   This is the workload exchange behind `POST /api/auth/oidc`:
   `WorkloadService.verify` (the bindings, the signature, the claims), then
   spending the token so it cannot be replayed, then a 5-minute credential,
   all with the exchange's limits and audit. The Vault role names the
   service account. A plugin never calls `verify` alone: spending and
   issuing are what make it safe, and they stay in core.
2. Bindings check the token's issuer. They discover its keys from the
   issuer's URL, which works for EKS and GKE, whose issuers are public. For
   a private cluster, the binding holds an uploaded key set (#241, in main),
   whose issuer may be any string, such as `https://kubernetes.default.svc`.
   The adapter does no key handling of its own.
3. The answer is `auth: { client_token: <5-minute coffre token>,
   lease_duration: <seconds left>, renewable: false }`. ESO logs in again
   when the token runs out.
4. `revoke-self` is `POST /api/auth/logout`, through `coffre.signOut`.
   With it, a token ESO is done with ends early.

Any `auth/<mount>/login` takes the same body, by PUT or POST:
`kubernetes`, `jwt`, or a mount name the client was given. vault-action's
`method: jwt` signs in this way with a GitHub run's ID token. The
interface it needs from core is the existing exchange, unchanged: `{
service, token } → { token, expiresAt }`. A refusal is Vault's 403 with the
exchange's reason, a closed limit 429, and an instance that trusts no
workloads 400, never 404.

## 6. Decisions

Each was taken on its recommendation on 2026-10-17 under R10, for Erwin to
review. Each is reversible.

1. **Where the adapter lives: `/v1` or `/vault/v1`.** The adapter takes
   `/v1`, so `VAULT_ADDR` is coffre's own origin. HashiCorp's Go client
   keeps a path in its address (`VAULT_ADDR=https://secrets.acme.example/vault`
   requests `/vault/v1/…`), so `/vault/v1` would work for Go tools. Other
   clients are not confirmed. *Recommendation: `/v1`*, the widest
   compatibility. It clashes with nothing coffre serves.
2. **The path mapping.** `secret/data/market/prod` is the environment and
   `secret/data/market/prod/STRIPE_KEY` is one value. Folders are not in
   the path. A personal config (R8) would be `market/prod@me`, passed
   through to the API as it is. *Recommendation: keep it.* A Vault user
   expects "a path is a map of keys", and an environment is exactly that.
3. **Versions.** `version: 0`, coffre's hash in `custom_metadata`, and
   `?version=N` refused, against inventing a counter for Vault's numeric
   version. *Recommendation: keep it.* ESO never reads the version, and
   refusing beats serving a version that means something else.
4. **The token's expiry in lookup-self.** The prototype reported `ttl: 0`,
   no expiry, as Vault does for tokens that never expire, so ESO could not
   warn before a 30-day token ran out. *Done in PR 1:* `GET /api/me` says
   `credentialExpiresAt`, and lookup-self derives `ttl` and `expire_time`
   from it.
5. **Which tokens count as a Vault token.** Any token the API accepts
   counts: service tokens, a person's personal token (`coffre_pat_`,
   #239), or their CLI session. So `vault kv get` works for a developer as
   themselves, within a personal token's scope, and a test holds that.
   *Recommendation: keep it*, since it is the API's rule. Refusing
   `coffre_web_` browser sessions in the header is also an option, at the
   cost of one more rule.
6. **LIST and metadata, for ESO's `find` and tag filters.** LIST maps
   cleanly: `secret/metadata/?list=true` gives `["market/"]` and
   `secret/metadata/market?list=true` gives `["prod", "staging"]`, both
   from `GET /api/me`, about 20 lines. Metadata with `custom_metadata`
   has nothing to map to. *Recommendation: LIST only when someone needs
   `find`.*
7. **Plugin reads in the audit log.** A read through the adapter is logged
   as `token:eso` read these keys, just as `coffre export` is. Marking it
   "via vault-kv", as MCP's entries say "via Claude", would take a `via`
   generalized beyond MCP. *Recommendation: later, if investigations ask
   for it.*
8. **Change notifications' delivery.** Best-effort plus a 15-minute
   catch-up, with no state, against durable delivery through a core
   `plugin_state` table. *Recommendation: the stateless one first.*

## 7. Plan

| PR | What | Effort |
|---|---|---|
| 1 | The plugin mechanism and the read-only Vault adapter. Adds a user doc (`docs/vault.md`: ESO, CLI, Terraform, vals setup), the ESO `webhook` alternative in the same doc, and `expiresAt` in `/api/me` (decision 4) | 1 to 2 days |
| 2 | `exchange`, Kubernetes and JWT login, and `revoke-self`, on uploaded key sets (#241). Done | 1 day |
| 3 | `events` and `scheduled`, and the `notify` plugin | 3 days |
| 4 | LIST, if wanted (decision 6) | Half a day |
| 5 | Rotation plugins on `scheduled`, from W108 and W109's prototypes | Per provider |

PR 1's code:

- `packages/server/src/plugins.ts`: the types, `checkPlugins` and the
  dispatch.
- `packages/server/src/plugins/vault-kv.ts`.
- `dev/deployment`: the `plugins` line and `routes/v1.$.ts`.
- `packages/server/test/vault-kv.test.ts`: ESO's requests as its Go client
  sends them, on Postgres and SQLite.

It was also run against `pnpm dev` with HashiCorp's Go client
v1.22.0 making ESO's calls (`dev/vault-kv/main.go` reproduces it), and with
the Vault 1.21 CLI. That check is manual, and the suite does not run it.

The examples and `coffre init` are unchanged: the adapter is opt-in, so a
deployment adds it by hand, following the docs. A `coffre init --vault-kv`
could come later if people ask for it.

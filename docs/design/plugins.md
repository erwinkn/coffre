# Plugins, and coffre as a Vault KV store

A plugin is code a deployment adds in its configuration, to answer paths of its own or to watch
the audit log. coffre ships three, as subpath exports of `@coffre/server`:

| Plugin | What it does |
|---|---|
| `@coffre/server/plugins/vault-kv` | A read-only HashiCorp Vault KV v2 API at `/v1`, so External Secrets Operator (ESO), `vault kv get`, vals and Terraform read coffre ([vault.md](../vault.md)) |
| `@coffre/server/plugins/credential-proxy` | The credential proxy at `/use` ([credential-proxy.md](credential-proxy.md)) |
| `@coffre/server/plugins/audit-watch` | Walks the audit log on the scheduled run and holds what it verified outside the database ([below](#watching-the-log)) |

The mechanism is `packages/server/src/plugins.ts`; the watch is `packages/server/src/watch.ts`.

## What a deployment writes

```ts
// app/src/coffre.ts
plugins: [vaultKv(), auditWatch({ anchor: durableAnchor(env.ANCHOR) })],
```

and, for a plugin with routes, one file route that hands its prefix to coffre, as `api.$.ts`
does for `/api`:

```ts
// app/src/routes/v1.$.ts
import { plugin } from '@coffre/server/routes';
export const Route = createFileRoute('/v1/$')({ ...plugin });
```

A file route per prefix, not an intercept in the middleware, keeps every path coffre answers
visible in the app's route tree, so a plugin can never shadow a page unseen.

## The plugin shape

```ts
type CoffrePlugin = {
  name: string;                       // `vault-kv`: lowercase, unique in the deployment
  routes?: {
    prefix: string;                   // `/v1`: it answers this path and everything under it
    fetch(request: Request, coffre: PluginContext): Promise<Response>;
    socket?(request: Request, coffre: PluginContext): Promise<Response | SocketSession>;
  };
};
```

`checkPlugins`, called by `resolveConfig`, fails at startup on a bad list: a name outside
`[a-z][a-z0-9-]{0,31}`, two plugins of one name, a prefix that is not a path such as `/v1`, or a
prefix that overlaps another plugin's or one of coffre's own (`/api`, `/auth`, `/mcp`,
`/.well-known`, `/livez`, `/readyz`).

A request reaches the plugin through `coffreRoute` in `packages/server/src/app.ts`, which matches
coffre's own paths first and plugins last. It has already passed `respond`, so it gets the
migration door (503 `migrating` below the schema), coffre's security headers and its
per-request database. The constructor runs inside the configuration, once per `env` an isolate
sees on Workers and once per process on Node; it returns a settled value, never a pending promise
(AGENTS.md, "What an isolate keeps").

## A plugin acts only as a caller coffre authenticated

**A plugin holds no authority of its own.** Its context gives it no database, vault or runtime.
Every capability acts as a caller coffre itself checked, from a credential the plugin read from
its request: a token, a credential proxy handle (`coffre_use_…`), or a workload's session. A
plugin can do what that caller could do with the CLI, and nothing more.

| Capability | What it is |
|---|---|
| `api(token)` | The typed client the CLI uses, in process: the same route table, checks, vault and audit. The token is checked at its first call |
| `exchange(asked)` | `POST /api/auth/oidc` on the plugin's request: a workload's ID token for a 5-minute credential. `asked` only says which body fields hold `{ service, token }` |
| `signOut(token)` | `POST /api/auth/logout`, in process |
| `use`, `useMadeFor`, `handle`, `useRoute`, `useRouteOrPlace`, `proxyItem` | Reads for a handle's person or a workload, the credential proxy's ([credential-proxy.md](credential-proxy.md), [proxy-ui.md](proxy-ui.md)) |
| `workload(request, at)`, `recheck(caller)` | The request as a workload's: its DPoP-bound session, proof and rate gate ([workload-access.md](workload-access.md)). `use` takes the caller it returns, and refuses one the plugin built itself |
| `binding` | Whether the request came through a Cloudflare service binding (`bindingRoute`); which service it was is coffre's to know |
| `publicFetch`, `publicConnect` | HTTP and TCP out to a host an Owner typed: on Node only to public addresses, checked as each connection opens; on Workers the platform's `fetch` and `connect()` |
| `deployment` | What the deployment's `deployment.ts` chose |

`exchange` keeps the security-critical steps in core: checking the ID token against the account's
trust bindings, spending it so it signs in once, issuing the credential, with the exchange's limits
and audit. A plugin never verifies a token alone, and handles no issuer's key.

**What a plugin cannot do**, and why:

| Never | Because |
|---|---|
| Act with authority of its own | It gets no database, vault or runtime, only capabilities that act as a checked caller |
| Read a cookie | `api` takes a token the plugin read from a header; coffre alone reads the session cookie. Another site's page cannot set a header without a CORS preflight, and coffre allows none |
| Skip the audit log | Every value it reads is a reveal or a use, which the vault logs |
| Own migrations | There is no hook for them: expand-then-contract stays coffre's alone |
| Read an environment variable | Options are arguments to its constructor (config is code) |
| Take one of coffre's paths | `checkPlugins` refuses the configuration |

The limit: a plugin is code the deployment imports, in the same process. Nothing stops a hostile
one from importing `@coffre/db` and opening the database itself. The capability API keeps honest
plugins inside the rules and makes review short (a plugin that imports anything but
`@coffre/client` and the plugin types is wrong at a glance); it is not a sandbox.

Sign-in providers, workload profiles and MCP stay in core, not plugins: whatever decides who a
caller is, or issues them a credential, would need session and credential internals.

## Watching the log

The audit watch (`@coffre/server/plugins/audit-watch`) is a plugin with no route: it watches the
audit log on the scheduled run (every 5 minutes on Node, the cron on Workers) and contributes to
`/readyz`. Walking the chain and holding what it verified needs more than any caller gets, so a
watcher gets a context of narrow capabilities instead (`WatchContext`, `watch.ts`), still with no
database or vault client:

| Capability | What core does with it |
|---|---|
| `log.walk({ held, from, to })` | Checks each held point is still at its hash, then walks the chain from `from` toward `to`, at most `CHAIN_WALK` (10,000) entries, every link, hash and app MAC (`walkChain`). In no transaction, one statement a batch: entries never change, and the walk ends at a hash the vault signed, which pins everything before it |
| `log.hashAt(seq)`, `log.check(seq, link)` | One entry's hash; one entry checked alone |
| `log.append(action, metadata)` | One entry of the watcher's own kinds only (`audit.heartbeat`, `audit.finding`, `audit.finding_cleared`, `audit.reanchor`, `audit.loss_accepted`, `audit.loss_unapplied`), in the scheduler's name or the Owner's whose request it answers |
| `log.movedOn()` | Whether the log has moved on from this instance's app key (a newer deployment rotated it) |
| `vault.checkpoint()`, `vault.checkpointKeys()` | The vault's checkpoint, asked once a run however many ask, and the keys checkpoints verify under |
| `alert(text)` | The deployment's alert channel |
| `seal(fields)`, `own(record)` | A record MACed under a key core derives from `auditChainKey`, which the watcher never sees |

The watcher's own storage, the anchor, is an option of its plugin: `durableAnchor(env.ANCHOR)` on
Workers, `fileAnchor(path)` on Node. Its hooks (`Watcher`): `scheduled` (its part of the run,
before core's checkpoint), `readiness` (what `/readyz` says of it), `verified` (where the audit
page's check starts), `walkOn` (a backlog, between runs), `acceptLoss` and `reseal` (the anchor
sealed again when the app key rotates).

A watcher can neither forge an app entry nor a checkpoint: the chain key and the vault's keys stay
core's. What it can do wrong is append its own kinds, and say red or green.

Third-party plugins get no watcher. The context reads every entry's place in the chain and
decides readiness, the instance's integrity signal. Core takes a watcher only if coffre's own code
made it (`watcher`, which records it in a module-private set), whatever a plugin object carries.

Accepting lost entries is `POST /api/audit/loss`, or `coffre audit accept-loss <from> <to>`: an
Owner of the whole instance, as a person, with a fresh confirmation. It has no page, on purpose
(`packages/ui/src/parity.ts`): it is rare and irreversible, and a button would invite it.

## The Vault KV adapter

`packages/server/src/plugins/vault-kv.ts`, mount `secret` by default (`vaultKv({ mount: 'kv' })`).
Setup for each tool is in [vault.md](../vault.md).

| Request | Answer |
|---|---|
| `GET /v1/<mount>/data/<project>/<env>` | The API's reveal of the environment, as the token's holder: every value as `data.data`. A person's read leaves sensitive keys out and names them in `warnings` |
| `GET /v1/<mount>/data/<project>/<env>/<KEY>` | `{ KEY: value }`, the API's reveal of one key |
| `GET /v1/auth/token/lookup-self` | Who the token is (`display_name: token:eso`), `ttl` the seconds it has left and `expire_time`, from `GET /api/me`'s `credentialExpiresAt` (0 and null behind Cloudflare Access) |
| `GET /v1/sys/internal/ui/mounts/<mount>` | KV version `"2"`, with no token: it holds no secret, and vals fails outright on a 403 there |
| `PUT` or `POST /v1/auth/<mount>/login` `{ role, jwt }` | `exchange` for service account `token:<role>`: a 5-minute token, `renewable: false`. Any mount name (`kubernetes`, `jwt`, deeper ones) |
| `PUT` or `POST /v1/auth/token/revoke-self` | `signOut`: the token ends early |
| Any other method | 405, read only |
| `?list=true`, on any path | 405: no listing (ESO's `dataFrom.find` is unsupported) |
| Any query on a read (`?version=N`) | 400: current values only |
| `X-Vault-Wrap-TTL`, a non-empty `X-Vault-Namespace` | 400 before anything is read. An empty namespace passes: vault-action always sends one |
| A path naming no environment, any other path | 400 |

`<env>` may be `<env>@me`, the caller's personal config, and a fork that inherits reads as the
API's reveal reads it: inherited keys need read on the parent, or the read is 403, never a partial
map ([forking.md](forking.md)).

**Errors: 404 only for an environment that is not there.** ESO reads a 404 as the secret deleted,
and with `deletionPolicy: Delete` deletes its target. So nothing else is a 404: a typo in a path is
400, and a key that is not there is 403, because the API gives one answer for "no such key" and
"no access to it" (`not_available`), and a 404 would have ESO delete a secret whenever its reader
lost a grant. coffre's 401 and 403 become Vault's `403 permission denied`, with coffre's reason. A
503 stays a 503, with `Retry-After`, so an outage is never read as a deletion. A login to an
instance that trusts no workloads is 400; a closed limit 429.

**Versions.** Vault's `version` is a number and coffre's environment version is a hash of what a
read opened, so the adapter answers `version: 0` and puts the hash in
`custom_metadata.coffre_version`, which `vault kv get` prints. Only a whole environment's read
carries it. `?version=N` is refused rather than served with a different meaning.

**Why a GET may reveal here.** coffre's own API reveals only to a POST, so that a link, a prefetch
or another site's `<img>` cannot trigger a read with the browser's cookie. Here the credential
comes only from the `X-Vault-Token` header, never a cookie (a browser session cookie gets 403);
no other site can set that header without a preflight coffre never allows; a prefetch carries no
header. Every answer is `cache-control: no-store` and passes the migration door.

**Tokens.** Any token the API accepts counts: a service token (`coffre_svc_`), a person's personal
token (`coffre_pat_`, within its scope) or their CLI session. So `vault kv get` works for a
developer as themselves.

**Audit.** Each read is one reveal, which the vault logs as one `secret.read` per environment it
opens values in, naming the keys: an ESO poll is logged exactly as `coffre export` would be. ESO
polling 10 environments every 15 minutes makes about 1,000 entries a day. A read through the
adapter is not marked as such.

**Checks.** `packages/server/test/vault-kv.test.ts` and `vault-kv-login.test.ts` send requests as
HashiCorp's Go client sends them. `dev/vault-kv/main.go` makes ESO's exact
calls against `pnpm dev`, by hand; the suite does not run it.

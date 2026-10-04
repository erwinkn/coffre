# Architecture: coffre as a library

coffre is a set of packages a deployment imports and configures in code,
rather than an app you fork or check out. The [roadmap](roadmap.md) says how
it got here and what comes next; [deploy.md](deploy.md) walks through a
deployment.

## A deployment is a small project

A Workers deployment is two Workers in one small repository of your own:

```ts
// app/src/worker.ts
import { coffre, github, postgres, signin } from '@coffre/server/cloudflare';

export default coffre((env: Env) => ({
  publicUrl: env.PUBLIC_URL,
  database: postgres(env.HYPERDRIVE),
  vault: env.VAULT, // a service binding to the Worker below
  auth: signin({
    providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })],
  }),
  auditChainKey: env.APP_KEY,
}));
```

```ts
// vault/src/worker.ts
import { postgres, vault } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  previousKeks: [], // older vault keys: what they wrapped still opens, and what the vault signed under them verifies
  rootAdmins: ['erwin@example.com'],
}));
```

All configuration is passed to these functions. coffre reads no environment
variable of its own: a deployment brings values however it likes (Worker
secrets, a password manager, a file) and hands them over. Settings are typed,
so a misspelt provider option fails the typecheck rather than a sign-in.
`coffre(…)` returns the Worker's `{ fetch, scheduled }`, and calls the
function once for each `env` object Workers hands it: in practice, once per
isolate.

A Node deployment is the same idea, as two processes:

```ts
// src/server.ts
import { github, serve, signin } from '@coffre/server/node';
import { connectVault } from '@coffre/vault/node';

await serve({ port: 3000, publicUrl, database: 'postgres://coffre_runtime:…@db:5432/coffre', vault: connectVault('vault.sock'), auth, auditChainKey });

// src/vault.ts
import { serveVault } from '@coffre/vault/node';

await serveVault({ socket: 'vault.sock', database: 'postgres://coffre_vault_runtime:…@db:5432/coffre', kek, rootAdmins });
```

For local development or tests, run one process with
`vault: await localVault({ database, kek, rootAdmins })` in the
server. `database` is a Postgres URL, or `file:` for SQLite in
local development and tests.

`coffre init --workers` or `coffre init --node` writes such a project:
[examples/workers](../examples/workers) or [examples/node](../examples/node)
exactly, including the Workers' `wrangler.jsonc` files (Hyperdrive, the
service binding, the Cron trigger and the UI's static files). Both Workers
use one Postgres database: `HYPERDRIVE` connects as `coffre_runtime`,
`VAULT_HYPERDRIVE` as `coffre_vault_runtime`, with caching disabled on both.

## Packages

| Package | What | Holds |
|---|---|---|
| `@coffre/ui` | the web UI, server-rendered, and its static files | nothing sensitive |
| `@coffre/server` | `/api`, sign-in, the heartbeat, the queries; hands pages to the UI | sessions, the app login |
| `@coffre/db` | the Drizzle schemas for Postgres and SQLite, their migrations and migrator, the dialect helpers, the connections, Hyperdrive's included | |
| `@coffre/vault` | wraps and unwraps data keys, decides who may, logs every use | the keys, the vault login |
| `@coffre/client` | the typed API client, the API's types printed from the server's routes | |
| `@coffre/core` | what the others share: access rules, envelope encryption, vault key providers, the audit chain, identity and sign-in, and `Vault`, the contract between server and vault | |
| `@coffre/cli` | `init`, `login`, secrets, audit; built on the client | a CLI session |

A package imports another by name, never by a relative path (a lint rule
holds every package to it), and all eight are released together at one
version. So each builds and ships on its own, and a deployment can take one
in, as its own code, to change it. Everything ships as compiled JavaScript
with declarations, since Node refuses to strip TypeScript types inside
`node_modules`, and with its sources beside them. The CLI bundles all it
runs, so it installs with no dependencies.

Inside this repository, a `coffre:source` export condition points each
package at its sources instead, for dev, the tests and typecheck: an edit to
one package is seen by the others without a build. Builds leave it off.

| Entry point | What a deployment calls |
|---|---|
| `@coffre/server/cloudflare` | `coffre(env => config)` → `{ fetch, scheduled }`; `postgres(env.HYPERDRIVE)` |
| `@coffre/server/node` | `serve({ port?, host?, database, …config })` → `{ url, close }`; `migrate(url)` |
| `@coffre/server` (both) | `signin`, `github`, `google`, `microsoft`, `oidc`, `cloudflareAccess`, `SigninError`; `githubActions`, `vercel`, `railway`, `cloudflareWorkers`, `SyncConfigError`, `SyncProviderError`; and the config types, `SigninProvider` and `SyncProvider` among them |
| `@coffre/vault/cloudflare` | `vault(env => config)`, the RPC Worker's default export; `postgres(env.VAULT_HYPERDRIVE)` |
| `@coffre/vault` (both) | `awsKms`, `KekUnavailableError`, `KekBadClaimError`, and the config types, `KekProvider` among them |
| `@coffre/vault/node` | `serveVault({ socket, database, …config })`, `connectVault(socket)`, `localVault({ database, …config })` |
| `@coffre/ui` | `createUi()` → `{ fetch(request, { context: { cspNonce, client } }) }`; files in `dist/client` |
| `@coffre/client` | `createClient({ url, headers?, transport? })` |

Where `config` is, for the server, `{ publicUrl, vault, auth, auditChainKey }`
and, for the vault, `{ database, kek, previousKeks?, rootAdmins,
signingKey?, bulkLimit? }`, a vault key being a local key or `awsKms(…)`
([keys.md](keys.md)). The vault derives its signing key from a local vault key;
`signingKey` is required only with a vault key a key service holds.
Each is checked when the deployment starts, and a bad value (a 31-byte key,
a public URL with a path, no root admin) fails it with a message naming the
setting.

Migrations live in `@coffre/db`. The schema must match the server's
version exactly, which the lockstep version guarantees. `coffre migrate`
applies the CLI's own migrations, so it first asks the instance which
version it runs (`/me`, to owners and root admins only) and refuses unless
the CLI is that version. `pnpm exec coffre-server migrate`, the server's
command, applies the installed version's, for automation. A Worker has no
files, so the migrations each version ships are compiled into
`@coffre/db/schema-version` from their journals: `/me` reports how many the
database has applied of those.

## The UI

The UI stays a server-rendered TanStack Start app, published prebuilt as
`@coffre/ui`. `@coffre/server` routes `/api`, `/auth/*`, `/livez` and
`/readyz` itself and hands every other path to the UI:

```ts
type Ui = {
  fetch(request: Request, options: { context: { cspNonce: string; client: CoffreClient } }): Promise<Response>;
};
export function createUi(options?: UiOptions): Ui;
```

The server mints the nonce, builds the request's client and sets the security
headers; the UI only renders. It reads no configuration, API or database of
its own, and `scripts/check-client-bundle.mjs` fails its build if database or
server code reached it. Its static files sit in
`node_modules/@coffre/ui/dist/client`, under `/_coffre/assets/` so they cannot
collide with a deployment's own paths:

- **On Workers**, `app/wrangler.jsonc` names that directory as the Worker's
  static assets, so Cloudflare serves them before the Worker runs.
  `wrangler deploy --dry-run` reads all of them through pnpm's symlink, and
  `pnpm test:consumer` runs it on an installed project.
- **On Node**, `serve` finds the directory with `import.meta.resolve` and
  serves files under `/_coffre/` itself, immutable-cached, before handing
  anything else to the UI.

[A spike](spikes/ssr-ui.md) first showed the approach: a separate
Worker imported the built UI, rendered with one copy of React and hydrated
with the nonce intact.

`@coffre/ui` and `@coffre/server` each bundle `@coffre/client`, so a page is
handed a client built from the server's copy. Anything the pages check by
class must survive that: `CoffreError` answers `instanceof` by a
`Symbol.for` mark every copy sets, not by its prototype.

Pages get their data through `@coffre/client`, the same client the CLI uses,
never by reaching into the services. The client takes a transport: HTTP in the
browser and the CLI, and during server rendering an in-process call to the
API's `fetch` with the visitor's cookie. So a loader reads the same in both
places:

```ts
loader: ({ context }) => context.client.secrets.list('market/dev')
```

and every read, the UI's included, goes through `/api` and its permission
checks. The nonce-based Content-Security-Policy stays as it is.

## The API

The API is small and addressed by path: `market` is a project, `market/prod`
an environment, `market/prod/DATABASE_URL` a secret, and `user:ada@acme.example`
or `token:ci-deploy` a member. The URL names the thing and the HTTP method is
the verb:

| Call | HTTP |
|---|---|
| how this instance signs people in (public) | `GET /api/auth` |
| who I am, and everything I can reach | `GET /api/me` |
| list, create, rename or archive a project | `GET /api/projects`, `PUT` / `PATCH /api/projects/market` |
| the same for an environment | `PUT` / `PATCH /api/projects/market/prod` |
| list an environment's secrets, never their values | `GET /api/secrets/market/prod` |
| set, add or archive secrets, one or many, in one transaction | `PATCH /api/secrets/market/prod {"DATABASE_URL": "…", "OLD_KEY": null}` |
| what that write would do, per key, without values and without writing | `PATCH /api/secrets/market/prod?dryRun=1 {…}` → `{"dryRun": true, "keys": {"DATABASE_URL": "changed", "OLD_KEY": "archived"}}` |
| rename a secret | `PATCH /api/secrets/market/prod/DB_URL {"key": "DATABASE_URL"}` |
| a secret's versions | `GET /api/secrets/market/prod/DATABASE_URL/versions` |
| restore a version, as a new version | `POST /api/secrets/market/prod/DATABASE_URL/restore {"version": 3}` |
| decrypt a secret or a whole environment | `POST /api/reveals {"path": "market/prod"}` |
| list, add or offboard members | `GET /api/members`, `PUT` / `DELETE /api/members/user:ada@acme.example` |
| what a member holds and has seen, before offboarding | `GET /api/members/user:ada@acme.example` |
| list, issue or revoke a token's credentials | `GET` / `POST /api/members/token:ci-deploy/tokens`, `DELETE …/tokens/:id` |
| list, make (`?dryRun=1` to preview) or remove a token's trust bindings | `GET` / `POST /api/members/token:ci-deploy/bindings`, `DELETE …/bindings/:id` |
| a public GitHub repository's or GitLab project's IDs, for a binding | `GET /api/workloads/lookup?github=acme/api` |
| change someone's access, in one transaction | `PATCH /api/access/user:ada@acme.example {"market": "developer", "market/prod": null}` |
| my sessions and linked sign-in accounts, and ending them | `GET` / `DELETE /api/sessions/:id`, `GET` / `DELETE /api/identities/:id` |
| approve or deny a `coffre login` device code | `GET` / `POST /api/device-logins/:code {"approve": true}` |
| the audit log, and verifying it | `GET /api/audit?path=market/prod`, `GET /api/audit/verification` |

Three conventions carry it:

- **`PATCH` bodies are JSON merge patches** (RFC 7396): a field you send is
  set, `null` removes it, a field you leave out stays. That is all
  `secrets.set` and `access.set` mean.
- **Decrypting is a `POST`.** A reveal writes an audit row in the caller's
  name, so no `GET` may do it, and no prefetch, crawler or retrying proxy can.
- **One role per member per place.** A grant maps `(member, place)` to one of
  the built-in roles, which live in code, not in tables.

A change made with a cookie must come from coffre's own pages. The browser
attaches its session cookie to every request to this origin, whichever site's
page sent it, so any `/api` call other than a `GET` that authenticates by
cookie needs `Sec-Fetch-Site: same-origin` (or, from a browser too old to
send it, a matching `Origin`), and otherwise gets `403 cross_origin` before
anyone is looked up. A bearer token or Access assertion in a header needs no
such check: another site's page cannot make the browser send one.

Sign-in itself (OAuth redirects and callbacks, the device-code exchange for
`coffre login`, signing out) stays on its own routes; it is a protocol, not
something done to the data. What a signed-in person does with their own
sessions, and a device-code approval, are ordinary routes in the table.

The server is one table keyed by method and route, each entry giving its input
schema, the permission it needs and its handler. `@coffre/client` is typed
from the same table by inference (`coffre.secrets.set('market/prod', {…})`),
so the two cannot drift, and the UI calls it like any other client.

Each segment names one level, so `/api/secrets/market/prod/versions` is a
secret named `versions`, and its history is one level further down. Where a
literal and a name could both fit a path, the literal wins among the routes
that take the request's method.

Behind it, a request asks the vault once who the caller is to this instance:
whether they are still a member, and the grants they hold
(`vault.access`). Every permission check after that is a plain function,
`can()`, over that answer, and a path resolves to its project, environment
and secret in one read.

## The vault

The app decides **who** someone is. The vault decides **what** they may
decrypt. The vault never sees a cookie, an OAuth flow or a session; the app
passes it a claim:

```ts
await vault.unwrap({
  principal: 'user:dev@acme.example',
  purpose: 'reveal', // or 'run', 'compare'
  requestId,
  operationId,
  items: [{ secretVersionId }],
});
// { ok: true, keys: [...] }
// { ok: false, refusal: { code: 'no_grant', message: '...' } }
```

The app names stored versions; the vault reads each one's wrapped key, and
the secret it belongs to, from the database itself, so the app cannot claim
a version is something it is not. Before it unwraps anything, the vault
checks that the principal is still a member and their row is the one it
wrote, that an unexpired grant covers that environment for reading, and that
the principal is under the bulk limit. A data key opens only for the secret
it was wrapped for, so a wrapped key copied onto another secret's row is
refused as `bad_claim`. The vault logs the attempt either way. A batch is all
or nothing: fifty keys for one `coffre run` are one decision and one
refusal.

The code lives in `packages/vault`: one `Vault` interface, one
implementation, and a Drizzle store over the shared database. The schemas
and migrations live in `@coffre/db`. Postgres row locks serialize decisions
about the same member, so separate vault instances share the bulk count
and membership generations. The interface:

| Call | Does |
|---|---|
| `unwrap`, `wrap`, `rewrap` | data keys, for a principal whose grants cover the secret |
| `access(principal)` | one principal's status, owner flag and grants, their rows checked; the app asks once per request |
| `setAccess` | several places for one principal, all or nothing (`PATCH /api/access/<member>`) |
| `admit`, `remove` | add or restore a member, or remove one and revoke every grant; both answer the member's generation |
| `checkpoint` | sign the shared log up to its last entry, in an entry of the vault's, and check every member's row |
| `about` | the public key checkpoints verify under, and the root admins: what only its configuration says |
| `verifyLog` | check the vault's MACs over the prefix the app verified (asked with no head, the whole chain too), every checkpoint, and replay members and grants |

Every argument and result is plain data, and a refusal is a value, not a
thrown error, so the same interface works across a process boundary. The app
turns a refusal into a 403 `vault_refused` carrying the vault's code
(`removed`, `no_grant`, `expired`, ...), or a 403 `bulk_limit`. The vault
logs what it refuses; the app adds its own entry, with code `vault_<code>`,
only where the refusal is part of something larger it was doing, a write
or requested grants.

**The vault key is checked before it is used.** Each vault key gets a check value, a
known value wrapped under it the first time the vault uses it, kept in a
`key.check` entry of the log. Before its first key operation, each vault
process opens it again; a vault key with no check value yet is first tried on a
few stored keys it wrapped. A vault key that opens neither is not the one that
wrapped the data: every read and write is refused as `wrong_kek` (a 503),
naming the provider and key id, and the next checkpoint is refused, so
`/readyz` turns red. A key service that cannot answer is not a verdict; the
next call asks again. With a local vault key, the vault knows sooner: its keys
come from the vault key, so a wrong one holds none of those its entries were
written under, and the vault writes nothing at all.
[restore.md](restore.md#if-the-vault-key-is-wrong) shows what an operator sees.

The vault owns everything that decides access: the vault key,
grants (`(principal, place) → role`, one per member per place, with an
optional expiry), principal status (active or removed), the root admins (from
its configuration, so no row anywhere makes someone one), and its log entries.
Whether a caller is still in, and what they may do, comes only from
`vault.access`. `can()` stays a plain function over the grants that call
returned.

**Lists are reads.** The Users page, `coffre access`, a project's Access tab
and a member's page read `vault_members` and `vault_grants` directly, with
the app's sessions and sign-in accounts, in one query: a list is a display,
not a decision. The app cannot check the vault's MAC over a member's row,
so a row changed around the vault lists as stored; the vault refuses it at
its first use. Every scheduled checkpoint has the vault check every row
too, and log a `vault.tampered` for each one it finds changed. A list marks
a member whose newest such finding is newer than the vault's newest change
to what they hold, and shows them holding nothing, until an owner removes
them, which starts them over.

### Transports

- **Workers**: the vault is a Worker of its own, `coffre-vault`, with no
  public route. The app reaches its RPC entrypoint through the `VAULT`
  service binding. Each call opens the shared Postgres database through
  `VAULT_HYPERDRIVE`, using the vault's login: one connection, which its
  queries take turns on, closed when the call is done. No database
  connection lives across requests.
- **Node, its own process** (`serveVault` and `connectVault`): the vault
  opens the same Postgres database as the app, through its own login, and
  answers on a Unix socket. The socket is its authentication: a file made
  `0660`, which only the vault's user and a group it shares with the server
  may open. Each call is one HTTP POST over the socket, `/<method>` with
  the arguments as a JSON array. The process facing the network holds no vault key.
- **Node, in process** (`localVault`): for tests and local development.
  Both components use one SQLite file. Each call's arguments and results
  go through JSON as over RPC, so nothing that only works in-process gets in.
- **Locally**, `pnpm dev` runs the vault as an auxiliary Worker of the
  app's `vite dev`, and conformance runs both with
  `wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc`. Either way
  the app's `VAULT` binding reaches it as in production.

### Where each secret lives

| | App (Worker `coffre`) | Vault (Worker `coffre-vault`) |
|---|---|---|
| Config | `auditChainKey`, `auth` (sign-in or Access settings) | `kek`, `previousKeks`, `rootAdmins`, `bulkLimit`; `signingKey` with a KMS key |
| Tables it writes | projects, environments, ciphertext and wrapped keys, the directory, sessions; app entries in `audit_log` | `vault_members`, `vault_grants`; vault entries in `audit_log` |
| Connection | `coffre_runtime`, through `HYPERDRIVE` or a Node Postgres URL | `coffre_vault_runtime`, through `VAULT_HYPERDRIVE` or a Node Postgres URL |

Both connections reach the same database. Each Worker gets only its own
configuration secrets. Neither stores the vault key or the app key in the database.
The database's grants protect members and grants from the app's login;
row-level security protects each author's entries from the other's login.
The owner can bypass those restrictions, but cannot forge an entry's MAC
without its author's key. SQLite has no logins and is only for tests and
local development.

### Transactions

No app transaction stays open across a vault call. A write asks the vault to
wrap its new data keys first, outside any transaction, then stores the
versions and its `secret.write` entries together in one short transaction
that checks nothing changed meanwhile, and starts again, under a new
operation id, if something did. A reveal needs no app transaction at all: the
vault has committed its `secret.read` entries before it returns a key. A wrap
whose write then failed stays in the log, under an operation no
`secret.write` shares; it records the attempt, not a value stored.

The vault locks affected members before the shared audit head. Its member
and grant changes commit with their audit entries. With a local vault key, a read
is one short transaction. With AWS KMS, the intent commits first; the member
row stays locked across the KMS calls, which settle within five seconds,
and each key's outcome is logged. Removal waits for a read already in
flight; the next read is refused before KMS is called.

### The bulk limit

At most `bulkLimit` data keys unwrapped per principal in any rolling window,
`{ count: 1000, windowMinutes: 15 }` by default: twenty `coffre run`s of a 50-key environment
back to back, which no person or pipeline does, while a script pulling every
value it can reach stops within seconds. Each unwrapped key counts, so one
50-key run is 50. A refusal is logged and answers 403 `bulk_limit`; the
principal reads again as the window rolls on.

### One log, two authors

Both authors append `coffre.audit.v2` entries to `audit_log`, sharing one
`audit_chain_head`. Each entry has an `author` (`app` or `vault`), a MAC
under a key derived from that author's configuration key, and a public
SHA-256 hash over its fields and MAC. The app derives its MAC key from
`auditChainKey`; the vault derives its own from its signing key, which
comes from its vault key unless it is given one. Neither can authenticate the
other's entries alone. An entry names the key it was MACed under. A vault
whose vault key was rotated verifies its earlier entries by the key of the vault key it
keeps in `previousKeks`, but only those before the rotation: at its first
call under the new vault key, the vault seals every member row again under the new
key and writes a `key.rotate` entry, and from there its keys only move
forward. A key it replaced counts for no entry, row or checkpoint after
that, and a vault still running with it writes nothing more
([keys.md](keys.md#a-local-key)).

An append locks the head, reads the database clock, and refuses a head that
does not name the last entry or is behind one the process remembers. A new
head is remembered only after commit. Postgres forbids both runtime logins
from changing or deleting entries and permits each to append only as its
own author. The owner can lift the triggers and bypass row-level security;
the MACs still expose changes made without the keys.

Every five minutes the Cron trigger appends an `audit.heartbeat` entry, then
asks the vault to checkpoint the log. The vault reads the log itself: it
recomputes the chain, every hash from content and its own entries by their
MACs, checks that the prefix its last checkpoint signed is still there,
then signs the log up to its last entry with Ed25519, in an
`audit.checkpoint` entry of its own. The first checkpoint of each hour
recomputes the whole chain from its first entry. The others resume from the
prefix the last one signed, which the vault recomputed itself, and
recompute only what is new since. They resume only while that prefix still
ends at the hash it signed, which a rewrite chained again changes, and
still has every entry, which a cut changes, as one count; otherwise they
recompute from the first entry too. So a rewrite or a cut anywhere is never
signed over, and an entry edited in place before the last checkpoint is
found within the hour (see [Limits](#limits)). A call with nothing new
returns the last checkpoint. The recomputation runs in a snapshot, without
the log's lock, so writes never wait for it. The same checkpoint checks every
member's row, as `access` would, and logs a `vault.tampered` for each one
changed around the vault.

`/readyz` is a query: ready while the newest heartbeat is under eleven
minutes old and a checkpoint after it carries the vault's signature. A log
that stops taking writes, a vault that stops signing, a cut in the log or a
wrong vault key all turn it red within one beat; an entry edited in place,
within the hour. There is no heartbeat table.

`GET /api/audit/verification` (owners only), also called by `coffre verify log`,
checks the chain from its first entry, every link and hash, and authenticates
the app's MACs. It hands the vault the head it reached, and the vault reads
its own entries in one pass: each by its MAC, every checkpoint against the
prefix it signed, the key batches accounted for, and member and grant
changes replayed. The links are the app's to recompute, as it just has
through that head; the vault confirms its snapshot still holds the head, and
asked with no head, it recomputes the chain itself.
A grant inserted by the owner without a matching vault entry is detected
by replay. The answer is the entry verified through, or the entry where it
breaks and whose check found it.

**One entry per human action.** A read is the vault's `secret.read`, one
per secret, with its purpose (`reveal`, `run`, `compare`); a
write is the app's `secret.write`, naming the vault's `key.wrap` by
`related_seq`; access and membership changes are the vault's
(`access.grant`, `access.revoke`, `member.*`), and the app keeps no copy.
One operation id ties together everything one action did. Sign-ins, tokens,
the vault's key operations and the heartbeat are detail: in the log and its
chain, but left out of `GET /api/audit` unless `detail=1`.

### What the vault stops

- **A permission bug in the app.** An endpoint checks the project but forgets
  the environment; someone with `market/dev` asks for
  `market/prod/DATABASE_URL`. The app lets it through, and the vault refuses:
  the grant covers `dev`.
- **Someone removed getting back in.** An offboarding bug leaves a session
  alive; the vault refuses the principal, which only it can restore.
- **A copy of the database.** It holds no vault key.
- **Rewritten log entries without the author's key.** Their MACs fail, even
  if the owner rebuilds the public chain.
- **Access granted around the vault.** Each member's row carries the vault's
  MAC over the row and every grant they hold, and names the newest log entry
  that changed them. A grant written straight into the database fails the
  MAC; an old row put back names an entry the log has moved past. Either way
  the vault refuses the member as `tampered` at their next request, logs a
  `vault.tampered`, and the next checkpoint finds it even if they never ask.
  An owner removes them to start them over. A decision seals only the grants
  it decided, so one written while it runs is refused, not sealed in.

What it does not stop: an app fully taken over can act as anyone who already
has access. The vault makes that loud rather than impossible: the key never
leaves it, every read lands in a log the app cannot edit, and bulk reads trip
its limit. Closing it would take requests signed by keys the principals hold
themselves, which fits this interface later without the vault learning about
sign-in. The rest of what coffre does not stop is under [Limits](#limits).

### Sign-in rows

The app authenticates each identity, credential and device authorization
before using it. A database writer cannot mint a session or edit its
authority without the app's key. Each row has a 32-byte `auth_mac`, an
HMAC-SHA-256 under HKDF-SHA-256 of `auditChainKey`, with empty salt and the
purpose `coffre/signin-rows/v1`. The message is a JSON tuple beginning with
`coffre.auth.v1` and the table name, followed by these fields in order:

| Table | Authenticated fields |
|---|---|
| `identities` | id, provider, issuer hash, subject, principal type and id, generation, revoked at |
| `credentials` | id, token hash, kind, principal type and id, generation, identity id, expires at, revoked at |
| `device_authorizations` | id, device code hash, user code, decision, decided at, principal type and id, generation, expires at, consumed at |
| `service_bindings` | id, principal, generation, profile, issuer, JWKS URL, claims, revoked at |

Dates are integer milliseconds, bytes are hex, and null is distinct from
any value. Row IDs and the device's short user code bind the MAC to the
target an approval or revocation selects. `decided_at` is covered because
clearing it would allow another decision. Display labels, email addresses
and last-use telemetry do not grant access and are outside the MAC.

Every state change checks the old MAC and writes the new one with the
change, conditional on the old MAC still matching. Listings check the rows
too, including revoked identities that could otherwise disappear from an
account-binding check. A failed MAC refuses the operation and reports
`auth_row_tampered` to the process log, with only the table and row ID.

The baseline requires issuer hashes, generations and MACs. Pending and
denied device requests have no principal and use generation zero; an
approval carries its member's generation. A credential's linked identity
must belong to the same member and generation, enforced by a foreign key.

Changing `auditChainKey` invalidates these rows too. A MAC proves a row
genuine, not current: see [Limits](#limits).

### Trust bindings

A service can be trusted to sign in with the ID token its CI platform signs
for a run. A trust binding names an issuer and the claims a token must
carry; the [design](design/oidc.md) has the reasons. A deployment turns
workloads on with `signin({ …, workloads: { limits } })` ([deploy.md](deploy.md#ci-runs-without-a-stored-token)).
Owners make and remove bindings on a service's page, under "Trusted
workloads", with `coffre trust` and `coffre untrust`, or through
`/api/members/token:…/bindings`. The page and the CLI show every claim, the
issuer and its keys' URL before anything is saved. A run trades its token at
`POST /api/auth/oidc` for a credential of the service that lasts five
minutes (below).

- **Profiles.** The server checks each binding against its profile, which
  sets the claims it must name:
  - `github`: a workflow of the repository;
  - `github-reusable` and `github-reusable-organization`: a reusable
    workflow, pinned to its commit;
  - `gitlab`;
  - `custom`: any other issuer, by `sub`.

  github.com's and gitlab.com's issuers force their profiles.
- **Discovery.** Making a binding asks the issuer's discovery document where
  its keys are. The transport follows no redirect and stops after 5 seconds
  and 64 KiB. On Node it connects only to public addresses. The binding
  keeps the keys' URL under its MAC.
- **Immutability.** Only a binding's label, last use and revocation ever
  change. Any other change is a new binding, which replaces the old one.
- **Limits.** A service holds at most 16 live bindings, and those on one
  issuer share one key set's URL.
- **Tombstones.** Removing a binding writes an allowed `token.unbind`, its
  tombstone. A binding with a tombstone never counts again, whatever its row
  says. A denied attempt is no tombstone.
- **Generations.** Removing the service moves its generation past every
  binding it had.

**The exchange.** `POST /api/auth/oidc {"service": "token:api-deploy",
"token": "<JWT>"}` answers `{"token": "coffre_svc_…", "expiresAt": "…"}`, in
this order, so that a stranger costs one bounded read at most:

1. **Admission**: the deployment's two limiters, per source address and in
   total, then the body, read only to 16 KiB. A limiter that fails refuses.
   Cloudflare counts per location and a Node process per process, so these
   bound a flood per location or process, not across the deployment.
2. **The token's shape**: a compact JWS of at most 8 KiB, `iss` and `sub`
   nonempty strings, `exp` and `iat` numbers.
3. **The bindings**: one read of the service's live bindings on the token's
   issuer, in its current generation, without tombstones.
4. **The token**, by jose, under the issuer's keys: RS256 or ES256 only,
   nothing taken from the header but `alg` and `kid`, the audience this
   instance's public URL alone, `exp`, `nbf` and `iat` within 30 seconds,
   `iat` at most an hour old; then the claims of one binding, exactly.
5. **Unspent**: a read of the token's signing input's SHA-256.
6. **The member**: one `vault.access`, outside any transaction.
7. **Commit**, holding the log's head: the member and the binding again,
   the times again, at most 60 credentials a minute per binding, the token
   spent (its hash's primary key decides a race), the credential issued,
   and `token.exchange` logged with the run the issuer asserts.

A token no binding can take costs its admission and step 3's one read,
through `service_bindings_principal_idx` on the service and issuer: no
other query, no transaction, no vault call, no fetch. The database's
migrations are asked only of a token some binding might take.
`workload-exchange.test.ts` counts the statements that reach Postgres.

A refusal answers 401 with a reason a CI user can act on, 429, or 503 when
the issuer cannot be asked, and stays out of the audit log: anyone can mint
a genuine token. Each isolate keeps the issuers' keys it fetched, settled
values only, for ten minutes; a key it lacks fetches them again once a
minute at most.

**The credential** is a service credential like any other, whose
`created_by` names its binding, `binding:<id>`. Its MAC is of its own kind
and covers that field, so the link can be neither cut nor added. Checking
it checks its binding too, in the same request: its MAC, its revocation,
its tombstone. Removing the binding ends it at once, and a credential row
put back with its binding stays dead. Spent tokens and exchanged
credentials are kept, since the runtime logins delete nothing; a CI run
adds two small rows.

**Which run did what.** Every entry a request on such a credential writes
names it, as `credentialId` in its metadata: the app's own, and the
vault's, through a `credentialId` in its calls' correlation that it copies
and never decides on. The exchange's entry names the same credential, with
the run's claims. A credential an entry acts on (one a sign-in opens, a
token issued, a session revoked) is its `targetCredentialId`, so revoking
another run's credential is the caller's act, never that run's. So a secret read leads back to its run in one indexed
read, whatever became of the credential's row, and the audit page shows the
run under the actor ("acme/api run 7001 at 3f2a9c1"): what the issuer
asserted, not proof of which run sent the request.

Bindings come with migration `0002_service_bindings` and spent tokens with
`0003_exchanges`. This release runs on the schema before them. Until
an owner runs `coffre migrate`, the bindings routes and the exchange answer
503.

## Databases

The deployed app database is Postgres. SQLite remains for tests, local Node
development and conformance. The integration suite runs on both through
Drizzle, using the same queries.

Every query lives in one module, `packages/server/src/db/queries.ts`, and the
rest of the server writes no SQL (lint keeps `drizzle-orm` inside it and
`packages/db/src/`, and the vault's own store). There are named
reads, one per shape of data the server needs (the caller, a path, an
environment's secrets, the members, a page of the log), each
returning everything its callers use in one statement. There are also four
generic writes (insert, insert if absent, upsert, update) and a row lock.
Writes do not check first and do not read back. A unique constraint answers
"is this slug taken". An update that matches the old value answers "was it
still there": `{ id, revokedAt: null }` changes one row or none. Row locks are
kept for real races (the audit head, offboarding against sign-in, version counters), and each one says which race it guards.

The database comes from its URL: `postgres://` or `postgresql://` opens
node-postgres; `file:` or `libsql:` opens @libsql/client for SQLite
(`packages/db/src/connect.ts`). The SQLite driver loads only when
asked for. The Worker builds its Postgres database from the Hyperdrive pool
with `createDatabase`: one connection for each request or vault call, which
its queries take turns on and a transaction holds until it ends.

Each query is written once, typed against the Postgres schema. Drizzle has no
type shared by its dialects, so the SQLite database is cast to the Postgres
one in `portable.ts`; at run time each database travels with its own tables.
The cast is guarded by a compile-time check that every table's row type
matches, a parity test for tables, columns, nullability, keys, indexes and
foreign keys, and the whole suite on both engines on every Drizzle upgrade.

What differs stays in the schemas and `packages/db/src/dialect.ts`:

- **Schemas and migrations.** `pgTable` and `sqliteTable` define two schemas
  and migration trees under `packages/db/src/migrations/`, each a
  single baseline. Generated tables sit inside a template in
  `packages/db/src/baseline/` that adds the first audit rows and the
  Postgres runtime roles. Until the first deployment, `pnpm db:generate`
  regenerates the baseline rather than adding migrations. Tests catch a
  schema or template that no longer matches its migration. Encrypted bytes
  use `bytea` in Postgres and `blob` in SQLite.
- **Ids come from the application.** Writes know their keys before insertion
  and do not read them back.
- **Named operations.** Insert if absent, upsert, row locks, rows changed,
  recognising a duplicate key, the clock and reading a condition stay in
  `dialect.ts`. Services contain no database branches.
- **Locks.** The audit chain locks a permanent head row with `FOR UPDATE`
  on Postgres. SQLite has one writer, but its driver does not queue for us,
  so `connect.ts` queues transactions once per database file however many
  clients open it. Each takes the write lock with its first statement;
  a row lock there is a no-op.
- **Shared constraints.** Active identities use a unique index on a generated
  column that holds the subject only while the identity is not revoked.
  Emails are stored lowercase. Checks stay in both databases, with expressions
  in each dialect. SQLite's `lower()` folds ASCII only, so the server folds
  non-ASCII case. No query filters on a JSON field.

The restricted runtime logins (`coffre_runtime` and
`coffre_vault_runtime`) and `pnpm test:schema` stay Postgres-only. The
schema test checks both logins, including which author each may append as.
SQLite has no logins; its file permissions protect access to the database.

D1 is not a fit for the app database: it has no interactive transactions, and
the audit chain reads the previous hash, computes the next in JavaScript, then
writes. Drizzle's D1 transactions send `BEGIN`, which D1 rejects. Both
Workers use Postgres.

## Limits

Each limit is stated here once; the other documents link to it.

- **Whoever controls the database can rewind it.** Restoring an older copy
  of the whole database, or cutting its newest entries and putting the head
  back, leaves a log that verifies: every entry kept is genuine, and nothing
  in the database can show that newer ones existed. Two things notice: an
  app or vault process that ran across the rewind, which refuses to append
  behind the head it remembers, and, with AWS KMS, CloudTrail, whose Decrypts
  then have no entries. Restarting both processes after a restore is what
  makes a deliberate rewind work ([restore.md](restore.md)).
- **A cut in the middle of the log is found at the next checkpoint, and an
  edit in place within the hour, not at once.** Say Ada was removed at entry
  812, and the database's owner deletes 812 and puts back Ada's row from
  before. Her row and the entries that remain agree, so the vault lets her
  in. Within five minutes the next checkpoint finds an entry missing,
  recomputes the chain, finds the gap, refuses to sign and turns `/readyz`
  red; full verification says the same. If the owner edits 812 in place
  instead, so that it is no longer about Ada, every entry is there and the
  hash the last checkpoint signed stays: the checkpoints of that hour sign
  on, each extending the chain the vault recomputed before the edit, so the
  log as it now is verifies no better. The hour's first checkpoint
  recomputes the chain from entry 0 and refuses; full verification finds it
  at once. Until then, her reads are logged under her name.

  That one case is what moved from five minutes to an hour, when
  checkpoints began resuming: an entry before the last signed checkpoint,
  edited in place, with its stored hash left as it was. Everything else is
  still found at the next checkpoint, within five minutes:
  - an entry cut from the middle;
  - a rewrite chained again, whether resealed or not;
  - the prefix the last checkpoint signed gone;
  - anything after the last checkpoint.

  `GET /api/audit/verification` and `coffre verify log` still recompute
  everything when asked.
- **The full recomputation grows with the log,** once an hour: about 4
  seconds per 100,000 entries on a small shared Postgres. A team's instance
  writes some 600 entries a day of heartbeats and checkpoints alone, plus
  its own work. The other checkpoints read only what is new since the last.
- **What only KMS gives.** With a local vault key, whoever holds the vault's
  configuration and a copy of the database holds every value, and nothing
  outside coffre records either being used. AWS KMS adds a second record
  (CloudTrail), lets the vault's access be revoked in IAM at once, and keeps
  the key material from ever being copied out ([keys.md](keys.md)). It also
  costs a round trip per key, and on the Workers Free plan an environment of
  more than 50 secrets cannot be read in one call.
- **A vault key cannot be retired yet.** A new vault key wraps new versions only; every
  older version still needs the vault key that wrapped it, configured in
  `previousKeks` and escrowed, until a rewrap command exists.
- **A holder of an author's key can forge that author's entries.** A copied
  database alone cannot. With a local vault key, the vault's key comes from the
  vault key: whoever holds it, and can write the database, can forge the vault's
  entries and member rows, grants included, besides reading every value.
- **A replaced vault key stays configured to verify the past, and can't vouch for
  anything after the rotation.** What the vault wrote under the key an old
  vault key stands for verifies only while that vault key is in `previousKeks`, and the
  log is checked from its first entry once an hour. After the
  rotation, nothing under its keys counts, so a vault key replaced because it
  leaked forges nothing new; what was forged with it before verifies like
  the rest. The app key, `APP_KEY`, and with KMS the vault's
  `signingKey`, cannot be changed at all.
- **A MAC proves a row is genuine, not current.** Putting back a genuine old
  sign-in row can undo one sign-out until the session's own expiry; a
  member's removal still ends it, through the generation.

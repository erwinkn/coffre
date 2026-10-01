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
  auditChainKey: env.AUDIT_CHAIN_KEY,
}));
```

```ts
// vault/src/worker.ts
import { postgres, vault } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.KEK_ID, key: env.KEK },
  previousKeks: [], // older KEKs, still unwrapping what they wrapped
  rootAdmins: ['erwin@example.com'],
  signingKey: env.SIGNING_KEY,
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

await serveVault({ socket: 'vault.sock', database: 'postgres://coffre_vault_runtime:…@db:5432/coffre', kek, rootAdmins, signingKey });
```

For local development or tests, run one process with
`vault: await localVault({ database, kek, rootAdmins, signingKey })` in the
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
| `@coffre/server` | `/api`, sign-in, syncs and their providers, the heartbeat, the queries; hands pages to the UI | sessions, the app login |
| `@coffre/db` | the Drizzle schemas for Postgres and SQLite, their migrations and migrator, the dialect helpers, the connections, Hyperdrive's included | |
| `@coffre/vault` | wraps and unwraps data keys, decides who may, logs every use | the keys, the vault login |
| `@coffre/client` | the typed API client, the API's types printed from the server's routes, and the helpers that turn a sync provider's fields into its config | |
| `@coffre/core` | what the others share: access rules, envelope encryption, KEK providers, the audit chain, identity and sign-in, and `Vault`, the contract between server and vault | |
| `@coffre/cli` | `init`, `login`, secrets, syncs, audit; built on the client | a CLI session |

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
| `@coffre/vault` (both) | `awsKms`, `KekUnavailableError`, and the config types, `KekProvider` among them |
| `@coffre/vault/node` | `serveVault({ socket, database, …config })`, `connectVault(socket)`, `localVault({ database, …config })` |
| `@coffre/ui` | `createUi()` → `{ fetch(request, { context: { cspNonce, client } }) }`; files in `dist/client` |
| `@coffre/client` | `createClient({ url, headers?, transport? })` |

Where `config` is, for the server, `{ publicUrl, vault, auth, auditChainKey,
syncs? }` and, for the vault, `{ database, kek, previousKeks?, rootAdmins, signingKey,
bulkLimit? }`, a KEK being a local key or `awsKms(…)` ([keys.md](keys.md)).
Each is checked when the deployment starts, and a bad value (a 31-byte key,
a public URL with a path, no root admin) fails it with a message naming the
setting.

Migrations live in `@coffre/db` and run through `@coffre/server`'s command,
`pnpm exec coffre-server migrate`, not the CLI: the schema must match the
server's version exactly, which the lockstep version guarantees, and the
CLI's may differ.

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
| change someone's access, in one transaction | `PATCH /api/access/user:ada@acme.example {"market": "developer", "market/prod": null}` |
| syncs, and where this instance can sync to | `GET` / `POST /api/syncs/market/prod`, `PATCH` / `DELETE /api/syncs/by-id/:id`, `POST …/:id/runs`, `GET /api/syncs/providers` |
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
that take the request's method: `DELETE /api/syncs/by-id/…` names a sync,
while `GET /api/syncs/by-id/prod` is still a project named `by-id`.

Behind it, a request loads the caller and all their grants in one query, and
every permission check after that is a plain function. With paths resolved in
one join, the app needs about a dozen reads, down from about a hundred
hand-written queries today.

## The vault

The app decides **who** someone is. The vault decides **what** they may
decrypt. The vault never sees a cookie, an OAuth flow or a session; the app
passes it a claim:

```ts
await vault.unwrap({
  principal: 'user:dev@acme.example',
  purpose: 'reveal', // or 'run', 'compare', 'sync'
  requestId,
  items: [{ secret: { projectId, environmentId, secretId, version: 4 }, wrapped }],
});
// { ok: true, keys: [...] }
// { ok: false, refusal: { code: 'no_grant', message: '...' } }
```

Before it unwraps anything, the vault checks that the principal has not been
removed, that an unexpired grant covers that environment for reading, that
the wrapped key belongs to that secret (the key is bound to the ids, so a key
moved to another row is refused as `bad_claim`), and that the principal is
under the bulk limit. It logs the attempt either way. A batch is all or
nothing: fifty keys for one `coffre run` are one decision and one refusal.

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
| `log` | the shared log filtered to vault entries, with its chain verified; root admins only |
| `verifyLog` | check the shared chain and the vault's MACs, and replay members and grants |

Every argument and result is plain data, and a refusal is a value, not a
thrown error, so the same interface works across a process boundary. The app
turns a refusal into a 403 `vault_refused` carrying the vault's code
(`removed`, `no_grant`, `expired`, ...), or a 403 `bulk_limit`. The vault
logs what it refuses; the app adds its own entry, with code `vault_<code>`,
only where the refusal is part of something larger it was doing, a write
or a new sync's grants.

The vault owns everything that decides access: the key encryption key (KEK),
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
  `VAULT_HYPERDRIVE`, using the vault's login. No database connection lives
  across requests.
- **Node, its own process** (`serveVault` and `connectVault`): the vault
  opens the same Postgres database as the app, through its own login, and
  answers on a Unix socket. The socket is its authentication: a file made
  `0660`, which only the vault's user and a group it shares with the server
  may open. Each call is one HTTP POST over the socket, `/<method>` with
  the arguments as a JSON array. The process facing the network holds no KEK.
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
| Config | `auditChainKey`, `auth` (sign-in or Access settings) | `kek`, `previousKeks`, `rootAdmins`, `signingKey`, `bulkLimit` |
| Tables it writes | projects, environments, ciphertext and wrapped keys, the directory, sessions, syncs; app entries in `audit_log` | `vault_members`, `vault_grants`; vault entries in `audit_log` |
| Connection | `coffre_runtime`, through `HYPERDRIVE` or a Node Postgres URL | `coffre_vault_runtime`, through `VAULT_HYPERDRIVE` or a Node Postgres URL |

Both connections reach the same database. Each Worker gets only its own
configuration secrets. Neither stores a KEK or audit key in the database.
The database's grants protect members and grants from the app's login;
row-level security protects each author's entries from the other's login.
The owner can bypass those restrictions, but cannot forge an entry's MAC
without its author's key. SQLite has no logins and is only for tests and
local development.

### Transactions

No app transaction stays open across a vault call. A request prepares its
keys outside SQL, then commits its app writes and audit entries together.
A reveal gets keys from the vault, then commits the app's audit before
returning values. If either audit append fails, no value is returned.
An unused wrap or a vault release followed by a failed app transaction can
remain in the log; it is evidence of that attempt, not a successful answer.

The vault locks affected members before the shared audit head. Its member
and grant changes commit with their audit entries. With a local KEK, a read
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
`auditChainKey`; the vault derives its own from `signingKey`. Neither can
authenticate the other's entries alone.

An append locks the head, reads the database clock, and refuses a head that
does not name the last entry or is behind one the process remembers. A new
head is remembered only after commit. Postgres forbids both runtime logins
from changing or deleting entries and permits each to append only as its
own author. The owner can lift the triggers and bypass row-level security;
the MACs still expose changes made without the keys.

Every five minutes the Cron trigger appends an `audit.heartbeat` entry, then
asks the vault to checkpoint the log. The vault reads the log itself: it
recomputes the whole chain from its first entry, every hash from content
and its own entries by their MACs, checks that the prefix its last
checkpoint signed is still there, then signs the log up to its last entry
with Ed25519, in an `audit.checkpoint` entry of its own. It signs nothing
over a rewrite or a cut, anywhere in the log, and a call with nothing new
returns the last one.
`/readyz` is a query: ready while the newest heartbeat is under eleven
minutes old and a checkpoint after it carries the vault's signature. There
is no heartbeat table.

`GET /api/audit/verification` (owners only), also called by `coffre verify`,
checks the chain from its first entry and authenticates the app's MACs.
It asks the vault to check its MACs over the same prefix, every checkpoint
against the prefix it signed, and to replay member and grant changes.
A grant inserted by the owner without a matching vault entry is detected
by replay. The answer is the entry verified through, or the entry where it
breaks and whose check found it.

**One entry per human action.** A read is the vault's `secret.read`, one
per secret, with its purpose (`reveal`, `run`, `compare`, `sync`); a
write is the app's `secret.write`, naming the vault's `key.wrap` by
`related_seq`; access and membership changes are the vault's
(`access.grant`, `access.revoke`, `member.*`), and the app keeps no copy.
One operation id ties together everything one action did. Sign-ins, tokens,
the vault's key operations and the heartbeat are detail: in the log and its
chain, but left out of `GET /api/audit` unless `detail=1`.

The limits:

- **A complete older backup can verify.** Someone able to restore the
  database and its head needs no key to restore a valid history. A live
  process remembers how far it got, but restarting it loses that witness.
  There is no external checkpoint export yet. AWS CloudTrail, when using
  KMS, records key use outside this database.
- **A holder of an author's key can forge that author's entries.** A copied
  database alone cannot do so. An app takeover can also act as a principal
  who already has access; the vault does not authenticate browser sessions.
- **Signing-key rotation is not implemented.** Checkpoints are verified
  with the current key, and vault entry MACs derive from it. Keep that key
  with backups. The app's audit key is needed for its entries and sign-in
  rows too.

### What the vault enforces and verifies

The shared log is append-only. The vault records every unwrap attempt and
every change to grants or status. Root admins read its entries through
`GET /api/audit/vault` and on the audit page. Each page verifies the entries
shown and the chain since the head the vault last verified. The first view
after startup, or `?full=1`, verifies from the first entry; a full check also
replays members and grants.

A sync reads as a principal of its own (`sync:<id>`), with a grant made when
the sync is added and revoked when it is removed. Revoking that grant stops
the sync: its next run is refused.

What the vault stops:

- **A permission bug in the app.** An endpoint checks the project but forgets
  the environment; someone with `market/dev` asks for
  `market/prod/DATABASE_URL`. The app lets it through, and the vault refuses:
  the grant covers `dev`.
- **Someone removed getting back in.** An offboarding bug leaves a session
  alive; the vault refuses the principal, which only it can restore.
- **A copy of the database.** It holds no KEK.
- **Rewritten log entries without the author's key.** Their MACs fail, even
  if the owner rebuilds the public chain.
- **Access granted around the vault.** Verification detects a grant or member
  written straight into the database without a matching vault entry. The
  vault can honour a forged grant until verification finds it; database
  privileges are what keep the app from writing one.

What it does not stop: an app fully taken over can act as anyone who already has
access. The vault makes that loud rather than impossible: the key never
leaves it, every read lands in a log the app cannot edit, and bulk reads trip
its limit. Closing it would take requests signed by keys the principals hold
themselves, which fits this interface later without the vault learning about
sign-in.

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

A MAC authenticates a row, not its freshness. Restoring a genuine old row
can undo an individual sign-out or revocation until expiry; the vault's
generation still rejects rows from a membership that was removed. Changing
`auditChainKey` invalidates these rows too.

## Databases

The deployed app database is Postgres. SQLite remains for tests, local Node
development and conformance. The integration suite runs on both through
Drizzle, using the same queries.

Every query lives in one module, `packages/server/src/db/queries.ts`, and the
rest of the server writes no SQL (lint keeps `drizzle-orm` inside it and
`packages/db/src/`, and the vault's own store). There are named
reads, one per shape of data the server needs (the caller, a path, an
environment's secrets, the members, the syncs, a page of the log), each
returning everything its callers use in one statement. There are also four
generic writes (insert, insert if absent, upsert, update) and a row lock.
Writes do not check first and do not read back. A unique constraint answers
"is this slug taken". An update that matches the old value answers "was it
still there": `{ id, revokedAt: null }` changes one row or none. Row locks are
kept for real races (the audit head, offboarding against sign-in, sync
leases, version counters), and each one says which race it guards.

The database comes from its URL: `postgres://` or `postgresql://` opens
node-postgres; `file:` or `libsql:` opens @libsql/client for SQLite
(`packages/db/src/connect.ts`). The SQLite driver loads only when
asked for. The Worker builds its Postgres database from the Hyperdrive pool
with `createDatabase`.

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

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
import { vault } from '@coffre/vault/cloudflare';
export { VaultObject } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
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

await serve({ port: 3000, publicUrl, database: 'postgres://…', vault: connectVault('vault.sock'), auth, auditChainKey });

// src/vault.ts
import { serveVault } from '@coffre/vault/node';

await serveVault({ socket: 'vault.sock', store: 'vault.db', kek, rootAdmins, signingKey });
```

or as one, with `vault: await localVault({ store, kek, rootAdmins, signingKey })`
in the server. `database` is a URL there: `postgres://`, `mysql://` or
`file:` for SQLite.

`coffre init --workers` or `coffre init --node` writes such a project:
[examples/workers](../examples/workers) or [examples/node](../examples/node)
exactly, including the Workers' `wrangler.jsonc` files (Hyperdrive, the
service binding, the Cron trigger, the UI's static files, the vault's Durable
Object).

## Packages

| Package | What | Holds |
|---|---|---|
| `@coffre/ui` | the web UI, server-rendered, and its static files | nothing sensitive |
| `@coffre/server` | `/api`, sign-in, syncs and their providers, the heartbeat, the database layer and its migrations; hands pages to the UI | sessions, the app database |
| `@coffre/vault` | wraps and unwraps data keys, decides who may, logs every use | the keys, the vault's store |
| `@coffre/client` | the typed API client, the API's types printed from the server's routes, and the helpers that turn a sync provider's fields into its config | |
| `@coffre/core` | what the others share: access rules, envelope encryption, KEK providers, the audit chain, identity and sign-in, and `Vault`, the contract between server and vault | |
| `@coffre/cli` | `init`, `login`, secrets, syncs, audit; built on the client | a CLI session |

A package imports another by name, never by a relative path (a lint rule
holds every package to it), and all six are released together at one
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
| `@coffre/vault/cloudflare` | `vault(env => config)`, the Worker's default export; `VaultObject`, its Durable Object |
| `@coffre/vault` (both) | `awsKms`, `KekUnavailableError`, and the config types, `KekProvider` among them |
| `@coffre/vault/node` | `serveVault({ socket, store, …config })`, `connectVault(socket)`, `localVault({ store, …config })` |
| `@coffre/ui` | `createUi()` → `{ fetch(request, { context: { cspNonce, client } }) }`; files in `dist/client` |
| `@coffre/client` | `createClient({ url, headers?, transport? })` |

Where `config` is, for the server, `{ publicUrl, vault, auth, auditChainKey,
syncs? }` and, for the vault, `{ kek, previousKeks?, rootAdmins, signingKey,
bulkLimit? }`, a KEK being a local key or `awsKms(…)` ([keys.md](keys.md)).
Each is checked when the deployment starts, and a bad value (a 31-byte key,
a public URL with a path, no root admin) fails it with a message naming the
setting.

Migrations ship with `@coffre/server`, not the CLI, because the schema must
match the server's version exactly and the CLI's may differ:
`pnpm exec coffre-server migrate`.

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
implementation, and a small storage layer. Every query is plain SQL in one
file, `store.ts`, over a five-call synchronous SQLite interface with two
backends: a Durable Object's own SQLite, and a file through Node's built-in
`node:sqlite`. Its migrations are SQL strings, applied in one transaction
when the vault opens. The interface:

| Call | Does |
|---|---|
| `unwrap`, `wrap`, `rewrap` | data keys, for a principal whose grants cover the secret |
| `access(principal)` | one principal's status, owner flag and grants; the app asks once per request |
| `members()` | everyone's, in one call, for the Users and project access pages |
| `setAccess` | several places for one principal, all or nothing (`PATCH /api/access/<member>`) |
| `admit`, `remove` | add or restore a member, or remove one and revoke every grant |
| `checkpoint`, `latestCheckpoint` | sign the heads of both logs; read the latest signature |
| `log` | a page of the vault's own log, with its chain verified; root admins only |
| `verifyLog` | check the whole of that log, and replay members and grants from it |

Every argument and result is plain data, and a refusal is a value, not a
thrown error, so the same interface works across a process boundary. The app
turns a refusal into a 403 `vault_refused` carrying the vault's code
(`removed`, `no_grant`, `expired`, ...), or a 403 `bulk_limit`, and logs it
in its own log as `vault_<code>`.

The vault owns everything that decides access: the key encryption key (KEK),
grants (`(principal, place) → role`, one per member per place, with an
optional expiry), principal status (active or removed), the root admins (from
its configuration, so no row anywhere makes someone one), and its own log.
The app keeps a directory row per member for names and sessions, but whether
that member is still in comes only from `vault.access`. `can()` stays a plain
function over the grants that call returned.

### Transports

- **Workers**: the vault is a Worker of its own, `coffre-vault`, with no
  route and no HTTP surface. It holds one Durable Object, `VaultObject`,
  whose SQLite is the store. The app reaches it only through the `VAULT`
  service binding, whose calls land on the Worker's entrypoint (RPC).
- **Node, its own process** (`serveVault` and `connectVault`): the vault
  over a SQLite file of its own (created `0600`; one that other users may
  write is refused), answering on a Unix socket. The socket is the whole of
  its authentication: a file made `0660`, which only the vault's user and a
  group it shares with the server may open. So there is no port to reach
  and no shared secret to leak or rotate, and the process facing the network
  holds no key. Each call is one HTTP POST over the socket, `/<method>` with
  the arguments as a JSON array. A TCP port with a shared token was the
  alternative; it would reach across machines, which the vault has no reason
  to.
- **Node, in process** (`localVault`): the same vault in the server's
  process, for the tests and for deployments where one process is enough.
  Each call's arguments and results go through JSON on the way, as over RPC,
  so nothing that only works in-process gets in.
- **Locally**, `pnpm dev` runs the vault as an auxiliary Worker of the
  app's `vite dev`, and conformance runs both with
  `wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc`. Either way
  the app's `VAULT` binding reaches it as in production.

### Where each secret lives

| | App (Worker `coffre`) | Vault (Worker `coffre-vault`) |
|---|---|---|
| Config | `auditChainKey`, `auth` (sign-in or Access settings) | `kek`, `previousKeks`, `rootAdmins`, `signingKey`, `bulkLimit` |
| Store | projects, environments, ciphertext and wrapped keys, the directory, sessions, syncs, the app's audit log | grants, principal status, unwrap counts, checkpoints, its own log |
| Where | Postgres or MySQL through Hyperdrive; any of the three in Node | the Durable Object's SQLite; a SQLite file in Node |

Each Worker gets only the secrets its own `wrangler.jsonc` declares, and no
config type has a field for the other side's keys. The separation comes from
storage, not database privileges, so it holds whatever database either side
uses: the vault's store is one the app has no credentials for, and neither
store holds a key.

### The bulk limit

At most `bulkLimit` data keys unwrapped per principal in any rolling window,
`{ count: 1000, windowMinutes: 15 }` by default: twenty `coffre run`s of a 50-key environment
back to back, which no person or pipeline does, while a script pulling every
value it can reach stops within seconds. Each unwrapped key counts, so one
50-key run is 50. A refusal is logged and answers 403 `bulk_limit`; the
principal reads again as the window rolls on.

### Checkpoints

The app's audit log is hash-chained with `auditChainKey`, which catches
someone who can write the database but not read the app's config. Someone
who holds the app could rewrite the log and chain it again. The vault's log
is the mirror: its chain is keyed from `signingKey`, and someone who holds
the vault could rewrite it and chain it again. So after each heartbeat, the
app has the vault sign both heads at once:

```ts
await vault.checkpoint({ seq: 812, headHash, previous: { seq: 640, hash } });
// { ok: true, checkpoint: { seq: 812, headHash, vault: { seq: 5031, hash }, signedAt, keyId, signature } }
```

The vault signs `coffre.checkpoint.v2|812|<headHash>|5031|<hash>|<signedAt>`
with an Ed25519 key only it holds, and only if both logs hold since the last
one: `previous` is the app head it signed last (else `checkpoint_diverged`),
and its own log still carries the vault head it signed last and hashes
forward from it (else `log_broken`). Either refusal is logged, and fails the
heartbeat. Its checkpoints table is append-only, like its log.

The app then writes the signed checkpoint into its own log, as an
`audit.checkpoint` entry, so each log holds a signed record of the other's
head:

| Rewritten | Caught by |
|---|---|
| the app log, behind a checkpoint | the vault's latest checkpoint: the app's entry 812 no longer hashes to `headHash` |
| the vault log, behind a checkpoint | the `audit.checkpoint` entry: the vault's entry 5031 no longer hashes to its `hash` |
| the vault's store, put back to an older copy | the same entry: the vault's latest checkpoint is behind it |

`GET /api/audit/verification` (owners only) checks all three. It recomputes
the app log's chain and checks the head the vault signed last, with the
vault's public key. It checks the signature on the last `audit.checkpoint`
entry, and that the vault's latest checkpoint is not behind it. Then it has
the vault check its own log whole (`verifyLog`): the chain from the first
entry, the vault heads both checkpoints signed, and the members and grants
in its store against a replay of the log. Every change to them is logged in
the transaction that makes it, so a grant inserted into the vault's SQLite,
or a removal undone, is a row the log does not explain. A failure names the
log (`log: 'audit'` or `'vault'`) and, when the fault is at one, the entry.

`auditChainKey` stays in the app. Signing covers someone who holds
the app; the keyed chain still covers the entries written since the last
checkpoint against someone who holds only the database. Moving the key would
put a vault call on every audited write, and the sign-in state key is derived
from it.

What checkpoints do not catch:

- **Entries appended to the vault log by someone who holds its keys.** The
  chain is an HMAC under a key derived from `signingKey`, so a copy of the
  store alone (a backup, `vault.db` on a shared disk) cannot take a forged
  `grant.create` entry that verifies. Whoever holds the configuration as
  well can append one, with the grant it explains, and it replays cleanly.
  The cost of the key: no one without it can recompute the chain, only check
  the heads the vault signed.
- **A rewrite of either log since the last checkpoint.** Heartbeats bound it
  to minutes; for the app log the keyed chain covers it too.
- **A new signing key.** Each checkpoint is checked with the vault's current
  public key, so rotating `signingKey` fails the recorded ones until
  rotation is designed.

### What the vault stops

The vault's own log is append-only (triggers refuse updates and deletes, and
its code has no path to either) and hash-chained. It records every unwrap
attempt and every change to grants or status. Root admins read it through
the app (`GET /api/audit/vault`), and on the audit page. Each page view
verifies the chain without rehashing all of it, which grows with every
unwrap: the rows shown, the head the vault verified last (which a rewrite
re-chained to hide would change), and what was appended since. The first
view after the vault starts, or one asking for `full` (`?full=1`), rehashes
from the first entry, one row in memory at a time, and replays members and
grants as `verifyLog` does.

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
- **A copy of either database.** Neither holds a key.
- **A rewritten app log.** It no longer matches the signed checkpoint.
- **A rewritten vault log, or its store put back.** It no longer carries the
  head the app recorded from the last checkpoint.
- **Access granted around the vault.** A grant or member written straight
  into its store does not follow from its log.

What it does not stop: an app fully taken over, or someone who can write to
the app's database and forge a session, can act as anyone who already has
access. The vault makes that loud rather than impossible: the key never
leaves it, every read lands in a log the app cannot edit, and bulk reads trip
its limit. Closing it would take requests signed by keys the principals hold
themselves, which fits this interface later without the vault learning about
sign-in.

## Databases

The app database can be Postgres, MySQL or SQLite. Every query goes through
Drizzle; none is written by hand. The integration suite runs against all
three. [A spike](spikes/drizzle-dialects.md) ran the same queries,
joins, a transaction, an upsert and 24 concurrent audit appends on all three.

Every query lives in one module, `packages/server/src/db/queries.ts`, and the
rest of the server writes no SQL (lint keeps `drizzle-orm` inside
`packages/server/src/db/`, and the vault's own store). There are named
reads, one per shape of data the server needs (the caller, a path, an
environment's secrets, the members, the syncs, a page of the log), each
returning everything its callers use in one statement. There are also four
generic writes (insert, insert if absent, upsert, update) and a row lock.
Writes do not check first and do not read back. A unique constraint answers
"is this slug taken". An update that matches the old value answers "was it
still there": `{ id, revokedAt: null }` changes one row or none. Row locks are
kept for real races (the audit head, offboarding against sign-in, sync
leases, version counters), and each one says which race it guards.

The database comes from its URL: `postgres://` opens node-postgres,
`mysql://` mysql2 and `file:` or `libsql:` @libsql/client (SQLite), each
loaded only when asked for (`packages/server/src/db/connect.ts`). The
Worker does not come through there: it builds its Postgres database from the Hyperdrive pool
with `createDatabase`, and stays on Postgres.

Each query is written once, typed against the Postgres schema. Drizzle has no
type shared by its dialects, so the MySQL and SQLite databases are cast to the
Postgres one in a single small module, `portable.ts`; at run time each
database always travels with its own dialect's tables. The cast is unsound by
construction, so three things guard it: a compile-time check in the same
module that every table's row type matches its Postgres twin, a parity test
(the three schemas have the same tables, columns, nullability, keys, indexes
and foreign keys), and the whole suite on every engine, on every Drizzle
upgrade.

What differs between them stays in the schemas and one module,
`packages/server/src/db/dialect.ts`:

- **Schemas and migrations.** Drizzle's table builders are per dialect
  (`pgTable`, `mysqlTable`, `sqliteTable`), so there are three schemas and
  three migration trees under `packages/server/src/db/migrations/`, each a
  single baseline: the generated tables inside a hand-written template
  (`packages/server/src/db/baseline/`) that adds the first audit rows,
  MySQL's collation and the Postgres runtime role. Until the first deployment,
  schema changes are regenerated into the baseline (`pnpm db:generate`)
  rather than added as new migrations. Tests fail when a tree falls behind:
  the parity test, and a check that each baseline is what its schema and
  template generate. Types differ on purpose: bytes are `bytea`, `longblob`
  (`blob` is too small for a 64 KiB secret) and `blob`.
- **Ids come from the application**, never from the database: MySQL has no
  `RETURNING`, and no write reads one back.
- **Named operations, never branches in the services.** Insert if absent,
  upsert, row locks, rows changed, recognising a duplicate key, the clock and
  reading a condition are each a function of `dialect.ts`, and its header
  tables how each engine does them.
- **Locks.** The audit chain locks a permanent head row (`FOR UPDATE` on
  Postgres and MySQL) instead of a Postgres advisory lock. MySQL runs at READ
  COMMITTED, set on every connection: at its default, REPEATABLE READ, two
  transactions that lock the same missing row and then both insert it
  deadlock. SQLite has a single writer but its driver does not queue for us
  (24 concurrent appends failed with `SQLITE_BUSY`), so `connect.ts` queues
  transactions itself, once per database file however many clients open it;
  each takes the write lock with its first statement, so a row lock there is a
  no-op.
- **Postgres-only SQL is remodelled, not written three ways.** Partial unique
  indexes became plain ones: a grant's scope columns are exactly one non-null
  (a check), so plain unique indexes over them do the same job, and "one live
  identity per subject" is a unique index on a generated column that holds the
  subject only while the identity is not revoked. Emails are stored lowercase
  and a check keeps them so, rather than matched with `lower()`. Checks stay
  in the database on all three, each in its dialect's words (a regex is `~`,
  `regexp_like` or `GLOB`; JSON is text that must parse, `::jsonb` or
  `json_valid`). One is only partly the database's: SQLite's `lower()` folds
  ASCII only, so non-ASCII case in an email is the server's to fold. No query
  filters on a JSON field.

Some things stay Postgres-only: the restricted runtime login
(`coffre_runtime`, which cannot rewrite the audit log) and `pnpm test:schema`,
which checks its privileges. On MySQL and SQLite the server connects with one
login.

D1 is not a fit for the app database: it has no interactive transactions, and
the audit chain reads the previous hash, computes the next in JavaScript, then
writes. Drizzle's D1 transactions send `BEGIN`, which D1 rejects. A Durable
Object's SQLite has them, for an all-Cloudflare deployment without Postgres.

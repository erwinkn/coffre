# Architecture: coffre as a library

Where coffre is going: a set of packages a deployment imports and configures
in code, rather than an app you fork or check out. This is the target; the
[roadmap](roadmap.md) says what exists today and in what order the rest
lands.

## A deployment is a small project

A Workers deployment is two Workers in one small repository of your own:

```ts
// app/src/worker.ts
import { coffre, signin, github, postgres } from '@coffre/server/cloudflare';

export default coffre((env: Env) => ({
  publicUrl: 'https://coffre.erwinkn.com',
  database: postgres(env.HYPERDRIVE),
  vault: env.VAULT, // a service binding to the Worker below
  auth: signin({
    title: 'coffre',
    providers: [github({ clientId: 'Ov23li…', clientSecret: env.GITHUB_CLIENT_SECRET })],
  }),
}));
```

```ts
// vault/src/worker.ts
import { vault } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
  keys: { current: { id: 'erwinkn-2026-09', key: env.COFFRE_KEK } },
  rootAdmins: ['erwin@example.com'],
}));
```

All configuration is passed to these functions. coffre reads no environment
variable of its own: a deployment brings values however it likes (Worker
secrets, a password manager, a file) and hands them over. Settings are typed,
so a misspelt provider option fails the typecheck rather than a sign-in.

A Node deployment is the same idea: `serve({ port, database, vault, auth })`
from `@coffre/server/node`, with the vault in a second process or, where
isolation does not matter, in the same one.

`coffre init --workers` or `coffre init --node` writes such a project,
including its `wrangler.jsonc` (Hyperdrive, the service binding, the Cron
trigger, the UI's static files).

## Packages

| Package | What | Holds |
|---|---|---|
| `@coffre/ui` | the web UI, server-rendered, and its static files | nothing sensitive |
| `@coffre/server` | `/api`, sign-in, syncs, the heartbeat; hands pages to the UI | sessions, the app database |
| `@coffre/vault` | encrypts and decrypts, decides who may, logs every use | the keys, the vault's store |
| `@coffre/client` | the typed API client | |
| `@coffre/cli` | `init`, `login`, secrets, syncs, audit; built on the client | a CLI session |

`packages/core` and `packages/db` stay internal and are bundled into the
packages above. Everything ships as compiled JavaScript with declarations:
Node refuses to strip TypeScript types inside `node_modules`.

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
headers; the UI only renders. Its static files are served straight from
`node_modules/@coffre/ui/dist/client`, under `/_coffre/assets/` so they cannot
collide with a deployment's own paths. [A spike](../spikes/ssr-ui/REPORT.md)
showed this works: a separate Worker imported today's built UI, served its
files through pnpm's symlink, rendered on the server with one copy of React and
hydrated with the nonce intact, and Node 24 ran the same build behind a small
`node:http` adapter. Still unproven: uploading symlinked files to Cloudflare
(check with `wrangler deploy --dry-run` in CI).

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
| syncs | `GET` / `POST /api/syncs/market/prod`, `PATCH` / `DELETE /api/syncs/by-id/:id`, `POST …/:id/runs` |
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
vault.unwrap(wrapped, {
  principal: 'user:42',
  secret: { project: 'market', environment: 'prod', key: 'DATABASE_URL', version: 4 },
  purpose: 'reveal', // or 'run', 'sync'
});
```

and before decrypting, the vault checks that the principal has not been
removed, that a grant covers `market/prod` for reading and has not expired,
and that the principal is under the bulk-read limit. It logs the attempt
either way.

The vault owns everything that decides access: the keys, grants, principal
status (active or removed), the root admins (from its configuration, so no
row anywhere makes someone one), and its own log. Changing a grant is a vault
call (`vault.grant`, `vault.revoke`, `vault.remove`), and the app asks
`vault.grantsFor(principal)` to decide what its pages show.

The separation comes from storage, not database privileges, so it holds
whatever database either side uses: the vault's store is one the app has no
credentials for.

| | App database | Vault store |
|---|---|---|
| Holds | projects, environments, ciphertext and wrapped keys, the directory, sessions, syncs, the app's audit log | grants, principal status, its log |
| Workers | Postgres or MySQL through Hyperdrive | a Durable Object's SQLite, bound to the vault Worker alone |
| Node | Postgres, MySQL or a SQLite file | a SQLite file the vault process owns |

The app's audit log stays tamper-evident without database permissions: the
vault signs its checkpoints, so a rewritten log no longer verifies. The
vault's own log is append-only by construction, since its code has no path
that updates or deletes a row, and hash-chained.

A sync reads as a principal of its own (`sync:<id>`), with a grant made when
the sync is added. Revoking that grant stops it.

What the vault stops:

- **A permission bug in the app.** An endpoint checks the project but forgets
  the environment; someone with `market/dev` asks for
  `market/prod/DATABASE_URL`. The app lets it through, and the vault refuses:
  the grant covers `dev`.
- **Someone removed getting back in.** An offboarding bug leaves a session
  alive; the vault refuses the principal, which only it can restore.
- **A copy of either database.** Neither holds a key.

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
three. [A spike](../spikes/drizzle-dialects/REPORT.md) ran the same queries,
joins, a transaction, an upsert and 24 concurrent audit appends on all three.

Every query lives in one module, `packages/db/src/queries.ts`, and the server
writes no SQL (lint keeps `drizzle-orm` out of `apps/web`). There are named
reads, one per shape of data the server needs (the caller, a path, an
environment's secrets, the members, the syncs, a page of the log), each
returning everything its callers use in one statement. There are also four
generic writes (insert, insert if absent, upsert, update) and a row lock.
Writes do not check first and do not read back. A unique constraint answers
"is this slug taken". An update that matches the old value answers "was it
still there": `{ id, revokedAt: null }` changes one row or none. Row locks are
kept for real races (the audit head, offboarding against sign-in, sync
leases, version counters), and each one says which race it guards.

Each query is written once, typed against the Postgres schema. Drizzle has no
type shared by its dialects, so the MySQL and SQLite databases are cast to the
Postgres one in a single small module; at run time each database always
travels with its own dialect's tables. The cast is unsound by construction, so
two things guard it: a parity test (the three schemas have the same tables,
columns, nullability and keys, and the same row types) and the whole suite on
every engine, on every Drizzle upgrade.

What differs between them stays in the schemas and a small per-dialect module:

- **Schemas and migrations.** Drizzle's table builders are per dialect
  (`pgTable`, `mysqlTable`, `sqliteTable`), so there are three schemas and
  three migration trees, changed together. Types differ on purpose: bytes are
  `bytea`, `longblob` (`blob` is too small for a 64 KiB secret) and `blob`.
- **Ids come from the application**, never from the database: MySQL has no
  `RETURNING`.
- **Upserts and locks** are named operations of the dialect module, never
  branches in the services. The audit chain locks a permanent head row
  (`FOR UPDATE` on Postgres and MySQL) instead of a Postgres advisory lock.
  SQLite has a single writer but its driver does not queue for us (24
  concurrent appends failed with `SQLITE_BUSY`), so the SQLite module queues
  writes itself, once per database.
- **Postgres-only SQL in today's services** (partial unique indexes, regex
  checks, `array_agg`, lateral joins, `jsonb ->>` filters, `lower()` matching)
  is remodelled rather than written three ways: a JSON field used in a filter
  becomes a column, a case-insensitive identity is stored normalised.

D1 is not a fit for the app database: it has no interactive transactions, and
the audit chain reads the previous hash, computes the next in JavaScript, then
writes. Drizzle's D1 transactions send `BEGIN`, which D1 rejects. A Durable
Object's SQLite has them, for an all-Cloudflare deployment without Postgres.

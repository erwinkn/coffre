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
`/readyz` itself and hands every other path to the UI.

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
three.

What differs between them is kept to a small per-dialect module:

- **Schemas.** Drizzle's table builders are per dialect (`pgTable`,
  `mysqlTable`, `sqliteTable`), so each dialect has its schema and migrations;
  a test checks the three describe the same tables and columns.
- **Ids come from the application**, never from the database: MySQL has no
  `RETURNING`.
- **Upserts and locks.** Postgres locks rows (`FOR UPDATE`) and takes advisory
  locks for the audit chain and for offboarding racing a sign-in; MySQL locks
  rows; SQLite has a single writer and needs neither.

D1 is probably not a fit for the app database: as far as we know it has no
interactive transactions, and the audit chain and offboarding read, then
write, under a lock. A Durable Object's SQLite has them, for an all-Cloudflare
deployment without Postgres.

## Open questions, settled by spikes first

1. **A prebuilt server-rendered UI.** Can a consumer's Worker import
   TanStack Start's built server and serve its static files from
   `node_modules`? If not, the fallback is a Vite plugin the template runs,
   so the consumer's project builds the UI itself.
2. **One set of Drizzle queries across three dialects.** Drizzle's types are
   per dialect. The question is how to write each query once, keep it typed,
   and confine the differences to the per-dialect module.

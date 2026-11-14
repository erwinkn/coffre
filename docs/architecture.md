# Architecture: coffre as a library

coffre is a set of packages a deployment imports and configures in code,
rather than an app you fork or check out. The [roadmap](roadmap.md) says how
it got here and what comes next; [deploy.md](deploy.md) walks through a
deployment.

## A deployment is a small project

A Workers deployment is two Workers in one small repository of your own.
The app is a TanStack Start app, configured once:

```ts
// app/src/coffre.ts
import { createCoffre, github, postgres, signin } from '@coffre/server/cloudflare';

export const coffre = createCoffre((env: Env) => ({
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
// app/src/server.ts: the Worker, Start's handler with coffre in each request
export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => handler.fetch(request, { context: coffre.request(env, ctx) }),
  scheduled: coffre.scheduled,
};
```

with coffre's middleware in its `app/src/start.ts` and coffre's routes in
its `app/src/router.tsx` ([The UI](#the-ui)). The vault is a Worker of its
own:

```ts
// vault/src/worker.ts
import { postgres, vault } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  previousKeks: [], // older vault keys: what they wrapped still opens, and what the vault signed under them verifies
  owners: ['erwin@example.com'], // Owners of the whole instance, made ones as it starts, whom nobody demotes while named
}));
```

All configuration is passed to these functions. coffre reads no environment
variable of its own: a deployment brings values however it likes (Worker
secrets, a password manager, a file) and hands them over. Settings are typed,
so a misspelt provider option fails the typecheck rather than a sign-in.
`createCoffre(…)` calls the function once for each `env` object Workers
hands it, in practice once per isolate; `coffre.request(env, ctx)` opens the
invocation's database client, closed once coffre's work for the request is
done.

0.16.0 runs on Workers only: a Node deployment stays on 0.14 until Node
comes back in 0.16.1 ([Node in 0.16.0](design/0.16.md#node-in-0160)). For tests,
`localVault(config, options)`, from `@coffre/vault/node`, runs the vault in
the server's process, on the same Postgres database.

`coffre init --workers` writes such a project:
[examples/workers](../examples/workers) exactly, including the Workers' `wrangler.jsonc` files (Hyperdrive, the
service binding, the Cron trigger and the UI's static files). Both Workers
use one Postgres database: `HYPERDRIVE` connects as `coffre_runtime`,
`VAULT_HYPERDRIVE` as `coffre_vault_runtime`, with caching disabled on both.
`coffre init --node` writes [examples/node](../examples/node), which waits
for 0.16.1.

## Packages

| Package | What | Holds |
|---|---|---|
| `@coffre/ui` | the web UI, server-rendered, and its static files | nothing sensitive |
| `@coffre/server` | `/api`, sign-in, the pages' queries; hands pages to the UI | the app key, the app's login, which only reads |
| `@coffre/db` | the Drizzle schema for Postgres, its migrations and migrator, the dialect helpers, the connections, Hyperdrive's included | |
| `@coffre/vault` | decides every use and change, writes every row and the log's entries; the signer | the keys, the vault login, the signer's storage |
| `@coffre/client` | the typed API client, the API's types printed from the server's routes | |
| `@coffre/core` | what the others share: access rules, envelope encryption, vault key providers, the log's entries and proofs, identity and sign-in, and `Vault`, the contract between server and vault | |
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
| `@coffre/server/cloudflare` | `createCoffre(env => ({ database, …config }))` → `{ request(env, ctx), scheduled }`; `postgres(env.HYPERDRIVE)` |
| `@coffre/server/start` | `coffreMiddleware`, for the app's `createStart(() => ({ requestMiddleware: [coffreMiddleware, …] }))` |
| `@coffre/server/routes` | `api`, `auth`, `livez`, `readyz`, `plugin`, route options for file routes |
| `@coffre/server/plugins/vault-kv` | `vaultKv()`, a plugin for `plugins: […]`: a read-only Vault KV v2 API at `/v1` ([vault.md](vault.md), [design/plugins.md](design/plugins.md)) |
| `@coffre/server` (both) | `signin`, `github`, `google`, `microsoft`, `oidc`, `cloudflareAccess`, `SigninError`; `githubActions`, `vercel`, `railway`, `cloudflareWorkers`, `SyncConfigError`, `SyncProviderError`; and the config types, `SigninProvider` and `SyncProvider` among them |
| `@coffre/vault/cloudflare` | `vault(env => config)`, the RPC Worker's default export; `postgres(env.VAULT_HYPERDRIVE)`; `CoffreSigner`, the signer's Durable Object, which the vault Worker exports |
| `@coffre/vault` (both) | `awsKms`, `KekUnavailableError`, `KekRefusedError`, `KekBadClaimError`, and the config types, `KekProvider` among them |
| `@coffre/vault/node` | `serveVault({ socket, database, …config })`, `connectVault(socket)`, `localVault({ database, …config })` |
| `@coffre/ui` | each layout's and page's route options, `shell`, `solo`, `projects` and the like; `createRouter(routeTree)`; `<CoffreProvider>`, `useCoffre()`; `CoffreContext` |
| `@coffre/ui/pages/<name>` | each page's component, `ProjectsPage` and the like, for its file route |
| `@coffre/ui/styles.css`, `icon.svg`, `apple-touch-icon.png` | the stylesheet and icons, for the root's head |
| `@coffre/ui/vite` | `coffre()`, the deployment's Vite plugin |
| `@coffre/client` | `createClient({ url, headers?, transport? })` |

Where `config` is, for the server, `{ publicUrl, vault, auth, auditChainKey,
rotateAfterDays? }` (`auditChainKey` is the app key: 0.16's app signs no
entry and derives from it only the keys of its sign-in state and Access
sessions, [The server](design/0.16.md#the-server); the days a value may go unchanged before the UI and
`coffre list` flag it for rotation: 365 if left out, `null` for none)
and, for the vault, `{ database, kek, previousKeks?, owners,
signingKey?, bulkLimit?, memorySeconds?, outageSeconds?, workloads?, log?, alert? }`, a vault key being a local key or `awsKms(…)`
([keys.md](keys.md)). The vault derives its signing key from a local vault key;
`signingKey` is required only with a vault key a key service holds.
Each is checked when the deployment starts, and a bad value (a 31-byte key,
a public URL with a path, no Owner in `owners`) fails it with a message naming the
setting.

Migrations live in `@coffre/db`, and run before the deploy, in the
deployment's pipeline ([expand, then contract](#expand-then-contract)). A
deployment pins `@coffre/cli` with its other coffre packages, and in its
directory `coffre migrate` applies the migrations that CLI carries, which
are the pinned version's: it refuses to run as another version, or on a
database a newer coffre migrated, and asks no instance; anywhere else it
refuses. `coffre-server migrate [database-url]`, the server's own command,
migrates from a URL. A Worker has no files, so the migrations each version
ships are compiled into `@coffre/db/schema-version` from their journals,
which the app holds the database to ([expand, then contract](#expand-then-contract)).

## The UI

The UI is server-rendered TanStack Start, and a deployment's app is a Start
app of its own, a conventional one, which mounts coffre's pieces as it would
an auth SDK's: Vite builds it once, with `@coffre/ui` and `@coffre/server`
as libraries inside it. Its files:

```
app/vite.config.ts            plugins: [cloudflare(…), tanstackStart(), viteReact(), coffre()]
app/src/start.ts              createStart(() => ({ requestMiddleware: [coffreMiddleware, createCsrfMiddleware(…)] }))
app/src/router.tsx            createRouter(routeTree), the tree Start generates from src/routes
app/src/routes/__root.tsx     the document: coffre's stylesheet and icons, <CoffreProvider>
app/src/routes/api.$.ts       createFileRoute('/api/$')({ ...api }); auth.$.ts, livez.ts, readyz.ts likewise
app/src/routes/_coffre.tsx    createFileRoute('/_coffre')({ ...shell }), and each page under it in _coffre/
app/src/routes/_solo.tsx      the sign-in pages' frame, and its pages in _solo/
app/src/server.ts             handler.fetch(request, { context: coffre.request(env, ctx) }); scheduled
app/src/coffre.ts             export const coffre = createCoffre(env => ({ publicUrl, database, … }))
```

**A request.** The Worker's `fetch` hands Start's handler the request with
coffre in its context: `coffre.request(env, ctx)`, the invocation's
database and vault.
Start runs coffre's middleware first, for every request: it mints the
response's nonce, builds the visitor's API client, an in-process call with
their credential, reads the visitor's preferences from their cookies, and
passes the three on; then it sets the security headers, nonce included, on
whatever comes back, in place: a page Start rendered, a redirect, a
not-found, a refusal, or one of coffre's server routes. In place, because
Start goes on to handle what the middleware hands back, a TanStack redirect
by a marker it carries, which a copy would lose; so a response must have
headers that can change, as a `new Response(…)`'s do and
`Response.redirect()`'s and `fetch()`'s do not. One response comes before
any middleware: Start answers a path that starts with `//` with a 308 to the
same path on the same origin, without coffre's headers. It names no other
site, so it is no open redirect. coffre's server routes, `/api/$`,
`/auth/$`, `/livez` and `/readyz`, hand the request to coffre's server,
which answers it as before. A route or a page rendered without the
middleware fails, saying how to add it, rather than answer without
headers. Nothing coffre answers waits for a request body it does not read.

**Server code stays on the server.** Start strips a file route's server
handlers from the browser's build, and coffre's server routes and its
middleware import nothing of the server besides: they reach it through the
request's context, which only the server entry, and what it imports, sets. Conformance checks what the browser loads,
in the build it runs, for the database layer, a driver, a table only the
server knows or a `COFFRE_*` read ([conformance](conformance.md)).

**Route options.** coffre gives each layout and page as route options: its
loader, search, redirects, and a layout's component; not its path. A
deployment mounts them as Start's file routes, a page's file naming its
component from `@coffre/ui/pages/<name>`, so that Start's splitter puts each
page in a chunk of its own, with Start's own preload hints
([Your own routes](deploy.md#your-own-routes)). An app that prefers routes
in code mounts the same options with TanStack's `createRoute`. `shell`, the nav, lets in only
signed-in, registered visitors; `solo` is the frame of the sign-in pages.
A page's component reads its own route's data through the match it renders
in, so it works wherever it is mounted. The app's router registers its
tree, so every link, coffre's and the app's, is checked against it, and
coffre's nav offers only the pages the deployment kept.

**Preferences.** The theme and the folded sidebar are cookies, which the
middleware reads and the browser reads back to hydrate, so a page is drawn
as its visitor left it from the first byte, with no script of coffre's own.
`<CoffreProvider>` renders them as attributes on coffre's element, which its
stylesheet, and its menus, dialogs and tooltips, are scoped to: the
deployment's document keeps its own look.

**What `@coffre/ui` ships.** ES modules, built by Vite in library mode: the
route options and provider, and each page as a module of its own. React, the router, Start and Query stay imports, so the
deployment's single copy of each serves both. The stylesheet and icons are
files of the package, which the root links with `?url`, so the
deployment's Vite processes them, fonts and all.

**One copy of what the pages share.** `@coffre/ui`'s peers, React,
react-dom, TanStack Router, Start, Query, the router's Query integration and
Vite, are pinned exactly, and the deployment pins them itself at those
versions: `coffre init` writes them, `coffre update` moves them with
coffre's packages, and the build stops, naming each, when one differs.
`pnpm check:pins` holds the examples to them, and `@coffre/server`'s peers
to `@coffre/ui`'s.

**`coffre()`, the deployment's Vite plugin.** It puts the static files under
`/_coffre/assets/`, beside `/api` and `/auth`, and never inlines a font, which
the Content-Security-Policy would refuse as `data:`. It makes the server's
build hold everything it runs (`ssr.noExternal`), as a Worker's does, so
that Node resolves nothing from `node_modules`. And it checks the versions above.

**On Workers**, `@cloudflare/vite-plugin` builds the app into
`app/dist/server`, with a `wrangler.json` that says `no_bundle`: `wrangler
deploy -c app/dist/server/wrangler.json` uploads what Vite built as it is,
and the client files Vite built are the Worker's static assets, which
Cloudflare serves before the Worker runs. Nothing bundles the code a second
time, so nothing rewrites what the pages send the browser: 0.1.17's blank
pages came from wrangler's esbuild wrapping seroval's functions in
`__name`, and Vite's build adds no such helper. Locally, `wrangler dev` of
such a build fails every request after one whose body the Worker left
unread, which `vite dev` and Cloudflare do not; conformance and the restore
drill, which run the built app under `wrangler dev`, put an entry of their
own in front of it that reads such a body before answering. coffre itself
never does.

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
or `token:ci-deploy` a member. A service account is `token:<name>` here, in the
vault and in the audit log, whose signed entries hold it; the CLI and the UI
show it as `service:<name>`, and take either (`@coffre/client`'s `shownMember`
and `apiMember`). The URL names the thing and the HTTP method is the verb:

| Call | HTTP |
|---|---|
| how this instance signs people in (public) | `GET /api/auth` |
| who I am, everything I can reach, and what this deployment turns on (`features`: MCP, trust bindings) | `GET /api/me` |
| list, create, rename or archive a project | `GET /api/projects`, `PUT` / `PATCH /api/projects/market` |
| the same for an environment | `PUT` / `PATCH /api/projects/market/prod` |
| delete an archived project or environment for good, owners only (`?dryRun=1` says what it would take) | `DELETE /api/projects/market`, `DELETE /api/projects/market/prod` |
| the keys an environment lacks of those its siblings have, read or not, by name; dismiss or restore them | `GET /api/projects/market/dev/missing`, `PATCH /api/projects/market/dev/dismissals {"SENTRY_DSN": true, "OLD": null}` |
| a version of what reading an environment would open, which changes whenever that does, inherited keys included: for pollers, with read on it and on each parent it inherits from; it reads no value and is not logged. A poller compares it with the version its last read answered, not with one asked before that read: a change undone in between brings that one back | `GET /api/projects/market/prod/version` → `{"version": "…"}` |
| fork an environment: a new one with each key's current value and folder, read and written in the caller's name | `PUT /api/projects/market/staging {"from": "prod"}` |
| list an environment's secrets, never their values: who wrote each value and when (a reference's, its source's current version), and the deployment's `rotateAfterDays` | `GET /api/secrets/market/prod` |
| set, add or archive secrets, one or many, in one transaction | `PATCH /api/secrets/market/prod {"DATABASE_URL": "…", "OLD_KEY": null}` |
| set a secret to a value the client generated, with its recipe (below) | `PATCH /api/secrets/market/prod {"SESSION_SECRET": {"value": "…", "generated": {"recipe": "bytes:32:hex"}}}` |
| what that write would do, per key, without values and without writing | `PATCH /api/secrets/market/prod?dryRun=1 {…}` → `{"dryRun": true, "keys": {"DATABASE_URL": "changed", "OLD_KEY": "archived"}}` |
| rename a secret | `PATCH /api/secrets/market/prod/DB_URL {"key": "DATABASE_URL"}` |
| file a secret or a project in a folder, or in none | `PATCH /api/secrets/market/prod/STRIPE_KEY {"folder": "stripe"}`, `PATCH /api/projects/acme {"folder": null}` |
| rename a folder, everything in it re-filed, or remove one, everything out | `PATCH /api/folders/Clients {"name": "Customers"}`, `DELETE /api/folders/market/prod/stripe` |
| a secret's versions | `GET /api/secrets/market/prod/DATABASE_URL/versions` |
| restore a version, as a new version | `POST /api/secrets/market/prod/DATABASE_URL/restore {"version": 3}` |
| decrypt a secret or a whole environment; a whole environment's read also answers the `version` of what it opened (null for one secret's), the one a poller keeps; `keys` reads only those of it, as `coffre export --keys` does, and opens, logs and counts against the bulk limit nothing else | `POST /api/reveals {"path": "market/prod"}` → `{"operationId": "…", "values": {…}, "version": "…"}`, `POST /api/reveals {"path": "market/prod", "keys": ["DATABASE_URL"]}` |
| make a key a reference to another secret, read live through it | `PATCH /api/secrets/billing/prod {"DATABASE_URL": {"ref": "market/prod/DATABASE_URL"}}` |
| the references into and out of a place, and who reads through them; break one | `GET /api/references?path=market/prod`, `DELETE /api/secrets/billing/prod/DATABASE_URL/reference` |
| list, add or offboard members | `GET /api/members`, `PUT` / `DELETE /api/members/user:ada@acme.example` |
| what a member holds and has seen, before offboarding | `GET /api/members/user:ada@acme.example` |
| a member's instance role and scope, and the grants you manage, in one query | `GET /api/members/user:ada@acme.example/access` |
| list, issue (`?dryRun=1` to preview what it reaches) or revoke a token's credentials | `GET` / `POST /api/members/token:ci-deploy/tokens`, `DELETE …/tokens/:id` |
| list, make or revoke your personal tokens, which act as you within their scope ([design](design/personal-tokens.md)); whoever runs the instance lists and revokes anyone's | `GET` / `POST /api/members/user:ada@acme.example/tokens {"label": "cursor-agent", "expiresInMinutes": 240, "scope": {"market/dev": "viewer"}}`, `DELETE …/tokens/:id` |
| list, make (`?dryRun=1` to preview) or remove a token's trust bindings | `GET` / `POST /api/members/token:ci-deploy/bindings`, `DELETE …/bindings/:id` |
| a GitHub repository's or GitLab project's IDs, for a binding: a public one, or one the deployment's GitHub App is installed on | `GET /api/workloads/lookup?github=acme/api` |
| the repositories the deployment's GitHub App is installed on, private ones too ([github-app.md](github-app.md)) | `GET /api/workloads/repositories` |
| change someone's access, in one transaction | `PATCH /api/access/user:ada@acme.example {"market": "developer", "market/prod": null}` |
| my sessions and linked sign-in accounts, and ending them | `GET` / `DELETE /api/sessions/:id`, `GET` / `DELETE /api/identities/:id` |
| approve or deny a `coffre login` device code | `GET` / `POST /api/device-logins/:code {"approve": true}` |
| what an MCP client asking to connect is and wants, and the person's answer | `GET /api/oauth/authorizations?client_id=…`, `POST /api/oauth/authorizations {"request": {…}, "approve": true, "scopes": ["read"]}` |
| the MCP clients I connected, and disconnecting one | `GET /api/apps`, `DELETE /api/apps/:id` |
| the audit log, each entry it shows proved to the signed head; the vault's keys and their checks, for `coffre verify keys` | `GET /api/audit?path=market/prod/DATABASE_URL`, `GET /api/audit/keys` |

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

MCP clients ([mcp.md](mcp.md), [design/mcp.md](design/mcp.md)) have coffre as
their OAuth authorization server, on routes of its own beside the table: the
metadata at `/.well-known/oauth-protected-resource[/mcp]` and
`/.well-known/oauth-authorization-server`, and `POST /api/oauth/token`,
`/api/oauth/register` and `/api/oauth/revoke`, form-encoded as OAuth wants
and answered in its errors. The consent page is `/oauth/authorize`, and its
calls, like Connected apps', are ordinary rows of the table. Their tokens are
good at `/mcp` and nowhere else: `/api` reads `credentials`, which an MCP
token is not, and `/mcp` takes nothing but one. A tool's call is API calls
in process, as its person, through this same table (`fetchApi`, as a page's
render): the request carries its connection (`via`), which the router holds
to a table of the scope each route needs (`ROUTE_SCOPES`), and which every
entry it writes names, as `via` in its detail. A tool that
changes something makes no change when called: it opens a row in
`mcp_approvals`, its tool and arguments, and the person decides it on
`/approvals/<id>`, whose Approve, an ordinary row of the table, makes the
change there, in process, as the person with the connection attached
(design/mcp.md, section 7).

The server is one table keyed by method and route, each entry giving its input
schema and its handler. `@coffre/client`'s types are generated from the same
table (`pnpm --filter @coffre/client generate`), and a test fails while they
differ, so the two cannot drift; the UI calls it like any other client.

Each segment names one level, so `/api/secrets/market/prod/versions` is a
secret named `versions`, and its history is one level further down. Where a
literal and a name could both fit a path, the literal wins among the routes
that take the request's method.

Behind it, the app decides nothing. A page read asks the vault once who
the caller is and what they hold (`caller`), shared by every call of one
render, and scopes its queries by the answer; a reveal or a change is one
vault call, which decides on rows whose MAC it checked. [The
server](design/0.16.md#the-server) gives a request's path and what each costs.

### Generated values

A value can be made rather than typed, by a recipe, short text that the CLI
and the pages read and write with the same code (`@coffre/core/recipe`):

| Recipe | Makes |
|---|---|
| `bytes:32`, `bytes:32:hex` | 1 to 256 random bytes, as base62 unless named, hex, base64 or base64url |
| `aes:256`, `aes:128` | an AES-GCM key: the raw key, base64 |
| `ecdsa:p-256`, `ecdh:p-384` | a key pair on P-256, P-384 or P-521: the private key PKCS #8, the public key SPKI, both base64 |

The client makes the value, with Web Crypto's CSPRNG, and sends it with its
recipe: `coffre set market/prod/SESSION_SECRET --generate bytes:32:hex`, or
the Generate dialog of a secret's value field. The server makes no value. It
checks that the recipe reads, stores it, written canonical
(`bytes:32:base62` for `BYTES:32`), on the secret's row (`secrets.recipe`),
and says it back in the listing as the key's
`generated`, and in its version history. Regenerate, `coffre regenerate
market/prod/SESSION_SECRET` or the row's menu, makes the next value by it, in
the environment it is asked of, and nobody sees either. It addresses keys by
name, so each value it sends says the version it `replaces`, by the
`versionId` the listing gave it (unique, as a version number is not), and the
server refuses the whole write (409) unless every key resolves to that
version now, checked again in the vault's change: renamed, archived, typed
over or regenerated meanwhile, by anyone, here or in a parent.
In a fork, a key it inherits lists the recipe of the parent's value it
reads, to a reader of that parent, as its version; regenerating it writes
an override in the fork, never the parent, and `replaces` is the inherited
version. A value written
without a recipe has none, by whichever client, so typing over a generated
value ends what Regenerate does for it; a rollback brings an old value back
with the recipe it had.

A key pair is two keys, written in one patch, each naming both:
`"generated": {"recipe": "ecdsa:p-256", "pair": {"private": "JWT_PRIVATE_KEY",
"public": "JWT_PUBLIC_KEY"}}` on each. Half a pair, or halves that disagree,
are refused (400). The two keys' rows share a fresh `pair_id`, each with its
`pair_half`. Typing over, archiving or
rolling back either half leaves both without a recipe until the pair is made
again; renaming one keeps it, as a rename moves no value.

A recipe is no secret: the listing names it. It is on the secret's row,
under the vault's MAC, so a database writer cannot weaken one unseen; still,
Regenerate says the recipe: the page asks with it, and `coffre regenerate` prints the one it
used.

## The vault

The app decides **who** someone is. The vault decides **what** they may
do. The vault never sees a cookie, an OAuth flow or a session; the app
passes it what the request showed (`Presented`: the credential's SHA-256,
the request's id and address), and the vault finds the caller itself.

The interface is `Vault` in `@coffre/core/vault`, six calls:

| Call | Does |
|---|---|
| `use` | open values: a reveal, `coffre run`, an export, a proxied request |
| `peek` | what a use would open, by version, opening nothing (`GET …/version`) |
| `caller` | who the caller is and what they hold, for a page to scope its queries; with `head`, the log's head under the vault's MAC |
| `change` | every write: values, places, members, grants, credentials, settings |
| `weigh` | what a change would do, without doing it (`?dryRun=1`) |
| `about` | its configuration alone: its vault keys by provider and ID, and its signing keys' checks (`GET /api/audit/keys`) |

Every argument and result is plain data, and a refusal is a value, not a
thrown error, so the same interface works across a process boundary. The
app words a refusal as [The server](design/0.16.md#the-server) tabulates: 403
`vault_refused` carrying the vault's word in most cases. [What became of
0.14's calls](design/0.16.md#operations) maps the old interface to this one.

The vault writes every row, and puts a MAC on each one that turns into
access; the app's login only reads ([Four rules](design/0.16.md#four-rules)). So the
Users page, a project's Access tab and a member's page read the rows
directly, scoped by the caller's answer: a list is a display, not a
decision. The app cannot check a row's MAC, so a row changed around the
vault lists as stored. The vault refuses it at its first use if its MAC
no longer covers it. The signer compares only MACs, against its own copy
of each: within about a minute it finds a row added, deleted or put back
from an older copy, but not one edited under its old MAC, which only the
vault's refusal catches ([What it promises](design/0.16.md#what-it-promises)).

### Transports

- **Workers**: the vault is a Worker of its own, `coffre-vault`, with no
  public route. The app reaches its RPC entrypoint through the `VAULT`
  service binding. Each call opens the shared Postgres database through
  `VAULT_HYPERDRIVE`, using the vault's login: one connection, which its
  queries take turns on, closed when the call is done. No database
  connection lives across requests. The signer is a Durable Object of the
  vault's Worker (`SIGNER`, `CoffreSigner`), whose storage holds what the
  database is held to.
- **In process** (`localVault`): for tests. Each call's arguments and
  results go through JSON as over RPC, so nothing that only works
  in-process gets in.
- **Locally**, `pnpm dev` runs the vault as an auxiliary Worker of the
  app's `vite dev`, and conformance runs both with `wrangler dev`, the app
  as Vite built it. Either way the app's `VAULT` binding reaches it as in
  production.

### Where each secret lives

| | App (Worker `coffre`) | Vault (Worker `coffre-vault`) |
|---|---|---|
| Config | `auditChainKey`, `auth` (sign-in or Access settings), `rotateAfterDays` | `kek`, `previousKeks`, `owners`, `bulkLimit`; `signingKey` with a KMS key |
| Tables it writes | none: its login only reads | every other table, the log's entries into `log_pending`; the signer moves them into `log` and writes the tiles and the head |
| Connection | `coffre_runtime`, through `HYPERDRIVE` | `coffre_vault_runtime`, through `VAULT_HYPERDRIVE` |

Both connections reach the same database. Each Worker gets only its own
configuration secrets. Neither stores the vault key or the app key in the
database. The owner can bypass the logins' grants, but cannot forge a row's
MAC without the vault's key, and what the vault sealed and a writer put
back is held to the signer's copy ([What it promises](design/0.16.md#what-it-promises)).

### Transactions

No app transaction stays open across a vault call, and the app writes
nothing. A change is one vault call: it reads the rows it decides on,
checks their MACs, and writes the rows and their entry in one statement; a
row that moved since the read starts it over. A use takes no lock
([Operations](design/0.16.md#operations)).

### The bulk limit

At most `bulkLimit` distinct keys used per principal in a sliding window,
`{ count: 1000, windowMinutes: 15 }` by default: a thousand different secrets, which no
person or pipeline reads in a quarter of an hour, while a script pulling every
value it can reach stops within seconds. A key counts once in the window however
often it is read, so a 50-key run is 50, and the same run again adds nothing.
A refusal answers 403 `bulk_limit`; the principal reads new keys again as the
window rolls on. The vault counts from `exposures`, one row per principal and
key with when they last saw it, and the requests in flight when the cap is
reached may overshoot it ([What it promises](design/0.16.md#what-it-promises),
relaxation 3).

### The log

Every entry is the vault's, each under its MAC: a change's, in the
statement that writes its rows, and a use's, into `log_pending`. About a
second later the signer, outside the database, numbers them into `log` and
signs the heads of two Merkle trees (RFC 9162), one of changes, kept for
good, one of uses, which age out ([How long the log is
kept](design/0.16.md#how-long-the-log-is-kept)); each minute it holds every access row
to its own copy of the row's MAC and alerts on what differs. `GET
/api/audit` proves each entry it shows to the head the vault vouches for.
0.14's history is kept as `audit_archive`, which the pages do not show
([The log](design/0.16.md#data-structures)).

### What the vault stops

- **A permission bug in the app.** An endpoint checks the project but forgets
  the environment; someone with `market/dev` asks for
  `market/prod/DATABASE_URL`. The app lets it through, and the vault refuses:
  the grant covers `dev`.
- **A sensitive value shown to a person.** A key marked sensitive is
  never handed back to anyone signed in as a person, Owners included:
  its data key is wrapped as sensitive, so a page, a CLI read or a plugin
  that asks for it is refused, and a row flipped back around coffre opens
  for nobody ([design](design/credential-proxy.md#2-the-model)).
- **Someone removed getting back in.** An offboarding bug leaves a session
  alive; the vault refuses the principal, which only it can restore.
- **A copy of the database.** It holds no vault key.
- **Rewritten log entries without the vault's key.** One not signed yet
  fails its MAC, and a signed one its tree's proof.
- **Access granted around the vault.** Every row that turns into access
  carries the vault's MAC. A grant written straight into the database fails
  it, and the vault refuses to decide on it (`tampered`). A genuine old row
  put back is honoured: the signer, holding its own copy of every such MAC,
  alerts within about a minute, but the alert revokes nothing, so the row
  stays in force until an operator acts on it ([What it promises](design/0.16.md#what-it-promises)).

What it does not stop: an app fully taken over can act as anyone who already
has access. The vault makes that loud rather than impossible: the key never
leaves it, every read lands in a log the app cannot edit, and bulk reads trip
its limit. A plain value is the exception, by its writer's choice: marked no
secret, its version keeps it in the clear too, and it is read without the
vault ([design](design/credential-proxy.md#2-the-model)). Closing it would take requests signed by keys the principals hold
themselves, which fits this interface later without the vault learning about
sign-in. The rest of what coffre does not stop is under [Limits](#limits).

### Sign-in rows

Sign-in's rows (`identities`, `credentials`, `bindings`, `device_logins`,
`enrollment_codes`, `oauth_clients`) are the vault's, each under its MAC
like every row that turns into access ([Tables](design/0.16.md#tables)). The app key
signs none of them: the app derives from it only the keys that seal its
sign-in state and its Access sessions, so a lost app key costs a sign-in.

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
  and 64 KiB. The binding
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
"token": "<JWT>"}` answers `{"token": "coffre_svc_…", "expiresAt": "…"}`
(`packages/server/src/exchange.ts`; [Operations](design/0.16.md#operations), "A
workload signing in"). The app admits the request through the deployment's
two limiters, reads the service's live bindings on the token's issuer in
one statement, so that a token no binding can take costs that read and no
vault call, and checks the signature under the binding's keys; the vault's
`token.exchange` change decides, spends the token and issues the
credential. A refusal answers 401 with a reason a CI user can act on, 429,
or 503 when the issuer cannot be asked.

**The credential** is a service credential like any other, whose
`created_by` names its binding, `binding:<id>`. Its MAC is of its own kind
and covers that field, so the link can be neither cut nor added. Checking
it checks its binding too, in the same request: its MAC, its revocation,
its tombstone. Removing the binding ends it at once, and a credential row
put back with its binding stays dead. Spent tokens and exchanged
credentials are kept, since the runtime logins delete nothing; a CI run
adds two small rows.

**Which run did what.** Every entry a request on such a credential writes
names it as its `credential`: the one the vault authenticated from the
token the call presented, not an ID the app passes. The exchange's entry
names the same credential, with the run's claims. A credential an entry
acts on (one a sign-in opens, a token issued, a session revoked) is in its
detail, as `credential`, so revoking another run's credential is the
caller's act, never that run's. So a secret read leads back to its run in one indexed
read, whatever became of the credential's row, and the audit page shows the
run under the actor ("acme/api run 7001 at 3f2a9c1"): what the issuer
asserted, not proof of which run sent the request.

Indexes keep what CI leaves behind out of the way: every run leaves an
expired credential, and every replaced binding a retired one. Indexes on
the live bindings, on a member's live credentials and on what a binding
issued lately bound the exchange's first read, its rate count, a binding's
removal and the members page by what is live, not by history.

## Deleting for good

Archiving hides a project or an environment and changes nothing stored.
Deleting an archived one, which only those who run the instance may do, frees the
space its values take and hides it for good. The place itself must be
archived: an environment under an archived project is deleted alone only
once it is archived too. `coffre projects delete market`
shows what it would take; with `--apply` it deletes:

One vault change, `project.delete` or `environment.delete`, by an Admin or
Owner of the whole instance, does it all: every version under the place
has its ciphertext and wrapped data key emptied, so it opens under no vault
key; the grants on it go; references into and out of it end. Its row, its
keys' and its versions' stay, names and dates only, since the log names
them, and the place takes a tombstone's slug, `market~deleted-2026-11-14`,
which no use, change, grant or reference reaches, its old slug free.
Backups taken before still hold the encrypted values, and restoring one
brings them back with the vault key ([restore.md](restore.md)). [A place
deleted for good](design/0.16.md#operations) has the rest, and its bound.

## Databases

The app database is Postgres, deployed, in tests, in local development and
in conformance; it is the only engine.

The app writes nothing, and its queries are the pages' reads, in
`packages/server/src/db/queries/`, each scoped by the vault's answer about
the caller; the vault's are its own. Lint keeps `drizzle-orm` inside those,
`packages/db/src/` and the vault.

The database comes from its URL: `postgres://` or `postgresql://` opens
postgres.js (`packages/db/src/connect.ts`); any other scheme is refused. The Worker builds its Postgres database from the Hyperdrive pool
with `createDatabase`: one connection for each request or vault call, which
its queries take turns on and a transaction holds until it ends.

postgres.js is coffre's own copy, in TypeScript, in `packages/db/src/postgres-js`,
so a deployment installs no driver. It keeps what coffre uses (statements,
transactions and savepoints, reserved connections, the pool) and leaves the
rest out: COPY, LISTEN/NOTIFY, cursors, the cache of named prepared statements, the
tagged template, reading URLs and the environment. One tree runs on Node and
on Workers: its sockets, TLS and hashes are behind `@coffre/db`'s
`#postgres/platform` import, Node's own modules or `cloudflare:sockets` and
WebCrypto, chosen where the package runs. It differs from upstream in ten
places (`packages/db/src/postgres-js/README.md`): a statement's values go with the
statement, as text the server types, as node-postgres sends them, where
upstream first asks the server for their types, a round trip more for every
statement with parameters (porsager/postgres#1225); a transaction's BEGIN
goes with its first statement, under one Sync, a round trip less, and
nothing of a transaction is sent once its BEGIN failed, its connection
closed or it ended, so none of it runs outside it;
a query cut short by its connection's close no longer keeps `end()` waiting,
a connection closed while it opens fails its query rather than being
dialled again for ever, an ending client opens no connection again, a
`reserve()` that opens its connection gets it, and a statement the client
cannot write fails alone;
the pool takes the connection idle the shortest, as pg-pool does, so
that a steady load keeps to a few warm backends rather than cycling through
all of them; a statement is prepared by name only when asked, named by a
hash of its text so that a pooler that keeps statements prepared knows it
from any client (a use's read, through `rowsOf(…, { prepare: true })`),
where upstream prepared every statement, named in the order a process sent
them; and a sign-in the client cannot work out fails its connection
rather than leave an unhandled rejection.

A postgres.js client dials a new connection for the next statement once its
own has closed, which holds none of what the last one set. What keeps a
session's state across statements, its own BEGIN, SETs or advisory locks
(the migrator, `coffre backup` and `restore`, `coffre setup`'s probes),
opens a `postgresSession` instead: once its connection has closed, every
statement after fails (`SessionLost`). `postgresClient` (`packages/db/src/postgres.ts`)
opens each client as coffre needs it: statements unnamed unless asked, no type lookup on
connecting, arrays, dates and objects sent and arrays read as node-postgres
does, and the URL read as node-postgres reads it, TLS included.

Each query is written once, typed against the Postgres schema. How the
queries reach the database:

- **Schema and migrations.** `pgTable` defines the schema, and its
  migration tree is under `packages/db/src/migrations/postgres`, from a
  single baseline. Generated tables sit inside a template in
  `packages/db/src/baseline/` that adds the Postgres runtime roles. Tests
  catch a schema or template that no longer matches its migration. Encrypted bytes
  use `bytea`.
- **Ids come from the application.** Writes know their keys before insertion
  and do not read them back.
- **Named operations.** Rows changed, a tombstone's test, the clock and
  reading a condition stay in `dialect.ts`. Services contain no database branches.
- **Shared constraints.** Active identities use a unique index on a generated
  column that holds the subject only while the identity is not revoked.
  Emails are stored lowercase. No query filters on a JSON field.

The restricted runtime logins are `coffre_runtime` and
`coffre_vault_runtime`. `pnpm test:schema` checks both logins, including
which author each may append as.

D1 is not a fit for the app database: it has no interactive transactions,
and Drizzle's D1 transactions send `BEGIN`, which D1 rejects. Both
Workers use Postgres.

### Expand, then contract

A deployment migrates in its pipeline, before it deploys
([deploy.md](deploy.md#upgrading)): on Workers, its deploy workflow migrates
before `pnpm run deploy`, and with Workers Builds instead, each Worker's
build does. Until the deploy is done, and for good if it fails, the previous
release runs on the new schema. The new release never runs on the old one:
the app checks, once per isolate or process until it holds, that the
database has every migration the release ships (`@coffre/db/schema-version`,
`migrated`), and below that answers everything but `/livez` and `/readyz`
with 503 `migrating`, at one door, `respond` in `app.ts`, which every request
Start answers goes through. `/readyz` is red until then. So code never asks
whether a table or a column is there; a migration only has to keep the
previous release working:

- **A migration expands.** It adds tables, columns that are nullable or have
  a default, indexes and grants, which the previous release does not know
  and does not mind: Drizzle names only the columns its schema has.
- **What contracts waits a release.** Dropping or renaming a table or a
  column, NOT NULL on an existing column, a narrower check or type, or a
  unique or foreign key the old code may break, ships one release after the
  code stops using what it changes. Retiring a column: release n stops
  reading and writing it, and release n+1 drops it.

0.4.0 began again from one baseline per engine, for new databases only
([deploy.md](deploy.md#from-a-release-before-040)): `coffre migrate` refuses
a database an earlier release made. `pnpm test:compat` holds the newest
release of the change's own line (0.14.x here) to the schema of the change under review: it installs that release
from npm as `coffre init` writes a deployment, and lets its own conformance
boot it, with the database migrated by the change's migrations instead of
the release's. A synthetic destructive migration on top must then fail it,
so that the check is known to be able to. CI runs it on every change; it
was off for 0.4.0, which had no earlier release on its schema, and is off
again for 0.16.0, which upgrades 0.14 in place and offline ([Upgrade from
0.14](design/0.16.md#upgrade-from-014)).

## Limits

Each limit is stated here once; the other documents link to it.

- **What a writer of the database can do, and how soon it is found,** is
  [What it promises](design/0.16.md#what-it-promises): a forged row is never honoured;
  a genuine old row put back, or an entry not yet signed edited, is found
  within about a minute, and coffre keeps serving; a signed entry edited is
  found by the signer's re-check of a slice of the log each minute, or by a
  page that shows it. What to do once the signer's storage is lost is
  [still to design](design/0.16.md#still-to-design).
- **What only KMS gives.** With a local vault key, whoever holds the vault's
  configuration and a copy of the database holds every value, and nothing
  outside coffre records either being used. AWS KMS adds a second record
  (CloudTrail), lets the vault's access be revoked in IAM at once, and keeps
  the key material from ever being copied out ([keys.md](keys.md)). It also
  costs a round trip per key, and on the Workers Free plan an environment of
  more than 50 secrets cannot be read in one call.
- **A vault key cannot be retired yet.** A new vault key wraps new versions only; every
  older version still needs the vault key that wrapped it, configured in
  `previousKeks` and escrowed, until a rewrap command exists. With local
  keys, the signing key a previous vault key stands for still verifies
  rows and entries, whenever they were signed ([keys](keys.md#a-local-key)).
- **A holder of the vault's signing key can forge its rows and entries.** A
  copied database alone cannot. With a local vault key, the signing key
  comes from the vault key: whoever holds it, and can write the database,
  can forge members and grants, besides reading every value.
- **The app key cannot be rotated yet** ([still to design](design/0.16.md#still-to-design)).
- **A MAC proves a row is genuine, not current.** Putting back a genuine old
  sign-in row can undo one sign-out. The signer alerts within about a
  minute, but the credential works until it expires or an operator acts;
  a member's removal still ends it, through the generation.

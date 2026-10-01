# coffre

A deliberately small in-house secrets manager. People sign in with GitHub,
Google, Microsoft or any OpenID Connect provider, or through Cloudflare Access;
Postgres is the backend of record, and the audit log is the point.

**Status: ready for a first deployment, still hardening.** coffre runs as a
Cloudflare Worker in front of Postgres, and [docs/deploy.md](docs/deploy.md)
deploys one. [Phase 1 of the roadmap](docs/roadmap.md#phase-1-harden) is still
open, so until it is done, keep the keys escrowed and a copy of anything you
move in.

## Why this exists

We self-host Infisical. Unlicensed self-hosted Infisical writes **no audit logs
at all** — verified in source, not inferred:

- `backend/src/ee/services/license/license-fns.ts`, `getDefaultOnPremFeatures()`
  returns `auditLogs: false`, `auditLogsRetentionDays: 0`
- `backend/src/ee/services/audit-log/audit-log-queue.ts:107`
  `if (!plan?.auditLogsRetentionDays) return null;`

Every audit entry is dropped. Silently: no error, no warning, no metric. That
failure mode — a logging system that stops logging without telling anyone — is
the thing this project is built to not repeat.

The driver is DORA. CDR (EU) 2024/1774 Article 12 is the relevant text. Note
what it actually says: **you** identify the events to be logged (12(2)(a)). It
does not mandate per-value read logging. "Who read which secret, when" is a
control we are choosing, which is a stronger position than pretending a
regulator demands it.

### What we are not claiming

Infisical's audit logging being paywalled is a fact about Infisical, not about
the market. **OpenBao ships request/response audit logging in its open-source
core**, unlicensed. The honest justification for building rather than adopting
is that we want a secrets service small enough to read end to end, with
identity delegated to a provider we already trust. Not "nothing else does this."

## The finding that changed the design

The original design assumed Scaleway Key Manager would give us an independent
audit trail that the application could not disable. **It does not.**

Scaleway Audit Trail logs exactly ten Key Manager endpoints, all management
plane: `CreateKey`, `UpdateKey`, `DeleteKey`, `ProtectKey`, `UnprotectKey`,
`RotateKey`, `DisableKey`, `EnableKey`, `ImportKeyMaterial`,
`DeleteKeyMaterial`. There is no `Decrypt`, no `Encrypt`, no `GenerateDataKey`.

Source: `scaleway/docs-content`,
`macros/audit-trail/key-manager-endpoints.mdx` (doc validated 2026-06-12).

The same page confirms Secret Manager logs no value access either — no
`AccessSecretVersion`. Our sync target is therefore a genuine un-audited read
path and needs tight IAM plus a written exception.

Consequences:

1. Tamper-evidence has to come from our own log. Hence the hash chain in
   `packages/core/src/audit/chain.ts`.
2. `KekProvider.wrap/unwrap` takes the secret context as a parameter, so a
   future KEK service *we* run (a Cloudflare Worker was discussed) can log
   which secret an unwrap was for. Retrofitting that would mean re-encrypting
   everything.
3. The eventual shape is likely double-wrap: Scaleway KMS for HSM-grade key
   protection, plus a Worker as a second layer whose log lives in a different
   trust domain. Cross-checking unwrap counts against our own audit log is a
   ready-made Article 12(2)(e) logging-failure detector.
4. AWS KMS does log every Decrypt, in CloudTrail, with the encryption
   context. So the first KMS provider is AWS's, `awsKms(…)`: it sends each
   secret's ids as that context, and CloudTrail becomes the independent record
   ([docs/keys.md](docs/keys.md)).

## Design decisions worth knowing

**AAD binds to UUIDs, never names.** A ciphertext is bound to
`project_id/environment_id/secret_id`. Binding to `project/environment/key`
names would make renaming an environment orphan every ciphertext in it.

**Two independent AAD layers.** The envelope binds context, and the KEK wrap
binds context *and* KEK identity. Either alone stops a cross-environment
relocation. `packages/core/test/envelope-aad-isolation.test.ts` exists because
the obvious test passes at the wrap layer and would not notice the envelope
layer regressing.

**The audit write is in-transaction and fail-closed.** Not a queue. If the
audit row cannot be written, the read does not happen.

**`seq` comes from a locked head row, not a bigserial.** A rolled-back
transaction burns a sequence value, and the resulting gap is indistinguishable
from a deleted row. Gaps must mean tampering.

**One audit row per secret, sharing a `bundle_id`.** A bulk fetch that writes a
single row degrades the answer to "they read the whole environment", which is
true and useless.

**Principals are a tagged union.** Cloudflare Access service tokens carry
`common_name` with an empty `sub` and **no `email` claim**. Code that reads
`claims.email` gets `undefined` for every machine caller. Machine callers
(external-secrets, CI) are most of the real traffic.

**`/api` is the one front door.** Every call, including a page's own server
render, is authenticated there and must come from an active principal row;
configured root admins are the sole empty-database bootstrap exception. A
change made with a cookie must also be same-origin, which stops another site
from making it in the visitor's name; the CLI and service tokens send a header
and are unaffected. Page middleware only rejects `x-middleware-subrequest` and
works out who is looking, for the sign-in routes.

**One route table is the whole API.** `packages/server/src/api/routes.ts` maps
each `METHOD /route` to its input schema, the permission it needs and its
handler, and one catch-all route serves it under `/api`. The client in
`packages/client` is typed from that table, and both the CLI and the UI call
through it; during a server render the UI hands its requests to the API
in-process, so there is no loopback request and no second path around
validation, permission checks or the audit log. See
[The API](#the-api) below.

**The `.env` parser refuses ambiguity rather than guessing.** It is the one
place where free text becomes credential material. Unrecognised escapes are
preserved verbatim, trailing text after a closing quote is an error, NUL bytes
are rejected (`execve` truncates at them), and all three line-ending
conventions are split. Writing tests for it found four ways it silently
corrupted values — see `packages/core/test/dotenv.test.ts`.

**Append-only by grant, not convention.** `coffre_app` has no `UPDATE`, no
`DELETE`, or `TRUNCATE` on history, and no `DELETE` or `TRUNCATE` anywhere.
Grants, and whether someone is still a member, are not in this database at
all: they live in the vault ([docs/architecture.md](docs/architecture.md#the-vault)).

**Owner and runtime are separate identities.** The one-shot migration process
receives the owner `DATABASE_URL`; the Worker receives only the `HYPERDRIVE`
binding backed by the restricted runtime login. Terraform creates and
password-manages the stable `coffre_runtime` login; the Postgres baseline
migration validates it and grants membership in the append-only `coffre_app`
role:

```sh
pnpm exec coffre-server migrate '<owner-database-url>'   # in a deployment
```

Hyperdrive contains the runtime credential, so no database password is exposed
as a Worker variable or secret. Database routing and TLS remain infrastructure
concerns. Local `pnpm dev` provisions its disposable runtime login automatically
and emulates the Hyperdrive binding against loopback PostgreSQL.

## Supply chain

`ignore-scripts`, exact pins, and a 7-day minimum release age.

Two traps found the hard way, both documented in `pnpm-workspace.yaml`:

- **pnpm 11 reads only auth and registry settings from `.npmrc`.** Everything
  else there is silently ignored. Our hardening was doing nothing until it was
  moved to `pnpm-workspace.yaml` (camelCase keys).
- **`savePrefix: ''` is read but not applied by `pnpm add`.** It still writes
  caret ranges. `scripts/check-pins.mjs` enforces the invariant instead, because
  a control that silently does nothing is worse than no control.

`minimumReleaseAge` earned its place immediately: it blocked `jose@6.2.4`,
published six days before we tried to install it.

**Releasing.** `pnpm bump 0.2.0`, merged, then a pushed tag, `v0.2.0`, has
`.github/workflows/release.yml` publish the seven packages
(`scripts/publish.sh`). npm takes the workflow's GitHub OIDC token rather
than a stored one (trusted publishing), and attaches provenance: each
version on npm names the commit and workflow run that built it. npm sets up
a trusted publisher only for a package that exists, so each package's first
version was published by hand, with the same script.

## Layout

```
packages/server       @coffre/server: /api, sign-in, syncs, the heartbeat, the database; /cloudflare and /node
packages/ui           @coffre/ui: the pages, a prebuilt TanStack Start handler and its static files
packages/vault        @coffre/vault: the KEK, grants, members, root admins, its own log; /cloudflare and /node
packages/client       @coffre/client: the API as typed calls, one fetch each, and the sync destinations
packages/cli          @coffre/cli: `coffre`, from init and login to secrets, syncs and audit
packages/conformance  @coffre/conformance: `coffre-conformance`, and the dev IdP it signs in through
packages/core         @coffre/core: access rules, envelope encryption, KEKs, the audit chain, identity, the vault contract
examples/workers      what `coffre init --workers` writes: two Workers
examples/node         what `coffre init --node` writes: a server and its vault process
dev/start.sh          `pnpm dev`: Postgres, the dev IdP, the dev deployment, then dev/seed.mjs
dev/deployment        what `pnpm dev` runs: examples/workers, on the packages' sources
dev/idp               runs the dev IdP, the local stand-in for Cloudflare Access, an OIDC provider and GitHub
scripts               what dev, tests and CI share: databases, the checks
```

The seven `@coffre/*` packages are the product, compiled with their
declarations and released together at one version; each imports the others
by name only. A deployment is
one of the examples: a small project that imports the packages and configures them
in code ([docs/architecture.md](docs/architecture.md),
[docs/deploy.md](docs/deploy.md)).

## Running it

```sh
pnpm install
pnpm dev              # Postgres + dev IdP + coffre and its vault as two Workers + seed data
```

Then open http://127.0.0.1:3000 and sign in as `admin@acme.example`.

`pnpm dev` runs a deployment like `examples/workers` under `vite dev`
(`dev/deployment/`), on the packages' sources, so an edit to a page, the
server or the vault reloads in place. It signs in as a deployment does, with
`signin(…)`: the dev IdP plays GitHub and an OpenID Connect provider, and its
page asks which seeded person you are. The seed signs in the same way, and
prints a service token for `ci-deploy`. A deployment uses `signin(…)`
([docs/deploy.md](docs/deploy.md)) or Cloudflare Access
([docs/deployment-auth.md](docs/deployment-auth.md)).

Individual pieces:

```sh
pnpm db:up            # Postgres on :55432
pnpm db:migrate
pnpm db:generate       # regenerate each engine's baseline from its schema (no deployment yet)
pnpm db:check          # validate the Postgres and SQLite Drizzle journals
pnpm seed             # directory + market/dev|prod + grants; loads .env.dev
pnpm test             # lint + unit + integration tests on Postgres (needs it up)
pnpm test:sqlite      # the same suite on SQLite, in a temporary file
pnpm test:all         # Postgres and SQLite, one after another
pnpm test:schema      # runtime-role guarantees in an isolated test database (Postgres only)
pnpm lint             # no server functions or Drizzle queries in the pages or the server
pnpm check:pins       # every dependency exactly pinned
pnpm check:contrast   # every admin-UI colour pair meets WCAG AA
pnpm build            # every package; @coffre/ui's fails if server code reached it
pnpm typecheck        # every package and both examples (after pnpm build)
pnpm conformance:workers  # examples/workers under wrangler dev, held to docs/conformance.md (after pnpm build)
pnpm conformance:node     # examples/node, its server and vault processes, on SQLite
pnpm test:consumer    # pack the packages, init both examples from the packed CLI, install, conformance
```

`.env.dev` holds the local fixtures (keys, root admins) that
`dev/deployment/` hands each Worker: the app its audit chain key and
sign-in settings, the vault its KEK, root admins and checkpoint signing key.
`pnpm dev` empties the vault's local store each time it seeds, since the
seed starts the database over.

Conformance boots a deployment, signs people in through the dev IdP
standing in for GitHub, and checks what must hold whatever code it runs:
access, cross-site requests, offboarding, the bulk limit, both logs and
their tampering, and no value anywhere it should not be
([docs/conformance.md](docs/conformance.md)). Every deployment has it as
`pnpm conformance`.

CLI:

```sh
coffre() { node --conditions=coffre:source --env-file=.env.dev packages/cli/src/main.ts "$@"; }

coffre login                                    # a device login: approve it in the browser

# secrets
coffre list     market/dev
coffre get      market/dev/DATABASE_URL
coffre run      market/dev -- printenv
coffre export   market/dev --format dotenv      # or json, shell
coffre history  market/dev/DATABASE_URL
coffre rollback market/dev/DATABASE_URL 2
coffre import   market/dev --file .env          # previews; --apply to write

# access
coffre projects
coffre roles
coffre access                                   # who holds what, everywhere
coffre grant market alice@acme.example --role developer --env dev
coffre offboard alice@acme.example               # previews; --apply to remove (docs/offboarding.md)

# syncs (docs/syncs.md)
coffre sync providers                           # where this instance can sync to
coffre sync add  market/prod github-actions owner=acme repo=market \
                 --credential ops/sync/GITHUB_TOKEN
coffre sync list market/prod
coffre sync run  market/prod github-actions

# audit
coffre audit --denied
coffre verify
```

The local helper loads `.env.dev` for the local `COFFRE_API_URL`. Against a
deployed instance, no settings are needed:

```sh
coffre login https://coffre.example.com   # shows a code to approve in the browser
coffre whoami
coffre use                                # every instance you are signed in to
coffre logout
```

`coffre login` asks the instance how it signs people in (`GET /api/auth`).
With coffre's own sign-in it runs a device login: the CLI prints a link and a
code, you approve it in a browser where you are signed in, and the CLI gets a
session token of its own (30 days by default), listed and revocable on the
account page. Behind Cloudflare Access it hands over to `cloudflared` (see
[docs/deployment-auth.md](docs/deployment-auth.md)). Sessions are kept per
instance in `~/.coffre/credentials.json` (mode 0600), so a company instance
and a personal one coexist.

CI sets environment variables instead and stores nothing:
`COFFRE_API_URL` plus `COFFRE_TOKEN` (a service token from the Tokens page),
or `COFFRE_ACCESS_CLIENT_ID`/`COFFRE_ACCESS_CLIENT_SECRET` behind Access.

## The API

Addressed by path: `market` is a project, `market/prod` an environment,
`market/prod/DATABASE_URL` a secret, `user:ada@acme.example` or
`token:ci-deploy` a member. The URL names the thing and the method is the
verb; the full table is in [architecture.md](docs/architecture.md#the-api).

```sh
curl -X PATCH $COFFRE/api/secrets/market/prod \
  -H 'content-type: application/json' \
  -d '{"DATABASE_URL": "postgres://…", "OLD_KEY": null}'
# {"keys":{"DATABASE_URL":{"version":4},"OLD_KEY":{"archived":true}}}
```

Or, typed, from TypeScript:

```ts
import { createClient } from '@coffre/client';

const coffre = createClient({ url: 'https://coffre.acme.example', headers: () => ({ authorization: `Bearer ${token}` }) });
await coffre.secrets.set('market/prod', { DATABASE_URL: 'postgres://…', OLD_KEY: null });
const { values } = await coffre.secrets.reveal('market/prod');   // logged, one row per key
await coffre.access.set('user:ada@acme.example', { market: 'developer', 'market/prod': null });
```

- `PATCH` bodies are JSON merge patches: a field you send is set, `null`
  archives or revokes it, a field you leave out stays. A secrets patch is one
  transaction with a version and an audit row per key; archiving needs
  `secret.archive`. An access patch is declarative: it says which role someone
  should hold at each place it names, one role per place, and applies all of
  it or none.
- Values leave only through `POST /api/reveals`, which is audited. No `GET`
  returns a value.
- Creating a project or an environment is a `PUT`: sending it twice is
  harmless, and the second answers `created: false`.
- Every error is `{ "error": "<code>", "message": "<sentence>" }` with its
  HTTP status: `bad_request` 400, `unauthenticated` 401, `forbidden`,
  `registration_required` and `cross_origin` 403 (a change made with a
  browser cookie from another site's page), `not_found` 404, `method_not_allowed` 405,
  `conflict` 409, `too_many_requests` 429, `internal_error` 500 (details in
  the server log only), `unavailable` 503. A refusal on a place that exists
  is logged; a place that does not exist is a 404 and is not.
- `DELETE /api/members/user:ada@acme.example` offboards and answers with
  what to rotate ([docs/offboarding.md](docs/offboarding.md)).

Sign-in (`/auth/*`, `/api/auth/device*`, logout) is a protocol, not part of
the table, and keeps its own routes.

## Progress

All five milestones are implemented and working locally.

- **M0.** Schema and migrations, envelope, local `KekProvider`, KEK registry
  with rotation, audit hash chain. Includes the cross-environment AAD test.
- **M1.** JWKS verification and the auth boundary, adversarial tests written
  first: forged signature, wrong `aud`, expired, not-yet-valid, wrong issuer,
  `alg=none`, RS256→HS256 confusion, missing header, proxy bypass,
  identity-less token. Plus the fail-closed chained audit writer.
- **M2.** Read/write API, bulk fetch, one audit row per secret on every read
  and an audit row on every denial. End-to-end test that a ciphertext relocated
  across environments in the database fails to decrypt.
- **M3.** CLI: `login`, `list`, `get`, `set`, `run -- <cmd>`, `audit`, `verify`.
  Zero dependencies.
- **M4.** Admin UI: browse projects and environments, reveal (audited), create
  and edit secrets, read the audit log, and verify chain integrity.

- **Management.** Projects, environments, secrets and grants are created,
  renamed and archived through the UI and the API. Every structural change is
  audited.
- **Version history and restore.** Every version records who wrote it and
  when. Restoring an old version writes it again as a new version, so nothing
  is overwritten and the history reads in order.
- **Bulk `.env` import.** Previews as a diff (added / changed / unchanged)
  before writing. The CLI and the UI parse with the same parser
  (`packages/core/src/dotenv.ts`) and plan with the same client function, so
  they cannot disagree about what a `.env` file means; malformed lines are
  reported, never silently mangled. The preview is a dry run of the write
  (`PATCH …?dryRun=1`): the server compares with the current values and
  answers per key, so no value leaves it, and each value it opens is logged
  as a read. Writing is one `PATCH` of the changed keys.
- **Identity directory.** Users and service accounts are managed separately
  from project permissions. Owners can manage the directory and read the full
  audit log; root admins remain deployment configuration.
- **Sign-in.** coffre's own sign-in page, with providers as configuration:
  GitHub (including an organisation check and Enterprise Server), Google
  (optionally one Workspace domain), Microsoft Entra, and any OpenID Connect
  issuer, which covers Okta, Auth0, Keycloak and the like. An account binds to
  the provider's stable user id, never to an email. The CLI signs in with a
  device code, and machines use service tokens coffre issues. See
  [phase 4 of the roadmap](docs/roadmap.md#phase-4-sign-in).
- **Deployment.** `coffre init --workers` or `--node` writes a small project
  that imports `@coffre/server`, `@coffre/ui` and `@coffre/vault` and
  configures them in code. See [docs/deploy.md](docs/deploy.md).
- **Syncs.** An environment can be pushed to GitHub Actions, Vercel, Railway
  or Cloudflare Workers and kept current there: on every change, and hourly
  to repair drift. Only keys coffre pushed are ever removed, and every value
  that leaves is audited first. See [docs/syncs.md](docs/syncs.md).
- **Keys.** The key-encryption key is a local key in the vault's
  configuration, or an AWS KMS key it never leaves, whose every use
  CloudTrail logs with the secret's ids. See [docs/keys.md](docs/keys.md).
- **Offboarding.** Removing someone revokes their grants, sessions, CLI
  logins and linked sign-in accounts in one step. Their page then lists the
  values they read or wrote that are still current, the syncs they set up and
  the tokens they issued, until each is dealt with. See
  [docs/offboarding.md](docs/offboarding.md).
- **Access overview.** `coffre access` still reports every principal and grant
  across the projects the caller administers, including scope and expiry. It
  remains available to project access managers for operational offboarding.

### The web UI

Two audiences use it and they want opposite things. An engineer glances at an
environment with a terminal open beside the browser; an auditor reads two
hundred log rows while writing a finding. So it ships both colour schemes,
following `prefers-color-scheme` with a manual override, and stays dense enough
for the first without being unreadable for the second.

Things worth knowing about it:

- **It is drawn as a plain developer tool.** Neutral surfaces, bordered
  cards, and tables as grids with a row-number gutter; Inter for the interface
  and JetBrains Mono for anything a machine reads back (keys, slugs, values,
  sequence numbers). A table too wide for the window scrolls sideways rather
  than squeeze a column to nothing, and on a phone its rows stack into cards.
  A sidebar opens on the workspace switcher, holds the sections (Projects,
  Users, Tokens, Audit, and the workspace's Settings) and, at its foot, your
  account with your own settings (theme, identity). It folds down to its icons
  (⌘B, or the button at the left of the bar) and stays folded across visits,
  set before first paint so a reload does not flash it open. The switcher is
  ahead of the server, which has no notion of workspaces yet: it shows the one
  this deployment is and says so if you try to create another.
  The bar above the page holds search and a
  link to this repository, and inside a project, the path to where you are.
  That path is itself a switcher: one click on `prod` lists its sibling
  environments. Hue is kept for meaning: blue for
  edits not yet saved, amber for a value on screen, red for what leaves or is
  refused, green for what was allowed. The fonts are self-hosted from exactly
  pinned packages, and every icon is Lucide at one stroke weight, drawn through
  `components/icons.tsx` so a second family cannot creep in beside it.
- **Colours are authored in OKLCH and verified, not eyeballed.**
  `scripts/check-contrast.mjs` converts every token back to sRGB and fails on
  any text pair under WCAG AA, or any accent whose chroma clips the gamut. It
  caught four real failures on the first run, including a muted grey that had
  been sitting at 4.2:1.
- **Both themes are one declaration each**, via CSS `light-dark()`. The obvious
  alternative writes every light value twice and the copies drift.
- **No decision is carried by colour alone.** `allow` / `deny` in the audit log
  is exactly the red/green pair deuteranopia collapses, so each row carries a
  glyph and the word as well as the hue.
- **Revealing is always a deliberate click.** Focusing or tabbing through a
  field never decrypts anything, and editing a value does not need to read it.
  A revealed value hides itself after 45 seconds, with a countdown so the
  disappearance is expected; re-revealing writes a second, honest row. It also
  belongs to the version it decrypted, so a save, a rollback or someone else's
  write clears it rather than leaving an old value on screen.
- **Edits are staged, then saved together.** Renames, new values, new secrets
  and archiving collect in a save bar and are written as the individual audited
  operations they are, stopping at the first refusal so a retry picks up
  exactly what did not land.
- **Restoring gets an undo toast, not a confirmation dialog.** Dialogs are
  reserved for changes that reach other people -- archiving a project or
  environment, revoking a grant -- and each one says what will actually break.
- **Access is managed from either side.** A project's page has tabs for its
  environments, the users and tokens that hold grants on it, and its settings;
  adding one picks from those registered, each shown with what it already
  holds there (only instance owners may list them; anyone else types a name). Each user and token has a page too, listing its grants across the projects
  you manage. Its "Edit access" dialog opens on what it holds -- a level per
  project (owner, read or write everywhere, or per environment), each grant
  with its own expiry -- and saving sends only the difference. Granting what
  is already held is not an error, from either side. The server has no call
  that moves an expiry, so a new expiry is a revoke and a re-grant, restored in
  place; the audit log shows the pair.
- **Permissions shape the page.** Sections are gated individually, so an access
  manager administers grants without seeing a rename control, and never meets an
  affordance that refuses them. A tab you cannot use is not drawn.

`⌘K` jumps to any project or environment.

#### Built on TanStack Start

Vite 8 plus TanStack Router, replacing Next.js. Notes for anyone reading the
code expecting the old shape:

- **Every UI read and write goes through `@coffre/client`**, with no server
  functions or server components. Loaders read through `context.client`: in
  the browser that is `fetch` to `/api`, and during the server render a
  transport that hands the request straight to the API in the same Worker
  invocation, carrying only the visitor's credential. No API base URL, no
  self-fetch, and the same checks and audit as the CLI. Mutations call the
  client from the browser, then invalidate the router.
- **`router.invalidate()` replaces `revalidatePath`.** The old version had to
  name the routes a mutation affected, and renaming a project meant remembering
  to revalidate both `/` and `/:project`. Invalidating refetches every mounted
  loader, so the path's project and environment lists cannot silently go stale.
- **The Vite 8 toolchain runs no install scripts.** It uses Rolldown and
  lightningcss, both shipped as prebuilt platform packages, so `ignoreScripts:
  true` costs nothing here. That was worth checking before committing to it.
- **The build is a handler, not an app.** `vite build` produces
  `@coffre/ui`: TanStack Start's fetch handler for the pages alone, which
  `@coffre/server` calls for every path that is not `/api`, `/auth` or a
  health check, on Workers and Node alike. The server owns the runtime:
  Hyperdrive's pool on Workers (coffre never keeps a `pg` client across
  requests), the five-minute heartbeat, and the security headers.
- `src/routeTree.gen.ts` is generated and gitignored; `vite build` writes it.

### There is no delete, and that is deliberate

`audit_log` holds `ON DELETE RESTRICT` references to projects, environments and
secrets, so anything that has ever been read or written cannot be removed:

```
ERROR: update or delete on table "secrets" violates foreign key constraint
       "audit_log_secret_id_fkey" on table "audit_log"
```

Letting a delete cascade would destroy the evidence this service exists to keep.
So "delete" is **archive** — for projects, environments and individual secrets
alike: hidden from listings, reads refused, every row still present and the
audit trail still valid. Archiving is reversible and the values survive intact.

Archiving a secret matters operationally, not just tidily: a rotated-out
credential stops being injected by `coffre run`.

Actually destroying data belongs to a retention policy under Art 12(2)(a) —
a decision to be written down and applied deliberately, not a button in an
web UI.

### Authorisation: roles and permissions

Permissions are a **fixed catalogue**, not a policy language. Roles are named
bundles of them.

| Permission | Scope |
|---|---|
| `secret.read` | project or environment |
| `secret.write` | project or environment |
| `secret.archive` | project or environment |
| `audit.read` | project or environment |
| `environment.manage` | project only |
| `grant.manage` | project only |
| `project.manage` | project only |

Built-in roles:

| Role | Permissions | Can read secrets? |
|---|---|---|
| `viewer` | `secret.read` | yes |
| `developer` | `secret.read`, `secret.write` | yes |
| `maintainer` | + `secret.archive`, `environment.manage` | yes |
| `access-manager` | `grant.manage` | **no** |
| `auditor` | `audit.read` | **no** |
| `owner` | everything | yes |

The project role `owner` is distinct from the instance role with the same
label. An instance owner manages users and service accounts and can read the
complete audit log. Project access is still granted only from the relevant
project, where `owner`, `viewer`, and the other project roles describe what the
identity can do there.

The last two are why roles exist at all. Under the previous `read < write <
admin` ladder, seeing the audit log required `admin`, which also meant reading
every secret — so appointing someone to answer "who read which secret" meant
handing them the whole vault. `auditor` and `access-manager` both deliberately
omit `secret.read`.

**Scope.** A grant targets a project or exactly one environment; the schema
enforces `(project_id IS NULL) <> (environment_id IS NULL)`. A project grant
applies to every environment in it, and effective permissions are the *union*
of project- and environment-scoped grants.

Environment permissions are inherently project-specific: `environments.project_id`
is `NOT NULL`, so an environment belongs to exactly one project, and grants are
always resolved by `(project_id, slug)`.

A role carrying project-only permissions **cannot** be scoped to one
environment — `environment.manage` on a single environment would authorise
creating its own siblings. The API rejects it with 409 rather than silently
granting less than asked.

Grants may carry an expiry. The vault enforces it on every unwrap, and the app's
`can()`, the single place every check goes through, only sees grants the vault
still counts.

Principals are `user` (matched on the Access `email` claim) or `service`
(matched on `common_name`, because service-token JWTs carry no email at all).

`root-admin` is not a project role. It is deployment-wide bootstrap authority
from the vault's `rootAdmins`, and is shown only in the cross-project Users view.
Creating a project writes a real `owner` grant for the creator. In the project
UI, the underlying role and scope are presented as one permissions value:
`Owner`, `Read: all`, `Write: all`, or read/write for one named environment.

### Things that are stubbed, not finished

- Syncs cover four destinations. Scaleway Secret Manager, AWS and the rest
  are not built in; `coffre run` or `coffre export` with a service token
  covers them.
- The KEK is a local key or AWS KMS (`awsKms`). No Scaleway provider (its
  Audit Trail does not log Decrypt), and no command yet to rewrap existing
  data keys under a new KEK.
- The vault signs checkpoints of both logs' heads, and the app records each
  in its own log, but nothing exports them further off-box yet.
- `.env` import does not support literal multi-line values (use `\n` inside
  double quotes) or variable interpolation. Both are reported as parse problems
  rather than guessed at.
- The project-only-permission rule (a role containing `grant.manage` cannot be
  scoped to one environment) is enforced in the API with tests, not by
  a database constraint — unlike the append-only guarantee, which is.
- The domain/API logic behind every screen and the TanStack auth/health boundary
  are automated. `check:contrast` mechanically verifies the palette; the React
  interaction layer is still verified by hand.
- The web UI has three UI runtime dependencies (`radix-ui`, `cmdk`, `sonner`)
  where it previously had none beyond React. They buy correct focus management,
  the command palette and toasts; they also mean ~75 more packages in a service
  that holds every credential we own. Pinned exactly and subject to the same
  7-day minimum release age as everything else. The two `@fontsource`
  packages are font files and CSS only, with no dependencies of their own.
- TanStack Start is on the 1.168 line, which moves fast. Server functions use
  the current `.validator()` API; pin bumps deserve a changelog and boundary
  test review rather than a version bump on trust.

### Why `--test-concurrency=1`

The integration tests share one database and reset it in `beforeEach`. Run in
parallel they clobber each other. Serialising is the pragmatic fix for a
prototype; the real fix is a schema (or database) per test file. Meanwhile
`COFFRE_TEST_DATABASE=<name>` points a Postgres run at another scratch
database. The deployed app uses Postgres; SQLite is for tests and local dev.

`COFFRE_TEST_ENGINE` (`postgres` or `sqlite`) picks the engine; the
`test:*` scripts set it. A few tests are Postgres-only, the restricted runtime
login and the session time zone among them, and each says why when skipped.

## Deliberately out of scope

No Terraform here (it lives in the infrastructure repository). No rotation
engine, no dynamic secrets, no PKI, no policy DSL (a grants table is enough),
no HA. No Kubernetes operator — external-secrets has a generic `webhook`
provider that can call this API later.

## Open question

If our Infisical data uses nested folders/paths, the flat
`project/environment/key` model will hurt on migration. Worth checking before
the schema is treated as settled.

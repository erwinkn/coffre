# <img src="docs/brand/mark.svg" width="64" height="64" alt="" align="absmiddle"> coffre

A small secrets manager you deploy yourself, built around its audit log.
People sign in with GitHub, Google, Microsoft or any OpenID Connect provider,
or through Cloudflare Access. Everything lives in one Postgres database.

**Status: ready for a first deployment.** The first live instance,
erwinkn.com, is next ([roadmap](docs/roadmap.md)). The packages are not on
npm yet: install from a checkout, or from packed tarballs, which
`pnpm test:consumer` exercises.

## Why this exists

We self-host Infisical. Unlicensed self-hosted Infisical writes **no audit
logs at all**, which we verified in its source:

- `backend/src/ee/services/license/license-fns.ts`, `getDefaultOnPremFeatures()`
  returns `auditLogs: false`, `auditLogsRetentionDays: 0`;
- `backend/src/ee/services/audit-log/audit-log-queue.ts:107`,
  `if (!plan?.auditLogsRetentionDays) return null;`.

Every entry is dropped, silently: no error, no warning, no metric. A logging
system that stops logging without telling anyone is the failure coffre is
built not to repeat.

The driver is DORA, and the text is CDR (EU) 2024/1774, Article 12. It says
*you* choose the events to log (12(2)(a)); it does not require a record of
every value read. "Who read which secret, when" is a control we chose, which
is a stronger position than claiming a regulator demands it.

What we do not claim: that nothing else does this. OpenBao logs every request
in its open-source core. We built rather than adopted because we want a
secrets service small enough to read end to end, with sign-in left to a
provider we already trust.

**Why the log is our own.** We first planned on Scaleway Key Manager as an
outside record of every key use. It is not one: Scaleway's Audit Trail logs
ten Key Manager endpoints, all of them changes to keys (`CreateKey`,
`RotateKey`, …), and no `Encrypt` or `Decrypt`
(`scaleway/docs-content`, `macros/audit-trail/key-manager-endpoints.mdx`,
checked 2026-06-12). Its Secret Manager does not log reads either. So
tamper-evidence comes from coffre's own log, and the one KMS coffre supports,
AWS's, is there because CloudTrail does log every `Decrypt`, with the
secret's ids ([docs/keys.md](docs/keys.md)).

## How it works, in one minute

A deployment is a small project of your own that imports coffre's packages
and configures them in code. It runs two components, as two Cloudflare
Workers or two Node processes:

- **the app**: the API, sign-in, the pages, and a job every five
  minutes;
- **the vault**: the vault key, which wraps every value's own key, who is a
  member, and who holds what. It decides every read and write of a key, and
  nothing else can.

Both use one Postgres database, each through its own login, and both write
to one audit log. Say Ada runs `coffre run market/prod -- ./deploy`. The app
checks her session and asks the vault for the data keys of
`market/prod`'s nine secrets. The vault checks her grants, logs nine
`secret.read` entries in her name, commits them, and only then hands the keys
back. If the log cannot be written, she gets nothing.

[docs/architecture.md](docs/architecture.md) explains the whole design, and
its [limits](docs/architecture.md#limits). [docs/deploy.md](docs/deploy.md)
walks through a deployment.

[Secrets in CI and deploys](docs/ci.md) covers the GitHub Action and pulling
values into Cloudflare, Vercel and other deploy pipelines.

## Running it locally

```sh
pnpm install
pnpm dev        # Postgres, the dev IdP, coffre and its vault, then seed data
```

Open http://127.0.0.1:3000 and sign in through either button as
`admin@acme.example`, the root admin, or any seeded person (`lead@`, `dev@`,
`auditor@`, `outsider@`, all at `acme.example`). The dev IdP plays GitHub and
an OpenID Connect provider, and asks which person you are. `pnpm dev` runs a
deployment like `examples/workers` on the packages' sources, so an edit
anywhere reloads in place; it resets and reseeds its database each time.

The checks:

```sh
pnpm test              # lint, then every test on Postgres (needs it up: pnpm db:up)
pnpm test:sqlite       # the same suite on SQLite
pnpm test:properties   # bounded Hegel properties; --long for 100x cases (docs/property-tests.md)
pnpm test:properties:server  # modeled server operations; --long for 40 sequences
pnpm test:schema       # what the restricted logins may and may not do
pnpm build             # every package
pnpm typecheck         # every package, the examples and dev/ (after pnpm build)
pnpm conformance:workers   # examples/workers, held to docs/conformance.md (after pnpm build)
pnpm conformance:node      # examples/node, its two processes, on SQLite
pnpm test:consumer     # pack the packages, init both examples outside the repo, run them
                       # --kind workers or --kind node selects one deployment
pnpm check:pins        # every dependency pinned exactly
pnpm check:contrast    # every colour pair in the UI meets WCAG AA
pnpm check:docs        # every path and script the docs name exists
```

`scripts/restore-drill.sh` restores a backup end to end on this machine
([docs/restore.md](docs/restore.md)). [AGENTS.md](AGENTS.md) has the rest:
ports, a second stack beside the first, and how the packages find each
other's sources.

## The CLI

`pnpm coffre <command>` runs the CLI from this checkout; `pnpm coffre login
http://127.0.0.1:3000` signs it in to the local stack. A deployed instance
needs only its address:

```sh
coffre setup                                # a new deployment's logins, migrations and keys, and on Workers, Cloudflare (docs/deploy.md)
pnpm exec coffre migrate --yes              # in a deployment, before its deploy: its pinned version's migrations
coffre login https://secrets.acme.example   # a device login: approve it in the browser
coffre whoami
coffre use                                  # the instances you are signed in to

coffre list     market/dev
coffre get      market/dev/DATABASE_URL
coffre set      market/dev/DATABASE_URL     # asks for the value, or reads it piped in
coffre run      market/dev -- printenv
coffre export   market/dev --format dotenv  # or json, shell, github
coffre history  market/dev/DATABASE_URL
coffre rollback market/dev/DATABASE_URL 2   # restores version 2 as a new version
coffre import   market/dev --file .env      # previews; --apply writes

coffre projects
coffre roles
coffre access                               # who holds what, where you manage access
coffre grant market alice@acme.example --role developer --env dev
coffre offboard alice@acme.example          # previews; --apply removes (docs/offboarding.md)
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
                                            # the CI runs trusted to sign in as token:api-deploy;
                                            # previews the claims, --apply saves (docs/design/oidc.md)
coffre untrust api-deploy <binding-id>

coffre audit --denied
coffre verify                               # asks which: instance, keys or log; owners only
coffre verify log                           # checks the whole log
coffre verify keys                          # checks the keys you keep, on your machine (docs/keys.md)
coffre verify instance                      # checks the instance from outside (docs/conformance.md)
```

`coffre export market/prod --format github` appends values to `GITHUB_ENV`
for subsequent GitHub Actions steps and emits mask commands for the values
and their individual lines before writing the file. It refuses outside an
Actions step without `GITHUB_ENV`, and refuses `NODE_OPTIONS`, which the
runner blocks there. GitHub's default metadata variables cannot be overridden.

The default `dotenv` format is data for `.env` parsers, including coffre's
import, with escaped line breaks. Do not source it as shell code. For a shell,
use `--format shell`, which quotes values literally, including quotes and
newlines, or use `coffre run` to pass them directly to a child process.

A session lasts 30 days, is kept per instance in `~/.coffre/credentials.json`
(mode 0600), and can be revoked from the account page. The CLI reads no
environment variable, and a secret is never a flag or an argument: a command
asks for it at a hidden prompt, or reads it from stdin. CI signs in the same
way, with a service token from the Tokens page, piped to `coffre login
--token`; or as a service by its ID token, `--service`
([docs/ci.md](docs/ci.md)); or with an Access service token
([docs/deployment-auth.md](docs/deployment-auth.md)):

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

## The API

The API is addressed by path: `market` is a project, `market/prod` an
environment, `market/prod/DATABASE_URL` a secret, and `user:ada@acme.example`
or `token:ci-deploy` a member. The URL names the thing; the method is the
verb.

```sh
curl -X PATCH $COFFRE/api/secrets/market/prod \
  -H 'content-type: application/json' \
  -d '{"DATABASE_URL": "postgres://…", "OLD_KEY": null}'
# {"operationId":"…","keys":{"DATABASE_URL":{"version":4},"OLD_KEY":{"archived":true}}}
```

Or, typed, from TypeScript:

```ts
import { createClient } from '@coffre/client';

const coffre = createClient({ url: 'https://secrets.acme.example', headers: () => ({ authorization: `Bearer ${token}` }) });
await coffre.secrets.set('market/prod', { DATABASE_URL: 'postgres://…', OLD_KEY: null });
const { values } = await coffre.secrets.reveal('market/prod');   // logged, one entry per secret
await coffre.access.set('user:ada@acme.example', { market: 'developer', 'market/prod': null });
```

A `PATCH` is a JSON merge patch: a field you send is set, `null` archives or
revokes it, and a field you leave out stays. Values leave only through
`POST /api/reveals`; no `GET` returns one. The full table, the error codes and
the rules behind them are in
[docs/architecture.md](docs/architecture.md#the-api).

## Roles

Permissions are a fixed list, and roles are named sets of them. A grant gives
one member one role at one place, a project or one of its environments, and
may carry an end date. A project grant covers every environment in it.

| Role | Permissions | Reads secrets? |
|---|---|---|
| `viewer` | `secret.read` | yes |
| `developer` | `secret.read`, `secret.write` | yes |
| `maintainer` | + `secret.archive`, `environment.manage` | yes |
| `access-manager` | `grant.manage` | **no** |
| `auditor` | `audit.read` | **no** |
| `owner` | all seven | yes |

`access-manager` and `auditor` are why roles exist at all. Under the old
read, write, admin ladder, reading the audit log took admin, which also read
every secret, so the person answering "who read which secret" could read them
all. A role with a project-wide permission (`environment.manage`,
`grant.manage`, `project.manage`) cannot be granted on one environment: the
API answers 409 rather than grant less than asked.

Two roles sit above projects. **Root admins** are named in the vault's
configuration, and no row anywhere makes someone one. They hold every
permission everywhere, reading secrets included, so keep the list short.
**Instance owners** are members a root admin or another owner marks as
owners. They add and remove members, create projects, manage access and read
the whole log, but read a secret only with a grant. Creating a project grants
no one anything.

## Design decisions worth knowing

**The log write is part of the read, and fails closed.** No queue. The vault
writes a read's entry in the transaction that decides it, before any key
leaves; if the entry cannot be written, the read does not happen.

**One entry per human action.** Ada's `coffre run` of nine secrets is nine
`secret.read` entries sharing one operation id: "she read these nine values,
at these versions", not "she read the environment", which is true and
useless.

**Gaps mean tampering.** An entry's number comes from a locked head row, not
a sequence, because a rolled-back transaction would burn a sequence value,
and that gap would look exactly like a deleted entry.

**Ciphertext is bound to ids, never names.** A value is encrypted for
`project_id/environment_id/secret_id`, so renaming an environment orphans
nothing. Two layers bind it: the value's encryption, and the wrapping of its
data key. `packages/core/test/envelope-aad-isolation.test.ts` exists because
the obvious test passes at the wrapping layer and would miss the other one
regressing.

**History is never deleted.** The log references projects, environments and
secrets with `ON DELETE RESTRICT`, so anything ever read or written cannot be
removed. "Delete" is *archive*: hidden from listings, refused to readers,
reversible, and every row still there. Archiving a rotated-out secret also
stops `coffre run` injecting it. Destroying data belongs to a retention
policy, a decision written down and applied deliberately, not a button.

**Append-only by grant, not by convention.** Neither login may change or
delete a log entry; each may append only as itself; only the vault's login
may change members and grants. Each entry also carries its author's MAC,
which even the database's owner cannot forge without that author's key.

**`/api` is the one front door.** Every call, a page's own server render
included, goes through it. The pages call the same typed client as the CLI,
in process during a server render, so there is no second path around the
permission checks or the log. A change made with a cookie must come from
coffre's own pages, which stops another site acting in a visitor's name.

**The `.env` parser refuses ambiguity rather than guess.** It is where free
text becomes credentials. Unknown escapes stay verbatim, text after a closing
quote is an error, NUL bytes are refused (`execve` cuts at them), and all
three line endings split lines. Writing its tests found four ways it used to
corrupt values silently (`packages/core/test/dotenv.test.ts`).

**Machines are not people.** A Cloudflare Access service token carries no
email and an empty `sub`, so code that reads `claims.email` gets `undefined`
for every machine caller, and machines are most of the traffic. Members are
`user:<email>` or `token:<name>`, never a bare email.

## The web UI

Two audiences with opposite needs: an engineer glancing at an environment
with a terminal beside the browser, and an auditor reading two hundred log
lines while writing a finding. So it is dense without being cramped, with
both colour schemes, following the system's with a manual override.

- **Revealing is always a deliberate click.** Tabbing through a field never
  decrypts anything, and editing a value does not read it. A revealed value
  hides itself after 45 seconds, with a countdown, and belongs to the version
  it decrypted: a save, a rollback or someone else's write clears it.
- **Edits are staged, then saved together**, as the separate logged
  operations they are, stopping at the first refusal so a retry picks up
  exactly what did not land.
- **No decision is carried by colour alone.** `allow` and `deny` are the
  red-green pair deuteranopia merges, so each line also carries a glyph and
  the word. Colours are written in OKLCH, and `pnpm check:contrast` fails any
  text pair under WCAG AA; it found four real failures on its first run.
- **Permissions shape the page.** A control you cannot use is not drawn, so
  an access manager administers grants without ever meeting a button that
  refuses them.
- **The audit page reads as sentences**, one line per action ("ada ran
  market/prod: 9 secrets"), with technical steps and sign-ins hidden until
  asked for.

The pages are TanStack Start, as `@coffre/ui`: a deployment's app is a
conventional Start app of its own, built once by Vite, whose route files
mount coffre's pages and server routes (`/api`, `/auth`, the health checks),
and whose start file its middleware, as it would an auth SDK's, beside pages
of its own ([Your own routes](docs/deploy.md#your-own-routes)). The pages
read and write only through `@coffre/client`.

## Layout

```
packages/server       @coffre/server: /api, sign-in, the scheduled job; /cloudflare, /node, /start and /routes
packages/vault        @coffre/vault: the vault key, members and grants, its entries in the log; /cloudflare and /node
packages/db           @coffre/db: the schemas, migrations and migrator, the connections
packages/core         @coffre/core: access rules, encryption, vault keys, the log's format, sign-in, the vault's contract
packages/client       @coffre/client: the API as typed calls
packages/ui           @coffre/ui: the pages, for a deployment's own Start app, and its Vite plugin
packages/cli          @coffre/cli: `coffre`, from init and login to secrets and the log
packages/conformance  @coffre/conformance: `coffre-conformance`, and the dev IdP it signs in through
examples/workers      what `coffre init --workers` writes: two Workers, the app a Start app built by Vite
examples/node         what `coffre init --node` writes: a server, its pages' Start app, and its vault process
dev/                  what only `pnpm dev` uses: its deployment, the dev IdP's launcher, the seed
scripts/              what dev, tests and CI share
```

The eight packages are released together at one version, and each imports
the others by name only. The GitHub Action's CLI pin moves with them.

## Supply chain and releases

See the [release notes](CHANGELOG.md) before upgrading.

Install scripts are off, every dependency is pinned exactly, and a version
must be seven days old before it can be installed. That last rule blocked
`jose@6.2.4` the first week, published six days before we tried it.

Two traps, both noted in `pnpm-workspace.yaml`:

- **pnpm 11 reads only auth and registry settings from `.npmrc`**, and
  ignores the rest without a word. Our hardening did nothing until it moved
  to `pnpm-workspace.yaml`.
- **`savePrefix: ''` is read but not applied by `pnpm add`**, which still
  writes caret ranges. Add dependencies with `pnpm run add:dep`, and
  `pnpm check:pins` catches any that slip through.

**Releasing.** `pnpm bump 0.2.0`, merged, then a pushed tag, `v0.2.0`: the
release workflow publishes all eight packages with npm's trusted publishing
(the workflow's OIDC token, no stored token) and provenance, so each version
on npm names the commit and run that built it.

## Not in scope

No Terraform (it lives with the infrastructure), no rotation engine, no
dynamic secrets, no PKI, no policy language (a grants table is enough), no
high availability, and no Kubernetes operator: external-secrets' generic
`webhook` provider can call the API.

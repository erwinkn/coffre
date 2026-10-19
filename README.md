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
`market/prod`'s nine secrets. The vault checks her grants, logs one
`secret.read` entry in her name listing the nine, commits it, and only then
hands the keys back. If the log cannot be written, she gets nothing.

[docs/architecture.md](docs/architecture.md) explains the whole design, and
its [limits](docs/architecture.md#limits). [docs/deploy.md](docs/deploy.md)
walks through a deployment.

[Secrets in CI and deploys](docs/ci.md) covers the GitHub Action and pulling
values into Cloudflare, Vercel and other deploy pipelines.
[Read coffre from tools that speak Vault](docs/vault.md) covers External
Secrets Operator, the `vault` CLI, vals and Terraform, through an optional,
read-only Vault KV v2 API.

## Running it locally

```sh
pnpm install
pnpm dev        # Postgres, the dev IdP, coffre and its vault, then seed data
```

Open http://127.0.0.1:3000 and sign in through either button as
`admin@acme.example`, the Owner, or any seeded person (`lead@`, `dev@`,
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
pnpm formal            # the locking protocol, model-checked over every interleaving (docs/formal.md)
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
coffre setup                                # a new deployment's logins, migrations and keys; on Workers, Cloudflare and deploys on push (docs/deploy.md)
pnpm exec coffre migrate --yes              # in a deployment, before its deploy: its pinned version's migrations
coffre login https://secrets.acme.example   # a device login: approve it in the browser; pins this directory to it
coffre whoami                               # who you are, where, and why there
coffre use                                  # the instances you are signed in to, and the directories pinned to each
coffre sessions                             # where you are signed in; sessions revoke <id> signs one out
coffre identities                           # the accounts you sign in with
coffre tokens issue --label cursor-agent --scope market/dev=developer --expires-in 4h
                                            # a personal token: acts as you, for a script or an agent, within
                                            # its scope and never past what you hold (docs/design/personal-tokens.md)
coffre tokens                               # your personal tokens; tokens revoke <id> ends one

coffre list     market/dev                  # keys, who wrote each value and how long ago; --stale, those due for rotation
coffre get      market/dev/DATABASE_URL     # the value; piped, exactly its bytes, no newline added (a terminal gets one)
coffre set      market/dev/DATABASE_URL     # asks for the value, or reads it piped in
coffre set      billing/prod/DATABASE_URL --ref market/prod/DATABASE_URL   # a reference: billing reads market's, live
coffre set      market/dev/TWILIO_SID AC0123456789 --plain   # no secret: listed as it is, given to apps as it is
coffre set      market/prod/STRIPE_SECRET_KEY --sensitive    # shown to nobody, Owners included: used through the proxy, read by services
coffre mark     market/prod sensitive       # its own values made stricter, kept; names the references and inherited keys it leaves
coffre set      market/prod/SESSION_SECRET --generate bytes:32:hex   # a value made here, never shown; the recipe is kept
coffre set      market/prod/JWT_PRIVATE_KEY --generate ecdsa:p-256  # a key pair: JWT_PUBLIC_KEY beside it, in one write
coffre regenerate market/prod/SESSION_SECRET   # rotates it: a new value by its recipe, a key pair both keys at once
coffre references market/prod               # what reads it through references; references break ends one
coffre run      market/dev -- printenv
coffre run      market/prod auth/prod -- ./deploy   # several: their keys together; a key in two of them stops it
coffre run --keep-existing market/dev -- ./app      # a variable already set in your shell (empty too) wins over coffre's
                                            # a person, where the deployment has the credential proxy: placeholders, not values;
                                            # the app's own config points at <coffre>/use/<credential> (docs/design/credential-proxy.md)
coffre export   market/dev --format dotenv  # or json, shell, github; several environments, as run
coffre export   market/prod --output-file .env --watch --on-change 'systemctl reload app'   # kept current, read only once it changed
coffre version  market/prod                 # what a read would open, as a version that changes when it would; reads no value
coffre history  market/dev/DATABASE_URL
coffre rollback market/dev/DATABASE_URL 2   # restores version 2 as a new version
coffre import   market/dev --file .env      # previews; --apply writes
coffre rename   market/dev/DB_URL DATABASE_URL   # the key, with its versions
coffre archive  market/dev/OLD_KEY          # out of reads, runs and exports; its versions kept
coffre unarchive market/dev/OLD_KEY         # back, as it was
coffre missing  market/dev                  # keys its sibling environments have and it lacks; missing dismiss, restore
coffre missing  market/prod --check        # for CI: exits 1 when one is missing, dismissed ones apart

coffre move     market/dev/STRIPE_KEY stripe   # into a folder, to arrange the list; --none takes it out
coffre move     market Clients              # a project into a folder of projects
coffre folders                              # the projects' folders, and what is in each
coffre folders  market/dev                  # an environment's key folders
coffre folders rename Clients Customers     # every project in it re-filed; market/dev stripe payments, its keys
coffre folders remove market/dev stripe     # every key out of it, each staying where it is; previews, --apply
                                            # a folder is a label: there while something is in it, made by move

coffre projects
coffre projects create market
coffre projects rename market --slug marketplace   # a new path: scripts naming market need it
coffre projects archive market              # every environment out of reach, nothing deleted
coffre projects unarchive market
coffre projects delete market               # an archived one, for good: previews; --apply deletes
coffre environments create market/dev
coffre environments rename market/dev --slug development
coffre environments archive market/dev
coffre environments unarchive market/dev
coffre fork     market/prod staging         # a new environment, each key a copy of prod's value, no history; --reference follows prod
coffre fork     market/prod prod-eu --inherit   # copies nothing: reads prod's keys live, but for those it sets or removes
coffre reset    market/prod-eu/DATABASE_URL # in a fork, back to prod's value; --undo serves its own again
coffre remove   market/prod-eu/SENTRY_DSN   # in a fork, does without prod's key; --undo inherits it again
coffre set      market/dev@me/DATABASE_URL  # your personal dev: values only you read; reads of dev@me are dev's while you have none
coffre personal market                      # the project's personal configs: whose, of what, key names; for its maintainers
coffre roles                                # every role, in two columns: anywhere, and in a protected environment
coffre environments protect market/prod     # people hold their role's protected column there; service accounts as before
coffre roles set developer --protected use,write,read   # an Owner edits a role: previews whom it widens, --apply saves
coffre roles set release-manager --name 'Release manager' --permissions use,write --protected use   # or makes one
coffre access                               # who holds what, where you manage access
coffre admit alice@acme.example             # a member first, then their grants
coffre grant market alice@acme.example --role developer --env dev
coffre revoke market alice@acme.example --env dev
coffre admit bob@acme.example --role developer --environments dev   # dev in every project, the ones made later too
coffre offboard alice@acme.example          # previews; --apply removes (docs/offboarding.md)

coffre admit api-deploy --service           # a service, for CI
coffre grant market api-deploy --role viewer --env prod --service
                                            # or both at once, all or nothing: --grant market/prod=viewer
coffre tokens issue api-deploy --output-file token   # a new 0600 file, reaching what api-deploy holds now
                                            # (or less: --scope market/prod=viewer); or trust it, and no token at all:
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
                                            # the CI runs trusted to sign in as service:api-deploy, by OIDC;
                                            # previews the claims, --apply saves (docs/design/oidc.md)
coffre trust api-deploy --issuer <iss> --jwks-file jwks.json --claim sub=…
                                            # an issuer coffre cannot reach, by its keys: a Kubernetes cluster (docs/kubernetes.md)
coffre untrust api-deploy <binding-id>      # the CI runs it would cut off; --apply removes it
                                            # anyone with access does these for what they hold, where
coffre settings service-accounts --except-environments prod   # this lets them: prod's take an Admin

coffre audit --denied
coffre audit market/prod/DATABASE_URL       # who read or changed it, a run of all of market/prod included
coffre verify                               # asks which: instance, keys or log; admins and owners
coffre verify log                           # checks the whole log, as an auditor, admin or owner of all of it
coffre verify keys                          # checks the keys you keep, on your machine (docs/keys.md)
coffre verify instance                      # checks the instance from outside (docs/conformance.md)
```

`coffre help` lists every command, and `coffre <command> --help` each one.
Everything the API does, the CLI does, but approving a `coffre login`, which
a browser signed in to coffre does: `packages/cli/src/commands.ts` maps each
route to its command, and a test fails when a route has neither a command
nor a reason.

`coffre export market/prod --format github` appends values to `GITHUB_ENV`
for subsequent GitHub Actions steps and emits mask commands for the values
and their individual lines before writing the file. It refuses outside an
Actions step without `GITHUB_ENV`, and refuses `NODE_OPTIONS`, which the
runner blocks there. GitHub's default metadata variables cannot be overridden.

The default `dotenv` format is data for `.env` parsers, including coffre's
import, with escaped line breaks. Do not source it as shell code. For a shell,
use `--format shell`, which quotes values literally, including quotes and
newlines, or use `coffre run` to pass them directly to a child process.

`--output-file .env` writes the export to a file only you can read (0600),
whole or not at all: beside it, then renamed over it. With `--watch`, coffre
keeps that file current. Every minute (`--interval`, from 5s to 24h) it asks
each environment's version, `coffre version market/prod`, which reads no
value and is not logged, and reads the values only once a version changed:
a value written, a key added, archived or renamed, or for a fork, anything
it inherits. It rewrites the file only when what it holds changed, then
runs `--on-change`, through the shell, without any value in its
environment. A round that fails keeps the file as it was, says why on
stderr, and waits twice as long before the next, up to 15 minutes or the
interval, whichever is longer; a first round that fails ends it, as an
export would. Each read is logged as any export's, and answers the version
of what it read, which the watch compares the next with.

A session lasts 30 days, is kept per instance in `~/.coffre/credentials.json`
(mode 0600), and can be revoked from the account page.

With several instances, say your company's and your own, each directory
picks its own. `coffre login <url>` pins the directory it ran in to that
instance, for it and every directory below, and makes the instance the
default too. A command uses `--url`, else the nearest pinned directory's
instance, else the default (`coffre use <url>` switches it):

```sh
cd ~/Code/acme && coffre login https://secrets.acme.example
cd ~/Code/mine && coffre login https://secrets.example.com
cd ~/Code/acme/web && coffre whoami
# ada@acme.example (user) on https://secrets.acme.example (pinned at ~/Code/acme), via coffre sign-in
```

A login where the CLI already holds a session the instance still knows
keeps it and only pins; `coffre logout` first for a new one. Only the
instance answering that it does not know the session starts a new login:
if it cannot be asked, the login stops and keeps the session. A login in
your home directory, or above it, sets the default only. A directory
pinned to an instance you are not signed in to says so, and never falls
back to another instance. Nor does a command that cannot tell which pin
applies, with a pins file it cannot read or reached through a symbolic
link, or run in a directory removed since: it stops, and `--url` names
the instance instead. `coffre logout` unpins every directory pinned
to the instance. The pins, which hold no secret, are in
`~/.coffre/directories.json`, by real path, so a directory reached
through a symbolic link uses its target's pin. Earlier CLIs do not
read them, and use the default everywhere.

A repository can name its instance for everyone who clones it, in a
`coffre.json` it commits, which holds that and nothing else:

```json
{ "url": "https://secrets.acme.example" }
```

Below it, a command with no `--url` and no nearer pin uses that instance:
the nearest pin or `coffre.json` above the directory wins, your own pin
first in the same directory, and a `coffre.json` in your home or above it
is ignored. The file only picks where commands go. What they carry is
still that instance's own session, so a clone that names another URL
reaches nothing you are signed in to. A fresh clone's first command says
so, `not signed in to https://secrets.acme.example, which
/home/ada/Code/acme/coffre.json names`, and `coffre login`, with no URL, signs in
there after saying which file named it. That login pins nothing, as the
file already routes the repository; `whoami` and `use` say `named by
~/Code/acme/coffre.json`. A secret handed to `coffre login` (`--token`,
`--access-client-id`, `--id-token`) goes only to a URL you name. A
`coffre.json` that is not a file, holds another key, or names anything
but an origin, as `https://…` (or `http://` on this machine), stops the
commands below it with its path, rather than send them elsewhere.

The CLI reads no environment variable, and a secret is never a flag or an
argument: a command asks for it at a hidden prompt, or reads it from stdin.
CI signs in as a
service account, a machine identity: by OIDC, its ID token matched by a trust
binding, `--service`, with nothing to store ([docs/ci.md](docs/ci.md)); or
with a bearer token from the service account's page, piped to `coffre login
--token`; or, behind Access, with an Access service token
([docs/deployment-auth.md](docs/deployment-auth.md)):

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

## The API

The API is addressed by path: `market` is a project, `market/prod` an
environment, `market/prod/DATABASE_URL` a secret, and `user:ada@acme.example`
or `token:ci-deploy` a member: the API, the vault and the audit log name a
service account `token:<name>`, which the CLI and the UI show as
`service:<name>`. The URL names the thing; the method is the verb.

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
const { values } = await coffre.secrets.reveal('market/prod');   // logged: one entry, naming each secret and version
await coffre.access.set('user:ada@acme.example', { market: 'developer', 'market/prod': null });
```

A `PATCH` is a JSON merge patch: a field you send is set, `null` archives or
revokes it, and a field you leave out stays. Values leave only through
`POST /api/reveals`; no `GET` returns one. The full table, the error codes and
the rules behind them are in
[docs/architecture.md](docs/architecture.md#the-api).

## Roles

Permissions are a fixed list, and roles are named sets of them. Each person
has one **instance role**, which applies in every project its scope takes
in, the ones made later too. A **grant** gives one member one project role
on a project or one of its environments, may carry an end date, and only
adds to the role. Service accounts are always members: they hold grants
only.

| Instance role | Holds, inside its scope | Reads secrets? |
|---|---|---|
| Member | nothing: only what grants give | no |
| Auditor | `audit.read` | **no** |
| Developer | `secret.read`, `secret.use`, `secret.write` | yes |
| Admin | `audit.read`, `environment.manage`, `grant.manage`, `project.manage`; people and service accounts | **no** |
| Owner | all eight, and what an Admin does | yes |

A role's **scope** has two filters, Projects and Environments, each all,
only some, or all except some. Projects are named by id, so a rename keeps
them; environments by name, so `dev` is the `dev` of every project:

| Scope | Reaches |
|---|---|
| projects all, environments only `dev` | every project's `dev`, never a project around one |
| projects all except `billing` | every project but billing, and every new one |
| projects only `web`, `api` | web and api, and nothing made later |

| Project role | Permissions | Reads secrets? |
|---|---|---|
| `viewer` | `secret.read`, `secret.use` | yes |
| `contributor` | `secret.use`, `secret.write` | **no**: uses them, through placeholders |
| `developer` | `secret.read`, `secret.use`, `secret.write` | yes |
| `maintainer` | + `secret.archive`, `environment.manage` | yes |
| `access-manager` | `grant.manage` | **no** |
| `auditor` | `audit.read` | **no** |
| `owner` | all eight | yes |

`secret.read` hands values back: a reveal, `coffre get`, the values of
`coffre run`. `secret.use` only uses them: a person's app gets
placeholders, which the credential proxy fills in
([design](docs/design/credential-proxy.md)). A Contributor adds and
changes values without ever reading one. What a person gets is the
narrower of their role and the key: a sensitive key is only ever used,
whatever the role.

Grants and the role add up, and none takes anything away: a Developer scoped
to `dev`, with `viewer` on `billing`, writes every `dev` and reads all of
`billing`. `access-manager`, `auditor` and Admin are why roles exist at all.
Under the old read, write, admin ladder, reading the audit log took admin,
which also read every secret, so the person answering "who read which
secret" could read them all. A project role with a project-wide permission
(`environment.manage`, `grant.manage`, `project.manage`) cannot be granted
on one environment: the API answers 409 rather than grant less than asked.

**Owners of the whole instance**, the Owner role with no scope, hold every
permission everywhere, reading secrets included, so keep them few. The
instance always has one: the vault's `owners` names Owners nobody demotes
while named, made ones as the vault starts and when they sign in, and the
last cannot be demoted or removed until there is another ([deployment-auth.md](docs/deployment-auth.md#the-owners-the-deployment-names)).
Only an Owner of the whole instance makes, changes or removes an Owner.
An Admin or Owner whose scope narrows nothing **runs the instance**: adds and removes people,
sets instance roles and the instance's settings, and manages every service
account. An Auditor, Admin or Owner whose scope narrows nothing reads the
whole log, the instance's own entries included, and verifies it. A scoped
Admin manages environments and grants inside its scope only, and sets no
role. Nobody changes their own role, but an Owner stepping down, or grants
themselves one, which stops a quiet read of one's own; it is no boundary. An Admin holds no secret
permission, but can still reach any value in its scope by admitting a
service account, granting it a reading role and issuing its token, each
step in the log, as a 0.4 owner could: make Admins only people you would
trust with the values.

**Anyone who holds access sets up service accounts for it.** A Developer of
every `dev` adds `ci-web`, gives it `developer` on `market/dev`, issues its
token or trusts its workflow by OIDC, with no Admin: at most what they hold
themselves, and only on an account whose every grant they hold. The
setting **Who sets up service accounts** (Settings, or `coffre settings
service-accounts --except-environments prod`) keeps the rest to Admins
([docs/design/instance-roles.md](docs/design/instance-roles.md)). It names
environments by slug, so a Maintainer who renames `prod` takes it out of
`all except prod`, and one who renames `staging` away, then `prod` to
`staging`, takes it into `only dev, staging`: both lists follow the
current slug. They hold it already, so it is policy rather than a
boundary; keep Maintainer of a project, which renames its environments,
to those you trust with its service accounts. A person brings back only
an account they removed; one someone else removed, only those who run
the instance bring back.

## Design decisions worth knowing

**The log write is part of the read, and fails closed.** No queue. The vault
writes a read's entry in the transaction that decides it, before any key
leaves; if the entry cannot be written, the read does not happen.

**One entry per human action.** Ada's `coffre run` of nine secrets is one
`secret.read` entry that lists them: "she read these nine values, at these
versions", not "she read the environment", which is true and useless. Ask
the log about any one of the nine and that entry answers.

**Gaps mean tampering.** An entry's number comes from a locked head row, not
a sequence, because a rolled-back transaction would burn a sequence value,
and that gap would look exactly like a deleted entry.

**Ciphertext is bound to ids, never names.** A value is encrypted for
`project_id/environment_id/secret_id`, so renaming an environment orphans
nothing. Two layers bind it: the value's encryption, and the wrapping of its
data key. `packages/core/test/envelope-aad-isolation.test.ts` exists because
the obvious test passes at the wrapping layer and would miss the other one
regressing.

**History is never deleted; values can be.** The log references projects,
environments, secrets and their versions with `ON DELETE RESTRICT`, so
nothing ever read or written leaves the database. Archiving hides a place
or a secret: refused to readers, reversible, every row still there.
Archiving a rotated-out secret also stops `coffre run` injecting it.
Deleting an archived project or environment is for good, and for those who
run the instance only: every version's ciphertext and wrapped data key is erased, the
vault revokes every grant there, and it leaves every list. A tombstone of
names stays, renamed `market~deleted-2026-10-05`, so the log still reads and
verifies, and `market` is free for a new project. Backups taken before still
hold the encrypted values ([Deleting for good](docs/architecture.md#deleting-for-good)).

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
- **A value's age is in plain sight.** Each key says how long ago its value
  was written, a reference's its source's, and the table sorts by it. Past
  the deployment's `rotateAfterDays`, a year unless it says, a quiet tag
  says to rotate it; `coffre list --stale` lists the same keys.
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

See the [release notes](CHANGELOG.md) before upgrading. 0.4.0 is a clean
break: no upgrade from 0.3 or earlier, which is deployed afresh, on a new
database ([deploy.md](docs/deploy.md#from-a-release-before-040)). From
0.4.0 on, each release migrates before it deploys, and serves nothing until
its migrations have run.

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

**Releasing.** Each change adds its note under `## Unreleased` in the
[release notes](CHANGELOG.md). A release is `pnpm bump 0.4.2`, a commit and
a PR, with no `pnpm install` and no hand edit: the bump moves every
package's version, the examples' pins and their entries in
`pnpm-lock.yaml`, and heads those notes `## 0.4.2 (<today>)`, under a new,
empty `## Unreleased`. Validate proves that diff version-only and skips the
full suite. Merged, then a pushed tag, `v0.4.2`: the release workflow
publishes all eight packages with npm's trusted publishing (the workflow's
OIDC token, no stored token) and provenance, so each version on npm names
the commit and run that built it.

## Not in scope

No Terraform (it lives with the infrastructure), no rotation engine, no
dynamic secrets, no PKI, no policy language (a grants table is enough), no
high availability, and no Kubernetes operator: external-secrets' generic
`webhook` provider can call the API.

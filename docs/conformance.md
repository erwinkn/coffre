# Conformance

A deployment is a small project of its own: it starts as what `coffre init`
writes, and may change from there, by configuration, by an edited Worker, or
by a package taken in and rewritten. `coffre-conformance`
(`@coffre/conformance`) checks what must hold whatever code it runs: nobody
reads a value without access, another site cannot act with someone's
cookie, a removed member is out at once, no value is given without an audit
entry, and both authors' entries in the shared log catch changes made
without their keys.

It checks from outside. It boots the deployment as its own scripts would,
signs people in through a stand-in GitHub, and uses the API, the pages and
the database like anyone who could reach them.

## Running it

From a deployment, a devDependency since `coffre init`:

```sh
pnpm conformance                   # Node: the server and its vault process, on SQLite in a temp dir
pnpm conformance \
  --postgres postgres://owner:…@127.0.0.1:5432 \
  --runtime postgres://coffre_runtime:…@127.0.0.1:5432 \
  --vault-runtime postgres://coffre_vault_runtime:…@127.0.0.1:5432
                                   # Workers: both, under wrangler dev
```

On Workers, `--postgres` is a login that may create databases: the run makes
one of its own, `coffre_conformance_<random>`, migrates it and drops it
after. `--runtime` is the same server as `coffre_runtime`, the login the app
runs as, and `--vault-runtime` as `coffre_vault_runtime`, the vault's. All
are local; nothing is deployed.

coffre takes `--port` (3082), the stand-in IdP the next port, and wrangler's
inspector the one after. `--bulk-limit <n>` names the vault's `bulkLimit`
when the deployment changed it. `--browser <path>` names the Chrome or
Chromium the pages are loaded in; without it, one found on the machine is,
and without one, that check is skipped and says so. Each run starts from nothing and leaves
nothing behind. It inspects the whole log several times, including deliberate rewrites; runtime depends on the deployment and database.

In this repository, `pnpm conformance:workers` and `pnpm conformance:node`
run it on the examples, and `pnpm test:consumer` on what the packed CLI's
`init` writes. Build first: the examples run the packages' `dist/`.

An instance that is running already is checked from outside by the CLI,
`coffre verify instance`; see [Against a running
instance](#against-a-running-instance). The local run takes it too, through
the CLI's own entry, so that it is tested in this repository's CI.

## How it runs a deployment

It first builds the app as it deploys: the deployment's own `vite build
app`, which leaves the server in `app/dist/server`, for wrangler, or on
Node srvx, to run as built, and the browser's files in `app/dist/client`.
A build that fails stops the run there.

The settings go in as the environment the deployment's own files would give
it: `wrangler dev` of `app/dist/server/wrangler.json` and
`vault/wrangler.jsonc`, with Worker secrets from the environment, or `src/vault.ts` and the
built app under srvx, as `pnpm start` runs it, with what `.env` and
`vault.env` would hold. Three things are the
run's own: fixed local keys; GitHub's URLs, pointed at the dev IdP
(`@coffre/conformance/idp`) in the checker's process; and
`ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT=true`, so that a trust binding may
name the dev IdP's CI issuer, plain HTTP on loopback, as an instance on
loopback may. So a deployment must
list `github(…)` among its `signin(…)` providers, as `init` writes it; one
behind Access, or with only other providers, cannot be booted as it is. Nothing from the shell's
`COFFRE_*` reaches it.

On Workers, wrangler runs the app's build behind an entry of the run's own,
written beside it in `app/dist/server` and replaced by the next build. It
reads a request's body before passing the app's answer on, when the app
left it unread, as every refusal does: locally, and only there, a Worker
wrangler did not bundle fails every request after one whose body it left
unread. The app itself never waits on a body it does not read, and a check
sends only bodies that end.

The people:

| | |
|---|---|
| root admin | `root@conformance.example`, the one root admin the vault is told of |
| reader | a viewer on `conformance/dev` |
| leaver | a developer on `conformance/dev`, in a browser and in the CLI (a device login); removed along the way |
| bulk reader | a viewer on `conformance/bulk`, where there are more values than the bulk limit |
| service | `token:conformance-ci`, a viewer on dev with a token; removed along the way |
| CI run | `token:conformance-run`, a viewer on dev with no token: a trust binding lets a GitHub workflow's runs sign in as it, by the ID token the dev IdP signs for them |
| stranger | never admitted |

Every value set is a canary, `coffre-canary-<random>`, never to be seen
outside a reveal by someone allowed to.

## The checks

In order, since each builds on the ones before:

| Check | What must hold |
|---|---|
| health | `/livez` answers. On Workers, `/readyz` fails before any heartbeat, and passes once the Cron trigger has run and the vault has checkpointed it |
| browser bundle | Nothing of the server in what the browser loads: every text file of the build's `app/dist/client`, read as the browser gets it, holds no database layer, driver, table only the server knows or `COFFRE_*` read. A page importing across the line otherwise just grows by the database layer, with no error |
| sign-in | The root admin signs in through GitHub, and is the root admin |
| setup, personas | The admin creates the project, its values and the people above |
| pages in a browser | Signed in as the admin, `/projects`, the project and `/audit`, in headless Chrome, over the DevTools protocol: each shows its heading once its scripts have run and settled, with no uncaught error, console error or failed load. Run between setup and personas. It is what caught wrangler's `keep_names` wrapping the functions seroval writes into a signed-in page in an `__name` only the Worker has |
| sign-in error, once | A member's address that GitHub now gives another account is refused as `account_mismatch`, and sent back to `/login?error=account_mismatch&with=github&via=github`. The server's HTML says the address already signs in with another GitHub account; in Chrome, the page says it, then its address is `/login`, and a reload shows no error |
| security headers | Twelve kinds of response, each with coffre's headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, the two cross-origin policies, `Cache-Control`) and a Content-Security-Policy whose nonce no other response had: the sign-in page, a signed-in page, a page's redirect to sign in, a page not found, an API read and an API refusal, a path under `/api` or `/auth` that is not one, a method refused with its body unread, sign-in's redirect to the provider, `/livez` and `/readyz`. Whatever answers each, Start's render or one of coffre's server routes, coffre's middleware must have secured it |
| members only | The stranger's sign-in is refused and leaves no session; no one gets 401 reading, revealing or writing, and a made-up token is refused |
| grant scoping | The reader reads dev and nothing else, and changes nothing: no write, no grant, no member, no token. So does the service, with its token. The bulk reader cannot read dev |
| folders | A project and a secret filed in folders are listed in them, and the secret is read and run by its own name, with its own value, by the same reader; the reader files neither, and a folder name with a slash is refused |
| forks | The admin forks dev: the fork holds dev's values, each with one version; the reader, a viewer on dev, can neither fork dev nor read the fork. It is archived after |
| references | The admin makes a key in dev a reference to a prod secret: the reader, a viewer on dev with no grant on prod, reads prod's value through it, and the read is in prod's log and in dev's. The leaver, a developer on dev who cannot read prod, makes none. A reference row written straight into the database, pointing at a vault entry about something else, is refused as `bad_claim`; once the admin breaks the reference, the read answers 409. The key is archived after |
| missing keys | The admin adds a key to prod alone: dev's missing keys show it to the admin, not to the reader, a viewer on dev who cannot read prod; the reader cannot dismiss it; the admin's dismissal moves it to the dismissed list, and restoring brings it back. The key is archived after |
| reveals audited, runs audited | A single-secret reveal or an environment read writes one `secret.read` of the vault's per value, under the reveal's operation and request, at the versions revealed |
| cross-site | A write, a reveal and a sign-out with the admin's cookie, from another site or from no page at all: 403, no value in the answer, nothing changed |
| live setup | The admin sets up what a token from CI needs: `conformance/live/CANARY`, and `token:conformance-live`, a viewer there and auditor on the project |
| verify with a token | `coffre verify instance`, the built CLI in a home of its own, signed in with that token, piped to `coffre login --token`, and its canary's value piped in, as CI runs it: every check [as no one and with the token](#against-a-running-instance) passes, but the token's verification, which it skips. Neither the token nor the canary shows in what it prints |
| login as a user, login as the admin | `coffre login`, in a CLI of each one's own, approved by the reader and by the root admin in their browsers |
| verify as a user | `coffre verify instance` with the reader's session, a plain user: it exits 1, says plainly it needs an owner or a root admin, and makes nothing. The session still works. No member, grant, project or environment changes |
| verify as the admin, verify again | With the root admin's session, twice: every check of the [owner tier](#signed-in-as-an-owner) passes, and none is skipped. The first makes `token:conformance-probe` and its grants; the second finds everything. No line shows a credential, the session or the canary, and the session still works after |
| verify interrupted | The same, stopped with Ctrl-C mid-run: it exits 130, its credential revoked and the session still signed in, and nothing it printed shows a credential or a canary |
| verify leftovers | After the runs: the service holds no credential, the CLI's session is the one `coffre login` made, `conformance/live/CANARY` is as the live setup wrote it, no other member, grant, project or environment changed, and the runs' entries are in the audit log |
| verify keys | `coffre verify keys` with the admin's session: the deployment's own keys pass, piped in, vault ID included; a wrong vault key and a malformed app key are each named. No key shows in what it prints |
| manage by CLI | With the admin's `coffre login` session: a project and its environment made, a secret set and renamed; `grant` to a service not yet admitted refused, naming `coffre admit … --service`; the service admitted and granted; `tokens issue --output-file` writes a 0600 file and prints no token; the token, piped to `coffre login --token` in a CLI of its own, reads the renamed secret; `tokens revoke` previews, then with `--apply` the token is refused, plainly; the grant revoked, the secret and the project archived, as `list --json` and `projects --json` show; `sessions --json` marks the CLI's own session |
| delete by CLI | With the same session: `coffre projects delete` refuses a live project; archived, it shows what it would erase (five versions), revoke (the one grant of a service) and leave holding nothing, warns that earlier backups still hold the values, and changes nothing. With `--apply`, every version under it has an empty ciphertext and wrapped key in the database, the project is renamed `conformance-gone~deleted-<date>`, leaves every list and revealing it by its tombstone is 404; a new `conformance-gone` is another project, reading its own value, and the log names the deletion under the tombstone. `coffre environments delete` does the same for an environment, whose slug is then free in its project. The log verifies |
| offboarding | Removing the leaver names the values they read, to rotate; their browser session, their CLI session and a new sign-in all stop at once. A removed service's token stops too |
| bulk limit | One more value at once than the limit allows gets 403 `bulk_limit`, with reason `bulk_limit`; a single value still opens |
| trust a run | The admin trusts `deploy.yml`, pushed to `main` of `acme/api`, to sign in as `token:conformance-run`, from the dev IdP's CI issuer (`/workloads`). A deployment that trusts no workloads skips this and the checks after it, to tokens unlogged |
| run signs in | That run's ID token buys a five-minute credential at `POST /api/auth/oidc`, which reads dev as the service. The vault's `secret.read` names the credential, and the audit log leads from the read to the run |
| run token spent | A token is taken once: sent again, it is refused as `replayed`, and so is an ES256 token's twin, its signature's (r, n − s) in place of (r, s) |
| runs refused | Tokens for another instance, expired, from a feature branch, from a pull request or from another repository, and a good token for a service no binding names: each 401 with its reason, never what the binding expects, and none logged as an exchange |
| run signs in by CLI | `coffre --service … get`, as on GitHub Actions (asking the runner's token endpoint), which keeps no credential on disk; and `coffre login --service … --id-token` with the token piped in, then `coffre get`: each reads the value and prints no token |
| run unbound | Removing the binding ends the credential it issued at once, and the next run's token buys none |
| exchanges limited | Malformed tokens from one address get 429 `busy`, with `Retry-After: 60`, within 200 a minute: the limit counts before anything is read. Last of these, since it spends the address's minute |
| tokens unlogged | No ID token or credential these checks used is in the processes' output, nor any service credential |
| checkpoints | Each Cron run has the vault sign the log up to its last entry, in an `audit.checkpoint` entry of its own that covers the one before, and the log verifies through it |
| keys behind writes | Every `secret.write` and `secret.restore` names, by `related_seq`, the vault's `key.wrap` or `key.rewrap` for the same member, request, operation, secret and version; and no value read is logged by the app, only by the vault |
| no audit, no value | With a trigger refusing `secret.read` appends, a reveal gets 500 `internal_error`, the injected cause appears in the process output, and no value leaves; it works again once the log does |
| canary scan | No value in any answer to any GET route, or any page, as each of the people, signed in or removed; nor in the database, in any column of any table; nor the processes' output |
| app login, vault login | Neither the app's login nor the vault's can update, delete, truncate or drop the audit log, append an entry as the other, change or delete a value's versions, delete a secret or a member, or create a table; nor can the app's write a member or a grant. Postgres only: SQLite has no logins |
| access authorship | Admission, grant, revoke, removal and re-admission leave only vault entries |
| no audit, no access | A refused append commits no grant, removal or admission |
| full verification | Verification reaches the actual head and counts every entry |
| checkpoint refused, checkpoint missing | A recent heartbeat without an accepted checkpoint turns readiness red; restoring checkpointing recovers |
| forged grant, forged member, stale member | A forged grant, an edited member or a genuine older member row put back is refused at use, marked tampered, and logged as vault.tampered. Sign-in mode refuses the credential with 401 |
| sealing race | On Postgres, a grant inserted while the vault's decision waits on the held log head is refused as `tampered` and logged; removal recovers the member. SQLite prevents that concurrent write; the vault suite covers review R2 on Postgres |
| forged credential, forged identity, forged approval, edited generation | Owner-written authentication rows cannot mint sessions or revive old tokens, and the row failure is reported |
| app rewritten, vault rewritten, vault forged | Verification catches rewrites at their sequence and a publicly chained vault entry without its MAC |
| middle gap, first gap, batch gap | Missing entries fail verification, including the first entry and the 1,000-entry paging boundary |
| middle cut | Two entries removed before the latest signed prefix make the next scheduled checkpoint refuse with `log_broken` and readiness turn red; restoring them recovers checkpointing |
| earlier checkpoint | An invalid earlier signature cannot be hidden by valid MACs and a later valid checkpoint |
| tail deleted | The newest entries removed with the head retained fail verification; this runs last |

All table inspection and tampering goes through the one database. There
is no vault file or Durable Object to discover. On Postgres, the canary scan
reads every public table as the owner, including binary columns as bytes.
Every run plants a binary canary to prove the table reader sees bytes.
Missing shared tables fail. On SQLite it also scans the database file and
its write-ahead log; a missing file fails. Workers also tests both restricted logins and the author policies.

A read has one entry, the vault's, committed before any key leaves, so there
is no second record of it to disagree. A write the app prepares again leaves
the vault's `key.wrap` for a version never stored, under an operation id no
`secret.write` shares. The unit and integration suites also test two vault
instances sharing the bulk limit and generations, removal during a KMS
call, and partial KMS failure.
The suites cover races during sign-in and late callbacks as well. Those
checks use controlled pauses inside requests; conformance cites their
evidence rather than booting a second app and vault pair.

A check that fails prints what it saw. The ones that need its result are
skipped, and the run ends with the processes' output.

## What it does not show

- **What the tampering checks cannot reach.** They write to the database
  as its owner, who can lift its triggers and pass its row-level security.
  They show that verification works, not that an attacker could get that
  far: the app's and the vault's logins cannot.
- **What an owner can still destroy.** The owner can remove or corrupt
  rows and stop access. Member MACs refuse forged grants and edited rows
  at use; they do not make the database available after destructive writes.
- **A live instance's keys and settings.** The run uses its own keys and a
  local database. `coffre verify instance` sees what anyone on the network
  can, and what one token of its own can; `coffre verify keys` holds the
  keys you keep to the instance ([keys.md](keys.md#check-your-escrow)).

## Against a running instance

`coffre verify instance` checks an instance someone runs, from the outside:
the current one, or the one its argument names. As no one, it writes
nothing. With a token, as in CI, it writes nothing either, with one
exception: each run adds a few entries to the instance's audit log, which is
append-only, so they stay for good. It says so when it starts. They are the
canary's read, and a refused read for each place it tries and must not
reach: two a run with the setup below, a refused one more for each other
environment in the canary's project. Besides, coffre notes when the token
was last used, as it does for any token. Signed in as an owner, it sets up
its own token: see [below](#signed-in-as-an-owner).

It runs in two tiers, and the local run above takes both, against the
deployment it booted.

**As no one**, always first:

| Check | What must hold |
|---|---|
| health | `/livez` and `/readyz` answer: the instance is up and its scheduled job beats |
| headers | As in the local run: a fresh CSP nonce per page, frames refused, `nosniff`, `no-store`, HSTS on https, no CORS for another origin |
| anonymous api | Every route of the API, whatever its method, answers no one 401 with `{ error, message }` and nothing more. The routes come from the client's route map, so a route added to the server fails the typecheck until it is listed, and is checked from then on |
| forged cross-site | Every change, and the sign-out, sent from another site with a session cookie gets 403. The cookie is made up: coffre refuses the request before it looks at the cookie, so a real one would get the same answer |
| sign-in info | `GET /api/auth` names the sign-in providers, or Cloudflare Access, and nothing more |
| anonymous answers | No page shows no one anything: every page but `/login` redirects to `/login` with an empty body, and `/login` carries no credential coffre issues. Without a value to look for, this is a best effort, and says so |

**With a token**, a service account's bearer token that reads one canary:

| Check | What must hold |
|---|---|
| token | The token is a service's, and reads the canary's environment, which holds its key |
| token reveal | The canary is revealed once, its value is the one given, and the audit log holds exactly one allowed `secret.read` of it under the reveal's operation and request |
| token scan | The canary's value, as text, base64 or hex, is in no answer to any GET route, as the token or as no one, nor in any page: only in its reveal |
| token scope | The token sees the canary's project and reads its environment, and nothing more: every other environment it is told of, a made-up place and the members refuse it, and the audit entries it reads are about its project only |
| token verification | The whole audit chain verifies. Verifying is for owners and root admins, which a token cannot be, so this is skipped with a token, and says it was not checked |

Each prints ✓, ✗ or – and a line, and the run exits 1 on any ✗. Behind
Cloudflare Access, which turns everyone away before coffre answers, neither
tier can run: `coffre verify instance` says so, and `coffre verify log`
verifies the audit log as you.

### Signed in as an owner

```sh
coffre login https://secrets.example.com     # once, as an owner or a root admin
coffre verify instance
```

uses the session `coffre login` made: no second sign-in, and it stays
signed in after. Without one, it says to run `coffre login` first. Then:

1. It finds `conformance`, `conformance/live` and `token:conformance-probe`,
   and makes whichever is missing, nothing else: on a first run, all three.
2. It gives the service its two grants, viewer on `conformance/live` and
   auditor on `conformance`, unless it holds them already.
3. It writes a fresh random canary to `conformance/live/SIGN_IN_CANARY`, and
   issues the service a fresh credential. A `CANARY` beside it, kept for a
   token from CI, is never touched.
4. It runs the token tier above as that credential, unchanged.
5. It verifies the whole audit chain as you, which the token tier cannot.
6. However the run ends, Ctrl-C included, it revokes the credential it
   issued, and only that: your session stays.

Neither the credential nor the canary is ever printed or written anywhere.
Signed in as anyone else, it says so and stops before it makes anything.

| Check | What must hold |
|---|---|
| owner | The session is an owner's or a root admin's |
| setup | What step 1 and 2 found and made, a fresh canary and a fresh credential |
| token, token reveal, token scan, token scope | The token tier, as the fresh credential. Its last check, token verification, which a token can only skip, is left out: yours comes next |
| owner verification | The whole audit chain verifies, read by you |
| clean-up | The credential revoked, your session left as it was; what stays |

What stays, for the next run: the project, the environment with its canary,
the service with no working credential, and the run's entries in the audit
log. A credential the service held already, from the setup below, is left
as it is, and the clean-up line says so.

### By hand, for a token in CI

The setup an owner's run does for itself, kept for a run that is
unattended, from CI, with a long-lived token. Once, as an owner. The CLI has
no command yet to create a project, an environment or a token, so those
three are made in the pages; the rest is the CLI.

1. In **Projects**, create a project `conformance`, and in it an environment
   `live`. Nothing else goes there.
2. In **Tokens**, add a token `conformance-probe`, and issue it a credential.
   It is shown once; keep it where the check will run, as a secret.
3. Write the canary, a random value nothing else uses, and give the token
   read on it and the project's audit:

   ```sh
   CANARY="coffre-canary-$(openssl rand -hex 16)"
   printf '%s' "$CANARY" | coffre set conformance/live/CANARY
   coffre grant conformance conformance-probe --service --role viewer --env live
   coffre grant conformance conformance-probe --service --role auditor
   ```

   Keep `$CANARY` beside the token: the check looks for it.

Then sign in with the token, as every CI job does, and check, the
canary's value asked for or piped in; neither is ever an argument:

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.example.com --token
printf '%s' "$CANARY" | coffre verify instance https://secrets.example.com --canary conformance/live/CANARY
```

For example, on an instance with another project, `market`, which the token
holds nothing on:

```
Checking https://secrets.example.com, as no one and with the bearer token `coffre login --token` saved
  The token's reads add a few entries to the instance's audit log, for good.

  ✓ health              /livez and /readyz
  ✓ headers             a fresh CSP nonce per page, frames refused, nosniff; no CORS; /_coffre/assets/index-C4woDgwj.js served
  ✓ anonymous api       35 routes, every method: 401, and nothing but the refusal
  ✓ forged cross-site   21 changes, sign-out included, from another site with a session cookie: 403
  ✓ sign-in info        coffre's sign-in through github, and nothing more
  ✓ anonymous answers   best effort, without a canary: 12 closed pages send no one to /login with nothing else; /login carries no credential
  ✓ token               service:conformance-probe, reading conformance/live
  ✓ token reveal        one secret.read of CANARY, entry 57, under request 1d3a7bc8-3fcf-419f-9771-c83026072506
  ✓ token scan          72 answers from 15 GET routes and 13 pages, as the token and as no one: no value
  ✓ token scope         only conformance/live; 6 reads elsewhere refused: no other environment of conformance, a made-up place, the members
  – token verification  verification is for owners and root admins, which this token is not: not checked

✓ Conformant
```

### Every day, from CI

A scheduled job, here on GitHub Actions, with the token and the canary as
the repository's secrets. This repository runs none; it is an example:

```yaml
name: Conformance
on:
  schedule:
    - cron: '17 6 * * *'
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - name: Verify the live instance
        run: |
          printf '%s' "$PROBE_TOKEN" | npx --yes @coffre/cli login https://secrets.example.com --token
          printf '%s' "$PROBE_CANARY" | npx --yes @coffre/cli verify instance https://secrets.example.com --canary conformance/live/CANARY
        env:
          PROBE_TOKEN: ${{ secrets.COFFRE_PROBE_TOKEN }}
          PROBE_CANARY: ${{ secrets.COFFRE_PROBE_CANARY }}
```

Each run adds its two entries to the audit log.

### What it cannot check

Everything that needs the deployment's insides, which only the local run
has: offboarding (it would remove someone), the bulk limit, matching app
and vault entries, a value refused when the audit log is, the tables and
processes' output holding no value, append-only logins, and tampering with
either author's entries. Nor anything the
token would have to write to show: that a viewer cannot write, grant or
add members is checked locally, not here. And it sees only what one token
reads: a leak to another member, in a place the token cannot reach, is
not something it can see.

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
pnpm conformance \
  --postgres postgres://owner:…@127.0.0.1:5432 \
  --runtime postgres://coffre_runtime:…@127.0.0.1:5432 \
  --vault-runtime postgres://coffre_vault_runtime:…@127.0.0.1:5432
                                   # Workers: both, under wrangler dev
                                   # Node: the server and its vault process
```

`--postgres` is a login that may create databases: the run makes
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
| admin | `root@conformance.example`, the one Owner the vault's deployment names, and so the instance's Owner |
| reader | a viewer on `conformance/dev` |
| leaver | a developer on `conformance/dev`, in a browser and in the CLI (a device login); removed along the way |
| bulk reader | a viewer on `conformance/bulk`, where there are more values than the bulk limit |
| service | `token:conformance-ci`, a viewer on dev with a token; removed along the way |
| CI run | `token:conformance-run`, a viewer on dev with no token: a trust binding lets a GitHub workflow's runs sign in as it, by the ID token the dev IdP signs for them |
| stranger | never admitted |

Every value set is a canary, `coffre-canary-<random>`, never to be seen
outside a reveal by someone allowed to.

## The checks

In order, since each builds on the ones before. A check that reads the
audit page waits for what it looks for there: the page lists only what the
signer has published, a second after the vault tells it of an entry, or at
its minute's run if that word was lost. So such a check can take up to
90 seconds (`PUBLISHED_SECONDS` in `packages/conformance/src/report.ts`),
and fails with what the page showed if the entry is not there by then:

| Check | What must hold |
|---|---|
| ready once adopted | Skipped until the app learns from the vault's `about` call whether it has adopted the database (T311): 0.16's `/readyz` says only that the database is migrated. On a fresh Workers deployment, `/readyz` fails until the vault has adopted the database and the signer has signed its first entry, then passes |
| health | `/livez` answers, and `/readyz` passes |
| browser bundle | Nothing of the server in what the browser loads: every text file of the build's `app/dist/client`, read as the browser gets it, holds no database layer, driver, table only the server knows or `COFFRE_*` read. A page importing across the line otherwise just grows by the database layer, with no error |
| sign-in | The admin signs in through GitHub, the first to, and is the Owner of the whole instance |
| setup, personas | The admin creates the project, its values and the people above |
| pages in a browser | Signed in as the admin, `/projects`, the project and `/audit`, in headless Chrome, over the DevTools protocol: each shows its heading once its scripts have run and settled, with no uncaught error, console error or failed load. Run between setup and personas. It is what caught wrangler's `keep_names` wrapping the functions seroval writes into a signed-in page in an `__name` only the Worker has |
| pasted values | In Chrome, a multi-line PEM key pasted into a new secret's value field, and over part of an existing value being edited: each time the field is a textarea after, focused, its caret right after the paste, and the values saved are the PEM byte for byte, and the old value with the paste in place of the selection, its `\r\n` saved as `\n`. A text input drops a paste's line breaks, so without the page's handling the key would be saved on one line. A value typed with Shift+Enter between two words turns the field into a focused textarea, its caret after the break, and saves as two lines. In an environment of its own, `conformance/pasted` |
| sign-in error, once | A member's address that GitHub now gives another account is refused as `account_mismatch`, and sent back to `/login?error=account_mismatch`, bare, as 0.16 says it (0.14.7 named the provider, `&with=github&via=github`). The server's HTML says the address already signs in with a different account; in Chrome, the page says it, then its address is `/login`, and a reload shows no error |
| security headers | Twelve kinds of response, each with coffre's headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, the two cross-origin policies, `Cache-Control`) and a Content-Security-Policy whose nonce no other response had: the sign-in page, a signed-in page, a page's redirect to sign in, a page not found, an API read and an API refusal, a path under `/api` or `/auth` that is not one, a method refused with its body unread, sign-in's redirect to the provider, `/livez` and `/readyz`. Whatever answers each, Start's render or one of coffre's server routes, coffre's middleware must have secured it |
| members only | The stranger's sign-in is refused and leaves no session; no one gets 401 reading, revealing or writing, and a made-up token is refused |
| grant scoping | The reader reads dev and nothing else, and changes nothing: no write, no grant of their own, no member. So does the service, with its token. The bulk reader cannot read dev, nor give the service dev or a token for it; the reader cannot give it prod |
| folders | A project and a secret filed in folders are listed in them, and the secret is read and run by its own name, with its own value, by the same reader; the reader files neither, and a folder name with a slash is refused |
| forks | The admin forks dev: the fork holds dev's values, each with one version; the reader, a viewer on dev, can neither fork dev nor read the fork. It is archived after |
| inheritance | The admin forks prod as a fork that inherits: it copies nothing and reads prod's values; the reader, given a viewer grant on the fork alone, reads none of what it inherits, the whole fork or one key. The grant is revoked and the fork archived after |
| personal configs | The reader, a viewer on dev, keeps a value in their personal config, `dev@me`, and reads it. The admin, an Owner of the whole instance, sees that it exists and its key's name, is refused its value (403), and their own `dev@me` reads dev. Made the admin's in the database, around coffre, the config opens nothing for them: the vault bound the value to its owner. The config is deleted after |
| references | The admin makes a key in dev a reference to a prod secret: the reader, a viewer on dev with no grant on prod, reads prod's value through it, and the read is in prod's log and in dev's. The leaver, a developer on dev who cannot read prod, makes none: 403 `no_access`. A key written straight into the database as a reference to prod's secret, with no MAC of the vault's, is no key to it: the read answers 404 `unknown_key` and carries nothing; once the admin breaks the reference, the key has no value until someone writes one: the read answers 404 `no_value` and carries nothing (0.14.7 answered 409). Neither prod nor its key can be archived while the reference reads them: 409 `referenced`, which does not name the holder as 0.14.7's refusal did; the source's references list, `GET /references`, does, and the refusal points to it. The key is archived after |
| loosening | The admin writes a sensitive key in dev, which the reader, a viewer on dev, may not read. The leaver, a developer on dev, is told the listing offers no loosening, and is refused one; the admin, told it does, makes it a secret in place: the answer carries no value, a second version is made and the first stays sensitive, the reader then reads it, and the log has one `secret.loosen` whose line for the key says the nature it `was` and the one it is now. The key is archived after |
| missing keys | The admin adds a key to prod alone: dev's missing keys show it, by name and as prod's, to the admin and to the reader, a viewer on dev who cannot read prod, with nothing of its value; the reader cannot dismiss it; the admin's dismissal moves it to the dismissed list, and restoring brings it back. The key is archived after |
| MCP connect | A client registered by DCR connects three times. A reused refresh token and a reused code each end their connection, and Connected apps ends the third. The log, once the signer publishes it, holds under the client (`metadata.client`) 3 `mcp.connect`, 4 `mcp.token` and 2 `mcp.disconnect`, the vault's own with no actor, saying `code_reused` and `refresh_reused`, and the third's end as a `token.revoke` of kind `mcp` naming its connection. 0.14.7 logged that one as a third `mcp.disconnect`, reason `person` |
| MCP changes | Each change a client asks for through Write (archive, rename, two writes) is made once, after the person approves it on coffre's page, by that person, in an entry naming the client's connection (`via`) and the approval (`approval`) by their IDs (the archive a `secret.write` whose key's line says `archived`, where 0.14.7 logged `secret.archive`); no `mcp.approve` beside it, nor any entry for the two decisions refused (already approved, another digest), which the app refuses before the vault. 0.14.7 logged each decision, those two among them. A read-only `tools/call` writes no entry under the client or its connection |
| reveals audited, runs audited | A single-secret reveal or an environment read writes one `secret.read` of the vault's per read, under the reveal's request, listing each value at the version revealed, in the audit page (once the signer publishes it, within its minute) and in the log's rows. Each value is written afresh before the read: the vault logs a credential's read of a version once a minute |
| cross-site | A write, a reveal and a sign-out with the admin's cookie, from another site or from no page at all: 403, no value in the answer, nothing changed |
| live setup | The admin sets up what a token from CI needs: `conformance/live/CANARY`, and `token:conformance-live`, a viewer there and auditor on the project |
| verify with a token | `coffre verify instance`, the built CLI in a home of its own, signed in with that token, piped to `coffre login --token`, and its canary's value piped in, as CI runs it: every check [as no one and with the token](#against-a-running-instance) passes, and none reads the log as the owner's run does. Neither the token nor the canary shows in what it prints |
| login as a user, login as the admin | `coffre login`, in a CLI of each one's own, approved by the reader and by the admin in their browsers |
| verify as a user | `coffre verify instance` with the reader's session, a plain user: it exits 1, says plainly it needs an admin or owner of the whole instance, and makes nothing. The session still works. No member, grant, project or environment changes |
| verify as the admin, verify again | With the admin's session, twice: every check of the [owner tier](#signed-in-as-an-owner) passes, `owner log proofs` among them, and none is skipped. The first makes `token:conformance-probe` and its grants; the second finds everything. No line shows a credential, the session or the canary, and the session still works after |
| verify interrupted | The same, stopped with Ctrl-C mid-run: it exits 130, its credential revoked and the session still signed in, and nothing it printed shows a credential or a canary |
| verify leftovers | After the runs: the service holds no credential, the CLI's session is the one `coffre login` made, `conformance/live/CANARY` is as the live setup wrote it, no other member, grant, project or environment changed, and the runs' entries are in the audit log |
| verify keys | `coffre verify keys` with the admin's session: the deployment's own vault key passes, piped in, vault ID included; a wrong key and a malformed one are each named. No key shows in what it prints |
| manage by CLI | With the admin's `coffre login` session: a project and its environment made, and made again, which says nothing changed (the server refuses it, `exists`); a secret set and renamed; `grant` to a service not yet admitted refused, naming `coffre admit … --service`; the service admitted and granted; `tokens issue --output-file` writes a 0600 file and prints no token; the token, piped to `coffre login --token` in a CLI of its own, reads the renamed secret; `tokens revoke` previews, then with `--apply` the token is refused, plainly; the grant revoked, the secret and the project archived, as `list --json` and `projects --json` show; `sessions --json` marks the CLI's own session |
| delete by CLI | With the same session: `coffre projects delete` refuses a live project; archived, it shows what it would erase (five versions), revoke (the one grant of a service) and leave holding nothing, warns that earlier backups still hold the values, and changes nothing. With `--apply`, every version under it has an empty ciphertext and wrapped key in the database, the project is renamed `conformance-gone~deleted-<date>`, leaves every list and revealing it by its tombstone is refused (400, as 0.16 takes the slug for no path, or 404); a new `conformance-gone` is another project, reading its own value, and the log names the deletion under the tombstone, once the signer publishes it (up to 90 seconds, above). `coffre environments delete` does the same for an environment, whose slug is then free in its project: made again, it is listed once, holding no key (0.16 names a place by its slug alone) |
| offboarding | Removing the leaver names the values they read, to rotate; their browser session, their CLI session and a new sign-in all stop at once. A removed service's token stops too |
| instance roles | No grant is on every project, and a service account holds no instance role. A Developer scoped to `dev` reads and writes the `dev` of a project made after the role, and no `prod`. An Admin scoped to one environment grants there and nowhere else, sets no role and makes no project, and an Admin of the whole instance does not change its own role, nor demote or remove the Owner (403 `not_allowed`, as in 0.14.7, not `last_owner`) |
| bulk limit | One more value at once than the limit allows gets 403 `bulk_limit`, with reason `bulk_limit`; a single value still opens |
| trust a run | The admin trusts `deploy.yml`, pushed to `main` of `acme/api`, to sign in as `token:conformance-run`, from the dev IdP's CI issuer (`/workloads`). A deployment that trusts no workloads skips this and the checks after it, to tokens unlogged |
| run signs in | That run's ID token buys a five-minute credential at `POST /api/auth/oidc`, which reads dev as the service. The vault's `secret.read` names the credential, and the audit log leads from the read to the run |
| run token spent | A token is taken once: sent again, it is refused as `replayed`, and so is an ES256 token's twin, its signature's (r, n − s) in place of (r, s) |
| runs refused | Tokens for another instance, expired, from a feature branch, from a pull request or from another repository, and a good token for a service no binding names: each 401 with its reason, never what the binding expects, and none logged as an exchange |
| run signs in by CLI | `coffre --service … get`, as on GitHub Actions (asking the runner's token endpoint), which keeps no credential on disk; and `coffre login --service … --id-token` with the token piped in, then `coffre get`: each reads the value and prints no token |
| keys uploaded | `token:conformance-pod` trusts `https://kubernetes.default.svc.cluster.local`, a host no binding could fetch from, by the dev IdP's keys uploaded with the binding, and its service account's UID, a nested claim. A pod's token reads dev; one of another UID is refused `no_match`, and one that lives past the hour `too_old`. With its keys replaced by the ES256 key alone, an RS256 token is refused `unknown_key` and an ES256 one taken |
| run unbound | Removing the binding ends the credential it issued within the vault's memory of its caller (2 seconds), and the next run's token buys none |
| exchanges limited | Malformed tokens from one address get 429 `busy`, with `Retry-After: 60`, within 200 a minute: the limit counts before anything is read. Last of these, since it spends the address's minute |
| tokens unlogged | No ID token or credential these checks used is in the processes' output, nor any service credential |
| keys behind writes | Every version stored in the conformance project is named, its secret and its number, by exactly one entry, signed or waiting to be: a `secret.write` or `secret.loosen`, or the `environment.create` of a fork that copied it. 0.14's app and vault each logged half of a write, the app's naming the vault's key wrap; in 0.16 the vault writes the version and its one entry together, and the app writes nothing |
| no audit, no value | With a trigger on `log_pending` refusing `secret.read` appends, a reveal of a key written just before, which no entry has said yet (the vault logs a credential's read of a version once a minute), gets 500 `internal_error`, the injected cause appears in the process output, and neither that value nor any other leaves; it works again, with that value, once the log does |
| canary scan | No value in any answer to any GET route, or any page, as each of the people, signed in or removed; nor in the database, in any column of any table; nor the processes' output |
| app login, vault login | The app's login holds no write privilege on any table and is refused every write, the log's included. The vault's, which writes every row and entry, cannot write 0.14's `audit_archive` or truncate any table. Neither can create, drop or truncate a table, turn off a trigger, or take another role. 0.14 also kept the vault's login off the app's tables and both off rewriting the log: in 0.16 the vault writes every table, the log's too, and the signer holds the log to its signed head |
| access authorship | Admission, grant, revoke, removal and re-admission each leave the vault's entry naming the member, read from the database, since the audit page lists only what the signer has taken |
| no audit, no access | A refused append commits no grant, removal or admission |
| forged grant, forged member, stale member | A forged grant on prod reads nothing (403 `no_access`), nor does a member row edited to Owner (401 `unauthenticated`); a genuine older grant put back is served until someone acts, as 0.16 promises (D216). The signer names the forged and the restored grant in its alert, in the processes' output, within the minute; the edited member row, under the MAC it had, is refused and not named, since the minute's check compares MACs (`docs/design/0.16.md`, "How long the log is kept"). 0.14 refused all three at use and logged `vault.tampered`, which 0.16 does not write |
| sealing race | A grant inserted while a change waits on the vault's held change lock is not sealed by the change, which goes through once the lock is let go, keeps no MAC, and reads nothing; removal recovers the member. 0.14's race held the log's head, which no 0.16 change locks |
| forged credential, forged identity, forged approval, edited generation | Owner-written authentication rows cannot mint sessions or revive old tokens. The signer names the inserted credential and identity in its alert; the approval and the generation, edited under the rows' own MACs, are refused and not named, as above |

A check that waits on a revocation, a reused MCP refresh token's, a service or personal token revoked by the CLI, or a row the vault no longer takes, waits the vault's default memory of a caller, 2 seconds (`memorySeconds`, D218), and a second more: a deployment that raised it raises the wait.

All table inspection and tampering goes through the one database. There
is no vault file or Durable Object to discover. The canary scan reads every
public table as the owner, including binary columns as bytes. Every run
plants a binary canary to prove the table reader sees bytes. Missing shared
tables fail. Each kind also tests both restricted logins and the author policies.

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

A check of a route 0.16 declares and does not serve yet is skipped by name,
saying what it waits for (`packages/conformance/src/unserved.ts`), and runs
again once the area that serves the route deletes its line. 0.14's checks
of `GET /audit/verification` (full verification, the rewritten, forged and
missing entries, the earlier checkpoint and the deleted tail) went with the
route, and `checkpoint refused`, `checkpoint missing` and `middle cut` with
the heartbeat and checkpoint they tested: in 0.16 readiness never turns red
on tampering, and the signer's full check reports a cut to the alert
function or the Worker's log.
In 0.16 the audit page proves each entry it lists against the head
the vault signed: `audit proven` requires every entry the head numbers
proven, only those past it not, and the page's stretch lacking none
(`judgeProofs`, which `coffre verify instance` shares; it asks again while
the page races its head: a batch signed between the head's read and the log's
can leave the whole page past it, and a pruning committed in between can
leave the older head counting aging entries it removed), and `audit page proofs` that the page is sent
with them rendered, each row's proof in `data-proof`, at least one proven
and none failed (it asks again while every row is past the head, for the
same race). Conformance does not hold either to a tampered log yet.

## What it does not show

- **What the tampering checks cannot reach.** They write to the database
  as its owner, who can lift its triggers and pass its row-level security.
  They show that verification works, not that an attacker could get that
  far: the app's and the vault's logins cannot.
- **What an owner can still destroy.** The owner can remove or corrupt
  rows and stop access. Row MACs refuse forged grants and edited rows
  at use; they do not make the database available after destructive writes.
- **A live instance's keys and settings.** The run uses its own keys and a
  local database. `coffre verify instance` sees what anyone on the network
  can, and what one token of its own can; `coffre verify keys` holds the
  key you keep to the instance ([keys.md](keys.md#check-your-escrow)).

## Against a running instance

`coffre verify instance` checks an instance someone runs, from the outside:
the current one, or the one its argument names. As no one, it writes
nothing. With a token, as in CI, it writes nothing either, with one
exception: each run adds a few entries to the instance's audit log. They
are uses, so they age out with the rest after `log.keepUsesDays` (90 days by
default). It says so when it starts. They are the
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
| health | `/livez` and `/readyz` answer: the instance is up, and its database has every migration its version ships |
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

Each prints ✓, ✗ or – and a line, and the run exits 1 on any ✗. Behind
Cloudflare Access, which turns everyone away before coffre answers, and
where 0.16.0 takes no CLI's credential, neither tier can run: `coffre verify
instance` says so. Neither checks the whole audit log, which 0.16.0's vault
watches itself (the owner tier holds the newest page of it to its head): the signer checks its end every minute and re-checks older
entries a few blocks a minute, and the audit page proves each entry it shows
([design](design/0.16.md), D222).

### Signed in as an owner

```sh
coffre login https://secrets.example.com     # once, as an admin or owner of the whole instance
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
5. It reads the newest page of the audit log as you, which the token tier
   cannot, and holds it to the head the vault signed, as conformance's
   `audit proven` does: one read, whatever the log's length.
6. However the run ends, Ctrl-C included, it revokes the credential it
   issued, and only that: your session stays.

Neither the credential nor the canary is ever printed or written anywhere.
Signed in as anyone else, it says so and stops before it makes anything.

| Check | What must hold |
|---|---|
| owner | The session is an admin's or owner's of the whole instance |
| setup | What step 1 and 2 found and made, a fresh canary and a fresh credential |
| token, token reveal, token scan, token scope | The token tier, as the fresh credential |
| owner log proofs | The newest 200 entries of the whole log: those the head numbers proven against it, none past it proven, none failed, and the page's stretch lacking no entry of either tree. It asks again for up to 90 s, each request held to that wait too, while the page races its head: every entry listed past it, signed since the vault's read, or only aging entries missing, pruned since |
| clean-up | The credential revoked, your session left as it was; what stays |

What stays, for the next run: the project, the environment with its canary,
the service with no working credential, and the run's entries in the audit
log. A credential the service held already, from the setup below, is left
as it is, and the clean-up line says so.

### By hand, for a token in CI

The setup an owner's run does for itself, kept for a run that is
unattended, from CI, with a long-lived token. Once, as an owner, with the
CLI:

1. Make a project `conformance`, and in it an environment `live`. Nothing
   else goes there.
2. Admit a service account `conformance-probe`, a viewer of
   `conformance/live` and an auditor of the project, and issue it a token.
   The token is written to a new file only you can read, and kept nowhere
   else; it lasts 90 days unless `--expires-in` says otherwise. Keep it
   where the check will run, as a secret, then delete the file.
3. Write the canary, a random value nothing else uses.

```sh
coffre projects create conformance
coffre environments create conformance/live
coffre admit conformance-probe --service --grant conformance/live=viewer,conformance=auditor
coffre tokens issue conformance-probe --label 'conformance, from CI' --output-file probe-token
CANARY="coffre-canary-$(openssl rand -hex 16)"
printf '%s' "$CANARY" | coffre set conformance/live/CANARY
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
  The token's reads add a few entries to the instance's audit log, kept as long as it keeps uses.

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

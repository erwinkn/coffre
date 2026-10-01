# Conformance

A deployment is a small project of its own: it starts as what `coffre init`
writes, and may change from there, by configuration, by an edited Worker, or
by a package taken in and rewritten. `coffre-conformance`
(`@coffre/conformance`) checks what must hold whatever code it runs: nobody
reads a value without access, another site cannot act with someone's
cookie, a removed member is out at once, no value is given without an audit
entry, and the two logs catch what is changed behind their back.

It checks from outside. It boots the deployment as its own scripts would,
signs people in through a stand-in GitHub, and uses the API, the pages and
the database like anyone who could reach them.

## Running it

From a deployment, a devDependency since `coffre init`:

```sh
pnpm conformance                   # Node: the server and its vault process, on SQLite in a temp dir
pnpm conformance \
  --postgres postgres://owner:…@127.0.0.1:5432 \
  --runtime postgres://coffre_runtime:…@127.0.0.1:5432
                                   # Workers: both, under wrangler dev
```

On Workers, `--postgres` is a login that may create databases: the run makes
one of its own, `coffre_conformance_<random>`, migrates it and drops it
after. `--runtime` is the same server as `coffre_runtime`, the login the app
runs as. Both are local; nothing is deployed.

coffre takes `--port` (3082), the stand-in IdP the next port, and wrangler's
inspector the one after. `--bulk-limit <n>` names the vault's `bulkLimit`
when the deployment changed it. Each run starts from nothing and leaves
nothing behind. It takes about 10 seconds on Node and 50 on Workers.

In this repository, `pnpm conformance:workers` and `pnpm conformance:node`
run it on the examples, and `pnpm test:consumer` on what the packed CLI's
`init` writes. Build first: the examples run the packages' `dist/`.

`coffre-conformance probe https://secrets.example.com` checks an instance
that is already running, from outside and without changing it; see
[Against a running instance](#against-a-running-instance).

## How it runs a deployment

The settings go in as the environment the deployment's own files would give
it: `wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc` with
Worker secrets from the environment, or `src/vault.ts` and `src/server.ts`
with what `server.env` and `vault.env` would hold. Two things are the
run's own: fixed local keys, and GitHub's URLs, pointed at the dev IdP
(`@coffre/conformance/idp`) in the checker's process. So a deployment must
list `github(…)` among its `signin(…)` providers, as `init` writes it; one
behind Access, or with only other providers, cannot be booted as it is. Nothing from the shell's
`COFFRE_*` reaches it.

The people:

| | |
|---|---|
| root admin | `root@conformance.example`, the one root admin the vault is told of |
| reader | a viewer on `conformance/dev` |
| leaver | a developer on `conformance/dev`, in a browser and in the CLI (a device login); removed along the way |
| bulk reader | a viewer on `conformance/bulk`, where there are more values than the bulk limit |
| service | `token:conformance-ci`, a viewer on dev with a token; removed along the way |
| stranger | never admitted |

Every value set is a canary, `coffre-canary-<random>`, never to be seen
outside a reveal by someone allowed to.

## The checks

In order, since each builds on the ones before:

| Check | What must hold |
|---|---|
| health | `/livez` answers. On Workers, `/readyz` fails with the heartbeat an hour old, and passes once the Cron trigger has run |
| headers, anonymous api, forged cross-site, sign-in info, anonymous answers | What `probe` checks as no one; see [below](#against-a-running-instance) |
| sign-in | The root admin signs in through GitHub, and is the root admin |
| setup, personas | The admin creates the project, its values and the people above |
| members only | The stranger's sign-in is refused and leaves no session; no one gets 401 reading, revealing or writing, and a made-up token is refused |
| grant scoping | The reader reads dev and nothing else, and changes nothing: no write, no grant, no member, no token, no vault log. So does the service, with its token. The bulk reader cannot read dev |
| reveals audited | A reveal writes one `secret.read` per value, under the reveal's bundle and request, at the versions revealed |
| cross-site | A write, a reveal and a sign-out with the admin's cookie, from another site or from no page at all: 403, no value in the answer, nothing changed |
| live setup | The admin sets up what `probe --token` asks an operator for: `conformance/live/CANARY`, and `token:conformance-live`, a viewer there and auditor on the project |
| token, token reveal, token scan, token scope, token verification | What `probe --token` checks, with that token; see [below](#against-a-running-instance) |
| offboarding | Removing the leaver names the values they read, to rotate; their browser session, their CLI session and a new sign-in all stop at once. A removed service's token stops too |
| bulk limit | One more value at once than the limit allows is refused; a single value still opens, so the refusal was the quantity, not the grant |
| checkpoints | The Cron trigger checkpoints both logs, and both verify |
| two logs agree | Every key the vault opened or sealed is in the audit log, once, for the same member, request and version, and every read and write in the audit log is in the vault's |
| no audit, no value | With the audit log refusing writes (a trigger), a reveal fails and carries no value; it works again once the log does |
| canary scan | No value in any answer to any GET route, or any page, as each of the people, signed in or removed; nor in the database, in any column of any table; nor the vault's store; nor the processes' output |
| append-only | The app's own login cannot update, delete, truncate or drop the audit log, change or delete a value's versions, delete a secret or a principal, or create a table. Postgres only: SQLite has no logins |
| tampering | Verification catches an audit entry rewritten in the database, a grant written into the vault's store, a vault log entry rewritten there, and the newest audit entries deleted; each put back verifies again, but for the last, which is why it is last |

A check that fails prints what it saw. The ones that need its result are
skipped, and the run ends with the processes' output.

## What it does not show

- **What the tampering checks cannot reach.** They write to the vault's
  store directly: `vault.db` on Node, the Durable Object's SQLite in
  wrangler's local state on Workers. On Cloudflare, nobody but the object
  itself can write there, so these show that verification works, not that
  an attacker could get that far.
- **A forged grant is caught, not stopped.** The vault honours the grant it
  finds in its store until verification flags it. What stops it is who can
  write that store.
- **A live instance's keys and settings.** The run uses its own keys and a
  local database. `probe` sees what anyone on the network can, and what one
  token of its own can.

## Against a running instance

`coffre-conformance probe <url>` checks an instance someone runs, from the
outside. It never writes anything, with one exception: each run with a
token adds a few entries to the instance's audit log, which is append-only,
so they stay for good. It says so when it starts. They are the canary's
read, and a refused read for each place it tries and must not reach: two a
run with the setup below, a refused one more for each other environment in
the canary's project. Besides, coffre notes when the token was last used, as
it does for any token.

It runs in two tiers. The local run above takes both too, against the
deployment it booted, so they are tested in this repository's CI.

**As no one**, the default:

| Check | What must hold |
|---|---|
| health | `/livez` and `/readyz` answer: the instance is up and its scheduled job beats |
| headers | As in the local run: a fresh CSP nonce per page, frames refused, `nosniff`, `no-store`, HSTS on https, no CORS for another origin |
| anonymous api | Every route of the API, whatever its method, answers no one 401 with `{ error, message }` and nothing more. The routes come from the client's route map, so a route added to the server fails the typecheck until it is listed, and is checked from then on |
| forged cross-site | Every change, and the sign-out, sent from another site with a session cookie gets 403. The cookie is made up: coffre refuses the request before it looks at the cookie, so a real one would get the same answer |
| sign-in info | `GET /api/auth` names the sign-in providers, or Cloudflare Access, and nothing more |
| anonymous answers | No page shows no one anything: every page but `/login` redirects to `/login` with an empty body, and `/login` carries no credential coffre issues. Without a value to look for, this is a best effort, and says so |

**With `--token`**, a service token the operator set up for it:

| Check | What must hold |
|---|---|
| token | The token is a service's, and reads the canary's environment, which holds its key |
| token reveal | The canary is revealed once, its value is the one given, and the audit log holds exactly one allowed `secret.read` of it under the reveal's bundle and request |
| token scan | The canary's value, as text, base64 or hex, is in no answer to any GET route, as the token or as no one, nor in any page: only in its reveal |
| token scope | The token sees the canary's project and reads its environment, and nothing more: every other environment it is told of, a made-up place, the members and the vault's log refuse it, and the audit entries it reads are about its project only |
| token verification | The whole audit chain verifies. Verifying is for owners and root admins, which a token cannot be, so this is skipped with a token, and says it was not checked |

Each prints `ok`, `skip` or `FAIL` and a line, and the run exits 1 on any
`FAIL`. The token tier needs coffre's own sign-in: behind Cloudflare Access,
coffre issues no service tokens.

### Setting up the canary and its token

Once, as an owner. The CLI has no command yet to create a project, an
environment or a token, so those three are made in the pages; the rest is
the CLI.

1. In **Projects**, create a project `conformance`, and in it an environment
   `live`. Nothing else goes there.
2. In **Tokens**, add a token `conformance-probe`, and issue it a credential.
   It is shown once; keep it where the probe will run, as a secret.
3. Write the canary, a random value nothing else uses, and give the token
   read on it and the project's audit:

   ```sh
   CANARY="coffre-canary-$(openssl rand -hex 16)"
   printf '%s' "$CANARY" | coffre set conformance/live/CANARY
   coffre grant conformance conformance-probe --service --role viewer --env live
   coffre grant conformance conformance-probe --service --role auditor
   ```

   Keep `$CANARY` beside the token: the probe looks for it.

Then:

```sh
coffre-conformance probe https://secrets.example.com                     # as no one
COFFRE_TOKEN=coffre_svc_… COFFRE_CONFORMANCE_CANARY="$CANARY" \
  coffre-conformance probe https://secrets.example.com --canary conformance/live/CANARY
```

`--token` and `--canary <project>/<env>/<KEY>=<value>` work too, but leave
both in the shell's history. Without `=<value>`, the value is read from
`COFFRE_CONFORMANCE_CANARY`, or else from the first line of stdin.

For example, with a project `payments` the token holds nothing on:

```
coffre-conformance: probing https://secrets.example.com, as no one and with a token
  (the token's reads add a few entries to the instance's audit log, for good)
  ok    health              /livez and /readyz
  ok    headers             a fresh CSP nonce per page, frames refused, nosniff; no CORS; /_coffre/assets/index-BBkrf0VJ.js served
  ok    anonymous api       35 routes, every method: 401, and nothing but the refusal
  ok    forged cross-site   21 changes, sign-out included, from another site with a session cookie: 403
  ok    sign-in info        coffre's sign-in through github, and nothing more
  ok    anonymous answers   best effort, without a canary: 12 closed pages send no one to /login with nothing else; /login carries no credential
  ok    token               token:conformance-probe, reading conformance/live
  ok    token reveal        one secret.read of CANARY, entry 14, under request 93bed984-625a-4a70-a28d-3412981816d4
  ok    token scan          70 answers from 15 GET routes and 13 pages, as the token and as no one: no value
  ok    token scope         only conformance/live; 7 reads elsewhere refused: no other environment of conformance, a made-up place, the members, the vault's log
  skip  token verification  verification is for owners and root admins, which this token is not: not checked
conformant
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
  probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - name: Probe the live instance
        run: npx --yes @coffre/conformance probe https://secrets.example.com --canary conformance/live/CANARY
        env:
          COFFRE_TOKEN: ${{ secrets.COFFRE_PROBE_TOKEN }}
          COFFRE_CONFORMANCE_CANARY: ${{ secrets.COFFRE_PROBE_CANARY }}
```

Each run adds its two entries to the audit log.

### What it cannot check

Everything that needs the deployment's insides, which only the local run
has: offboarding (it would remove someone), the bulk limit, the two logs
agreeing entry for entry, a value refused when the audit log is, the
tables, the vault's store and the processes' output holding no value,
append-only logins, and tampering with either log. Nor anything the
token would have to write to show: that a viewer cannot write, grant or
add members is checked locally, not here. And it sees only what one token
reads: a leak to another member, in a place the token cannot reach, is
not something it can see.


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
that is already running: health and headers only, since it cannot sign
anyone in.

## How it runs a deployment

The settings go in as the environment the deployment's own files would give
it: `wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc` with
Worker secrets from the environment, or `src/vault.ts` and `src/server.ts`
with what `server.env` and `vault.env` would hold. Two things are the
run's own: fixed local keys, and GitHub's URLs, pointed at the dev IdP
(`@coffre/conformance/idp`) in the checker's process. So a deployment must
sign in with `signin({ github })`, as `init` writes it; one behind Access or
another provider cannot be booted as it is. Nothing from the shell's
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
| headers | A CSP with a fresh nonce per page, which the page's scripts carry; frames refused; `nosniff`, `same-origin` resources, `no-store`; HSTS on https; no CORS for any origin; the page's script served |
| sign-in | The root admin signs in through GitHub, and is the root admin |
| setup, personas | The admin creates the project, its values and the people above |
| members only | The stranger's sign-in is refused and leaves no session; no one gets 401 reading, revealing or writing, and a made-up token is refused |
| grant scoping | The reader reads dev and nothing else, and changes nothing: no write, no grant, no member, no token, no vault log. So does the service, with its token. The bulk reader cannot read dev |
| reveals audited | A reveal writes one `secret.read` per value, under the reveal's bundle and request, at the versions revealed |
| cross-site | A write, a reveal and a sign-out with the admin's cookie, from another site or from no page at all: 403, no value in the answer, nothing changed |
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
  local database. `probe` sees only what anyone on the network can.

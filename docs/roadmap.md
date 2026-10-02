# Roadmap

From a source checkout that deployed one Cloudflare Worker to packages that
deployments import and configure in their own repositories, and then to a
first live instance.

## Where we are

- **The product works end to end:** the API, the CLI, the web UI, coffre's own
  sign-in, syncs, offboarding, and conformance for every deployment.
- **It is packages** (phase 2): `coffre init --workers` or `--node` writes a
  deployment, and `coffre setup` prepares its database and keys in one go
  ([deploy.md](deploy.md)). The `@coffre` names are reserved on npm with
  `0.0.0` placeholders; the first release is published from a tag.
- **One database** (#22 to #46, designed in
  [design/single-database.md](design/single-database.md)): one Postgres
  database, two components each with its own login, one audit log, the
  vault's member list, checkpoints as log entries, `/readyz` as a query, a
  KEK check, and a restore runbook drilled locally
  ([restore.md](restore.md)). A final independent review's findings are
  fixed or parked.
- **erwinkn.com is next** (phase 3).

## Sequence

| Phase | Goal | State |
|---|---|---|
| 1. Harden | Safe to hold real secrets | Done, or parked under [Later](#later); what is left belongs to phase 3's setup |
| 2. Package | The product apart from its instances | Done |
| 3. erwinkn.com | Dogfood | Next |
| 4. Sign-in | Deployable without a proxy in front | Done |

## Phase 1: harden

1. ~~**Security headers and a CSP.**~~ Done
   (`packages/server/src/security-headers.ts`). Each response gets its own
   nonce, and `script-src` is `'self'` plus that nonce; styles stay
   `'unsafe-inline'` for React's `style` props. `Referrer-Policy` is
   `same-origin`, not `no-referrer`: under `no-referrer` a same-origin POST
   carries `Origin: null`, which the cross-site check refuses.
2. ~~**Escrow the keys, then prove recovery.**~~ Done locally:
   `scripts/restore-drill.sh` restores one database backup with the escrowed
   keys and checks values, members, grants, the log and verification, then
   the wrong-KEK case ([restore.md](restore.md)). The same drill on a
   PlanetScale branch is part of phase 3's exit.
3. **Rotation that can retire a key.** Parked under [Later](#later): the
   rewrap command.
4. **A heartbeat someone hears.** Readiness tolerates one late or missed Cron
   run (11 minutes), and turns red on a stopped log, an unsigned checkpoint,
   a cut in the log or a wrong KEK. Attaching an external monitor to
   `/readyz` is part of phase 3's setup.
5. **Checkpoints off the box.** Parked under [Later](#later), with the other
   defences against the database's owner.
6. **Backups.** PlanetScale's point-in-time recovery, part of phase 3.
7. **Guard main.** Still open, and only a setting: `main` is unprotected.
   `.github/workflows/validate.yml` runs the whole suite on every pull
   request; protect `main`, requiring a pull request and the `Validate`
   check.
8. ~~**Machine callers in the CLI.**~~ Done: `COFFRE_TOKEN` for coffre's
   service tokens, `COFFRE_ACCESS_CLIENT_ID` and `COFFRE_ACCESS_CLIENT_SECRET`
   behind Access.

## Phase 2: package

Done. coffre is eight packages a deployment imports and configures in code
([architecture.md](architecture.md)):

- one route table under `/api`, with `@coffre/client` typed from it, and the
  CLI and the pages built on the client;
- the pages as `@coffre/ui`, a prebuilt handler the server calls, which reads
  only through the client;
- Postgres through Drizzle, with SQLite for tests and local development, and
  one set of queries for both;
- the vault, `@coffre/vault`, which holds the KEK and decides access, as a
  Worker behind a service binding or a Node process behind a Unix socket;
- `coffre init`, whose output is `examples/workers` and `examples/node`, a
  test diffing the two, and `coffre-conformance`, which holds every
  deployment to what it must never do ([conformance.md](conformance.md)).

## Phase 3: erwinkn.com

The deployment lives in its own repository and imports the packages; this
repository holds no instance's configuration.

- **Database:** PlanetScale Postgres (the smallest cluster), reached through
  two Hyperdrive configs with caching off
  ([design, question 9](design/single-database.md#9-planetscale-and-hyperdrive)).
- **Sign-in:** coffre's own, with GitHub. Machines get coffre service tokens.
- **Moving in:** `coffre import` from the existing `.env` files.
- **Monitoring:** an external check on `/readyz` that pages.
- **Conformance:** `pnpm conformance` in the deployment's repository before
  each deploy, and `coffre-conformance probe` against the live address after.
- **Exit:** a few weeks of daily use with no open bugs, a restore drill on a
  PlanetScale branch, and a rotation drill (a new KEK, the old one in
  `previousKeks`).

### Syncs

Built as a server-side engine: an environment is pushed to GitHub Actions,
Vercel, Railway or Cloudflare Workers on every change, and checked hourly for
drift ([syncs.md](syncs.md)). A CLI push happens only when someone remembers
to run it, and the point is that nobody has to. The cost is that coffre holds
deploy tokens; they are ordinary secrets, so they get the same encryption,
grants and log as everything else. Still open: plain `.env` files as a
destination.

## Phase 4: sign-in

Done. coffre has a sign-in page of its own, with providers as configuration:
GitHub (with an organisation check, and Enterprise Server), Google (optionally
one Workspace domain), Microsoft Entra (one tenant), and any OpenID Connect
issuer, which covers Okta, Auth0, Keycloak and the like. A provider is an
interface, `SigninProvider`, for one that speaks neither protocol. Behind
Cloudflare Access, Access's own page does the job instead
([deployment-auth.md](deployment-auth.md)).

- **Accounts bind to a provider's user, never to an email.** A first sign-in
  binds a registered, verified email to the provider's stable user id; every
  later sign-in must match it. Say Bob leaves and IT deletes his Google
  account, but his personal GitHub account still lists bob@acme.example as
  verified: he still cannot get in through the GitHub button.
- **The CLI signs in with a device code**, which also works over SSH, and
  machines use service tokens coffre issues.
- **Sessions are coffre's**, kept on the server; ending one revokes it
  rather than deleting a row.

Still open: noticing a removal at the identity provider by itself (over SCIM
for Entra and Okta, or by polling Google Workspace's directory); until then,
someone removed there cannot sign in again but keeps an open session until it
ends. Passkeys would make a good recent sign-in for revealing.

## Later

- **Rewrap**, a maintenance command that wraps every stored data key again
  under the current KEK, leaving the ciphertext alone, so an old or leaked
  KEK can be retired, and data written under a local key can move to KMS
  ([keys.md](keys.md#moving-from-a-local-key)).
- **Defences against the database's owner**, should the threat model need
  them ([the limits](architecture.md#limits)): witnesses, where each CLI and
  browser remembers the newest entry it saw and checks the log still holds
  it; checkpoints copied off the box behind a retention lock; and each
  member's state under the checkpoint's signature, so a cut the checkpoint
  covers is refused at use rather than found at the next one.
- **A slower or resumable full recomputation**, once the log passes about
  250,000 entries ([the limits](architecture.md#limits)).
- **Changing the app's key**, and with KMS the vault's signing key: neither
  can change today, since what each signed verifies only under it.
- **The current-version pointer, and sync results as log entries**, two
  schema tidy-ups from the storage review
  ([design, plan step 11](design/single-database.md#implementation-plan)).
- A retention policy: the only sanctioned way to destroy data.
- Import from other secret managers such as Infisical, after settling how
  nested folders map to coffre's flat `project/environment/key` model.
- An external-secrets `webhook` provider for Kubernetes.
- An external review of the cryptography and the sign-in boundary.

## Decided

- **Where it is published:** publicly, at
  [erwinkn/coffre](https://github.com/erwinkn/coffre), under MIT, and on npm
  under the `@coffre` scope.
- **Sync model:** a server-side engine (phase 3).
- **Postgres for erwinkn.com:** PlanetScale Postgres (phase 3).

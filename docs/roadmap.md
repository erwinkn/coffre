# Roadmap

From a source checkout that deploys one Cloudflare Worker to a packaged
product that deployments import and configure in their own repositories.

## Where we are

- The product works end to end: API, CLI, web UI, audit chain, and now
  coffre's own sign-in (phase 4), syncs (phase 3) and offboarding.
- The in-repository instance files and deployment pipeline are gone. Until
  phase 2 packages coffre, a checkout can still deploy `apps/web` directly
  with Wrangler; [deploy.md](deploy.md) describes that temporary path.
- erwinkn.com will deploy from the erwinkn.com repository once phase 2, step 6
  provides packages that a small deployment project can import.
- Most of phase 1 is still open; only the security headers are done. The
  README says *ready for a first deployment, still hardening* until the rest
  is.

## Sequence

| Phase | Goal | Done when |
|---|---|---|
| 1. Harden | Safe to hold real secrets | Every item below shipped; restore and rotation drills pass |
| 2. Package | The product apart from its instances; Cloudflare and Node adapters; a vault; three databases | A deployment is a small project importing `@coffre/server` and `@coffre/vault`; the suite passes on Postgres, MySQL and SQLite, and the smoke suite on both adapters |
| 3. erwinkn.com | Dogfood | Your secrets live in it, the CLI and sync are in daily use, a few weeks pass with no open bugs |
| 4. Sign-in | Deployable without a proxy in front | A Node deployment signs in with Google, GitHub and an arbitrary OIDC issuer, and the CLI logs in through it |

Hardening comes first because it is mostly independent of the package layout,
and it is what the README's status line is waiting on. Packaging comes before
erwinkn.com so the first live instance uses the same package boundary as every
other deployment. Sign-in was planned last but landed early because a public
release must work without an identity-aware proxy.

## Phase 1: harden

Each item says what is wrong today.

1. ~~**Security headers and a CSP.**~~ Done, in
   `apps/web/src/server/security-headers.ts`. The Worker mints a nonce per
   response and TanStack puts it on every script it renders, so `script-src`
   is `'self'` plus that nonce; styles stay `'unsafe-inline'` for React's
   `style` props. It is enforced in development too, so a script without the
   nonce breaks where it is written. `Referrer-Policy` is `same-origin`, not
   `no-referrer`: under `no-referrer` a same-origin POST carries
   `Origin: null`, which the CSRF check refuses.
2. **Escrow the keys, then prove recovery.** `COFFRE_KEK_LOCAL`,
   `COFFRE_VAULT_SIGNING_KEY` (the vault's) and `COFFRE_AUDIT_CHAIN_KEY` (the
   app's) are Worker secrets, and that store is write-only. The vault's
   Durable Object, which holds every grant, needs a backup too.
   If no other copy exists, losing the Worker
   loses every secret. Keep an offline copy, then run a restore drill: a fresh
   database from backup plus the escrowed KEK, then `coffre verify` passes
   and a canary secret decrypts.
3. **Rotation that can retire a key.** Rotation today only changes which KEK
   wraps *new* versions. Every old version still needs the old KEK forever, so
   a leaked KEK cannot be retired. Add a `rewrap` maintenance command: it
   re-wraps each DEK under the primary, leaves the ciphertext untouched, and
   writes one audit row per secret.
4. **A heartbeat someone hears.** Readiness now tolerates one late or missed
   Cron run (11 minutes, where it used to fail at 5, the Cron interval itself,
   and flapped). Nothing monitors it yet: attach an external check on
   `/readyz` that pages you.
5. **Checkpoints off the box.** `audit_checkpoints` exists but nothing exports
   it. Whoever holds the database owner role can delete the last N audit rows
   and rewind the head, and the chain still verifies. The scheduled handler
   should write `(seq, head_hash)` somewhere outside the database's trust
   domain (on Cloudflare, R2 with a bucket-lock retention rule), and `verify`
   should compare against it.
6. **Backups.** Point-in-time recovery on whatever hosts Postgres, exercised by
   the drill in item 2.
7. **Guard main.** `main` is unprotected. `.github/workflows/validate.yml`
   runs the full contract suite on every pull request. What is left is a
   setting: protect `main`, requiring a pull request and the `Validate` check.
8. ~~**Machine callers in the CLI.**~~ Done: `COFFRE_TOKEN` for coffre's own
   service tokens, `COFFRE_ACCESS_CLIENT_ID` and `COFFRE_ACCESS_CLIENT_SECRET`
   behind Access.

Then drop "still hardening" from the README's status line.

## Phase 2: package

coffre becomes packages a deployment imports and configures in code:
`@coffre/ui`, `@coffre/server`, `@coffre/vault`, `@coffre/client` and
`@coffre/cli`, on Postgres, MySQL or SQLite through Drizzle, with a vault
that holds the keys and decides who may decrypt. The design is in
[architecture.md](architecture.md). In order:

1. ~~**Two spikes**~~: done, both positive. A prebuilt server-rendered UI
   imported by another Worker ([report](../spikes/ssr-ui/REPORT.md)), and one
   set of Drizzle queries across three dialects
   ([report](../spikes/drizzle-dialects/REPORT.md)).
2. ~~**The API**~~ ([design](architecture.md#the-api)): done. One route
   table under `/api`, on Drizzle against Postgres, with roles in code and
   one role per member per place; every query in one module of
   `packages/db`; `@coffre/client` typed from it; the CLI on the client. The
   old routes and services are gone. Import has no endpoint: the client plans
   it (a reveal and a list) and writes the changed keys with one `PATCH`.
3. ~~**The UI on the client**~~: done. Loaders read through
   `context.client`, built per request: in the browser `fetch` to `/api`, in
   the server render an in-process call to the API carrying only the
   visitor's credential. Pages change things by calling the client from the
   browser, and a cookie-authenticated change must be same-origin. The server
   functions are gone, and sessions, linked accounts and device approval
   joined the route table.
4. ~~**MySQL and SQLite**~~ ([design](architecture.md#databases)): done.
   The database comes from its URL; queries are written once against the
   Postgres schema, with MySQL and SQLite cast to it in one module, and a
   parity test keeps the three schemas and migration trees in step.
   Postgres-only SQL (partial unique indexes, `lower()` matching) was
   remodelled, the audit chain locks a head row, and SQLite queues its own
   writes. The integration suite runs on all three (`pnpm test:all`); the
   restricted runtime login stays Postgres-only.
5. ~~**The vault**~~ ([design](architecture.md#the-vault)): done.
   `packages/vault` holds the KEK, grants, principal status, root admins and
   a hash-chained log of its own, over SQLite; the app keeps ciphertext and
   wrapped keys, and asks the vault to wrap and unwrap, once per batch. It
   runs as its own Worker, `apps/vault`, a Durable Object behind a service
   binding, next to the app in dev and the smoke test, or in process over
   libSQL for the tests. Callers' grants come from the vault once per
   request; changing access and removing a member are vault calls, and a
   refusal is a 403 with the vault's code. Unwraps are capped per principal
   (`1000/15m` by default), syncs read as `sync:<id>`, and the vault signs
   checkpoints of the app's audit log, which verification checks.
6. **The packages**: configuration in code, compiled output, the Node
   adapter, `coffre init`, and example deployments the smoke suite runs.

The instance files and deployment scripts are already gone. Step 6 replaces
the remaining environment-variable configuration with typed configuration in
each deployment project.

## Phase 3: erwinkn.com

The deployment lives in the erwinkn.com repository and imports coffre's
packages; this repository contains no instance-specific configuration.

- **Postgres:** any TLS Postgres that Hyperdrive can reach. The database holds
  ciphertext and the audit log, while values need the KEK, which lives in
  Cloudflare. A database leak therefore exposes names and who read what, but
  not values. That makes a public endpoint acceptable for a personal instance.
- **Sign-in:** coffre's own, with GitHub, rather than an Access application
  (phase 4 landed early). Machines get coffre service tokens.
- **Moving in:** `coffre import` from your existing `.env` files.
- **CLI:** run from a checkout until it is published as `@coffre/cli`.
  `coffre login` signs in with a device code.
- **Exit:** a few weeks of daily use with no open bugs, plus a rotation drill
  and a restore drill on the live instance.

### Sync

Built, as a server-side engine rather than the CLI-driven push first planned:
an environment is pushed to GitHub Actions, Vercel, Railway or Cloudflare
Workers on every change, and checked hourly for drift. See
[syncs.md](syncs.md).

- **Why the engine won.** A CLI push only happens when someone remembers to
  run it, and the point, as with Doppler, is that nobody has to. The cost the
  plan named is real: coffre now holds deploy tokens. They are ordinary
  secrets, named by path (`ops/sync/GITHUB_TOKEN`), so they get the same
  encryption, versioning, grants and audit as everything else, and adding a
  sync requires being able to read the token already.
- **Write-only targets** are handled as planned: coffre records which version
  it pushed where, so a run compares ids and decrypts only what changed.
- **Still open:** plain `.env` files as a target, and a declarative
  `coffre.sync.toml` if keeping syncs in the repository that deploys turns
  out to matter.

## Phase 4: sign-in

Built, on Workers. Where the build departed from the plan below: Microsoft
takes one tenant, by GUID, because the multi-tenant endpoints publish an
issuer template that standard validation rejects; the CLI signs in with a
device code rather than a local port, which also works over SSH; and the page
takes a title and a note but no logo yet. The plan, as written:

Behind Cloudflare Access, the login page is Access's own. GitHub, Google,
Microsoft, one-time email codes and any OIDC or SAML provider are login
methods toggled in the Cloudflare dashboard, and the page takes a logo,
colours and text. That covers both deployments above. Anywhere else, "first
put an identity-aware proxy in front" is where most people would give up on
self-hosting coffre. So coffre gets a sign-in page of its own: a second
identity mode beside the proxy one, producing the same principal.

A deployment lists the buttons its page shows:

```ts
identity: signIn({
  providers: [
    google({ clientId, clientSecret, domain: 'acme.example' }),
    github({ clientId, clientSecret }),
    microsoft({ tenant: 'organizations', clientId, clientSecret }),
    oidc({ label: 'Okta', issuer: 'https://acme.okta.com', clientId, clientSecret }),
  ],
  page: { title: 'Acme secrets', note: 'No access yet? Ask in #it.' },
})
```

- **One provider implementation, not one per vendor.** `oidc({ issuer })`
  reads everything else from the issuer's discovery document, so Okta, Entra,
  GitLab, Auth0, Keycloak, Authentik, Clerk and WorkOS take configuration and
  no code. It runs the authorization-code flow with PKCE on `oauth4webapi`,
  which has no dependencies and comes from the author of `jose`. Not
  better-auth: its security advisories cluster in exactly this flow, and it
  updates and deletes rows in tables of its own, where coffre's runtime role
  has no DELETE anywhere.
- **A preset is defaults plus at most one quirk.** `google` checks the `hd`
  claim when `domain` is set, so only that Workspace domain gets in.
  `microsoft` handles the multi-tenant endpoints, whose discovery document
  gives the issuer as a `{tenantid}` template rather than a URL.
- **GitHub is the one exception.** It speaks OAuth 2 but not OIDC: there is no
  ID token, and a private address is only visible through `GET /user/emails`.
  It gets a small implementation of its own, which a developer tool can
  justify.
- **Anything else goes through a broker.** For SAML, LDAP or Bitbucket, run
  Dex, Authentik or WorkOS, which speak those and present coffre with one OIDC
  issuer.
- **Accounts bind to a provider's user, never to an email.** The principal
  directory stays the allowlist. A first sign-in binds a registered email to
  the provider's stable user id (`sub`, or GitHub's numeric id), and only if
  the provider says the address is verified. Every later sign-in must match
  that binding, and a second provider can only be linked by its owner while
  signed in through the first. Example: Bob leaves Acme and IT deletes his
  Google account. His personal GitHub account still lists bob@acme.example as
  verified, because GitHub checked it once, when he added it. Matching on
  email would let him back in through the GitHub button.
- **Sessions are coffre's.** They are kept on the server and short-lived, and
  ending one sets `revoked_at` rather than deleting a row. Sign-in, refused
  sign-in and sign-out each write an audit row. Owning sessions also lets
  Reveal ask for a recent sign-in.
- **The CLI and machines don't depend on which providers are on.**
  `coffre login` opens the browser and receives the result on a local port.
  CI jobs and sync get tokens coffre issues itself: prefixed, stored hashed,
  expiring, one per service principal.
- **The page is configured, not replaced.** Title, logo, a note, and the order
  and labels of the buttons come from configuration, and the logo is inlined
  so the CSP stays strict. Swapping in components of your own would mean
  shipping source instead of a prebuilt bundle.
- **Not in v1: passwords and email links.** Both need a mail sender and an
  account-recovery path. Passkeys are a good later addition, as the recent
  sign-in that Reveal asks for.
- **Tests.** The dev IdP, today a stand-in for Cloudflare Access, also becomes
  an OIDC issuer, so the suite covers both modes without an account anywhere.
  Each preset gets a setup guide and a check against a real tenant before a
  release.
- **Offboarding: built, by hand.** Removing someone from coffre's directory
  ends their sessions, CLI logins, tokens and linked accounts at once, and
  lists the values they saw that still need rotating (see
  [offboarding.md](offboarding.md)). Still open: noticing removals at the
  identity provider by itself. Until then, someone removed there cannot sign
  in again, but keeps an open session until it expires. Entra and Okta can
  push removals over SCIM; Google Workspace would need its directory polled.

## Later

- Add a KMS-backed `KekProvider`, for example Scaleway or AWS KMS, make it the
  primary provider, then rewrap existing DEKs under it.
- Write a retention policy that defines the only sanctioned way to destroy
  data.
- Import from other secret managers such as Infisical, after settling how
  nested folders map to coffre's flat `project/environment/key` model.
- Add an external-secrets `webhook` provider for Kubernetes workloads.
- Commission an external review of the cryptography and authentication
  boundary.

## Open decisions

1. ~~**Where it is published, and under what license.**~~ Decided: publicly,
   at [erwinkn/coffre](https://github.com/erwinkn/coffre), under MIT. On npm,
   `coffre` is taken; the `@coffre` scope looks free but that is unconfirmed.
2. **Postgres for erwinkn.com:** whichever host already runs your stack, given
   the ciphertext argument above.
3. ~~**Sync model.**~~ Decided: a server-side engine (see phase 3).

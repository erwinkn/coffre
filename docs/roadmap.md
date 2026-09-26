# Roadmap

From demo software that deploys to one Cloudflare account, to a packaged
product that runs first on erwinkn.com and then inside Equisafe.

## Where we are

- The product works end to end: API, CLI, web UI, audit chain, and now
  coffre's own sign-in (phase 5), syncs (phase 3) and offboarding.
- Product and instance are apart. `apps/web/wrangler.jsonc` describes coffre,
  and a file in `deploy/` says where one copy runs and how people sign in,
  named by `COFFRE_INSTANCE` at build time. That is the "deployment is a
  config file" half of phase 2, without the npm packages or the Node adapter.
- erwinkn.com is ready to deploy: [deploy.md](deploy.md) walks through it, and
  `deploy/erwinkn.jsonc` needs two values filled in.
- Equisafe's pipeline (`deploy-worker.yml`, a private migration runner, the
  `coffre-production` and `coffre-migrations` GitHub environments) has never
  run.
- Most of phase 1 is still open. The README says *ready for a first
  deployment, still hardening* until it is done.

## Sequence

| Phase | Goal | Done when |
|---|---|---|
| 1. Harden | Safe to hold real secrets | Every item below shipped; restore and rotation drills pass |
| 2. Package | The product apart from its instances; Cloudflare and Node adapters | A deployment is a config file depending on `@coffre/cloudflare`; the smoke suite passes on both adapters |
| 3. erwinkn.com | Dogfood | Your secrets live in it, the CLI and sync are in daily use, a few weeks pass with no open bugs |
| 4. Equisafe | Internal rollout | KMS-backed KEK, two-person review, Infisical migrated |
| 5. Sign-in | Deployable without a proxy in front | A Node deployment signs in with Google, GitHub and an arbitrary OIDC issuer, and the CLI logs in through it |

Hardening comes first because it is mostly independent of the package layout,
and it is what the README's status line is waiting on. Packaging comes before
erwinkn.com so your instance is deployed the way every other one will be, and
Equisafe's becomes the second consumer of the packages rather than a migration
off a fork. Sign-in comes last because both deployments sit behind Cloudflare
Access, which already offers the login methods they want; it is what a public
release needs, so it moves ahead of phase 4 if publishing comes first.

## Phase 1: harden

Each item says what is wrong today.

1. **Security headers and a CSP.** No response sets any today. In a secrets
   manager an XSS is a full read of whatever the victim can see, audited in
   their name. Add a `Content-Security-Policy` (a nonce or hash for our two
   boot scripts and for the scripts TanStack emits for hydration, and
   `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: no-referrer`, and HSTS. Spike first: nonce support in
   Start 1.168.
2. **Escrow the keys, then prove recovery.** `COFFRE_KEK_LOCAL` and
   `COFFRE_AUDIT_CHAIN_KEY` are Worker secrets and GitHub environment secrets,
   and both stores are write-only. If no other copy exists, losing the Worker
   loses every secret. Keep an offline copy, then run a restore drill: a fresh
   database from backup plus the escrowed KEK, then `coffre verify` passes
   and a canary secret decrypts.
3. **Rotation that can retire a key.** Rotation today only changes which KEK
   wraps *new* versions. Every old version still needs the old KEK forever, so
   a leaked KEK cannot be retired. Add a `rewrap` maintenance command: it
   re-wraps each DEK under the primary, leaves the ciphertext untouched, and
   writes one audit row per secret. The `coffre-maintenance` GitHub
   environment already exists and nothing uses it yet; this is its job.
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
7. **Guard main.** `main` is unprotected and nothing runs on pull requests. A
   deploy accepts anything that reached `main` and passes the tests, so nothing
   reviews what gets there. Add a PR workflow that reuses the deploy's validate
   job, and make both a PR and that workflow required.
8. ~~**Machine callers in the CLI.**~~ Done: `COFFRE_TOKEN` for coffre's own
   service tokens, `COFFRE_ACCESS_CLIENT_ID` and `COFFRE_ACCESS_CLIENT_SECRET`
   behind Access.

Then drop "still hardening" from the README's status line.

## Phase 2: package

### Layout

```
packages/core        @coffre/core        envelope, KEK providers, audit chain, identity   (exists)
packages/db          @coffre/db          schema, migrations, a coffre-migrate bin         (exists)
packages/server      @coffre/server      services, auth boundary, /api, the built UI      (today's apps/web)
packages/cloudflare  @coffre/cloudflare  Worker entry, Cron handler, wrangler template
packages/node        @coffre/node        coffre-server bin, Dockerfile
packages/cli         @coffre/cli         the coffre bin
apps/dev-idp                              local tooling, never published
```

### The seam

Everything platform-specific already enters at one place, `createRuntime` in
`apps/web/src/server/runtime.ts`. The work is to make that the public API:

```ts
const coffre = createCoffre({
  database,       // pg-shaped: a Hyperdrive client per request on Workers, a pg.Pool on Node
  identity,       // how a request proves who it is (see below)
  keks,           // a KekRegistry: local keys today, a KMS later
  auditChainKey,
  rootAdmins,
});

coffre.fetch(request); // the whole app: UI, server functions, /api
coffre.heartbeat();    // Cron calls it on Workers, a timer on Node
```

The adapters are then small:

- **Cloudflare** maps bindings to options on each invocation, as it does today.
- **Node** builds the options once from the environment, serves the static
  assets, runs the heartbeat timer, and shuts down gracefully.

### A deployment becomes a config file

```jsonc
// wrangler.jsonc in your infra repository, not this one
{
  "name": "coffre",
  "main": "node_modules/@coffre/cloudflare/dist/worker.js",
  "assets": { "directory": "node_modules/@coffre/cloudflare/dist/client" },
  "routes": [{ "pattern": "coffre.erwinkn.com", "custom_domain": true }],
  "hyperdrive": [{ "binding": "HYPERDRIVE", "id": "…" }],
  "triggers": { "crons": ["*/5 * * * *"] }
}
```

### What changes on the way

- **Imports go through package names.** Today `apps/web` reaches into
  `../../../../packages/core/src/…`.
- **Ship JavaScript, not TypeScript.** Everything runs `.ts` directly through
  Node 24's type stripping, which Node refuses to do inside `node_modules`: a
  published CLI would crash on its first import. Compile with `tsc`, emitting
  declarations as well. The CLI also needs a `package.json`; it has none.
- **Identity becomes pluggable.** Cloudflare Access becomes one preset of a
  general trusted-proxy JWT verifier, configured by header, issuer, JWKS,
  audience, and which claims name users and machines. The same verifier covers
  Pomerium, oauth2-proxy and Google IAP, which makes the Node adapter usable
  before coffre has a sign-in of its own (phase 5). Later, GitHub Actions OIDC could be a machine identity so CI needs no stored
  credential. Behind Cloudflare Access it would need an API hostname that
  bypasses Access, which weakens the outer wall, so it fits Node deployments
  better.
- **Dev mode is compiled out of published builds**, the way the Agentation
  toolbar is today, so no configuration of a packaged coffre can switch on
  persona minting.
- **The Node adapter rate-limits.** On Cloudflare only Access-authenticated
  callers reach the origin. On Node, the adapter is the edge.
- **The smoke suite runs against both adapters.** A second adapter is what
  proves the core does not quietly lean on Workers, which is why Node lands in
  this phase rather than later.

Two spikes go first:

- Ship TanStack Start's Cloudflare build prebuilt, and deploy it with a
  consumer's own wrangler config.
- Try Start's Node server output.

## Phase 3: erwinkn.com

- **Postgres:** any TLS Postgres that Hyperdrive can reach. The database holds
  ciphertext and the audit log, while values need the KEK, which lives in
  Cloudflare. A database leak therefore exposes names and who read what, but
  not values. That makes a public endpoint acceptable for a personal instance.
- **Sign-in:** coffre's own, with GitHub, rather than an Access application
  (phase 5 landed first). Machines get coffre service tokens.
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

## Phase 4: Equisafe

- **Take the KEK out of Terraform state.** `docs/deployment-workers.md` copies
  the KEK from Terraform's `worker_runtime_environment` output, which makes the
  state bucket as sensitive as the vault. Implement the Scaleway KMS
  `KekProvider` the README anticipates, make it primary, and run `rewrap`.
- **Google Workspace as the only login method**, required by the Access
  policy. coffre recognises Access users by their email, so leaving GitHub
  enabled as well would let a leaver back in through a personal GitHub account
  that still lists their work address (the example in phase 5).
- **Two-person rule:** required review on `main`, and required reviewers on
  the `coffre-production` environment.
- **A written retention policy** (Art. 12(2)(a)), as the only sanctioned way
  data is ever destroyed.
- **Infisical migration:** first settle the README's open question (nested
  folders against flat `project/environment/key`), then write an importer.
- **The external-secrets `webhook` provider,** if Equisafe's Kubernetes
  workloads need it.
- **An external review** of the crypto and the auth boundary before coffre
  holds company credentials.

## Phase 5: sign-in

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
    google({ clientId, clientSecret, domain: 'equisafe.io' }),
    github({ clientId, clientSecret }),
    microsoft({ tenant: 'organizations', clientId, clientSecret }),
    oidc({ label: 'Okta', issuer: 'https://equisafe.okta.com', clientId, clientSecret }),
  ],
  page: { title: 'Equisafe secrets', note: 'No access yet? Ask in #it.' },
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
  signed in through the first. Example: Bob leaves Equisafe and IT deletes his
  Google account. His personal GitHub account still lists bob@equisafe.io as
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

## Open decisions

1. **Where it is published, and under what license.** The repository is
   private under the `equisafe` organisation, so publishing it publicly means
   open-sourcing Equisafe's code. On npm, `coffre` is taken; the `@coffre`
   scope looks free but that is unconfirmed. For the license I'd recommend
   Apache-2.0.
2. **Postgres for erwinkn.com:** whichever host already runs your stack, given
   the ciphertext argument above.
3. ~~**Sync model.**~~ Decided: a server-side engine (see phase 3).

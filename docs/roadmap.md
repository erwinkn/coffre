# Roadmap

From demo software that deploys to one Cloudflare account, to a packaged
product that runs first on erwinkn.com and then inside Equisafe.

## Where we are

- The product works end to end locally: API, CLI, audit chain, and the web UI
  (landed in #8). 228 tests pass.
- The README still says *demo software, do not store real secrets*, and that
  is still true: the gaps are listed under phase 1.
- A production pipeline exists for Equisafe (`deploy-worker.yml`, a private
  migration runner, the `coffre-production` and `coffre-migrations` GitHub
  environments). It has never run.
- Product and instance are one thing. `apps/web/wrangler.jsonc` names the
  Worker `equisafe-coffre` and routes it to `coffre.equisafe.dev`, so a second
  deployment today means forking the configuration.

## Sequence

| Phase | Goal | Done when |
|---|---|---|
| 1. Harden | Safe to hold real secrets | Every item below shipped; restore and rotation drills pass |
| 2. Package | The product apart from its instances; Cloudflare and Node adapters | A deployment is a config file depending on `@coffre/cloudflare`; the smoke suite passes on both adapters |
| 3. erwinkn.com | Dogfood | Your secrets live in it, the CLI and sync are in daily use, a few weeks pass with no open bugs |
| 4. Equisafe | Internal rollout | KMS-backed KEK, two-person review, Infisical migrated |

Hardening comes first because it is mostly independent of the package layout,
and it is what the README's status line is waiting on. Packaging comes before
erwinkn.com so your instance is deployed the way every other one will be, and
Equisafe's becomes the second consumer of the packages rather than a migration
off a fork.

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
4. **A heartbeat someone hears.** There are two problems:
   - The readiness threshold (`age > 300` in `server/heartbeat.ts`) equals the
     Cron interval (`*/5`). So `/readyz` returns 503 for a few seconds whenever
     Cron fires late, and a monitor would flap.
   - Nothing monitors it.

   Allow two missed beats (about 11 minutes) and attach an external check that
   pages you.
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
8. **Machine callers in the CLI.** The CLI can only send a human's
   `cloudflared` token. CI jobs and sync need Access service tokens
   (`CF-Access-Client-Id` and `CF-Access-Client-Secret`).

Then flip the README's status line.

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
  Pomerium, oauth2-proxy and Google IAP. That is what makes the Node adapter
  useful without coffre growing a login of its own; I recommend none for v1.
  Later, GitHub Actions OIDC could be a machine identity so CI needs no stored
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
- **Access:** one application for `coffre.erwinkn.com`, and one service token
  per machine that reads from it.
- **Moving in:** `coffre import` from your existing `.env` files.
- **CLI:** installed with `npm i -g @coffre/cli`. `coffre login` wraps
  `cloudflared` instead of asking you to export a token by hand.
- **Exit:** a few weeks of daily use with no open bugs, plus a rotation drill
  and a restore drill on the live instance.

### Sync

Start with a push driven by the CLI from a declarative file, before any
server-side engine:

```toml
# coffre.sync.toml, in the repository that owns the deployment
[[sync]]
from = "blog/prod"
to   = "cloudflare-worker:blog-api"

[[sync]]
from = "infra/prod"
to   = "railway:infra/production"
keys = ["DATABASE_URL", "REDIS_URL"]
```

`coffre sync --plan` shows what would change, and `coffre sync` pushes it.

- **Target credentials** stay with whoever runs the sync (your laptop, a CI
  job) and never enter coffre.
- **Audit already fits.** A sync is a read by the syncing principal: one row
  per secret, sharing a bundle id, with the target in the metadata.
- **Write-only targets.** Workers secrets and GitHub Actions secrets cannot be
  read back, so the plan cannot diff their values. Instead, coffre records
  which version it pushed where, so the plan can say `DATABASE_URL v3 → v4`.
- **Targets, in order:**
  1. Cloudflare Workers secrets.
  2. Railway variables.
  3. GitHub Actions secrets. These need libsodium sealed boxes: either a
     dependency, or shelling out to `gh`.
  4. Plain `.env` files.
- **A server-side engine** (pushing on every write) would hold deploy tokens
  for every service. It is only worth it if drift becomes the pain.

## Phase 4: Equisafe

- **Take the KEK out of Terraform state.** `docs/deployment-workers.md` copies
  the KEK from Terraform's `worker_runtime_environment` output, which makes the
  state bucket as sensitive as the vault. Implement the Scaleway KMS
  `KekProvider` the README anticipates, make it primary, and run `rewrap`.
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

## Open decisions

1. **Where it is published, and under what license.** The repository is
   private under the `equisafe` organisation, so publishing it publicly means
   open-sourcing Equisafe's code. On npm, `coffre` is taken; the `@coffre`
   scope looks free but that is unconfirmed. For the license I'd recommend
   Apache-2.0.
2. **Postgres for erwinkn.com:** whichever host already runs your stack, given
   the ciphertext argument above.
3. **Identity outside Cloudflare:** a trusted-proxy JWT (recommended) or a
   built-in OIDC login.
4. **Sync model:** a CLI push first (recommended), or a server-side engine.

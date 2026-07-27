# coffre

A deliberately small in-house secrets manager. Cloudflare Access is the identity
provider, Postgres is the backend of record, and the audit log is the point.

**Status: local prototype. Nothing is deployed. No Scaleway or Cloudflare calls.**

## Why this exists

We self-host Infisical. Unlicensed self-hosted Infisical writes **no audit logs
at all** — verified in source, not inferred:

- `backend/src/ee/services/license/license-fns.ts`, `getDefaultOnPremFeatures()`
  returns `auditLogs: false`, `auditLogsRetentionDays: 0`
- `backend/src/ee/services/audit-log/audit-log-queue.ts:107`
  `if (!plan?.auditLogsRetentionDays) return null;`

Every audit entry is dropped. Silently: no error, no warning, no metric. That
failure mode — a logging system that stops logging without telling anyone — is
the thing this project is built to not repeat.

The driver is DORA. CDR (EU) 2024/1774 Article 12 is the relevant text. Note
what it actually says: **you** identify the events to be logged (12(2)(a)). It
does not mandate per-value read logging. "Who read which secret, when" is a
control we are choosing, which is a stronger position than pretending a
regulator demands it.

### What we are not claiming

Infisical's audit logging being paywalled is a fact about Infisical, not about
the market. **OpenBao ships request/response audit logging in its open-source
core**, unlicensed. The honest justification for building rather than adopting
is that we want a secrets service small enough to read end to end, with
Cloudflare Access as the only identity system. Not "nothing else does this."

## The finding that changed the design

The original design assumed Scaleway Key Manager would give us an independent
audit trail that the application could not disable. **It does not.**

Scaleway Audit Trail logs exactly ten Key Manager endpoints, all management
plane: `CreateKey`, `UpdateKey`, `DeleteKey`, `ProtectKey`, `UnprotectKey`,
`RotateKey`, `DisableKey`, `EnableKey`, `ImportKeyMaterial`,
`DeleteKeyMaterial`. There is no `Decrypt`, no `Encrypt`, no `GenerateDataKey`.

Source: `scaleway/docs-content`,
`macros/audit-trail/key-manager-endpoints.mdx` (doc validated 2026-06-12).

The same page confirms Secret Manager logs no value access either — no
`AccessSecretVersion`. Our sync target is therefore a genuine un-audited read
path and needs tight IAM plus a written exception.

Consequences:

1. Tamper-evidence has to come from our own log. Hence the hash chain in
   `packages/core/src/audit/chain.ts`.
2. `KekProvider.wrap/unwrap` takes the secret context as a parameter, so a
   future KEK service *we* run (a Cloudflare Worker was discussed) can log
   which secret an unwrap was for. Retrofitting that would mean re-encrypting
   everything.
3. The eventual shape is likely double-wrap: Scaleway KMS for HSM-grade key
   protection, plus a Worker as a second layer whose log lives in a different
   trust domain. Cross-checking unwrap counts against our own audit log is a
   ready-made Article 12(2)(e) logging-failure detector.

## Design decisions worth knowing

**AAD binds to UUIDs, never names.** A ciphertext is bound to
`project_id/environment_id/secret_id`. Binding to `project/environment/key`
names — as originally sketched — would make renaming an environment orphan
every ciphertext in it.

**Two independent AAD layers.** The envelope binds context, and the KEK wrap
binds context *and* KEK identity. Either alone stops a cross-environment
relocation. `packages/core/test/envelope-aad-isolation.test.ts` exists because
the obvious test passes at the wrap layer and would not notice the envelope
layer regressing.

**The audit write is in-transaction and fail-closed.** Not a queue. If the
audit row cannot be written, the read does not happen.

**`seq` comes from a locked head row, not a bigserial.** A rolled-back
transaction burns a sequence value, and the resulting gap is indistinguishable
from a deleted row. Gaps must mean tampering.

**One audit row per secret, sharing a `bundle_id`.** A bulk fetch that writes a
single row degrades the answer to "they read the whole environment", which is
true and useless.

**Principals are a tagged union.** Cloudflare Access service tokens carry
`common_name` with an empty `sub` and **no `email` claim**. Code that reads
`claims.email` gets `undefined` for every machine caller. Machine callers
(external-secrets, CI) are most of the real traffic.

**The auth boundary is in Fastify, not Next.js middleware.** CVE-2025-29927 was
an authorization bypass in exactly that position via `x-middleware-subrequest`.
The admin UI calls this API and never reads the database — a UI querying
Postgres directly would read secrets without writing an audit row.

**Append-only by grant, not convention.** `coffre_app` has no `UPDATE`, no
`DELETE`, no `TRUNCATE` on `audit_log`. Proven in
`packages/db/test/schema-guarantees.sql`, which runs as that role and asserts
each of those fails.

## Supply chain

`ignore-scripts`, exact pins, and a 7-day minimum release age.

Two traps found the hard way, both documented in `pnpm-workspace.yaml`:

- **pnpm 11 reads only auth and registry settings from `.npmrc`.** Everything
  else there is silently ignored. Our hardening was doing nothing until it was
  moved to `pnpm-workspace.yaml` (camelCase keys).
- **`savePrefix: ''` is read but not applied by `pnpm add`.** It still writes
  caret ranges. `scripts/check-pins.mjs` enforces the invariant instead, because
  a control that silently does nothing is worse than no control.

`minimumReleaseAge` earned its place immediately: it blocked `jose@6.2.4`,
published six days before we tried to install it.

## Layout

```
packages/core   envelope encryption, KEK providers, audit hash chain, identity
packages/db     migrations, fail-closed audit writer, schema guarantee tests
apps/api        Fastify: the authentication boundary and the read/write API
apps/dev-idp    local stand-in for Cloudflare Access (serves JWKS, mints tokens)
apps/cli        login / list / get / set / run / audit / verify
apps/admin      Next.js admin UI (calls the API; never touches Postgres)
```

## Running it

```sh
pnpm install
pnpm dev              # Postgres + dev IdP + API + UI + seed data, all local
```

Then open http://127.0.0.1:3000 and sign in as `erwin@equisafe.io`.

Individual pieces:

```sh
pnpm db:up            # Postgres on :55432
pnpm db:migrate
pnpm seed
pnpm test             # 61 tests, unit + integration (needs Postgres up)
pnpm test:schema      # append-only guarantees, run as coffre_app
pnpm check:pins       # every dependency exactly pinned
```

CLI:

```sh
node apps/cli/src/main.ts login --email erwin@equisafe.io
node apps/cli/src/main.ts list market/dev
node apps/cli/src/main.ts run  market/dev -- printenv
node apps/cli/src/main.ts audit --denied
node apps/cli/src/main.ts verify
```

## Progress

All five phases are implemented and working locally.

- **M0.** Schema and migrations, envelope, local `KekProvider`, KEK registry
  with rotation, audit hash chain. Includes the cross-environment AAD test.
- **M1.** JWKS verification and the auth boundary, adversarial tests written
  first: forged signature, wrong `aud`, expired, not-yet-valid, wrong issuer,
  `alg=none`, RS256→HS256 confusion, missing header, proxy bypass,
  identity-less token. Plus the fail-closed chained audit writer.
- **M2.** Read/write API, bulk fetch, one audit row per secret on every read
  and an audit row on every denial. End-to-end test that a ciphertext relocated
  across environments in the database fails to decrypt.
- **M3.** CLI: `login`, `list`, `get`, `set`, `run -- <cmd>`, `audit`, `verify`.
  Zero dependencies.
- **M4.** Admin UI: browse projects and environments, reveal (audited), create
  and edit secrets, read the audit log, and verify chain integrity.

- **Management.** Projects, environments, secrets and grants are created,
  renamed and archived through the UI and the API. Every structural change is
  audited.

### There is no delete, and that is deliberate

`audit_log` holds `ON DELETE RESTRICT` references to projects, environments and
secrets, so anything that has ever been read or written cannot be removed:

```
ERROR: update or delete on table "secrets" violates foreign key constraint
       "audit_log_secret_id_fkey" on table "audit_log"
```

Letting a delete cascade would destroy the evidence this service exists to keep.
So "delete" is **archive** — for projects, environments and individual secrets
alike: hidden from listings, reads refused, every row still present and the
audit trail still valid. Archiving is reversible and the values survive intact.

Archiving a secret matters operationally, not just tidily: a rotated-out
credential stops being injected by `coffre run`.

Actually destroying data belongs to a retention policy under Art 12(2)(a) —
a decision to be written down and applied deliberately, not a button in an
admin UI.

### Authorisation: roles and permissions

Permissions are a **fixed catalogue**, not a policy language. Roles are named
bundles of them.

| Permission | Scope |
|---|---|
| `secret.read` | project or environment |
| `secret.write` | project or environment |
| `secret.archive` | project or environment |
| `audit.read` | project or environment |
| `environment.manage` | project only |
| `grant.manage` | project only |
| `project.manage` | project only |

Built-in roles:

| Role | Permissions | Can read secrets? |
|---|---|---|
| `viewer` | `secret.read` | yes |
| `developer` | `secret.read`, `secret.write` | yes |
| `maintainer` | + `secret.archive`, `environment.manage` | yes |
| `access-manager` | `grant.manage` | **no** |
| `auditor` | `audit.read` | **no** |
| `owner` | everything | yes |

The last two are why roles exist at all. Under the previous `read < write <
admin` ladder, seeing the audit log required `admin`, which also meant reading
every secret — so appointing someone to answer "who read which secret" meant
handing them the whole vault. `auditor` and `access-manager` both deliberately
omit `secret.read`.

**Scope.** A grant targets a project or exactly one environment; the schema
enforces `(project_id IS NULL) <> (environment_id IS NULL)`. A project grant
applies to every environment in it, and effective permissions are the *union*
of project- and environment-scoped grants.

Environment permissions are inherently project-specific: `environments.project_id`
is `NOT NULL`, so an environment belongs to exactly one project, and grants are
always resolved by `(project_id, slug)`.

A role carrying project-only permissions **cannot** be scoped to one
environment — `environment.manage` on a single environment would authorise
creating its own siblings. The API rejects it with 409 rather than silently
granting less than asked.

Grants may carry an `expires_at`. Expiry is enforced in permission resolution,
which is the single place every check goes through.

Principals are `user` (matched on the Access `email` claim) or `service`
(matched on `common_name`, because service-token JWTs carry no email at all).

### Things that are stubbed, not finished

- `SyncTarget` (push to Scaleway Secret Manager) is designed but not
  implemented — it is a non-goal for this phase.
- The `scaleway` `KekProvider` does not exist yet; only `local` does.
- Rollback is free in the data model (versions are append-only with a current
  pointer) but no endpoint exposes it yet.
- Audit checkpoints have a table but nothing exports them off-box, so tail
  truncation is currently detectable only in principle.
- The UI has no automated tests. The API logic behind every screen is covered,
  but the React layer is verified by hand.

### Why `--test-concurrency=1`

The integration tests share one Postgres database and reset it in `beforeEach`.
Run in parallel they clobber each other. Serialising is the pragmatic fix for a
prototype; the real fix is a schema (or database) per test file.

## Deliberately out of scope

No deployment, no Terraform, no real KMS. No rotation engine, no dynamic
secrets, no PKI, no policy DSL (a grants table is enough), no HA. No Kubernetes
operator — external-secrets has a generic `webhook` provider that can call this
API later.

## Open question

If our Infisical data uses nested folders/paths, the flat
`project/environment/key` model will hurt on migration. Worth checking before
the schema is treated as settled.

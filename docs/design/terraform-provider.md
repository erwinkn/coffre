# A write-only Terraform provider

Written on 2026-11-03, for 0.16, from task T108 and Erwin's go for it
that day. It decides the shape of `coffre_secret`, a Terraform resource that sends a value
Terraform made straight into coffre, and whose value never lands in
Terraform's state or plans.

## 1. What it is for

Terraform makes credentials: a Scaleway API key for the nightly backup's
bucket, a database user's password, a webhook's signing secret. Today
Terraform copies each one into the place that needs it, a GitHub environment secret or
a Kubernetes secret, so that place and Terraform's state both hold the value.
With coffre, the job that needs the key does not need its value at all: it calls the provider
through coffre's proxy (`https://<instance>/use/<credential>`), and coffre
fills the key in. What is missing is the step that puts the value into
coffre, without a person copying it by hand.

```hcl
resource "scaleway_iam_api_key" "backup" {
  application_id = scaleway_iam_application.backup.id
  secret_id      = scaleway_secret.backup_key.id # secret_key goes to Secret Manager, not state
}

ephemeral "scaleway_secret_version" "backup_key" {
  secret_id  = scaleway_secret.backup_key.id   # revision defaults to "latest"
  depends_on = [scaleway_iam_api_key.backup]
}

resource "coffre_secret" "backup_key" {
  project     = "infra"
  environment = "prod"
  key         = "SCW_BACKUP_SECRET_KEY"
  sensitivity = "sensitive"

  value_wo         = base64decode(ephemeral.scaleway_secret_version.backup_key.data)
  value_wo_version = scaleway_iam_api_key.backup.id # a new key, a new version
}
```

`terraform apply` writes the key into `infra/prod` as a new version. The
plan shows `value_wo` as `(write-only attribute)`, and the state stores
`null` for it. The backup job then signs in as its own service account and
calls `/use/scaleway-backup`. It never holds the key, and neither does any
GitHub secret.

**What it is not.** No data source and no ephemeral resource that returns
values: a value read through Terraform lands in its plan or state, or in the
hands of everyone who can run a plan, and coffre's own readers (`coffre
run`, `export`, the Action, the proxy) already cover reading. No management
of projects, environments, members, grants or proxy definitions: those stay
in coffre's pages, CLI and deployment config, where their own rules apply
(protected environments, the Owner-only role editor, R65). The README's "No
Terraform" (Not in scope) becomes "no Terraform beyond this one resource"
when the provider ships.

**Versions.** Write-only arguments need Terraform 1.11 or OpenTofu 1.11, and
ephemeral resources need Terraform 1.10 or OpenTofu 1.11. The provider
declares the write-only attribute, so an older Terraform refuses the
configuration instead of storing the value.

## 2. The resource

| Argument | Kind | Meaning |
|---|---|---|
| `project` | required, replaces on change | The project's name |
| `environment` | required, replaces on change | The environment's name, a fork's included |
| `key` | required, replaces on change | The key name, `^[A-Za-z_][A-Za-z0-9_]{0,127}$` as coffre checks |
| `sensitivity` | required | `plain`, `secret` or `sensitive`, coffre's nature for the key (R16) |
| `value_wo` | required, write-only, sensitive | The value. Never stored, never shown |
| `value_wo_version` | required, string | Any string. When it changes, the next apply writes `value_wo` as a new version |
| `on_destroy` | optional, default `keep` | `keep` or `archive`: what destroying the resource does in coffre (section 6) |
| `version` | computed | The version number coffre gave the value Terraform last wrote |

The resource's ID is `infra/prod/SCW_BACKUP_SECRET_KEY`, which `terraform
import` takes as well.

**`sensitivity` is required.** coffre's own default is `secret`, and most
credentials Terraform makes are for services, which `sensitive` suits
(no person sees them, Owners included). A default either way surprises
someone. A required argument makes every configuration say which nature it wants,
in one line that reviewers read in the plan.

**No `value` beside `value_wo`.** A plain value in Terraform belongs to the
app's own config (R38), and a second way to pass a value would invite the
one that lands in state. `sensitivity = "plain"` still works for a key that
must live in coffre beside its pair (a client ID with its secret).

**No `folder`, `comment` or reference.** Folders are cosmetic and set in the
pages. Coffre has no comment field. A reference (one key pointing at
another's value) is made by an Owner with read access to its source (R24),
which a write-only principal never has.

## 3. Signing in

The provider takes one of three credentials, all coffre's existing ones. It
never uses a person's session, and adds no credential kind or endpoint.

```hcl
# 1. GitHub Actions, by OIDC: nothing stored. The job has `permissions: id-token: write`.
provider "coffre" {
  url     = "https://secrets.acme.example"
  service = "terraform-infra"
}

# 2. Any other OIDC issuer (GitLab, a custom one): its ID token, from an ephemeral variable.
provider "coffre" {
  url      = "https://secrets.acme.example"
  service  = "terraform-infra"
  id_token = var.coffre_id_token # variable "coffre_id_token" { ephemeral = true }
}

# 3. A bearer token: a service token for CI without OIDC, or a person's token for an apply run by hand.
provider "coffre" {
  url   = "https://secrets.acme.example"
  token = var.coffre_token # variable "coffre_token" { ephemeral = true, sensitive = true }
}
```

**OIDC first, as for the Action.** A GitHub run asks the runner for an ID
token for the instance's URL (`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`,
the platform's variables, as the CLI does in `packages/cli/src/workload.ts`)
and trades it at `POST /api/auth/oidc` for a five-minute `coffre_svc_`
credential. A trust binding on the service account decides which workflow,
branch and GitHub environment may do this ([ci.md](../ci.md#without-a-stored-token)).
An apply can run longer than five minutes. The provider then fetches a
fresh ID token and trades it again, at most once per credential, when coffre
answers 401 on an expired one. With `id_token`, there is no second token
to fetch, and an ID token is spent once: such an apply has five minutes,
and a job that runs `terraform plan` and `terraform apply` as two commands
declares two ID tokens, one for each (GitLab's `id_tokens:` takes several).

**A bearer token** is `coffre_svc_…` (a service token, 1 to 366 days) or
`coffre_pat_…` (a person's token, at most 7 days, scope required). A
person's token acts as that person within its scope, and never counts as an
Owner. It suits an apply run from a laptop. The provider
sends it as `Authorization: Bearer`, as the CLI does.

**Exactly one** of `service` alone, `service` with `id_token`, or `token`.
Anything else is a configuration error at `terraform validate`, never a
guess at runtime.

**The provider reads no environment variable of its own.** Coffre's packages
and CLI read none (AGENTS.md, "Config is code"), and the provider keeps that
rule: no `COFFRE_TOKEN`. A token reaches it through an ephemeral variable,
which Terraform fills from `TF_VAR_coffre_token` when the CI sets one, so
the CI still keeps it in one environment variable, under a name Terraform
already knows. The platform's own variables (GitHub's) are read, as the CLI
reads them.

**What it holds, and nothing more.** The credential is scoped when it is
made, as every coffre credential is: the binding or token names its places,
`--scope infra/prod=contributor`, and a request holds what both the scope
and the service account hold at that moment ([personal-tokens.md](personal-tokens.md#what-it-holds)).
Giving the account more later never widens the credential. An instance
configured `workloads: { useOnly: true }` refuses `coffre_svc_` credentials
and the OIDC exchange, so the provider works there only with a person's
token.

### Calls it makes

| When | Call | Right needed |
|---|---|---|
| Sign in (OIDC) | `POST /api/auth/oidc` `{ service, token }` | a binding that matches |
| Refresh, and before each create or update | `GET /api/secrets/:project/:environment` | `secret.use` or `secret.read` |
| Create, update | `PATCH /api/secrets/:project/:environment` `{ KEY: { value, sensitivity, replaces? } }` | `secret.write` |
| Destroy with `on_destroy = "archive"` | `PATCH /api/secrets/:project/:environment/:key` `{ archived: true }` | `secret.archive` |

No new server endpoint. None of these returns a secret value. The list
returns the values of `plain` keys, which anyone who can list the
environment sees already: the provider drops them and never stores them.
From the list it keeps, for its key, `version`, `versionId`, `updatedBy`,
`sensitivity`, `archived` and `reference`. The dry run (`?dryRun=1`), which
would say whether a value changed, is not used: it decrypts the stored
value to compare and needs `secret.read` (section 5).

## 4. What a Terraform principal may write

**Coffre grants per environment, not per key.** Grants, token scopes and
binding scopes name a project or a project's environment
(`packages/server/src/api/access.ts`, `parsePath(raw, [1, 2])`), and key
names have no `/` in them. So `ci/*` or `backend/<env>` cannot be a key
pattern. They become places: Terraform writes environments of its own.

**One service account per Terraform stack, `contributor` on its places, nothing else.**

```sh
coffre admit terraform-infra --service --grant infra/prod=contributor
coffre trust terraform-infra --github acme/infra --workflow apply.yml --branch main \
  --github-environment production --scope infra/prod=contributor --apply
```

`contributor` is `secret.use` and `secret.write`: it writes values and
never reads one back, which is exactly what a write-only provider needs.
It has no `secret.archive`, so the credential cannot archive a key, even
with `on_destroy = "archive"` (section 6). It has `secret.use`, which lets
the provider list key names and versions, and which also lets the
principal use, through the proxy, every key in the places it writes.

**So Terraform's places hold only what Terraform writes.** Picture a
`contributor` on `market/prod`: it could overwrite Stripe's key with one it
knows, and use the other keys through the proxy. On `infra/prod` (or
`terraform/prod`, any name), which holds only credentials Terraform made,
the same rights reach only keys whose values Terraform's pipeline already
has. Using or overwriting those adds nothing: whoever runs the pipeline
already holds those values. An app that needs one of these keys in its own environment gets a
reference to it, made once by an Owner who can read the source (R24): the
reference takes its value and nature from `infra/prod`, so Terraform's next
version reaches the app with no copy.

| Principal | Grant | Can | Cannot |
|---|---|---|---|
| `service:terraform-infra` | `contributor` on `infra/prod` | write and use `infra/prod`'s keys, list their names | read any value, archive, touch `market/*` |
| `service:backup` | `viewer` on `infra/prod`, signed in as a workload, whose session is use-only ([workloads.md](../workloads.md)) | use `SCW_BACKUP_SECRET_KEY` through the proxy | read it, write it |
| Ada, Owner of `infra` | `owner` | everything, for `secret` keys; for `sensitive`, use only | see a sensitive value (R16) |

**Writing `sensitive` takes writing alone.** Typing a value at any nature,
and making a key stricter, need only `secret.write` ([roles.md](roles.md#8-rules-that-hold-the-policy)):
what is written is what the writer has seen. Making a key looser, sensitive
to secret, writes the value again, which `value_wo` provides at every
apply. The provider never asks coffre to loosen a value in place: that is
an Owner's act (R30), which no service credential can perform.

**Rejected: key-prefix grants.** A credential scoped to some keys of an
environment would let Terraform share `market/prod` with people. It is a new
dimension in `@coffre/core/access`, in the vault's decision, and in the Lean
and TLA+ models, built for one client whose need an environment already
meets. Revisit it if a second writer ever has to share an environment with
Terraform.

## 5. Rotation: when Terraform writes again

Terraform cannot see `value_wo` in its state. It compares
`value_wo_version`, which it does store, as Terraform's convention for write-only arguments asks
(the AWS, Azure, Google and Vault providers do the same).

```hcl
value_wo_version = "1"                                   # by hand: bump to write again
value_wo_version = scaleway_iam_api_key.backup.id       # a new key, replaced upstream
value_wo_version = time_rotating.backup_key.id          # every 90 days, with a key that rotates on the same clock
```

It is a string, not a number: the commonest trigger is an upstream
resource's ID, which changes exactly when the value does. A number in HCL
converts to a string, so `value_wo_version = 2` works too.

The plan reads:

```
  # coffre_secret.backup_key will be updated in-place
  ~ resource "coffre_secret" "backup_key" {
        id               = "infra/prod/SCW_BACKUP_SECRET_KEY"
      ~ value_wo_version = "SCWQ1TZN2D5K" -> "SCW7H0B4M1RX"
      ~ version          = 3 -> (known after apply)
        # (5 unchanged attributes hidden)
    }
```

**Every write is a new version.** Coffre keeps the old ones, so a bad
rotation is one `coffre restore` away (by someone allowed to read what comes
back). An apply that changes only `sensitivity` writes the value again too,
a new version with the new nature, since `value_wo` is at hand: one path for
every change.

**Rejected: a hash of the value in state.** The provider sees `value_wo` at
plan time and could store its hash, so that a changed value is noticed
without a version. But a hash of a short password is a guess away from the
password for anyone who reads state, which is what write-only arguments are
there to prevent. And an ephemeral source that mints a new value on every
run (Scaleway's ephemeral `scaleway_iam_api_key`, below) would write a new
version on every apply. **Rejected: asking coffre whether the value
changed.** That answer is a test any writer could run on a guess. Coffre's
dry run refuses it without `secret.read` for that reason.

### Values written outside Terraform

The provider remembers, in the resource's private state, the version it
wrote. Each refresh compares it with coffre's current version for the key:

| Coffre has | The plan |
|---|---|
| the version Terraform wrote | nothing to do |
| a later version, written by someone else | an update, with a warning naming who wrote it (`updatedBy`): this apply writes Terraform's value again |
| no such key | create (the resource leaves state; Terraform makes it again) |
| the key, archived | an error at plan: archived in coffre; unarchive it there, or remove the resource |
| the key as a reference | an error at plan: a reference is not Terraform's to overwrite |

Terraform owns the keys it declares, so a newer value written by hand is
drift, and the next apply puts Terraform's value back. That matches every
other Terraform resource, and the warning names who wrote the newer version.
If that value matters (a leaked key rotated by hand), rotate it in Terraform: a
value rotated only in coffre leaves the old key live upstream anyway.

**Writes never overwrite an unseen version.** An update sends `replaces`,
the `versionId` the provider read just before writing, and stops on coffre's
409 `stale` if anyone wrote in between. Telling coffre "create only if
absent" is not possible today (`replaces` names an existing version), so a
create checks that the key is absent first and a create racing another
writer may still win. The other writer's version stays in the history, and
the audit log shows both.

**Adopting a key that exists.** A create refuses a key already live in
coffre ("exists; import it"). `terraform import coffre_secret.backup_key
infra/prod/SCW_BACKUP_SECRET_KEY` (or an `import` block) adopts it; the
next apply writes Terraform's value as a new version, since the imported
state has no `value_wo_version`.

## 6. Destroy keeps the secret

Equisafe's infrastructure rule: Terraform never destroys anything without
an explicit go. A `coffre_secret` removed from the configuration, or a
`terraform destroy`, could otherwise end a production credential when a module is
refactored.

**By default, destroying the resource only stops managing it.**
`on_destroy = "keep"`: the provider removes it from state, calls
nothing, and says so:

```
coffre_secret.backup_key: Destroying... [id=infra/prod/SCW_BACKUP_SECRET_KEY]
Warning: infra/prod/SCW_BACKUP_SECRET_KEY kept in coffre
  on_destroy is "keep": Terraform no longer manages the key; its value and versions stay.
  Archive it in coffre (coffre archive infra/prod/SCW_BACKUP_SECRET_KEY) if it should go.
```

A changed `project`, `environment` or `key` replaces the resource, so the
old key is kept and the new one is written: a rename leaves the old key
behind on purpose, to be archived once nothing uses it.

**An archive is asked for in two steps, each a reviewed plan.**

1. Set `on_destroy = "archive"` and apply. The plan shows only that
   change; nothing happens in coffre.
2. Remove the resource and apply. The plan says `destroy`, and the apply
   archives the key.

The principal also needs `secret.archive` on the place, which `contributor`
lacks: by default, step 2 fails with coffre's 403, before the provider
removes the resource from state. So an archive takes a go in the
configuration and a grant that someone gave on purpose (`maintainer` on
`infra/prod`, for the apply that archives). Most teams will never grant it and will
archive by hand, in coffre.

Coffre has no hard delete of one key: an archived key keeps its versions,
out of every read, run and export, and comes back with `coffre unarchive`.
So the option is named `archive`, not `delete`.

Terraform's own `removed` block (1.7) stops managing a resource whatever
`on_destroy` says:

```hcl
removed {
  from = coffre_secret.backup_key
  lifecycle { destroy = false }
}
```

## 7. The source side

`coffre_secret` keeps the value out of its own state. The resource that
made the value may still put it in state, as the Scaleway key does unless
told otherwise. So each source needs a look:

| Source | Value lands in state? | Use |
|---|---|---|
| Scaleway `scaleway_iam_api_key`, plain | yes, `secret_key` | avoid |
| Scaleway `scaleway_iam_api_key` with `secret_id` | no: `secret_key` goes to a Scaleway Secret Manager secret as a new version | **recommended**, with ephemeral `scaleway_secret_version` feeding `value_wo` (section 1) |
| Scaleway ephemeral `scaleway_iam_api_key` (experimental) | no, but each plan and apply makes a new key, deleted when the run ends unless `delete_on_close = false` (v2.90) | unusable for a key that must outlive the run |
| A generated password, ephemeral `random_password` (hashicorp/random 3.7+) | no | feed the same value to the upstream's write-only argument (Scaleway's `scaleway_rdb_user.password_wo`) and to `value_wo`, with one shared version |
| Any resource with a plain `sensitive` output | yes | coffre_secret still removes the GitHub or Kubernetes copy, but state stays as sensitive as before |

A database password, never in any state:

```hcl
ephemeral "random_password" "app_db" {
  length = 40
}

locals { app_db_rotation = "2026-11" } # bump to rotate both

resource "scaleway_rdb_user" "app" {
  instance_id         = scaleway_rdb_instance.main.id
  name                = "app"
  password_wo         = ephemeral.random_password.app_db.result
  password_wo_version = 1 # Scaleway's is a number: bump it with local.app_db_rotation
}

resource "coffre_secret" "app_db_password" {
  project          = "infra"
  environment      = "prod"
  key              = "APP_DB_PASSWORD"
  sensitivity      = "sensitive"
  value_wo         = ephemeral.random_password.app_db.result
  value_wo_version = local.app_db_rotation
}
```

Both resources write in the same apply, from the same ephemeral value,
so they cannot disagree. Bumping one version and not the other would: the
example keeps them side by side for that reason.

With Scaleway's Secret Manager pattern, the key's secret lives in one more
place, inside the same Scaleway account that made it. Delete that secret's
versions once coffre has the value if that copy matters. On the first
apply, the ephemeral `scaleway_secret_version` must open only after the
key has written its version: section 1's `depends_on` orders it so, as
Scaleway's own examples do. Whether the first plan also defers it, rather
than failing on a secret with no version yet, is Terraform's behaviour and
Infra's configuration, not this provider's; that first apply is where to
check it (`-target=scaleway_iam_api_key.backup` first, if not). The
secret's payload is base64, hence `base64decode`.

## 8. The code, its release and its tests

**A Go module in this repository, `terraform-provider/`**, on
terraform-plugin-framework, the current SDK and the only one with write-only
attributes. It lives beside the server it calls: a PR that changes a route
it uses changes and tests the provider in the same PR, and its acceptance
tests run against this checkout's coffre in CI. It talks to the HTTP API
directly (four calls, a small client of its own). No `@coffre/*` package
imports Go, and the provider ships no TypeScript.

**Published from a mirror repository.** The Terraform Registry (and
OpenTofu's) publishes from a public GitHub repository named
`terraform-provider-coffre`, from its tags' GitHub releases: zips for each
OS and architecture, a `SHA256SUMS` file, its detached GPG signature, and
a manifest, which GoReleaser builds. The registry checks the signature
against a GPG public key added to the namespace. The release workflow here
pushes `terraform-provider/` to that repository as its own history (`git
subtree split`) and tags it. GoReleaser runs there, signing with a key kept
in that repository's Actions secrets. The provider takes its own versions (`0.1.0` first),
apart from coffre's: `pnpm bump` leaves it alone, and its notes say which
coffre release it needs.

Publishing waits for Erwin's go, at publishing time, not before building:
creating the repository (and in which account, `erwinkn` or `equisafe`, which is
also the registry namespace: `erwinkn/coffre` in `required_providers`),
making the GPG key, and the first registry release. Until then, Infra can
use a local build through Terraform's `dev_overrides`, or a filesystem
mirror.

**Tests, never against a live instance.**

- Unit tests (`go test`): the plan logic of section 5's drift table, the
  credential choice of section 3, `replaces` on update, the re-exchange on
  401, and that no code path writes `value_wo` into state, a diagnostic or
  a log line.
- Acceptance tests (`TF_ACC=1`, terraform-plugin-testing), against a local
  coffre that the test harness boots as `pnpm conformance:node` does: the
  Node example on SQLite in a temp directory, on ports of its own, with no
  shared Postgres. A seed made through the API: project `infra`,
  environments `prod` and `market`, a service account with `contributor`
  on `infra/prod`, a scoped service token, and an OIDC binding with
  uploaded keys whose ID tokens the test signs (the `id_token` path). The
  GitHub path gets a fake `ACTIONS_ID_TOKEN_REQUEST_URL` from the same test.
  Each runs on Terraform 1.11 and OpenTofu 1.11, and covers:
  - create, update on a new `value_wo_version`, and a change of
    `sensitivity`. After each step it reads the value back with an Owner's
    session and checks it, and checks that neither the state file nor
    `terraform show -json` of the saved plan contains the value;
  - drift: a version written by hand is overwritten with a warning; a
    deleted key is made again; an archived key fails the plan;
  - destroy with `keep` (the key and its versions stay) and with
    `archive`, without `secret.archive` (403, the resource stays in state)
    and with it (archived);
  - scope: a write to `market/prod` is refused, and `terraform plan` makes
    no write;
  - `terraform import`, then an apply that writes a new version;
  - a credential expiring mid-apply: the GitHub path trades again; the
    `id_token` path fails with an error that says why.
- CI: a job "Terraform provider" runs both on changes to
  `terraform-provider/`, to `packages/server/src/api/`, or to
  `packages/client/src/api.ts`, with Go and both Terraform binaries pinned by
  version and checksum, as `pnpm formal` pins TLC.

## 9. Decisions

1. One resource, `coffre_secret`, write-only: `value_wo` and a string
   `value_wo_version`. No data source, no ephemeral resource, nothing that
   reads a value.
2. It signs in with coffre's existing credentials: GitHub OIDC
   (`service`), another issuer's ID token (`id_token`), or a bearer token.
   Scope is fixed when the credential is made. No new endpoint, no
   environment variable of its own.
3. A Terraform principal is a service account with `contributor` on
   environments that hold only what Terraform writes. No key-prefix grants.
4. `sensitivity` is required. Writing at any nature needs only
   `secret.write`. Loosening writes the value again, never in place.
5. A changed `value_wo_version` writes a new version. Versions written by
   others are drift, overwritten with a warning. Every update is guarded by
   `replaces`.
6. Destroy keeps the key (`on_destroy = "keep"`). Archiving takes
   `on_destroy = "archive"` in a reviewed apply, and `secret.archive`,
   which `contributor` lacks.
7. Code in `terraform-provider/`, its own versions, published from a
   mirror repository once Erwin says go. Acceptance tests boot a local
   coffre, on Terraform and OpenTofu.

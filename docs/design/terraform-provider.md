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
resource "terraform_data" "backup_key" {
  # Everything that replaces the key, so that a new key always gets a new secret (section 7).
  input = { rotation = 1, application_id = scaleway_iam_application.backup.id }
}

resource "scaleway_secret" "backup_key" {
  name = "backup-key"
  lifecycle { replace_triggered_by = [terraform_data.backup_key] }
}

resource "scaleway_iam_api_key" "backup" {
  application_id = terraform_data.backup_key.output.application_id
  secret_id      = scaleway_secret.backup_key.id # secret_key goes to Secret Manager, not state
}

data "scaleway_secret" "backup_key" { # read after the key is made, when it is made in this run
  secret_id  = scaleway_secret.backup_key.id
  depends_on = [scaleway_iam_api_key.backup]
}

ephemeral "scaleway_secret_version" "backup_key" {
  secret_id = scaleway_secret.backup_key.id
  revision  = "1" # this key's secret_key: its secret holds no other, and "latest" may be anyone's

  lifecycle {
    precondition { # one version: only this key wrote to its secret (section 7)
      condition     = data.scaleway_secret.backup_key.version_count == 1
      error_message = "The key's secret holds more than its value (the key was made again, or a version added): bump rotation in terraform_data.backup_key."
    }
  }
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
| `version` | computed | The key's current version number in coffre, as the last refresh or write saw it |
| `version_id` | computed | That version's ID, which an update sends as `replaces` (section 5) |

`value_wo` is sent to coffre on create and when `value_wo_version`
changes, and at no other time: Terraform's convention for write-only
arguments, and the one rule that keeps two destinations of one value in
step (section 7).

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
Terraform starts and configures the provider once per phase, so a single
`terraform apply` (or `destroy`) configures it twice, for its plan and for
its apply, and the provider exchanges a fresh ID token each time. An apply
can also run longer than five minutes: the provider then fetches another
ID token and trades it again, at most once per credential, when coffre
answers 401 on an expired one.

**With `id_token`, one token serves one phase.** Coffre spends an ID token
on its first exchange and refuses it after as `replayed`
(`packages/server/src/api/workloads.ts`), and the provider has no way to
fetch another. So this mode is for saved plans: `terraform plan -out=tfplan`
and `terraform apply tfplan` as two commands, each given its own token
(GitLab's `id_tokens:` declares several), each phase within five minutes.
A combined `terraform apply` fails at its apply phase, and the provider
says why: "this ID token was spent by the plan phase of this run; plan
with -out and apply the saved plan with a fresh token". A job that wants a
combined apply trades its ID token itself (`POST /api/auth/oidc`) and passes
the five-minute `coffre_svc_` credential through `token`, from a variable,
never a file: nothing outlives the job.

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
| Refresh, and before each create | `GET /api/secrets/:project/:environment` | `secret.use` or `secret.read` |
| Create, write a new version | `PATCH /api/secrets/:project/:environment` `{ KEY: { value, sensitivity, replaces? } }` | `secret.write` |
| Make the key stricter, with no new value | `PATCH /api/secrets/:project/:environment` `{ KEY: { sensitivity, replaces } }` | `secret.write` |
| Destroy with `on_destroy = "archive"` | `PATCH /api/secrets/:project/:environment/:key` `{ archived: true }` | `secret.archive` |

No new server endpoint, and two small additions to the existing write:

- **A mark takes `replaces`.** Today `{ sensitivity }` is a strict schema
  (`marked` in `packages/server/src/api/routes.ts`) and marks whatever
  version is current. It gains the same optional `replaces` a value write
  has, so a sensitivity-only apply refuses with 409 `stale` when someone
  wrote after its plan (section 5).
- **The write says which version it made.** The response's outcome for a
  key, `{ version, sensitivity }` (`SetOutcome` in
  `packages/server/src/api/secrets.ts`), gains `versionId`. Without it the
  provider would have to list the environment after writing, and a version
  someone else committed in between would pass for its own (section 5).
  It is metadata the list already shows; no value comes back.

None of these calls returns a secret value. The list
returns the values of `plain` keys, which anyone who can list the
environment sees already: the provider drops them and never stores them.
From the list it keeps, for its key, `version`, `versionId`, `updatedBy`,
`sensitivity`, `archived`, `reference` and, in a fork, `parent.state`
(section 5). The dry run (`?dryRun=1`), which
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
to secret, needs the value written again, so the plan requires a changed
`value_wo_version` with it (section 5). The provider never asks coffre to
loosen a value in place: that is an Owner's act (R30), which no service
credential can perform.

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
value_wo_version = time_rotating.backup_key.id          # every 90 days, with the key's generation (section 7) on the same clock
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
back).

**What each change of the configuration plans:**

| Change | The plan | The apply |
|---|---|---|
| `value_wo_version` (with or without `sensitivity`) | update, `version` known after apply | writes `value_wo` at the configured nature, `replaces` guarded |
| `sensitivity` stricter only | update, `version` known after apply | marks the current value stricter (`{ sensitivity, replaces }`), a new version holding the same value; `value_wo` is not sent |
| `sensitivity` looser only | an error: "making KEY looser writes its value again; change value_wo_version in the same apply" | |
| `sensitivity` only, on a fork's key that inherits (below) | an error: "KEY has no value of its own in infra/prod-eu to mark; change value_wo_version to write one" | |
| `on_destroy` only | update, `version` and `version_id` kept | calls nothing |
| none | nothing | |

A plan modifier (`ModifyPlan`) makes `version` and `version_id` unknown in
the first two rows and keeps them from state in the others
(`UseStateForUnknown`). A `value_wo_version` not yet known at plan (an
upstream ID that the same apply makes, as in section 1) plans the first
row; at apply, the provider writes only if the now-known value differs
from the state's. No other input schedules a write: not drift, not a
refresh (below).

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

The provider remembers, in the resource's private state, the version ID
it last wrote, taken from the write's own response (`versionId`, section
3), never from a list made after it: if Terraform writes A and someone
writes B before that list, the list would record B as Terraform's and
hide the drift. Each refresh (`Read`) lists the environment, stores coffre's
current `version` and `version_id` in state, and compares:

| Coffre has | The refresh | The plan |
|---|---|---|
| the version Terraform wrote | nothing | nothing to do |
| a later version, written by someone else | state takes the new `version`; a warning names who wrote it (`updatedBy`) | nothing to write; Terraform lists the change under "Objects have changed outside of Terraform" |
| no such key | the resource leaves state | create |
| the key, archived | an error: archived in coffre; unarchive it there, or remove the resource | |
| the key as a reference | an error: a reference is not Terraform's to overwrite | |
| in a fork, the key inheriting its parent's (`parent.state` `inherited`): Terraform's override was reset | state takes the inherited `version` and `version_id`, null where the credential is not told the parent's, and keeps its `sensitivity`; a warning says the fork reads the parent's value now | nothing to write |
| in a fork, the key removed (`parent.state` `removed`) | an error: removed in this fork; restore it there, or remove the resource | |

**A version written by hand is reported, not overwritten.** The provider
cannot tell whether that version holds the value its source has now (a
person may have rotated a leaked key in coffre and upstream both), and
writing `value_wo` again outside a version change would break section 7's
guarantee 2. So the warning repeats on every plan until Terraform writes again,
and says how: change `value_wo_version`. If the hand-written value matters,
rotate in Terraform anyway: a value rotated only in coffre leaves the old
key live upstream.

**In a fork, a key can stop being the fork's own.** Say Terraform writes
`APP_DB_PASSWORD` into `infra/prod-eu`, a fork of `infra/prod`, and someone
then resets it to the parent's: coffre archives the override and lists
the key as `inherited`, unarchived, no reference, so the rows above would
not catch it. The provider keeps `parent.state` from each list in private
state and treats a reset like a hand-written version: reported, not
overwritten, since the person may have meant the fork to follow its
parent. Terraform takes the key back only on a changed `value_wo_version`,
which writes a new override (coffre brings the reset row back for it).
Until then the key has no value of its own, so a sensitivity-only change
fails at plan instead of at coffre's mark ("KEY is inherited: mark it
where it is held"), and the state keeps the nature Terraform wrote, not
the parent's, so a parent's nature never plans a mark here. A removal
(`removed`) is the fork deciding to do without the key, so it fails the
plan as an archive does: a write would end the removal unasked.

**A write never overwrites a version its plan did not see.** An update,
a value write or a mark alike, sends `replaces` with the `version_id` of the prior state, which is what
the plan's refresh read (and what a saved plan carries), not a fresh read
at apply. If anyone wrote between the plan and the apply, coffre answers
409 `stale` and the apply stops: "KEY was written after this plan; plan
again". The new plan shows the drift warning, so whoever approves it sees
the version it is about to replace. Telling coffre "create only if absent"
is not possible today (`replaces` names an existing version), so a create
checks that the key is absent at plan and again at apply, and a create
racing another writer between that check and the write may still win. The
other writer's version stays in the history, and the audit log shows both.
A write over an inherited key sends the inherited version's ID as
`replaces`, which coffre checks against the parent's current version; when
the list hid it (the credential is not told the parent's versions), the
write has no `replaces` and is checked at plan and at apply, as a create.

**Adopting a key that exists.** A create refuses a key already live in
coffre ("exists; import it"). In a fork, a key it inherits is not its own:
a create over it writes an override, which the plan shows as a create of
`infra/prod-eu/APP_DB_PASSWORD`, and a key the fork removed is refused at plan
("removed in infra/prod-eu; restore it there first"), as is its import. `terraform import coffre_secret.backup_key
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

The credential also needs `secret.archive` on the place, which `contributor`
lacks: by default, step 2 fails with coffre's 403, before the provider
removes the resource from state. No built-in role fits: `maintainer` holds
`environment.manage`, which only a project takes, and coffre refuses it on
`infra/prod` in a grant or a scope. So an archive takes a go in the
configuration and a role someone made on purpose: an Owner makes
`terraform-archiver` in the role editor (`secret.use`, `secret.write`,
`secret.archive`), grants it on `infra/prod`, and issues a new credential
scoped to it (a token, or a binding's `--scope`), since a credential made
before never gains what the account gains after. Most teams will never do
this and will archive by hand, in coffre.

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

`coffre_secret` keeps the value out of its own state and plans. The
resource that made the value may still put it in its own, so a source is
usable only if it gives every guarantee below. A source here is whatever
feeds `value_wo`; a destination is each resource that takes the value
(`coffre_secret`, a database user's `password_wo`, …).

1. **No copy in Terraform's files.** The value is in no state, no plan,
   and no plan's private data: an SDKv2 provider's `PlannedPrivate`,
   `_new_extra_shim` included, which keeps a raw input next to a
   `StateFunc`'s output. `terraform show -json` does not print private
   data, so it cannot prove this.
2. **One durable value per generation.** A generation (one key, one
   rotation of a password) has one stored value, which every destination
   reads. Nothing feeds two destinations straight from a source that mints
   a new value each run (an ephemeral `random_password`): a retry after a
   partial apply would give the second destination a value the first
   never got.
3. **Reads pinned to the written revision.** Each run reads the exact
   revision that generation wrote, never `latest`, so a version added
   between a failed apply and its retry is not handed to the destinations
   still missing the value.
4. **Triggers follow the source version's identity.** Each destination's
   version trigger changes exactly when the source version does, a
   recreated source included: an ID, never a counter (a recreated source
   resets it) or a creation time (to the second, it can repeat). A
   destination whose trigger is an int gets one that fits a signed 32-bit
   int, which SDKv2 providers' `int` is on their 386 and arm builds.
5. **Checked on the saved plan.** Before a source is recommended, a run
   saves a plan and an apply's state with a known value, and the value is
   searched for in the raw files: the state, and the plan file unzipped,
   private data included. Section 8's acceptance tests do the same for
   `coffre_secret`.

| Source | Gives all five? |
|---|---|
| Scaleway `scaleway_iam_api_key`, plain | no: `secret_key` lands in state |
| Scaleway `scaleway_iam_api_key` with `secret_id`, read through ephemeral `scaleway_secret_version` (section 1) | 1 to 4, as section 1 builds it (below); check 5 is still to run |
| Scaleway ephemeral `scaleway_iam_api_key` (experimental) | no: a new key every plan and apply, deleted when the run ends unless `delete_on_close = false` |
| Ephemeral `random_password` stored through Scaleway `scaleway_secret_version.data_wo` (v2.90.0) | **no, fails 1**: `data_wo` has a `StateFunc`, so SDKv2 keeps the raw password in the saved plan's private data. Waits on an upstream fix |
| Any resource with a plain `sensitive` output | no: state holds the value; `coffre_secret` still removes the GitHub or Kubernetes copy |

**Section 1's API key.** Scaleway's key writes its `secret_key` to the
secret it names, as a new version, and keeps neither the value (1) nor
which revision it wrote. So each generation gets a secret of its own:
every argument that replaces the key goes through
`terraform_data.backup_key`, whose change replaces the secret as well,
and the read pins revision `"1"` (2, 3). A key made again within one
generation (deleted in Scaleway's console, or `-replace`) writes revision
2 to the old secret; the read's precondition, one version only, stops the
run before coffre is written, and the fix is to bump `rotation`, never to
`-replace` the key. The precondition can stop a safe run (a version added
by hand trips it too), never let a wrong value through. `value_wo_version`
is the key's ID (4). The secret must stay readable while Terraform manages
the key, since every plan and apply reads it; deleting it makes Terraform
recreate the secret, which replaces the key.

**Not usable yet: a database password with two destinations.** Shown for
its shape only, until Scaleway's `data_wo` passes guarantee 1:

```hcl
ephemeral "random_password" "app_db" { length = 40 }

resource "scaleway_secret_version" "app_db" { # fails guarantee 1 in v2.90.0
  secret_id       = scaleway_secret.app_db.id
  data_wo         = ephemeral.random_password.app_db.result
  data_wo_version = 1 # bump to rotate
}

ephemeral "scaleway_secret_version" "app_db" {
  secret_id = scaleway_secret.app_db.id
  revision  = scaleway_secret_version.app_db.revision
}

# scaleway_rdb_user.password_wo and coffre_secret.value_wo both read
# base64decode(ephemeral.scaleway_secret_version.app_db.data); their triggers
# follow scaleway_secret_version.app_db.id (guarantee 4).
```

**Known upstream limits.** What this design depends on from other
providers, and does not fix:

- Scaleway v2.90.0, `scaleway_secret_version.data_wo`: its `StateFunc`
  makes SDKv2 keep the raw input in `PlannedPrivate` (`_new_extra_shim`).
  The fix is upstream: drop the `StateFunc` and read the value from the
  raw configuration, as write-only arguments should. The database pattern
  waits on a release with it, pinned.
- Scaleway's `scaleway_iam_api_key` exposes no revision for the
  `secret_key` it writes. A computed `secret_revision` would replace
  section 1's secret per generation and its precondition with one pinned
  read.
- Whether the first plan defers an ephemeral read that `depends_on` a
  resource the same apply makes, rather than failing on a secret with no
  version yet, is Terraform's behaviour; the first apply is where to check
  it (`-target` on the source first, if not).
- Ephemeral `scaleway_secret_version` returns its payload base64-encoded,
  hence `base64decode`.

## 8. The code, its release and its tests

**A Go module in this repository, `terraform-provider/`**, on
terraform-plugin-framework, HashiCorp's current SDK (SDKv2 has write-only
arguments too, but plan modification and private state are the
framework's strengths, and section 5 leans on both). It lives beside the server it calls: a PR that changes a route
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

- Unit tests (`go test`): the plan logic of section 5's two tables, the
  credential choice of section 3, `replaces` from the prior state, the
  re-exchange on 401, the `replayed` error's message, and that no code path writes `value_wo` into state, private state, a diagnostic or
  a log line.
- Acceptance tests (`TF_ACC=1`, terraform-plugin-testing), against a local
  coffre that the test harness boots as `pnpm conformance:node` does: the
  Node example on SQLite in a temp directory, on ports of its own, with no
  shared Postgres. A seed made through the API: projects `infra` and
  `market`, each with an environment `prod`, `infra/prod` with an
  inheriting fork `prod-eu`, a service account with
  `contributor` on `infra/prod` and `contributor` on `market/prod` too
  (more than any credential the tests give it), service tokens and an OIDC binding all
  scoped to `infra/prod=contributor`, with uploaded keys whose ID tokens
  the test signs (the `id_token` path), and a `verifier` service account,
  `viewer` on `infra/prod`, with a token an Owner of `infra` issued (R32),
  which alone may read a sensitive value back. The GitHub path gets a
  fake `ACTIONS_ID_TOKEN_REQUEST_URL` from the same test. Each runs on
  Terraform 1.11 and OpenTofu 1.11, and covers:
  - create, update on a new `value_wo_version`, a stricter `sensitivity`
    (a mark, no value sent) and a looser one (refused at plan without a
    version change). After each step the verifier reads the value back
    and checks it, and Terraform's own credential is refused the same
    read. The Owner's session is refused it while the key is `sensitive`,
    and reads it at `secret` and `plain`, as coffre's natures say. Neither the state file nor the saved
    plan file, unzipped and searched raw (private data included, not only
    `terraform show -json`), contains the value;
  - the write rule: an `on_destroy`-only change and a refresh call no
    `PATCH` (the fake records calls), and `version` stays;
  - drift: a version written by hand gives a warning, no write, and the
    following plan has no change; a version written between a saved plan
    and its apply stops the apply with `stale`, for a value write and for
    a sensitivity-only mark alike; a version written right after
    Terraform's own, before any list, still gives the warning on the next
    plan (the receipt, not a list, names Terraform's version); a key gone
    from coffre is made again; an archived key fails the plan;
  - two destinations: section 7's sketch against a fake upstream
    provider that gives guarantees 1 to 4, with the apply failing after
    one destination; the retry leaves both holding the same value, also
    when a newer source version was added between the failure and the
    retry (the pinned revision), and when the source was deleted between
    them (both take the recreated source's value); and section 1's API
    key, whose coffre write fails, gets a revision 2 added by hand
    between the retry's plan and its apply, and whose retry still writes
    revision 1's value; which, with that revision added before the plan,
    fails the read's precondition and writes nothing; whose application
    change plans its secret's replacement with it; and which, deleted
    upstream or forced with `-replace`, fails the read's precondition
    before any coffre write, then writes the new key's value once
    `rotation` is bumped;
  - forks: a key Terraform overrides in a fork, then reset to the
    parent's between applies, gives a warning and no write; a
    sensitivity-only change then fails at plan; a changed
    `value_wo_version` writes the override back, with `replaces` the
    inherited version, and with none from a credential scoped to the fork
    alone; a key removed in the fork fails the plan, and its import;
  - destroy with `keep` (the key and its versions stay) and with
    `archive`, without `secret.archive` (403, the resource stays in state)
    and with a credential scoped to a `terraform-archiver` role (archived);
  - scope: a write to `market/prod`, which the account may write and the
    credential may not, is refused for each credential, after the
    account's grants widen, and after the GitHub path trades again;
    `terraform plan` makes no write;
  - `terraform import`, then an apply that writes a new version;
  - phases: a combined `terraform apply` on the GitHub path trades twice
    and succeeds; on the `id_token` path it fails at its apply phase with
    the error of section 3, and a saved plan with a token per phase
    succeeds;
  - a credential expiring mid-apply: the GitHub path trades again.
- CI: a job "Terraform provider" runs both on changes to
  `terraform-provider/`, to `packages/server/src/api/`, or to
  `packages/client/src/api.ts`, with Go and both Terraform binaries pinned by
  version and checksum, as `pnpm formal` pins TLC.

## 9. Decisions

1. One resource, `coffre_secret`, write-only: `value_wo` and a string
   `value_wo_version`. No data source, no ephemeral resource, nothing that
   reads a value.
2. It signs in with coffre's existing credentials: GitHub OIDC
   (`service`), another issuer's ID token (`id_token`, one per phase:
   saved plans), or a bearer token.
   Scope is fixed when the credential is made. No new endpoint, no
   environment variable of its own; the existing write gains `replaces`
   on a mark and returns each new version's `versionId`.
3. A Terraform principal is a service account with `contributor` on
   environments that hold only what Terraform writes. No key-prefix grants.
4. `sensitivity` is required. Writing at any nature needs only
   `secret.write`. Loosening writes the value again, never in place.
5. `value_wo` is sent only on create and on a changed `value_wo_version`.
   A stricter nature is a mark; a looser one needs a new version. Versions
   written by others are reported with a warning, never overwritten
   unasked. Every update sends `replaces` with the version its plan saw,
   whenever the list showed one.
   A value source must give section 7's five guarantees: no copy in
   state, plans or their private data; one stored value per generation
   that every destination reads; reads pinned to the written revision;
   triggers that follow the source version's ID (an int one within 32
   bits); and a check of the raw saved plan. Section 1's API key gives
   the first four, its raw-plan check still to run; Scaleway's `data_wo`
   fails the first, so the database-password pattern waits on an
   upstream fix. In a fork, a key reset to its
   parent's is reported like a hand-written version, and a removed one
   fails the plan.
6. Destroy keeps the key (`on_destroy = "keep"`). Archiving takes
   `on_destroy = "archive"` in a reviewed apply, and a credential made for
   a custom role holding `secret.archive`, which `contributor` lacks.
7. Code in `terraform-provider/`, its own versions, published from a
   mirror repository once Erwin says go. Acceptance tests boot a local
   coffre, on Terraform and OpenTofu.

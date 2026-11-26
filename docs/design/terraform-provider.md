# Terraform provider

A Terraform and OpenTofu provider that writes coffre secrets from
infrastructure code, and never holds a value anywhere it keeps:
not in state, a plan, a log or an error. Secrets first; the configuration
(environments, service accounts, trust, grants) comes later, as more
resources beside this one (section 9). It needs Terraform 1.11 or OpenTofu
1.11 at least: both take write-only attributes from those releases on.

```hcl
provider "coffre" {
  url  = "https://secrets.acme.example"
  oidc = { service = "terraform" }   # in GitHub Actions; or token = var.coffre_token
}

variable "stripe_key" {
  type      = string
  sensitive = true
  ephemeral = true                    # kept out of a saved plan too (section 7)
}

resource "coffre_secret" "stripe" {
  project          = "billing"
  environment      = "prod"
  key              = "STRIPE_KEY"
  value_wo         = var.stripe_key   # write-only: sent to coffre, kept nowhere
  value_wo_version = 3                # bump it to write the value again
  sensitivity      = "sensitive"      # plain, secret (the default) or sensitive
}
```

After an apply, the state holds exactly this, and nothing that comes from
the value:

```json
{ "id": "billing/prod/STRIPE_KEY", "project": "billing", "environment": "prod", "key": "STRIPE_KEY",
  "value_wo": null, "value_wo_version": 3, "sensitivity": "sensitive", "version": 7,
  "version_id": "0b6d…", "updated_by": "token:terraform" }
```

## 1. One resource: `coffre_secret`

| Attribute | Kind | What it is |
|---|---|---|
| `project`, `environment`, `key` | required; a change replaces | where the key is. `key` as coffre names one, `^[A-Za-z_][A-Za-z0-9_]{0,127}$` |
| `value_wo` | required, write-only, sensitive | the value: text with no NUL, at most 65,536 UTF-16 code units, as coffre counts them |
| `value_wo_version` | required number | a change writes `value_wo` again. Terraform cannot tell a write-only value changed, so this says it did |
| `sensitivity` | optional, default `secret` | who sees the value (`plain`: any lister; `sensitive`: nobody, it is only used) |
| `version`, `version_id` | computed | the version the key reads now, by number and id, as the last refresh or write saw it |
| `updated_by` | computed | who wrote that version |
| `id` | computed | `project/environment/key`, the import ID too |

No data source. A data source's result lands in state, so one that reads
values breaks the rule above, and one that reads only metadata has no use
yet. An ephemeral resource (Terraform 1.10, OpenTofu 1.11) could open a
value for another provider's write-only argument without keeping it; it is
left for later (section 9).

## 2. What each step asks of coffre

Every call is one the CLI and the pages already make, on `/api`:

| Terraform step | Call |
|---|---|
| refresh (`Read`) | `GET /secrets/billing/prod`: the key's row, its version, id and author. A listing may carry a plain value; the provider never decodes it |
| create | `PATCH /secrets/billing/prod` `{"STRIPE_KEY": {"value": "…", "sensitivity": "sensitive", "replaces": null}}`, then the listing again for the new version's id |
| update | the same write, `"replaces": "<version_id from the plan>"`, then the listing |
| destroy | `PATCH /secrets/billing/prod/STRIPE_KEY` `{"archived": true}`: coffre deletes no key, it keeps its history, and an archived key can be brought back |
| import | `terraform import coffre_secret.stripe billing/prod/STRIPE_KEY`, then a refresh |

The service account lists the environment (`secret.use`), writes it
(`secret.write`) and archives in it (`secret.archive`), and never reads a
value back. No built-in role holds exactly those: `maintainer` holds them,
`secret.read` and `environment.manage`. A custom role with those three
holds no more than the provider needs, and without `secret.read` the
account cannot reveal a value at all.

A change of `value_wo_version` or `sensitivity` is an update, and both
write the configured value again: a sensitivity is changed by writing the
value as a new version, never by marking the stored one in place. So one
call covers both, and it carries the guard below.

After an import, Terraform has never written the key, so the first apply
writes the configured value once (`value_wo_version` goes from nothing to
a number). From then on the key is Terraform's.

## 3. Drift: someone else wrote the key

The provider remembers, in the resource's private state (kept in the state
file, never shown, and holding only a version number and a row id), which
version it wrote: `{"version": 7, "secret": "<the key's row id>"}`. A refresh
compares that with what the key reads now. Say Ada writes the key from the
pages, making version 8:

```
  # coffre_secret.stripe will be updated in-place
  ~ resource "coffre_secret" "stripe" {
      ~ version    = 8 -> (known after apply)
      ~ version_id = "4f1e…" -> (known after apply)
      ~ updated_by = "ada@acme.example" -> (known after apply)
    }
Warning: billing/prod/STRIPE_KEY was written outside Terraform
  It is at version 8, written by ada@acme.example. Applying writes the configured value over it.
```

The same holds when the key was reset to what a parent passes down, or
renamed away and another renamed onto its name: whatever it reads is not
what Terraform wrote. A key made a reference is drift too, but one the
provider does not write over (section 8). A key deleted with its
environment, or archived, leaves the state, and the next plan creates it
(creating over an archived key is refused; section 8).

So the configuration wins, as everywhere in Terraform. A value someone
rotates by hand comes back on the next apply; who wants to rotate by hand
leaves the key out of Terraform.

## 4. The guard: a plan's write never overwrites what it did not see

A saved plan can be applied much later. Say the plan above saw version 8,
then Bo writes version 9, then the plan is applied. Overwriting 9 with the
configured value would undo a change nobody reviewed. So every write says
which version it replaces, the one the plan's refresh saw, and coffre
writes it only if the key still reads that version (it already takes
`replaces` on a value: the pages and Regenerate use it):

```
PATCH /api/secrets/billing/prod
{"STRIPE_KEY": {"value": "…", "sensitivity": "sensitive", "replaces": "<id of version 8>"}}

409 {"error": "conflict", "reason": "stale", …}
Error: billing/prod/STRIPE_KEY changed after this plan was made
  Someone wrote, archived or renamed it since. Nothing was written: plan again.
```

A create says `"replaces": null`: the key holds no value, here or passed
down (section 5). Over a key that exists, coffre answers `stale`, and the
provider says to import it. In a fork, over a value a parent passes down,
the provider reads the listing and writes once more, replacing the
inherited version: the configuration asks for this environment's own
value, whatever the parent holds, and the parent's is not changed. That
takes the listing to show the inherited version, so a service account that
lists the parent too (`secret.use` there); when it shows none (the
parent is not the account's to list, or its key is a reference), the
provider says so and writes nothing. The same holds for an update or an
import that finds the key inherited with no version listed, such as an
override reset outside Terraform: the plan has nothing to replace, and the
apply refuses.

What is not guarded, on purpose:

- **Destroy** archives whatever the key holds: the archive route takes no
  `replaces`, and nothing is lost, since an archived key keeps its versions.
- **The listing after a write** names the new version's id. If someone
  writes between the two calls, the listing shows their version: the
  provider keeps its number and id as what the key reads (`version`,
  `version_id` and `updated_by` are computed, so any value is consistent
  with the plan), keeps the configured `sensitivity`, and the next plan
  reports drift (section 3). It never takes their version for its own: it
  takes a row as its own only when it is this environment's own live
  value (not archived, not a reference, and not what a parent passes
  down) at the number its write was answered with. Anything else is
  drift. For example, a fork's override reset between the two calls lists
  the parent's row, and the parent may well be at version 1 too: the
  number matches, the row is not the write's, and the next plan reports
  it. An archived key still lists its version, marked `archived`, and the
  next refresh drops it from the state. If the listing fails (a given ID
  token's five-minute session ended between the calls, say), the write
  has landed all the same: the provider saves the state with the number
  written and no id, warns, and the next refresh lists it again, so the
  key is not left made and unrecorded, which the next create would
  refuse as `stale`. One race goes unseen: the key renamed away and
  another made under its name, at the same version number, between the
  two calls, milliseconds apart; the provider then takes the new key for
  its own, and reports no drift on it.

## 5. The one addition to coffre

The write route took `replaces` as a version id only: `null` was a 400. So
a create could not say "only while the key holds nothing", and had two
worse ways:

- **No `replaces`:** a key made by hand, or a value a parent passes down,
  is overwritten without a word. A configuration that names `STRIPE_KEY`
  in an instance that already has one replaces the live value.
- **List, then write:** the same overwrite, for a key made between the two
  calls, and one call more on every create.

The vault already decides `replaces: null` ("no value and no reference,
here or passed down"), for Regenerate and MCP approvals; the route did not
pass it. So the change is one line of the route's schema,
`replaces: rowId.nullable().optional()`, beside a value, typed or
generated, and a dry run refuses a stale one as the write does. It adds:
no route, no migration, and a client that never sends `null` sees nothing
new. It ships first, in a pull request of its own.

Two more were weighed, and are not needed:

- **The write's answer naming the new version's id.** The listing after a
  write gives it (section 4), at one call per write, and a write is rare.
  To drop that listing, the answer would have to name the row and its
  author too (`secret`, `updatedBy`), not just the version's id. It would
  close the one race the listing leaves (section 4), which takes a rename
  and another key made under its name within milliseconds and costs only
  a drift unreported: not worth a second change to the API now.
- **`replaces` on a mark**, a sensitivity changed in place. The provider
  never marks: it writes the value again (section 2), with `replaces`.

## 6. Signing in

One of two, in the provider block. No environment variable of the
provider's own, as coffre's CLI reads none: a value comes from the
configuration, `var.coffre_token` and `TF_VAR_coffre_token` included.

- **`token`**: a service account's bearer credential (`coffre_svc_…`),
  sent as `Authorization: Bearer`. Marked sensitive.
- **`oidc = { service = "terraform" }`**: the CI run's ID token, traded at
  `POST /api/auth/oidc` `{"service": "token:terraform", "token": "<ID token>"}`
  for a five-minute credential, as `coffre login --service` does. In GitHub
  Actions (`permissions: id-token: write`) the provider asks the runner for
  a fresh ID token, audience the instance's URL, each time it needs one;
  elsewhere `id_token = var.ci_id_token` gives it. An ID token is spent by
  its exchange, and a given one serves one command: `terraform plan -out`,
  or the `apply` of a saved plan, each with its own. `terraform apply`
  without a saved plan plans, then applies, as two, and the second is told
  why it is refused (`replayed`). In GitHub Actions, the credential is
  renewed with a fresh ID token before it expires, so a long apply does
  not stop partway; on a given ID token, a command has its one credential,
  five minutes, and is refused past them.

Instances that issue no bearer credential to services (`useOnly`) answer
the exchange 410; their key-bound sign-in (`/api/auth/workload`) is not
in this provider yet.

The URL must be `https`, or `http` on loopback for a local instance. The
client follows no redirect, so a credential never leaves for another host.
It asks again, a few times and within a minute, when coffre answers 429 or
503 with `Retry-After`; it never retries a write that got no answer.

## 7. Nothing of a value leaves the write

- `value_wo` is write-only: Terraform keeps it in neither state nor plan.
  `value_wo_version` is a number the configuration chooses, not a hash of
  the value (a hash would carry it).
- The value is in memory for the write's body, and nowhere else. The
  provider logs places, keys and statuses, never a body; an error says the
  server's `message`, which coffre writes to be shown, never what was sent.
- A plain value comes back in listings; the provider's listing type has no
  field for it, so it is never decoded.
- The credential and ID tokens are sensitive, never logged, and never in
  state.
- A variable that holds a value or a credential is declared
  `ephemeral = true` (Terraform 1.10, OpenTofu 1.11), as the examples do:
  a saved plan keeps every other variable's value, sensitive or not, which
  no provider can change. An ephemeral one is given again to the apply.

The acceptance suite holds every one of these on Terraform and on
OpenTofu: it writes a canary value, then requires that no byte of it, nor
of the credential, appears in the state, in the saved plan (`show -json`
and the raw file), in every command's output under `TF_LOG=trace`, or in
the error of a refused write (section 10).

## 8. Edges

- **An archived key** (`terraform destroy`, then `apply`, or `-replace`):
  coffre refuses a value over an archived key (`archived`), and the provider
  says to bring it back in coffre and import it. Bringing it back from the
  provider would serve the archived value again until the write lands. In
  a fork, an override archived falls back to what the parent passes down,
  and is made again as any override is (section 4).
- **A reference** (`{"ref": …}`) is not managed here. A key made one
  outside Terraform lists no version id, and the write route's `replaces`
  takes a version id or `null`, never a reference's source
  (`{"source": …}`), so no write could say what it replaces: the plan
  reports the drift, and the apply says so and writes nothing.
- **A personal config** (`dev@me`) is a person's; a service account has
  none, so the provider refuses an environment with `@`.
- **A change of `key`** replaces the resource: the old key is archived with
  its history, and a new one is written. Renaming in place is left for later.

## 9. Room for the configuration

The provider is a framework provider (`terraform-plugin-framework`) with an
API client of its own (`internal/coffre`), one file per resource. The
configuration's resources go beside `coffre_secret`, on the same client and
sign-in: `coffre_environment`, `coffre_service_account`, `coffre_trust`,
`coffre_grant`. Later too: the ephemeral `coffre_secret` (section 1),
`useOnly` sign-in (section 6), and a rename that keeps a key's history.

## 10. Where it lives, and how it is checked

`terraform-provider/` at the root: a Go module, outside pnpm's workspace.

- **Unit tests** (`go test ./...`): the client against a fake coffre, each
  attribute's validation, the plan's drift decisions, the sign-in's
  renewal, and that no error text carries what was sent.
- **Acceptance tests** (`TF_ACC=1`): a Node harness boots the Workers
  example as `pnpm conformance:workers` does, on its own database and
  ports, signs its Owner in through the dev IdP and makes a project, a
  fork and a service account with a token and a trust binding. The suite
  then runs create, update, a sensitivity change, drift, a stale saved
  plan, import, a fork's override and destroy, through both sign-ins, and
  the leak check (section 7), once per binary: Terraform and OpenTofu,
  each at 1.11 and at the newest release.
- **CI**: a `Terraform provider` job in Validate runs both, on a change
  under `terraform-provider/` or to the API it calls.
- **Release** (built, not run): GoReleaser builds the provider for each
  platform with its checksums and signature, as the Terraform and OpenTofu
  registries read them. Publishing 0.1.0 is a decision of its own.

# Terraform provider

A Terraform and OpenTofu provider that writes coffre secrets from
infrastructure code, and never holds a value anywhere it keeps:
not in state, a plan, a log or an error. Secrets first, then the
configuration: environments and grants, which CI may apply, and service
accounts and their trust bindings, which a person applies from their own
session (section 9). It needs Terraform 1.11 or OpenTofu
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
      ~ updated_by = "user:ada@acme.example" -> (known after apply)
    }
Warning: billing/prod/STRIPE_KEY was written outside Terraform
  It is at version 8, written by user:ada@acme.example. Applying writes the configured value over it.
```

The same holds when the key was reset to what a parent passes down, or
renamed away and another renamed onto its name: whatever it reads is not
what Terraform wrote. A key made a reference is drift too, but one the
provider does not write over (section 8).

A key that holds nothing leaves the state, and the next plan creates it,
with `replaces: null`: one the listing does not have (renamed away with
nothing renamed onto its name), one listed `archived` (creating over it is
refused; section 8), a fork's key dismissed from what its parent passes
down (`parent.state` is `removed`), and an own key with no version, which a
reference broken in coffre leaves. An inherited key whose version this
account cannot see is not one of them: it holds the parent's value, so it
stays, and an apply over it refuses (section 4).

A deleted or archived environment is different: its listing answers 403
`no_access`, the same refusal a revoked grant or a narrowed role gets, and
coffre means them to look alike. Dropping the state on that refusal would
let a token's lost access empty the state silently, so the refresh fails
instead, saying what coffre answered; who deleted the environment removes
its keys from the configuration, or `terraform state rm`s them.

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

One of three, in the provider block. No environment variable of the
provider's own, as coffre's CLI reads none: a value comes from the
configuration, `var.coffre_token` and `TF_VAR_coffre_token` included. The
third, `session = true`, a person's `coffre login` session, is for the
resources only a person may apply (section 9.1).

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
It asks again, at most five times and within a minute, when coffre answers
429, or 503 to a read, with `Retry-After`; it never retries a write that got
no answer, nor one answered 503, which may come after the write was made.

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

## 9. The configuration

Four resources beside `coffre_secret`. Two a service account may apply,
in CI; two only a person may, from their own `coffre login` session:

| Resource | What it is | Who coffre lets change it | Signs in as |
|---|---|---|---|
| **`coffre_environment`** | a project's environment | `environment.manage` on the project | any (section 6) |
| **`coffre_grant`** | one member's role at one place | `grant.manage` where the grant is | any |
| **`coffre_service_account`** | a service account, and every grant it holds | a person on a session who could set one up there, or whoever runs the instance | a person (`session`) |
| **`coffre_trust`** | one of its trust bindings: which CI runs or workloads sign in as it | a person on a session who manages the account, or whoever runs the instance | a person (`session`) |

coffre keeps whatever can mint a credential with people. A service
account's credential always carries a scope, so it is never "on a
session" (`onSession` in the vault's `ops/services.ts`), and it holds
project grants only, never an instance role, so it never runs the
instance: the vault refuses it `access.grant` with `admit`, `token.bind`
and `token.unbind` whatever it holds. The vault says why: "a service's
token that holds `grant.manage` would make another's tokens, or a new
one of its own past its revocation". The provider does not change that
rule; it signs in as a person, as the CLI does, for the resources that
need one.

```hcl
provider "coffre" {
  url     = "https://secrets.acme.example"
  session = true                   # the session `coffre login https://secrets.acme.example` saved
}

resource "coffre_service_account" "deploy" {
  name   = "deploy"
  grants = { "billing" = "maintainer" }       # every grant it holds, by place
}

resource "coffre_trust" "deploy_main" {
  service = coffre_service_account.deploy.member   # token:deploy
  profile = "github"
  claims  = { repository_owner_id = "9919", repository_id = "41532", ref = "refs/heads/main",
              workflow_ref = "acme/api/.github/workflows/deploy.yml@refs/heads/main" }
  events  = ["push"]
}

resource "coffre_environment" "staging" {
  project = "billing"
  slug    = "staging"
  parent  = "prod"                 # inherits prod: its keys are prod's until it holds its own
}

resource "coffre_grant" "bo" {
  member      = "user:bo@acme.example"
  project     = "billing"
  environment = "staging"          # leave it out for a grant on the whole project
  role        = "developer"
}
```

### 9.1 A person's session

`session = true` signs in with the session `coffre login <url>` saved for
the provider's `url`, a third way beside `token` and `oidc` (section 6),
and the only one `coffre_service_account` and `coffre_trust` take.

- **Where it is read.** `~/.coffre/credentials.json`, the CLI's own file
  (`CREDENTIALS_PATH` in `packages/cli/src/main.ts`; `~` is `$HOME`, as
  Go's `os.UserHomeDir` reads it): its `instances[<origin>]`, the origin
  as the CLI names it (section 6's URL rule). The provider takes it only
  if it is a person's (no `kind`; a saved service token or CI run's is
  `token` or `run`), on coffre's sign-in (`mode: signin`), with a `token`,
  and not past its `expiresAt`. Anything else is refused at configure,
  saying to run `coffre login <url>`.
- **Read, never written.** The provider reads the file once per run and
  keeps the token in memory. It never renews, rewrites or removes it:
  `coffre login` and `coffre logout` own the file. A session that ends
  mid-run (401) fails the call, saying to log in again.
- **Kept nowhere.** `session` is a boolean, so the provider block that
  the plan records holds nothing. The token goes in an `Authorization`
  header and nowhere else: no attribute holds it, no log line names it,
  and an error names the file and the origin, never what is in it. The
  acceptance tests hold every run to it (section 7's leak check, with the
  session's token among the secrets).
- **Tests** never read the developer's file: each run's `HOME` is a
  directory of its own, whose `credentials.json` the fixture's device
  login filled (`coffre_cli_…`), on the run's own deployment and
  database.

### 9.2 A configuration CI applies

The provider knows how it signs in from its own block, before any call.
Signed in with `token` or `oidc`, a `coffre_service_account` or
`coffre_trust` fails at plan, refresh and import, before coffre is asked
anything:

```
Error: coffre_service_account "deploy" is applied by a person
  coffre lets only a person on their own session, or whoever runs the
  instance, set up service accounts and their trust, and this provider
  signs in as a service account (token). Apply it with `session = true`,
  after `coffre login https://secrets.acme.example`, from a configuration
  of its own that CI does not apply.
```

So a team keeps two configurations: one a person applies, with the
accounts and their trust; one CI applies, with the environments, grants
and secrets. The service account CI signs in as is in the first.

### 9.3 No token

Terraform never creates or holds a token. CI signs in through a trust
binding (`coffre_trust`, then `oidc` in the provider block), whose
credentials last five minutes and are never in state. A token a team
still wants (`coffre token issue`) is shown once, when it is made, so a
resource that made one would have to keep it in state or lose it; a
person issues it in the pages or the CLI, as before.

### 9.4 Whoever applied last

The state is whatever the person or account that applied last could see
and change. Someone else applying the same state sees through their own
grants, and each resource says so rather than empty the state:

| Resource | Refresh reads | Gone (leaves the state) | Not visible to whoever applies now (fails the refresh, names who can) |
|---|---|---|---|
| `coffre_environment` | `GET /projects` | archived, or not listed in a project that is | the project is not listed (section 3), or the environment is listed by name alone (`details: null`, to a caller holding a grant on a sibling only), which does not say whether it is archived |
| `coffre_grant` | `GET /members/:member/access` | no grant at the place, while the caller sees every grant there | 403, or a place where the caller does not manage access, whose grants coffre does not show |
| `coffre_service_account` | `GET /members/token:x/access` | 404, or `removed`, to whoever runs the instance or manages access somewhere | 403, or `managed: false`: coffre then shows only the grants at places the caller manages, and the plan would undo the rest. A removed account manages no one's: to anyone else, coffre answers 403 for it too |
| `coffre_trust` | `GET /members/token:x/bindings` | its id not listed, or the account removed (404 `unknown_principal`, to whoever runs the instance) | 403: only the account itself, whoever manages it and whoever runs the instance list its bindings; a removed account's, to anyone else |

Who manages a service account is coffre's rule (`managesService` in
`@coffre/core/access`): whoever runs the instance, or a person who could
give it every grant it holds; one that holds nothing, only the person
who admitted it. So Ada makes `token:deploy` with `billing: maintainer`;
Bo, a Developer on `billing/dev`, plans the same configuration, and the
refresh fails with "user:bo@acme.example does not manage token:deploy",
not with a plan to make it again.

### 9.5 Each resource's life

`coffre_environment`:

| Attribute | Kind | What it is |
|---|---|---|
| `project`, `slug` | required; fixed once made | the environment, by its project's slug and its own, `^[a-z0-9][a-z0-9-]{0,62}$` |
| `parent` | optional; fixed once made | the environment it inherits from, in the same project. None: it inherits nothing |
| `protected` | optional, computed | whether it is protected: in it, a role holds only its protected column (`docs/design/roles.md`). Left out, as coffre makes it: a fork of a protected environment is protected, any other not; once made, as coffre has it |
| `id` | computed | `project/slug`, the import ID too |

| Step | Call |
|---|---|
| create | `PUT /projects/billing/staging` `{"from": "prod", "inherit": true}`, or `{}` with no parent; then `PATCH … {"protected": true}` if asked |
| update | `PATCH /projects/billing/staging` `{"protected": …}` |
| destroy | `PATCH /projects/billing/staging` `{"archived": true}` |

- **Fixed once made.** A change of `project`, `slug` or `parent` is
  refused at plan, saying what to do instead. Replacing would archive
  the environment and make one under the same slug, which coffre
  refuses: an archived environment keeps its slug (`exists`), and only
  an Admin or Owner of the instance deletes one for good. coffre renames
  in one call (`{"slug": …}`), but every `coffre_secret` in it names the
  old slug; a rename is done in coffre, then the resources are imported
  under the new slug. coffre has no call that changes a parent.
- **A copy is not declared.** A fork by copy (`from` without `inherit`)
  is a one-time act the listing does not trace, so a refresh could not
  say whether it still matches: `coffre_environment` makes environments
  that inherit, or nothing.
- **Protection.** Anyone with `environment.manage` protects an
  environment; only an Owner of the project, on their own session, takes
  it off (R30, `docs/design/roles.md`). So `protected` going to `false`
  is refused at plan when the provider signs in as a service account,
  and on a session the listing says whether this person may
  (`unprotectable`), refusing at plan otherwise. coffre protects a fork
  of a protected environment as it makes it, so the plan says so when
  `protected` is left out, and refuses `protected = false` there.
- **Made, then protected.** coffre makes an environment unprotected
  and protects it in a second call. One whose protection fails is in
  the state, unprotected, with the error, and Terraform marks it
  tainted: replacing it would archive it and keep its slug, so the
  error says to `terraform untaint` it, and the next plan protects it.
- **Destroy archives**, and stops there: a deletion erases every value
  and takes an Admin or Owner of the instance. coffre refuses to archive
  one a fork inherits from (`inherited`) or a reference reads
  (`referenced`); the error says which. With `parent =
  coffre_environment.prod.slug`, Terraform destroys the children first.
- **Archived** leaves the state; the next plan creates it, which coffre
  refuses (`exists`), saying to restore and import it. A slug with `@`
  (a personal config) is refused.
- **Forking reads its parent.** coffre makes an inheriting environment
  only for whoever reads its parent (`secret.read` there).

`coffre_grant`:

| Attribute | Kind | What it is |
|---|---|---|
| `member` | required; a change replaces | `user:<email>`, lowercase as coffre keeps it, or `token:<name>` |
| `project` | required; a change replaces | the project's slug |
| `environment` | optional; a change replaces | one of its environments. None: the whole project |
| `role` | required; updates in place | the role's id: one coffre ships (`viewer`, `developer`, …) or a custom one |
| `until` | computed | an end someone set outside Terraform; always planned `null` |
| `id` | computed | `billing/prod/token:deploy`, the import ID: the place, then the member, from the first segment with a `:` |

| Step | Call |
|---|---|
| create | `PATCH /access/token:deploy` `{"billing/prod": {"role": "viewer", "until": null, "was": null}}` |
| update | the same, `"was": {"role": "developer", "until": null}`: the grant the plan's refresh saw |
| destroy | `PATCH /access/token:deploy` `{"billing/prod": null}` |

- **The guard.** A write never overwrites a grant it did not see. Create
  says `"was": null`: a grant made by hand is not taken over (`stale`;
  the provider says to import it). Update says what the plan saw: a plan
  raises Bo from `viewer` to `developer`; before it is applied, Bo's
  grant is revoked over a stolen laptop. Unguarded, the saved plan would
  give it back; guarded, it is refused, and the next plan shows the
  revocation. Revoking is not guarded: it is the safe direction. This
  is the one addition to coffre the configuration needs, `was` on
  `PATCH /access/:member` (#856), which the vault already decided for
  the MCP approvals.
- **No end.** A grant that lapses leaves the listing, and coffre refuses
  an end in the past, so a Terraform-owned end would break every plan
  after it. A grant Terraform owns has none; one found with an end shows
  it in `until`, and the plan makes it standing again.
- **Refused by coffre**, in its words: a grant to someone not a member
  (`not_a_member`, `removed`), to the caller itself, or of a role holding
  a project-wide permission on one environment.
- `grant.manage` gives any role there to anyone but its holder, Owner
  included: a reason to keep grants on an account of their own, apart
  from the one that writes secrets.

`coffre_service_account`:

| Attribute | Kind | What it is |
|---|---|---|
| `name` | required; a change replaces | `deploy`: coffre has no rename |
| `grants` | required, at least one; updates in place | every grant it holds, by place: `{"billing" = "maintainer", "web/prod" = "viewer"}` |
| `ends` | computed | the grants found with an end, by place; always planned empty |
| `member`, `id` | computed | `token:deploy`, the import ID too |

| Step | Call |
|---|---|
| create | `PUT /members/token:deploy` `{"access": {"billing": {"role": "maintainer", "until": null, "was": null}}}`: admitted with its grants, all or none |
| update | `PATCH /access/token:deploy`, each place that changed, guarded by what the plan saw, as `coffre_grant`; a place left out of `grants`, `null` |
| destroy | `DELETE /members/token:deploy` |

- **Every grant it holds.** The resource owns the account's grants: a
  grant made outside Terraform shows as drift and is revoked. So an
  account declared here takes no `coffre_grant`.
- **Create** refuses an account already there (`GET` first, then the
  guard): import it instead. One set up by someone else between the two
  is given the grants asked, `created: false` in coffre's answer: the
  apply fails, saying so, and keeps it out of the state, to import.
- **Destroy removes it**: its grants are revoked, and its tokens, trust
  bindings and sessions end with it. coffre keeps its row, `removed`,
  and brings the name back only for the person who removed it, or
  whoever runs the instance; anyone else's create is refused
  (403 `no_access`, which the provider reads as the removal when its
  `GET` saw one).

`coffre_trust`:

| Attribute | Kind | What it is |
|---|---|---|
| `service` | required; a change replaces | `token:deploy` |
| `profile` | required | `github`, `github-reusable`, `github-reusable-organization`, `gitlab`, `custom`, or a workload's platform: `kubernetes`, `gcp`, `azure`, `fly`, `vercel`, `aws` |
| `issuer` | optional | the issuer's URL; the profile's own when left out (github.com's, gitlab.com's, Google's, `urn:coffre:aws`) |
| `claims` | required | the claims a token must carry, each its exact value |
| `events` | optional | the profile's event claim, several allowed: GitHub's `event_name`, GitLab's `pipeline_source` |
| `claim_prefixes` | optional, `custom` only | claims matched by their start, whole `/`-ended segments: `{sub = "org/1/project/2/"}` (#853) |
| `scope` | optional, computed | what its credentials reach, by place and role. coffre seals it on the binding as it makes it; left out, what the account holds then, or, made in place of another, what that one reached and the account still holds: a change never widens it, so a grant given to the account later reaches its CI runs only once the scope names it |
| `policy` | optional | a workload's binding, for key-bound sessions at `/api/auth/workload`: `audience`, `key_audience`, `sources`, `session_hours`, `unsigned_uploads`, and `repeats` (#853: a `custom` issuer that hands the same token out until it expires). Left out, a `github`, `gitlab` or `custom` binding is a CI run's, for `oidc`; a workload platform's binding is always a workload's, with coffre's defaults; and an instance that issues no bearer credential (`useOnly`) makes every binding a workload's |
| `label` | optional | a label |
| `id` | computed | the binding's id; `token:deploy/<id>` imports it |

| Step | Call |
|---|---|
| create | `POST /members/token:deploy/bindings` `{profile, issuer, claims, scope, policy, label}` |
| update | the same, `"replaces": ["<id>"]`: the new binding made and the old ended in one change, so no run is refused between; its id is new |
| destroy | `DELETE /members/token:deploy/bindings/<id>`: what it issued ends with it |

- **Every change is a new binding.** coffre never edits one; it replaces
  it, atomically. A binding changed outside Terraform (re-keyed,
  replaced) is not listed under its id any more: it leaves the state and
  the next plan makes it again, beside the other. So the binding listed
  under the state's id is the one the state made: a refresh keeps the
  configuration's spelling (a CIDR coffre writes another way, a policy
  coffre fills in), and reads the listing into the state only on import.
- **Unknown at plan.** A value known only at apply, even one element of
  `claims`, `events` or `sources`, plans a new binding: the plan cannot
  tell it is the same one.
- **Checked by coffre**, in its words, before the issuer is asked
  anything: the claims each profile requires, a prefix that stops in a
  segment, `repeats` beside `key_audience`, a scope wider than what the
  account holds, a sensitive place only an Owner of its project binds
  (R32).
- **Left out**: enrollment and Cloudflare bindings, uploaded keys
  (`jwks`), and `reads`, the policy's escape hatch by id.

### 9.6 What each signs in with, and holds

| Resources | Signed in as | It needs, on the project |
|---|---|---|
| `coffre_secret` | any | `secret.use`, `secret.write`, `secret.archive` (section 2) |
| `coffre_environment` | any | `environment.manage`; `secret.read` on each parent it forks |
| `coffre_grant` | any | `grant.manage` |
| `coffre_service_account`, `coffre_trust` | a person (`session`) | what coffre asks to set up and manage the account: every grant it gives it, or running the instance |

In a protected environment a role holds only its protected column: an
environment Terraform protects keeps working for its account only if its
role lists `secret.use`, `secret.write` and `secret.archive` there too,
as `maintainer` does.

Left out: **roles**, which are the whole instance's and changed by its
Owner after a preview of whom a change reaches (`?dryRun=1`, then
`?revision=`), which a plan cannot show; **projects**, made by an Admin or
Owner of the instance; and **tokens** (9.3). Also later: the ephemeral
`coffre_secret` (section 1), `useOnly` sign-in (section 6), and a rename
that keeps a key's history.

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
- **CI**: a workflow of its own, `Terraform provider`
  (`.github/workflows/terraform-provider.yml`), runs both, on a change
  under `terraform-provider/` or to the API, sign-in or vault write it
  calls.
- **Release** (built, not run): GoReleaser builds the provider for each
  platform with its checksums and signature, as the Terraform and OpenTofu
  registries read them. Publishing 0.1.0 is a decision of its own.

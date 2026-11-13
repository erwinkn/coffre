# Instance roles with scopes

This note says who holds what across an instance's projects. It
replaces the grants on every project of 0.4 ([instance-grants.md](instance-grants.md)).

- **A person has one instance role**, with a **scope**: what they hold in every project the
  scope takes in, the ones made later too.
- **A grant is on a project or an environment**, and only adds to the role.
- **A service account has grants only**, never an instance role.

## The roles

As they ship; an Owner may edit them, and protected environments narrow them ([roles.md](roles.md)).

| Instance role | Holds, inside its scope | Reads values |
|---|---|---|
| Member | nothing: only what projects grant | no |
| Auditor | `audit.read` | no |
| Developer | `secret.read`, `secret.use`, `secret.write` | yes |
| Admin | `audit.read`, `environment.manage`, `grant.manage`, `project.manage`; people and service accounts | no |
| Owner | every permission, `secret.archive` too | yes |

## The scope

Two filters, each `all`, `only [...]` or `all except [...]`: **projects** by id (a rename keeps
them in or out) and **environments** by slug (`dev` is the `dev` of every project, later ones too).

| Scope | Reaches |
|---|---|
| projects all, environments only [dev] | every project's `dev` |
| projects all except [billing] | every project but billing, and every new one |
| projects only [web, api] | web and api, and nothing made later |

A project **as a whole** is in a scope only when the scope keeps all of its environments. So an
Admin scoped to `dev` manages `market/dev`'s grants, not `market`'s: a grant on `market` would reach
`market/prod`.

## The check

One function in core, `allows` (`packages/core/src/access.ts`), which the app and the vault both
ask: the credential's scope, if any, must allow it ("Credentials' scopes", below); then the
instance role inside its scope, or any grant that covers the place, gives it. Ada is a Developer,
environments only [dev], with `viewer` on `billing`:

| Place | `secret.read` | `secret.write` | Why |
|---|---|---|---|
| `market/dev` | yes | yes | her role, inside its scope |
| `market/prod` | no | no | outside it, and no grant |
| `billing/prod` | yes | no | her grant on billing |
| `billing` (renaming it) | no | no | `project.manage` is no Developer's |

## Who runs the instance

**Running the instance** takes an Admin or Owner whose scope narrows nothing (`runsInstance`):
adding and removing people, setting instance roles, the instance's settings, offboarding reports,
deleting an archived project or environment for good, and managing every service account.

**Reading the whole log** takes `audit.read` from an instance role whose scope narrows nothing
(`readsWholeLog`): the instance's own entries (sign-ins, people, service accounts, settings) beside
every project's, and `coffre verify log`, which a part of the log cannot verify. A scoped Auditor
reads its places' entries, never the instance's own, and verifies nothing.

**A scoped Admin** manages environments and grants only on the places its scope takes in, never
sets an instance role, and makes a project only when its scope takes new ones in whole (projects
`all` or `all except`, environments `all`: `makesProjects`).

- **Nobody changes their own instance role or scope, nor grants themselves a role** (`not_allowed`).
  Giving one up is fine. The one exception is an Owner of the whole instance, who holds all there is
  and so may change their own role, stepping down included (`ownsInstance` in
  `packages/vault/src/vault.ts`).
- **An Admin holds no secret permission, and that is no boundary.** It can grant a reading role to
  someone else, or reach any value in its scope in three logged steps: admit a service account,
  grant it `owner` on a project, issue its token. Keep Admins to people you would trust with the
  values, and read the log for those steps.

## Setting up service accounts

Anyone who holds access sets up service accounts for it, CI above all, without an Admin, inside an
instance setting, **Who sets up service accounts**: a scope as a role's is. It is everywhere until
someone who runs the instance narrows it; each change is a `settings.change` entry.

| Setting | A Developer of every environment sets up | Who sets up prod's |
|---|---|---|
| everywhere | dev's, staging's and prod's | the same Developer, or an Admin |
| environments all except [prod] | dev's and staging's | an Admin whose scope takes in prod |
| projects only [] | none | an Admin, inside its scope |

Inside the setting, a person who holds access somewhere (`setsUpServices`):

- **adds a service account**, empty or with its first grants in one vault decision: a grant refused
  adds nothing, so no account is left without the access it was made for;
- **gives it a grant** where they hold everything the role does (`givesService`): a Developer of
  `market/dev` gives `viewer` or `developer` there, never `maintainer`, nor `market`, which takes
  holding all of `market`;
- **manages it** (`managesService`) while they could give every grant it holds: its tokens, its
  trust bindings, its grants, its removal. A Developer of `dev` manages no account that also holds
  `market/prod`, whoever gave it that.

Whoever manages access on a place gives any role there, setting or not. A person's lists show only
the accounts they manage. Four rules close what "could give every grant" leaves open:

- **An account with no grant is its maker's**, and theirs who run the instance: otherwise anyone
  could issue a token for an Admin's new, empty account before the Admin grants it prod.
- **Losing access loses the accounts.** A maker who leaves or is narrowed no longer manages what
  they no longer reach. Its tokens and bindings keep working until revoked: offboarding a person
  lists the tokens they issued (`issuedTokens`).
- **A wider grant widens no credential**: each token and binding has its own scope (below).
- **A removed account is its remover's.** A person brings back only an account they removed
  themselves; otherwise anyone who sets up accounts could undo an Admin's removal.

The setting names environments by slug, so it is policy, not a boundary, for those who rename
environments: a Maintainer of `market` who renames `market/prod` to `market/production` takes it
out of `all except [prod]`. They gain no read they did not hold, and the rename is logged. To keep
prod to Admins, give those you would not trust with its service accounts less than Maintainer.

The vault reads the setting from its newest `settings.change` that carries its MAC, and reports any
in its name it did not write. It looks back 1024 entries at most; when there are such entries but
none of its own within reach, the setting is closed (`projects only []`), so inserting rows into
the log never opens it. Only a log with no `settings.change` at all means everywhere.

## Credentials' scopes

Every service token and trust binding carries its own **scope**: grants, as its account's are. It
is fixed when the credential is made. A request made with it holds what both the scope and the
account hold then:

| | `market/dev` | `market/prod` |
|---|---|---|
| ci-web holds | `developer` | `viewer`, given after the token |
| its token's scope | `developer` | |
| a request with the token | reads and writes | nothing |
| once ci-web holds only `viewer` on `market/dev` | reads | nothing |

So widening an account widens none of its credentials, and narrowing it narrows them all at once.
A scope lists grants, not a role's filters: a filter that takes in places made later would let a
grant given later through. A grant on a project does reach environments made in it later, as the
account's own grant does: no wider than the account.

**Making one.** Whoever manages the account makes a credential whose every grant the account holds
and they could give it (`issuesCredential`); a refusal is logged `beyond_account`. Left out, the
scope is everything the account holds; for a binding that replaces others, what those reached of
it, so trusting a workload again never widens it. A scope that reaches nothing is refused. It never
changes after: make another and revoke the first. Its issuer losing access later shrinks nothing,
so CI keeps working when they leave.

Each grant of a scope also keeps whether its issuer was an Owner of its project (`sensitive`): only
then does the credential read that project's sensitive values (`readsSensitive`; [roles.md](roles.md)).

**Where it is enforced.** The app checks the scope on every request and passes it to every vault
call (`credentialScope`); the vault decides on it too, so a token scoped to `dev` asking the vault
for a `prod` value is refused and logged. A CI run's credential carries its binding's scope. A
person's personal tokens carry one of the same shape ([personal-tokens.md](personal-tokens.md)).

**Where it lives.** A `scope` column on `credentials` and `service_bindings`, the grants as JSON,
places by id, under the row's app MAC (`auth_mac`) and vault seal: a scope changed or cleared
around the app fails them, and the credential is refused. A credential left with no scope from
before scopes existed is sealed with what its account holds, once per process (`sealScopes`) or at
its first use (`sealCredentials`), each logged `token.seal`.

## Owners of the whole instance

An Owner whose scope narrows nothing (`ownsInstance`) is a member like any other, under the rules
above. An Owner scoped to `market` owns market, not the instance.

**The instance always has one.** The last active Owner of the whole instance is not demoted,
narrowed or removed, by anyone, themselves included (`last_owner`). The vault counts the others
under the log's head, not only the rows it locks: Ada removing herself while Omar steps down lock no
row in common, and a count under the rows alone would let both pass. `formal/Coffre.tla` checks it
(`OwnerStays`).

**The deployment declares its Owners.** The vault's `owners` (`OWNERS` in a deployment `coffre init`
writes; the deprecated `bootstrapOwners` and `rootAdmins` are read as it) names at least one person
who is an Owner of the whole instance whatever the database says. At the first call of each process,
and when a listed person who owns nothing signs in, the vault admits them, brings them back or gives
them the role, as `system:vault`, `reason: 'owners'`. That is how a new instance's first sign-in
works, and how one whose Owners are all locked out recovers: add an email you control, deploy, sign
in. While listed, nobody demotes or removes them (`not_allowed`), and their Owner tag says "Set by
deployment". Taking an email off the list demotes nobody.

**Only Owners make Owners.** Making someone an Owner, scoped or not, and changing or removing an
Owner, takes an Owner of the whole instance; the vault refuses anyone else, an unscoped Admin too.
So an Admin cannot make itself or a friend an Owner and read every value, nor push an Owner out. It
decides under the actor's and the subject's rows, locked first, so neither role changes before it
commits.

A member's row that fails the vault's check holds nothing, an Owner's too, and is reported. The vault
changes no such member, nor makes a listed one an Owner, until the row is as the vault wrote it.

## Where it lives

On `principals`, which only the vault writes: `role` (the instance role, `INSTANCE_ROLES`), `scope`
(JSON, projects by id; null for everywhere) and `owner` (whether the role is Admin or Owner, for
older readers). The row's MAC and seal cover them: one written around the vault fails, and the vault
refuses that member. `member.add` and `member.restore` log `role` and `scope`; a change is
`member.role`, with `previousRole` and `previousScope`.

0.4's grants on every project (`*`, `*/dev`) are replaced by the vault once per process, before its
first call does anything else (`#convert`), by `convertEveryProjectGrants` in core: the strongest
instance role they add up to without granting more, the rest as grants on each project there is now
(`reason: 'every-project'`). A property test holds it to taking nothing away but what it names, and
`coffre migrate` lists what it will make of each member.

## Where it shows

- **API.** `GET` and `PUT /api/settings`: `{ "serviceAccounts": <scope> }`, for those who run the
  instance. `GET /api/me`: `setsUpServices` and `serviceSetup`. `PUT /api/members/<member>`: `{ role,
  scope }`, projects by slug, or for a service account `{ access }`, its first grants. Members list
  `instanceRole`, `scope` (null but for those who run the instance: it names projects the caller may
  not see) and `managed`. `POST /api/members/<member>/tokens` and `/bindings` take a `scope` by path:
  `{ "market/dev": "viewer" }`.
- **CLI.** `coffre admit <member> --role <role> [--projects …] [--environments …]`; `coffre settings
  service-accounts --except-environments prod`; `coffre tokens issue <service>` and `coffre trust`
  take `--scope market/dev=viewer,…`. Through MCP, `admit_member`, `issue_service_token` and
  `trust_workload` take the same; the setting is the pages' and the CLI's alone.

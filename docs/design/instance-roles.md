# Instance roles with scopes

Written on 2026-10-10, from Erwin's decisions that week (D82, D84; the
Auditor's log, D96; people setting up service accounts, D97 and D99). It
replaces the grants on every project of 0.4 ([instance-grants.md](instance-grants.md)).

0.4 had two ways to reach many projects: an instance role, `user` or
`owner`, and grants on every project, `*` and `*/<environment>`. People
found the split confusing: an owner managed everything but read nothing,
and reading everywhere took a grant on `*` beside it. 0.5 keeps one of each:

- **A person has one instance role**, with a **scope**: what they hold in
  every project their scope takes in, the ones made later too.
- **A grant is on a project or an environment**, and only adds to the role.
- **A service account has grants only.** It is always a member.

## The roles

| Instance role | Holds, inside its scope | Reads values |
|---|---|---|
| Member | nothing: only what projects grant | no |
| Auditor | `audit.read` | no |
| Developer | `secret.read`, `secret.write` | yes |
| Admin | `audit.read`, `environment.manage`, `grant.manage`, `project.manage`; people and service accounts | no |
| Owner | everything an Admin holds, and every secret permission, `secret.archive` too | yes |

Root admins, named in the vault's configuration, are Owners everywhere and
cannot be changed. Project roles (viewer, developer, maintainer,
access-manager, auditor, owner) are unchanged.

## The scope

Two filters, each `all`, `only [...]` or `all except [...]`:

- **Projects**, by id: a rename keeps them in or out.
- **Environments**, by slug: `dev` is the `dev` of every project, those
  made later too.

| Scope | Reaches |
|---|---|
| projects all, environments all | everything |
| projects all, environments only [dev] | every project's `dev` |
| projects all except [billing] | every project but billing, and every new one |
| projects only [web, api] | web and api, and nothing made later |

A project **as a whole** is in a scope only when the scope keeps all of its
environments. So an Admin scoped to `dev` manages `market/dev`'s grants, but
not `market`'s: a grant on `market` would reach `market/prod`. And a
Developer scoped to `dev` reads every `dev`, never a project around one.

## The check

Still one function in core, `allows`, which the app and the vault both ask:

```ts
allows(holder, permission, place) =
  holder.isRootAdmin
  || (INSTANCE_ROLES[holder.role] holds permission && inScope(holder.scope, place))
  || holder.grants.some((grant) => covers(grant, place) && ROLES[grant.role] holds permission)
```

For example, Ada is a Developer, projects all, environments only [dev], and
holds `viewer` on `billing`:

| Place | `secret.read` | `secret.write` | Why |
|---|---|---|---|
| `market/dev` | yes | yes | her role, inside its scope |
| `market/prod` | no | no | outside it, and no grant |
| `billing/prod` | yes | no | her grant on billing |
| `billing` (renaming it) | no | no | `project.manage` is no Developer's |

## Who runs the instance

**Running the instance** takes a root admin, or an Admin or Owner whose
scope narrows nothing (`runsInstance`): adding and removing people,
setting instance roles, the instance's settings, a member's offboarding
report, deleting an archived project or environment for good. They manage
every service account too; people set up their own where the setting lets
them ("Setting up service accounts", below).

**Reading the whole log** takes `audit.read` from an instance role whose
scope narrows nothing: an Auditor, Admin or Owner everywhere, or a root
admin (`readsWholeLog`). They read the instance's own entries, sign-ins,
people, service accounts and settings, beside every project's, and verify
the log whole (`coffre verify log`), which a part of it could not be. An
Auditor of the whole instance changes none of what it reads about: it runs
nothing. A scoped Auditor reads the entries of the places in its scope, and
verifies nothing.

A **scoped Admin** manages only inside its scope: environments and grants,
people's and service accounts' alike, on the places its scope takes in. It
makes a project only when its scope takes new ones in as a whole (projects
`all` or `all except`, environments `all`: `makesProjects`). Its Users and
Service accounts pages list everyone, with the grants it manages; nobody
else's.

Nobody hands out more than they reach:

- A scoped Admin gives and takes grants only inside its scope, and never
  sets an instance role.
- **Nobody changes their own instance role or scope**, not even an
  unscoped Admin: another admin does it, and the log says who.
- An Admin holds no secret permission, scoped or not, and **nobody grants
  themselves a role** (giving one up is fine; a root admin, who reads
  everything anyway, is exempt). That stops a quiet read of one's own, and
  is no boundary: an Admin can grant a project role that reads to someone
  else, as an access manager can in a project, and an Admin can reach any
  value in its scope in three steps, each in the log, by admitting a
  service account, granting it `owner` on a project and issuing its token,
  as a 0.4 owner could. An Admin scoped to market, which manages market's
  grants, manages an account that holds only market's, its tokens
  included. Keep Admins to people you would trust with the values, and
  read the log for those steps.
- An Auditor of the whole instance reads all of the log; a scoped one, the
  projects and environments in its scope, never the instance's own entries.

## Setting up service accounts

Anyone who holds access sets up service accounts for it, CI above all,
without an Admin, inside an instance setting that keeps some places to
Admins: **Who sets up service accounts**, a scope as a role's is (projects
by id, environments by slug, so `prod` is every project's `prod`, later
ones too). Everywhere, until someone who runs the instance narrows it;
only they change it, and each change is a `settings.change` entry, with
what it was.

| Setting | A Developer of every environment | Who sets up prod's |
|---|---|---|
| everywhere | dev's, staging's and prod's | the same Developer, or an Admin |
| environments all except [prod] | dev's and staging's | an Admin whose scope takes in prod |
| projects only [] | none | an Admin, inside its scope |

Inside the setting, a person who holds access somewhere
(`setsUpServices`):

- **adds a service account**, which holds nothing yet;
- **gives it a grant** on a place where they hold everything the role
  does (`givesService`): a Developer of `market/dev` gives `viewer` or
  `developer` there, never `maintainer` or `owner`, nor `market`, which
  takes holding all of `market`;
- **manages it** (`managesService`) while they reach every grant it holds:
  issue, list and revoke its tokens, add and remove its trust bindings,
  change and take away its grants, remove it. A token reads everything its
  account holds, so a Developer of `dev` manages no account that also
  holds `market/prod`, whoever gave it that.

Outside the setting, or beyond what they hold, nothing changes: an Admin
gives and takes grants where its scope reaches, as before, and with them
manages the accounts whose grants all lie there. Who runs the instance
manages every account.

For example, prod kept to Admins (environments all except [prod]), Ada a
Developer of every `dev`:

| Ada asks to | Answer |
|---|---|
| add `ci-web` | yes, logged `member.add` by her |
| give it `developer` on `market/dev` | yes |
| give it `viewer` on `market/prod` | no: outside the setting, and she holds nothing there |
| give it `maintainer` on `market` | no: she holds neither the project nor that role |
| issue a token for it, or trust `ci.yml` to sign in as it | yes, while it holds only what she reaches |
| the same, once an Admin gives it `viewer` on `market/prod` | no: she does not reach prod |

Every step is in the log, with who took it. A person's lists show them
only the accounts they manage, each with everything it holds, which they
reach anyway; no other account, no person, and no scope (D95).

Three rules close what reaching every grant leaves open:

- **An account with no grant is its maker's.** Only the person who added
  it, as its row says, and those who run the instance, manage it until it
  holds something: otherwise anyone could issue a token for an Admin's new,
  empty account before the Admin grants it prod.
- **Losing access loses the accounts.** An account stays as it is when its
  maker leaves or is narrowed; whoever reaches its grants manages it, and
  they no longer do. Its tokens and bindings keep working until revoked,
  as anything an Admin issued does: offboarding a person lists the tokens
  they issued (`issuedTokens`), to revoke.
- **A wider grant widens its credentials.** An Admin who gives prod to an
  account a Developer set up for dev gives it to the tokens and bindings
  that Developer made, which the account's page lists, by who made each.
  Read them before granting it more.

No one grants a person through this, nor themselves (D91), nor a role any
wider than their own: a service account a person sets up reads, at most,
what that person reads.

## Where it lives

Two nullable columns on `vault_members`, beside `owner`, from migration
`0002_instance_roles` on both engines:

| Column | Holds |
|---|---|
| `role` | the instance role; null on a row no vault of 0.5 wrote, which `owner` says all of (an owner of 0.4 is an Admin) |
| `scope` | the scope as JSON, projects by id; null for everywhere |

The vault writes `owner` too, as whether the role is Admin or Owner, for a
vault of 0.4 to read. It is an expand migration: 0.4 runs on the new schema
and never reads the new columns. The vault's login gains `UPDATE (role,
scope)`.

**The member's MAC covers them.** The member tuple's `owner` slot becomes
the role and scope: `false` and `true` as before for a Member or an Admin
everywhere, so every row 0.4 sealed holds as it is; `[role, scope]`
otherwise, which no row of 0.4 matches. A role or scope written around the
vault fails the MAC, and the vault refuses that member as it does today.

**The log.** `member.add` and `member.restore` say `role` and `scope`;
changing them is `member.role`, with `previousRole` and `previousScope`.
`coffre verify log` replays them (and `member.owner` entries of 0.4, an
owner being an Admin).

Rolling back to 0.4: a Member or Admin everywhere reads as before; anyone
else fails 0.4's MAC check and is refused until an owner removes them. It
fails closed.

## Replacing the grants on every project

Rows can only be sealed by the vault, so the vault replaces them, not the
SQL migration: once per process, before its first call does anything else
(`#convert`), one decision per member holding any, logged as
`system:vault`. A grant on every project left behind reaches nothing
anyway: core's `covers` knows only projects and environments. The first
request after the upgrade waits for it, one member after another, so on an
instance with many holders it may be slow; one cut short leaves the rest
to the next. Two kinds of holder it leaves as they are: a member the vault
has reported tampered with (`vault.tampered`), until their access next
changes or they are started over, and a root admin while they are one,
who holds everything anyway; once they are not, the next process converts
theirs. The first is the vault's report in the log, not whether their row
checks out now: a genuine row put back after a report stays left, as
`coffre migrate`, which holds no key to check a row, says. `coffre migrate`
leaves out the first; the second it cannot tell, since the vault's
configuration names root admins and the database does not.

The rule (`convertEveryProjectGrants`, in core, with a property test that
nobody ends up holding more anywhere, at any time, including in a project
made later): pick the strongest instance role their grants on every project
add up to without granting more, then give whatever is left as project
grants on the projects there are now. A service account gets only the
latter.

| Before (0.4) | After (0.5) | Narrower? |
|---|---|---|
| developer on `*` | Developer, everywhere | no |
| developer on `*/dev` (and `*/staging`) | Developer, environments only [dev, staging] | no |
| auditor on `*` | Auditor, everywhere | no |
| viewer on `*` | Member, `viewer` on each project there is now | later projects |
| maintainer on `*` | Developer everywhere, `maintainer` on each project there is now | later projects lose archive and environments |
| owner on `*` | Developer everywhere, `owner` on each project there is now | later projects lose the rest |
| owner (instance) | Admin, everywhere | no |
| owner (instance), and owner or maintainer on `*` | Owner, everywhere | no |
| owner (instance), and developer on `*` | Admin everywhere, `developer` on each project there is now | later projects |
| any grant on `*` with an end date | the same role and end date on each project there is now | later projects |
| service account, developer on `*/dev` | `developer` on each `dev` there is now | later projects |

A place holds one grant per member. Where a member already holds one
there, the new one takes its place if it holds all the old one does, for
at least as long, and is left out if the old one holds all of it. Neither
taking away what they hold in a project there is now:

| Before (0.4) | After (0.5) | Narrower? |
|---|---|---|
| viewer on `*`, auditor on billing | auditor on billing, `viewer` on each of billing's environments | billing's later environments |
| viewer on `*`, developer on billing until June | developer on billing until June, `viewer` on each of its environments | the same |
| service account, auditor on `*`, viewer on billing | auditor on billing, `viewer` on each of its environments | the same |
| service account, maintainer on `*`, access-manager on billing | maintainer on billing | loses access-manager there |
| viewer on `*/dev`, auditor on billing/dev | viewer on billing/dev | loses auditor there |

On a project, one of the two goes on to each of its environments instead,
which reaches what it did but for environments made later (`narrowed:
[{ kind: 'environments', ... }]`); the one that reads no log goes, as an
environment's grant reads none of its project's entries. Only roles an
environment takes can go (viewer, developer, auditor). Where neither can,
or on an environment, one is lost: the one that reads stays, else the one
they held (`narrowed: [{ kind: 'lost', ... }]`), and `coffre migrate`
names it before you deploy ("loses access-manager on billing (keeps
maintainer)"). The property test holds the conversion to taking nothing
away, at any time, in any place there is now, but what it names. Each grant
replaced is an `access.revoke` whose payload says what replaced it
(`replacedBy`) and what it no longer reaches (`narrowed`); each project
grant given is an `access.grant` with `reason: 'every-project'`.

## Where it shows

- **API.** `GET` and `PUT /api/settings` read and set
  `{ "serviceAccounts": <scope> }`, for those who run the instance.
  `GET /api/me` says `setsUpServices`, and `serviceSetup`, the setting with
  the projects the caller sees. Members and a member's access say
  `managed`, for an account the caller manages; removing one answers its
  `report` only to those who run the instance.
  `PUT /api/members/<member>` takes `{ role, scope }`, the scope's
  projects by slug: `{ "role": "developer", "scope": { "environments": { "only": ["dev"] } } }`
  (either filter left out is `all`). Members list `instanceRole` and
  `scope`, which is null but for those who run the instance: a scope names
  projects the caller may not see. `GET /api/members?path=market` lists those who reach `market` by
  their instance role too, with no grant. `GET /api/members/<member>/access`
  answers one member's role, scope and the grants the caller manages in one
  SQL query, for their page. `PATCH /api/access/<member>`
  takes projects and environments only: `*` is a 400. Making a project or
  an environment no longer answers `inherited`.
- **CLI.** `coffre members add <member> --role <role> [--projects …]
  [--environments …]`; `coffre grant` takes a project or an environment;
  `coffre settings service-accounts --except-environments prod` sets the
  setting, `coffre settings` shows it. `coffre offboard` of an account its
  manager runs removes it, without the report.
- **MCP.** `admit_member` takes `role` and `scope`; `set_access` takes
  projects and environments; tools for running the instance are listed to
  those who run it, and those for service accounts to anyone who holds
  access, each checked against the account as the API checks it. The
  setting itself is the pages' and the CLI's, as permanent deletion is.
- **UI.** A person's role is one dropdown, with a compact scope editor
  under it for every role but Member. "Grant on every project" is gone; a
  service account's Access tab grants on projects and environments only,
  and to someone who set it up, only what they may give. Service accounts
  is in the sidebar of anyone who sets one up, listing those they manage;
  Settings edits who sets them up with the same scope editor.

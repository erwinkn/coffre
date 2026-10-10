# Instance roles with scopes

Written on 2026-10-10, from Erwin's decisions that week (D82, D84). It
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
scope narrows nothing (`runsInstance`): adding and removing people and
service accounts, setting instance roles, service tokens and trust
bindings, a member's offboarding report, the instance's own log entries
(sign-ins, people), verifying the whole log, deleting an archived project
or environment for good.

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
- Managing access never reads a value: an Admin reads none, scoped or not,
  and **nobody grants themselves a role** (giving one up is fine). An Admin
  can grant a project role that reads to someone else, as an access manager
  can in a project, and the grant is in the log; only a root admin, who
  reads everything anyway, is exempt.
- An Auditor reads the log of the projects and environments in its scope,
  never the instance's own entries.

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
anyway: core's `covers` knows only projects and environments.

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

Where a member already holds a project grant at a place, it stays unless
the new one holds all it does for at least as long; otherwise it is kept
and the case is logged (`narrowed: [{ kind: 'kept', ... }]`). Each grant
replaced is an `access.revoke` whose payload says what replaced it
(`replacedBy`) and what it no longer reaches (`narrowed`); each project
grant given is an `access.grant` with `reason: 'every-project'`.

## Where it shows

- **API.** `PUT /api/members/<member>` takes `{ role, scope }`, the scope's
  projects by slug: `{ "role": "developer", "scope": { "environments": { "only": ["dev"] } } }`
  (either filter left out is `all`). Members list `instanceRole` and
  `scope`; `GET /api/members?path=market` lists those who reach `market` by
  their instance role too, with no grant. `GET /api/members/<member>/access`
  answers one member's role, scope and the grants the caller manages in one
  SQL query, for their page. `PATCH /api/access/<member>`
  takes projects and environments only: `*` is a 400. Making a project or
  an environment no longer answers `inherited`.
- **CLI.** `coffre members add <member> --role <role> [--projects …]
  [--environments …]`; `coffre grant` takes a project or an environment.
- **MCP.** `admit_member` takes `role` and `scope`; `set_access` takes
  projects and environments; tools for running the instance are listed to
  those who run it.
- **UI.** A person's role is one dropdown, with a compact scope editor
  under it for every role but Member. "Grant on every project" is gone; a
  service account's Access tab grants on projects and environments only.

# Grants on every project

Written on 2026-10-05, from Erwin's decision that day: a member can hold a
role on every project, including the ones created later, or on one
environment name in every project. Revised as built, the same day.

Today a grant gives one member one role at one place: a project
(`market`), or one of its environments (`market/prod`). Two new places
join them, written as paths like the others:

| Place | Covers | Example |
|---|---|---|
| `*` | every project, and every environment in it | `coffre grant '*' user:ada@acme.example --role auditor` |
| `*/<environment>` | the environment of that name in every project | `coffre grant '*' user:ada@acme.example --role developer --env dev` |

Say Ada holds `developer` on `*/dev`. She reads and writes `market/dev`
and `billing/dev`, and the `dev` of a project created next year, but
never `market/prod`, and nothing about `market` itself: an environment's
grant never reaches up to its project.

Everything else is what a grant already is: one role, an optional end
date, its entries in the log, and its end when the member is removed. A
role with a project-wide permission (`maintainer`, `access-manager`,
`owner`) goes on `*` but not on `*/dev`, as it goes on `market` but not on
`market/dev`.

**Only instance owners and root admins grant or revoke them.** An
`access-manager` on `market` manages `market`'s grants and nothing wider;
`owner` on `*` manages every project's grants, but not the grants on `*`.

## Where they live

In `vault_grants`, beside every other grant, with one new nullable column,
`environment_slug`. A row names its place by which columns it fills:

| Place | `project_id` | `environment_id` | `environment_slug` |
|---|---|---|---|
| `market` | market's id | null | null |
| `market/dev` | null | dev's id | null |
| `*` | null | null | null |
| `*/dev` | null | null | `dev` |

Its checks are loosened to allow the last two rows, and no more: the slug
is a slug, a role on a slug is one assignable to an environment, and two
new unique indexes keep one grant per member on `*` and one per slug.

The first draft put them in a table of their own. The previous release's
conformance rules that out: it holds the vault's database login to writing
`vault_members`, `vault_grants` and the log, and nothing else, so a new
table the vault writes fails it (`test:compat`). Changing a check is the
other expand migration: every row the previous release writes passes the
new checks, and it never reads the new column. On SQLite, which changes a
check only by building the table again, the migration does that.

**The member's MAC covers them.** The vault seals each member's row
together with their grants as one sorted set (`rows.ts`). Instance grants
join that set as tuples of a new kind, `['every-project', environment_slug,
role, expires_at, granted_at, granted_by]`. A member with none has the same set,
and so the same MAC, as before. A row inserted, edited or deleted around
the vault fails the MAC, and the vault refuses that member, as it does
today for `vault_grants`. Replaying the log (`coffre verify log`) rebuilds
them too, so a row the log never gave is named.

## The access decision

The decision is still one function in core, `allows`, which both the app and
the vault call. A grant now covers a place when:

| Grant | Covers `market` (the project) | Covers `market/dev` |
|---|---|---|
| `market` | yes | yes |
| `market/dev` | no | yes |
| `*` | yes | yes |
| `*/dev` | no | yes, by the slug `dev` |

Grants add up: someone with `viewer` on `*` and `developer` on `market`
writes in `market` and reads everywhere else. There is no deny.

To match `*/dev`, the decision needs the environment's slug, not just its
id. The vault reads it itself, from the `environments` table, in the
decision's transaction, rather than trust the path the app sends; and only
when the member holds a grant on an environment name, so nobody else pays
for the lookup. An environment whose project is not the one the request
names matches no name.

**Matching is on the environment's slug, exact, at the time of each
decision.** That gives:

- **A project without that environment:** the grant reaches nothing in it,
  and the project is not listed for them. Once someone creates
  `billing/dev`, it reaches it.
- **A rename:** renaming `billing/staging` to `billing/dev` brings it in;
  renaming `billing/dev` to `billing/development` takes it out. This lets
  someone with `environment.manage` on a project widen who reads one of its
  environments. It gives them nothing they lack: they read those secrets
  already, and could create a `dev` and copy them over. The rename is in the
  log, and the API's answer to it names who gains access by the new slug.
- **Archived environments:** a grant on `*/dev` covers an archived `dev`
  exactly as a grant on `billing/dev` would. Archiving stops reads and writes
  through the app's rules for archived places, the same for every grant.
  Slugs stay unique among a project's environments, archived ones included,
  so an archived `dev` and a live `dev` never coexist.

## The migration

One migration, `0005_instance_grants`, on both engines: add the column,
replace two checks with looser ones, and add a check on the slug and two
unique indexes. The logins' privileges are the table's already. Every row
the previous release writes passes the new checks, so it runs on the new
schema unchanged (`pnpm test:compat` holds it to that).

The other half of expand, then contract: this release runs on the schema
before its migration, until the migration runs. Drizzle names every column
it knows in a select and in an insert, so a grant read or written through it
would fail on a table without `environment_slug`. Grants go through
`@coffre/db/grants` instead, for the vault and the app's lists alike: it
reads `SELECT g.*`, whatever columns the table has, and names
`environment_slug` in an insert only for a grant that has one. Until the
migration has run, by the migrator's ledger, the API answers a grant on
every project with 503, "an owner runs `coffre migrate`", and the vault
refuses one on its own too (`sync-removal.test.ts` runs this release on the
baseline schema).

Rolling back to the previous release once instance grants exist: its vault
reads them as grants on no project, which reach nothing, and seals a
member's grants in the older form, so a member who holds one fails its MAC
check and is refused until an owner removes them. It fails closed. Revoke
instance grants before rolling back past this release.

## The log

The same actions as any grant, from the vault: `access.grant` and
`access.revoke`, with `role`, `expiresAt` and `previousRole` as now. Their
`project_id` and `environment_id` are null, and the metadata names the
place as a path: `"place": "*"` or `"place": "*/dev"`. A slug never holds
`*` or `/`, so the two cannot be confused with a project's grant. A
refusal is logged the same way, with the place.

Entries about no project are owners' to read, so only owners and root admins
see these in the log, as with `member.add`. An auditor on `*` reads every
project's log, not the owners' entries.

The UI words them as "granted Ada developer on dev in every project".

## Offboarding

Removing a member revokes every grant they hold, instance grants included,
each with its `access.revoke` entry, and the count `coffre offboard`
previews includes them. Adding them back starts from nothing, as now.

## Where they show

- **The API.** `PATCH /api/access/<member>` takes `"*"` and `"*/dev"` as
  places, beside `"market"` and `"market/dev"`. Member lists return them as
  grants whose `project` is `"*"`, with the `environment` slug or null.
  A project's list (`GET /api/members?path=market`) includes the ones that
  reach it, for whoever manages that project's access to see, and not to
  change; `?path=*` lists only them.
- **Making a project or an environment, or renaming an environment,**
  answers with who reaches it through them:
  `inherited: [{ member, place: "*/dev", role, roleName, expiresAt }]`.
  `GET /api/projects` lists them all as `everyProject`, for owners and for
  whoever manages environments or access somewhere, so that a dialog can say
  so before anything is made.
- **The CLI.** `coffre grant '*' <member> --role <role> [--env <name>]`,
  `coffre revoke '*' <member> [--env <name>]`, `coffre access '*'`, and
  `coffre access <project>` marks them "(dev in every project)". `projects
  create`, `environments create`, and `environments rename` to a new slug
  print who reaches the place. A `*` the shell expanded into file names is
  answered with "quote it: '*'".
- **The UI.** The member page shows "All projects · Developer" or "dev in
  every project · Developer" above its project access. A project's access
  list shows them where they reach, marked "every project", with no revoke:
  owners change them with the CLI or the API. The dialogs that make a
  project or an environment, or rename an environment, say who it is
  reachable by before you confirm.

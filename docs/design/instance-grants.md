# Grants on every project

Written on 2026-10-05, from Erwin's decision that day: a member can hold a
role on every project, including the ones created later, or on one
environment name in every project.

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

In a table of their own, `vault_instance_grants`, beside `vault_grants`:

```
principal     text  not null   → vault_members
environment   text  null       null: every project; otherwise a slug, '^[a-z0-9][a-z0-9-]{0,62}$'
role          text  not null   any role; with an environment, only viewer, developer, auditor
expires_at    bigint null
granted_at    bigint not null
granted_by    text  not null
unique (principal, coalesce(environment, ''))
```

Only the vault writes it (`coffre_vault`: select, insert, delete); the app
reads it for lists (`coffre_app`: select), as with `vault_grants`.

A table of its own rather than new columns on `vault_grants`, because
`vault_grants` has a check that a grant names exactly one of a project or
an environment. Loosening it means dropping and adding a constraint, and
on SQLite rebuilding the table. A new table is the plainest expand
migration there is, and the previous release never reads it.

**The member's MAC covers them.** The vault seals each member's row
together with their grants as one sorted set (`rows.ts`). Instance grants
join that set as tuples of a new kind, `['instance', environment, role,
expires_at, granted_at, granted_by]`. A member with none has the same set,
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

One migration, `0005_instance_grants`, on both engines: create the table,
its index and its foreign key, and grant the runtime logins their
privileges. It adds and removes nothing else, so the previous release runs
on the new schema unchanged (`pnpm test:compat` holds it to that).

Rolling back to the previous release once instance grants exist: its vault
does not know them, so a member who holds one fails its MAC check and is
refused, until they are removed and admitted again. It fails closed. Revoke
instance grants before rolling back.

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
  A project's list (`GET /api/members?path=market`) includes the instance
  grants that reach it, for whoever manages that project's access to see,
  and not to change.
- **Creating a project or an environment, or renaming an environment,**
  answers with who already has access there through instance grants:
  `inherited: [{ member, role, place: "*/dev", expiresAt }]`.
- **The CLI.** `coffre grant '*' <member> --role <role> [--env <name>]`,
  `coffre revoke '*' <member> [--env <name>]`, `coffre access` lists them
  first, and `projects create` and `environments create` print who already
  has access.
- **The UI.** The member page shows "All projects · Developer" or "dev in
  every project · Developer". A project's access list shows them, marked as
  granted on the instance, without a revoke button for those who cannot.
  Creating a project or an environment says who already has access.

# Folders, forks, references and missing keys

Four features that arrange and fill environments. References matter most: they let someone read a
secret without a grant on it, so the vault decides them, and most of this note is about how.

The examples use two projects. `market` holds `market/prod/DATABASE_URL`. `billing` is another
team's, with `billing/prod`. Ada reads `market/prod`. Bo reads `billing/prod` and nothing in
`market`.

## Folders

One level, for projects and for secrets, only to arrange lists: a folder never grants, hides or
changes anything else. It is a `folder` column on `projects` and on `secrets` (nullable; 1 to 64
characters, no `/`, no control character, no space at either end), not a row of its own: it exists
while something is in it. Key names stay unique per environment whatever their folder, so `run`
and `export` inject `DATABASE_URL`, never `database/DATABASE_URL`.

| | API | CLI |
|---|---|---|
| move a project | `PATCH /api/projects/acme {"folder": "Clients"}` (`project.manage`) | `coffre move acme Clients` |
| move a secret | `PATCH /api/secrets/market/prod/STRIPE_KEY {"folder": "stripe"}` (`secret.write`) | `coffre move market/prod/STRIPE_KEY stripe`, or `--none` |
| rename a folder | `PATCH /api/folders/Clients {"name": "Customers"}`, `PATCH /api/folders/market/prod/stripe …` | `coffre folders rename …` |
| remove a folder | `DELETE /api/folders/Clients`, `DELETE /api/folders/market/prod/stripe` | `coffre folders remove …`, `--apply` past one item |

Renaming onto a name in use merges the two. Each move is logged by the app (`project.move`,
`secret.move`), one per item, in one transaction. A folder of projects is renamed only by whoever
manages every project in it. Folders have their own `/api/folders` paths, so a folder named
`reference` never reads as a route.

## Forks

Forking `market/prod` makes `market/staging`, a new environment in the same project, with every
live key of `prod` and its folder, none of its history. Each key is a **copy** of prod's current
value by default, or, with `--reference`, a [reference](#references) to prod's key. A fork that
**inherits** (`--inherit`) copies nothing and keeps reading its parent's keys live:
[forking.md](forking.md).

`coffre fork market/prod staging [--reference | --inherit]`, or `PUT /api/projects/market/staging
{"from": "prod"}` (with `references` or `inherit`). Forking
takes `environment.manage` on the project and read on the environment it copies: copying is
reading, so the vault logs one `secret.read` per key with the purpose `copy`, then the writes. The
environment is made first, since the vault's entries name it, then filled; if filling fails it
stays, empty, and the same fork run again fills it (a `PUT` with `from` on an environment with no
live secrets fills it; one with secrets answers 409). Forks stay within one project, and a
personal config is never forked.

## References

**A reference is a decision taken when it is made.** Ada makes `billing/prod/DATABASE_URL` a
reference to `market/prod/DATABASE_URL`. From then on, whoever reads `billing/prod` reads market's
current `DATABASE_URL` through it, Bo included, though Bo has no grant in `market`. Making it took
read on the source (Ada's own grant) and write where it is made. Market rotates the value, and
billing reads the new one at its next `coffre run`.

**Once made, it is read as the holder's own key.** Every read and use is decided where it is held:
the holder's grants, a workload's `reads` listed at the holder by the reference's own id, and, for
a sensitive value, a service credential an Owner of the holder's project issued. The source is
asked nothing after the reference is made: it lends its value and nature, never its permissions.
So marking the source sensitive later turns the reference sensitive too, and the holder's
Owner-issued credentials keep reading it. The source side's lever is to break the reference. With
`landing/prod/CLERK_SECRET_KEY` a reference to a sensitive key of `backend/prod`:

| Reader of `landing/prod` alone | `CLERK_SECRET_KEY` |
|---|---|
| a service token an Owner of `landing` issued | read |
| a service token a Developer of `landing` issued | used through the proxy, not read (`not_owner_issued`) |
| a person, any role | used, never read |

Whoever could write a reference row would read any secret, so the vault makes every reference,
checks it at each read, and refuses one it did not make.

### The seal is the vault's own log entry

1. The app asks the vault, `reference({ principal, items: [{ id, holder, source }] })`: a fresh id
   for each, the holder's ids and path, the source secret's id.
2. The vault reads the source itself, and checks that the actor holds read on the source and
   write on the holder, by their own grants, under the log's head.
3. It appends a `reference.create` entry, under its MAC, naming the reference id, the holder and
   the source, and answers with its `seq`.
4. The app stores the row, with its own `secret.reference` entry naming the vault's by
   `related_seq`.

The row, in `secret_references`, points: `id`, the holder's `project_id`, `environment_id` and
`secret_id`, the source's `source_project_id`, `source_environment_id` and `source_secret_id`,
`created_seq` (the vault's entry), `created_by`, `created_at`, and `ended_at`. The holder key is an
object of the vault's log whose seal covers its source and the reference row's id, so a row edited
to point elsewhere fails it.

**A read through a reference** names the version and the way in: `{ secretVersionId, via:
{ reference, seq } }`. The vault then checks, besides what it checks for any read, that the entry
at `seq` is its own allowed `reference.create` for this id, that no authentic `reference.end` names
it, that the version is the current version of the source the entry names, and that the reader is
allowed at the holder. Otherwise it refuses, logs it, and releases nothing. The bulk limit counts
these reads like any other.

| Someone with the app's login, or the database's owner… | Then |
|---|---|
| inserts a row naming no `reference.create`, or one about other secrets | refused, `bad_claim` |
| edits a genuine row to point at another source | refused: not the entry's source |
| writes a `reference.create` entry themselves | no vault MAC: refused |
| puts back a reference after it was broken | its `reference.end` still names it: refused |
| uses a genuine reference for someone who cannot read `billing/prod` | refused, `no_grant` |

What it does not stop is what a reference is for: an app fully taken over can act as Bo and read
market's value through billing's reference, as it can read anything Bo reads; the read is logged in
both projects. Nor can it stop such an app inserting an old value as the source's newest version.

Each read costs two index lookups more than a plain one: the entry by `seq`, its end by
`related_seq` (`audit_log_reference_end_idx`). An entry verifies under a rotated key while that key
is in `previousKeks`, which it must be anyway for the values it wrapped.

### One hop, and no loops

The vault releases only the source's own current version, and a secret that is a reference holds
none, so a chain is refused and nothing can loop. The app refuses to build one: no reference to a
reference, and no secret made a reference while others read it ("break them first").

Forking a forked environment as references resolves to the original sources: forking staging, whose
`DATABASE_URL` reads prod's, makes `qa/DATABASE_URL` read prod's too, which needs the forker's own
read on prod. Reading through a reference never counts as read on its source for making a new one,
so a reference cannot be passed on. A key whose source the forker reads only through the parent is
copied instead, and the fork's answer and dialog name it.

### Ending a reference

Each way is a vault `reference.end` entry naming the reference's `reference.create` by
`related_seq`; the vault's decision also sets the row's `ended_at`, where there is a row:

- **Broken, by either side**, `reason: "broken"`: by whoever holds `grant.manage` on the source's
  project, or `secret.write` on the holder's environment. Reads of that key stop until a value is
  set or the reference is made again.
- **Replaced by the holder's side**, `reason: "replaced"`: setting or restoring a value ends the
  reference first, in a vault call before the app's write. If the write then fails, the key has no
  value until written again: refused, never stale.
- **Abandoned, by the app**, `reason: "abandoned"`: when the row's write stores nothing, the app
  ends the seal at once, as its maker; the vault takes this end from the seal's maker alone. A crash
  between the two leaves a seal with no row, which is no reference. Reviving it takes the app's
  login, and yields only a reference its maker was allowed to make, read only by whoever reads its
  holder.

An ended reference stays ended. Archiving the holder ends nothing: unarchiving brings it back.

### When the source is gone

**Archiving a source is refused**, 409, while a live reference reads it from outside what is being
archived: the key, its environment or its project. The refusal names each reference and who can
break it, and the archive dialogs list them with Break. The check runs under the log's head in the
archive's transaction, and making a reference checks its source there too, so the two cannot both
land. Restoring is never refused. Deleting for good ends the references to and from what it deletes.

A key whose source cannot be read shows why, and is never read as empty:

| State | Shown as | `get`, `run`, `export` |
|---|---|---|
| source, its environment or its project archived | "Source archived" | refused, naming the key |
| source's project deleted for good | "Source deleted" | refused |
| broken, by either side | "Broken by … on …" | refused |
| source became a reference itself | "Source is a reference" | refused |

A read of a whole environment is all or nothing: `coffre run billing/prod` refuses, naming
`billing/prod/DATABASE_URL`, why, and who can fix it, rather than start a process without it.

### Who sees what

The holder's side shows the key as "→ market/prod/DATABASE_URL", with who made it and when, linking
to the source only for those who can open it. The source's side lists the references that read it,
with Break for those who may (`canBreak`), and its access view (`coffre access market/prod`) adds
"Also readable through references". Names are metadata: billing's readers learn the source's path.

### The log, in both projects

Bo's `coffre run billing/prod` reads market's key. The vault logs a `secret.read` of the source,
whose project, environment, secret and version are market's, so market's history and offboarding
report count it like any read. Its metadata names the way in, `via` (the reference, its `seq`, the
holder's path, who made it and when), and `also`, the holder's place. Every entry about a reference
(made, read, ended) carries `also`, and a place's log matches its own columns or `also`
(`audit_log_also_*_idx`), so an auditor of either project sees it.

### Offboarding

A reference belongs to the environment that holds it, so removing its maker ends nothing. Their
offboarding report lists the references they made, from the log's `reference.create` entries by
actor, never from `created_by`, which the app's login can write.

### API and CLI

A reference is not a secret, so it may be a flag. In a merge patch a value is a string and a
reference an object:

```
PATCH  /api/secrets/billing/prod {"DATABASE_URL": {"ref": "market/prod/DATABASE_URL"}}
GET    /api/references?path=market/prod                    into and out of a place
DELETE /api/secrets/billing/prod/DATABASE_URL/reference    break, or end from the holder's side
coffre set billing/prod/DATABASE_URL --ref market/prod/DATABASE_URL
coffre references break billing/prod/DATABASE_URL          who would stop reading; --apply breaks
```

A value is never parsed for references: `${market/prod/DATABASE_URL}` typed at `coffre set`'s
prompt is that string, and `coffre import` makes none. `get`, `run` and `export` resolve references
on the server; the CLI receives values.

## Missing keys

`market/dev` lacks `STRIPE_WEBHOOK_SECRET`, which `prod` and `staging` have: its page shows a strip
of such keys, each with Add (a new, empty row: copying a value is a separate reveal) and Dismiss
(the team's, logged, undone by `coffre missing restore`). Every sibling environment is compared,
read or not, since within a project key names are not secret; other projects never are. A key
archived here is not missing.

```
GET   /api/projects/market/dev/missing      {"missing": [{"key", "in": ["prod"], "folder"}], "dismissed": [...]}
PATCH /api/projects/market/dev/dismissals   {"SENTRY_DSN": true, "OLD_KEY": null}   true dismisses, null restores
```

`coffre missing market/prod --check` exits 1 when a key is missing, for CI ([ci.md](../ci.md)).
Listing takes `secret.read` or `secret.use`; dismissing, `secret.write`. The app logs
`missing.dismiss` and `missing.restore`, one entry per key. Dismissals live in `dismissed_keys`, one
row per environment and key, updated in place: `dismissed_at`, `dismissed_by`, `restored_at`,
`restored_by`.

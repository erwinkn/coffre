# Folders, forks, references and missing keys

Written on 2026-10-05, from Erwin's decisions that day: folders for
projects and secrets, forking an environment, references between secrets,
and the keys an environment is missing. It covers the four features and
the order they ship in. References come first in importance: they let
someone read a secret without a grant on it, so the vault has to decide
them, and most of this note is about how.

The examples use two projects. `market` holds `market/prod/DATABASE_URL`.
`billing` is another team's project, with `billing/prod`. Ada can read
`market/prod`. Bo can read `billing/prod` and nothing in `market`.

## Folders

One level, for projects and for secrets, and only for arranging lists.
A folder never grants, hides or changes anything else.

- **A project's folder** is a row of `project_folders`. The projects page
  groups by it: `Clients / acme`, `Clients / globex`, then the projects
  in no folder.
- **A secret's folder** is a row of `secret_folders`, per secret, so each
  environment's keys are arranged on their own: `database/` holds
  `DATABASE_URL` and `DATABASE_POOL`, `stripe/` holds `STRIPE_KEY`.
  Key names stay unique per environment whatever their folder, so `run`
  and `export` inject `DATABASE_URL`, never `database/DATABASE_URL`.

A folder is a name, not a row of its own: it exists while something is
in it, and there is nothing to create or delete.

**Tables beside `projects` and `secrets`, not columns on them.** Drizzle
names every column of a table in each insert, and in each select of a
whole row. A `folder` column on `secrets` would make this release fail
every write on a database its migration has not reached yet, and a release
must run on the schema before its own migration. So folders live in
tables of their own, read only once `0007_folders` has run. Before
that, everything lists in no folder, and moving answers 503. A name is 1 to 64 characters, with
no `/`, no control character, and no space at either end.

| | API | CLI |
|---|---|---|
| move a project | `PATCH /api/projects/acme {"folder": "Clients"}` (`project.manage`) | `coffre move acme Clients` |
| move a secret | `PATCH /api/secrets/market/prod/STRIPE_KEY {"folder": "stripe"}` (`secret.write`) | `coffre move market/prod/STRIPE_KEY stripe` |
| out of its folder | `{"folder": null}` | `coffre move market/prod/STRIPE_KEY --none` |

Both are logged by the app (`project.move`, `secret.move`), like a rename.
`coffre list` and `coffre projects` print the groups. In the UI, each
folder is a heading in the list, foldable, with "Move to folder…" in a
row's menu and a folder picker on a new secret's row.

## Forks

Forking `market/prod` makes `market/staging`, a new environment in the
same project, with every live key of `prod`. By default each key is a
**copy** of prod's current value, without its history. With
`--reference`, each key is a **reference** to prod's key instead,
following it until someone gives it a value of its own (see
[References](#references)).

```sh
coffre fork market/prod staging              # copies
coffre fork market/prod staging --reference  # each key a reference to prod's
```

```
PUT /api/projects/market/staging {"name": "Staging", "from": "prod", "references": false}
```

Forking takes what creating an environment takes, `environment.manage`
on the project, and read on the environment it copies: copying is
reading. The vault logs it as one `secret.read` per key, with the purpose
`copy`, then one write per key, as any write. Each key keeps its folder.

The environment is created first, then filled, because the vault's
entries for the new keys name the environment, which must exist by then.
If filling fails (a refusal, the bulk limit, an outage), the new
environment stays, empty, and the answer says so. Running the same fork
again fills it: a `PUT` with `from` on an existing environment that has
no live secrets fills it, and on one that has secrets answers 409.

Forks stay within one project. Copying into another project is a fork
followed by references, or an import.

## References

**The rule, from Erwin: a reference is a decision taken when it's
created.** Ada sets `billing/prod/DATABASE_URL` to be a reference to
`market/prod/DATABASE_URL`. From then on, whoever can read `billing/prod`
reads market's current `DATABASE_URL` through it, Bo included, though Bo
has no grant in `market`. Creating it took read on the source (Ada has
it) and write where it is created. Market rotates the value, and billing
reads the new one at its next `coffre run`.

The danger is plain: whoever can write a reference row reads any secret.
So the app's word is not enough. The vault creates every reference,
checks it at each read, and refuses one it did not create.

### The seal is the vault's own log entry

Creating a reference is a vault decision, like a grant:

1. The app asks the vault: `reference({ actor, items: [{ id, holder, source }] })`,
   with a fresh id for each reference, the holder as a write names a new
   version (its project, environment and secret ids, and its path), and
   the source secret's id.
2. The vault reads the source's ids and path from the database itself,
   and checks that the actor holds `secret.read` on the source's
   environment and `secret.write` on the holder's, by their own grants.
3. It appends a `reference.create` entry and answers with its `seq`. The
   entry names the reference id, the holder's ids and the source's ids.
   Like every vault entry, it carries the vault's MAC, which neither the app
   nor the database's owner can compute.
4. The app stores the reference, in one transaction with its own entry
   (`secret.reference`, naming the vault's by `related_seq`), as a write
   names its `key.wrap`.

The app's row, in a new table `secret_references`, is only a pointer:

```
id                 uuid    the reference's id, in the vault's entry
project_id, environment_id, secret_id               the holder, billing/prod/DATABASE_URL
source_project_id, source_environment_id, source_secret_id    market/prod/DATABASE_URL
created_seq        bigint  the vault's reference.create entry
created_by, created_at
```

**A read through a reference.** The app finds the source's current
version and hands the vault, as for any read, the version's id, and also
which reference it reads through: `{ secretVersionId, via: { reference, seq } }`.
The vault then checks, besides what it checks for any read:

1. **The entry at `seq` is its own** `reference.create`, allowed, its MAC
   good under one of its keys, naming this reference id.
2. **Nothing has ended it:** no allowed `reference.end` names it by
   `related_seq`.
3. **The version belongs to the source the entry names,** and is that
   secret's current version.
4. **The reader holds `secret.read` on the holder's environment,** the one
   the entry names, not one the app says.

If any fails, it refuses, logs the refusal, and releases nothing. The bulk
limit counts these reads like any other.

The vault never reads `secret_references`. The authority is the entry,
and the row only says where to find it. Here is what that stops, from
the app's login, a compromised app or the database's owner:

| Someone… | Then |
|---|---|
| inserts a row whose `created_seq` names no `reference.create`, or one about other secrets | refused, `bad_claim`, logged |
| edits a genuine row to point at another source | refused: the version is not the entry's source |
| writes a `reference.create` entry themselves | no vault MAC: refused, and the next checkpoint refuses to sign, so `/readyz` turns red |
| puts back a reference after it was broken | its `reference.end` still names it: refused |
| uses a genuine reference for someone who cannot read `billing/prod` | refused, `no_grant` |
| deletes the `reference.end` entry | the logins cannot. The database's owner can, but a cut is found at the next checkpoint |

What it does not stop is what a reference is for: an app fully taken over
can act as Bo and read market's value through billing's reference, as
it can read anything Bo reads. That read is logged in both projects.

**What a read costs.** Per reference read, two lookups more than a
plain read, both by index, never a scan of the log: the sealing entry by
`seq`, the log's primary key, and its end by `related_seq`, through a
partial index on the vault's allowed `reference.end` entries, which holds
only ended references. The version, its secret and that secret's current
version come in the join the vault already makes for every read.

No seal column, and no resealing when the vault key is rotated: an entry
written before a rotation verifies under the replaced key for as long as
it is in `previousKeks`, which it must be anyway for the values it wrapped.

**Why not a sealed row, as for members?** The vault's login may write
four tables, and 0.3.0's conformance, which `test:compat` runs on this
schema, fails if it can write a fifth. The all-projects grants met the
same wall (D26). The vault writes only the log here, which it can already
write.

### One hop, and no loops

The vault releases, through a reference, only a version of the source its
entry names, and never follows a second reference. So a chain cannot be
read: if `market/prod/DATABASE_URL` later became a reference itself, the
vault would still release only `market/prod/DATABASE_URL`'s own versions,
and it holds none current (a secret that is a reference has no current
version), so the read is refused. With one hop at most, there is nothing
for a loop to go round. No cycle detection, in the vault or the app.

The app adds two refusals, so nobody builds what cannot be read:

- a reference to a secret that is itself a reference: "market/prod/DATABASE_URL
  is a reference to …; point at its source instead";
- making a secret a reference while others point at it: "2 references
  read this secret: billing/prod, ops/dev; break them first".

**Forking a forked environment as references resolves to the original
sources.** I confirm the brief. `market/staging/DATABASE_URL` is a
reference to `market/prod/DATABASE_URL`. Fork staging as references, and
`market/qa/DATABASE_URL` becomes a reference to prod's, not to staging's.
Creating it needs read on prod's key by the forker's own grants.
Reading through a reference never counts as read on its source for
making a new one, so a reference cannot be passed on: whoever the source's
owners reached through billing cannot extend that to a third project. A
fork as references copies a key whose source the forker cannot read
directly, and its preview lists those keys before anyone confirms.

### Ending a reference

Two ways, each a vault `reference.end` entry naming the reference's
`reference.create` by `related_seq`:

- **Broken, by either side.** Whoever holds `grant.manage` on the
  source's project (its owners and access managers, and instance owners),
  or `secret.write` on the holder's environment, breaks it: `reason:
  "broken"`. Billing sees "Reference broken by lead@acme.example on 5 Oct",
  and its reads of that key stop until a value is set or the reference is
  made again.
- **Replaced by the holder's side.** Setting a value on
  `billing/prod/DATABASE_URL`, or restoring one of its old versions, ends
  the reference first (`reason: "replaced"`), in a vault call before the
  app's write. That needs `secret.write` on billing/prod. If the write then
  fails, the key has no value until it is written again: refused, never
  stale.

An ended reference stays ended. Following the source again is a new
reference, which takes read on it again. Archiving the holder does not end
it: archiving is reversible, and unarchiving brings the reference back.

`secret_references` is insert-only: whether a reference is live comes from
the log, so a list shows what the vault decides, whatever the row says.
So do its holder and source: lists, Break and a deletion read them from
the `reference.create` entry the row names, and a row with no such entry
is no reference.

The vault releases, through a reference, only its source's newest version,
by the versions' own order and the source's `current_version_id` both: the
app's login may write the pointer, never a version.

### When the source is gone

Live resolution reads the source's current version at each read. A key
whose source cannot be read shows why, and is never read as an empty value:

| State | Shown as | `get`, `run`, `export` |
|---|---|---|
| source archived, or its environment or project archived | "Source archived" | refused, naming the key |
| source's project permanently deleted (D25) | "Source deleted" | refused |
| broken, by either side | "Broken by … on …" | refused |
| source became a reference itself | "Source is a reference" | refused |

A read of a whole environment is all or nothing, as the vault's batches
are: `coffre run billing/prod` refuses, naming
`billing/prod/DATABASE_URL` and why, rather than start a process without
it. The message says which state, and who can fix it: "billing/prod/DATABASE_URL
is a reference to market/prod/DATABASE_URL, which lead@acme.example broke
on 6 Oct: set a value here, or ask someone who reads market/prod to make
the reference again", or "…whose source was archived: market's
maintainers can unarchive it, or set a value here". The UI marks the row
the same way. Archiving the source, or its
environment or project, is reversible, and the reference comes back with
it. Permanent deletion should end the references to what it deletes,
and its confirmation should list them. I'll agree that with the deletion
work (thr_9ebs5hytxt) when the two meet.

### Who sees what

- **On the holder's side**, the key shows as a reference: "→
  market/prod/DATABASE_URL", the source's current version, who made the
  reference and when. The path links to the source when the viewer can
  read it there; otherwise it says "you can't open the source". The
  value reveals like any other, and is logged as a read of the source.
- **On the source's side**, the secret shows "2 references", and its
  details list each one: "billing/prod/DATABASE_URL, made by ada on 5 Oct,
  readable by 4 people", with a Break button for those who may break it.
- **"Who can read this secret" includes reference readers.** The
  project's access view (`coffre access market/prod`, `GET /api/members?path=market/prod`)
  gains a section, "Also readable through references", listing each
  reference into the place and who can read its holder's environment.
- **Names are metadata.** Billing's readers learn that
  `market/prod/DATABASE_URL` exists, and its path. That comes with the
  reference.

### The log, in both projects

Bo's `coffre run billing/prod` reads market's key. The vault logs it as a
read of the source: a `secret.read` whose project, environment, secret
and version are market's, so market's history, and its offboarding
report's "what to rotate", count it like any read of that secret. Its
metadata names the way in:

```json
{ "subject": "market/prod/DATABASE_URL", "version": 7, "purpose": "run",
  "via": { "reference": "9f…", "seq": 5120, "path": "billing/prod/DATABASE_URL",
           "createdBy": "user:ada@acme.example", "createdAt": "2026-10-05T09:12:00Z" },
  "also": { "projectId": "…billing", "environmentId": "…billing/prod", "secretId": "…" } }
```

The audit page words it as "bo read market/prod/DATABASE_URL through
billing/prod/DATABASE_URL, a reference ada made on 5 Oct". Every entry
about a reference (its creation, its reads, its end) carries `also`: the
place on the other side. A project's, environment's or secret's log
matches its own columns or `also`, through expression indexes like the
existing `audit_log_unbind_idx`. So the read is in market's log and in
billing's. An auditor of either project sees it.

### Offboarding

A person's references outlive them: they were decisions. Their
offboarding report (`coffre offboard`, the member's page) lists the
references they made, live ones first, for review: holder, source, when,
and how many people read through each. Removing them ends nothing.

### API and CLI

A reference is not a secret, so it may be a flag. A JSON merge patch
already tells the two apart: a value is always a string, and a reference
an object.

```
PATCH /api/secrets/billing/prod {"DATABASE_URL": {"ref": "market/prod/DATABASE_URL"}, "PORT": "8080"}
GET   /api/references?path=market/prod            references into and out of a place
DELETE /api/secrets/billing/prod/DATABASE_URL/reference     break, or end from the holder's side
```

```sh
coffre set billing/prod/DATABASE_URL --ref market/prod/DATABASE_URL
coffre references market/prod                     # into and out of it; --json
coffre references break billing/prod/DATABASE_URL # who would lose read; --apply breaks
```

**How is a literal `${…}` written? As it is.** A value is never parsed for
references: it comes from the hidden prompt or stdin, and is stored
byte for byte. `${market/prod/DATABASE_URL}` typed at `coffre set`'s
prompt is that string. Only `--ref` makes a reference, so the two cannot
be confused, and nothing needs escaping. `coffre import` never makes
references either.

`get`, `run` and `export` resolve references on the server: the CLI
receives values, as now. `coffre list` shows them:

```
database/
  DATABASE_URL   → market/prod/DATABASE_URL  v7   ada  5 Oct
  DATABASE_POOL  20                          v2   bo   1 Oct
STRIPE_KEY       → market/prod/STRIPE_KEY    broken by lead on 6 Oct
```

## Missing keys

`market/dev` lacks `STRIPE_WEBHOOK_SECRET`, which `prod` and `staging`
have. The environment's page shows a strip above its secrets:

```
2 keys from other environments aren't here
  STRIPE_WEBHOOK_SECRET   in prod, staging     [Add] [Dismiss]
  SENTRY_DSN              in prod              [Add] [Dismiss]
                                               [Dismiss all]   Dismissed (1)
```

- **Only environments the viewer can read are compared.** Key names are
  metadata, and listing an environment's keys takes `secret.read`. Bo,
  reading only `market/dev`, sees no strip at all.
- **Add** opens a new row with the key's name, empty; the strip says which
  folder the key is in elsewhere, when they agree, and moving it there is a
  step of its own. Copying a value from another environment is a separate,
  deliberate reveal.
- **Dismiss** is shared: stored, logged, and listed under "Dismissed",
  each with who and when, and a Restore. A dismissed key the viewer cannot
  see elsewhere is not listed to them either. Archived keys are not
  missing: archiving one was a decision.

```
GET   /api/projects/market/dev/missing         {"missing": [{"key", "in": ["prod"], "folder"}], "dismissed": [...]}
PATCH /api/projects/market/dev/dismissals      {"SENTRY_DSN": true, "OLD_KEY": null}    true dismisses, null restores
```

```sh
coffre missing market/dev                       # and the dismissed ones, --dismissed
coffre missing dismiss market/dev/SENTRY_DSN    # or market/dev --all
coffre missing restore market/dev/SENTRY_DSN
```

Reading the list takes `secret.read`; dismissing takes `secret.write`.
The app logs `missing.dismiss` and `missing.restore`, one entry per key,
"Dismiss all" sharing one operation id. They live in a new table,
`dismissed_keys`, one row per environment and key, updated in place (the
app's login deletes nothing): `dismissed_at`, `dismissed_by`, and
`restored_at`, `restored_by`.

## Migrations

Four, each in the PR that needs it, each only adding:

| Migration | Adds | Grants |
|---|---|---|
| folders | `project_folders`, `secret_folders`: a folder per project or secret, nullable, with its check | app: `SELECT, INSERT, UPDATE (folder, moved_at, moved_by)` |
| references | `secret_references`, its indexes and foreign keys; on `audit_log`, an index on `related_seq` for `reference.end`, and the `also` indexes | app: `SELECT, INSERT`; vault: `SELECT` |
| missing keys | `dismissed_keys` | app: `SELECT, INSERT, UPDATE` on its four columns |
| forks | none | |

The vault writes no new table and no new column, so 0.3.0's
`checks/logins.ts` still holds, and `test:compat` stays green. Values and
wrapped keys never move. The previous release on the new schema ignores
the new columns and tables. One case is worth stating: rolled back after
references exist, the previous release sees a reference key as a secret
with no current value, and leaves it out of `run`, as it would an empty
one. It reads nothing it should not, since its vault knows no `via`.

## The UI

- **Projects page:** folder headings, foldable; "Move to folder…" in a
  project's settings.
- **Environment page:** folder groups as heading rows in the secrets
  table; the missing-keys strip and its Dismissed list above it; "Fork"
  beside the environment's name, opening a dialog with the new name and
  the choice "Copy values" (default) or "Reference each key". The second
  says what it means before anyone confirms: "Whoever can read staging
  will read prod's values through these references, even without access
  to prod."
- **A reference row:** "→ market/prod/DATABASE_URL", a link or not, with
  the source's version; its menu has "Give it its own value…" (ends the
  reference, after a confirmation) and, on a value row, "Make a
  reference…", a picker of the secrets the viewer can read.
- **A source secret:** a "2 references" badge, and in its details the
  list with Break.
- **Project access tab:** "Also readable through references".
- **Member page:** "References they made".

`packages/ui/CONVENTIONS.md`, which the brief names, does not exist on
`main` yet. I'll follow the existing pages, and that file if it lands
first.

## The order of the PRs

Each green on its own, with its conformance checks, in this order,
because references build on forks and missing keys on folders' `Add`:

1. **Folders.** Migration, API, `coffre move`, list grouping, UI groups.
2. **Forks, as copies.** `from` on `PUT`, the `copy` purpose,
   `coffre fork`, the dialog. Conformance: a fork copies values, and
   forking without read on the source is refused.
3. **References.** The vault's `reference`, `endReferences` and `via` on
   `unwrap`, the migration, the API, the CLI, fork `--reference`, the
   source side, offboarding, and the UI. If it gets too big to review,
   the UI goes in a fourth PR. Conformance:
   - Bo, with no grant in market, reads market's value through billing's
     reference, and the read is in both projects' logs;
   - a forged `secret_references` row (written with the owner's
     connection) is refused, as is a genuine row edited to another source;
   - a broken reference stops reading, and putting back the row as it was
     does not revive it;
   - creating a reference without read on the source is refused.
4. **Missing keys.** Migration, API, `coffre missing`, the strip.

Each runs lint, typecheck, `pnpm test`, `test:sqlite`, `test:schema`,
both conformance runs, `test:compat` and `test:consumer`.

## Decided with the PM

On 2026-10-05 the PM approved this design, with two answers:

1. Reading through a reference never counts as read on its source for
   making new references; you need your own grant. A fork of a fork
   copies such keys, listed in its preview.
2. A reference that cannot be read refuses the whole read (`get`, `run`,
   `export`), naming the key, its state and who can fix it.

Worth knowing: anyone who reads `market/prod` and writes anywhere else
can share a market secret by reference, as they could copy it today, but
following rotations. Market's owners see every reference and can break
it. A project setting that refuses references into it would be a small
follow-up if wanted.

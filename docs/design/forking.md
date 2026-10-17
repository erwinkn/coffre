# Forks that inherit, and personal configs

Written on 2026-10-17 for T93, from Erwin's request: "let's allow forking
environments, either to define a personal config (like Doppler allows) or
an environment that shares most secrets with another one but may
add/remove/overwrite a few."

Coffre already forks, but a fork is a one-off. `coffre fork market/prod
staging` copies prod's values into staging, and `--reference` makes each
key a reference to prod's (docs/design/environments.md). A copy never
follows prod. References follow each key's value, but a key added to prod
later never reaches staging. The log's `environment.create` entry says
staging was forked from prod, but nothing links the two afterwards. This
note adds the missing piece: an environment that keeps reading its
parent, live, except for the keys it sets or removes. A personal config is the same thing, owned by one person.

The examples use one project, `market`, and four people. Ada is a
developer on `market`. Bo reads `market/dev` only. Cy is a maintainer on
`market`. Dee reads `market/prod-eu` only, once it exists.

```
market/prod   DATABASE_URL=postgres://prod   STRIPE_KEY=sk_live_1   SENTRY_DSN=https://sentry/prod
market/dev    DATABASE_URL=postgres://dev    STRIPE_KEY=sk_test_1
```

## In short

- **One model.** An environment may have a parent in its project, set
  when it is made and never changed. Its keys are its own live keys, then
  its parent's, then its grandparent's, for the keys no nearer
  environment holds or removed. A personal config is such an environment
  with an owner.
- **A key in a fork is in one of four states:** inherited (no row of its
  own), overridden (a value or a reference of its own), added (a key the
  parent lacks), or removed. Removing is a dismissal, the record the
  missing-keys strip already keeps for "this environment does without K".
  No new table, and only two new columns, both on `environments`.
- **Inheriting never grants.** An inherited value is the parent's value,
  read by the reader's own grants on the parent and logged as the
  parent's read. It also shows up in the fork's log. A fork lends nothing.
  Lending a value across a trust boundary stays what references are for,
  one key at a time, sealed by the vault.
- **Nothing is re-encrypted.** The fork opens the parent's ciphertext as
  the parent's. The vault and the key formats don't change for overlays.
  The vault gains one log label, `through`, which decides nothing.
- **A personal config is readable by its owner alone,** instance Owners
  included. The vault enforces it by binding the owner into each wrapped
  data key, so a forged database row fails to decrypt instead of granting
  access.
- **Status.** Erwin agreed to the three recommendations below (no
  lending, owner-only personal configs, explicit `@me`). Forks that
  inherit shipped first, as 0.7's first PR: section 7 says what it built.
  Personal configs are the second PR; their `owner` column comes with
  their own migration.

## 1. The model

### One kind of thing: an environment with a parent

```
environments
  parent_id   uuid, null       the environment it inherits from, same project
  owner       text, null       a personal config's owner, user:<email>; needs parent_id
```

`parent_id` has a foreign key on `(parent_id, project_id)` to `(id,
project_id)`, so a parent is always in the same project. The app's login
may insert both columns and update neither, so a parent can't change.
The app makes a parent before its child, so its chains can't loop. The
database can't promise that alone: its login could insert two rows naming
each other in one statement. So a check refuses the simplest case, an
environment that is its own parent, and a read refuses a chain that
loops or runs past the cap, written around the app, instead of following
it. A unique index on `(parent_id, owner)` gives each person at most one
personal config per environment. It's partial, leaving out tombstones, so
deleting a personal config frees its place.

A fork's own keys are ordinary `secrets` rows in its environment. Here is
`market/prod-eu`, forked from prod, after Cy sets two keys and removes one:

| Key | Row in prod-eu | Dismissal in prod-eu | prod-eu reads |
|---|---|---|---|
| `DATABASE_URL` | v1, `postgres://eu` | | its own, an override |
| `EU_REGION` | v1, `eu-west-1` | | its own, an addition |
| `STRIPE_KEY` | none | | prod's `sk_live_1`, inherited |
| `SENTRY_DSN` | none | yes | nothing, removed |

A read walks the chain nearest first, in one read-only snapshot, so a
write that sets a key and ends its removal meanwhile is seen whole or not
at all, and the snapshot closes before the vault is asked. A key is settled by the first
environment that holds it live or dismissed it. That's the whole rule.
It's `readableValues` in `packages/server/src/api/references.ts`, a loop
over the layers.

**Reset to the parent** archives the override row. Archived rows are not
live, so the parent's value shows through again, and the override keeps
its history ("prod-eu set its own DATABASE_URL from 3 Oct to 9 Oct").
Writing the key again revives the row with a new version. Reset takes
`secret.write`, not `secret.archive`, since it loses nothing: a Developer
who may override may also stop overriding.

**Removing is dismissing.** A dismissal already means "this environment
deliberately does without K" (`dismissed_keys`, from 0.6). In a plain
environment that only hides K from the missing-keys strip. In a fork it
also hides the parent's K. One fact, one record. Restoring the dismissal
brings the inherited value back. A live row of the fork's own beats its
dismissal, so writing a removed key gives it a value. Two records, the
row and the dismissal, now describe one key, so one rule keeps them
apart: whatever makes a fork's row live ends its key's removal, in the
same transaction, through one function, `endRemovals`. A row becomes live
in exactly four places, and each calls it: a write (a value or a
reference), a restored version, an unarchive, and a rename onto the key.
A later reset then lands on the parent's value, not on "removed".

This is the design's one sharp edge. Reviewers found the missing call
four times, a different path each time, before the list above was
checked to be complete. A future fifth path has to call `endRemovals`
too. The alternative is a removed state on the fork's own row, one record
per key. It needs a new column, and every write path would have to clear
it, so it has the same edge with no reuse. I kept dismissals, and a test
per path.

### A personal config is a fork with an owner

`market/dev@ada` is an environment with `parent_id = dev` and `owner =
user:ada@acme.example`. It inherits, overrides, adds and removes exactly
like `prod-eu`. Only three things differ, and all of them are access:

1. Only its owner reads or writes it, and only while they read its parent
   (section 3).
2. It isn't one of the project's environments. It stays out of lists,
   switchers and the missing-keys comparison, except for its owner, and
   for the project's maintainers, who may delete it.
3. Its address is the parent's path plus `@me` (section 5). Its slug is
   generated and never shown, for example `dev-p-3f9c2a1b`.

So one model covers both asks. Splitting them would mean two resolution
rules, two UIs and two sets of tests, for a difference that lives only in
who may read.

### How Doppler does it, and where coffre differs

Doppler has root configs, one per environment, and branch configs under
them (`dev_stripe_billing`). A branch reads its root live and may
override a key or add one. Its docs never show a branch hiding a key the
root has, and a branch can't have a branch. A personal config is a branch
named `dev_personal` that resolves to a different config for each user,
private to them. A repo commits `config: dev_personal` in `doppler.yaml`.
Access is per environment, so whoever reads a branch reads its root. A
separate paid feature, Config Inheritance, lets any config inherit others,
across projects, in a ranked list.

Coffre keeps the parts that matter and differs in four ways:

- **Removal exists.** An overlay often needs it: `prod-eu` doesn't
  report to the US Sentry. It costs nothing, since dismissals already
  exist.
- **One parent, and chains, capped.** No ranked list of parents; one
  parent keeps "where does this value come from" a single answer. Chains
  are allowed, at most three parents above any environment, for example
  `prod → prod-eu → prod-eu-canary → prod-eu-canary@ada`. A fork can't
  have a personal config as its parent.
- **Access is never inherited.** Doppler gets this for free because
  branches live inside their root's environment. In coffre a fork is an
  environment with its own grants, so the rule has to be stated: inherited
  values take read on the parent.
- **Cross-project sharing stays references.** Doppler's Config Inheritance
  is sharing across projects. Coffre has references for that, which the
  vault seals key by key. Inheritance stays within a project.

### Options I rejected

- **A fork made of references.** `coffre fork --reference` exists. Its
  keys follow prod's values, but it doesn't pick up keys added to prod
  later, it writes one sealed vault entry per key, and only its creation's
  log entry says where it came from. It's the right tool for lending
  specific keys to people who can't read the source, which is a different
  job.
- **Inheritance that lends, sealed by the vault.** The vault would seal
  "prod-eu inherits prod", and anyone reading prod-eu would read prod's
  values through it, as references work. It's the same machinery as
  references, but it breaks their founding rule, "a reference is a
  decision taken when it's created". The decision would cover keys that
  don't exist yet. Add `PAYMENTS_ROOT_KEY` to prod next month, and every
  reader of every fork of prod reads it, with nobody having decided they
  should.
- **Personal overrides as a property of each secret** (Infisical's model).
  That's an override per key per person, with no inheritance of new keys
  and no removal. It's also a second model next to environments.

## 2. Semantics, by example

**The parent's value changes.** Cy rotates `market/prod/STRIPE_KEY` to
`sk_live_2`. The next `coffre run market/prod-eu` reads `sk_live_2`. A
fork that overrides the key keeps its own value. Its row is marked
"prod changed since" while prod's version is newer than the override,
because an override that silently drifts from what it overrides is the
classic overlay bug.

**A key is added to the parent.** Cy adds `NEW_KEY` to prod. It's in
`prod-eu` at once, and in `dev@ada` if it was added to dev. That's the
point of inheriting.

**A key is renamed in the parent.** Cy renames `STRIPE_KEY` to
`STRIPE_SECRET_KEY` in prod. The inherited key follows by itself, since
its name lives in prod's row. A fork's override or removal is keyed by
name, though. Left alone, `prod-eu` would export its old `STRIPE_KEY`
override and prod's `STRIPE_SECRET_KEY` side by side: EU would quietly run
on the US key. So a rename in a parent renames the same key's overrides
and removals in every fork below it, in the same transaction, logging a
`secret.rename` in each fork, personal configs included. A rename moves no
value, so the renamer needs no access to the forks. If a shared fork
already holds `STRIPE_SECRET_KEY`, the rename is refused and names that
fork. A personal config is never named to anyone but its owner: there,
the colliding key of its own is renamed out of the way
(`STRIPE_SECRET_KEY_2`), the cascade goes through, and its owner is told
on their next read and in their config's log.

**A key moves to a folder.** Folders are per environment. A key the
parent holds is shown in the parent's folder wherever it's inherited or
overridden. A key only the fork has is filed in the fork, as today. That's
derived, not copied, so a move in prod shows in every fork at once.

**A key is archived in the parent.** Inheriting stops, as archived keys
are not live. A fork's override of it stays, and now reads as an
addition. A fork's removal of it does nothing, and the page shows it as
"removed; prod no longer has it", which can be cleaned up.

**The parent is archived or deleted.** Archiving an environment that live
forks inherit from is refused. The 409 names them: "market/prod is
inherited by market/prod-eu: archive it first". This is D41's rule for
references, applied to parents, and it is built. Personal
configs are the exception: they're private and derived, so archiving dev
archives every `dev@…` with it, and restoring dev restores them. A fork
is restored only while its parent is live. Deleting a parent for good is
refused while any fork names it, archived or not: "market/prod is the
parent of market/prod-eu: delete it first". A deleted parent would leave
its forks naming a tombstone forever, unrestorable, and deleting is rare
and the instance Owners' alone, so they delete forks first. Personal
configs are deleted with their parent. If a
parent is archived anyway, around the app, a read of the fork refuses
and says why ("market/prod-eu inherits from market/prod, which is
archived"). It never runs half empty.

**Chains.** Fork `prod-eu` into `prod-eu-canary`, and the canary reads
its own keys, then prod-eu's (including prod-eu's overrides and
removals), then prod's. The canary can set a key prod-eu removed. Making
a fourth level is refused (409). One query per level, three at most,
before the values. The cap is about clarity, not speed: past three, a
reader of a key can't tell where it comes from without a diagram.

**References.**

- *The parent holds a reference.* Say `prod/SHARED` is a reference to
  `billing/prod/SHARED`. prod-eu inherits it, so its readers read through
  prod's reference. The vault checks the reader on the reference's
  holder, prod, which is what inheriting needs anyway.
- *Something references a fork's key.* A reference to a key a fork only
  inherits is refused: "market/prod-eu/STRIPE_KEY is inherited from
  market/prod; reference that instead". A reference to an override is
  fine, as for any key.
- *Personal configs* hold values only: no references out, none in. A
  read through a reference unwraps its source's data key, which isn't
  bound to any owner (section 4). So a reference held in Ada's personal
  config would be guarded only by the `owner` column, which a forged row
  or a 0.6 vault ignores. Ada who wants `billing/dev/X` locally copies
  it.
- *Forking a fork as references* resolves each key to where its value
  really lives, prod's key for an inherited one, as one hop already
  requires.

## 3. Access and audit

**Who may fork.** An inheriting fork takes what any fork takes:
`environment.manage` on the project and read on the parent. A personal
config takes only read on its parent. A Viewer who wants a local
`DATABASE_URL` shouldn't need a maintainer. A service account can't own
one.

**A fork lends nothing.** Bo reads `market/dev` only. Cy makes
`market/dev-eu`, inheriting dev, and grants Bo on it. Bo reads dev-eu's
own keys and, through the fork, dev's, because Bo reads dev. Now suppose
Cy grants Dee on `market/prod-eu` and nothing else. Dee's `coffre run
market/prod-eu` refuses, 403, naming what's missing: "market/prod-eu
inherits SENTRY_DSN, STRIPE_KEY from market/prod, which you cannot read".
Dee still reads prod-eu's own keys one at a time
(`market/prod-eu/DATABASE_URL`). It's all or nothing, as references
already are: never run without a key. The app refuses before the vault is
asked. The vault refuses anyway if asked, since it decides an inherited
read on the parent's place, by the reader's own grants (tested). The
parent check comes before any other refusal. If prod's `SHARED` is a
broken reference into `billing`, Dee hears only that SHARED comes from
prod, never which billing key it pointed at or who broke it.

**What a fork's reader sees of the parent.** The inherited key names,
since key names are not secret within a project (docs/design/environments.md,
"Missing keys"). That they come from prod and prod's folder, too. Version and age
only if they read prod. Never values without read on prod.

**Scoped roles and slugs.** Reading a fork takes read on the fork, and
on each parent it inherits a value from. An overlay is an environment with
its own slug, `prod-eu`, and scopes treat it like any other. A Developer
scoped `only: [prod]` doesn't read prod-eu at all; they read prod. One
scoped `except: [prod]` reads prod-eu's own keys one at a time, but not
what it inherits, so their `run` of prod-eu refuses. That's right: a scope
that excludes prod excludes prod's values wherever they show up. Name forks so scopes read well: `prod-eu`, not `eu`. A personal
config's slug never matters, because nobody's grant decides it (below).

**Personal configs: the owner alone.** Ada's `market/dev@ada` is hers.
Nobody else reads or writes its values: not Cy, not the project's Owners,
not the instance's Owners. The vault reads it for Ada only while Ada reads
dev, deciding on dev's place. So losing dev also loses her personal dev,
and a scope or a grant on the personal environment itself means nothing.
Values in a personal config are typically the person's own (their
sandbox API key, their local database). Nobody else needs them, and an
Owner who could read them would just be one more way they leak. What
others see:

- The project's maintainers (`environment.manage`) see that personal
  configs exist: who owns one, its parent, its key names, and when
  it was last read. They may delete one, which is how offboarding cleans
  up.
- Nobody else sees them: not in lists, the switcher or the missing-keys
  comparison.
- Removing a member makes their personal configs unreadable at once, as
  any removal does. The offboarding report lists them for deletion.

**The log.** Every inherited value is the parent's read. The vault logs
one `secret.read` per key under prod's project, environment and secret,
so prod's history and its offboarding "what to rotate" count it. It also
carries `through`, the fork it was read in, and `also`, which puts it in
the fork's log too:

```json
{ "subject": "market/prod/STRIPE_KEY", "version": 2, "purpose": "run",
  "through": { "environmentId": "…prod-eu", "slug": "prod-eu" },
  "also": { "projectId": "…market", "environmentId": "…prod-eu" } }
```

The audit page words it "cy read market/prod/STRIPE_KEY in
market/prod-eu". `through` is the app's word, checked by the vault to be
a live environment of the same project, other than the value's own. It's
checked once, not again under the log's head as grants are, because it
decides nothing: the vault doesn't ask whether the reader reads the fork
it names. The worst a lying app does is file a read under another live
environment of the same project, a read the reader was allowed anyway. One gap remains. A read
of a reference that the fork inherits has three places (the source, the
holder prod, the fork) and `also` names one, so it goes to the fork, and
prod's log misses that read. That's acceptable for now. A list-valued
`also` would close it, at the price of the log's expression indexes.

## 4. Vault and crypto

Each version has its own data key. The instance's KEK wraps it, with AAD
`coffre.aad.v1|project|environment|secret` (and under KMS, the same three
ids as the encryption context). There's no per-environment key. The
ciphertext is bound to the environment that holds it, so it can't be
reused under another environment's ids.

**Inherited values are served without re-encrypting.** The fork never
copies anything. A read of `prod-eu/STRIPE_KEY` opens prod's current
version as prod's (`SecretRef` with prod's ids), exactly as a reference
opens its source's. So:

- **KEK rotation** changes nothing: no new wraps, and old versions unwrap
  under the key their row names, forks included.
- **Rotating a value** in prod is one write, and every fork reads it next
  time. That's better than copies, which each need rotating.
- **Revocation** is immediate. Take prod away from Cy, and Cy's next read
  of prod-eu's inherited keys refuses. There's nothing cached in the fork
  to revoke.
- **An override** is an ordinary write in the fork, under the fork's ids.

**Personal configs: the owner is in the wrapped key.** A personal config's
privacy can't rest on `environments.owner`, which the app's login writes.
Flip it to Bo, and Bo would read Ada's values. Nor can it rest on grants:
Cy's project grant covers every environment of `market`. The design that
needs no new sealed state:

1. When it wraps a data key for a personal config's value, the vault adds
   the owner to the wrap's AAD: `…|owner:<sha256 of user:ada@acme.example>`
   for a local KEK, and `coffre:owner` in the KMS encryption context. It's
   hashed, because AAD fields are joined with `|` and an email isn't a
   UUID.
2. The vault wraps only for the owner, and only while the owner reads the
   parent. That's `allows(owner, 'secret.read', parent place)`, from the
   vault's own grants, with the parent taken from the database.
3. To unwrap, the vault reads the version's environment's owner from the
   database, refuses anyone else (`personal`), checks the owner reads the
   parent, and unwraps with the owner in the AAD.

A forged `owner` column now fails to decrypt instead of granting: Bo as
owner computes Bo's AAD, which isn't the one Ada's keys were wrapped
under. A cleared column fails the same way. A forged `parent_id` could
only let Ada read her own values after losing the parent, which is the
mildest case. And rolling back to 0.6, whose vault knows nothing of
owners, fails closed: it unwraps without the owner and gets an
authentication failure, so an old release can't leak personal values to
project readers. That's the real reason to bind the owner
cryptographically and not with a sealed log entry, the way references
work. It also explains why personal configs hold no references: a value
read through one is wrapped under its source's ids alone, so the binding
can't reach it.

## 5. Surfaces

### UI

The environment page of a fork:

```
prod-eu  ·  inherits from prod                     All  Overrides  Inherited  Removed
database/
  DATABASE_URL   ••••••••   overrides prod  ·  prod changed since    v1   cy   3 Oct
  DATABASE_POOL  ••••••••   from prod                                v2   prod · 1 Oct
EU_REGION        ••••••••                                            v1   cy   3 Oct
STRIPE_KEY       ••••••••   from prod                                v2   prod · 2 Oct  Rotate
SENTRY_DSN       removed   ·  prod has it                                              Restore
```

- An **inherited** row is muted, with "from prod" linking to the parent's
  row. Its menu has "Override…" and "Remove from prod-eu". Editing its
  value in place is overriding: the save bar counts it as "override
  DATABASE_POOL".
- An **override** says "overrides prod". Its menu has "Reset to prod",
  whose confirmation says the value stops being used and stays in
  history, and "Compare with prod", a deliberate reveal of both, logged
  as two reads.
- A **removed** key is struck through, with Restore.
- An **addition** is an ordinary row.
- The filter chips appear only on a fork.
- **Age and Rotate.** An inherited key's age is its parent's version's,
  and its Rotate tag links to the parent, where rotating happens. An
  override has its own age. That's how references already show "source ·
  1y ago".
- **Switcher.** Forks are indented under their parent: `prod`, then
  `prod-eu`. Your personal configs read `dev · yours`.
- **New environment.** "Start from" offers "Inherit from prod" first, and
  preselects it. Then "A copy of prod", "References to prod" and "Empty".
  The inherit option says what it means: "Keeps reading prod's keys, live,
  except those you set or remove here. Readers of this environment need
  read on prod for those."
- **Personal configs.** "Make my own dev" in dev's menu. Project settings
  list the personal configs, with Delete, for maintainers.
- **The missing-keys strip** is unchanged (below).

### CLI

```sh
coffre fork market/prod prod-eu --inherit          # a fork that inherits
coffre list market/prod-eu                         # each key: (from prod), (overrides prod), (removed: prod has it)
coffre set market/prod-eu/DATABASE_URL             # an override, prompted as ever
coffre remove market/prod-eu/SENTRY_DSN            # does without prod's key; --undo inherits it again
coffre reset market/prod-eu/DATABASE_URL           # back to prod's, its own kept; --undo serves it again
coffre run market/dev@me -- pnpm dev               # your personal dev, or dev if you have none
coffre set market/dev@me DATABASE_URL              # makes your personal dev on first write
```

`coffre.json` names only the instance's URL, and every command takes its
`project/environment` explicitly, so a personal config has to be part of
the path. `@me` is that part. `market/dev@me` reads your personal config
of `market/dev`, and falls back to `market/dev` itself when you have none.
So a repo commits `coffre run market/dev@me -- pnpm dev` in its
`package.json`, and it works for everyone: for Ada with her overrides, for
Bo without any, and in CI, where a service account owns no personal
config. That's Doppler's committed `config: dev_personal`, but in the
path. Writes never fall back: `coffre set market/dev@me` writes yours and
makes it if needed, and `coffre set market/dev` writes the shared one.
`get`, `export` and `missing` resolve forks on the server, as `run` does.
The CLI receives values, as now. `fork --inherit` stays a flag: the CLI's
default is a compatibility promise, and copying stays the default.

### API

```
PUT   /api/projects/market/prod-eu                 {"from": "prod", "inherit": true}
GET   /api/secrets/market/prod-eu                  "parents": ["prod"]; each key's "parent"
PATCH /api/secrets/market/prod-eu/DATABASE_URL     {"inherit": true}      reset to the parent; false undoes it
PATCH /api/projects/market/prod-eu/dismissals      {"SENTRY_DSN": true}   remove; null inherits it again
POST  /api/reveals                                 {"path": "market/dev@me"}   a personal config (PR 2)
```

Each listed key's `parent` is null outside a fork and for a key only the
fork holds; otherwise `{ from, state, changed, reset }`: `state` is
`inherited`, `overridden` or `removed`, `from` the environment holding
the parent's key, `changed` that its value is newer than the override,
and `reset` that the fork's own value was reset and is kept. A key is
listed once: a reset override is folded into its inherited entry, not
listed again as archived.

`GET /api/projects` lists each environment's `parent`, and its owner for a
personal config, to those who may see it. A fork's count is of the keys
it resolves to.

### MCP

The tools take paths, so `market/prod-eu` and `market/dev@me` work as
they are. `list_secrets` gains each key's `parent`, and
`reveal_secret_values` resolves forks like `run`. `create_environment`
takes `inherits`, a slug of the same project, and makes a fork that
inherits; its approval page names the parent. It makes no copies: a copy
reads every value, which is no approval's to grant in passing.

### Missing keys

A fork has what it resolves to: inherited keys aren't missing, and its
removals are dismissals already. A parent is never "missing" a key that
only its own forks hold: `EU_REGION` in prod-eu doesn't flag prod.
Personal configs aren't siblings, either way. So `coffre missing
market/prod-eu --check` in CI behaves as people expect.

### The Action

Unchanged. `environments: market/prod-eu` exports the resolved values, and
`require-complete` uses the resolved check above. CI never meets a
personal config.

## 6. Migrations

`0004_environment_parents` adds `parent_id`, nullable, with its index
and check. On Postgres it also adds the same-project foreign key. This is
an expand-only change. The previous release, serving on the new schema
during a deploy, ignores the column and meets no fork, since only the new
code makes them. Personal configs' `owner`, with its check and its unique
index on `(parent_id, owner)`, comes in PR 2's own migration: nothing in
PR 1 reads or writes it, and a column added before the code that guards
it would only be one the app's login could write unchecked.

- **The foreign key is `NO ACTION`, not `RESTRICT`.** It's checked at the
  end of a statement, not at each row, so one statement that deletes a
  fork and its parent together isn't an orphan. SQLite checks `RESTRICT`
  row by row, which broke the tests' reset.
- **On SQLite the migration is written by hand.** drizzle-kit rebuilds the
  table for any new constraint, and its generated copy selected the new
  columns from the old table. Worse, a migration runs in one transaction,
  where SQLite ignores `foreign_keys=OFF`, so dropping a table other rows
  reference would fail on any database with data. The hand-written
  version adds the columns in place. `parent_id` gets a single-column
  foreign key, since SQLite can't add a table constraint to an existing
  table, and the same-project rule is the app's on SQLite. The
  migration's first line says so. Deployed databases are Postgres.
- **Rollback.** Rolled back to 0.6.2 after forks exist, the old release
  reads a fork as an environment holding only its overrides: inherited
  keys vanish from `run`. Personal configs fail closed (section 4). Worth
  a line in the release notes: archive forks before rolling back past
  0.7.
- **Grants.** No new grant is needed. The app's table-level `INSERT` on
  `environments` covers the columns, and the absent `UPDATE` keeps them
  immutable.

## 7. What 0.7's first PR built

Forks that inherit, everywhere but personal configs:

- **Schema.** `0004_environment_parents`, both engines (section 6).
- **Reads.** `readableValues` resolves the chain in one snapshot (`run`,
  `export`, `get`, reveals); `inheritedRows` and `resolveKeys`
  (`packages/server/src/api/inheritance.ts`) do the same by name for the
  list, the missing keys, the project list's counts, resets and renames.
  The parent check comes before any other refusal, and the vault logs
  inherited reads under the parent with `through` and `also`.
- **Writes.** `PUT … {from, inherit}` makes a fork; a write in a fork
  revives a reset override and ends its key's removal (`endRemovals`, in
  five places now: the reset's undo is the fifth). Reset and its undo are
  `PATCH /secrets/…/:key {inherit}`, under `secret.write`, logged as
  `secret.reset` and `secret.unarchive`, and refused where the parent holds
  no such key or a reference reads the override. A rename carries down to
  every fork below, archived ones included (`renameBelow`), moving
  removals with the key and refusing, named, where a fork holds the new
  name. A reference to a key a fork only inherits is refused, naming the
  parent's key.
- **Guards.** No archiving a parent with live forks, no deleting one any
  fork names, no restoring a fork under an archived parent.
- **Missing keys** compare what environments resolve to, and leave out a
  key only an environment's own forks hold.
- **Surfaces.** The UI's Add environment offers "Inheriting from …"; the
  environment page says what it inherits from, tags each key "from prod",
  "overrides prod" (with "prod changed since") or "removed · prod has it",
  and offers Override, Remove, Restore, Reset to prod and Use its own value
  again, each with an Undo. The CLI has `fork --inherit`, `reset`, `remove`
  and a fork's `list`; MCP's `create_environment` takes `inherits`; the
  audit page reads "revealed market/prod/STRIPE_KEY in market/prod-eu".
- **Tests.** `packages/server/test/inheritance.test.ts` on both engines,
  the CLI's, the UI's sentences, MCP's approval, and the conformance
  check `inheritance`.

Left out, on purpose or for later:

- personal configs (PR 2);
- the page's filter chips, the switcher's indenting, "Compare with prod",
  and preselecting "Inheriting from" in Add environment: an empty
  environment stays the default, as the CLI's copy does;
- a list-valued `also`, so a read of a reference a fork inherits also
  reaches the holder's log (section 3).

## 8. Recommendation

Build it as above, in two PRs, for **0.7.0**. A schema change and a new
read rule make it a minor release.

1. **Forks that inherit.** Built: section 7.
2. **Personal configs.** The vault's owner binding (both KEK providers),
   `@me` in path parsing (server, client, CLI, MCP), privacy in lists,
   switcher, missing keys and audit, the settings list, offboarding and
   deletion, and conformance: another member, an instance Owner included,
   is refused; a forged owner column fails to decrypt; a 0.6 vault fails
   closed (`test:compat`). Two to three days. The binding needs the most
   care in review.

## Questions for Erwin

Answered on 2026-10-17: Erwin took each recommendation (standing rule
R8), reversible before 0.7.0.

1. **Should a fork lend its parent's values to people who can't read the
   parent?** I recommend no. Inheriting is a view of the parent, never a
   grant, and anyone who must read prod's values without prod access gets
   references, key by key, which the vault seals and prod's owners can
   see and break. Saying yes means the vault seals the inheritance, and
   every key added to prod later reaches every fork's readers without
   anyone deciding it.
2. **Who sees a personal config?** I recommend: values for the owner
   alone, instance Owners included, enforced by the vault. The project's
   maintainers see that it exists and its key names, and can delete it.
   The alternative, Owners reading everything, removes the vault binding
   and makes personal configs readable by project grants, like any other
   environment.
3. **How is a personal config chosen?** I recommend an explicit
   `market/dev@me`, falling back to `market/dev` for people who have
   none, so one committed script serves everyone. The alternative is
   swapping `market/dev` for your personal config automatically, as soon
   as you have one. That's less typing, but `coffre set market/dev` then
   needs a way to mean the shared one, and a script reads different values
   for different people with nothing in it saying so.

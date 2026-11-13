# Forks that inherit, and personal configs

`coffre fork market/prod staging` makes a one-off: it copies prod's values, or with `--reference`
makes each key a reference to prod's (docs/design/environments.md). A copy never follows prod, and
a key added to prod later never reaches staging. `fork --inherit` makes an environment that keeps
reading its parent live, except for the keys it sets or removes. A personal config is the same
thing, owned by one person: a developer's own `DATABASE_URL` over the shared dev.

The examples use one project, `market`, and four people. Ada is a developer on `market`. Bo reads
`market/dev` only. Cy is a maintainer on `market`. Dee reads `market/prod-eu` only.

```
market/prod   DATABASE_URL=postgres://prod   STRIPE_KEY=sk_live_1   SENTRY_DSN=https://sentry/prod
market/dev    DATABASE_URL=postgres://dev    STRIPE_KEY=sk_test_1
```

## In short

- **Inheriting never grants.** An inherited value is the parent's, read by the reader's own grants
  on the parent and logged as the parent's read. Lending across a trust boundary stays what
  references are for, one key at a time, sealed by the vault.
- **Nothing is re-encrypted.** The fork opens the parent's ciphertext as the parent's.
- **A personal config is readable by its owner alone,** instance Owners included: the vault binds
  the owner into each wrapped data key, so a forged database row fails to decrypt. Its sensitive
  values, as anywhere, are handed to no person, its owner included.

## 1. The model

### One kind of thing: an environment with a parent

```
environments
  parent_id   uuid, null    the environment it inherits from, same project
  owner       text, null    a personal config's owner, user:<email>; needs parent_id
```

In `packages/db/src/schema.ts`:

- `environments_parent_in_project`, a foreign key on `(parent_id, project_id)` to `(id,
  project_id)`, keeps a parent in the same project. It is `NO ACTION`, checked at the end of a
  statement, so one statement that deletes a fork and its parent together leaves no orphan.
- The app's login gets `UPDATE (slug, name, archived_at)` on `environments` only, so neither column
  can change after insert.
- `environments_parent_check` refuses an environment that is its own parent. The app makes a parent
  before its child, so its chains cannot loop; a longer loop written around the app is refused at
  read, as is a chain past the cap (`MAX_PARENTS`, 3, in `packages/core/src/vault.ts`).
- `environments_owner_check`: an owner needs a parent and is a `user:`.
- `environments_parent_id_owner_key`, unique on `(parent_id, owner)`, gives each person at most one
  personal config per environment. It leaves out tombstones, so deleting one frees its place.

A fork's own keys are ordinary `secrets` rows. Here is `market/prod-eu`, forked from prod, after
Cy sets two keys and removes one:

| Key | Row in prod-eu | Dismissal in prod-eu | prod-eu reads |
|---|---|---|---|
| `DATABASE_URL` | v1, `postgres://eu` | | its own, an override |
| `EU_REGION` | v1, `eu-west-1` | | its own, an addition |
| `STRIPE_KEY` | none | | prod's `sk_live_1`, inherited |
| `SENTRY_DSN` | none | yes | nothing, removed |

**The rule:** a key is settled by the first environment in the chain, nearest first, that holds it
live or dismissed it. A read walks the chain in one read-only snapshot, closed before the vault is
asked, so a write that sets a key and ends its removal meanwhile is seen whole or not at all. Values
resolve in `readableValues` (`packages/server/src/api/references.ts`); `inheritedRows` and
`resolveKeys` (`packages/server/src/api/inheritance.ts`) do the same by name for the list, missing
keys, project counts, resets and renames.

**Reset to the parent** archives the override row. The parent's value shows through again, and the
override keeps its history. It takes `secret.write`, not `secret.archive`, since it loses nothing,
and is logged as `secret.reset`; its undo serves the fork's own value again. It is refused where
the parent holds no such key, or while a reference reads the override.

**Removing is dismissing.** In a plain environment a dismissal only hides K from the missing-keys
strip; in a fork it also hides the parent's K. Restoring the dismissal inherits K again. A fork
cannot remove a key it holds a live value of, which it would go on serving: `coffre remove` says to
reset or archive it first, checked under the log's head.

**The sharp edge: `endRemovals`.** Two records, the row and the dismissal, describe one key. So
whatever makes a fork's row live ends its key's removal in the same transaction, through
`endRemovals` (`packages/server/src/api/secrets.ts`). Otherwise a later reset would land on
"removed" instead of the parent's value. A row becomes live in five places, and each calls it: a
write, a restored version, an unarchive, a rename onto the key, and an override undoing a reset. A
sixth path must call it too; the tests hold one case per path.

### A personal config is a fork with an owner

`market/dev@ada` is an environment with `parent_id = dev` and `owner = user:ada@acme.example`. It
inherits, overrides, adds and removes exactly like `prod-eu`. Only access differs:

1. Only its owner reads or writes it, and only while they read its parent (section 3).
2. It is not one of the project's environments: it stays out of lists, switchers and the
   missing-keys comparison, except for its owner, and for the maintainers who may delete it.
3. Its address is the parent's path plus `@me` (section 5). Its slug is generated and never shown.
4. It holds values only: no references out of it or into it, and nobody forks one (section 4).

### Why this shape

- **One parent, chains capped at three.** One parent keeps "where does this value come from" a
  single answer; past three levels a reader cannot tell without a diagram. For example
  `prod → prod-eu → prod-eu-canary → prod-eu-canary@ada`.
- **Removal exists.** An overlay often needs it (`prod-eu` does not report to the US Sentry), and
  dismissals already exist.
- **No lending.** If the vault sealed "prod-eu inherits prod", every key added to prod later would
  reach every reader of every fork, with nobody having decided it. References lend, one decided
  key at a time.
- **Cross-project sharing stays references.** Inheritance stays within a project.

## 2. Semantics, by example

**The parent's value changes.** Cy rotates `market/prod/STRIPE_KEY`; the next `coffre run
market/prod-eu` reads the new value. A fork's override keeps its own value, marked "prod changed
since" while prod's version is newer, because an override that silently drifts is the classic
overlay bug.

**A key is added to the parent.** It is in every fork at once. That is the point.

**A key is renamed in the parent.** The inherited key follows by itself. An override or a removal
is keyed by name, though: left alone, `prod-eu` would export its old `STRIPE_KEY` override beside
prod's `STRIPE_SECRET_KEY`, and EU would quietly run on the US key. So a rename carries down to
every fork below, archived ones and personal configs included (`renameBelow`), logging a
`secret.rename` in each. It moves no value, so the renamer needs no access to the forks. If a shared
fork already holds the new name, the rename is refused and names that fork. A personal config is
named to nobody but its owner, so there its own key of the new name moves aside (`STRIPE_SECRET_KEY_2`),
logged in it, and the rename goes through.

**Folders.** A key the parent holds is shown in the parent's folder wherever it is inherited or
overridden; a key only the fork has is filed in the fork.

**A key is archived in the parent.** Inheriting stops. A fork's override stays, and reads as an
addition. A fork's removal does nothing and stays listed as such ("removed · prod dropped it"),
with Restore, as when a parent between them removes the key too.

**The parent is archived or deleted.** Archiving a parent with live forks is refused, 409: "market/prod
is inherited by market/prod-eu: archive it first". A fork is restored only while its parent is live.
Deleting a parent is refused while any fork names it, archived or not: a deleted parent would leave
its forks naming a tombstone forever. Personal configs are the exception: private and derived, they
are archived, restored and deleted with their parent. A parent archived anyway, around the app, makes
the fork's read refuse and say why. A fork never runs half empty.

**References.**

- *The parent holds a reference.* prod-eu inherits it; the vault checks the reader on the
  reference's holder, prod.
- *A reference to a key a fork only inherits* is refused, naming the parent's key to a reader of the
  fork. A reference to an override is fine.
- *Forking a fork as references or copies* takes what each key resolves to: where it is held, with
  that folder.

## 3. Access and audit

**Who may fork.** An inheriting fork takes `environment.manage` on the project and read on the
parent. A personal config takes only read on its parent: a Viewer who wants a local `DATABASE_URL`
should not need a maintainer. A service account keeps none.

**A fork lends nothing.** Cy makes `market/dev-eu`, inheriting dev, and grants Bo on it. Bo reads
its own keys and, through it, dev's, because Bo reads dev. Now Cy grants Dee on `market/prod-eu`
alone. Dee's `coffre run market/prod-eu` is 403: "market/prod-eu inherits SENTRY_DSN, STRIPE_KEY from
market/prod, which you cannot read". It is all or nothing, as references are: never run without a key. Dee still reads
prod-eu's own keys one at a time. The app refuses before the vault is asked, and the vault refuses
anyway, since it decides an inherited read on the parent's place. The parent check comes before any
other refusal, so Dee never learns more than a key's name: not where a broken reference of prod's
pointed, nor who broke it.

A fork's reader sees the inherited key names (not secret within a project), that they come from
prod, and prod's folder; versions and ages only if they read prod; never values.

**Scoped roles.** A fork is an environment with its own slug, and scopes treat it like any other.
A Developer scoped `except: [prod]` reads prod-eu's own keys but not what it inherits, so their
`run` of prod-eu refuses: a scope that excludes prod excludes prod's values wherever they show up.
Name forks so scopes read well: `prod-eu`, not `eu`.

**Personal configs: the owner alone.** Nobody else reads or writes `market/dev@ada`'s values: not
Cy, not the project's Owners, not the instance's Owners. The app's `can()` decides its `secret.*`
permissions on its owner and their read on dev, never on grants or roles there, and a grant on one
is refused. So losing dev also loses her personal dev. The values are typically the person's own
(a sandbox key, a local database); an Owner who could read them would be one more way they leak.
What others see:

- Maintainers (`environment.manage`) list a project's personal configs (`GET /personal/:project`,
  `coffre personal`): whose, of what, their key names, and the slug that deletes one. Deleting is
  how offboarding cleans up; the owner may delete theirs too. Neither archives it first.
- The offboarding report lists a member's personal configs. Removing a member makes them unreadable
  at once.
- The log files a personal config's entries under it, so its project's auditors see its key names.

**The log.** An inherited value is the parent's read. The vault logs one `secret.read` under prod
listing the keys it opened there, so prod's history and its offboarding "what to rotate" count it.
It carries `through`, the fork it was read in, and `also`, which puts it in the fork's log too:

```json
{ "secrets": [{ "subject": "market/prod/STRIPE_KEY", … }], "purpose": "run",
  "through": { "environmentId": "…prod-eu", "slug": "prod-eu" },
  "also": { "projectId": "…market", "environmentId": "…prod-eu" } }
```

The audit page words it "… market/prod/STRIPE_KEY in market/prod-eu". `through` is the app's
claim. The vault checks it is a live environment of the same project, other than the value's own,
and refuses a read whose claim fails (`bad_claim`); it decides nothing else, so the worst a lying
app does is file a read under another live environment of the same project, a read the reader was
allowed anyway. A read of a reference the fork inherits has three places (the source, the holder
prod, the fork); `also` names the holder, as for any reference read, and the fork's log does not
list it: that read is the source's, perhaps in another project, which is prod's to tell.

## 4. Vault and crypto

Each version has its own data key, wrapped by the instance's KEK with AAD
`coffre.aad.v1|<project>|<environment>|<secret>` (under KMS, the same ids as the encryption
context), so a ciphertext cannot be reused under another environment's ids.

**Inherited values are served without re-encrypting.** A read of `prod-eu/STRIPE_KEY` opens prod's
current version as prod's, exactly as a reference opens its source's. So KEK rotation adds no wraps
for forks; rotating a value in prod is one write every fork reads next time; taking prod away from
Cy refuses Cy's next read of prod-eu's inherited keys, with nothing cached in the fork to revoke.
An override is an ordinary write under the fork's ids.

**Personal configs: the owner is in the wrapped key.** Privacy cannot rest on `environments.owner`,
which the app's login writes: flip it to Bo, and Bo would read Ada's values. Nor on grants: Cy's
project grant covers every environment of `market`. So:

1. The vault adds the owner to a personal config's wrap: `|owner:<ownerKey>` in the AAD for a local
   KEK, `coffre:owner` in the KMS encryption context. `ownerKey` is the SHA-256 of
   `user:<email>` (`packages/core/src/context.ts`), hashed because AAD fields are joined with `|`.
2. On every key operation the vault reads the environment's owner from the database, refuses anyone
   else (`personal`), checks the owner reads the parent by its own grants, and binds the owner it
   read into the wrap or unwrap.

A forged `owner` column now fails to decrypt instead of granting: Bo as owner computes Bo's AAD, not
the one Ada's keys were wrapped under. A cleared column fails the same way, and so does a vault that
knows nothing of owners. A forged `parent_id` could only let Ada read her own values after losing
the parent, the mildest case.

A **plain** value is stored in the clear beside its ciphertext and read without
the vault, so only the app's `can()` holds it to Ada, the one door every read goes through (list,
`get`, `export`, the proxy's plan, history, versions, dry runs, MCP); whoever reads the database
reads it, as every plain value. A value nobody else should see in a dump is a secret, not plain.
And a personal config holds **no references**: a value read through one is wrapped under its
source's ids alone, so the binding cannot reach it, and only the `owner` column would guard it.

A value written to a personal config without a level takes the level of the value the key reads
now, plain included (`bareLevel`); a generated value is never plain.

## 5. Surfaces

### CLI

```sh
coffre fork market/prod prod-eu --inherit          # a fork that inherits; copying stays the default
coffre list market/prod-eu                         # each key: from prod, overrides prod, removed here
coffre set market/prod-eu/DATABASE_URL             # an override, prompted as ever
coffre remove market/prod-eu/SENTRY_DSN            # does without prod's key; --undo inherits it again
coffre reset market/prod-eu/DATABASE_URL           # back to prod's, its own kept; --undo serves it again
coffre run market/dev@me -- pnpm dev               # your personal dev, or dev if you have none
coffre set market/dev@me DATABASE_URL              # makes your personal dev on first write
```

**`@me` is explicit.** `market/dev@me` reads your personal config of dev, and falls back to dev
itself when you have none. So a repo commits `coffre run market/dev@me -- pnpm dev`, and it works
for Ada with her overrides, for Bo without any, and in CI, where a service account's `@me` is dev.
Swapping `market/dev` for your config automatically would leave `coffre set market/dev` needing a
way to mean the shared one, and a script reading different values for different people with
nothing in it saying so. Writes never fall back: `coffre set market/dev@me` writes yours, making it
if needed. `list` notes when `@me` fell back.

### API

```
PUT   /api/projects/market/prod-eu                 {"from": "prod", "inherit": true}
GET   /api/secrets/market/prod-eu                  "parents": ["prod"]; each key's "parent"
PATCH /api/secrets/market/prod-eu/DATABASE_URL     {"inherit": true}      reset; false undoes it
PATCH /api/projects/market/prod-eu/dismissals      {"SENTRY_DSN": true}   remove; null inherits again
POST  /api/reveals                                 {"path": "market/dev@me"}
```

A listed key's `parent` is `{ from, state, changed, reset, held }`, null outside a fork and for a
key only the fork holds; `held` is false for a removal of a key no parent passes down any more. A
reset override is folded into its inherited entry. For `@me`, the list says `personal: { of,
fallback }`. With no personal config, a write to `dev@me` makes one and any other non-read is 404.
`GET /api/projects/<p>/<e>/version` hashes the read's own resolution, so a rotation in the parent,
an override, a removal or a reset changes it.

### UI, MCP, missing keys, the Action

- **UI.** Add environment offers "Inheriting from …". A fork's page says what it inherits from and
  tags each key "from prod", "overrides prod" (with "prod changed since") or removed, with
  Override, Remove, Restore, Reset to prod and its undo. An inherited key's age and Rotate are its
  parent's. Dev's menu has "My own dev"; the project's Environments tab lists personal configs.
- **MCP.** Tools take paths, so `market/prod-eu` works as it is, and read tools read a person's
  own `@me`. `list_secrets` gives each key's `parent`. `create_environment` takes
  `inherits`, a slug of the same project, and its approval names the parent. It makes no copies: a
  copy reads every value, which is no approval's to grant in passing.
- **Missing keys** compare what environments resolve to: inherited keys are not missing, and a
  parent misses nothing only its forks hold (`EU_REGION` does not flag prod). Personal configs are
  compared with nothing. The Action's `require-complete` uses the same check.

## 6. Tests

The columns came in `0004_environment_parents` and `0007_personal_configs`
(`packages/db/src/migrations/postgres`). Tests: `packages/server/test/inheritance.test.ts`, `packages/server/test/personal.test.ts`, and the
conformance checks for inheritance and personal configs (`packages/conformance/src/checks/environments.ts`).

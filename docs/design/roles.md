# Protected environments, and roles an Owner edits

A design for 0.10, written on 2026-10-18 (W128 PR 4), from Erwin's brief
and R15. Each decision in section 6 is his to review, and reversible.

## 1. What it is for

`market/prod` holds the keys that move money. Its developers need to run
the backend against it and set new values, but nobody should read them:
Developer reads in `dev`, and only uses in `prod`.

```sh
$ coffre environments protect market/prod
market/prod is protected: each role holds there what its protected column says, for people; service accounts as before
$ coffre roles developer
developer  Developer  Read, use and write secrets.
  secret.read   yes   protected: no
  secret.use    yes   protected: yes
  secret.write  yes   protected: yes
```

Ada, a Developer of `market`, reads `market/dev` as before. In `market/prod`
her reveal is refused, and her `coffre run market/prod` gets placeholders
(docs/design/credential-proxy.md): she uses its values and reads none. CI's
service account, a Viewer of `market/prod`, reads them as it always did.

## 2. Protected environments

- **A flag on the environment**, set by anyone who manages environments
  in its project (`environment.manage`), and taken off only by an Owner
  of the whole instance (R15): protecting tightens, unprotecting widens.
  No name patterns: `prod` is protected because someone said so.
- **Forks stay protected.** A fork of a protected environment, a copy or
  one that inherits, is protected from its first moment: the vault
  protects its id before its row exists, and only an Owner unprotects it.
  Each protected id keeps when it was protected: one with no row ten
  minutes later is a fork refused or abandoned, and protects nothing.
  Until then, a scoped instance role's holder, whose filters take in no
  environment without a slug, gives nothing on its project that reaches
  it: a refusal for a few minutes, never a widening.
- **The vault keeps it**, as it keeps the instance's settings: the set of
  protected environments is in the vault's newest `policy.change` entry,
  under its MAC, with the roles (section 3). An environment's row says
  nothing of it, so a row written around coffre protects or unprotects
  nothing. Each change is its own entry, naming what changed. Every
  decision the vault makes is made under the log's head, which each
  change takes, so one in flight when prod is protected is refused as
  prod is when it commits (section 8, rule 1).
  A deleted environment, or one in a deleted project, protects nothing:
  the vault leaves it out of the policy it answers, and keeps it in the
  entry.
- **The app's decisions are fenced the same way.** A request reads the
  number of the newest `policy.change` before it asks the vault who is
  calling, so the policy it decides from is that one or newer. Every
  transaction the request commits reads that number again under the head,
  and every plain value it hands back reads it again after the value was
  read; either answers 409, reason `policy_changed`, if it moved: a change
  appends under the same head, so one that passes was not overtaken
  (section 8, rule 2). A Developer's service token weighed before prod was
  protected, and issued after, is refused; asked again, it is weighed as
  prod is now. `coffre run`, `export` and `get` ask again once, after a
  short pause; the UI's confirmations ask the person again.
- **A reference into a protected environment** lends its values to no
  person who does not read them there. A read through a reference is
  decided where its holder is, so `market/dev/DATABASE_URL`, a reference
  to `market/prod/DATABASE_URL` made before prod was protected, would let
  every Developer read prod through dev. Where the source is protected, the
  vault asks a person for the permission at the source too, in their
  protected column, on their own standing, whatever credential they read
  with (its scope governs the holder), and refuses otherwise; the app says so first, the key
  unreadable with why, so a whole environment's read refuses rather than
  go without it, and the listing says it is not readable. The reference
  stays, and reads again once prod is unprotected. A service account
  holds its normal column in prod, and reads through it as before. Making
  one into a protected environment takes reading there, as making any
  reference takes reading its source, decided under the head (rule 1).
- **When the vault cannot read its own policy**, only entries forged in
  its name within reach, no role holds anything, a service account's
  neither, but Owner, which holds everything: a narrowing hidden by forged
  rows is never undone by them. Its edits are unknown, not none, so no
  change is made from them, which would write a policy without the
  protections and role edits the forged rows hide: every change is
  refused but an Owner's of the whole instance, on no credential's scope,
  which starts a fresh policy, the roles as they ship and only what it
  protects. That is the recovery: the Owner then protects again what was
  protected, and edits again what was edited, from the log's own entries
  (`coffre audit`), which still name each change.

## 3. Roles, in two columns

Each role holds permissions in an environment that is not protected, and
in one that is. Project-wide permissions (`environment.manage`,
`grant.manage`, `project.manage`) have one column: a project is never
protected.

| Role | Not protected | Protected |
|---|---|---|
| Viewer | read, use | use |
| Contributor | use, write | use, write |
| Developer | read, use, write | use, write |
| Maintainer | read, use, write, archive; manage environments | use, write, archive |
| Access manager | manage access | |
| Auditor | the log | the log |
| Owner | everything | everything |

The instance's roles have the same two columns (Developer as above).

- **The protected column is for people.** A person, on any credential of
  theirs (a session, a personal token, MCP, a handle), holds a role's
  protected column in a protected environment. A service account holds
  its normal column everywhere: CI and production read what they read,
  as R16 has services get values.
- **What a person gets is the narrowest of three**: their role there, the
  key's sensitivity, and their credential's scope.
- **A service account holds no more than its giver.** A person gives a
  service account a role on a whole project only if they hold it in that
  project's protected environments too, where the service would hold its
  normal column: a Developer of a protected prod gives no Viewer of all of
  `market`, which would read prod.
- **Reading the whole log** takes `audit.read` in both columns of the
  instance role, with nothing narrowing its scope: an Auditor edited to
  read no protected environment's log reads every other place's, as
  anyone who reads places does, and does not verify the whole.
- **The defaults** make protecting mean something at once. No environment
  is protected until someone says so, so 0.10 changes nobody's access.

## 4. The role editor

Settings → Roles, for Owners of the whole instance only (R1, R15):

- A grid per role: one row per permission, a column for normal and one for
  protected environments, and one column for project-wide permissions.
  Reading implies using, and the protected column holds no more than the
  normal one: the grid keeps both true as it is edited.
- **Built-in roles are editable**, each with **Reset to default**. Owner,
  and the instance's Member, are fixed.
- **Custom roles**: an Owner makes one (`release-manager`, a name and a
  description), edits it, and deletes it once no grant names it.
- **Impact, before saving**: the editor asks what the change would do, and
  says it in words: "Widens read for 6 people on 4 protected environments;
  narrows write for 2 people on market/dev". Every person reached by a
  grant of the role, or holding it as their instance role, is weighed at
  every environment they reach, with the role as it is and as it would be.
- **Every edit is audited**: one `policy.change` entry, with the role as
  it was and as it is.

## 5. Tokens never grow

A personal token, a service token and a trust binding carry a scope: a
role at each place. In 0.10 each place keeps the permissions the role held
when the credential was issued, both columns. At each use it holds the
intersection of those and of what its holder holds now:

```
Developer edited to read in prod, after Ada's token was issued
token     developer on market, as issued: prod use, write
Ada now   prod read, use, write
request   prod use, write: the token did not grow
```

Narrowing a role narrows every token at once, through its holder. Each
place keeps both columns as they were at issue, and no more than its
issuer held there then (section 8, rule 3): neither the role nor the
issuer, widened later, widens the token. A scope issued before 0.10,
which kept its role's name alone, holds that role as it ships, a constant
no edit changes, so it never widens either. A binding that takes another's place holds the narrower of the
two: replacing a Viewer's binding keeps what the Viewer held.

## 6. Decisions

1. **The protected column applies to people, never to service accounts.**
   *Alternative:* to everyone, which makes a Viewer CI account of a
   protected environment use only, and breaks it.
2. **Role definitions and protection live in the vault's newest
   `policy.change` entry**, as settings live in `settings.change`: one
   read per decision, authenticated by the vault's MAC, each change logged
   by being made. *Alternative:* vault-owned tables with sealed rows, as
   members have, which a migration and a seal per row would cost.
3. **Protecting takes `environment.manage`; unprotecting, an Owner of the
   whole instance.** R15.
4. **Default protected columns drop read from Viewer, Developer and
   Maintainer** (section 3), as Erwin's example has it. *Alternative:* the
   same as their normal columns, so protecting changes nothing until an
   Owner edits the roles.
5. **Custom roles are project roles**, granted as any is. *Alternative:*
   custom instance roles too.
6. **A credential's scope keeps both columns as issued**, capped by what
   its issuer held, always, never the role's name alone (R17).
   *Alternative:* resolve its role against the defaults always, which is
   simpler, and lets a token issued under a narrowed role grow back when
   the role is reset.
7. **Every vault decision takes the log's head before it reads**, a key
   operation's excepted (rule 1). *Alternative:* re-check under the head
   method by method, which three review rounds showed misses some. Cost:
   a decision holds the head for its reads, a few queries.
8. **Every transaction a request commits is fenced**, not only those
   that commit a decision made from the policy (rule 2). *Alternative:*
   fence call site by call site. Cost: a write that races a policy
   change answers 409 once, and a read that hands back a plain value
   reads the newest change and the protected environments' rows again,
   with no lock; one of sealed values reads none.
9. **A scope kept by its role's name alone, before 0.10, holds the role
   as it ships**, a constant no edit changes: it never widens, and the
   credentials CI already holds keep working. *Alternative:* none at all,
   each issued again, which R17 would allow but which narrows nothing a
   constant does not already hold.

## 7. The API

```
GET    /api/roles                     every role and instance role: both columns, `builtin`, `edited`,
                                      `fixed`, `default` (as it ships), `grants`; and `editable`
PUT    /api/roles/<role>              { name, description, permissions, protected }: an edit, or a new role
DELETE /api/roles/<role>              a built-in role as it ships again; one an Owner made, deleted (409 while granted)
PUT    /api/instance-roles/<role>     the same, for an instance role; DELETE resets it
PATCH  /api/projects/<p>/<e>          { "protected": true }: managing its environments; false: an Owner of the whole instance
```

`?dryRun=1` on a `PUT` or `DELETE` answers what the change would do, and
writes nothing: each person reached by a grant of the role, or holding it
as their instance role, and each service account reached by a grant,
weighed at every place they could hold it, with the role as it is and as
it would be, and the policy's revision it was weighed from:

```json
{
  "impact": [
    { "change": "widens", "permission": "secret.read", "protected": true,
      "people": 6, "services": 0, "environments": 4, "projects": 2, "examples": ["ada@acme.example on market/prod"] }
  ],
  "sentence": "Widens secret.read for 6 people on 4 protected environments",
  "revision": "57.3f9a0c2e81b4d7a6"
}
```

`?revision=57.3f9a0c2e81b4d7a6` on the same `PUT` or `DELETE` makes it
as weighed, or answers 409 `policy_changed` if the policy changed since
(section 8, rule 2). A project-wide permission counts `projects` and no environments. Projects
and environments say `protected` where they are listed (`GET
/api/projects`, `GET /api/secrets/<p>/<e>`), a personal config as the
environment it is a config of.

## 8. Rules that hold the policy

Three review rounds found one kind of bug, case by case: a decision made
from one policy and committed under another, and a check on a project
that forgot its protected environments. Four rules close it. Each says
where it applies, all of it, and names a test that fails without it.

**Rule 1: the vault decides under its log's head.** Every vault decision
locks the head right after its members' rows and before it reads
anything (`#decide`, packages/vault/src/vault.ts). Every change to the
policy, the settings, a member or a place appends under that head, so
nothing the decision reads moves before it commits. It applies to
`setAccess`, `admit`, `remove`, `changePolicy` (the actor's standing
included), `setSettings`, `reference`, `endReferences`, `checkpoint`,
a key operation's intent, and the vault's own conversions
(`#replaceEveryProject`, `#declare`). One exception: a key operation
(`#keys`: `unwrap`, `wrap`, `rewrap`) must not hold the head while its key
service answers, so it checks, asks the key service, then takes the head
and checks again before it releases anything.

```
Ada, a Developer of market, asks for a reference from market/prod/KEY to market/dev
meanwhile an Owner protects prod, whose entry appends under the head
before   Ada's reference, decided from the old policy, committed: she read prod through dev
now      it waits for the head, reads prod protected, and is refused
```

Tests, Postgres only (packages/vault/test/policy.test.ts): "a reference
made as prod is protected…", "a service account removed by its manager
as prod is protected…", and "a read in flight when an environment is
protected…".

**Rule 2: everything a request commits, and every value the app opens
itself, is fenced.** `audited` (packages/server/src/api/context.ts),
given the request's caller, checks under the head that the newest
`policy.change` is still the one the caller was loaded with
(`policyStill`), and answers 409 otherwise. Its 409 says `policy_changed`, as does the vault's refusal of a policy
change weighed from an older one. A sealed value needs no fence of the
app's: the vault releases each under its own head (rule 1). A plain
value, which the app opens from its own rows, is handed back only after
`fenced`, one read of the newest `policy.change` and of the protected
environments' rows after the value's,
which takes no lock: a change committed before it is seen, and one after
it came after the value was read, which stands before it. By a reveal,
`coffre run`, the credential proxy's `use`, MCP's and plugins' reads
(`reveal`, through `recorded`'s `fence`), by a listing (`listSecrets`),
and as an import preview's "unchanged" (`dryRunSecrets`). Reads that
hand back no value (key names, history, the log, who holds what) answer
as the policy was when the request began. Every write is fenced:
secrets (set, generate, patch, sensitivity, archive, inherit, restore,
folders), references the app writes, projects and environments (create,
fork, rename, archive, restore, delete, folders), personal configs,
dismissals, MCP approvals; and through the sign-in service, which passes
the caller to `audited`: personal tokens, handles, service tokens, trust
bindings (bound, keys replaced, unbound), and revoking a token. Left
unfenced: what follows through on the vault's own decision, made under
its head (a membership's old sessions and tokens revoked after `admit`
or `remove`), and sign-in's own writes, which decide nothing from a
policy: signing in and out, device login, linking and unlinking
accounts, connecting and disconnecting an MCP app, a CI run's exchange.

The fence reads two things, each by id: the newest `policy.change`, and
the rows of the environments the caller's policy protects. The policy
names those by id, and reads each one's slug, which a scoped instance
role's filters match, from its row (`livePolicy`), so a protected
environment renamed, deleted, or written since (a fork's) is a policy
changed with no entry of its own; `policyStill` reads the rows again and
answers 409 for it, and nothing that renames or deletes one has to
remember to say so. What changes the policy, and how the fence sees each,
is the table below.

A request that changes the policy itself goes on as of its change. It
names the policy it was weighed from by its revision (`policyRevision`,
packages/core/src/vault.ts): the newest `policy.change` and a digest of
the protected environments' slugs, by id, which the vault computes again
under its head and refuses, `policy_changed`, unless equal.
`protectIds` (packages/server/src/api/roles.ts) asks with the caller's,
and the request's caller then holds the policy it made, as of its own
entry. A role's edit (`changeRole`) is asked with its preview's: the
preview answers with the revision it was weighed from, the confirmation
sends it back (`?revision=`), so what was confirmed is what is made, or
the UI weighs it again and asks again, saying why. The UI confirms the
role and definition it weighed, and weighs again one the grid changed
under while it was weighed. A
fork of a protected environment protects its id first and writes on; a
change in between stops it. Its row comes well within the ten minutes the policy
keeps an id with none (`UNWRITTEN_FORK_MS`), or the fork is refused: a
row written later could protect again an id the policy had let go, which
no request is fenced on.

Tests (packages/server/test/roles.test.ts): "rule 2: a reveal of plain
values…", "rule 2: a plain value is fenced by a read…", "rule 2: a
protected environment renamed while a token is given…", "a role edit
weighed from a policy another change overtook…", "a role edit confirmed
with its preview…", "a fork of a protected environment whose row would
come after…", and one per row of the table below.

**Rule 3: a credential never holds more than its issuer held, in either
column.** Each grant of a scope keeps the columns it resolved to at
issue, its role's as the policy defined it then, capped by what its
issuer held there (`issuedGrant`, `heldColumns`,
packages/core/src/access.ts): the normal column as if nothing were
protected, the protected one as a person in a protected environment; for
a grant on a project, in an environment of it no grant names, the least
of all of them, those protected later included: an instance role scoped
to environments by slug (Owner of every `prod`) reaches no such
environment, and counts for nothing there. Every credential issued
now stores both columns (R17): personal tokens and handles
(`personalScope`), a handle keeping at each place what its person holds
there of reading and using, in each column, so an Owner's reads a
protected prod as they do. A handle reaches the environments it is made
for and those they inherit from, nothing else. A credential's scope
governs where a reference is held; at a protected source, the reference
is weighed on its person's own standing (`readsThrough`, and the vault's
`#keys`), never widened by the scope and never narrowed by it: an app
given a handle for `market/dev`, whose person reads `market/prod`, reads
dev's reference into prod, that one key, and `/use/market/prod` refuses
it; an Owner's token on `market/dev` reads all of dev. Service tokens and trust bindings (`issuedScope`), a
binding replaced or its keys replaced (no more than it held before, nor
than two it replaces held at one place, `narrowest`, and weighed by what
it keeps: a role widened since neither widens it nor stops it), and the scopes
sealed onto 0.4's credentials (`sealCredentials`, fenced by the policy
the vault answered with, as rule 2 fences a request). A service credential
is capped by its role alone: issuing one takes the account, and the
issuer unless they manage access there, holding all of the role's normal
column wherever it reaches, protected environments included
(`issuesCredential`), and a service holds no other column. A scope kept
by its role's name alone, before 0.10, holds its built-in role as it ships
(`scopeDefinition`), and a name no built-in role has holds nothing. MCP's connected apps carry feature scopes (`read`,
`write`, `reveal`, `manage-access`), not roles: nothing to keep.

```
Viewer edited to read in protected environments; nothing protected yet
Ada, a Developer of market, makes a token: viewer on market
kept     read, use / use: her Developer's protected column caps the second
prod protected, then Developer widened to read there
Ada reads prod; her token still only uses it
```

A 0.9 app reads a scope with columns as no scope, so a credential 0.10
issues reaches nothing there until a rolling deploy finishes; a 0.9
vault refuses it outright (it throws on a grant it does not know, 500),
so the vault Worker deploys with the app, or first. Acceptable under
R17, nobody running Coffre in production yet. 0.10 reads one 0.9 issued
as its roles ship.

Tests (packages/server/test/roles.test.ts): "rule 3: a personal token
holds no more…", "rule 3: a service token issued under a narrowed
role…".

**Rule 4: a check on a whole project checks its protected environments
too.** A grant on a project reaches each environment of it the policy
protects (`protectedWithin`, packages/core/src/access.ts, each with its
slug, which a scoped instance role's filters read), where a person
holds the protected column and a service account the normal one, so a
check of what someone holds on a project is made there too: giving a
service account a role (`givesService`, and through it `managesService`,
`issuesCredential` and `setsUpServices`, in the app and in the vault's
`setAccess`, `admit` and `remove`, so service tokens and trust bindings
too), and a personal token's scope (`personalScope`). Handles name
environments only. Who reads through a reference (`readersAt`) is weighed
as the policy has each reader, at its source too where that is protected
(`readsThrough`, as the vault's `#keys` decides). The project-wide checks left
(`environment.manage`, `grant.manage`, `project.manage`) have one column,
and a project's log leaves out each protected environment its reader's
role leaves out (`listAudit`).

Tests (packages/server/test/roles.test.ts): "rule 4: a personal token on
a whole project…", "rule 4: who reads through a reference…", "a
reference made before its source was protected…", "a person
gives a service account a role on a whole project only if…", and "a
service token weighed before prod was protected…".

### What changes the policy

Each change that can change what a decision made from the policy
decides, and how the fence (rule 2) sees it: by the newest
`policy.change` (seq), by the protected environments' rows read again
by id (rows), or not at all, and why it need not. A change to the
policy itself, and a role's edit confirmed from its preview, is checked
by the vault for both at once, under its head, as the revision. A change to this list,
or a new way to make one, comes with its row here and its case in
packages/server/test/roles.test.ts ("what changes the policy: …"), where
each is made while Ada gives a token on all of market, a decision rule 4
weighs in protected prod.

| Change | Fenced by | Why |
|---|---|---|
| An environment protected, or unprotected | seq | the vault's `policy.change` |
| A fork of a protected environment | seq, then rows | its id protected first, its row written after, which the forking request carries on (`rowWritten`) |
| A role edited, made, put back or deleted; an instance role edited | seq | the vault's `policy.change` |
| A protected environment renamed | rows | its slug is what a scoped instance role matches |
| A protected environment deleted, or its project | rows | a deleted one protects nothing |
| A fork's id dropped, its row never written | none | an id with no row is in no scope (null slug), and protects no place a request names; until it is dropped, ten minutes on, a check on its project weighs it, and refuses a scoped instance role's holder, never widens |
| An environment not protected renamed or made | none | the policy names no other environment; who holds what there is each grant's, at its slug, as the request found it |
| An environment named again (`name`), archived or restored | none | the policy reads neither |
| A project renamed | none | scopes, grants and the policy name projects by id |
| A grant, a member's instance role or its scope changed | none | who holds what, not the policy: the vault decides each change to it under its head (rule 1), and a credential holds at most what its holder holds at each use (section 5) |
| The policy unreadable (an entry forged or lost) | seq | the closed policy is the newest entry's, read as such; only an unscoped Owner writes it again |


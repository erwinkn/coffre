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
| Developer | `secret.read`, `secret.use`, `secret.write` | yes |
| Admin | `audit.read`, `environment.manage`, `grant.manage`, `project.manage`; people and service accounts | no |
| Owner | everything an Admin holds, and every secret permission, `secret.archive` too | yes |

An Owner whose scope narrows nothing is an **Owner of the whole
instance**: the instance always keeps one, and the vault's configuration
names who becomes the first ("Owners of the whole instance", below).
Project roles (viewer, developer, maintainer,
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
  (INSTANCE_ROLES[holder.role] holds permission && inScope(holder.scope, place))
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

**Running the instance** takes an Admin or Owner whose scope narrows
nothing (`runsInstance`): adding and removing people,
setting instance roles, the instance's settings, a member's offboarding
report, deleting an archived project or environment for good. They manage
every service account too; people set up their own where the setting lets
them ("Setting up service accounts", below).

**Reading the whole log** takes `audit.read` from an instance role whose
scope narrows nothing: an Auditor, Admin or Owner everywhere
(`readsWholeLog`). They read the instance's own entries, sign-ins,
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
  unscoped Admin: another admin does it, and the log says who. An Owner
  of the whole instance may step down, since nothing is more than what
  they hold ("Owners of the whole instance", below).
- An Admin holds no secret permission, scoped or not, and **nobody grants
  themselves a role** (giving one up is fine). That stops a quiet read of one's own, and
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

- **adds a service account**, which holds nothing yet, or adds it with
  its first grants, in one vault decision: a grant refused adds nothing,
  so no account is left without the access it was made for;
- **gives it a grant** on a place where they hold everything the role
  does (`givesService`): a Developer of `market/dev` gives `viewer` or
  `developer` there, never `maintainer` or `owner`, nor `market`, which
  takes holding all of `market`;
- **manages it** (`managesService`) while they reach every grant it holds:
  issue, list and revoke its tokens, add and remove its trust bindings,
  change and take away its grants, remove it. A Developer of `dev`
  manages no account that also holds `market/prod`, whoever gave it that.

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
| issue a token for it, or trust `ci.yml` to sign in as it | yes, while it holds only what she reaches; the token reaches `developer` on `market/dev`, or `viewer` there if she says so |
| the same, once an Admin gives it `viewer` on `market/prod` | no: she does not reach prod |

Every step is in the log, with who took it. A person's lists show them
only the accounts they manage, each with everything it holds, which they
reach anyway; no other account, no person, and no scope (D95).

Four rules close what reaching every grant leaves open:

- **An account with no grant is its maker's.** Only the person who added
  it, as its row says, and those who run the instance, manage it until it
  holds something: otherwise anyone could issue a token for an Admin's new,
  empty account before the Admin grants it prod.
- **Losing access loses the accounts.** An account stays as it is when its
  maker leaves or is narrowed; whoever reaches its grants manages it, and
  they no longer do. Its tokens and bindings keep working until revoked,
  as anything an Admin issued does: offboarding a person lists the tokens
  they issued (`issuedTokens`), to revoke.
- **A wider grant widens no credential.** Each token and binding carries
  its own scope, fixed when it is made ("Credentials' scopes", below): an
  Admin who gives prod to an account a Developer set up for dev gives it
  to none of the tokens and bindings that Developer made.
- **A removed account is its remover's.** A person brings back only an
  account they removed themselves, as its row says; one someone else
  removed, an Admin or another person, comes back only through those who
  run the instance. Otherwise anyone who sets up accounts could undo an
  Admin's removal.

No one grants a person through this, nor themselves (D91), nor a role any
wider than their own: a service account a person sets up reads, at most,
what that person reads.

The setting names environments by slug, so it is policy, not a boundary,
for those who rename environments. Both lists follow the current slug. A
Maintainer of `market` renames `market/prod` to `market/production`, and
`all except [prod]` no longer keeps it to Admins. Under `only [dev,
staging]`, they rename `market/dev` to `market/dev-old`, then
`market/prod` to `market/dev`, and the setting lets it in. Either way,
they set up accounts for it, giving them what they hold. They gain no
read, since they already hold it; they only skip asking an Admin. Each
rename is in the log (`environment.update`). Renaming takes
`environment.manage` on the project, which a Maintainer or an Owner of it
holds: to keep prod to Admins, give those you would not trust with its
service accounts less than Maintainer on the project.

The vault reads the setting from its newest `settings.change` that carries
its MAC, and reports each one in its name it did not write. It reads back
up to 1024 of those, 32 at a time; when there are such entries but none of
its own within reach, the setting is closed (`projects only []`), never
the default, so inserting rows into the log never opens it. Only a log
with no `settings.change` at all is everywhere.

## Credentials' scopes

Every service token and trust binding carries its own **scope**: grants,
as its account's are, a role on a project or an environment. It is fixed
when the credential is made, and a request made with it holds what both
the scope and the account hold then (`allows`, which asks the scope
first):

| | `market/dev` | `market/prod` |
|---|---|---|
| ci-web holds | `developer` | `viewer`, given after the token |
| its token's scope, made before | `developer` | |
| a request with the token | reads and writes | nothing |
| once ci-web holds only `viewer` on `market/dev` | reads | nothing |

So widening an account widens none of its credentials, and narrowing it
narrows them all at once. A scope is the shape of the account's grants
rather than a role's filters (`all`, `only`, `except`): a filter that
takes in projects or environments made later would let a grant the
account is given later through, which is the widening the scope is there
to stop. A grant on a project in a scope does reach the environments made
in it later, as the account's own grant on it does (`covers`): that is no
wider than the account, which holds them through the same grant, and
taking it back from the account takes it from the credential.

**Making one.** Whoever manages the account (`managesService`) makes a
credential whose every grant is one the account holds, every permission
of its role there, and one they could give it (`givesService`):
`issuesCredential`, which the API checks for the pages, the CLI and MCP
alike, and logs `beyond_account` when it refuses. Left out, the scope is
everything the account holds, or, for a binding that replaces others
(`--replace`, or its issuer's keys moved), what those reached of what
the account still holds, so trusting a workload again never widens it.
Through MCP, Approve reads the scope again and is refused if it changed
since the page showed it. One that reaches nothing is refused: the
account needs a grant first. The scope never changes after; to change
it, make another and revoke the first. Its issuer losing access later
shrinks nothing, so CI keeps working when they leave: offboarding them
lists the tokens they issued, each with its scope, to revoke.

Each grant of a scope also keeps whether its issuer was an Owner of its
project (`sensitive`): only then does the credential read the sensitive
values there (R32, `readsSensitive`; docs/design/roles.md, section 3).
Ada's token for ci-web reads `market/dev`'s secrets and none of its
sensitive values, and is told so when it is made (`withheld`).

| Ada, a Developer of every `dev`, for ci-web, which holds `developer` on `market/dev` | Answer |
|---|---|
| a token, scope left out | `developer` on `market/dev` |
| a token for `viewer` on `market/dev` | yes |
| a token for `maintainer` on `market/dev`, or anything on `market/prod` | no: ci-web does not hold it |

**Where it is enforced.** The app reads the scope with the credential,
and asks `allows` with it on every check; it passes it to every vault
call (`credentialScope`), and the vault decides on it too, so a token
scoped to `dev` that asks the vault for a value in `prod` is refused and
logged (`no_grant`). A credential a binding issued for a CI run carries
its binding's.

**A person's personal tokens** (0.7) carry a scope of the same shape,
weighed the same way against what their person holds at each request:
[personal-tokens.md](personal-tokens.md).

**Where it lives.** A `scope` column on `credentials` and
`service_bindings`, from migration `0003_credential_scopes`: the grants as
JSON, projects and environments by id, under the row's MAC (the app's,
`auth_mac`), which a scope makes another kind of tuple: a scope changed
or cleared around the app fails it, and the credential is refused, as a
token row changed around it is. The app's login gains `UPDATE (scope)` for
the conversion below.

**Tokens and bindings of 0.4.** They have no scope. Once per Node
process or Worker isolate (a Worker builds its runtime each request, so
the isolate keeps the flag beside its configuration), before it checks
its first credential, the app seals each live one with what its account holds then, after the vault's conversion
of the grants on every project (`sealScopes`), so each keeps exactly what
it reached. Each account's are sealed in one transaction with a
`token.seal` entry naming them, so a row put back unsealed and sealed
again shows in the log. A vault that cannot answer seals nothing, and the
credential is uncheckable (503) until it can. One that 0.4 makes while
both run, after the process or isolate sealed, is sealed on its first use
instead (`sealCredentials`): a token or a run's credential when `verify`
checks it, a binding when it exchanges, each with the account's grants
the check already asked the vault for, and its own `token.seal` entry.
No 0.5 process uses one unsealed, so nothing granted after its first use
reaches it. `coffre migrate` lists them by account
(`unsealedCredentials`, which `sealScopes` reads too), and says which
account holds nothing, whose credentials would reach nothing for good.
Rolling back to 0.4 fails closed: a sealed row fails 0.4's MAC, and its
token or binding is refused; so does a 0.4 instance still serving while
0.5 rolls out, for every row 0.5 has sealed.

## Owners of the whole instance

Written on 2026-10-14, from Erwin's decision D120. Before 0.6, root
admins, emails in the vault's configuration (`rootAdmins`), held
everything, outside the member table and its rules: nobody could change or
remove them, they granted themselves anything, and the vault checked no
row of theirs. 0.6 has one kind of principal. The most anyone holds is the
Owner role with no scope, an **Owner of the whole instance**
(`ownsInstance`): a member like any other, in People, changed by the rules
above. An Owner scoped to `market` owns market, not the instance, and
counts for neither rule below.

**The instance always has one.** The last active Owner of the whole
instance is not demoted, narrowed or removed, by anyone, themselves
included: the vault refuses with `last_owner`, "you're the last Owner of
the whole instance: make someone else an Owner first", and logs it. The
vault counts the others under the log's head, after the rows it locks:
`admit` and `remove` lock only the actor's row and the subject's, so two
changes about different Owners, Ada removing herself while Omar steps
down, lock nothing in common, and a count under the rows alone would let
both pass, leaving none. The head puts one after the other.
`formal/Coffre.tla` models it (`Owners`: `OwnerStays`, which fails without
`LastOwnerCheckUnderHead`). A row that fails the vault's check counts for
nothing.

**The deployment declares its Owners** (Erwin's decision, 2026-10-16,
standing rule R3). The vault's `owners` (`OWNERS` in a deployment `coffre
init` writes; `bootstrapOwners` and 0.5's `rootAdmins` are read until 0.7)
names people who are Owners of the whole instance whatever the database
says. The vault makes each one an Owner as it starts, at the first call of
each process or Worker isolate once its log holds an entry of its own, and
when one who owns nothing signs in or makes a request (`access`), which is
how a new instance's first sign-in works, before the vault has written
anything. It admits them, brings them back, or gives them the role, as
`system:vault`, `reason: 'owners'`, each change an entry under the vault's
MAC like any other (`#declare`). One whose row fails its check is started
over first, as removing them would. While named, nobody demotes, narrows
or removes them, themselves included: the vault refuses with `not_allowed`,
"the deployment names root@acme.example an Owner (owners, in the vault's
configuration): take them off that list and deploy first", and Users shows
other Owners their Owner tag greyed, hinting "Set by deployment", with a lock
in place of their menu (`about().owners`, which the members list reads).

| The list, at a deploy | Sam, before | After |
|---|---|---|
| `[root, sam]`, a new instance | never signed in | an Owner, at the vault's first call after root's sign-in |
| `[root, sam]` | a Developer, demoted while unlisted | an Owner, at the first call |
| `[root, sam]` | removed | an Owner, brought back |
| `[root]`, Sam taken off | an Owner | an Owner, now one like any other: an Owner may demote him, and he may step down |

So setup and recovery are the same step. Every Owner locked out (they
left, or lost the account they sign in with): add an email you control to
the list, deploy, sign in. A row edited around the vault never adds anyone
to the list, and an edited Owner's row owns nothing: their next request,
or the next process, starts it over and makes them an Owner again. Taking
an email off the list demotes nobody. A listed Owner holds what any Owner
of the whole instance holds, no more: none of a root admin's exceptions. The vault takes
their row, then the log's head its entries take; it only ever adds an
Owner, so `OwnerStays` holds, and the model's `Declare` scenario checks
`DeclaredStay`: someone the list names, once made an Owner, stays one. The
list must name at least one email, so an instance always has an Owner its
deployment can reach; the last-Owner rule above still counts for the
Owners the list does not name, as when the one it names has a row the log
never admitted, which the vault cannot start over.

**Only Owners make Owners** (Erwin's decision, 2026-10-15, standing rule
R1). Making someone an Owner, scoped or not, adding or bringing them back
as one, and changing or removing an Owner, scoped or not, take an Owner of
the whole instance: the vault refuses anyone else, an Admin of all of it
included, with `not_allowed`, "only an Owner of the whole instance makes
someone an Owner, or changes or removes one", and logs it. An Owner of the
whole instance may change their own role, which only ever narrows what
they hold, so may step down, unless they are the last. An Admin keeps
everything else: anyone's role but an Owner's, and an Owner's grants on
projects, which add nothing to what an Owner holds. So an Admin cannot
make itself, or anyone it trusts, an Owner and read every value, nor push
an Owner out.

| Ada, an Admin of the whole instance, asks to | Answer |
|---|---|
| make Carol an Owner, or an Owner of `market` | no |
| make Omar, an Owner of `market`, an Admin, or an Owner of everything | no |
| remove Omar | no |
| make Carol a Developer | yes |

The vault decides it in the decision about the change, under the actor's
row and the subject's, which it locks first (`#decide`): neither role can
change before it commits. So Omar, an Owner, making Carol one while Root
takes Omar's Owner away, either finishes first or finds himself an Admin
and is refused; and Ada removing Carol while Root makes her an Owner
either removes a Member or is refused. Those two decisions share a row,
so the head adds nothing. In the model's `Owners` scenario an Admin tries
both and is refused, beside two Owners stepping down or leaving at once,
who lock nothing in common and leave one, by the head. The app and the pages follow the vault:
People offers the Owner role only to an Owner of the whole instance, and
in place of an Owner's menu shows anyone else a lock saying who may change
them.

A row the vault finds tampered with holds nothing, an Owner's too, so
whoever runs the instance may start it over (remove it) as before; an
Owner whose row fails its check owns nothing until then, unless the
deployment names them, when the vault starts them over itself.

**Upgrading from 0.5.** The list keeps its emails and, until 0.7, its
name, so the first call of a 0.6 vault makes every email 0.5 held a root
admin an Owner of the whole instance, as `system:vault`, `reason:
'owners'`: one who never signed in gets a row too, and nobody loses
anything. Rolled back to 0.5 and forward again, the vault reads the list
it is given, never a root admin's row of 0.5, so it makes nobody an Owner
the list no longer names:

| On an instance that ran 0.6, then 0.5, then 0.6 again | After |
|---|---|
| Sam, taken off the list and made a Developer on 0.6 | a Developer |
| Carol, still listed | an Owner |
| Dan, a root admin of 0.5's list only, who signed in during the rollback | the Member 0.5 made him |

No migration: the rows are 0.5's, `role` `owner` and a null `scope`,
sealed as 0.5 seals them, so 0.5 reads them during the rollout and after a
rollback, when it holds the configured emails root admins again anyway.

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
to the next. It leaves a member the vault has reported tampered with
(`vault.tampered`) as they are, until their access next changes or they
are started over: the vault's report in the log decides, not whether
their row checks out now, so a genuine row put back after a report stays
left. A root admin of 0.5 kept theirs; 0.6 converts theirs like anyone's,
by their row's role, then makes everyone the list names an Owner ("The
deployment declares its Owners", above). That order is the one `coffre
migrate` can say: it reads the same rows by the same function
(`everyProjectConversion`), and cannot tell whom the configuration names.

One rule says whether a report stands, `reportStands` in
`@coffre/db/grants`: the vault applies it to its own entries, passing over
those forged in its name, and `coffre migrate`, which holds no key to tell
them apart, to every entry in its name (`tamperedMembers`, as the app's
lists do). So `coffre migrate` lists every
member the vault may convert, with what it makes of them, and marks one
with a standing report: "left as it is: the vault reported their row
tampered with (if the vault finds that report forged, it makes: …)". What a key decides, it
cannot: the vault converts a marked member whose reports are all forged,
unless 1024 or more are forged, all it reads back, and leaves an unmarked
one whose row was changed and not yet reported, or whose genuine report an
access entry forged after it covers. A forged report never hides a
conversion.

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
  (either filter left out is `all`); for a service account, `{ access }`
  instead, its first grants as `PATCH /api/access` takes them, in the same
  vault call (`setAccess` with `admit`). Members list `instanceRole` and
  `scope`, which is null but for those who run the instance: a scope names
  projects the caller may not see. `GET /api/members?path=market` lists those who reach `market` by
  their instance role too, with no grant. `GET /api/members/<member>/access`
  answers one member's role, scope and the grants the caller manages in one
  SQL query, for their page. `PATCH /api/access/<member>`
  takes projects and environments only: `*` is a 400. Making a project or
  an environment no longer answers `inherited`. `POST
  /api/members/<member>/tokens` and `/bindings` take a credential's
  `scope` by path, as `PATCH /api/access` does, `{ "market/dev":
  "viewer" }`, all the account holds when left out; tokens, bindings and
  offboarding's `issuedTokens` list it the same way, null for one of 0.4
  not sealed yet. `token.create` and `token.bind` log it, by id.
- **CLI.** `coffre members add <member> --role <role> [--projects …]
  [--environments …]`; `coffre grant` takes a project or an environment;
  `coffre settings service-accounts --except-environments prod` sets the
  setting, `coffre settings` shows it. `coffre offboard` of an account its
  manager runs removes it, without the report. `coffre tokens issue` and
  `coffre trust` take `--scope market/dev=viewer,…`, and `coffre tokens`,
  `coffre trust <service>` and `coffre offboard` say what each reaches.
- **MCP.** `admit_member` takes `role` and `scope`; `set_access` takes
  projects and environments; tools for running the instance are listed to
  those who run it, and those for service accounts to anyone who holds
  access, each checked against the account as the API checks it;
  `issue_service_token` and `trust_workload` take a `scope`, which the
  approval page shows. The setting itself is the pages' and the CLI's, as
  permanent deletion is.
- **UI.** A person's role is one dropdown, with a compact scope editor
  under it for every role but Member. "Grant on every project" is gone; a
  service account's Access tab grants on projects and environments only,
  and to someone who set it up, only what they may give. Service accounts
  is in the sidebar of anyone who sets one up, listing those they manage;
  Settings edits who sets them up with the same scope editor. Issuing a
  token or trusting a workload lists the account's grants, each kept or
  left out, at its role or a smaller one; each token and binding says
  what it reaches.

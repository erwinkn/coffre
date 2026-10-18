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
- **The vault keeps it**, as it keeps the instance's settings: the set of
  protected environments is in the vault's newest `policy.change` entry,
  under its MAC, with the roles (section 3). An environment's row says
  nothing of it, so a row written around coffre protects or unprotects
  nothing. Each change is its own entry, naming what changed. Every read
  is decided again under the log's head, which each change takes, so one
  in flight when prod is protected is refused as prod is when it commits.
  A deleted environment, or one in a deleted project, protects nothing:
  the vault leaves it out of the policy it answers, and keeps it in the
  entry.
- **The app's decisions are fenced the same way.** A request reads the
  number of the newest `policy.change` before it asks the vault who is
  calling, so the policy it decides from is that one or newer. A
  transaction that commits a decision made from it (a fork left
  unprotected, a token, a trust binding or a handle with its scope)
  reads that number again under the head and answers 409, "try again",
  if it moved: a change appends under the same head, so one that passes
  was not overtaken. A Developer's service token weighed before prod was
  protected, and issued after, is refused; asked again, it is weighed as
  prod is now.
- **When the vault cannot read its own policy**, only entries forged in
  its name within reach, no role holds anything, a service account's
  neither, but Owner, which holds everything and so writes the policy
  again: a narrowing hidden by forged rows is never undone by them.

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

Narrowing a role narrows every token at once, through its holder. A scope
issued before 0.10 holds the role as its default was, never as edited. A
role as it ships is kept by its name alone, which reads the same, so a
scope written while an older release still serves reads there too: only
an edited or a made role, which no older release knows, keeps its columns.
A binding that takes another's place holds the narrower of the two, each
read the same way, and keeps the result by its name alone where that is
the role as it ships: replacing a Viewer's binding keeps a Viewer.

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
6. **A credential's scope keeps both columns as issued.** *Alternative:*
   resolve its role against the defaults always, which is simpler, and
   lets a token issued under a narrowed role grow back when the role is
   reset.

## 7. The API

```
GET    /api/roles                     every role and instance role: both columns, `builtin`, `edited`,
                                      `fixed`, `default` (as it ships), `grants`; and `editable`
PUT    /api/roles/<role>              { name, description, permissions, protected }: an edit, or a new role
DELETE /api/roles/<role>              a built-in role as it ships again; one an Owner made, deleted (409 while granted)
PUT    /api/instance-roles/<role>     the same, for an instance role; DELETE resets it
PATCH  /api/projects/<p>/<e>          { "protected": true }, or false, an Owner's alone
```

`?dryRun=1` on a `PUT` or `DELETE` answers what the change would do, and
writes nothing: each person reached by a grant of the role, or holding it
as their instance role, weighed at every place they could hold it, with
the role as it is and as it would be:

```json
{
  "impact": [
    { "change": "widens", "permission": "secret.read", "protected": true,
      "people": 6, "environments": 4, "projects": 2, "examples": ["ada@acme.example on market/prod"] }
  ],
  "sentence": "Widens secret.read for 6 people on 4 protected environments"
}
```

A project-wide permission counts `projects` and no environments. Projects
and environments say `protected` where they are listed (`GET
/api/projects`, `GET /api/secrets/<p>/<e>`), a personal config as the
environment it is a config of.

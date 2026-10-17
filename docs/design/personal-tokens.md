# Personal tokens

Written on 2026-10-17, for 0.7, from Erwin's decision D109: a credential's
scope is fixed when it is made, capped by its maker's current rights;
widening the account never widens the credential; narrowing or removing the
account narrows or ends it.

A service account has had bearer tokens since 0.1. A person had only
sessions: a browser's, a `coffre login`'s, and since 0.5 the MCP clients
they connect. A personal token is the missing half: a bearer token that
acts as the person who made it, for a script or a coding agent, for an
afternoon, within a scope they name.

```sh
coffre tokens issue --label cursor-agent --scope market/dev=developer --expires-in 4h
```

## What it holds

**Its scope is a credential scope.** The shape service tokens and trust
bindings carry ([instance-roles.md](instance-roles.md#credentials-scopes)):
a role on a project or an environment, `{ "market/dev": "developer" }`,
places by id under the row's MAC. Not a role's filters (`all`, `only`,
`except`): a filter takes in places made later, which would let a person's
later rights through, the widening the scope is there to stop.

**A request holds what both its scope and its person hold then.** The app
loads the person from the vault at every request, as for a session, and
sets the token's scope as the caller's `credentialScope`, which `allows`
already intersects with; the vault applies the same scope to its own
decisions (`Through`). So, for Ada, a Developer of every `dev`, with a token
for `developer` on `market/dev`:

| Then | The token |
|---|---|
| as made | reads and writes `market/dev`; nothing else |
| Ada is given `viewer` on `market/prod` | still nothing on prod |
| Ada becomes a Member with `viewer` on `market/dev` | reads `market/dev`, writes nothing |
| Ada is removed | refused (401), and added back, still refused |

Removal ends it twice over: the credential carries the generation it was
issued in, which removal moves past, and removal revokes every credential
the person holds, as it does their sessions.

**Made from what they hold now.** Each grant of the scope must be a role
they hold all of at its place when they make it, by their instance role or
a grant (`personalScope`), or the request is refused and logged
(`beyond_holder`). Ada cannot make one for `market/prod`, nor for `market`
as a whole: her role reaches every `dev`, never a project around one.

**Never a role that manages access.** The scope names only `viewer`,
`developer`, `maintainer` and `auditor` (`delegable`): `owner` and
`access-manager` hold `grant.manage`. A project's Owner who wants a token
for all of it names `maintainer`. Since `allows` intersects, no request on
a token holds `grant.manage` anywhere, in the app or in the vault.

**Nothing of the instance's.** A scope names places, so a request on any
credential with a scope runs no instance, reads no whole log and makes no
project (`runsInstance`, `readsWholeLog` and `makesProjects` say no), and
gives no service account anything under the instance's setting
(`givesService`). Service accounts held none of these already; for an
Owner's token, they now hold too.

## What it cannot do

A token acts as its person on their secrets and places, never on who holds
what or how anyone signs in. So it makes nothing that would outlive it or
hold more than it does. The API refuses every route outside its table
(`PERSONAL_TOKEN_ROUTES`, typed over the route table so a new route must
say), and logs each attempt as a refused `token.use` naming the route, for
"ada tried to use a personal token for POST /members/:member/tokens":

- **tokens**: making, listing or revoking any token, a personal one or a
  service account's;
- **people and access**: adding, changing or removing members, their roles
  and grants, and reading the member list or what someone holds;
- **service accounts**: setting one up, its trust bindings, and the
  repository lookups they use;
- **settings**: reading or changing where people set up service accounts;
- **sign-in**: sessions, linked accounts, approving a `coffre login`,
  connecting an MCP client, deciding an MCP client's change;
- **forever**: deleting a project or an environment for good, and
  verifying the whole log or reading what its keys are checked against.

Approving a `coffre login` or an MCP client would each make a credential
with all the person holds, so both also refuse a caller with a scope
themselves, should a route ever reach them.

What it may do is everything else its scope and person allow: read and
reveal, write, archive and restore, folders, references, missing keys,
environments of a project it maintains, `/me`, and the log of the places it
holds `audit.read` in. `coffre logout`, signed in with it, revokes it.

## Lifetime

`--expires-in 30m`, `4h` or `2d`: a minute to a week, an hour unless told.
An hour suits a script or an agent's task; a week is the most, so a token
never quietly becomes a standing credential. Whoever needs one longer
makes another, as a person. Service tokens keep their days (1 to 366).

## Label, and the log

A label is required, and kept on the row and in the `token.create` entry
that made it. Every entry a request on the token writes names its
credential (`credentialId`), the app's directly and the vault's through
its calls' correlation, as for a CI run's credential; the actor is the
person. `GET /api/audit` reads each such entry's token back from its
`token.create` entry, one read per page through an index of its own
(`audit_log_token_create_idx`), and returns it as `token: { id, label }`.
So the log shows "ada@acme.example via token 'cursor-agent' revealed
market/dev", in the pages and `coffre audit`, and the label comes from the
log, under its MAC, not from the row.

## Listing and revoking

`GET /api/members/user:<email>/tokens`, the same route as a service
account's, lists a person's live personal tokens: for them, and for whoever
runs the instance, as their sessions are. `DELETE …/tokens/:id` revokes one,
on the same terms. In the UI, your own are under Sessions in your account;
a person's are on their page, for whoever runs the instance, and their
removal report counts them. In the CLI, `coffre tokens` and `coffre tokens
revoke <id>`, with no service named.

## Storage, and the release before

A `personal` kind of `credentials` row, prefix `coffre_pat_`. Migration
`0005_personal_tokens` widens the kind's check and adds the audit index:
nothing removed or tightened. 0.6 code serving on the new schema during a
deploy makes no personal token, and refuses one, since its prefix is not a
token to 0.6, so it is never read there as a session without its scope.

## The formal model

Making one is the shape of every credential issued from a session: the
vault's answer read before, then, under the log's head, the member's
generation and the asking credential checked again (`#currentCaller`) and
the row inserted with that generation. The model's
`CredentialsAtCurrentGeneration` covers it; no lock or re-check changed.

## Not done

- **Making one in the UI.** The CLI makes them. A picker of what a person
  holds, by place and role, is a page of its own; the account page shows
  the command.
- **A token through MCP.** `/mcp` takes only its own tokens, as before.

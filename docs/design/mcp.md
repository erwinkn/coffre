# An MCP server for coffre

People connect an MCP client, Claude among them, to their coffre instance. The client then
acts as that person, within the scopes they chose when they connected and never beyond their
own grants. coffre confirms every change on its own page before making it, and keeps secret
values away from the model unless the person granted **Reveal values**. The user guide is
[mcp.md](../mcp.md); this note is how it works and why.

## 1. One session, end to end

1. Ada runs `claude mcp add --transport http coffre https://secrets.acme.example/mcp`. Claude
   Code's first request has no token; coffre answers `401` with a pointer to its metadata, and
   Claude Code opens coffre's consent page in her browser, naming itself by its metadata
   document, `https://claude.ai/oauth/claude-code-client-metadata`.
2. The page shows Claude Code, its host `claude.ai`, a warning that the answer goes to
   `localhost`, her email, and the four scopes with Read ticked. She approves with a passkey
   touch. Claude Code gets a one-hour access token and a refresh token.
3. "What does market/staging have?" `list_secrets` answers key names, versions and who changed
   them, never values.
4. "Generate a new SESSION_SECRET." `generate_secret_value` needs Write: `403
   insufficient_scope`. Claude Code re-authenticates, and the consent page opens with Write
   ticked.
5. The next call changes nothing: coffre opens an approval and asks Claude Code to open
   `/approvals/<id>`. The page says it sets `market/staging/SESSION_SECRET` to a new random
   value, replacing version 3, set by Bob on 2 October. Ada approves with a touch; coffre
   writes version 4. Claude Code's retry hears "set, version 4".
6. "Run the tests with staging's secrets." Claude runs `coffre run market/staging -- npm test`
   in the terminal: the values go to the process, not the chat.

## 2. The protocol

coffre serves MCP **2026-07-28**, and the 2025 revisions beside it, at `POST /mcp`
(`packages/server/src/mcp/endpoint.ts`). Each request gets one JSON answer, never a stream, and
there is no session: nothing coffre does needs progress, and on Workers no request should wait
on another or share state across isolates.

**2026-07-28** is stateless: each request carries its version and the client's capabilities in
`_meta`. A server that needs input answers `input_required` with an opaque `requestState`, and
the client sends the same call again with its answers (Multi Round-Trip Requests). coffre
answers `server/discover` (cacheable by anyone for an hour), `tools/list` (`cacheScope:
"private"`, five minutes, since the list is the person's own) and `tools/call`; anything else is
`404` `-32601`. Another `_meta` version is `400` `-32022`. The `MCP-Protocol-Version`,
`Mcp-Method` and, for `tools/call`, `Mcp-Name` headers must match the body, or it is `400`
`-32020`.

**2025-11-25 and 2025-06-18** open with `initialize`, which coffre answers with the version
asked for and no session ID. It then serves `ping`, `tools/list` and `tools/call`, with the same
tools and checks, to requests whose `MCP-Protocol-Version` names one of them; no header at all
(a client older than 2025-06-18) is refused. A stateless server can't remember what a client
declared in `initialize`, so it never elicits from a 2025 client: such a client confirms changes
through the approval link (section 7). No client is read-only because of its revision; only its
scopes limit it.

**Always:** a request whose `Origin` is not coffre's own is refused `403`. Real clients send
none, so no web page can call `/mcp`, and coffre serves no CORS. Methods other than `POST` are
`405`; a notification is answered `202`; a batch is refused. The token is checked before the
body is read.

## 3. Where it lives

Everything is in `@coffre/server`. `coffre init` writes the file routes for both kinds:
`app/src/routes/mcp.ts` (`POST /mcp`), `app/src/routes/[.]well-known.$.ts` (the two metadata
documents, RFC 9728 and RFC 8414), and the consent and approval pages,
`app/src/routes/_solo/oauth.authorize.tsx` and `app/src/routes/_solo/approvals.$approval.tsx`.
The token, registration and revocation endpoints are `POST /api/oauth/token`, `/register` and
`/revoke`, protocol routes beside the device login's; what the pages and the CLI call
(`/api/oauth/authorizations`, `/api/approvals/:id`, `/api/apps`) are in the API's route table.

MCP is on when the deployment's sign-in says so, with one limit:

```ts
auth: signin({
  providers: [github({ … })],
  mcp: { limits: { perSource: env.SIGN_IN_PER_SOURCE } }, // on Node: processLimits()
}),
```

Without `mcp`, all these routes answer `404`, saying which setting turns them on. Behind
Cloudflare Access there is no `signin()`, so no MCP: coffre issues no tokens there, and Access
would stop Claude's servers at the door anyway.

## 4. The authorization server

coffre is its own OAuth 2.1 authorization server (`packages/server/src/mcp/service.ts`): the
issuer is the public URL, the protected resource `<publicUrl>/mcp`.

**Discovery.** A request to `/mcp` without a good token answers:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://secrets.acme.example/.well-known/oauth-protected-resource/mcp", scope="read"
```

The resource metadata names coffre as its one authorization server and `scopes_supported:
["read"]`. The server metadata lists the endpoints; all four scopes and `offline_access`
(accepted and ignored: every connection gets a refresh token); the code and refresh grants;
S256 PKCE; `none` as the only client authentication; `client_id_metadata_document_supported`;
and the `iss` response parameter. Claude uses a metadata document only when both that flag and
`none` are listed. Clients are told only `read` because they ask for what they are told, and the
consent page starts with that ticked; naming all four would have them ask for Reveal values and
Manage access by default.

### Clients

Every client is public: it holds no secret, and PKCE protects its codes. The rules are in
`packages/core/src/mcp.ts`.

- **Client ID Metadata Documents (preferred).** The `client_id` is an HTTPS URL with a path, and
  no query, fragment, user or dot segment, at most 2,048 characters. The consent page fetches it
  through the transport trust bindings use: no redirect, 5 seconds, 64 KiB, and on Node public
  addresses only. The document must name its own URL as `client_id`, list 1 to 10
  `redirect_uris`, and use no client authentication. Each isolate keeps up to 200 parsed
  documents for ten minutes, never a pending fetch.
- **Dynamic Client Registration (fallback).** `POST /api/oauth/register` takes `client_name` and
  1 to 10 `redirect_uris`. A redirect that breaks the rules below is left out rather than
  failing the registration, as long as one remains (RFC 7591 lets the server change what was
  asked): Cursor registers `cursor://…` beside its loopback callback, and refusing it whole would
  lock Cursor out. It answers a random `client_id`. Such a client shows as **Unverified**, since
  its name is only its own claim.

Names are shown without control or bidirectional characters, cut to 100 characters. **Redirect
URIs** must be HTTPS, matched exactly, and for a document on the document's own host, so the
consent page names one host and a document on `evil.example` can't send codes to `claude.ai`;
or loopback HTTP (`127.0.0.1`, `[::1]`, `localhost`) on any port with the exact path, since RFC
8252 lets a native client bind whatever port it gets, and Claude Code does. Nothing else: no
custom scheme, fragment, user or password.

### Consent

`/oauth/authorize` is a coffre page in the sign-in frame. A visitor not signed in signs in and
comes back. Its loader calls `GET /api/oauth/authorizations`, which resolves the client and
checks every parameter. A bad `client_id` or `redirect_uri` is shown on the page and never
redirected to, which would be an open redirect; anything else wrong (no `response_type=code`, no
S256 challenge, a `state` over 1,024 characters, another `resource`, an unknown scope) goes back
to the client as an OAuth error.

The page shows the client's name and, larger, its host; where the answer goes, with a warning
when every redirect is loopback, since any program on the machine can listen there; the person's
email; every scope, those asked for ticked and Read fixed; the person's connections of the same
client this one would replace (section 9); and how many days it lasts.

**Approve** posts the request and the ticked scopes to `POST /api/oauth/authorizations`. The
server checks everything again, since it keeps nothing between the two calls. It requires a
person signed in as themselves, not through a personal token, and a passkey touch bound to the
request and scopes from anyone a passkey stands behind
([passkeys.md](passkeys.md#42-holder-and-ceremony)). Past 20 live connections it refuses. It then
creates the connection and its code, logs `mcp.connect` with the scopes asked for and granted,
and answers `redirect_uri?code=…&state=…&iss=…` (or `error=access_denied`), which the page opens
with `location.assign`: a form post would hit the page's `form-action 'self'`. Every
authorization shows this page, even for a client connected before.

### Codes and tokens

A **connection** is one approved authorization: one person, one client, its scopes. Connected
apps lists them, and ending one ends everything issued under it. A person holds at most 20,
counting those whose code still waits. The same client on two laptops is two connections, so
neither sign-in signs the other out.

- **Code**: 256 random bits, kept as a hash with its S256 challenge, its `redirect_uri` and an
  expiry 60 seconds out. The token endpoint (form-encoded, each field once) checks `client_id`,
  `redirect_uri`, `code_verifier`, and `resource` when given. Redeeming clears the code with a
  conditional update, so of two racing requests one wins; a code presented again ends its
  connection (OAuth 2.1, 4.1.3).
- **Access token**: `coffre_mcp_` + base64url of the connection ID, its scopes, its issue and
  expiry times, and an HMAC-SHA-256 under a key derived from `auditChainKey`
  (`coffre/mcp-tokens/v1`), so a database writer can't mint one. It lasts an hour, never past its
  connection, and has no row. Each request checks the MAC and the time, reads the connection once
  (its own MAC holds; redeemed, unrevoked, unexpired; the passkey it names still live), then asks
  the vault once whether the person is still a member at the connection's generation
  (`vault.access`). So revoking a connection, or removing its person, ends its tokens at the next
  request.
- **Refresh token**: `coffre_mcr_` + 256 random bits, kept as a hash and rotated on every use.
  The previous hash is kept: a replaced token presented again ends the connection (reuse
  detection). A dead one answers `invalid_grant`. A `scope` on refresh may narrow, never widen.
  A connection lasts as long as a CLI login (`people.cliSessionDays`, 30 days unless set).
- **Revocation**: `POST /api/oauth/revoke` (RFC 7009) with either token ends the connection, and
  answers `200` whatever the token, so it tells nobody which exist.

**Audience.** An MCP token is good only at `/mcp`: `/api` reads credentials, and `coffre_mcp_`
is none of their shapes; `/mcp` accepts nothing else, neither a CLI session nor a browser cookie.
So the scopes can't be dodged by calling the API directly.

**Admission.** The endpoints anyone may call (token, registration, revocation, and the consent
page's read when it would fetch a document) pass a limit per source address, each endpoint
counted apart, before any database or network work: the limiter CI sign-ins use, 10,000 per 10
seconds in the examples. Past it, `429`; a limiter that fails refuses with `503`. Their bodies
are read to 128 KiB (`SIGN_IN_BODY_BYTES`). Tool calls pass no limit: a connection acts as its
person, whose other ways in have none.

## 5. Scopes and permissions

| Scope | Label | Lets the client |
|---|---|---|
| `read` | Read, always | see projects, environments, key names, versions, access, the audit log; show a value **to the person** on coffre's page |
| `write` | Write | set, generate, rename, archive, unarchive and restore secrets; create projects and environments |
| `reveal` | Reveal values | receive secret values in tool results |
| `manage-access` | Manage access | grants, admitting and offboarding members, service tokens, trust bindings |

**Never beyond the person's own grants.** Three layers hold that:

1. **Every tool is API calls as the person**, in process, through the same route table,
   permission checks and vault as a page's render. A tool can do no more than the person could
   with the CLI: Ada, a viewer on `market/prod`, gets the API's `403` from `archive_secret`
   there, with or without Write.
2. **Scopes gate tools.** A tool outside the connection's scopes answers HTTP `403` with
   `WWW-Authenticate: Bearer error="insufficient_scope", scope="read write"`, naming what the
   connection holds plus what's missing, because a client asks for exactly that. Not every
   client steps up (Claude Desktop doesn't), so the body is also a tool result telling the model
   how the person grants it: connect again and tick the scope.
3. **The API checks the scope too.** The router refuses any route a request's connection lacks
   the scope for, by `ROUTE_SCOPES` in `packages/server/src/mcp/scopes.ts`. Routes MCP never
   reaches map to `null`: the person's own sign-in, passkeys, connected apps and approvals,
   permanent deletion, freezes, roles, settings. The table is typed over the route table, so a
   new route fails the typecheck until it says. A tool with a bug still can't reach `POST
   /reveals` without `reveal`.

**The tool list is the person's.** `tools/list` leaves out a tool no role the person holds
reaches anywhere, and keeps one their roles reach but their scopes withhold, so clients can step
up when needed. Each tool declares what it needs (`usable` in `packages/server/src/mcp/tools.ts`):
any member, one who may make projects, one who may set up service accounts
([instance-roles.md](instance-roles.md#setting-up-service-accounts)), or a permission held
somewhere. The list is computed from the `vault.access` answer the token check already read. It
only hides: a hidden tool called by name meets the same checks.

**Picking scopes at connection.** Clients ask for `read`, and some never ask for more: Claude
Desktop, given Read, never stepped up and could make no change. So the consent page offers all
four scopes every time, ticks what was asked, and grants what the person ticks. The token
answer's `scope` says what was granted, which may be more than was asked (RFC 6749, 3.3).

## 6. The tools

Paths are coffre's: `market/prod` is an environment, `market/prod/STRIPE_KEY` a secret. Every
tool has `openWorldHint: false`. "Approval" means the call only opens one (section 7).

| Tool | Scope | Read-only, destructive, idempotent | Approval |
|---|---|---|---|
| `whoami`, `list_projects`, `list_secrets {environment}`, `secret_history {secret}`, `list_access {place?}`, `describe_member {member}` | read | ✓ ✗ ✓ | |
| `read_audit_log {path?, actor?, decision?, before?, limit?}`: 50 entries unless asked, 200 at most | read | ✓ ✗ ✓ | |
| `show_secret_value {secret}` | read | ✓ ✗ ✓ | the page shows the value |
| `reveal_secret_values {path}`: a secret or an environment | reveal | ✓ ✗ ✓ | |
| `request_secret_value {secret, note?}` | write | ✗ ✓ ✗ | the person types the value |
| `generate_secret_value {secret, length?, alphabet?}`, `restore_secret_version {secret, version}` | write | ✗ ✓ ✗ | ✓ |
| `rename_secret {secret, newKey}`, `archive_secret {secret}` | write | ✗ ✓ ✓ | ✓ |
| `unarchive_secret {secret}`, `create_project {project}`, `create_environment {environment, inherits?}` | write | ✗ ✗ ✓ | ✓ |
| `set_access {member, changes}`, `offboard_member {member}`, `revoke_service_token {service, id}`, `untrust_workload {service, id}` | manage-access | ✗ ✓ ✓ | ✓ |
| `admit_member {member, role?, scope?, access?}` | manage-access | ✗ ✗ ✓ | ✓ |
| `issue_service_token {service, label?, expiresInDays, scope?}`, `trust_workload {service, profile, issuer?, claims, scope?, label?}` | manage-access | ✗ ✗ ✗ | ✓; a token is shown on the page only |

The hints are for the client; coffre enforces the approval, not them. Overwriting a value counts
as destructive though every version is kept, because a running deploy reads the new one. No tool
takes a secret value as input, so an agent can't supply one. Removing projects or environments,
permanent deletion and the instance's settings stay with people.

Results are JSON in `structuredContent`, repeated as text, under each tool's `outputSchema`, and
lists are paged, to stay under Claude Code's 25,000 tokens and claude.ai's 150,000 characters a
result. The read tools are in `tools.ts`; each change in `changes.ts` is four functions over the
API: a summary, a check before asking, a preview, and the change itself.

## 7. Confirming changes and handling values

### Approvals

An **approval** is a row in `mcp_approvals` (`packages/server/src/mcp/approvals.ts`): its
connection; the tool and its arguments, never an API request; their digest, SHA-256 of the
canonical JSON of both; a status (`pending`, `approved`, `denied`, `cancelled` or `failed`; a
pending one past its expiry reads as expired); its outcome, without values; and when it was
asked, decided, and reported to the client. The person has 5 minutes to decide; the client may
read the outcome for 10 minutes after asking.

**Asking.** A change's call first runs the tool's check, so a call the person could not make is
refused before any approval opens. Then, under the audit log's head, it rejoins the approval the
same call (same connection, same digest) opened in the last 10 minutes, if its client hasn't
heard the outcome, or inserts a new one, at most five pending per connection. Identical calls at
once open one approval, and a burst stays within five.

**With URL elicitation** (a 2026-07-28 client that declared `elicitation.url`, as Claude Code
does), the call answers `input_required` with an `elicitation/create` request in URL mode, the
approval's URL and "Approve on coffre: …", and a `requestState` sealing the approval, the
connection, the call's digest and an expiry under a key of its own
(`coffre/mcp-request-state/v1`). The client retries with the same state; another call's
arguments under it are refused `-32602`. The retry waits on the approval, reading it every
second in plain queries and holding no transaction, for up to 25 seconds, well inside claude.ai's
240 seconds a call; still pending, it answers `input_required` with the state alone, which the
client retries without asking the person again. A `decline` cancels the approval. A `cancel`
means the prompt was dismissed, or that a client with nobody to ask answered it (Claude Code with
`-p` does): the approval stays pending, and the result carries its link.

**Without** (claude.ai and Desktop today, and every 2025 client), the result carries the link for
the model to show, with `structuredContent: { status: "pending", approval: { id, url, expiresAt } }`:

```text
Nothing has changed yet: coffre asks the person to approve this on its own page.
Show them this link, to open signed in to coffre (it expires at 14:08:00Z):

  https://secrets.acme.example/approvals/0b9e5c1a-…

Once they have approved or denied it, call archive_secret again with the same arguments: it answers what became of it.
```

Calling again rejoins it, waits up to 25 seconds, and answers the outcome or the link again. The
person still confirms the exact change on coffre's page, so what coffre enforces is the same.
What is lost is the client vouching that the link is coffre's: a steered model could show a
lookalike, but it could print one at any time anyway.

**The page.** Only the approval's own person decides it, through a live connection at the
generation they connected it in; anyone else is told "this approval is for someone else" and
nothing more. Its API takes a browser session only, never a CLI session or a token, so an app
holding the person's CLI session can't decide its own approvals. Asked with a cookie, its `GET`
needs `Sec-Fetch-Site: same-origin` like its `POST`, since the preview reads as the person. The
page shows:

- the client, the change in coffre's words, and what it replaces, read as the person when the
  page opens, from the API's own previews (`dryRun` for tokens and bindings, the member's report
  for access and offboarding);
- what the client wrote, labelled as the app's ("The app says"), never as coffre's;
- for `trust_workload`, what each numeric ID names, read back from github.com's or gitlab.com's
  API, or "private or unknown: check this ID yourself"; any other issuer is flagged, since
  whoever runs it can sign in as the account. The model picks IDs; the person reads names;
- when the connection holds Reveal values, that the app can read the values the person can,
  including one they are setting;
- a warning when the same change was approved before with no known outcome.

**Approve** sends back the digest the page showed and its **basis**, a digest of what the change
replaces as shown (a secret's current version; the member's roles at each place). The server:

1. recomputes the digest from the stored arguments and refuses one that differs, so what runs is
   what the person read; checks the status, and that the connection still holds the scope;
2. reads the basis again, as the person, and refuses "this changed since you opened it" if it
   moved; when either side couldn't read it, nothing is approved. The API takes no expected
   version, so a write in the moment between this read and the change still lands first;
3. asks a passkey touch bound to the digest, basis and any typed value from anyone a passkey
   stands behind ([passkeys.md](passkeys.md#44-who-is-never-asked-and-who-cannot-be)): one touch,
   one change. Without a passkey under the `optional` policy, a change whose route always needs a
   fresh check (granting, admitting, removing, issuing a token, trusting a workload) is refused
   until the person adds one, and stays pending;
4. under the log's head, reads the approval and connection again and moves `pending` to
   `approved` with a conditional update checked against the database's clock: a double click
   acts once, and a disconnect or an expiry since refuses it;
5. **makes the change there and then**, outside any transaction, through the API in process as
   the person with the connection attached, every check running again;
6. stores the outcome, or `failed` with the API's error, for the client's retry.

The change happens when the person approves, whether or not the client returns, which also
carries what only the page can: a typed value, a token shown once. If the request dies between 4
and 6, the approval stays `approved` with no outcome; a minute on it reads as `failed`, and the
client is told coffre doesn't know whether the change was made, never that nothing changed.

### Values

The agent never supplies a value. **`request_secret_value`** puts a value field on the approval
page; what the person types goes to coffre only. **`generate_secret_value`** has coffre make the
value when the person approves: 32 random bytes in base64url by default, or `hex` or
`alphanumeric`, 16 to 128 characters, seen by nobody unless someone reveals it later.

To read one:

- **To the person (Read):** `show_secret_value` opens an approval whose page shows the value when
  the person presses Reveal. The model hears that it was shown, and no value. It is the one MCP
  call that may reach `POST /reveals` without Reveal values, since the value goes to the page
  alone.
- **To the model (Reveal values):** `reveal_secret_values` returns values in its result, with no
  page: it is a read. The vault logs the reveal and its bulk limit applies. A whole environment's
  reveal leaves out values marked sensitive, naming them. The text begins "These values are now
  part of this conversation and its history", and the consent page warns when the scope is
  ticked.

With a shell, values should go to the process that needs them, not the transcript. The server's
`instructions` tell the model to run `coffre run <project>/<env> [<project>/<env> …] --
<command>` in the person's terminal, to avoid commands that print values, never to ask for a
secret in the chat, and to reveal values only when the person wants the model to see them. The
CLI signs in with its own login; the MCP connection grants it nothing.

## 8. The audit log

Every entry a request through MCP writes carries `via` (the connection, the client's ID and name,
and the approval when there is one) and `credentialId`, the connection's ID, as an exchanged CI
credential's entries carry theirs. The audit page shows "ada@acme.example via Claude Code".

| Action | When |
|---|---|
| `mcp.connect` | consent approved, with scopes asked and granted, or denied |
| `mcp.token` | a code redeemed, a refresh (detail) |
| `mcp.disconnect` | a connection ended, with its reason: `person`, `owner`, `revocation_endpoint`, `code_reused`, `refresh_reused`, `superseded` |
| `mcp.read` | a read-only tool's call that went through (detail) |
| `mcp.call` | a change's call that opens an approval, and every refusal: scope, too many approvals, a bad `requestState`, the API's own |
| `mcp.approve`, `mcp.deny`, `mcp.cancel` | the person's decision, or the client's decline |
| the change's own entries | `secret.write`, `access.grant`, …, with `via` |

Detail actions are in the log and its chain, but `GET /api/audit` leaves them out unless
`detail=1`, as it does sign-ins. A retry that only waits on its approval is not logged again.
Entries name the tool and the paths in its arguments, never a value.

## 9. Connected apps

The account page's **Connected apps** tab lists each connection: name, host, **Unverified** for a
registered client, scopes, last use, expiry, and **Disconnect**. An owner sees and disconnects
anyone's on that person's page, as with sessions; the offboarding report lists them, and removal
ends them through the generation. The CLI has `coffre apps [--json]` and `coffre apps revoke <id>
[--apply]`; the API, `GET /api/apps` and `DELETE /api/apps/:id`.

**A step-up replaces.** A new connection that grants everything an earlier connection of the same
client holds, and more, supersedes it, whether the client asked for the more or the person ticked
it: the earlier one ends when the new one's code is redeemed (`mcp.disconnect`, `superseded`).
One with the same scopes, on a second laptop say, stays.

## 10. Claude as the client

coffre must work with Claude as a custom connector in claude.ai and Desktop (personal or added
by an Owner for a whole organization) and in Claude Code. Most choices above follow
[Claude's connector docs](https://claude.com/docs/connectors/building/authentication): one
authorization server, since Claude reads only the first; the `scope` rules of the `401` and the
step-up; a token endpoint that answers within 10 seconds and rotates refresh tokens.

Claude Code speaks 2026-07-28 with URL elicitation, so it opens approvals itself. claude.ai,
Desktop, mobile and Cowork speak 2026-07-28 for their tool calls (their setup probe sends a
2025-11-25 `initialize`) and declare no elicitation, so they make changes through the link.
coffre reads the capability on every request, so a client that gains it uses it with no change
here. An org-wide connector shares Anthropic's one client ID, but each member connects as
themselves.

**Reachability.** The hosted apps call `/mcp`, `/.well-known/…`, `/api/oauth/token` and
`/api/oauth/register` from Anthropic's servers, `160.79.104.0/21`, so an IP allowlist must let
that range in on those paths. The person's browser reaches the pages from wherever they are.
Claude Code calls from the person's own machine.

## 11. Library

The wire is hand-written rather than built on the official server SDK: coffre needs one endpoint,
a handful of methods and JSON answers, and what makes it safe (tokens, scopes, approvals) is
coffre's either way. The official client, `@modelcontextprotocol/client`, is a dev dependency of
the server's tests (`packages/server/test/mcp-fixture.ts`). It connects in both eras and runs the
OAuth flow and MRTR rounds, so an independent implementation fails the build when coffre's wire
drifts.

## 12. Storage

Three tables on both engines (`packages/db/src/schema.ts`):

- **`oauth_clients`**: registered clients: ID, name, redirect URIs, created at and from where,
  revoked at. MACed over its ID, name, redirect URIs and revocation, so a database writer can't
  add a redirect of their own to a client people approved. Each registration revokes up to ten
  registrations over a week old that no connection names; nothing is deleted.
- **`mcp_connections`**: the person (`user:<email>`) and generation; the client's ID, name and
  host as shown, and how it registered; scopes and redirect URI; the code's hash, challenge and
  expiry; the refresh token's hash and the previous one's; expiry, creation, last use (time and
  address, written at most every five minutes), revocation (when, by whom); the passkey that
  confirmed it. Its MAC covers every field that grants something, as for the other
  [sign-in rows](../architecture.md#sign-in-rows). Where the vault keeps its log of changes
  ([log-015.md](log-015.md)), making or ending a connection is also a change there, sealed by the
  vault before the app commits it (`seal`), as for credentials.
- **`mcp_approvals`**: as in section 7. Not MACed: approving runs nothing by itself. A changed row
  can only make the client report a false outcome, or show the person a different change, which
  they read before approving and whose digest the server recomputes from the stored arguments.

Access tokens and `requestState` have no rows: both are MACed and checked against a connection.

## 13. Security review points

- **Consent phishing.** A link to
  `/oauth/authorize?client_id=https://evil.example/c.json&redirect_uri=https://evil.example/cb`
  shows `evil.example` as the app's host and where the answer goes, larger than the name it
  claims. Redirects must be on the document's host, or loopback, which is flagged; registered
  clients say Unverified; nothing is approved silently. Ada can still approve it; she then sees
  it in Connected apps, and every call it makes is in the log.
- **Already covered above:** token audience (section 4), CSRF (the decisions and the two reads
  that work as the person need `Sec-Fetch-Site: same-origin`; both pages are unframeable), and
  replay (an approval acts once; a `requestState` is bound to its approval, connection and call;
  the approval URL is no credential).
- **An agent driving the person's browser** (Claude in Chrome, a browser tool) could open the
  link and press Approve: coffre sees a valid same-origin session. A passkey touch for that one
  act is the control it can't pass, so connecting and Approve ask one of anyone with a passkey. A
  person without one, under `optional`, stays exposed for the changes that need no fresh check
  (secret writes), which the same agent could make through coffre's UI anyway.
- **A signed-in CLI on the agent's machine.** `coffre run` needs the CLI signed in as the person,
  often where the agent runs. Whoever runs commands there holds that session, and `coffre export`
  or `coffre set` act as the person with none of MCP's scopes or approvals. The approval API
  refuses that session, so an app can't decide its own approvals with it, but it bounds nothing
  else. To keep an agent to its scopes, sign the CLI in elsewhere, or give the agent a scoped
  personal token ([personal-tokens.md](personal-tokens.md)).
- **Prompt injection.** Secret keys match `[A-Za-z_][A-Za-z0-9_]{0,127}` and slugs are slugs, so the
  names the model sees most can't carry sentences; free text (names, labels, audit metadata) is
  returned as JSON data. No change happens without the person reading coffre's page, and no value
  reaches the model without Reveal values. Not defended: a well-formed harmful change the person
  approves without reading; with Reveal values, a value carrying instructions, or a model passing
  a value on to another tool.
- **Approval fatigue.** Five pending at most per connection; an identical call rejoins its
  approval; each is shown alone.
- **Workers.** No isolate keeps a pending promise, no app transaction stays open across a vault
  call, and a waiting retry polls with plain queries.

## 14. Conformance and tests

`coffre-conformance` checks, for both kinds (`packages/conformance/src/checks/mcp.ts`):

1. **Connect.** Discovery, registration (a custom-scheme redirect left out), consent (another
   site's answer refused), redemption and rotation; the tools on 2026-07-28 and after a
   2025-11-25 `initialize`, with no session.
2. **Read can't write.** `403 insufficient_scope`, `scope="read write"`, a result saying how to
   grant Write, and nothing changed; Write ticked on a Read request gives `scope` `read write`.
3. **No change without approval**, with or without URL elicitation. Another person, a forged
   digest, another site and the person's CLI session can neither open nor decide it; Approve acts
   once; the retry reports it; a replayed `requestState` is refused; a typed value is written, a
   generated one reaches nobody.
4. **No value without Reveal values**: every Read and Write result is searched for the seeded
   values.
5. **Every call audited with the client**, the changes' entries with `via`.
6. **Audience and lifecycle.** Tokens refused where they don't belong (`401`), a foreign `Origin`
   (`403`), reused codes and refresh tokens ending the connection, disconnection taking effect at
   the next call, each end logged with its reason.

The server's own suites (`packages/server/test/mcp-endpoint.test.ts`, `mcp-oauth.test.ts`,
`mcp-approvals.test.ts`, `mcp-values.test.ts` and others, on both engines) test each piece and
run the official client against coffre, under the integration fixture that rejects a vault call
made inside a transaction.

# An MCP server for coffre

A proposal, written on 2026-10-05, for Erwin's decision D31, and built
since (#150, #151 and the pull requests after them); where building it
settled a detail, this says what the code does. It targets MCP revision **2026-07-28**, final since 28 July 2026, and
serves 2025-era clients too (section 2).

People connect an MCP client, Claude among them, to their coffre instance.
The client then acts as that person, within the scopes they chose when they
connected and never beyond their own grants. coffre confirms every change on
its own page before making it, and keeps secret values away from the model
unless the person opted into **Reveal values**.

## 1. One session, end to end

Ada works on `market`. She runs this once:

```sh
claude mcp add --transport http coffre https://secrets.acme.example/mcp
```

1. **Connecting.** Claude Code's first request has no token, and coffre
   answers `401` with a pointer to its metadata. Claude Code discovers that
   coffre is its own authorization server. It identifies itself by its
   Client ID Metadata Document, `https://claude.ai/oauth/claude-code-client-metadata`,
   and opens `https://secrets.acme.example/oauth/authorize?...` in the browser.
2. **Consent.** Ada is already signed in to coffre. If she weren't, she would
   sign in with the usual buttons first. The consent page says:

   > **Claude Code** (`claude.ai`) wants to act as you, ada@acme.example, on
   > secrets.acme.example.
   > It receives the answer on this computer (`localhost`). Continue only if
   > you just started this from an app on this computer.
   >
   > ☑ Read: projects, environments, key names, history, access, the audit log
   > ☐ Write · ☐ Reveal values · ☐ Manage access

   Claude Code asked for Read, so only Read is ticked; she could tick
   the others here, and leaves them. She approves. Claude Code gets a
   one-hour access token and a refresh token.
3. **Browsing.** "What does market/staging have?" Claude calls `list_secrets`
   with `market/staging` and gets key names, versions and who changed them,
   never values. The audit log records `mcp.call` from Ada, via Claude Code.
4. **Asking for more.** "Generate a new SESSION_SECRET for staging."
   `generate_secret_value` needs the **Write** scope. coffre answers `403
   insufficient_scope`. Claude Code asks Ada whether to re-authenticate
   "for the scope read write", and opens the consent page again, with
   **Write** ticked this time. Ada approves.
5. **Confirming.** Claude calls `generate_secret_value` again. coffre makes
   no change. It records a pending approval and answers with a URL-mode
   elicitation for `https://secrets.acme.example/approvals/7QF2…`. Claude
   Code asks Ada whether to open that link. The page shows exactly this:

   > Claude Code asks to set **market/staging/SESSION_SECRET** to a new
   > random value (32 bytes, base64url). It replaces version 3, set by
   > bob@acme.example on 2 October. Nobody sees the new value; earlier
   > versions stay restorable.
   >
   > [Approve] [Deny]

   Ada approves. coffre generates the value, writes it as version 4, and logs
   `mcp.approve` and `secret.write`, both naming Claude Code.
6. **Finishing.** Claude Code retries its call with the state coffre gave it.
   coffre sees that the approval was used and answers "SESSION_SECRET is at
   version 4".
7. **Using it.** "Run the tests with staging's secrets." Claude calls
   runs `coffre run market/staging -- npm test` in the terminal, as the
   server's instructions say. The values go to the test process and never
   into the conversation.

Ada can see Claude Code, its scopes and when it was last used on her
account page under **Connected apps**, or with `coffre apps`. She can
disconnect it from either.

## 2. The protocol

**Target: 2026-07-28**, the current revision. It is stateless: there is no
`initialize` and no `Mcp-Session-Id`. Every request carries its protocol
version and the client's capabilities in `_meta`, and a server asks the
client for input with Multi Round-Trip Requests (MRTR). The server answers
`input_required` with what it needs and an opaque `requestState`, and the
client sends the same call again with its answers. That suits Workers: no
request waits on another, and nothing needs to be shared between isolates.

coffre's endpoint is `POST /mcp`. It answers each request with one JSON body
and never streams, because nothing coffre does takes long enough to need
progress. It implements:

- **Modern methods:** `server/discover`, `tools/list` and `tools/call`.
  `tools/list` is the person's own (section 5), so it carries
  `cacheScope: "private"` and a `ttlMs` of five minutes: a role granted or
  taken shows within them. `server/discover`, the same for every token,
  stays `public`, for an hour. Any other method answers `404` with
  `-32601`.
- **Header checks.** `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` must
  match the body, or the answer is `400` `HeaderMismatch` (`-32020`).
  `Mcp-Name` is decoded from its Base64 form first.
- **Origin.** A request whose `Origin` is not coffre's own is refused with
  `403`. Claude's servers and native clients send none, so browser pages
  cannot call `/mcp`. That also means coffre serves no CORS at all.
- **Everything else on `/mcp`.** `GET` and `DELETE` answer `405`.

**Clients on 2025-11-25 (and 2025-06-18).** These are the "legacy" era: they
open with `initialize`. The spec lets one endpoint serve both eras, and
coffre does:

- It answers `initialize` with the version the client asked for, mints no
  session ID, and serves `tools/list` and `tools/call` with the same tools
  and the same checks.
- What it can't do there is elicit. 2025-11-25's equivalent is the
  `-32042` error, which carries a URL. A stateless server can't know
  whether the client declared URL elicitation, because that declaration
  happened in an `initialize` request it no longer remembers.
- So a legacy client confirms changes, and sees values on coffre's page,
  through the approval link, as any 2026-07-28 client without URL
  elicitation does (section 7; Erwin's D62, which replaced answer 3). No
  client is read-only for its protocol version; only its connection's
  scopes limit it.

Requests from a client older than 2025-06-18, with no
`MCP-Protocol-Version` header, are refused.

Section 10 shows where each Claude surface lands.

## 3. Where it lives

Everything is in `@coffre/server`, as the API is. A deployment mounts two
new server routes as file routes and two new pages:

| Path | What | Where |
|---|---|---|
| `POST /mcp` | the MCP endpoint | `app/src/routes/mcp.ts`, `{ ...mcp }` from `@coffre/server/routes` |
| `GET /.well-known/oauth-protected-resource[/mcp]` | protected resource metadata (RFC 9728) | `app/src/routes/[.]well-known.$.ts`, `{ ...wellKnown }` |
| `GET /.well-known/oauth-authorization-server` | authorization server metadata (RFC 8414) | the same file |
| `/oauth/authorize` | the consent page | `app/src/routes/_solo/oauth.authorize.tsx` |
| `/approvals/:id` | the approval page | `app/src/routes/_solo/approvals.$approval.tsx` |
| `POST /api/oauth/token`, `/api/oauth/register`, `/api/oauth/revoke` | the token, registration and revocation endpoints | coffre's own paths under `/api/$`, beside `/api/auth/device` |
| `/api/apps`, `/api/approvals/:id`, `/api/oauth/authorizations` | what the pages and the CLI call | ordinary rows in the API's route table |

The OAuth endpoints live under `/api` so they need no new route files: they
are protocol routes, like the device login's. The MCP URL people type stays
short: `https://<instance>/mcp`.

**Configuration** is code, like everything else. MCP is on when sign-in says
so, as trust bindings are:

```ts
auth: signin({
  providers: [github({ … })],
  workloads: { … },
  // MCP clients, Claude among them, may act as the people who connect them (docs/mcp.md).
  mcp: { limits: { perSource: env.MCP_PER_SOURCE, perConnection: env.MCP_PER_CONNECTION, total: env.MCP_TOTAL } },
}),
```

The limits are three more rate-limiting bindings in `app/wrangler.jsonc` on
Workers, and `processLimits()` on Node (section 4, "Admission").
Without `mcp`, `/mcp` and the OAuth routes answer `404` and say which
setting turns them on.

**`coffre init`** writes all of this for both kinds, and the examples follow,
as they must. **`coffre update`** adds the four new route files to an
existing deployment. It only adds files and never overwrites one. It then
prints the lines to add to `coffre.ts` and `wrangler.jsonc`, because it
doesn't edit a deployment's own code. Until those lines are added, MCP stays
off.

**Cloudflare Access deployments are out of v1.** Behind Access, coffre has
no sign-in of its own and issues no tokens. Access would also stop Claude's
servers at the door. Section 10 covers reachability.

## 4. The authorization server

coffre is its own authorization server: the issuer is the instance's public
URL, and the protected resource is `<publicUrl>/mcp`.

**Discovery.** An unauthenticated request to `/mcp` answers:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://secrets.acme.example/.well-known/oauth-protected-resource/mcp", scope="read"
```

```json
{ "resource": "https://secrets.acme.example/mcp",
  "authorization_servers": ["https://secrets.acme.example"],
  "scopes_supported": ["read"],
  "bearer_methods_supported": ["header"],
  "resource_name": "coffre at secrets.acme.example" }
```

```json
{ "issuer": "https://secrets.acme.example",
  "authorization_endpoint": "https://secrets.acme.example/oauth/authorize",
  "token_endpoint": "https://secrets.acme.example/api/oauth/token",
  "registration_endpoint": "https://secrets.acme.example/api/oauth/register",
  "revocation_endpoint": "https://secrets.acme.example/api/oauth/revoke",
  "scopes_supported": ["read", "write", "reveal", "manage-access", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "revocation_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true }
```

The resource metadata lists only `read`, the minimum, and the `401`
names it too: it is what clients ask for, and what the consent page starts
with ticked. The person ticks the others there, at connection, whatever was
asked; a client that steps up asks for one later (section 5). Claude picks
CIMD only when both
`client_id_metadata_document_supported` and `"none"` are present, and adds
`offline_access` when it is listed (section 10).

### Clients

Every client is public: it holds no secret, and PKCE protects its codes.

- **Client ID Metadata Documents (preferred).** The `client_id` is an HTTPS
  URL with a path, such as `https://claude.ai/oauth/claude-code-client-metadata`.
  - The consent page fetches it through the transport trust bindings
    already use. That transport follows no redirect, stops after 5 seconds
    and 64 KiB, and on Node connects only to public addresses.
  - The document must parse, its `client_id` must equal the URL, it must
    name `redirect_uris`, and `token_endpoint_auth_method` must be `none`.
  - Each isolate or process keeps documents for ten minutes. It keeps the
    parsed document only, never a pending fetch.
  - Nothing is stored until someone consents. The connection then keeps the
    client's name and host for display.
- **Dynamic Client Registration (fallback, deprecated by the spec).**
  - `POST /api/oauth/register` takes `client_name` and `redirect_uris` only:
    at most 5 URIs, and `token_endpoint_auth_method: none`.
  - A redirect URI that breaks the rules below is left out of the
    registration rather than failing it, as RFC 7591 allows, as long as one
    usable URI remains. Cursor registers `cursor://…` beside its localhost
    callback. Refusing the whole registration would lock Cursor out, as it
    does at providers that refuse it.
  - It answers a random `client_id` and stores a row in `oauth_clients`.
  - The consent page shows such a client as **unverified**, because its name
    is only its own claim.
  - Registration passes the admission limits below. MCP Inspector, some
    other clients, and a Claude connector set to "Register automatically"
    use it.

**Redirect URIs** must be one of:

- **HTTPS**, matched exactly. For a CIMD client, it must also be on the
  `client_id`'s host. Claude's hosted callback,
  `https://claude.ai/api/mcp/auth_callback`, is on `claude.ai`, the same
  host as its document. This rule means the consent page names one host,
  and a document on `evil.example` can't send codes to `claude.ai`, or the
  other way round.
- **Loopback HTTP**: `http://127.0.0.1`, `http://[::1]` or
  `http://localhost`, with any port and the exact path. RFC 8252 allows the
  port to vary, and Claude Code needs it, since it binds a new port each
  time.
- Nothing else: no custom schemes such as `cursor://…`, and no plain HTTP
  elsewhere. See the open questions.

### Consent

`/oauth/authorize` is a coffre page in the sign-in frame, built like the
device login page:

1. A visitor who isn't signed in goes to `/login?next=…` and comes back.
2. The page's loader calls `GET /api/oauth/authorizations?…` with the
   request's parameters. The server checks them, fetches the CIMD and
   returns what the page shows. A bad `client_id` or `redirect_uri` is
   shown on the page and never redirected to: an unchecked redirect would
   be an open redirect.
3. The page shows:
   - the client's name;
   - its host, which matters more than the name;
   - where the answer goes, with a warning when that is only `localhost`;
   - the person's own email;
   - every scope, those the client asked for ticked and the others not.
     Read can't be unticked; the person's ticks decide, whatever was
     asked. **Reveal values** carries its warning (section 7).
4. **Approve** and **Deny** call `POST /api/oauth/authorizations` with a
   cookie. The API's same-origin rule applies, so another site can't post
   it.
   - The server checks every parameter again. It keeps nothing between the
     two requests.
   - On Approve, it creates the connection and its code, and logs
     `mcp.connect` with the scopes asked for and those granted. The token
     answer's `scope` says what was granted (RFC 6749, section 3.3), which
     may be more than was asked.
   - It answers the URL to go to:
     `redirect_uri?code=…&state=…&iss=https://secrets.acme.example`, or
     `error=access_denied` on Deny.
   - The page goes there with `location.assign`. A form post would not
     work: the page's `form-action 'self'` would block the cross-origin
     redirect.
5. Every authorization shows this page, even for a client connected before.
   There is no silent re-consent.

### Codes and tokens

A **connection** is one approved authorization: one person, one client, its
scopes. It is what **Connected apps** lists, and revoking it ends
everything issued under it. A person may hold at most 20 live connections.
Past that, consent is refused, with a link to Connected apps. If someone
connects the same client on two laptops, that is two connections, so
neither sign-in signs the other out.

- **Code.**
  - 256 random bits. The connection row stores its hash, its S256
    challenge, its `redirect_uri` and an expiry 60 seconds out.
  - The token endpoint checks:
    - `client_id`, `redirect_uri` and `code_verifier`;
    - `resource`, which must be `<publicUrl>/mcp` if given (Claude always
      sends it).
  - Redeeming clears the code with a conditional update, so of two racing
    requests one wins.
  - A code presented again revokes its connection (OAuth 2.1, section 4.1.3).
- **Access token**: `coffre_mcp_` + base64url(connection ID, issue time,
  expiry, MAC).
  - It lasts **one hour**.
  - It is MACed under a key derived from `auditChainKey`
    (`coffre/mcp-tokens/v1`), so a database writer can't mint one.
  - It has no row of its own. Each request checks the MAC, then reads the
    connection in one query. The connection must be live, unexpired, at
    the member's current generation, and its own MAC must hold. Then comes
    the request's one `vault.access`.
  - So revoking a connection, or removing its member, ends its tokens at
    the next request, not at their expiry.
- **Refresh token**: `coffre_mcr_` + 256 random bits, stored as a hash on
  the connection.
  - **Rotated on every use.** The connection keeps the previous hash too,
    and a rotated-out token presented again revokes the connection (OAuth
    2.1 reuse detection).
  - A dead refresh token answers `invalid_grant`, as Claude expects.
  - A connection lasts as long as a CLI login, `cliSessionDays` (30 days by
    default), and then the person connects again.
  - `scope` on a refresh may narrow the scopes, never widen them.
- **Revocation.** `POST /api/oauth/revoke` (RFC 7009) with either token ends
  the connection.

**Audience.** An MCP token is good only at `/mcp`, by construction:

- `/api` never accepts one. Its credential lookup reads `credentials`, and
  the `coffre_mcp_` shape isn't a credential.
- `/mcp` accepts nothing else, neither a CLI session nor a browser cookie.

The token is bound to the MCP resource (RFC 8707), and the scopes can't be
dodged by calling the API directly.

**Admission.** The unauthenticated endpoints (`token`, `register`, the
consent page's CIMD fetch) pass a limiter per source address and one in
total, before any database or network work, as the OIDC exchange does.
Each connection's tool calls pass a limiter of their own. On Workers these
are Cloudflare rate-limiting bindings; on Node, `processLimits()`. Bodies
are read to 16 KiB at most. A token endpoint that waits on nothing slow
answers well inside Claude's 10 seconds.

## 5. Scopes and permissions

| Scope | Lets the client | Default |
|---|---|---|
| `read` | see projects, environments, key names, versions, access, the audit log; show a value **to the person** on coffre's page | always |
| `write` | set, generate, rename, archive, unarchive and restore secrets; create projects and environments | opt-in |
| `reveal` | receive secret values in tool results | opt-in, with a warning |
| `manage-access` | grants, admitting and offboarding members, service tokens, trust bindings | opt-in |

Their labels are Read, Write, Reveal values and Manage access. Before
0.4.2 the first was `browse` (Browse) and the third `read-values` (Read
values); a connection made then holds an unknown scope for each, which
counts as nothing, so it keeps Read alone until its person connects it
again.

**Never beyond the person's own grants.** Three layers hold that:

1. **Every tool is API calls as the person.** The MCP endpoint
   authenticates the token. It then calls the API in process, with that
   caller, through the same table, permission checks and vault. This is
   the path a page's render takes (`pageClient`). A tool can do no more
   than the person could with `curl` and their session. Ada, a viewer on
   `market/prod`, gets the API's `403` from `archive_secret` there, with or
   without `write`.
2. **Scopes gate tools.** A tool outside the token's scopes answers HTTP
   `403` with `WWW-Authenticate: Bearer error="insufficient_scope",
   scope="read write"`. The `scope` names everything the connection
   already holds plus what's missing, because Claude's docs ask for the
   union. A client that steps up (MCP's incremental consent) asks for it,
   and the consent page opens with it ticked. Not every client does: the
   `403`'s body is the tool's result, an error that names the scope and
   tells the person how to grant it, by connecting the client again and
   ticking it, with the steps in Claude's apps and Claude Code.
3. **The API checks the scope too.** A request that comes in through MCP
   carries its connection. `serveApi` refuses any route that the
   connection's scopes don't allow, by a table of `route → scope`. So a
   tool with a bug can't reach `POST /reveals` without `reveal`.

**The tool list is the person's** (D76). `tools/list`, in either era,
leaves out a tool no role the person holds now reaches anywhere, and keeps
a tool their roles reach but their connection's scopes withhold: clients
see what they could do, and step up when they need to. Each tool declares
what it needs: any member (`whoami`, `list_projects`); someone who runs the
instance, or a person who holds anything anywhere, who may set up service
accounts
([instance-roles.md](instance-roles.md), "Setting up service accounts")
(`list_access`, `describe_member`, `admit_member`, `offboard_member`, the
service-token and trust tools, each checked against the account before it
is offered for approval); one whose scope takes in new projects
(`create_project`); or a permission held
somewhere, by a grant's role or the person's instance role, as the API lets
them. The list is computed on
each request from the `vault.access` answer the token check already read,
so it costs no read of its own. It only hides: `tools/call` is unchanged,
and a hidden tool called by name is refused by the same checks as before.

**Picking scopes at connection.** Clients ask for what the `401` and the
resource metadata name, `read`. Claude Desktop never asked for more:
connected to Erwin's instance, it got Read, and every write tool,
approval link and `request_secret_value` was refused, with no step-up. So
the consent page offers all four scopes on every connection, ticking only
what was asked, and grants what the person ticks. The metadata still names
only `read`: naming all four would have clients ask for, and the page
tick, Reveal values and Manage access by default.

## 6. The tools

Paths are coffre's: `market/prod` is an environment, and
`market/prod/STRIPE_KEY` is a secret. Every tool has `openWorldHint: false`,
because it touches only this instance. "Approval" means the change waits for
coffre's page (section 7).

| Tool | Scope | Hints (read-only, destructive, idempotent) | Approval | API calls |
|---|---|---|---|---|
| `whoami` | read | ✓ · ✓ | | `GET /me`; the connection's scopes and client |
| `list_projects` | read | ✓ · ✓ | | `GET /projects` |
| `list_secrets {environment}` | read | ✓ · ✓ | | `GET /secrets/:p/:e` |
| `secret_history {secret}` | read | ✓ · ✓ | | `GET /secrets/:p/:e/:key/versions` |
| `list_access {place?}` | read | ✓ · ✓ | | `GET /members?path=` |
| `describe_member {member}` | read | ✓ · ✓ | | `GET /members/:m`; for a service, its tokens and bindings |
| `read_audit_log {path?, actor?, decision?, before?, limit?}` | read | ✓ · ✓ | | `GET /audit` |
| `show_secret_value {secret}` | read | ✓ · ✓ | the page shows it | `POST /reveals`, from the page |
| `request_secret_value {secret, note?}` | write | ✗ ✓ ✗ | the person types it | `PATCH /secrets/:p/:e` |
| `generate_secret_value {secret, length?, alphabet?}` | write | ✗ ✓ ✗ | ✓ | `PATCH /secrets/:p/:e`, value made on the server |
| `rename_secret {secret, newKey}` | write | ✗ ✓ ✓ | ✓ | `PATCH /secrets/:p/:e/:key {key}` |
| `archive_secret {secret}` | write | ✗ ✓ ✓ | ✓ | `PATCH …/:key {archived: true}` |
| `unarchive_secret {secret}` | write | ✗ ✗ ✓ | ✓ | `PATCH …/:key {archived: false}` |
| `restore_secret_version {secret, version}` | write | ✗ ✓ ✗ | ✓ | `POST …/:key/restore` |
| `create_project {project, name}` | write | ✗ ✗ ✓ | ✓ | `PUT /projects/:p` |
| `create_environment {environment, name}` | write | ✗ ✗ ✓ | ✓ | `PUT /projects/:p/:e` |
| `reveal_secret_values {path}` | reveal | ✓ · ✓ | | `POST /reveals`; an environment or one secret |
| `set_access {member, changes}` | manage-access | ✗ ✓ ✓ | ✓ | `PATCH /access/:m`, the API's merge patch |
| `admit_member {member, role?, scope?}` | manage-access | ✗ ✗ ✓ | ✓ | `PUT /members/:m` |
| `offboard_member {member}` | manage-access | ✗ ✓ ✓ | ✓ | `DELETE /members/:m`; the page shows its report |
| `issue_service_token {service, label?, expiresInDays}` | manage-access | ✗ ✗ ✗ | ✓, the token is shown on the page only | `POST /members/:m/tokens` |
| `revoke_service_token {service, id}` | manage-access | ✗ ✓ ✓ | ✓ | `DELETE /members/:m/tokens/:id` |
| `trust_workload {service, profile, issuer?, claims, label?}` | manage-access | ✗ ✗ ✗ | ✓ | `POST /members/:m/bindings`, previewed with `?dryRun=1` |
| `untrust_workload {service, id}` | manage-access | ✗ ✓ ✓ | ✓ | `DELETE /members/:m/bindings/:id` |

The hints are for the client. Overwriting a live value counts as
destructive, even though coffre keeps every version, because a running
deploy reads the new one. coffre does not rely on the hints: the approval
is what it enforces.

No tool takes a secret value as input, so an agent can't supply one.
Removing projects or environments, permanent deletion, and the instance's
settings stay with people, in the UI and the CLI.

Results are JSON in `structuredContent`, repeated as a text block, and each
tool declares its `outputSchema`. Lists are paged: the audit log gives 50
entries per call by default. That keeps a result under Claude Code's 25,000
tokens and claude.ai's 150,000 characters.

## 7. Confirming changes and handling values

### Approvals

An **approval** is a row in `mcp_approvals`. It holds:

- its connection;
- the tool;
- a digest of the call: SHA-256 of the canonical JSON of the tool name and
  its arguments;
- the change in API terms;
- a status (`pending`, `approved`, `denied`, `cancelled`, `failed` or
  `expired`);
- a result without values;
- an expiry 5 minutes out, answer 1's bound, for every client; the client
  may read the outcome for 10 minutes after it asked;
- when the client heard the outcome. Until then, the same call (same
  connection, same digest) rejoins the approval, and reads its outcome; after,
  it asks afresh.

The row stores the tool and its arguments, never the API request: the page's
preview and the change itself are both made from them, by the tool's own
code (`packages/server/src/mcp/changes.ts`). The page sends back the digest
it showed, and the server recomputes it from the stored arguments, so what
runs is what the person read.

**On the wire (2026-07-28).** The first call:

```json
{ "resultType": "input_required",
  "inputRequests": { "approve": { "method": "elicitation/create", "params": {
      "mode": "url",
      "url": "https://secrets.acme.example/approvals/0b9e5c1a-…",
      "message": "Approve on coffre: set market/staging/SESSION_SECRET to a new random value" } } },
  "requestState": "<MACed: approval id, connection id, call digest, expiry>" }
```

The client asks the person, opens the URL, then retries with
`inputResponses: { "approve": { "action": "accept" } }` and the same
`requestState`. On that retry, coffre:

1. checks the `requestState` MAC, its expiry, that it belongs to this
   token's connection, and that the call's digest matches. Different
   arguments under the same state are refused.
2. reads the approval:
   - **Approved:** answers the result.
   - **Denied, expired or failed:** answers a tool error that says which.
   - **Pending:** waits. It reads the row again every second, for up to 25
     seconds. If still pending, it answers `input_required` with the state
     only and no new prompt, and the client retries without asking the
     person again.

   The official client SDK, which Claude Code's v2 runtime is built on,
   retries ten rounds by default: about four minutes. claude.ai allows 240
   seconds per tool call.
3. treats `decline` from the client as cancelling the approval, logged as
   `mcp.cancel`. A `cancel`
   means the prompt was dismissed, or that a client with no one to ask
   answered it (Claude Code run with `-p` does, as the live check found):
   the approval stays pending, and the result carries its link, as for a
   client without URL elicitation.

A call identical to a pending one (same connection, same digest) rejoins
that approval rather than opening another. A connection may hold at most
five pending approvals. The call reads its connection's open approvals and
inserts its own under the audit log's head, with its `mcp.call` entry, so
identical calls at once open one approval and a burst stays within five.
It reads only those asked in the last 10 minutes: older ones can no longer
be rejoined, nor still wait. A call the person could not make is refused
before any approval opens, as the API would refuse it on Approve.

**The page.** `/approvals/:id` requires the person's coffre session in
their browser, and only the approval's own person, at the same generation,
may decide it. Anyone else, Bob for instance, sees "this approval is for
someone else", and nothing more. Its API, `GET` and `POST
/api/approvals/:id`, takes a browser session only, never a CLI session or
a service token: deciding on coffre's page is literally what the person
does. Behind Cloudflare Access, it takes Access's cookie, which a client
that is no browser can set too. Its `GET`, asked with a cookie, needs
`Sec-Fetch-Site: same-origin`, as the consent page's does: another site
cannot make coffre run the preview as the person.

The page shows:

- the client;
- the change in coffre's words, with what it replaces. The preview comes
  from the API's own previews: `?dryRun=1` for secrets and bindings, the
  member report for access and offboarding;
- what the client wrote, labelled as the app's ("The app says", "The app
  calls it"), never as coffre's;
- for `trust_workload`, what each numeric ID names, read back from
  github.com's or gitlab.com's API through the transport bindings use (a
  repository, a project, an owner by its path), or "private or unknown:
  check this ID yourself". The model picks the IDs; the person reads the
  names. Only those two hosts are asked: the app may name its own issuer,
  whose API could name its IDs anything. For any other issuer the IDs read
  "coffre can't check this host", and the issuer is flagged: whoever runs
  it can sign in as the account;
- when the connection holds Reveal values, that the app can read values
  the person can read, the one they are setting included, instead of
  "the app never sees it";
- when it was asked for, and when it expires.

**Approve** calls `POST /api/approvals/:id` with the cookie, so the
same-origin rule applies. It sends back the digest the page showed, and the
basis: what the change replaces, read once for the page, so the basis is
what it showed (a secret's current version for the tools that write one,
the member's roles at each place and when they end for `set_access`). The
server:

1. checks the person, the connection (live, at its generation), the scope
   and the expiry;
2. reads the basis again, as the person: a version set or a role changed
   since refuses Approve with "this changed since you opened it". Unread on
   either side, nothing is approved: a page that couldn't read it says so
   and offers no Approve, and a read that fails now refuses, to retry. The API
   takes no expected version, so a write in the moment between this read
   and the change still lands first;
3. moves the approval from `pending` to `approved` with a conditional
   update, under the log's head, after reading the approval and its
   connection again there: a double click acts once, a disconnect since
   the first checks refuses it, and so does an expiry, which the update
   itself checks against the database's clock;
4. **makes the change there and then.** It calls the stored API request in
   process, as the person, with the connection attached. Every check runs
   again, and the change's own entries name the client.
5. stores the outcome (or `failed`, with the API's error) for the client's
   retry.

If the request dies between 3 and 5, or the outcome can't be stored, the
approval stays `approved` with no outcome; the page still hears the change
was made, and sees what only it may. While coffre makes the change, the
page and the client say so. A minute on, it reads as `failed`, its outcome unknown: the client
is told coffre doesn't know whether the change was made, never that nothing
changed, on every call that rejoins it. Its client is never told it ended,
so when the same call opens a new approval later, that page warns the
person they approved it before, with no known outcome.

The change happens when the person approves, on coffre's page. That's what
they saw and clicked, whether or not the client ever comes back. The
client's retry only reads the outcome. It also covers changes that only the
page can carry: a value typed by the person, or a token shown once.

**Without URL elicitation** (answer 1). A 2026-07-28 client that didn't
declare `elicitation.url`, claude.ai's among them, gets the approval link in
the tool's result, as text for the model to show the person:

```text
Nothing has changed yet: coffre asks the person to approve this on its own page.
Show them this link, to open signed in to coffre (it expires at 14:08:00Z):

  https://secrets.acme.example/approvals/0b9e5c1a-…

Once they have approved or denied it, call archive_secret again with the same arguments: it answers what became of it.
```

with `structuredContent: { status: "pending", approval: { id, url,
expiresAt } }`. The same call again rejoins the approval: it waits up to 25
seconds for the person, then answers the outcome, or the link again. The
person still confirms the exact change on coffre's page, signed in as
themselves, so what coffre enforces is unchanged. Legacy clients get the
same link (section 2, D62).

### Setting a value

The agent never supplies a value. There are two tools:

- **`request_secret_value`**: the approval page has a value field (with
  Import .env's paste handling). The person types or pastes; coffre writes
  it. The client gets back "set, version 4".
- **`generate_secret_value`**: coffre generates the value on the server.
  The defaults are 32 random bytes in base64url; `hex` and `alphanumeric`
  are the other alphabets, from 16 to 128 characters. It writes the value
  when the person approves. Nobody ever sees it, unless someone with read
  access reveals it later.

### Reading a value

- **To the person (Read):** `show_secret_value` opens the approval page.
  The value shows only when the person clicks **Reveal**, a `POST` logged
  as a reveal, requested by the client. The model gets "shown to
  ada@acme.example at 14:03" and no value. It is an approval like a
  change's: its Reveal reads the value as the person, with the connection
  attached, and is the one call through MCP that may reach `POST /reveals`
  without Reveal values, since the value goes to the page alone.
- **To the model (Reveal values):** `reveal_secret_values` returns values in its
  result, with no page. It is a read, so it needs no approval. The vault
  logs it as a `reveal` under the access token's credential ID, and the
  app's `mcp.call` names the client. The vault's bulk limit applies as
  always. The result begins with a plain warning: "These values are now
  part of this conversation and its history."

The consent page warns when Reveal values is asked for:

> Values will be sent to Claude. They become part of the conversation:
> whoever can read that conversation, and wherever Claude stores it, has
> them.

### Using secrets: `coffre run`

When the agent has a shell, the values should go to the process that needs
them, not to the transcript. No tool does this: a tool could only print the
command, which the model can write itself. The server's `instructions` tell
the model to run `coffre run <project>/<env> [<project>/<env> …] --
<command>` in the person's terminal. (`coffre login <url>` once per
machine; `coffre run` itself is refused for anyone who cannot read the
environment.)

The CLI signs in with its own device login, as the person, and the MCP
connection grants it nothing.

The server's `instructions`, which clients pass to the model, say the same
in one paragraph:

- never ask the person to paste a secret into the chat;
- to set one, use `request_secret_value` or `generate_secret_value`;
- to use secrets in a command, run it with `coffre run`, and avoid commands
  that print them;
- `reveal_secret_values` puts values into the conversation, so use it only
  when the person wants the model to see them.

**Without a shell** (a claude.ai chat), the model has nowhere to run it; the
person can. The tool descriptions of
`reveal_secret_values` and `show_secret_value` say plainly which one puts the
value in front of the model.

## 8. The audit log

Every entry a request through MCP writes names its connection. The app's
entries carry `via`: the client ID, its name, and the connection. The
vault's entries carry the access token's ID in the `credentialId`
correlation, as an exchanged CI credential's do, and that leads to the
connection. The audit page shows the actor as "ada@acme.example via Claude
Code".

| Action | When |
|---|---|
| `mcp.connect` | consent approved (scopes asked and granted, client, redirect host) or denied |
| `mcp.disconnect` | a connection revoked: by the person, an owner, the revocation endpoint, a reused code or refresh token |
| `mcp.call` | each `tools/call`, with the tool and its arguments' paths; never a value. Refusals too: scope, capability, the API's own. A retry that only waits on its approval is not logged again |
| `mcp.approve`, `mcp.deny` | the person's decision on coffre's page |
| the change's own entries | `secret.write`, `access.grant`, … as today, with `via` and the approval ID |

Calls made with read-only tools are detail, like sign-ins: they are in the
log and its chain, but left out of `GET /api/audit` unless `detail=1`.
Changes, reveals, approvals and refusals show by default. Token refreshes
are detail.

## 9. Connected apps

- **UI.** The account page gets a **Connected apps** tab, a table with
  these columns:
  - the app: its name, its host, and an **Unverified** tag for registered
    clients;
  - its scopes;
  - when it connected;
  - its last use;
  - its expiry;
  - **Disconnect**, in its row.

  A person's page shows an owner that person's connected apps, with
  Disconnect, as owners may already revoke others' sessions. The offboarding
  report lists them too, and removal ends them through the generation.
- **CLI.** `coffre apps [--json]` and `coffre apps revoke <id> [--apply]`,
  shaped like `coffre sessions`.
- **API.** `GET /api/apps` lists your own; a member's report lists theirs;
  `DELETE /api/apps/:id` disconnects. These routes join the UI parity map.

## 10. Claude as the client

Claude must work as a custom connector in claude.ai and Claude Desktop,
including one an organization Owner adds for everyone, and in Claude Code.
Anthropic's docs, read on 2026-10-05:
[authentication](https://claude.com/docs/connectors/building/authentication),
[building a server](https://claude.com/docs/connectors/building/index),
[lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication),
[adding a connector](https://claude.com/docs/connectors/custom/add-unlisted),
[Claude Code and MCP](https://code.claude.com/docs/en/mcp).

**What Claude requires, and what coffre does:**

| Claude requires | coffre |
|---|---|
| `401` with `resource_metadata` to start sign-in; a `WWW-Authenticate` on a `200` is ignored | `401` before any MCP parsing |
| `resource` equal to the URL the person enters | `https://<instance>/mcp`, and docs/mcp.md says to enter exactly that |
| Claude uses only the first entry in `authorization_servers` | coffre lists exactly one |
| CIMD only with `client_id_metadata_document_supported` and `none` in `token_endpoint_auth_methods_supported`; otherwise DCR | both are listed, and DCR is there too |
| Hosted apps redirect to `https://claude.ai/api/mcp/auth_callback` | HTTPS on the document's own host, allowed |
| Claude Code: CIMD `https://claude.ai/oauth/claude-code-client-metadata`, redirects to `http://localhost/callback` and `http://127.0.0.1/callback` on any port | loopback matched with the port ignored, `localhost` included |
| S256 PKCE; `code_challenge_methods_supported` | yes |
| Scopes come from the `401`'s `scope`, else `scopes_supported`; `offline_access` is added when listed | `scope="read"`; `offline_access` listed |
| Step-up on `403 insufficient_scope`, whose `scope` should name everything still needed | the union of held and needed scopes; the body is a tool result saying how to grant it, for a client that doesn't step up (Claude Desktop didn't) |
| Token endpoint takes form-urlencoded and answers in 10 s (refresh in 30 s); rotate refresh tokens; `invalid_grant` for a dead one | yes |
| Tool results ~150,000 characters (hosted), 25,000 tokens (Claude Code); tool calls 240 s (hosted) | paged lists; approvals wait 25 s per round |

**Org-wide connectors.** An Owner adds the URL under Organization settings,
Connectors. Each member then clicks Connect and goes through coffre's sign-in
and consent as themselves. Every member's connection is their own, with
their own scopes and their own grants behind them. The hosted apps share
one client ID, Anthropic's CIMD, so coffre's Connected apps shows "Claude
(claude.ai)" for each person who connected.

**Where each surface lands:**

| Surface | Protocol | URL elicitation | What coffre allows |
|---|---|---|---|
| Claude Code, v2 runtime (on by default from v2.1.232 where it fetches flags, v2.1.274 elsewhere) | 2026-07-28, which it asks for | yes: it declares `elicitation: {form: {}, url: {}}` and opens the browser | everything, with approvals |
| Claude Code, v1 runtime | 2025-era | documented only on 2026-07-28 connections | everything, changes through the approval link |
| claude.ai, Desktop, mobile, Cowork (custom connector, personal or org-wide) | 2026-07-28 for its tool calls; its connector-setup probe sends a 2025-11-25 `initialize` | declares none | everything, changes through the approval link |

Without URL elicitation, a claude.ai connector makes changes through an
approval link in the tool result, which the person opens on coffre (section
16, answer 1). When claude.ai supports URL elicitation, it uses that
instead, with no change to coffre: coffre reads the capability from each
request.

What claude.ai speaks was checked on 2026-10-05 from servers that logged it
on 2026-09-26 and 2026-10-04: its user-facing client sends `server/discover`,
`tools/list` and `tools/call` on 2026-07-28 with no session and no
elicitation capability, and only its connector-setup probe opens with a
2025-11-25 `initialize`, which coffre answers. A live check from claude.ai
needs an instance it can reach.

What Claude Code sends was checked on 2026-10-06, with Claude Code 2.1.291
against a local stack:

- **Authorize:** `scope=read offline_access` and `prompt=consent`, its
  CIMD and a loopback redirect. Its **Re-authenticate** in `/mcp` asks again
  for the scopes it last held.
- **Requests:** 2026-07-28, with `elicitation: {form: {}, url: {}}` in
  every request's capabilities.
- **A `403 insufficient_scope`:** it asks the person whether to
  re-authenticate "for the scope read write", opens the consent page,
  with Write ticked, and retries the call once. If the person says not now,
  the model reads Claude Code's own message, "needs additional permissions
  (scope: "read write") — run /mcp to re-authenticate", not the body.
- **A change:** a URL elicitation, "Approve on coffre: …", with Open in
  browser, I'm done and Decline. The call it retries right after a step-up
  doesn't show it: that call gets the approval link instead, and works the
  same. Both made their change once the person approved on coffre's page.

Claude Desktop, connected to Erwin's instance on 2026-10-06, was granted
Read and never stepped up, so it could make no change until the consent
page offered Write at connection (section 5). That is his report: a local
stack can't be reached from claude.ai, so it was not checked here.

**Reachability.** The hosted apps call coffre from Anthropic's servers,
`160.79.104.0/21`. They reach `/mcp`, `/.well-known/…`, `/api/oauth/token`
and `/api/oauth/register` from there. The person's browser reaches the
consent and approval pages from wherever they are.

- An instance on the open internet works as is.
- An IP allowlist in front of it must let in `160.79.104.0/21`, on those
  four paths at least.
- Cloudflare Access in front blocks Claude's servers, because they hold no
  Access identity. Bypassing Access for those paths, limited to Anthropic's
  range, would work at the network level. But coffre's Access mode has no
  tokens of its own, so v1 doesn't support it.
- An instance inside a private network can use Anthropic's
  [MCP tunnels](https://claude.com/docs/connectors/mcp-tunnels/overview).
  This is untested.
- Claude Code needs none of this: it calls from the person's own machine.

## 11. Library: hand-written, with the official client in the tests

coffre implements the protocol itself and doesn't take the official
TypeScript SDK at run time. The SDK is
[`@modelcontextprotocol/server`](https://www.npmjs.com/package/@modelcontextprotocol/server)
2.x, which serves both eras and does run on Workers.

| | Hand-written | SDK 2.x |
|---|---|---|
| Runtime dependencies | none new (zod is already there) | `@modelcontextprotocol/server` and `/core`, about 7.7 MB unpacked |
| Surface used | one POST endpoint; 3 modern and 4 legacy methods; JSON answers only | all of MCP: tasks, subscriptions, SSE, sessions, stdio |
| Release pace and the 7-day gate | none to follow | 2.0.0 on 27 July, 2.3.0 on 2 October: we would always be a release behind |
| What we write anyway | the `401`/`403` gate, tokens, scopes, approvals, `requestState`, Origin | the same: the SDK "performs no token verification" and its entry is "deliberately validation-free" |
| Wire correctness | ours to get right: header checks, Base64 names, error codes, eras | the SDK's |

The part the SDK would own is the smallest: about 300 lines of JSON-RPC
over one endpoint. The parts that make this safe are coffre's either way.
So the wire is hand-written, and its correctness is held by the **official
client**:

- [`@modelcontextprotocol/client`](https://www.npmjs.com/package/@modelcontextprotocol/client),
  exactly pinned and age-gated, as a dev dependency of the server's tests.
- It connects to coffre in both eras, runs the OAuth flow, and runs MRTR
  rounds against coffre's approvals.

An independent implementation, written by the spec's authors, then fails
the build whenever coffre's wire drifts. If the protocol later grows
something we need (streaming, tasks), the SDK becomes the better trade, and
the tools move over unchanged, since they are plain functions over the API.

## 12. Storage

One migration, adding three tables on both engines. It expands only:

- **`oauth_clients`**: registered clients. Columns: ID, name, redirect URIs,
  created at and from where, last use, revoked at. MACed over its ID, its
  redirect URIs and its revocation.
- **`mcp_connections`**: one row per approved authorization.
  - Columns:
    - principal, generation;
    - client ID, its name and host as shown at consent, how it registered;
    - scopes, redirect URI;
    - the code's hash, challenge and expiry;
    - the refresh token's hash and the previous one's;
    - expiry, created, last used (time and address), revoked (when and by
      whom).
  - Its MAC covers every field that grants something. It is a fifth table
    in [Sign-in rows](../architecture.md#sign-in-rows), and every change
    checks the old MAC, as there.
  - The principal and generation reference `vault_members`, as
    credentials' do.
- **`mcp_approvals`**: as in section 7. Not MACed: approving runs nothing
  by itself. A changed row can only make the client report a false
  outcome, or show the person a different change, which they then read
  before approving: the page's Approve carries the digest of what it
  showed, recomputed from the stored arguments on the server.

A registration no connection names is revoked a week after it was made,
ten at a time, by later registrations, and connects no more. Nothing is
deleted, as nowhere in coffre (schema guarantee 3): the rows stay, at the
pace the registration limits allow.

Access tokens and `requestState` have no rows: both are MACed and checked
against a connection. Last use is written once per five minutes at most,
as for credentials.

The previous release ignores all three tables, and old code can't verify an
MCP token, since its credential check refuses the prefix. Until the
migration runs, `/mcp` and the OAuth routes answer `503`, as trust bindings
did before theirs.

## 13. Security review points

- **Consent phishing.** An attacker sends Ada a link to
  `/oauth/authorize?client_id=https://evil.example/c.json&redirect_uri=https://evil.example/cb`.
  The page shows `evil.example` as the app's host and as where the answer
  goes, in larger type than the name the document claims. Redirects must be
  HTTPS on the document's host, or loopback. Registered clients say
  **Unverified**. Nothing is ever approved silently.
  - What coffre doesn't stop: Ada approving `evil.example` anyway. She
    then sees it in Connected apps, and every call it makes is in the log.
  - Loopback-only clients get a warning, because any program on Ada's
    machine can listen on a port.
- **Token audience.**
  - An MCP token is refused at `/api`, and an API credential at `/mcp`.
  - `resource` must be coffre's MCP URL.
  - Tokens carry their connection under a MAC, and the connection carries
    its scopes under another.
- **CSRF.**
  - The consent and approval decisions are `POST`s to `/api`, with a
    cookie, so they need `Sec-Fetch-Site: same-origin`.
  - Both pages are unframeable (`frame-ancestors 'none'`).
  - The consent request is checked again in full when it is posted.
  - Codes need the PKCE verifier, and the `iss` parameter defeats mix-ups.
- **A signed-in CLI on the agent's machine.** `coffre run` needs the CLI
  signed in as the person, often on the machine the agent runs on. Whoever
  can run commands there holds that session: `coffre export`, `coffre set`
  and the rest act as the person, with none of MCP's scopes or approvals.
  coffre keeps that session off the approval page's API, so an app can't
  decide its own approvals with it, but it bounds nothing else: an agent
  that has a shell beside a signed-in CLI has the person's access. Sign
  the CLI in elsewhere, or not at all, to keep the agent to its scopes.
- **Replaying an approval.**
  - An approval is one stored change, for one person, under one
    connection, and it acts once.
  - A `requestState` is MACed and bound to that approval, that connection,
    the call's digest and an expiry. It can't confirm a different call or
    be used by another connection.
  - The approval URL is not a credential: whoever opens it must be
    signed in as its person.
  - It expires in 10 minutes.
- **Prompt injection.**
  - **What we do:**
    - Secret keys match `[A-Za-z_][A-Za-z0-9_]*`, and slugs are slugs, so
      the names the model sees most can't carry sentences.
    - Free text (display names, token labels, client names, audit
      metadata) is returned as JSON data, never as instructions.
    - No change happens without the person reading coffre's page. That
      page, not the model's summary, is what they approve.
    - Values never reach the model without Reveal values.
  - **What we don't defend:**
    - A model steered into proposing a harmful but well-formed change. The
      page shows it, but the person must read it.
    - With Reveal values, a value that itself carries instructions.
    - With Reveal values, a model that reads a value and then passes it to
      another tool or connector of the client's. This is why Reveal values is
      opt-in, with its warning.
    - A person who approves without reading.
- **Approval fatigue.** At most five pending approvals per connection. An
  identical call rejoins its approval. Each approval is shown alone, never
  in bulk.
- **Step-up.** A consent that grants all an earlier connection of the same
  client holds and more supersedes it, whether the client asked for the
  more or the person ticked it: the earlier one ends when the new
  one's code is redeemed, logged as `mcp.disconnect`, `superseded`, and the
  consent page says so. One with the same scopes, a second laptop, stays.
- **Workers.** No isolate keeps a pending promise: a CIMD document or a
  limiter answer is kept only once it has settled. No app transaction
  stays open across a vault call. A held retry polls with plain queries
  and holds no transaction.

## 14. Conformance and tests

`coffre-conformance` gains MCP checks, for both kinds:

1. **Connect.** The `401` and both metadata documents are as above. Then:
   - a client registers;
   - a seeded person signs in through the dev IdP and consents to Read;
   - the code is exchanged;
   - `server/discover` and `tools/list` succeed, on 2026-07-28 and through
     a 2025-11-25 `initialize`;
   - a CIMD client, served by the harness on loopback under a development
     flag like trust bindings' loopback issuers, does the same.
2. **Read can't write.** `archive_secret` and `reveal_secret_values` answer
   `403 insufficient_scope`, with the right `scope`, and a tool result
   saying how to grant it. The secret is still live, and the API refused
   nothing on the token's behalf. A connection that asked for Read, with
   Write ticked, gets a token whose `scope` is `read write`.
3. **No change without approval.** With Write:
   - without URL elicitation: `-32021`, and nothing changed;
   - with it: `input_required`, and nothing changed;
   - another person opening the approval is refused;
   - a `requestState` replayed with other arguments is refused;
   - the person approves, the change is made once, and the retry reports
     it.
4. **No value without Reveal values.** Every Read and Write tool's result is
   searched for the seeded values, which must not appear. With Reveal values,
   `reveal_secret_values` returns them.
5. **Every call audited with the client.** Each call above has its entry
   naming the client ID, and the change's own entries carry `via`.
6. **Audience and lifecycle.**
   - An MCP token at `/api`: `401`. A CLI session at `/mcp`: `401`.
   - A reused refresh token or code revokes the connection.
   - Disconnecting ends the token at the next call.
   - A foreign `Origin`: `403`.

The server's own suites (both engines) test each piece, run the official
client against it, and test the transaction rule for every tool. CI runs
all of it: lint, typecheck, `pnpm test`, `test:sqlite`, `test:schema`, both
conformance runs, `test:compat` and `test:consumer`.

## 15. Pull requests

Each one is green, reviewable alone, and rebased on #137 (grants on all
projects), #134 (permanent deletion), the environment features and UI
parity as they merge.

1. **The authorization server.**
   - Migration, `oauth_clients`, `mcp_connections`.
   - Metadata, DCR, CIMD.
   - The consent page, codes, tokens, refresh, revocation, limits.
   - `signin({ mcp })`, `init`, `update`, both examples.
   - `/mcp` answers only `401`, or `server/discover` once authenticated.
2. **The MCP endpoint with Read.** Both eras, the tools,
   the scope gate in `serveApi`, the audit's `via`, and the conformance
   checks 1, 2, 5 and 6.
3. **Changes with approvals.** `mcp_approvals`, the approval page, MRTR, the
   Write and Manage access tools, and check 3.
4. **Values.** `request_secret_value`, `generate_secret_value`,
   `show_secret_value`, `reveal_secret_values`, the consent warning, and
   check 4.
5. **Connected apps.** The account tab, the person's page, the offboarding
   report, `coffre apps`, and docs/mcp.md.

## 16. Open questions for Erwin

All four are settled. Erwin answered 1, 3 and 4 as recommended (D44): Claude,
in claude.ai's connectors and in Claude Code, is to support every feature,
and he tests its flows by hand.

- **1: the approval link**, with the cheap bounds; a passkey step-up on
  Approve is the follow-up.
- **3: replaced by D62.** Older protocol versions are not read-only: a
  2025-era client makes changes through answer 1's link, as any client
  without URL elicitation does. Only a connection's scopes make it
  read-only.
- **4: read-only calls are detail**, under Show details (`mcp.read`; a
  refusal is `mcp.call`, shown).

PR 3 checked what claude.ai speaks (section 10): 2026-07-28, without
elicitation. So it makes changes through answer 1's link. Since the link
works in any revision, Erwin then extended it to 2025-era clients (D62).

1. **Clients that can't elicit, claude.ai today.**
   - **Default (D31):** refuse changes and showing values, so a claude.ai
     connector can read and, with Reveal values, receive values.
   - **Alternative:** for such clients, the tool result carries the
     approval link as text for the model to show the person ("Open
     https://secrets.acme.example/approvals/7QF2… to approve"). The client
     retries or calls again for the outcome. The person still confirms the
     exact change on coffre's page, signed in as themselves, so what coffre
     enforces is unchanged.
   - **What we'd lose:** the client no longer vouches that the link came
     from coffre. A manipulated model could show a lookalike link, though
     it could print one at any time anyway.
   - **Threat model.** The model now holds the URL, which brings three
     threats:
     1. **An agentic browser that holds the person's cookies**, such as
        Claude in Chrome or the agent's own browser tool, opens the link and
        clicks Approve. coffre sees a valid same-origin session and can't
        tell it from the person, so the confirmation fails. The same agent
        could already make the change through coffre's UI with that
        session; the link only hands it the exact target.
     2. **A lookalike link**, injected into the model's output, phishes the
        sign-in.
     3. **A forwarded link** is opened by someone else, who is refused.
   - **What resists the agentic browser**, from weakest to strongest:
     - **Cheap bounds**, which ship either way, though none stops an agent:
       single use, bound to the person, connection and digest, a 5-minute
       expiry, a POST-only Approve, `frame-ancestors 'none'`, same-origin.
     - **A recent sign-in.** An IdP session lets an agent sign in again
       silently, and `prompt=login` is per provider; GitHub has none.
     - **A passkey with user verification** (WebAuthn,
       `userVerification: required`) on Approve. This is the one control
       an agent can't pass. It needs per-person passkeys, a new feature,
       and it would protect elicitation clients that drive a browser too.
     - **Approval on another device.** Stronger, and much heavier.
   - **Recommendation:** the alternative, with the cheap bounds. Say plainly
     that an agent driving the person's signed-in browser can approve, just
     as it can use coffre's UI. Passkeys on approvals are the follow-up.
     Without the alternative, the org-wide claude.ai connector can't change
     anything at all.
2. **Custom-scheme redirects** (`cursor://…`, `vscode://…`). *Settled: v1
   refuses them, and DCR leaves them out of a registration.* D31 says to
   refuse non-HTTPS. coffre allows loopback HTTP because the spec and Claude
   Code need it. By their own docs, no mainstream client needs a custom
   scheme:
   - **Cursor** documents `http://localhost:8787/callback` and
     `https://www.cursor.com/agents/mcp/oauth/callback`, through DCR. Its
     `cursor://anysphere.cursor-mcp/oauth/callback` is an undocumented
     fallback for when that port is taken. DCR leaves it out (section 4).
   - **VS Code** has a CIMD at `https://vscode.dev/oauth/client-metadata.json`,
     redirecting to `https://vscode.dev/redirect` and
     `http://127.0.0.1:33418/`.
   - **Windsurf** documents no MCP redirect.
   - **Claude**: section 10.

   v1 refuses custom schemes. If one is ever needed, the future path, and
   the narrowest allowance, is a reverse-domain scheme (RFC 8252 §7.1, such as
   `com.example.app:/cb`), declared in a CIMD document and matched exactly,
   with a warning on the consent page. Never through DCR, and never a
   one-word scheme.
3. **2025-era clients: reads only.** *Superseded by D62: they get the
   approval link.* The full `-32042` path would let them
   make changes. It needs a session ID that carries the client's declared
   capabilities under a MAC. Claude Code's 2025 runtime doesn't declare URL
   elicitation, and the hosted apps don't document it, so it would buy
   little. **Recommendation:** reads only.
4. **Read-only calls in the audit page.** **Recommendation:** detail, like
   sign-ins: in the log, shown with "Show details". Changes and reveals show
   by default.

## Appendix: docs/mcp.md, the user guide (draft)

This becomes `docs/mcp.md` with the fifth pull request.

> ### Connect Claude, or another MCP client, to coffre
>
> coffre serves MCP at `https://<your instance>/mcp`. Clients sign in as
> you, with your coffre sign-in, and can never do more than you can. They
> can do less: you choose what they may do when you connect them.
>
> **Scopes.** You grant these on coffre's consent page:
> - **Read**, always: projects, environments, key names, history, access,
>   the audit log.
> - **Write**: set, generate, rename, archive and restore secrets; create
>   projects and environments.
> - **Reveal values**: secret values sent to the client. They become part of
>   the conversation.
> - **Manage access**: grants, members, service tokens, trusted workloads.
>
> Tick what a client may do when you connect it: clients ask for Read
> alone. One that needs more later may ask, and you see the consent page
> again.
>
> **Every change is confirmed on coffre.** When a client wants to change
> something, coffre opens its own page with the exact change, and nothing
> happens until you approve it there. A client never types a secret value:
> you type it on coffre's page, or coffre generates it.
>
> **Claude Code.**
> `claude mcp add --transport http coffre https://secrets.acme.example/mcp`,
> then `/mcp` to sign in. To run code with secrets, Claude uses
> `coffre run <project>/<environment> -- <command>`, so the values go to the
> command, not the conversation.
>
> **claude.ai and Claude Desktop.** Under Customize, Connectors, choose
> **Add custom connector** and enter `https://secrets.acme.example/mcp`
> exactly. Leave the OAuth client on "Use Claude's published identity". On
> Team and Enterprise plans, an Owner adds it once under Organization
> settings, Connectors, and each person then clicks **Connect** and signs in
> as themselves. Claude's apps can't open coffre's approval page
> themselves, so Claude shows you its link, and you open it.
>
> **Reaching your instance.** claude.ai and Desktop connect from
> Anthropic's servers (`160.79.104.0/21`). An instance behind an IP
> allowlist must let that range in. One behind Cloudflare Access can't be
> connected yet. Claude Code connects from your machine.
>
> **Connected apps.** Your account page lists every client you connected,
> its scopes and its last use, and disconnects any of them. So does
> `coffre apps`. Every call a client makes is in the audit log as "you via
> <client>".

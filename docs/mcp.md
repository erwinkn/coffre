# Connect Claude, or another MCP client, to coffre

coffre serves MCP at `https://<your instance>/mcp`, which your account's
Connected apps tab, `/account/apps`, shows with the steps below. A client
signs in as you, with your coffre sign-in, and can never do more than you
can. It can do less: you choose what it may do when you connect it. The design, and why
each piece is as it is, is [design/mcp.md](design/mcp.md).

## Connecting

**Claude Code.**
`claude mcp add --transport http coffre https://secrets.acme.example/mcp`,
then `/mcp` to sign in. Claude Code opens coffre's consent page in your
browser.

**claude.ai and Claude Desktop.** Under Customize, Connectors, choose
**Add custom connector** and enter `https://secrets.acme.example/mcp`
exactly. Leave the OAuth client on "Use Claude's published identity". On
Team and Enterprise plans, an Owner adds it once under Organization
settings, Connectors, and each person then clicks **Connect** and signs in
as themselves.

**Other clients.** Any client that speaks MCP's authorization (OAuth 2.1
with PKCE) connects the same way. One that publishes a client metadata
document, as Claude does, shows on the consent page under its website. One
that registers itself instead shows as **Unverified**: its name is its own
claim, so look at where coffre's answer goes before you approve.

**The consent page.** Every connection shows it, even for a client you
connected before. It names the client's website, where the answer goes
(with a warning when that is only a program on your computer), you, and
every scope, with what the client asked for ticked. Nothing is granted
until you press Approve.

## Scopes

You grant these on the consent page:

- **Read** (`read`), always: projects, environments, key names, history,
  access, the audit log. Never a value.
- **Write** (`write`): set, generate, rename, archive and restore secrets;
  create projects and environments.
- **Reveal values** (`reveal`): secret values sent to the client. They
  become part of the conversation, wherever the client keeps it.
- **Manage access** (`manage-access`): grants, members, service tokens,
  trusted workloads.

The words in brackets are the OAuth scopes a client asks for. Clients ask
for Read alone, and not all ask for more later (Claude Code
does, Claude Desktop did not), so tick what you want the client to do when
you connect it: Write to make changes, which you still approve one by one.
You can tick or untick any but Read, whatever the client asked for. A
connection lasts as long as a `coffre login` session (30 days unless the
deployment says otherwise); then you connect again.

## Tools

With **Read**, a connected client can, as you:

- `whoami`: who it acts as, and what it may do.
- `list_projects`, `list_secrets`, `secret_history`: projects,
  environments, keys, versions, and who changed what. Never a value.
- `list_access`, `describe_member`: who has access, and what a member
  holds.
- `read_audit_log`: the log, 50 entries a call.
- `show_secret_value`: shows you a secret's value on coffre's page, when
  you press Reveal there. The value is never sent to the client.

With **Reveal values**, `reveal_secret_values` sends the values of a secret or
an environment to the client, and they become part of the conversation:
its answer says so first. The consent page warns before you grant it.

With **Write**, it can ask to change secrets and places:
`request_secret_value`, `generate_secret_value`, `rename_secret`, `archive_secret`,
`unarchive_secret`, `restore_secret_version`, `create_project` and
`create_environment`. With **Manage access**: `set_access`, `admit_member`,
`offboard_member`, `issue_service_token`, `revoke_service_token`,
`trust_workload` and `untrust_workload`.

To use secrets in a command, a client with a shell runs it in your
terminal as `coffre run market/staging -- npm test`, which sets them for
that process only: the values never enter the conversation. The CLI must be
signed in (`coffre login`), and the MCP connection grants it nothing.

Each tool is coffre's API called as you, so a tool can do no more than you
could with the CLI.

**Your client lists only the tools your roles reach.** A viewer's client
sees the reads and the two that show values, not `set_access` or the
audit log; an access manager's sees `list_access` and `set_access`, not
values; an instance owner's sees the instance's own tools, such as
`admit_member` and `create_project`. A tool your roles allow but your
connection's scopes don't stays listed: calling it asks for the scope, as
below. Clients keep the list for five minutes at most, so a role granted
or taken shows in it within minutes. The list is only what is shown: every
call is still checked when it is made, so a tool called by name that your
roles don't allow is refused as before.

## Every change is approved on coffre

A client never changes anything itself. When it asks to, coffre opens an
approval, and the change waits for you on coffre's own page,
`/approvals/<id>`, signed in as you: it shows the app, the change, and what
it replaces, read as the page opens. **Approve** makes the change there and
then, as you, and the app only hears what became of it; **Deny** changes
nothing. Nobody else can decide your approvals, and each expires after five
minutes.

- **Claude Code**, and any client on MCP 2026-07-28 that can open a URL,
  asks you to open the page, and picks up the outcome by itself.
- **claude.ai and Claude Desktop**, and any client that can't, gets the
  link in the tool's answer: Claude shows it to you, you open it, and once
  you have decided, Claude asks again for the outcome.
- **Clients on a 2025 revision** of MCP get the link too.

A client never types a secret value. `request_secret_value` asks you to
type it on the approval page, and it goes to coffre only;
`generate_secret_value` has coffre make a random one on its own server
(32 bytes in base64url unless asked), which nobody sees. A service token
`issue_service_token` makes is shown to you on the page, once, and never to
the app. A connection may have five changes waiting at once.

When a client calls a tool its connection lacks the scope for, coffre
refuses it and says, in the tool's answer, which scope it needs and how you
grant it: connect the client again, ticking that scope. Claude Code asks
you whether to re-authenticate and opens the consent page itself, with the
scope ticked; in claude.ai or Desktop, disconnect coffre under Customize,
Connectors, and connect it again. The new connection replaces the client's
earlier one that it grants all of and more; one with the same scopes, on a
second laptop say, stays.

## Connected apps

Your account's Connected apps tab lists every client you connected: its
website, what it may do, when it was last used and when it expires.
**Disconnect** ends it at its next request. So do `coffre apps` and
`coffre apps revoke <id> --apply`. An owner sees anyone's on that person's page, and may disconnect
them there, as with sessions. Removing someone from coffre disconnects
theirs: the removal dialog and `coffre offboard` name them first
([offboarding.md](offboarding.md)). Each connection, its tokens and its end
are in the audit log, under the client's name.

## Reaching your instance

claude.ai and Desktop connect from Anthropic's servers (`160.79.104.0/21`).
An instance behind an IP allowlist must let that range in. One behind
Cloudflare Access can't be connected: MCP needs coffre's own sign-in.
Claude Code connects from your machine.

## Turning it on

A deployment turns MCP on in `app/src/coffre.ts`, under `signin({ mcp })`,
with three limits: one per address and one in total for the OAuth requests
that come before anyone is signed in, and one per connection for its
calls. `coffre init` writes it on:

- **Workers:** three rate-limiting bindings in `app/wrangler.jsonc`,
  `MCP_PER_SOURCE`, `MCP_PER_CONNECTION` and `MCP_TOTAL`, passed as
  `mcp: { limits: { perSource, perConnection, total } }`.
- **Node:** `mcp: { limits: processLimits({ perSource: 30, perConnection:
  120, total: 300 }) }`, counted in the process.

Without `mcp`, `/mcp` and its metadata answer 404, and the account page has
no Connected apps tab.

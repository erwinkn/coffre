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
what the client asks to do. Nothing is granted until you press Approve.

## Scopes

You grant these on the consent page:

- **Browse**, always: projects, environments, key names, history, access,
  the audit log. Never a value.
- **Write**: set, generate, rename, archive and restore secrets; create
  projects and environments.
- **Read values**: secret values sent to the client. They become part of
  the conversation, wherever the client keeps it.
- **Manage access**: grants, members, service tokens, trusted workloads.

You can untick any but Browse. A connection lasts as long as a `coffre
login` session (30 days unless the deployment says otherwise); then you
connect again.

## Tools

A connected client can browse, as you:

- `whoami`: who it acts as, and what it may do.
- `list_projects`, `list_secrets`, `secret_history`: projects,
  environments, keys, versions, and who changed what. Never a value.
- `list_access`, `describe_member`: who has access, and what a member
  holds.
- `read_audit_log`: the log, 50 entries a call.
- `run_with_secrets`: how to run a command with an environment's secrets,
  `coffre run market/staging -- npm test`, which sets them for the command
  only, so no value enters the conversation. Claude Code runs it itself;
  in a chat without a shell, you do.

- `show_secret_value`: shows you a secret's value on coffre's page, when
  you press Reveal there. The value is never sent to the client.

With **Read values**, `read_secret_values` sends the values of a secret or
an environment to the client, and they become part of the conversation:
its answer says so first. The consent page warns before you grant it.

With **Write**, it can ask to change secrets and places:
`request_secret_value`, `generate_secret_value`, `rename_secret`, `archive_secret`,
`unarchive_secret`, `restore_secret_version`, `create_project` and
`create_environment`. With **Manage access**: `set_access`, `admit_member`,
`offboard_member`, `issue_service_token`, `revoke_service_token`,
`trust_workload` and `untrust_workload`.

Each tool is coffre's API called as you, so a tool can do no more than you
could with the CLI.

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

When a client needs a scope it doesn't hold, coffre's consent page opens
again, asking for it. The new connection replaces the client's earlier one
that it grants all of and more; one with the same scopes, on a second
laptop say, stays.

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

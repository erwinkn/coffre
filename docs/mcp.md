# Connect Claude, or another MCP client, to coffre

coffre serves MCP at `https://<your instance>/mcp`. A client signs in as
you, with your coffre sign-in, and can never do more than you can. It can
do less: you choose what it may do when you connect it. The design, and why
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

Each tool is coffre's API called as you, so a tool can do no more than you
could with the CLI. Changing secrets, and reading values, come with later
releases.

## Connected apps

Your account page lists every client you connected: its website, what it
may do, when it was last used and when it expires. **Disconnect** ends it
at its next request. So do `coffre apps` and `coffre apps revoke <id>
--apply`. An owner may disconnect anyone's, as with sessions, and removing
someone from coffre ends theirs. Each connection, its tokens and its end
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
no Connected apps.

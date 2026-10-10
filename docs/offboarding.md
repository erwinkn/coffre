# Offboarding

When someone leaves, two things need doing: stop them getting in, and change
the values they may have kept. coffre does the first in one step, and turns
the second into a list that shrinks as you work through it.

## Removing someone

On the web, **Users → ⋯ → Remove user** (or **Tokens** for a service). From
the CLI, `offboard` previews first, like `import`:

```
$ coffre offboard alice@acme.example
alice@acme.example is active; removing would revoke 3 grants, 2 sessions, 1 linked account, 1 connected app

Values they saw that nobody has changed since, to rotate once they leave (4)
  market/prod/DATABASE_URL       v4    read 2026-09-12
  market/prod/STRIPE_SECRET_KEY  v3    wrote 2026-08-30
  ops/deploy/GITHUB_TOKEN          v1    read 2026-09-01
  market/dev/REDIS_URL           v3    read 2026-09-25

Connected apps, which removing them disconnects (1)
  Claude  claude.ai, may read, write, last used 2026-09-30

Nothing changed. Re-run with --apply to remove alice@acme.example.

$ coffre offboard alice@acme.example --apply
removed alice@acme.example: revoked 3 grants, 2 sessions, 1 linked account, 1 connected app
…
```

The vault removes them in one transaction of its own: it revokes every
grant they hold, on a project or an environment, takes their instance role,
marks them removed, and moves their *generation* on.
Every session, CLI login, service account's bearer token, linked account,
device approval and connected MCP app carries the generation it was issued under, so all of them stop working at
that moment, whatever happens next. The vault logs one `member.remove`, and
one `access.revoke` per grant, so each project's log shows who lost access to
it. Then the app marks the sessions, tokens, linked accounts and connected
apps revoked, so they no longer list as live. The removal dialog names the
apps it disconnects, and so does the person's page, for owners, on its
**Connected apps** tab, where each can be disconnected on its own.

A sign-in racing a removal either finishes first and is cut off by the new
generation, or is refused. Every request checks the member, in both sign-in
modes, so a session still open elsewhere answers 401 on its next call.

**A member whose record failed its check** (marked "Integrity check failed",
because their row or grants were changed outside the vault) is removed the
same way. That starts them over from what the log says of them, and
re-adding them gives them back nothing the tampering added.

**Adding someone back starts from nothing.** No grants, no sessions, and their
sign-in account binds again by email the next time they sign in. A CLI login
they approved before being removed cannot be collected afterwards.

**Removal does not reach outside coffre.** Remove them from your identity
provider as well (the GitHub organisation, the Google Workspace). With
Cloudflare Access in front, also remove them from the Access policy.

## What they leave behind

A person's page (owners only) shows it, and so does `coffre offboard`, before
and after removal. Removed people and tokens stay listed under **Removed** on
the Users and Tokens pages, with how much is left to rotate, so they do not
drop out of sight once they can no longer sign in.

- **Values to rotate.** Every secret whose *current* value they read or
  wrote. Change it where it comes from (a new API key, a new database
  password), save the new value in coffre, and it leaves the list. Rolling
  back to a version they saw puts it back; archiving the secret, its
  environment or its project takes it off, since coffre no longer serves it.
- **Bearer tokens they issued** to service accounts. Each was shown once, to them, when it was
  made. Revoke any they may have kept a copy of.

### How "saw" is decided

From the audit log: every allowed `secret.read` (the vault's) or
`secret.write` in their name, which records the exact version, following each
`secret.restore` back to the version it copied. That covers the web UI's
Reveal, `coffre get`, `run` and `export`, and imports (which compare with the
current value, a read).

It lists what they *did* see, not what they *could* have. Someone with read
access to `market/prod` who never opened it has nothing listed there. That is
the point of the list, but if you doubt the log (someone copied a database
dump, say), rotate by their grants instead.

Values that reached them some other way, such as a GitHub secret a deploy pipeline
pushed to a repository they administer, are outside what coffre can know.

## API

```
GET    /api/members/user:ada@acme.example   the report
DELETE /api/members/user:ada@acme.example   remove; answers with the report
```

Services are `token:<name>`. From the client, `coffre.members.get(member)` and
`coffre.members.remove(member)`.

Both need an Admin or Owner whose scope narrows nothing, or a root admin.

The generation is what makes removal stick. Even if the app's own clean-up
failed after the vault committed, re-adding someone cannot revive a session,
token or approval from before.

# Offboarding

When someone leaves, two things need doing: stop them getting in, and change
the values they may have kept. coffre does the first in one step, and turns
the second into a list that shrinks as you work through it.

## Removing someone

On the web, **Users → ⋯ → Remove user** (or **Tokens** for a service). From
the CLI, `offboard` previews first, like `import`:

```
$ coffre offboard alice@acme.example
alice@acme.example is active; removing would revoke 3 grants, 2 sessions, 1 linked account

Values they saw that nobody has changed since, to rotate once they leave (4)
  market/prod/DATABASE_URL       v4    read 2026-09-12
  market/prod/STRIPE_SECRET_KEY  v3    wrote 2026-08-30
  ops/sync/GITHUB_TOKEN          v1    read 2026-09-01
  market/dev/REDIS_URL           v3    read 2026-09-25

Syncs they set up, which keep pushing
  market/prod -> GitHub Actions acme/market

Nothing changed. Re-run with --apply to remove alice@acme.example.

$ coffre offboard alice@acme.example --apply
removed alice@acme.example: revoked 3 grants, 2 sessions, 1 linked account
…
```

Removal is one transaction, under the same lock that sign-in takes, so a
sign-in racing it either finishes first and is revoked, or is refused:

- every grant, on every project, is revoked;
- every browser session and CLI login ends (for a service: every token);
- every sign-in account linked to them (GitHub, Google, …) is unlinked;
- they are marked removed, and every request checks that, in both auth modes;
- one `directory.remove` audit row records who did it and the counts above.

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
- **Syncs they set up.** A sync keeps pushing after its creator is gone. Check
  each one still points somewhere you control.
- **Service tokens they issued.** Each was shown once, to them, when it was
  made. Revoke any they may have kept a copy of.

### How "saw" is decided

From the audit log: every allowed `secret.read`, `secret.write` or
`secret.import` in their name, which records the exact version. That covers the
web UI's Reveal, `coffre get`, `run` and `export`, and imports (which compare
with the current value, a read).

It lists what they *did* see, not what they *could* have. Someone with read
access to `market/prod` who never opened it has nothing listed there. That is
the point of the list, but if you doubt the log (someone copied a database
dump, say), rotate by their grants instead.

Values that reached them some other way, such as a GitHub secret a sync
pushed to a repository they administer, are outside what coffre can know.

## API

```
GET    /api/members/user:ada@acme.example   the report
DELETE /api/members/user:ada@acme.example   remove; answers with the report
```

Services are `token:<name>`. From the client, `coffre.members.get(member)` and
`coffre.members.remove(member)`.

Both need the instance owner role (root admins have it).

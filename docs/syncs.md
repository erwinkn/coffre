# Syncs

A sync pushes every secret in one environment to a service that runs code,
and keeps it current there. coffre ships four destinations:

| Destination         | Writes                                              | Token it needs                                   |
| ------------------- | --------------------------------------------------- | ------------------------------------------------ |
| GitHub Actions      | repository secrets, or one environment's secrets    | fine-grained PAT: Secrets (or Environments) R/W  |
| Vercel              | project variables, for chosen targets (and branch)  | access token scoped to the owning team           |
| Railway             | a service's variables, or an environment's shared   | project token for that environment (preferred)   |
| Cloudflare Workers  | a Worker's secrets                                  | API token with Workers Scripts: Edit             |

Anything else reads secrets at run time with `coffre run` or `coffre export`
and a service token (see the README). Each destination's exact fields, name
rules and quirks are in [packages/sync/README.md](../packages/sync/README.md).

## Setting one up

The destination's token is itself a coffre secret, named by path. Keep sync
tokens in an environment of their own, so the people who can read `app/prod`
cannot also read a token that writes to your CI:

```sh
coffre set ops/sync/GITHUB_TOKEN            # paste the token on stdin
coffre sync add app/prod github-actions owner=acme repo=app environment=production \
  --credential ops/sync/GITHUB_TOKEN
```

or, on the environment page, **Syncs → Add sync**. Both refuse a token you
cannot read yourself, and neither shows it to you. The first push starts at
once. From then on:

```sh
coffre sync list   app/prod                  # state, counts, last error
coffre sync run    app/prod github-actions   # push now; a destination name or an id prefix
coffre sync pause  app/prod github-actions
coffre sync resume app/prod github-actions
coffre sync remove app/prod github-actions   # stops syncing; what was pushed stays
coffre sync --help                           # every destination's fields
```

Rotating the destination's token is writing a new version of
`ops/sync/GITHUB_TOKEN`; the next run uses it.

## What a run does

coffre records, per key, which secret version it last pushed. A run compares
that to the environment now and only touches the difference:

```
secrets now      pushed last      this run
API_KEY  v7      API_KEY  v6      push API_KEY
DB_URL   v3      DB_URL   v3      -
NEW_FLAG v1      -                push NEW_FLAG
-                OLD_KEY  v2      remove OLD_KEY   (archived in coffre)
```

- **It only removes what it pushed.** A variable someone set by hand at the
  destination is never touched, even if coffre has a key of the same name
  archived.
- **Runs happen** when a secret in the environment is written, imported,
  renamed, archived, restored or rolled back; when someone runs it by hand;
  and from the scheduler, every 5 minutes, which sends anything still
  pending, retries a failed sync after 15 minutes, and once an hour asks the
  destination which keys it has, to put back any that were deleted there.
- **One key failing does not stop the others.** The sync is then `partial`,
  and the failed keys stay pending for the next run. A bad token or a missing
  repository fails the whole run, with the destination's own message.
- **Some keys cannot exist at some destinations**, such as `GITHUB_TOKEN` on
  GitHub or `RAILWAY_*` on Railway. They are listed as skipped, with why,
  instead of failing every run.
- **The token is never pushed.** If it lives in the environment being synced,
  it is left out of the push.
- Two runs of one sync never overlap. A run that dies mid-way (the Worker was
  stopped) is picked up again after 5 minutes.

## Who can do what

| Action                    | Needs, on the synced environment                          |
| ------------------------- | --------------------------------------------------------- |
| See syncs                 | any of read, write or archive                             |
| Add a sync                | manage **and** read, plus read on the token's secret      |
| Pause, resume, remove     | manage                                                    |
| Run now                   | write or manage                                           |

Adding needs read because a sync sends every value somewhere else, which is a
read by other means. Running needs only write, because it sends nothing that
writing would not have sent anyway.

## What the audit log records

Every value that leaves is logged before it leaves, so if the push then fails,
the log shows more going out than did, never less.

| Action        | When                                                   | Actor                           |
| ------------- | ------------------------------------------------------ | ------------------------------- |
| `sync.create` | a sync was added (or refused, with the reason)         | the person                      |
| `sync.run`    | a run opened the destination's token                   | the person, or `sync:<id>`      |
| `sync.push`   | one key's value was sent, with its version             | the person, or `sync:<id>`      |
| `sync.remove` | one key was deleted at the destination                 | the person, or `sync:<id>`      |
| `sync.pause`, `sync.resume`, `sync.archive` | as named                 | the person                      |

Runs that nobody pressed a button for (after a change, or from the scheduler)
are logged under the system actor `sync:<id>`, with `trigger` in the metadata
saying which. Every row of one run shares a bundle id.

## Operating notes

- The scheduler is the app Worker's Cron trigger (`*/5 * * * *` in
  `app/wrangler.jsonc`), or on Node a timer in `serve`, at the same rate.
  Without it, syncs still run after changes and by hand, but nothing retries
  or repairs drift. `syncs: { driftCheckMinutes, retryAfterMinutes }` in the
  server's configuration tunes it.
- Railway redeploys the service on every change, and Cloudflare deploys a new
  Worker version, so a burst of edits means a burst of deploys. Writing
  several keys at once (`coffre import --apply`) goes out as one run.
- Removing a sync does not clean up the destination. That is deliberate:
  deleting production variables should be a decision made there, not a side
  effect of tidying coffre.

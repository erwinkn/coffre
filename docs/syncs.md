# Syncs

A sync pushes every secret in one environment to a service that runs code,
and keeps it current there. Each kind of service is a provider, and coffre
ships four:

| Provider            | Writes                                              | Token it needs                                   |
| ------------------- | --------------------------------------------------- | ------------------------------------------------ |
| GitHub Actions      | repository secrets, or one environment's secrets    | fine-grained PAT: Secrets (or Environments) R/W  |
| Vercel              | project variables, for chosen targets (and branch)  | access token scoped to the owning team           |
| Railway             | a service's variables, or an environment's shared   | project token for that environment (preferred)   |
| Cloudflare Workers  | a Worker's secrets                                  | API token with Workers Scripts: Edit             |

Anything else reads secrets at run time with `coffre run` or `coffre export`
and a service token (see the README), or gets a [provider of its
own](#a-provider-of-your-own). Each provider's exact fields, name rules and
quirks are in [packages/server/src/sync/README.md](../packages/server/src/sync/README.md).

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
coffre sync providers                        # what this instance offers, and each one's fields
```

Rotating the destination's token is writing a new version of
`ops/sync/GITHUB_TOKEN`; the next run uses it.

## Which providers a deployment offers

A deployment that says nothing offers all four. Listing them picks which,
in the order the pages and `coffre sync providers` show them:

```ts
import { coffre, githubActions, vercel } from '@coffre/server/cloudflare';

export default coffre((env: Env) => ({
  // …
  syncs: { providers: [githubActions(), vercel()] },
}));
```

`providers: []` offers none, and the page says so instead of a form. A
provider dropped from the list takes nothing with it: its syncs still list,
with a plain mark, and each run fails with `this deployment no longer lists
the sync provider "railway"` until it is listed again or they are removed.

### A provider of your own

A provider is a `SyncProvider`: the form a person fills in, a parser that
turns what they typed into a config, and two calls, one to list the keys the
destination has and one to write and delete some. A deployment can write one
for a service coffre does not know, and list it beside the others:

```ts
import { SyncConfigError, SyncProviderError, type SyncProvider } from '@coffre/server/cloudflare';

const acme: SyncProvider<{ app: string }> = {
  id: 'acme-deploy',           // stable: stored with every sync to it, and what `coffre sync add` takes
  label: 'Acme Deploy',
  brand: 'other',              // the mark: github, vercel, railway, cloudflare, or other (the sync glyph)
  fields: [{ type: 'text', name: 'app', label: 'App', placeholder: 'my-app' }],
  credential: { placeholder: 'ops/sync/ACME_TOKEN', hint: 'A deploy token limited to this app.' },
  parseConfig(input) {
    const app = (input as { app?: unknown } | null)?.app;
    if (typeof app !== 'string' || !/^[a-z0-9-]{2,63}$/.test(app)) {
      throw new SyncConfigError('Acme Deploy: app must be an app name, like my-app');
    }
    return { app };
  },
  describe: ({ app }) => `Acme app ${app}`,
  checkKey: (key) => (key.startsWith('ACME_') ? { ok: false, reason: 'ACME_ names are Acme’s own' } : { ok: true }),
  async listKeys(ctx, { app }) {
    const response = await (ctx.fetch ?? fetch)(`https://deploy.acme.example/apps/${app}/secrets`, {
      headers: { authorization: `Bearer ${ctx.token}` },
      signal: ctx.signal,
    });
    if (!response.ok) throw new SyncProviderError(`Acme answered ${response.status}`, 'upstream', response.status);
    return ((await response.json()) as { name: string }[]).map((secret) => secret.name);
  },
  async apply(ctx, { app }, plan) {
    // Write plan.upsert and delete plan.delete; report each key that fails in `failed`.
    return { upserted: [], deleted: [], failed: [] };
  },
};

syncs: { providers: [githubActions(), acme] },
```

coffre does everything around the calls: it decides what changed, opens the
token, logs every value before it leaves, retries, and checks for drift. It
also holds every provider, its own four included, to two rules it enforces
itself. A key `checkKey` refuses is reported as skipped and never reaches
`apply`. And no error, thrown or per key, carries the token or a value out:
both are replaced with `[redacted]`, even when an upstream quotes the request
back. What the provider owns is the protocol: `parseConfig` must refuse
anything it cannot write to (its message is shown as is), `apply` reports a
key the destination refuses in `failed` and throws only when the whole call
cannot succeed, and `listKeys` returns only names. A provider's shape (its
id, fields and credential) is checked with the rest of the configuration, so
a malformed one fails the deployment on start.

The pages and the CLI render the form from what `GET /api/syncs/providers`
returns, so a provider of your own needs no change to either. A text field
can be asked only when an options field has some exact set of options
picked, like Vercel's branch, asked only when previews are the one target:

```ts
{ type: 'text', name: 'gitBranch', label: 'Branch', placeholder: 'staging', optional: true,
  when: { field: 'targets', is: ['preview'] } }
```

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
| `sync.update` | paused or resumed, `paused` in the metadata            | the person                      |
| `sync.delete` | a sync was removed, and its principal with it          | the person                      |

Runs that nobody pressed a button for (after a change, or from the scheduler)
are logged under the system actor `sync:<id>`, with `trigger` in the metadata
saying which. Every row of one run shares an operation id, and so do the
vault's `secret.read` entries for the values it opened, for the purpose `sync`.

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

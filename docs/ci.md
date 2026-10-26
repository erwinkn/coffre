# Secrets in CI and deploys

Give each pipeline a service account, a machine identity, `service:<name>`,
with a `viewer` grant on only the environments it reads. It signs in one of
two ways:

- **by OIDC**: its CI's ID token, matched by a trust binding, with nothing to
  store or rotate. Use it wherever the CI signs one, as GitHub Actions and
  GitLab do ([Without a stored token](#without-a-stored-token));
- **with a bearer token**, kept in the CI's secrets, for CI without OIDC.

On coffre's Service accounts page, or with the CLI:

```sh
coffre admit api-deploy --service
coffre grant market api-deploy --role viewer --env prod --service
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --apply   # OIDC
coffre tokens issue api-deploy --output-file api-deploy.token   # or a bearer token, in a new 0600 file
```

A member is admitted before it holds anything: `coffre grant` does not make
one, and says so. To add one and grant it at once, `coffre admit api-deploy
--service --grant market/prod=viewer`, or on a project's Service accounts
page, Add service account with a new name: both are one change, and a
grant refused adds no account either. Grant before you trust or issue: each binding and token
reaches what its account holds when it is made, or less with `--scope
market/prod=viewer`, and nothing the account is given later. To widen one,
make another and remove the first. With a bearer token, store it in your CI provider's secret store. The
CLI reads no environment variable, and a secret is never a flag or an
argument, which `ps`, the shell's history and CI logs would show: the job
pipes the token to `coffre login --token`, which saves the session the
commands after it use.

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

The session lives in the job's home, `~/.coffre`, one per instance. On a
runner that several jobs share under one user, a self-hosted runner or a
GitLab shell executor, give each job a home of its own, so that no other
job signs in over it or reads with it: `export HOME="$(mktemp -d)"` before
`coffre login`, removed when the job ends. `coffre logout` forgets the
token there too, and revokes nothing.

A bearer token works without an interactive login. The runner must be
able to reach your instance; behind Cloudflare Access, the job signs in
with an Access service token instead, its secret piped in the same way:
`coffre login <url> --access-client-id <id>`
([deployment-auth.md](deployment-auth.md)). See the
[deployment settings](deploy.md#1-settings).

Each value read is audited before it reaches the pipeline. Revoking the
token stops future reads. Values already exported to a runner or copied to
a platform remain there until that job ends or the platform updates them.
coffre holds no Cloudflare, Vercel or GitHub write credential for this.

## Without a stored token

A CI run can sign in as a service account by OIDC, with the ID token its
platform signs for it, instead of a bearer token kept in the CI's secrets. An
owner trusts the workflow, on the service account's page under "Sign in with
OIDC", or with
`coffre trust` ([how a binding is checked](design/oidc.md)). Each run then
trades its ID token for a credential that lasts five minutes, and nothing
long-lived is stored. A deployment `coffre init` writes has this on; an
older one turns it on ([deploy.md](deploy.md#ci-runs-without-a-stored-token)).

```sh
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --apply
```

A binding trusts one workflow file, at one branch or tag, on the events you
list. By default that is `push`, and the preview says which events the
binding accepts and how to add others. A workflow a person can start by
hand and that runs on a schedule as well:

```yaml
# .github/workflows/deploy.yml
on:
  push:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: '17 6 * * *'
```

is trusted with one binding:

```sh
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --event push,workflow_dispatch,schedule --apply
```

A schedule runs on a branch, and a release at a tag (`--tag v1 --event
release`). On GitLab, `--source push,web,schedule` does the same for the
pipeline's source.

### In a GitHub environment

`--github-environment production` (in the dialog, "GitHub environment")
takes only the workflow's jobs that run in that GitHub environment:

```yaml
jobs:
  deploy:
    environment: production
    permissions: { id-token: write, contents: read }
```

```sh
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --github-environment production --apply
```

The job then signs in only once the environment's protection rules, such
as required reviewers, let it run. Without them, naming an environment adds
nothing: anyone who can push a workflow can name one. The name matches
whatever its case, as GitHub's environment names do.

### CI on pull requests

`--event pull_request` trusts the workflow's runs for pull requests into
the binding's branch. Such a run is at `refs/pull/<n>/merge`, so coffre
matches it by `base_ref`, the branch it merges into, as GitHub's own
`on.pull_request.branches` filter does:

```sh
coffre trust api-ci --github acme/api --workflow ci.yml --branch main --event push,pull_request --apply
```

A pull request runs its own code and its own copy of the workflow file,
before anyone reviews it. So anyone who can push a branch to the
repository can read what the service account reads. Pull requests from
forks get no ID token: GitHub turns `id-token: write` off for them, unless
an admin enabled "Send write tokens to workflows from pull requests" on a
private repository. Dependabot's are treated like forks. Give a service
account trusted on pull requests only the secrets CI needs, never
production's.

`workflow_run` runs the default branch's workflow after another one
finishes, and a fork's pull request can start it. It is safe while it runs
none of the code or artifacts of the run that started it.

`pull_request_target` is refused. It runs with the base repository's tokens
for anyone's pull request, forks included, and exists to label or comment
on them.

coffre looks up a repository's or project's IDs, which a binding keeps, so
that a name passed on to someone else trusts nothing: the dialog as you type
the name, and `coffre trust` before it shows the binding. GitHub and GitLab
show a private one only to those signed in to it. With a GitHub App of the
deployment's own ([github-app.md](github-app.md)), coffre resolves the names
of the repositories it is installed on, private ones too. Otherwise, for a
private one coffre says so and gives the command that gets them, whose
output is the two flags to add (in the dialog, the fields under "Private
repository? Enter IDs"):

```sh
gh api repos/acme/website --jq '"--repository-id \(.id) --owner-id \(.owner.id)"'
```

With the CLI:

- **GitHub Actions**: give the job `permissions: id-token: write`, and
  pass `--service` (the service account, `api-deploy` or `service:api-deploy`) and
  `--url`, nothing else. Each command asks the runner for a fresh ID token,
  for your instance's URL, and keeps the credential it buys in memory:

  ```sh
  coffre --url https://secrets.acme.example --service api-deploy run market/prod -- ./deploy
  ```

  In a repository whose `coffre.json` names the instance (the README's
  CLI section), `--url` can go: the ID token is asked for the URL the
  file names, and only that instance takes it.
- **GitLab**: declare an ID token for your instance, and pipe it to
  `coffre login --service --id-token`, which trades it for the credential
  and saves it as the session the commands after it use, for its five
  minutes:

  ```yaml
  deploy:
    id_tokens:
      ID_TOKEN:
        aud: https://secrets.acme.example
    script:
      - export HOME="$(mktemp -d)"   # on a shell executor, a home of the job's own
      - printf '%s' "$ID_TOKEN" | coffre login https://secrets.acme.example --service api-deploy --id-token
      - coffre run market/prod -- ./deploy
  ```

  A token is spent once used: a job that runs past five minutes signs in
  again with a second ID token.
- **Any other issuer** a `custom` binding trusts: the same, its ID token
  for your instance's URL piped to `coffre login --service <name>
  --id-token`.

### Issuers coffre cannot reach

coffre fetches an issuer's keys from the URL its discovery document names:
an `https` URL on a public host. An issuer on a private network, a
Kubernetes cluster's say, has no such URL. Upload its public keys with the
binding instead, a JWKS, `{ "keys": [ … ] }`:

```sh
coffre trust api-deploy --issuer https://kubernetes.default.svc.cluster.local --jwks-file cluster-jwks.json \
  --claim sub=system:serviceaccount:ci:deploy --claim kubernetes.io.serviceaccount.uid=4f1c8d2a-… --apply
```

In the dialog, "Other issuer", the keys go under Keys. With keys uploaded:

- **coffre fetches nothing**, when the binding is made or at any exchange.
  The issuer is then any string, the token's `iss` exactly, whatever its
  scheme, host or port. github.com's and gitlab.com's issuers are the
  exception: they rotate their keys, so coffre always fetches theirs.
- **The keys are checked when uploaded.** coffre keeps RSA keys of 2048 bits
  or more, for RS256, and P-256 keys, for ES256, each with only the members
  that verify. It leaves out keys for encryption. A private or secret key
  refuses the whole set: coffre keeps nothing of the issuer's that is
  secret. The binding shows each key by its `kid`, or its RFC 7638
  thumbprint when it has none.
- **A token lives an hour at most**, `exp` minus `iat`, besides being
  issued at most an hour before it is exchanged and spent once, as every
  token is. coffre cannot ask such an issuer whether a token still stands,
  so the hour is what a copied token is good for.
- **A claim may be nested**, named by its path, its keys joined by dots:
  `kubernetes.io.serviceaccount.uid` is `uid` in `serviceaccount` in
  `kubernetes.io`. A key may hold dots of its own, so a name matches only
  when exactly one reading of it reaches a value in the token. This holds
  for every binding, not only those with uploaded keys.
- **The service's bindings on an issuer share their keys.** A binding with
  other keys than the others on its issuer is refused. When the issuer
  rotates, give them all the new keys at once:

  ```sh
  coffre trust api-deploy --issuer https://kubernetes.default.svc.cluster.local --replace-keys --jwks-file cluster-jwks.json --apply
  ```

  Each binding on the issuer is replaced by one that is the same except
  for its keys, and the credentials the old one issued end. Upload a set
  that holds the old key and the new while the issuer moves from one to the
  other, and tokens signed by either sign in. In the pages: a binding's
  Claims, Replace keys.

[Kubernetes](kubernetes.md) walks through it for a cluster's pods, with
the projected token and a key rotation.

## Several environments

A deploy that needs two environments' secrets names both:

```sh
coffre run deploy/prod auth/prod -- ./deploy
coffre export deploy/prod auth/prod --format json
```

The command gets their keys together. Every environment is read, one
audited read each, or none is: the CLI first lists each one's keys, which
opens no value, and stops before reading anything if it may not read one
of them, if one holds a reference that cannot be read, or if two of them
define the same key. coffre does not pick a winner for a key in two
places; it names the key and both environments, never a value:

```text
coffre: deploy/prod and auth/prod both define API_URL: a key comes from one environment only. Nothing was read
```

Keep each key in one of them, and archive the other's copy. The listing
narrows the window but does not close it: an environment changed between
the listing and the reads, a grant revoked or a clashing key added, still
stops the command, and no value is used, but the reads made before it are
in the audit log. The service account needs a `viewer` grant on each
environment.

## A key the other environments have

You add `STRIPE_WEBHOOK_SECRET` to `market/staging` and forget
`market/prod`. `coffre missing --check` stops the deploy before it reads
anything:

```sh
coffre missing market/prod --check && coffre run market/prod -- ./deploy
```

```
STRIPE_WEBHOOK_SECRET        in staging
coffre: market/prod lacks a key its sibling environments have: `coffre set market/prod/<KEY>` adds one; `coffre missing dismiss market/prod/<KEY>`, or --all, says it is not needed
```

It exits 1 when the environment lacks a live key that another live
environment of its project has, and 0 otherwise. It compares against every
one of the project's environments, including those the credential can't
read: a token that reads only `market/prod` still sees that `staging` has
`STRIPE_WEBHOOK_SECRET`. Within a project, key names are not secret: anyone
who reads one of its environments can learn which keys its other
environments have, never their values. Other projects are never compared.
A key that `market/prod` doesn't need, dismissed with `coffre missing
dismiss market/prod/<KEY>`, never fails the check. `--json` lists the same
keys as JSON and fails the same way. An instance older than 0.6 compares
only the environments the credential reads.

## GitHub Actions

Use a released tag containing the [Action](../action/action.yml), replacing
`<version>` with that release's version:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: erwinkn/coffre/action@v<version>
    with:
      url: https://secrets.acme.example
      token: ${{ secrets.COFFRE_TOKEN }}
      environment: market/prod
      keys: DATABASE_URL STRIPE_*
  - run: ./deploy
```

Or, without a stored token, with a binding that trusts the workflow:

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/checkout@v4
  - uses: erwinkn/coffre/action@v<version>
    with:
      url: https://secrets.acme.example
      service: token:api-deploy
      environment: market/prod
      keys: DATABASE_URL STRIPE_*
  - run: ./deploy
```

`keys` names what the job gets: each key by its name, or every key that
starts with a prefix, `STRIPE_*`, separated by spaces or lines. It is
required, and a bare `*` is refused. Whatever the Action exports, every
later step of the job sees, so the workflow, which its reviewers read,
says what that is, as `env: FOO: ${{ secrets.FOO }}` does for GitHub's
own secrets. Without it, anyone who may only write `market/prod` could add
`BASH_ENV` or a build tool's hook there, and the next step would run
their code with the job's access. A name that none of the environments
holds, or a prefix that starts none of their keys, stops the step before
anything is read, as a typo should: `market/prod holds no key that --keys
names as DATABSE_URL. Nothing was read`. Only the keys named are read,
logged and counted against the vault's bulk limit; the others are never
opened. To hand every key of an environment to one process, and to no
other step, run it with `coffre run market/prod -- ./deploy`.

The Action uses your job's existing Node, which must be version 20 or newer,
and runs `@coffre/cli` at the same exact version as the tag. It leaves your
toolchain and `PATH` unchanged. It pipes the token to `coffre login --token`,
never in a command argument, with the CLI in a home of the step's own,
removed when the step ends: no other job on the runner sees the session. The secrets become environment variables in subsequent steps
of the same job. Their values, and each line of multiline values, are
masked before being written to `GITHUB_ENV`. Newlines, quotes, `=` and `%`
are kept intact. Empty values are exported too.

A key that a later step's shell, dynamic loader, language runtime or git
reads as code to run, or as where to load it from, is refused, and the
export with it, before anything is read, naming the key, whether `keys`
names it or a prefix finds it: `PATH`, `BASH_ENV`, `LD_PRELOAD`,
`NODE_OPTIONS`, `GIT_SSH_COMMAND`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS` and the
rest of `RUNS_CODE` (`packages/cli/src/github-env.ts`). Set through
`GITHUB_ENV`, one such secret would run code in every later step of the
job. The list is a backstop behind `keys`, not a boundary: it blocks the
common one-variable hijacks and is not exhaustive. Prefer names to broad
prefixes: what a prefix matches, whoever writes the environment chooses.
GitHub's default metadata variables cannot be overridden.
Other names such as `GITHUB_TOKEN` work.
[GitHub documents these runner rules](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-an-environment-variable).

The inputs are `url`, `environment`, `keys`, one of `token` or `service`, and
`require-complete`. `environment` takes several environments, separated by
spaces or lines, read together as [above](#several-environments): each key
`keys` names comes from whichever holds it, and an environment it names
none of is not read. Only the keys named clash:

```yaml
  - uses: erwinkn/coffre/action@v<version>
    with:
      url: https://secrets.acme.example
      service: token:api-deploy
      environment: deploy/prod auth/prod
      keys: |
        CLOUDFLARE_API_TOKEN
        GITHUB_CLIENT_*
      require-complete: true
```

`require-complete: true` (the default is `false`) runs [`coffre missing
--check`](#a-key-the-other-environments-have) on each environment before
anything is read. When one lacks keys, the step fails before exporting,
with an error annotation per environment that lists each missing key and
where it is: `market/prod lacks keys its sibling environments have:
STRIPE_WEBHOOK_SECRET in staging`.

With `service`, the run's ID token and the credential it buys are masked too.

The step's log says each request the CLI made, with its answer and how
long it took, and each time it asked again, as `--verbose` does: never a
header, a body or a value. A slow step shows where its time went:

```text
coffre: GET pipelines.actions.githubusercontent.com: 200 in 212 ms
coffre: POST /api/auth/oidc: 200 in 1.4 s
coffre: GET /api/secrets/deploy/prod: 200 in 310 ms
coffre: POST /api/reveals: 200 in 480 ms
```

Each `coffre` the step runs starts through `npx` first, which these lines
do not count: the timestamps GitHub puts on each line of the log show it.

When the instance answers 503 for a moment's trouble (it could not reach
its database or its vault, count exchanges, fetch the issuer's keys, or is
moving to its new app key), the step's sign-in, its reads of values and
its `require-complete` check are asked again, about 2 s and then 5 s
later, before the step fails. An instance that says `Retry-After` (5 s on
a 503 `unavailable`) is asked no sooner than that, and no wait is longer
than 15 s. Each wait varies by up to half, so that
the jobs of one run do not all ask again at once, and each sign-in asks
GitHub for a fresh ID token. A 503 an operator or a deploy must clear
(`wrong_kek`, `vault_outdated`, `app_key`, `migrating`) fails the step at
once. `coffre --service <name> run` against an instance that signs it in
with a key of its own (a key-bound session) is not asked again yet:

```text
coffre: POST /api/auth/oidc: 503 in 15.2 s
coffre: the instance could not answer POST /api/auth/oidc: asking again in 2.3 s
coffre: GET pipelines.actions.githubusercontent.com: 200 in 205 ms
coffre: POST /api/auth/oidc: 200 in 1.1 s
```

To use an installed CLI directly inside a step:

```sh
coffre --url https://secrets.acme.example --service api-deploy export market/prod --format github --keys 'DATABASE_URL STRIPE_*'
```

It requires `GITHUB_ENV`, and `--keys`, as the Action requires `keys`. The
`json`, `dotenv` and `shell` formats write to stdout and do not issue
GitHub mask commands; they take `--keys` too, and read every key without
it. A person's export, on an instance with the credential proxy, gets
placeholders of whole environments and refuses `--keys`. Use `github` when loading values into an Actions job.

## Cloudflare Workers

In your deploy job, with the CLI installed and Wrangler pinned in your
deployment's dependencies:

```sh
set -o pipefail
coffre export market/prod --format json | pnpm exec wrangler secret bulk --env prod
pnpm exec wrangler deploy --env prod
```

The job uses the `CLOUDFLARE_API_TOKEN` it already holds to deploy. JSON
preserves multiline values and is accepted on stdin by
[`wrangler secret bulk`](https://developers.cloudflare.com/workers/wrangler/commands/workers/#secret-bulk).
This updates the supplied keys; keys absent from the export remain in the
Worker's secret store. Remove obsolete keys there explicitly. A later
coffre revocation does not revoke the copy already deployed to Cloudflare.

## Vercel

`coffre run` gives a command its environment without a temporary secret
file. For credentials and configuration consumed by your local deploy CLI:

```sh
coffre run market/prod -- pnpm exec vercel deploy --prod
```

Vercel does not automatically upload that process environment as remote
build or runtime variables. Those are
[configured separately](https://vercel.com/docs/cli/deploy#env).
To push a runtime value from the pipeline, use stdin, keeping its exact
value out of command arguments:

```sh
set -o pipefail
coffre run market/prod -- sh -c 'printf "%s" "$DATABASE_URL" | pnpm exec vercel env add DATABASE_URL production --force'
pnpm exec vercel deploy --prod
```

Repeat the push for the keys that deployment needs. The job uses its
existing Vercel credentials. [`vercel env add`](https://vercel.com/docs/cli/env)
accepts stdin; `--force` replaces a value already set for that target.
`vercel env pull .env.local --environment=production` pulls Vercel's stored
values for local use, rather than reading coffre. For `vercel build`, use
`vercel pull` to fetch the project settings and variables under `.vercel/`.

## Other pipelines

Give the deploy process values directly:

```sh
coffre run market/prod -- ./deploy
```

For a tool that needs a file, use `coffre export market/prod --format json`
or `--format dotenv`. The dotenv output is parser input, not shell code.
If a shell script needs assignments, `--format shell` quotes them
literally. `coffre run` avoids parsing or sourcing an export.

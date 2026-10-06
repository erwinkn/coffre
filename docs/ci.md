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
one, and says so. With a bearer token, store it in your CI provider's secret store. The
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

A binding matches one event: the one that started the run. By default that
is `push`, and the preview says which events the bindings accept and how to
add others. A workflow a person can start by hand and that runs on a
schedule as well:

```yaml
# .github/workflows/deploy.yml
on:
  push:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: '17 6 * * *'
```

is trusted with a binding for each, made in one go:

```sh
coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main --event push,workflow_dispatch,schedule --apply
```

A schedule runs on a branch, and a release at a tag (`--tag v1 --event
release`). On GitLab, `--source push,web,schedule` does the same for the
pipeline's source.

coffre looks up a repository's or project's IDs, which a binding keeps, so
that a name passed on to someone else trusts nothing. GitHub and GitLab
show a private one only to those signed in to it, so for one coffre says
so and gives the command that gets them, whose output is the two flags to
add:

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
  - run: ./deploy
```

The Action uses your job's existing Node, which must be version 20 or newer,
and runs `@coffre/cli` at the same exact version as the tag. It leaves your
toolchain and `PATH` unchanged. It pipes the token to `coffre login --token`,
never in a command argument, with the CLI in a home of the step's own,
removed when the step ends: no other job on the runner sees the session. The secrets become environment variables in subsequent steps
of the same job. Their values, and each line of multiline values, are
masked before being written to `GITHUB_ENV`. Newlines, quotes, `=` and `%`
are kept intact. Empty values are exported too.

GitHub blocks `NODE_OPTIONS` through `GITHUB_ENV`, so an environment with
that key is refused. GitHub's default metadata variables cannot be
overridden. Other names such as `GITHUB_TOKEN` work.
[GitHub documents these runner rules](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-an-environment-variable).

The inputs are `url`, `environment`, and one of `token` or `service`.
`environment` takes several environments, separated by spaces or lines,
read together as [above](#several-environments):

```yaml
  - uses: erwinkn/coffre/action@v<version>
    with:
      url: https://secrets.acme.example
      service: token:api-deploy
      environment: deploy/prod auth/prod
```

With `service`, the run's ID token and the credential it buys are masked too.

To use an installed CLI directly inside a step:

```sh
coffre --url https://secrets.acme.example --service api-deploy export market/prod --format github
```

It requires `GITHUB_ENV`. The `json`, `dotenv` and `shell` formats write to
stdout and do not issue GitHub mask commands. Use `github` when loading
values into an Actions job.

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

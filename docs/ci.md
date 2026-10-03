# Secrets in CI and deploys

Give each pipeline a service member and a token, with a `viewer` grant on
only the environments it reads. Create the member and token in coffre's
Access page. Store the token in your CI provider's secret store as
`COFFRE_TOKEN`, and set `COFFRE_API_URL` to your instance's URL. A service
token works without an interactive login. The runner must be able to reach
your instance; a Cloudflare Access gate also needs its own service token,
passed as `COFFRE_ACCESS_CLIENT_ID` and `COFFRE_ACCESS_CLIENT_SECRET` in the
job's environment. See the [deployment settings](deploy.md#1-settings).

Each value read is audited before it reaches the pipeline. Revoking the
token stops future reads. Values already exported to a runner or copied to
a platform remain there until that job ends or the platform updates them.
coffre holds no Cloudflare, Vercel or GitHub write credential for this.

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

The Action installs Node 24 and runs `@coffre/cli` at the same exact version
as the tag. It passes the token through the environment, never command
arguments. The secrets become environment variables in subsequent steps
of the same job. Their values, and each line of multiline values, are
masked before being written to `GITHUB_ENV`. Newlines, quotes, `=` and `%`
are kept intact. Empty values are exported too.

GitHub blocks `NODE_OPTIONS` through `GITHUB_ENV`, so an environment with
that key is refused. GitHub's default metadata variables cannot be
overridden. Other names such as `GITHUB_TOKEN` work.
[GitHub documents these runner rules](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-an-environment-variable).

The inputs are `url`, `token` and `environment`. `oidc` is coming; it has no
effect yet, and a service token is still required.

To use an installed CLI directly inside a step:

```sh
coffre export market/prod --format github
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

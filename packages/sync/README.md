# @coffre/sync

Pushes coffre's variables to the places that run code. There is one provider
per target, and all of them have the same shape (`src/types.ts`):

```ts
import { getProvider } from '@coffre/sync';

const github = getProvider('github-actions')!;
const config = github.parseConfig({ owner: 'acme', repo: 'app' });
const ctx = { token };
const current = await github.listKeys(ctx, config);
const result = await github.apply(ctx, config, {
  upsert: [{ key: 'DATABASE_URL', value }],
  delete: ['OLD_KEY'],
});
// result: { upserted, deleted, failed: [{ key, operation, message }] }
```

`apply` throws a `SyncProviderError` only when the whole call cannot succeed
(the token is bad, the target is missing, the target is rate limiting us, or
the upstream is down). A key the target refuses lands in `failed`, and the
other keys still go through. Neither thrown errors nor `failed` messages ever
contain the token or a value. The code runs as is in Node 24 and in
Cloudflare Workers.

## GitHub Actions

`{ owner, repo, environment? }`. This sets repository secrets, or
environment secrets when `environment` is given.

- **Credential:** a fine-grained personal access token limited to the
  repository, or a GitHub App installation token.
  - Repository secrets need **Secrets: Read and write**.
  - Environment secrets need **Environments: Read and write**.
  - A classic token needs the `repo` scope.
- **Write-only:** every value. GitHub never returns secret values, only
  names and timestamps.
- **Names:** letters, digits and `_`, with no leading digit and no `GITHUB_`
  prefix. They must also be upper case: GitHub upper-cases names, and would
  otherwise report back a different key from the one we sent.

## Vercel

`{ projectId, teamId?, targets, gitBranch? }`, where `targets` is some of
`production`, `preview` and `development`.

- **Credential:** an access token from Account Settings → Tokens, scoped to
  the team that owns the project. Pass that team's `teamId` as well.
- **Write-only:** production and preview values, which are stored as
  **sensitive** and can never be read back. Vercel does not allow sensitive
  development values, so those are stored as **encrypted**, and anyone on
  the project can read them.
- **Semantics:** one key can therefore become two Vercel records. A record
  that also covers targets outside the config is narrowed, never deleted.
  Changes only take effect on the next deployment.

## Railway

`{ projectId, environmentId, serviceId?, tokenKind? }`. Leave out `serviceId`
to write the environment's shared variables.

- **Credential:** a **project token** (project settings → Tokens) is limited
  to a single environment. It is the one to prefer, and needs
  `tokenKind: 'project'`. An account or workspace token (account settings →
  Tokens) also works, with the default `tokenKind: 'account'`, but it can
  touch much more.
- **Write-only:** nothing by default. Anyone with access to the project can
  read the values unless they are sealed in the dashboard. The API never
  returns sealed values.
- **Semantics:** every change redeploys the service. Upserts go in a single
  call, so they trigger one redeploy, but each delete triggers its own. Names
  starting with `RAILWAY_` are reserved.

## Cloudflare Workers

`{ accountId, scriptName }`.

- **Credential:** an API token with **Account → Workers Scripts → Edit**
  ("Workers Scripts Write"), limited to the account.
- **Write-only:** every value. Cloudflare only returns secret names.
- **Semantics:** each apply creates and deploys a new Worker version at once
  (one per 100 changes). The edit is refused while the latest version is not
  the deployed one, for example during a gradual rollout.

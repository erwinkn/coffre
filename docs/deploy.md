# Deploying coffre

The long-term deployment model is a small project that imports coffre's
packages and configures them in code. That arrives with phase 2, step 6 of the
[roadmap](roadmap.md#phase-2-package); [architecture.md](architecture.md)
describes the target.

Until then, deploy `apps/web` yourself with Wrangler. Put the Worker name,
routes, Hyperdrive binding and non-secret `COFFRE_*` variables directly in
[`apps/web/wrangler.jsonc`](../apps/web/wrangler.jsonc). Set the secret values
listed there with `wrangler secret put` or in the Cloudflare dashboard. The vault
is a second Worker, [`apps/vault`](../apps/vault/wrangler.jsonc), and its secrets
(the KEK, the root admins, the checkpoint signing key) are set on it, not on the
app, which refuses to start with them. The
[Cloudflare Access guide](deployment-auth.md) documents proxy authentication;
the same config file can select coffre's own sign-in providers instead.

Run database migrations with the owner connection before deploying a revision
that adds one:

```sh
DATABASE_URL='postgres://<owner>:<password>@<host>:5432/coffre?sslmode=require' \
  pnpm db:migrate
```

Then build and deploy the Worker from this checkout:

```sh
pnpm --dir apps/web build                    # builds both Workers
pnpm --dir apps/web exec wrangler deploy --config dist/coffre_vault/wrangler.json
pnpm --dir apps/web exec wrangler deploy
```

The vault goes first: the app's `VAULT` binding names it. Its Durable Object
holds every grant and member, so back it up like the database.

This is a temporary source-checkout workflow. Once the packages land, each
deployment should live in its own repository and import the published server,
UI and vault packages.

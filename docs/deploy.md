# Deploying coffre

The long-term deployment model is a small project that imports coffre's
packages and configures them in code. That arrives with phase 2, step 5 of the
[roadmap](roadmap.md#phase-2-package); [architecture.md](architecture.md)
describes the target.

Until then, deploy `apps/web` yourself with Wrangler. Put the Worker name,
routes, Hyperdrive binding and non-secret `COFFRE_*` variables directly in
[`apps/web/wrangler.jsonc`](../apps/web/wrangler.jsonc). Set the secret values
listed there with `wrangler secret put` or in the Cloudflare dashboard. The
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
pnpm --dir apps/web build
pnpm --dir apps/web exec wrangler deploy
```

This is a temporary source-checkout workflow. Once the packages land, each
deployment should live in its own repository and import the published server,
UI and vault packages.

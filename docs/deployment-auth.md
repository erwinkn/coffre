# Signing in behind Cloudflare Access

A deployed coffre signs people in one of two ways, chosen by the `auth` it
is configured with:

- `signin({ providers })`: coffre's own sign-in page, with GitHub, Google,
  Microsoft or any OpenID Connect provider. `coffre init` sets up GitHub;
  [deploy.md](deploy.md) walks through it.
- `cloudflareAccess({ teamDomain, audience })`: Cloudflare Access in front of
  coffre, which verifies the token Access forwards. This page describes it.

Neither runs a password flow or a persona picker.

## Cloudflare Access inputs

Configure one Cloudflare Access application for the production hostname, then
give the app Worker (`app/src/worker.ts`) that application instead of
`signin(…)`:

```ts
import { cloudflareAccess, coffre, postgres } from '@coffre/server/cloudflare';

export default coffre((env: Env) => ({
  // …
  auth: cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: env.ACCESS_AUD }),
}));
```

- `teamDomain` is `<your-team-name>.cloudflareaccess.com`. coffre takes the
  issuer and its keys (`/cdn-cgi/access/certs`) from it, and refuses any
  other domain.
- `audience` is the AUD tag copied from **Zero Trust > Access controls >
  Applications > Configure > Additional settings** for this specific
  application. It is not the application ID or hostname. Put it in
  `wrangler.jsonc` as a var; it is not a secret.

The GitHub settings and `GITHUB_CLIENT_SECRET` are then unused: drop them
from `wrangler.jsonc` and the worker's `Env`.

Cloudflare documents that the origin receives the application token in
`Cf-Access-Jwt-Assertion`, and recommends validating that header rather than
the browser cookie. Coffre verifies its signature, issuer, and audience before
any `/api` handler runs, and every page reads through `/api`.

Official references:

- [Validate JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Create an Access application](https://developers.cloudflare.com/learning-paths/clientless-access/access-application/create-access-app/)
- [Connect through Access using a CLI](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/)

### The CLI

`coffre login` recognises an Access-protected instance by the redirect to
Access's login page, and hands over to `cloudflared`:

```sh
coffre login https://<coffre-api-hostname>
```

`cloudflared` opens the browser, keeps the resulting application token, and
refreshes it; the CLI asks it for the current token on every command
(`cloudflared access token -app=…`) and sends it as `cf-access-token`, which
Cloudflare validates at the edge before adding the `Cf-Access-Jwt-Assertion`
header the origin verifies. If the Access application answers non-browser
clients with a 401 instead of a redirect, say which mode to use:
`COFFRE_AUTH_MODE=cloudflare coffre login https://…`.

CI and other machines use an Access service token instead, with nothing
stored on disk:

```sh
COFFRE_API_URL=https://<coffre-api-hostname> \
COFFRE_ACCESS_CLIENT_ID=<id>.access \
COFFRE_ACCESS_CLIENT_SECRET=<secret> \
  coffre run app/prod -- ./deploy.sh
```

The CLI refuses a plaintext, credentialed, or path-bearing address before
sending anything, and never follows Access login redirects: a rejected or
expired token is reported as such instead of loading the browser login page.

## Closed-door behavior

The production hostname must be protected by an Access Allow policy. Coffre
still fails closed at the origin boundary: every path except exact `/livez`
and `/readyz` returns `401 unauthenticated` without the forwarded
assertion. There is no production persona picker or local login route.

Do not treat this application check as a substitute for protecting the data
plane. The Worker receives PostgreSQL access only through its Hyperdrive
binding; the Scaleway database has no public endpoint.

## Root-admin bootstrap

Root admins are the vault's configuration (`vault/src/worker.ts`), not the
app's: at least one human email.

```ts
rootAdmins: ['first.admin@example.com'],
```

`coffre init` reads them from the vault's `ROOT_ADMINS` var, comma-separated.

Each value must be an email and match the `email` claim Cloudflare Access
emits. Service-token `common_name` values cannot be root admins. That person
must also be allowed by the Access application policy. Root admins are the
configuration-owned bootstrap principals that can create the first project and
grant; an empty or malformed list makes a new instance unadministrable, so the
vault refuses to start with one.

Every non-root identity must also be an active member, which the vault decides. Passing the Cloudflare Access policy authenticates the person; it
does not register them in this Coffre instance. An authenticated but
unregistered browser is confined to `/unregistered`, while `/api` returns
`403 registration_required` for everything but `GET /api/me`.

Changes to `rootAdmins` are deployment configuration changes. Keep at
least one controlled bootstrap identity until the operational recovery path is
defined and tested.

## Local development is a separate mode

Local development (`pnpm dev`, whose deployment is `dev/deployment/app.ts`)
uses `devIdp({ url: 'http://127.0.0.1:8081' })`: the dev IdP stands in for
Access, minting Access-shaped tokens for a persona picker. `devIdp` refuses
any URL that is not on loopback, so no deployment can end up trusting it.

The dev IdP (`@coffre/conformance/idp`, which `dev/idp` runs), `dev/seed.mjs`,
the seeded persona page, and CLI email/service persona minting are local
tooling. The dev IdP is not deployed: conformance runs it in its own process,
for the run. Both `dev/idp` and the seed script refuse to run unless their
shell has `COFFRE_AUTH_MODE=dev`. The seed additionally requires the exact checked-in
loopback database, API, IdP, and local AUD values before performing its
destructive reset.

# Signing in behind Cloudflare Access

A deployed coffre signs people in one of two ways, chosen by
`COFFRE_AUTH_MODE` in its Worker configuration:

- `signin`: coffre's own sign-in page, with GitHub, Google, Microsoft or any
  OpenID Connect provider. [deploy.md](deploy.md) sets one up.
- `cloudflare`: Cloudflare Access in front of the Worker, and coffre verifies
  the token Access forwards. This is coffre's default and what this page
  describes.

Neither runs a password flow or a persona picker.

## Cloudflare Access inputs

Configure one Cloudflare Access application for the production hostname, then
set the following bindings on the Worker:

```dotenv
COFFRE_AUTH_MODE=cloudflare
COFFRE_ACCESS_ISSUER=https://<your-team-name>.cloudflareaccess.com
COFFRE_ACCESS_JWKS_URL=https://<your-team-name>.cloudflareaccess.com/cdn-cgi/access/certs
COFFRE_ACCESS_AUD=<the Application Audience (AUD) Tag>
```

- `COFFRE_ACCESS_ISSUER` is the HTTPS team domain, with no trailing slash.
- `COFFRE_ACCESS_JWKS_URL` is exactly that issuer plus
  `/cdn-cgi/access/certs`.
- `COFFRE_ACCESS_AUD` is the AUD tag copied from **Zero Trust > Access
  controls > Applications > Configure > Additional settings** for this
  specific application. It is not the application ID or hostname.
- `COFFRE_DEV_IDP_URL` must be absent. Its presence contradicts Cloudflare mode
  and makes configuration loading fail before the application accepts an
  authenticated request.

Cloudflare documents that the origin receives the application token in
`Cf-Access-Jwt-Assertion`, and recommends validating that header rather than
the browser cookie. Coffre's global request middleware verifies its signature,
issuer, and audience before either a UI server function or `/api` handler runs.

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

Set `COFFRE_ROOT_ADMINS` on the web service to at least one comma-separated human email
identity:

```dotenv
COFFRE_ROOT_ADMINS=first.admin@example.com
```

Each value must be an email and match the `email` claim Cloudflare Access
emits. Service-token `common_name` values cannot be root admins. That person
must also be allowed by the Access application policy. Root admins are the
configuration-owned bootstrap principals that can create the first project and
grant; an empty or malformed list makes a new instance unadministrable, so the
web service refuses to initialize with one in Cloudflare mode.

Every non-root identity must also have an active row in Coffre's principal
directory. Passing the Cloudflare Access policy authenticates the person; it
does not register them in this Coffre instance. An authenticated but
unregistered browser is confined to `/unregistered`, while `/api` and all
product server functions return `403 registration_required`.

Changes to `COFFRE_ROOT_ADMINS` are deployment configuration changes. Keep at
least one controlled bootstrap identity until the operational recovery path is
defined and tested.

## Local development is a separate mode

Local development uses:

```dotenv
COFFRE_AUTH_MODE=dev
COFFRE_DEV_IDP_URL=http://127.0.0.1:8081
COFFRE_ACCESS_ISSUER=http://127.0.0.1:8081
COFFRE_ACCESS_JWKS_URL=http://127.0.0.1:8081/cdn-cgi/access/certs
COFFRE_ACCESS_AUD=coffre-local-dev-aud
```

`apps/dev-idp`, `scripts/seed.mjs`, the seeded persona page, and CLI
email/service persona minting are local tooling. The dev IdP is not deployed.
Both the dev IdP and seed script refuse to run unless
`COFFRE_AUTH_MODE=dev`. The seed additionally requires the exact checked-in
loopback database, API, IdP, and local AUD values before performing its
destructive reset.

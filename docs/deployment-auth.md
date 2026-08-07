# Production authentication

Production authentication is Cloudflare Access. Coffre does not run an
identity provider, a password flow, or a persona picker in production.

## Cloudflare Access inputs

Configure one Cloudflare Access application for the production hostname, then
set the following variables on the single web process:

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

### CLI user tokens

For interactive CLI use, point `COFFRE_API_URL` at the explicit HTTPS origin
of the Access-protected web service, set `COFFRE_AUTH_MODE=cloudflare`, and obtain a
user application token:

```sh
cloudflared access login https://<coffre-api-hostname>
export COFFRE_TOKEN="$(cloudflared access token -app=https://<coffre-api-hostname>)"
```

Cloudflare mode refuses a missing, plaintext, credentialed, or path-bearing
`COFFRE_API_URL` before sending the token. The CLI sends this client-side token
as `cf-access-token`, which Cloudflare validates at the edge. Cloudflare then adds the separate
`Cf-Access-Jwt-Assertion` header that the coffre API verifies at the origin.
The CLI does not follow Access login redirects; a rejected or expired token is
reported as unauthenticated instead of loading the browser login page.

## Closed-door behavior

The production hostname must be protected by an Access Allow policy. Coffre
still fails closed at the origin boundary: every path except exact `/livez`
and `/readyz` returns `401 cloudflare_access_required` without the forwarded
assertion. There is no production persona picker or local login route.

Do not treat this application check as a substitute for protecting the origin
network. The production deployment must expose only the intended
Access-protected path to users.

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

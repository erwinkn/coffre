# How people sign in

A deployment says who vouches for people with its `auth`, one of two:

- `signin({ providers })`: coffre's own sign-in page, with GitHub, Google,
  Microsoft, any OpenID Connect provider, or one of the deployment's own.
  `coffre init` sets up GitHub; [deploy.md](deploy.md) walks through it.
- `cloudflareAccess({ teamDomain, audience })`: Cloudflare Access in front of
  coffre, which verifies the assertion Access forwards.

Either way, coffre decides who is a member: signing in proves who someone
is, not that they may enter. With `signin`, the sessions, the CLI's device
logins and service tokens are coffre's too. Behind Access, Access keeps the
browser's session, `cloudflared` the CLI's, and CI uses Access service
tokens. Neither runs a password flow.

## Providers

```ts
auth: signin({
  providers: [
    github({ clientId, clientSecret: env.GITHUB_CLIENT_SECRET, organization: 'acme' }),
    google({ clientId, clientSecret: env.GOOGLE_CLIENT_SECRET, domain: 'acme.example' }),
    oidc({ id: 'okta', label: 'Okta', issuer: 'https://acme.okta.com', clientId, clientSecret }),
  ],
  title: 'Acme secrets',
}),
```

Each provider's callback is `<publicUrl>/auth/callback/<id>`. `github()`,
`google()` and `microsoft()` are presets of GitHub's OAuth and of OpenID
Connect; anything else that speaks OIDC (Okta, Auth0, Keycloak, Authentik,
Clerk, WorkOS…) needs only `oidc()` and its issuer.

### A provider of your own

A provider is a `SigninProvider`: a way to send the browser to whoever knows
the person, and to take back who they are. A deployment can write one for a
provider that speaks neither protocol, and list it beside the others:

```ts
import type { SigninProvider } from '@coffre/server/cloudflare';

const acme: SigninProvider = {
  id: 'acme',
  issuer: 'https://sso.acme.example',                  // stable: in the callback URL and every account bound through it
  label: 'Acme SSO',           // "Continue with Acme SSO"
  brand: 'oidc',               // the button's mark: github, google, microsoft, or oidc (a key)
  async start(redirectUri) {
    const state = randomToken();
    const url = new URL('https://sso.acme.example/authorize');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    return { url, pending: { state, codeVerifier: '', nonce: null } };
  },
  async finish(callbackUrl, redirectUri, pending) {
    if (callbackUrl.searchParams.get('state') !== pending.state) {
      throw new SigninError('state_mismatch', 'the callback is not for this sign-in');
    }
    const user = await exchange(callbackUrl.searchParams.get('code'), redirectUri);
    return { subject: user.id, emails: user.verifiedEmails, name: user.name };
  },
};

auth: signin({ providers: [github({ … }), acme] }),
```

coffre does everything around the two calls. It seals `pending` in a
short-lived encrypted cookie between them. It files the profile under the
provider's `id`, so one provider cannot pass its accounts off as another's.
It binds `subject` to a member, and issues the session. What the provider
owns is the protocol: `finish` must check `state` against `pending`, and
return only addresses the provider has verified. A provider's shape is
checked with the rest of the configuration, and its profile on every
sign-in: a malformed one refuses that sign-in with `invalid_response`.

## What the pages and the CLI read

Neither branches on how the deployment is configured. They ask
`GET /api/auth`, which anyone may call:

```sh
curl https://coffre.example.com/api/auth
# {"signin":{"title":"Acme secrets","note":null,
#            "providers":[{"id":"github","label":"GitHub","brand":"github"}]},
#  "access":null}
```

Behind Access it answers `{"signin":null,"access":{"assertion":true}}`:
`assertion` says whether this request carried one, so the page can tell
"open coffre through Access" from "Access vouched, and coffre could not
verify it". `coffre login` runs a device login when `signin` is set, and
hands over to `cloudflared` when `access` is, or when Access turns the
request away before it reaches coffre.

## Behind Cloudflare Access

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

### Closed-door behavior

The production hostname must be protected by an Access Allow policy. Coffre
still fails closed at the origin boundary: without the forwarded assertion,
every `/api` route but `GET /api/auth` answers `401 unauthenticated`, and
every page says to open coffre through Access.

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

Each value must be an email, and match what the first person signs in with:
a verified address of their GitHub or OIDC account, or the `email` claim
Cloudflare Access emits (who must then be allowed by the Access policy).
Service tokens cannot be root admins. Root admins are the
configuration-owned bootstrap principals that can create the first project and
grant; an empty or malformed list makes a new instance unadministrable, so the
vault refuses to start with one.

Every non-root identity must also be an active member, which the vault
decides. Signing in, with a provider or through Access, authenticates the
person; it does not register them in this Coffre instance. An authenticated
but unregistered browser is confined to `/unregistered`, while `/api`
returns `403 registration_required` for everything but `GET /api/me`.

Changes to `rootAdmins` are deployment configuration changes. Keep at
least one controlled bootstrap identity until the operational recovery path is
defined and tested.

## Local development

`pnpm dev` signs in as a deployment does, with `signin(…)`
(`dev/deployment/app/src/server.ts`): the dev IdP (`@coffre/conformance/idp`, which
`dev/idp` runs on :8081) stands in for GitHub and for an OpenID Connect
provider, and its authorize page asks which seeded person you are. Plain
HTTP is accepted for a provider on loopback only, so no deployment can end
up trusting it. The seed signs in the same way, as the root admin, and
conformance does too, with the dev IdP in its own process for the run.
It also plays a CI platform under `/workloads`, which a trust binding may
name in development: `curl -s -X POST http://127.0.0.1:8081/workloads/token
-d aud=http://127.0.0.1:3000` mints a run's ID token, for the CLI's
`COFFRE_ID_TOKEN`.
Nothing local stands in for Access: its verifier is covered by unit tests
against Access-shaped tokens.

### Email admission

Generic OIDC providers must send `email_verified: true` before an address can
match an invitation or bootstrap a root administrator. Google also requires a
Gmail address or a Workspace `hd` claim. A third-party Google account may still
carry an address whose ownership has changed.

Microsoft Entra's email and username claims do not prove address ownership.
Sign in through another provider and link the Microsoft account in Settings.
Later sign-ins use its stable subject, without relying on an email claim. An
Entra-only deployment needs another sign-in provider for initial admission.

### Changing an identity issuer

An account binding includes the configured provider ID, a fingerprint of its
issuer, and its subject. OIDC uses the issuer URL; GitHub uses the API base URL
that supplies the account ID. Custom providers must name their stable `issuer`.

Changing the issuer under an existing provider ID refuses the old bindings and
browser sessions. Before changing it, link another provider so that members can
sign in there and explicitly link their accounts at the new issuer. Matching an
email does not transfer an existing binding. Legacy bindings without an issuer
fingerprint are refused too; they cannot be upgraded by guessing their issuer.

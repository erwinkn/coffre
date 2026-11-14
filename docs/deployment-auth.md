# How people sign in

A deployment says who vouches for people with its `auth`, one of two:

- `signin({ providers })`: coffre's own sign-in page, with GitHub, Google,
  Microsoft, any OpenID Connect provider, or one of the deployment's own.
  `coffre init` sets up GitHub; [deploy.md](deploy.md) walks through it.
- `cloudflareAccess({ teamDomain, audience })`: Cloudflare Access in front of
  coffre, which verifies the assertion Access forwards, and signs a browser
  in on its first request.

Either way, coffre decides who is a member: signing in proves who someone
is, not that they may enter. With `signin`, the sessions, the CLI's device
logins and service accounts' bearer tokens are coffre's too. Behind Access,
a browser's session is coffre's too, made by its first request through
Access; the CLI and machines are not served there yet. Neither runs a
password flow.

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

`github()` takes an OAuth app's or a GitHub App's client, or
`github({ app })`, the deployment's GitHub App made with `githubApp(…)`:
the same value its `workloads.github` lists repositories with, passed to
each side ([github-app.md](github-app.md)). With `organization`, a GitHub
App needs the Members organization permission and an installation on the
organization, or nobody signs in.

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
verify it". `coffre login` runs a device login when `signin` is set. When
`access` is, or when Access turns the request away before it reaches
coffre, it signs in nowhere and says why ([The CLI and
machines](#the-cli-and-machines)).

## Behind Cloudflare Access

Configure one Cloudflare Access application for the production hostname, then
give the app's configuration (`app/src/coffre.ts`) that application instead
of `signin(…)`:

```ts
import { cloudflareAccess, createCoffre, postgres } from '@coffre/server/cloudflare';

export const coffre = createCoffre((env: Env) => ({
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
from `wrangler.jsonc` and the configuration's `Env`.

Cloudflare documents that the origin receives the application token in
`Cf-Access-Jwt-Assertion`, and recommends validating that header rather than
the browser cookie. Coffre verifies its signature, issuer, audience and
expiry on every request but health's, before any page or `/api` handler
runs.

A browser's first request signs its person in, as a provider's callback
does with `signin`: coffre binds their Access account (its subject) to the
member their email names, opens a session of its own, and sets its cookie
beside a second one, sealed, that ties the session to that Access subject.
Every later request shows both, and the assertion is still verified each
time, so Access's own revocation takes effect on the next request. When
someone else signs in to Access on the same browser, their first request
ends the session it finds and signs them in. The session lasts 12 hours at
most, or `cloudflareAccess({ …, browserSessionHours })`; Access's own
session is the one people notice. Signing out in coffre ends its session,
then Access's (`/cdn-cgi/access/logout`).

Official references:

- [Validate JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Create an Access application](https://developers.cloudflare.com/learning-paths/clientless-access/access-application/create-access-app/)
- [Connect through Access using a CLI](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/)

### The CLI and machines

Not served behind Access yet. A request from the CLI through `cloudflared`,
with an Access service token, with a bearer token of coffre's, or with a
workload's session (`Authorization: DPoP`) answers `401 unauthenticated`, saying that behind Access only browsers sign in. They
will sign in with coffre's own credentials, Access checking them at the
edge: `coffre login` through a device login approved in the browser, and
machines with a service token or a binding of coffre's beside an Access
service token. Until then, a deployment whose CLI or machines reach coffre
through Access stays on 0.14, and its machines keep 0.14's Access service
tokens; in 0.16.x they will need coffre's tokens instead, beside them.

The CLI says so, in each of the ways 0.14's signed in behind Access:

```
$ coffre login https://secrets.acme.example
coffre: https://secrets.acme.example is behind Cloudflare Access, where coffre 0.16.0 signs people in through the browser only; the CLI and machines come back in 0.16.x
$ coffre login https://secrets.acme.example --access-client-id 1b2c….access
coffre: Behind Cloudflare Access, coffre 0.16.0 signs people in through the browser only; the CLI and machines come back in 0.16.x
```

What it holds to there is three things:

1. A credential goes to the instance's own origin and nowhere else: the
   CLI follows no redirect, Access's to its login page included.
2. What it knows already, it refuses before it reads or sends anything:
   `--auth-mode cloudflare` and `--access-client-id`, the second line above,
   and a session 0.14's CLI saved behind Access, by `cloudflared` or an
   Access service token, the first, for any command. `coffre login` asks
   `GET /api/auth` first, with nothing of yours, so behind Access it reads no
   secret, starts no `cloudflared` and sends no session saved here.
3. What it learns from an answer, it says: Access's redirect to
   `<team>.cloudflareaccess.com`, or coffre's own 401 for a credential
   behind Access (`"reason": "browsers_only"`), ends any command with the
   first line above, at the first request it answers: `coffre verify
   instance`'s checks as no one included, so its session or token is not
   sent after them, and a run's plan, `GET /use/<project>/<env>`. Not what
   the credential proxy relays from another service, under
   `/use/<project>/<env>/<name>/…` or `/use/<name>/<path>/…`: that service's
   own Access login page is the app's answer.

So a credential can still reach the instance's hostname once. A session
`coffre login` saved before the instance went behind Access goes with the
next `coffre whoami`; Access answers it with its redirect, and the CLI prints
the first line. Cloudflare's edge serves that hostname with or without
Access, and opens every request to it, so the token reaches no one it did
not reach before.

### Closed-door behavior

The production hostname must be protected by an Access Allow policy. Coffre
still fails closed at the origin boundary: without the forwarded assertion,
whatever cookie comes with it, every `/api` route but `GET /api/auth`
answers `401 unauthenticated`, and every page says to open coffre through
Access. Someone Access lets in who is no member of coffre is told so on
every page, and binds nothing.

Do not treat this application check as a substitute for protecting the data
plane. The Worker receives PostgreSQL access only through its Hyperdrive
binding; the Scaleway database has no public endpoint.

## The Owners the deployment names

coffre's most powerful people are its **Owners of the whole instance**:
members like any other, with the Owner role and no scope, in People, and
changed by the same rules. The vault's configuration names some of them
(`vault/src/worker.ts`):

```ts
owners: ['first.owner@example.com'],
```

`coffre init` reads them from the vault's `OWNERS` var, comma-separated.
Each value must be an email, and match what that person signs in with: a
verified address of their GitHub or OIDC account, or the `email` claim
Cloudflare Access emits (who must then be allowed by the Access policy).
An empty or malformed list makes a new instance unadministrable, so the
vault refuses to start with one.

**Everyone on the list is an Owner.** Each time the vault starts (a deploy,
a new Worker isolate, a restart on Node), and when a listed person signs
in, it makes everyone the list names an Owner of the whole instance who
is not one yet: added, brought back, or given the role, by the vault
itself and logged as such (`system:vault`, "the deployment names them
one"). On a new instance, the first listed person to sign in becomes its
Owner, and the others follow at the vault's next call, whether they have
signed in or not.

While listed, nobody can demote, narrow or remove them, not another Owner
and not themselves: People greys their Owner tag for other Owners, with the hint "Set by
deployment" and a lock in place of their menu, and the API answers 403, "the deployment names omar@acme.example an Owner
(owners, in the vault's configuration): take them off that list and deploy
first".
Taking an email off the list demotes nobody: they stay an Owner, now one
like any other, whom another Owner may demote, and who may step down.

**Getting back in.** When no Owner can sign in any more (they left, or
lost their GitHub account), add an email you control to the list, deploy,
and sign in: you are an Owner. The same holds if someone with the database
demotes a listed Owner by writing their row: the row fails the vault's
check, and the vault starts it over and makes them an Owner again at their
next request, or at the next deploy. A row written around the vault never
puts anyone on the list, which lives in the deployment's code. So the list
is a standing way in: keep it to people you would trust as Owner, and take
people off it when they leave.

The instance keeps an Owner from then on. The last Owner of the whole
instance cannot be demoted, narrowed to a scope, or removed, by anyone,
themselves included: "you're the last Owner of the whole instance: make
someone else an Owner first". Only an Owner of the whole instance makes
someone an Owner, or changes or removes one; an Admin does neither.
Nobody changes their own role but an Owner of the whole instance, who may
step down, unless they are the last or listed.

Every other identity must also be an active member, which the vault
decides. Signing in, with a provider or through Access, authenticates the
person; it does not register them in this Coffre instance. An authenticated
but unregistered browser is confined to `/unregistered`, while `/api`
returns `403 registration_required` for everything but `GET /api/me`.

Before 0.6 the list was `rootAdmins` (`ROOT_ADMINS`), people who held
everything and were in no member row; during 0.6's development it was
`bootstrapOwners` (`BOOTSTRAP_OWNERS`). 0.6 reads both names until 0.7, and
makes the root admins they name Owners ("Upgrading from 0.5" in the
[release notes](../CHANGELOG.md)).

## Local development

`pnpm dev` signs in as a deployment does, with `signin(…)`
(`dev/deployment/app/src/server.ts`): the dev IdP (`@coffre/conformance/idp`, which
`dev/idp` runs on :8081) stands in for GitHub and for an OpenID Connect
provider, and its authorize page asks which seeded person you are. Plain
HTTP is accepted for a provider on loopback only, so no deployment can end
up trusting it. The seed signs in the same way, first, as the Owner, and
conformance does too, with the dev IdP in its own process for the run.
It also plays a CI platform under `/workloads`, which a trust binding may
name in development: `curl -s -X POST http://127.0.0.1:8081/workloads/token
-d aud=http://127.0.0.1:3000` mints a run's ID token, to pipe to the CLI's
`coffre login <url> --service <name> --id-token`.
Nothing local runs behind Access: its verifier is covered by unit tests
against Access-shaped tokens, and signing in behind it by the server's
`packages/server/test/behind-access.test.ts`, on the dev IdP's Access keys.

### Email admission

Generic OIDC providers must send `email_verified: true` before an address can
match an invitation or bootstrap an Owner. Google also requires a
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

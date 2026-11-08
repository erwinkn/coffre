# How people sign in

A deployment says who vouches for people with its `auth`, one of two:

- `signin({ providers })`: coffre's own sign-in page, with GitHub, Google,
  Microsoft, any OpenID Connect provider, or one of the deployment's own.
  `coffre init` sets up GitHub; [deploy.md](deploy.md) walks through it.
- `cloudflareAccess({ teamDomain, audience })`: Cloudflare Access in front of
  coffre, which verifies the assertion Access forwards.

Either way, coffre decides who is a member: signing in proves who someone
is, not that they may enter. With `signin`, the sessions, the CLI's device
logins and service accounts' bearer tokens are coffre's too. Behind Access, Access keeps the
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
verify it". `coffre login` runs a device login when `signin` is set, and
hands over to `cloudflared` when `access` is, or when Access turns the
request away before it reaches coffre.

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
`coffre --auth-mode cloudflare login https://…`.

CI and other machines sign in with an Access service token instead. Its ID
is a flag; its secret is asked for, or piped in, never a flag's value. The
session it makes is the instance's, for the commands after it, and `coffre
logout` forgets it there without revoking anything:

```sh
printf '%s' "$ACCESS_CLIENT_SECRET" | coffre login https://<coffre-api-hostname> --access-client-id <id>.access
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

## Passkeys

With `signin`, a passkey can follow the provider: GitHub says who someone
is, and a touch of a passkey on their laptop or phone says it is them at
this browser, now. A stolen GitHub session then gets an attacker as far as
"Confirm it's you", with nothing written, and a phishing site relaying the
sign-in gets no answer: a passkey made for `secrets.acme.example` answers
that origin alone. Passkeys are the second factor coffre supports, the only
one: no TOTP, no SMS. Cloudflare Access runs its own sign-in, so behind it
there are none.

```ts
auth: signin({
  providers: [github({ app })],
  passkeys: 'required', // 'off' | 'optional' (the default) | 'required'
}),
```

`coffre init` reads it from the app's `PASSKEYS` var, `optional` as
written (`app/wrangler.jsonc` on Workers, `.env` on Node), so that turning
it off to recover (below) is a var and a deploy.

| | `off` | `optional` (default) | `required` |
|---|---|---|---|
| Signing in, no passkey yet | the provider | the provider; an Owner adds one first | the provider, then adding one, before any session exists |
| Signing in, with a passkey | the provider | the provider, then a touch | the provider, then a touch |
| Changing access, issuing a service's credentials, the other acts below | as is | a touch in the last 5 minutes; no passkey yet: add one first | a touch in the last 5 minutes |
| Approving a terminal, connecting an MCP client, approving its change | as is | a touch for that act, if you hold a passkey | a touch for that act |
| Reading values | as is | as is | as is |
| `/use`, CI and workload sign-in, services | untouched | untouched | untouched |

Under `optional`, everyone with a passkey signs in with it, and so does
every Owner of the whole instance and every Owner the deployment names:
they add one at their next sign-in. A Developer who never adds one signs
in with GitHub alone, as before, and is asked for one the first time they
do something that needs a fresh check. People add more (ten at most) and
rename or remove theirs in **Account → Passkeys**.

**What needs a fresh check.** A touch at sign-in, or in the step-up dialog
an act opens when the session is not fresh, keeps that browser's session
fresh for five minutes. The acts that
need one widen someone's reach, mint a credential or cannot be undone:
adding, changing or removing a member, their grants or instance role, a
role, issuing a service's token, a trust binding or an enrollment code,
approving a workload's waiting session, the instance's settings,
unprotecting an environment, lifting a freeze, making a sensitive value a
secret, erasing a project or an environment, accepting lost audit entries,
linking another sign-in account, adding a passkey, resetting someone's.
Revoking sessions, tokens, bindings and connected apps, freezing and
protecting never need one: in an incident they must be quick.
The table is `FRESH_ROUTES` (`packages/server/src/api/fresh-routes.ts`); a
refused request answers `403 fresh_check_required`, and the pages ask for
the touch and send it again. The CLI asks the same of its terminal, through
a browser that approves it. Those two touches, at sign-in and the step-up,
also end the session they came in on and issue a new one, so a copy of the
old cookie stops working. Approving a terminal, an MCP client's change or
its connection takes a touch of its own, for that act alone: it approves
that act and nothing else, and neither refreshes the session nor replaces
it. A copy of that browser's cookie keeps working until it expires or is
revoked, and needs a fresh touch of its own for anything above.

**What a change to someone's passkeys ends.** Adding a first passkey ends
every session, terminal, personal token, handle and MCP client of theirs
that none confirmed. Removing one, or an Owner's reset, ends every one of
theirs but the browser that removed it. Services, their tokens and CI runs
never hold a passkey and are untouched.

**The relying party.** A passkey belongs to a host name. coffre makes them
for `publicUrl`'s host unless `passkeys: { policy, rpId }` names a parent
of it (`rpId: 'acme.example'` for `secrets.acme.example`): the origin must
still be `publicUrl`'s, so `evil.acme.example` gets no answer either way.
A `publicUrl` that is an IP address does not start with passkeys on:
browsers make none there, so use `http://localhost:<port>` locally. A passkey
is made for the `rpId` in force then and answers only for it, so changing
`rpId` is itself a move: from `secrets.acme.example` to `acme.example`,
every passkey made before is refused at once, on the same host. Moving
coffre to another host keeps the passkeys only if `rpId` was a parent of
both before the first one was made. So choose the parent before anyone
enrolls. Otherwise nobody is signed out by the change itself: sessions,
terminals and tokens already issued stand on their passkey's row, which
names no RP ID, and keep working. What fails is every touch of an old
passkey after it: a sign-in's, a step-up's, a terminal's or an MCP client's,
and a removal's. A session touched in the last five minutes still stands
on that touch, so for those minutes its person can add a passkey, made for
the new `rpId`, and an Owner can reset someone's. Once no session is that
fresh, the way back is the last Owner's, below, for everyone: `off` for
minutes, each person removes their old passkeys, then the policy back, and
each adds a new one at their next sign-in.

### Lost passkeys

- **One of several lost.** Sign in with another and remove the lost one in
  **Account → Passkeys**. Everything else you were signed in with ends.
- **All of them lost.** An Owner of the whole instance opens **Users →
  the person → ⋯ → Reset passkeys…**, touches their own passkey, and every
  passkey of that person's goes, with everything they were signed in with.
  Their next sign-in asks for a new passkey under `required`, takes GitHub
  alone under `optional` (an Owner's adds one again), and says who reset
  them, and when. Only an Owner of the whole instance resets anyone, and
  never their own: keep two.
- **The last Owner lost theirs.** Nobody can reset them. Set `PASSKEYS` to
  `off` (or `passkeys: 'off'`), deploy, sign in with GitHub alone, remove
  the lost passkeys, set the policy back and deploy again; the next
  sign-in adds a new one. There is no reset command and no exemption for
  one person: this is the way back, and while it is `off` a GitHub account
  is enough for everyone, so keep the window to minutes. `off` deletes no
  passkey, and turning it back restores everyone's. Sessions, terminals,
  personal tokens and MCP clients made meanwhile name no passkey, and are
  refused at their next request once it is back, for everyone who holds
  one. Handles are the exception: `/use` does not hold a handle to the
  policy at each request, so one made meanwhile keeps working once it is
  back, until it expires (twelve hours unless asked, a week at most). A
  reset of its person's passkeys, or their removal, ends it. What they
  did meanwhile stays done: read the log for the window (**Audit**, or
  `coffre audit`), and look for `member.*`, `access.*`, `role.*`, service
  tokens and trust bindings, handles (`token.create` of kind `handle`),
  and `passkey.*`.

### When someone else added their passkey

The one gap `optional` leaves is a person who has no passkey yet: until
they add one, they are as strong as their GitHub account. Someone holding
Bob's GitHub account can sign in and add a passkey of their own, which
ends Bob's sessions, terminals and tokens, and Bob's next sign-in asks for
a passkey Bob does not have. It is loud: Bob is locked out, and the log has
a `passkey.add` in Bob's name. When it happens, confirm with Bob some other
way than this account, have an Owner reset Bob's passkeys, read the log
from that `passkey.add` on for what was done in Bob's name, and rotate
what Bob's access could reach that was read meanwhile (the person's page
lists what was read, as for offboarding: [offboarding.md](offboarding.md)).
`required` closes the gap for everyone signed in since, Owners are closed
already, and the provider's own two-factor closes it the most.

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
Nothing local stands in for Access: its verifier is covered by unit tests
against Access-shaped tokens.

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

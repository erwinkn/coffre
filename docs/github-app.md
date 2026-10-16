# A GitHub App for picking repositories

A trust binding names a repository by its IDs, not its name
([design](design/oidc.md)): `acme/api` is `repository_id 41532`,
`repository_owner_id 9919`. coffre looks a public repository's IDs up
itself. A private one, GitHub shows only to those signed in to it, so
without more, an owner types its IDs.

With a GitHub App of the deployment's own, installed on your
organizations, "Trust a workload" lists the repositories it is installed
on, private ones too, and picking one fills in its IDs. A name typed by
hand, or given to `coffre trust`, resolves through the app as well. It is
optional: without it, nothing changes.

The app holds one permission, **Metadata: read-only**, which every GitHub
App has and none can drop. It reads the names and IDs of the repositories
it is installed on, nothing of their code, issues or settings, and no
person's account. No one's personal token is ever asked for or kept.

## 1. Register the app

On GitHub, **Settings › Developer settings › GitHub Apps › New GitHub
App**, under the organization that owns the repositories:

- **Name**: anything, `coffre (acme)` say. The pages show it.
- **Homepage URL**: your instance, `https://secrets.acme.example`.
- **Callback URL**: none, and leave "Request user authorization (OAuth)
  during installation" off.
- **Webhook**: untick **Active**. coffre asks GitHub when a page asks it,
  and needs no events.
- **Permissions**: none to add. Metadata, read-only, is already there.
- **Where can this GitHub App be installed?** **Only on this account**
  for one organization. Repositories in several organizations or personal
  accounts need **Any account**: it is still installed only where an
  owner of that account installs it, and reads only there.

Create it, note its **App ID** (a number, not the client ID), and under
**Private keys**, generate one: GitHub downloads its PEM file.

If people sign in to coffre with a GitHub App, the one `coffre setup`
makes, that app can serve as this one too: it has Metadata already, so
generate a private key on its settings page and install it as below.

## 2. Install it

On the app's page, **Install App**, then the organization, then **All
repositories** or **Only select repositories**. The pages list what you
choose here; change it there at any time, and the next listing follows.
Until it is installed somewhere, the pages say so and link to this step.

## 3. Pass it to coffre

The App ID is no secret; the private key is.

On Workers, in `app/wrangler.jsonc`, the ID beside the other `vars`:

```jsonc
"vars": {
  "GITHUB_APP_ID": "123456"
}
```

and the key as a secret of the app Worker:

```sh
pnpm exec wrangler secret put GITHUB_APP_PRIVATE_KEY -c app/wrangler.jsonc < coffre-acme.private-key.pem
```

On Node, both in `.env`, the key on one line, each of its newlines
written `\n`:

```sh
echo 'GITHUB_APP_ID=123456' >> .env
printf 'GITHUB_APP_PRIVATE_KEY=%s\n' "$(awk '{ printf "%s\\n", $0 }' coffre-acme.private-key.pem)" >> .env
```

A deployment `coffre init` writes reads both in `app/src/coffre.ts`, and
turns the app on when `GITHUB_APP_ID` is set. One from before 0.6 adds
the line to its `workloads`:

```ts
workloads: {
  limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL },
  githubApp: env.GITHUB_APP_ID ? { appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY ?? '' } : undefined,
},
```

It is for github.com: GitHub Enterprise Server's runs sign their tokens
under its own issuer, which the pages and `coffre trust` do not bind to
yet, so the app refuses another API. The configuration is checked when the app starts: an ID that is not a
number, or a key that is not a PEM, stops it with a message saying which,
never the key.

## Where the key lives, and what coffre keeps

The private key is the app Worker's secret (on Node, the server's), beside
the GitHub sign-in's client secret, not the vault's. It opens no secret:
whoever holds it reads repository names and IDs. The vault is kept apart
for the keys that open secrets, and taking this one in would give it a way
out to GitHub for nothing it protects.

coffre signs a JWT with the key for each request it makes as the app, and
GitHub trades it for an installation token, valid an hour. Both stay in
the Worker's or the process's memory: the token until five minutes
before it expires, the key for as long as it runs. Neither is written to
the database, the audit log or the process log, or sent in an answer, and
an error says what GitHub answered, never what was sent.

To rotate the key, generate a new one on the app's page, set it as above,
deploy, then delete the old one there.

## Who sees the list

Whoever may set up a service account sees the repositories the app is
installed on, private ones' names included: the same people who may look
up a repository's IDs. What a binding then trusts is checked as always.

One listing makes at most 40 requests to GitHub, for every installation
and every hundred repositories. Past that, the pages say the list is
partial; type the others by name.

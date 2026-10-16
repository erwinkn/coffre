# One GitHub App, for sign-in and repositories

A GitHub App of the deployment's own does two things for coffre, each
usable without the other:

- **Sign-in.** People sign in with GitHub through the app's OAuth client,
  and with `organization`, only that organization's members do.
- **Repositories.** Where an owner trusts a CI run, "Trust a workload"
  lists the repositories the app is installed on, private ones too, and
  picking one fills in its IDs. A binding names a repository by its IDs,
  not its name ([design](design/oidc.md)): `acme/api` is `repository_id
  41532`, `repository_owner_id 9919`. Without the app, coffre looks up a
  public repository's IDs itself, and a private one's are typed. A name
  typed by hand, or given to `coffre trust`, resolves through the app too.

In the common case one app does both. The deployment makes it once and
passes the same value to each side, which uses only what it needs:

```ts
const app = githubApp({ appId, privateKey, clientId, clientSecret });

auth: signin({
  providers: [github({ app, organization: 'acme' })],
  workloads: { limits, github: app },
}),
```

Sign-in takes its client ID and secret; the repository list, its ID and
private key. Neither picks up the other's credentials by itself: a side
left without the app goes without it. No one's personal token is ever
asked for or kept.

## 1. Register the app

On GitHub, **Settings › Developer settings › GitHub Apps › New GitHub
App**, under the organization:

- **Name**: anything, `coffre (acme)` say. The pages show it.
- **Homepage URL**: your instance, `https://secrets.acme.example`.
- **Callback URL**: `<PUBLIC_URL>/auth/callback/github`. Leave "Request
  user authorization (OAuth) during installation" off; "Expire user
  authorization tokens" may stay on, as coffre uses a person's token only
  while they sign in, and keeps none.
- **Webhook**: untick **Active**. coffre asks GitHub when a page asks it,
  and needs no events.
- **Permissions**, each read-only:
  - Repository › **Metadata**, which every GitHub App has: the
    repositories' names and IDs, nothing of their code or settings.
  - Account › **Email addresses**: the verified addresses sign-in matches
    to the people the instance admits.
  - Organization › **Members**, with `organization` only: whether the
    person signing in is a member.
- **Where can this GitHub App be installed?** **Only on this account**
  for one organization. Repositories in several organizations or personal
  accounts need **Any account**: it is still installed only where an
  owner of that account installs it, and reads only there.

Create it and note its **App ID** (a number) and **Client ID**. Generate
a **client secret**, and under **Private keys**, a private key: GitHub
downloads its PEM file.

`coffre setup` on Workers makes such an app from a manifest, for sign-in:
it has Metadata and Email addresses already. To list repositories with
it too, generate a private key on its settings page; with `organization`,
add Members.

## 2. Install it on the organization

On the app's page, **Install App**, then the organization, then **All
repositories** or **Only select repositories**. The membership check and
the repository list both reach only where it is installed: until then,
an `organization` check refuses everyone, and the pages say the app is
installed nowhere and link to this step. Change the repositories there at
any time, and the next listing follows. A permission added later waits
for the organization's owners to accept it on GitHub.

## 3. Pass it to coffre

The App ID and client ID are no secret; the client secret and the
private key are.

On Workers, the IDs in `app/wrangler.jsonc`, beside the other `vars`:

```jsonc
"vars": {
  "GITHUB_CLIENT_ID": "Iv23liAbCdEf123456",
  "GITHUB_APP_ID": "123456"
}
```

and the secrets of the app Worker:

```sh
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET -c app/wrangler.jsonc
pnpm exec wrangler secret put GITHUB_APP_PRIVATE_KEY -c app/wrangler.jsonc < coffre-acme.private-key.pem
```

On Node, all four in `.env`, the key on one line, each of its newlines
written `\n`:

```sh
echo 'GITHUB_APP_ID=123456' >> .env
printf 'GITHUB_APP_PRIVATE_KEY=%s\n' "$(awk '{ printf "%s\\n", $0 }' coffre-acme.private-key.pem)" >> .env
```

A deployment `coffre init` writes reads them in `app/src/coffre.ts`: it
signs in with the client alone, and makes the app, for both sides, once
`GITHUB_APP_ID` is set. One from before 0.6 changes its configuration to
the same:

```ts
const client = { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
const app = env.GITHUB_APP_ID ? githubApp({ ...client, appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY ?? '' }) : undefined;

auth: signin({
  providers: [app ? github({ app }) : github(client)],
  workloads: { limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL }, github: app },
}),
```

The configuration is checked when the app starts: an ID that is not a
number, a key that is not a PEM, or half a client stops it with a
message saying which, never the key or the secret.

## Each side alone

- **Sign-in without the repository list.** `github({ clientId,
  clientSecret })`, from the app's client or an OAuth app's, as before:
  no private key, and repositories are typed.
- **The repository list without GitHub sign-in**, say for people who
  sign in with Google: `githubApp({ appId, privateKey })`, with no client
  and Metadata alone, and `workloads: { limits, github: app }`.

## GitHub Enterprise Server

Sign-in works with an Enterprise Server's app: `githubApp({ …, webUrl:
'https://github.acme.example', apiUrl: 'https://github.acme.example/api/v3' })`,
or `github({ clientId, clientSecret, webUrl, apiUrl })`. The repository
list does not yet: an Enterprise Server's runs sign their tokens under its
own issuer, which the pages and `coffre trust` do not bind to, so
`workloads.github` refuses its API and the instance does not start. Leave
`GITHUB_APP_ID` unset there.

## Where the key lives, and what coffre keeps

The private key and the client secret are the app Worker's secrets (on
Node, the server's), not the vault's. Neither opens a secret: the key
reads repository names and IDs, the client signs people in, whom coffre
then checks as always. The vault is kept apart for the keys that open
secrets, and taking these in would give it a way out to GitHub for
nothing it protects.

coffre signs a JWT with the key for each request it makes as the app, and
GitHub trades it for an installation token, valid an hour. Both stay in
the Worker's or the process's memory: the token until five minutes
before it expires, the key for as long as it runs. Neither is written to
the database, the audit log or the process log, or sent in an answer, and
an error says what GitHub answered, never what was sent. A person's user
token serves their sign-in and is dropped.

To rotate the key or the secret, generate a new one on the app's page,
set it as above, deploy, then delete the old one there.

## Who sees the list

Whoever may set up a service account sees the repositories the app is
installed on, private ones' names included: the same people who may look
up a repository's IDs. What a binding then trusts is checked as always.

One listing makes at most 40 requests to GitHub, for every installation
and every hundred repositories. Past that, the pages say the list is
partial; type the others by name.

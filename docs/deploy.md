# Deploying coffre

A coffre is one Cloudflare Worker, one Postgres database, and one instance
file saying where it runs. This walks through a personal instance at
`coffre.erwinkn.com` that signs in with GitHub, which is
[`deploy/erwinkn.jsonc`](../deploy/erwinkn.jsonc). Equisafe's instance, behind
Cloudflare Access and deployed by CI, is
[`deploy/equisafe.jsonc`](../deploy/equisafe.jsonc); its pipeline is in
[deployment-workers.md](deployment-workers.md).

Allow about an hour. You need:

- a Cloudflare account holding the domain's zone;
- a Postgres 16 or later that Cloudflare can reach over TLS (Neon, Supabase,
  Railway, a VM of your own);
- a GitHub account, for the sign-in app;
- this repository checked out, with Node 24 and pnpm (see the README).

## What goes where

| | Where it lives | Example |
|---|---|---|
| What coffre is | `apps/web/wrangler.jsonc` | entry point, Hyperdrive binding, Cron schedule |
| Where this copy runs | the instance file | Worker name, domain, sign-in providers |
| Its secrets | your password manager, then Cloudflare | the key that encrypts every value |
| Its data | Postgres | ciphertext, the directory, the audit log |

The database never holds a usable value: every secret is encrypted under a
key (the KEK) that only the Worker has. Someone who copies the database learns
names and who read what, not values. Someone who can *write* to it can bind
their own GitHub account to you, though, so its passwords deserve the same
care as the keys.

## 1. The database

coffre connects with two logins:

- the **owner**, which runs migrations. It must own the database and be
  allowed to create roles, which the admin login your provider hands you
  (`neondb_owner` on Neon, `postgres` elsewhere) usually is. Only you use it,
  from your machine, and it never goes near Cloudflare;
- **`coffre_runtime`**, which the Worker uses. It can read and write rows but
  not change the schema, and it cannot edit or delete a single audit row. The
  migrations refuse to run if it has more power than that, such as
  `CREATEROLE` or owning a table.

Create the database and the runtime login as the owner:

```sql
CREATE DATABASE coffre;
CREATE ROLE coffre_runtime LOGIN PASSWORD '<a long random password>';
```

Then apply the migrations as the owner, and check the runtime login from its
own side:

```sh
DATABASE_URL='postgres://<owner>:<password>@<host>:5432/coffre?sslmode=require' \
  pnpm db:migrate

DATABASE_URL='postgres://coffre_runtime:<password>@<host>:5432/coffre?sslmode=require' \
COFFRE_RUNTIME_ROLE=coffre_runtime \
  node packages/db/src/verify-runtime.ts
```

Do the same, in that order, whenever a release adds a migration, before
deploying it. Until you do, `/readyz` reports the database as not ready.

## 2. Hyperdrive

Hyperdrive is how the Worker reaches Postgres. Point it at the **runtime**
login, and turn its query cache off:

```sh
npx wrangler login
npx wrangler hyperdrive create coffre --caching-disabled \
  --connection-string='postgres://coffre_runtime:<password>@<host>:5432/coffre'
```

The cache matters. By default Hyperdrive answers a repeated `SELECT` from a
copy up to a minute old, so someone you remove, or a session you revoke,
would keep working for that minute. coffre's load is a few queries a minute;
it has nothing to gain from a cache.

Keep the ID it prints: that is `CLOUDFLARE_HYPERDRIVE_ID`.

## 3. Keys

Two keys, each 32 random bytes:

```sh
openssl rand -base64 32   # COFFRE_KEK_LOCAL: encrypts every value
openssl rand -base64 32   # COFFRE_AUDIT_CHAIN_KEY: seals the audit log
```

and a name for the first, `COFFRE_KEK_ID`, such as `erwinkn-2026-09`. The
name is stored beside everything the key encrypts, so a later key can take
over for new values while this one still opens old ones.

**Keep both keys somewhere that survives losing Cloudflare,** such as your
password manager, before deploying. Cloudflare will not show a secret back
once set. Lose the KEK and every value in coffre is lost with it; lose the
chain key and the audit log can no longer be verified.

## 4. GitHub sign-in

Create an OAuth app at **GitHub → Settings → Developer settings → OAuth Apps
→ New OAuth App**:

- Homepage URL: `https://coffre.erwinkn.com`
- Authorization callback URL: `https://coffre.erwinkn.com/auth/callback/github`

Copy its **Client ID** into the instance file (next step). Generate a
**client secret** and keep it with the keys: it is
`COFFRE_SIGNIN_GITHUB_CLIENT_SECRET`.

coffre asks GitHub for your profile and your verified email addresses. The
first time a GitHub account with an address from `COFFRE_ROOT_ADMINS` signs
in, coffre binds you to that account's numeric id. From then on it signs in
as you whatever emails it lists, and another account showing the same address
is turned away.

To let only members of an organisation sign in, add
`COFFRE_SIGNIN_GITHUB_ORGANIZATION` to the vars. Other providers need no
code, only variables (see [Sign-in providers](#sign-in-providers) below).

## 5. The instance file

[`deploy/erwinkn.jsonc`](../deploy/erwinkn.jsonc) is ready bar two values:
your email in `COFFRE_ROOT_ADMINS`, and the OAuth app's client ID. The build
refuses an empty value, so a forgotten blank stops it before anything
deploys.

```jsonc
{
  "name": "coffre",                        // the Worker's name in Cloudflare
  "routes": [{ "pattern": "coffre.erwinkn.com", "custom_domain": true }],
  "vars": {                                // plain text, visible in the dashboard
    "COFFRE_AUTH_MODE": "signin",
    "COFFRE_PUBLIC_URL": "https://coffre.erwinkn.com",
    "COFFRE_ROOT_ADMINS": "you@example.com",
    "COFFRE_SIGNIN_PROVIDERS": "github",
    "COFFRE_SIGNIN_GITHUB_CLIENT_ID": "Ov23li…"
  },
  "secrets": {                             // names only; values come at deploy time
    "required": [
      "COFFRE_SIGNIN_GITHUB_CLIENT_SECRET",
      "COFFRE_KEK_LOCAL",
      "COFFRE_KEK_ID",
      "COFFRE_AUDIT_CHAIN_KEY"
    ]
  }
}
```

The file uses Wrangler's own keys, and may set only `name`, `routes`,
`workers_dev`, `vars` and `secrets`. Each replaces coffre's default
outright, so what you read is the whole list. `vars` and `secrets` come as a
pair, because the sign-in method decides which secrets exist. The build
refuses a key or a client secret written as a var, where it would sit in
plain text in the file and the dashboard.

The file can live anywhere, such as your infrastructure repository. A
relative `COFFRE_INSTANCE` path is resolved from this checkout's root.

## 6. Deploy

Create a Cloudflare API token from the **Edit Cloudflare Workers** template,
limited to your account and the `erwinkn.com` zone. Then, with everything in
the environment:

```sh
export CLOUDFLARE_ACCOUNT_ID=…  CLOUDFLARE_API_TOKEN=…  CLOUDFLARE_HYPERDRIVE_ID=…
export COFFRE_SIGNIN_GITHUB_CLIENT_SECRET=…
export COFFRE_KEK_LOCAL=…  COFFRE_KEK_ID=erwinkn-2026-09  COFFRE_AUDIT_CHAIN_KEY=…

COFFRE_INSTANCE=deploy/erwinkn.jsonc pnpm --dir apps/web deploy
```

A password manager's CLI saves the exports and keeps the values off disk and
out of your shell history. With 1Password, for instance, keep the lines
above as `op://` references in a file and run
`COFFRE_INSTANCE=deploy/erwinkn.jsonc op run --env-file=erwinkn.env -- pnpm --dir apps/web deploy`.

The deploy builds the Worker with the instance applied, prints where it is
going (`Deploying coffre to coffre.erwinkn.com, in signin mode`), and hands
every secret the instance names to Wrangler in one step, so a Worker never
runs with half of them. It refuses to start if any is missing. Add
`COFFRE_DEPLOY_DRY_RUN=true` to see the bindings without deploying.

## 7. First sign-in

1. Open `https://coffre.erwinkn.com` and continue with GitHub. You are a root
   admin, allowed everything everywhere, including reading any value. Each
   read is still written to the audit log in your name.
2. Within five minutes, `https://coffre.erwinkn.com/readyz` should answer
   200. A Cron job writes a heartbeat through the audit log every five
   minutes, and readiness fails once the last one is more than 11 minutes
   old. A lasting 503 means the audit log or the database is broken; point
   an uptime monitor at it.
3. Sign the CLI in. It shows a code to approve in the browser:

   ```sh
   coffre() { node ~/code/coffre/apps/cli/src/main.ts "$@"; }   # until it is published
   coffre login https://coffre.erwinkn.com
   coffre whoami
   ```

## 8. Moving secrets in

1. On the web, create a project for each app and an environment for each
   place it runs (`myapp`, with `dev` and `prod`).
2. Import each `.env` file. `import` shows what it would change first:

   ```sh
   coffre import myapp/prod --file ~/code/myapp/.env.production
   coffre import myapp/prod --file ~/code/myapp/.env.production --apply
   ```

3. Stop reading the file. Either run the app through coffre, which fetches
   the values into its environment and nothing else:

   ```sh
   coffre run myapp/dev -- pnpm dev
   ```

   or have coffre push them to where the app runs, and keep them current
   there: GitHub Actions, Vercel, Railway or Cloudflare Workers
   ([syncs.md](syncs.md)).

4. Delete the plaintext files.

## Later

- **Updating** is the same deploy command. Run the migrations first when a
  release adds one.
- **Rotating the KEK**: generate a new key and name, deploy with them as
  `COFFRE_KEK_LOCAL` and `COFFRE_KEK_ID`, and with the old pair as
  `COFFRE_KEK_LOCAL_PREVIOUS=<old id>:<old key>`, so old values still open.
  Every deploy sets it, so a deploy without it clears the old key from the
  Worker.
- **Someone leaves**: [offboarding.md](offboarding.md).

## Sign-in providers

`COFFRE_SIGNIN_PROVIDERS` lists the buttons on the sign-in page, by id. Each
id then takes `COFFRE_SIGNIN_<ID>_*` variables. The ids `github`, `google`,
`microsoft` and `oidc` are also their type; any other id needs `_TYPE`.

| Variable | For | |
|---|---|---|
| `_CLIENT_ID` | all | a var |
| `_CLIENT_SECRET` | all | a secret |
| `_LABEL` | all | the button reads "Continue with {label}" |
| `_TYPE` | other ids | `github`, `google`, `microsoft` or `oidc` |
| `_ORGANIZATION` | GitHub | only this organisation's members |
| `_WEB_URL`, `_API_URL` | GitHub | a GitHub Enterprise Server host |
| `_DOMAIN` | Google | only this Workspace domain's accounts |
| `_TENANT` | Microsoft | the directory (tenant) ID, a GUID |
| `_ISSUER` | OIDC | the issuer URL; everything else comes from its discovery document |
| `_SCOPES` | OIDC | default `openid email profile` |

Each provider's callback URL is `<COFFRE_PUBLIC_URL>/auth/callback/<id>`.
Okta, Auth0, Keycloak, Authentik, Zitadel, Clerk and WorkOS are all `oidc`.
For SAML or LDAP, put a broker such as Dex in front and point coffre at it.

The page itself takes `COFFRE_SIGNIN_TITLE` and `COFFRE_SIGNIN_NOTE` (a line
under the title, such as "Use your equisafe.io Google account"). Sessions last
`COFFRE_SESSION_HOURS` (12 by default) in the browser and
`COFFRE_CLI_SESSION_DAYS` (30) for the CLI.

Google for Equisafe, as an example:

```jsonc
"COFFRE_SIGNIN_PROVIDERS": "google",
"COFFRE_SIGNIN_GOOGLE_CLIENT_ID": "….apps.googleusercontent.com",
"COFFRE_SIGNIN_GOOGLE_DOMAIN": "equisafe.io",
// and COFFRE_SIGNIN_GOOGLE_CLIENT_SECRET in secrets.required
```

To stay behind Cloudflare Access instead, leave `vars` and `secrets` out of
the instance: coffre's defaults are Access mode and its secrets, described in
[deployment-auth.md](deployment-auth.md).

## Trying it locally

`pnpm dev:signin` runs the sign-in page on your machine, with the local dev
IdP standing in for GitHub and for an OIDC provider. It uses the data the
last `pnpm dev` seeded.

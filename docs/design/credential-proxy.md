# Placeholders, and the credential proxy

A design for 0.8, written on 2026-10-18 (W125), from Erwin's R11 and R13.
PR 1 is built: placeholders for people, handles, the proxy's HTTP shapes
(a header, a query parameter, Basic) and `coffre run`'s side of it. PR 2
adds SigV4, for S3. PR 3 adds the Postgres tunnel, on Node (section 9).
0.9 (W127) adds the stable URL, `/use/<credential>`, and removes
`baseUrl` (section 4). The decisions in section 8
were taken on the recommended option while Erwin was away (R10), and each
is his to revisit. 0.9 closes the gaps that kept keys on `expose`
(section 2, "What replaces `expose`"). 0.10 (W128) replaces the
deployment-wide `people` switch and `expose` with one setting per key, its
sensitivity (section 2). 0.11 (W146) runs the tunnel on Workers, in a
Durable Object, and through a VPC Network binding to a private database
(section 5).

## 1. What it is for

An agent on a developer's machine runs the backend and its tests. The
backend needs Schumann's API key, an S3 key pair and a database password.
Until now `coffre run market/dev -- pnpm dev` put those values in its
environment, and the agent could print them, paste them into a prompt or
commit them. With placeholders it holds none of them:

```sh
$ coffre run market/dev -- pnpm dev
coffre: placeholders for market/dev: schumann, s3 through https://secrets.acme.example/use; the handle lasts 12 hours (`coffre tokens` lists it)
coffre: values as they are, which you may read: STRIPE_WEBHOOK_SECRET
coffre: left out, neither proxied nor yours to read: SIGNING_KEY
```

The app's environment, as the backend sees it:

```sh
SCHUMANN_API_KEY=coffre_use_Qm9Y…            # the handle, where the key was
STRIPE_WEBHOOK_SECRET=whsec_local_…          # a secret its person reads: given as it is
COFFRE_CREDENTIALS={"schumann":"https://secrets.acme.example/use/market/dev/schumann"}
COFFRE_HANDLE=coffre_use_Qm9Y…
```

and the base URL is the app's own configuration, which already maps each
of its environments to Schumann's: its local one points at the proxy's
stable URL for the credential, the same for every coffre environment.

```ts
const schumannUrl = { local: 'https://secrets.acme.example/use/schumann', production: 'https://api.schumann.example/v1' }[APP_ENV];
```

Schumann's client is unchanged. It still appends `/companies` to its base
URL and sends the key as `x-api-key`. The request reaches coffre, which
finds the handle where the key goes, opens `SCHUMANN_API_KEY` of the
environment the handle was made for, `market/dev`, for the person it
stands in for, puts the real key in `x-api-key` and sends the request to
`https://api.schumann.example/v1/companies`. The real key never reaches
the machine.

## 2. The model

**Sensitivity (0.10).** Each key says who sees its value, one setting
with three levels, loosest first:

| Level | Who sees the value | The page's hint |
|---|---|---|
| `plain` | Anyone who can list the environment | Visible to anyone who can see this environment |
| `secret`, the default | People whose role can read secrets | Visible to people whose role can read secrets |
| `sensitive` | No person, Owners included. Their apps get a placeholder and use it through the proxy; service accounts read it. An Owner of the project may make it a secret, its value kept (loosening, below) | Never shown to anyone, Owners included. Used through the proxy or by services |

```sh
$ coffre set market/prod/STRIPE_SECRET_KEY --sensitive   # a new value, shown to nobody from here on
$ coffre mark market/prod/DATABASE_URL sensitive         # the value as it is, made stricter
$ coffre mark market/prod sensitive                      # every value of market/prod's own that is looser now
$ coffre mark market/prod/DATABASE_URL secret            # an Owner of market: sensitive made a secret, its value kept
$ coffre list market/prod
DATABASE_URL	v4	admin@acme.example	today  sensitive
STRIPE_SECRET_KEY	v2	admin@acme.example	today  sensitive
TWILIO_SID	v1	admin@acme.example	today  plain: AC0123456789
```

A reference reads its source's level, and a fork's inherited key its
parent's, so `mark` of an environment leaves them as they are, naming
each one looser than asked and where to mark it: `coffre: left as they
are: API_KEY, a reference to market/shared/API_KEY: mark it there`. The
listing says each key's level, those included.

**Two delivery modes (R13), by key.** Who asks, and the key's level,
decide what a read hands back:

| Who | A `secret` key | A `sensitive` key |
|---|---|---|
| A person, on any credential of theirs: a browser session, a `coffre login`, a personal token, an MCP connection, a handle | The value, where their role reads it | **A placeholder.** The value is opened only for coffre to use for them: the vault refuses a read that would hand it back (`sensitive`), and allows the proxy's `use` and a fork's `copy` |
| A service account: a service token, a CI run's or a cluster's ID token | The value | The value: CI and production read their environment once, at full speed |

The rule is in the vault, the one place every read goes through, not in
the CLI or the API's routes. `coffre get`, the UI's reveal, `POST
/api/reveals`, the Vault KV plugin and MCP's `reveal_secret_values` and
`show_secret_value` all reach the vault's `unwrap`, so all are refused the
same way, and each refusal is in the vault's log. So is an import's dry
run (`compare`): its `changed` or `unchanged` tells whoever sent a guess
whether it was right, so a sensitive value is compared with no person's
guess (`changed`). A fork's `copy` hands nothing back, and stays. Every
purpose but `use` and `copy` counts as handing back, one a later app
might name included.

- **Bound by the vault.** A sensitive version says so in its row
  (`secret_versions.sensitive`, migration `0012_sensitive_values`), and the
  vault's wrap of its data key binds it, as it binds a personal config's
  owner: AAD `|sensitive`, or `coffre:sensitive` in KMS's encryption
  context. A row flipped back to secret around coffre opens for nobody
  (`bad_claim`), rather than for people. The value's own ciphertext binds
  the secret's ids alone, so a key made sensitive keeps it. A fork's
  `copy` opens one only for an app that says it keeps it sensitive
  (`keepsSensitive`), which an app of 0.9, mid-deploy, never says; and
  `wrap` answers what it bound, so this app stores no sensitive version a
  vault of 0.9 wrapped as a secret.
- **A person's read of a whole environment** (`coffre run` and `export`
  without the proxy, the page's Reveal all, `POST /api/reveals` of
  `market/prod`) leaves its sensitive values out and names them
  (`sensitive`), rather than refuse the run: `coffre: left out, sensitive,
  which nobody is handed: STRIPE_SECRET_KEY`. A read of one sensitive key
  is refused whole, 403 `sensitive`. `coffre version` answers, for a
  person, the version of what their read would open.
- **Stricter at any time, looser only by a new value, or by an Owner.**
  Making a key stricter keeps its value: `{ "sensitivity": "sensitive" }`,
  with no value, in `PATCH /secrets/…`, is a new version of the same
  ciphertext, its data key wrapped again as the new level (the vault's
  `rewrap`), which takes write and opens nothing. Making one looser takes
  the value written again (`coffre set … --secret`), so nobody ever shows
  a value they could not read by flipping it (decision 17's rule, for
  every level). The vault holds rewraps to it: a new version is never
  less sensitive than the one it is made from, nor than its secret's
  newest (`invalid`). A rollback brings the old value back as it was
  held, plain or secret, and sensitive while the key is.
- **Loosening, in place (R30).** One flip is allowed: an Owner of the
  project, or of the whole instance, as a person on no credential's
  scope, makes a sensitive value a secret, `{ "sensitivity": "secret" }`
  with no value (`coffre mark market/prod/DATABASE_URL secret`, or the
  row's Who sees it › Secret, behind a confirmation). They could read it
  anyway (break-glass, below), so retyping protected nothing from them.
  It is a new version of the same ciphertext, its key opened as sensitive
  and wrapped again without the binding, by the vault, which refuses it
  to anyone else (`not_allowed`): the value never reaches the app, nor
  its caller, by it. Only the key's current version: its older ones stay
  sensitive, and a rollback to one brings it back sensitive, as any
  rollback brings a value back as it was held. Its own entry,
  `secret.loosen` (`from: 'sensitive'`, `to: 'secret'`, and the version
  whose value it `kept`; a refusal, `not_owner`, is one too), beside the
  vault's `key.rewrap` (`was: 'sensitive'`), so no reader of the log takes it for a value written or
  seen. A reference reads its source loosened, live (R23), and a fork's
  inherited key its parent's: each is loosened where it is held.
  Secret to plain stays a reveal, then a write (decision 17).
- **A write that says nothing keeps the key as strict.** It is a secret,
  or sensitive where the key is sensitive now: rotating a sensitive key
  with `coffre set` leaves it sensitive. Plain is still said by each write
  (decision 18). A fork's override of a sensitive key it inherits is
  sensitive unless it says otherwise.
- **Logged.** A write's `secret.write` says `sensitive: true` (or `plain:
  true`), and `was`, the level before, when it changed one; a mark also
  says the version whose value it `kept`. A loosening is `secret.loosen`.
- **Personal tokens count as people**, as does a handle. A personal
  config's own values are plain, secret or sensitive, as anywhere, and
  read by their owner alone, a sensitive one used (R8, R20, decision 27).
- **A fork's copy keeps each value's level**, as it keeps plain.

0.8 and 0.9 had one switch for the whole deployment, `people:
'stand-ins'`, which refused every value to every person, and `expose`,
configuration that let some through again by environment. 0.10 removes
both: a deployment that still sets either fails at startup, saying what
to do (decision 20).

**A handle** (`coffre_use_…`, 32 random bytes) is what a person's app
holds in place of a value. It is a credential row of its own kind
(migration `0009_handles`, which only widens a check):

- It acts as its person, within its scope, as a personal token does:
  `viewer` on each environment it was made for, and on each parent a fork
  of them inherits from that the person reads too, so inherited keys work
  through it; `contributor` where they only use (0.10, decision 26). `market/dev@me` is scoped as `market/dev`, which is what a
  personal config's owner needs to read it. Their losing a grant narrows
  it, and their removal ends it.
- It reaches nothing but the proxy. The API, the pages and a plugin's
  `api(token)` all refuse it (`authenticateRequest`, reason `handle`), so
  it reads no listing and makes nothing: no token, no binding, no other
  handle.
- It lasts 12 hours unless told, a week at most, and never past the
  personal token that made it. It is revoked as a token is (`coffre
  tokens revoke`), and both its making and its revocation are logged.
- `coffre run` makes one per run, with the person's session or personal
  token (`POST /api/handles`), labelled `coffre run market/dev on
  <hostname>`.
- It keeps the environments it was made for, by id and whether as `@me`
  (`market/dev@me`), under its row's MAC (migration `0010_handle_places`,
  a nullable column). They are what the stable URL resolves to (section
  4), by the names they have now: a project or an environment renamed
  while the handle lasts is still its environment. Its scope cannot say:
  `market/dev@me` is scoped as `market/dev`, and a fork's scope holds its
  parents too.

**A credential** is a named bundle of an environment's keys, plus the
rule by which they authenticate, declared in the deployment's
configuration:

```ts
credentialProxy({
  credentials: {
    schumann: { upstream: 'https://api.schumann.example/v1', inject: header('x-api-key', '{SCHUMANN_API_KEY}') },
    openai: { upstream: 'https://api.openai.com/v1', inject: header('authorization', 'Bearer {OPENAI_API_KEY}') },
    maps: { upstream: 'https://maps.googleapis.com/maps/api', inject: query('key', '{MAPS_API_KEY}'), methods: ['GET'] },
    // The account's id is in Twilio's paths, /Accounts/{sid}/Messages.json: TWILIO_SID is plain, and the app holds it as it is.
    twilio: { upstream: 'https://api.twilio.com/2010-04-01', inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), paths: ['/Accounts'] },
  },
})
```

- The keys are those the rule names, `{KEY}`, and come from the
  request's environment: the one the handle was made for, or the one its
  URL names. One credential then serves `market/dev` and `market/staging`
  alike, each with its own values.
- `upstream` is where its requests go: `/use/<name>/<path>`, and
  `/use/<project>/<env>/<name>/<path>`, go to `<upstream>/<path>` and
  nowhere else.
- A handle grants the use of every credential its environment holds, and
  each only to its own upstream.
- A key the rule reads that is no secret, an account's id in its URLs, is
  marked plain (below), and the app holds it as it is; the handle stands in
  for the rest. `identifiers: ['TWILIO_SID']`, which said the same in
  configuration, was deprecated in 0.9 and is refused at startup in 0.10.
- A credential's keys are placeholders in a person's app whatever their
  level: its configuration points at the proxy for them. A secret one its
  person may still read with `coffre get`.

**Plain values (0.9).** A key can be marked not secret: an account's id, a
region, a public address. It is a property of what is written, as a
recipe is:

```sh
$ coffre set market/dev/TWILIO_SID AC0123456789 --plain   # a plain value may be an argument
$ coffre list market/dev
TWILIO_SID	v1	admin@acme.example	today  plain: AC0123456789
TWILIO_TOKEN	v1	admin@acme.example	today
```

- **Who sees it.** Whoever lists the environment sees the value, in the
  listing (`value`), the page (inline, with a Plain tag) and MCP's list.
  Inherited by a fork, it shows to a reader of the parent that holds it,
  as an inherited value always reads. A reference to it reads as a
  secret, through the vault.
- **Reading it is no secret read.** A plain version keeps its value in
  the clear beside its ciphertext (`secret_versions.plaintext`, migration
  `0011_plain_values`), and a read serves that, with no vault call
  (`openValues`). So any person who lists the environment gets it (`coffre get`, a
  reveal, `coffre run` and `export` through the plan), it is in no
  `secret.read` entry, and it counts towards no bulk limit. The proxy
  leaves it unredacted in an upstream's answer: Twilio quotes the account
  back in every one, and a rule made of plain values alone is not redacted
  either. The ciphertext stays for what opens values through
  the vault: a reference, KEK rotation.
- **A write says it, every time.** `{ "value": "…", "plain": true }` in
  `PATCH /secrets/…`; any other write is a secret, so writing over a plain
  value without `--plain` makes the key secret again, and that needs only
  write. A personal config is the exception (decision 27): there, a write
  that says nothing keeps the level of the value it replaces. Its version and its `secret.write` entry say `plain`. A rollback
  to a plain version is plain again: that value was shown already. A
  fork's copy keeps it plain.
- **Making a stored secret plain discloses it**, so it is a reveal and a
  write: the client reads the value (an audited `secret.read`), then writes
  it plain with the version it `replaces`, refused if someone wrote since.
  A person may only publish a value they can read, and never a
  sensitive one, which nobody reads: they type it again, plain (decision
  17). A service account may.
- **In a personal config, its owner's alone.** A plain value of
  `dev@me` lists, inline, to its owner, and to nobody else, by any path:
  the app's `can()` decides every read of a personal config on its owner,
  as it does for its secrets, which the vault also binds to them (R8). A
  plain value has no such binding anywhere, being in the clear: whoever
  reads the database reads it. A plain value of the environment it
  overrides reaches its owner as any reader of that environment.

**Values of a person's own (0.9).** A backend that refuses to boot without
its own keys (a key that seals its local data, its webhooks' HMAC secret,
the key that encrypts its local database) needs *a* value, not the one
in `backend/local`. Where that one is sensitive, nobody reads it, so each person
gets one of their own, made once, kept in their personal config:

```ts
credentialProxy({ credentials: { … }, generate: { 'backend/local': 'all' } })   // or a list of keys
```

```sh
$ coffre set backend/local/ROOT_ENCRYPTION_KEY --generate bytes:32:hex   # the recipe, once, by an Owner
$ coffre run backend/local -- pnpm dev                                    # Ada, the first time
coffre: made your own ROOT_ENCRYPTION_KEY, POLICY_SEAL_KEY in backend/local@me, each by its recipe: your next runs use them
```

- **What it reads.** For an environment under `generate`, a person's use
  of it, the plan and every request through the proxy alike, reads their
  personal config of it (`backend/local@me`), or the environment while
  they have none. So each person's app holds their own values, and a
  personal override of a credential's key is the one sent.
- **What gets one.** A key the app would go without (none of the
  credentials', and no value it is given: a sensitive one), whose current value a recipe made
  (`coffre set … --generate`, one value: a key pair's half has none
  here), in the environment's list, and not a value of the person's own
  they made sensitive, which stays theirs. The plan names each,
  `generate: { ROOT_ENCRYPTION_KEY: { recipe, replaces, sensitivity: 'secret' } }`, with the
  version it read. `coffre run` and `coffre export` make each value by its
  recipe, as `coffre regenerate` does, and write them to the personal
  config with the person's session, an ordinary audited write, then ask for the
  plan again, which now gives them as that config's own. Each is written
  the secret the plan says, which the app is given: saying nothing, it
  would be as sensitive as the key it overrides (decision 27). A CLI
  before 0.10 says nothing, and its person's app goes without the value.
- **Once, and once only at a time.** The write replaces the version the
  plan read, or is refused (409). Of two runs at once, one writes, and
  the other, refused, reads the plan again and finds the winner's. The
  next run finds the person's own values and makes nothing. Stable across
  runs, so a key that encrypts the local database keeps opening it.
- **Who.** People only: the plan is for people, and a service account
  reads the environment's values as before. The deployment opts each
  environment in, a local one (decision 19), so production never grows
  personal values by itself.

**What replaced `expose`, by what the value is.** Equisafe's
`backend/local` listed 17 keys under `expose` in 0.8. 0.9 replaced each
kind, and 0.10 the last row, as a secret its people read:

| The value is | 0.9 | Equisafe's keys |
|---|---|---|
| No secret | A plain value | `DFNS_CREDENTIAL_ID`, `STARKNET_TESTNET_ACCOUNT_ADDRESS` |
| The app's own key: sealing, encryption, HMAC, webhook secrets | A value generated for each person in `<env>@me` | `POLICY_SEAL_KEY`, `IFRAME_TOKEN_SECRET`, `DELEGATED_SESSION_SECRET`, `PLAYWRIGHT_SERVICE_SECRET`, `ROOT_ENCRYPTION_KEY`, `FIAT_CHALLENGE_SECRET`, `*_WEBHOOK_SECRET` |
| A key whose host is in the app's code | A credential, the app pointing at its proxy URL | `LEMONWAY_API_KEY`, `YOUSIGN_API_KEY`, and `backend/tests`' `TEST_LEMONWAY_SANDBOX_API_KEY` |
| A token the SDK decodes (a JWT) | A shaped placeholder | `DFNS_AUTH_TOKEN` |
| A key the app signs with | `credential(name).sign()` | `DFNS_PRIVATE_KEY` |
| A key no proxy can use yet (a STARK-curve key) | A secret its people read (0.10), `expose` in 0.9 | `STARKNET_TESTNET_PRIVATE_KEY` |

**What a person's app holds as it is (0.10).** The plan gives the app
every value its person may read, as `coffre get` would: plain ones, and
secrets their role reads where the value is held. A sensitive one it never
gives: the app uses it through the proxy, as a credential's, a signer's or
a tunnel's, or does without it, or, under `generate`, gets one of the
person's own. A value the app must hold as it is, a webhook's HMAC secret
the backend verifies a signature with, a testnet signing key, is a secret
its people read; the agent can read it too, so better a local-only value
than a real one:

| `coffre run …` | `STRIPE_WEBHOOK_SECRET` secret | sensitive |
|---|---|---|
| `market/dev` | Real value | Left out |
| `market/dev-eu`, a fork of dev that inherits the key | Real value, to a reader of dev | Left out |
| `market/dev@me`, with a personal config | Real value: its owner reads dev. Its *own* values, which only its owner writes, are its owner's app's, so `DATABASE_URL=postgres://localhost/ada` there reaches Ada's app | Left out, or a value of Ada's own under `generate` |

**The recommended layout is a local environment of fakes.** A backend that
verifies Stripe's webhooks locally needs *a* webhook secret, not Stripe's.
Make `market/local` (or `backend/local`), fill it with local-only values
(`coffre set market/local/STRIPE_WEBHOOK_SECRET --generate`, a fresh local
encryption key, a testnet key with no funds), and leave them secret, which
its people read. Mark real keys sensitive in the environments that hold
them, `market/dev` and `market/prod`, and their apps use those through the
proxy.

**Break-glass.** A person who must see a value (an Owner pasting a key
into a provider's dashboard) has no path to it as themselves while it is
sensitive. An Owner of its project may make it a secret (loosening,
above), which shows it to everyone who reads secrets there; to read it
and leave it sensitive, the escape
is the one coffre already has: a service account. An Owner gives one read
on the place, issues it a token, and reads with it (`coffre --url …
--service …`, or `coffre login --token`). Each step is logged: the
account's admission, its grant, the token's creation and every read. A
personal token or a handle cannot take that path. The route that issues
service tokens and bindings refuses both, and a test holds this. An
instance that wants even that narrower sets its service setting
(`settings.serviceAccounts`), so that only those who run it set accounts
up. A page that reveals behind a fresh sign-in, for Owners, is possible
later (decision 3).

## 3. What a deployment writes

```ts
// app/src/coffre.ts
import { basic, credentialProxy, header, query } from '@coffre/server/plugins/credential-proxy';
plugins: [credentialProxy({ credentials: { … } })],
```

```ts
// app/src/routes/use.$.ts
import { createFileRoute } from '@tanstack/react-router';
import { plugin } from '@coffre/server/routes';

export const Route = createFileRoute('/use/$')({ ...plugin });
```

The vault needs nothing more: which values no person reads is each key's
own setting (section 2), `coffre mark market/prod sensitive` for a whole
environment's own values. A person's `coffre run` gets the plan wherever the instance
has the proxy: placeholders for the credentials' keys, whatever their
level, and the values they may read as they are.

## 4. The proxy, request by request

`GET /use` says the instance has a proxy, and names its credentials.
`coffre run` asks it first. It holds no secret.

`GET /use/<project>/<env>`, with the handle as a bearer token, is the
**plan**: one read of what the environment holds, which opens only the
values the app is given as they are, chosen from the very rows it opens
(`PickKeys`, each row saying whether it is plain or sensitive, and
whether the person reads where it is held), so an override reset between
two reads cannot swap a parent's value in. It answers:

```json
{
  "environment": "market/dev",
  "env": { "SCHUMANN_API_KEY": "coffre_use_…", "STRIPE_WEBHOOK_SECRET": "whsec_…" },
  "credentials": { "schumann": "https://…/use/market/dev/schumann" },
  "left": ["SENTRY_DSN"]
}
```

A credential appears when its environment holds every key of its rule.
Each of those keys becomes the handle, but a plain one, which the app holds
as it is, so a rule that frames its keys (`Bearer {K}`, Basic's
`user:password`) finds the handle wherever it ends up. A plain key stays
the handle where giving it would leave the handle nowhere the proxy looks:
S3's access key id, which the SDK sends as `Credential=` while the secret
only signs, or a header's only key. Twilio's `TWILIO_SID` is given, its
token still carrying the handle in Basic's password. A tunnel's URL,
which the proxy fills itself, is never given as the environment holds it,
plain or not. `left` lists what the app does without, and `coffre run` prints it.
`credentials` is what `COFFRE_CREDENTIALS` holds for `credential(name)`:
each credential's URL for the environment, which a run of several
environments tells apart, and from which `presign()` finds the
environment's.

`ANY /use/<credential>/<path>` is the **stable URL**, the same for every
environment, which the app's own configuration names. Its environment is
the one the handle was made for: a fork, or
`market/dev@me` and with it the person's own values over dev's. Nothing
of the app's (no `APP_ENV`, no environment's name) reaches coffre:

```sh
$ coffre run market/dev -- pnpm dev        # GET https://…/use/schumann/companies → market/dev's key
$ coffre run market/dev@me -- pnpm dev     # the same URL → the personal config's key, or dev's while it has none
$ coffre run market/dev-eu -- pnpm dev     # → dev-eu's, or the key it inherits from dev
```

- **A handle made for several environments** (`coffre run market/dev
  auth/dev`) gets a 409 on the stable URL, naming each environment's
  (`…/use/market/dev/schumann or …/use/auth/dev/schumann`), which still
  work. The rule depends on the handle alone, never on what the
  environments hold now, so a key set in one of them later cannot move a
  running app's requests to the other, and nothing is opened to find out.
  One of them deleted still counts, and a handle whose one environment
  was deleted gets a 409 too.
- **No handle**, where the credential takes its key or as
  `x-coffre-handle`, is a 401, and nothing goes upstream: there is no
  default environment.
- **A handle of 0.8**, which kept no environments, gets a 409 that says to
  run `coffre run` again. Its environments' URLs work as before, unless
  the project is named like a credential: the rule below needs them.
- **Which route.** `/use/<a>/<b>/…` names an environment exactly when
  `<a>/<b>` is one the handle was made for, and is otherwise the stable
  URL of credential `<a>`. The URL and the handle decide, and a request
  never goes through an environment its handle was not made for by
  accident. Project slugs and credential names overlap
  (`^[a-z0-9][a-z0-9-]{0,62}…$` and `^[a-z][a-z0-9-]{0,31}$`), so a
  project named `schumann`, beside the credential, is the case this rule
  is for. With a handle made for `schumann/dev`:

  | Request | Is |
  |---|---|
  | `GET /use/schumann/dev` (a bearer) | `schumann/dev`'s plan |
  | `ANY /use/schumann/dev/schumann/companies` | `schumann/dev`'s, through credential schumann |
  | `ANY /use/schumann/companies` | the stable URL: credential schumann, `/companies` |
  | `ANY /use/schumann/dev/companies` with a handle for `market/dev` | the stable URL: credential schumann, `/dev/companies` |
  | `ANY /use/schumann/dev/companies` with the handle for `schumann/dev` | `schumann/dev`'s, through a credential `companies`: Schumann's own `/dev/…` is `/use/schumann/dev/schumann/dev/…` for this run |

  Where `<a>` names no credential, the URL is an environment's, as in 0.8,
  and costs nothing more. Where it does, the request carries a handle (in
  the slot of credential `<a>` or of `<c>`, or as a bearer, for a plan),
  whose environments' paths are asked of coffre (the handle's check, and
  one read of their names) and kept for `cacheSeconds`, as values are. Its
  values are opened and kept as an environment URL's are, in the same
  cache, so both URLs of one environment share one opening a minute.

  The other rule is a reserved segment, one no project slug can be:
  `/use/-/schumann/…`, as GitLab's `/-/` keeps its own routes apart from
  its users' names. It decides from the URL alone, with no lookup, and
  has no case like the last row above. It was not taken because the
  stable URL is what people write in their configuration, and
  `https://secrets.acme.example/use/schumann` is the one they would
  expect. The last row, the one case it reads differently, needs a
  project named like a credential, a run of it, and an upstream path
  that begins with the name of the environment it runs.
- **Tunnels and `presign` stay an environment's** (`/use/<project>/<env>/<tunnel>`,
  `POST /use/<project>/<env>`). `coffre run` sets a tunnel's URL itself,
  and `presign()` reads the environment's from `COFFRE_CREDENTIALS`: no
  app configuration names either, so a stable form would serve no one.

**`baseUrl` is gone (0.9).** In 0.8 a credential named the key the app
read its upstream's address from, and `coffre run` set it to the
environment's proxy URL (`SCHUMANN_BASE_URL=…/use/market/dev/schumann`).
That URL changed with each environment, fork and `@me`, so the app could
not name it, and coffre wrote into the app's configuration. With the
stable URL the app names it, once. A configuration that still has
`baseUrl` fails, at typecheck (its type is the message) and at startup
(`credentialProxy: schumann's baseUrl is gone in 0.9, … point the app's
own config at … <publicUrl>/use/schumann …`), rather than be ignored. A
key of that name the environment still holds is listed in `left`.

`ANY /use/<project>/<env>/<credential>/<path>`, or the stable URL, is a
request sent on:

1. **Where.** The target is `<upstream>/<path>?<query>`, checked to
   stay under `upstream`'s origin and path. A dot segment is resolved
   before coffre sees it, so it climbs out of the credential altogether,
   and an encoded slash or backslash is refused. A credential's `methods`
   and `paths` narrow it further.
2. **Who.** The handle, from `x-coffre-handle` if present, else from
   where the rule puts the key: the header, the query parameter, or
   Basic's user or password. A shaped placeholder's slot must be that shape
   exactly (section 5). No handle gets a 401.
3. **What.** The credential's keys, from the cache for the handle,
   environment and credential, or opened now: `use(handle, …)`, the API's
   read in process, purpose `use`. That is one vault entry naming the keys,
   and one `credential.use` entry naming the credential and the upstream's
   host, and `egress: true` where it leaves through one (section 5). A key
   the environment lacks is a 409.
4. **Sent on.** Every header but those about the hop, coffre's caller,
   its cookies and the handle; then the rule's header, parameter or
   Basic authorization, filled in. The body is read up to 16 MiB and no
   further, whatever it declares. If the handle is still anywhere in the
   request (a header, inside another header's Basic base64, the URL, the
   body), it is refused rather than leaked to a third party. The request
   goes out with `redirect: 'manual'`, through the global `fetch` or the
   credential's `egress` (section 5).
5. **Back.** The upstream's answer, without `set-cookie` (it would land on
   coffre's origin), and always `cache-control: no-store`, its own cache
   headers dropped: a cache on the way would serve the next caller, with
   another handle or none, without coffre's checks. Every answer is
   sandboxed (`content-security-policy: sandbox; default-src 'none'`,
   which coffre's security headers keep): an upstream's HTML on coffre's
   origin runs no script and holds no cookie of coffre's, so a file an
   agent uploads cannot act as an Owner who opens its link. A redirect
   stays on the proxy. A `Location` under the upstream becomes the proxy's
   own URL for it, the environment's even from the stable URL, with the
   app's placeholder back in a query rule's parameter (what it sent there, if
   that stands in for its handle). On the stable URL, a path that begins
   with an environment of the handle's would read as that environment's
   (`/use/schumann/dev/maps/…`, another credential). A
   redirect anywhere else is a 502, naming no destination, so the app
   never follows it with the handle.
6. **Redacted.** Every string the request carried, each value and
   Basic's assembled base64, as stored and as sent (`Headers` trims a
   value's surrounding whitespace), 8 characters or longer, is replaced by
   `[redacted by coffre]` wherever an honest upstream may quote it back:
   in headers, the reason phrase, and a text body (JSON, XML, text, event
   streams), streamed. The forms are a closed list: as it is; URL-encoded
   both ways; HTML's and XML's entities; and as a JSON string as
   JavaScript, Go (`\u003c`), PHP (`\/`) and Python (`\u00e9`) write one.
   Each form is matched as the bytes it travels as, UTF-8 or Latin-1, on
   the body's bytes, so a body in any charset passes byte for byte.
   Matches are leftmost, then longest, and a part is let through only once
   no longer value could still match across the next chunk, so the output
   is what redacting the whole body at once would give. A binary body
   passes as it is. This guards against an echo, an error message quoting
   the request, not against a hostile upstream, which holds the key anyway
   and could encode it in any way at all. Nor does it cover an encoding
   off the list (base64 of a single value, UTF-16 bodies): the guarantee
   coffre makes is that it never hands a value to the app, and redaction
   is a second line against the upstream doing it.

coffre's own refusals carry `coffre-proxy: refused`, so the app can tell
them from the upstream's.

**The capability it needs.** The plugin mechanism gives plugins the API
as a caller, and a read there hands values back, which is exactly what a
person may no longer get. So plugins gain one capability, `use(handle,
{ path, keys, purpose, logged })`. It authenticates a handle and nothing
else, runs the API's read in process (`reveal` with its `use` option: the
same resolution, checks and vault call, for those keys only) and returns
the values to the plugin, never over HTTP. It exists only in process, so
no caller reaches it. The honest limit of section 2 of
[plugins.md](plugins.md) applies: a plugin is deployment code, and one that
returned what it opened would undo placeholders. The proxy is first-party and
small enough to read.

## 5. The other shapes

**S3 and SigV4 (PR 2, built).** The credential:

```ts
s3: {
  upstream: 'https://s3.eu-west-3.amazonaws.com',
  inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }),
},
```

and the app's client, as an app configures one for MinIO:

```ts
new S3Client({
  endpoint: 'https://secrets.acme.example/use/s3', // the app's own config for local; the stable URL
  forcePathStyle: true,                           // the bucket in the path: the proxy has one host
  requestChecksumCalculation: 'WHEN_REQUIRED',    // no aws-chunked uploads (below)
  responseChecksumValidation: 'WHEN_REQUIRED',
});
```

The SDK signs with the handle as both its access key ID and its secret.
coffre finds the handle in the Authorization header's `Credential=`,
discards the signature and the headers it signed, and signs again with the
real keys for the upstream's host and path (`packages/server/src/plugins/sigv4.ts`,
WebCrypto only, so the same on Workers). It signs as the AWS SDK does,
which a test holds it to: a path encoded once for S3 and twice for any
other service (`execute-api` and the like), header values with ASCII
whitespace folded and any other kept. A value no header can carry (a
session token with a line break) is refused, and quoted nowhere. The payload hash is the client's
own `x-amz-content-sha256`, a literal SHA-256 or `UNSIGNED-PAYLOAD`, which
the upstream checks against the body. Refused before anything is sent:

- `STREAMING-*` (aws-chunked) uploads, whose chunk signatures chain from
  a seed signature only the real key makes. The SDK sends them for
  flexible checksums unless told `WHEN_REQUIRED`.
- Presigned URLs the app signs itself (`X-Amz-Signature` in the query),
  since the app signs with the handle. coffre presigns instead (below).

**Uploads stream.** A request the SDK signs with its payload's hash (a
literal SHA-256 or `UNSIGNED-PAYLOAD`) and its `Content-Length` streams
through, never held whole, up to S3's own 5 GiB for one request. Its
signature needs no byte of it. It is checked as it passes: a handle
anywhere in it, a chunk boundary included, or a length other than the one
it declared, and it stops, so the upstream stores nothing. What a handle
could still begin, and its last bytes, are held back until that is known. Other bodies are
read whole, up to 16 MiB. Equisafe's PutObject past 16 MiB failed on that
limit (a 413), not on Workers' own request limit, which Cloudflare sets
by plan (100 MB on Free and Pro, 200 MB on Business, 500 MB on
Enterprise): past that, a Workers deployment needs multipart uploads,
each part a request of its own. On Workers, a streamed body
keeps its length through `FixedLengthStream`. The SDK's `Expect:
100-continue` stays at the proxy.

**Presigned GETs.** An app that hands out download links asks coffre for
one, with its handle: `credential('s3').presign('/uploads/kyc/a%20b.pdf',
{ expiresIn: 300 })` (`@coffre/client/credential`), which is `POST
/use/<project>/<env>` with `{ presign: { credential, path, method,
query, expiresIn } }`. coffre signs a GET (or HEAD) of that path under the
credential's upstream with the real key pair, for at most an hour and never
past the handle, and answers `{ url, expiresAt }`. The URL is the
upstream's own (MinIO's, S3's), for a browser to use until it expires. It
holds the access key's id and a signature, never the secret or the handle:
a path or query that carries the handle is refused. S3's URLs leave the
payload unsigned, as its own presigner does; any other service's sign the
empty body a GET has.
Each URL is one use in the log, naming the path and its lifetime, never
served from the cache. Uploads are not presigned: they go through the proxy.
The SDK's own `getSignedUrl` signs with the handle, so it needs replacing
by the helper where the app presigns.

Tested two ways. In the suite (`packages/server/test/credential-proxy-s3.test.ts`),
the AWS SDK v3 puts, gets and lists through the proxy against a fake S3,
which checks each request's signature with the SDK's own signer
(`@smithy/signature-v4`) under the real secret, as S3 does. It also puts
20 MiB in one PutObject, and checks presigned URLs against the SDK's own
presigner, byte for byte. By hand, against MinIO in Docker, the same put,
get and list passed, a 40 MiB PutObject streamed through, and a presigned
GET fetched straight from MinIO. A client holding the handle as its keys was
refused by MinIO directly, and a GET's median was 1.3 ms direct against
2.6 ms through the proxy, over loopback HTTP to coffre.

**Postgres through a tunnel (PR 3, built on Node).** The deployment
names the key that holds the database's real URL:

```ts
credentialProxy({ credentials: { … }, tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) } })
```

and, on Node, hands its HTTP server's upgrades to coffre:
`server.on('upgrade', (request, socket, head) => coffre.upgrade(request, socket, head))`.

The plan names the tunnel, `tunnels: { db: { key: 'DATABASE_URL', url:
'wss://…/use/market/dev/db' } }`, and gives the app no `DATABASE_URL` of
its own. `coffre run` starts a listener on 127.0.0.1 for it, for as long as
its command runs, and sets
`DATABASE_URL=postgres://app:<handle>@127.0.0.1:<port>/app?sslmode=disable`.
The listener (`packages/cli/src/tunnels.ts`) holds nothing and reads
nothing. It carries each connection over a WebSocket to coffre, with the
handle as its bearer token, and pipes bytes, each side reading only as fast
as the other takes. `coffre export` leaves the key
out: a tunnel lives only as long as a run.

On coffre's side (`packages/server/src/plugins/postgres-tunnel.ts`, web
streams and WebCrypto only), each connection does this:

1. Checks the handle, then opens the URL, as a credential's values are
   opened (one `credential.use` entry, `tunnel: true`, cached for a
   minute).
2. Checks the URL's host against `hosts` (and refuses a private address,
   or `sslmode=disable`, without `insecureUpstreams`).
3. Speaks Postgres's startup to the app as a server. It answers
   `SSLRequest` and `GSSENCRequest` with `N`, since the hop to the
   listener is local, and asks for a cleartext password. That password
   must be the handle: any process on the machine reaches the listener,
   and only one that holds the handle gets in.
4. Opens TCP to the database, TLS unless `sslmode=disable`, and logs in
   itself with the real password: SCRAM-SHA-256, or cleartext if the
   server asks. MD5 is refused, since WebCrypto has no MD5.
5. Relays what the database says until it is ready, with its
   `BackendKeyData` swapped for a cancel key of coffre's own (below), then
   pipes bytes both ways. Queries, the extended protocol, COPY both ways
   and LISTEN/NOTIFY work unchanged.

The startup is held to limits: 30 seconds from the first byte to the
database's `AuthenticationOk`, messages bounded by step (a password is a
handle, not 2 GiB), the handle checked again just before the login, and
the session ended at once when the app goes away. SCRAM-SHA-256 checks
the server's nonce and requires its final signature: a server that says
`AuthenticationOk` without proving it knows the password is refused. The
password goes through SASLprep, as Postgres's own does, and falls back to
the password as it is when that fails. Two approximations stay, both at
the edges of Unicode: "unassigned" is the runtime's Unicode, not 3.2, and
a right-to-left letter is a letter of the Hebrew, Arabic, Syriac, Thaana
or N'Ko scripts, not RFC 3454's D.1 table. A password that falls between
the two fails to log in, with the database's own error, and never reaches
anyone. *Decision:* port Postgres's tables only if someone hits it. The
database's host is read as Node dials it (`127.1`, `2130706433` and
`0x7f000001` are all `127.0.0.1`) before any check, and a dial still
under way when the session ends is given up. A server that sends anything past
its one-byte answer to `SSLRequest`, before TLS begins, is refused.

The app's own startup parameters go through (`application_name`, …), but
the user and database are the real URL's. Measured locally: a query adds
0.14 ms (0.08 ms direct, 0.22 ms tunnelled), and opening a connection takes
54 ms against 6 ms direct: the handle's check, the read, the WebSocket and
SCRAM. A pool pays that once per connection.

**Revocation mid-session.** The open sessions of one handle, environment
and tunnel are one group, with one timer: every `recheckSeconds` (60 unless
set) it opens the database's URL again, as the vault decides it, for all of
them at once, logged as a use. Ten pooled connections cost one read a
minute, not ten. A check the vault has not answered within ten seconds
(or the interval, if shorter) is a no, so a stalled vault ends the
sessions rather than freeing them. The handle's end ends them too, on a
timer of its own. A new group whose first session came in on a cached URL
checks at once, so the interval always starts from the vault's own
answer. The group lives as long as its sessions. So a revoked handle
and a person's lost grant each end the sessions, within the minute: the
first check that fails ends every session of that handle and tunnel at
once, both sockets of each close, and the app's driver sees its
connections drop. Every new
connection checks the handle afresh, at admission and again just before the
login, whatever the cache holds. *Decision:* end open sessions rather than
let them run out.

**Cancel requests.** A `CancelRequest` comes on a connection of its own,
before any password, with the key the app was given in `BackendKeyData`.
That key is coffre's, random, and maps to one live session of this
process: its database and the database's real key. A cancel request is
forwarded, over TLS as the session is, only when its key names a live
session of the same handle. A guessed key, or another handle's, reaches
nothing, and the database's own keys never leave coffre. psql's Ctrl-C
works, and tests hold both. On Workers, the map is the object's (below): a cancel request comes with
the same handle, for the same tunnel, so it reaches the object that holds
the session. It must name a session of the same tunnel too, here and on
Node, so it goes out the way that session's connection did, through the
tunnel's network binding or not.

**Not yet:**
- *A check on a deployed Worker* (section 7): whether an open socket
  counts toward the six connections (a pool of six through two rechecks),
  an idle object kept alive, a deploy's disconnect.
- *The privileged-role warning* (section 6): reading `rolsuper` and
  `rolcreaterole` after login, before the app's first query.
- *Minted short-lived logins* (W108), which replace the shared password.

**Workers: one Durable Object per run and database (0.11).** A Worker's
invocation is no place for a connection that lasts an hour, and a cancel
request comes on a connection of its own, which could land in any
isolate. So the Worker only routes: `coffre.upgrade(request, env)` sends a
WebSocket a plugin takes to a Durable Object named by a digest of its path
and its bearer token, `sha256('["","use","market","dev","db"]\ncoffre_use_…')`,
the path's segments decoded. That
is one `coffre run`'s connections to one database: the same group a Node
process checks as one. There the plugin admits it exactly as on Node
(`socket-admission.ts`: the migration door, then the proxy's own checks
and its `credential.use` entry), and the session runs the same `tunnel()`,
with TCP out through `cloudflare:sockets` (`cloudflare-sockets.ts`). The
object holds nothing an instance decides: access, the vault and the log
are reached through the plugin's context, by a coffre of the object's own
whose database client opens with a query and closes ten seconds after its last
(`closeIdleMs`). The object is given its admission as a function
(`socketsObject(env => admit)`), so that a session held by the Worker
itself, with only the cancel map in an object, would change the routing
and leave the tunnel as it is.

A walk-through. `coffre run market/dev -- psql "$DATABASE_URL"`: psql
connects to the run's listener, which opens `wss://…/use/market/dev/db`
with the handle; the Worker sends it to object `9f3c…`, which checks the
handle, opens the URL (one `secret.read` and one `credential.use`), logs in
with SCRAM, and swaps the database's `BackendKeyData` (pid 4242, its
secret) for a random key of its own. Ctrl-C: psql opens a second
connection with a `CancelRequest` for that key; the listener carries it
with the same handle, to the same path, so to the same object `9f3c…`,
whose map has the key, and which sends the database its real one. No key
names an object and none needs to: the bearer already does. The handle is
revoked: the group's check, a timer in the object, gets a refusal within
`recheckSeconds` and ends both sockets of every session; the next
connection is refused at admission.

*Flow control.* A Workers WebSocket has no back-pressure either way: no
`bufferedAmount`, and no way to stop reading. Unpaced, a `SELECT *` of a
large table read by a slow psql would wait in the object's 128 MB, and a
large `COPY … FROM STDIN` the same way the other direction. So the tunnel
paces itself by credit, in-band. Each side counts back what it has taken:
a text message holding the bytes of binary messages it took since its
last count, sent once 128 KiB have piled up. Each side sends at most a
window, 1 MiB, that the other has not counted. In the object, a write to
the app waits while a window is uncounted, so the session stops reading
the database socket, and TCP holds the database back. A message from the
app is counted when the session takes it, so the database socket's own
pace reaches the app. `coffre run`'s listener does the same on its side
(`packages/cli/src/tunnels.ts`). The listener asks for it in a header,
`coffre-tunnel-flow: credit`, and the object says it paces with a first
count, `0`, before any byte: in-band, so no proxy that drops a header
leaves the two waiting on each other. The listener counts back whatever
coffre it reaches, and holds the app to the window until coffre's first
message says: a count, and it paces; a byte, a database's answer from a
coffre on Node, which reads its WebSocket only as fast as it writes and
ignores the counts, and it does not. A count that is none, or for more
than was sent, ends the connection, on either side. The object holds a
client to its window: one that sends two windows uncounted is ended
(close code 1008), so a client that ignores the window, the app itself
speaking WebSocket with its handle, cannot fill the object. A WebSocket without
the header, an older CLI's, or without a bearer, is refused by the
Worker, with 426 or 401, before any object is made. An object holds 32
sessions at most, so a pool gone wrong cannot fill it: the 33rd is
refused with 503. A connection takes its slot before admission, and one
refused keeps it until its admission is done, past a refusal for taking
too long, a minute at most: neither a burst nor a slow database gets past
the 32, and a database that never answers holds no slot for good. The
listener says each refusal once a run, on stderr, with coffre's reason. The object's name digests the bearer token alone and
the path's segments decoded, as admission reads them, so no spelling of
either splits a run's connections. This is how any
plugin's WebSocket carries its bytes on Workers, not the tunnel's own:
a session is given a byte pipe (`Pipe`), and this is the pipe. So a
plugin's WebSocket on Workers has coffre's CLI as its client: a browser
can neither ask for credit nor count, and is refused. Measured with `vite
dev` and the real CLI, 200 MB through the object at about 48 MB/s: with
the app stalled 10 s mid-result, workerd's memory rose 2 MB (41 MB with the
window off), and the test holds the object to a window: an app that
counts nothing receives about 1 MiB, then nothing until it counts
(`credential-proxy-tunnel-workers.test.ts`).

*Keepalive.* Cloudflare closes a WebSocket idle for 100 seconds, and its
edge answers a protocol ping itself, without reaching the object. So the
listener sends a count every 30 seconds on each open connection, `0` when
it owes none: a message that reaches the object, so an idle psql at its
prompt keeps its WebSocket, and its object stays in memory with it. It
sends a ping too, whose pong, the edge's, must come before the next: a
connection whose network went away without a word ends within a minute,
and the app's driver sees it drop, rather than a query that hangs.

*A private database, through a VPC Network binding.* `connect()` reaches
public addresses only. A database inside a private network, a read
replica on Scaleway's say, is reached through a Cloudflare Tunnel whose
connector runs in that network, and a VPC Network binding to it, whose
`connect('10.0.1.5:5432')` opens TCP to the address given. The tunnel
names it:

```ts
// app/src/coffre.ts
tunnels: { replica: postgres('REPLICA_URL', { hosts: ['10.0.1.5'], connect: env.REPLICA_NET }) },
// app/wrangler.jsonc
"vpc_networks": [{ "binding": "REPLICA_NET", "tunnel_id": "<the tunnel's id>" }]
```

With `connect`, and only then, `hosts` may name a private address, and
must name the hosts the URL may: a binding reaches a whole network. The
URL says `sslmode=disable`: such a binding carries plaintext TCP only, so
the leg from the connector to the database runs unencrypted inside that
network, and Cloudflare's own carries it encrypted up to the connector. A
URL that asks for TLS is refused with 409, rather than tried. A binding
the Worker lacks is `undefined`: the configuration fails, and never dials
without it, as a credential's `egress` does. Without `connect`, nothing
changes: public addresses only, TLS unless `insecureUpstreams`. A cancel
request goes through the binding too.

The deployment opts in, in code. `coffre init` writes the object's wiring
(examples/workers does), idle until a plugin takes WebSockets:

```ts
// app/src/coffre.ts: sockets: env.SOCKETS, and, to open the tunnel,
//   plugins: [credentialProxy({ … tunnels: { db: postgres('DATABASE_URL') } })], with its route, routes/use.$.ts
// app/src/server.ts
export default { fetch: (request, env, ctx) => coffre.upgrade(request, env) ?? handler.fetch(request, { context: coffre.request(env, ctx) }) };
export const CoffreSockets = coffre.Sockets;
// app/wrangler.jsonc
"durable_objects": { "bindings": [{ "name": "SOCKETS", "class_name": "CoffreSockets" }] },
"migrations": [{ "tag": "sockets", "new_sqlite_classes": ["CoffreSockets"] }]
```

Without `sockets`, a WebSocket under `/use` gets 501; Node is unchanged.

**Shaped placeholders.** Some clients check their key before they send it.
DFNS's SDK decodes its token's middle part on every request, to read the
organization from the `https://custom/app_metadata` claim, so an opaque
handle throws before anything is sent. A credential whose header or query
rule carries one key may say what shape its placeholder takes:

```ts
dfns: {
  upstream: 'https://api.dfns.io',
  inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'),
  placeholder: jwt({ claims: ['https://custom/app_metadata'] }),
},
stripe: { upstream: 'https://api.stripe.com', inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}'), placeholder: prefix('sk_test_') },
```

and the app's SDK, its base URL the stable URL in its own config:
`new DfnsApiClient({ baseUrl: 'https://secrets.acme.example/use/dfns', authToken: process.env.DFNS_AUTH_TOKEN, … })`.

- `jwt({ claims })` gives the app `header.payload.<handle>`. The header is
  `{"alg":"none","typ":"JWT"}`. The payload holds the named claims,
  copied from the real token, and `exp`, the handle's end. The plan opens
  the real token for them, as a use of the credential, logged (`placeholder:
  { claims }`), and copies nothing else: DFNS's `sub` and `iss` stay in
  coffre. A key that holds no JWT fails the plan with a 409 that names it.
- `prefix('sk_test_')` gives `sk_test_coffre_use_…`.

The proxy reads the slot as the rule's template with the placeholder in its
place, exactly: `Bearer <anything>.<anything>.<handle>` for DFNS. It reads
the handle from the last part, ignores the rest, and the rule's header or
parameter replaces the whole with the real value. The bare handle, or the
placeholder framed otherwise, is a 401; `x-coffre-handle` still works. An
opaque placeholder is found wherever the rule frames it, as before. The leak
check and redaction are unchanged: the handle anywhere else is refused,
and the real token quoted back is redacted. A shaped placeholder is refused
at configuration for Basic (two keys), `sigv4()` (a key pair), and a
template with more than one key or the same key twice. Two credentials
that read one key must give it the same placeholder, since the app holds
one value for it.

Tested with DFNS's own SDK (`@dfns/sdk`, a dev dependency): it reads its
organization from the placeholder, and a fake DFNS reads the token it gets
with the SDK's own `extractTokenScope` and requires the real one
(`packages/server/test/credential-proxy-placeholders.test.ts`).

**Redis.** The same tunnel, intercepting the first `AUTH <password>` or
`HELLO 3 AUTH <user> <password>` and replacing the handle with the real
password. Then it pipes bytes. TLS upstream as for Postgres.

**Signing (0.9, built).** A private key the app signs with stays in
coffre, and the app asks for each signature. The deployment names the key
that holds it, as a tunnel names its URL's:

```ts
credentialProxy({ credentials: { … }, signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY') } })
```

A signer is no credential with an upstream: it reaches no host, and has
no rule to fill in. So it is a map of its own beside `credentials` and
`tunnels`, its names shared with theirs. The plan gives the app the handle
where the key was, never the key, whatever its level, and names the
signer among `credentials`, for `credential(name)` to find. The app signs
with `credential('dfns-key').sign(message)` (`@coffre/client/credential`),
which is `POST /use/<project>/<env>` with `{ sign: { credential, message } }`,
the message base64url, and answers the signature, base64url, as Node's
`crypto.sign(undefined, message, key)` makes it:

| The key, a PKCS#8 PEM | The signature |
|---|---|
| Ed25519 | its 64 bytes |
| EC on P-256 | ECDSA with SHA-256, DER-encoded |
| RSA | PKCS#1 v1.5 with SHA-256 |

The key says what it is: coffre reads its algorithm, and an EC key's curve,
from the PEM, and refuses any other (secp256k1, P-384) with a 409 that names
the key and quotes none of it. A PEM in another form (`BEGIN EC PRIVATE
KEY`) converts with `openssl pkcs8 -topk8 -nocrypt`. Line breaks may be
written `\n`, as an env file has them. WebCrypto only
(`packages/server/src/plugins/sign.ts`), so the same on Workers, which
convert ECDSA's `r || s` to DER as OpenSSL writes it. Each signature is one
use in the log, naming the message by its SHA-256, never served from the
cache.

DFNS's own signer, `AsymmetricKeySigner`, signs a user action's challenge
with the key. Equisafe's backend replaces it, where `coffre run` gave the
app placeholders, with one that asks coffre:

```ts
import type { CredentialSigner, KeyAssertion, UserActionChallenge } from '@dfns/sdk';
import { credential, type ProxiedCredential } from '@coffre/client/credential';

/** AsymmetricKeySigner's assertion, its signature made by coffre: the private key never reaches the backend. */
export class CoffreKeySigner implements CredentialSigner<KeyAssertion> {
  readonly credId: string;
  readonly key: ProxiedCredential;

  constructor(credId: string, key: ProxiedCredential = credential('dfns-key')) {
    this.credId = credId;
    this.key = key;
  }

  async sign(challenge: UserActionChallenge): Promise<KeyAssertion> {
    if (challenge.allowCredentials && !challenge.allowCredentials.key.some((allowed) => allowed.id === this.credId)) {
      throw new Error(`${this.credId} is not among the credentials DFNS allows for this action`);
    }
    const clientData = JSON.stringify({ type: 'key.get', challenge: challenge.challenge });
    const signature = await this.key.sign(clientData);
    return { kind: 'Key', credentialAssertion: { credId: this.credId, clientData: Buffer.from(clientData).toString('base64url'), signature } };
  }
}
```

A service, which reads values, keeps `AsymmetricKeySigner`: the backend
picks `CoffreKeySigner` when `COFFRE_CREDENTIALS` names `dfns-key`. The
test (`packages/server/test/credential-proxy-sign.test.ts`) runs this very
class in DFNS's SDK, which creates a wallet through the proxy against a fake DFNS
that checks the signature with `node:crypto.verify`, as DFNS does.

**Egress (after 0.10.1, built).** Some upstreams let in only the addresses they
know. Schuman's API, on AWS API Gateway, allowlists its clients' IPs, and
a Worker's `fetch` leaves from Cloudflare's shared addresses, which nobody
can allowlist. Such a credential names what its requests leave through,
in place of the global `fetch`:

```ts
schumann: {
  upstream: 'https://dev.api.europ.schuman.io',
  inject: header('x-api-key', '{SCHUMANN_API_KEY}'),
  egress: env.SCHUMAN_EGRESS,
},
```

`egress` is anything with a `fetch(url, init)` method: a Workers VPC
Service binding, a service binding, or an object of the deployment's own,
on Node as on Workers. The proxy hands it exactly what it would have sent
the global `fetch`: the upstream's URL and the request it made,
`redirect: 'manual'` included. Every check of section 4 comes first (the
handle, `methods` and `paths`, the rule's injection, the handle anywhere
else refused), and the answer is treated as any upstream's (redacted,
`no-store`, its redirects kept on the proxy). The `credential.use` entry
says `egress: true`, and nothing of the binding; the audit page reads
"used the credential schumann on dev.api.europ.schuman.io, through the
deployment's egress". A binding that throws is the upstream not
answering, a 502.

For Schuman, Equisafe's path is a Cloudflare Tunnel to a `cloudflared` VM
whose traffic leaves from one fixed address, which Schuman allowlists:

```
app → coffre's Worker, /use/schumann/… → env.SCHUMAN_EGRESS.fetch(…) → Cloudflare Tunnel → cloudflared → NAT → Schuman
```

```sh
# Once: the VPC Service, Schuman's own host, through the tunnel.
wrangler vpc service create schuman-egress --type http --tunnel-id <tunnel id> --hostname dev.api.europ.schuman.io
```

```jsonc
// app/wrangler.jsonc, beside "services"
"vpc_services": [{ "binding": "SCHUMAN_EGRESS", "service_id": "<the id it printed>" }],
```

and `SCHUMAN_EGRESS: Fetcher` in the app's `Env`. What Cloudflare's docs
([VPC Services](https://developers.cloudflare.com/workers-vpc/configuration/vpc-services/))
say, and what it means here:

- **The binding's host must be the upstream's.** A VPC Service reaches
  the one host and port it was made for. The URL its `fetch` is given
  only sets the request's `Host` header and TLS's SNI, and its port is
  ignored. coffre cannot read the binding's target, so this is a
  requirement on the deployment, not a check: one VPC Service per upstream
  host, made for that host. The scheme is the URL's, HTTPS here, and the
  certificate is verified by default (`verify_full`).
- **The target may be a public hostname.** DNS is resolved on the tunnel's
  side and the request leaves from `cloudflared`'s host; Cloudflare's own
  example targets `s3.us-west-2.amazonaws.com`. That needs `cloudflared`
  2025.7.0 or later on QUIC (UDP 7844): on `http2`, its DNS fails.
- **A deploy needs the right token.** Binding a VPC Service takes the
  Connectivity Directory Bind permission, which a Workers Builds token
  lacks unless given it (workers-sdk issue
  [#15704](https://github.com/cloudflare/workers-sdk/issues/15704)).
- **Local development has no VPC Service.** wrangler and the Vite plugin
  reach the real one (a remote binding) or fail; there is no local
  simulator. A local stack names no `egress`, or a `{ fetch }` of its own.
- Workers VPC is in beta, free on every plan for now.

**Fails closed.** A binding missing from `wrangler.jsonc` is `undefined` in
`env`, so `egress: env.SCHUMAN_EGRESS` is then a key that is there with
the value `undefined`. The proxy tells it apart from no `egress` at all
(`'egress' in credential`) and refuses the configuration:

```
credentialProxy: schumann's egress is undefined, as a Worker's binding is when wrangler.jsonc lacks it: add the binding, or remove egress. schumann's requests never leave without it
```

An `egress` with no `fetch` method (`{}`, `null`) is refused too. On
Workers the configuration is read from `env` at the first request, so the
Worker answers nothing until the binding is there, as with any
configuration error. It never falls back to the global `fetch`, which
would send the real key by a road other than the one the deployment
chose: at best a 403 from the allowlist to debug, at worst, for a name
that resolves elsewhere outside the tunnel's network, another host.

**Not settled, and not built on.** Cloudflare documents neither of these
for VPC Services, and nothing here was run against a real one:

- *Redirects.* workerd returns a 3xx as it is when `redirect` is
  `'manual'`, for any binding (its `fetch` follows only on `'follow'`), so
  the proxy gets it as it does from the global `fetch`. Whether
  Cloudflare's side of a VPC binding follows one itself is not
  documented. If it did, the next request would still go to the
  binding's one host, so the key reaches no other.
- *Streamed bodies.* An upload streams through a service binding in
  workerd, 24 MiB with its length kept (`FixedLengthStream`), as
  `packages/server/test/credential-proxy-egress-workers.test.ts` checks.
  Through a VPC Service it is untested, and Cloudflare documents no limit
  of its own beyond Workers' (the request into coffre's Worker is capped
  by plan anyway: 100 MB on Free and Pro). Streamed answers are untested
  too.

**Through Cloudflare Access, if the VPC Service cannot be used.** A
tunnel's public hostname behind Access, its policy Service Auth, takes a
service token in two headers. The deployment writes that as its own
`{ fetch }`, sending the proxy's request to the tunnel's hostname with
the token added; `cloudflared`'s ingress for that hostname points at
`https://dev.api.europ.schuman.io`, with `httpHostHeader` and
`originServerName` set to Schuman's host:

```ts
import type { Egress } from '@coffre/server/plugins/credential-proxy';

/** Schuman through the tunnel's public hostname, behind Access: the service token from the Worker's secrets, sent to Access and logged nowhere. */
function throughAccess(origin: string, token: { id: string; secret: string }): Egress {
  return {
    fetch(url, init) {
      const headers = new Headers(init.headers);
      headers.set('cf-access-client-id', token.id);
      headers.set('cf-access-client-secret', token.secret);
      return fetch(new URL(`${url.pathname}${url.search}`, origin), { ...init, headers });
    },
  };
}

egress: throughAccess('https://schuman-egress.equisafe.example', { id: env.SCHUMAN_ACCESS_ID, secret: env.SCHUMAN_ACCESS_SECRET }),
```

The token is the deployment's, not the environment's: coffre's redaction
knows only the credential's values, so an upstream that echoed the two
headers back would show them to the app. Whether Access removes them
before the request reaches `cloudflared`'s origin is not documented;
assume Schuman sees them. No helper ships for this: it is eight lines,
and a VPC Service needs none.

**Later: `verify`, HMAC, and SDK credential files.** Other secrets used
for computation get helpers of the same kind: an HMAC that signs or
verifies a webhook (a signer of another kind, `hmac('WEBHOOK_SECRET')`), a
JWT signed with a service account's key. An SDK that reads a credentials
file (Google's service-account JSON) gets a file whose private key is a
placeholder and whose `token_uri` points at coffre, which signs the token
exchange with the real key. Both change app code or its configuration.

## 6. Security

**What an agent with placeholders can still do.** It can use every credential
of the environment, against that credential's upstream, for as long as the
handle lives. It can, for example, call Schumann's API with the real key,
which is the point. It cannot read a value, send one to another host, or
keep using one after the handle is revoked (within `cacheSeconds`) or
expires. Every use is logged against the person and the handle.

**A database the tunnel reaches must accept connections only from coffre.**
Any Postgres role may change its own password (`ALTER ROLE CURRENT_USER
PASSWORD '…'`), superuser or not, and the tunnel pipes that query like any
other. If the database also accepts the holder's own connections, they
can set a password they know, connect directly, and outlive the handle.
So the role connects from coffre's address and nothing else: a firewall
rule or a private network in front of the database, or a `pg_hba.conf`
line that takes the role only from that address. The tunnel stops a
holder from reading the password, not from changing it.

**A credential that can mint credentials defeats this.** A Postgres login
with CREATEROLE or superuser lets the agent `CREATE ROLE me LOGIN PASSWORD
…` and connect directly. An AWS key with IAM write lets it create an
access key. An API key that can create API keys does the same. The proxy
cannot tell, so the docs say it plainly: give `market/dev` least-privilege
credentials (a database role that owns its schema and nothing else, an IAM
user scoped to its buckets). A warning is cheap where the proxy can see
it: the Postgres tunnel can read `rolcreaterole`/`rolsuper` after login
and log a warning entry (PR 3).

**A leaked handle.** It ends up in the app's logs, a crash report or a
`.env` file, as any variable does. It reaches only the proxy, for its
person's environments, for 12 hours at most, and its prefix
(`coffre_use_`) is what secret scanners match. Per-credential handles would
narrow a leaked one to one credential. They would cost one handle per
credential per run, and are easy to add if wanted.

**Upstreams.** Each credential has exactly one upstream origin and path,
with no wildcard and no host taken from the request, over HTTPS. A literal
private, loopback or link-local address (`10.0.0.8`, `169.254.169.254`,
`[::1]`, `localhost`) is refused at configuration.
`insecureUpstreams: true` allows both, for local fakes in development, and
never belongs in production. A hostname that *resolves* to a private
address is the operator's own DNS. On Workers, `fetch` cannot reach a
private network anyway; a credential's `egress` can (section 5), and a
VPC Service binding reaches only the host it was made for. A tunnel's
`connect`, a VPC Network binding, reaches a whole network, so the tunnel
names the hosts in it its URL may (section 5). On Node, pinning the resolved address is left for
later (decision 9).

**Injection** goes into headers, the query and Basic only. Nothing is
injected into a body, so a provider that wants its key in a JSON body
(rare) is not proxied yet.

## 7. Questions, answered

**Latency.** Measured locally: Node 24, the app's runtime and the vault in
one process as in the test suite, a fake upstream on loopback, 200 calls
each after 20 to warm up, median:

| Path | SQLite | Postgres |
|---|---|---|
| Direct to the upstream | 0.39 ms | 0.36 ms |
| Through the proxy, values cached | 0.48 ms | 0.43 ms |
| Through the proxy, values opened (first call of the minute, or `cacheSeconds: 0`) | 7.8 ms | 14.9 ms |

A cached call costs a route match, the handle's lookup (none: the cache
is keyed by the handle) and the header rewrite. An opened call adds the
handle's check (one database read and one vault `access` call) and the
read (one vault `unwrap`, two audit entries). Deployed, add the hop from
the developer's machine to coffre and from coffre to the upstream, which
for a provider in the same region as coffre is close to what the app
would have spent anyway.

**Audit volume.** One opening of a credential's keys per handle per
minute: a vault `secret.read` naming the keys (purpose `use`, the bulk
shape of #242), and a `credential.use` entry naming the credential and
its host, sharing its operation id. A dev loop that calls Schumann 500
times a minute writes 2 entries a minute for it, not 1,000. A call per
entry would also take the log's head once per call, which serializes every
request of the instance. And it would run into the vault's bulk limit
(1,000 keys per 15 minutes per person) in under a minute of
tests. The cost: between openings the log says "used schumann from 10:41"
rather than each call, and a revoked handle keeps working for up to the
cache's minute (`cacheSeconds: 0` turns both off).

**What `coffre run` makes a placeholder, and what it leaves out.** A person
on an instance with the proxy gets the plan (section 4): placeholders for each
credential's keys, the values they may read as they are, and nothing else. It
sets no base URL: the app's configuration names the stable URL. A service account gets values, as before.
An instance without the proxy gets the old read, which leaves a person's
sensitive values out (section 2). `coffre export` writes the same
placeholders (a `.env` for Docker Compose holds handles, not keys).
`export --watch` is refused for people: nothing it would watch changes.

**Workers.** The HTTP shapes are a `fetch` from the app's Worker, so they
work as they do on Node. The tunnel needs an inbound WebSocket, which
Workers take (`WebSocketPair`), and an outbound TCP connection, which
`connect()` from `cloudflare:sockets` opens, with `secureTransport:
'starttls'` and `startTls()` for Postgres's TLS upgrade. Both are
documented and general, and Hyperdrive is not involved: the tunnel
connects to the database's public address, as any TCP client would. The
limits: `connect()` reaches public addresses only (a private network
through a VPC Network binding, section 5) and port 25 is blocked. The
tunnel runs in a Durable Object (section 5); what the prototype found,
locally under workerd and in Cloudflare's documentation:

- *Six connections: assumed, to confirm.* Cloudflare's limits page counts
  six connections per invocation "simultaneously waiting for response
  headers", a `connect()` among them, and queues the seventh rather than
  refusing it; a connection stops counting "once response headers
  arrive". A TCP socket has no headers, so whether an *open* socket still
  counts is not said, and local workerd enforces no limit. Read as
  "until it opens", a pool of ten opens six at once, then four. Read as
  "while open", it is worse than a queued dial: a pool of six at its
  prompt holds the budget, and the object's recheck, a Hyperdrive query
  and a vault call, waits behind it until its 10 s deadline says no,
  which ends all six, every minute. Locally, twelve connections of one
  run, one object, opened within 0.2 s and ran together, which settles
  nothing here. To confirm on Cloudflare, before a release carries a
  production database: a real `coffre run` with six idle connections
  held through two rechecks, the log showing both `recheck` entries and
  the sessions still open, and twelve opened at once. *Fallback, if open
  sockets count:* `MOST_SESSIONS` drops to four, leaving two for the
  recheck's database and vault, and deploy.md tells pools to stay under
  it.
- *Hibernation* saves nothing here. It frees an object whose WebSockets
  are idle, but an open TCP socket to Postgres cannot survive it, and the
  group's check is a timer. An object holding a run's connections is in
  memory, billed as 128 MB of duration, for as long as they are open:
  450 GB-s an hour, about $0.0056 an hour past the paid plan's 400,000
  GB-s a month; the free plan's 13,000 GB-s a day is 29 hours of runs.
  One object per run, not per connection: a pool of ten costs one.
- *STARTTLS* works: `startTls()` with no options, which checks the
  certificate against the host `connect()` dialled. workerd refuses
  `expectedServerHostname` ("unsupported"). Locally, TLS 1.3 to a
  Postgres whose certificate a test CA signed (given to workerd with
  `SSL_CERT_FILE`), and a refusal when dialled by an address its
  certificate does not name.
- *Eviction and deploys* end every session: a deploy restarts every
  object and disconnects its WebSockets, and an evicted object's TCP
  sockets are gone. The app's driver sees its connections drop, as when a
  database restarts, and its pool connects again, through a new object.
  `vite dev`'s reload swaps the module in place and keeps them.
- *Cost.* Measured with `vite dev`, one psql session of 20,000 one-row
  queries: 175 µs of workerd's main thread per query (one message each
  way, the JavaScript and the I/O together), 0.45 ms a query against
  0.08 ms direct; 110 MB read in 2 s of its CPU. An object is one thread:
  a run's connections share about 5,000 queries a second. With flow
  control (0.11), through the real CLI: 200 MB in 4.2 s, 48 MB/s, for
  3.9 s of workerd's CPU, the whole process's, `coffre run`'s own requests
  included; 1 GB in 21.9 s for 18.1 s. About 19 ms of CPU a MB, as before
  the counts: they cost nothing measurable. Each message is far under the
  30 s of CPU an event may take.

**Cloudflare Access.** The proxy's callers are apps and the CLI, not
browsers, and a handle is not an Access identity. So `/use/*` needs an
Access *bypass* policy for that path, and coffre authenticates the handle
itself. The CLI's own `POST /api/handles` still goes through Access as
the person. Behind Access coffre has no sign-in of its own, though, and so
no credentials table to keep handles in: handles, and with them the
proxy, need coffre's sign-in for now (decision 7).

## 8. Decisions

Each was taken on 2026-10-18 under R10 and R13, for Erwin to review. Each
is reversible.

1. *(Superseded in 0.10 by decision 20.)* **`people: 'stand-ins'` is a vault option, default `values`.** It is
   off by default so that 0.7 deployments, which have no proxy and no
   credentials declared, keep working, and the conformance suite and every
   test that reads as a person stay as they are. *Recommendation: make it
   the default once the proxy covers the common shapes (after PR 3), with
   a release note.*
2. *(Superseded in 0.10 by decision 26.)* **No new permission or role.** A person's `secret.read` is the use
   right: with placeholders, it opens values to be used, never handed back.
   `use` and `expose` are purposes of the same read, checked by the same
   grants. A `consumer` role (use without read) adds nothing while people
   never read values anyway. It would also need a migration of the grants'
   role check.
3. **Break-glass is a service account, no new path.** It is explicit,
   logged at each step, and already exists. *Alternative:* a reveal page
   for Owners behind a fresh sign-in.
4. **One handle per run, for all its environments' credentials.**
   *Alternative:* one per credential, if a leaked handle's reach matters
   more than the extra rows.
5. **12 hours, a week at most, never past the personal token that made
   it.**
6. **Logged per credential per handle per minute** (`cacheSeconds: 60`),
   not per call: see the audit volume above.
7. **Handles need coffre's sign-in.** Behind Cloudflare Access the proxy
   has no handles. *Later:* keep handles in coffre's own table whatever the
   sign-in, minted by an Access-authenticated person, with `/use/*`
   bypassed in Access.
8. *(Superseded in 0.10 by decision 20.)* **`expose` is configuration, by exact environment, never inherited.**
   A fork is listed by its own path, or not exposed. A personal config is
   never listed; its own values, written by its owner alone (R8), reach
   its owner's app. Otherwise a personal config, made for local
   overrides, would serve no app. What it inherits follows the
   environment it is a config of (0.9): its owner reads that environment,
   so exposing it there too gives them nothing new, and a deployment that
   generates values in personal configs (below) keeps what it exposes.
9. **No DNS pinning yet.** Literal private addresses are refused. A name
   that resolves to one is the operator's DNS.
10. **Redaction of values 8 characters or longer**, in headers and text
    bodies; never a plain value's (0.9).
11. **Bodies read whole, up to 16 MiB**, so the upstream gets a
    `Content-Length`. Uploads larger than that go through S3's own path
    (PR 2) or a presigned URL.

Taken in 0.9 (W127), each for Erwin to review, each reversible:

12. **The stable URL is `/use/<credential>`, told apart by the handle's
    environments**: `/use/<a>/<b>/…` is an environment's when the handle was made
    for `<a>/<b>`. *Alternative:* a reserved segment, `/use/-/<credential>`,
    decided by the URL alone (section 4).
13. **A handle keeps the environments it was made for** (`0010_handle_places`),
    by id and whether as `@me`, under its MAC: its scope cannot tell
    `market/dev@me` from `market/dev`, nor a fork from the parents it
    holds. By id, as its scope is, so a rename keeps them.
14. **A handle for several environments gets a 409 on the stable URL**,
    naming the environments' URLs. *Alternative:* resolve to the one
    environment that holds the credential's keys, which `coffre run`'s
    own rule (a key comes from one environment only) makes unique within
    a run, but which costs a read of each to find, and moves when a key is
    set later.
15. **`COFFRE_CREDENTIALS` keeps the environment's URLs.** `coffre run`
    sets it for every run, so its URLs need not be stable; an
    environment's works for a run of several, and `presign()` derives the
    environment's URL from it.
16. **`baseUrl` is removed, not deprecated**: refused at startup and by
    its type, with the URL to configure instead.
17. **Making a stored secret plain is a reveal, then a write (0.9).**
    Erwin's brief had it need `secret.read` on the key, and audited. Under
    placeholders, though, `secret.read` is a person's right to *use* a value,
    never to see it (decision 2), and a plain value is shown to everyone
    who lists the environment: a person, or their agent with a personal
    token, could publish any key they may use. So the flip is the client's
    reveal, which the vault refuses a person where the value is sensitive (R13; 0.10), and a
    plain write of what it showed. Of a secret they read, that is exactly
    `secret.read` and an audited read and write. A person types a value
    they know again, plain. *Alternative:* a flip the server does, allowed
    to people, if publishing what one may use is wanted.
18. **Plain is said by each write, and stored beside the ciphertext.** A
    write that does not say `plain` is a secret, so nothing becomes or
    stays plain without someone saying so then. The clear copy is what
    lets a listing show it and a read skip the vault. The ciphertext keeps
    the paths that open through the vault (references, KEK rotation)
    unchanged.
19. **Personal values are opted into by environment, in the proxy's
    configuration (`generate`)**, not by key in the data nor everywhere a
    recipe is. A value made for a person protects only their own local
    data, which suits `backend/local` and nothing deployed; listing the
    environment in configuration keeps that choice with the deployment's
    code. The client makes each value, as for `coffre set
    --generate`: the server never makes one. *Alternative:* the server
    generates in the plan, which would let any client of the proxy have
    them, at the cost of the server making values.

Taken in 0.10 (W128), each for Erwin to review, each reversible:

20. **Sensitivity is per key, and `people` and `expose` are removed, not
    deprecated.** Erwin's design (2026-10-18). A deployment that still sets
    `people` or `expose` fails at startup, and by its type, naming what to
    do, as `baseUrl` did in 0.9 (decision 16): the old switch refused every
    value to every person, and keeping it beside a per-key setting would
    leave two answers to one question. `identifiers`, which plain values
    cover, goes the same way.
21. **Sensitivity is held by each version, bound by the vault's wrap.** As
    plain is (decision 18), and as a personal config's owner is bound: the
    key's level is its current version's. *Alternative:* a column of the
    key's own, which the vault would have to trust as the app wrote it.
22. **A write that says nothing is a secret, or sensitive where the key
    is.** The brief's default is `secret`; keeping a sensitive key
    sensitive when its value is rotated (`coffre set`, the page's edit,
    Regenerate) avoids the one surprise that would undo it. Plain stays
    said by each write. *Alternative:* `secret` always.
23. **A person's read of a whole environment leaves sensitive values out,
    and says which, rather than refuse.** A run of `market/prod` without
    the proxy then starts, without them. The vault still refuses any read
    that names one. *Alternative:* refuse the whole read, as 0.9's
    `people: 'stand-ins'` did.
24. **A dry run compares no person's guess with a sensitive value**: it
    answers `changed`, so an import is never an oracle for one.
25. **A credential's keys are placeholders whatever their level.** The
    app's configuration points at the proxy for them (R14), where the real
    key would be refused as no handle. A person who reads one still gets it
    with `coffre get`.

26. **`secret.use` is a permission of its own, and Contributor the role
    that holds it without read (0.10).** `secret.read` hands a value back;
    `secret.use` lets coffre use it for its holder: the proxy's `use`, a
    plan's placeholders, listing the keys. Every role that read uses too,
    so nobody's access changed: Viewer, Developer, Maintainer and Owner
    hold both, and the instance's Developer too. A Contributor (`secret.use`,
    `secret.write`) writes values and runs its app on placeholders, and
    reads none. A person gets the narrower of role and key: a Contributor
    nothing of a secret but its placeholder, a Developer nothing of a
    sensitive key but its placeholder. The vault decides: a read to `use`
    takes `secret.use`, any other `secret.read`. A handle is scoped
    `viewer` where its person reads, `contributor` where they only use.
    The role is a project role, granted on a project or one of its
    environments; *alternative:* an instance role too, for which 0.10's
    role editor (PR 4) makes Developer's protected column use-only.
27. **A personal config is a partial overlay, and its values have any
    level (R18, Erwin 2026-10-19).** Each key the owner of `dev@me` sets,
    whatever their role, overrides dev's or adds one; every other key
    falls through to dev's, live, read as on dev. Each value of their own
    is plain, secret or sensitive, as anywhere: they read their plain and
    secret ones, and a sensitive one, theirs or not, is used, never read.
    A write that says nothing takes the level of the value the key reads
    now: dev's for an override (dev's sensitive `DATABASE_URL` gives a
    sensitive override), then their own (`coffre set … --secret` once, and
    it stays a secret), plain included, unlike elsewhere, since nobody but
    them lists it; a generated value is never plain, so a secret. A local
    `DATABASE_URL` their app is given is said: `coffre set
    market/dev@me/DATABASE_URL --secret`. A level they choose may be
    looser than dev's key: they type a new value, so retyping to loosen
    (decision 22) holds of dev's key, which they never see, not of theirs.
    Their own value is loosened by a write, as anywhere. A plain value is
    held to its owner by the app's `can()`, not the vault, as plain values
    are everywhere (forking.md, section 3). *Alternatives:* a bare
    override always a secret, as 0.10's first build had it, which hid an
    inherited plain `REGION` the person overrode; or a plain value in
    `dev@me` stored sealed and shown as plain, which keeps the vault's
    binding at the cost of a vault read for each listing, and a plain
    that behaves unlike plain elsewhere (logged reads, bulk limits).
28. **A credential's `egress` is any `{ fetch }`, named by value, and fails
    closed (Erwin 2026-10-19).** The binding itself, `egress:
    env.SCHUMAN_EGRESS`, rather than a name coffre looks up or an
    `egress(name, binding)` helper: the deployment already holds it, and a
    `{ fetch }` of its own covers every other road (Access, a test fake).
    Named and missing, it refuses the configuration rather than leave by
    the global `fetch`. HTTP credentials only: a signer reaches no
    upstream, and a tunnel dials through a `connect` of its own (decision
    31).

29. **An Owner loosens a sensitive value in place (R30, Erwin
    2026-10-21).** An Owner of the project, or of the whole instance,
    makes a sensitive value a secret with its value kept, as marking
    stricter does, rather than typing it again: they read it anyway
    through break-glass, so retyping protected nothing from them, and a
    project's Owner holds that inside their project. Decided by the
    vault, for the key's current version alone: older versions keep
    their binding, and come back sensitive, as a rollback brings any
    value back as it was held. The simplest consistent rule: a loosening
    is one new version, as a tightening is, and no version is rewritten.
    Its own entry, `secret.loosen`, not a `secret.write`, which the
    offboarding report reads as a value its writer saw. *Alternatives:*
    retyping, always (R16); loosening the key's history too, which would
    rewrite versions in place, unlike everything else.

30. **The tunnel on Workers paces itself by credit, and refuses a CLI that
    does not (W146, 0.11).** In-band counts, text messages beside the
    binary ones, rather than a second channel or relying on TCP: a Workers
    WebSocket gives no back-pressure to rely on, and a count needs no
    state but two numbers each side. A 1 MiB window keeps a pool of ten
    under 20 MB of the object's 128 MB in the worst case. An older CLI is
    refused with 426, since it would send no counts: the Workers tunnel is
    new in 0.11, so no deployment loses a working CLI. The keepalive is a
    count, not a protocol ping, which Cloudflare's edge answers itself.
    *Alternatives:* a smaller window, at the cost of throughput far from
    the object (window over round trip: 1 MiB over 30 ms is 33 MB/s).

31. **A tunnel's `connect` is a VPC Network binding, named by value, which
    lets it name private hosts and plaintext, and fails closed (Erwin
    2026-10-21, TLS option a).** As a credential's `egress`: the binding
    itself, refused at configuration when missing, never a direct dial in
    its place. A binding reaches a whole network, so `hosts` is required
    with it. Plaintext, since the binding carries no TLS yet: the last leg,
    connector to database, stays in the private network. A URL asking for
    TLS is refused rather than downgraded. *Alternatives:* TLS through the
    binding once Cloudflare offers it, which would then be the default.

32. **`coffre init` writes the sockets object's wiring, idle (W146).** The
    binding, its migration, `coffre.upgrade` in the server entry and
    `sockets: env.SOCKETS`, though the example adds no credential proxy:
    opening the tunnel is then the plugin and its route alone, and the
    example and `pnpm dev` share their server entry. An object nobody
    reaches costs nothing. *Alternative:* leave it to the docs, at the
    cost of a wrangler migration each deployment writes by hand.

## 9. Plan

| PR | What |
|---|---|
| 1 | Placeholders in the vault (`people`), handles (`0009_handles`, `POST /api/handles`), the plugin's `use` capability, `credentialProxy` with header, query and Basic, the plan, `coffre run`/`export` placeholders, `@coffre/client/credential`. Built |
| 2 | `sigv4()`: S3 through the proxy, tested with the AWS SDK against a signature-checking fake, and by hand against MinIO. Built |
| 3 | The Postgres tunnel: a socket capability for plugins (`routes.socket`, Node's `upgrade`), the listener in `coffre run`, SCRAM, cancel, revocation mid-session. Built |
| 0.9 E | The stable URL, `/use/<credential>`, from the environments a handle keeps (`0010_handle_places`); `baseUrl` removed. Built |
| 3b | The tunnel on Workers (`WebSocketPair`, `connect()`), one Durable Object per run and database, paced by credit; through a VPC Network binding (`connect`). Built (0.11); to check on a deployed Worker. The privileged-role warning, not yet |
| 4 | Redis through the tunnel |
| 5 | `presign` (built in 0.8.1) and `sign` (0.9 D); `verify`, HMAC, SDK credential files |
| 0.9 C | Shaped placeholders, `jwt({ claims })` and `prefix(…)`: DFNS's token through the proxy. Built |
| 0.9 A | Plain values (`0011_plain_values`, `coffre set --plain`, the page's Plain toggle), which deprecate `identifiers`. Built |
| 0.9 B | Values of a person's own: `generate`, reads through `<env>@me`, `coffre run` making them by recipe. Built |
| 0.10 | Sensitivity per key (`0012_sensitive_values`, `coffre set --sensitive`, `coffre mark`, the page's control); `people`, `expose` and `identifiers` removed. Built |
| 0.9 D | Signers, `privateKey(…)`, and `credential(name).sign(message)`: DFNS's user-action key stays in coffre. Built |
| Egress | A credential's `egress`: its requests leave through a VPC Service binding, for an upstream that allowlists addresses (Schuman). Built; untested against a real VPC Service |

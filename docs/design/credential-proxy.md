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
(section 5). After 0.14.3, W190 puts a key in one field of a small form or JSON
body, `form()` and `json()` (section 5, "A field of the body").
0.17 adds `passthrough`, a credential that carries a browser's cookies
and redirects in an envelope, for Clerk's Frontend API on brand domains
(section 10, designed, not built).

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
| `sensitive` | No person, Owners included. Their apps get a placeholder and use it through the proxy; service accounts read it, on a token or binding an Owner of the project issued. An Owner of the project may make it a secret, its value kept (loosening, below) | Never shown to anyone, Owners included. Used through the proxy or by services |

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
| A service account: a service token, a CI run's or a cluster's ID token | The value | The value, on a token or binding an Owner of its project issued: CI and production read their environment once, at full speed. On anyone else's, refused (`not_owner_issued`, R32) |

The rule is in the vault, the one place every read goes through, not in
the CLI or the API's routes. `coffre get`, the UI's reveal, `POST
/api/reveals`, the Vault KV plugin and MCP's `reveal_secret_values` and
`show_secret_value` all reach the vault's `unwrap`, so all are refused the
same way, and each refusal is in the vault's log. So is an import's dry
run (`compare`): its `changed` or `unchanged` tells whoever sent a guess
whether it was right, so a sensitive value is compared with no person's
guess (`changed`), nor a service's on a credential no Owner issued. A fork's `copy` hands nothing back, and stays. Every
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
account's admission, its grant, the token's creation and every read.

Only an Owner of the project takes that path (R32). Anyone may set up a
service account where the instance lets them, and give it what they hold
(`givesService`), so a Developer of `market/dev`, who does not read its
sensitive `STRIPE_SECRET_KEY`, could otherwise give an account read
there, issue it a token, and read the key with it; or issue one while
nothing there is sensitive, and read a key marked sensitive later. So each
place of a service token's or binding's scope says whether it reads the
sensitive values there, true only where its issuer was an Owner of the
project, of the whole instance or by a grant or role scoped to it, as a
person on no credential's scope (`ownsProject`). The vault hands a
service a sensitive value only on a credential that says so for the
project the key is held in (`readsSensitive`, `not_owner_issued`): a
fork's parent's for what it inherits, and a reference's holder's, as any
key held there (R71). A reference takes only its value and nature from
its source, and its source is checked once, when it is made, by its
maker's reading the value there (R24): a token an Owner of `billing`
issued for `billing/dev` reads `billing/dev/STRIPE_SECRET_KEY`, a
reference to `backend/prod`'s, whatever it says for `backend`, and one a
Developer of `billing` issued does not. Everything else the account
reads as before, and its credential's maker is told, when it is made,
which places hold a sensitive value it will not read (`withheld`). A
personal token or a handle cannot take the path at all: the route that
issues service tokens and bindings refuses both, and a test holds this.
A page that reveals behind a fresh sign-in, for Owners, is possible
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

Workloads use the same proxy, signing in with a key-bound session in place
of a handle ([workload-access.md](workload-access.md), section 7.1, and
"As PR 1d built it" in its section 12). For them a credential or a signer
may say how often it is used, counted per workload:

```ts
credentials: { stripe: { upstream: 'https://api.stripe.com', inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}'), limit: { perMinute: 120, perDay: 20_000 } } },
signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY', { limit: { perMinute: 10 } }) },
```

**Several rules, an allow list, and environments (0.16).** A credential's
`inject` may be a list, applied in order, and `allow` says which requests
it takes, path by path:

```ts
openai: {
  upstream: 'https://api.openai.com/v1',
  inject: [header('authorization', 'Bearer {OPENAI_API_KEY}'), header('openai-organization', '{OPENAI_ORG}')],
  allow: [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }],
},
s3: {
  upstream: 'https://s3.eu-west-3.amazonaws.com',
  inject: [header('x-tenant-key', '{TENANT_KEY}'), sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' })],
},
replica: { upstream: 'https://replica.acme.example', inject: header('x-api-key', '{REPLICA_KEY}'), environments: ['market/prod'] },
```

- **Rules.** One per header (by name, any case), query parameter or
  field; `path()` once at most (section 5, "A segment of the path"); `basic()` once at most, and never beside a rule that sets
  `authorization`; `sigv4()` once at most, last, beside no rule that sets
  `authorization`, an `x-amz-` header or parameter, or a field of the
  body, whose hash it signs. SigV4 signs the headers the rules before it
  set (`SignedHeaders` lists them), so none is swapped on the way. A form's
  or a JSON body's fields, never both. Each rule names a key.
- **The handle** rides where the plan put it: in each slot of a key that is
  no plain one (every slot, when all are plain, which then stay
  placeholders), or in `x-coffre-handle`. Two different handles in one
  request are a 400, every occurrence counted, whatever its shape: a
  parameter given twice (`?token=p_H1&token=H2`, the second outside the
  placeholder's `p_`), a header given twice, two Basic pairs, a handle in
  `Authorization` beside a `basic()` or `sigv4()` rule, two in one slot. Only
  one in the placeholder's shape, or in `x-coffre-handle`, lets a request in. A field the handle rides in must hold it; a field of
  plain keys holds what the app sent. A `placeholder` shapes the one header,
  query, form or JSON slot the handle rides in, which the environment's
  plain keys decide: where its secret keys sit in several rules, the plan is
  a 409 naming it.
- **`allow`.** A request any entry takes goes: its method among the
  entry's `methods` (any, when none or empty, unlike the legacy
  `methods: []`), and its path matching the entry's `path` (any, when
  none). An entry of any method on any path, `{}` or `{ methods: [] }`,
  is refused at startup: it would take every request. The path is matched segment by segment, each
  percent-decoded once, to bytes: `docu%6Dents` is `documents`, and
  `a%2520b` is `a%20b`, never `a b`. A plain path is a prefix by segments
  (`/companies` takes `/companies/42`, never `/companiesX`); `*` is one
  non-empty segment, matched exactly (`/companies/*/documents`); `**`,
  last, is the rest, none included (`/models/**` takes `/models`); a
  trailing slash, in code, a segment below that a server reads as one
  (`/bucket/*/` takes `/bucket/a/b`, never `/bucket/a`, `/bucket/a/`,
  `/bucket/a/...` or `/bucket/a/;x`, which a server that drops what
  vanishes, or a trailing slash, reads as `/bucket/a`). No
  regexes, no partial-segment globs (`doc*`). A pattern is decoded once,
  as it is read. A `*` takes no empty segment (`//`), and none of `;`
  parameters alone (`;x`, `%3Bx`) or of spaces and dots alone (`%20`,
  `...`), which a server that drops them, as Tomcat and Spring do the
  parameters and Windows the trailing spaces and dots, reads as empty or
  none: `/companies/;x/documents` is `/companies/documents` to it, which
  `/companies/*/documents` does not take. Anywhere else such a segment
  goes on, as on 0.15: past a prefix, a `**`, or a trailing slash and a
  segment a server reads as one, what a server makes of it is still inside (`/bucket/a//b`, an S3 key, under
  `/bucket`). A pattern's literal segment must read as itself to every
  server behind, or the pattern is refused at startup: none empty or a dot
  segment, none still percent-encoded once decoded (`%2561`, `%61` once
  decoded, which a server that decodes twice reads as `a`), none with `;`
  parameters (`a;v1`, `a` to Tomcat), none ending in a space or a dot
  (`a.`, `a` to Windows). Matched as written, `/tenants/%2561/*` would take
  `/tenants/%2561/x`, which such a server reads as `/tenants/a/x`, outside
  the list. A
  request no entry takes is a 405 when no entry takes its method, on its
  path or any, and a 403 otherwise; an empty list takes nothing, a 403.
  A method override in a header or the query is held to the list too
  (T189): many upstreams act on a POST that says
  `X-HTTP-Method-Override: DELETE`, or `?_method=DELETE`, as on a DELETE
  (Google's and ASP.NET's APIs; OData's `X-HTTP-Method`; Express's
  `method-override`). So each method a request names in
  `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` (or
  the same with `_` or `.`, as Rack and PHP read them), or in a `_method`
  query parameter, must be one the list takes on its path, or the request
  is a 405 naming it, before anything goes upstream: through a handle,
  before any value opens, and before its body is read unless the handle
  is in it (a stable URL's `form` or `json` field, which is read first to
  find the handle); through a UI route, after
  its one vault call, which opens them; a workload's, after its signed
  body is checked. A name is `_method` as PHP and Tomcat read one too
  (`.method`, `_method[]`, `_method `, any case), and a parameter named
  as one of those headers counts as one, as ServiceStack and ASP.NET MVC
  read them, ASP.NET's `%uXXXX` decoded too (`%u0058-HTTP-Method-Override`).
  An empty value names no method and changes nothing (`?_method=`).
  Every override, header or query, is held both as written and
  uppercased, because upstreams disagree: Express, Rack, Laravel and
  Symfony uppercase it, while ASP.NET Core, ASP.NET MVC, ServiceStack and
  Hono set the request's method to it as written. So a list that takes
  `PATCH` refuses `X-HTTP-Method-Override: pAtCh`, `?_method=pAtCh` and
  `?_method=patch` alike, as it would a request whose own method is
  `pAtCh` or `patch` (`delete` is DELETE, as fetch reads it). A client
  that writes `PATCH` is never refused for its case. An override the list takes
  goes on as it came (Google's `PATCH` through a POST): the upstream acts
  on a method the list allows either way, so refusing what it does not
  take closes the gap and breaks no client that stays inside the list,
  where stripping the override would quietly change what such a client
  asked for. Where an entry takes any method on the path, nothing is
  looked for. A narrowed session's `methods` hold the override the same
  way (a 403, `narrowed`). The check reads the headers that go upstream:
  one a workload's proof does not sign is dropped on the way, so an
  override header it leaves unsigned is no override.

  **A body is not read for one** (D179). A method-limited
  credential does not stop an override hidden in a POST's body: a
  `_method` field of a form or multipart body, which Rails, Laravel,
  Symfony and Spring honour (Laravel reads one in JSON too), goes on as
  it came. `allow: [{ methods: ['POST'], path: '/items/**' }]` refuses a
  POST with `X-HTTP-Method-Override: DELETE` or `?_method=DELETE`, but
  lets `_method=DELETE` in its form through, and such an upstream deletes.
  Reading bodies the way every framework parses them proved a contest
  coffre cannot win (two review rounds found fifteen parser differences:
  multipart framing, header folding, encoded names, compression), so
  against such an upstream a method limit is not a boundary: hold its
  credential to paths, or to a key whose own scope holds what it may do.
  The same holds for an override under a name of the upstream's own: the
  conventional names above are held, but every framework listed lets a
  deployment rename its override (Express's `methodOverride('X-Do')`,
  Spring's `methodParam`, Hono's `header` and `query` options, Restlet's
  `?method=`), and a POST with `X-Do: DELETE` goes on as it came. A bare
  `method` parameter is not held either: RPC-style APIs name a call with
  it (`?method=flickr.photos.search`), and refusing those would break
  them.
  `methods` and `paths`, as before, are one entry per path, and keep what
  they meant: `/` takes every path, `/companies/` what is below
  `/companies` and not it, a `*` is itself, never a glob (with a warning
  at startup), `methods: []` takes nothing, `paths: []` no path while
  its methods still answer first (`methods: ['POST'], paths: []` is a 405
  to a GET, a 403 to a POST, a presigned URL's too, before its other
  arguments are read), and a path of theirs is
  compared as written with the path as it goes, undecoded, `//`, `;x` and
  `%20` included, as an S3 key prefix may hold them (`/bucket//prefix`
  takes `/bucket//prefix/file`); another spelling is another path
  (`/files/%61` takes `/files/%61/x`, never `/files/a/x`), and one a URL
  never holds as written (`/café`, `/a b`) takes no request, with a warning
  at startup. A presigned URL is held to
  the same list, after the same refusals as a request (no segment that
  decodes, however often, to a slash, a control byte or a dot segment;
  past 8 decodings, a segment is refused as one). A path of `paths` with a
  segment that decodes to a dot segment or a slash matched nothing before,
  and still does, with a warning at startup.
- **`environments`**, on any credential, tunnel, signer or verifier: the
  environments it serves, by full path (a bare `prod` would be every
  project's), `market/dev@me` as `market/dev`. Elsewhere its name is still
  the deployment's: the plan leaves it out, and a request through it is a
  404 naming the environment, before anything is opened where the URL
  names it.

### Definitions written in the UI (0.16)

A deployment may also let its Owners write routes, signers, verifiers and
databases per environment, in the environment's **Proxy** tab, beside its
Secrets ([proxy-ui.md](proxy-ui.md) is the design):

```ts
// deployment.ts
export const deployment = defineDeployment({ proxy: { editable: true } });
```

`coffre init` writes `editable: true` from 0.16, with an empty
`credentials`, and the `/use` route and the tab's route file
(`app/src/routes/_coffre/projects.$project_.$environment_.proxy.tsx`). A
deployment upgraded with `coffre update` gains the tab's route file and
`/use`'s, and nothing else: unless its `deployment.ts` says
`proxy: { editable: true }`, the tab shows what code defines and writes
nothing. (0.15's `credentialProxy({ editable })` is still read in 0.16,
with a warning, and refused in 0.17.)

What the tab shows and does:

- **One list, one panel.** Every item of the environment, whatever its kind,
  one line each; the one picked, its fields beside it, with a sample call
  through a route (the proxy's own matcher says whether it is allowed) and
  the item as code, to move it there.
- **Code's items, locked.** An item `credentialProxy` defines shows with
  code's values and a lock, and its name is code's in every environment: a
  code item scoped with `environments: ['market/prod']` shows in
  `market/dev` too, dimmed, saying it serves `market/prod` only, and no item
  of `market/dev`'s own may take the name (R66).
- **Forks inherit by name.** A fork lists its parents' items, marked with the
  parent they come from; changing one makes the fork's own, over the
  parent's, and deleting that reverts to the parent's.
- **Who may change what.** Whoever lists the environment reads its
  definitions, every field inert. `proxy.edit` (Owners, and a role an Owner
  gives it) edits, and only what its holder reads: a route sending a key
  they cannot read stays as it is, deletable. A sensitive key is routed by
  an Owner of its project alone, and the save says it is audited (R66).
- **One save, reviewed.** Edits wait on the page; Save shows each change
  field by field, each copied item's keys and where they will go ("`schuman`
  will send market/prod's SCHUMAN_API_KEY to sandbox.schuman.example (copied
  from market/dev)"), and, when a destination changes, that requests already
  decided may reach the old one for up to R, the deployment's
  `proxy.revokedWithinSeconds` (a minute unless set), as a revoked
  handle's may. Another person's save since the page
  loaded is a 409: the review then says what they changed, and saving again
  is a decision.
- **Routes that no longer route.** An item whose editor no longer reads one
  of its keys, or one made sensitive since a save that was not an Owner's,
  is marked: each use answers `route_not_cleared` until someone who reads
  its keys saves it again ("Save again as you"). A member's page lists the
  items they saved, and removing them says which it stops.
- **Names code reserved.** A name an earlier deployment's code defined stays
  reserved after code drops it; the tab lists it, and an Owner of the whole
  instance releases it, instance-wide.

Named egresses and networks, which a UI item would pick by name, come with
0.16's use path for UI items; until then a UI item goes direct.

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
  one read of their names) and kept for R, as values are. Its
  values are opened and kept as an environment URL's are, in the same
  cache, so both URLs of one environment share one opening about every
  45 seconds.

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
   and an encoded slash or backslash is refused, as is a dot segment with
   path parameters, which Tomcat and Spring read as one (`/..;/`), and any
   of these encoded twice (`%252e%252e`), which a server behind another
   decodes twice. A credential's allow list (`allow`, or `methods` and
   `paths`, section 3) narrows it further.
2. **Who.** The handle, from `x-coffre-handle` if present, and from
   where each rule puts its key: the header, the query parameter, the
   body's field, the path's segment, Basic's user or password, or SigV4's access key id. A
   shaped placeholder's slot must be that shape exactly (section 5). No
   handle gets a 401, two different ones a 400.
3. **What.** The credential's keys, from the cache for the handle,
   environment and credential, or opened now: `use(handle, …)`, the API's
   read in process, purpose `use`. That is one vault entry naming the keys,
   and one `credential.use` entry (the vault appends it beside its read
   since 0.14.5, so a use takes the log's head once) naming the credential and the upstream's
   host, and `egress: true` where it leaves through one (section 5). A key
   the environment lacks is a 409.
4. **Sent on.** Every header but those about the hop, coffre's caller,
   its cookies and the handle; then the rule's header, parameter or
   Basic authorization, filled in, or the body's field (section 5). The body is read up to 1 MiB and no
   further (`@coffre/core/memory`), unless it says its length and either
   declares its digest (below, "Declared bodies stream") or goes through a
   credential nothing of which signs its hash (a header, Basic, a query
   parameter or a path segment), which streams it as it came past 1 MiB;
   a body whose field coffre fills, up to 64 KiB, and never streamed. The
   bodies an isolate reads whole are held to 16 MiB together: past that,
   503 with `Retry-After: 1`, before a byte is read. If the handle is still anywhere in the
   request (a header, inside another header's Basic base64, the URL, the
   body), it is refused rather than leaked to a third party. The request
   goes out with `redirect: 'manual'`, through the global `fetch` or the
   credential's `egress` (section 5). It has no time bound of coffre's
   own: the upstream request ends when the app's does (its hang-up, or its
   own timeout), through the incoming request's abort signal, so a hung
   upstream costs coffre no more than it costs the app. On Workers that
   signal fires for a hang-up only with the `enable_request_signal`
   compatibility flag, which the app's `wrangler.jsonc` in the examples and
   in what `coffre init` writes carries; a deployment that has not added
   it keeps waiting as before.
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
6. **Redacted.** Every string the request carried, each value of every
   rule's and what each rule made of them (a header's filled template,
   Basic's assembled base64), as stored and as sent (`Headers` trims a
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

**Declared bodies stream.** A body of any credential that says its length
and declares its SHA-256 in a `Content-Digest` (RFC 9530, its `sha-256`
member, `sha-256=:<base64>:`) streams through, never held whole, up to 95
MiB (`MAX_DIGESTED_BODY` in `@coffre/client/dpop`): 99,614,720 bytes, under
the 100 MB (decimal) a Cloudflare zone takes on Free and Pro, so a body
near it gets coffre's 413, which says what to do, and not the zone's. The
SDK and `coffre serve` send it on every body, unless the app set a
`Content-Digest` of its own, which the SDK keeps as it is and the sidecar
adds its `sha-256` to
([workloads](../workloads.md#what-the-sdk-does-on-its-own)), which is what
lets a workload upload a 50 MB Yousign document or a KYC file. coffre
hashes the bytes as they pass (`scanned`, with the handle or session-token
check and the length) and holds back the last of them until the digest
matches. A body with other bytes, short of its length or past it, is cut
off before that last byte, so the upstream, which was told the length,
never gets a complete request, and the app gets a 400 naming why. An
empty body has no last byte to hold back, and its request is whole once its
headers are sent, so it is checked before anything goes. On
Workers, the length goes with the body through `FixedLengthStream`; on
Node, fetch sends the header as given and errors the request when the body
does. A `Content-Digest` whose `sha-256` member is no SHA-256 is a 400; one
with no `sha-256` member (an app's own `sha-512`) declares nothing, and its
body is read whole. A body read whole, up to 1 MiB, must be what its
`Content-Digest` says too.

What this leaves: an upstream that acts on a request before it ends, such
as a multipart part stored as soon as it is read, may act on a body whose
digest then fails. The request that does it carries other bytes than its
proof signed, so it comes from the session's holder, who could have signed
those bytes, or from a copy of a proof read on its way to coffre and sent
first. Bodies with no digest are read whole up to 1 MiB: an older SDK's,
and a person's app, which `coffre run` gives a handle and which sends none
of its own. Past it, a workload's (whose proof signs the body's hash) or
an AWS-signed one's is refused, 413, naming the digest to send; any other
streams, if it says its length.

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
read whole, up to 1 MiB (16 MiB before 0.16), unless they declare a `Content-Digest` (section 4). Equisafe's PutObject past 16 MiB failed on that
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

**A field of the body (after 0.14.3, built).** A few upstreams take their key in
the request's body. Firebase's token refresh, which Gather's API uses,
sends its refresh token as a form field. Cloudflare Turnstile's siteverify
sends its secret as a form or JSON field. `form()` and `json()` name the
field, and a template as `header()` does:

```ts
gather: { upstream: 'https://securetoken.googleapis.com/v1', inject: form('refresh_token', '{GATHER_REFRESH_TOKEN}') },
turnstile: { upstream: 'https://challenges.cloudflare.com/turnstile/v0', inject: form('secret', '{TURNSTILE_SECRET_KEY}') },
```

The app sends the body it always did, with its handle as that field's value:

```
POST /use/gather/token?key=AIzaSy…        grant_type=refresh_token&refresh_token=coffre_use_…
→ https://securetoken.googleapis.com/v1/token?key=AIzaSy…   grant_type=refresh_token&refresh_token=AMf-vB…%2B…
```

Firebase's API key is no secret. It stays in the app's config and in the
query, as the app sends it. coffre reads the body whole, 64 KiB at most,
finds the field, puts the real value in its place, and leaves every other
byte as it was. For a form, that means the field's name as written and the
other pairs untouched, with the value form-encoded. For JSON, only the
value's string is written again, as `JSON.stringify` writes it, so the
spacing, the key order and a number too long for a double keep every digit.
Then fetch sets `Content-Length` from what goes out, and a `Content-Digest`
the request carried is computed again over it (`Repr-Digest`, `Digest` and
`Content-MD5` are dropped, since they would no longer match).

A body is refused, with nothing sent and nothing of it quoted back, when:

| The body | Answer |
|---|---|
| is of another type than the rule's (`application/x-www-form-urlencoded` or `application/json`), another charset than UTF-8, or compressed (`Content-Encoding`) | 415 |
| is over 64 KiB | 413 |
| holds more than 256 fields (a JSON document's strings counting as a name and a value each), or nests deeper than 32, checked before anything is parsed | 400 |
| is no body at all (a GET) | 400 |
| is no JSON, or no JSON object, or no UTF-8 (a byte order mark is taken, and kept) | 400 |
| lacks the field (at the top of a JSON object: `{"data":{"secret":…}}` is no field) | 400 |
| holds the field twice, or another name at the top alike it, which some upstream reads as the field: the same once decoded (`refresh%5Ftoken`, `"\u0073ecret"`), up to a `[` (`refresh_token[]`, `refresh_token[0]`, as PHP and qs read arrays), in another case (`SECRET`, `ſecret`, as Go's JSON folds), or with other punctuation (`refresh.token`, `refresh token`, as PHP reads them) | 400 |
| gives a JSON field as anything but a string | 400 |
| holds the handle anywhere but in the field, in a name or a value, decoded: `%5F` in a form, `\u005f` in JSON, a nested object | 400 |
| holds no handle in the field, or one other than `x-coffre-handle`'s | 401, or 400 |

The rule decides where the value goes, and the app only decides what fills
that one field. So a value never lands in a field the upstream echoes back,
such as Turnstile's `cdata` or a JSON-RPC `id`, however the app writes the
body, and an upstream that echoes the body anyway is redacted as any
answer is (section 4). A shaped placeholder (below) works as in a header:
`json('secret', '{K}')` with `prefix('pk_')` takes `pk_coffre_use_…` in the
field, and nothing else.

On the stable URL, the handle is in the body before the route is known
(section 4, "Which route"). coffre reads a copy of the body
(`request.clone()`) to find it, and sends what it read. So does a route
through another body rule's credential it read as well
(`/use/<project>/<env>/<credential>`, the project named like this one).
A route through any other credential reads the request itself. A workload's session, which carries no handle, has its field
replaced whatever the app put there, as a header rule replaces the
`apiKey: 'coffre'` an SDK wanted. Its proof signs the body the app sent,
whose `Content-Digest` coffre checks before the field is filled, and the
field must be there once, with no session token anywhere else in the body.
SigV4 signs the body's hash, so it takes no body rule; no rule mixes the two.

Every body is read before the handle is checked, since the handle is in
it, so the parse is bounded for anyone at all. A real siteverify or refresh
body is a few hundred bytes and parses in microseconds. 65,000 empty form
pairs or 30,000 nested arrays are refused within 0.1 ms, before any
per-field work. What costs the most is a body under every bound whose 64
KiB is all `%XX` escapes, which the check for a handle decodes. That takes
3.5 ms of CPU on Node 24 on a loaded host. The JSON worst case is 0.5 ms.
A request parses its body once. The one exception is a route
through another body rule's credential of a project named like this one
(`/use/<a>/<b>/<c>`, both body rules), which parses it twice. Nothing adds
a query, and nothing is shared between requests.

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

**A segment of the path (0.16).** Telegram's Bot API takes its token
in the URL's path, `https://api.telegram.org/bot<token>/sendMessage`, and
its files under `/file/bot<token>/<file_path>`. Every SDK builds that URL
from a base URL and the token it holds (grammY, Telegraf, aiogram and
python-telegram-bot alike: `${root}/bot${token}/${method}`). `path()`
names the segment's template, one key in it once:

```ts
telegram: {
  upstream: 'https://api.telegram.org',
  inject: path('bot{TELEGRAM_BOT_TOKEN}'),
  allow: [{ methods: ['POST'], path: '/*/sendMessage' }, { methods: ['GET'], path: '/file/*/**' }],
},
```

The app points its SDK's base URL at the stable URL
(`new Bot(process.env.TELEGRAM_BOT_TOKEN, { client: { apiRoot: 'https://secrets.acme.example/use/telegram' } })`;
Telegraf's `apiRoot` takes a trailing slash, as it resolves `./bot…`
against it), and holds the placeholder as its token:

```
POST /use/telegram/botcoffre_use_…/sendMessage          → https://api.telegram.org/bot123456789:AAE…/sendMessage
GET  /use/telegram/file/botcoffre_use_…/photos/file_0.jpg → https://api.telegram.org/file/bot123456789:AAE…/photos/file_0.jpg
```

- **Which segment.** The first segment under the upstream that the
  template frames: its text before the key and after it, with at least
  one character between, read decoded once, as an allow list reads it
  (`bot…` in `/bot…/sendMessage` and in `/file/bot…/photos/x.jpg`). A
  template of the key alone frames the first segment. A path with none is
  a 400. Its handle must be that whole segment, in the template's shape
  (the placeholder's too, if shaped), as a field's must be the field: the
  handle anywhere else in the URL is refused by the leak check, as before,
  and two different handles are a 400. A workload's session, which
  carries no handle, has whatever its SDK put there replaced
  (`new Bot('coffre', …)` sends `/botcoffre/…`).
- **Before the value.** Routing, the allow list and a narrowed session's
  constraints read the path as the app sent it, placeholder and all
  (`/*/sendMessage` takes `/botcoffre_use_…/sendMessage`). The value goes
  in after them, so it can never change which route, entry or
  environment a request is.
- **As a segment.** The value goes in percent-encoded, every byte but
  letters, digits, `-._~` and `:` (Telegram's tokens are `<bot id>:<35
  characters>`, which go as they are). A value that is empty, or holds
  `/`, `\`, `?`, `#`, `%`, `;`, `..`, a space or a control character, is
  refused with a 409 naming the key and none of the value, with nothing
  sent: encoded or not, a server behind might read it as another path. The
  segment it makes must read as one segment to every server: no dot
  segment (`climbs`, as a request's own segments), and none a server
  drops (`vanishes`, as a `*` of an allow list takes none:
  `path('..{T}')` with `.` is `...`); and the URL that goes out must be
  the one the app sent with that one segment changed, or nothing goes.
- **One rule.** One `path()` per credential, beside any other rules; before
  a `sigv4()`, which signs the path as filled.
- **Shaped placeholders.** aiogram checks its token's shape before it
  sends anything (`<digits>:<anything>`, no whitespace:
  `aiogram/utils/token.py`), and reads the bot's id from it; grammY,
  Telegraf and python-telegram-bot only refuse an empty one. So
  `placeholder: prefix('123456789:')`, the bot's own id (no secret: its
  users see it), gives aiogram `123456789:coffre_use_…`, and the slot is
  then `bot123456789:coffre_use_…` exactly. No new kind of placeholder is
  needed. A route with a `path()` rule takes a prefix with no `/`.
- **What it says, what it logs.** coffre's refusals quote the path as the
  app sent it; the audit's `credential.use` names the upstream's host, as
  for every rule; no log line has the URL. A `Location` is read as a URL
  first, a relative one (`getMe`, `?offset=1`, `#top`, an empty one)
  against the URL the app sent, never the one the value went out in. If
  it is under the upstream, each segment of its path that is the segment
  as it went out, compared decoded once (`%3a` and `%41` are `:` and
  `A`), gets the app's segment back, so the app follows it through the
  proxy with its placeholder
  (`/bot123456789:AAE…/getMe` → `…/use/market/dev/telegram/botcoffre_use_…/getMe`).
  A relative `Location` whose first segment holds a raw colon is read as
  a scheme, as every client reads it: `bot123456789:AAE…/getMe` is the
  scheme `bot123456789:`, nowhere under the upstream, so it is a 502, not
  a path (`./bot123456789:AAE…/getMe` is one). A colon written `%3A` or
  `%3a` is a path, and `%253A`, a colon encoded twice, decodes once to
  `%3A`, which is not the value: the check below refuses it in a path
  and in a query alike (502, nothing of the answer). The check errs shut: a
  value made only of escapes (`%2F%2F%2F%2F`, set through a `query()` rule,
  as `path()` refuses `%`) makes a redirect to `/tg/keep////next` a 502 too,
  as that path reads as the value once decoded.
  Only the path's segments: swapped in the text before it is read,
  `bot123456789%3AAAE…/getMe` would become the scheme `bot123456789:`,
  and a value that is the upstream's own `host:port` would replace its
  authority. A `query()` rule's parameter gets the app's placeholder the
  same way, every other pair of the query left as the upstream wrote it,
  taken from the raw `Location` (`?` to `#`) and redacted before any
  parser reads it: written again through `searchParams`, `echo=%41%42…`,
  a key that is those escapes, would be `echo=AB…`, and the parser's own
  copy encodes `'` as `%27`, so `%41%42'` would be `%41%42%27`; neither
  is a form redaction names. Its spaces go as `%20`, as the parser's
  would: `?cursor=abc #top` without its fragment ends in one, which a
  header's value loses.
  The value anywhere else in it, or in an answer's headers or text body,
  is redacted as any value is (section 4), its encoded form and the whole
  segment included. The path is the parser's, which encodes `"` or a
  space, so a check comes last: the `Location` read as the app's client
  reads it (decoded once, tabs and newlines dropped, `\` as `/`) must
  hold no value, nor any echo of one (section 4's list), read the same
  way, or it is a 502 with nothing of the answer (`/x%41%42"` is
  `/x%41%42%22`, both `/xAB"`; Go's JSON `foo\u003cbar`, for the value
  `foo<bar`, is `foo/u003cbar` in the parsed path, which the echo's own
  reading matches). Whether a form is long enough to mask is decided as
  written, before the reading shortens it: `%41%42%43"`, a key of ten
  characters, reads `ABC"`, which the check still looks for. As with
  `query()`, the URL that goes out holds the
  value, and so does what a platform records of outgoing requests
  (Workers' tracing, which what `coffre init` writes leaves off). The
  other way, the handle rides in the URL the app sends, as a `query()`
  rule's does, so a log of incoming URLs (Workers Logs, which `coffre
  init` turns on) holds the handle, never the value; a handle reaches only
  the environments it was made for, until it ends or is revoked. A
  workload's session puts nothing of its own in the path.
- **In the UI.** The Proxy tab's routes take a Path rule, its template
  checked by the vault's save as code's is at startup.

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
   or `sslmode=disable`, without `insecureUpstreams`). A tunnel with no
   `hosts` dials only an address: whoever writes the value picks its
   host, and a name may resolve to a private address.
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
and tunnel are one group, with one timer. With R the deployment's
`proxy.revokedWithinSeconds` (60 unless set), each check is given
d = min(R ÷ 2, 10 s) to answer, and every R − d (50 seconds by default)
the group opens the database's URL again, as the vault decides it, for all
of them at once, logged as a use. Ten pooled connections cost one read a
check, not ten. A check the vault has not answered within d is a no, so a
stalled vault ends the sessions rather than freeing them. The handle's end ends them too, on a
timer of its own. A new group whose first session came in on a cached URL
checks at once, so the interval always starts from the vault's own
answer. The group lives as long as its sessions. So a revoked handle
and a person's lost grant each end the sessions within the interval and
a check's deadline, R, 60 seconds by default (formal/Tunnel.tla: revoked
just after a check, the next comes 50 seconds later and may take its ten
seconds; 0.15's two settings made it 70): the
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
session of the same handle, and coffre waits, as libpq does, for the
database to close that connection, 5 seconds at most: a VPC Network
binding's socket is open before its connector has dialed, and closed at
once it would send nothing. A guessed key, or another handle's, reaches
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
R, and ends both sockets of every session; the next
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
too long, a minute past its refusal at most: neither a burst nor a slow database gets past
the 32, and a database that never answers holds no slot for good. The
object admits its connections in the order they came, one at a time until
one is in, then four at once: measured on Cloudflare, a pool's 32 made
together each read the URL from the vault and wrote two log entries, all
on the object's one database client, and past 16 they reached their time
to decide together. The first one in leaves the URL in the cache for the
rest. Each has 45 seconds to be decided from its turn. One that has
waited 15 seconds for the first stops waiting for the cache: four go at
once from then, so that one never decided holds up no other for good; the
listener waits 70 seconds for its answer. The time is that long for a
burst of runs, each admitted in an object of its own and each writing to
the one audit chain: 64 together took up to 22 seconds each. The
listener says each refusal once a run, on stderr, with coffre's reason.
Bytes go each way in a loop of reads and writes, not `pipeTo`: on
Workers, piping into a stream of JavaScript's own, as this pipe is, keeps
a promise for each chunk until the pipe ends, and a session that streamed
4.7 GB from the database outgrew the object's 128 MB. The object's name digests the bearer token alone and
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
and the app's driver sees it drop, rather than a query that hangs. A
terminal's Ctrl-C reaches the run's command and the run alike: the run
leaves it to its command (a psql cancels its query through the listener)
and waits for it, and passes a SIGTERM or SIGHUP sent to it alone on to
it. When its command ends, or fails to start, the run revokes its handle
(`DELETE /handles/:id`, which reaches a person's own handles only, a
personal token's included: any of them, the token's scope aside, since a
handle records its person, not the credential that made it). Under a
supervisor that stops processes with SIGINT alone, the run waits for its
command: stop it with SIGTERM, which it passes on. An app
that stops reading (a psql in its pager) keeps its connection: paced, the
listener goes on reading pongs and counts, and coffre sends no more than a
window; with a coffre on Node, which does not pace, the listener stops
reading for the app, and a pong it could not read ends nothing.

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
//   plugins: [credentialProxy({ … tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) } })], with its route, routes/use.$.ts
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

**Verifying, and HMAC (0.14.3, built).** An inbound webhook carries a
signature its provider made with a secret the app shares, an HMAC of the
body. The secret stays in coffre, and the app asks whether a signature is
its. The deployment names the key, how the provider writes the signature,
and whether the app may only check signatures or also make them:

```ts
credentialProxy({
  credentials: { … },
  verifiers: {
    yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }),
    dfns: hmac('DFNS_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }),
    lemonway: hmac('LEMONWAY_WEBHOOK_SECRET', { encoding: 'hex' }),
  },
  signers: { 'iframe-token': hmac('IFRAME_TOKEN_SECRET', { encoding: 'base64url' }) },
})
```

The app passes the body as it came and the header as it is:

```ts
const signature = request.headers['x-yousign-signature-256'];
if (typeof signature !== 'string' || !(await coffre.credential('yousign').verify(request.rawBody, signature))) throw new UnauthorizedException();
```

That is `POST /use/<project>/<env>` with `{ verify: { credential, message,
signature } }`, the message base64url, through `coffre serve`'s listener
(`http://127.0.0.1:7300/use/market/prod`) or the SDK, and the answer is
`{ "valid": true }` or `{ "valid": false }`. A person's app under `coffre
run` calls the same `credential(name).verify` from
`@coffre/client/credential`, with its handle.

| Provider | Header | `hmac(…)` |
|---|---|---|
| Yousign | `x-yousign-signature-256: sha256=<hex>` | `{ encoding: 'hex', prefix: 'sha256=' }` |
| DFNS | `x-dfns-webhook-signature: sha256=<hex>` | `{ encoding: 'hex', prefix: 'sha256=' }` |
| Lemonway, as Equisafe's code checks it | `x-signature: <hex>` | `{ encoding: 'hex' }` |

- **HMAC-SHA256, and nothing more general.** The key is the value's UTF-8
  bytes, as `createHmac('sha256', value)` takes a string. The signature
  is written in `hex` (read in either case), `base64` or `base64url`
  (read with or without padding), after an optional `prefix`, compared
  exactly. coffre decodes it and asks WebCrypto's `verify`, which compares
  in constant time on Node and in workerd (BoringSSL's `CRYPTO_memcmp`).
  A signature of the wrong prefix, encoding or length is `valid: false`,
  and the answer says nothing else. A request past its bound (below) is
  413, whatever it carries, a signature of 100,000 characters included. A scheme of another shape (Stripe's
  `t=…,v1=…`, which signs a timestamp with the body) gets a helper of its
  own when someone needs one, never a template language.
- **The raw body, byte for byte.** A provider signs the bytes it sent. An
  app that parses the JSON and writes it again (`JSON.stringify(req.body)`)
  hashes other bytes whenever the provider's spacing, key order or number
  format differ. Equisafe's DFNS and Lemonway guards do that today, and
  pass the raw body when they move to coffre; its Yousign guard already
  does.
- **Freshness stays in the app.** DFNS puts `timestampSent` in the signed
  body, and its docs refuse an event more than five minutes old. The app
  parses the body anyway, so it checks the time after `valid`, failing
  closed when the field is missing: `Math.abs(now - timestampSent) > 300`
  is false for `NaN`, so write `!(Math.abs(now - timestampSent) <= 300)`.
  coffre answers about the bytes only.
- **A verifier never signs.** A webhook's secret that the app could sign
  with would let whoever holds its session forge the provider's calls to
  the app's own public endpoint, a payment notification included. So
  `sign` refuses a verifier (404). An HMAC among `signers` signs, as its
  scheme writes it (`{ signature: '<prefix><encoded>' }`), and verifies
  too, since it could check a signature by making one: the app's own keys,
  Equisafe's `IFRAME_TOKEN_SECRET` (`payload.signature`, base64url) and
  `DELEGATED_SESSION_SECRET` (an HS256 JWT: the HMAC of
  `<header>.<payload>`, base64url).
- **Bounded.** A message is 64 KiB at most: Equisafe's largest webhook in
  90 days of production was DFNS's, 5,234 bytes (p99 2,272), Yousign's
  2,013. `hmac(…, { maxBytes })` takes up to 1 MiB for a provider whose
  bodies run longer. coffre reads a request up to what the longest of its
  signers and verifiers takes, before it knows who asks, and refuses past
  it with 413, before anything is opened. That read counts against the
  16 MiB of bodies an isolate holds read whole, as any other. On a
  413 the client's `verify` throws, and the app answers the provider
  4xx, so that it stops retrying. The CPU is the body's: about 0.2 ms at
  4 KiB, 3 ms at 512 KiB and 5 ms at 1 MiB on Node, within a Worker's
  10 ms on the Free plan.
- **Opened as a credential's values are, logged once a minute.** A
  webhook comes on a request's path, and the vault is the instance's
  narrowest point, so a verify or an HMAC signature opens its secret as a
  request through a credential opens its key: once per handle or session,
  environment and name for R (60 s), one `secret.read` and one
  `credential.use` entry (`hmac: true`) each time. A warm verify by a
  workload costs its session's one statement and its gate's check, and
  nothing of the vault's; by a handle, nothing of the database's. A cold
  one costs what a proxied request does: one vault call and its
  entries (`request-cost.test.ts`). A private key's signatures stay logged
  one by one, each naming its message: what DFNS's key signs moves money.
- **Not yet.** `POLICY_SEAL_KEY` seals with HMAC-SHA256 too (`v1:` and
  hex), but keyed with the 32 bytes its hex value decodes to, not its
  text: that needs an option saying how the value is written (`key:
  'hex'`), which nobody uses yet. The AES-GCM key Equisafe derives from it
  with HKDF is encryption, which neither `sign` nor `verify` covers.

Lemonway documents no signature on its notifications: its webhook pages
describe a URL, a method and a content type, form-encoded or JSON, with
flat fields (`NotifCategory`, `IntId`, `ExtId`, `Status`), and no header,
secret or algorithm. Equisafe's check (`x-signature`, hex HMAC-SHA256)
matches no scheme Lemonway publishes; Lemon Squeezy, another company,
signs exactly so. Whether Lemonway sends it at all is for Lemonway's
support to say, before the app relies on it.

**Later: SDK credential files.** A JWT signed with a service account's
key, and an SDK that reads a credentials file (Google's service-account
JSON), get helpers of the same kind: a file whose private key is a
placeholder and whose `token_uri` points at coffre, which signs the token
exchange with the real key. That changes app code or its configuration.

## 6. Security

**What an agent with placeholders can still do.** It can use every credential
of the environment, against that credential's upstream, for as long as the
handle lives. It can, for example, call Schumann's API with the real key,
which is the point. It cannot read a value, send one to another host, or
keep using one after the handle is revoked (within R, the deployment's
`proxy.revokedWithinSeconds`) or
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

**Injection** goes into headers, the query, Basic, an AWS signature, or one
named field of a small form or JSON body (section 5). The rule names the
field, so the app decides only what fills it, never where a value goes: a
handle anywhere else in the body is refused. A body coffre fills is read
whole, 64 KiB at most, so a large upload never carries a key in its body.

## 7. Questions, answered

**Latency.** Measured locally: Node 24, the app's runtime and the vault in
one process as in the test suite, a fake upstream on loopback, 200 calls
each after 20 to warm up, median:

| Path | SQLite | Postgres |
|---|---|---|
| Direct to the upstream | 0.39 ms | 0.36 ms |
| Through the proxy, values cached | 0.48 ms | 0.43 ms |
| Through the proxy, values opened (first call of the minute, or `cacheValues: false`) | 7.8 ms | 14.9 ms |

A cached call costs a route match, the handle's lookup (none: the cache
is keyed by the handle) and the header rewrite. An opened call adds the
handle's check (one database read and one vault `access` call) and the
read (one vault `unwrap`, two audit entries). Deployed, add the hop from
the developer's machine to coffre and from coffre to the upstream, which
for a provider in the same region as coffre is close to what the app
would have spent anyway.

**Audit volume.** One opening of a credential's keys per handle about
every 45 seconds while it is used: a vault `secret.read` naming the keys
(purpose `use`, the bulk shape of #242), and a `credential.use` entry
naming the credential and its host, sharing its operation id. An entry
serves R, a minute unless the deployment says (`proxy.revokedWithinSeconds`), from when the vault was asked, and in its
last quarter one request opens the keys again while the others are served
it, so a steady caller meets no lapse. A dev loop that calls Schumann 500
times a minute writes under 3 entries a minute for it, not 1,000. A call per
entry would also take the log's head once per call, which serializes every
request of the instance. And it would run into the vault's bulk limit
(1,000 keys per 15 minutes per person) in under a minute of
tests. The cost: between openings the log says "used schumann from 10:41"
rather than each call, and a revoked handle keeps working for up to the
cache's minute (`proxy: { cacheValues: false }` turns both off). Whatever
is kept, a request sends within R of when its values were decided, or not
at all (503 `late`): a request that paused after they opened goes out
with none.

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
   logged at each step, and already exists. Only an Owner of the project
   issues a token or binding that reads sensitive values (R32, Erwin
   2026-10-21). *Alternative:* a reveal page for Owners behind a fresh
   sign-in.
4. **One handle per run, for all its environments' credentials.**
   *Alternative:* one per credential, if a leaked handle's reach matters
   more than the extra rows.
5. **12 hours, a week at most, never past the personal token that made
   it.**
6. **Logged per credential per handle about every 45 seconds while used**
   (values kept R, 60 s, opened again in its last quarter), not per call:
   see the audit volume above.
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
9. **No DNS pinning yet.** Private addresses are refused however they are
   written (`127.1`, `localhost.`, `[::ffff:a00:1]`). A name that resolves
   to one is the operator's DNS when the operator wrote it: an upstream, or
   a tunnel's `hosts`. A tunnel's URL is a secret's value, which anyone who
   writes the environment picks, so without `hosts` it dials only an
   address (W157).
10. **Redaction of values 8 characters or longer**, in headers and text
    bodies; never a plain value's (0.9).
11. **Bodies read whole, up to 1 MiB** (16 MiB until 0.16), so the
    upstream gets a `Content-Length`. Larger ones stream with the length
    they say, through a credential that signs no hash of them, S3's own
    path (PR 2), a declared `Content-Digest`, or go by a presigned URL.

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

33. **An HMAC's secret is opened as a credential's values are, and logged
    once a minute, where a private key's signatures are logged one by one
    (W189).** A webhook's check is on a request's path, as many a minute as
    the provider sends, and an entry each would be an append to the log,
    under its head, per webhook: the lock every write of the instance
    waits for. The cache holds the secret no longer than a credential's
    key (R), and a revoked handle or a frozen session stops
    at once or within it, as for requests. *Alternative:* an entry per
    verify, naming the body's SHA-256, as `sign` with a private key does.

34. **A verifier is not a signer (W189).** `verifiers` only check; an
    HMAC among `signers` also checks. A webhook's secret that signs would
    let a stolen session forge the provider. *Alternative:* one map, each
    `hmac()` saying what it may do, which reads worse and defaults
    somewhere.

35. **A body rule fills one field its credential names, at the top of the
    body, in a body of 64 KiB, 256 fields and 32 levels at most, every
    other byte as it was (W190,
    Erwin approved 2026-10-26).** `form(name, template)` and
    `json(name, template)`, as `header()` reads. The value replaces the
    field's whole value, as a header rule replaces the whole header. Two
    rules, not one `body()` taking either type: the rule says what the
    upstream takes, and a body of the other type is refused rather than
    guessed at. A JSON field is a top-level name. No real user needs a path,
    and a path adds escaping rules (`a.b` as a key) for nothing. Any other
    name alike the field's (`alike`: up to a `[`, case folded, letters and
    digits alone) is refused as a duplicate. That is one conservative rule
    for the ways PHP, qs and Go read two names as one, not a rule per
    parser. Such an alias never moves the value, which goes only in the
    field the rule names. It only lets the app's own value shadow it. The JSON
    is spliced, not parsed and written again, because writing it again
    changes a number past 2^53 and the bytes a signature or an idempotency
    check may cover. *Alternatives:* a JSON Pointer path, if an upstream
    nests its key; a larger bound, if one sends a larger body.

## 9. Plan

| PR | What |
|---|---|
| 1 | Placeholders in the vault (`people`), handles (`0009_handles`, `POST /api/handles`), the plugin's `use` capability, `credentialProxy` with header, query and Basic, the plan, `coffre run`/`export` placeholders, `@coffre/client/credential`. Built |
| 2 | `sigv4()`: S3 through the proxy, tested with the AWS SDK against a signature-checking fake, and by hand against MinIO. Built |
| 3 | The Postgres tunnel: a socket capability for plugins (`routes.socket`, Node's `upgrade`), the listener in `coffre run`, SCRAM, cancel, revocation mid-session. Built |
| 0.9 E | The stable URL, `/use/<credential>`, from the environments a handle keeps (`0010_handle_places`); `baseUrl` removed. Built |
| 3b | The tunnel on Workers (`WebSocketPair`, `connect()`), one Durable Object per run and database, paced by credit; through a VPC Network binding (`connect`). Built (0.11); to check on a deployed Worker. The privileged-role warning, not yet |
| 4 | Redis through the tunnel |
| 5 | `presign` (built in 0.8.1) and `sign` (0.9 D); `verify` and `hmac()` (built in 0.14.3); SDK credential files |
| 0.9 C | Shaped placeholders, `jwt({ claims })` and `prefix(…)`: DFNS's token through the proxy. Built |
| 0.9 A | Plain values (`0011_plain_values`, `coffre set --plain`, the page's Plain toggle), which deprecate `identifiers`. Built |
| 0.9 B | Values of a person's own: `generate`, reads through `<env>@me`, `coffre run` making them by recipe. Built |
| 0.10 | Sensitivity per key (`0012_sensitive_values`, `coffre set --sensitive`, `coffre mark`, the page's control); `people`, `expose` and `identifiers` removed. Built |
| 0.9 D | Signers, `privateKey(…)`, and `credential(name).sign(message)`: DFNS's user-action key stays in coffre. Built |
| Egress | A credential's `egress`: its requests leave through a VPC Service binding, for an upstream that allowlists addresses (Schuman). Built; untested against a real VPC Service |
| After 0.14.3 | `form()` and `json()`: a key in one field of a small body (section 5). Built |
| 0.17 | `passthrough`: a credential that carries a browser's cookies and redirects in an envelope, so that coffre can be Clerk's Frontend API proxy on brand domains (section 10). Designed, not built |

## 10. Passthrough: a browser's session through the proxy (0.17)

A design for 0.17, written on 2026-11-10 (W368) from Fred's proposal
(Equisafe, "Proxy Clerk via Coffre", v4) and the shape Erwin approved.
Nothing in it is built. 0.16 is unchanged by it.

### The problem, by example

Each Equisafe brand domain, `invest.marque.com` say, is a Clerk satellite.
Today its owner must create a CNAME, `clerk.invest.marque.com`, and many
never do: the domain stays `awaiting_owner`. Clerk's other option is a
Frontend API (FAPI) proxy
([Clerk's guide](https://clerk.com/docs/guides/dashboard/dns-domains/proxy-fapi)).
clerk-js calls `https://invest.marque.com/__auth_proxy/v1/…`, and a
server forwards each call to `https://frontend-api.clerk.dev/v1/…`,
"with the body and all headers intact", plus three of its own:

```http
Clerk-Proxy-Url: https://invest.marque.com/__auth_proxy
Clerk-Secret-Key: sk_live_…
X-Forwarded-For: 203.0.113.7
```

`X-Forwarded-For` must be the end user's IP, read from a header the
server's own CDN sets (Cloudflare's `CF-Connecting-IP`), never the one the
browser sent. Clerk's own proxy, `clerkFrontendApiProxy` in
`@clerk/backend/proxy`, also sets `X-Forwarded-Host` and
`X-Forwarded-Proto`, passes cookies both ways, and rewrites a `Location`
on the FAPI host onto the proxy URL.

The secret key is the instance's master key. Coffre should put it in, so
that neither the brand's Worker nor Equisafe's backend holds it. Today
coffre refuses every part of this, on purpose:

| What the FAPI proxy needs | What coffre does today | Where |
|---|---|---|
| The browser's `Cookie` to Clerk | dropped, with every header about the hop or the caller | `DROPPED`, `credential-proxy.ts:417`; `sent()`, `:2675` |
| The user's IP in `X-Forwarded-For` | dropped (`x-forwarded-*`, `forwarded`, `x-real-ip`, `true-client-ip`, `cf-*`) | `sent()`, `:2675` |
| Clerk's `Set-Cookie` back | dropped | `DROPPED_ANSWER`, `:421` |
| A redirect to Google, or to the brand | 502 off the upstream; on it, rewritten to coffre's `/use/…` | `send()`, `:3175`–`:3216` |
| Clerk's own `Content-Type`, `Cache-Control`, CORS headers | kept, but every answer also gets `cache-control: no-store`, `content-security-policy: sandbox; …`, `nosniff` | `redacted()`, `:3914`–`:3925` |

The reason is one rule: an answer of the proxy is served on coffre's own
origin, so **nothing a browser acts on may cross coffre's origin, in
either direction.** A `Set-Cookie` passed through could set a cookie on
`secrets.acme.example`, beside `__Host-coffre-session`. A `Cookie`
forwarded would send coffre's own session upstream. A `Location` passed
through would make coffre an open redirect.

Passthrough keeps the rule. Nothing a browser acts on crosses coffre's
origin live: it crosses renamed, in an envelope that only coffre's own
client side opens, off coffre's origin.

### The design in one example

A sign-in through Equisafe's client Worker (topology 1, below). The
browser sends the Worker:

```http
POST https://invest.marque.com/__auth_proxy/v1/client/sign_ins?_clerk_js_version=5.103.0
Content-Type: application/x-www-form-urlencoded
Origin: https://invest.marque.com
Cookie: __client_uat=1793000000; __client=eyJhbGc…; _ga=GA1.2.1; app_theme=dark
CF-Connecting-IP: 203.0.113.7
X-Forwarded-For: 198.51.100.9, 203.0.113.7
```

The Worker keeps Clerk's cookies alone, takes the IP from
`CF-Connecting-IP` (the first `X-Forwarded-For` value is the browser's
own), and sends coffre, through its service binding:

```http
POST https://coffre/use/clerk/prod/clerk-fapi/v1/client/sign_ins?_clerk_js_version=5.103.0
Content-Type: application/x-www-form-urlencoded
Origin: https://invest.marque.com
Clerk-Proxy-Url: https://invest.marque.com/__auth_proxy
coffre-pass-cookie: __client_uat=1793000000; __client=eyJhbGc…
coffre-pass-x-forwarded-for: 203.0.113.7
coffre-pass-x-forwarded-host: invest.marque.com
coffre-pass-x-forwarded-proto: https
```

coffre unwraps each `coffre-pass-<name>` into `<name>`, puts the key in
last, and sends Clerk:

```http
POST https://frontend-api.clerk.dev/v1/client/sign_ins?_clerk_js_version=5.103.0
Content-Type: application/x-www-form-urlencoded
Origin: https://invest.marque.com
Clerk-Proxy-Url: https://invest.marque.com/__auth_proxy
Cookie: __client_uat=1793000000; __client=eyJhbGc…
X-Forwarded-For: 203.0.113.7
X-Forwarded-Host: invest.marque.com
X-Forwarded-Proto: https
Clerk-Secret-Key: sk_live_…
```

Clerk answers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache
X-Clerk-Trace-Id: 3f9a…
Set-Cookie: __client=eyJhbGc…; Path=/; Expires=Thu, 11 Nov 2027 12:16:00 GMT; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __client_uat=1793004000; Path=/; Domain=marque.com; Expires=Thu, 11 Nov 2027 12:16:00 GMT; Secure; SameSite=Strict

{"response":{"object":"sign_in_attempt",…},"client":{…}}
```

coffre answers the Worker with every one of Clerk's headers renamed, and
its own plain:

```http
HTTP/1.1 200 OK
coffre-proxy: passthrough
Content-Type: application/octet-stream
Cache-Control: no-store
Content-Security-Policy: sandbox; default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
coffre-upstream-content-type: application/json
coffre-upstream-cache-control: no-cache
coffre-upstream-x-clerk-trace-id: 3f9a…
coffre-set-cookie-0: __client=eyJhbGc…; Path=/; Expires=Thu, 11 Nov 2027 12:16:00 GMT; HttpOnly; Secure; SameSite=Lax
coffre-set-cookie-1: __client_uat=1793004000; Path=/; Domain=marque.com; Expires=Thu, 11 Nov 2027 12:16:00 GMT; Secure; SameSite=Strict

{"response":{"object":"sign_in_attempt",…},"client":{…}}
```

A browser that loaded this from coffre's origin would download an opaque
file: no cookie set, no redirect followed, no CORS grant read, no script
run. The Worker unwraps it (`unwrap` from `@coffre/client`, below) into
Clerk's answer as Clerk sent it, checks the cookies' `Domain`, and answers
the browser on `invest.marque.com`.

### 10.1 The mark

One mark per credential, `passthrough: true` (the name is open). It is
part of the credential's definition, never a row of its own, so a
database writer cannot turn it on:

```ts
credentialProxy({
  credentials: {
    'clerk-fapi': {
      upstream: 'https://frontend-api.clerk.dev',
      inject: header('clerk-secret-key', '{CLERK_SECRET_KEY}'),
      paths: ['/v1/'],
      passthrough: true,
    },
  },
});
```

- **In code,** it is a field of `Credential` (`credential-proxy.ts:191`),
  deployed with the code like `upstream`.
- **In the Proxy tab,** it is a field of a route, `passthrough: boolean`
  in `ProxyRoute` (`packages/core/src/proxy.ts:39`), which
  `canonicalDefinition` (`proxy.ts:135`) writes only when true. Every item
  saved before 0.17 then keeps its canonical bytes and its digest. The
  item's digest is in the vault's sealed index (proxy-ui.md, section 2,
  "Sealed by the vault, not the app"), so a writer who adds
  `"passthrough": true` to a stored item makes it `tampered`, as a writer
  who edits its `upstream` does. The app reads it into the credential
  (`credentialOf`, `credential-proxy.ts:1104`). Saving it takes
  `proxy.edit`, like any other field, and the save's review says it:
  "`clerk-fapi` will pass cookies, the caller's address and redirects, in
  coffre's envelope". The mark sends no key anywhere new: the key still
  goes only to the route's upstream.
- **A plan says it.** `GET /use/<place>` (`plan`, `credential-proxy.ts:1154`)
  gains `passthrough: ["clerk-fapi"]` beside `credentials`, for the
  sidecar (section 10.4). A client of 0.16 ignores the field.

A passthrough route still has its upstream, its allow list, its
`limit`, its redaction and its log entries, exactly as any other. The
mark changes the headers in and out, and the redirect rule, nothing else.

Mixed versions, during a deploy or with a CLI newer than its server:

| Who is older | What happens | Safe? |
|---|---|---|
| A 0.16 vault, a 0.17 app | the save is refused, `no field "passthrough"` (`only()`, `proxy.ts:143`) | yes: nothing saved |
| A 0.16 app isolate reads a 0.17 item | it ignores the field and serves an ordinary route: `Set-Cookie` dropped, off-upstream redirects 502 | yes, closed: Clerk fails for the minutes of the deploy |
| A 0.17 sidecar, a 0.16 server | the plan names no passthrough credential, so the sidecar wraps and unwraps nothing (section 10.4) | yes: as 0.16 |

### 10.2 Requests: `coffre-pass-<name>`

On a passthrough credential:

1. Plain headers go on as today, through `sent()`. A plain `Cookie`,
   `X-Forwarded-For` or `CF-Connecting-IP` is still dropped. That is the
   point of the prefix: on Workers, the request coffre receives carries
   `CF-Connecting-IP`, written by Cloudflare's edge for whoever called
   coffre (the backend's pod, on the sidecar path), and whatever
   `X-Forwarded-For` the hops before it wrote; a browser that reaches
   coffre carries coffre's own cookie. Only a
   header the caller wrote on purpose, under a name no browser or CDN
   writes, may stand in for the end user.
2. Each `coffre-pass-<name>: <value>` goes on as `<name>: <value>`,
   replacing a plain header of the same name. No list says which names
   may pass: ordinary headers (`Clerk-Proxy-Url`, `Origin`,
   `User-Agent`) already pass plain, so the prefix is needed only for the
   few `sent()` drops as naming the caller. The exception is a short list
   of names that would break or forge the hop itself: `host`, `connection`,
   `keep-alive`, `proxy-connection`, `proxy-authorization`, `te`,
   `trailer`, `transfer-encoding`, `upgrade`, `content-length`, `expect`,
   `cdn-loop` (Cloudflare's loop detection), `x-coffre-handle`, `cf-*` and
   `coffre-*`. Wrapped, any of them is a 400 naming it: an app that wraps
   `Host` has a bug it should see.
3. The credential's rules then set what they set (`send()`,
   `credential-proxy.ts:3074`), replacing whatever the caller sent under
   that name, plain or wrapped. `coffre-pass-clerk-secret-key: x` reaches
   Clerk as the real key, once.
4. Every check that reads what goes upstream reads the unwrapped headers:
   the unwrap is in `outbound()` (`credential-proxy.ts:2462`), so the
   method override check (`overridden()`, `:2429`: a wrapped
   `X-HTTP-Method-Override: DELETE` is refused as a plain one is) and the
   leak check (`:3134`: a handle or session token in a wrapped cookie is a
   400) see `Cookie`, not `coffre-pass-cookie`.
5. Through a key-bound session, only the headers the proof signs go on
   (`hdr`, `outbound(request, signed)`), by the name the proof signed, the
   wrapped one. A `coffre-pass-*` header added on the way, unsigned, is
   dropped. A binding's call has no `hdr`, so every one it sends counts.

On every other credential, `coffre-pass-*` is dropped, never sent under
either name (today it would go on as an ordinary header, `sent()`). An app
or a sidecar that wraps by mistake leaks nothing.

coffre does not check what a wrapped header says: whether
`X-Forwarded-For` is one valid address (Fred's spec had a 400 for two),
or whether `Clerk-Proxy-Url` names a brand. The caller could already send
any ordinary header, and whatever it says, Clerk is the only one who
reads it. What it may say is the app's to check (section 10.5).

### 10.3 Answers: `coffre-upstream-<name>` and `coffre-set-cookie-<n>`

On a passthrough credential, the answer is built from the upstream's like
this, in `redacted()` (`credential-proxy.ts:3914`):

- **`coffre-proxy: passthrough`.** coffre's refusals already carry
  `coffre-proxy: refused` (`failure()`, `:4314`) "so the app can tell them
  from the upstream's" (section 4). Today an upstream can send that header
  itself, since nothing drops it; from 0.17, an upstream's own
  `coffre-proxy` is dropped on every answer, passthrough or not. Then
  `passthrough` means "the upstream's answer, in the envelope", and its
  absence means coffre's own: a proxy refusal, or a workload's
  (`refusedWith`, `plugins.ts:356`, which carries no `coffre-proxy` at all).
- **Every upstream header, renamed** `coffre-upstream-<name>`, its value
  redacted as every header is today (`whole()`). No list of dangerous
  headers to keep: `Location`, `Set-Cookie`, `Content-Security-Policy`,
  `Access-Control-Allow-Origin`, `Refresh`, `Link`, and whatever browsers
  act on next year all cross dead. The only headers not passed are those
  about the hop or the bytes as fetch decoded them, dropped as today:
  `connection`, `keep-alive`, `transfer-encoding`, `upgrade`, `trailer`,
  `content-length`, `content-encoding`.
- **Each `Set-Cookie` apart,** as `coffre-set-cookie-0`,
  `coffre-set-cookie-1`, … in the upstream's order, read with
  `getSetCookie()`.
- **coffre's own headers, plain:** `cache-control: no-store`, the sandbox
  CSP, `nosniff`, as today, and `content-type: application/octet-stream`,
  since the upstream's type is renamed. The body is the upstream's,
  redacted by the upstream's type, as today.
- **A redirect keeps its status** and goes back as
  `coffre-upstream-location`, neither followed, rewritten nor refused.
  The check that a `Location` quotes no value in a form coffre does not
  mask (`:3213`) stays, and is a 502 as today: the value would leave in it
  otherwise. FAPI has no reason to quote the secret key.

**Why every `Set-Cookie` needs its own header.** A `Headers` object
joins repeated headers with `", "`, which is lossless for every field but
`Set-Cookie` (RFC 9110, section 5.3), and the only one Fetch keeps apart
is `Set-Cookie` itself. A renamed copy is an ordinary header, so two of
them would arrive as one:

```http
coffre-upstream-set-cookie: __client=eyJhbGc…; Expires=Thu, 11 Nov 2027 12:16:00 GMT; HttpOnly, __client_uat=1793004000; Domain=marque.com
```

and no split can tell the comma in `Thu, 11 Nov` from the one between the
cookies. Numbered headers keep each cookie whole, byte for byte.

**Why `coffre-set-cookie-<n>` and not `coffre-upstream-set-cookie-<n>`.**
An upstream may send a header literally named `set-cookie-0`. Under the
`coffre-upstream-` prefix it would be `coffre-upstream-set-cookie-0`, the
same name as the first cookie. A prefix of its own, which no renamed
header can take, has no such case and needs no rule against it.

The unwrap, in `@coffre/client` and in the sidecar alike, is then:

1. No `coffre-proxy: passthrough`: coffre's own answer. Leave it alone.
2. Otherwise, status, reason and body as they are; for each
   `coffre-upstream-<name>`, a `<name>`; for each `coffre-set-cookie-<n>`,
   in increasing `n`, one `set-cookie`, appended; nothing else (coffre's
   CSP, `no-store`, `octet-stream`, `dpop-nonce`, the marker).

**One wire format on every path.** On the binding path no browser ever
sees coffre's answer: the Worker does. The envelope stays there all the
same, for three reasons, and none was found against it:

- **The proxy has one answer.** It does not know how its caller came in,
  and should not: "the proxy's code is the same; only the authentication
  differs" (workload-access.md, section 9.2). A plain answer for bindings
  would be a second shape, tested twice, and coffre's own `no-store` and
  sandbox CSP would have to come off on that path alone, a rule about
  what protects coffre's origin that depends on the way in.
- **A mistake fails closed.** A Worker that writes `return
  env.COFFRE.fetch(request)` on its `/__auth_proxy` route would, without
  the envelope, serve Clerk's cookies and redirects live on the brand,
  unchecked. With it, the browser gets an opaque file and the first test
  fails.
- **It costs one rename per header.** No body is copied, and the CPU is
  a few string operations per answer.

### 10.4 Coffre's client side unwraps, so apps see plain HTTP

**`@coffre/client`** gains two helpers, which work over any fetch (a
binding's, a session's, a handle's):

```ts
import { wrap, unwrap } from '@coffre/client/passthrough';

// wrap: drops every `coffre-*` header the request carries (a browser's included),
// then renames cookie, forwarded, x-forwarded-*, x-real-ip and true-client-ip to coffre-pass-<name>.
const answer = await env.COFFRE.fetch(wrap(request));
// unwrap: the upstream's answer as it sent it, every Set-Cookie apart; null for coffre's own.
const clerk = unwrap(answer);
if (clerk === null) return failed(answer);        // a 403, 429 or 503 of coffre's: log it, never show it
```

`wrap` drops every `coffre-*` header first because a Worker that copies
the browser's headers would otherwise forward a browser's
`coffre-pass-x-forwarded-for: 1.2.3.4`, which coffre would believe. An
app that wants to pass another header (`coffre-pass-authorization`, say)
sets it after `wrap`.

**`coffre serve`**, the sidecar on `127.0.0.1` (`forwarder`,
`packages/cli/src/workload.ts:159`), does the same without the app
knowing, for the credentials the plan marks (`passthrough`, section
10.1), and only those:

- It reads the plan of each place it serves at start, and again every R
  (`proxy.revokedWithinSeconds`, 60 s).
- A request to a marked credential is wrapped before the sidecar's own
  filter. Today that filter drops `Cookie` (`UNSIGNED_HEADERS`,
  `packages/client/src/dpop.ts:47`, which the sidecar's `DROPPED`
  includes, `workload.ts:148`); wrapped, the cookie goes as
  `coffre-pass-cookie`, which the proof signs like any header the app set.
- An answer with `coffre-proxy: passthrough` on a marked credential is
  unwrapped into plain headers, `Set-Cookie` each apart, as today's
  forwarder already writes them (`getSetCookie()`, `workload.ts:240`). The
  sidecar then sets `coffre-proxy: passthrough` on it, last, so that the
  app can tell Clerk's 403 from coffre's: coffre's own answers reach the
  app as they are, with `coffre-proxy: refused` or none. Set last, the
  marker replaces any upstream header of that name, which never reaches
  the app.
- On any other credential, it does what it does today.

Why only marked credentials. A sidecar is often newer than its server. A
0.17 sidecar that wrapped every request for a 0.16 server would turn the
app's cookies into `coffre-pass-cookie`, which 0.16 forwards to every
upstream as an ordinary header. And one that unwrapped every answer would
let any upstream behind a 0.16 server, which drops no `coffre-proxy`, forge
the envelope and set the app's cookies. With the plan, a 0.16 server names
no passthrough credential, and a stale plan fails closed both ways: a
credential newly marked gets no cookie for up to a minute; one newly
unmarked gets `coffre-pass-*`, which coffre drops, and an answer with no
marker, which the sidecar leaves alone.

**The checks that need the brands stay with the app.** Only the app
knows which hosts are its brands and which origins its sign-ins may
redirect to. Section 10.5 lists what it must check.

### 10.5 Two topologies

Both are settled (Erwin). The credential is the same in both: `clerk-fapi`,
above, in an environment holding the Clerk key.

**1. Equisafe's own workspaces: the brand Worker binds coffre.**

```
browser ──▶ client Worker (invest.marque.com/__auth_proxy/*) ══ service binding ══▶ coffre (CoffreWorkload) ──▶ frontend-api.clerk.dev
```

Everything is on Cloudflare, and the Worker holds no secret: its
`wrangler.jsonc` binds coffre's `CoffreWorkload` entrypoint with `props`
naming its service (workload-access.md, section 9.2):

```jsonc
"services": [{ "binding": "COFFRE", "service": "coffre", "entrypoint": "CoffreWorkload", "props": { "service": "client-worker-prod" } }]
```

**This path does not serve the proxy today.** On `main`,
`CoffreWorkload.fetch` answers 501, "coffre's workload entrypoint is not
built yet" (`packages/server/src/cloudflare-workload.ts:10`–`:14`). What
it would call is built and tested in process: `bindingRoute`
(`packages/server/src/plugins.ts:453`), which runs the plugin with
`workloadFromBinding` (`:467`) as its caller, and the proxy takes that
caller as any workload (`workloadForward`, `credential-proxy.ts:2730`;
`credential-proxy-ui-workload.test.ts` and `ways-in-cost.test.ts` call
`bindingRoute` directly). The entrypoint that reads `this.ctx.props` and
calls it is workload-access.md's PR 6, draft #300 (W164), last updated
2026-10-24 and waiting on PR 1d. So topology 1 needs #300 merged first.
Passthrough itself needs nothing more on that path: a binding's request
reaches `send()` like any other, with no `hdr`, so every wrapped header
it sends counts; #300 sends its answers through `respond`, whose security
headers are coffre's own and plain.

What §9.2 asks of a binding, for this Worker:

- **The same Cloudflare account as coffre.** Service bindings do not
  cross accounts; a Worker elsewhere uses `enrollment` and a session,
  which works the same through `@coffre/client`.
- **Whoever deploys Workers to the account can set any `props`**, and so
  act as `client-worker-prod`. The account's deployers are this path's
  trust root.
- **Preview builds keep their bindings.** With Workers Builds, a branch's
  preview runs with production's `props`, so whoever pushes a branch could
  call Clerk FAPI with production's key. The Worker turns off
  non-production branch builds, or gives previews a wrangler environment
  of their own, bound to a service with its own binding, on a Clerk
  development instance.
- **`props` need wrangler deploys**: as of 2026-10, Cloudflare's API and
  Terraform may not carry them.
- **A binding reaches whole environments** (its service's grants; the
  binding's policy, `BindingPolicy` in
  `packages/core/src/identity/workloads.ts:677`, names no credential).
  A Worker whose service reaches `backend/prod` could use every credential
  there, Stripe's included. So the Clerk key moves to an environment of
  its own, `clerk/prod` in the example, which the Worker's service and
  the backend's both reach, and nothing else of the backend's does.

The Worker's route, in about twenty lines:

```ts
// apps/client/worker/index.ts (Equisafe's)
import { wrap, unwrap } from '@coffre/client/passthrough';

const PROXY = '/__auth_proxy';
const FAPI = 'frontend-api.clerk.dev';

async function authProxy(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (!(await isActiveBrand(env, url.host))) return new Response(null, { status: 404 });   // no open proxy
  const headers = new Headers(request.headers);
  headers.set('cookie', clerkCookies(request.headers.get('cookie')));   // Clerk's alone, never the app's
  headers.set('x-forwarded-for', request.headers.get('cf-connecting-ip')!);  // never the browser's X-Forwarded-For
  headers.set('x-forwarded-host', url.host);
  headers.set('x-forwarded-proto', 'https');
  headers.set('clerk-proxy-url', `https://${url.host}${PROXY}`);       // from the checked host, never the browser
  const target = `https://coffre/use/clerk/prod/clerk-fapi${url.pathname.slice(PROXY.length)}${url.search}`;
  const answer = await env.COFFRE.fetch(wrap(new Request(target, { method: request.method, headers, body: request.body })));
  const clerk = unwrap(answer);
  if (clerk === null) return new Response(null, { status: 502 });      // coffre refused: logged, never shown
  return checked(clerk, url.host);                                      // Location and Domain, below
}
```

**2. SDK customers building their own frontend: through Equisafe's backend.**

```
browser ──▶ customer's edge (/__auth_proxy/*) ──▶ Equisafe backend /__auth_proxy ──▶ coffre serve (127.0.0.1) ──▶ coffre ──▶ frontend-api.clerk.dev
```

The backend's route does what the Worker does, against its sidecar,
`http://127.0.0.1:7300/use/clerk/prod/clerk-fapi/…`, with plain `Cookie`
and `X-Forwarded-For`: the sidecar wraps and unwraps (section 10.4). Two
things differ. The backend is not behind Cloudflare's edge itself, so the
user's IP comes from a header its own load balancer sets and that the
backend trusts only from it, never the leftmost `X-Forwarded-For`. And the
brand host comes from the customer's edge, so the backend accepts the
route only from that edge (a shared header, or mTLS), and checks the host
against its active brand domains.

**What the app checks, on either path.** coffre forwards what it is
given and gives back what Clerk said; these are the app's, because only
it knows its brands:

| Check | Rule | Example refused |
|---|---|---|
| The host | an active brand domain of a workspace, else 404 | `evil.example/__auth_proxy/v1/client` |
| Cookies sent | Clerk's alone, by name (`__client`, `__session`, `__clerk_*`, with their instance suffixes); the list is Clerk's to change, so it lives in one place, tested against Clerk's development instance | the app's `app_theme`, Google Analytics' `_ga` |
| The user's IP | `CF-Connecting-IP` (Worker) or the backend's own load balancer's header, one address | the browser's `X-Forwarded-For: 198.51.100.9` |
| `Clerk-Proxy-Url`, `X-Forwarded-Host` | written from the checked host, never copied from the browser | a browser's `Clerk-Proxy-Url: https://other-brand.example/__auth_proxy` |
| A `coffre-*` header from the browser | dropped (`wrap` does it) | `coffre-pass-x-forwarded-for: 1.2.3.4` |
| `Location` | on the FAPI host (or relative, resolved against it): rewritten onto `https://<brand><PROXY>`, as `clerkFrontendApiProxy` does; on the brand host: kept; on a listed origin (`accounts.google.com`, the primary `client.equisafe.io` for satellite sync): kept; else 502 | `Location: https://evil.example/` |
| `Set-Cookie`'s `Domain` | absent, or one the brand host domain-matches (RFC 6265, section 5.1.3), else the cookie is dropped | `Domain=equisafe.io` on `invest.marque.com` |
| coffre's own answer | logged and answered 502, its message never shown: it names environments and credentials | `{"error":"credential_proxy","message":"…clerk/prod…"}` |
| The sidecar's marker | `coffre-proxy: passthrough` dropped before the browser | – |

clerk-js, given a `proxyUrl`, also loads its own script and `@clerk/ui`
from it, `https://invest.marque.com/__auth_proxy/npm/@clerk/clerk-js@5/dist/clerk.browser.js`
(`loadClerkJsScript.ts` in `@clerk/shared`). That takes no key, is a few
hundred kilobytes a page load, and is cacheable; through coffre it would
be scanned for the key and answered `no-store`. So `clerk-fapi` allows
`/v1/` alone, and the Worker serves `/npm/` itself (from Clerk's CDN, or
`clerkJSUrl` pointing there).

### 10.6 Open points, with numbers

**(a) The audit volume.** Fred's estimate counts one `/use` and one log
entry per FAPI call: clerk-js refreshes its session token about once a
minute per tab, so 1,000 open tabs make about 17 calls a second, 20 with
the rest, 1.5 million a day. Logged one each, at today's 800 bytes a
logged use (config.md, section 2.9: the use's row, its share of the
audit tree, the reads' projection and its indexes), that is 1.2 GB a day,
440 GB a year, every day kept by default (config.md, Q6); the
use's own row alone, 141 bytes, is 211 MB a day.

That is not what happens: two caches stand between a call and an entry.

- **The proxy keeps the values** for `cacheMs`, R, 60 s, per app isolate
  and caller (`valuesFor`, `credential-proxy.ts:3403`; the key is the
  binding or session, the place and the credential, `cacheKey`, `:3385`),
  and asks the vault again from 45 s on (`refreshWindow`, min(R ÷ 4,
  15 s)). A steady stream of calls through one binding makes at most one
  vault use every 45 s per isolate: 1,920 a day, whatever the number of
  tabs.
- **The vault covers repeats**: a use of the same credential, key, place,
  purpose and route within 60 s, in the same vault isolate, writes no
  entry (`audit.repeatsWithinSeconds`, config.md, section 2.3).

So entries a day are at most 1,920 × I, I the app isolates serving the
Worker's calls at once, and fewer with covers. At I = 10, 19,200 entries,
15 MB a day, 5.6 GB a year; at I = 100, 154 MB a day, 56 GB a year. I is
not measured: it is Cloudflare's to pick, and grows with colos and load,
not with tabs one for one. It is the one number to read in the first week
(the log's entries for `clerk-fapi`, a day).

What does grow with tabs is per-call work, not storage: each call checks
its caller live, one Postgres statement for a binding (`callBindings`,
`plugins.ts:484`, in `workloadFromBinding`; a session's statement and its
gate, workload-access.md, section 5.3), and redacts Clerk's JSON. At 20
calls a second that is 1.7 million statements a day, each an indexed
lookup that stays flat as the log grows (R48), and far under R44's 1,000
uses a second.

The options, for if I turns out large:

| Option | Storage | Evidence | R48 |
|---|---|---|---|
| **Keep, as built (recommended)** | 15 to 154 MB a day, above | every value use stays in the log | flat (0057's day-bound cover check, `use-days.alone.ts`) |
| Retention, `audit.keepUsesDays` (config.md, Q6) | a deployment's choice, for every key alike | the oldest days go | flat |
| A longer cover, `audit.repeatsWithinSeconds` up to 3,600 | little: a cover also ends at each refresh of the bulk cap's row, 60 s at the default window (config.md, section 2.3) | coarser | flat |
| Sampling | arbitrary | a log that misses uses breaks R53's replay, which decides as live did | – |

Recommendation: keep. No mechanism of its own: the cache and the covers
already make the log grow with isolates, not with calls.

**(b) Does Clerk check `Clerk-Proxy-Url`?** Clerk's guide does not say.
It says the proxy URL is validated when it is set on a domain (the
Backend API's `PATCH /v1/domains/{id}`), and Clerk's own proxy writes the
header from each request's forwarded host, which suggests FAPI finds the
domain by it. One community report, unverified, has FAPI answering
`host_invalid` when the host did not match the instance's domain.
Recommendation: a ten-minute check on Clerk's development instance before
building, `GET /v1/environment` with a `Clerk-Proxy-Url` of a host no
domain registered, and the doc updated with what it answers. The design
does not depend on it: the app writes the header from a host it checked.
If Clerk does not check it, whoever holds the binding can act as any of
the instance's proxies, which is what the binding grants anyway.

**(c) Bodies and streaming.** FAPI's requests are small forms (a sign-in,
a sign-up, a token refresh: under 4 KB); the one large one is a profile
image, `POST /v1/me/profile_image`, multipart, a few MB. The proxy's
bounds today (section 4, step 4):

| Path | A body up to 1 MiB | Larger |
|---|---|---|
| Binding (no proof) | read whole (`BODY_READ_WHOLE_BYTES`, `packages/core/src/memory.ts:76`) | streams up to 5 GiB when it says its `Content-Length`, which a header rule signs nothing of (`carriedAs`, `credential-proxy.ts:2496`); without one, 413 |
| Sidecar (a session's proof signs it) | read whole by the sidecar, its digest declared | the same, up to 95 MiB (`MAX_DIGESTED_BODY`, `packages/client/src/dpop.ts:184`) |

So a Worker that forwards a profile image keeps its `Content-Length`;
the binding test sends 2 MiB to check it. Answers stream, with no bound
of coffre's, redacted as they pass (a JSON body is scanned for the key).
No time bound either (config.md, Q7): the upstream request ends with the
caller's. Nothing here needs a new limit.

### 10.7 What the implementation tests

- A plain `Cookie` never reaches the upstream, on a passthrough credential
  or any other; `coffre-pass-cookie` does, as `Cookie`, on a passthrough
  one only.
- A plain `X-Forwarded-For` (and `CF-Connecting-IP`, `Forwarded`) never
  reaches the upstream; the wrapped one does, replacing nothing else.
- No live `Set-Cookie`, `Location`, `Content-Security-Policy` of the
  upstream's, or `Access-Control-*` ever leaves coffre: an upstream that
  sends all of them, with a 302 to a foreign host, gets an answer with
  status 302, `coffre-proxy: passthrough`, each one renamed, coffre's
  sandbox CSP, `no-store`, `nosniff` and `octet-stream`, and no 502.
- A credential without `passthrough` behaves as today: the existing suite
  passes unchanged, plus `coffre-pass-*` dropped and an upstream's own
  `coffre-proxy` header dropped.
- Two cookies survive the round trip, one carrying `Expires=Thu, 11 Nov
  2027 12:16:00 GMT`: the app sees exactly two `Set-Cookie`, byte for
  byte, through `unwrap` and through the sidecar.
- An upstream header named `set-cookie-0` comes back as
  `coffre-upstream-set-cookie-0` and does not become a cookie.
- Injected headers beat the caller's: `coffre-pass-clerk-secret-key` and
  a plain `clerk-secret-key` both reach the upstream as the real key, once.
- A wrapped hop header (`coffre-pass-host`, `-content-length`,
  `-transfer-encoding`, `-x-coffre-handle`, `-cf-connecting-ip`) is a 400
  naming it.
- A handle or session token inside a wrapped header is refused, as in a
  plain one; a wrapped `X-HTTP-Method-Override` the allow list does not
  take is refused, as a plain one is.
- Through a session, a `coffre-pass-*` the proof does not sign is
  dropped.
- A key echoed in an upstream header is redacted in its renamed copy.
- coffre's own refusals on a passthrough credential (403, 429, 503) carry
  no `coffre-proxy: passthrough`; `unwrap` returns null; the sidecar
  passes them as they are.
- A forged `"passthrough": true` written into a stored UI item is
  `tampered`; a 0.16 vault refuses saving it.
- The sidecar wraps nothing for a credential its plan does not mark, and
  against a server whose plan has no `passthrough`.
- The binding path, end to end: two Workers in workerd (as #300's
  `workload-caller-worker.ts` and `workload-coffre-worker.ts`), the
  caller's `authProxy` against a fake FAPI: cookies both ways, a 302 onto
  the FAPI host rewritten by the app, a 2 MiB body with its length.
- The sidecar path, end to end: `coffre serve` against the Node example
  and the same fake, the app sending plain `Cookie` and `X-Forwarded-For`
  and reading plain `Set-Cookie` and `Location`.
- Conformance (`@coffre/conformance`) holds a deployment to it: through a
  passthrough credential, no answer carries a live `Set-Cookie` or
  `Location`.

**The formal models.** Passthrough takes no lock, opens no transaction and
changes no use, so the locking model (`formal/Coffre.tla`) is untouched.
Two models read nearby, and both hold as they are. `formal/Routing.tla`
asks where a key may go, with the definition's body sealed by its
version: the mark is part of that body, so a forged mark is a forged body,
refused like a forged host, and the mark sends the key nowhere new.
`formal/Workload.tla`'s `OnlySignedHeadersForwarded` holds because the
unwrap runs on the headers the proof signed, by their wrapped names. The
Lean proofs (`formal/lean`) cover access rules, the vault's decision, the
AAD and the chain verifier, none of which changes.

### 10.8 The build

| PR | What |
|---|---|
| A | `passthrough` on `Credential` and `ProxyRoute` (canonical only when true), the request unwrap in `outbound()`, the envelope in `redacted()`, `coffre-pass-*` and an upstream's `coffre-proxy` dropped everywhere else, the plan's `passthrough` list, the tests above but the sidecar's, conformance |
| B | `@coffre/client/passthrough`: `wrap`, `unwrap` |
| C | `coffre serve` wraps and unwraps by the plan |
| D | The Proxy tab's toggle and its line in the save's review |
| — | Topology 1 also needs #300 (the `CoffreWorkload` entrypoint), merged before A's binding test can run in workerd |

**What changed from Fred's proposal.** His `relay: { cookies, clientIp,
headers, redirects }` becomes one mark: four switches would be four
combinations to test and explain, and each half-open one (cookies but no
redirects) breaks Clerk anyway. His `x-coffre-*` names become
`coffre-pass-*` and `coffre-upstream-*` (RFC 6648 retires `X-`), and his
`x-coffre-set-cookie`, one per cookie, becomes numbered headers, which a
`Headers` object cannot join. His list of headers that pass
(`relay.headers`) is not needed: ordinary headers already pass. His
single-IP check and `callers` list are not coffre's: what a caller may
say to Clerk is the app's to check, and who may use the credential is
already its environment's grants.

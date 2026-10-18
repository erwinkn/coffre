# Placeholders, and the credential proxy

A design for 0.8, written on 2026-10-18 (W125), from Erwin's R11 and R13.
PR 1 is built: placeholders for people, handles, the proxy's HTTP shapes
(a header, a query parameter, Basic) and `coffre run`'s side of it. PR 2
adds SigV4, for S3. PR 3 adds the Postgres tunnel, on Node (section 9).
0.9 (W127) adds the stable URL, `/use/<credential>`, and removes
`baseUrl` (section 4). The decisions in section 8
were taken on the recommended option while Erwin was away (R10), and each
is his to revisit. 0.9 closes the gaps that kept keys on `expose`
(section 2, "What replaces `expose`").

## 1. What it is for

An agent on a developer's machine runs the backend and its tests. The
backend needs Schumann's API key, an S3 key pair and a database password.
Until now `coffre run market/dev -- pnpm dev` put those values in its
environment, and the agent could print them, paste them into a prompt or
commit them. With placeholders it holds none of them:

```sh
$ coffre run market/dev -- pnpm dev
coffre: placeholders for market/dev: schumann, s3 through https://secrets.acme.example/use; the handle lasts 12 hours (`coffre tokens` lists it)
coffre: exposed as they are, by the deployment: STRIPE_WEBHOOK_SECRET
coffre: left out, neither proxied nor exposed: SENTRY_DSN
```

The app's environment, as the backend sees it:

```sh
SCHUMANN_API_KEY=coffre_use_Qm9Y…            # the handle, where the key was
STRIPE_WEBHOOK_SECRET=whsec_local_…          # exposed: a local-only value
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

**Two delivery modes (R13).** Who asks decides what a read hands back:

| Who | What a read opens | How |
|---|---|---|
| A person, on any credential of theirs: a browser session, a `coffre login`, a personal token, an MCP connection | **Placeholders.** Values are opened only for coffre to use for them | The vault refuses `reveal`, `run` and `compare` reads to any `user:` principal (`stand_ins`), and allows `use`, `expose` and a fork's `copy` |
| A service account: a service token, a CI run's or a cluster's ID token | **Values**, as before | Unchanged: CI and production read their environment once, at full speed |

The rule is in the vault, the one place every read goes through, not in
the CLI or the API's routes. `coffre get`, the UI's reveal, `POST
/api/reveals`, the Vault KV plugin and MCP's `reveal_secret_values` and
`show_secret_value` all reach the vault's `unwrap`, so all are refused the
same way, and each refusal is in the vault's log. So is an import's dry
run (`compare`): its `changed` or `unchanged` tells whoever sent a guess
whether it was right. A fork's `copy` hands nothing back, and stays. A deployment turns it on in its vault's
configuration (`people: 'stand-ins'`). Left out, it is `values`, as in
0.7 (decision 1).

**A handle** (`coffre_use_…`, 32 random bytes) is what a person's app
holds in place of a value. It is a credential row of its own kind
(migration `0009_handles`, which only widens a check):

- It acts as its person, within its scope, as a personal token does:
  `viewer` on each environment it was made for, and on each parent a fork
  of them inherits from that the person reads too, so inherited keys work
  through it. `market/dev@me` is scoped as `market/dev`, which is what a
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
  expose: { 'market/local': 'all', 'market/dev': ['STRIPE_WEBHOOK_SECRET'] },
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
  configuration, still works in 0.9 and is deprecated: it held only an
  environment's own value, so a fork that inherited `TWILIO_SID` got the
  handle for it. It goes in a later release.

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
  (`openValues`). So a person gets it under placeholders (`coffre get`, a
  reveal, `coffre run` and `export` through the plan), it is in no
  `secret.read` entry, and it counts towards no bulk limit. The proxy
  leaves it unredacted in an upstream's answer: Twilio quotes the account
  back in every one, and a rule made of plain values alone is not redacted
  either. The ciphertext stays for what opens values through
  the vault: a reference, KEK rotation.
- **A write says it, every time.** `{ "value": "…", "plain": true }` in
  `PATCH /secrets/…`; any other write is a secret, so writing over a plain
  value without `--plain` makes the key secret again, and that needs only
  write. Its version and its `secret.write` entry say `plain`. A rollback
  to a plain version is plain again: that value was shown already. A
  fork's copy keeps it plain.
- **Making a stored secret plain discloses it**, so it is a reveal and a
  write: the client reads the value (an audited `secret.read`), then writes
  it plain with the version it `replaces`, refused if someone wrote since.
  Under placeholders a person has no reveal, so a person never publishes a
  value they cannot read: they type it again, plain (decision 17). A
  service account may.
- **Never in a personal config.** Its values are its owner's alone (R8):
  a plain write there is refused. A plain value of the environment it
  overrides reaches its owner as any reader of that environment.

**Values of a person's own (0.9).** A backend that refuses to boot without
its own keys (a key that seals its local data, its webhooks' HMAC secret,
the key that encrypts its local database) needs *a* value, not the one
in `backend/local`. Under placeholders nobody reads that one, so each person
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
  credentials', plain or exposed), whose current value a recipe made
  (`coffre set … --generate`, one value: a key pair's half has none
  here), in the environment's list. The plan names each,
  `generate: { ROOT_ENCRYPTION_KEY: { recipe, replaces } }`, with the
  version it read. `coffre run` and `coffre export` make each value by its
  recipe, as `coffre regenerate` does, and write them to the personal
  config with the person's session, an ordinary audited write, then ask for the
  plan again, which now exposes them as that config's own.
- **Once, and once only at a time.** The write replaces the version the
  plan read, or is refused (409). Of two runs at once, one writes, and
  the other, refused, reads the plan again and finds the winner's. The
  next run finds the person's own values and makes nothing. Stable across
  runs, so a key that encrypts the local database keeps opening it.
- **Who.** People only: the plan is for people, and a service account
  reads the environment's values as before. The deployment opts each
  environment in, a local one (decision 19), so production never grows
  personal values by itself.

**What replaces `expose`, by what the value is.** Equisafe's
`backend/local` listed 17 keys under `expose` in 0.8. 0.9 replaces each
kind:

| The value is | 0.9 | Equisafe's keys |
|---|---|---|
| No secret | A plain value | `DFNS_CREDENTIAL_ID`, `STARKNET_TESTNET_ACCOUNT_ADDRESS` |
| The app's own key: sealing, encryption, HMAC, webhook secrets | A value generated for each person in `<env>@me` | `POLICY_SEAL_KEY`, `IFRAME_TOKEN_SECRET`, `DELEGATED_SESSION_SECRET`, `PLAYWRIGHT_SERVICE_SECRET`, `ROOT_ENCRYPTION_KEY`, `FIAT_CHALLENGE_SECRET`, `*_WEBHOOK_SECRET` |
| A key whose host is in the app's code | A credential, the app pointing at its proxy URL | `LEMONWAY_API_KEY`, `YOUSIGN_API_KEY`, and `backend/tests`' `TEST_LEMONWAY_SANDBOX_API_KEY` |
| A token the SDK decodes (a JWT) | A shaped placeholder | `DFNS_AUTH_TOKEN` |
| A key the app signs with | `credential(name).sign()` | `DFNS_PRIVATE_KEY` |
| A key no proxy can use yet (a STARK-curve key) | `expose`, still | `STARKNET_TESTNET_PRIVATE_KEY` |

**`expose`** names the few secret values an environment's apps may hold as they
are, because they cannot be used through a proxy: a webhook's HMAC secret
the backend verifies a signature with, a local encryption key, a testnet
signing key. It is configuration only, with no API and no page. It
applies to the exact environment a read resolves to, never to its parents:

| `coffre run …` | With `expose: { 'market/dev': ['STRIPE_WEBHOOK_SECRET'] }` |
|---|---|
| `market/dev` | Real value |
| `market/dev-eu`, a fork of dev that inherits the key | Not exposed: list `market/dev-eu` itself |
| `market/dev@me`, with a personal config | Real value, as `market/dev` lists it (0.9): its owner gets it through `market/dev` anyway. A personal config is never listed itself. Its *own* values, which only its owner writes, are its owner's app's, so `DATABASE_URL=postgres://localhost/ada` there reaches Ada's app |
| `market/dev@me`, with none | Real value: the read is of `market/dev` |

**The recommended use of `expose` is a local environment of fakes.** A
backend that verifies Stripe's webhooks locally needs *a* webhook secret,
not Stripe's. Make `market/local` (or `backend/local`), fill it with
local-only values (`coffre set market/local STRIPE_WEBHOOK_SECRET
--generate`, a fresh local encryption key, a testnet key with no funds),
and expose it whole: `expose: { 'market/local': 'all' }`. Tests that sign
their own webhooks use the same fake. Keep `expose` on a real environment
for a value that genuinely has to be real and cannot be proxied, and know
that such a value is no longer protected from the agent.

**Break-glass.** A person who must see a value (an Owner pasting a key
into a provider's dashboard) has no path to it as themselves. The escape
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
plugins: [credentialProxy({ credentials: { … }, expose: { … } })],
```

```ts
// app/src/routes/use.$.ts
import { createFileRoute } from '@tanstack/react-router';
import { plugin } from '@coffre/server/routes';

export const Route = createFileRoute('/use/$')({ ...plugin });
```

```ts
// vault/src/index.ts
export default vault((env: Env) => ({ …, people: 'stand-ins' }));
```

The proxy without `people: 'stand-ins'` works too: people's `coffre run`
gets placeholders wherever the instance has the proxy. Their other reads
still open values, though, so nothing stops the agent from asking for them.

## 4. The proxy, request by request

`GET /use` says the instance has a proxy, and names its credentials.
`coffre run` asks it first. It holds no secret.

`GET /use/<project>/<env>`, with the handle as a bearer token, is the
**plan**: one read of what the environment holds, which opens only its
plain values and the keys it exposes, chosen from the very rows it opens
(`PickKeys`, each row saying whether it is plain), so an override reset
between two reads cannot swap a parent's value in. It answers:

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
   host. A key the environment lacks is a 409.
4. **Sent on.** Every header but those about the hop, coffre's caller,
   its cookies and the handle; then the rule's header, parameter or
   Basic authorization, filled in. The body is read up to 16 MiB and no
   further, whatever it declares. If the handle is still anywhere in the
   request (a header, inside another header's Basic base64, the URL, the
   body), it is refused rather than leaked to a third party. The request
   goes out with `redirect: 'manual'`.
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
works, and tests hold both. On Workers, where calls land on different
isolates, the map would live in a Durable Object.

**Not yet:**
- *Workers.* The tunnel's code is platform-neutral, but only Node's
  `upgrade` is wired. Workers take an inbound WebSocket (`WebSocketPair`)
  and open TCP with `connect()` from `cloudflare:sockets` (`startTls()`
  for Postgres's upgrade), so the adapter is about 40 lines. It needs a
  check on a deployed Worker first: see section 7.
- *The privileged-role warning* (section 6): reading `rolsuper` and
  `rolcreaterole` after login, before the app's first query.
- *Minted short-lived logins* (W108), which replace the shared password.

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
where the key was, never the key, whatever `expose` says, and names the
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
private network anyway. On Node, pinning the resolved address is left for
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
credential's keys, the exposed values as they are, and nothing else. It
sets no base URL: the app's configuration names the stable URL. A service account gets values, as before.
An instance without the proxy gets the old read, which the vault refuses
to people with `people: 'stand-ins'`. `coffre export` writes the same
placeholders (a `.env` for Docker Compose holds handles, not keys).
`export --watch` is refused for people: nothing it would watch changes.

**Workers.** The HTTP shapes are a `fetch` from the app's Worker, so they
work as they do on Node. The tunnel needs an inbound WebSocket, which
Workers take (`WebSocketPair`), and an outbound TCP connection, which
`connect()` from `cloudflare:sockets` opens, with `secureTransport:
'starttls'` and `startTls()` for Postgres's TLS upgrade. Both are
documented and general, and Hyperdrive is not involved: the tunnel
connects to the database's public address, as any TCP client would. The
limits: `connect()` reaches public addresses only (no private network
without Cloudflare Tunnel), port 25 is blocked, and a Worker invocation
has a CPU budget and up to six simultaneous open connections, so a session
with many parallel connections should stay on Node or a Durable Object
holding the sockets. To be checked on a deployed Worker in PR 3. Locally,
workerd's `connect()` behaves the same, but Cloudflare's network does not.

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

1. **`people: 'stand-ins'` is a vault option, default `values`.** It is
   off by default so that 0.7 deployments, which have no proxy and no
   credentials declared, keep working, and the conformance suite and every
   test that reads as a person stay as they are. *Recommendation: make it
   the default once the proxy covers the common shapes (after PR 3), with
   a release note.*
2. **No new permission or role.** A person's `secret.read` is the use
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
8. **`expose` is configuration, by exact environment, never inherited.**
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
    reveal, which the vault refuses a person under placeholders (R13), and a
    plain write of what it showed. Without placeholders, that is exactly
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
    code, beside `expose`. The client makes each value, as for `coffre set
    --generate`: the server never makes one. *Alternative:* the server
    generates in the plan, which would let any client of the proxy have
    them, at the cost of the server making values.

## 9. Plan

| PR | What |
|---|---|
| 1 | Placeholders in the vault (`people`), handles (`0009_handles`, `POST /api/handles`), the plugin's `use` capability, `credentialProxy` with header, query and Basic, the plan, `coffre run`/`export` placeholders, `@coffre/client/credential`. Built |
| 2 | `sigv4()`: S3 through the proxy, tested with the AWS SDK against a signature-checking fake, and by hand against MinIO. Built |
| 3 | The Postgres tunnel: a socket capability for plugins (`routes.socket`, Node's `upgrade`), the listener in `coffre run`, SCRAM, cancel, revocation mid-session. Built |
| 0.9 E | The stable URL, `/use/<credential>`, from the environments a handle keeps (`0010_handle_places`); `baseUrl` removed. Built |
| 3b | The tunnel on Workers (`WebSocketPair`, `connect()`), checked on a deployed Worker; the privileged-role warning |
| 4 | Redis through the tunnel |
| 5 | `presign` (built in 0.8.1) and `sign` (0.9 D); `verify`, HMAC, SDK credential files |
| 0.9 C | Shaped placeholders, `jwt({ claims })` and `prefix(…)`: DFNS's token through the proxy. Built |
| 0.9 A | Plain values (`0011_plain_values`, `coffre set --plain`, the page's Plain toggle), which deprecate `identifiers`. Built |
| 0.9 B | Values of a person's own: `generate`, reads through `<env>@me`, `coffre run` making them by recipe. Built |
| 0.9 D | Signers, `privateKey(…)`, and `credential(name).sign(message)`: DFNS's user-action key stays in coffre. Built |

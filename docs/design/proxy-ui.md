# Proxy definitions in the UI (0.16, T186)

A design for 0.16's headline, written on 2026-11-01 (W304), for Erwin's
review before any code. Rules R65 and R66; the UX is prototype
[#421](https://github.com/erwinkn/coffre/pull/421) (layout B, refined by
W260 and W263; draft, never merged). The model is
[`formal/Routing.tla`](../../formal/Routing.tla), described in
[docs/formal.md](../formal.md#routingtla). Nothing here is built.
Section 11 lists the questions only Erwin can settle.

## In short

Today a credential (a route like `openai`, a signer, a verifier, a database
tunnel) exists only in the deployment's code, `credentialProxy({ … })`. 0.16
lets an Owner write them per environment in the UI, beside code's. The
question underneath everything here is **where may a key go**, because a
definition that points `{STRIPE_KEY}` at a new upstream is a read of that
key by whoever controls the upstream.

1. **Storage.** One Postgres row per environment holds its UI definitions.
   The row is a 0.15 sealed object of the vault's log, kind `proxy`, changed
   only through the vault's change path, like a grant. A database writer
   cannot forge one, nor put an old one back unseen.
2. **Ordering.** An edit is a change under the fence, exclusive. A use reads
   the definition in its one statement, under the fence, shared. So every
   use is decided wholly before or wholly after an edit. Values already
   decided keep going to the old upstream for at most `cacheSeconds` (60 s,
   or the 3 s deadline with no cache): the same bound a revoked handle has
   today. TLC checks this, and finds a run for each protection removed.
3. **Who may route what.** Saving a definition freezes what its editor
   could read, exactly as issuing a service token does. Each use decides the
   route's keys twice: for the caller, as today, and for that frozen
   editor. An editor who cannot read a value can never route it. A sensitive
   value is routed only by a definition an Owner covering the place saved
   (R66), the same people R30 already lets loosen it to a secret.
4. **Cost.** No round trip is added to a `/use` whose route names the same
   keys as before. The definition rides in the vault's call as one more row
   and one more probe, and comes back in the answer only when the isolate's
   copy is stale. An edit that adds a key costs each isolate one extra call
   once, the map miss any new key costs today.
5. **Code wins.** A UI definition whose name code also defines is ignored
   and shown locked (R66). The first proxy request under a new code config
   deletes such a row, audited, so that it never comes back to life when
   code later drops the name.
6. **Matching** runs on the percent-decoded path, segment by segment.
   `..`, `.`, encoded slashes and double encoding are refused, never
   resolved. `*` matches one segment and `**` the rest; a plain path is a
   prefix. No regexes.
7. **`proxy.edit`** is a new place permission. The Owner role holds it
   (Owners hold every permission), so by default only project and instance
   Owners edit. The role editor gets a row for it.

An example, end to end. Ada is an Owner of `market`. In `market/dev`'s
Proxy tab she adds a route:

```
openai   https://api.openai.com/v1
  sends   header authorization: Bearer {OPENAI_API_KEY}
  allows  POST /chat/completions, GET /models/**
```

She saves. The vault checks that she holds `proxy.edit` on `market/dev`,
freezes her holdings into the definition, seals the environment's new
`proxy` object, and logs one `proxy.save` entry naming the route, its
upstream and its keys. The save answers once that entry is sealed in a
checkpoint (R51, about half a second). Bo's app, run with `coffre run
market/dev`, calls `https://secrets.acme.example/use/openai/chat/completions`
with its handle. The app finds the handle, asks the vault in one call for
route `openai` of `market/dev`, and gets back the definition with the key.
It checks `POST /chat/completions` against the allow list and sends the
request to `api.openai.com`. Ten minutes later Ada points `openai` at
`https://eu.api.openai.com/v1`. A use decided after her save goes to the EU
host. Values decided before it may still go to the old host for up to a
minute.

## 1. What a definition is

The shapes are #421's (`packages/ui/src/lib/proxy-prototype.ts` on that
branch), which extend today's `Credential`, `Signer` and `Tunnel` types:

| Kind | Fields | New in 0.16 |
|---|---|---|
| Route | `upstream`, `inject[]`, `allow[]` (`{ methods, path }`), `limit` (`perMinute`, `perDay`), `placeholder`, `egress` (a name) | several inject rules; several allow entries with globs |
| Signer | `privateKey(key)` or `hmac(key, encoding, prefix, maxBytes)`, `limit` | |
| Verifier | `hmac(…)`, `limit` | |
| Database | `key`, `hosts[]`, `network` (a name) | |

What a UI definition cannot hold is a binding. An egress (a VPC Service) or
a network (a VPC Network) is a Worker binding, so code declares them by
name and the UI picks one:

```ts
credentialProxy({
  credentials: { … },                                     // code's, as today
  egresses: { 'schuman-prod': { via: env.SCHUMAN_EGRESS, hosts: ['api.schuman.example'] } },
  networks: { replica: { via: env.REPLICA_NET, hosts: ['10.0.1.5'] } },
  editable: true,                                         // the Proxy tab may write; off by default
});
```

A UI route that names an egress must have an upstream among its `hosts`. An
egress name that code no longer declares makes the route answer 503 naming
it. It never falls back to a direct fetch, as code's rule is today. A
database through a network must name hosts among the network's, which
keeps R31's rule: private addresses and `sslmode=disable` need an explicit
binding.

`editable: false`, the default, keeps a deployment exactly as today: no
Proxy tab writes, and the use path never reads a `proxy` object.

## 2. Storage

### Where

One table, Postgres first (R50), SQLite for tests and local development:

```sql
CREATE TABLE proxy_definitions (
  environment_id uuid PRIMARY KEY REFERENCES environments(id),
  items          jsonb NOT NULL,   -- the canonical object: every item, with who saved it
  seal           bytea NOT NULL    -- the vault's HMAC over (kind, id, items), 16 bytes
);
GRANT SELECT ON proxy_definitions TO coffre_app, coffre_backup;
-- written only by the vault's logins, through its change functions
```

The migration only adds (AGENTS.md, "expand, then contract"), and grants
`coffre_backup` by name as every new table does. An environment with no UI
definitions has no row.

**Why one row per environment, not one per item.** The page saves all its
pending edits at once (save, discard, review), and copying from another
environment writes many items. One object makes that one change, one seal
and one entry. A use reads one row for its environment: two for a fork,
whose parent's definitions it inherits (question 6). The cost is that two
Owners saving different routes of one environment at once conflict. The
second gets a 409 and reviews the first's change (below), which is what the
page should do anyway.

### Sealed by the vault, not the app

The row is a sealed object of the 0.15 log, kind `proxy`, id the
environment's uuid ([sealed-inputs.md](sealed-inputs.md)). Two other
options were weighed:

| | Vault-sealed object (chosen) | App-MAC'd row (`APP_KEY`, like a credential's row) | Plain row |
|---|---|---|---|
| A writer edits the upstream | refused, `tampered` | refused | **served** |
| A writer puts back last year's row (an upstream whose domain has since lapsed) | refused, `stale`: the row's seal is not its newest change's | **served**: a MAC proves the row was once valid, not that it is current | served |
| Replay of the log decides uses as live did (R53) | yes: every decision input is in the log | no | no |
| Who checks the editor's rights | the vault, on its own sealed rows | the app | the app |

The second row decides it. R64 accepts side channels from a database
writer, never a key served on forged state, and a rolled-back upstream
would be exactly that.

The object holds each item with what its save froze:

```json
{ "items": [
  { "definition": { "kind": "route", "name": "openai", "upstream": "https://api.openai.com/v1", "inject": [ … ], "allow": [ … ] },
    "savedBy": "user:ada@acme.example", "savedAt": 1793560000000,
    "holdings": [ { "projectId": "…", "environmentId": null, "role": "owner", "permissions": { "normal": [ … ], "protected": [ … ] }, "sensitive": true } ] }
] }
```

`holdings` is the editor's grants as a service token's scope keeps them
(`ScopeGrant` in `@coffre/core/access`: place, columns held, and `sensitive`
where they could hand a service sensitive reads, R32). Section 8 explains
how a use weighs it. An item the save did not change keeps its `savedBy` and
`holdings`. So Bo's edit of `maps` leaves Ada's `openai` cleared as Ada.

### Changes and audit

Two change ops, each through the vault's change path (`change_input`: CAS
on the seal the caller read, the fence exclusive, the entry numbered under
it, the answer once sealed):

| Op | Who | Payload, in the entry (R53: the request, not the outcome) |
|---|---|---|
| `proxy.save` | a person holding `proxy.edit` on the environment | the environment, the seal the page loaded, and each item added, changed or removed, whole |
| `proxy.code` | the deployment (actor `deployment`), section 6 | the code config's names (digest and list), and each UI item it deletes, whole |

The audit page shows a `proxy.save` as a diff: `openai: upstream
api.openai.com → eu.api.openai.com`, with the keys each changed item sends.
It carries a mark when the item sends a sensitive key (`routes sensitive:
STRIPE_SECRET_KEY`), the audited flag of R66. A removed item's entry holds
its whole definition, so it can be restored from the log, and so can each
row `proxy.code` deletes.

**A stale page.** The page's save names the seal it loaded. If anyone
saved since, the CAS fails and the page answers 409: "Lin saved this
environment's proxy 2 minutes ago: review their change". It reloads, keeping
the pending edits on top. Nobody overwrites a change they never saw.

## 3. Ordering against `/use` and revocation

### What must hold

The brief's property: *an edit that redirects a key's upstream must never
let an in-flight or later use send the key to a host no current definition
allows.* Taken literally, no design meets it without an extra round trip
on every use, because the app already caches opened values (`cacheSeconds`,
60 s by default) and serves them with no vault call. What holds, and what
TLC checks:

- **`EverySendAllowed`.** Every request that carries a key goes to the
  upstream of a definition that (a) the vault decided on, (b) was the log's
  newest when it decided (not a row put back, not one an edit had
  replaced), and (c) was cleared for the key's nature at that decision.
- **`WithinWindow`.** That request leaves within W of the decision: W is
  `cacheSeconds` with the cache, or the use's 3 s deadline without it.
- **`NoRevival`.** A UI definition that code shadowed is never used again
  after code drops the name.
- **`StrictlyCurrent`**, the literal reading, fails with every protection
  on. That is an `EXPECTED` gap in `scripts/formal.sh`, kept so the window
  stays documented: values decided before an edit serve out their W.

The window, as a timeline. `cacheSeconds` is 60.

| Time | Event |
|---|---|
| 12:00:00 | Bo's app uses `openai`. The vault decides on version 7 (`api.openai.com`). The app keeps the key, bound to version 7, until 12:01:00 |
| 12:00:20 | Ada saves version 8 (`eu.api.openai.com`). It is sealed and answered at 12:00:20.5 |
| 12:00:30 | Bo's app calls again. A cache hit: the key goes to **`api.openai.com`**, version 7's upstream, never to the EU host, which the vault has not decided on for these values |
| 12:00:45 | In the entry's last quarter, one request asks the vault again. It decides on version 8, and from here the key goes to the EU host |
| 12:01:00 | At the latest: version 7's values serve no more |

A revocation already works this way: "a revoked handle's values serve no
longer than this" (`cacheSeconds`'s doc). Its uses and an edit's are
ordered the same way, by the fence and the log number. A revoke numbered
before a use refuses it; one numbered after leaves it decided, and its
values serve out the window. Question 4 offers the strict alternative.

### The protocol

```
use (a named use, as 0.15's: one call on a map hit, section 4)
  app      find the handle in the request by its shape (it does not need the definition for that)
  call     use_credential(token, place, route 'openai', the ids the map holds, the seal of the isolate's copy)
             fence shared
             one statement, one snapshot:
               the caller's rows, as today
               the proxy row(s) of the place (and a fork's parent), and the seal of their newest change
               the route's keys as the definition read names them, held to the map's ids (else `moved`), and their rows
             the entry: the request, the route's name included, under its MAC
           commit
  vault    seals checked (proxy object included), then decided twice:
             for the caller (purpose use, as today)
             for the definition's frozen editor (section 8)
           answers: the values, and the definition decided on (omitted when the isolate's copy has that seal)
  app      checks the handle (section 7), and the method and path against the definition's allow list
           keeps the values beside that definition (the cache key includes its seal)
           sends, before the use's deadline, to that definition's upstream

edit (one change)
  vault    reads the row and decides proxy.edit, freezing the editor's holdings
  call     change_input: fence exclusive, CAS on the seal read, write, entry numbered, commit
  answer   once the entry is sealed (R51)
```

### What each protection is for

Each row is a constant of `Routing.tla`. With it off, TLC finds the run
described, which `scripts/formal.sh` holds as a failure on every CI run.

| Protection | Without it, TLC finds |
|---|---|
| `FencedRead`: the definition is read in the use's statement, after the fence, in one snapshot with the decision | the use reads `openai` → `api.openai.com`, Ada's edit commits, the use is decided on the old row and numbered after the edit (`EverySendAllowed`) |
| `SealChecked`: the row's seal must be its newest change's | a writer puts back version 7 after version 8, and a use is decided on it |
| `SentAsDecided`: the app sends by the definition the vault decided on (returned in the answer, or confirmed by seal), never by its own unchecked copy | the app's copy still says version 7. The vault decides on version 8, a Developer's (clearance `secret`, host `evil`), and the app sends to version 7's host, which no current definition allows |
| `BoundToDefinition`: kept values go only to the definition they were decided under | values decided on version 7 (`good`) are served from the cache after the app re-read version 8 (`evil`). The key reaches `evil`, which the vault never decided on for them |
| `ClearanceAtUse`: each use weighs the key's nature now against the definition's clearance | a Developer routes `K` while it is secret. An Owner marks it sensitive, and the next use sends the sensitive value to the Developer's upstream |
| `KeptExpires`: kept values serve W, no longer | values sent long after their decision (`WithinWindow`) |
| `ClearSuperseded`: the `proxy.code` change deletes the shadowed UI row | code defines `openai` for a while, then drops it, and the stale UI `openai`, unseen for months, serves again (`NoRevival`) |
| `CodeGate`: an isolate serves no proxy request before its code set is logged | the same revival, through a deployment that served `openai` from code without ever logging that it shadowed the UI row |

What the model does not cover: the fence's own correctness (that a use and a
change never overlap, and the number orders them) is `HotPathOne.tla`'s, for
any input. Here an edit is one step. One route, one key, two hosts, one
isolate, one live deployment at a time. The frozen holdings are reduced to
one clearance per version ("sensitive" for an Owner, "secret" otherwise).
The matching rules of section 7 are pure functions, which property tests
hold, not TLC. That a map hit's ids are held to the route's names is
Naming.tla's `HeldToNames`, unchanged. Renames are not modelled, because
they cannot change what code shadows (section 6).

## 4. What `/use` costs, in round trips

A use through the proxy is a **named use** (`useNamed` in
`packages/vault/src/use.ts`): the request names its token, its place and its
keys, and the isolate keeps a map from those names to ids. On a map hit it
is one call. On a miss, the first call reads the ids and the second makes the
use by them, because the use's entry MAC binds the key's id, which the
isolate cannot compute before it has read it. A named call always probes
every input's seal, never the seal cache, so that its work is the same
whatever the key and whatever the isolate kept (D153). A route use keeps all
of that and adds the route's name to what the request names.

| Case | Today (0.15) | With UI definitions |
|---|---|---|
| Map hit, uncached (`cacheSeconds: 0`, or an entry's refresh) | 1 call | **1 call.** The proxy object is one more input of the statement: one more row and one more probe of its newest change, inside the same call. Its body is not sent, because the isolate's copy has the row's seal |
| Map miss: an isolate cold for that environment, or a key it has not used | 2 calls | **2 calls.** The first resolves the route in the definition read, its keys by name, and answers with the ids and the definition (a few hundred bytes to a few KB). The second makes the use |
| Right after an edit that keeps the route's keys (a new upstream, rules or allow list) | 1 call | **1 call.** The statement sees the row's seal differ from the copy's and returns the new body in the same answer. Nothing is refused or retried |
| Right after an edit that adds a key to the route | 1 call | **2 calls, once per isolate**: a map miss for the new key, as any key used for the first time is today |
| Cache hit | 0 calls | **0 calls** |
| A code route | as today | as today. The app names the keys, and no `proxy` row is read |

**What the entry records** (R53: the request, so that the replay decides
it as live did). A route use's entry carries the route's name in a new
nullable column, under the entry's MAC; reveals and code routes leave it
null. Which definition it was decided on needs no column: it is the newest
`proxy.save` or `proxy.code` change of the place's object numbered below the
entry, as for every other input (R50: the number orders everything). So two
routes that name the same key with different editors' holdings replay
apart. The route's two decisions use the place the use resolved (the
handle's environment, or the one the URL names), and the route as that
place's object holds it, or its fork parent's, by name (question 6).

**A map hit holds the ids to the definition.** The second call of a miss, and
every hit, carries the ids the map holds. The statement checks that the
definition it reads still names those keys for that route, and otherwise
answers `moved`, writing nothing, and the isolate reads again. That is
Naming.tla's `HeldToNames`, applied to the route's names. An edit between
the two calls of a miss therefore cannot have a key used that the route no
longer names.

**Invalidation costs no round trip.** The definition's body is the only
thing the isolate caches, and only to save bytes. Postgres compares the
copy's seal with the row's inside the use's own snapshot, under the fence:
no change commits between that comparison and the decision, so it cannot
be wrong. The seals are probed on every call anyway, as above. A kept value
cache entry is invalidated by time only: the window of section 3.

**Bytes and CPU.** The definition body crosses the wire only when stale. The
second decision (the frozen editor's) is CPU in the Worker over rows the
statement already read: the key rows are the same, and the holdings come
with the definition. The cost the statement does add is one row and one
probe per use, two through a fork, whose parent's object it reads too; the
`whole` shape already reads the parent environment. The new entry column
costs bytes on every route use: PR C measures them as PR 3 measured the
place column (sealed-inputs.md, "A use"). PR C also measures the probes
against the 30-buffer budget, holds the statement flat as the log grows
(`request-cost.test.ts`, R48), and must show no regression in the `/use`
bench (R44).

## 5. The vault makes no outbound call

Unchanged (R63). The vault reads Postgres, decides and answers. The app,
the `coffre` Worker or the Node server, makes every upstream request,
exactly as for code definitions. What changes is who writes the upstream:
an Owner through a web page rather than a deployment through a review and a
deploy. That calls for two checks code upstreams never needed:

- **No private targets.** A UI upstream is `https://` to a DNS name or a
  public address. Loopback, private, link-local and metadata addresses
  (`169.254.169.254`) are refused at save, as are `localhost` and single-label
  names. On Workers the platform refuses them anyway. On Node a name can
  resolve to a private address at request time (DNS rebinding), so the
  Node fetch for a UI route checks the address it connects to, through
  undici's `connect` lookup. `insecureUpstreams` lifts both for local fakes,
  as it lifts the rest today.
- **The upstream's origin is fixed by the definition.** The existing rule
  stands: a request goes to `<upstream>/<path>` and nowhere else, and
  redirects stay on the proxy.

## 6. Code definitions and UI definitions together

**Code wins, by name, and the row shows locked** (R66). The app resolves a
name in code first, then in the environment's UI definitions. The page shows
the code item once, locked, with code's values and no banner. A UI item of
that name is neither shown nor served.

**A code name is taken in every environment, whatever its scope.** Code's
`environments` (below) decides where a code item *serves*; its name is
reserved for UI items everywhere. With code `replica` scoped to
`market/prod`, `market/dev` has no `replica` at all, and its tab says
"`replica` is defined in code (market/prod only)" instead of offering the
name. The reason is renames. If shadowing followed the scope, a UI
`replica` in `market/dev` would be hidden by renaming dev to prod, and
would come back, unseen since, when it was renamed back. No code change or
deploy would be involved, so nothing would clear it. With the name taken
everywhere, whether code shadows a UI item depends on the code config alone,
never on what environments are called.

**Which URL names what.** Today `/use/<a>/<b>/…` names an environment when
`<a>/<b>` is one the handle was made for, and is otherwise the stable URL of
credential `<a>`; where `<a>` names no credential, it is an environment's
URL with no lookup ([credential-proxy.md](credential-proxy.md), section 4,
"Which route"). A UI name depends on the environment, so the app can no
longer tell from its config alone that `<a>` names nothing. Any `<a>` that
is no code name now takes the lookup the stable URL already takes: the
handle's environments (`madeFor`, kept for `cacheSeconds`). The rule itself
is unchanged. `GET /use`, which answers with no credential, keeps listing
code names only, so it reveals nothing of an environment's own. The plan
(`GET /use/<p>/<e>`) lists the environment's UI routes beside code's.

**Scoping code items** (R66): `environments: ['market/prod']` on any code
item, by full path, because the config is instance-wide and a bare `prod`
would match every project's prod. With none, a code item applies to every
environment, as today. The path is matched against the request's environment
by its current name. An environment renamed away from `market/prod` leaves
that scope (which only moves where the code item serves, never what a UI
item may be called), and the app's startup check warns about a scope that
names no existing environment. A `*/prod` glob can come later if someone asks.

**Names unique across kinds** (W260's pushback 4, question 3). Routes and
tunnels share `/use/<name>`, signers and verifiers are named in the same
URL space, and one list shows all four. A UI name may not equal any other UI
item's in the environment, nor any code item's of any kind. Code keeps
today's per-kind rule: making it stricter would break a deployment that has
a credential and a signer both named `dfns`.

**Clearing superseded rows** (W260's proposal, which Erwin allowed: "the
deployment may clear superseded UI state"). Without clearing, a UI `maps`
hidden by code's `maps` comes back to life the day code drops `maps`, with an
upstream nobody has looked at since. So:

- Each isolate, at its first proxy request (a use, or the Proxy tab),
  compares a digest of its code config's names (scopes play no part: see
  above) with the newest
  `proxy.code` change in the log. This is one indexed read, no lock, as the
  vault does for `bulk.limit` at its start (`#limit`). Most isolates find
  it equal and go on.
- If they differ, it writes a `proxy.code` change. In the same change, the
  vault deletes every UI item, in every environment, whose name code now
  defines, each whole in the entry. The actor is the deployment.
- The isolate serves no proxy request until that change has landed, or it
  found the log already equal (`CodeGate`). So a deployment that ever served
  `maps` from code has logged it, and the UI `maps` is gone before any later
  deployment could revive it.
- **During a deploy**, two app versions with different code sets may serve at
  once, and each new isolate of either writes its set: the changes
  alternate until the old version is gone. Clearing only deletes, so the
  only harm is this. An Owner creates UI `maps` after the new config
  dropped it; an isolate of the old config, still starting, then deletes it
  again. That deletion is in the log, whole, and restorable. The alternation
  costs a change per isolate start for the overlap's length; a deploy on
  Workers rolls over in a minute or two.

## 7. Matching, injection and redaction

### The path

The request's path below the route, `/use/<name>/<rest>`, goes through
today's refusals unchanged, and only then is matched:

1. **Today's check, kept whole** (`aim`'s `climbs` in `credential-proxy.ts`).
   Each raw segment is decoded as often as decoding changes it, because a
   server behind another decodes twice. Every form along the way is refused
   if it holds a slash, a backslash, a control byte (which a server may cut a
   segment at: `..%00`) or an overlong UTF-8 lead byte (`%c0%ae`, a dot to an
   old decoder), or if it is a dot segment: `.` or `..`, with trailing blanks
   (`..%20`) and with its `;` parameters dropped, as Tomcat and Spring drop
   them (`..;x`).
2. **New:** an empty segment other than a trailing one (`//`) is refused,
   since a glob counts segments.
3. **New:** each segment is percent-decoded once (UTF-8; an invalid sequence
   is refused), and the decoded segments are matched against the allow list.
4. The path goes on as the app encoded it, byte for byte. After step 1, the
   upstream's own decoding, however often it runs, reads the segments the
   match read.

| Request | Matched as | Result |
|---|---|---|
| `/companies/42/documents/a%20b.pdf` | `companies`, `42`, `documents`, `a b.pdf` | matched |
| `/companies/42/docu%6Dents` | `companies`, `42`, `documents` | matched as `documents`, not missed |
| `/kyc/%2e%2e/admin` | | 400: a dot segment (today too) |
| `/kyc/..%2fadmin` | | 400: a slash once decoded (today too) |
| `/kyc/%25252e%25252e/admin` | | 400: a dot segment three decodings down (today too) |
| `/kyc/..%20/admin`, `/kyc/..%00/admin` | | 400: a dot segment with a blank; a control byte (today too) |
| `/kyc/..;/admin` | | 400: a dot segment with parameters (today too) |
| `/companies//x` | | 400: an empty segment (new) |

What is new is only the matching: today `paths` is compared with the encoded
path. Globs need the decoded one: `*` must see `a b.pdf`, and a literal
`documents` must not miss `docu%6Dents`. PR B's property tests run every
row above, and random encodings of paths outside a pattern, through the
old check and the new matcher together.

### The allow list

A route holds entries `{ methods, path }`. A request is allowed when any
entry allows it: its method is in `methods` (empty means any), and its path
matches. With no entries, every method on every path is allowed, as today.

- A plain path is a **prefix by segments**: `/companies` matches
  `/companies` and `/companies/42`, never `/companiesX`. That is today's
  `paths` rule (`relative === prefix || relative.startsWith(prefix + '/')`),
  so existing configs read the same.
- `*` is exactly one non-empty segment, and stands alone in its segment:
  `/companies/*/documents`.
- `**` is zero or more segments, and comes last: `/companies/*/documents/**`.
  A pattern ending in `**` is exact, not a prefix.
- No regexes, and no partial-segment globs (`doc*`). That keeps patterns
  readable at a glance and matching linear: segments × entries, with no
  backtracking, since `**` is only ever last.
- At save: no `.`, `..` or empty segments, `**` only last, no duplicate
  entries, methods from the fixed list.

Code definitions take the same `allow` shape. `methods` and `paths` stay
accepted and are read as one entry: `{ methods, path }` for each path.

### Several inject rules

A route's `inject` is an ordered list. Each rule fills a header, a query
parameter, a form or JSON field, Basic authorization, or a SigV4 signature,
in that order. Validation, at save and at the app's startup for code:

- at most one `basic`, at most one `sigv4`, and `sigv4` last;
- one rule per header (case-insensitive), parameter or field name;
- no `basic` beside a rule that sets `authorization`, and no rule sets a
  header SigV4 owns (`authorization`, `x-amz-*`);
- a `placeholder` (`jwt`, `prefix`) only where the route's non-plain keys sit
  in exactly one header, query, form or JSON slot, the case it shapes today.

**SigV4 signs what the earlier rules set.** It runs last, over the request
as the earlier rules left it, and adds the headers they set to
`SignedHeaders`. So the signature covers the request exactly as sent, and
an earlier header cannot be swapped on the way.

**Where the handle is.** Two sources, as today. `x-coffre-handle`, which the
SDK's `credential(name).fetch()` sends and which fills no slot of the rule,
is accepted on its own, whatever the definition's slots. Without it, the
plan gave the app the handle in place of each non-plain key, so every slot
that carries one carries the same handle. The proxy finds it by its shape
(`coffre_use_` and 43 characters), before the vault call, without the
definition. After the vault answers, a handle taken from a slot must have sat
in one the decided definition names (a form or JSON rule's field read as
today, from the parsed body), else 400 before anything is sent. Two different
handles in one request are a 400. As today, a handle left anywhere after
filling is refused, never sent.

### Redaction

Every value any rule of the route read, and every string a rule assembled
(Basic's base64, a header's filled template such as `Bearer sk-…`), goes into
the redaction set, in every encoding the closed list names today
([credential-proxy.md](credential-proxy.md), section 4, step 6). A plain value
stays out of the set, as today. So does a rule made of plain values alone.

## 8. Who may edit, and what a definition may route

### The permission

`proxy.edit`, a place permission like `secret.write`, held on an environment
or on a project (all its environments). It joins `PERMISSIONS` in
`@coffre/core/access`, and therefore:

- **The Owner role holds it**, normal and protected columns, because the
  Owner role is every permission. No other built-in role holds it. So by
  default only project and instance Owners edit (R65).
- **The role editor** shows it as a row, "Edit proxy definitions", below
  `secret.write`. An Owner may add it to a role, in either column. One new
  rule, beside "a role that reads values uses them too": *a role that edits
  the proxy reads values too*, in each column. An editor who can read
  nothing could only route plain values, which is no use, and the rule
  keeps every editor's routing within their reads.
- **Reading the tab** needs only access to the environment. Upstreams, rules
  and key names are not secret (R6). Anyone who lists the environment sees
  its definitions, inert (#421's disabled fieldsets).
- A token or a handle cannot save: `PUT …/proxy` is a person's, on a browser
  session or `coffre login`, as a role edit is.

The vault decides a save on its own sealed rows (the editor's principal
object, the roles, the environment, protected or not). The app's check is
for the page, never the guarantee.

### Frozen holdings, decided at each use

A definition is, in effect, a standing read by its editor: wherever its
upstream sends what it receives, the editor could arrange to see it. So
it is treated like the credential that already is one, a service token:

- **At save**, the vault freezes the editor's holdings into each changed item:
  their grants, as columns held, the way `ScopeGrant` keeps a token's issued
  rights, and `sensitive: true` at the places where they are an Owner of
  the project or the instance, as a person on no credential's scope. That is
  `readsSensitive`'s rule from R32, unchanged.
- **At each use**, the vault decides the route's keys for the caller (purpose
  `use`, unchanged), and then again for the frozen holdings, as if they were a
  token's scope reading the value (purpose `read`). The second decision
  reuses `decideChecked` over rows the statement already read. Both must
  allow.

What that gives, with examples:

| Case | Outcome |
|---|---|
| Lin (a Maintainer whose role an Owner gave `proxy.edit`) routes `{STRIPE_KEY}`, a secret she reads | allowed, at save and at use |
| Lin routes `{STRIPE_SECRET_KEY}`, sensitive | refused at save, naming who may: "an Owner of market may route sensitive keys" |
| Lin's route saved while `STRIPE_KEY` was secret; an Owner marks it sensitive later | each use refused, `route_not_cleared`, naming the route and the key. The page marks the item: "an Owner of market must save it again" |
| Lin, in fork `market/dev-eu`, routes an inherited key she cannot read in `market/dev` | refused (R8: inherited values take read on the parent) |
| Lin routes `{API_KEY}`, a reference into `billing/prod` | decided where it lives (R20): her read of `market/dev` covers it; sensitive takes an Owner of `billing` too, as R32 has it for service tokens |
| Ada, an Owner of market, routes `{STRIPE_SECRET_KEY}` | allowed, and the entry says `routes sensitive` (R66) |

This makes routing **preventive for everyone but an Owner covering the
place**. For those Owners it grants nothing new. R30 already lets them
loosen a sensitive value to a secret and read it, audited, and break-glass
lets them read it through a service account. That bears on W260's pushback
1 (question 1).

Whether the frozen holdings should also be intersected with the editor's
holdings now, as R15 does for tokens, is question 5.

### Copying from another environment

"Copy from environment" fills the target's pending edits with every field
of the source items, upstream and egress included (R66). Saving them is an
ordinary save in the target, by the person saving, with their holdings
frozen there. Nothing is cleared because it came from elsewhere.

That copy can send the target's keys to the source's servers. Copy
`schuman` from `market/dev` to `market/prod`, where dev's route says
`upstream: https://sandbox.schuman.example, egress: 'schuman-dev'`, and save
it unchanged: prod's `{SCHUMAN_API_KEY}` now goes to the sandbox host. The
sandbox's certificate is valid for its own name, and the egress's host check
passes, so nothing fails. The key reaches Schuman's sandbox, a server of the
same provider, but not the one prod's key is for. Nobody without
`proxy.edit` in prod can cause it, and the save is audited, so this is a
review problem, not an access problem. Question 2 is what the review step
shows.

## 9. Threats, in one table

| Who | Tries | Outcome |
|---|---|---|
| A database writer, no key | edits an upstream, adds a route, or puts back an old row | refused (`tampered`, `stale`); fails closed (R64) |
| A database writer | deletes the row | the use's probe finds the newest change's seal and no row: `stale` |
| A Developer with `proxy.edit` | routes a value they cannot read, or one made sensitive later | refused at use: the frozen holdings decide (`ClearanceAtUse`) |
| An Owner covering the place | routes a sensitive key to a host they control | allowed and audited: the same power as R30's loosening (question 1) |
| An editor who later leaves | keeps a route to their host, and the value rotates | under question 5's option (a) it keeps sending, their holdings frozen; option (b) stops it |
| An Owner | copies a dev route into prod and saves it unchanged | prod's key goes to dev's upstream, audited; the review step names that destination (question 2) |
| An Owner, racing an app | edits mid-traffic | old values go to the old host for at most W, never to the new host undecided (section 3) |
| Someone with a stale page | saves over a newer change | 409: CAS on the seal |
| A compromised app (the `coffre` Worker) | anything | out of scope, as today: it holds the values it opens. The vault makes that loud (every decision logged), not impossible |
| An Owner | points an upstream at `169.254.169.254` | refused at save; on Node also at connect time |
| A code change | drops a name UI also had | the UI row was deleted when code first shadowed it, audited (`NoRevival`) |
| Anyone with `environment.manage` | renames an environment into or out of a code item's scope | nothing a UI item may be called changes: code names are taken in every environment (section 6) |

## 10. The implementation, in four PRs

Each runs the suite on both engines (`pnpm test`, `pnpm test:sqlite`), and
`pnpm formal` keeps `Routing.tla` and the code in step (R45).

**PR A: storage, the change path and the permission.**
- Migration `0050` (Postgres and SQLite): `proxy_definitions`, grants.
- `@coffre/vault`: object kind `proxy` (`inputs.ts`: its shape, seal and
  `applyOp` for `proxy.save` and `proxy.code`; `log-replay.ts`); the vault
  method that decides a save (proxy.edit on its sealed rows, frozen holdings,
  CAS).
- `@coffre/core/access`: `proxy.edit`, the role editor's new rule;
  `formal/lean` updated in the same PR (AGENTS.md: a change to the access
  rules changes the Lean model).
- API: `GET` and `PUT /api/projects/<p>/environments/<e>/proxy`, the save
  answering once sealed.
- Tests: save, CAS 409, permission matrix (built-in and edited roles,
  protected environments, tokens refused), replay agrees, the row tampered,
  put back or deleted (`stale`, `tampered`), the backup login reads it
  (`test:schema`), Lean cases.

**PR B: matching and injection, for code definitions first.** Server only,
no storage.
- The path rules and the allow list (section 7); several inject rules with
  their order rules; SigV4 over earlier headers; redaction across all of a
  route's keys; `environments` scoping on code items; `allow` beside
  `methods`/`paths`.
- Tests: hegel property tests of the matcher (no encoded form of a path
  outside a pattern is ever allowed; matching is linear in segments ×
  entries), the table of section 7 as unit tests, multi-inject end to end
  against a fake upstream (header + query, header + SigV4 with the signature
  verified), redaction of every key's forms.

**PR C: the use path for UI definitions.**
- `use_credential`: the proxy object(s) as inputs in both shapes, in the seal
  cache; the named use takes a route; the vault resolves its keys by name,
  decides twice and answers with the definition.
- The proxy: UI routes, signers, verifiers and tunnels; the value cache keyed
  by the definition's seal; the send before the deadline; the plan
  (`GET /use/<p>/<e>`) listing UI routes; `proxy.code` with its gate.
- Tests, one per `Routing.tla` protection, each on Postgres and SQLite: an
  edit between a use's statement and its send; a row put back; a key marked
  sensitive after a Developer's save; kept values never sent to a newer
  upstream; code shadowing then dropping a name. Also `request-cost.test.ts`
  (statements and rows flat as the log grows and as an environment gains
  definitions), the `/use` bench against 0.15.1 (no regression, R44),
  conformance for both examples.

**PR D: the page.**
- #421's Proxy tab on the API: the mock store goes, and so do the "0.16"
  badges. Locked code rows, `environments` scopes, copy, review, the role
  editor's row, the audit page's `proxy.save` and `proxy.code`, the
  `route_not_cleared` mark.
- Docs: `credential-proxy.md`'s sections on UI definitions; `coffre init`
  writes `editable: true`, so new deployments get the tab, while an upgraded
  one changes nothing until it opts in.
- Tests: the page's own (save, discard, 409 review, inert fields for a
  reader), the examples' parity test, `check:docs`.

PR B can go in parallel with A. C needs A and B. D needs A, and C for real
uses.

## 11. Questions for Erwin

Each has a recommendation; all are reversible.

**1. Owners routing sensitive keys: detective or preventive?** (W260's
pushback 1.) R16 and R32 say no person ever gets a sensitive value. A
definition that sends one to a host its editor controls gets it to them, and
the audit entry only tells after the fact.
- (a) As decided (R66): Owners covering the place may, audited. Section 8
  makes it preventive for everyone else.
- (b) As (a), plus a code-side list the deployment may set,
  `uiUpstreams: ['*.openai.com', 'api.stripe.com']`: a UI definition that
  sends a sensitive key must point inside it.
- (c) A second Owner approves each change that routes a sensitive key.

*Recommendation: (a), with (b) easy to add later.* R30 already lets the same
Owners read the value, by loosening it or through a service account, so
(a) adds no power to anyone. (c) adds a workflow for a case that is
already covered.

**2. What a copy shows before it is saved.** (W260's pushback 2.) Copying
keeps every field (R66), so a copied route sends the target's keys to the
source's upstream through the source's egress until someone edits it.
Section 8 has the example: prod's Schuman key sent to dev's sandbox host,
with no error anywhere. W260 assumed TLS would fail; it doesn't, because the
upstream moves with the egress.
- (a) Keep it silently.
- (b) Keep it, and the review step names, for each copied item, where it will
  send which of the target's keys: "`schuman` will send market/prod's
  SCHUMAN_API_KEY to sandbox.schuman.example (copied from market/dev)".
  Non-blocking: saving still saves.
- (c) Clear the upstream and egress on copy, so the copy cannot be saved
  until someone fills them in.

*Recommendation: (b).* It keeps "copy keeps everything" (R66) and puts the one
fact that matters, the destination of prod's keys, in front of the Owner
who saves. (c) would contradict R66.

**3. Names unique across kinds?** (W260's pushback 4.)
- (a) For UI items: unique across the four kinds in the environment, and
  against every code name. Code keeps today's per-kind rule, with a startup
  warning on a cross-kind clash.
- (b) Per kind everywhere, as code is today.

*Recommendation: (a).* Routes and tunnels share `/use/<name>`, one list shows
all four, and "code wins by name" needs one meaning of "name".

**4. The window after an edit.** Values decided before an edit keep going to
the old upstream for up to `cacheSeconds` (section 3).
- (a) Accept it, as for revocation. The save's confirmation says "the old
  upstream may receive requests for up to a minute".
- (b) A save that removes or changes an upstream answers only once the
  window has passed, up to 60 s of spinner, so that "saved" means "nothing
  goes there any more".
- (c) UI routes never cache values (`cacheSeconds: 0` for them): a vault call
  per request, more load on the hot path.

*Recommendation: (a).* It is the bound the proxy already documents, and the
old upstream was allowed a moment before.

**5. When the editor leaves or is demoted.**
- (a) Frozen at save: a definition keeps routing what its editor could read
  then. The offboarding preview lists the definitions they last saved.
- (b) Frozen and intersected with the editor's holdings now, as R15 does for
  tokens: a removed or demoted editor's definitions stop routing what they
  can no longer read. Each use answers `route_not_cleared`, naming who must
  save again, until an editor who can does. The use statement reads one
  more object, the editor's principal (no extra round trip).

*Recommendation: (b).* It closes the case of an editor who plants an upstream,
leaves, and receives every rotated value after. It also matches tokens. The
cost is loud breakage when an Owner leaves; the offboarding preview names
every affected route before the removal, so it never comes as a surprise.

**6. Do forks inherit UI definitions?**
- (a) By name, like values: `market/dev-eu` serves dev's `openai` unless it
  has its own `openai`. One more row per use through a fork.
- (b) No: each environment holds its own, and "copy from environment" fills
  a fork.

*Recommendation: (a).* A fork that loses its routes would surprise everyone
who forked for values.

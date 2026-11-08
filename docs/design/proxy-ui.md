# Proxy definitions in the UI (0.16, T186)

A design for 0.16's headline, written on 2026-11-01 (W304) before any
code. Rules R65 and R66; the UX is prototype
[#421](https://github.com/erwinkn/coffre/pull/421) (layout B, refined by
W260 and W263; draft, never merged). The model is
[`formal/Routing.tla`](../../formal/Routing.tla), described in
[docs/formal.md](../formal.md#routingtla). Nothing here is built.
Section 11 records the eight decisions it needed (2026-11-02).

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
   cannot forge one, nor put an old one back unseen. Its seal covers an
   index of item names and digests, so a use reads its own route's item,
   not the whole environment.
2. **Ordering.** An edit is a change under the fence, exclusive. A use reads
   the definition in its one statement, under the fence, shared. So every
   use is decided wholly before or wholly after an edit. Values already
   decided keep going to the old upstream for at most `cacheSeconds` (60 s,
   or the 3 s deadline with no cache): the same bound a revoked handle has
   today. TLC checks this, and finds a run for each protection removed.
3. **Who may route what.** Saving a definition freezes what its editor
   could read, exactly as issuing a service token does. Each use decides the
   route's keys twice: for the caller, as today, and for that frozen
   editor, intersected with what the editor still holds (decision 5). An editor who cannot read a value can never route it. A sensitive
   value is routed only by a definition an Owner covering the place saved
   (R66), the same people R30 already lets loosen it to a secret.
4. **Cost.** No round trip is added to a `/use` whose route names the same
   keys as before. The definition rides in the vault's call as two more
   rows and two more probes (its own and its editor's principal), and
   comes back in the answer only when the isolate's copy is stale. An edit that adds a key costs each isolate one extra call
   once, the map miss any new key costs today, and each isolate's first
   proxy request makes one call to check code's names (section 6).
5. **Code wins.** A UI definition whose name code also defines is ignored
   and shown locked (R66). An isolate reserves its code's names in the log
   before it serves its first proxy request. Reserving a name deletes the UI
   item of that name, audited, and the vault refuses new saves of it. No
   deploy drops a reservation, so a hidden item never comes back when code
   later drops the name; only an instance Owner's audited release frees it.
6. **Matching** runs on the percent-decoded path, segment by segment.
   `..`, `.`, encoded slashes and double encoding are refused, never
   resolved. `*` matches one segment and `**` the rest; a plain path is a
   prefix. No regexes.
7. **`proxy.edit`** is a new place permission. The Owner role holds it
   (Owners hold every permission), so by default only project and instance
   Owners edit. The role editor gets a row for it.
8. **One version at a time.** The app and the vault Workers run one
   release, and a deploy or a rollback moves both. Every app-to-vault call
   carries its release; a vault on another one refuses it before it reads
   anything, and the app answers 503 `deploying` with `Retry-After: 1`.
   No part of this design serves across two releases (section 3, decision
   8).

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

An egress gains a `hosts` list in 0.16: today it is only `{ fetch }`, and
code's route trusts it whatever its upstream. A UI route that names an
egress must have an upstream among its `hosts`. An egress name that code no
longer declares makes the route answer 503 naming it. It never falls back to a direct fetch, as code's rule is today. A
database through a network must name hosts among the network's, which
keeps R31's rule: private addresses and `sslmode=disable` need an explicit
binding.

`editable: false`, the default, keeps a deployment's uses as today: no
Proxy tab writes, and no use reads a `proxy` object. One thing still runs:
the gate of section 6, which reserves the names code defines, once per
isolate, whenever `credentialProxy` is configured. Without it, this run
would revive a route: D1 (`editable: true`) has a UI `maps`; D2 sets
`editable: false` and adds code `maps`, which serves `/use/maps`; D3 turns
`editable` back on and drops code `maps`, and the UI `maps`, unseen since
D1, would serve again. So `editable` decides what the tab may write and
whether uses read UI items, never whether code's names are reserved.

## 2. Storage

### Where

One table, Postgres first (R50), SQLite for tests and local development:

```sql
CREATE TABLE proxy_definitions (
  environment_id uuid PRIMARY KEY REFERENCES environments(id),
  items          jsonb NOT NULL,   -- the canonical object: name -> item, with who saved it
  digests        bytea NOT NULL,   -- the index: (name, SHA-256(canonical item)) of each item, sorted by name
  seal           bytea NOT NULL    -- the vault's HMAC over (kind, id, digests), 16 bytes
);                                 -- (not `index`: a keyword SQLite refuses as a column name)
CREATE TABLE proxy_reserved (    -- one row: the instance's
  id     smallint PRIMARY KEY CHECK (id = 1),
  names  jsonb NOT NULL,           -- every name code has reserved, the whole set
  seal   bytea NOT NULL
);
GRANT SELECT ON proxy_definitions, proxy_reserved TO coffre_vault, coffre_backup;
-- written only by the vault's logins, through its change functions; the app
-- reads neither: every read of them is a vault call (section 4)
```

**A use reads one item, not the environment.** The seal covers an index,
not the items themselves: each item's name beside the SHA-256 of its
canonical body, sorted by name. A use's statement reads its route's item
(`items -> 'openai'`), the index and the seal. The vault checks the MAC
over the index, looks up the name it asked for there, and hashes the item
it read against that entry. A forged item fails the digest, a forged index
fails the MAC, and so does a moved item: a writer who drops `a` and stores
A's body under `b` leaves the sealed entry `b` naming B's digest, which A
does not hash to.

The names are in the index, not only in the hashes, so that the vault can
tell a route the object lacks from one a writer deleted. That matters for a
fork (decision 6): `market/dev-eu` with its own
`openai` serves it, and without one serves `market/dev`'s. If the index
held only `SHA-256(name || item)`, a writer could delete `openai` from
dev-eu's `items` alone, leave the index and seal alone, and the use would
fall back to dev's item: dev-eu's key would go to dev's upstream, which no
dev-eu definition says. With names in the index, the vault falls back to
the parent only when the child's sealed index has no entry by that name.
An entry whose item is missing is `tampered`. Values inherit through a
chain of forks, up to three parents (`MAX_PARENTS`), and definitions do
too: the lookup walks the ancestors nearest first, applying these rules at
each level, and stops at the first sealed index that names the route. The
statement reads every level's row at once, in one snapshot: up to four
rows and four probes per reading. It checks each level, seal and index,
nearest first, through the one that serves, and weighs none past it: a
forged grandparent row fails only the uses whose lookup reaches it. The
seal an answer carries, which `OneVersion` holds and each value-cache
entry carries, is the list of the checked levels' seals, nearest first, so an edit at
any of them changes it, a nearer level adding the name included. A missing child row is the
same check one level up: the child has no row only if its object has no
logged change (the seal probe sees its newest change), and a row deleted
after a save is `stale`.

What crosses from Postgres to the vault, and what the vault hashes, is one
item and the index: a name of at most 32 bytes (section 6's name rule)
and 32 bytes of digest per item, about 2.5 KB at 50 items with typical
names. A save may hold at most 256 items, so the index stays under 17 KB.
Sealing the whole `items` instead would carry every item, every editor's
frozen holdings included, on every use of any of them.

The migration only adds (AGENTS.md, "expand, then contract"), and grants
`coffre_backup` by name as every new table does. An environment that never
had a UI definition has no row. Once its object has a change, the row
stays: removing the last item saves an empty index, so a later missing row
is still `stale` and a fork's lookup still falls back by the empty index.

**Why one row per environment, not one per item.** The page saves all its
pending edits at once (save, discard, review), and copying from another
environment writes many items. One object makes that one change, one seal
and one entry, and the index keeps a use's reads to its own item. A use reads one row for its environment, and one more
for each parent of a fork, whose definitions it inherits (decision 6), up to four. The cost is that two
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
    "holdings": { "role": "member", "scope": { "projects": "all", "environments": "all" }, "instance": { "normal": [], "protected": [] },
                  "grants": [ { "projectId": "…", "environmentId": null, "role": "owner", "permissions": { "normal": [ … ], "protected": [ … ] } } ] } }
] }
```

No answer to the app carries `holdings`: a use's, `proxyItem`'s and
`GET …/proxy`'s carry the definition, and `route_not_cleared` names the
editor in the vault's own message.

`holdings` is the editor's standing as a service token's scope keeps it:
their instance role, its scope and its columns, and each grant with its
role's columns (`ScopeGrant` in `@coffre/core/access`), each as the policy
defined it at the save, so no role widened later widens the route. It is
their grants, not what they held at the places the save saw: a fork made
later inherits the definition, and is decided by the grants that reach it
(a `router` on `market/dev` reads none of `market/dev-eu`'s own keys, a
`router` on all of `market` does). Who routes sensitive values is whoever
those holdings make an Owner of the project (R66). Section 8 explains how a
use weighs it. An item the save did not change keeps its `savedBy` and
`holdings`. So Bo's edit of `maps` leaves Ada's `openai` cleared as Ada.

### Changes and audit

Three change ops, each through the vault's change path (`change_input`: CAS
on the seal the caller read, the fence exclusive, the entry numbered under
it, the answer once sealed):

| Op | Who | Changes | Payload, in the entry (R53: the request, not the outcome) |
|---|---|---|---|
| `proxy.save` | a person holding `proxy.edit` on the environment | the environment's `proxy` object | the environment, the seal the page loaded, and each item added, changed or removed, whole |
| `proxy.code` | the deployment (actor `deployment`): the app's own call to the vault at its gate, with no HTTP route, so no person or token can make one | the `proxy-reserved` object, and the `proxy` object of each environment holding a name it adds, in one transaction | the names it adds, and each UI item it deletes, whole |
| `proxy.release` | an instance Owner, through `PUT /api/proxy/reserved` | the `proxy-reserved` object | the name released |

The reserved set follows the policy object's precedent
([sealed-inputs.md](sealed-inputs.md)): one instance-wide object, kind
`proxy-reserved`, whose every change carries the **whole set** as its
value. So "is `maps` reserved" is one read of one row, checked current
against its newest change's seal, never a sum over earlier entries. Three
statements probe it: a save (`SaveChecksReserved`), a release, and an
isolate's gate (section 6). A `proxy.code` change is one entry per object
it changes, the reserved set's and each environment's, in one transaction
under the fence.

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
  replaced), and (c) was cleared for the key's nature at that decision. A
  request that carries several keys (Basic's user and password, SigV4's
  two) carries them under one version.
- **`WithinWindow`.** That request leaves within W of the decision: W is
  `cacheSeconds` with the cache, or the use's 3 s deadline without it.
- **`NoRevival`.** No use is decided on a UI definition once code has
  shadowed it, by any isolate, then or after code drops the name. Code
  shadows a UI item when an isolate running it reserves the name (its gate,
  before its first proxy request) or shows the item locked. A deployment
  that never served a proxy request shadowed nothing, because nothing ever
  served or showed its definition. Values decided on the UI item just
  before the reservation serve out their W, as after an edit.
- **`RoutingRelease`**: an instance Owner who releases a reserved name while an older
  deployment still serving defines it, then saves it, is the one revival
  left: `EXPECTED` broken, and the release dialog says so (section 6).
- **`MismatchInert`.** No vault call reads or changes a route while the
  caller's release and the vault's differ (`RoutingVersion`, decision 8).
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
values serve out the window. Decision 4 accepts that window; section 11
lists the strict alternatives it set aside.

### The protocol

Two isolates keep two things. The vault's keeps 0.15's map from names to
ids (`cache.named` and `cache.keyed` in `use.ts`). The app's keeps its copy
of each route's item (the definition and its digest), the place's index,
and when an answer last confirmed them.

```
use (a named use, as 0.15's: one call on a map hit, section 4)
  app      find the handle in the request by its shape (it does not need the definition for that)
  call     use_credential(token, both URL readings, the ids the vault's map holds, the digest of the app's copy)
             fence shared
             one statement, one snapshot:
               the caller's rows, as today
               the editor's principal (decision 5)
               the route's item, the index and seal of the place's proxy row (and each fork parent's,
                 nearest first, taken only when every nearer sealed index has no entry by the route's name),
                 and the seal of their newest change
               every key of the route as that item names it, held to the map's ids (else `moved`), and their rows
             one entry per key: the request, the route's name included, under its MAC
           commit
  vault    seals checked (proxy object included), then every key decided twice:
             for the caller (purpose use, as today)
             for the definition's editor: frozen holdings, intersected with current ones (section 8)
           answers: the values, the definition's seal, its item digest, and its definition, never its holdings (omitted when the app's copy has that digest)
  app      sends by the definition the answer names (its item, or the copy whose digest it confirmed);
             each later round and chunk's seal list must be the first statement's, which the vault
             checks, else `moved` (`OneVersion`)
           checks the handle (section 7), and the method and path against the definition's allow list
           keeps the values beside that definition (the entry carries its seal and item)
           sends, before the use's deadline, to that definition's upstream
```

**One version at a time** (decision 8). The app and the vault Workers run
one release, and a deploy or a rollback moves both: `pnpm run deploy` deploys
the vault, then the app (docs/deploy.md), and Workers Builds deploys both
on every push. No part of this design serves across two releases. The
release is the packages' one version, read from `@coffre/core`'s
`package.json` (a JSON import both Workers bundle), so `pnpm bump` moves
it and nobody bumps a protocol number by hand.

The check has one funnel on each side, so that no call, the hot path's
included, goes around it. Many of `Vault`'s methods take no input
(`about()`, `settings()`, `checkpoint()`) or a bare string (`access`),
so the release does not ride in their inputs; it rides in an envelope
around every call:

- **The vault: one entry, `call(release, method, args)`.** It compares the
  release before anything else, before `#prepared()` reads the config or
  any pool opens, and on a mismatch answers `{ release: <its own> }` and
  runs nothing. On a match it runs the method and answers `{ release,
  result }`. The contract is in `@coffre/core/vault`, beside `Vault`:
  `VaultEntry`, the object with that one `call`, and its answer type.
  Each vault process gates once, at its outermost entry, and nothing
  inside it gates again:
  - Workers: `VaultEntrypoint.call` is the Worker's only public method.
    Its per-method members become private (`#use`, `#useNamed`,
    `#unwrap`, and the rest), so the hot path's `#behind` and
    `#prepared` sit behind the check like `#call`. `call` compares the
    release, then dispatches to the private member with its body intact:
    each keeps its own pool and start (`use`, `useNamed` and `useMany` the
    hot login's pool under `#behind`, closed by the deadline in their first
    argument; the rest `#call` under `#ready`; `sealing` no database and
    no start, so `/readyz` stays bounded), and `about` still adds `uses`
    and `batchUses`.
  - In process: `openLocalVault` returns a `VaultEntry` whose `call`
    gates, then dispatches into its `METHODS`, JSON round trip included.
    `LocalVault` becomes `VaultEntry & { close() }`, so `serveVault` still
    stops it.
    The two sides are one bundle and cannot differ, but answers go
    through the same envelope so its tests hold it.
  - Node: `serveVault` holds that same entry (`localVault` →
    `openLocalVault`) and has one route, `POST /call`, whose body is
    `{ release, method, args }` and which forwards to the entry without
    gating again. `connectVault` returns a `VaultEntry` whose `call`
    posts there and resolves the envelope whole. The per-method routes
    (`POST /<method>`) go.

  The Workers binding is typed `VaultEntry`, not `Vault`, in the
  examples, `coffre init`'s templates, `dev/deployment` and
  `createCoffre`'s config.
- **The app: one wrapper, `versioned(entry, release)`**, which gives the
  app back a `Vault`: each method becomes `entry.call(<release>, name,
  args)`. An answer on another release, or with none, throws
  `ApiError('deploying', …)` with `retryAfter: '1'` (`deploying: 503` in
  `ERROR_STATUS`, and `errorResponse` adds the header for `deploying` as
  it does for `unavailable`). No handler sees a mismatch. Sign-in checks
  ask the vault before any handler runs, and their catch-alls in
  `auth.ts` answer `unavailable`; each rethrows an `ApiError` whose code
  is `deploying` instead, so a signed-in route answers `deploying` too. The wrapper
  replaces `createRuntime`'s `vault` parameter on its first line, before
  `SigninService`, `WorkloadService` and `McpService` are built from it,
  so no service holds the raw transport. It is kept in a `WeakMap` keyed
  by the entry it wraps, as `{ release, vault }`, and rebuilt when a call
  names another release (a bundle constant in production; tests build
  both over one fake entry): on Workers `createRuntime` runs per request, and
  a new wrapper each time would miss `about015`'s cache (keyed by the
  vault object) and add an `about()` call to every use.

A refusal is an answer, not a thrown error: a Workers RPC error keeps
its message but not its fields, and a Node failure would map to 500
(`failureOf`), so neither could say `deploying` reliably. What the tests
hold is per call: a mismatched call runs no statement and writes no
entry. The envelope adds a string comparison, not a round trip (R44).

That covers the one upgrade into the rule. The 0.16 vault, deployed
first, has no public per-method entry, so a 0.15 app's calls (to `use`,
`access`, and the rest) fail before any read, as that app fails any
vault error, for the seconds until the app deploys. A 0.16 app in front
of a 0.15 vault finds no `call`: the Workers stub throws, `/call`
answers 404, and the app fails as on any vault error (500), not with
`deploying`, reading no route; the 0.15 vault has no proxy definitions
anyway. Only a release that has `call` can answer `deploying`. During a
deploy, mismatched calls wait out the seconds until both Workers match.
Main has no per-call version today: `about()` lists capabilities (`uses`,
`batchUses`, `sealing`), which is how 0.15 serves an app ahead of its
vault. The proxy adds no capability bit and no code for a mixed pair.
TLC's `RoutingVersion` holds that a call on another release never reads
or changes a route (below, "What each protection is for").

**Every route use takes this one shape.** Today only a handle with exactly
one key goes by name (`byName` in `packages/server/src/plugins.ts`); a
handle with several keys, every workload, and `sign`/`presign` and a
tunnel's `run` go by ids, through `reveal`, `useValues` and `useMany`,
whose answers (`UseManyOutcome`, `Used`) carry no seal, no digest and no
item. A use by ids reads no route: the vault would decide the caller
alone, never the definition or its editor, and the app would send a UI
SigV4 route (two keys, and presign's only kind) by its own copy
(`SentAsDecided`). So a UI route's use never goes by ids. It is one
call, a route use, whose contract is:

- **Input.** The caller, as `proxyItem` names it: a handle by its token's
  hash (`NamedUseInput`'s `tokenHash` and `accepts`), or a workload by its
  credential's id and `way` (`connection`, `binding`, `access`), as a
  batch names it today; a Cloudflare binding has no token, and is the
  second kind. Then both readings of the URL, the place reading and the
  stable one (section 6), on a hit too, since the statement answers
  `moved` when the rule would now pick the other; with the map's ids for
  the reading it picked, when it holds them. A workload has no token,
  so no made-for list: its hit keys on the requested place's id (not the
  fork ancestor that serves the item) and the route's name. For a batch,
  the route replaces `items`.
- **The route's keys are the item's own list.** A route's keys live in its
  inject templates (`{KEY}`), which today only a TypeScript regex in the
  proxy reads. The vault does not parse templates in SQL. At save, it
  computes each item's key names once, with one parser in `@coffre/core`
  that the proxy's startup validation also uses, and stores the list in
  the canonical item, under its digest. The statement holds the map's ids
  to that stored list, save-time clearance reads it, and replay reads it
  from the same item. So live and replay cannot disagree on a key set
  (R53), whatever a template's braces look like.
- **Places.** The statement serves fork places: it finds the item through
  the fork chain (section 2) and resolves each of the route's key names
  through the chain too, nearest first, as values inherit. Today's named
  resolution serves only an environment with no parent and no owner
  (`v_live` in `0045_decide_first.sql`, `served: false` otherwise); the
  route use lifts that for routes only. A personal config (a fork owned by
  one person, `docs/design/forking.md`, and the proxy's `@me` reading for
  generated keys) is not served by UI routes in 0.16: the editor's frozen
  holdings can never read an owner-only value, so every use there would
  be `route_not_cleared`. The route use reads the base place, never `@me`,
  and a UI route asked for at a personal config answers 409
  `route_not_personal`, naming the base environment (decision 7). Code
  routes keep `@me` as today.
- **Outcome.** `NamedUseOutcome`'s `name` route, widened per key: for each
  key its use outcome, a sealed value or a plain one (a plain key has no
  envelope, and a route of plain keys only is still one use, below), with
  the plain list redaction reads; the caller's standing and its credential's
  `expiresAt`, from which the value cache takes its bound, as `valuesFor`
  does today; the place by slugs and ids; the seal list; the item digest;
  and the item when the isolate's copy is stale. One outcome type for
  handles and workloads.
- **One app function.** Every path that consumes a UI route's values calls
  it: a handle's forward of any number of keys, the stable URL's
  no-cache path (today `coffre.useMadeFor`, which bypasses `valuesFor`), a
  workload's forward, sign with a private key (which calls `coffre.use`
  and never caches today), verify and presign, and a tunnel's dial and its
  rechecks. It takes the definition from the answer before anything else
  sees it: before the value cache keeps it, before a sign or presign, and
  before a tunnel dials. A thrown vault error and `served: false` are a
  503, never the by-ids fallback a code route takes when `byName` returns
  null.

The plan's placeholder shaping is not a route use. To copy a JWT's claims
into its placeholder, the plan opens the key's value for the caller alone,
purpose `expose`, so the claims show the caller nothing they may not read
(a code route's opens it as a use: the deployment's code chose its claims,
an editor chose a UI route's). That value goes into the
caller's own environment and never to the definition's upstream, so the
editor is not decided there, and the plan's `proxyItem` call is what holds
it to the vault-checked item. Code routes keep today's shapes unchanged.

All of a route's keys are decided on one version, in that one statement.
A use of several keys may need a second round today (`useMany`: a key that
takes its principal's lock is decided again on fresh rows, after the
first), and a large batch runs in chunks. Every later round of a route use
must read the seal the first one read, or the whole use answers `moved`
and starts over. Otherwise a SigV4 route could have its access key decided
on version 7 (`good`) and its secret key on version 8 (`evil`), and one
request carries both to one host (`OneVersion`).

```
edit (one change)
  vault    reads the row and decides proxy.edit, freezing the editor's holdings
  call     change_input: fence exclusive, CAS on the seal read, write, entry numbered, commit
  answer   once the entry is sealed (R51)
```

### The app's checks on its copy, on every path

Every path checks a request against its route before the use answers, as
code routes are checked today:

| Path | What it checks before the use's answer |
|---|---|
| A handle's route (`forward`) | `aim` (the path against the upstream and allow list), `carried` (stream the body or read it whole, by inject kind), `fieldIn` (where the handle sits) |
| A workload's route (`workloadForward`) | the same, the DPoP body-line rule, and the limit's counts |
| Sign, verify, presign (`compute`) | which signer, verifier or credential the name is, its kind, presign's path and `narrow` checks |
| A tunnel's open | the item's hosts |

For a code name these read code. For a UI name they read the app isolate's
copy of the item, which may predate an edit, or be missing (a cold
isolate). One rule covers every path:

- **What the copy lets through is provisional.** The use's answer brings
  the decided item, or confirms the copy's digest, and the checks run again
  on it, with the target rebuilt from its upstream; on a value-cache hit
  they run on the entry's item instead (section 4). If the decided item
  would have carried the body otherwise, bound another body line, or found
  the handle's field elsewhere, the request is 503 `moved` and nothing is
  sent. The client's retry finds the new copy.
- **What the copy refuses stands only while the copy is fresh.** The app
  isolate keeps, beside each copy, when an answer last confirmed it. A
  refusal on a copy confirmed within `cacheSeconds` stands. On an older
  copy the isolate makes one `coffre.proxyItem` call, replaces its copy
  and checks again; what the checks refuse then is refused. With no copy
  there is nothing to refuse yet: a handle's checks wait for its use's
  answer, which carries the item, and a workload's, sign's or verify's
  run on the item its counts' `proxyItem` brought (below). A name
  in neither code nor the place's index answers 404 only after that:
  `compute`, which today answers 404 from code's maps before anything
  else, keeps that 404 for a name code lacks until the call, made for a
  workload once the proof is verified and the caller stands, for a handle
  with the handle.
- **`coffre.proxyItem(caller, place, name)`** is a new context method,
  used only under `editable: true` (under `false` a name code lacks is 404
  at once): a vault call that checks its caller as a use would, by the same ways
  (`USE_WAYS`: a handle's credential row, a connection, a Cloudflare
  binding's row, read whole as `w_row` is, or a session's access), reads the place's sealed
  proxy rows as a use's statement does, and answers in the shape a use
  sees. That is: the item and its digest; the seal list of the levels it
  checked, nearest first (section 2); the serving index, every name the
  chain serves with the level that serves it, so a parent-only route is
  found in it. It is given a place already resolved and never chooses
  between a stable URL's two readings (section 6), which only a use
  does: a refusal's refresh takes the place its copy was keyed under, a
  workload's counts its session's place, and the plan the place its URL
  names. It also resolves the
  item's keys by name, and the vault isolate's map keeps their ids as a
  miss's first call does, so the use that follows is a map hit. With no
  name it answers every item the place serves (the plan's call, section
  6). It decides no use, opens no value and writes no entry. A caller the
  vault refuses gets that refusal and refreshes nothing, which costs what
  a bogus handle's use costs today. The app keeps the serving index, so a
  name absent from one confirmed within `cacheSeconds` is 404 with no call.
  It cannot be `coffre.use`, whose caller is the session a workload is
  still standing up.
- **When it is called, by whom.** Two sites, apart. *Counts:* a
  workload's limit on a cold copy (below) is read inside `standingSession`
  or `bindingWorkload`, after the proof and every clause are verified and
  the place is resolved, before `gate.admit`: the caller is the session
  row's principal at that place, or, in `bindingWorkload`, the binding's
  row (principal `token:<service>`, no session row), and the `jti` is not
  spent yet. If the
  call is refused, or finds no such name, or finds it `tampered`, the
  counts are `[]` and the outcome is kept: the gate then admits or refuses
  as it does today, and an admitted request answers that outcome, never a
  raw error out of `standingSession`. *Refusal refresh:* after the caller
  stands and, for a workload, after the gate has counted the request.
- **Where a UI name enters.** Today each entry point finds a name in
  code's maps and answers 404 before anything else: `serve` tries a
  workload only for a code credential, an environment URL 404s a name code
  lacks, a stable URL peeks for a field handle only in known credentials,
  and a tunnel's `open` 404s before any caller. For a name code lacks,
  under `editable: true`, each takes one order. `serve` and `compute`:
  a session-shaped request (DPoP, a binding) stands its workload first,
  with its counts as above; otherwise the handle is found by the bearer,
  `x-coffre-handle` or the query, and else by its shape in the body read
  whole (within today's body limit), and the decided item's `fieldIn`
  must find it there after the answer, or 503 `moved`. Then the copy;
  with none, the use itself for a handle (its answer carries the item, as
  section 4's cost row says), or `proxyItem` where counts need the item
  before the use (workloads, sign, verify); a 404 only when that use or
  call finds no such name. `open`: the caller from the
  socket's handshake as today, then the copy or `proxyItem`, then 404. A
  stable URL's place is known only once its caller stands, which is why
  the caller comes first on every path.
- **What that costs.** Refreshes go by place and name, not by request:
  refused traffic costs at most one call per route per `cacheSeconds` per
  isolate, and unknown names at most one per place. An app isolate with
  no copy of a route costs nothing more on a handle's path (its use,
  carrying no digest, gets the item in its answer) and one `proxyItem`
  call on a workload's, sign's or verify's (its counts), once per isolate
  per route; section 4 counts it. A widening edit (an Owner adds `POST /responses/**`
  to `openai`) takes effect on every path within `cacheSeconds`, as a
  limit edit does, and no warm isolate refuses it for good.

### Workloads, signers, verifiers, tunnels and presign

The protocol above is a handle's route use. The other callers and kinds
take the same use, with what changes for each:

- **Workloads** (a DPoP session or a Cloudflare binding's caller,
  [workload-access.md](workload-access.md)). UI routes serve them as code
  routes do, since prod's callers are workloads (R38's sidecar among them).
  Today's `workloadForward` reads the credential at several steps before
  the use's answer exists. For a UI route each step reads the isolate's
  copy, which came from the vault (`CopyFromVault`) but may be older than
  the version the use decides on, so each is either provisional or moved
  after the answer:
  - *The limit.* Today the counts are a plain function of the credential
    (`countsOf`, giving `GateCounts`), and the gate (the principal's
    Durable Object) takes them with the proof's `jti` in one call, after
    the proof is verified. A stable URL's place is known only inside
    `standingSession` or `bindingWorkload`, and `PluginContext.workload`
    makes no vault call. So for a UI route the counts become
    `(principal, place) => Promise<GateCounts>`, which those two call once
    they have the place, before `gate.admit`. On a warm isolate it reads
    the copy. On a cold one it calls `coffre.proxyItem` (above), as the
    session's principal, or the binding's row for a binding's caller. The use's own call follows the gate, so a cold request still costs 2 calls, now one
    before the gate and one after. Sign, verify and presign take their
    counts the same way. After an edit
    to a limit, an isolate counts against the old one until its next use
    answer brings the new item: at most `cacheSeconds` (60 s by default)
    while its values are kept, one request when `cacheSeconds` is 0. A
    limit is a throttle, not who may use what: the two decisions of the use
    still decide that, on the newest version.
  - *What is read before the answer.* `aim` (the path against the
    upstream and allow list), `carried` (stream the body, or read it
    whole, by inject kind), the DPoP body-line rule (a `sigv4` copy admits
    an unsigned body line only with `unsignedUploads`) and `fieldIn`
    (where the handle sits) read the route. Today they all run before
    `standingSession`, because the body line is an input of the proof's
    verification. A cold isolate has no copy there, so for a stable URL
    the order is: the body line and `carried` are computed from the
    request's headers alone, by the client's rule whatever the inject kind
    (`bodyLine` in `dpop.ts`, which `workload.ts` applies: a declared `Content-Digest` or
    `x-amz-content-sha256` streams, any other body is read whole); the
    proof is verified and the caller stands; then, with the copy (or
    `proxyItem`'s item), `aim`, `fieldIn` and `compute`'s kind checks run.
    The server admits an unsigned `x-amz-content-sha256` line only for a
    `sigv4` item with `unsignedUploads`, so a request that came with one to
    any other item is 503 `moved`. A field-kind item (form or JSON, whose
    handle is in the body) reached by a request that streams is read whole
    at that point, before anything is sent: its line stays the one the
    proof bound, and the declared digest still checks the bytes.
  - *Refusals on the copy* are provisional, as the section above says.
    The gate counts the request before the `proxyItem` call.
  - *After the answer.* When the answer's item digest differs from the
    copy's, the app runs `aim`, the allow list and `fieldIn` again on the
    decided item, and if the decided item's inject kinds would have
    carried the body differently, bound another body line or put the
    handle's field elsewhere, it answers 503 `moved` and sends nothing.
  - *On a value-cache hit* no answer comes, and the isolate's copy may be
    newer than the values: session A's values were decided on version 7,
    and session B's use has since brought version 8. The checks have run
    on the copy, provisionally, as on every path. The cache entry carries
    the item its values were decided on: `aim`, the allow list and
    `fieldIn` run again on that item, the target is rebuilt from its
    upstream, and `narrow` and the send go by it, never by the copy
    (`BoundToDefinition`). If the copy carried the body, bound the line or
    found the field in a way the entry's item would not, the request is
    503 `moved` and the entry is evicted. The same holds for a handle's
    route use.
  - *`narrow` constraints* are weighed after the use's answer, on the URL
    built from the decided definition's upstream, never the copy's, just
    before the send. A constraint that refuses there sends nothing.
  - *The use* is the route use above, the session or binding named as the
    caller (never today's `reveal` and `useMany` by ids): the session is
    the caller of the first decision, the frozen editor the second's, and
    the values are kept per session, place and route, each entry carrying
    the object seal and item they were decided on (section 4).
- **Signers and verifiers.** A named use of the item by its name, decided
  twice like a route's keys, the entry carrying the name. The editor's
  frozen holdings must read the key, sensitive included only for an Owner
  covering the place (section 8). Signing alone never hands the key out, so
  that is stricter than it needs to be; it keeps one rule for every kind,
  and Erwin may loosen it for signers later. A signer's `limit` is counted
  as a route's (above). On a value-cache hit, an HMAC sign or verify takes
  its parameters (`encoding`, `prefix`, the algorithm) from the entry's
  item, never the copy: a copy refreshed to version 8 with a new `prefix`
  must not wrap a secret decided on version 7 (`BoundToDefinition`, as
  for a route's send).
- **Tunnels.** A named use of the database item; the tunnel dials the
  decided item's hosts, checked as section 5 says, and the session keeps
  that item's digest. Today's recheck, every `recheckSeconds`, is a plain
  use reduced to "the key is still there" (`run` in `credential-proxy.ts`),
  which an edit to the item leaves passing: an Owner who narrows `hosts`
  mid-session would see logins keep going to the host dialled before. For
  a UI tunnel the recheck is a named use of the item, like the open, and
  it passes only if the decided item's digest is the session's. Otherwise
  the session ends, and the client's reconnect dials by the new item. An
  edit to another route of the environment changes the object seal, not
  this digest, and ends nothing. The bound is Tunnel.tla's: a session
  outlives the edit by at most `recheckSeconds` plus the check's deadline
  (70 s by default).
- **Presign.** Today a presigned URL assumes one `sigv4` rule and checks the
  path with its own, weaker rules; it builds the target URL and checks
  `paths` and `narrow` before the use, then signs that target after it. A
  UI route presigns only when `sigv4` is its one inject rule, and any other
  route answers presign with 400. The checks before the use run on the
  copy, and their refusals are provisional (above). After the answer, the target is built again from
  the decided item's upstream. The decided item must still have `sigv4`
  as its one inject rule, and allow the method; section 7's matcher, its
  allow list and the `narrow` constraints run again on it, and only then
  is anything signed, with the decided item's `sigv4` parameters. An edit
  between the copy and the use can never get a URL for the old host, or
  under the old rule, signed with keys decided on the new version: any
  mismatch is 503 `moved`. The use's entry logs the decided item's host,
  not the copy's: for every route use, the vault derives the logged host
  from the item it decided on and ignores the host the app passes, which
  the app built from its copy before the use.

### What each protection is for

Each row is a constant of `Routing.tla`. With it off, TLC finds the run
described, which `scripts/formal.sh` holds as a failure on every CI run.

| Protection | Without it, TLC finds |
|---|---|
| `FencedRead`: the definition is read in the use's statement, after the fence, in one snapshot with the decision | the use reads `openai` → `api.openai.com`, Ada's edit commits, the use is decided on the old row and numbered after the edit (`EverySendAllowed`) |
| `SealChecked`: the row's seal must be its newest change's | a writer puts back version 7 after version 8, and a use is decided on it |
| `CopyFromVault`: the isolate's copy comes only from vault answers, never from a read of its own | a writer forges the item beside its genuine index entry, the app reads that pair, the writer puts the genuine row back; the vault checks the genuine row, sees the app's digest, omits the item, and the app sends by the forged body (section 4) |
| `SentAsDecided`: the app sends by the definition the vault decided on (returned in the answer, or omitted because the copy has its digest), never by its own unchecked copy | the app's copy still says version 7. The vault decides on version 8, a Developer's (clearance `secret`, host `evil`), and the app sends to version 7's host, which no current definition allows |
| `BoundToDefinition`: kept values go only to the definition they were decided under | values decided on version 7 (`good`) are served from the cache after the app re-read version 8 (`evil`). The key reaches `evil`, which the vault never decided on for them |
| `ClearanceAtUse`: each use weighs the key's nature now against the definition's clearance | a Developer routes `K` while it is secret and is made an Owner since. An Owner marks `K` sensitive, and the next use sends the sensitive value to the upstream she saved as a Developer (`RoutingEditor`) |
| `EditorStillHolds`: each use weighs the key against its editor's standing now, read in the same statement | Ada saves `openai` and is removed from the instance; her route keeps sending `K` to the upstream she chose (`RoutingEditor`) |
| `KeptExpires`: kept values serve W, no longer | values sent long after their decision (`WithinWindow`) |
| `OneVersion`: a route's keys are all decided on one version, and the app sends only answers carrying one seal | key 1 is decided on version 7 (`good`), an Owner's edit to version 8 (`evil`) commits, a later round decides key 2 on version 8, and the request carries both to `good`: key 2 goes where no version it was decided on says |
| `ClearSuperseded`: the `proxy.code` change that reserves a name deletes its UI item | code defines `openai` for a while, then drops it, and the stale UI `openai`, unseen for months, serves again (`NoRevival`) |
| `SaveChecksReserved`: the vault refuses a save of a reserved name | during a deploy, an Owner saves `openai` through an old isolate after the new one reserved it; the new code hides it, and it serves again when a later deployment drops the name |
| `CodeGate`: an isolate serves no proxy request before its code's names are reserved | the same revival, through a deployment that served `openai` from code without ever reserving it |
| `VersionGate`: the vault refuses a call on another release before it reads anything | the vault moves to the next release while an app isolate still runs the last one, and that isolate's save or use reads and changes the route (`MismatchInert`, `RoutingVersion`) |

The model runs two isolates, which may run different code during a deploy
(two configs of one release: a deploy that changes `credentialProxy` alone
keeps the release, so the version gate does not separate them), and a
writer who can forge a body or put a row back. What it does not
cover: the fence's own correctness (that a use and a
change never overlap, and the number orders them) is `HotPathOne.tla`'s, for
any input. Here an edit is one step. One route, two hosts; its second key
appears only when `OneVersion` is off, since with it on both keys share
every decision. The frozen holdings are reduced to one clearance per
version ("sensitive" for an Owner, "secret" otherwise), and the editor's
current standing to one clearance per editor, which a change of their
principal moves either way (PR C, decision 5(b): `EditorStillHolds`,
scenario `RoutingEditor`). The matching rules of section 7 are pure
functions, which property tests hold, not TLC. That a map hit's ids are
held to the route's names is Naming.tla's `HeldToNames`, unchanged. Renames
are not modelled, because they cannot change what code shadows (section 6).
The caller is one kind: a workload's use differs only in who the first
decision is for, and its limit and `narrow` constraints (above) decide
nothing about where a key may go. The sealed index is below the model's
one body per version: PR A's tests move an item under another name, and
delete a fork's item to make the parent's serve, and expect `tampered`.
A deleted row is the vault's `stale` (PR A tests it). Covers are
`HotPathOneCovers`'s, for any input: a route use only adds the route to a
cover's identity and the proxy object and editor to its inputs, which
PR C's cover tests hold (one route here cannot share a key with another).
The plan sends nothing, so it is below `EverySendAllowed`; PR C's plan
tests hold that it gives handles and fails closed. Two releases never
serve together: `RoutingVersion` moves either Worker to another release
and holds that a call across them reads and changes no route; that the
gate comes before the vault's first statement is PR A's test. Its moves
keep each isolate's code config (`MaxDeploys = 0`), where a real upgrade
restarts an isolate on the new release and a new `credentialProxy` at
once; the restart resets `logged` either way, so the gate runs again
before it serves, but no scenario composes the two. The scenarios with
deploys put back no rows: a writer who puts back the item `proxy.code`
deleted is a rollback like any other, which `SealChecked` refuses in
`Routing`, since a deletion is a change of the object.

## 4. What `/use` costs, in round trips

A use through the proxy is a **named use** (`useNamed` in
`packages/vault/src/use.ts`): the request names its token, its place and its
keys, and the vault's isolate keeps a map from those names to ids. On a map hit it
is one call. On a miss, the first call reads the ids and the second makes the
use by them, because the use's entry MAC binds the key's id, which the
isolate cannot compute before it has read it. A named call always probes
every input's seal, never the seal cache, so that its work is the same
whatever the key and whatever the isolate kept (D153). A route use keeps all
of that, names the route instead of a key, and covers all of the route's
keys in that call (section 3), whichever path makes it.

| Case | Today (0.15) | With UI definitions |
|---|---|---|
| Map hit, uncached (`cacheSeconds: 0`, or an entry's refresh) | 1 call | **1 call.** Two more inputs of the statement, each one more row and one more probe of its newest change, inside the same call: the proxy object (the route's item and the index) and the editor's principal (decision 5); one more proxy row and probe per fork parent, up to four; at a fork, each key resolved through the chain reads one more key row and probe per level until it is found, as an inherited value's read does today, inside the same statement. The item is not sent back, because the isolate's copy has its digest |
| Map miss: an isolate cold for that environment or URL, or a key it has not used | 2 calls | **2 calls.** The first reads both URL readings by name (section 6): up to two places' proxy rows and probes, eight through forks of three parents. It picks the reading, resolves the route's keys by name, and answers the vault with the reading, the ids, the item and its digest (a few hundred bytes to a few KB). The vault's map keeps the ids. The second makes the use, reading the chosen place only, and the app gets the definition and digest in the use's answer |
| Right after an edit that keeps the route's keys (a new upstream, rules or allow list) | 1 call | **1 call.** The statement sees the route's item hash to another digest than the copy's and returns the new item in the same answer. Nothing is refused or retried |
| Right after an edit that adds a key to the route | 1 call | **2 calls, once per isolate**: a map miss for the new key, as any key used for the first time is today |
| Cache hit | 0 calls | **0 calls** |
| An app isolate with no copy of the route, the vault's map warm | 1 call | **1 call** for a handle (the answer carries the item); **2, once per app isolate per route**, for a workload, a sign or a verify: `proxyItem` for the counts before the gate, then the use, a map hit |
| A code route | as today | as today. The app names the keys, and no `proxy` row is read |
| An isolate's first proxy request | as above | **1 more call, once per isolate**, `editable: false` included: its gate (section 6), a vault call that reads the reserved set. When the isolate's code adds a name, that call makes a `proxy.code` change and answers once it is sealed, about half a second; that happens once per deploy that adds a name |

**What the entry records** (R53: the request, so that the replay decides
it as live did). A route use's entry carries the route's name in a new
nullable column, under the entry's MAC; reveals and code routes leave it
null. Which definition it was decided on needs no column: it is the newest
`proxy.save` or `proxy.code` change of the place's object numbered below the
entry, as for every other input (R50: the number orders everything). So two
routes that name the same key with different editors' holdings replay
apart. The route's two decisions use the place the use resolved (the
handle's environment, or the one the URL names), and the route as that
place's object holds it, or its nearest fork ancestor's, by name (decision 6).

**A cover is per route.** 0.15 lets a repeat of a use ride the entry of
the one before it (a cover) for up to a minute, writing nothing, when it
is the same credential, key, place and purpose and no input of that entry
changed since (the isolate's `coverKey` in `use.ts`, the statement's
`is_covered` in `0046_way_in_uses.sql`, which superseded 0045's). A route use adds two things to
that. The route's name is part of a cover's identity on both sides: the
isolate's key, and the statement's match on the entry's new column. And
the proxy object (each fork level the lookup checked) and the editor's
principal join the inputs whose newest change a cover must postdate. With
routes `a` (Ada's, upstream `good`) and `b` (Lin's, upstream `evil`) both
sending `{K}`, a use of `b` a second after one of `a` writes its own entry,
which replay decides under Lin's holdings; and the first use after an
edit of the route, or after its editor is demoted, writes its own entry
too. Without this, the log would credit `b`'s use to `a`'s entry, and R53
would break exactly where this section claims it holds.

**A map hit holds the ids to the definition.** The second call of a miss, and
every hit, carries the ids the map holds. The statement checks that the
definition it reads still names those keys for that route, and otherwise
answers `moved`, writing nothing, and the isolate reads again. That is
Naming.tla's `HeldToNames`, applied to the route's names. An edit between
the two calls of a miss therefore cannot have a key used that the route no
longer names.

**A warm use of one key is one function call (T205).** Until 0071, a map
hit was `use_route`: it picked the URL's reading again from the handle's
places, asked the gate (a named call of no key, `use_credential`, its
answer's JSON parsed back), read the route, then made the key's use by
ids, `use_credential` again. Three PL/pgSQL calls, about 2.2 ms of
Postgres CPU a use where a code route's named call costs 1.5. Now, when
the isolate's map holds the reading, the place's ids and a route of one
key, the vault asks `use_credential` itself, as a code route's named call
(D153), naming the route instead of a key: after the caller's standing
(`use_stands`), under the same fence, it reads the route's levels, its
editor and the one key the item names, resolves that key by its name
through the chain as it would a request's, and makes the use when the
map's ids are that key's now (Routing.tla, `StandingFirst` and
`KeyByItem`). The route's reads answer beside the key's row, and the
vault decides on them as on `use_route`'s. With Bo's handle at
`/use/openai/v1/chat/completions` and Ada's `openai` naming
`OPENAI_API_KEY`:

| What the call finds | What happens |
|---|---|
| Bo stands at dev, the map's ids are the key's | the use, one call |
| Bo's grant revoked | his use of no key at dev, refused there, nothing of the route read: one call |
| an Owner pointed `openai` at another key since | the new key's ids read; `use_route` makes the use by them: two calls, as a miss |
| `openai` now names two keys, or is gone | the caller's use of no key at dev; `use_route` reads on (a route of several keys, a miss), or the route's refusal |
| the map's reading wrong (the handle made for another place since a rename) | `reread`, nothing read; `use_route` picks the reading: as a cold map |

A route of several keys, a cold map, the place itself, `dev@me` and a
workload's use stay `use_route`'s.

**The isolate's copy comes only from the vault's answers.** The copy saves
bytes: a call that carries its digest gets the item omitted when the row's
item still has that digest. So a digest the isolate sends must stand for an
item the vault checked. If the copy could come from a read of the app's own
(a bootstrap read of the table, say: why its login gets no `SELECT` on
it), a database writer could do this: change the item's body to `evil` (an item whose digest fails, which
the app, holding no key, does not check), let the app read it with the
index, whose genuine entry gives D, and put the genuine row back. The vault
then checks the genuine row, sees the app's D, omits the item, and the app
sends by its forged copy. An app that hashed the body it read would send
the forged body's digest instead, and the vault would answer with the
item; but one rule is simpler to hold than that care. So the use path never
fills its copy from its own reads: a cold isolate sends no digest and gets
the item (`CopyFromVault` in the model, which finds exactly that run
without it; the model's version number stands for the item digest, since
it runs one route).

Two values travel, and they do different jobs. The **item digest**
identifies the copy: an edit of another route of the environment changes
the object seal but not this item's digest, so the copy stays good. The
**object seal** is what the answer carries for `OneVersion` (every round of
one use must read the same one), and what each value-cache entry carries
beside its item. The value cache is keyed by caller, place and route, not
by seal: a lookup finds the caller's entry whatever the isolate's copy is
now, and the send goes by the entry's own item (`BoundToDefinition`). A
use's answer replaces the entry of its caller, place and route, so there
is one entry per key and no rule is needed to pick among seals. That is
the cache-hit case of section 3: session A's entry, decided on version 7,
is found and sent by version 7's item after session B's use brought
version 8 to the copy.

**Invalidation costs no round trip.** The route's item is the only thing
the isolate caches, and only to save bytes. Postgres compares the copy's
digest with the row's inside the use's own snapshot, under the fence:
no change commits between that comparison and the decision, so it cannot
be wrong. The seals are probed on every call anyway, as above. A kept value
cache entry is invalidated by time only: the window of section 3. It keeps
the item its values were decided on, and a cache hit checks and sends by
that item, never by the isolate's copy, which another caller's use may
have refreshed since (`BoundToDefinition`). The answers carry the item's
digest beside the seal, so the app never hashes an item itself and needs
none of the vault's canonical form.

**Bytes and CPU.** From Postgres to the vault, every route use carries the
route's item and the environment's index: the item's bytes plus a name and
32 bytes a definition, which the vault hashes once and MACs once. That
grows with the environment's definitions, slowly, and is capped by the 256
items a save may hold (under 17 KB of index). From the vault to the app, the item crosses
only when the isolate's copy is stale. The second decision (the frozen
editor's) is CPU in the Worker over rows the statement already read: the
key rows are the same, the frozen holdings come with the item, and the
editor's current ones with their principal's row. The cost the statement
adds is two rows and two probes per use, one more of each per fork
parent, whose objects it reads too; the `whole` shape already reads the parent
environment. The new entry column costs bytes on every route use: PR C
measures them as PR 3 measured the place column (sealed-inputs.md, "A
use"). PR C also measures the probes against the 30-buffer budget, holds
the statement flat as the log grows (`request-cost.test.ts`, R48), and runs
the `/use` bench against 0.15.1 with an environment of 1 and of 256
definitions: no regression at 1 (R44), and the cost at 256 stated in the PR.

## 5. The vault makes no outbound call

Unchanged (R63). The vault reads Postgres, decides and answers. The app,
the `coffre` Worker or the Node server, makes every upstream request,
exactly as for code definitions. What changes is who writes the upstream:
an Owner through a web page rather than a deployment through a review and a
deploy. That calls for two checks code upstreams never needed:

- **No private targets.** A UI upstream is `https://` to a DNS name or a
  public address. Loopback, private, link-local and metadata addresses
  (`169.254.169.254`) are refused at save, as are `localhost` and single-label
  names. On Node a name can resolve to a private address at request time
  (DNS rebinding), so the Node fetch for a UI route resolves the name
  itself, through undici's `connect` lookup, checks every address it
  returns, and dials only a checked one, before any byte leaves. On Workers
  a `fetch` and a `connect()` both leave from Cloudflare's network, which
  does not route to private addresses: only a binding reaches them (R31).
  PR C checks that claim against production for both, and if `connect()`
  does reach one, UI tunnels on Workers take only literal public addresses.
  `insecureUpstreams` lifts these checks for local fakes, as it lifts the
  rest today. It is the app's code config, which the vault cannot see, so
  the app passes it in the save's input, as a named use passes `accepts`;
  the use-time check, on the sending isolate's own config, is what holds. An egress lifts nothing: a code route's upstream is refused
  when private, egress or not (`privateHost` at startup), and a UI route's
  is too. The egress only carries the request.
- **Database tunnels too.** Today a tunnel's `hosts` is deployment code, so
  the tunnel dials a name it lists without asking where it resolves
  (`dialled` in `postgres-tunnel.ts`). In the UI that list is an Owner's
  input: `hosts: ['db.attacker.example']`, resolving to `10.0.1.5`, would
  reach a private address with no network binding, and the TCP connection
  and Postgres's SSL request go out before TLS could object. So a UI
  tunnel's hosts follow the same rule: public names or addresses at save,
  and on Node the tunnel resolves the name, checks the addresses and dials a
  checked one, so no SYN reaches a private address. The one exception stays
  R31's: a tunnel through a network code declares, to hosts among that
  network's.
- **An egress's hosts are checked at use too.** A UI route's upstream must
  be among its egress's `hosts` at save (section 1), and a later deploy may
  narrow that list. So the fetch checks it again on every request, a check
  new in 0.16 (code routes have no hosts to check against), and answers
  503 naming the egress when the upstream has left it.
- **Who checks what.** The vault decides a save (section 8) but cannot see
  code: it knows no egress's or network's hosts. So the checks split. The
  vault refuses what needs no code: a non-HTTPS upstream, a private,
  loopback, link-local or metadata literal, `localhost`, a single-label
  name, and a tunnel's private literal unless the item names a network.
  The app, which serves the save, checks the rest against its isolate's
  code before it calls the vault: the egress or network exists, and the
  upstream or hosts are among its hosts. An old isolate checks against old
  code, so the save-time check is a courtesy to the editor; the guarantee
  is the use-time check, on the code of the isolate that sends or dials.
- **The upstream's origin is fixed by the definition.** The existing rule
  stands: a request goes to `<upstream>/<path>` and nowhere else, and
  redirects stay on the proxy.

## 6. Code definitions and UI definitions together

**Code wins, by name, and the row shows locked** (R66). The app resolves a
name in code first, then in the environment's UI definitions, on each
entry point in the order section 3 gives. The page shows
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

**Which URL names what, in the same call.** Today `/use/<a>/<b>/…` names an
environment when `<a>/<b>` is one the handle was made for, and is otherwise
the stable URL of credential `<a>` ([credential-proxy.md](credential-proxy.md),
section 4, "Which route"). Where `<a>` names a code credential, the app asks
the handle's environments first (`madeFor`, a vault call of its own, kept for
`cacheSeconds`); with no cache, a named use already folds that question into
its one call (`unless` in `NamedUseInput`: "served not by name when the
handle's is one"). A UI name depends on the environment, so the app can no
longer tell from its config that `<a>` names nothing, and taking `madeFor`
for every such URL would be a second call on every request with
`cacheSeconds: 0`. So a route use carries **both readings** of the URL, and
the statement picks one in its snapshot:

| Reading | Place | Route | Taken when |
|---|---|---|---|
| the environment's | `<a>/<b>` | `<c>`, the rest after it | `<a>/<b>` is an environment the handle was made for |
| the stable URL | the handle's one environment | `<a>`, the rest from `<b>` | otherwise (a handle of several environments: 409, as today) |

Concretely, for `/use/market/dev/openai/chat`:

- **The request** names the token and both candidates by name:
  `{ place: 'market/dev', route: 'openai' }` and
  `{ place: the handle's own, route: 'market' }`.
- **On a map miss**, the first call resolves both, which reads up to two
  places' proxy rows (up to eight through forks), picks the reading by the table,
  and answers the vault with it, the place's id, the route's key ids, the
  item and its digest.
- **The vault isolate's map** (0.15's) keeps two things, neither keyed by
  the path. Per token: the handle's made-for list, which the miss's
  statement reads among the caller's rows anyway and answers with (as
  today's stable URL is kept by token alone, `use.ts`). Per place id and
  route name: the route's key ids, beside today's per-key ids
  (`cache.keyed`). A later request picks its reading from the token's
  list, by the table, whatever its path, and finds the ids by the chosen
  place and route. So `/use/openai/companies/42/documents/x.pdf` and
  `/use/openai/models` from one `market/dev` handle are both map hits
  after the first, one call each under `cacheSeconds: 0`, as today's
  stable URL is (Fable 5.1's review, `aee4142c`: keying by the URL's
  first three segments would have made each new path a miss). The app
  isolate keeps the definition and its digest, from the use's answer, as
  its copy.
- **On a map hit**, the call names the reading the map picked, with its ids.
  The statement reads that place only, and answers `moved`, writing
  nothing, if the rule would now pick the other reading (the handle's
  made-for list is among the caller's rows it reads anyway) or the route no
  longer names those keys. Then the isolate reads again, as on a miss.

**URLs of one or two segments** take the same table, for UI names only.
When `<a>` is a code credential's name, the URL alone decides, as today
(`serve` in `credential-proxy.ts`), for handles and workloads alike: code
wins (R66), so a project slug equal to a code credential's name changes
nothing that works now. `/use/<a>` is
always the stable reading of route `<a>`. `/use/<a>/<b>` is the place
reading, the plan (`GET`) or `compute` (`POST`), only when `<a>/<b>` is an
environment the handle or session was made for; otherwise it is the stable
reading of route `<a>` at path `/<b>`. So `GET /use/openai/models` from a
`market/dev` handle is a GET of route `openai` at `/models`, and `GET
/use/market/dev` from it is the plan. The plan and `compute` answer 404
only after the call has decided the reading, never from code's maps
alone. With no made-for list kept (`cacheSeconds: 0`, or a cold isolate),
the route use decides: the app sends both readings, the statement picks
one from the caller's rows, and an answer for the place reading carries
no values, after which the plan or `compute` goes on as section 4 counts
it (the plan's `proxyItem`).

So a `/use` costs what section 4 counts, whatever the URL, and the
statement adds the second reading's rows only on a miss. A kept `madeFor`
still saves the question when present. `GET /use`, which
answers with no credential, keeps listing code names only, so it reveals
nothing of an environment's own.

**The plan shapes UI items as it shapes code's.** The plan
(`GET /use/<p>/<e>`, what `coffre run` builds the app's environment from)
is more than a list. Today it gives the handle in place of every key a
code credential covers, whoever may read it, and keeps the real value
from the app; it names the credentials, signers and tunnels, and gives
each tunnel's key the listener's URL. All of that comes from the items'
contents (their keys, kind and `placeholder`), which a list of names does
not carry. So the plan first makes one `coffre.proxyItem` call with no
name, as its caller: the vault answers every item the place serves, fork
chain included, checked as a use's statement checks them. The plan then
takes the covering set, the signers' and tunnels' keys and each
placeholder's shape from code and those items together, before its
`expose` use picks the keys whose values the app gets. Example: UI route
`openai` in `market/dev` sending `{OPENAI_API_KEY}`, a secret its holder
reads. Without the items, the key looks uncovered and the app's
environment gets the real value; with them it gets the handle, as a code
route's key does. The plan fails closed: if `proxyItem` is refused or
finds any item `tampered` (one forged body among 256), it answers 503 and
no environment, never a plan shaped from code alone, which would hand the
app the forged route's values through the uncovered-and-reads branch. A UI
item whose name code holds is left out, as a use never reaches it: taken
in, its extra keys would get handles no served route sends. Those items shape the plan only: they are never kept as
a sending copy (`CopyFromVault` holds of the use's answers, and nothing
here sends). A workload's plan does the same for its credential and
tunnel lists. One more call per plan, which runs once per `coffre run`.

**Scoping code items** (R66): `environments: ['market/prod']` on any code
item, by full path, because the config is instance-wide and a bare `prod`
would match every project's prod. With none, a code item applies to every
environment, as today. The path is matched against the request's environment
by its current name. An environment renamed away from `market/prod` leaves
that scope (which only moves where the code item serves, never what a UI
item may be called), and the app's startup check warns about a scope that
names no existing environment. A `*/prod` glob can come later if someone asks.

**Names unique across kinds** (W260's pushback 4, decision 3). Routes and
tunnels share `/use/<name>`, signers and verifiers are named in the same
URL space, and one list shows all four. A UI name takes code's rule for a
credential's name, `CREDENTIAL_NAME` in `@coffre/core` (a lowercase letter,
then up to 31 lowercase letters, digits or dashes), which the vault checks
at save: `OpenAI`, `a/b` or a 40-character name is refused there, since a
binding's caller and `serve`'s segment decoding could never reach it. A UI
name may not equal any other UI item's in the environment, nor any code
item's of any kind. Code keeps
today's per-kind rule: making it stricter would break a deployment that has
a credential and a signer both named `dfns`.

**Reserved names, and clearing superseded rows** (W260's proposal, which
Erwin allowed: "the deployment may clear superseded UI state"). Without
clearing, a UI `maps` hidden by code's `maps` comes back to life the day
code drops `maps`, with an upstream nobody has looked at since. Clearing
once at a deploy is not enough either, because during a deploy two app
versions serve at once. Example: deployment B adds code `maps`, and B's
first isolate to serve a proxy request clears the UI `maps`. An isolate of
the old deployment A, whose code has no `maps`, is still serving, and an
Owner saves a new UI `maps` through it.
B's isolates hide it. Months later deployment C drops `maps`, and the hidden
UI `maps` serves again. So the log keeps the names code has reserved, and
they outlive the deployment that reserved them:

- **Reserving: the gate.** Each isolate, before its first proxy request,
  makes one vault call with its code's names. The gate sits at the
  plugin's two entries, so nothing that serves or shows a definition gets
  past it: `routes.fetch` (`serve`: every `/use` request, `GET /use` and
  the plan's `GET`/`POST /use/<p>/<e>` included, routes, sign, verify and
  presign alike) and `routes.socket` (`open`: tunnels). The Proxy tab's
  APIs (`GET`/`PUT …/proxy`, `PUT /api/proxy/reserved`) call it too, before
  they read or write. Nothing is exempt.
  The vault reads the reserved set (one row, section 2, checked against its
  newest change's seal, with no lock, as it reads `bulk.limit` at its
  start), and most isolates find their names there and go on. The isolate
  keeps settled values only, never the pending call (AGENTS.md, "What an
  isolate keeps"): its first request makes the call, and its other first
  requests join that call's attempt and wait for its outcome on timers of
  their own, polling, take over a call not settled in 3 s, and answer 503
  `starting` to ask again once they have waited 6 s in all, a call of
  their own taken over included, which they poll as they did the one
  they joined (`packages/server/src/asked-once.ts`, T201). The gate passes
  that refusal on as it is: 503 `starting` when it waited on `about()`.
  An outcome is its attempt's:
  a retry's followers never take the failure before it, nor a superseded
  call's late one. Each making its own call instead, a Node deployment's start at
  1,000 requests a second queued 200 to 270 calls a thread on its vault's
  pool of 8 for 2 s, and the uses held behind them burst into the in-flight
  cap. Only a name missing from the read, or a read that cannot say (unsealed, torn by a
  change), decides under the head, which reports it and refuses: an empty ask,
  from a deployment of UI routes alone, as much as any. Under the head every time, as the first
  cut did, those calls queued one behind the other and every use behind them,
  up to 147 s for one use in #467's bench at 1,000 a second. The deploy that
  adds a name sends every isolate's first call there at once, each finding it missing: so only
  one waits for the head, in a place in line of the code's own (the reads'
  places, `READ_HEAD_WAITERS`, are apart). The others, refused that place at
  once, pause (25 ms, doubled each time, up to 400 ms) and try again, and
  read the name the one wrote; their waits, for the place and for the head,
  within one bound for the call, the vault's call deadline (15 s until
  W331, 5 s since). The one that writes waits besides
  for the issue lock and the fence, each within what was left when its
  attempt began, as every change waits for each lock it takes. Each waiting
  its turn instead, 3,080 no-op decisions queued 200 s in the same bench. On
  Postgres the read is the decision's first statement, on its connection,
  before any lock: in a read of its own, a Node deployment's pool of 8
  queued the first call's decision behind every other call's read, and the
  last answered after 15 s. On SQLite, whose every transaction queues for the
  file's one writer and a plain read not, it is a read of its own.
- **One release at a time.** The gate's call is a vault call like any
  other: from an app on another release it is 503 `deploying` before the
  vault reads the reserved set (section 3, "One version at a time"). What
  the gate handles is the overlap of two configs of one release, below. A
  rollback moves both Workers. Rolled back to 0.15, the pair serves code
  routes as 0.15 did, with no gate, and UI items stay in their rows,
  unread; the next upgrade's first isolate gates before it serves. A code
  name added and dropped again while on 0.15 was never reserved, so its UI
  item serves again after that upgrade: an accepted gap, and 0.16's
  release notes say not to change code's proxy names while rolled back.
- If a name is missing, the same call makes a `proxy.code` change adding
  it: CAS on the reserved set's seal, and in the same transaction every UI
  item of that name, in every environment, deleted, each whole in its
  entry. Two first isolates of one deploy race: the loser's CAS fails, it
  reads the set again, finds the names there, and writes nothing, so
  reserving is idempotent. The isolate serves no proxy request until its
  names are reserved (`CodeGate`).
- **When code shadows.** At that gate, not at the deploy. Until a B isolate
  serves its first proxy request, A's isolates keep serving the UI `maps`
  as they did before B, which is the overlap any deploy has. A deployment
  that never served a proxy request reserved nothing, and nothing ever
  served or showed its `maps`, so there is nothing to revive. Reserving at
  the deploy itself would need the deploy pipeline to run the app's config
  against the vault (`coffre migrate` reads only the schema), for no case
  anyone could observe.
- **A save checks the reservation.** The vault refuses a save of a reserved
  name, whichever isolate's page sent it (`SaveChecksReserved`). A's page
  allowed `maps`, but the vault does not: "`maps` is reserved by code".
- **No deploy drops a reservation.** A deployment that no longer defines
  `maps` leaves it reserved, so nothing hidden can return when code lets go
  of the name. The tab shows it: "`maps` was defined by an earlier
  deployment's code". An instance Owner may **release** it, a change of
  its own (`proxy.release`, audited). A release frees the name in every
  environment of every project, which is why a project Owner cannot. The
  app refuses a release of a name its own code defines; the vault cannot,
  since deployment code is no input of its log. The release dialog says it
  frees `maps` instance-wide, and what neither can check: that no older
  deployment still serving defines `maps`. An instance Owner who releases
  during a deploy and then saves `maps` is the one revival left, which TLC
  finds (`RoutingRelease`, an `EXPECTED` gap): it takes that Owner's
  deliberate, audited act.
- **During a deploy**, reservations only grow, so the two versions do not
  alternate. The cost is a stale name that stays reserved until someone
  releases it, which is the safe default.

## 7. Matching, injection and redaction

### The path

The request's path below the route, `/use/<name>/<rest>`, goes through
today's refusals unchanged, and only then is matched. As built in PR B,
after nine review rounds: [credential-proxy.md](credential-proxy.md),
section 3, "Several rules, an allow list, and environments", holds the
exact rules; this section is their reasons.

1. **Today's check, kept whole** (`aim`'s `climbs` in `credential-proxy.ts`).
   Each raw segment is decoded as often as decoding changes it, because a
   server behind another decodes twice. Every form along the way is refused
   if it holds a slash, a backslash, a control byte (which a server may cut a
   segment at: `..%00`) or an overlong UTF-8 lead byte (`%c0%ae`, a dot to an
   old decoder), or if it is a dot segment: `.` or `..`, with trailing blanks
   (`..%20`) and with its `;` parameters dropped, as Tomcat and Spring drop
   them (`..;x`).
2. **New:** a `*` takes no empty segment (`//`), nor one a server may read
   as none: `;` parameters alone (`;x`, which Tomcat and Spring drop),
   spaces or dots alone (which Windows drops from a segment's end). Since a
   glob counts segments, `/companies/;x/documents` must not pass
   `/companies/*/documents` when the upstream reads it as
   `/companies/documents`. Past a prefix or a `**` such a segment is
   harmless and taken: the path the upstream makes of it stays inside, and
   S3 keys hold `//` (`/bucket/a//b`). Past a trailing slash it is taken
   only beside another segment that survives the upstream's normalization:
   under `allow: [{ path: '/bucket/*/' }]`, `/bucket/a/;x/k` passes and
   `/bucket/a/;x` is a 403.
3. **New:** each segment is percent-decoded once, to bytes, and the decoded
   segments are matched against an `allow` list. Bytes, not text: no UTF-8
   check beyond step 1's overlong refusal (a `%FF` segment is forwarded
   today and still is), no case folding, no Unicode normalization. `Café`
   written precomposed and decomposed are two different segments, as they
   are to the upstream.
4. The path goes on as the app encoded it, byte for byte. After step 1, the
   upstream's own decoding, however often it runs, reads a path the `allow`
   list still takes; it need not read the same segments (`/kyc/a%2520b`
   is `a%20b` to the match and `a b` to a server that decodes twice, both
   under `/kyc`).

| Request | Matched as | Result |
|---|---|---|
| `/companies/42/documents/a%20b.pdf` | `companies`, `42`, `documents`, `a b.pdf` | matched |
| `/companies/42/docu%6Dents` | `companies`, `42`, `documents` | matched as `documents`, not missed |
| `/kyc/%2e%2e/admin` | `admin` | 403 under the example list: URL parsing resolves `%2e%2e` before the proxy sees the path, so it is `/admin`, outside `/kyc` (today too) |
| `/kyc/..%2fadmin` | | 400: a slash once decoded (today too) |
| `/kyc/%25252e%25252e/admin` | | 400: a dot segment three decodings down (today too) |
| `/kyc/..%20/admin`, `/kyc/..%00/admin` | | 400: a dot segment with a blank; a control byte (today too) |
| `/kyc/..;/admin` | | 400: a dot segment with parameters (today too) |
| `/companies//documents`, `/companies/;x/documents` under `/companies/*/documents` | | 403: a `*` takes neither (new) |
| `/bucket/a//b` under `/bucket` or `/bucket/**` | `bucket`, `a`, ``, `b` | matched (under `/bucket`, as today) |

What is new is only the matching, and only for `allow`: globs need the
decoded path, since `*` must see `a b.pdf` and a literal `documents` must
not miss `docu%6Dents`. Legacy `paths` keep today's comparison with the
encoded path, unchanged: `paths: ['/files/%61']` takes `/files/%61/x` and
never `/files/a/x`, as on 0.15. Decoding them too would have widened
existing configs, which review round 8 caught.

**`allow` patterns are decoded too, once,** when read: at save for the UI,
at startup for code. `/companies/a%20b` becomes the segment `a b` and
matches `/companies/a%20b`, not `/companies/a%2520b`, which decodes once to
`a%20b`, a different segment. A pattern that decodes to a dot segment, a
slash or an empty segment is refused at save. So is a literal some server
may read as another (review round 5): one that still decodes (`%2561`,
`a` to a server that decodes twice), one with `;` (`a;v1`, `a` to Tomcat),
one ending in a space or a dot (`a.`, `a` to Windows). In code each is a
startup error. A legacy path keeps matching what it matched before, with
no warning for these: `paths: ['/a;v1', '/a.', '/a%2561', '//']` start
silently, as on 0.15. A legacy path warns at startup only when it is dead
(it holds a segment no request reaches the upstream with, `/a/../b`), when a
URL spells it otherwise (`/café`, `/a b`: compared as written, it matches
nothing), or when it holds a `*`, which it takes as itself. Two code forms keep their meaning: `/` matches every path,
and a trailing slash, `/companies/`, matches what is below `/companies`
and not it. In `allow` that slash needs a segment below that a server
reads as one: `/bucket/*/` takes `/bucket/a/b`, never `/bucket/a/...`,
which a server may read as `/bucket/a` (review round 6). The UI refuses a
trailing slash at save and offers `/companies/**`. PR B's property tests
(`test/proxy-match-properties.test.ts`) run every row above, and random
encodings of paths, through the old check and the new matcher together,
against a model of how servers behind may read them: under an `allow` list,
no path outside it reaches the upstream under any reading. Legacy `paths`
are held to 0.15's answers instead, and the unstable literals above are
exempt: `paths: ['/a;v1']` forwards `/a;v1/k`, which Tomcat reads as
`/a/k`, as 0.15 did.

### The allow list

A route holds entries `{ methods, path }`. A request is allowed when any
entry allows it: its method is in `methods` (empty means any), and its path
matches. With no allow list, every method on every path is allowed, as
today; an empty one takes nothing (403). An entry of any method on any
path, `{}` or `{ methods: [] }`, is refused: it would take every request,
whatever the others say.

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
accepted, with their 0.15 meaning, as one entry `{ methods, path }` for
each path: `*` is itself, never a glob (a startup warning says so),
`methods: []` takes no method, and `paths: []` no path, its methods still
answering first: `methods: ['POST'], paths: []` is a 405 to a GET and a 403
to a POST (review round 9). A method override in a header or the query
(`X-HTTP-Method-Override`, `?_method=`) is held to the list as the request's
own method is; one in a body is not read (T189, D179,
[credential-proxy.md](credential-proxy.md), section 3, `allow`).

### Several inject rules

A route's `inject` is an ordered list. Each rule fills a header, a query
parameter, a form or JSON field, a path segment (0.16, `{ kind: 'path',
template: 'bot{TELEGRAM_BOT_TOKEN}' }`, [credential-proxy.md](credential-proxy.md),
section 5, "A segment of the path"), Basic authorization, or a SigV4 signature,
in that order. Validation, at save and at the app's startup for code:

- every rule names at least one key (`{KEY}`), as code's startup check
  requires today, so no route use is ever standing-only;
- at most one `path`, its template one segment naming one key once; at most
  one `basic`, at most one `sigv4`, and `sigv4` last;
- one rule per header (case-insensitive), parameter or field name;
- no `basic` beside a rule that sets `authorization`, and no rule sets a
  header SigV4 owns (`authorization`, `x-amz-*`);
- a `placeholder` (`jwt`, `prefix`) only where the route's non-plain keys sit
  in exactly one header, query, form, JSON or path slot, the case it shapes today.

**SigV4 signs what the earlier rules set.** It runs last, over the request
as the earlier rules left it, and adds the headers they set to
`SignedHeaders`. So the signature covers the request exactly as sent, and
an earlier header cannot be swapped on the way.

**Where the handle is.** Two sources, as today. `x-coffre-handle`, which the
SDK's `credential(name).fetch()` sends and which fills no slot of the rule,
is accepted on its own for the header, query and Basic slots: the proxy
fills them whatever they held. A form or JSON rule carrying a non-plain key
is the exception: its field must hold the handle too, as the plan gave it
to the app there. With
`inject: form('secret', '{KEY}')`, `x-coffre-handle` and `secret=mine` is a
400 (after the vault answers, before anything is sent). Without it, the
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
  its definitions, inert (#421's disabled fieldsets). `GET …/proxy` is a
  vault call, not the app's own read: the app holds no key, so it could
  not tell a forged item, and an Owner who edited or copied one would seal
  a forgery as their own. The vault checks the seal, the index and the
  newest change, and answers a display shape: each definition, who saved
  it and when, and its clearance mark, never the frozen holdings (an
  editor's grants across projects). A forged object shows as `tampered`
  and cannot be edited, only replaced whole by an Owner. That save CASes
  on the seal of the object's newest logged change, which the vault's
  probe reads and the display answer carries, never on the forged row's.
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
  `readsSensitive`'s rule from R32, unchanged. It then clears each changed
  item's keys now, the list it stores in the item (section 3): it resolves
  them by name in the place, inherited and
  referenced keys included, and refuses the save if the frozen holdings
  would not read one, sensitive included, as the use would. A key the place
  does not have yet is accepted (a route may be saved before its key) and
  decided at each use like any other.
- **At each use**, the vault decides the route's keys for the caller (purpose
  `use`, unchanged), and then again for the frozen holdings, intersected
  with the editor's current ones (decision 5), as if they were a
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
| Lin routes `{API_KEY}`, a reference into `billing/prod` | decided where it lives (R20, R71): her read of `market/dev` covers it; sensitive, it takes an Owner of `market`, as any sensitive key there, whatever project its source is in |
| Ada, an Owner of market, routes `{STRIPE_SECRET_KEY}` | allowed, and the entry says `routes sensitive` (R66) |
| Lin saved `openai`; she is later demoted to Viewer, or leaves | each use refused, `route_not_cleared`, until someone who reads its keys saves it again (decision 5) |

This makes routing **preventive for everyone but an Owner covering the
place**. For those Owners it grants nothing new. R30 already lets them
loosen a sensitive value to a secret and read it, audited, and break-glass
lets them read it through a service account. That bears on W260's pushback
1 (decision 1).

The frozen holdings are also intersected with the editor's holdings now,
as R15 does for tokens (decision 5): a removed or demoted editor's
definitions stop routing what they can no longer read, and each use
answers `route_not_cleared`, naming who must save again. The use's
statement reads one more object, the editor's principal, in the same call.

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
review problem, not an access problem. Decision 2 is what the review step
shows.

## 9. Threats, in one table

| Who | Tries | Outcome |
|---|---|---|
| A database writer, no key | edits an upstream, adds a route, or puts back an old row | refused (`tampered`, `stale`); fails closed (R64) |
| A database writer | forges an item beside its genuine index entry, lets the app read them, puts the genuine row back | nothing sent by the forged body: the isolate's copy comes only from vault answers (section 4) |
| A database writer | deletes the row | the use's probe finds the newest change's seal and no row: `stale` |
| A Developer with `proxy.edit` | routes a value they cannot read, or one made sensitive later | refused at use: the frozen holdings decide (`ClearanceAtUse`) |
| An Owner covering the place | routes a sensitive key to a host they control | allowed and audited: the same power as R30's loosening (decision 1) |
| An editor who later leaves | keeps a route to their host, and the value rotates | stops at their next use once they no longer hold the key: `route_not_cleared` (decision 5) |
| An Owner | copies a dev route into prod and saves it unchanged | prod's key goes to dev's upstream, audited; the review step names that destination (decision 2) |
| An Owner, racing an app | edits mid-traffic | old values go to the old host for at most W, never to the new host undecided (section 3) |
| Someone with a stale page | saves over a newer change | 409: CAS on the seal |
| A compromised app (the `coffre` Worker) | anything | out of scope, as today: it holds the values it opens. The vault makes that loud (every decision logged), not impossible |
| An Owner | points an upstream, or a tunnel's host, at `169.254.169.254` or `localhost` | refused at save: a literal private address, `localhost` or a single-label name (section 5) |
| An Owner | points one at a name resolving to `10.0.1.5` | the vault resolves nothing, so the save cannot see it: refused at connect on Node, HTTP and TCP alike; on Workers, Cloudflare's network does not route there, which PR C checks (section 5) |
| An Owner, during a deploy | saves a name the new code reserved, through an old isolate | refused by the vault: the name is reserved (section 6) |
| A code change | drops a name UI also had | the UI item was deleted when the first isolate of that code reserved the name, audited (`NoRevival`) |
| A project Owner | releases a name code reserved | refused: a release frees the name instance-wide, so it takes an instance Owner (section 6) |
| An Owner | edits a route between the rounds of a use of its two keys | the later round finds another seal: `moved`, and the use starts over on one version (`OneVersion`) |
| Anyone with `environment.manage` | renames an environment into or out of a code item's scope | nothing a UI item may be called changes: code names are taken in every environment (section 6) |

## 10. The implementation, in four PRs

Each runs the suite on both engines (`pnpm test`, `pnpm test:sqlite`), and
`pnpm formal` keeps `Routing.tla` and the code in step (R45).

**PR A: storage, the change path and the permission.**
- Migration at the next free number on both engines, read from `main` when
  PR A is written (#453, #454 and #456 are taking numbers now): `proxy_definitions`,
  `proxy_reserved`, grants.
- `@coffre/vault`: object kinds `proxy` and `proxy-reserved` (`inputs.ts`:
  their shapes, the sealed index, `applyOp` for `proxy.save`,
  `proxy.code` and `proxy.release`; `log-replay.ts`); the vault method that
  decides a save (proxy.edit on its sealed rows, the reserved set, frozen
  holdings, each changed item's keys resolved and cleared, CAS, at most
  256 items). The vault resolves the keys' names itself, in the save
  decision's reads of the place, its fork parents and each reference's
  source; the app sends names only, so an old or buggy app cannot
  under-clear a save.
- `@coffre/core/access`: `proxy.edit`, the role editor's new rule;
  `formal/lean` updated in the same PR (AGENTS.md: a change to the access
  rules changes the Lean model).
- The version gate (section 3, "One version at a time"): `VaultEntry`
  and its answer `{ release, result }` in `@coffre/core/vault`; the gate
  once per vault process, at `VaultEntrypoint.call` (its per-method
  members made private, the hot path's included) and at
  `openLocalVault`'s entry, which `serveVault` serves as `POST /call`;
  `connectVault`'s `call`; the binding typed `VaultEntry` in the
  examples, `init`'s templates and `dev/deployment`; `LocalVault` keeping
  `close`; the test fixtures that speak `Vault` to a local vault (the
  vault suite's `speaking`, the server suite's `TestVault`) going through
  `versioned`, and the socket tests posting to `/call`; `auth.ts`'s
  catch-alls rethrowing `deploying`; `versioned` replacing `createRuntime`'s
  `vault` parameter, kept per entry; `deploying: 503` with
  `Retry-After: 1` in `ERROR_STATUS` and `errorResponse`. Tests, on
  Workers, through the real `serveVault`/`connectVault` pair, and in
  process: a call on another release refused with no statement run and
  no entry (counted as `request-cost.test.ts` counts), for a `useNamed`,
  a no-argument method (`about()`) and a string-argument one (`access`);
  an answer on another release, or with none, answered 503 `deploying`
  with the header, asserted at the API on a signed-in route and a
  workload route; two runtimes over one Workers
  binding asking `about()` once.
- PR A and PR C ship in one release, 0.16: code's names must be reserved
  (PR C's gate) from the first UI save (PR A), or a code name served
  meanwhile hides a UI item nobody deleted.
- API: `GET` and `PUT /api/projects/<p>/environments/<e>/proxy`, the save
  answering once sealed; `PUT /api/proxy/reserved` (release, instance
  Owners only).
- Tests: save, CAS 409, permission matrix (built-in and edited roles,
  protected environments, tokens refused), replay agrees, the row tampered,
  put back or deleted (`stale`, `tampered`), an item moved under another
  name (`tampered`), an item deleted from a fork's row with its index left
  (`tampered`, never the parent's item), a fork of a fork served by its
  grandparent's item, the last item removed (an empty index, the row
  kept), `GET …/proxy` showing a forged row as `tampered` and never
  answering holdings, a save refused under `editable: false`, the backup login reads it
  (`test:schema`), Lean cases. Section 8's save-time rows: a sensitive key
  refused naming who may, an inherited key the editor cannot read in the
  parent refused, a reference decided where it lives, a key not yet
  created accepted.

**PR A as built** (W310). Where it settles what this section left open, or
reads it otherwise:
- **The routes** take the API's shape for an environment's own leaf:
  `GET`/`PUT /api/projects/<p>/<e>/proxy`, as `…/missing` and `…/version`.
  The page's answer adds `editable` (this caller may save here now) and
  `code` (the names this deployment's code defines, shown locked).
- **Frozen holdings** are the editor's standing, as section 2 has it
  (`FrozenHoldings` in `inputs.ts`): their instance role, its scope and
  columns, and each live grant with its role's columns. PR C decides them
  with `frozenAllows` and `frozenOwns` (`packages/vault/src/proxy.ts`), as
  `allows` and `ownsProject` decide over roles as they were, at any place:
  a fork made after the save, or a key that became a reference into another
  project, included.
- **The object's CAS is on its newest change, not its row.** `change_input`
  writes a `proxy` row whole from its value, moving on only from the seal
  of the object's newest change, under the fence; it never weighs the row.
  The vault decides each save from the object as its log has it
  (`heldByLog`), so a forged row is never carried on, and a `tampered` or
  `stale` one takes only a save that replaces it whole (`replace: true`),
  by an Owner of the project. An item the save does not name keeps its
  editor and holdings. One it names is saved again under its editor's
  standing now, its definition unchanged included: that is how an Owner
  clears a route its earlier editor no longer can (section 8's "must save
  it again"). Only an item named with the same definition, by the same
  editor, holding the same, changes nothing, and a save of only those logs
  nothing. A replace's entry names every item it drops.
- **Every decision also writes a vault entry** (`proxy.save`, `proxy.code`,
  `proxy.release`): each refusal, and the audit page's diff, the sensitive
  keys an item routes among it (R66).
- **`proxy.code` is a vault method already** (`reserveProxy`), with no
  route: PR C's gate calls it. An environment whose row fails its seal is
  passed over: it serves nothing (R64), and the name stays reserved.
- **The fork lookup** (section 2) is a pure function, `proxyLookup` in
  `packages/vault/src/proxy.ts`, over full rows; PR C's statement reads one
  item and the index.
- **The version gate's helpers live in `@coffre/core/vault`**: `gated`
  (the vault's side), `versioned` (the app's) and `Deploying`, which the
  app's `toErrorBody` answers 503 `deploying` and sign-in's catch-alls
  rethrow (`deployingIn`), so the vault suite speaks through the envelope
  too (`spoken`). `CoffreConfig.vault` is a `VaultEntry`; the app's two
  handlers wrap it before `createRuntime`, the one place a `Vault` is made
  from the deployment's entry.
- **A definition is saved only as the proxy would take it.** The allow
  list's patterns are read by the proxy's own parser (`readPattern` as a
  Proxy tab's, in `@coffre/core/proxy-match`, moved from the server), so
  `/tenants/%2561/*`, `/a;v1/*` and `/a./*` are refused at save as code's
  are; inject rules' names and slots are the proxy's too (`PARAMETER_NAME`,
  `FIELD_NAME`, `alike`: query `secret` and `SECRET` are one). No allow list
  is kept as `null`, every request, and an empty one as `[]`, none: the
  sealed definition says which.
- **The app's checks**: `credentialProxy({ editable })`, off by default; a
  name code defines (409); an egress or a network, none of which code can
  declare before PR C (400).

**PR C as built, the vault's half (C1, W312).** PR C ships as two PRs:
C1, the model and the vault; C2, the app and the proxy on top of it.
Where C1 settles what this section left open, or reads it otherwise:
- **The model first.** `Routing.tla` gains two editors, the version's
  clearance frozen from its editor's standing at the save, `Restand` (a
  promotion, a demotion, a removal), and `EditorStillHolds`. Scenario
  `RoutingEditor` (1,061,512 states) holds; TLC breaks `EverySendAllowed`
  without `EditorStillHolds` (Ada removed, her route still sends), without
  `ClearanceAtUse` (now found only with a promotion: Lin saved as a
  Developer, made an Owner, the key marked sensitive), and without
  `FencedRead` (the editor's principal read before the fence).
- **One statement, `use_route` (0058),** in the shape of `use_named_batch`:
  the gate first (a handle's named call with no key; a workload's use of no
  key at its place, by ids, which writes nothing), then, for one who
  stands, the chain, each level's row through the first whose `items`
  holds the route (`items -> route`, the `digests` column, the seal, and the
  object's newest change), the serving item's editor's principal, the
  item's stored keys resolved by name through the chain, and, when the
  vault's ids are the names' now at the reading it picked, each key's use
  by ids, `use_credential` with `p_route`. Otherwise it uses nothing and
  answers the ids: the vault's second call makes the use (2 calls on a
  miss, whatever the map holds, `names: 0` included).
- **The reading** is the statement's: it reads the credential's `places`
  and the candidate environment, and answers the handle's made-for paths,
  which the vault keeps per token (`UseCache.madeFor`) to pick the next
  reading; the route's keys' ids are kept per place and route
  (`UseCache.routeKeys`), never per path. A pick the statement disagrees
  with uses nothing, and the next call is made by the statement's own.
  The statement picks it before the fence, so that a cold session plans
  `use_credential` before it holds the fence, then once more under it,
  after the gate: if a rename moved it in between, it asks the gate again
  by the new one (review r2: `/use/market/dev/openai`, dev renamed to
  stage meanwhile, would otherwise answer `served: false` where the rule
  now picks the stable route `market`). A session whose first call
  planned it (`coffre.route_planned`, 0060) takes the fence first and
  picks once, under it: the pick the second round would make. The
  made-for paths are answered only where the statement makes no use (a
  use made by the map's ids was made at the reading the map picked).
- **The gate light (T200, 0060).** A statement made with the map's ids
  (`p_light`, which the vault passes then) asks `use_credential` for a
  light gate (`p_gate`): its named resolution and `use_stands`, as
  before, and for one who stands at a live place whose chain is whole,
  `stood` with its names and the app's rows of the place, nothing more
  read. The route is then read and each key's use made by the ids, as
  before; the first key's row, read under the same fence, carries every
  row the whole gate's would (the credential, the account and its
  grants, the roles, the policy, the place), and the vault decides the
  caller on it: its checked view with the key taken out, the caller's use
  of no key at the place (`lightGate` in `use.ts`). A statement that
  makes no use (a personal config, a chain cut, no item, ids that moved)
  asks the whole gate before it answers, under the fence still held. One
  who stands nowhere reads on as before, the whole gate's row. So the
  order is the same (standing first, from rows no key decides, then the
  route, then the keys, all under one fence) and only the caller's rows
  are read once instead of twice. Measured at 1,000 uses a second, cache
  off: Postgres CPU 2.95 ms a UI use against 1.52 for a code route
  before, 2.16 to 2.23 against main's 1.49 to 1.53 after (1.45x; the
  rest is the route's own reads and a second function call; T200's
  1.3x is a follow-up's, the route read inside the named call).
- **Quiet uses.** A route use's key that the place does not hold, or that
  is plain, writes no entry and takes no lock (`v_quiet`, as a named call's),
  and a plain value goes back as its text. A workload's gate is such a use
  of no key at its place (its route named, or `every` for `proxyItem`'s
  every item), which writes nothing.
- **The chain is the vault's.** Each level the statement reads carries its
  environment's row, seal and newest change's seal, and the vault checks
  every level of the chain, whichever serves: sealed, current, the first
  the place, each the parent of the one before, the last a root
  (`chainFault`). A parent re-pointed around the log fails it, `tampered`
  (review r1: a child's key would otherwise reach an unrelated
  environment's sealed route; review r2: above the level that serves too,
  since the keys resolve through the whole chain, so `x → eu → dev` with
  `eu` re-pointed at `other` would send `other`'s key of the same name
  through `x`'s own route). Levels past the serving one carry their
  environment only, not their definitions.
- **`OneVersion`** is held across rounds and chunks by comparing each
  statement's levels' seals, the item's digest, the editor's newest seal,
  and the roles' and the policy's newest seals with the first's
  (`versionOf`; the roles and policy since review r1: the editor's decision
  weighs them; every level's environment since review r2: the keys resolve
  through them); any difference starts the use over, at
  most three times, then `late`. A second round passes every key of its
  chunk, the ones it does not make with no request id: only checked.
  A use that starts over is made by the ids its newest statement read,
  which every statement also leaves in the isolate's map: an edit landing
  between two statements costs one attempt, not two (Fable's review of
  #464). A first statement whose ids are right but whose map held a list
  of another length (a key added past the first chunk, or one dropped from
  the end) is a miss too, never a later chunk sent past the list's end.
- **Covers**: `use_route` passes a key's cover to `use_credential` only past
  the newest change of the route's levels and editor, which
  `use_credential` does not read; `use_credential` matches the cover's
  entry on its route too.
- **The editor's decision** (`routeEditorRefusal`, proxy.ts) is one
  function for the live use and the replay (`routeDecision` in
  log-replay.ts, over the log's own objects): `routeRefusal` on the
  editor's standing now, then `frozenAllows`/`frozenOwns` on what the save
  froze, at the key's holder, the place protected or not as the policy is
  now. An editor's principal row that fails its seal, or is not its
  newest change, refuses the use `tampered` or `stale` (R64).
- **A level's lookup on the item alone** (`routeLookup`): the index parsed
  from `digests` (`parseIndex`) and its seal checked as the whole object's
  (`sealedIndex`), the item hashed against its entry; an item the sealed
  index lacks is `tampered`. Every item (`proxyItem` with no name) checks
  each level whole (`proxyServing`), and one level that fails fails all.
- **Cost** (`use-route-cost.test.ts`): one statement warm; 114 buffers at
  10k entries of history, 113 at 1M; 119 with 256 definitions in the
  environment (its index, about 11 KB, read whole), the same rows; with a
  handle's made-for list read (a place reading), 167 at 1k environments in
  the instance and 158 at 10k (8 to 13 more than before review r2: the
  reading picked again under the fence, and every level's environment). That list is read a subquery per place, by
  key: as a join, the generic plan hashed every environment (114 buffers at
  10k, review r1). The new
  `log_uses.route` column costs every use row its null bitmap's second
  byte, which pads the header: measured over 100,000 rows, 126 B a row
  without it, 134 with it null (+8 B, every use but a route's), 141 with
  a route of six letters.
  No CHECK on it: on the partitioned table it would scan every day under
  an exclusive lock while the previous release serves.

**PR C as built, the app's half for handles (C2a, W312).** C2 ships as
two PRs: C2a, the gate and a handle's routes, with the plan; C2b,
workloads (their counts, section 3), signers, verifiers, presign and
tunnels of UI items, and `/use/<a>/<b>` in one call. Until C2b, a
workload, sign, verify or tunnel naming a UI item finds none: 404, as
before PR C. Where C2a settles what this section left open:
- **The gate** (`proxy-gate.ts`) keeps, per isolate and vault, the code
  names it reserved, settled answers only. A gate that fails answers the
  request itself, before the plugin: 503 `unavailable` (`proxy_gate`,
  `Retry-After: 1`), or `deploying` for a vault on another release, and
  keeps nothing, so the next request asks again. The tests' database
  reset forgets it with the log (`forgetProxyGates`). A vault of 0.14's
  log holds no proxy definitions and has nothing to reserve: the gate
  passes it without a call (`keeps015`, settled per vault, whose log is
  fixed when it is made). Nor is the proxy given `useRoute` or
  `proxyItem` there (`servesUi`: 0.15's uses, log and hot login), which
  that vault throws on: an editable proxy's plan on 0.14's log is code's,
  and a UI route's URL is 404 (review r5 of #467).
- **The handle on a cold isolate** is found by its shape before any item
  says where it rides: any header (`x-api-key: <handle>`, SigV4's
  `Credential=<handle>/…`, a Basic pair decoded), the query, the path (a
  path rule's segment, as sent and decoded once), then the body
  (64 KiB). The query and the body are read as sent and as decoded, every
  way a rule reads its slot: `?key=coffre%5Fuse_…`, a form's percent escapes
  and a JSON string's `\u005f` find the handle `sendAs` reads there (review
  r7 of #467). A body is decoded only as its Content-Type lets a rule read
  it (`bodyKind`, `fieldsIn`'s own test): a JSON note holding
  `coffre%5Fuse_…` is text there, as `sendAs` reads it, not a second handle,
  and a form's `"…\u005f…"` the same. JSON's strings are found in one pass
  (`jsonStrings`), which discovery and a JSON rule's fields share: the regex
  before it, retried from each quote, took about 3.7 s of CPU on 64 KiB of
  escaped quotes that never close (`"\"\"…`), before any check, on `main`'s
  JSON rules too (review r8 of #467). Two different handles: 400. The decided item must then find it
  where it takes its key (`sendAs`), or nothing is sent. Bearer,
  `x-coffre-handle` and the query alone missed SigV4 and every header
  rule but `authorization`.
- **The send's window** (review r1 of #467). A UI route's values are
  decided before the body is read, since on a cold isolate the item that
  says how to carry it comes with them. So each send carries a send-by
  time, checked just before it goes: a kept entry's `until`, or, decided
  now, the use's deadline (3 s), or `cacheSeconds` if longer. A body that
  stalls past it is 503 `late` and nothing is sent: values decided before
  an edit or a revocation never ride a request that came after it. The
  check is the fetch's own first step, after the body's digest and every
  signature (SigV4's) are made, so slow signing is late too (review r3 of
  #467).
- **The handle decides the reading before code's precedence.** For
  `/use/<a>/<b>` and for `/use/<a>/<b>/<a code name>/…` (`<a>` no code
  name), the handle's made-for list says whether the URL is the place's
  (the plan or compute; code's credential) or route `<a>` at `/<b>…`:
  `/use/openai/models/maps` from a `market/dev` handle is UI route
  `openai` at `/models/maps`. The handle is found outside the body or,
  for a form or JSON route, in it. Under `cacheSeconds: 0` that list was
  one more call; since C2b4 the route use answers the reading itself.
- **Only readings whose name can be a route's.** `/use/s3/bucket/report.csv`
  is route `s3` at `/bucket/report.csv`; `report.csv` is no route name, so
  no place reading is offered. The vault takes a malformed name as the
  app's bug and fails the call.
- **A copy's refusal** stands only for the reading the vault would take:
  the place reading where the handle's kept made-for list names `<a>/<b>`,
  else the stable one. The place reading's copy is keyed by place and
  route, not by handle, so another handle's copy says nothing of this
  URL; with no list kept, the use's answer decides. That holds for a URL
  with the place reading alone too (`/use/123/dev/openai/files`, `123`
  being no route name; review r2 of #467): a list is kept only once the
  vault checked the handle, so a stranger's handle-shaped token is the
  use's 401, never the copy's 403 telling them the route and its allow
  list.
- **A service binding's call** carries no handle and is served no UI route
  until C2b: the proxy tells it by `PluginContext.binding`, before it
  looks at any copy, since a handle's kept values would otherwise answer
  a binding's request that carries the same handle, skipping the
  binding's own checks (review r2 of #467). It gets code's answer, 404 for
  a name code lacks.
- **An Owner's upstream on Node** (section 5, "No private targets"; review
  r2 of #467). A UI route's request goes out through the runtime's
  `publicFetch` (`PluginContext.publicFetch`, from the platform's
  transport): on Node, undici's fetch on an `Agent` whose connections
  resolve the name through `publicLookup` as they open, so
  `internal.acme.example` resolving to `10.0.0.5` is refused before the
  SYN, however it resolved at save; on Workers, the platform's fetch. A
  runtime without one (a hand-built one) answers 503 before the use, so no
  use is logged for a request that is never sent. `insecureUpstreams`
  keeps the global fetch, for local fakes. Code's routes are unchanged:
  their upstream is the deployment's, reviewed and deployed.
  `@coffre/server` depends on `undici` (7.30.1, Node 24's own) for it;
  only the Node entry imports it. Node dials an address written as one
  (`https://240.0.0.1/x`) without asking the lookup, so `publicFetch`
  checks such a host itself, as the lookup checks a name's answers, and
  refuses one that is not public before undici is called (review r3 of
  #467).
- **A project named as code's credential is.** With code's `maps` and an
  environment `maps/dev`, `/use/maps/dev/openai/models` from a handle made
  for `maps/dev` is the place reading: its third segment is code's
  credential if code has it, else the environment's UI route `openai`
  (review r2 of #467; the opposite collision, a third segment code names,
  was r1's). Where code's `maps` finds no handle where it takes its key,
  the handle is looked for wherever a UI item may take it
  (`x-openai-key`, a form field), and the made-for list decides as
  before. Under `cacheSeconds: 0`, code's `maps` reads the body before
  the vault's one call says the handle is `maps/dev`'s; the UI route then
  sends those same bytes (review r3 of #467). Code's reading reads a copy
  of the request, so the body stays whole for the UI route even where code
  refuses it: a JSON body that code's form rule calls no form still
  reaches route `openai` (review r4 of #467).
- **Values are kept by the reading the vault took, never by the URL**, as
  section 3 keys them (caller, place and route). A `market/dev` handle's
  `/use/openai/models/gpt-a` and `/use/openai/models/gpt-b` are both the
  stable reading of `openai`: one use, then one kept copy for every path
  under it within `cacheSeconds`. That copy never answers a URL whose
  `<a>/<b>` is the handle's environment (`/use/market/dev/openai/…`),
  which section 6 reads as the place; a stable answer means a handle of
  one environment, so that is the only such `<a>/<b>`. The app's
  `credential.use` entry, which a route of plain keys alone keeps, names
  the route of that reading too (`openai`, never `gpt-a`) (review r4 of
  #467).
- **One key, one placeholder**, across code's and the UI's routes: two
  that read `OPENAI_API_KEY` with different placeholders (`a_`, `b_`)
  would give the app one value that one of them refuses. Startup refuses
  this of code alone; the plan refuses it (409 `conflict`, naming both) of
  the routes the environment serves, code's and its UI's together (review
  r2 of #467). A code signer's or verifier's key is the handle as it is,
  so a UI route shaping it with a placeholder is refused the same way
  (review r3 of #467).
- **Refusals.** A key the item's editor no longer routes is 403
  `route_not_cleared`, the vault's reason naming them: the caller may
  read the key, so D153's single 404 hides nothing here. A refusal of the
  caller's own standing stays the read's 404 `not_available`. A handle
  made for `market/dev` reads `/use/market/dev@me/openai` as route
  `market` (404); one made for `market/dev@me` reads the place, and is
  409 `route_not_personal`.
- **The plan** makes one `proxyItem` call with no name before its
  `expose` read. Routes the proxy can read join the covering set; the
  keys of any other item (a signer's, verifier's or tunnel's, which C2a
  does not serve, or a route the proxy cannot take) are the handle too,
  and no URL is listed for them. A `tampered` or `stale` level, or an
  item answered without its definition, is 503 and no environment. A
  name code holds is left out; a personal config shapes nothing (the
  vault answers `personal` with no items, checked before the items are).
  A generated environment's plan (`generate`) reads `market/dev@me` once
  the person has a value of their own there: the read's answer says so,
  and the base environment's items are then dropped, so the plan gives
  their own `OPENAI_API_KEY`, never a handle and route `openai`'s URL,
  which would send the base key (review r5 of #467). Decided on each
  attempt's answer: a read the app retries (`AccessChanged`) that first
  resolved the personal config and then, the config deleted between the
  two, the base environment gives the base's items again, the handle and
  the URL, never the base key (review r6). A UI route's JWT
  placeholder copies claims through an `expose` read (section 3): a
  Contributor's plan, or anyone's on a sensitive key, is 403
  `placeholder_unread`, nothing of it opened.
- **Cost** (`proxy-use-cost.test.ts`, `cacheSeconds: 0`, a warm vault
  map): the place URL and a stable URL of three segments or more are one
  `use_route` statement and nothing of the app's; `/use/<a>/<b>` was the
  handle's made-for list (`use_credential`) and then the use, one call
  since C2b4, whose route use answers "the place" for a place reading. The
  same rows with 256 definitions in the environment as with one.

**PR C as built, workloads (C2b1, W312).** C2b ships as a stack: C2b1,
workloads' UI routes; C2b2, signers, verifiers and presign; C2b3,
tunnels; C2b4, `/use/<a>/<b>` in one call. Where C2b1 settles what this
section and section 3 left open:
- **The model is unchanged.** `Routing.tla`'s value cache is per caller
  and its copy per route, whoever the caller is; a workload is one more
  caller. What C2b1 adds before the use (the reading, the counts) takes no
  lock and decides nothing the use does not decide again.
- **The URL's readings, as the workload's client writes them**
  (`url(name)` in `@coffre/client/workload`: `/use/<name>` with one place,
  `/use/<project>/<env>/<name>` with several). `/use/<a>/<b>/<c>/…`, `<a>`
  and `<c>` names code lacks, is route `<a>` at the one environment the
  workload reaches, unless it reaches several or none, or that one is
  `<a>/<b>`: then route `<c>` there (`WorkloadAt.or`). The session's
  checks decide it before the gate (`OtherReading`), so the proof is spent
  once, by the reading taken: the client's own URLs cost one statement,
  and only a place URL from a workload of one environment costs two.
  `/use/<a>/<b>` stays the plan and compute (C2b2 and C2b4).
- **The counts** are a function of the caller, made after the proof's
  nonce, just before the gate takes them (`GateCounts`, `CountsAt`): the
  service, the place by ID, the credential named and the way in, as the
  vault names a workload. The proxy counts a UI route's limit from this
  isolate's copy of the item at that place (`w` readings), or, on a cold
  isolate, `proxyItem`'s, asked as the workload; a refusal there is
  answered after the gate. Section 3 left one case out: a limit an Owner
  raises. A request the copy's lower limit refuses brings no use's answer,
  so the copy would refuse until the window ends (a day, for `perDay`).
  So a limit refusal counted on a kept copy asks `proxyItem` for the item
  again: one refusal more at most.
- **The body** is carried by its headers alone (`carriedAs` with `sigv4`
  and no field: the client's `bodyLine` rule), and the decided item takes
  it or refuses it (`uiCarried`): a declared `x-amz-content-sha256` binds a
  body only through a `sigv4` item, else 503 `moved`, nothing sent, the
  kept values evicted; a form or JSON item reached by a streamed body
  reads it whole (64 KiB) and holds it to the digest the proof bound. A
  client that sends `x-amz-content-sha256` to a route of another kind
  signs a line this rule reads otherwise, and is refused: no client of
  coffre's does.
- **The use** is `useRoute` as the workload (`RouteCaller` `workload`: the
  session's credential, or the binding's ID with `way: 'binding'`, at the
  place its statement checked). The vault's answer carries its standing
  there (`standing`), which the read takes in place of `access()`: one
  call a use. The values are kept per session (or binding), place and
  route, each entry with its item; every check runs again on that item
  before the send: aim, the allow list, `uiCarried`, the `narrow`
  constraints on the URL its upstream makes. A narrowed child reaches no
  UI route in a test yet: 0.15's log refuses one planted around the app,
  and `/api/auth/workload/narrow` answers 501 until its PR.
- **The plan** (`workloadPlan`) names the place's UI routes whose keys the
  environment holds, from one `proxyItem` call with no name, and answers
  503 on a forged level, as a handle's plan does. Values are given only as
  the workload reads them, for code's and the UI's routes alike.
- **Cost**: warm, cache off, one vault call (`useRoute`); cold, two
  (`proxyItem`, then `useRoute`); a kept entry, none. No `access()`.

**PR C as built, signers, verifiers and presign (C2b2, W312).** Where
C2b2 settles what section 3's "Signers and verifiers" and "Presign" left
open:
- **The model is unchanged.** A sign, verify or presign is a route use
  of the item by name (`useRoute`, the handle's place reading or the
  workload's stable one), decided twice like a route's keys; what the app
  does with the answer is `Routing.tla`'s `Send`, with the value cache
  per caller and its entry carrying the item (`BoundToDefinition`). No
  lock or recheck is added.
- **Where:** `POST /use/<project>/<env>` for a handle, and a workload's
  `POST /use` or `POST /use/<project>/<env>`, `{ sign | verify | presign:
  { credential: <name>, … } }`, a name code lacks of any kind (R66). The
  compute body is read up to what an HMAC saved in the UI may take
  (`maxBytes`, 1 MiB) under `editable`, as code's longest otherwise.
- **The checks** (`unfit`, `presignTarget`) run on the copy before the
  use, and stand only for a fresh copy (confirmed within `cacheSeconds`;
  for a handle, only on a place its checked made-for list names); then on
  the decided item, the kind and the message's size inside
  `RouteAsked.refuses`, before the read opens any value, and presign's
  target after it, built from the decided route's upstream before
  anything is signed. A request a fresh copy admitted and the decided
  item refuses is 503 `moved` (`Retry-After: 1`), nothing made; the
  decided item is then the isolate's copy, which answers the next one. A
  sign of a route or verifier, a verify with a private key, a presign of
  a signer: 404; a presign of a route whose one inject rule is not
  `sigv4`: 400.
- **The cache.** An HMAC sign or verify keeps its values for
  `cacheSeconds` beside a route use of the same name and caller, the
  entry carrying its item, whose `encoding`, `prefix` and `maxBytes` a
  kept sign takes, never a newer copy's. A private key's signature and a
  presigned URL are a use each, never kept, as code's are.
- **Own values only** (review r3 of #480). The read answers its values
  as an ordinary object, so an item's key is taken only as the object's
  own (`Object.hasOwn`, as code's `valuesFor` does): a key named
  `toString` or `constructor` that the read does not hold is 409, never
  the function the prototype lends, which would sign, or check as
  valid, with a key anyone can compute. `routeUsed` holds every key the
  vault decided on to the same before any kind is served. In practice
  the read refuses first: a key the environment does not hold is 409
  `changed`; one gone after the decision is 404 on SQLite, and on
  Postgres the read serves the value decided on, by ID.
- **The window** (`WithinWindow`, review r1 of #480). What a UI item
  makes is answered by when its values may be used, as a route's request
  is sent by then: values decided now, within the use's deadline
  (`USE_DEADLINE_MS`, or `cacheSeconds` if longer, and never past the
  caller's end); kept values, until they lapse. A signature, a check or a
  URL ready later, a slow private key's or a stalled isolate's, is 503
  `late` (`Retry-After: 1`) and goes nowhere.
- **No token in a URL.** A presigned URL is for sharing, so neither a
  handle nor the request's own session token may be in it: its path or
  its query, as it is or decoded as often as it changes (8 times at
  most), is 400 before anything is signed (review r1 of #480). A URL that
  still decodes after the eighth pass is 400 too, as a path segment that
  does is: a ninth reading would go unchecked (review r2 of #480). This
  holds for code's presign too, which checked the handle alone.
- **The log.** `RouteAsked.logged` may be a function of the decided
  item: a presign's entry names the decided route's host, never the
  copy's; a private key's sign names the message's SHA-256, hashed only
  once the vault has decided on a private-key signer, which holds the
  message to 64 KiB by then: an unknown bearer gets no 1 MiB hash out of
  the isolate (Fable's review of #480). Both are the
  app's `credential.use` entry, which 0.15 writes only when no key is
  secret: a secret's use is the vault's slim row (R53), naming the route,
  and the item by the object's seal. A refusal thrown before the use,
  from a kept entry or a fresh copy, is answered in the proxy's shape,
  `coffre-proxy: refused`, as the decided item's is.
- **Counts**: a signer's or verifier's limit is the item's (`itemCounts`,
  shared with C2b1's routes; a presign counts the route's), from this
  isolate's copy or, cold, one `proxyItem` call before the gate. A
  request counts against the copy's limit whatever the copy's kind: the
  counts are taken before the gate, so before the session's kept values
  are known, and those may still serve it. A signer saved over as a
  verifier with the same limit, another session's verify bringing the
  verifier's copy, leaves the first session's kept signer signing until
  its values lapse; each of those signs is counted against the limit the
  name has now, never let through uncounted for the verifier's kind
  (review r2 of #480). A tunnel has no limit, so a name saved over as one
  counts nothing until kept values lapse.
- **Cost**: a handle, one vault call (`useRoute`); a workload, one warm
  and two cold; a kept HMAC, none.

**PR C as built, tunnels (C2b3, W312).** Where C2b3 settles what section
3's "Tunnels" left open:
- **The model first** (R45). `Tunnel.tla` gains an edit of the session's
  item and an edit of another item of the environment, each at any tick,
  and an invariant, `EditEndsWithinBound`: a session whose item was saved
  anew ends within R + D of the save, the bound a revocation has. Two
  protections, each shown necessary: the recheck compares the decided
  item's digest with the one dialled (`DigestRecheck`; without it, TLC
  finds a session open past the bound behind checks that see the key and
  nothing else), and that digest is the item's own, never the object
  seal (`ItemDigest`; comparing the seal, another item's save ends a
  session whose item stands, `StandingStaysOpen`). No lock is added: the
  check is the use a route makes.
- **Where:** `/use/<project>/<env>/<name>` as a WebSocket, a name code
  lacks (R66), for a handle (the place reading) or a workload (its stable
  reading at the place its statement checked), each as code's tunnel
  authenticates it. The vault's one call decides the item and its key;
  the item is checked before the read opens any value (`refuses`): a
  route, signer or verifier is no database (404), and a database naming
  a network is 503, never dialled directly, since no deployment's code
  declares networks yet (the Proxy tab refuses one at save, 400). Then
  the decided item's hosts and section 5's checks (`dialled`, code's).
- **The session's group is the item's.** A session is grouped by caller,
  place, name and the digest it dialled, so one opened on a newer item
  never joins the checks that hold the older one's sessions: an edit
  that keeps the host ends the sessions of the item before it, and those
  dialled since stand.
- **The recheck** is the same use, the item's digest given as the copy's
  so the vault sends no definition back, and refuses a decided item of
  another digest before the read (503 `moved`): the check is a no and
  the group ends. A deleted item, a revoked handle or a lost grant is a
  no the same way. A handle's group keeps code's one check, which arms
  the watchdog; a workload's, code's two: its statement every two thirds
  of the bound, and the item's use every `recheckSeconds`.
- **Each connection is a use.** A UI tunnel keeps no values: unlike
  code's, whose open may take the value cache's URL and decide at once,
  every connection asks the vault, as a private key's sign does. A pool
  of connections is a use each, at the connect, never a query.
- **The plan** names the place's UI databases under `tunnels`, as code's,
  with the key the listener stands in for and never the URL; a
  workload's plan the same, from its one `proxyItem` call.
- **An Owner's database on Node** (section 5; review r1 of #485). The
  hosts are an Owner's, so a name they typed may resolve to the server's
  own network: `dialled` checks the URL's host against them by spelling,
  and the session then dials through the runtime's `publicConnect`
  (`PluginContext.publicConnect`, from the platform's transport), never
  the platform's plain TCP. On Node it resolves the name through
  `publicLookup` as the connection opens, so `db.attacker.example`
  resolving to `10.0.1.5` gets no SYN, and Postgres's SSL request never
  reaches it; an address written as one is checked as written. TLS, once
  Postgres says it will, still checks the certificate against the name.
  On Workers it is `connect()`, whose network reaches no private address
  (the Sockets object's runtime carries it). A runtime without one answers
  503 before the use; `insecureUpstreams` keeps the platform's, for a
  local database. Code's tunnels are unchanged: their hosts are the
  deployment's.
- **The clock starts at the admission** (review r1 of #485;
  `Tunnel.tla`'s `AdmitClock` and `LateAdmitRefused`). The vault may
  decide the item well before its answer reaches the proxy, and an Owner
  may save the item anew in between. The group's watchdog and its first
  check count from when the admission's use started, not from when the
  group was made: an answer that came after a recheck's interval is
  checked again at once. One that came after the whole bound (R + D for a
  handle) lets nothing in, 503 `late`, and the client asks again, by the
  new item. Code's tunnels keep the clock they had, from when the group
  is made, and no such refusal: a pool's 32 connections opened at once
  take turns at their admission, and with `recheckSeconds: 1` the last is
  answered some 16 s after it asked, which must still be let in
  (`credential-proxy-tunnel-workers.test.ts`). Fable's review of #485
  suggested the UI's clock for them, which would refuse those, so C2b3
  changes no code tunnel's. A UI tunnel pays for its bound under such a
  burst: a handle's admission, which may take 45 s at most
  (`ADMISSION_MS`), is late only below the default `recheckSeconds`, but
  a workload's bound is 15 s, so a workload admission answered later is
  refused 503 `late` and asks again.
- **The copy it claims is the copy it holds** (review r1 of #485). The
  open tells the vault the digest it holds a definition for only when it
  does: its copies of definitions (`ui.items`) and of which digest each
  reading last had (`ui.last`) turn over apart, past ten thousand
  entries, and claiming a digest whose definition is gone would have the
  vault leave the definition out, and every open answer 503 `moved` until
  something else brought it back. The copy claimed is kept through the
  use, so the answer finds it however the isolate's copies turned over
  meanwhile, and a decided item whose definition neither has is refused
  before any value opens (`refuses`).
- **A workload's refusals carry its nonce**, the ones the open returns as
  its thrown ones (`nonced`), so the next proof signs the current nonce.
- **Cost**: the open, one vault call (`useRoute`); a recheck, one.

**PR C as built, `/use/<a>/<b>` in one call (C2b4, W312).** Where C2b4
settles section 6's "URLs of one or two segments" for handles:
- **The model is unchanged.** The reading was already picked by the route
  use's statement, under the fence, from the handle's rows, and picked
  again there if a rename moved it in between (review r2 of #464). C2b4
  only offers that statement one more place reading, the place itself,
  which uses nothing: no lock, recheck or order of the use changes, and
  the plan, compute and code's credential that follow make their own
  calls, each deciding for itself, as they did after the made-for list.
- **Both readings in the one call** (`useRouteOrPlace`). `/use/<a>/<b>`,
  and `/use/<a>/<b>/<code's name>/…`, `<a>` a name code lacks, send
  `{ place: <a>/<b>, route: none }` and `{ stable: <a> }`. The statement
  takes the place for a handle made for `<a>/<b>`, and answers it with
  nothing of a route read or used (`found` null, no keys); otherwise
  route `<a>` at the handle's one environment, its values in that call.
  `use_route` takes a place reading only with a route named (`p_named`),
  so the place itself is `''` to it, a name no item may have; taken, the
  statement leaves the route block before the place's chain and levels
  are read (0070, on 0069's body, T207's; SQLite's `callRoute` the same):
  the reading, the gate and the handle's places are its answer (Sol's
  review r1 of #486).
- **What is kept.** A made-for list this isolate keeps (`madeFor`, which
  code's stable URLs still ask) decides first, no call. Without one, with
  `cacheSeconds`, a place answer is kept by handle and path for
  `cacheSeconds` (`placeKept`), as the list was: the next plan or sign
  asks nothing to tell its URL, and a place copy's refusal stands for
  that handle as the list let it (`uiCompute`). Route `<a>`'s values,
  kept for its stable reading, serve `/use/<a>/<b>` for any `<b>` but
  when `<a>/<b>` is the environment they were decided at, which is the
  place's (`keptFor`): a route named as the handle's project is never
  sent the plan's request. A kept place lasts no longer than its handle:
  the answer carries when the handle ends, as the list's entry did, so a
  copy's refusal never answers an ended handle, which the vault's call
  answers 401 (Sol's review r1 of #486).
- **A runtime without a public fetch** asks the made-for list, as before:
  the vault would otherwise log a use of route `<a>` for a request never
  sent (section 5).
- **Cost** (`proxy-use-cost.test.ts`, `cacheSeconds: 0`, a warm vault
  map): `GET /use/<a>/<b>` of a UI route is one `use_route` statement and
  nothing of the app's. A plan, a sign or code's credential under the
  place is the place's answer, a `use_route` of the gate and the
  handle's places, no definition read (`use-route.test.ts` holds both
  engines' statements to no level read), then their own calls: as many
  calls as before.


**PR B: matching and injection, for code definitions first.** Server only,
no storage.
- The path rules and the allow list (section 7), code's `/` and trailing-slash forms kept; several inject rules with
  their order rules; SigV4 over earlier headers; redaction across all of a
  route's keys; `environments` scoping on code items; `allow` beside
  `methods`/`paths`.
- Tests: hegel property tests of the matcher (no encoded form of a path
  outside a pattern is ever allowed; matching is linear in segments ×
  entries), the table of section 7 as unit tests, multi-inject end to end
  against a fake upstream (header + query, header + SigV4 with the signature
  verified), redaction of every key's forms.

**PR C: the use path for UI definitions.**

The route use's contract in section 3 (its input, the keys and places it
serves, and its outcome) is the target this design sets; PR C proves it
buildable. It extends `Routing.tla` first, then writes the tests listed
below: the version gate refusing a mixed pair and a rollback of both,
binding callers, forks, both URL readings, signing and presign, and the
personal config's 409. A gap found while building it
is fixed in this document, within PR C.

- Migration at the next free number: `log_uses` gains the nullable route
  column, under the entry MAC; `use_credential` and `use_batch` take the
  route, read the proxy object(s) and the editor's principal, and match a
  cover on the route (section 4), on both engines.
- `@coffre/core/vault`: the route use's input and outcome (section 3:
  the caller union, handles by token hash and workloads by credential id
  and `way`; per-key sealed or plain values, standing, `expiresAt`, the
  seal list, the digest and the item), and `proxyItem`'s; the template key
  parser, shared by the vault's save and the proxy's startup check. No UI
  route goes through `reveal`, `useValues` or `useMany` by ids: one app
  function makes every route use, for handles of any number of keys,
  workloads, signers, verifiers, presign and tunnels, and takes the
  definition from the answer before the cache, a signature or a dial sees
  it (section 3). Tests: a UI route's use decided for its editor and sent
  by the decided item, for a handle route of one key (the stable URL with
  `cacheSeconds: 0` too), of two keys (SigV4), a workload route from a
  DPoP session and from a binding, a presign, a private-key sign and a
  tunnel dial, each at a plain place and at a fork; a route of plain keys
  only, decided the same; a route use at a fork resolving its item and
  keys through the chain; a UI route at a personal config, 409
  `route_not_personal`; a template whose braces the old regex and the
  shared parser could read apart, saved and replayed to the same key set;
  the gate and `proxyItem` each failing, the request 503 and the next one
  asking again. Versions (section 3, "One version at a time"): an app on
  the next release in front of this vault, each proxy request 503
  `deploying` with `Retry-After: 1` and no route read or changed; this
  app in front of 0.15's vault, which has no `call`, each proxy request
  failing with no route read or changed; both Workers rolled back
  to the previous release together, served as that release serves; rolled
  back to 0.15 and upgraded again, the UI items served, gated first.
- `use_credential`: the proxy object(s) and the editor's principal as
  inputs in both shapes, in the seal cache; the named use takes a route; the vault resolves its keys by name,
  decides twice and answers with the definition.
- The proxy: UI routes, signers, verifiers and tunnels; the value cache keyed
  by caller, place and route, each entry carrying its seal and item
  (section 4); the send before the deadline; the plan
  (`GET /use/<p>/<e>`) shaping UI routes as code's (section 6); `proxy.code` with its gate;
  `coffre.proxyItem` and the provisional checks on every path (section 3).
- First, before any code (R45, decision 5(b)): `Routing.tla` extended with
  the editor's current holdings as an input of the use's statement, an
  action that removes or demotes the editor, and a protection
  (`EditorStillHolds`) whose removal TLC must break.
- **From the expert review** (Fable 5.1 on `aee4142c`, 2026-11-02):
  1. The stable reading's map key: settled in section 6 (the made-for list
     per token, route ids per place and route, never the path). PR C's
     `/use` bench gains a row: a no-cache stable UI route over distinct
     paths, one call each (R44); and a test that a changed made-for list
     answers `moved` on a hit, then serves.
  2. URLs of one or two segments: settled in section 6. Both shapes join
     the URL-readings tests, `GET /use/openai/models` and `GET
     /use/market/dev` from one handle included.
  3. `SealPresent`, a model of an older vault's answer with no seal and no
     digest, arises only with two releases serving together. The version
     gate (decision 8) rules that out, so it is not built.
- Tests, one per `Routing.tla` protection, each on Postgres and SQLite: an
  edit between a use's statement and its send; an edit landing between a
  route's two keys (its second round, and a chunk boundary), answered
  `moved`; a row put back; a key marked sensitive after a Developer's save;
  kept values never sent to a newer upstream; code shadowing then dropping
  a name; two first isolates reserving at once; the gate reserving under
  `editable: false`; a fork's item deleted with its index left
  (`tampered`, not the parent's). A workload's route use: its limit
  counted on a cold isolate through a stable URL, and a limit edit under a
  warm cache counted against the old one only until the next answer; a
  `narrow` constraint weighed on the decided upstream after an edit; an
  inject-kind edit between the copy and the answer answered 503 `moved`;
  an allow-list widening served by a warm isolate whose copy refused the
  path (allowed within `cacheSeconds`, one `proxyItem` call), and the same
  for a handle's route use; a cold stable-URL sign and presign of a UI name
  (no 404 before the caller stands); an editor demoted or removed, their
  route answering `route_not_cleared` until a holder saves it; two sessions
  on one isolate, A's values on version 7 checked and sent by version 7's
  item after B's use brought version 8; a cold stable-URL request whose
  body line the item's inject kind would have chosen otherwise (503
  `moved`).
  Presign refused unless `sigv4` is the route's one rule, and an upstream,
  allow-list or inject edit between the copy and the use never signs the
  old target (503 `moved`), its entry logging the rebuilt host. A tunnel whose `hosts` an Owner narrows mid-session ends within
  one recheck. Both URL readings, on a hit
  and a miss, with `moved` when the handle's environments change. Also `request-cost.test.ts`
  (statements and rows flat as the log grows and as an environment gains
  definitions), the `/use` bench against 0.15.1 (no regression, R44),
  conformance for both examples.
  Covers: the same key used through two UI routes within a minute, and a
  repeat right after a proxy edit and right after an editor's demotion,
  each writing its own entry, replay agreeing. The plan: a UI route's key
  given as the handle, never its value, in a handle's plan and in a
  non-reading workload's (a workload that may read a key gets its value
  for code and UI routes alike, as `workloadPlan` does today); a forged
  item answering the plan 503 with no environment; a UI item a code name
  shadows left out of the plan. Cold entry: a stable-URL workload forward, a stable
  field-kind handle, a UI tunnel's open, each served without a 404 first;
  a `proxyItem` refused during counts answering its outcome after the
  gate. An HMAC `prefix` edit under a warm value cache, the sign still by
  the entry's item.

**PR D: the page.**
- #421's Proxy tab on the API: the mock store goes, and so do the "0.16"
  badges. Locked code rows, `environments` scopes, copy, review, the role
  editor's row, the audit page's `proxy.save` and `proxy.code`, the
  `route_not_cleared` mark; the save confirmation's window (decision 4),
  the copy review naming each copied item's keys and destination
  (decision 2), and the offboarding preview naming the routes a removal or
  demotion stops (decision 5).
- Docs: `credential-proxy.md`'s sections on UI definitions; `coffre init`
  writes `editable: true`, so new deployments get the tab, while an upgraded
  one changes nothing until it opts in.
- Tests: the page's own (save, discard, 409 review, inert fields for a
  reader), the examples' parity test, `check:docs`.

**PR D as built** (W314). Where it settles what this section left open:
- **The page's answer** (`ProxyPage`) adds, beside `editable`: `readOnly`
  (why not, in the API's words), `code` as code's items, not names
  (`ProxyCodeItem`: the definition in the tab's shape, `environments`, a
  limit per service, and whether a binding carries it), `routesSensitive`
  (the reader owns the project), `releases` (an instance Owner),
  `useUrl` and `windowSeconds` (decision 4's window: `cacheSeconds`, or the
  3 s deadline), and `insecureUpstreams`, so the page checks a definition
  with the vault's own rules (`proxyDefinitionProblem`, now
  `@coffre/core/proxy`, which a browser loads) before it asks.
- **The `route_not_cleared` mark** is the vault's: `Vault.proxy()` decides
  each item's keys for its frozen holdings and its editor's standing now
  (`notCleared` in `packages/vault/src/proxy.ts`, the rule section 8 gives
  the use), and answers `notCleared` per item: the first key that does not
  clear, the environment that holds it, and why, as a code the tab words
  (`NotClearedCode`: `unread`, `unread_at_save`, `not_owner_at_save`,
  `not_owner`), never by matching the vault's text (T197). A save's answer leaves it
  out: its reads would hold the change's locks two round trips longer
  (`change-cost.test.ts`). PR C's use decides the same way, through the
  same `editorRefusal`. A fork's read also
  marks what it inherits (`inheritedNotCleared`), decided where the fork
  resolves the keys: dev's `openai`, saved by someone who reads dev's
  OPENAI_API_KEY, does not route in dev-eu once dev-eu sets its own value
  they do not read, though it still routes in dev.
- **A sensitive reference** is routed as any sensitive key of the place, by
  an Owner of its project (`routesSensitive`; R71): its source was checked
  when it was made (R24), never at a route.
- **Edits against another save**: the page keeps the seal it began editing
  from, so a save that came since, even one a background read already
  shows, is a 409 whose review says what changed. An edit whose item that
  save removed stays a row, made again on saving. "Save again" queues the
  item as its editor saw it: an inherited item, whose parent's save is no
  409 to the fork, shows that parent's change since as fields its save
  would set back, in the review, rather than clearing what its editor
  never saw.
- **The offboarding preview** reads `Vault.proxySavedBy({ member })`: the
  rows that name the member found by their JSON, each object then held by
  the log, so a forged row lists nothing. The member's page lists them, and
  the Remove dialog names those it stops. A demotion stops those whose keys
  it takes away; the page says so rather than predicting each.
- **Forks**: the tab reads each parent's page beside its own, one round
  trip; editing an inherited item, or saving it again as it is to clear
  it, saves the fork's own (decision 6). Inheritance shows up to the
  first parent the page cannot read (closed to the caller) or trust
  (tampered, stale), and says so: past it, an unseen parent may override
  what its own parents hold, and the vault refuses a use through a forged
  object.
- **Code's allow lists** keep code's matching: a code item says how
  (`ProxyCodeItem.allowAs`): `code`, an `allow` whose trailing slash takes
  what is below it; `legacy`, `methods` and `paths` as before 0.16, `*`
  itself, with `methods` as code wrote them (`[]` took none), kept apart
  since `paths: []` has no entry to carry them: `methods: ['POST'],
  paths: []` is still a 405 to a GET. The sample call follows it, and
  reads its path as the proxy does: encoded (`/café` is `/caf%C3%A9`), its
  query apart, a segment that climbs out (`/%2e%2e/admin`) a 400. Code
  takes any HTTP method (`PROPFIND`), the tab's own items its seven: a
  code item's show as written, and the sample call offers them. An empty
  allow list takes no request, a 403.
- **Narrow screens**: the list stacks above the panel below 46rem of the
  page's width (a container query, so the sidebar counts), and below 32rem
  each label goes over its field.
- **As code** writes a UI item out scoped to the environment it is in
  (`environments: ['market/dev']`), as it serves now; a code item shows no
  snippet, since its binding or limit per service has no words in the tab.
- **Egresses and networks** stay direct in the tab until PR C declares them
  by name (PR A refuses one with 400).

PR B can go in parallel with A. C needs A and B. D needs A, and C for real
uses.

## 11. Decisions (2026-11-02, recommendations taken; reversible)

1. **Owners routing sensitive keys: (a)**, as R66 decided: Owners covering
   the place may, audited. A code-side `uiUpstreams` allow list (b) can be
   added later; a second Owner's approval (c) is not needed, since R30
   already lets those Owners read the value.
2. **What a copy shows: (b)**. Copying keeps every field (R66), and the
   review step names, per copied item, which of the target's keys it will
   send where, e.g. "`schuman` will send market/prod's SCHUMAN_API_KEY to
   sandbox.schuman.example (copied from market/dev)". Saving still saves.
3. **Names: (a)**, unique across the four kinds for UI items and against
   every code name; code keeps its per-kind rule, warning at startup on a
   cross-kind clash.
4. **The window after an edit: (a)**, accepted as for revocation: old values
   may reach the old upstream for up to `cacheSeconds`, and the save's
   confirmation says so.
5. **An editor who leaves or is demoted: (b)**, holdings frozen at save and
   intersected with the editor's current ones, as R15 does for tokens; uses
   answer `route_not_cleared` until someone who holds the keys saves again,
   and the offboarding preview names the routes affected. The model checks
   (a) today, so PR C extends `Routing.tla` first (section 10).
6. **Forks: (a)**, definitions inherit by name through the chain of
   parents, as values do; a fork's own item overrides, and removing it
   says "revert to dev's".
7. **Personal configs: refused in 0.16.** A UI route asked for at a
   personal config (`<env>@me`) answers 409 `route_not_personal`, naming
   the base environment; code routes keep `@me` as today. A UI route's
   use is cleared by its editor's frozen holdings, and no editor can ever
   read another person's owner-only values (R8, R20), so every such use
   would be `route_not_cleared`; a clear refusal beats a route that can
   never work. Reversible: a later release may define how personal values
   reach a UI route.
8. **Versions: one at a time** (Erwin, 2026-11-02). The app and the vault
   Workers are never served on two releases at once. Every call carries
   the release, a mismatch is 503 `deploying` with `Retry-After: 1` before
   the vault reads anything, and a deploy or a rollback moves both
   Workers (section 3). Rounds 9 to 12 of review and the expert pass kept
   finding gaps in serving an app ahead of, or behind, its vault; holding
   requests for the seconds of a deploy is simpler than any of the fixes.
   A finding that arises only across two releases is answered by this
   decision.

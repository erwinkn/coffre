# Proxy definitions in the UI (0.16, T186)

A design for 0.16's headline, written on 2026-11-01 (W304) before any
code. Rules R65 and R66; the UX is prototype
[#421](https://github.com/erwinkn/coffre/pull/421) (layout B, refined by
W260 and W263; draft, never merged). The model is
[`formal/Routing.tla`](../../formal/Routing.tla), described in
[docs/formal.md](../formal.md#routingtla). Nothing here is built.
Section 11 records the six decisions it needed (2026-11-02).

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
  index          bytea NOT NULL,   -- (name, SHA-256(canonical item)) of each item, sorted by name
  seal           bytea NOT NULL    -- the vault's HMAC over (kind, id, index), 16 bytes
);
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
    "holdings": [ { "projectId": "…", "environmentId": null, "role": "owner", "permissions": { "normal": [ … ], "protected": [ … ] }, "sensitive": true } ] }
] }
```

No answer to the app carries `holdings`: a use's, `proxyItem`'s and
`GET …/proxy`'s carry the definition, and `route_not_cleared` names the
editor in the vault's own message.

`holdings` is the editor's grants as a service token's scope keeps them
(`ScopeGrant` in `@coffre/core/access`: place, columns held, and `sensitive`
where they could hand a service sensitive reads, R32). Section 8 explains
how a use weighs it. An item the save did not change keeps its `savedBy` and
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
  app      sends only if every key's answer carries a seal and an item digest, the same seal for every key
             (no seal or no digest: 503, never "the copy's digest confirmed"; another seal: asks again)
           checks the handle (section 7), and the method and path against the definition's allow list
           keeps the values beside that definition (the entry carries its seal and item)
           sends, before the use's deadline, to that definition's upstream
```

An answer to a route use that carries no seal or no item digest is a
refusal, never a confirmation. A 0.15 vault ignores the `route` field it
does not know and answers a plain named use: values, with no item, no seal
and no digest. Read as "the copy's digest confirmed", that answer would send
by whatever copy the isolate holds, to its upstream, with the editor never
decided. That happens when a vault is rolled back under warm 0.16 isolates
(docs/deploy.md: the vault goes first), which have seen `proxies` and will
not ask again (section 6). So the app checks presence on every answer, and
the `proxies` bit is an early gate, not the protection.

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
  - *The use* is today's workload use with the route's name: the session is
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
| `ClearanceAtUse`: each use weighs the key's nature now against the definition's clearance | a Developer routes `K` while it is secret. An Owner marks it sensitive, and the next use sends the sensitive value to the Developer's upstream |
| `KeptExpires`: kept values serve W, no longer | values sent long after their decision (`WithinWindow`) |
| `OneVersion`: a route's keys are all decided on one version, and the app sends only answers carrying one seal | key 1 is decided on version 7 (`good`), an Owner's edit to version 8 (`evil`) commits, a later round decides key 2 on version 8, and the request carries both to `good`: key 2 goes where no version it was decided on says |
| `ClearSuperseded`: the `proxy.code` change that reserves a name deletes its UI item | code defines `openai` for a while, then drops it, and the stale UI `openai`, unseen for months, serves again (`NoRevival`) |
| `SaveChecksReserved`: the vault refuses a save of a reserved name | during a deploy, an Owner saves `openai` through an old isolate after the new one reserved it; the new code hides it, and it serves again when a later deployment drops the name |
| `CodeGate`: an isolate serves no proxy request before its code's names are reserved | the same revival, through a deployment that served `openai` from code without ever reserving it |

The model runs two isolates, which may run different code during a deploy,
and a writer who can forge a body or put a row back. What it does not
cover: the fence's own correctness (that a use and a
change never overlap, and the number orders them) is `HotPathOne.tla`'s, for
any input. Here an edit is one step. One route, two hosts; its second key
appears only when `OneVersion` is off, since with it on both keys share
every decision. The frozen holdings are reduced to one clearance per
version ("sensitive" for an Owner, "secret" otherwise). Decision 5 takes
option (b), the frozen holdings intersected with the editor's current
ones, which is not modelled yet: PR C extends the model first. The matching rules of section 7 are pure
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
tests hold that it gives handles and fails closed. Old-vault skew (section
6, "Against an older vault") is held by PR C's tests: no UI item exists
until the vault says `proxies`, and an isolate gates before serving
once it does. The scenarios with
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
of that and adds the route's name to what the request names.

| Case | Today (0.15) | With UI definitions |
|---|---|---|
| Map hit, uncached (`cacheSeconds: 0`, or an entry's refresh) | 1 call | **1 call.** Two more inputs of the statement, each one more row and one more probe of its newest change, inside the same call: the proxy object (the route's item and the index) and the editor's principal (decision 5); one more proxy row and probe per fork parent, up to four. The item is not sent back, because the isolate's copy has its digest |
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
- **The vault isolate's map** (0.15's) keys that answer by the token and
  the URL's first three segments (`market`, `dev`, `openai`), and holds
  the reading, the place id and the key ids. The app isolate keeps the
  definition and its digest, from the use's answer, as its copy.
- **On a map hit**, the call names the reading the map holds, with its ids.
  The statement reads that place only, and answers `moved`, writing
  nothing, if the rule would now pick the other reading (the handle's
  made-for list is among the caller's rows it reads anyway) or the route no
  longer names those keys. Then the isolate reads again, as on a miss.

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
  keeps the settled answer, never the pending call (AGENTS.md, "What an
  isolate keeps").
- **Against an older vault.** A deploy can put the 0.16 app in front of
  its 0.15 vault for some minutes, and a 0.15 vault has no gate to call.
  One bit decides every proxy surface: `proxies` in `about()`, which a
  vault with 0.16's proxy calls says, as `useMany` has `batchUses`. While
  the vault does not say it, code routes, signers, verifiers and tunnels
  serve as in 0.15, ungated; the Proxy tab's APIs, `proxyItem`, UI routes
  and the plan's UI items answer 503 naming the vault's release. Unlike
  the other bits, its absence is not kept: each proxy request on an
  isolate that has not seen it asks `about()` again, one more call per
  proxy request for those minutes only, and the first answer that says
  `proxies` runs the gate before that request is served. The re-ask is
  the same at every gated entry: `fetch`, `socket`, the plan and the
  Proxy tab's APIs. A failed `about()`, gate or `proxyItem` call is not
  an absence: that request answers 503, gated or not yet, and the next
  one asks again, so an error never serves code ungated. On Workers that
  extra call is not free: `about()` goes through the vault's `#call`,
  which waits on its isolate's checkpointer start (at most 2 s, once per
  cold vault isolate), where a use goes on behind it (R58). It adds no
  Postgres statement (R44, R50), and the wait is accepted for the minutes
  of a deploy, on isolates that have not seen the bit. That keeps
  `CodeGate` whole. No UI item can exist before the vault says `proxies`,
  since only a vault that says it saves one, so an ungated isolate serving
  code's `maps` hides nothing. Once the vault says it, every proxy request
  is gated first, and a gate deletes any UI `maps` saved meanwhile. Keeping
  the absence instead, as `about015` keeps `batchUses`, would leave that
  isolate serving code's `maps` ungated for its whole life while a
  different deployment's tab saved a UI `maps`: the `NoRevival` run the
  gate exists to stop. The other order, a vault newer than its app, needs
  nothing: a 0.15 app has no tab and no UI routes.
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
3. **New:** each segment is percent-decoded once, to bytes, and the decoded
   segments are matched against the allow list. Bytes, not text: no UTF-8
   check beyond step 1's overlong refusal (a `%FF` segment is forwarded
   today and still is), no case folding, no Unicode normalization. `Café`
   written precomposed and decomposed are two different segments, as they
   are to the upstream.
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
`documents` must not miss `docu%6Dents`.

**Patterns are decoded too, once.** A pattern's segments are percent-decoded
when it is read: at save for the UI, at startup for code. So today's
`paths: ['/companies/a%20b']` becomes the segment `a b` and still matches
`/companies/a%20b`. It does not match `/companies/a%2520b`, which decodes
once to `a%20b`, a different segment. A pattern that decodes to a dot segment, a slash or an empty
segment is refused at save. In code it is a startup warning and matches
nothing, which is what it matches today, since step 1 refuses every
request it could have matched. Two code forms keep today's meaning, as
special cases: `/` is the prefix of no segments and matches every path,
and one trailing slash, `/companies/`, matches what it matches today:
`/companies/` and everything below it, not `/companies` itself. The UI
refuses a trailing slash at save and offers `/companies/**`. PR B's property tests run every
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
  item's keys now: it resolves them by name in the place, inherited and
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
| Lin routes `{API_KEY}`, a reference into `billing/prod` | decided where it lives (R20): her read of `market/dev` covers it; sensitive takes an Owner of `billing` too, as R32 has it for service tokens |
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
- Migration at the next free number (Postgres `0053`, SQLite `0029` on
  `main` today, after #453, #454 and #456): `proxy_definitions`,
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
- `about()`'s `proxies` bit (section 6, "Against an older vault"), said
  by a vault with the save; without it the tab's APIs answer 503 naming
  the vault's release. PR C widens what the bit promises (the gate,
  `proxyItem`, route uses), so no release ships PR A without PR C: they
  go out together in 0.16, and none of them is a release on its own or a
  rollback target. Splitting them would need a second bit.
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
- Migration at the next free number: `log_uses` gains the nullable route
  column, under the entry MAC; `use_credential` and `use_batch` take the
  route, read the proxy object(s) and the editor's principal, and match a
  cover on the route (section 4), on both engines.
- `@coffre/core/vault`: `NamedUseInput` gains the route; its outcome, the
  item, the seal list and the digest; `proxyItem`'s input and answer. The
  `proxies` bit (section 6, "Against an older vault"), which PR A adds with
  the save and which now also covers the gate, `proxyItem` and route uses:
  an old vault ignores an unknown `route` field and answers with no item,
  which would read as "the copy's digest confirmed", so without the bit
  the app refuses UI routes (503, naming the vault's release). The app
  asks `about()` again while the bit is absent, and never keeps that
  absence. Seen once, the bit is kept, and an answer with no seal or no
  item digest is still a 503 (section 3): that, not the bit, covers a
  vault rolled back under warm isolates. Tests: a vault rolled back to
  0.15 after the bit was seen, a UI route's use refused, never sent by the
  copy; `about()`, the gate and `proxyItem` each failing, the request 503
  and the next one asking again.
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
  the entry's item. A vault without `proxies`: code routes served
  ungated, UI routes, `proxyItem`, the plan's UI items and the tab
  refused (503); the vault upgraded mid-run, the next proxy request asks
  `about()` again, gates, and deletes a UI item saved meanwhile under a
  code name.

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

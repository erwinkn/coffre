# Proxy definitions in the UI

A credential proxy definition (a route like `openai`, a signer, a verifier,
a database tunnel) can live in the deployment's code, `credentialProxy({ … })`,
or be written by an Owner in an environment's Proxy tab. This note is the
design of the second kind, as built. The model is
[`formal/Routing.tla`](../../formal/Routing.tla), described in
[docs/formal.md](../formal.md#routingtla). The exact matching and injection
rules are in [credential-proxy.md](credential-proxy.md); this note gives their
reasons where the UI changes them.

The question under everything here is **where may a key go**. A definition
that points `{STRIPE_KEY}` at a new upstream is a read of that key by whoever
controls the upstream.

## In short

1. **Storage** (section 2). One row per environment, a sealed object of the
   vault's log, changed only through the vault. A database writer cannot forge
   one, nor put an old one back unseen.
2. **Ordering** (section 3). An edit is a change under the fence, exclusive; a
   use reads the definition in its one statement, under the fence, shared. So
   every use is decided wholly before or wholly after an edit. Values already
   decided may still go to the old upstream for at most R, the deployment's
   `proxy.revokedWithinSeconds` (60 s unless set, 3 s at least), the bound a
   revoked handle has ([config.md](config.md), section 1).
3. **Who may route what** (section 8). A save freezes what its editor could
   read. Each use decides the route's keys for the caller and for that frozen
   editor, intersected with what the editor still holds. An editor who cannot
   read a value can never route it, and only an Owner of the project routes a
   sensitive one.
4. **Cost** (section 4). A warm use of a UI route is one vault call, as a code
   route's.
5. **Code wins** (section 6). A UI item whose name code defines is never
   served. Code's names are reserved in the log, and no deploy drops a
   reservation.
6. **One version at a time** (decision 8). The app and the vault run one
   release; a call across two is 503 `deploying` before the vault reads
   anything.

An example, end to end. Ada is an Owner of `market`. In `market/dev`'s Proxy
tab she adds a route:

```
openai   https://api.openai.com/v1
  sends   header authorization: Bearer {OPENAI_API_KEY}
  allows  POST /chat/completions, GET /models/**
```

She saves. The vault checks that she holds `proxy.edit` on `market/dev`,
freezes her holdings into the definition, seals the environment's new `proxy`
object, and logs one `proxy.save` entry naming the route, its upstream and its
keys. Bo's app, run with `coffre run market/dev`, calls
`https://secrets.acme.example/use/openai/chat/completions` with its handle. The
app asks the vault in one call for route `openai` of `market/dev`, and gets
back the definition with the key. It checks `POST /chat/completions` against
the allow list and sends the request to `api.openai.com`. Ten minutes later Ada
points `openai` at `https://eu.api.openai.com/v1`. A use decided after her save
goes to the EU host. Values decided before it may still go to the old host for
up to a minute.

## 1. What a definition is

The shapes are `@coffre/core/proxy`'s (`ProxyDefinition`), checked by
`proxyDefinitionProblem` at save, in the vault, and in the browser before the
page asks:

| Kind | Fields |
|---|---|
| Route | `upstream`, `inject[]` (several rules), `allow[]` (`{ methods, path }`, with globs), `limit` (`perMinute`, `perDay`), `placeholder`, `egress` (a name) |
| Signer | a private key, or an HMAC (`key`, `encoding`, `prefix`, `maxBytes`, 1 MiB at most), `limit` |
| Verifier | an HMAC, `limit` |
| Database (tunnel) | `key`, `hosts[]`, `network` (a name) |

A save holds at most 256 items (`MAX_PROXY_ITEMS`).

**Egresses and networks are not usable from the UI.** An egress (a VPC
Service) or a network (a VPC Network) is a Worker binding, so only code could
declare one, and code has no way to declare one by name yet. So the API
refuses a UI item that names one (400), and a use of such an item answers 503
naming it, never a direct fetch or dial in its place.

`proxy.editable` in `deployment.ts` (false unless set) decides whether the
Proxy tab may write and whether uses read UI items. One thing runs whatever
it says: the gate of section 6, which reserves the names code defines, once
per isolate, whenever `credentialProxy` is configured. Without that, this run
would revive a route: D1 (`editable: true`) has a UI `maps`; D2 sets
`editable: false` and adds code `maps`; D3 turns `editable` back on and drops
code `maps`, and the UI `maps`, unseen since D1, would serve again.

## 2. Storage

### Where

```sql
CREATE TABLE proxy_definitions (
  environment_id uuid PRIMARY KEY REFERENCES environments(id),
  items          jsonb NOT NULL,   -- the canonical object: name -> item, with who saved it
  digests        bytea NOT NULL,   -- the index: (name, SHA-256(canonical item)) of each item, sorted by name
  seal           bytea NOT NULL    -- the vault's HMAC over (kind, id, digests), 16 bytes
);
CREATE TABLE proxy_reserved (      -- one row: the instance's
  id     smallint PRIMARY KEY CHECK (id = 1),
  names  text[] NOT NULL,          -- every name code has reserved, the whole set
  seal   bytea NOT NULL
);
```

Only the vault's logins write them, through its change functions. The app
reads neither: every read of them is a vault call.

**A use reads one item, not the environment.** The seal covers the index, not
the items: each item's name beside the SHA-256 of its canonical body, sorted by
name. A use's statement reads its route's item (`items -> 'openai'`), the index
and the seal. The vault checks the MAC over the index, finds the name it asked
for there, and hashes the item against that entry. A forged item fails the
digest, a forged index fails the MAC, and so does a moved item: a writer who
drops `a` and stores A's body under `b` leaves the sealed entry `b` naming B's
digest, which A does not hash to. At 256 items the index stays under 17 KB.

**Names are in the index so that a deleted item is not a missing one.** That
matters for forks (decision 6). `market/dev-eu` with its own `openai` serves
it; without one it serves `market/dev`'s. If the index held only
`SHA-256(name || item)`, a writer could delete `openai` from dev-eu's `items`
alone, and the use would fall back to dev's item: dev-eu's key would go to
dev's upstream, which no dev-eu definition says. With names in the index, the
vault falls back to the parent only when the child's sealed index has no entry
by that name. An entry whose item is missing is `tampered`.

**Forks.** Definitions inherit through the chain of forks, up to three parents
(`MAX_PARENTS`), as values do. The lookup walks the ancestors nearest first and
stops at the first sealed index that names the route. The vault checks every
level of the chain, whichever serves: each sealed, current, the first the
place, each the parent of the one before, the last a root (`chainFault`). A
parent re-pointed around the log is `tampered`. Example: `x → eu → dev` with
`eu` re-pointed at `other` would otherwise send `other`'s key of the same name
through `x`'s own route, since keys resolve through the whole chain.

**A missing row.** An environment that never had a UI definition has no row.
Once its object has a change, the row stays: removing the last item saves an
empty index. So a row deleted after a save is `stale` (the probe sees a newest
change and no row), and a fork's lookup still falls back by the empty index.

**One row per environment, not one per item,** because the page saves all its
pending edits at once and a copy from another environment writes many items:
one object makes that one change, one seal and one entry. The cost is that two
Owners saving different routes of one environment at once conflict; the second
gets a 409 and reviews the first's change.

### Sealed by the vault, not the app

The row is a sealed object of the log, kind `proxy`, id the environment's uuid
([sealed-inputs.md](sealed-inputs.md)). An app-MAC'd row (`APP_KEY`, like a
credential's row) would refuse an edited upstream, but serve last year's row
put back, say an upstream whose domain has since lapsed: a MAC proves a row
was once valid, not that it is current. A vault-sealed object is refused
`stale` unless its seal is its newest change's. A database writer may cause
side channels, never a key served on forged state.

The object holds each item with what its save froze:

```json
{ "items": [
  { "definition": { "kind": "route", "name": "openai", "upstream": "https://api.openai.com/v1", "inject": [ … ], "allow": [ … ] },
    "savedBy": "user:ada@acme.example", "savedAt": 1793560000000,
    "holdings": { "role": "member", "scope": { … }, "instance": { … }, "grants": [ … ] } }
] }
```

`holdings` (`FrozenHoldings` in `packages/vault/src/inputs.ts`) is the
editor's standing as a service token's scope keeps it: their instance role,
its scope and columns, and each live grant with its role's columns, each as the
policy defined it at the save, so no role widened later widens the route. It
is their grants, not what they held at the places the save saw: a fork made
later is decided by the grants that reach it (a `router` on `market/dev` reads
none of `market/dev-eu`'s own keys; a `router` on all of `market` does).
`frozenAllows` and `frozenOwns` (`packages/vault/src/proxy.ts`) decide over
them at any place.

No answer to the app carries `holdings`: they name an editor's grants across
projects.

### Changes and audit

Three change ops, each through the vault's change path (`change_input`: CAS on
the seal of the object's newest change, the fence exclusive):

| Op | Who | Changes | The entry holds |
|---|---|---|---|
| `proxy.save` | a person holding `proxy.edit` on the environment | the environment's `proxy` object | the environment, the seal the page loaded, each item added, changed or removed, whole |
| `proxy.code` | the deployment, through the app's gate (`reserveProxy`, no HTTP route) | the `proxy-reserved` object, and the `proxy` object of each environment holding a name it adds | the names it adds, and each UI item it deletes, whole |
| `proxy.release` | an instance Owner, `PUT /api/proxy/reserved` | the `proxy-reserved` object | the name released |

The reserved set is one instance-wide object whose every change carries the
whole set. So "is `maps` reserved" is one read of one row, checked against its
newest change's seal, never a sum over earlier entries.

**The CAS is on the object's newest change, never the row.** The vault decides
each save from the object as its log has it (`heldByLog`), so a forged row is
never carried on. A `tampered` or `stale` object takes only a save that
replaces it whole (`replace: true`), by an Owner of the project; its entry
names every item it drops. An item the save does not name keeps its editor and
holdings: Bo's edit of `maps` leaves Ada's `openai` cleared as Ada. An item it
names is saved again under the editor's standing now, even with its definition
unchanged: that is how an Owner clears a route its earlier editor no longer
can (section 8). A save that changes nothing logs nothing.

Every decision, refusals included, writes a vault entry. The audit page shows
a `proxy.save` as a diff (`openai: upstream api.openai.com → eu.api.openai.com`)
with the keys each changed item sends, marked when one is sensitive
(`routes sensitive: STRIPE_SECRET_KEY`). A removed item's entry holds its whole
definition, so it can be restored from the log, and so can each item
`proxy.code` deletes.

**A stale page.** The page keeps the seal it began editing from. If anyone
saved since, the save is 409 `proxy_changed`, and the page reloads, keeping the
pending edits on top, with a review of what changed. Nobody overwrites a change
they never saw.

## 3. Ordering against `/use` and revocation

### What must hold

The literal property, *an edit must never let an in-flight or later use send
the key to a host no current definition allows*, cannot hold without a round
trip on every use, because the app caches opened values for up to R and serves
them with no vault call. What holds, and what TLC checks:

- **`EverySendAllowed`.** Every request that carries a key goes to the upstream
  of a definition that (a) the vault decided on, (b) was the log's newest when
  it decided, and (c) was cleared for the key's nature at that decision. A
  request carrying several keys (Basic's user and password, SigV4's two)
  carries them under one version.
- **`WithinWindow`.** That request leaves within W of the decision, W being R
  (cached values or not; R is 3 s at least, the use's own deadline).
- **`NoRevival`.** No use is decided on a UI definition once code has shadowed
  it, then or after code drops the name.
- **`MismatchInert`.** No vault call reads or changes a route while the
  caller's release and the vault's differ.
- Two runs `scripts/formal.sh` keeps as expected failures, so the gaps stay
  written down: `StrictlyCurrent`, the literal reading (values decided before
  an edit serve out their W), and `RoutingRelease`, an instance Owner who
  releases a reserved name while an older deployment still serving defines it,
  then saves it (section 6).

The window, as a timeline. R is 60.

| Time | Event |
|---|---|
| 12:00:00 | Bo's app uses `openai`. The vault decides on version 7 (`api.openai.com`). The app keeps the key, bound to version 7, until 12:01:00 |
| 12:00:20 | Ada saves version 8 (`eu.api.openai.com`) |
| 12:00:30 | Bo's app calls again. A cache hit: the key goes to **`api.openai.com`**, version 7's upstream, never to the EU host, which the vault has not decided on for these values |
| 12:00:45 | One request asks the vault again. It decides on version 8, and from here the key goes to the EU host |
| 12:01:00 | At the latest: version 7's values serve no more |

A revocation works the same way, ordered by the fence and the log number: a
revoke numbered before a use refuses it; one numbered after leaves it decided,
and its values serve out the window (decision 4).

### The protocol

The vault isolate keeps its map from names to ids (`UseCache`): per token, the
handle's made-for list; per place and route, the route's key ids. The app
isolate keeps its copy of each route's item (the definition and its digest),
the place's serving index, and when an answer last confirmed them.

```
use (a route use)
  app      find the handle in the request by its shape (no definition needed for that)
  call     useRoute(caller, both URL readings, the map's ids, the digest of the app's copy)
             fence shared, one statement, one snapshot:
               the caller's rows; the route's item, the index and seal of each fork level
               through the one that serves; the newest change's seal of each; the editor's
               principal; every key the item names, resolved by name through the chain and
               held to the map's ids (else `moved`)
             one entry per key, the route's name included, under its MAC
  vault    seals checked, then every key decided twice:
             for the caller (purpose use)
             for the editor: frozen holdings, intersected with current ones (section 8)
           answers: the values, the levels' seals, the item digest, and the definition
             (omitted when the app's copy has that digest), never the holdings
  app      checks the request again on the decided item (section 3, "The app's checks")
           keeps the values beside that item
           sends, before the send-by time, to that item's upstream
```

**One version at a time** (decision 8). The app and the vault Workers run one
release (the packages' one version, which `pnpm bump` moves), and a deploy or a
rollback moves both. Each side has one funnel, so no call goes around the
check. The vault has one entry, `call(release, method, args)` (`VaultEntry`,
`gated`, in `@coffre/core/vault`; on Workers `VaultEntrypoint`'s only public
method, on Node `serveVault`'s `POST /call`), which compares the release before
any config read or pool open, and on a mismatch answers `{ release: <its own> }`
and runs nothing. The app wraps the entry once, `versioned(entry, release)`,
before `createRuntime`; an answer on another release throws `Deploying`, which
the API answers 503 `deploying` with `Retry-After: 1`, signed-in routes
included. A refusal is an answer, not a thrown error: a Workers RPC error loses
its fields and a Node failure maps to 500, so neither could say `deploying`
reliably.

**Every UI route use takes this one shape** (`useRoute`). A use by ids
(`reveal`, `useValues`, `useMany`) carries no seal, no digest and no item, so
the vault would decide the caller alone and the app would send by its own
copy. No UI route goes that way:

- **The caller** is a handle by its token's hash, or a workload by its
  credential's id and way in (`connection`, `binding`, `access`). A Cloudflare
  binding has no token, and is the second kind.
- **The route's keys are the item's own list.** At save, the vault computes
  each item's key names once, with the one template parser in `@coffre/core`
  that the proxy's startup check also uses, and stores the list in the
  canonical item, under its digest. The statement holds the map's ids to that
  list, and replay reads it from the same item, so live and replay cannot
  disagree on a key set, whatever a template's braces look like.
- **Places.** Item and keys resolve through the fork chain, nearest first. A
  personal config (`<env>@me`) answers 409 `route_not_personal` (decision 7).
- **One version.** All of a route's keys are decided on one version. A use of
  several keys may need a second round, and a large batch runs in chunks; every
  later statement must read the first's levels' seals, item digest, editor's
  seal, and the roles' and policy's seals (`versionOf`), or the use starts
  over (three attempts at most, then `late`). Otherwise a SigV4 route could have
  its access key decided on version 7 (`good`) and its secret on version 8
  (`evil`), and one request would carry both to one host (`OneVersion`).
- **One app function.** Every path that consumes a UI route's values calls it:
  a handle's forward, a workload's forward, sign, verify, presign, and a
  tunnel's dial and rechecks. It takes the definition from the answer before
  the value cache, a signature or a dial sees it. A thrown vault error is a 503,
  never a fallback to a use by ids.

**The placeholder is not a route use.** To copy a JWT's claims into its
placeholder, the plan opens the key's value for the caller alone, purpose
`expose`, so the claims show the caller nothing they may not read. A
Contributor's plan, or anyone's on a sensitive key, is 403
`placeholder_unread`, nothing opened.

**`coffre.proxyItem(caller, place, name)`** is a vault call that checks its
caller as a use would, reads the place's sealed proxy rows as a use's statement
does, and answers the item, its digest, the levels' seals and the serving
index (every name the chain serves, with the level that serves it). With no
name it answers every item the place serves, and one level that fails fails
all (`proxyServing`). It decides no use, opens no value and writes no entry. It
also warms the vault's map with the item's key ids, so the use that follows is
a map hit. It exists because a workload's limit and a sign's checks need the
item before the use, when the caller is a session still standing up, which
`coffre.use` cannot name.

### The app's checks on its copy, on every path

Every path checks a request against its route before sending:

| Path | What it checks |
|---|---|
| A handle's route | `aim` (the path against the upstream and allow list), `carried` (stream the body or read it whole), `fieldIn` (where the handle sits) |
| A workload's route | the same, the DPoP body-line rule, and the limit's counts |
| Sign, verify, presign | the item's kind, presign's target and `narrow` checks, the message's size |
| A tunnel's open | the item's hosts |

For a UI name these read the app isolate's copy, which may predate an edit or
be missing. One rule covers every path:

- **What the copy lets through is provisional.** The use's answer brings the
  decided item, or confirms the copy's digest, and the checks run again on it,
  the target rebuilt from its upstream. If the decided item would have carried
  the body otherwise, bound another body line, or found the handle elsewhere,
  the request is 503 `moved` and nothing is sent; the client's retry finds the
  new copy.
- **What the copy refuses stands only while the copy is fresh**: confirmed
  within R (never, with `cacheValues: false`). On an older copy the isolate
  makes one `proxyItem` call, replaces its copy and checks again. So an allow
  list an Owner widens takes effect on every path within R, and no warm isolate
  refuses it for good. A refusal on a copy also stands only for the reading
  the vault would take, and a copy keyed by place says nothing of another
  handle: a stranger's handle-shaped token gets the use's 401, never the copy's
  403 telling them the route and its allow list.
- **A name in neither code nor the serving index is 404 only after the
  caller stands**, never from code's maps alone.

**Where the handle is, on a cold isolate.** The handle is found by its shape
(`coffre_use_` and 43 characters) before any item says where it rides: any
header (`x-api-key`, SigV4's `Credential=<handle>/…`, a decoded Basic pair), the
query, a path segment, then the body (64 KiB), each read as sent and as
decoded, every way a rule may read its slot (`?key=coffre%5Fuse_…`, a JSON
string's `_`). Two different handles: 400. After the answer, the decided
item must find the handle where it takes its key, or nothing is sent. JSON
strings are found in one pass (`jsonStrings`): a regex retried from each quote
took about 3.7 s of CPU on 64 KiB of unclosed escaped quotes.

**The send-by time.** On a cold isolate a UI route's values are decided before
the body is read, since the item that says how to carry the body comes with
them. So each send carries a send-by time, checked as the fetch's first step,
after the body's digest and any SigV4 signature are made: a kept entry's end,
or for values decided now, the use's deadline (`USE_DEADLINE_MS`, 3 s) or R if
longer. A body that stalls past it is 503 `late`, nothing sent: values decided
before an edit or a revocation never ride a request that came after it.

### Workloads, signers, verifiers, tunnels and presign

- **Workloads** (a DPoP session or a Cloudflare binding's caller,
  [workload-access.md](workload-access.md)). UI routes serve them as code
  routes do. The use is `useRoute` with the session (or binding) as the caller;
  its answer carries the caller's standing, so no `access()` call is made.
  Values are kept per session (or binding), place and route.
  - *URLs.* `/use/<a>/<b>/<c>/…` is route `<a>` at the one environment the
    workload reaches, unless it reaches several or none, or that one is
    `<a>/<b>`: then route `<c>` there. The reading is decided before the gate,
    so the proof's nonce is spent once.
  - *The limit.* The counts are a function of the caller and place
    (`CountsAt`), made after the proof is verified and just before the gate
    takes them, from the isolate's copy, or on a cold isolate from
    `proxyItem`'s item, asked as the workload. After an Owner raises a limit, a
    copy's lower limit would refuse until the window ends (a day, for
    `perDay`), since a refused request brings no use's answer. So a limit
    refusal on a kept copy asks `proxyItem` again: one refusal more at most. A
    limit is a throttle, not who may use what: the two decisions of the use
    still decide that, on the newest version.
  - *The body line.* The proof binds the body line before any item is known, so
    it comes from the request's headers alone (`bodyLine` in `dpop.ts`). The
    decided item then takes it or refuses it (`uiCarried`): an unsigned
    `x-amz-content-sha256` line passes only a `sigv4` item with
    `unsignedUploads`, else 503 `moved`; a form or JSON item reads a streamed
    body whole (64 KiB) and holds it to the digest the proof bound.
  - *On a value-cache hit* no answer comes, and the copy may be newer than the
    values: session A's values were decided on version 7, and session B's use
    has since brought version 8. Each cache entry carries the item its values
    were decided on, and `aim`, the allow list, `fieldIn` and the `narrow`
    constraints run again on that item, the target rebuilt from its upstream
    (`BoundToDefinition`). A mismatch is 503 `moved` and evicts the entry. The
    same holds for a handle's route.
- **Signers and verifiers.** A route use of the item by name, decided twice
  like a route's keys: the editor's frozen holdings must read the key,
  sensitive only for an Owner of the project. That is stricter than signing
  needs (it never hands the key out), and keeps one rule for every kind. They
  live at `POST /use/<project>/<env>` for a handle, and a workload's `POST /use`
  or `POST /use/<project>/<env>`. The checks (`unfit`, `presignTarget`) run on
  the copy, then on the decided item before any value opens.
  - An HMAC sign or verify keeps its values for R beside a route use of the
    same name and caller. A kept sign takes `encoding`, `prefix` and `maxBytes`
    from the entry's item, never a newer copy: a copy refreshed to version 8
    with a new `prefix` must not wrap a secret decided on version 7. A private
    key's signature is a use each, never kept.
  - What a UI item makes (a signature, a check, a URL) and is ready after its
    values' send-by time is 503 `late`.
  - **Own values only.** An item's key is taken only as the answer's own
    property (`Object.hasOwn`): a key named `toString` that the read does not
    hold must be 409, never the function the prototype lends, which would sign
    with a key anyone can compute.
  - A private key's sign logs the message's SHA-256, hashed only once the vault
    has decided on a private-key signer, which holds the message to 64 KiB by
    then: an unknown bearer gets no 1 MiB hash out of the isolate.
  - A signer's or verifier's `limit` is counted as a route's, against the
    copy's limit whatever its kind: a signer saved over as a verifier never
    lets a kept signer's signs through uncounted.
- **Presign.** A UI route presigns only when `sigv4` is its one inject rule;
  any other route answers presign with 400. The checks before the use run on
  the copy and are provisional. After the answer, the target is built again
  from the decided item's upstream, and the matcher, the allow list and the
  `narrow` constraints run again on it before anything is signed. An edit
  between the copy and the use can never get a URL for the old host signed
  with keys decided on the new version: any mismatch is 503 `moved`. The
  use's entry logs the decided item's host, never the copy's.
  **No token in a presigned URL.** A presigned URL is for sharing, so neither
  a handle nor the request's own session token may be in its path or query,
  as written or decoded as often as it changes (8 times at most; one that
  still decodes after that is refused too): 400 before anything is signed.
  This holds for code's presign too.
- **Tunnels.** A route use of the database item at
  `/use/<project>/<env>/<name>` as a WebSocket. The vault decides the item and
  its key; a route, signer or verifier is no database (404), and the tunnel
  dials the decided item's hosts, checked as section 5 says.
  - *Each connection is a use.* A UI tunnel keeps no values: every connection
    asks the vault, as a private key's sign does. A pool's connections are a
    use each, at the connect.
  - *The session is grouped by the item's digest* (with caller, place and
    name), so an edit ends the sessions of the item before it, and those
    dialled since stand.
  - *The recheck* is the same use, the dialled item's digest given as the
    copy's; a decided item of another digest is a no (503 `moved`) and the
    group ends. An Owner who narrows `hosts` mid-session thus ends it within
    one recheck. An edit to another route of the environment changes the
    object seal, not this digest, and ends nothing (`Tunnel.tla`'s
    `DigestRecheck`, `ItemDigest`). The bound is R: checks every R − d, each
    given d = min(R ÷ 2, 10 s) to answer.
  - *The clock starts at the admission* (`Tunnel.tla`'s `AdmitClock`). The
    vault may decide well before its answer reaches the proxy, and an Owner may
    save the item anew in between. So the group's watchdog and first check
    count from when the admission's use started; an answer that came after the
    whole bound lets nothing in, 503 `late`. Code tunnels keep their clock from
    when the group is made: a pool of 32 connections opened at once must all
    be let in, however long they queue for admission.

### What each protection is for

Each row is a constant of `Routing.tla`. With it off, TLC finds the run
described, which `scripts/formal.sh` holds as a failure.

| Protection | Without it, TLC finds |
|---|---|
| `FencedRead`: the definition is read in the use's statement, after the fence, in one snapshot with the decision | the use reads `openai` → `api.openai.com`, Ada's edit commits, the use is decided on the old row and numbered after the edit |
| `SealChecked`: the row's seal must be its newest change's | a writer puts back version 7 after version 8, and a use is decided on it |
| `CopyFromVault`: the isolate's copy comes only from vault answers | a writer forges the item beside its genuine index entry, the app reads that pair, the writer puts the genuine row back; the vault checks the genuine row, sees the app's digest, omits the item, and the app sends by the forged body |
| `SentAsDecided`: the app sends by the definition the vault decided on | the app's copy says version 7; the vault decides on version 8, and the app sends to version 7's host |
| `BoundToDefinition`: kept values go only to the definition they were decided under | values decided on version 7 (`good`) are served from the cache after the app re-read version 8 (`evil`) |
| `ClearanceAtUse`: each use weighs the key's nature now against the definition's clearance | Lin saves a route as a Developer, is made an Owner, an Owner marks `K` sensitive, and the next use sends it to Lin's upstream |
| `EditorStillHolds`: each use weighs the key against its editor's standing now | Ada saves `openai` and is removed; her route keeps sending `K` to the upstream she chose |
| `KeptExpires`: kept values serve W, no longer | values sent long after their decision |
| `OneVersion`: a route's keys are all decided on one version | key 1 decided on version 7, an edit to version 8, key 2 decided on version 8, and the request carries both to version 7's host |
| `ClearSuperseded`: reserving a name deletes its UI item | code defines `openai`, then drops it, and the stale UI `openai` serves again |
| `SaveChecksReserved`: the vault refuses a save of a reserved name | during a deploy, an Owner saves `openai` through an old isolate after the new one reserved it; it serves again when a later deployment drops the name |
| `CodeGate`: an isolate serves no proxy request before its code's names are reserved | the same revival, through a deployment that served `openai` from code without reserving it |
| `VersionGate`: the vault refuses a call on another release before it reads anything | an app isolate on the last release reads and changes the route through a vault on the next |
| `StandingFirst`: the call decides the caller's standing at the place before it reads the route | the route and its key read for a caller the call then refuses (`NoRouteBeforeStanding`) |
| `KeyByItem`: the use is made by the map's id only when it is the key the row read names now | an earlier answer's id used, whatever the route names now |

What the model leaves to tests: the matching rules of section 7 (pure
functions, property tests); the sealed index (a moved item and a fork's
deleted item are `tampered`); covers; the plan, which sends nothing. The
fence's own correctness is `HotPathOne.tla`'s.

## 4. What `/use` costs, in round trips

A route use is a named use (`packages/vault/src/use.ts`): the request names its
token, its place and its route, and the vault isolate's map holds the ids. On
a map hit it is one call. On a miss, the first call reads the ids and the
second makes the use, because the use's entry MAC binds each key's id, which
the isolate cannot compute before it has read it.

| Case | Vault calls |
|---|---|
| Map hit, nothing cached | **1.** The statement reads two more inputs, each one more row and one probe of its newest change: the proxy object (item and index) and the editor's principal; one more of each per fork level |
| Map miss (a cold isolate, or a key not used yet) | **2.** The first reads both URL readings (section 6), picks one, resolves the route's keys and answers the ids and the item |
| Right after an edit that keeps the route's keys | **1.** The item hashes to another digest than the copy's, and the answer carries the new item |
| Right after an edit that adds a key | **2, once per isolate**: a map miss, as any key's first use |
| Value-cache hit | **0** |
| No app copy, vault map warm | **1** for a handle (the answer carries the item); **2, once per isolate per route**, for a workload, sign or verify (`proxyItem` for the counts, then the use) |
| A code route | as before: no `proxy` row is read |
| An isolate's first proxy request | **1 more, once per isolate**, `editable: false` included: the gate (section 6) |

**What the entry records.** A route use's entry carries the route's name
(`log_uses.route`), under the entry's MAC; other uses leave it null. Which
definition it was decided on needs no column: it is the newest `proxy.save` or
`proxy.code` change of the place's object numbered below the entry. So two
routes that send the same key with different editors replay apart.

**A cover is per route.** A repeat of a use may ride the entry of the one
before it (a cover) when nothing it depends on changed. For a route use, the
route's name is part of the cover's identity, and the proxy object's levels
and the editor's principal join the inputs whose newest change a cover must
postdate. Example: routes `a` (Ada's, upstream `good`) and `b` (Lin's, upstream
`evil`) both send `{K}`. A use of `b` a second after one of `a` writes its own
entry, which replay decides under Lin's holdings. Without that, the log would
credit `b`'s use to `a`'s entry.

**A map hit holds the ids to the definition.** The statement checks that the
item still names the map's keys for that route, and otherwise answers `moved`,
writing nothing, and the isolate reads again (Naming.tla's `HeldToNames`). An
edit between the two calls of a miss therefore cannot have a key used that the
route no longer names.

**The isolate's copy comes only from the vault's answers** (`CopyFromVault`).
A call that carries the copy's digest gets the item omitted when the row's
item still has it, so a digest the isolate sends must stand for an item the
vault checked. If the copy came from a read of the app's own, a database writer
could swap the body to `evil`, let the app read it with the genuine index, put
the genuine row back, and the vault would omit the item for the app's digest:
the app would send by its forged copy. That is also why the app's login has no
`SELECT` on these tables.

**Two values travel.** The **item digest** identifies the copy: an edit of
another route of the environment changes the object seal, not this digest, so
the copy stays good. The **seals** are what `OneVersion` compares and what each
value-cache entry carries beside its item. The value cache is keyed by caller,
place and route, not by seal, and a hit sends by the entry's own item.
Invalidation costs no round trip: the statement compares the copy's digest
with the row's in its own snapshot, under the fence, and a kept value lapses
by time only, R. The app never hashes an item, so it needs none of the vault's
canonical form.

`use-route-cost.test.ts` and `proxy-use-cost.test.ts` hold the statement's
rows flat as the log grows and as an environment gains definitions (one
definition or 256 read the same rows).

## 5. The vault makes no outbound call

The vault reads Postgres, decides and answers. The app, the `coffre` Worker or
the Node server, makes every upstream request, as for code definitions. What
changes is who writes the upstream: an Owner through a web page rather than a
deployment through a review and a deploy. That calls for checks code upstreams
never needed:

- **No private targets.** A UI upstream is `https://` to a DNS name or a public
  address. Loopback, private, link-local and metadata addresses
  (`169.254.169.254`), `localhost` and single-label names are refused at save.
  A name can still resolve to a private address at request time (DNS
  rebinding). On Node a UI route's request goes through the runtime's
  `publicFetch`: undici on an `Agent` whose connections resolve the name
  through `publicLookup` as they open, so `internal.acme.example` resolving to
  `10.0.0.5` gets no SYN. An address written as one (`https://240.0.0.1/x`),
  which undici dials without a lookup, is checked as written. On Workers a
  `fetch` leaves from Cloudflare's network, which does not route to private
  addresses; only a binding reaches them. A runtime with no `publicFetch` (a
  hand-built one) answers 503 before the use, so no use is logged for a
  request never sent.
- **Database tunnels too.** A UI tunnel's hosts are an Owner's input:
  `hosts: ['db.attacker.example']`, resolving to `10.0.1.5`, would reach a
  private address, and the TCP connection and Postgres's SSL request go out
  before TLS could object. So the hosts follow the same rule at save, and the
  session dials through the runtime's `publicConnect`: on Node it resolves
  through `publicLookup` as the connection opens; on Workers it is
  `connect()`, whose network reaches no private address. TLS, once Postgres
  agrees to it, still checks the certificate against the name.
- **`insecureUpstreams`** lifts these checks for local fakes. It is the app's
  code config, which the vault cannot see, so the app passes it in the save's
  input; the use-time check, on the sending isolate's own config, is what
  holds.
- **Who checks what.** The vault refuses at save what needs no code: a
  non-HTTPS upstream, a private, loopback, link-local or metadata literal,
  `localhost`, a single-label name. The app checks the rest against its code
  before it calls the vault: a name code defines (409), an egress or network
  (400, section 1). An old isolate checks against old code, so the save-time
  check is a courtesy; the guarantee is the use-time check, on the code of the
  isolate that sends or dials.
- **The upstream's origin is fixed by the definition.** A request goes to
  `<upstream>/<path>` and nowhere else, and redirects stay on the proxy.

## 6. Code definitions and UI definitions together

**Code wins, by name, and the row shows locked.** The app resolves a name in
code first, then in the environment's UI definitions. The page shows the code
item once, locked, with code's values. A UI item of that name is neither shown
nor served.

**A code name is taken in every environment, whatever its scope.** Code's
`environments` option decides where a code item serves; its name is reserved
for UI items everywhere. With code `replica` scoped to `market/prod`,
`market/dev` cannot have a UI `replica`. The reason is renames: if shadowing
followed the scope, a UI `replica` in `market/dev` would be hidden by renaming
dev to prod, and would come back, unseen since, when renamed back, with no code
change or deploy to clear it.

**Which URL names what.** `/use/<a>/<b>/…` names an environment when `<a>/<b>`
is one the handle was made for, and is otherwise the stable URL of route `<a>`
([credential-proxy.md](credential-proxy.md), section 4, "Which route"). A UI
name depends on the environment, so the app cannot tell from its config that
`<a>` names nothing. So a route use carries **both readings** of the URL, and
the statement picks one in its snapshot, from the handle's made-for list:

| Reading | Place | Route | Taken when |
|---|---|---|---|
| the environment's | `<a>/<b>` | `<c>`, the rest after it | `<a>/<b>` is an environment the handle was made for |
| the stable URL | the handle's one environment | `<a>`, the rest from `<b>` | otherwise (a handle of several environments: 409) |

The vault keys its map by token and by place and route, never by path, so
`/use/openai/companies/42/x.pdf` and `/use/openai/models` from one `market/dev`
handle are both map hits after the first, and share one kept entry. On a hit
the statement answers `moved` if the rule would now pick the other reading,
and it picks once more under the fence: `/use/market/dev/openai` with dev
renamed to stage in between must take the stable route `market`. Only readings
whose name can be a route's are offered (`report.csv` in
`/use/s3/bucket/report.csv` is none).

**URLs of one or two segments.** When `<a>` is a code credential's name, the
URL alone decides, as before, for handles and workloads alike: code wins.
Otherwise `/use/<a>` is always the stable reading of route `<a>`.
`/use/<a>/<b>` is the place (the plan for `GET`, compute for `POST`) only when
`<a>/<b>` is an environment the handle or session was made for; otherwise it
is route `<a>` at path `/<b>`. So `GET /use/openai/models` from a `market/dev`
handle is route `openai` at `/models`, and `GET /use/market/dev` is the plan.
The route use answers that in its one call (`useRouteOrPlace`): for a place
reading it reads no route and uses nothing, and the plan or compute then makes
its own calls. A place answer is kept by handle and path for R, no longer than
the handle lives. `GET /use`, which answers with no credential, lists code
names only, so it reveals nothing of an environment's own.

**The plan shapes UI items as it shapes code's.** The plan (`GET /use/<p>/<e>`,
what `coffre run` builds the app's environment from) gives the handle in place
of every key a route covers, keeps the real value from the app, and lists the
routes, signers and tunnels. That needs the items' contents, not their names.
So the plan first makes one `proxyItem` call with no name, then shapes the
environment from code and those items together. Example: UI route `openai`
sending `{OPENAI_API_KEY}`, a secret its holder reads. Without the items the
key looks uncovered and the app gets the real value; with them it gets the
handle.

- The plan fails closed: a refused `proxyItem`, a `tampered` or `stale` level,
  or an item without its definition is 503 and no environment. A plan shaped
  from code alone would hand the app a forged route's values.
- A UI item whose name code holds is left out. A personal config shapes
  nothing (the vault answers `personal` with no items).
- A generated environment's plan reads `market/dev@me` once the person has a
  value of their own there, and then drops the base environment's items: it
  gives their own `OPENAI_API_KEY`, never route `openai`'s URL, which would
  send the base key.
- Two routes, code's or the UI's, that read one key with different
  placeholders are 409 `conflict`: the app gets one value per key.
- A workload's plan (`workloadPlan`) does the same from its one `proxyItem`
  call.

**Scoping code items.** `environments: ['market/prod']` on any code item, by
full path, since the config is instance-wide and a bare `prod` would match
every project's prod. With none, a code item applies everywhere. The path is
matched against the environment's current name.

**Names unique across kinds** (decision 3). Routes and tunnels share
`/use/<name>`, signers and verifiers are named in the same URL space, and one
list shows all four. A UI name follows `CREDENTIAL_NAME` (a lowercase letter,
then up to 31 lowercase letters, digits or dashes), checked by the vault at
save, and may not equal any other UI item's in the environment, nor any code
item's of any kind. Code keeps its per-kind rule: a deployment may have a
credential and a signer both named `dfns`.

**Reserved names.** Without them, a UI `maps` hidden by code's `maps` comes
back to life the day code drops `maps`, with an upstream nobody has looked at
since. Clearing once at a deploy is not enough, because two app versions serve
during a deploy. Example: deployment B adds code `maps` and clears the UI
`maps`; an isolate of the old deployment A, whose code has no `maps`, still
serves, and an Owner saves a new UI `maps` through it. B hides it; months later
deployment C drops `maps`, and the hidden item serves again. So the log keeps
the names code reserved, and they outlive the deployment that reserved them:

- **The gate** (`proxy-gate.ts`). Each isolate, before its first proxy request,
  makes one vault call with its code's names (`reserveProxy`), at the plugin's
  two entries (`routes.fetch`, every `/use` request; `routes.socket`, tunnels)
  and before the Proxy tab's APIs read or write. Nothing is exempt. Concurrent
  first requests share one attempt (`packages/server/src/asked-once.ts`: take
  over after 3 s, 503 `starting` after 6 s). A failed gate is 503 `unavailable`
  (`proxy_gate`) and keeps nothing, so the next request asks again. A
  deployment that never served a proxy request reserved nothing, but nothing
  served or showed its definition either, so there is nothing to revive.
- **Most gate calls only read** the reserved set, checked against its newest
  change's seal. Only a name missing from it takes the log's head, makes a
  `proxy.code` change (CAS on the set's seal) and, in the same transaction,
  deletes every UI item of that name, each whole in its entry. Taking the head
  on every call queued uses up to 147 s in a bench at 1,000 requests a second.
  Two racing writers are safe: the loser's CAS fails, and it reads the set
  again and writes nothing.
- **A save checks the reservation** (`SaveChecksReserved`), whichever isolate's
  page sent it.
- **No deploy drops a reservation.** An instance Owner may release one
  (`proxy.release`, audited); it frees the name in every project, which is why
  a project Owner cannot. The app refuses a release of a name its own code
  defines (409 `defined_in_code`); nothing can check that no older deployment
  still serving defines it, so the dialog says so. Releasing during a deploy and
  then saving the name is the one revival left (`RoutingRelease`).

## 7. Matching, injection and redaction

### The path

The request's path below the route goes through the proxy's refusals first,
and only then is matched. [credential-proxy.md](credential-proxy.md), section
3, "Several rules, an allow list, and environments", holds the exact rules;
this section is their reasons.

1. **The climb check** (`aim`'s `climbs` in `credential-proxy.ts`). Each raw
   segment is decoded as often as decoding changes it (up to 8 times), because
   a server behind another decodes twice. Every form along the way is refused
   if it holds a slash, a backslash, a control byte (a server may cut a segment
   at `..%00`) or an overlong UTF-8 lead byte (`%c0%ae`, a dot to an old
   decoder), or if it is a dot segment: `.` or `..`, with trailing blanks
   (`..%20`) and with its `;` parameters dropped, as Tomcat and Spring drop
   them (`..;x`).
2. A `*` takes no empty segment (`//`), nor one a server may read as none: `;`
   parameters alone (`;x`), spaces or dots alone (which Windows drops from a
   segment's end). A glob counts segments, so `/companies/;x/documents` must
   not pass `/companies/*/documents` when the upstream reads it as
   `/companies/documents`. Past a prefix or a `**` such a segment is harmless
   and taken: S3 keys hold `//` (`/bucket/a//b`).
3. Each segment is percent-decoded once, to bytes, and matched against the
   `allow` list. Bytes, not text: no case folding, no Unicode normalization.
   `Café` precomposed and decomposed are two segments, as they are to the
   upstream.
4. The path goes on as the app encoded it, byte for byte.

| Request | Matched as | Result |
|---|---|---|
| `/companies/42/documents/a%20b.pdf` | `companies`, `42`, `documents`, `a b.pdf` | matched |
| `/companies/42/docu%6Dents` | `companies`, `42`, `documents` | matched as `documents`, not missed |
| `/kyc/%2e%2e/admin` | `admin` | 403 under a `/kyc` list: URL parsing resolves `%2e%2e` before the proxy sees the path |
| `/kyc/..%2fadmin` | | 400: a slash once decoded |
| `/kyc/%25252e%25252e/admin` | | 400: a dot segment three decodings down |
| `/kyc/..%20/admin`, `/kyc/..%00/admin` | | 400: a dot segment with a blank; a control byte |
| `/kyc/..;/admin` | | 400: a dot segment with parameters |
| `/companies//documents`, `/companies/;x/documents` under `/companies/*/documents` | | 403: a `*` takes neither |
| `/bucket/a//b` under `/bucket` or `/bucket/**` | `bucket`, `a`, ``, `b` | matched |

Only `allow` matches on decoded segments, since `*` must see `a b.pdf` and a
literal `documents` must not miss `docu%6Dents`. Code's legacy `paths` keep
their comparison with the encoded path, so no existing config widens.

**Patterns are decoded once, by the proxy's own parser** (`readPattern` in
`@coffre/core/proxy-match`), at save for the UI and at startup for code. It
refuses a literal some server may read as another: `%2561` (`a` to a server
that decodes twice), `a;v1` (`a` to Tomcat), `a.` (`a` to Windows). The UI
refuses a trailing slash and offers `/companies/**`.
`packages/server/test/proxy-match-properties.test.ts` runs random encodings
through the climb check and the matcher against a model of how servers behind
may read them: under an `allow` list, no path outside it reaches the upstream
under any reading.

### The allow list

A request is allowed when any entry `{ methods, path }` allows it. With no
allow list (`null`), every request is allowed; an empty one (`[]`) takes
nothing (403); an entry of any method on any path is refused, since it would
take every request whatever the others say. A plain path is a prefix by
segments (`/companies` takes `/companies/42`, never `/companiesX`), `*` is one
non-empty segment, and `**`, last only, is zero or more. No regexes and no
partial-segment globs (`doc*`): patterns read at a glance and matching is
linear, segments × entries, with no backtracking. The tab shows a code item's
list as code matches it (`ProxyCodeItem.allowAs`).

### Several inject rules

A route's `inject` is an ordered list; the rules on how they combine (one
`sigv4`, last; no `basic` beside an `authorization` rule; one rule per name)
are in [credential-proxy.md](credential-proxy.md), section 3, and the UI's
save checks the same ones, with the proxy's own parsers.

**SigV4 signs what the earlier rules set.** It runs last, over the request as
the earlier rules left it, and adds their headers to `SignedHeaders`, so an
earlier header cannot be swapped on the way.

**Where the handle is.** `x-coffre-handle`, which the SDK's
`credential(name).fetch()` sends, is accepted on its own for the header, query
and Basic slots. A form or JSON rule carrying a non-plain key is the exception:
its field must hold the handle too, as the plan gave it there. With
`inject: form('secret', '{KEY}')`, `x-coffre-handle` and `secret=mine` is a 400.
A handle taken from a slot must sit in one the decided definition names, else
400 before anything is sent. A handle left anywhere after filling is refused,
never sent.

### Redaction

Every value any rule of the route read, and every string a rule assembled
(Basic's base64, a filled template such as `Bearer sk-…`), goes into the
redaction set, in every encoding the closed list names
([credential-proxy.md](credential-proxy.md), section 4, step 6). A plain value
stays out of the set.

## 8. Who may edit, and what a definition may route

### The permission

`proxy.edit` is a place permission like `secret.write`, held on an environment
or a project (`PERMISSIONS` in `@coffre/core/access`).

- **The Owner role holds it**, in both columns, since it holds every
  permission. No other built-in role does, so by default only project and
  instance Owners edit.
- **The role editor** shows it as a row. One rule goes with it: *a role that
  edits the proxy reads values too*, in each column. An editor who can read
  nothing could only route plain values, and the rule keeps every editor's
  routing within their reads.
- **Reading the tab** needs only access to the environment. Upstreams, rules
  and key names are not secret. `GET …/proxy` is a vault call, not the app's
  own read: the app holds no key, so it could not tell a forged item, and an
  Owner who edited or copied one would seal a forgery as their own. The vault
  checks the seal, the index and the newest change, and answers a display
  shape: each definition, who saved it and when, and its clearance mark, never
  the frozen holdings. A forged object shows as `tampered`, and only an Owner's
  replacing save fixes it, CAS on its newest logged change.
- A token or a handle cannot save: `PUT /api/projects/<p>/<e>/proxy` takes a
  person, on a browser session or `coffre login`.

The vault decides a save on its own sealed rows (the editor's principal, the
roles, the environment, protected or not). The app's check is for the page.

### Frozen holdings, decided at each use

A definition is, in effect, a standing read by its editor: wherever its
upstream sends what it receives, the editor could arrange to see it. So it is
treated like the credential that already is one, a service token:

- **At save**, the vault freezes the editor's holdings into each changed item,
  as columns held, the way `ScopeGrant` keeps a token's rights. It then
  resolves each changed item's keys by name in the place, inherited and
  referenced keys included, and refuses the save if the frozen holdings would
  not read one, sensitive included, as the use would. The app sends names
  only, so an old or buggy app cannot under-clear a save. A key the place does
  not have yet is accepted (a route may be saved before its key) and decided
  at each use.
- **At each use**, the vault decides the route's keys for the caller (purpose
  `use`), then again for the frozen holdings, intersected with the editor's
  current standing (decision 5), as a token's scope reading the value. Both
  must allow. One function does this for the live use and the replay
  (`routeEditorRefusal`). An editor's principal row that fails its seal, or
  is not its newest change, refuses the use `tampered` or `stale`.

| Case | Outcome |
|---|---|
| Lin (a Maintainer whose role an Owner gave `proxy.edit`) routes `{STRIPE_KEY}`, a secret she reads | allowed, at save and at use |
| Lin routes `{STRIPE_SECRET_KEY}`, sensitive | refused at save: "an Owner of market may route sensitive keys" |
| Lin's route saved while `STRIPE_KEY` was secret; an Owner marks it sensitive later | each use 403 `route_not_cleared`, naming the route and the key; the page marks the item: "an Owner of market must save it again" |
| Lin, in fork `market/dev-eu`, routes an inherited key she cannot read in `market/dev` | refused: an inherited value takes a read on the parent |
| Lin routes `{API_KEY}`, a reference into `billing/prod` | decided where it lives: her read of `market/dev` covers it; sensitive, it takes an Owner of `market` |
| Ada, an Owner of market, routes `{STRIPE_SECRET_KEY}` | allowed, and the entry says `routes sensitive` |
| Lin saved `openai`; she is later demoted to Viewer, or leaves | each use 403 `route_not_cleared`, until someone who reads its keys saves it again |

A refusal of the caller's own standing stays the read's 404 `not_available`;
`route_not_cleared` is a 403 because the caller may read the key, so it hides
nothing.

So routing is **preventive for everyone but an Owner of the project**. For
those Owners it grants nothing new: they may already loosen a sensitive value
to a secret and read it, audited.

**The clearance mark** is the vault's too: `Vault.proxy()` decides each item's
keys as the use would (`notCleared`) and answers, per item, the first key that
does not clear, where, and why, as a code the tab words (`NotClearedCode`:
`unread`, `unread_at_save`, `not_owner_at_save`, `not_owner`). A fork's read
also marks what it inherits (`inheritedNotCleared`): dev's `openai`, saved by
someone who reads dev's `OPENAI_API_KEY`, does not route in dev-eu once dev-eu
sets its own value they do not read. A save's answer leaves the mark out: its
reads would hold the change's locks longer.

**The offboarding preview** reads `Vault.proxySavedBy({ member })`: the items
the member saved, each object held to the log, so a forged row lists nothing.
The Remove dialog names the routes a removal stops; for a demotion the page
says it stops those whose keys it takes away.

### Copying from another environment

"Copy from environment" fills the target's pending edits with every field of
the source items, upstream and egress included. Saving them is an ordinary
save in the target, by the person saving, with their holdings frozen there.

That copy can send the target's keys to the source's servers. Copy `schuman`
from `market/dev` to `market/prod`, where dev's route says
`upstream: https://sandbox.schuman.example`, and save it unchanged: prod's
`{SCHUMAN_API_KEY}` now goes to the sandbox host. Nothing fails: the
certificate is valid for its own name. Only someone with `proxy.edit` in prod
can cause it, and the save is audited, so this is a review problem, not an
access problem. The review step names, per copied item, where it will send
which key: "`schuman` will send market/prod's SCHUMAN_API_KEY to
sandbox.schuman.example (copied from market/dev)" (decision 2).

## 9. Threats, in one table

| Who | Tries | Outcome |
|---|---|---|
| A database writer, no key | edits an upstream, adds a route, or puts back an old row | refused (`tampered`, `stale`); fails closed |
| A database writer | forges an item beside its genuine index entry, lets the app read them, puts the genuine row back | nothing sent by the forged body: the isolate's copy comes only from vault answers |
| A database writer | deletes the row | `stale`: the probe finds a newest change and no row |
| A database writer | re-points a fork's parent | `tampered`: every level of the chain is checked |
| A Developer with `proxy.edit` | routes a value they cannot read, or one made sensitive later | refused at use: the frozen holdings decide |
| An Owner of the project | routes a sensitive key to a host they control | allowed and audited: the same power as loosening it (decision 1) |
| An editor who later leaves | keeps a route to their host, and the value rotates | stops at the next use once they no longer hold the key: `route_not_cleared` |
| An Owner | copies a dev route into prod and saves it unchanged | prod's key goes to dev's upstream, audited; the review names that destination |
| An Owner, racing an app | edits mid-traffic | old values go to the old host for at most W, never to the new host undecided |
| An Owner | edits a route between the rounds of a use of its two keys | `moved`, and the use starts over on one version |
| Someone with a stale page | saves over a newer change | 409 `proxy_changed` |
| An Owner | points an upstream or a tunnel's host at `169.254.169.254` or `localhost` | refused at save |
| An Owner | points one at a name resolving to `10.0.1.5` | refused at connect on Node, HTTP and TCP alike; on Workers, Cloudflare's network does not route there |
| An Owner, during a deploy | saves a name the new code reserved, through an old isolate | refused by the vault: reserved |
| A code change | drops a name UI also had | the UI item was deleted, audited, when the first isolate of that code reserved the name |
| A project Owner | releases a reserved name | refused: a release is instance-wide, so it takes an instance Owner |
| Anyone with `environment.manage` | renames an environment into or out of a code item's scope | nothing a UI item may be called changes: code names are taken everywhere |
| A compromised app (the `coffre` Worker) | anything | out of scope: it holds the values it opens. Every decision is logged, so it is loud, not impossible |

## 10. Decisions

Each stands; each could be revisited.

1. **Owners of the project may route sensitive keys**, audited. They may
   already loosen such a value to a secret and read it, so a second Owner's
   approval would add nothing.
2. **A copy keeps every field**, and the review step names, per copied item,
   which of the target's keys it will send where. Saving still saves.
3. **UI names are unique across the four kinds and against every code name**;
   code keeps its per-kind rule.
4. **The window after an edit is accepted**, as for revocation: old values may
   reach the old upstream for up to R, and the save's confirmation says so.
5. **An editor who leaves or is demoted stops routing**: holdings frozen at
   save are intersected with the editor's current ones, as for tokens (5(b) in
   the model's comments). Uses answer `route_not_cleared` until someone who
   holds the keys saves again, and the offboarding preview names the routes
   affected.
6. **Forks inherit definitions** by name through the chain of parents, as
   values do; a fork's own item overrides, and removing it reverts to the
   parent's.
7. **Personal configs are refused**: a UI route at `<env>@me` answers 409
   `route_not_personal`, naming the base environment. A UI route's use is
   cleared by its editor's frozen holdings, and no editor can read another
   person's owner-only values, so every such use would fail anyway; a clear
   refusal beats a route that can never work.
8. **One version at a time.** The app and the vault are never served on two
   releases at once: every call carries the release, a mismatch is 503
   `deploying` before the vault reads anything, and a deploy or rollback moves
   both. Serving an app ahead of or behind its vault kept producing gaps;
   holding requests for the seconds of a deploy is simpler than any fix. A
   finding that arises only across two releases is answered by this decision.

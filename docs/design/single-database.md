# One database

A proposal to run coffre on a single Postgres or MySQL database, the vault's
tables included, with one audit log written by both the app and the vault.
It says what the second store buys today, how much of that one database can
keep, what it costs to get there, and what needs deciding. Written on
2026-10-01 against `ui-fixes` (#18), and revised the same day for Erwin's
proposal of one log instead of two. Nothing here is built yet, apart from
step 0 (#22). It folds in the findings of that day's two security reviews
that bear on the design: F1, F2, F5 and F8 from the review of keys and
integrity, and A01, A07 and A08 from the review of the app. The section
"What the security reviews change" says where each one lands.

## In short

- **The vault stays a separate Worker, or process on Node, with its own
  database login.** It keeps the KEK and the signing key out of the app's
  large bundle. It loses its Durable Object and keeps its members and
  grants in the shared database, in `vault_*` tables the app's login cannot
  touch.
- **One audit log, two authors.** Every entry, the app's and the vault's,
  goes into `audit_log`, chained by a plain SHA-256 that anyone can
  recompute, and authenticated by an HMAC under its author's key. An app
  holding its key cannot rewrite an entry once a vault entry follows it,
  and the vault cannot rewrite one once an app entry follows it. Vault
  entries come with every unwrap, so the two anchor each other within
  seconds rather than at five-minute checkpoints. The checkpoint protocol
  that review F1 broke goes away; a checkpoint becomes a signed vault entry.
- **Each event is recorded once, by whoever decided it.** A read is the
  vault's unwrap entry, written before the key leaves, with the app's
  request context in it. An access change is the vault's entry, in the
  transaction that makes the change, which settles most of review A01. Only
  a removal's revocation of sessions still spans two transactions, ordered
  so a failure leaves less access.
- **A locked row replaces the Durable Object's single thread.** Every vault
  decision and every app append takes the log's head row,
  `audit_chain_head`, with `SELECT … FOR UPDATE`. One lock for both halves
  the ceiling: about 50 appends a second at 5 ms per round trip, against
  110 with two heads. That is plenty for coffre. The app must never hold
  that lock while it waits for the vault, or both stall with no deadlock
  reported.
- **One data key per secret version, wrapped directly by the KEK, as
  today.** Intermediate keys would save KMS calls that cost about a dollar a
  month, and would cost CloudTrail its record of which secret was read.
- **The database enforces what it can, and keys catch the rest.** On
  Postgres, logins keep the app out of the vault's tables, row-level
  security lets each login write only its own author's entries, and
  triggers keep the log append-only. On every engine, a MAC over each
  member's access means a forged grant is refused at once.
- **Rollback is caught by witnesses.** The vault refuses a member's rows
  when the log holds a later change to them. Clients remember the newest
  entry they saw and check the log still holds it, and whoever offboards
  someone gets that entry in the response. Two things stay invisible to
  everyone who has not seen past them: a rewind of the whole database, and
  the newest entries cut off with the head put back. The first is what
  dropping the second store costs; the second is true today.
- **Host on PlanetScale Postgres.** It has SQL roles, table-level GRANTs,
  row-level security, triggers and two days of point-in-time recovery, from
  $5 a month. PlanetScale MySQL has none of these, so coffre's guarantees
  there rest on its keys alone.

## What the second store buys today

| | App, Worker `coffre` | Vault, Worker `coffre-vault` |
|---|---|---|
| Keys it holds | `auditChainKey` | the KEK, `signingKey` |
| What it stores | projects, ciphertext and wrapped data keys, the directory, sessions, syncs, the audit log | members, grants, its own log, checkpoints |
| Where | Postgres through Hyperdrive; on Node, Postgres, MySQL or SQLite | a Durable Object's SQLite; on Node, a SQLite file |

Say Mallory gets the database password, or the account that hosts the
database. Today:

1. She reads ciphertext and wrapped keys, and opens none of them. The KEK
   is a Worker secret.
2. She cannot give herself access. Members and grants live in the Durable
   Object, which only the vault's code can write.
3. She cannot quietly edit the audit log. Its chain is keyed with
   `auditChainKey`, and the vault signs its head every five minutes.

One database keeps the first and the third. It gives up the second: the
vault's rows sit where Mallory's login reaches. The rest of this document is
about getting as much of the second back as possible.

## The proposal

```
  browser, CLI
       │
       ▼
  app Worker  ──────── service binding ────────▶  vault Worker
  login  coffre_runtime                           login  coffre_vault_runtime
  holds  auditChainKey                            holds  KEK, signingKey
       │                                                │
       ▼                                                ▼
  ┌─────────────────────────────── one database ───────────────────────────────┐
  │ projects, environments, secrets,  │  audit_log, audit_chain_head │ vault_   │
  │ secret_versions, principals,      │  written by both, each entry │ members, │
  │ credentials, identities, syncs, … │  under its author's MAC      │ vault_   │
  │ the app's alone                   │                              │ grants   │
  └────────────────────────────────────────────────────────────────────────────┘
```

The `Vault` interface and its RPC and socket transports stay. What changes:
where the vault keeps its rows, how it serialises its decisions, what it
checks on each row before deciding on it, and that both components write
one log.

### Mallory, after

With PlanetScale Postgres and the logins of question 4:

| Mallory has | She can | She cannot | What catches her |
|---|---|---|---|
| The app's login, `coffre_runtime` | read ciphertext, the directory and the log; insert a session row and act as an existing member | open a value without the vault; touch `vault_members` or `vault_grants`; write a vault entry; change or delete any entry | every value she opens is a vault entry, under the member she plays, and counts toward that member's bulk limit. This gap is today's, unchanged |
| The owner login, PlanetScale's default role | anything in the database, triggers and row-level security included | open a value: no KEK. Forge a grant or an entry: no key | a grant forged or edited: refused at its next use. Old rows put back: refused, since the log holds the later change. An entry changed: its MAC, or the next entry's. The newest entries cut off with the head put back, or the whole database rewound: only a witness that saw past that point |
| `auditChainKey` and the owner login | rewrite app entries newer than the last vault entry | rewrite anything a vault entry follows | the vault's next entry anchors the rewrite as it stands; the window is seconds when people use coffre, at most five minutes otherwise |
| The PlanetScale account | the owner's powers, and restore a backup to a new branch | make coffre use that branch without the Cloudflare account | as for the owner |
| The Cloudflare account | deploy code that reads the KEK | | nothing coffre can do, as today |

### What the security reviews change

Two reviews of `3dfa720` on 2026-10-01, one of keys and integrity (F) and
one of the app (A), found problems this design has to answer.

| Finding | What it showed | Where the design answers it |
|---|---|---|
| F1, high | A checkpoint takes the caller's word that it extends the last one, and verification checks only the newest | Question 6: with one log there is no claim to check. A vault entry extends whatever head it finds, and its MAC pins everything before it. Plan step 7 |
| F2, high | A second Durable Object loads the same KEK with an empty log and a fresh bulk counter | Question 2: no Durable Object, every instance decides under one database lock, and nothing in an instance's memory allows anything. Plan step 5. The fix in flight, refusing any object but the canonical one, still matters until then |
| F3, medium | A refused checkpoint leaves `/readyz` green | Question 6: readiness needs a recent vault entry. Plan step 7 |
| F5, medium | A KMS failure halfway through a batch leaves no vault record of the keys KMS did open | Question 2: the intent is logged before KMS, every call settles, and each key's outcome is logged. Plan step 5 |
| F8, low | The database owner can cut the newest entries off the log and put its head back | Question 7: bounded by the vault's memory and by witnesses; `architecture.md` stops overstating the chain. Plan step 11 |
| A01, high | The vault commits an access change before the app's audit append; if that fails, the change stays live with no app entry, and a half-done removal revives old sessions | Question 6: the vault's entry is the record, in the transaction that makes the change. A removal revokes sessions first. Plan steps 1 and 7 |
| A07, A08, medium, being fixed on #19 | An account binding survives a change of its provider's issuer; linking an account can race offboarding and survive re-admission | Their fixes change the schema this design moves: `identities` bound to their issuer, and a membership generation the vault keeps per member and bumps on removal. Question 5 carries both. Plan steps 2 to 6, rebased on #19 |
| Closing note | The shared database needs separate logins, protected grant and log tables, and bulk and authorisation accounting that holds across instances | Questions 1, 2 and 4. Where logins do not exist, on PlanetScale MySQL and SQLite, MACs stand in, and question 4 says what that leaves open |

## The decisions

### 1. The vault stays a separate component

- **(a) Separate.** Its own Worker, or process on Node. It holds the KEK and
  the signing key and makes every decision, as today. It gets its own
  database login and its own Hyperdrive config, and no Durable Object.
- **(b) Merged**, as Infisical does it. The vault becomes a module inside
  the app: one Worker, keys in its environment.

| | (a) Separate | (b) Merged |
|---|---|---|
| Code that can read `env.KEK` | the vault's: `@coffre/core`, `@coffre/vault`, Drizzle, `pg` | every module in the app Worker: the server, the sync providers, TanStack Start and React, and the UI's three libraries, which alone bring about 75 packages. Any module can `import { env } from 'cloudflare:workers'` and read a secret from anywhere |
| What a bug or a malicious dependency in the app gets | values, by asking the vault as some member: each one logged under the vault's key, capped by the bulk limit, refused for removed members, and in CloudTrail with KMS. It ends when the app is fixed | the KEK. With any copy of the database, past or future, that opens every value offline, and no log ever hears of it. It ends only when every value is re-encrypted under a new KEK |
| Who can write the vault's rows | its own login: on Postgres the app's login cannot touch them | one login for everything; MACs only |
| An access change and its record | one transaction, the vault's (question 6) | one transaction |
| Cost of a vault call | a service binding: per Cloudflare, "zero overhead", both Workers on the same thread by default | none |
| What `coffre init --workers` writes | `app/` and `vault/` as today, minus the Durable Object, plus a Hyperdrive binding | one Worker |

**Recommendation: (a).** The row that decides it is the second: with (a), a
compromised app gets reads, each logged where it cannot erase it. With (b),
it gets the KEK, and every read after that is silent. Erwin's deployment
uses a local KEK, which is the case where (b) does worst.

What (b) used to gain was one transaction for an access change and its
record, and review A01 shows that it matters. With one log, (a) gets it
too: the vault writes the record itself (question 6).

On latency the two are equal. Each decision makes about five round trips to
the database. With both Workers placed near the database, that is a few
milliseconds each. Today a decision is one trip to the Durable Object, which
sits in one Cloudflare location.

### 2. Serialising decisions without a Durable Object

The Durable Object runs one call at a time, and each decision is a
synchronous SQLite transaction. Once several vault isolates or processes
share one database, the serialising has to move into the database. Every
decision becomes one transaction whose first statement locks the log's
head, the same row every app append locks:

```
unwrap(user:ada@acme.example, market/prod, 50 keys)

1. pre-check   read Ada's member row, grants and recent unwraps         no lock, one round trip
               refused? skip to 4
2. intent      with KMS only: BEGIN; lock audit_chain_head; append one
               unwrap.intent entry naming the request and its 50 keys; COMMIT
3. keys        50 KMS Decrypts, or 50 local unwraps;                    no transaction open
               every call settles before step 4
4. decide      BEGIN
               SELECT next_seq, head_hash FROM audit_chain_head
                 WHERE only_row FOR UPDATE                              every append queues here
               read Ada's rows again; check the MAC, freshness, bulk limit
               INSERT 50 entries, each with its outcome; UPDATE the head
               COMMIT                                                   about five round trips
```

Advisory locks are out: Hyperdrive does not support them on Postgres, and
MySQL's `GET_LOCK` pins the session to a reserved connection under Vitess.

What this keeps:

- **A refused call never reaches KMS.** The pre-check comes first, as
  `#mayAll` does today.
- **A decision sees every change committed before it.** In the spike
  (appendix A), a transaction that waited on the head row and then read the
  grants saw a grant committed while it waited. That held on Postgres at
  READ COMMITTED, and on MySQL at both READ COMMITTED and REPEATABLE READ.
- **The bulk limit is exact.** Ada's recent unwraps are counted under the
  lock.
- **The log stays one chain.** Only the lock holder appends.
- **Every instance shares one log and one set of limits.** Review F2 showed
  a second Durable Object loading the same KEK with an empty log and a
  fresh bulk counter. Today's `#serial` queue orders the calls of one
  isolate, which only the Durable Object made the only one. Here every
  isolate and process reads grants, members, bulk counts and the head under
  the database's lock, and `#serial` goes. What an instance keeps in memory
  (the last head it saw, how far it verified the log) can only add a
  refusal, never allow anything. A second vault on a second database with
  the same KEK remains possible, for whoever can deploy the vault, who
  holds the KEK anyway.

Three rules make this hold on every engine:

1. **The lock is the transaction's first statement, and nothing reads
   before it.** On MySQL at REPEATABLE READ, a plain read before the lock
   fixes the snapshot, and the reads after it miss what committed during
   the wait. The spike saw 0 grants instead of 1. REPEATABLE READ is
   PlanetScale MySQL's default. It is also what a Hyperdrive connection
   falls back to, since Hyperdrive resets each connection between
   transactions. So the `SET SESSION` that `connect.ts` sends on Node
   cannot carry over to Workers.
2. **Postgres decisions run at READ COMMITTED, its default.** At REPEATABLE
   READ, a transaction whose snapshot predates a concurrent commit fails its
   `FOR UPDATE` with `40001 could not serialize access`.
3. **The app never holds the head while it waits for the vault.** Its
   `audited` transactions call the vault first and append last, as
   `appendAudit` does today, and that order becomes a rule with a test.
   Broken, it stalls: the app's transaction holds the head and waits for the
   vault's answer, and the vault waits for the head. Postgres sees one
   waiter, not a cycle, so it reports no deadlock; the spike's vault
   decision simply timed out. Every vault decision sets a `lock_timeout` of
   a few seconds, so a break shows as an error, not a hang.

KMS stays outside the transaction. A lock held across 50 Decrypts, with a
5-second timeout and three attempts each, would stall every other append
behind KMS. It would also hold a pooled connection the whole time, and
Hyperdrive has about 20 per config on the Free plan and 100 on Paid.
PlanetScale MySQL kills any transaction after 20 seconds.

The price is a race the Durable Object prevented. Say Bob removes Ada
between steps 1 and 4. KMS has already opened her 50 keys. Step 4 sees the
removal, refuses, logs 50 refusals and zeroes the keys. Ada gets nothing,
but CloudTrail shows 50 Decrypts the vault then refused. The refusal entries
record that the keys were opened (`detail.opened: true`), so a check of
CloudTrail against the log can pair them. I think that is acceptable.
Avoiding it means holding the lock across KMS.

The opposite race needs a fix. Say the pre-check refuses, so no keys are
opened, and Ada is granted access before step 4. Today's `unwrap` would then
answer `ok` with no keys, and the app would fail on the missing key. The
Durable Object made this impossible. Without it, a decision must refuse
whenever its pre-check did.

A KMS outage halfway through a batch must leave a record too. Review F5
showed today's `unwrap` starting every Decrypt with `Promise.all`: when
one fails, the call throws before anything is logged, though other Decrypts
succeeded and are in CloudTrail. Three changes close it:

- **Record the intent first** (step 2), in its own short transaction, when
  the KEK is in KMS. If the vault dies after calling KMS and before step 4,
  the log still says which keys it was about to open, and verification
  reports an intent with no outcome after a minute. CloudTrail's Decrypts
  then pair with that intent.
- **Let every call settle** before deciding (`Promise.allSettled`), so no
  KMS call from a failed batch is still running when the next decision
  starts.
- **Log each key's outcome** in step 4: given, refused, opened but withheld,
  or KMS unavailable. The call still fails as an outage, and returns no key
  at all, but only after the log says which keys KMS opened.

A local KEK skips step 2. A process that dies after unwrapping in memory
leaves nothing outside to reconcile, so Erwin's deployment pays nothing for
this. With KMS, the intent costs a second short transaction, about three
round trips, on every call. `wrap` and `rewrap` follow the same steps,
since an Encrypt is in CloudTrail too.

**Throughput.** One head for both authors means one queue. The spike
simulated 5 ms per round trip, with each append holding the lock for about
four of them:

| Writers at once | One head, both authors | Two heads, one per author |
|---|---|---|
| 1 | 40 appends a second | |
| 8 | 52 a second, waiting 133 ms at the median | 108 a second, waiting 50 ms |
| 32 | 59 a second, waiting 587 ms at the median | 113 a second, waiting 274 ms |

So one log halves the ceiling, to about 50 appends a second. Each event is
now appended once rather than twice, which gives some of that back: a
`coffre run` of 50 keys is one append, where today it is one in each log.
For erwinkn.com, or a team of fifty, that ceiling is two orders of magnitude
away. Merging the insert and the head update into one statement, which
Postgres allows, takes a round trip off every append if it is ever needed.

`access(principal)`, which the app asks once per request, takes no lock.
It is one read of the member, the grants and the freshness check, in one
round trip.

On SQLite a transaction begins `IMMEDIATE` and holds the database's write
lock, so the head lock does nothing there, as `forUpdate` in `dialect.ts`
already arranges.

### 3. The key hierarchy

Today each secret version has its own 32-byte data key. AES-256-GCM binds
the value to the project, environment and secret ids. The vault wraps the
data key with the KEK, either locally or with one KMS Encrypt whose
encryption context carries the same ids. So with AWS KMS, each value read is
one Decrypt, and CloudTrail names the secret.

The alternative is Infisical's layering. Each environment gets a key, which
the KEK wraps, and which the vault caches in memory for a few minutes. The
environment key wraps the data keys locally.

The numbers below assume KMS at $0.03 per 10,000 requests (the key itself
is $1 a month either way), 20 to 40 ms per Decrypt from Cloudflare, and the
vault's 8 calls in flight at once.

| | A data key per version, wrapped by the KEK (today) | An environment key, cached 5 minutes |
|---|---|---|
| `coffre run` of 60 secrets | 60 Decrypts in 8 waves, about 0.2 to 0.3 s | none when cached, one when not |
| Workers Free, 50 subrequests per invocation | an environment of more than about 50 secrets cannot be read at once | no limit in practice |
| erwinkn.com, local KEK | no KMS | no KMS |
| erwinkn.com with KMS, about 300 reads a day | 9,000 calls a month, $0.03 | about none |
| A 50-person team, 200 CI runs a day of 60 secrets | 360,000 calls a month, $1.08 | a few hundred calls |
| What CloudTrail shows | each secret, at each read | the environment, once per cache miss |
| What the vault's memory holds | one request's data keys, zeroed after | each cached environment key, which opens every version in that environment, past and future |
| Moving from a local KEK to KMS | one Encrypt per version: 10,000 versions in under a minute, $0.03 | one per environment |
| Recovering from a leaked KEK | rewrap every data key, locally, in seconds | rewrap the environment keys, then replace them, which means rewrapping every data key anyway |

**Recommendation: keep today's hierarchy.** At coffre's scale KMS calls cost
cents, or a dollar a month for a busy team. The per-secret CloudTrail record
is why coffre supports KMS at all: Infisical sends no encryption context, so
its CloudTrail cannot tell one secret from another. Cheap rotation is real
for routine rotation, and moot after a leak. If the Free plan's limit or KMS
latency ever bites, an environment key fits in later as one more
`KekProvider`. Each version
records which provider wrapped it, so old rows keep opening and nothing
needs migrating.

### 4. Integrity on each engine

Six guards, outermost first. The first three come from the database and
depend on the engine. The other three come from keys and hold everywhere.

1. **Logins.** The app's login cannot touch `vault_members` or
   `vault_grants`. The vault's login touches nothing of the app's but the
   log and its head. Both may read the whole log, insert into it and move
   its head; neither may change or delete an entry. In the spike, every
   forbidden statement failed with `42501` on Postgres and
   `ER_TABLEACCESS_DENIED_ERROR` on MySQL.
2. **Row-level security** on `audit_log` lets each login insert only its
   own author's entries: `WITH CHECK (author = 'app')` for one,
   `'vault'` for the other. In the spike, each login's attempt to write the
   other's entry failed with `42501 new row violates row-level security
   policy`. The table's owner bypasses it, as owners do.
3. **Triggers** refuse UPDATE, DELETE and TRUNCATE on `audit_log`, for every
   login, the owner's too. They stop bugs and a careless owner, not a
   determined one. On Postgres the table's owner can
   `ALTER TABLE … DISABLE TRIGGER`, and on MySQL `TRUNCATE` skips delete
   triggers. The spike did both.
4. **A MAC over each member's access.** Each `vault_members` row carries
   `mac = HMAC(rowKey, [principal, status, owner, since, by, generation,
   access_seq, that member's grants, sorted])`, where `rowKey` is
   `HKDF(signingKey, "coffre.vault.rows")`, derived the way the log's key is
   today. The vault checks it on every read it decides on. That includes
   `access()`, since the app's own permission checks come from it. A grant
   inserted, edited or deleted under a member changes the set, so the MAC
   fails. The vault then refuses that member with a new code, `tampered`,
   and logs it. A grant under someone with no member row is already ignored
   (`not_a_member`). One MAC per member, rather than one per row, catches
   deleted grants too, and costs a decision one check.
5. **One chain, a MAC per entry.** Each entry's hash is a plain SHA-256 over
   the previous hash and the entry, and its MAC an HMAC of that hash under
   its author's key: `auditChainKey` for the app, the vault's log key for
   the vault. Question 6 says what that buys. Every append also checks that
   the head names the log's last entry, so the newest entries deleted
   without the head fail the next append.
6. **Checkpoints** become vault entries signed every five minutes, and
   witnesses remember what they saw (questions 6 and 7).

What each engine allows. Sources are in appendix B.

| | PlanetScale Postgres | Postgres, self-hosted | MySQL, self-hosted | PlanetScale MySQL | SQLite |
|---|---|---|---|---|---|
| Logins with table-level GRANTs | yes, `CREATE ROLE` in SQL | yes | yes, `CREATE USER` | no: four fixed roles per password, each database-wide | no logins |
| Each login writes only its author | yes, row-level security | yes | a trigger on `CURRENT_USER()`, in the optional script | no | no |
| Append-only triggers | yes | yes | yes, except against `TRUNCATE` | no: "We do not support any form of stored routines" | yes |
| `SELECT … FOR UPDATE` | yes | yes | yes | yes, in transactions of at most 20 s | not needed |
| Member MACs, entry MACs, signed checkpoints, witnesses | yes | yes | yes | yes | yes |
| Point-in-time recovery | yes, 2 days by default | your own | your own | no: a backup every 12 hours | copies of the file |

Without guards 1 to 3, on PlanetScale MySQL and SQLite, the app's login can
write the vault's tables and entries in the vault's name. Guards 4 to 6
still refuse a forged grant and expose a forged or edited entry. What they
cannot stop there: deleting a member's grants, which the vault refuses as
`tampered`, so a denial of service but not access; deleting the vault's
recent unwraps to reset a bulk count, which breaks the chain and shows at
the next verification rather than at once; and rolling rows back, which is
question 7.

On PlanetScale Postgres:

- The default role is not a superuser, but it has `CREATEROLE`, `BYPASSRLS`
  and `pg_write_all_data`. Treat it as the owner: it runs migrations and
  never goes into a Worker.
- A role created in SQL logs in as `<role>.<branch id>`, for example
  `coffre_runtime.nk35mx55qq`, and does not appear in the dashboard.
- A restore resets the passwords of these roles. The restore drill sets
  them again.

On MySQL, coffre connects with one login and creates no triggers today, and
that stays the default, since PlanetScale MySQL allows neither. Self-hosted
MySQL gets an optional script with the GRANTs and triggers, and a MySQL run
of `pnpm test:schema` to check it.

### 5. The schema

The vault's tables join the shared migrations, named `vault_*` on every
engine. A Postgres schema, `vault.grants`, would make the GRANTs one line,
but MySQL has no schemas inside a database, and a second database on
PlanetScale is a second bill.

| Table | Change | App's login | Vault's login |
|---|---|---|---|
| `audit_log` | the two logs' columns in one table (below); adds `author` and `mac`; the hash no longer keyed; no foreign keys | SELECT; INSERT of `author = 'app'` | SELECT; INSERT of `author = 'vault'` |
| `audit_chain_head` | shared by both authors | SELECT, UPDATE of its columns | SELECT, UPDATE of its columns |
| `vault_members` | `generation` from #19, then adds `access_seq` and `mac` | nothing | SELECT, INSERT, UPDATE |
| `vault_grants` | adds `place_id`, the environment's id or, for a project grant, the project's; unique with `principal` | nothing | SELECT, INSERT, DELETE |
| the app's other tables | none | as today | nothing |

The vault's `log`, its `checkpoints` table and the head this document first
proposed for it, `vault_head`, all go.

An entry is the union of what the two logs record today. `seq`,
`occurred_at` from the database clock for both authors, `author`, `actor`,
`action`, `outcome`, `code`, the place's `project_id`, `environment_id` and
`secret_id`, `version`, `bundle_id`, `request_id`, `source_ip`, `subject`,
`detail` as JSON, then `prev_hash`, `hash` and `mac`. Two indexes join the
app's: `author, actor, action, occurred_at` for the bulk limit, and
`author, subject, seq` for the freshness check. The entry's encoding, which
both authors hash, lives in `@coffre/core` under a new version tag, so the
two packages cannot drift apart on it.

No foreign keys from `audit_log` to the app's tables. The vault writes a
secret's id while the app's transaction that inserts the secret is still
open, and the spike shows what a foreign key does then. Postgres refuses
the vault's entry at once, with `23503`. MySQL waits for the app's
transaction, which is waiting for the vault, until the lock times out after
50 seconds. So "nothing that was ever audited can be deleted", which the
README pins on those foreign keys today, rests on the runtime logins having
no DELETE and on the triggers. Neither ever stopped the owner, who can drop
a constraint as easily as a trigger.

`place_id` replaces the two partial unique indexes the vault's SQLite has
today. That follows the rule `architecture.md` set for the app: remodel
what one engine cannot say, rather than write it three ways.

Two changes to the app's tables are in flight on #19, from app review A07
and A08, and the move carries them as they land. Its PR will give the
exact columns. A07 binds each sign-in account to the authority that issued
it: an OIDC issuer, or a GitHub server, beside the subject. That stays in
the app's `identities` table, and the move into `@coffre/db` carries it
unchanged. A08 adds a membership generation to the vault's contract: a
counter the vault keeps per member and bumps on each removal. Linked
accounts, credentials and device approvals store the generation they were
issued under, and the app refuses one from an older generation, so nothing
issued before a removal works after a re-admission. A grant does not bump
it, so changing access signs no one out. The vault already holds it when
its tables move, so the move carries it: `vault_members.generation`, which
the member MAC covers and which the replay reproduces from the log, since
every removal is logged and each one adds one. A generation put back to an
older value then fails the MAC if edited alone, or the replay if restored
with its genuine old row. `access()` returns it, as it will once #19
lands.

`@coffre/vault` owns the `vault_*` tables and is the only code that queries
them. `@coffre/server` owns the rest, and the two share the log. Appending
an entry, which locks the head, hashes, MACs and inserts, is one function in
`@coffre/db` that both call with their own author and key. The lint rule
that confines Drizzle to `server/src/db` grows to say which package may
name which tables.

Where the code lives: a package again, `@coffre/db`, holding the three
schemas, the migrations, `dialect.ts`, `portable.ts`, `connect.ts`, the
Hyperdrive pool and that append, moved out of `packages/server/src/db`.
PR #8 folded `packages/db` into the server because the server was its one
user. The vault is a second. Queries stay with their owners: the app's in
`queries.ts`, the vault's in its `store.ts`, now written with Drizzle. That
undoes #9's "without Drizzle", for the reason the app uses it: one schema
per engine, a parity test, and queries that read the same on all three.
`coffre-server migrate` stays the one command and migrates both. The other
way, the vault importing tables from `@coffre/server`, would pull the
server's dependencies into the bundle we want small.

Migrations:

- **No deployment exists yet,** so the new tables and columns go into each
  engine's baseline, regenerated by `pnpm db:generate` like every schema
  change so far. No data moves out of a Durable Object.
- **PlanetScale Postgres** has no deploy requests. `coffre-server migrate`
  runs plain DDL as the owner, on port 5432. That is the direct port; 6432
  is PgBouncer in transaction mode. A branch restored from a backup is a
  place to rehearse.
- **PlanetScale MySQL** refuses DDL on a production branch once safe
  migrations are on (`ERROR 1105 … direct DDL is disabled`, `TRUNCATE`
  included). A migration runs on a development branch and reaches production
  through a deploy request. Drizzle's journal, `__drizzle_migrations`, is
  data, so the database needs PlanetScale's "copy migration data" setting
  naming it. The baseline's starting rows (`audit_chain_head`,
  `audit_heartbeat`) also move out of the DDL, into an insert-if-absent
  step that `migrate` runs against production.
- **Once deployments exist,** the two Workers deploy one after the other,
  after the migration. A migration must then work with the code before and
  after it: add a column, fill it, then constrain it.

### 6. One log, two authors

Today the app and the vault each keep a log, each chained under its own
key, and every five minutes the vault signs both heads so that each log
anchors the other. Review F1 showed the weak point: the vault signs a head
on the app's word that it extends the last one, and verification looks only
at the newest signature, so whoever holds `auditChainKey` can rewrite
checkpointed history and verify green again. With one database there is a
simpler shape: one log, which both write.

Each entry is hashed into a plain chain, and authenticated under its
author's key:

```
hash = SHA-256(prev_hash ‖ entry)            anyone can recompute it
mac  = HMAC(key of the entry's author, hash)  only its author can make it

41  app    secret.write  market/prod/DB_URL  by ada   mac = HMAC(auditChainKey, h41)
42  vault  wrap          market/prod/DB_URL  for ada  mac = HMAC(vaultKey, h42)
43  app    project.update market             by bob   mac = HMAC(auditChainKey, h43)
```

Say Mallory holds `auditChainKey` and the owner's login, and rewrites
entry 41. Its new hash h41' needs a new MAC, which she can make. But entry 42
links to h41: either it keeps h41 and the chain breaks there, or it takes
h41' and its own hash changes, and she cannot make the vault's MAC for that.
So each author can rewrite only its own entries since the other's last one.
Here is who can do what:

| Holds | Can rewrite | Cannot |
|---|---|---|
| the owner's login, no key | nothing; can cut the newest entries off and put the head back (F8) | change, insert or remove any entry the next one depends on |
| `auditChainKey` and the owner's login | the app's entries since the last vault entry | anything a vault entry follows |
| the vault's key and the owner's login | the vault's entries since the last app entry | anything an app entry follows |
| both keys | everything, as today | |

The vault writes an entry with every unwrap, wrap and access change, so
when people use coffre the windows are seconds long. When nobody does, the
Cron bounds them, as below. The chain needs no key because the MACs carry
the authenticity. That lets anyone who reads the table check the links: a
witness, conformance, `coffre verify` from a backup.

**What checkpoints keep.** Three jobs, and a checkpoint becomes a vault
entry rather than a table and a protocol:

1. **Anchor quiet periods.** Every five minutes the Cron has the vault
   append a `checkpoint` entry, so no app entry stays unanchored longer than
   that. Before appending it, the vault checks the links since its previous
   checkpoint and the MACs of its own entries among them.
2. **Evidence without the MAC key.** The entry carries an Ed25519
   signature, under the vault's signing key, of the head it extends. A
   witness, an off-box copy or an outside auditor can check that with the
   public key alone.
3. **Readiness.** `/readyz` needs a vault entry less than 11 minutes old.
   Today a refused checkpoint leaves `/readyz` green (review F3); here a
   vault that stops appending turns it red.

F1 has nothing left to attack: the vault takes no claim about the app's
log. It appends after whatever head it finds, and its MAC pins everything
before it. The `vault_checkpoints` table, the `audit.checkpoint` entries the
app writes and `CheckpointInput.previous` all go.

**Each event is recorded once, by whoever decided it.**

| Event | Recorded by | Change |
|---|---|---|
| A value read: a reveal, a `coffre run`, an import's preview, a sync | the vault's `unwrap` entry, one per key, with the app's request id, bundle, purpose, source address, path and version | the app's `secret.read` entries go |
| A value written | the app's `secret.write`, in the transaction that stores the version; the vault's `wrap` | two entries, two facts: a version stored, a key wrapped |
| An access change: a grant, an admission, a removal | the vault's entry, with the app's request context, in the transaction that makes the change | the app's own entries for it go |
| A refusal by the vault | the vault's entry | the app's `vault_<code>` entries go |
| A refusal by the app, before it asks the vault | the app's entry | none |
| A sync's push | the app's `sync.push`, naming where the value went; the vault's `unwrap` | none |

"No audit, no value" still holds, from the other side: the vault commits
its entry before a key leaves it, and every path that returns a value goes
through an unwrap. Conformance's check, with the log refusing writes,
still finds no value in the answer. The context the app passes is the
app's claim, which the vault records as such under its MAC, as it records
the principal today.

**Access changes (review A01).** The vault's entry is the record, in the
transaction that changes the grant or the member, so there is nothing for
the app's append to fail to match. What still spans two transactions is a
removal's clean-up in the app's tables, sessions, tokens and linked
accounts, and its order makes any failure leave less access:

```
DELETE /api/members/user:ada@acme.example

A. app transaction   take Ada's principal row lock; revoke her sessions, tokens
                     and linked accounts; log that          fails: nothing changed
B. vault call        remove Ada and log it, in one transaction
                                                            fails: Ada is signed out,
                                                            still a member; retry
C. app transaction   revoke again whatever was issued between A and B
```

A takes the principal's row lock, the one sign-in and account linking take
once review A08 is fixed, so no account is linked between A and C unseen.
The membership generation makes anything issued before the removal useless
after a re-admission, whatever else goes wrong. A sync's removal follows the
same order: the app archives the sync, then asks the vault to remove its
principal; the heartbeat removes any grant left on an archived sync. The
intent entries, the `vault_seq` column and the recovery job that the first
version of this document needed are gone.

**Verification** reads the log once on each side, since each side holds one
key. The app checks every link, that the numbers run from 0 without a gap
(review F4), and its own MACs. The vault checks its MACs and signatures, and
replays members, grants and generations from its access entries. The
verdict names the entry where either fails, and its author. A page view
checks the entries it shows and those since the last view, as today.

**A forged vault entry,** written by the app's login where nothing stops it
(PlanetScale MySQL, SQLite), fails its MAC. Verification reports it. The
vault checks the MAC of every vault entry it decides on, such as the newest
access entry for a member, and ignores and reports one that fails; it does
not stop serving, or the app's login would hold a switch that turns coffre
off. A forged unwrap can only raise a member's bulk count.

**The costs.** One head lock for both, halving the throughput ceiling
(question 2). No foreign keys from the log (question 5). The two packages
share an entry format, so a change to it is a change to both, under a new
version tag. The app's login reads the vault's entries, which it shows
anyway: the audit page becomes one list with an author on each row, and
who may read which entries is the app's rule, where the vault's log was
root admins' only. And the app must never hold the head while it waits for
the vault (question 2, rule 3).

### 7. Rollback detection

Mallory has the owner's login and puts genuine old rows back. There are
three cases.

**Ada's rows alone.** Ada was offboarded at entry 812, a vault entry.
Mallory kept a copy of Ada's member row and grants from before, and writes
them back. Their MAC is genuine, so the MAC alone would let Ada in. The
vault catches this at Ada's next decision, for free. Ada's member row holds
`access_seq`, the entry that last changed her access, and the MAC covers it.
The decision's read also asks the log for the newest vault access entry
about Ada: the log says 812, the row says 640, and the vault refuses her as
`tampered`. That is one indexed lookup, folded into the read the decision
makes anyway. To get past it, Mallory must take entry 812 out of the log,
which breaks the chain, unless it is recent enough to cut off with
everything after it. That is the next case.

**The newest entries, cut off.** Review F8. Mallory saves
`audit_chain_head`, lets coffre run for four minutes, then deletes those
entries and puts the saved head back. She uses no key. What is left is
genuine and its chain verifies. A chain proves that what is kept is
authentic, not that nothing was cut from its end, and `architecture.md`
overstates it today. With one log she must cut both authors' entries
together, and if a cut access entry changed a member, the member's row now
names an entry the log no longer has: refused as `tampered`, unless she
puts that row back too, which is the whole-database case. Otherwise, two
things catch the cut: a vault or app instance that wrote one of the cut
entries and still remembers the head it left, at its next append; and any
witness that saw one of them.

**The whole database, rewound.** Mallory puts every row back as it was at
some earlier moment, or restores a backup. Every row, MAC and link is then
genuine and agrees with every other. Nothing inside the database can tell.
Today this takes both the database and the Durable Object; with one
database it is one restore. So detection has to come from outside the
database:

| | What it catches | Cost | |
|---|---|---|---|
| Memory | a rewind while a vault or app instance is running: the head it last saw goes backwards | none: compare the locked head with the last one seen | yes, plan steps 3 and 5 |
| Witnesses | a rewind past anything a person has seen | about 150 lines in `@coffre/client`, a route | yes, plan step 10 |
| Checkpoints off the box | a rewind of more than five minutes, with nobody looking | an R2 bucket with a retention lock, or S3 Object Lock on Node, and its settings in `init` | later: roadmap item 5 |

Witnesses are the idea already on the table, made precise in two ways.

**What a client remembers.** Per instance, the newest entry it has seen:
its `seq` and `hash`. Checking that the number only grows is not enough,
since after a rewind to 800 the log passes 812 again within minutes. So the
client asks for the hash at the number it remembers:
`GET /api/witness?seq=812` answers with the current entry's hash there and
the newest signed checkpoint. A rewound log has a different entry 812,
since its hash covers its time and contents, or none at all. The CLI checks
before a command, at most once an hour, and keeps its anchor in
`~/.coffre/credentials.json`. The browser checks once per page load and
keeps it in `localStorage`. A mismatch is a loud error: "this instance's
log was rewound: it no longer holds entry 812, which you saw on
2026-10-03."

**Witnesses for the changes that matter.** `admit`, `remove` and
`setAccess` return the entry the vault wrote, and the API passes it on. So
whoever offboards Ada holds entry 812 at once, and a rewind past her
removal is caught the next time that person opens coffre.

Plain heads are enough to detect a rewind: Mallory, with only the database,
controls what the app reads, not what it answers. The checkpoint's
signature, checked against the vault's public key the client pins at
`coffre login`, turns that into evidence someone else can check.

A legitimate restore looks exactly like an attack to a witness, which is
right. The restore drill ends with telling people, and with
`coffre verify --accept-rewind` to reset a client's anchor.

What stays invisible: a rewind to a moment after the last thing any witness
saw, before anyone looks again. Off-box checkpoints, later, shrink that to
the five minutes between two of them.

### 8. Node deployments

| | Today | After |
|---|---|---|
| The vault as its own process | `serveVault({ socket, store: 'vault.db', … })`, its own SQLite file | `serveVault({ socket, database: 'postgres://coffre_vault_runtime:…', … })` |
| The vault in the server's process | `localVault({ store, … })` | `localVault({ database, … })`, preferably with the vault's login |
| The server | `serve({ database, vault: connectVault(socket), … })` | unchanged |
| The socket | HTTP over a Unix socket, `0660` | unchanged |
| Backups | the database and `vault.db`, taken at the same moment | the database |

On SQLite both processes open one file, and SQLite's file lock serialises
them. There are no logins, so the separation between the tables rests on
guards 3 to 5. The vault's own SQLite layer (`sqlite.ts`, `sqlite-node.ts`,
`sqlite-durable-object.ts`) is deleted.

**Recommendation: keep SQLite,** for the tests, `pnpm conformance:node` and
a one-machine Node deployment. Its cost is already paid: a third schema and
baseline, and dialect branches that exist today. The vault adds nothing
SQLite-specific, since its lock is the existing no-op. Dropping SQLite would
make every test run need Docker and would add nothing to what coffre
guarantees.

### 9. PlanetScale and Hyperdrive

| | PlanetScale Postgres | PlanetScale MySQL (Vitess) |
|---|---|---|
| Smallest | PS-5, $5 a month on one node, $15 with high availability | PS-10 with high availability, $39 a month |
| Roles, GRANTs, triggers | yes | no |
| Point-in-time recovery | yes, from the WAL, 2 days by default; restores to a new branch | no; a backup every 12 hours |
| Schema changes | plain DDL | deploy requests |
| Hyperdrive | yes, with `pg`, Cloudflare's recommended driver | yes, GA since 2026-08-07, with `mysql2` 3.13 or later and `disableEval: true`; no prepared statements, no multi-statement queries |
| coffre's Worker | `postgres(env.HYPERDRIVE)`, today | not built: the Worker speaks only Postgres |
| Drizzle | `node-postgres`, as today | `mysql2`; its `mode: 'planetscale'` only changes how relational queries compile. PlanetScale's HTTP driver 2.0 breaks Drizzle's adapter for it (drizzle-orm#6398) |

**Recommendation: PlanetScale Postgres for erwinkn.com.** It keeps guards 1
and 2, has point-in-time recovery, costs less, and coffre's Worker already
speaks it. MySQL stays supported on Node, as today, with the integrity of
its column in question 4's table. Running the Worker on MySQL is a later
step, for when someone needs it.

Hyperdrive, for both Workers:

- **Query caching off: `wrangler hyperdrive create … --caching-disabled`.**
  Shipped in #22. Caching is on by default, serves a read for up to 60
  seconds plus 15 stale, and a write does not clear it, so a revoked token
  could keep working for about a minute. A `wrangler.jsonc` binding takes
  only a name and an id, so it cannot pin this; the session lookup reads
  the database clock, which Hyperdrive never caches, whatever the config
  says. Once the vault reads through Hyperdrive, its reads on Postgres do
  the same. Cloudflare's docs say nothing about reads inside a transaction.
- **One config per login,** so two. The Free plan allows 10 per account,
  Paid 25.
- **Port 5432, not 6432.** Hyperdrive pools, and PgBouncer behind it would
  pool again. coffre keeps no session state on Postgres, so pooling per
  transaction is fine.
- **Connections.** Hyperdrive opens up to about 20 connections to the
  database per config on Free, and 100 on Paid. PlanetScale does not
  publish PS-5's `max_connections`; it is in the branch's Parameters tab.
  Both configs must fit under it.
- **Placement.** Both Workers near the database's region, with Cloudflare's
  placement hint, since a decision makes several round trips.

## What it costs to get there

**Conformance.** Today the tamper checks write the vault's store directly:
`vault.db` on Node, and on Workers the Durable Object's SQLite file in
wrangler's local state (`vaultStore()`, `durableObjectFile`). They become
plain SQL on the deployment's database, as its owner, and that plumbing
goes. "Two logs agree" becomes "one record per event": every value revealed
has exactly one unwrap entry, under the right member, request and version,
and no `secret.read` beside it; every write has its app entry and its
vault's wrap. The tampering checks get stricter:

| Check | Today | After |
|---|---|---|
| a grant written into the vault's table | verification flags it | the grantee's next reveal is refused as `tampered`, and verification flags it |
| an offboarded member's old rows put back | not checked | refused as `tampered` |
| an app entry rewritten and re-MACed with the run's chain key, behind a vault entry | not checked; it would verify after the next checkpoint (F1) | verification fails at the vault entry after it |
| a vault entry written by the app's login | no shared log | refused by row-level security on Postgres; flagged by verification elsewhere |
| the app's login on the vault's tables | no such tables | every read and write refused, on Postgres |
| an access change with the log refusing writes | not checked; the change commits in the vault (A01) | the change fails and changes nothing |
| the newest entries cut off and the head put back | not checked | the admin's client reports it |

Workers conformance takes `--vault-runtime`, the vault's login, beside
`--runtime`.

**The audit page and `coffre verify`.** The page's two panels, "App log"
and "Vault log", become one list with the author on each row and a filter
for it. `GET /api/audit/vault` and the root-admin-only vault view go;
reading vault entries follows the same project-scoped rules as the rest.
Verification is one line naming the entry where it fails and its author,
and `coffre verify` prints the same, with `--accept-rewind` for a restore.

**The dev loop.** `pnpm dev` stops deleting the Durable Object's state,
since there is none: the seed starts one database over, and the vault's
rows go with it. `scripts/ensure-postgres.sh` creates a second local login,
`coffre_vault_runtime`. The vault Worker gets its own
`CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_*`.

**`coffre init`.** For Workers, `vault/wrangler.jsonc` loses
`durable_objects` and `migrations` and gains a `hyperdrive` binding.
`vault/src/worker.ts` passes `database: postgres(env.HYPERDRIVE)`. The
README's database step creates two logins and two Hyperdrive configs, both
without caching. For Node, `vault.env` trades `VAULT_STORE` for
`DATABASE_URL`. The examples follow, and the test that diffs them against
`init`'s output keeps the two in step.

**The restore drill.** What is escrowed: the KEK, `SIGNING_KEY`,
`AUDIT_CHAIN_KEY` and the GitHub client secret, in Erwin's password
manager, and access to the PlanetScale account. Then:

1. Restore the database to a moment T, as a new branch
   (`pscale branch create … --restore-point`).
2. Set the passwords of `coffre_runtime` and `coffre_vault_runtime` again;
   the restore reset them.
3. Point both Hyperdrive configs at the new branch
   (`wrangler hyperdrive update`).
4. `coffre verify`: every link, both authors' MACs, the signatures, and the
   replay of members and grants. It passes, since everything is genuine as
   of T.
5. Reveal a canary secret.
6. Clients that saw past T report a rewind. After a restore that is
   expected: tell people, and each runs `coffre verify --accept-rewind`.

Everything after T is gone. Today the same drill needs the database and the
Durable Object restored to the same moment, and the Durable Object has no
copy outside Cloudflare.

**Docs.** `architecture.md`: the vault, its transports, where each secret
lives, checkpoints, which become a section on the one log, and databases.
The README: "There is no delete" no longer leans on foreign keys.
`deploy.md`: PlanetScale Postgres from start to finish, and backups.
`conformance.md`: the tampering checks, and its "what it does not show",
since a forged grant is now stopped. `keys.md`: a line on the hierarchy.
The roadmap: phase 1 items 2, 5 and 6 change shape. `AGENTS.md` and the
README's layout.

## Lessons from Infisical

Read in source at `7528452` (2026-09-30), under `backend/src`. It confirms
the summary from their docs, and corrects it in places.

- **Keys.** A root key, from `ENCRYPTION_KEY` or `ROOT_ENCRYPTION_KEY` or a
  PKCS#11 HSM, wraps an internal root key stored in `kms_root_config`. That
  wraps one KMS key per organisation and per project. Each wraps one data
  key, and a project's data key encrypts every value in the project
  directly. There is no key per secret
  (`services/secret-v2-bridge/secret-v2-bridge-service.ts:771`). It is
  AES-256-GCM with no associated data (`lib/crypto/cipher/cipher.ts`), so
  nothing binds a ciphertext to its secret.
- **Caching.** Redis holds the project's wrapped data key for 5 minutes
  (`services/kms/kms-service.ts:122`). The plaintext key is unwrapped again
  on every request.
- **External KMS.** AWS or GCP wraps the project's data key once, and
  switching rewraps that one key. That means one AWS Decrypt per request,
  sent with no encryption context
  (`ee/services/external-kms/providers/aws-kms.ts:92`). It needs a paid
  plan.
- **Rotation.** A new KEK from the environment rewraps one row, staged so
  that old servers keep working (`encryption-key-rotation-service.ts`). A
  project's data key never rotates: "Reserved Infisical-managed KMS keys
  cannot be rotated."
- **Permissions.** Plain rows (`memberships`, `membership_roles`, `roles`
  with CASL rules as JSON), and one database user for everything. Anyone
  with the database password can make themselves an admin.
- **Audit.** Entries go through a Redis stream, outside the request's
  transaction, at most once: "the produced event is now lost (not retried)"
  (`ee/services/audit-log/audit-log-queue.ts:138`). The stream is capped
  at about a million entries and trimmed silently. There is no hash and no
  signature, and nothing is written without a licence. Reading a whole
  environment logs one event with a count, not the names.
- **Infrastructure.** Postgres only, Redis required, and Postgres advisory
  locks to create keys.

| Worth taking | Worth leaving |
|---|---|
| Staged KEK rotation, with a history of key labels. coffre's `previousKeks` and the planned rewrap command are the same idea; the label history is worth borrowing | No associated data. coffre binds every ciphertext to its ids, in the envelope and in the KMS encryption context |
| A version in every ciphertext, so the format can change. coffre has `envelopeVersion` and a KEK id on every row | One permanent key for every value in a project |
| Creating a key under a lock, then checking again inside the transaction | Permission rows that any database login can rewrite. coffre's member MACs exist because of this |
| A KEK per project, chosen by the customer. coffre could pick a KEK by project later, in the KEK registry | An audit log outside the transaction, best effort, behind a licence. It is why coffre exists |
| A transactional outbox, for when coffre streams its log elsewhere | Redis as a requirement, and locks that only one engine has |

The lesson people usually draw from Infisical is that layered keys make
rotation cheap. That is true, and its code shows the catch: the layer that
makes rotation cheap is the one that never rotates.

## Implementation plan

Each step is one pull request for one agent, stacked in this order unless
it says otherwise. "The suite" means `pnpm test:all`, `pnpm typecheck`,
`pnpm lint` and `pnpm test:schema`.

0. **Hyperdrive's cache off.** Shipped as #22: `--caching-disabled` in the
   deploy guide and the Workers template, and the session lookup reading the
   database clock, which Hyperdrive never caches.
1. **A removal's clean-up first** (review A01). Revoke sessions, tokens and
   linked accounts before asking the vault to remove, and again after. Works
   on today's vault, so it can land at once; the grant half of A01 closes in
   step 7. Verified by the app review's A01b, ported: with the vault call
   failing, a removal leaves no live credential.
2. **`@coffre/db`.** Move `packages/server/src/db` into a package: the
   schemas, migrations, `dialect.ts`, `portable.ts`, `connect.ts`, the
   Hyperdrive pool and the migrator. The server imports it by name, and
   `coffre-server migrate` delegates to it. Nothing else changes; the
   `identities` and `credentials` columns from #19 (A07, A08) move with the
   rest, so this step lands after #19 (`app-fixes`) or rebases onto it.
   Verified by the suite on all three engines, `db:check`, `check:pins` and
   `test:consumer`.
3. **The log's new format, written by the app alone.** `audit_log` gains
   `author`, `mac` and the vault's columns, loses its foreign keys, and
   chains with a plain SHA-256 and an HMAC per entry; the encoding lives in
   `@coffre/core`, and the append, which checks that the head names the
   last entry, in `@coffre/db`. Append-only triggers on Postgres and
   SQLite. The app remembers the last head it saw and refuses to append
   behind it. Verification checks every link, the numbers from 0 and the
   app's MACs. Verified by the suite, and the review's R3a and R3b
   (sequence gaps), ported.
4. **The vault's tables and logins.** `vault_members`, with #19's
   `generation`, `access_seq` and `mac`, and `vault_grants`, in all three
   schemas. On Postgres, the `coffre_vault` role, a check that
   `coffre_vault_runtime` exists, the GRANTs, and row-level security on
   `audit_log` per author. Nothing uses the tables yet. Verified by the
   parity test, the baseline check, `test:schema` extended (the app's login
   cannot touch the vault's tables, and each login inserts only its own
   author's entries), and `scripts/ensure-postgres.sh` creating the login.
5. **The vault on the shared database.** `store.ts` rewritten with Drizzle
   against `@coffre/db`. Decisions take `audit_chain_head` first, with a
   `lock_timeout`, and write vault entries under the vault's MAC: pre-check,
   intent when the KEK is in KMS, keys with every call settled, decide with
   each key's outcome logged. A decision refuses whenever its pre-check did.
   The store keeps #19's generation, bumped on each removal in the same
   transaction, and `access()` returns it. `#serial` goes; the vault
   remembers the last head it saw. The vault's own chain code gives way to
   the shared append; delete `sqlite.ts`, `sqlite-node.ts`,
   `sqlite-durable-object.ts` and the vault's `schema.ts`.
   Verified by `packages/vault/test` on three engines; two vault instances
   on one database, where parallel unwraps against a bulk limit of 10 allow
   exactly 10, a removal racing an unwrap never yields a key after it
   commits, and the chain verifies after both; a test that no `audited`
   transaction calls the vault after it has appended; and the review's R4
   (a partial KMS failure leaves a record) and R6 (a second instance shares
   the log and the limit), ported.
6. **Row integrity.** The member MAC over the member's grants, `generation`
   and `access_seq`; the freshness check against the newest vault access
   entry; vault entries that fail their MAC ignored and reported; the
   `tampered` refusal code in `@coffre/core`, worded on the pages and in
   the CLI. Verified by unit tests for a grant forged, edited and deleted;
   an old member row and its grants put back; a generation edited back, and
   one restored with its old row; a vault entry forged by the app's login.
7. **One record per event.** Unwraps and access changes carry the app's
   request context into the vault's entries, and the app drops its
   `secret.read`, access-change and `vault_<code>` entries. Checkpoints
   become signed vault entries every five minutes; the vault's checkpoints
   table, the app's `audit.checkpoint` entries and
   `CheckpointInput.previous` go. `/readyz` needs a vault entry less than 11
   minutes old. Verification reads the log once per side and combines the
   two. The audit page becomes one list; `GET /api/audit/vault` goes.
   Verified by the suite; the review's R1 and R1b (a rewritten history
   cannot verify again) and R2 (a stalled vault turns readiness red),
   ported; and the app review's A01, ported: an access change with the log
   refusing writes changes nothing.
8. **Transports and deployments.** Workers:
   `vault(env => ({ database: postgres(env.HYPERDRIVE), … }))`, and no
   Durable Object. Node: `serveVault({ database })` and
   `localVault({ database })`. The examples, `init`, `dev/deployment`,
   `dev/start.sh`, and the conformance harness (`--vault-runtime`, no
   `vaultStore`). Verified by `pnpm conformance:workers`,
   `pnpm conformance:node`, `test:consumer`, and a `pnpm dev` session that
   signs in and reveals.
9. **Stricter conformance.** The checks in "What it costs to get there".
   Verified by both conformance runs, and by each new check failing against
   a build with step 6 or 7 reverted.
10. **Witnesses.** Access changes return the vault's entry.
    `GET /api/witness`. `@coffre/client` keeps and checks the anchor; the
    CLI stores it with its credentials and the UI in `localStorage`.
    `coffre verify --accept-rewind`. Verified by unit tests, by the review's
    R7 rewritten to expect a witness that saw a cut entry to report it, and
    by a conformance check that rewinds the database as its owner and
    expects the admin's client to report it. Depends on step 7 only, so it
    can run beside 8 and 9.
11. **Docs and the restore drill.** The docs listed in "What it costs to get
    there", with `architecture.md` no longer claiming a chain protects the
    newest entries against removal (F8), and a runbook for PlanetScale
    Postgres. Verified by running the drill on a PlanetScale branch:
    restore, set the passwords, repoint Hyperdrive, `coffre verify`, reveal
    a canary.
12. **Later.** The Worker on MySQL through Hyperdrive (`mysql2`,
    `disableEval`); the GRANT and trigger script for self-hosted MySQL;
    checkpoints to R2 behind a retention lock.

## For Erwin to decide

1. Keep the vault a separate Worker and process, with its own login?
   Recommended: yes. A compromised app then gets logged reads, not the KEK.
2. Host erwinkn.com on PlanetScale Postgres? Recommended: yes. Roles,
   row-level security, triggers and point-in-time recovery from $5 a month;
   PlanetScale MySQL has none of them.
3. Keep MySQL supported on Node as today, with logins and triggers as an
   optional script for self-hosted MySQL, and build the Worker on MySQL
   when someone asks? Recommended: yes. PlanetScale MySQL can only ever
   have the keys' guarantees.
4. Keep SQLite for the tests and one-machine Node? Recommended: yes. Its
   cost is paid, and it keeps Docker out of the test suite.
5. Keep one data key per version, wrapped directly by the KEK? Recommended:
   yes. A per-secret CloudTrail record is worth more than KMS calls that
   cost about a dollar a month.
6. One MAC per member, covering their grants, rather than one per row?
   Recommended: yes. It catches deleted grants too, with one check per
   decision.
7. Accept that a removal landing during a KMS call shows in CloudTrail as a
   Decrypt the vault then refused? Recommended: yes. Avoiding it means
   holding the global lock across KMS.
8. Witnesses now, off-box checkpoints later? Recommended: yes. They are the
   cheapest way to catch a rewind of the whole database, and they work on
   Node too.
9. Bring back `@coffre/db`, with the shared append in it, and write the
   vault's store with Drizzle? Recommended: yes. Two packages now share the
   schema and the log.
10. Hyperdrive's cache off: shipped in #22.
11. One log written by both, chained by a plain SHA-256 with an HMAC per
    entry under its author's key, each login writing only its own author,
    and checkpoints as signed vault entries? Recommended: yes. Each side
    anchors the other within seconds, and review F1's protocol is gone.
12. With a KEK in KMS, log the intent before calling KMS, at the price of a
    second short transaction per call? Recommended: yes. It keeps the log
    and CloudTrail in step through a partial outage (F5), and costs a local
    KEK nothing.
13. Let the vault's entry be the only record of an access change, with the
    app's request context in it, and do a removal's clean-up of sessions
    first? Recommended: yes. The change and its record then commit
    together (A01), with no mirror to retry.
14. Accept that the database owner can cut the newest entries off the log
    and put its head back, caught only by a witness or an instance that saw
    them? Recommended: yes. It is true today, and closing it means
    anchoring every append outside the database.
15. Record each read once, as the vault's unwrap entry, and keep two entries
    per write, the app's version and the vault's wrap? Recommended: yes.
    The vault's entry commits before any key leaves, and a write records
    two different facts.
16. Drop the log's foreign keys to the app's tables? Recommended: yes. The
    vault writes ids the app has not committed yet, which Postgres refuses
    and MySQL waits on until it times out.
17. When the vault meets a vault entry that fails its MAC, ignore and report
    it rather than stop serving? Recommended: yes. Otherwise, where
    row-level security does not exist, the app's login could turn coffre
    off.

## Appendix A: spikes

Run on 2026-10-01 against the repository's Postgres 16.14 (`:55432`) and
MySQL 8.4.11 (`:53306`), each in a database and logins of its own, dropped
after. The scripts are not committed. The first two predate the one log:
their `vault_log` is the vault's own log, which now merges into
`audit_log`, and their `vault_log_head` is the row every append now locks,
`audit_chain_head`.

Postgres. Two transactions; T2 queues on the head row while T1 inserts a
grant and commits:

```
READ COMMITTED: T2 waiting on the head row -> lock acquired; then sees T1's grant: 1
REPEATABLE READ: T2 waiting on the head row -> 40001 could not serialize access due to concurrent update

app  SELECT vault_grants:            42501 permission denied for table vault_grants
app  INSERT vault_grants:            42501 permission denied for table vault_grants
app  SELECT vault_log:               42501 permission denied for table vault_log
vault INSERT vault_log:              ok
vault UPDATE vault_log:              42501 permission denied for table vault_log
vault DELETE vault_log:              42501 permission denied for table vault_log
vault TRUNCATE vault_log:            42501 permission denied for table vault_log
vault SELECT audit_log:              42501 permission denied for table audit_log
vault lock head FOR UPDATE:          ok
app  lock vault head FOR UPDATE:     42501 permission denied for table vault_log_head

owner UPDATE vault_log:              42501 vault_log is append-only        (trigger)
owner DELETE vault_log:              42501 vault_log is append-only
owner TRUNCATE vault_log:            42501 vault_log is append-only        (statement trigger)
owner DISABLE TRIGGER then UPDATE:   ok
vault DISABLE TRIGGER:               42501 must be owner of table vault_log
vault SET session_replication_role:  42501 permission denied to set parameter "session_replication_role"
```

MySQL. The same two transactions; in the third run T2 reads the grants
before taking the lock:

```
READ COMMITTED, plain read before the lock: lock acquired; plain read sees T1's grant: 1; locking read: 1
REPEATABLE READ: lock acquired; plain read sees T1's grant: 1; locking read: 1
REPEATABLE READ, plain read before the lock: lock acquired; plain read sees T1's grant: 0; locking read: 1

app   SELECT vault_grants:   ER_TABLEACCESS_DENIED_ERROR SELECT command denied … for table 'vault_grants'
app   INSERT vault_grants:   ER_TABLEACCESS_DENIED_ERROR INSERT command denied … for table 'vault_grants'
vault INSERT vault_log:      ok
vault UPDATE vault_log:      ER_TABLEACCESS_DENIED_ERROR UPDATE command denied … for table 'vault_log'
vault DELETE vault_log:      ER_TABLEACCESS_DENIED_ERROR DELETE command denied … for table 'vault_log'
vault TRUNCATE vault_log:    ER_TABLEACCESS_DENIED_ERROR DROP command denied … for table 'vault_log'
vault lock head FOR UPDATE:  ok

owner UPDATE vault_log:      ER_SIGNAL_EXCEPTION vault_log is append-only   (trigger)
owner DELETE vault_log:      ER_SIGNAL_EXCEPTION vault_log is append-only
owner TRUNCATE vault_log:    ok (rows left: 0)
```

One log, two authors. Each login inserting the other's entries, under
row-level security; a vault entry referencing a project the app has not
committed; the app holding the head while it waits for the vault; and one
head against two, with the round trip simulated at 5 ms in the client and
each append holding the lock for about four of them. The last two lines
are MySQL's answer to the foreign-key case:

```
## A. Each login writes only its own author (row-level security)
app   INSERT author=app:    ok
app   INSERT author=vault:  42501 new row violates row-level security policy for table "audit_log"
vault INSERT author=vault:  ok
vault INSERT author=app:    42501 new row violates row-level security policy for table "audit_log"
app   SELECT both authors:  app,vault
owner INSERT author=vault:  ok  (the owner bypasses RLS)

## B. A vault row referencing a row the app has not committed yet
vault INSERT referencing the uncommitted project: 23503 insert or update on table "audit_log" violates foreign key constraint "audit_log_project_id_fkey" after 1 ms

## C. The app holding the head lock while it waits for the vault
vault decision while the app holds the head and awaits it: 55P03 canceling statement due to lock timeout after 2002 ms (no deadlock reported)

## D. One head lock for both authors, with 5 ms per round trip
 1 clients, 1 head :  40 appends/s, wait for the lock p50 1 ms, p99 2 ms
 8 clients, 1 head :  52 appends/s, wait for the lock p50 133 ms, p99 160 ms
32 clients, 1 head :  59 appends/s, wait for the lock p50 587 ms, p99 908 ms
 8 clients, 2 heads: 108 appends/s, wait for the lock p50 50 ms, p99 75 ms
32 clients, 2 heads: 113 appends/s, wait for the lock p50 274 ms, p99 348 ms
MySQL READ COMMITTED: vault INSERT referencing the uncommitted project: ER_LOCK_WAIT_TIMEOUT after 2004 ms
MySQL REPEATABLE READ: vault INSERT referencing the uncommitted project: ER_LOCK_WAIT_TIMEOUT after 2001 ms
```

## Appendix B: sources

Checked on 2026-10-01.

PlanetScale Postgres:
[roles](https://planetscale.com/docs/postgres/connecting/roles),
[compatibility](https://planetscale.com/docs/postgres/postgres-compatibility),
[connecting](https://planetscale.com/docs/postgres/connecting),
[PgBouncer](https://planetscale.com/docs/postgres/connecting/pgbouncer),
[branching](https://planetscale.com/docs/postgres/branching),
[backups](https://planetscale.com/docs/postgres/backups),
[point-in-time recovery](https://planetscale.com/docs/postgres/backups/point-in-time-recovery),
[pricing](https://planetscale.com/pricing).

PlanetScale MySQL and Vitess:
[MySQL compatibility](https://planetscale.com/docs/vitess/troubleshooting/mysql-compatibility),
[password roles](https://planetscale.com/docs/vitess/security/password-roles),
[foreign keys](https://planetscale.com/docs/vitess/foreign-key-constraints),
[system limits](https://planetscale.com/docs/vitess/troubleshooting/planetscale-system-limits),
[deploy requests](https://planetscale.com/docs/vitess/schema-changes/deploy-requests),
[safe migrations](https://planetscale.com/docs/concepts/safe-migrations),
[migration data](https://planetscale.com/blog/versioned-schema-migrations),
[backups](https://planetscale.com/docs/vitess/backups),
[restore points are Postgres only](https://planetscale.com/docs/api/reference/create_branch),
[Vitess MySQL compatibility](https://vitess.io/docs/22.0/reference/compatibility/mysql-compatibility/).

Cloudflare:
[Hyperdrive MySQL GA](https://developers.cloudflare.com/changelog/post/2026-08-07-hyperdrive-mysql-ga/),
[PlanetScale MySQL through Hyperdrive](https://developers.cloudflare.com/hyperdrive/examples/connect-to-mysql/mysql-database-providers/planetscale/),
[supported features](https://developers.cloudflare.com/hyperdrive/reference/supported-databases-and-features/),
[how Hyperdrive pools](https://developers.cloudflare.com/hyperdrive/concepts/how-hyperdrive-works/),
[query caching](https://developers.cloudflare.com/hyperdrive/concepts/query-caching/),
[limits](https://developers.cloudflare.com/hyperdrive/platform/limits/),
[Postgres drivers](https://developers.cloudflare.com/hyperdrive/examples/connect-to-postgres/),
[importing `env`](https://developers.cloudflare.com/workers/runtime-apis/bindings/),
[service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/).

Drizzle:
[PlanetScale](https://orm.drizzle.team/docs/connect-planetscale),
[`mode: 'planetscale'`](https://orm.drizzle.team/docs/latest-releases/drizzle-orm-v0280),
[drizzle-orm#6398](https://github.com/drizzle-team/drizzle-orm/issues/6398).

Infisical: [github.com/Infisical/infisical](https://github.com/Infisical/infisical)
at `752845215bbfe62aa78313ee5d89fd54c4444986`.

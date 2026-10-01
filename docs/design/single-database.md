# One database

A proposal to run coffre on a single Postgres or MySQL database, the vault's
tables included. It says what the second store buys today, how much of that
one database can keep, what it costs to get there, and what needs deciding.
Written on 2026-10-01 against `ui-fixes` (#18). Nothing here is built yet.
It folds in the findings of the same day's two security reviews that bear
on the design: F1, F2, F5 and F8 from the review of keys and integrity, and
A01 from the review of the app. The section "What the security reviews
change" says where each one lands.

## In short

- **The vault stays a separate Worker, or process on Node, with its own
  database login.** It keeps the KEK and the signing key out of the app's
  large bundle. It loses its Durable Object and keeps its rows in the
  shared database, in `vault_*` tables the app's login cannot write. An
  access change then spans the vault's transaction and the app's, so the
  app logs its intent and revokes first, and its record of the outcome is
  retried until it lands.
- **A locked row replaces the Durable Object's single thread.** Every vault
  decision starts with `SELECT … FOR UPDATE` on `vault_head`, which is how
  the app's audit chain already serialises its appends. Grants, members and
  bulk counts are read under that lock by every instance, and nothing an
  instance keeps in memory decides anything. KMS calls stay outside the
  transaction, and with KMS the vault logs its intent before calling it.
- **A checkpoint proves that the log grew, rather than taking the caller's
  word for it.** Each side's login can read the other log's hashes, and
  only its hashes. The vault checks the app's log from the last head it
  signed before it signs the next one. The app checks the vault's log from
  the last head it recorded before it records the next one. Full
  verification holds every signed head as a constraint, not only the
  newest.
- **One data key per secret version, wrapped directly by the KEK, as
  today.** Intermediate keys would save KMS calls that cost about a dollar a
  month, and would cost CloudTrail its record of which secret was read.
- **The database enforces what it can, and keys catch the rest.** On
  Postgres, logins and triggers keep the app out of the vault's tables and
  keep both logs append-only. On every engine, a MAC over each member's
  access means a forged grant is refused at once, not flagged at the next
  verification. The keyed log chains and signed checkpoints stay.
- **Rollback is caught by witnesses.** The vault refuses a member's rows
  when its log holds a later change to them. Clients remember the newest
  log entries they saw and check the log still holds them, and whoever
  offboards someone gets that entry in the response. Two things stay
  invisible to everyone who has not seen past them: a rewind of the whole
  database, and the last five minutes of either log cut off. The first is
  what dropping the second store costs; the second is true today.
- **Host on PlanetScale Postgres.** It has SQL roles, table-level GRANTs,
  triggers and two days of point-in-time recovery, from $5 a month.
  PlanetScale MySQL has none of these, so coffre's guarantees there rest on
  its keys alone.
- **Turn off Hyperdrive's query cache now.** It is on by default, today's
  deploy guide leaves it on, and a revoked session can keep working for
  about a minute. This one is independent of the rest.

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
  │ projects, environments, secrets,          │ vault_members, vault_grants,   │
  │ secret_versions, principals, credentials, │ vault_log, vault_head,         │
  │ syncs, audit_log, …                       │ vault_checkpoints              │
  └────────────────────────────────────────────────────────────────────────────┘
```

The `Vault` interface, its RPC and socket transports, both logs and the
checkpoints stay as they are. Three things change: where the vault keeps its
rows, how it serialises its decisions, and what it checks on each row before
deciding on it.

### Mallory, after

With PlanetScale Postgres and the logins of question 4:

| Mallory has | She can | She cannot | What catches her |
|---|---|---|---|
| The app's login, `coffre_runtime` | read ciphertext, the directory and the audit log; insert a session row and act as an existing member | open a value without the vault; read the vault's members, grants or log entries, beyond the log's hashes; write any `vault_*` table; change or delete an audit entry | every value she opens is in the vault's log, under the member she plays, and counts toward that member's bulk limit. This gap is today's, unchanged |
| The owner login, PlanetScale's default role | anything in the database, triggers included | open a value: no KEK. Forge a grant or a log entry: no vault key | a grant forged or edited: refused at its next use. Old rows put back: refused, since the log holds the later change. A log rewritten and its chain recomputed: the next checkpoint refuses it. The newest entries since the last checkpoint cut off, or both logs and the vault's rows rewound together: only a witness that saw past that point |
| The PlanetScale account | the above, and restore a backup to a new branch | make coffre use that branch without the Cloudflare account; copying rows back is the case above | as above |
| The Cloudflare account | deploy code that reads the KEK | | nothing coffre can do, as today |

### What the security reviews change

Two reviews of `3dfa720` on 2026-10-01, one of keys and integrity (F) and
one of the app (A), found five problems this design has to answer, and one
more it answers on the way.

| Finding | What it showed | Where the design answers it |
|---|---|---|
| F1, high | A checkpoint takes the caller's word that it extends the last one, and verification checks only the newest | Question 6: each side reads the other log's hashes and checks the extension itself, and verification keeps every commitment. Plan step 6 |
| F2, high | A second Durable Object loads the same KEK with an empty log and a fresh bulk counter | Question 2: no Durable Object, every instance decides under one database lock, and nothing in an instance's memory allows anything. Plan step 4. The fix in flight, refusing any object but the canonical one, still matters until then |
| F3, medium | A refused checkpoint leaves `/readyz` green | Question 6, point 4. Plan step 6 |
| F5, medium | A KMS failure halfway through a batch leaves no vault record of the keys KMS did open | Question 2: the intent is logged before KMS, every call settles, and each key's outcome is logged. Plan step 4 |
| F8, low | The database owner can cut the newest entries off a log and put its head back | Question 7: a window of at most five minutes, bounded by checkpoints, the vault's memory and witnesses. `architecture.md` stops overstating the chain. Plan step 10 |
| A01, high | The vault commits an access change before the app's audit append; if that fails, the change stays live with no app entry, and a half-done removal revives old sessions on re-admission | Question 1, "Access changes across two transactions": intent and revocations first, then the vault, then a retried record keyed by the vault's entry. Plan step 1 |
| A07, A08, medium, being fixed on #19 | An account binding survives a change of its provider's issuer; linking an account can race offboarding and survive re-admission | Their fixes change the schema this design moves: `identities` bound to their issuer, and a membership generation the vault keeps per member and bumps on removal, stored on accounts, credentials and device approvals. Question 5 carries both. Plan steps 2 to 5, rebased on #19 |
| Closing note | The shared database needs separate logins, protected grant and log tables, and bulk and authorisation accounting that holds across instances | Questions 1, 2 and 4. Where logins do not exist, on PlanetScale MySQL and SQLite, member MACs and checkpoints stand in, and question 4 says what that leaves open |

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
| What a bug or a malicious dependency in the app gets | values, by asking the vault as some member: each one logged where the app cannot erase it, capped by the bulk limit, refused for removed members, and in CloudTrail with KMS. It ends when the app is fixed | the KEK. With any copy of the database, past or future, that opens every value offline, and no log ever hears of it. It ends only when every value is re-encrypted under a new KEK |
| Who can write the vault's rows | its own login: on Postgres the app's login cannot touch them | one login for everything; MACs only |
| An access change and the app's record of it | two transactions: the design below orders them and retries the second | one transaction |
| Cost of a vault call | a service binding: per Cloudflare, "zero overhead", both Workers on the same thread by default | none |
| What `coffre init --workers` writes | `app/` and `vault/` as today, minus the Durable Object, plus a Hyperdrive binding | one Worker |

**Recommendation: (a).** The row that decides it is the second: with (a), a
compromised app gets reads, each logged where it cannot erase it. With (b),
it gets the KEK, and every read after that is silent. Erwin's deployment
uses a local KEK, which is the case where (b) does worst.

What (b) gains is one transaction for both logs, and app review A01 shows
that it matters for access changes. Today the vault commits a grant, then
the app's audit append fails: the API answers 500, the grant is live, and
the app's log never hears of it. A removal whose app transaction fails
leaves the person removed in the vault while their sessions survive, and
re-admitting them revives those sessions. One database does not fix this
while the vault commits on its own login. (a) fixes it as below, and I
think that is the better trade than handing the app the KEK. For reads
nothing changes: the app already refuses to return a value it could not
log.

#### Access changes across two transactions

Two logins cannot share a transaction, so the design orders the two so that
a failure anywhere leaves less access rather than more, and makes the app's
record of the change something that is retried until it lands.

```
PATCH /api/access/user:ada@acme.example   or   DELETE /api/members/user:ada@acme.example

A. app transaction    the intent entry: who asks to change what, with the request id;
                      for a removal, revoke Ada's sessions, tokens and sign-in accounts too
                      COMMIT                       fails: 500, nothing changed anywhere
B. vault call         decide, apply, log in the vault's own transaction
                                                   fails: Ada is signed out but still a member
C. app transaction    the outcome entries, each naming the vault entry it mirrors;
                      for a removal, revoke again whatever was issued since A
                      COMMIT                       fails: the change is live and in the
                                                   vault's log; recovery writes C
```

- **Reductions come first.** A removal revokes Ada's credentials in A,
  before the vault removes her. If B fails she is signed out but still a
  member, which the admin sees as an error and retries. C revokes again,
  for a token issued between A and B. A takes the principal's row lock,
  the one sign-in and account linking take once app review A08 is fixed,
  so no account is linked between A and C unseen, and C's sweep covers
  linked accounts too. The membership generation (A08, question 5) makes a credential from before a removal useless after a
  re-admission whatever else goes wrong.
- **The intent is durable before anything changes.** Every live access
  change has its entry in the vault's log, written in the transaction that
  made it, and an intent in the app's log written before it.
- **Recovery is a retry, not a guess.** The heartbeat, and the start of
  every access change, look for intents with no outcome. For each, they
  ask the vault what it did with that request id, then write the outcome
  entries it is missing, or "not applied". `audit_log` gains a nullable
  unique `vault_seq` column, so an outcome cannot be written twice. A
  removal the vault did not apply is retried, since taking access away is
  always safe to repeat; a grant is not, since the admin saw an error and
  may have changed their mind.

So an access change and its record no longer commit together, but within
one heartbeat both logs hold it, and no failure grants access the app's log
never mentions or leaves a credential alive after a removal. Access changes
are rare, so the second transaction costs nothing that matters.

On latency the two are equal. Each decision makes about five round trips to
the database. With both Workers placed near the database, that is a few
milliseconds each. Today a decision is one trip to the Durable Object, which
sits in one Cloudflare location.

### 2. Serialising decisions without a Durable Object

The Durable Object runs one call at a time, and each decision is a
synchronous SQLite transaction. Once several vault isolates or processes
share one database, the serialising has to move into the database. Every
decision becomes one transaction whose first statement locks a permanent
row:

```
unwrap(user:ada@acme.example, market/prod, 50 keys)

1. pre-check   read Ada's member row, grants and recent unwraps         no lock, one round trip
               refused? skip to 4
2. intent      with KMS only: BEGIN; lock vault_head; append one
               unwrap.intent entry naming the request and its 50 keys; COMMIT
3. keys        50 KMS Decrypts, or 50 local unwraps;                    no transaction open
               every call settles before step 4
4. decide      BEGIN
               SELECT next_seq, head_hash, mac FROM vault_head
                 WHERE only_row FOR UPDATE                              every decision queues here
               read Ada's rows again; check the MAC, freshness, bulk limit
               INSERT 50 log rows, each with its outcome; UPDATE vault_head
               COMMIT                                                   about five round trips
```

That is the pattern the app's audit chain uses with `audit_chain_head`.
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
- **No deadlocks.** Each vault transaction takes one lock, first. The app
  may hold its own rows while it calls the vault, but the vault never
  writes the app's tables, so no cycle can form.
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

Two rules make this hold on every engine:

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

KMS stays outside the transaction. A lock held across 50 Decrypts, with a
5-second timeout and three attempts each, would stall every other decision
behind KMS. It would also hold a pooled connection the whole time, and
Hyperdrive has about 20 per config on the Free plan and 100 on Paid.
PlanetScale MySQL kills any transaction after 20 seconds.

The price is a race the Durable Object prevented. Say Bob removes Ada
between steps 1 and 4. KMS has already opened her 50 keys. Step 4 sees the
removal, refuses, logs 50 refusals and zeroes the keys. Ada gets nothing,
but CloudTrail shows 50 Decrypts the vault then refused. The refusal entries
record that the keys were opened (`detail.opened: true`), so a check of
CloudTrail against the vault's log can pair them. I think that is
acceptable. Avoiding it means holding the lock across KMS.

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

Throughput: the lock is held for about five round trips. At 5 ms each that
is 25 ms, or about 40 decisions a second. A decision covers a whole batch,
so a `coffre run` of 50 keys is one decision. The audit chain already has
the same ceiling.

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

Five guards, outermost first. The first two come from the database and
depend on the engine. The other three come from keys and hold everywhere.

1. **Logins.** The app's login cannot write any `vault_*` table, and reads
   only the vault log's hashes. The vault's login writes only `vault_*`
   tables, may only insert into `vault_log` and `vault_checkpoints`, and
   reads only the audit log's hashes outside its own tables. In the spike,
   every forbidden statement failed with `42501` on Postgres and
   `ER_TABLEACCESS_DENIED_ERROR` on MySQL.
2. **Triggers** refuse UPDATE and DELETE on `audit_log`, `vault_log` and
   `vault_checkpoints`, for every login, the owner's too. They stop bugs and
   a careless owner, not a determined one. On Postgres the table's owner can
   `ALTER TABLE … DISABLE TRIGGER`, and on MySQL `TRUNCATE` skips delete
   triggers. The spike did both.
3. **A MAC over each member's access.** Each `vault_members` row carries
   `mac = HMAC(rowKey, [principal, status, owner, since, by, access_seq,
   that member's grants, sorted])`, where `rowKey` is
   `HKDF(signingKey, "coffre.vault.rows")`, derived the way the log's key is
   today. The vault checks it on every read it decides on. That includes
   `access()`, since the app's own permission checks come from it. A grant
   inserted, edited or deleted under a member changes the set, so the MAC
   fails. The vault then refuses that member with a new code, `tampered`,
   and logs it. A grant under someone with no member row is already ignored
   (`not_a_member`). One MAC per member, rather than one per row, catches
   deleted grants too, and costs a decision one check. `vault_head` carries
   a MAC over `next_seq` and `head_hash`, and each decision checks that the
   log's last entry is the one the head names. So deleting the newest
   entries, say Ada's unwraps to reset her bulk limit, fails the next
   decision.
4. **Keyed log chains** on both logs, as today.
5. **Signed checkpoints** of both heads every five minutes, each now
   checked against the database before it is signed or recorded (question
   6), and the witnesses of question 7.

What each engine allows. Sources are in appendix B.

| | PlanetScale Postgres | Postgres, self-hosted | MySQL, self-hosted | PlanetScale MySQL | SQLite |
|---|---|---|---|---|---|
| Logins with table-level GRANTs | yes, `CREATE ROLE` in SQL | yes | yes, `CREATE USER` | no: four fixed roles per password, each database-wide | no logins |
| Append-only triggers | yes | yes | yes, except against `TRUNCATE` | no: "We do not support any form of stored routines" | yes |
| `SELECT … FOR UPDATE` | yes | yes | yes | yes, in transactions of at most 20 s | not needed |
| Foreign keys | yes | yes | yes | opt-in, unsharded only | yes |
| Member MACs, keyed chains, checkpoints, witnesses | yes | yes | yes | yes | yes |
| Point-in-time recovery | yes, 2 days by default | your own | your own | no: a backup every 12 hours | copies of the file |

Without guards 1 and 2, on PlanetScale MySQL and SQLite, the app's login
can write the vault's tables. Guards 3 to 5 still refuse a forged grant and
catch an edited log. What they cannot stop there: deleting a member's grants,
which the vault refuses as `tampered`, so a denial of service but not
access; and rolling rows back, which is question 7.

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

| Table | Change from the vault's SQLite | App's login | Vault's login |
|---|---|---|---|
| `vault_members` | `generation` from #19, then adds `access_seq` and `mac` | nothing | SELECT, INSERT, UPDATE |
| `vault_grants` | adds `place_id`, the environment's id or, for a project grant, the project's; unique with `principal` | nothing | SELECT, INSERT, DELETE |
| `vault_log` | adds an index on `subject, seq` | `seq`, `prev_hash`, `hash`: SELECT | SELECT, INSERT |
| `vault_head` | new: the lock row, with `next_seq`, `head_hash`, `mac` | SELECT | SELECT, UPDATE on those columns |
| `vault_checkpoints` | none | nothing | SELECT, INSERT |
| the app's tables | none | as today | `seq`, `prev_hash` and `hash` of `audit_log`, and `audit_chain_head`: SELECT only, to check a checkpoint (question 6) |

Each side reads the other log's hashes and nothing else: no actor, no
subject, no detail. Postgres and MySQL both grant SELECT per column.

`place_id` replaces the two partial unique indexes the vault's SQLite has
today. That follows the rule `architecture.md` set for the app: remodel
what one engine cannot say, rather than write it three ways. Times stay
integers of milliseconds, which the vault's chain already hashes.

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
them. `@coffre/server` owns the rest. The lint rule that confines Drizzle to
`server/src/db` grows to say which package may name which tables.

Where the code lives: a package again, `@coffre/db`, holding the three
schemas, the migrations, `dialect.ts`, `portable.ts`, `connect.ts` and the
Hyperdrive pool, moved out of `packages/server/src/db`. PR #8 folded
`packages/db` into the server because the server was its one user. The
vault is a second. Queries stay with their owners: the app's in
`queries.ts`, the vault's in its `store.ts`, now written with Drizzle. That
undoes #9's "without Drizzle", for the reason the app uses it: one schema
per engine, a parity test, and queries that read the same on all three.
`coffre-server migrate` stays the one command and migrates both. The other
way, the vault importing tables from `@coffre/server`, would pull the
server's dependencies into the bundle we want small.

Migrations:

- **No deployment exists yet,** so the vault's tables go into each engine's
  baseline, regenerated by `pnpm db:generate` like every schema change so
  far. No data moves out of a Durable Object.
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
  `audit_heartbeat`, now `vault_head`) also move out of the DDL, into an
  insert-if-absent step that `migrate` runs against production.
- **Once deployments exist,** the two Workers deploy one after the other,
  after the migration. A migration must then work with the code before and
  after it: add a column, fill it, then constrain it.

### 6. Checkpoints that prove extension

Review F1, rated high. Today the vault signs a new checkpoint when the
caller says the previous one still holds: `checkpoint({ seq, headHash,
previous })`. That is the app's claim, not evidence. Verification then
checks only the newest checkpoint, and only the newest vault head the app
recorded. So whoever holds `auditChainKey` and can write the audit log can
rewrite history that a checkpoint already covers, and still verify green:

```
10:00  checkpoint C1: the vault signs audit entry 5120, hash 9f3a…
10:02  Mallory rewrites the actor of entry 4000 and recomputes the chain
       with auditChainKey. Entry 5120's hash is now 77c1…
10:05  Today: she calls checkpoint({ seq: 5170, …, previous: { seq: 5120,
       hash: 9f3a… } }). The vault believes the old hash, signs C2, and
       verification, which looks only at C2, passes.
       After: the vault reads entry 5120 from audit_log itself, finds 77c1…
       where it signed 9f3a…, and refuses. /readyz goes red.
```

The mirror image works against the app, for whoever holds the vault's
store and signing key: rewrite the vault log, sign a later checkpoint, and
the next honest heartbeat records it over the old anchor. The reviewer
demonstrated both on Postgres and MySQL. One database does not fix this by
itself, but it makes the fix cheap, because each side can now read the
other's log.

1. **The vault reads instead of being told.** `checkpoint()` takes no claim
   about the app's log. The vault reads `audit_chain_head`, then the
   `seq`, `prev_hash` and `hash` of each audit entry from the last head it
   signed to the current one. It signs only if the entry at its last signed
   `seq` still has the hash it signed, the numbers run without a gap, each
   `prev_hash` is the hash before it, and the last one is the head. It
   cannot recompute the app's HMACs, and must not be able to: a vault
   holding `auditChainKey` could rewrite the app's log. It does not need
   to. The links prove the new head descends from the signed one, and the
   app's verifier, which has the key, checks every entry's contents.
2. **The app checks before recording.** Before the heartbeat writes a
   signed checkpoint into the audit log, it reads the vault log the same
   way, from the last vault head it recorded to the new one, and checks the
   same four things. A vault log rewritten and re-chained with the vault's
   key no longer has the recorded hash at that `seq`, so the app refuses to
   record it.
3. **Verification keeps every commitment.** Full verification already reads
   the whole audit log. On the way it gathers every `audit.checkpoint` entry
   and every row of `vault_checkpoints`, and checks each: every head the
   vault signed against the audit log's hash at that `seq`, and every vault
   head the app recorded against the vault log's. A later signature never
   replaces an earlier one. A page view still checks only the newest, as
   today.
4. **Readiness counts checkpoints.** Review F3: the heartbeat writes its row
   before it tries the checkpoint, so today a refused checkpoint still
   leaves `/readyz` green. Readiness then needs a recent heartbeat and a
   recent checkpoint that was signed and recorded.

The cost is small. Signing and recording read only what is new since the
last checkpoint, three columns of about 70 bytes a row, and the vault reads
them before it takes its lock:

| Write rate | Entries per checkpoint | Read per checkpoint, each side |
|---|---|---|
| erwinkn.com, about one a minute | 5 | under 1 KB |
| a 50-person team, about 10 a minute | 50 | about 4 KB |
| a million entries a day, about 700 a minute | 3,500 | about 250 KB, in one query |

Full verification gains one lookup per checkpoint: 288 a day, about 105,000
a year, gathered during the scan it already makes and checked against the
other log in batches. That is about 4 MB of reads per year of history, next
to a full scan of an audit log that is far larger.

`CheckpointInput.previous` leaves the `Vault` contract in `@coffre/core`.
What this does not cover: entries newer than the last checkpoint. Changing
one still breaks the keyed chain, but cutting them off the end does not
(review F8, question 7).

### 7. Rollback detection

Mallory has the owner's login and puts genuine old rows back. There are
three cases.

**Ada's rows alone.** Ada was offboarded at vault log entry 812. Mallory
kept a copy of Ada's member row and grants from before, and writes them
back. Their MAC is genuine, so the MAC alone would let Ada in. The vault
catches this at Ada's next decision, for free. Ada's member row holds
`access_seq`, the log entry that last changed her access, and the MAC
covers it. The decision's read also asks the log for the newest access
entry about Ada: the log says 812, the row says 640, and the vault refuses
her as `tampered`. That is one indexed lookup, folded into the read the
decision makes anyway. To get past it, Mallory must take entry 812 out of
the log, which breaks the chain, unless 812 is recent enough to cut off
with everything after it. That is the next case.

**The newest entries, cut off.** Review F8. Mallory saves
`audit_chain_head` just after a checkpoint, lets the app write for four
minutes, then deletes those entries and puts the saved head back. She uses
no key. What is left is genuine, its chain verifies, and the last
checkpoint still matches. The same works on the vault's log with
`vault_head`, whose saved row carries a genuine MAC. A keyed chain proves
that what is kept is authentic, not that nothing was cut from its end, and
`architecture.md` overstates it today: it says the chain covers the entries
since the last checkpoint against someone with only the database. It covers
changing them, not removing them from the end. Three things bound the cut.
Once a checkpoint covers an entry, cutting it breaks that checkpoint, so
only the last five minutes are exposed, provided a refused checkpoint fails
readiness. An app or vault instance that wrote one of the cut entries and
still remembers the head it left catches it at its next append. And any
witness that saw one of them catches it. Comparing the two
logs' newest entries would catch a cut of one log but not of both, and the
two legitimately disagree whenever the app fails to log a value the vault
opened. So the design does not rely on that comparison.

**The whole database, rewound.** Mallory deletes both logs' entries since
a moment before Ada's removal, vault entry 800 say, and puts every vault
row, `vault_head` included, back as it was then. Or she restores a backup.
Every row, MAC and chain is then genuine and agrees with every other.
Nothing inside the database can tell. Today this takes both the database
and the Durable Object; with one database it is one restore. So detection
has to come from outside the database:

| | What it catches | Cost | |
|---|---|---|---|
| The vault's memory | a rewind while a vault isolate or process is running: the head it last wrote goes backwards | none: compare the locked head with the last one seen | yes, plan step 4 |
| `/readyz` fails on a refused checkpoint | one log rewound or rewritten but not the other, within 11 minutes, through the `/readyz` monitor of roadmap item 4. Today a refused checkpoint still leaves `/readyz` green (review F3) | record the last good checkpoint beside the heartbeat | yes, plan step 6 |
| Witnesses | a rewind past anything a person has seen | about 150 lines in `@coffre/client`, a route, a vault call | yes, plan step 9 |
| Checkpoints off the box | a rewind of more than five minutes, with nobody looking | an R2 bucket with a retention lock, or S3 Object Lock on Node, and its settings in `init` | later: roadmap item 5 |

Witnesses are the idea already on the table, made precise in two ways.

**What a client remembers.** Per instance, the newest entry it has seen in
each log: the vault log's `seq` and `hash`, and the audit log's. Checking
that the numbers only grow is not enough, since after a rewind to 800 the
vault log passes 812 again within minutes. So the client asks for the hash
at the number it remembers: `GET /api/witness?vault=812&audit=5120`
answers with the current entries' hashes there and the newest signed
checkpoint. A rewound log has a different entry 812, since the HMAC covers
its time and contents, or none at all. The CLI checks before a command, at
most once an hour, and keeps its anchor in `~/.coffre/credentials.json`.
The browser checks once per page load and keeps it in `localStorage`. A
mismatch is a loud error: "this instance's logs were rewound: they no
longer hold vault log entry 812, which you saw on 2026-10-03."

**Witnesses for the changes that matter.** `admit`, `remove` and
`setAccess` return the vault's head after the change, and the API passes it
on. So whoever offboards Ada holds entry 812 at once, without waiting for
the next checkpoint, and a rewind past her removal is caught the next time
that person opens coffre.

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
  Caching is on by default. It serves a read for up to 60 seconds, plus 15
  stale, and "Hyperdrive does not purge or invalidate cached read query
  results when your application writes". Today's `deploy.md` and the
  `init` READMEs create the config without the flag. The session lookup,
  `findCredential`, is a plain read with no time function in it, so the
  cache can answer it: a token revoked or a session signed out may keep
  working for about a minute. Removing a member is not affected, because
  every request asks the vault, which today is a Durable Object, not a
  query. After this change the vault reads through Hyperdrive too, so as a
  second guard each vault read on Postgres carries the database clock,
  which Hyperdrive documents it never caches. Cloudflare's page says
  nothing about reads inside a transaction. This fix does not wait for the
  rest.
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
goes. They also get stricter, since a forged grant is now refused rather
than flagged:

| Check | Today | After |
|---|---|---|
| a grant written into the vault's store | verification flags it | the grantee's next reveal is refused as `tampered`, and verification flags it |
| an access change with the audit log refusing writes | not checked; the change commits in the vault (A01) | the change fails and changes nothing |
| an audit entry rewritten and re-chained with the run's chain key, behind a checkpoint | not checked; it would verify after the next checkpoint (F1) | the next Cron run's checkpoint is refused, and `/readyz` fails |
| an offboarded member's old rows put back | not checked | refused as `tampered` |
| the app's login on the vault's tables | no such tables | every read and write refused, on Postgres |
| the vault's login on its log | SQLite has no logins | insert only, on Postgres |
| both logs rewound | not checked | the admin's client reports it |

Workers conformance takes `--vault-runtime`, the vault's login, beside
`--runtime`.

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
4. `coffre verify`: both chains, the last checkpoint's signature, and the
   replay of members and grants from the vault's log. It passes, since
   everything is genuine as of T.
5. Reveal a canary secret.
6. Clients that saw past T report a rewind. After a restore that is
   expected: tell people, and each runs `coffre verify --accept-rewind`.

Everything after T is gone. Today the same drill needs the database and the
Durable Object restored to the same moment, and the Durable Object has no
copy outside Cloudflare.

**Docs.** `architecture.md`: the vault, its transports, where each secret
lives, databases. `deploy.md`: PlanetScale Postgres from start to finish,
and backups. `conformance.md`: the tampering checks, and its "what it does
not show", since a forged grant is now stopped. `keys.md`: a line on the
hierarchy. The roadmap: phase 1 items 2, 5 and 6 change shape. `AGENTS.md`
and the README's layout.

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

0. **Hyperdrive's cache off.** Independent; ship it first. `deploy.md`, the
   `init` READMEs and the examples' comments create every config with
   `--caching-disabled`, and say why. Verified by reading, and by
   `test:consumer`'s diff of `init`'s output.
1. **Access changes across two transactions** (app review A01). Intent
   entry and, for a removal, revocations first; the vault call; then the
   outcome entries and a second revocation. `audit_log.vault_seq`, unique.
   Recovery in the heartbeat and before each access change, asking the
   vault what it did with a request id, which needs a vault call for one
   principal's changes by request id. Works on today's vault, so it can
   land before step 2. Verified by the app review's A01 and A01b, ported:
   with the outcome append failing, a grant leaves an intent and gains its
   outcome at the next heartbeat; a removal leaves no live credential; and
   a conformance check, "no audit, no access change", where with the audit
   log refusing writes an access change fails and changes nothing.
2. **`@coffre/db`.** Move `packages/server/src/db` into a package: the
   schemas, migrations, `dialect.ts`, `portable.ts`, `connect.ts`, the
   Hyperdrive pool and the migrator. The server imports it by name, and
   `coffre-server migrate` delegates to it. Nothing else changes; the
   `identities` and `credentials` columns from #19 (A07, A08) move with the
   rest, so this step lands after #19 (`app-fixes`) or rebases onto it.
   Verified by the
   suite on all three engines, `db:check`, `check:pins` and
   `test:consumer`.
3. **The vault's tables in the baseline.** `vault_members`, `vault_grants`,
   `vault_log`, `vault_head` and `vault_checkpoints` in all three schemas.
   `vault_members` keeps the `generation` column #19 gives the vault's
   store. On Postgres, the `coffre_vault` role, a check that `coffre_vault_runtime`
   exists, the GRANTs, including each side's SELECT on the other log's
   `seq`, `prev_hash` and `hash`, and append-only triggers on both logs and
   the checkpoints. The same triggers on SQLite. Nothing uses the tables
   yet. Verified by the parity test, the baseline check, and `test:schema`
   extended: the app's login writes no `vault_*` table and reads only the
   vault log's hashes; the vault's login only inserts into its log and reads
   only the audit log's hashes. `scripts/ensure-postgres.sh` creates the new
   login.
4. **The vault on the shared database.** `store.ts` rewritten with Drizzle
   against `@coffre/db`. Decisions take the head lock first: pre-check,
   intent when the KEK is in KMS, keys with every call settled, decide with
   each key's outcome logged. A decision refuses whenever its pre-check did.
   The store keeps #19's generation: bumped on each removal, in the same
   transaction, and returned by `access()` as #19 defines it. `#serial`
   goes; the vault remembers the last head it saw and refuses if
   it goes backwards. Delete `sqlite.ts`, `sqlite-node.ts`,
   `sqlite-durable-object.ts` and the vault's `schema.ts`. Verified by
   `packages/vault/test` on three engines; a new test with two vault
   instances on one database, where parallel unwraps against a bulk limit
   of 10 allow exactly 10, a removal racing an unwrap never yields a key
   after the removal commits, and the chain verifies after both; and the
   review's R4 (a partial KMS failure leaves a record) and R6 (a second
   instance shares the log and the limit), ported.
5. **Row integrity.** The member MAC over the member's grants,
   `access_seq` and `generation`; the freshness check; the replay
   reproducing `generation` from the removals in the log; the `vault_head` MAC and last-entry check; the `tampered`
   refusal code in `@coffre/core`, worded on the pages and in the CLI; and
   `verifyLog` reporting MAC faults. Verified by unit tests for a grant
   forged, edited and deleted; an old member row and its grants put back;
   a generation edited back to an older value, and one restored with its
   genuine old row; the log's newest entries deleted without the head.
6. **Checkpoints that prove extension.** `checkpoint()` loses `previous`:
   the vault reads the audit log's hashes from its last signed head and
   signs only an extension. The heartbeat reads the vault log's hashes from
   its last recorded head and records only an extension. Full verification
   checks every signed and every recorded head. `/readyz` needs a recent
   checkpoint as well as a recent heartbeat. The app remembers the last
   audit head it wrote, as the vault does its own, and refuses to append
   behind it. Depends on steps 3 and 4.
   Verified by the review's R1 and R1b (a rewritten and re-chained log
   cannot get a new checkpoint signed or recorded) and R2 (a refused
   checkpoint turns readiness red), ported to the shared database.
7. **Transports and deployments.** Workers:
   `vault(env => ({ database: postgres(env.HYPERDRIVE), … }))`, and no
   Durable Object. Node: `serveVault({ database })` and
   `localVault({ database })`. The examples, `init`, `dev/deployment`,
   `dev/start.sh`, and the conformance harness (`--vault-runtime`, no
   `vaultStore`). Verified by `pnpm conformance:workers`,
   `pnpm conformance:node`, `test:consumer`, and a `pnpm dev` session that
   signs in and reveals.
8. **Stricter conformance.** The checks in "What it costs to get there" on
   the shared database, the login checks on Postgres, and a rewrite of the
   audit log behind a checkpoint that the next Cron run must refuse.
   Verified by both conformance runs, and by each new check failing against
   a vault with step 5 or 6 reverted.
9. **Witnesses.** Access changes return the vault's head.
   `GET /api/witness`. `@coffre/client` keeps and checks anchors; the CLI
   stores them with its credentials and the UI in `localStorage`.
   `coffre verify --accept-rewind`. Verified by unit tests, by the review's
   R7 rewritten to expect a witness that saw a cut entry to report it, and
   by a conformance check that rewinds both logs as the owner and expects
   the admin's client to report it. Depends on step 5 only, so it can run
   beside 6 to 8.
10. **Docs and the restore drill.** The docs listed in "What it costs to get
   there", with `architecture.md` no longer claiming the keyed chain
   protects the newest entries against removal (F8), and a runbook for
   PlanetScale Postgres. Verified by running the drill on a PlanetScale
   branch: restore, set the passwords, repoint Hyperdrive, `coffre verify`,
   reveal a canary.
11. **Later.** The Worker on MySQL through Hyperdrive (`mysql2`,
    `disableEval`); the GRANT and trigger script for self-hosted MySQL;
    checkpoints to R2 behind a retention lock.

## For Erwin to decide

1. Keep the vault a separate Worker and process, with its own login?
   Recommended: yes. A compromised app then gets logged reads, not the KEK.
2. Host erwinkn.com on PlanetScale Postgres? Recommended: yes. Roles,
   triggers and point-in-time recovery from $5 a month; PlanetScale MySQL
   has none of them.
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
9. Bring back `@coffre/db`, and write the vault's store with Drizzle?
   Recommended: yes. Two packages now share the schema.
10. Ship the Hyperdrive caching fix before all of this? Recommended: yes.
11. Let each side's login read the other log's hashes, so the vault checks a
    checkpoint's extension before signing it and the app before recording
    it? Recommended: yes. It replaces the caller's word with a check
    against the database (F1), and exposes hashes only.
12. With a KEK in KMS, log the intent before calling KMS, at the price of a
    second short transaction per call? Recommended: yes. It keeps the vault
    log and CloudTrail in step through a partial outage (F5), and costs a
    local KEK nothing.
13. Keep the vault separate even though an access change then spans two
    transactions, ordered so that a failure leaves less access and the
    app's record is retried until it lands? Recommended: yes. One
    transaction is what merging buys (A01); the KEK in the app's bundle is
    what it costs.
14. Accept that the database owner can cut up to five minutes off the end
    of either log, caught only by a witness or a vault instance that saw
    it? Recommended: yes, with readiness counting checkpoints (F3) so the
    five minutes hold. Closing it means anchoring every append outside the
    database.

## Appendix A: spikes

Run on 2026-10-01 against the repository's Postgres 16.14 (`:55432`) and
MySQL 8.4.11 (`:53306`), each in a database and logins of its own, dropped
after. The scripts are not committed. They called the head row's table
`vault_log_head`; this document calls it `vault_head`.

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

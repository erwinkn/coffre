# One database

A design for running coffre on a single Postgres or MySQL database: the
vault's tables, one member directory and one audit log that both the app and
the vault write. It says what the second store buys today, how much of that
one database can keep, what it costs, and what is left to decide. Written on
2026-10-01. Nothing here is built yet apart from step 0 (#22).

Already settled: two Workers, with server rendering kept; one database; one
log; `@coffre/db`. This version folds in three reviews of that day. The
security reviews of keys and integrity (F) and of the app (A) found problems
the design has to answer. A storage review (S) looked for what one database
lets coffre merge, and most of its proposals are taken; "What the reviews
change" says where each lands. Erwin backs the storage review's core: one
event format, one directory, checkpoints as events, and the transaction
rules.

## In short

- **Two writers, one database.** The vault keeps its own Worker, its own
  login and the KEK, and stays the only writer of members and grants. The
  app writes everything else. Each reads what it needs of the other's rows.
- **One member directory, owned by the vault.** The app's `principals` and
  the vault's `principals` merge into `vault_members`. A removal bumps the
  member's generation, and every session, token, linked account and device
  approval issued under an older generation stops working, whether or not
  the app ever touches its row.
- **One audit log, two authors.** Every event, the app's and the vault's,
  goes into `audit_log` under one lock. Each entry carries an HMAC under its
  author's key, and a public SHA-256 chain commits to every entry and every
  MAC. Neither author can rewrite an entry once the other has written after
  it. Each event is recorded once, by whoever decided it: a read is the
  vault's key release; a grant or removal is the vault's entry, committed
  with the change.
- **Checkpoints are signed vault entries, and readiness is a query.** The
  vault signs a prefix of the log every five minutes; `audit_heartbeat`, the
  vault's checkpoints table and review F1's caller-supplied claims go.
- **No app transaction stays open across a vault call.** That one rule
  keeps the two writers from waiting on each other, on Postgres, MySQL and
  a shared SQLite file alike.
- **The app can no longer mint a session from the database alone.** The
  security fields of identities, credentials and device approvals carry a
  MAC under a key derived from the app's.
- **One data key per secret version, wrapped directly by the KEK, as
  today.** Intermediate keys would save KMS calls that cost about a dollar a
  month, and would cost CloudTrail its record of which secret was read.
- **Rollback is caught by witnesses.** A member's old rows put back are
  refused, because the log holds the later change. A rewind of the whole
  database, or its newest entries cut off with the head put back, is seen
  only by a client or a process that saw past it.
- **Host on PlanetScale Postgres.** SQL roles, row-level security,
  triggers and two days of point-in-time recovery, from $5 a month.
  PlanetScale MySQL has none of them, so coffre's guarantees there rest on
  its keys alone.
- **Seventeen tables and two migration ledgers become thirteen and one.**

## What the second store buys today

| | App, Worker `coffre` | Vault, Worker `coffre-vault` |
|---|---|---|
| Keys it holds | `auditChainKey` | the KEK, `signingKey` |
| What it stores | projects, ciphertext and wrapped data keys, a member directory, sessions, syncs, the audit log | members' status and owner flag, grants, its own log, checkpoints |
| Where | Postgres through Hyperdrive; on Node, Postgres, MySQL or SQLite | a Durable Object's SQLite; on Node, a SQLite file |

Say Mallory gets the database password, or the account that hosts the
database. Today:

1. She reads ciphertext and wrapped keys, and opens none of them. The KEK
   is a Worker secret.
2. She cannot give herself access. Members and grants live in the Durable
   Object, which only the vault's code can write.
3. She cannot quietly edit the audit log. Its chain is keyed with
   `auditChainKey`, and the vault signs its head every five minutes.
4. She can mint a session, though: insert a credential row whose token she
   knows, for an existing member, and use the API as them. Both security
   reviews note it.

One database keeps the first and the third, and the design closes the
fourth. It weakens the second: the vault's rows sit where the owner's
login reaches. On Postgres the app's runtime login still cannot write them;
the owner and engines without logins are different threats. The rest of
this document is about getting as much of the second back as possible.

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
  │ written by the app          │ written by both          │ written by the vault │
  │ projects, environments,     │ audit_log, under each    │ vault_members,       │
  │ secrets, secret_versions,   │ author's MAC             │ vault_grants         │
  │ identities, credentials,    │ audit_chain_head, the    │                      │
  │ device_authorizations,      │ one lock                 │ read by the app      │
  │ syncs, sync_keys            │                          │                      │
  └────────────────────────────────────────────────────────────────────────────┘
```

The target schema, one line per table. "Reads" means the component's
database login; what each API caller may see is still the server's rule.

| Table | Holds | Writes | Reads |
|---|---|---|---|
| `projects` | id, slug, name, archive state | app | app, vault |
| `environments` | id, project, slug, name, archive state | app | app, vault |
| `secrets` | id, environment, key, current version, archive state | app | app, vault |
| `secret_versions` | one immutable envelope per version: ciphertext, wrapped data key, KEK labels | app, append only | app, vault |
| `vault_members` | the one directory: principal, created, status, owner, status changed, `generation`, `access_seq`, `mac` | vault | app, vault |
| `vault_grants` | principal, exactly one of project or environment, role, expiry, granted | vault | app, vault |
| `audit_log` | every event of both authors, with its MAC and chain hash | app and vault, each its own author, append only | app, vault |
| `audit_chain_head` | the one row every append and every vault decision locks | app, vault | app, vault |
| `identities` | a provider account bound to a member: provider, `issuer_hash`, subject, generation, `auth_mac` | app | app |
| `credentials` | hashed browser, CLI and service tokens, with generation and `auth_mac` | app | app |
| `device_authorizations` | a `coffre login` approval, with generation and `auth_mac` | app | app |
| `syncs` | a sync's configuration, source, credential secret and lease | app | app, vault |
| `sync_keys` | what each destination accepted, and so what coffre may delete there | app | app |

Today there are thirteen app tables and four vault tables, with a migration
ledger each; after, thirteen tables and Drizzle's one ledger. Gone:
the app's `principals`, `audit_heartbeat`, and the vault's `principals`,
`grants`, `log` and `checkpoints`, along with the earlier drafts'
`vault_head` and `place_id`. Nothing new is added: no sessions table, no
sync-runs table, no separate table of wrapped keys.

### Mallory, after

With PlanetScale Postgres and the logins of question 4:

| Mallory has | She can | She cannot | What catches her |
|---|---|---|---|
| The app's login, `coffre_runtime` | read ciphertext, members, grants and the log | open a value without the vault; write a member, a grant or a vault entry; change or delete any entry; mint a session, which needs the app's key for its MAC | nothing is left to catch. Putting back a genuine old row, say a session from before its user signed out, is the one thing her login allows; a removal's generation still kills it |
| The owner login, PlanetScale's default role | anything in the database, row-level security and triggers included | open a value: no KEK. Forge a grant, a session or an entry: no key | a forged or edited row: refused at its next use. A member's old rows put back: refused, since the log holds the later change. The newest entries cut off with the head put back, or the whole database rewound: only a witness or a process that saw past that point |
| `auditChainKey` and the owner's login | rewrite the app's entries since the vault's last entry; mint sessions | rewrite anything a vault entry follows; grant access | the vault's next entry anchors what it finds; in use that is seconds later. Every value opened is still a vault entry under the member she plays |
| The PlanetScale account | the owner's powers, and restore a backup to a new branch | make coffre use that branch without the Cloudflare account | as for the owner |
| The Cloudflare account | deploy code that reads the KEK | | nothing coffre can do, as today |

### What the reviews change

| Finding | What it showed | Where the design answers it |
|---|---|---|
| F1, high | A checkpoint takes the caller's word that it extends the last one, and verification checks only the newest | Question 6: the vault reads the log itself and signs a prefix; full verification keeps every signed prefix. Plan step 6 |
| F2, high | A second Durable Object loads the same KEK with an empty log and a fresh bulk counter | Question 2: no Durable Object; every instance decides under one database lock. Until then #21 refuses any object but the canonical one. Plan step 4 |
| F3, medium | A refused checkpoint leaves `/readyz` green | Fixed by #21; in the design, readiness is a query that needs a heartbeat and a checkpoint covering it. Plan step 6 |
| F4, medium | Verification misses sequence gaps at batch boundaries | Fixed by #21; one chain keeps that check from the first entry. Plan step 3 |
| F5, medium | A KMS failure halfway through a batch leaves no vault record of the keys KMS did open | Question 2: intent before KMS, every call settled, each key's outcome logged. Plan step 4 |
| F6, F9 | The canary scan missed binary columns; a missing vault store skipped the tamper check | Fixed by #21; conformance keeps both on the one database. Plan step 9 |
| F8, low | The database owner can cut the newest entries off the log and put its head back | Question 7: caught by witnesses and process memory only. #21 states the limit in `architecture.md`. Plan step 11 |
| A01, high | The vault commits an access change before the app's audit append; if that fails, the change is live with no app entry, and a half-done removal revives old sessions | Questions 5 and 6: the vault's entry, committed with the change, is the record, and a removal's generation is the revocation. Plan steps 4 and 6 |
| A07, A08, fixed by #23 | An account binding survives a change of its provider's issuer; linking can race offboarding and survive re-admission | #23 added `issuer_hash` and generations, which the target schema keeps and question 5 builds on. Plan steps 4 and 7 |
| S1 to S12 | The storage review's twelve proposals | Taken: one event format (S1), one directory (S2), listings as reads (S3), checkpoints as events (S4), grant scope as one foreign key (S5), MACs on auth rows (S6), one clock and operation id (S9), one storage package (S10), constraints and indexes (S11), transaction boundaries (S12). Later and not blocking: the current-version pointer (S7) and sync results as events (S8). Plan step 12 |

## The decisions

### 1. The vault stays a separate component

Settled by Erwin: two Workers, with server rendering kept. The reasons, for
the record:

| | (a) Separate | (b) Merged into the app |
|---|---|---|
| Code that can read `env.KEK` | the vault's: `@coffre/core`, `@coffre/vault`, `@coffre/db`, Drizzle, `pg` | every module in the app Worker: the server, the sync providers, TanStack Start, React, and the UI's three libraries, which alone bring about 75 packages. Any module can `import { env } from 'cloudflare:workers'` |
| What a bug or a malicious dependency in the app gets | values, by asking the vault as some member: each logged under the vault's key, capped by the bulk limit, refused for removed members, and in CloudTrail with KMS | the KEK. With any copy of the database, past or future, that opens every value offline, and no log ever hears of it |
| An access change and its record | one transaction, the vault's | one transaction |
| Cost of a vault call | a service binding: per Cloudflare, "zero overhead", both Workers on the same thread by default | none |

Review A01 showed what (b) used to have over (a): one transaction for an
access change and its record. With one log, the vault writes that record
itself, so (a) has it too.

### 2. Transactions, locks and serialised decisions

The Durable Object runs one call at a time, and each decision is a
synchronous SQLite transaction. Once several vault isolates or processes
share one database, the serialising moves into the database: every
transaction that appends to the log, the app's and the vault's, locks
`audit_chain_head` first. A vault decision looks like this:

```
unwrap(user:ada@acme.example, operation 7f3c…, 50 secret version ids)

1. pre-check   read Ada's member row and grants, her recent releases,   no lock, one round trip
               and the 50 versions' wrapped keys; refused? skip to 4
2. intent      with KMS only: BEGIN; lock the head; append one
               key.intent entry naming the operation and its 50 keys; COMMIT
3. keys        50 KMS Decrypts, or 50 local unwraps;                    no transaction open
               every call settles before step 4
4. decide      BEGIN
               SELECT next_seq, head_hash FROM audit_chain_head
                 WHERE only_row FOR UPDATE                              every append queues here
               read the database clock; read Ada's rows again;
               check the MAC, freshness, generation, bulk limit
               INSERT 50 key.unwrap entries, each with its outcome; UPDATE the head
               COMMIT, and only then hand back the keys                 about five round trips
```

The app now sends version ids rather than wrapped keys, and the vault reads
the envelopes itself (review S3): the version it records is a row it
checked, not a label the app supplied. Advisory locks are out: Hyperdrive
does not support them on Postgres, and MySQL's `GET_LOCK` pins the session
to a reserved connection under Vitess.

**Four rules.** Each one comes from a spike or a review probe.

1. **No app transaction stays open across a vault call.** Today `audited()`
   opens a transaction, calls the vault inside it, then appends. With one
   database that fails three ways. On a shared SQLite file, the app's
   transaction holds the file's write lock, so the vault's own transaction
   fails with `database is locked` (S12's probe). On Postgres or MySQL, an
   app transaction holding the head makes the vault wait for it while it
   waits for the vault, and Postgres reports no deadlock, since it sees one
   waiter; in the spike the vault timed out after 2 s. And a vault entry
   naming a row the app has not committed fails its foreign key at once on
   Postgres, and waits until the lock times out on MySQL (spike B). So every
   flow reads, calls the vault, and only then opens its short transaction.
2. **The head is the first lock, and nothing reads before it.** Every
   appending transaction, the app's included, locks the head before any row.
   On MySQL at REPEATABLE READ, PlanetScale's default and what a Hyperdrive
   connection falls back to, a plain read before the lock fixes the
   snapshot, and reads after it miss what committed during the wait: the
   spike saw 0 grants instead of 1.
3. **Time is read after the lock.** Postgres's `CURRENT_TIMESTAMP` is the
   transaction's start, so a transaction that waited on the head would date
   its entry before an earlier one's (S9's probe). The append reads
   `clock_timestamp()`, or the engine's equivalent, in a statement after the
   lock.
4. **Postgres runs at READ COMMITTED, its default.** At REPEATABLE READ a
   transaction whose snapshot predates a concurrent commit fails its
   `FOR UPDATE` with `40001 could not serialize access`.

The flows that follow from rule 1:

| Flow | Order |
|---|---|
| Reveal, `coffre run`, import preview | read committed versions; the vault decides and logs each key's release; the keys leave only after its commit; the app decrypts and answers |
| Write, restore | prepare ids, context and the expected next versions; the vault wraps or rewraps; one short app transaction locks the head, then the secrets, checks the expected versions and archive state, and inserts the versions with their write entries. A conflict throws the wrapped keys away and retries as a new operation |
| A new secret | its id is chosen before the wrap; the vault's wrap entry names it in its payload, since the row does not exist yet, and the app's write entry points back at it |
| Grant, admission, removal | one vault transaction: the rows, the generation, the entry |
| Sign-in, linking an account, approving a device | `access()` gives the member's generation first; one app transaction locks the head, reads the member again, refuses if the generation moved, then issues or binds and logs |
| Sync | the lease in one short transaction; the vault authorises and releases; the result in another. A new sync is committed disabled, its principal is granted, then it is enabled |
| Heartbeat | the app's heartbeat entry commits; then the vault checkpoints |

What this keeps:

- **A refused call never reaches KMS.** The pre-check comes first, as
  `#mayAll` does today.
- **A decision sees every change committed before it.** In the spike, a
  transaction that waited on the head row and then read the grants saw a
  grant committed while it waited, on Postgres at READ COMMITTED and on
  MySQL at both levels.
- **The bulk limit is exact,** counted under the lock from the vault's own
  `key.unwrap` entries: one per released key, syncs and import previews
  included, intents and refusals not.
- **Every instance shares one log and one set of limits.** Review F2 showed
  a second Durable Object loading the same KEK with an empty log and a fresh
  bulk counter. `#serial` orders the calls of one isolate, which only the
  Durable Object made the only one. Here every isolate and process decides
  under the database's lock, and `#serial` goes. What an instance remembers,
  such as the last head it saw, can only add a refusal.
- **A removal that commits before the vault's final check stops the
  release.** One that commits after cannot recall a key already handed to
  the app; that is the honest point at which a release happened.

KMS stays outside the transaction. A lock held across 50 Decrypts, with a
5-second timeout and three attempts each, would stall every append behind
KMS, hold a pooled connection the whole time (Hyperdrive has about 20 per
config on Free, 100 on Paid), and run into PlanetScale MySQL's 20-second
limit on transactions. The price is a race the Durable Object prevented: if
Bob removes Ada between steps 1 and 4, KMS has already opened her keys, and
step 4 refuses, logs them as opened and withheld, and zeroes them.
CloudTrail then shows Decrypts the vault refused, and the log pairs them.
The reverse race needs a fix: if the pre-check refused, the decision refuses
too, even if a grant arrived in between, rather than answer `ok` with no
keys as today's code would.

Review F5 showed a KMS outage halfway through a batch leaving no record of
the Decrypts that succeeded. With KMS, the vault records its intent first
(step 2), lets every started call settle (`Promise.allSettled`), and logs
each key's outcome: released, refused, opened and withheld, or KMS
unavailable. The call still fails as an outage and returns no key, but
only after the log says what KMS opened. A local KEK skips step 2, since an
unwrap in memory leaves nothing outside to reconcile; Erwin's deployment
pays nothing. `wrap` and `rewrap` follow the same steps.

**Throughput.** One head for both authors is one queue. The spike simulated
5 ms per round trip, each append holding the lock for about four:

| Writers at once | One head, both authors | Two heads, one per author |
|---|---|---|
| 1 | 40 appends a second | |
| 8 | 52 a second, waiting 133 ms at the median | 108 a second, waiting 50 ms |
| 32 | 59 a second, waiting 587 ms at the median | 113 a second, waiting 274 ms |

So one log halves the ceiling, to about 50 appends a second, and taking the
head first holds it a little longer in the app's transactions. Each event
is now appended once, which gives some back: a `coffre run` of 50 keys is
one append where today it is one in each log. erwinkn.com, or a team of
fifty, is two orders of magnitude below. Folding the insert and the head
update into one statement, which Postgres allows, would take a round trip
off every append if it were ever needed.

`access(principal)`, which the app asks once per request, takes no lock: one
read of the member, the grants and the freshness check. On SQLite every
transaction begins `IMMEDIATE` and holds the database's write lock, so the
head lock does nothing there, as `forUpdate` already arranges; two Node
processes on one file rely on SQLite's file lock, which the tests must
exercise with two processes, not two clients of one.

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
needs migrating. The wrapped key stays in its version's row, beside the
ciphertext: a separate table of wrapped keys would add a join and hide
nothing from the app.

### 4. Integrity on each engine

Seven guards, outermost first. The first three come from the database and
depend on the engine. The other four come from keys and hold everywhere.

1. **Logins.** The app's login reads members and grants and never writes
   them. The vault's login writes members and grants, reads the projects,
   environments, secrets and versions it decides on, and nothing else of the
   app's. Both read and append to the log and move its head; neither may
   change or delete an entry. The app no longer needs today's artificial
   `UPDATE (created_by)` on `principals`, kept only so it could lock a row:
   it serialises on the head instead. In the spikes every forbidden
   statement failed with `42501` on Postgres and
   `ER_TABLEACCESS_DENIED_ERROR` on MySQL.
2. **Row-level security** on `audit_log` lets each login insert only its
   own author's entries: `WITH CHECK (author = 'app')` for one, `'vault'`
   for the other. In the spike, each login's attempt to write the other's
   entry failed with `42501`. The table's owner bypasses it, as owners do.
3. **Triggers** refuse UPDATE, DELETE and TRUNCATE on `audit_log`, for every
   login, the owner's too. They stop bugs and a careless owner, not a
   determined one: on Postgres the owner can `DISABLE TRIGGER`, and on MySQL
   `TRUNCATE` skips delete triggers. The spike did both.
4. **A MAC over each member's access.** Each `vault_members` row carries an
   HMAC, under `HKDF(signingKey, "coffre.vault.rows")`, over every field that
   bears on access, `generation` and `access_seq` included, and over that
   member's grants as a sorted set, lapsed ones included. A grant inserted,
   edited or deleted under a member fails it, and the vault refuses that
   member as `tampered` and logs it. One MAC per member rather than one per
   row catches deletions too, and costs a decision one check.
5. **A MAC over each sign-in row** (S6). Identities, credentials and device
   approvals carry an `auth_mac` under a key derived from `auditChainKey`,
   over the fields that confer authority: for a credential, its token hash,
   kind, principal, generation, linked identity, expiry and revocation; for
   an identity, its provider, `issuer_hash`, subject, principal, generation
   and revocation; for a device approval, its code hash, decision,
   principal, generation, expiry and consumption. The app checks it before
   it trusts the row. A database writer can no longer mint a session; she
   can only put back a genuine old row, which its generation then decides.
6. **The log's MACs and public chain.** Each entry carries an HMAC under its
   author's key, and a SHA-256 chain commits to every entry and every MAC
   (question 6). Every append also checks that the head names the log's last
   entry, so the newest entries deleted without the head fail the next
   append.
7. **Signed checkpoints and witnesses** (questions 6 and 7).

What each engine allows. Sources are in appendix B.

| | PlanetScale Postgres | Postgres, self-hosted | MySQL, self-hosted | PlanetScale MySQL | SQLite |
|---|---|---|---|---|---|
| Logins with table-level GRANTs | yes, `CREATE ROLE` in SQL | yes | yes, `CREATE USER` | no: four fixed roles per password, each database-wide | no logins |
| Each login writes only its author | yes, row-level security | yes | a trigger on `CURRENT_USER()`, in an optional script | no | no |
| Append-only triggers | yes | yes | yes, except against `TRUNCATE` | no: "We do not support any form of stored routines" | yes |
| `SELECT … FOR UPDATE` | yes | yes | yes | yes, in transactions of at most 20 s | not needed |
| Guards 4 to 7 | yes | yes | yes | yes | yes |
| Point-in-time recovery | yes, 2 days by default | your own | your own | no: a backup every 12 hours | copies of the file |

Without guards 1 to 3, on PlanetScale MySQL and SQLite, the app's login can
write the vault's rows and entries in the vault's name. Guards 4 to 7 still
refuse a forged grant or session and expose a forged or edited entry. What
they cannot stop there: deleting a member's grants, which the vault then
refuses as `tampered`, a denial of service; deleting the vault's recent
releases to reset a bulk count, which breaks the chain and shows at the
next verification rather than at once; and rolling rows back (question 7).

On PlanetScale Postgres, the default role is not a superuser but has
`CREATEROLE`, `BYPASSRLS` and `pg_write_all_data`: treat it as the owner,
for migrations only. A role made in SQL logs in as `<role>.<branch id>`, and
a restore resets its password. On MySQL, coffre keeps one login and no
triggers by default, since PlanetScale MySQL allows neither; self-hosted
MySQL gets an optional script with the GRANTs and triggers.

### 5. The schema

The target is the table in "The proposal". What changes, and why:

**One directory** (S2). Today the app's `principals` is a directory and a
foreign-key target, the vault's `principals` decides membership, and
`members.ts` joins two separately fetched lists. Both become
`vault_members(principal, created_at, created_by, status, owner,
status_changed_at, status_changed_by, generation, access_seq, mac)`, written
by the vault alone. Principals are the canonical strings coffre already uses
at its edges, `user:<email>`, `token:<id>` and `sync:<id>`, so the
`service`-versus-`token` conversion leaves storage. The app's identities,
credentials and device approvals reference it by foreign key. Root admins
still come from the vault's configuration; the vault writes a member row for
each the first time it is asked about one, so the app has a row to point at,
and a row never makes anyone a root admin.

**Generations revoke** (S2, building on #23's fix for A08). A removal sets
`status`, clears `owner` and the grants, bumps `generation` and logs, in one
vault transaction. A re-admission keeps the bumped generation. A session,
token, linked account or device approval is live only if it is not revoked
or expired, its member is active, and its generation is the member's. So
nothing issued before a removal works after it, even if the app dies before
touching a row, and the app's sweep that stamps `revoked_at` becomes
housekeeping: it stamps only older generations, so it never revokes a new
session. A sign-in started under generation 7 carries 7 to its end and is
refused if the member is at 8 by then.

**Grants name exactly one place** (S5). `vault_grants(principal,
project_id NULL, environment_id NULL, role, expires_at, granted_at,
granted_by)`, with a check that exactly one of the two is set, a unique key
on each with the principal, and foreign keys to both. An environment grant
finds its project through `environments`. That replaces the partial unique
indexes of the vault's SQLite and the `place_id` of the earlier draft, and
the review's probes found it behaves the same on all three engines. It
belongs in the core change because the table is being created anyway.

**The sign-in tables** keep the shape #23 merged: `issuer_hash` binds an
identity to the authority that issued it, with uniqueness on provider,
`issuer_hash` and the active subject, and `generation` on all three. A fresh
baseline has no legacy rows, so both become NOT NULL. Each gains `auth_mac`
(question 4). Device approvals get an explicit state check: the current
`(decision = 'approved') = (principal_id IS NOT NULL)` lets a principal sit
on an undecided row, because a CHECK passes when its predicate is NULL
(S11's probe).

**One event shape.** The two logs' columns merge: `seq`, `author`,
`key_id`, `occurred_at`, `actor`, `action`, `decision` (`allow` or `deny`;
finer outcomes such as "opened and withheld" go in the payload), `code`,
`subject_principal`, `project_id`, `environment_id`, `secret_id`,
`secret_version_id`, `operation_id`, `request_id`, `source_ip`,
`related_seq`, `metadata`, `prev_hash`, `mac`, `hash`. `author` says which
component wrote the entry; `actor` says who acted. `operation_id` replaces
`bundle_id`: one id for a reveal batch, an access change, a write batch or a
sync run, carried through the vault call (S9). `audit_log.id` goes; an entry
is `seq` and `hash` within its instance.

**Foreign keys stay.** The earlier draft dropped the log's foreign keys,
because the vault wrote ids the app had not committed. With rule 1 of
question 2 it never does, apart from a new secret's wrap, which names the
id in its payload instead. So the log keeps its references to projects,
environments, secrets and versions, and "nothing audited can be deleted"
keeps its footing.

**One clock, one counter** (S9). Persisted times are integer milliseconds
from the database's clock, read after the lock; ISO strings only at the
API. That removes the microsecond string normalisation and keeps
engine-specific timestamp bytes out of the MACs. Sequence numbers are 64-bit
integers in SQL, `bigint` in TypeScript and decimal strings over JSON, from
0 for both authors.

**Constraints and indexes for the hot paths** (S11). The bulk count reads
`audit_log(author, actor, action, decision, occurred_at)`; the freshness
check `(author, subject_principal, seq)`; checkpoints and heartbeats
`(author, action, seq)`; audit pages page by `seq` within project,
environment, secret or actor; operations group by `(operation_id, seq)`.
Live sign-in rows by member use `(principal, generation)`. A credential's
linked identity must name the same member and generation, by a composite
foreign key. Owners must be users, removed members cannot be owners, and
roles and environment-assignable roles are checked against one catalogue
shared with the code. Two indexes that duplicate a unique key go. The list
gets checked against query plans on representative history before
anything optional stays.

**One package** (S10, settled). `@coffre/db` holds the three Drizzle
schemas, the migrations, `dialect.ts`, `portable.ts`, `connect.ts`, the
Hyperdrive pool, the event codec's storage half and the append, moved out of
`packages/server/src/db`. PR #8 folded `packages/db` into the server because
the server was its one user; the vault is a second. Queries stay with their
owners. The vault's SQLite interface, its two backends and its hand-written
migrations go, and its store is rewritten with Drizzle, which undoes #9's
"without Drizzle" for the reason the app uses it. `coffre-server migrate`
stays the one command; runtime Workers never migrate. The three physical
schemas stay, with the parity test made to compare CHECK predicates and
index semantics, not only names.

**Migrations.** No deployment exists yet, so every change here goes into
the baselines, regenerated by `pnpm db:generate`, and no history is
converted. PlanetScale Postgres takes plain DDL as the owner, on the direct
port 5432. PlanetScale MySQL's deploy requests, and the journal and seed
rows they would need to carry, wait until a MySQL deployment exists. Once
deployments exist, the two Workers deploy one after the other after the
migration, so a migration must work with the code before and after it.

### 6. One log, two authors

Today the app and the vault each keep a log, each chained under its own
key, and every five minutes the vault signs both heads so each log anchors
the other. Review F1 broke that: the vault signs a head on the app's word
that it extends the last one, and verification looks only at the newest
signature, so whoever holds `auditChainKey` can rewrite checkpointed
history and verify green again. With one database the simpler shape is one
log that both write.

**The format.** Two drafts met here. The earlier one MACed the hash:
`hash = SHA-256(prev_hash ‖ entry)`, `mac = HMAC(key, hash)`. The storage
review MACs the fields and hashes the MAC:

```
fields = canonical(seq, author, key_id, occurred_at, actor, action, decision, …, metadata)
mac    = HMAC(key of the entry's author, "coffre.audit.mac.v2"   ‖ prev_hash ‖ fields)
hash   = SHA-256(                         "coffre.audit.chain.v2" ‖ prev_hash ‖ fields ‖ mac)
```

I take the review's. Both stop an author from rewriting an entry the other
has written after, since each MAC covers the previous hash. The difference
is what the public chain commits to. In the earlier draft the chain covered
the contents but not the MACs, so an owner could replace a MAC without
moving any hash, and only a keyholder would notice. In this one the chain
covers every byte, MACs included, so a signed checkpoint pins a prefix
exactly, and a client or an auditor with only the vault's public key can
check a copy of it. The domain tags keep the two uses of the same inputs
apart, and the cost is the same: one HMAC and one SHA-256 per entry, both
after reading the head. The fields use a length-prefixed encoding that tells
null from empty. The format is `coffre.audit.v2`, and its test vectors live
in `@coffre/core` as one JSON file: entries with their keys, MACs and hashes,
covering nulls, empty strings, non-ASCII text, sequence numbers past 2^53 and
both authors. The app's tests, the vault's tests and conformance's verifier
all run them.

```
41  app    secret.write   market/prod/DB_URL  by ada   mac under auditChainKey
42  vault  key.wrap       market/prod/DB_URL  for ada  mac under the vault's key
43  app    project.update market              by bob   mac under auditChainKey
```

Say Mallory holds `auditChainKey` and the owner's login, and rewrites
entry 41. She can make its new MAC and hash. But entry 42's MAC covers entry
41's old hash: either 42 keeps it and the chain breaks there, or 42 takes
the new one and needs a MAC under the vault's key, which she cannot make. So
each author can rewrite only its own entries since the other's last one:

| Holds | Can rewrite | Cannot |
|---|---|---|
| the owner's login, no key | nothing; can cut the newest entries off and put the head back (F8) | change, insert or remove an entry the next one depends on |
| `auditChainKey` and the owner's login | the app's entries since the vault's last entry | anything a vault entry follows |
| the vault's key and the owner's login | the vault's entries since the app's last entry | anything an app entry follows |
| both keys | everything, as today | |

The vault writes an entry with every key release, wrap and access change,
so in use those windows are seconds long; the Cron's checkpoint closes them
when nobody uses coffre.

**Each event is recorded once, by whoever decided it.**

| Event | Recorded by | Instead of |
|---|---|---|
| A value read: a reveal, a `coffre run`, an import preview, a sync | the vault's `key.unwrap`, one per version, with the operation, purpose, source address and path the app supplied, before the key leaves | the app's `secret.read` and the vault's `unwrap`, both |
| A value written or restored | the vault's `key.wrap` or `key.rewrap`, and the app's `secret.write` or `secret.restore` in the transaction that stores the version, pointing at the wrap by `related_seq` | both, as today: a wrapped key does not prove a version was stored |
| A grant, an admission, a removal | the vault's entry, committed with the change | the app's copy and the vault's entry |
| A refusal by the vault | the vault's entry | the app's `vault_<code>` copy |
| A refusal by the app, before any vault call | the app's entry | unchanged |
| A sync's push | the vault's release to `sync:<id>`, and the app's `sync.push` naming the destination | unchanged |

A release means the app could decrypt, not that a person saw the answer: an
error or a dropped connection may follow. That is the conservative account,
and the fact the vault can prove. The context the app passes is its claim,
recorded as such, as the vault records the principal today.

**Access changes** (A01). The vault's entry is the record, in the
transaction that changes the member or the grant, so nothing can commit
without it. A removal's generation bump is the revocation (question 5), so
the app's clean-up of sessions afterwards cannot fail in a way that leaves
access. The intent entries, the `vault_seq` column and the recovery job of
the first draft are gone. A lost response is ordinary uncertainty, and a
retried grant is never replayed over a later change.

**Listings become reads** (S3). The app may read members, grants and the
log, so the vault calls that only fetched stored rows become queries:

| Vault call today | After |
|---|---|
| `members()`, for the users and access pages | one query joining members, grants, identities and credentials; root admins' labels come from the vault's configuration |
| `log()`, a page of the vault's log | the ordinary audit query, with an author filter |
| `latestCheckpoint()` | the newest checkpoint entry, its signature checked against the vault's public key, which comes from the vault, not the database |
| `access(principal)`, deciding a request | stays a vault call: the app cannot check the member MAC, and a plain row is fine to display, not to authorise |
| `verify`, `checkpoint`, `admit`, `remove`, `setAccess`, `wrap`, `unwrap`, `rewrap` | stay: signing, mutation and key decisions; `unwrap` and `rewrap` now take version ids |

The audit page keeps today's rules for what each reader sees: project
auditors see the reads and grants in their projects, now vault entries;
membership events and diagnostic payloads stay with owners and root admins.

**What checkpoints keep** (S4). A checkpoint becomes a vault entry,
`audit.checkpoint`, with a signed payload: format, instance id, the `seq`
and `hash` of the last entry before it, the time, the key id and an Ed25519
signature. It signs a prefix that ends just before itself. Before writing
one, the vault reads the log: the previous checkpoint's prefix must still
end at the hash it signed, and every link since must hold, with its own
entries' MACs. Because each hash commits to everything before it, the
newest prefix still holding implies every older one does; full verification
checks them all anyway. Three jobs remain: anchoring quiet periods, giving
evidence anyone can check with the public key, and readiness. The
`vault_checkpoints` table, the app's `audit.checkpoint` copies and
`CheckpointInput.previous` go, and with them review F1's attack.

**Readiness is a query** (S4). `audit_heartbeat` goes. The Cron writes an
app `audit.heartbeat` entry, then asks the vault to checkpoint. `/readyz`
passes when the newest heartbeat is under 11 minutes old and a checkpoint
covers it, its MAC and signature checked. A heartbeat alone, a checkpoint
without a heartbeat, or a refused checkpoint all leave it red. A fresh
database is unready until the first pair.

**Verification** checks one prefix with both keys. The vault takes a
consistent snapshot, checks every link from 0, its own MACs, every
checkpoint, and replays members, grants and generations from its access
entries; it returns the `seq` and `hash` it reached. The app checks the
same prefix with its key. The verdict says "verified through 5170" and
names the entry where either check fails, and its author; entries appended
meanwhile are not a failure. Replay authenticates every entry it uses, so
an app entry that says `grant.create` never becomes a grant.

**A forged vault entry,** written by the app's login where nothing stops it
(PlanetScale MySQL, SQLite), fails its MAC. Verification reports it. The
vault checks the MAC of every vault entry it decides on, such as a member's
newest access entry, and ignores and reports one that fails, without
stopping: otherwise the app's login would hold a switch that turns coffre
off. A forged release can only raise a bulk count.

**The costs.** One lock for both writers, which halves the throughput
ceiling (question 2). One entry format for two packages, so a change to it
ships in both, under a new version. The app reads the vault's rows and
entries, which it displays anyway. And rule 1 of question 2 restructures
every flow that calls the vault today.

### 7. Rollback detection

Mallory has the owner's login and puts genuine old rows back. Three cases.

**One member's rows.** Ada was removed at entry 812. Mallory kept her
member row and grants from before and writes them back; their MAC is
genuine. The vault catches this at Ada's next decision, for free: her row
says its last access change was entry 640, and the log's newest vault
access entry about her, its MAC checked, is 812, so she is refused as
`tampered`. That is one indexed lookup in the read the decision makes
anyway. To get past it Mallory must take 812 out of the log, which breaks
the chain, unless it is recent enough to cut off with everything after it.

**The newest entries, cut off** (F8). Mallory saves the head, lets coffre
run, then deletes the entries since and puts the head back. She uses no
key, and what remains is genuine. A chain proves that what is kept is
authentic, not that nothing was cut from its end; #21 already says so in
`architecture.md`. If a cut entry changed a member, that member's row now
names an entry the log no longer has, and is refused, unless she rolls the
row back too, which is the next case. Otherwise only two things catch the
cut: an app or vault instance that wrote one of the cut entries and still
remembers the head it left, at its next append; and a witness that saw one.

**The whole database, rewound.** Every row, MAC and link is genuine as of
the moment Mallory restores. Nothing inside the database can tell,
checkpoints included, since they roll back with it. Today this takes the
database and the Durable Object; with one database it is one restore. The
Cron's five minutes are a cadence, not a bound on what an owner can
rewind.

| | What it catches | Cost | |
|---|---|---|---|
| Memory | a rewind while an app or vault instance is running: the head it last saw goes backwards | none | yes, plan steps 3 and 4 |
| Witnesses | a rewind past anything a person has seen | about 150 lines in `@coffre/client`, one route | yes, plan step 10 |
| Checkpoints off the box | a rewind past the last checkpoint copied out, with nobody looking | an R2 bucket with a retention lock, or S3 Object Lock on Node | later: roadmap item 5 |

**Witnesses.** A client remembers, per instance, the instance id, the newest
entry it has seen, as `seq` and `hash`, and the vault's public key, pinned
at `coffre login`. Checking that the number grows is not enough, since after
a rewind the log passes 812 again within minutes, so the client asks for the
hash at the number it remembers: `GET /api/witness?seq=812` answers with the
current entry's hash there and the newest checkpoint. A rewound log has a
different entry 812, or none. The CLI checks before a command, at most once
an hour, and keeps its anchor in `~/.coffre/credentials.json`; the browser
checks once per page load and keeps it in `localStorage`. Access changes
answer with the entry the vault wrote, so whoever removes Ada holds entry
812 at once. A legitimate restore looks exactly like an attack to a witness,
which is right; the restore drill ends with telling people, and
`coffre verify --accept-rewind`.

What stays invisible: a rewind to a moment after the last thing any witness
saw, before anyone looks again.

### 8. Node deployments

| | Today | After |
|---|---|---|
| The vault as its own process | `serveVault({ socket, store: 'vault.db', … })`, its own SQLite file | `serveVault({ socket, database: 'postgres://coffre_vault_runtime:…', … })` |
| The vault in the server's process | `localVault({ store, … })` | `localVault({ database, … })`, for tests and small setups; the example keeps two processes |
| The server | `serve({ database, vault: connectVault(socket), … })` | unchanged |
| The socket | HTTP over a Unix socket, `0660` | unchanged |
| Backups | the database and `vault.db`, taken at the same moment | the database |

On SQLite both processes open one file, and SQLite's file lock serialises
them, which is one more reason for rule 1 of question 2: an app transaction
held open across a vault call locks the vault out of the file. There are no
logins, so the separation between the tables rests on guards 4 to 7. The
vault's own SQLite layer (`sqlite.ts`, `sqlite-node.ts`,
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
to 3, has point-in-time recovery, costs less, and coffre's Worker already
speaks it. MySQL stays supported on Node, as today, with the integrity of
its column in question 4's table. Running the Worker on MySQL, and
PlanetScale MySQL's deploy requests, wait for a deployment that needs them.

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

**Conformance** stops comparing two logs and checks facts that commit (S12).
Today the tamper checks write the vault's store directly, `vault.db` on Node
or the Durable Object's file on Workers; they become SQL on the one
database, as its owner, and the store discovery goes. "Two logs agree"
expects every app read to match a vault unwrap, which a legitimate partial
failure breaks. It is replaced by these invariants:

1. Every value returned has a vault release entry for its version, under
   the response's operation, committed before the answer.
2. Every stored version has the app's write entry, in the same transaction,
   pointing at the vault's wrap. A wrapped key never used is visible as
   such, not as a write.
3. A grant or member change cannot commit when the log refuses writes, and
   a removal and re-admission revive no session, token, linked account or
   device approval, late callbacks included.
4. Two vault instances share the bulk limit and the generations exactly, on
   Postgres and MySQL connections and on two SQLite processes.
5. On Postgres, the app's login cannot write members, grants or a vault
   entry, nor change either author's entries.
6. Editing either author's entries, swapping an author, deleting an entry in
   the middle, or a gap at the first entry or a batch boundary fails
   verification; replay ignores app entries that name access actions.
7. A later checkpoint cannot hide a mismatch with an earlier one, and a
   refused checkpoint leaves readiness red.
8. A session, token, identity or device approval inserted by the database's
   owner is refused.
9. Every table is inspected through the one database, a missing one fails
   rather than skips, and binary columns are scanned as bytes with a planted
   canary, keeping #21's fixes for F6 and F9. The app review's regressions
   all carry over.

**The audit page and `coffre verify`.** The page's two panels, "App log"
and "Vault log", become one list with the author on each row and a filter
for it; `GET /api/audit/vault` goes. Verification says how far it got and
names the entry and author where it failed.

**The dev loop.** `pnpm dev` stops deleting the Durable Object's state: the
seed starts one database over, and the vault's rows go with it.
`scripts/ensure-postgres.sh` creates a second local login,
`coffre_vault_runtime`, and the vault Worker gets its own
`CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_*`.

**`coffre init`.** For Workers, `vault/wrangler.jsonc` loses
`durable_objects` and `migrations` and gains a `hyperdrive` binding;
`vault/src/worker.ts` passes `database: postgres(env.HYPERDRIVE)`; the
README's database step creates two logins and two Hyperdrive configs, both
without caching. For Node, `vault.env` trades `VAULT_STORE` for
`DATABASE_URL`, and the vault stays a process of its own in the example.
The examples follow, and the test that diffs them against `init`'s output
keeps the two in step.

**The restore drill.** Escrowed: the KEK, `SIGNING_KEY`, `AUDIT_CHAIN_KEY`
and the GitHub client secret, in Erwin's password manager, and access to
the PlanetScale account. Then:

1. Restore the database to a moment T, as a new branch
   (`pscale branch create … --restore-point`).
2. Set the passwords of `coffre_runtime` and `coffre_vault_runtime` again;
   the restore reset them.
3. Point both Hyperdrive configs at the new branch
   (`wrangler hyperdrive update`).
4. `coffre verify`: every link, both authors' MACs, every checkpoint, the
   replay. It passes through the last entry before T.
5. Reveal a canary secret.
6. Clients that saw past T report a rewind. After a restore that is
   expected: tell people, and each runs `coffre verify --accept-rewind`.

Today the same drill needs the database and the Durable Object restored to
the same moment, and the Durable Object has no copy outside Cloudflare.

**Docs.** `architecture.md`: the vault, its transports, where each secret
lives, checkpoints (now a section on the one log), databases, keeping #21's
statement of the chain's limits. The README's "There is no delete" and its
layout. `deploy.md`: PlanetScale Postgres from start to finish, and
backups. `conformance.md`: the new invariants. `keys.md`: a line on the
hierarchy. The roadmap: phase 1 items 2, 5 and 6 change shape. `AGENTS.md`.

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

Each step is one pull request for one agent, from `main`, in this order
unless it says otherwise. "The suite" means `pnpm test:all`,
`pnpm typecheck`, `pnpm lint` and `pnpm test:schema`. Steps 1 to 11 are the
core change; step 12 lists what can follow without blocking it.

0. **Hyperdrive's cache off.** Shipped as #22.
1. **No app transaction across a vault call** (S12). On today's vault:
   reveals read, then call the vault; writes and restores
   prepare, wrap, then store in one short transaction that checks the
   expected versions and retries as a new operation on conflict; a new
   secret's id is chosen before its wrap; access and member changes call the
   vault outside any transaction; a new sync is committed disabled, granted,
   then enabled. Verified by the suite, a test that fails any vault call
   made while an app transaction is open, and #23's A08 regressions.
2. **`@coffre/db`** (S10). Move `packages/server/src/db` into a package; the
   server imports it by name and `coffre-server migrate` delegates to it.
   Nothing else changes. Verified by the suite on all three engines,
   `db:check`, `check:pins` and `test:consumer`.
3. **The log's v2 format, written by the app alone** (S1, S9, S11). The
   codec and its test vectors in `@coffre/core`; the append in `@coffre/db`,
   which locks the head first, checks that it names the last entry and
   reads the clock after the lock. New columns, integer milliseconds,
   `operation_id` for `bundle_id`, `related_seq`, no `audit_log.id`, the
   paging indexes; append-only triggers on Postgres and SQLite. The app
   remembers the last head it saw. Verification checks every link, the
   numbers from 0 and the app's MACs. Verified by the vectors, the suite and
   #21's sequence tests.
4. **The vault on the shared database, owning the directory** (S2, S3, S5,
   F2, F5). `vault_members`, which replaces both `principals` tables, and
   `vault_grants` with one foreign key per grant; canonical principals; the
   sign-in tables pointing at `vault_members`, with #23's columns made NOT
   NULL. On Postgres, the `coffre_vault` role, the GRANTs and row-level
   security per author. The vault's store rewritten with Drizzle, appending
   v2 entries under its key; decisions take the head first, with KMS intent,
   settled calls and per-key outcomes; removals bump the generation;
   root admins get member rows; sign-in, linking and device approval
   serialise on the head and compare generations; `unwrap` and `rewrap`
   take version ids; `#serial` goes, and the vault remembers the last head
   it saw. Delete the vault's SQLite layer and its migrations. Verified by
   the vault's tests on three engines; two vault instances, and two SQLite
   processes, sharing the bulk limit and generations exactly; the review's
   R4 and R6; and #23's A08 regressions.
5. **Member integrity.** The member MAC over the member's grants,
   `generation` and `access_seq`; the freshness check against the newest
   authenticated access entry; the `tampered` refusal code, worded on the
   pages and in the CLI; forged vault entries ignored and reported.
   Verified by tests for a grant forged, edited and deleted; old member rows
   put back; a generation edited back, or restored with its row; a vault
   entry forged by the app's login.
6. **One record per event, checkpoints and readiness** (S1, S3, S4). Reads
   and access changes recorded by the vault alone; the app's duplicates go.
   Checkpoints as signed vault entries over a prefix; `audit_heartbeat`, the
   vault's checkpoints and `CheckpointInput.previous` go; readiness as a
   query. Verification with both keys over one prefix, keeping every
   checkpoint. `members()`, `log()` and `latestCheckpoint()` become queries;
   the audit page becomes one list with today's visibility rules;
   `coffre verify` reports how far it got. Verified by the review's R1, R1b
   and R2, the app review's A01, and "no audit, no access change".
7. **Sign-in rows authenticated** (S6, S11). `auth_mac` on identities,
   credentials and device approvals, checked before use and recomputed on
   every change of state; the device-state check; the composite foreign key
   from a credential to its identity. Verified by sessions, identities and
   approvals inserted as the database's owner being refused, and #23's A07
   and A08 regressions.
8. **Transports and deployments.** Workers:
   `vault(env => ({ database: postgres(env.HYPERDRIVE), … }))`, no Durable
   Object. Node: `serveVault({ database })`, `localVault({ database })`, one
   SQLite file for both processes. The examples, `init`, `dev/deployment`,
   `dev/start.sh` and the conformance harness (`--vault-runtime`, no
   `vaultStore`). Verified by `pnpm conformance:workers`,
   `pnpm conformance:node`, `test:consumer`, and a `pnpm dev` session that
   signs in and reveals.
9. **Conformance around facts that commit** (S12). The nine invariants of
   "What it costs to get there". Verified by both conformance runs, and by
   each new check failing against a build with step 5, 6 or 7 reverted.
10. **Witnesses.** Access changes answer with the vault's entry;
    `GET /api/witness`; `@coffre/client` keeps and checks the anchor, the
    CLI with its credentials and the UI in `localStorage`;
    `coffre verify --accept-rewind`. Verified by unit tests, the review's R7
    rewritten to expect a witness that saw a cut entry to report it, and a
    conformance check that rewinds the database as its owner. Depends on
    step 6 only, so it can run beside 7 to 9.
11. **Docs and the restore drill.** The docs listed above, and a runbook for
    PlanetScale Postgres. Verified by running the drill on a PlanetScale
    branch.
12. **Later, not blocking.**
    - The current-version pointer (S7): keep `secrets.current_version` with
      a composite foreign key to its own version, drop
      `current_version_id`, `updated_at` and the parent `project_id` on
      `secrets` and `syncs`.
    - Sync results as events (S8): a `sync.finished` entry, `last_run_seq`
      for the cached result, a lease token, and one unique destination per
      provider.
    - The Worker on MySQL, the GRANT and trigger script for self-hosted
      MySQL, PlanetScale MySQL's deploy requests, and checkpoints copied to
      R2 behind a retention lock.

## For Erwin to decide

Already settled: two Workers, with server rendering kept; one database; one
log; `@coffre/db`; Hyperdrive's cache off, shipped in #22. Marks compare
with the previous version of this list: unchanged, changed (★) or new (✚).

**The storage review's core, which Erwin backs** (S1, S2, S4, S12). Each
line names the choice inside it that still wants his word.

1. ★ The log's format: each author's MAC over the previous hash and the
   fields, a public SHA-256 over the fields and the MAC, versioned, with
   shared test vectors? Recommended: yes; the public chain then pins every
   byte a checkpoint signs. The choice: the review's formula over the
   earlier draft's.
2. ★ Record each event once, by whoever decided it: a read is the vault's
   release, an access change the vault's entry? Recommended: yes. The
   choice: an app read's only record is the vault's, which counts a key
   handed to the app, not an answer delivered.
3. ✚ One member directory owned by the vault, with generations as the
   revocation and one MAC per member over its grants? Recommended: yes. The
   choice: the app keeps no membership state of its own, so every request
   still asks the vault.
4. ✚ Checkpoints as signed vault entries over a prefix, and readiness as a
   query, without `audit_heartbeat`? Recommended: yes. The choice: a
   checkpoint stored in the database rolls back with it, so only witnesses
   and off-box copies give freshness.
5. ✚ No app transaction open across a vault call, the head locked first,
   and the log keeping its foreign keys? Recommended: yes. The choice: every
   flow that calls the vault today is restructured first, as plan step 1.

**Still open.**

6. Postgres first: PlanetScale Postgres for erwinkn.com, MySQL on Node only
   until someone deploys it? Recommended: yes. Unchanged; merges two items.
7. Keep SQLite for the tests and one-machine Node? Recommended: yes.
   Unchanged.
8. One data key per secret version, wrapped directly by the KEK?
   Recommended: yes. Unchanged.
9. ✚ Listings as plain reads, with `access`, verification and every
   decision kept as vault calls, and `unwrap` taking version ids?
   Recommended: yes.
10. ✚ An app-key MAC on the security fields of identities, credentials and
    device approvals, so the database alone cannot mint a session?
    Recommended: yes.
11. ✚ One clock, the database's read after the lock, in integer
    milliseconds, and one operation id per batch? Recommended: yes.
12. ✚ Grant scope as exactly one foreign key, in the core change, and the
    current-version pointer and sync results after it? Recommended: yes.
    Replaces `place_id`.
13. With KMS, log the intent before calling it, and accept that a removal
    during a KMS call shows as a Decrypt the vault then refused?
    Recommended: yes. Unchanged; merges two items.
14. Witnesses now, off-box checkpoints later, accepting that a
    whole-database rewind or a cut-off tail is seen only by a witness or a
    running process? Recommended: yes. Unchanged; merges two items.

What the vault does with a forged vault entry became a detail of the
design.

## Appendix A: spikes

Run on 2026-10-01 against the repository's Postgres 16.14 (`:55432`) and
MySQL 8.4.11 (`:53306`), each in a database and logins of its own, dropped
after. The scripts are not committed. The storage review's own probes,
cited in the text, add the shared SQLite file's write lock, the transaction
clock, grant scope as one foreign key on all three engines, and the CHECK
that passes on NULL. The first two spikes below predate the one log:
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

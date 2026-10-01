# One database

The design for running coffre on a single Postgres database: the vault's
tables, one member directory and one audit log that both the app and the
vault write. Written on 2026-10-01 and built that week, in #22 to #46; it is
kept as the record of what was decided and why. Throughout, "today" means
coffre before this design, with the vault's own store; the
[implementation plan](#implementation-plan) names the pull request that built
each step, and what was parked is under its step 11, "Later".
[architecture.md](../architecture.md) describes coffre as it now is.

Every decision in it is settled; the list is at the end. This version folds
in three reviews of that day. The security reviews of keys and integrity (F)
and of the app (A) found problems the design has to answer. A storage review
(S) looked for what one database lets coffre merge, and most of its
proposals are taken; "What the reviews change" says where each lands.

## In short

- **Two writers, one Postgres database.** The vault keeps its own Worker,
  its own login and the KEK, and stays the only writer of members and
  grants. The app writes everything else. SQLite remains for tests and local
  development only.
- **One member list, owned by the vault.** The app's and the vault's
  `principals` merge into `vault_members`. A removal bumps the member's
  generation, and every session, token, linked account and device approval
  issued before it stops working, whether or not the app ever touches its
  row.
- **One audit log that reads like what people did.** One entry per human
  action, named for it: `secret.read`, `secret.write`, `access.grant`,
  `member.remove`. A column says which component wrote it. The vault writes
  a read when it releases the key, before the key leaves; the app writes a
  value's change in the transaction that stores it. Technical steps stay in
  the log as detail the audit page hides by default.
- **Each entry is authenticated by its author and chained in public.** An
  HMAC under the author's key, and a SHA-256 chain over every entry and
  every MAC, so neither component can rewrite an entry once the other has
  written after it.
- **Checkpoints are signed log entries, and readiness is a query.** The
  vault signs a prefix of the log every five minutes; `audit_heartbeat`, the
  vault's checkpoints table and review F1's caller-supplied claims go.
- **No app transaction stays open across a vault call.** Otherwise a write
  and its log entry can wait on each other through an HTTP call, which
  Postgres cannot see and so cannot break.
- **With KMS, a read in flight holds its reader's member row.** A removal
  then waits for the read instead of racing it, and nobody else waits. With
  a local KEK there is no race.
- **The database alone can no longer mint a session.** The security fields
  of identities, credentials and device approvals carry a MAC under a key
  derived from the app's.
- **One data key per secret version, wrapped directly by the KEK, as
  today.**
- **Rollback by the database's owner is an accepted limit.** A member's old
  rows put back are refused while the log holds the later change; with that
  change cut from the middle of the log as well, they are let in until the
  next checkpoint, which recomputes the chain and turns readiness red. A
  rewind of the whole database, or its newest entries cut off, is seen only
  by an instance running across it, or by CloudTrail with KMS; question 7
  walks through all three. Witnesses, off-box checkpoints and members'
  state under the checkpoint's signature are parked for later.
- **Host on PlanetScale Postgres,** from $5 a month. Seventeen tables and
  two migration ledgers become thirteen and one.

## What the second store bought

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
| The owner login, PlanetScale's default role | anything in the database, row-level security and triggers included | open a value: no KEK. Forge a grant, a session or an entry: no key | a forged or edited row: refused at its next use. A member's old rows put back: refused while the log holds the later change; with that change cut from the middle of the log too, let in until the next checkpoint, which recomputes the chain from its first entry, finds the cut and turns readiness red. The newest entries cut off with the head put back, or the whole database rewound: an accepted limit, seen only by an instance running across it, or CloudTrail with KMS |
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
| F8, low | The database owner can cut the newest entries off the log and put its head back | Question 7: an accepted limit, caught only by a running instance's memory. #21 states it in `architecture.md`. Plan step 10 |
| A01, high | The vault commits an access change before the app's audit append; if that fails, the change is live with no app entry, and a half-done removal revives old sessions | Questions 5 and 6: the vault's entry, committed with the change, is the record, and a removal's generation is the revocation. Plan steps 4 and 6 |
| A07, A08, fixed by #23 | An account binding survives a change of its provider's issuer; linking can race offboarding and survive re-admission | #23 added `issuer_hash` and generations, which the target schema keeps and question 5 builds on. Plan steps 4 and 7 |
| S1 to S12 | The storage review's twelve proposals | Taken: one event format (S1), one directory (S2), listings as reads (S3), checkpoints as events (S4), grant scope as one foreign key (S5), MACs on auth rows (S6), one clock and operation id (S9), one storage package (S10), constraints and indexes (S11), transaction boundaries (S12). Later and not blocking: the current-version pointer (S7) and sync results as events (S8). Plan step 11 |

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

**Why no app transaction may stay open across a vault call.** Say Ada
saves a new secret, `market/prod/STRIPE_KEY`. Today the app opens a
database transaction, inserts the secret's row, and then, still inside that
transaction, asks the vault over HTTP to wrap the secret's key. With one
database, the vault writes its log entry for that wrap into the same
database, on its own connection, and the entry names the new secret. Two
things go wrong:

- The secret's row is not committed yet, so the vault's connection cannot
  see it, and the entry's foreign key fails. Ada's save fails. The spike
  got `23503` at once.
- Worse, say the app's open transaction holds a lock the vault needs, such
  as the log's head, which any app append takes. The vault waits for the
  app's transaction to end, and the app waits for the vault's HTTP answer.
  Each waits on the other. Postgres breaks the deadlocks it can see, but it
  cannot see that the app is waiting on an HTTP call: it sees one waiter and
  no cycle. Both hang until a timeout; Postgres has none by default, and in
  the spike a 2-second `lock_timeout` ended it. On SQLite, in tests and
  local dev, it is immediate: the app's open transaction holds the whole
  file's write lock, and the vault's write fails with `database is locked`.

Today it works only because the vault keeps its own store. So every flow
reads what it needs, calls the vault, and only then commits in a short
transaction of its own:

| Flow | Order |
|---|---|
| Reveal, `coffre run`, import preview | read the committed versions; the vault decides, logs and releases the keys; the app decrypts and answers |
| Write, restore | prepare ids and the expected next versions; the vault wraps or rewraps; one short app transaction locks the head, then the secrets, checks the expected versions and archive state, and stores the versions with their entries. A conflict throws the wrapped keys away and retries as a new operation |
| A new secret | its id is chosen before the wrap; the vault's entry names it in its payload, since the row does not exist yet |
| Grant, admission, removal | one vault transaction: the rows, the generation, the entry |
| Sign-in, linking an account, approving a device | `access()` gives the member's generation first; one app transaction locks the head, reads the member again, refuses if the generation moved, then issues or binds and logs |
| Sync | the lease in one short transaction; the vault authorises and releases; the result in another. A new sync is committed disabled, its principal granted, then enabled |
| Heartbeat | the app's heartbeat entry commits; then the vault checkpoints |

**Three more rules.**

1. **Locks in one order: a member row, then the log's head, then the app's
   rows.** The vault locks the member a decision is about, then the head for
   its final append. The app locks the head, then its own rows, and never
   locks a member row. Nobody holding the head ever waits for a member row,
   so no cycle can form. Advisory locks are out: Hyperdrive does not support
   them.
2. **Time is read after the lock.** Postgres's `CURRENT_TIMESTAMP` is the
   transaction's start, so a transaction that waited would date its entry
   before an earlier one's (S9's probe). The append reads
   `clock_timestamp()` in a statement after the lock.
3. **READ COMMITTED, Postgres's default.** At REPEATABLE READ, a transaction
   whose snapshot predates a concurrent commit fails its `FOR UPDATE` with
   `40001 could not serialize access`. At READ COMMITTED, the spike's
   transaction that waited on the head then saw the grant committed while it
   waited.

#### Releasing a key, and the race with KMS

With a local KEK there is no race. A read is one short transaction: lock
Ada's member row, check her standing, grants and bulk count, unwrap the
data keys in memory, lock the head, write the `secret.read` entries, commit,
and only then hand the keys to the app. A removal waits for the few
milliseconds that takes. Erwin's deployment is this case.

With AWS KMS, each key is a network call of 20 to 40 ms, and 50 of them take
a quarter of a second. Something has to give. Say Bob removes Ada while her
`coffre run` is at KMS.

- **(a) Lock nothing across KMS, as the previous draft had it.** Check, log
  the intent, call KMS, then lock and check again. Bob's removal commits
  during the KMS call; the final check sees it and refuses. Ada gets
  nothing, but CloudTrail shows 50 Decrypts the vault then refused; the log
  explains them with the intent and a "decrypted, withheld" outcome. It
  costs nothing, and it reads oddly: KMS opened keys for someone who was
  being removed.
- **(b) Lock Ada's member row across KMS.** Log the intent in its own short
  transaction, then: begin, lock Ada's member row (`FOR UPDATE`), check
  again, call KMS, lock the head for the final append, write the entries,
  commit, hand back the keys. Bob's removal asks for the same row and waits
  for the read in flight; then Ada is out, and her next read is refused
  before any KMS call. Nobody else waits: other members' reads lock other
  rows, and the head is held only for the final append. The spike, with a
  300 ms stand-in for KMS, ran exactly so: the removal waited 250 ms, a
  read by Carol and an app write did not wait at all, and Ada's next read
  saw her removed (appendix A).
- **(c) Hold the global head across KMS.** One lock for everything, as the
  Durable Object had. Every decision and every app append would queue behind
  every KMS call: about four `coffre run`s a second for the whole instance,
  and a KMS outage would stop every audited action, not just reads.

| | (a) | (b) | (c) |
|---|---|---|---|
| A removal during a read | commits; the read is refused after KMS | waits for the read, then commits | waits for every read |
| KMS opens keys for a refused read | yes, explained by the log | no | no |
| Who else waits | nobody | Ada's own other reads and access changes | everyone |
| Held across KMS | nothing | a transaction and one pooled connection per read in flight | the whole instance |
| A KMS outage | reads fail; nothing waits | each read holds its member's row and a connection for the KMS budget, then fails as an outage | everything stops |

**Decided: (b), with KMS.** It gives the order people expect, reads
in flight finish and then the person is out, for the price of one
connection per read in flight. At erwinkn.com's or a team's scale that is
a handful of Hyperdrive's 20 (Free) or 100 (Paid) connections. Three
details make it safe:

- **A budget.** All of a read's KMS calls must finish within 5 seconds, or
  the read fails as an outage, logs each key as "KMS unavailable", commits
  and lets go of the row. A removal waits at most that long, and its own
  `lock_timeout` sits above the budget.
- **Ada's reads queue behind each other,** which keeps her bulk count exact
  before any KMS call. A token running ten parallel `coffre run`s waits a
  few hundred milliseconds; nobody else does.
- **The intent survives a crash** (review F5). It commits before the locked
  transaction begins, so a vault that dies mid-KMS leaves an intent with no
  outcome, which verification reports and CloudTrail's Decrypts pair with.
  Every started call settles before the decision (`Promise.allSettled`), and
  each key's outcome is logged, so a partial outage is accounted for too.

`wrap` and `rewrap` take the same path: an Encrypt is in CloudTrail too.

**What this keeps.**

- **A refused call never reaches KMS.** The check comes first, as `#mayAll`
  does today, and with (b) it is made under the member's lock.
- **The bulk limit is exact,** counted under the lock from the vault's own
  `secret.read` entries: one per released key, syncs and import previews
  included, refusals not.
- **Every instance shares one log and one set of limits.** Review F2 showed
  a second Durable Object loading the same KEK with an empty log and a fresh
  bulk counter. `#serial` orders the calls of one isolate, which only the
  Durable Object made the only one. Here every isolate and process decides
  under the database's locks, and `#serial` goes. What an instance
  remembers, such as the last head it saw, can only add a refusal.
- **A refused pre-check stays refused,** even if a grant arrives before the
  decision, rather than answer `ok` with no keys as today's code would.

**Throughput.** Every append takes the one head. The spike simulated 5 ms
per round trip, each append holding the head for about four:

| Writers at once | One head, both authors | Two heads, one per author |
|---|---|---|
| 1 | 40 appends a second | |
| 8 | 52 a second, waiting 133 ms at the median | 108 a second, waiting 50 ms |
| 32 | 59 a second, waiting 587 ms at the median | 113 a second, waiting 274 ms |

So one log halves the ceiling, to about 50 appends a second. Each event is
now appended once, which gives some back. erwinkn.com, or a team of fifty,
is two orders of magnitude below. Folding the insert and the head update
into one statement would take a round trip off every append if it were ever
needed.

`access(principal)`, which the app asks once per request, takes no lock:
one read of the member, the grants and the freshness check. On SQLite,
every transaction holds the file's write lock, so the locks above do
nothing there; the tests run two processes on one file to cover it.

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

**Decided: keep today's hierarchy.** At coffre's scale KMS calls cost
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

### 4. Integrity in the database, and around it

Seven guards, outermost first. The first three come from Postgres; the
other four come from keys, and hold on SQLite too.

1. **Logins.** The app's login reads members and grants and never writes
   them. The vault's login writes members and grants, reads the projects,
   environments, secrets and versions it decides on, and nothing else of the
   app's. Both read and append to the log and move its head; neither may
   change or delete an entry. The app no longer needs today's artificial
   `UPDATE (created_by)` on `principals`, kept only so it could lock a row:
   it serialises on the head instead. In the spikes every forbidden
   statement failed with `42501`.
2. **Row-level security** on `audit_log` lets each login insert only its
   own author's entries: `WITH CHECK (author = 'app')` for one, `'vault'`
   for the other. In the spike, each login's attempt to write the other's
   entry failed with `42501`. The table's owner bypasses it, as owners do.
3. **Triggers** refuse UPDATE, DELETE and TRUNCATE on `audit_log`, for every
   login, the owner's too. They stop bugs and a careless owner, not a
   determined one: the owner can `DISABLE TRIGGER`, as the spike did.
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
7. **Signed checkpoints** (question 6), and each running instance's
   memory of the last head it wrote (question 7).

| | PlanetScale Postgres | Postgres, self-hosted | SQLite, tests and local dev |
|---|---|---|---|
| Logins with table-level GRANTs | yes, `CREATE ROLE` in SQL | yes | no logins |
| Each login writes only its author | yes, row-level security | yes | no |
| Append-only triggers | yes | yes | yes |
| Guards 4 to 7 | yes | yes | yes |
| Point-in-time recovery | yes, 2 days by default | your own | not needed |

Every deployment runs on Postgres, so guards 1 to 3 always hold where it
matters. SQLite has no logins; there the app's process could write the
vault's rows, and guards 4 to 7 still refuse a forged grant or session and
expose a forged entry, which is what the tests check.

On PlanetScale Postgres, the default role is not a superuser but has
`CREATEROLE`, `BYPASSRLS` and `pg_write_all_data`: treat it as the owner,
for migrations only. A role made in SQL logs in as `<role>.<branch id>`, and
a restore resets its password.

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
the review's probes found it behaves the same on Postgres and SQLite. It
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
because the vault wrote ids the app had not committed. Under the rule that
opens question 2, it never does, apart from a new secret's wrap, which names
the id in its payload instead. So the log keeps its references to projects,
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

**One package** (S10, settled). `@coffre/db` holds the two Drizzle schemas,
the migrations, `dialect.ts`, `portable.ts`, `connect.ts`, the Hyperdrive
pool, the event codec's storage half and the append, moved out of
`packages/server/src/db`. PR #8 folded `packages/db` into the server because
the server was its one user; the vault is a second. Queries stay with their
owners. The vault's SQLite interface, its two backends and its hand-written
migrations go, and its store is rewritten with Drizzle, which undoes #9's
"without Drizzle" for the reason the app uses it. `coffre-server migrate`
stays the one command; runtime Workers never migrate. The two physical
schemas, Postgres and SQLite, stay, with the parity test made to compare
CHECK predicates and index semantics, not only names.

**Migrations.** No deployment exists yet, so every change here goes into
the baselines, regenerated by `pnpm db:generate`, and no history is
converted. PlanetScale Postgres takes plain DDL as the owner, on the direct
port 5432, with no deploy requests to go through. Once
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

**Risks of the log format.**

- **Both writers must encode an entry the same way,** or the other side's
  chain check fails. The codec is one function in `@coffre/core`, used by
  both; the shared test vectors run in both packages' tests and in
  conformance's verifier; and the packages ship at one version, so a
  release cannot pair two codecs.
- **Losing a key loses verification, not the secrets.** Without
  `auditChainKey`, the app's entries can no longer be authenticated;
  without `signingKey`, neither can the vault's entries, its checkpoints or
  its member MACs, so the vault would refuse every member until they are
  sealed again under a new key by hand. Values stay readable with the KEK
  either way. Both keys are on the escrow list, beside the KEK.
- **Rotating a key needs `key_id` on every entry,** which the format has.
  A new key signs new entries; old keys stay, for verification only, as long
  as their entries are kept, as `previousKeks` do for the KEK. Rotating the
  vault's key also reseals every member row, in one transaction.
- **One lock for both writers** caps the log at about 50 appends a second at
  5 ms per round trip (question 2): far above coffre's use, but a ceiling.
- **A format change is a new version.** Old entries keep theirs and verify
  under their own codec, so a verifier keeps every codec it has shipped, and
  history is never re-serialised into a new one.
- **Full verification costs one HMAC per entry on each side,** a few
  seconds for a million entries; page views check only what is new.

**What the log says: one entry per human action.** Each entry is named for
what a person, a token, a sync or the scheduler did or tried, and a column
says which component wrote it. Technical steps stay in the log, so the chain
and CloudTrail stay complete, but as detail entries the audit page hides by
default.

| Someone… | Entry | Written by, and when |
|---|---|---|
| reads a secret: a reveal, a `coffre run` or export, a sync, an import preview | `secret.read`, one per secret, with the purpose and the batch | the vault, in the transaction that releases the key, before it leaves |
| is refused a read | `secret.read`, refused, with the reason | whoever refused: the app, when its own check fails; the vault, for no grant, removal or the bulk limit |
| writes or restores a value | `secret.write` or `secret.restore`, one per version | the app, in the transaction that stores the version |
| renames or archives a secret, a project, an environment | `secret.rename`, `project.archive`, … | the app |
| changes someone's access | `access.grant` or `access.revoke`, one per place | the vault, in the transaction that changes it |
| adds, removes or restores a member, or makes one an owner | `member.add`, `member.remove`, `member.restore`, `member.owner` | the vault, likewise |
| signs in or out, issues or revokes a token, approves a `coffre login` | `sign_in`, `sign_out`, `token.create`, `token.revoke`, `device.approve` | the app; hidden by default |
| sets up, changes or removes a sync | `sync.create`, `sync.update`, `sync.delete` | the app |
| a sync pushes | `secret.read` for each value, with the sync as the reader, and `sync.push` for each key, naming the destination | the vault, then the app |

Detail entries, hidden by default: `key.wrap`, `key.rewrap` and
`key.intent` from the vault; `audit.heartbeat` and `audit.checkpoint`. One
system entry is never hidden: `vault.tampered`, written when the vault finds
a row or an entry that fails its MAC.

A `coffre run` of 12 secrets is 12 `secret.read` rows that share one
operation, and the page shows them as one line, "ada ran market/prod: 12
secrets", which opens to the twelve. Rows stay per secret because the
questions people ask are per secret: who read `DATABASE_URL`, what a leaver
read and must be rotated, how many keys a token took in 15 minutes.

**What `secret.read` proves.** That the vault checked the reader's standing
and grant, released this version's key to the app for this purpose, and
committed the entry before the key left. The vault releases a key only to
serve a read, so each one is a read. It does not prove that a person saw the
value: the app may fail to decrypt, or the connection drop, after the key is
released. The reader it names is the app's claim, checked against the
grants: a compromised app can read as anyone who holds a grant, and every
such read still lands here, under that name, in the bulk limit, and with
KMS in CloudTrail. And it cannot see a read that bypasses coffre, a copy of
the database opened with a stolen KEK; with KMS, a Decrypt in CloudTrail
with no entry here shows one.

**Writes.** `secret.write` is the app's, written in the transaction that
stores the version, which is what makes it true. The vault's wrap is a
technical step, logged as a `key.wrap` detail entry and linked from the
write by `related_seq`. It stays because with KMS each wrap is an Encrypt in
CloudTrail, which pairs with its `key.wrap` by the secret's ids and the
time, whether or not the app's transaction then committed; a wrap without a
write is then visible as such. A refused write is a human action:
`secret.write`, refused, written by the vault. A restore's rewrap is a
Decrypt and an Encrypt in CloudTrail, and both pair with its `key.rewrap`.

The audit page, by default, as a human would see it:

```
  seq  time   who                  what they did                                           decided by
 1188  10:01  ada@acme.example     ran market/prod: 12 secrets                             vault
 1201  10:02  ada@acme.example     changed market/prod/DATABASE_URL, now version 5         app
 1202  10:03  bob@acme.example     gave carol@acme.example developer on market/dev         vault
 1203  10:03  carol@acme.example   revealed market/dev/API_KEY                             vault
 1204  10:04  carol@acme.example   tried to reveal market/prod/API_KEY: no grant           vault, refused
 1205  10:05  sync to GitHub       pushed market/prod to acme/market: 3 secrets            vault, app
 1211  10:06  bob@acme.example     removed dave@acme.example, who held 2 grants            vault
 1212  10:07  token:ci-deploy      tried to run market/prod, 50 secrets: bulk limit        vault, refused
 1263  10:08  ada@acme.example     restored market/prod/DATABASE_URL to version 3, now 6   app
 1264  10:09  erwin@acme.example   created project billing                                 app
             hidden: 2 key wraps (1200, 1262); sign-ins, heartbeats and checkpoints when there are any
```

**Access changes** (A01). The vault's entry is the record, in the
transaction that changes the member or the grant, so nothing can commit
without it. A removal's generation bump is the revocation (question 5), so
the app's clean-up of sessions afterwards cannot fail in a way that leaves
access. The intent entries, the `vault_seq` column and the recovery job of
the first draft are gone. A lost response is ordinary uncertainty, and a
retried grant is never replayed over a later change.

**Pages that become plain reads** (S3). The app may read members, grants
and the log, so the vault calls that only fetched stored rows become
queries:

| Page or command | Today | After |
|---|---|---|
| The Users page and `coffre access`: everyone, their status, owner flag and grants (`GET /api/members`) | `vault.members()`, then joined with the app's directory | one query over `vault_members`, `vault_grants`, identities and credentials |
| A member's page: status, grants, sessions, what they read (`GET /api/members/user:ada@acme.example`) | `vault.access()` for status and grants, plus the app's queries | the same query, for one member |
| A project's Access tab: who holds what on `market` | `vault.members()`, filtered to the project | `vault_grants` joined to members, for one project |
| The audit page's "Vault log" panel (`GET /api/audit/vault`) | `vault.log()`, the vault's own pager and serialiser | gone: one audit page reads `audit_log` |
| The audit page's checkpoint status | `vault.latestCheckpoint()` | the newest `audit.checkpoint` entry, its signature checked with the vault's public key, which comes from the vault |

What stays a vault call: `vault.access(principal)`, which the app asks on
every request to decide what the caller may do; verification; and every
decision that changes access or releases a key.

A forged row looks like this. Say the database's owner inserts a grant
giving herself `owner` on `market`. The Users page and `market`'s Access tab
show it, as stored: the app cannot check the member MAC, so a listing is a
display, not a decision. The first time it would matter, it does not: her
next request's `access()` call fails the MAC over her grants, so the vault
refuses her as `tampered`, and writes a `vault.tampered` entry that the
audit page shows. Verification flags it too, and the pages show a failed
verification as a banner. A forged row can be displayed; it cannot be used.

**What checkpoints keep** (S4). A checkpoint becomes a vault entry,
`audit.checkpoint`, with a signed payload: format, instance id, the `seq`
and `hash` of the last entry before it, the time, the key id and an Ed25519
signature. It signs a prefix that ends just before itself. Before writing
one, the vault recomputes the whole chain from its first entry, every hash
from the entry's content and its own entries' MACs, in a snapshot and
without the log's lock; then, under the lock, the previous checkpoint's
prefix must still end at the hash it signed, and every link since the
snapshot must hold. A hash commits to everything before it only when it is
recomputed: comparing the stored hash at the previous checkpoint's seq
proves nothing about the rows before it, which can change or go while that
one stored value stays (the final review's R1). Recomputing from entry 0
costs about 4 seconds per 100,000 entries on a small shared Postgres, so
every checkpoint does it while the log is small; past 250,000 entries or
so, ten seconds a pass, it should move to a slower cadence or a resumable
pass. Full verification checks every checkpoint too. Three jobs remain: anchoring quiet periods, giving
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
an app entry that says `access.grant` never becomes a grant.

**A forged vault entry,** written by the app's process on SQLite in tests or
local development, where no login stops it, fails its MAC. Verification
reports it. The vault checks the MAC of every vault entry it decides on,
such as a member's newest access entry, and ignores and reports one that
fails, without stopping: otherwise the app's login would hold a switch that
turns coffre off. A forged release can only raise a bulk count.

**The costs.** One lock for both writers, which halves the throughput
ceiling (question 2). One entry format for two packages, so a change to it
ships in both, under a new version. The app reads the vault's rows and
entries, which it displays anyway. And the rule that opens question 2
restructures every flow that calls the vault today.

### 7. Rollback: an accepted limit

Mallory has the owner's login, or the PlanetScale account, and puts genuine
old rows back. Erwin's call: "if someone has access to the database and can
roll it back, I would expect this to happen. I don't expect strong
guarantees if someone can just alter the database." So the design catches
what it can for free and states the rest plainly. Three cases.

**One member's rows: caught.** Ada was removed at entry 812. Mallory kept
her member row and grants from before and writes them back; their MAC is
genuine. The vault catches this at Ada's next decision: her row says its
last access change was entry 640, and the log's newest vault entry about
her, its MAC checked, is 812, so she is refused as `tampered`. That is one
indexed lookup in the read the decision makes anyway. To get past it,
Mallory must take 812 out of the log as well: the next three cases.

**An entry cut from the middle: seen at the next checkpoint.** Mallory
deletes 812 itself, now well before the newest checkpoint, and writes Ada's
old rows back. Ada's row and the newest entry about her left, 640, agree,
so the vault lets her in: the check at use reads the entries that remain,
each by its own MAC, not the chain around them. The next checkpoint
recomputes the chain from entry 0, finds the gap at 812, refuses to sign,
and `/readyz` turns red within five minutes; full verification says the
same. Until then Ada reads, and each read is logged under her name. The
same cut can erase `secret.read` entries, with the same signal. Catching it
at use would need each member's state under the checkpoint's signature,
parked under "Later".

**The whole database, rewound: mostly unseen.** Mallory has the PlanetScale
account and, from a phished laptop, Bob's browser session. At 10:06 she
reveals `market/prod` with Bob's session, and the vault writes 12
`secret.read` entries in Bob's name, 1300 to 1311. At 10:20 she restores the
database to 10:04, to erase them. A restore makes a new branch, so she also
needs the Cloudflare account to point Hyperdrive at it; with only the
owner's login, she can delete the rows written since 10:04 and put back the
ones they changed, which looks the same. Everything left is genuine as of
10:04, checkpoints included, so verification passes. Who notices:

| Who | How |
|---|---|
| An app or vault instance running since before 10:20 | at its next append, the head it last wrote is ahead of the one it finds: it refuses and writes an alarm |
| CloudTrail, with KMS | 12 Decrypts at 10:06 with no `secret.read`, when someone compares |
| Nobody else | the database is consistent as of 10:04 |

With a local KEK and no instance alive across the restore, nothing notices.
That is the price of one store: today she would also need the Durable
Object, which lives in the Cloudflare account. The Cron's five minutes are
a cadence, not a limit on how far back an owner can rewind.

**The newest entries, cut off: mostly unseen** (F8). The same 10:06 reveal,
but at 10:07, with the owner's login, Mallory deletes entries 1300 to 1311
and puts the head back to 1299. Nothing else was written in between. What
is left is genuine and its chain verifies: a chain proves that what is kept
is authentic, not that nothing was cut from its end, as #21 already says in
`architecture.md`.

| Who | How |
|---|---|
| The vault instance that wrote 1311 | at its next decision the head is behind the one it wrote: it refuses and writes an alarm. Isolates live for minutes under traffic, so this is likely, not certain |
| CloudTrail, with KMS | 12 Decrypts at 10:06, no entries |
| The 10:10 checkpoint, and verification | nothing: they see the cut log, which is genuine |

Had the cut entries changed a member, say a grant Mallory gave herself
with Bob's session, that member's row would name an entry the log no longer
has, and the vault would refuse the member at once, unless she rolled the
row back too: the whole-database case.

**What the design keeps, and what is parked.** The running instance's
memory costs nothing and stays: each app and vault instance remembers the
last head it wrote and refuses to append behind it (plan steps 3 and 4).
So does the checkpoint's recomputation of the whole chain, which turns a
cut anywhere in the log into a red `/readyz` within one beat. Three
defences are parked under "Later", should the threat model change:
witnesses, where each CLI and browser remembers the newest entry it saw and
checks the log still holds it; checkpoints copied off the box to a bucket
behind a retention lock; and each member's state under the checkpoint's
signature, so that a cut the checkpoint covers is refused at use.

### 8. Node deployments

Node deployments run on Postgres, like Workers, and the vault stays a
process of its own with its own login.

| | Today | After |
|---|---|---|
| The vault as its own process | `serveVault({ socket, store: 'vault.db', … })`, its own SQLite file | `serveVault({ socket, database: 'postgres://coffre_vault_runtime:…', … })` |
| The vault in the server's process | `localVault({ store, … })` | `localVault({ database, … })`, for tests and local development |
| The server | `serve({ database, vault: connectVault(socket), … })` | unchanged, on Postgres |
| The socket | HTTP over a Unix socket, `0660` | unchanged |
| Backups | the database and `vault.db`, taken at the same moment | the database |

SQLite stays for the test suite, conformance's Node run and local
development. There both processes open one file, and SQLite's file lock
serialises them, which is one more reason no app transaction may stay open
across a vault call. The vault's own SQLite layer (`sqlite.ts`,
`sqlite-node.ts`, `sqlite-durable-object.ts`) is deleted.

### 9. PlanetScale and Hyperdrive

**PlanetScale Postgres for erwinkn.com.** The smallest cluster, PS-5, is
$5 a month on one node, $15 with high availability. It is Postgres 17 or 18
with SQL roles, table-level GRANTs, row-level security and triggers, so
guards 1 to 3 hold; point-in-time recovery reaches back 2 days by default
and restores to a new branch; schema changes are plain DDL, with no deploy
requests; and coffre's Worker already speaks it through Hyperdrive with
`pg`, Cloudflare's recommended driver. PlanetScale's MySQL product has none
of the first three and no point-in-time recovery, and coffre no longer
supports MySQL.

Hyperdrive, for both Workers:

- **Query caching off,** shipped in #22: a cached read could keep a revoked
  token working for about a minute, a `wrangler.jsonc` binding cannot pin
  caching off, and the session lookup reads the database clock, which
  Hyperdrive never caches. Once the vault reads through Hyperdrive, its
  reads do the same.
- **One config per login,** so two. The Free plan allows 10 per account,
  Paid 25.
- **Port 5432, not 6432.** Hyperdrive pools, and PgBouncer behind it would
  pool again. coffre keeps no session state, so pooling per transaction is
  fine.
- **Connections.** Hyperdrive opens up to about 20 connections to the
  database per config on Free, and 100 on Paid; with KMS, each read in
  flight holds one of the vault's (question 2). PlanetScale does not
  publish PS-5's `max_connections`; it is in the branch's Parameters tab,
  and both configs must fit under it.
- **Placement.** Both Workers near the database's region, with Cloudflare's
  placement hint, since a decision makes several round trips.

## What it took

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
   Postgres connections and on two SQLite processes.
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
6. Restart both Workers, or redeploy them: an instance running since before
   the restore refuses to append behind the head it remembers, which after a
   restore is the intended state.

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

Each step was one pull request, or a few, from `main`. "The suite" means
`pnpm test`, `pnpm test:sqlite`, `pnpm typecheck`, `pnpm lint` and
`pnpm test:schema`. Steps 0 to 10 are built; step 11 is what was parked.
Built after the plan: the final independent review's fixes, #44 (recovery by
removal, and one bad sign-in row no longer taking down a list) and #46 (a
decision seals only the grants it decided; every checkpoint recomputes the
whole chain; the member sweep reads one snapshot).

0. **Hyperdrive's cache off.** Shipped as #22.
1. **No app transaction across a vault call** (S12), built in #27. On the vault of the time:
   reveals read, then call the vault; writes and restores prepare, wrap,
   then store in one short transaction that checks the expected versions
   and retries as a new operation on conflict; a new secret's id is chosen
   before its wrap; access and member changes call the vault outside any
   transaction; a new sync is committed disabled, granted, then enabled.
   Verified by the suite, a test that fails any vault call made while an
   app transaction is open, and #23's A08 regressions.
2. **`@coffre/db`** (S10). Shipped as #25.
3. **The log's v2 format, written by the app alone** (S1, S9, S11), built in
   #28 and hardened in #29. The
   codec and its test vectors in `@coffre/core`; the append in `@coffre/db`,
   which locks the head, checks that it names the last entry and reads the
   clock after the lock. New columns, integer milliseconds, `operation_id`
   for `bundle_id`, `related_seq`, no `audit_log.id`, the paging indexes;
   append-only triggers. The app remembers the last head it saw.
   Verification checks every link, the numbers from 0 and the app's MACs.
   Verified by the vectors, the suite and #21's sequence tests.
4. **The vault on the shared database, owning the directory** (S2, S3, S5,
   F2, F5), built in #31 (the vault's tables and logins), #33 (one member
   list), #34 (KMS deadlines and accounting) and #45 (version ids). `vault_members`, which replaces both `principals` tables, and
   `vault_grants` with one foreign key per grant; canonical principals; the
   sign-in tables pointing at `vault_members`, with #23's columns made NOT
   NULL. The `coffre_vault` role, the GRANTs and row-level security per
   author. The vault's store rewritten with Drizzle, appending v2 entries
   under its key. Decisions lock the member row, then the head; with a local
   KEK, a read is one short transaction; with KMS, option (b) of question 2:
   the intent commits first, the member row is held across KMS within a
   5-second budget, every call settles and each key's outcome is logged.
   Removals bump the generation; root admins get member rows; sign-in,
   linking and device approval serialise on the head and compare
   generations; `unwrap` and `rewrap` take version ids; `#serial` goes, and
   the vault remembers the last head it saw. Delete the vault's SQLite layer
   and its migrations. Verified by the vault's tests on Postgres and SQLite;
   two vault instances, and two SQLite processes, sharing the bulk limit and
   generations exactly; a removal during a slow KMS call waiting for the
   read in flight; the review's R4 and R6; and #23's A08 regressions.
5. **Member integrity**, built in #35. The member MAC over the member's grants,
   `generation` and `access_seq`; the freshness check against the newest
   authenticated access entry; the `tampered` refusal and the
   `vault.tampered` entry, worded on the pages and in the CLI; forged vault
   entries ignored and reported. Verified by tests for a grant forged,
   edited and deleted; old member rows put back; a generation edited back,
   or restored with its row; a vault entry forged on SQLite.
6. **One entry per human action, checkpoints and readiness** (S1, S3, S4),
   built in #36 (the vocabulary, checkpoints and readiness), #37 and #38 (the
   audit page) and #39 (lists as reads).
   The vocabulary of question 6: `secret.read` written by the vault at
   release, `secret.write` by the app with the version, access and member
   entries by the vault, sign-ins and technical steps as hidden detail; the
   app's duplicates go. Checkpoints as signed vault entries over a prefix;
   `audit_heartbeat`, the vault's checkpoints and `CheckpointInput.previous`
   go; readiness as a query. Verification with both keys over one prefix,
   keeping every checkpoint. The listings of question 6 become queries; the
   audit page becomes one list, grouped by operation, with today's
   visibility rules; `coffre verify` reports how far it got. Verified by
   the review's R1, R1b and R2, the app review's A01, "no audit, no access
   change", and the sample log rendered from a seeded instance.
7. **Sign-in rows authenticated** (S6, S11), built in #26. `auth_mac` on identities,
   credentials and device approvals, checked before use and recomputed on
   every change of state; the device-state check; the composite foreign key
   from a credential to its identity. Verified by sessions, identities and
   approvals inserted as the database's owner being refused, and #23's A07
   and A08 regressions.
8. **Transports and deployments**, built in #31 and #32. Workers:
   `vault(env => ({ database: postgres(env.HYPERDRIVE), … }))`, no Durable
   Object. Node: `serveVault({ database })` on Postgres, with the example's
   `DATABASE_URL` a Postgres URL; `localVault({ database })` for tests.
   The examples, `init`, `dev/deployment`, `dev/start.sh` and the
   conformance harness (`--vault-runtime`, no `vaultStore`). Verified by
   `pnpm conformance:workers`, `pnpm conformance:node`, `test:consumer`,
   and a `pnpm dev` session that signs in and reveals.
9. **Conformance around facts that commit** (S12), built in #40. The nine invariants of
   "What it took". Verified by both conformance runs, and by
   each new check failing against a build with step 5, 6 or 7 reverted.
10. **Docs and the restore drill.** The runbook and a local drill (#41), the
    database privileges reasserted by every migration (#42), the KEK check
    the drill called for (#43), and a docs pass. The same drill on a
    PlanetScale branch is part of erwinkn.com's exit
    ([roadmap](../roadmap.md#phase-3-erwinkncom)).
11. **Later, not blocking.**
    - The current-version pointer (S7): keep `secrets.current_version` with
      a composite foreign key to its own version, drop
      `current_version_id`, `updated_at` and the parent `project_id` on
      `secrets` and `syncs`.
    - Sync results as entries (S8): a `sync.finished` entry, `last_run_seq`
      for the cached result, a lease token, and one unique destination per
      provider.
    - Should rollback by the database's owner come into scope: witnesses,
      where each CLI and browser remembers the newest entry it saw and checks
      the log still holds it (`GET /api/witness`, an anchor kept with the
      CLI's credentials and in `localStorage`, access changes answering with
      the vault's entry), and checkpoints copied to R2 behind a retention
      lock.
    - With them, each member's state under the checkpoint's signature (the
      final review's fix 2a): every `audit.checkpoint` carries each member's
      `access_seq` and generation, or a digest of them, and a decision
      refuses a row older than what the newest checkpoint signed for that
      member, its signature checked. A cut the checkpoint covers is then
      refused at use rather than found at the next checkpoint.

## Decided

Erwin settled every question on 2026-10-01.

- Two Workers, with server rendering kept; the vault separate, with its own
  login.
- One Postgres database; SQLite for tests and local development only.
- One audit log for both writers, in the format of question 6: each
  author's MAC over the previous hash and the fields, a public SHA-256 over
  the fields and the MAC, `coffre.audit.v2`, with shared test vectors.
- One entry per human action, named for what the person did, with the
  author as a column: `secret.read` written by the vault at release,
  `secret.write` by the app with the version, technical steps as hidden
  detail.
- One member list owned by the vault, with generations as the revocation
  and one MAC per member over its grants.
- Checkpoints as signed log entries, and readiness as a query.
- No app transaction open across a vault call.
- Pages that only list rows read them directly; `access()` and every
  decision stay vault calls.
- With KMS, the reader's member row is held across the KMS call, option (b)
  of question 2, in plan step 4.
- One data key per secret version, wrapped directly by the KEK.
- An app-key MAC on identities, credentials and device approvals.
- One clock, the database's, read after the lock, and one operation id.
- Grant scope as exactly one foreign key.
- `@coffre/db`, shipped as #25; Hyperdrive's cache off, shipped as #22.
- Rollback by the database's owner is an accepted limit (question 7).
  Witnesses, off-box checkpoints and members' state under the checkpoint's
  signature are parked under plan step 11. A cut in the middle of the log is
  found by the next checkpoint's full recomputation (#46).

## Appendix A: spikes

Run on 2026-10-01 against the repository's Postgres 16.14 (`:55432`), each
in a database and logins of its own, dropped after. MySQL runs from the
two-engine drafts are left out, since coffre is Postgres only now. The
scripts are not committed. The storage review's own probes, cited in the
text, add the shared SQLite file's write lock, the transaction clock, grant
scope as one foreign key, and the CHECK that passes on NULL. The first two
spikes below predate the one log: their `vault_log` is the vault's own log,
which now merges into `audit_log`, and their `vault_log_head` is the row
every append now locks, `audit_chain_head`.

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

One log, two authors. Each login inserting the other's entries, under
row-level security; a vault entry referencing a project the app has not
committed; the app holding the head while it waits for the vault; and one
head against two, with the round trip simulated at 5 ms in the client and
each append holding the lock for about four of them:

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
```

A per-member lock across KMS, option (b) of question 2: Ada's read locks
her member row and holds it across a 300 ms stand-in for KMS; Bob's removal
of Ada, a read by Carol and an app write start meanwhile:

```
  30 ms  ada's read: locked her row (active), calling KMS
  87 ms  ada's removal: asks for her row
  90 ms  an app append: committed, not waiting
  93 ms  carol's read: committed, not waiting
 335 ms  ada's read: logged and committed; keys released
 336 ms  ada's removal: got her row
 340 ms  ada's removal: committed
 365 ms  ada's next read: sees status removed, refused before any KMS call
log: 0 secret.write by app | 1 secret.read carol | 2 secret.read ada | 3 member.remove ada
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

PlanetScale MySQL, for the comparison in question 9:
[MySQL compatibility](https://planetscale.com/docs/vitess/troubleshooting/mysql-compatibility).

Cloudflare:
[supported features](https://developers.cloudflare.com/hyperdrive/reference/supported-databases-and-features/),
[how Hyperdrive pools](https://developers.cloudflare.com/hyperdrive/concepts/how-hyperdrive-works/),
[query caching](https://developers.cloudflare.com/hyperdrive/concepts/query-caching/),
[limits](https://developers.cloudflare.com/hyperdrive/platform/limits/),
[Postgres drivers](https://developers.cloudflare.com/hyperdrive/examples/connect-to-postgres/),
[importing `env`](https://developers.cloudflare.com/workers/runtime-apis/bindings/),
[service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/).

Drizzle with PlanetScale Postgres: [connect-planetscale-postgres](https://orm.drizzle.team/docs/connect-planetscale-postgres).

Infisical: [github.com/Infisical/infisical](https://github.com/Infisical/infisical)
at `752845215bbfe62aa78313ee5d89fd54c4444986`.

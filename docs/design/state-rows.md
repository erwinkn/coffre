# State rows and the audit projection (0.16)

Draft, `[DESIGN, DO NOT MERGE]`: the build plan for finishing what 0.15 started. Settled before it: Workers on
Postgres; a clean break (0.16 upgrades offline from exactly 0.15.0, rollback is restoring the backup); at most 2
secondary indexes per table; derive, don't sync; typed columns; no planner steering; the 5 s statement timeout last.
Decided since the first draft and folded in (section 8): the two JSON values SQL never reads stay JSON (D199); the
audit page checks the log on every visit, at a flat cost (D200); per-object locks are in 0.16, last before the timeout
(D201); the offboarding report covers what retention keeps; old heartbeats and checkpoints are not listed. Assumed:
audit filtered by place stays for the CLI and API; a change still answers only once sealed. Numbers were measured on
2026-11-12 on main `021a8863`, on a Postgres 16.14 of my own: `pg_stat_statements` under the dev stack, `EXPLAIN
(ANALYZE, BUFFERS)` in a warm session, `pgbench` with one client, and `change-cost.test.ts`'s harness for round trips.
Catalog facts come from a migrated database.

## 1. Today in one page

Take one use: a signed-in person reads one key. The vault makes one call, `use_credential`. It reads the credential,
the member, the key, its environment and the policy by primary key. Each row carries a **seal**, a 16-byte MAC over
its columns, and the call seeks each row's newest entry in `log_changes` to check that the entry carries the same seal
(7 to 10 seeks, none when the isolate already knows the log's newest number). Then it reads the old log twice: the
newest `audit_log` entry about the member's access, and the newest `policy.change`. Those two reads, and their cousins
everywhere else, are what is left of 0.14.

| Table | From | Job today | Secondary indexes |
|---|---|---|---|
| `audit_log` | 0.14 | Hash-chained log. Also the store of a dozen facts of current state. Every change still appends to it, under a global lock. | 33 |
| `log_changes` | 0.15 | One signed entry per change to a sealed row. | 20, of which 18 serve the audit page |
| `log_uses` | 0.15 | One slim signed row per use, partitioned by day. | 2 |
| `log_reads` and 3 more | 0.15 | Uses as pages list them, with two day tables, two triggers and a cursor. | 10 |
| `principals`, `credentials`, `secrets`, `environments`, `service_bindings`, `mcp_connections`, `policy`, `roles` | 0.15 | State, one sealed row per object, read by primary key. | few |

**State still read from the old log.** Each line is a "newest entry of kind K" read, with a partial index of its own.

| Fact | Read by | After |
|---|---|---|
| Policy revision (newest `policy.change` seq) | every authenticated request, every use that carries an app token, token issue, bind, revoke: 11 reads in SQL, 5 in TypeScript | no row: the seals the request already read (section 3) |
| Policy content (protected environments, roles) | every vault decision, `GET /api/me` | `environments.protected`, `roles`: exist, sealed, not yet read |
| Instance settings | sign-in, `/api/me`, decisions | `settings`, new |
| A member's access revision | every use, key write, member add | no row: `principals.seal` already says it |
| App key retired, vault key in force | sign-in, token issue, bind, every decision | `log_keys`, new |
| Trust binding removed (`token.unbind` entry) | every request through a binding | `service_bindings.revoked_at`, already under its seal |
| Reference ended (`reference.end` entry) | reads through a reference, lists | `secret_references.ended_at`, already under the holder key's seal |
| Workload frozen | 5 probes per workload request | deleted: nothing writes a freeze |

**What the database runs.** Every statement of the three logins while the dev stack answers one operation, the
checkpointer's ticks and the projector's batches included. Section 3 has the request's own cost.

| Operation | Statements | Mention `audit_log` | Mention `log_changes` |
|---|---|---|---|
| Use, one key | 30 | 3 | 7 |
| Change, one secret written | 39 | 8 | 10 |
| Sign-in, browser | 59 | 13 | 16 |
| Audit page, one visit | 87 | 33 | 24 |
| Secrets list | 33 | 10 | 9 |
| `GET /api/me` | 17 | 4 | 3 |

Every authenticated request pays the same toll, whatever it does: the vault's snapshot statement reads the policy and
the caller's access from `audit_log` 2 to 4 times, and a cutover check (`SELECT number FROM log_changes WHERE object =
$1`) runs as often. Changes are written twice: a seeded database holds 56 `audit_log` entries beside 58 changes. And a
change takes two global locks, the row `audit_chain_head`, then an advisory lock exclusive (the **fence**) that every
use takes shared, so one write stalls every use until it commits.

**The cost is planning.** In a warm session:

| Statement | Plan | Run |
|---|---|---|
| Newest `policy.change` in `audit_log` (34 indexes) | 0.20 ms | 0.016 ms |
| A member's newest access entry in `audit_log` | 0.46 ms | 0.022 ms |
| The `policy` row by primary key | 0.022 ms | 0.012 ms |
| A `principals` row by primary key | 0.072 ms | 0.011 ms |
| Nine seal seeks planned each call, `log_changes` with main's 21 indexes | 1.00 ms in all | |
| The same with 2 indexes | 0.60 ms in all | |

Reading state from a log costs ten to twenty times its execution in planning, and every index on a log table taxes
every statement that names it. Once reads are by primary key, measure again before building anything for planning.

## 2. The target schema

Three kinds of table, one job each. **Chains** are append-only and signed. **State** is one sealed row per object,
read by primary key. **Projections** are caches the vault's projector rebuilds from the chains.

```sql
-- CHAINS
-- log_changes: columns unchanged. It keeps its primary key (number) and two indexes:
--   log_changes_object_idx      UNIQUE (object, number) INCLUDE (seal)   the seal seek
--   log_changes_request_id_key  UNIQUE (request_id)                      a retry finds its entry
-- Its 18 partial indexes on strpos(payload, …) are dropped.
-- log_uses: unchanged, 2 indexes: UNIQUE (at, request_id) and (number).
-- audit_log: frozen. INSERT revoked from both logins; its 33 secondary indexes and 3 of its 5 triggers dropped.

-- STATE
CREATE TABLE settings (                 -- the instance's settings, one sealed row; read by key at sign-in and in /api/me
  name text PRIMARY KEY CHECK (name = 'instance'),
  service_accounts text NOT NULL,       -- who sets up service accounts themselves
  service_account_projects uuid[] NOT NULL DEFAULT '{}',
  seal bytea NOT NULL CHECK (octet_length(seal) = 16)
);
CREATE TABLE log_keys (                 -- every key the app or the vault has written under; read by key at sign-in, issue, bind
  holder text NOT NULL CHECK (holder IN ('app', 'vault')), key_id text NOT NULL,
  retired boolean NOT NULL DEFAULT false,                 -- one key per holder is in force
  seal bytea NOT NULL CHECK (octet_length(seal) = 16),
  PRIMARY KEY (holder, key_id)
);
ALTER TABLE principals DROP COLUMN access_seq, DROP COLUMN mac;   -- 0.14's pointer into audit_log and its row MAC
-- secret_references.created_seq loses its foreign key to audit_log and stays, as the number that orders a key's
-- references. The chain's sequence moves past the old log's last seq, so a new reference sorts after every old one:
ALTER TABLE secret_references DROP CONSTRAINT secret_references_created_seq_fkey;
SELECT setval('log_number', greatest(nextval('log_number'), (SELECT coalesce(max(seq), 0) + 1 FROM audit_log)));
DROP TABLE log_config, audit_chain_head, log_reads, log_read_days, log_read_place_days, log_reads_cursor;

-- PROJECTIONS: written only by the vault's projector, read only by pages
CREATE TABLE audit_events (             -- one row per entry of any generation
  at bigint NOT NULL,                   -- ms, the entry's own time
  number bigint NOT NULL,               -- its number in the chain; a 0.14 entry's seq
  log smallint NOT NULL,                -- 14: audit_log, 15: log_changes, 16: log_uses
  action text NOT NULL,                 -- 'secret.read', 'access.grant', …
  shown boolean NOT NULL,               -- false for sign-ins and technical steps (?detail=1)
  allowed boolean NOT NULL, code text,  -- code: a refusal's reason
  actor text NOT NULL, subject text,    -- subject: the member it is about
  credential uuid,                      -- the way in
  project uuid, environment uuid, secret uuid, version uuid,
  request_id text, operation_id uuid, related bigint, source_ip text,
  detail text,                          -- what the API returns as `metadata`, JSON; no query reads it (D199)
  mac bytea NOT NULL CHECK (octet_length(mac) = 16),      -- the vault's, over the row, an old entry's row included
  PRIMARY KEY (at, number, log)         -- the page with ?detail=1, newest first
);
CREATE INDEX audit_events_shown_idx ON audit_events (shown, at, number);   -- the default page
CREATE INDEX audit_events_actor_idx ON audit_events (actor, at, number);   -- a member's page
CREATE TABLE audit_event_places (       -- the page of a project, an environment or a key
  place uuid NOT NULL, at bigint NOT NULL, number bigint NOT NULL, log smallint NOT NULL,
  PRIMARY KEY (place, at, number, log)
);
CREATE TABLE audit_member_keys (        -- the offboarding report: the newest time a member read or wrote each value
  principal text NOT NULL, secret uuid NOT NULL, version uuid NOT NULL, wrote boolean NOT NULL,
  at bigint NOT NULL, number bigint NOT NULL, PRIMARY KEY (principal, secret, version, wrote)
);
CREATE TABLE audit_cursor (             -- how far the projector has gone, one row
  only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
  through bigint NOT NULL, pair bigint NOT NULL, at bigint NOT NULL,   -- the chains: listed through this checkpoint
  old_from bigint NOT NULL, old_hash bytea NOT NULL,                   -- the frozen log: listed down to this seq, and
                                                                       -- the hash the entry below it must have
  mac bytea NOT NULL CHECK (octet_length(mac) = 16)
);
```

**Where this corrects the sketch.** `log_changes` gets no `kind` column: it was for the audit page's indexes, and the
page stops reading the chain. The projector classifies each entry once, in TypeScript, from the payload whose MAC it
has checked. There is no table of object heads (section 4). And entries that change no object need a home, or
`audit_log` cannot freeze: a refusal, a refused sign-in, a finding. They go in `log_changes` as refused writes
already do, with the object `hash('event', request id)` and no seal, signed by the vault as everything in the chain
is. The app hands them over in one call, `note`; section 3 says which requests gain that call.

**Each projection must beat its absence.**

| Table | The page's query | Why the chain cannot serve it flat |
|---|---|---|
| `audit_events` | newest 200, of everyone or of one member | A use row has no member and no project (`log_uses` holds a credential id and a key id, by design). The page merges three logs in application code today, with a cursor of three positions. |
| `audit_event_places` | newest 200 at a project, environment or key | One entry touches up to 7 places: its key, environment and project, a reference's source's three, a personal config's parent. A filter over several values needs rows. `log_reads` spends 8 indexes on it today. |
| `audit_member_keys` | every value a member read or wrote, newest time each | Measured at 440k entries: 18 pages against 18,421 reading the entries, and the scan grows with every read the member makes. A CI token reads on every deploy. |
| `audit_cursor` and the projector | | They exist today for `log_reads` (533 lines). The new projector covers changes and events too, and replaces the day tables and triggers. |

One job writes all three tables and the cursor in one transaction per batch. It has three sources: the two chains,
of which it reads only windows the checkpointer has signed, and the frozen `audit_log`, which it reads backward from
its anchor, leaving out heartbeats and checkpoints (section 6). Rebuilding is the same code: `coffre audit rebuild`
empties the tables and sets both of the cursor's positions back, so the old log's rows are rebuilt as the new are.
Retention deletes a dropped day's uses with one range delete on the primary key, which starts with `at`. Residual
filters (a member at a place, `decision`, a scoped reader's visibility) run over a bounded window of the best index,
and the page returns what it found with `next`. The API already allows a short page with `more`, so no combination of
filters needs an index of its own.

**JSON columns, by the typed-columns rule (D199).** Two values stay JSON, because SQL never reads them and a test
fails any SQL that does: `log_changes.payload`, one signed value only the vault reads whole (no more `strpos`, no
`->>`), and `audit_events.detail`, display only, about 65 keys over 60 actions. `audit_log.metadata` is frozen
with its table and its 11 expression indexes dropped; `log_config` is dropped. Three lists of scalars become `text[]`
in 0.16, one small PR (T1): `proxy_reserved.names`, `passkeys.transports`, `oauth_clients.redirect_uris`.
`service_bindings.claims` and `.jwks` and `mcp_approvals.arguments` stay JSON: the identity provider or the tool
decides their shape. `roles.definition`, `proxy_definitions.items` and the five scope and policy columns are typed in
a task after 0.16: each is sealed and read inside SQL on the proxy's use path, 6 to 8 days that this redesign does
not need.

**The seal after.** A seal is the MAC of the object that one mapping (`packages/vault/src/objects.ts`) builds from the
row's typed columns. Once `log_config` is gone, no seal but a role's covers a stored JSON value. Splitting a JSON
column into typed ones later changes no seal while the object is the same, so it never needs the vault's keys.

## 3. What each operation costs after

**The request's own cost.** Measured through the harness of `change-cost.test.ts`, which runs a request as Workers do
(a connection per call, every Sync a round trip), with 0.15's log, warm. A statement is one the request waits for,
`BEGIN` and `COMMIT` aside; the checkpointer's seal and the projector run apart. The targets are the budgets that
`request-cost.alone.ts` and `change-cost.test.ts` hold each PR to.

| Operation | Today: statements, round trips, vault calls | Target | What changes |
|---|---|---|---|
| Use, one key by name | 1, 1, 1 | 1, 1, 1 | The statement is half as long and reads no `audit_log` (V2a, V2b). |
| Key write, one key | 7, 2, 2 (`writeKeys`, `waitSealed`) | 6, 2, 2 | The head lock's statement goes (A1). |
| Sign-in, browser | 10, 8, 3 (`access`, `prepare`, `waitSealed`) | 8, 5, 3 | The two reads of the head and the `audit_log` insert go. The transaction asks its reads together and leaves its writes to the commit, as a key write does (A1). |
| Audit page, one visit | 24, 26, 3 at a seeded log, more as the log grows | 6, 4, 2 | The flat check below (P2, P3). |
| Secrets list | 4, 4, 1 | 4, 4, 1 | The vault's statement reads rows by key; today it spends 3.1 ms planning its reads of `audit_log`. |
| `GET /api/me` | 2, 2, 0 | 2, 2, 0 | The credential's statement drops its read of the newest `policy.change`. |

Four of the six are already at their floor in statements and round trips. There the redesign buys planning time and
locks, and section 1's larger numbers are mostly the checkpointer and the projector at work beside the request. The
counts fall on the audit page, on sign-in and on refusals.

**What an event costs.** The chain has one signer, the vault, so an event the app decides reaches it through a vault
call, `note`: one statement under the fence shared, answered once written, as a use is, without waiting for its seal.
No allowed read and no page writes an event: a use's row is its record, and a list writes nothing today either.

| Event | Today, measured | After | Added to the request |
|---|---|---|---|
| A read allowed | The use's row, in the use's statement | The same | nothing |
| A read the vault refuses (no grant, no such key) | The use, then the app's transaction under the head: 5 round trips | The vault writes the refusal in the call that decided it, before it answers: 2 round trips | no call; 3 round trips fewer |
| A key write or member add the vault refuses | `recordRefusal`, a second call: 2 round trips | The same call, named `note` | nothing |
| A refusal the app decides (a route the caller may not use, an unknown environment) | The app's transaction under the head: 4 of the request's 9 round trips | `note`: 1 of 6 | 1 vault call; 3 round trips fewer |
| A sign-in allowed, a token issued or exchanged | An `audit_log` entry beside the credential's change | The credential's change is the record | nothing |
| A sign-in refused | The app's transaction under the head: 4 of 6 round trips | `note`: 1 of 3 | 1 vault call; 3 round trips fewer |
| A finding, an alert | The beat's own transaction | `note`, from the beat | no request |

So no audited read gains a vault call. The requests that gain one are those the app refuses on its own, and each
trades four round trips under a global lock for one under none. Nothing cheaper is safe there: the entry cannot ride
the caller's check, which comes before the decision, and an entry the app signed with its own key would be a second
chain, which is what `audit_log` is.

**The audit page's check, flat (D200).** Today a visit asks the list, a walk of 0.14's chain from its last anchored
point, and 0.15's trees. The walk is what grows: in #559's sweep the checks took 42 statements at 2,000 entries and
241 at 20,000. After, the page asks the list on its own connection and one vault call, `check`, which reads in one
round trip:

1. The newest signed checkpoint: both trees' notes and their Ed25519 signatures, held to the pair the signer
   remembers outside the database (the checkpointer's Durable Object, written before the row). A database writer who
   serves an older checkpoint ends below that pair, and the check says `behind`. A witness, where one is configured,
   is a second copy for a signer that lost its memory.
2. The entries above it, each one's MAC. The checkpointer ticks every 500 ms, so they are a handful; the check reads
   at most two ticks of the deployment's `/use` cap, derived from both, with no setting of its own: 1,250 entries at
   today's cap of about 1,250 uses a second. Past that the page says the checkpointer is late, not "verified".
3. The frozen log's last row, against the change that anchored it at the upgrade (section 6).
4. Handed in with the call: the rows shown and the cursor. Each row's MAC, the cursor's, and how far the cursor is
   behind the checkpoint, which the page shows as "listed through 14:05:03".

That is 6 statements, 4 round trips and 2 vault calls (`access`, `check`) at 2,000, 20,000 and 1M entries: the page's
budget, with its pages held flat by the sweep (S1). Section 4 lists what it catches and what it leaves.

**The full recheck is asked for.** The Verify button and `coffre verify log` walk everything in bounded steps, a
request each, as `verifyWhole` and `verifyReads` do today: 10,000 entries of the old chain, or one checkpoint's range
of the new one, re-derived and held to its signed root and to the projection's rows. Each step is far inside the 5 s
timeout, so nothing has to run outside its reach. Its cost follows the log, and nothing runs it unasked.

**No `log_verified`, and the beat writes nothing.** With a check on every visit, the row the first draft had the page
read has no reader, so the table is not built. The 5-minute beat keeps one job: it runs the same `check` when nobody
is looking and raises a finding when it fails. A scheduled re-derivation of the projections does not earn its place:
it would vouch for rows as they were when it ran, and a row deleted later is the recheck's to find, as today.

**One use function.** `use_credential` is 1,157 lines because its statement exists four times: with or without the
seal seeks, with or without a reference and forks; 648 lines are those copies. The target is one statement of about
500 lines: the seal seeks hang on `LEFT JOIN LATERAL … ON NOT cached`, the reference and fork rows are left joins by
primary key, and the access rule stays in `decide.ts`, written once. It reads the credential, the member, the grants,
the key, its version, its environment, the policy, the cap row and the fence row by key, with no seal seek when the
isolate knows the log's newest number and up to 10 after a change, as today. Still one call per use.

**The policy revision disappears.** The app re-checks "the policy has not changed since I loaded the caller" on the
seq of the newest `policy.change`. After, it compares seals it already read, the roles' and those of the environments
the request touches, in the digest the two-trip key write already checks under its lock (`hold_inputs`).

**Locks after.** The head's row, and what is read under it, go with the last append to `audit_log`. Its other job does
not: it serializes changes against each other from their first statement, which 29 modelled re-checks rely on, and the
fence cannot take that over where it sits, in a change's last statement (A0's finding: two Owners who each remove
themselves both pass a count made before it). The shape is the coordinator's to pick; my proposal keeps a lock that
only changes take, an advisory lock with no row and nothing read under it. Then, last before the timeout (D201), L1
makes the fence the checkpointer's alone: uses and changes both take it shared, a change locks the objects it writes
exclusive, and a use locks the objects it reads shared, in key order. A write to one key then stalls only uses of that
key. Ten shared advisory locks cost a use 0.013 ms (0.052 ms against 0.039 ms for the one it takes today). The models
state each re-check against what it needs, the lock that excludes a change to what the flow read, so that L1 moves
none of them a second time.

## 4. The security argument

Example. Someone with write access to the tables, and no key, sets `revoked_at` back to null on a credential. The
row's seal no longer matches its columns, so the vault refuses it. They put the whole old row back, seal included. The
row is consistent, but the credential's newest change in `log_changes` is the revoke, with another seal, so the vault
refuses it. They delete the revoke from the log. The use passes until the next check of the signed Merkle tree, which
finds a leaf missing. A fact in a sealed row is as safe as a fact in the log, and it is read by key.

| Fact moved | Row | Altered or rolled back | Row or entry deleted | Caught by |
|---|---|---|---|---|
| Settings | `settings` | seal differs from its newest change's | no row but a change in the log: refused | the vault, on the request that reads it |
| Keys in force and retired | `log_keys` | the same | the same | the vault, at sign-in, issue and bind |
| Protected, roles, the cap | `environments`, `roles`, `policy` | the same | the same | the vault, on every use and decision (already so) |
| Access revision | none | `principals.seal` | the same | already so; the read of `audit_log` only guarded against 0.14 writers, and none is left |
| Binding removed, reference ended, revoked | their rows | the flag is inside the sealed object (`objects.ts`: `revoked`, `ended`) | the same | the vault, on every use |
| What the pages list | the projections | a row's `mac` fails when the page shows it | the cursor's MAC covers how far it went; a row deleted behind it is the recheck's to find | the vault on every visit; the Verify button and `coffre verify log` |

**The three hard spots.**
1. *A projection can omit rows.* The offboarding report answers from `audit_member_keys` only when the cursor has
   passed the checkpoint that sealed the member's removal. Removal is a change, it answers only once sealed and
   witnessed, and every earlier read has a smaller number, so every read is inside. Before that the report says
   `behind`, as today. The summary row is written with the event, and its time only rises.
2. *Flags must be inside the seal.* They are: `revoked` for credentials, connections and bindings, `ended` for a
   reference under its holder's key, `protected` and both archivals for an environment. This design adds no flag
   outside a sealed object.
3. *Objects made before the upgrade need a first change to seal against.* 0.15.0's cutover wrote one for every
   existing object. 0.16 adds two kinds, the settings and each key, and the vault writes their first change in its
   upgrade step (section 6). No existing object changes what its seal covers, so nothing is sealed again.

**What a visit's check catches.** For a database writer with no key:

| They | The visit | The recheck |
|---|---|---|
| alter or forge an entry above the newest checkpoint | caught: its MAC | |
| delete a checkpoint, or serve an older one | caught: the database ends below the pair held outside it | |
| alter a row the page shows | caught: the row's MAC | |
| stop the projector, or put an older cursor back | shown: "listed through" falls behind the checkpoint | |
| cut or extend the frozen log | caught: its last row is not the anchor | |
| alter or delete an entry inside a signed range, or an old entry of the frozen log | not seen: the page shows the projection's own signed rows | caught: the range's root, the chain's hashes |
| delete a projection row | not seen | caught: the range re-derived and compared |
| delete a use younger than one tick, before a checkpoint covers it | not seen by any check, today or after. A change answers only once sealed for this reason; a use does not wait. | |

**The seal seek stays on `log_changes`.** Nine seeks on `(object, number)` against nine primary-key reads of a heads
table, prepared: 0.143 ms against 0.132 ms at 100k changes, 0.196 ms against 0.134 ms at 5M. A heads table would save
0.06 ms at fifty times Equisafe's size, as a second copy every writer keeps in step. Not built.

**Which changes need a model first.**

| Change | Model | When |
|---|---|---|
| The head lock leaves changes | `Coffre.tla` with its 11 scenarios, `Credentials`, `Issuing`, `Factor`, `Bulk`, `WorkloadEnrollment`, `AppKey`, `Writing`, `WriteLocks`, `Lifecycle`: 29 "recheck under the head" protections become "under the lock that excludes a change to what was read", bound to the fence | first (A0) |
| The policy revision becomes a digest of seals | `Lifecycle` (LifecyclePolicy), `Writing` (WritingProtect) | first (A0) |
| The cap read from the `policy` row, the 0.14 guard gone from uses | `HotPathOne` (CapSealed, HotPathOnePolicy) | first, small |
| Per-object locks | `HotPathOne` (UseLocks, ChangeLocks, LockToCommit), `WriteLocks` (NoWaitCycle), `Batching` | first, the largest: its model starts once A0's is in review, stacked on it, ahead of V2b's and A1's code |
| Two new sealed objects | `SealedObjects`, after `Roles.tla`'s pattern | with the PR |
| The projector covers changes, the summary | `Reads.tla`, with #560's scenario | with the PR |
| The cutover deleted | `Migration015` goes; its issue-lock order moves to `WriteLocks` | with the PR |

## 5. What gets deleted

| What | Size |
|---|---|
| The vault's 0.14 mode (`log: '0.14'`), its CI job | 76 branch lines in `vault.ts`, 252 in 70 test files, `audit-writer.test.ts` (322) |
| The 0.14 write path | `packages/db/src/log.ts` append and head code (348), `appendAudit` (57), the vault's `#append`, `#record`, `#weigh` (62), 155 entry sites in the app rewritten as events |
| The cutover | 1,139 source lines, 7 SQL functions (164), 2 test files (1,294), `Migration015.tla` and 11 scenarios (1,531), 819 lines of docs |
| The head lock | 6 statements in 5 SQL functions, about 95 lines of `log.ts`, 10 callers, `audit_chain_head`, #552's head waiters |
| `audit_log` reads on request paths | 26 reads in 10 SQL functions, 16 read sites in TypeScript: the snapshot statement's five, `answers.ts`, `policyNow`, `hasTombstone`, `referenceRows` |
| Freeze probes | about 200 source lines, 22 SQL, 230 test, `WorkloadFreezing.cfg` |
| Triggers | `audit_log_fence`, `audit_log_refuse_old`, `log_reads_placed_insert`, `log_reads_placed_update`, and `audit_log_releases` with `vault_releases` once V1 deletes the 0.14 read path that counts from them: 5 of 9 |
| Indexes | all 33 on `audit_log`; 18 on `log_changes` (`sign_in`, `issue_revoke`, `written`, `admitted`, `refused_write`, `refused_add`, each with its `_actor`, `_environment` and `_object` variants); 10 on `log_reads`; `secrets_lookup_idx`; 4 on `secret_references`; `credentials_enrollment_roots_idx` |
| `log_reads` and its family | 4 tables, 6 functions (182), 955 source lines, 430 test |
| The 0.14 chain's upkeep | heartbeats and checkpoints every 5 minutes, `Audit.tla` and 6 scenarios (910, the 7 to 11 minute `Tampering` run among them); `Audit.lean` stays for the verifier |
| `use_credential`'s copies, last release's overloads | 1,157 lines to about 500; `sign_in/35`, `issue_token/28`, `change_bindings/53` (111) |
| Functions restated whole in migrations | 30,607 of the 33,140 lines of migration SQL, 19,347 of them `use_credential` 22 times |
| Drizzle snapshots | 328,176 lines; the migrator reads only the journal |
| `docs/design/0.15-plan.md`, `log-015.md` | 5,204 lines |

**The three open PRs.** **#559** gives the growth sweep (`scripts/history-sweep.*`, `history.sweep.ts`, `growth.ts`,
about 1,300 lines), which runs every runtime statement at 2,000 and 20,000 entries and fails one whose pages double:
the timeout's proof. Also kept: the cap of 246 key rotations. Lost: its 4 `audit_log` indexes, `hiddenMore`, and
`log_uses (at, number)`, a third index there, unless the checkpointer's `lowestAbove` gives it a measured reason.
**#560** gives the rule that a version is still current when its `(iv, auth_tag)` equal the current version's, its
tests and the `Reads.tla` scenario. Lost: its table, triggers and migration, which `audit_member_keys` replaces.
**#552** gives the pools derived from `max_connections` (`connections.ts`, land now) and the timeout's code
(`holdRuntimeTimeouts`, 60 s for retention's two statements). Lost: the head waiters, which die with the head lock.

## 6. The upgrade from 0.15.0

1. **Stop.** Run `coffre verify log` on 0.15.0: the full walk of the old chain, in steps, green. Take the app off its
   route, let one 5-minute beat pass so that the chain ends in a checkpoint its anchor holds, then back up. The beat
   is the Worker's cron, which fires with the route gone; 0.15.0 has no command or route that runs it on demand.
2. **`coffre migrate`**, as the owner, one migration. It refuses a database that is not a cut-over 0.15.0 (no cutover
   change in `log_changes`, or a schema past 0049 that is not 0.16's). In SQL it creates the tables; fills `settings`
   and `log_keys` from the newest entries, unsealed; drops the indexes, triggers, functions and tables of section 5;
   revokes INSERT on `audit_log`. It copies nothing into the projections. 0.15.0's code cannot run on the result: the
   functions it calls are gone or changed, and a row it writes directly has no seal, which the vault refuses.
3. **Deploy 0.16.**
4. **The vault's step**, on its first call, while the app answers 503 `upgrading` at its one door. It is the same
   size whatever the log holds. It checks the old chain from the newest checkpoint the anchor holds to its last
   entry, as 0.15.0's own check does between beats: the app its entries' MACs, the vault its own, and the hashes
   that link them. That is one beat's entries, 10,000 a call at most. It writes the change that names the chain's
   final seq and hash, the **anchor** the old log answers to from then on. It checks the settings' and keys' rows
   against the signed entries they came from and writes each one's first change and seal. It signs the cursor at
   the anchor, writes the change that marks the upgrade done, and the door opens.

**The projector lists the old log; the migration does not.** From the anchor it walks `audit_log` backward, 5,000
entries a batch. An entry's hash covers its content and the hash before it (`entryHash`), so each batch is
authenticated by the one above it, down from the anchored hash, with no key and no walk from the first entry. It
lists every entry but heartbeats and checkpoints, signs each row, and moves the cursor's old position (a seq, and the
hash the entry below must have) in the batch's transaction, so a batch that dies is done again from the cursor. A
batch is about 1.7 MB and a few milliseconds of hashing, well inside a Worker's 128 MB and its CPU limit. Equisafe's
440,000 entries are 88 batches. `coffre audit rebuild` reads the frozen log again the same way, so the old rows stay
a cache that one job rebuilds, and the filter is one predicate: listing heartbeats after all is a rebuild. The door
does not wait for the walk. Until it reaches the first entry, the audit page says how far back it lists and the
offboarding report says `behind`.

**What a database writer can do in the gap.** Before the anchor: cut entries off the end of the old chain, back to
the newest checkpoint held outside the database at most. Those are the last beat's entries, of the kinds 0.15.0
writes to the old log alone (sign-ins, refusals, token issues), and 0.15.0 has the same window between two beats;
the beat that step 1 waits for leaves nothing in it. They cannot add or alter an entry without a key. After the
anchor: an old entry altered before the projector reaches it stops the walk there, with a finding; one altered after
is the recheck's to find, and the rows the page shows carry MACs of their own.

**If the step dies halfway, it is rerun.** Each write is one change with a request id made from what it seals
(`upgrade-0.16:settings`), compared-and-set on a null seal, so the next call skips what is done and goes on. It only
adds changes and fills null seals. Restore is for a step that refuses: the old chain's tail does not verify, or a row
disagrees with its entry. The door then says which, and the operator restores the backup, or accepts the loss with the
existing `coffre audit accept-loss`.

**How long.** The migration creates and drops, and the vault's step reads one beat's entries and writes a handful of
changes: seconds, whatever the log holds. The walk runs behind the open door. Its SQL equivalent took 6 s for 440,000
entries on my Postgres (3.2 s the events, 2.3 s their 607,200 place rows, 0.4 s the summary), so I expect about a
minute through the projector. The rehearsal on a copy of Equisafe's database (T265) measures the migration, the step,
the walk, the size after (285 MB of events and places for 440k entries beside 153 MB of `audit_log`, before the
heartbeats and checkpoints are left out), the first audit page, and the sweep at that size.

**How it is tested.** One script, `scripts/upgrade-check.sh`, built on `test:compat`'s installer: install 0.14.5 from
npm, run its own conformance to fill a database, update to 0.15.0 and let it cut over, save the audit API's pages
(heartbeats and checkpoints filtered out) and one offboarding report, then run this checkout's migrate and start.
Once the walk is done it requires the same entries in the same order, the same report, a green `coffre verify log`,
a use, a change, a second run of the vault's step killed between two of its writes, and a walk killed between two
batches. `pnpm test:compat` is off for 0.16.0, as it was for 0.4.0, and returns with 0.16.1. A dev database on main's
unreleased migrations starts over.

## 7. The work graph

Three lanes by the files they own. **V** is the vault (`packages/vault/src`). **P** is the projection and the pages
(`vault/src/reads.ts`, `server/src/api/audit.ts`, `api/members.ts`, `packages/ui`). **A** is the app
(`server/src/api`, `server/src/db`, `packages/db/src/log.ts`). Each schema PR adds its own numbered migration until
the collapse. Days are working days for one agent under the fast gate. Net lines are rough.

| PR | What, main files | After | Model first | Migration | Days | Net lines |
|---|---|---|---|---|---|---|
| E1-E7 | The early list, handed out: snapshots, sessions, `ActionsLog`, the 0.14 mode, freeze probes, dead indexes | #564 for four of them | no | E6 | 3 | -330,000 |
| V0 | Cutover deleted; migrate refuses a database not cut over. `vault/cutover.ts`, `server/cutover.ts`, `store.ts`, `vault.ts`, `formal/Migration015*` | E4 | no, `WriteLocks` edit with it | no | 1.5 | -4,800 |
| V2a | One use statement, same reads. `use_credential`, `use_route`, `vault/use.ts` | E4 | no | yes | 3 | -700 |
| P1 | The projector and its four tables; every change, event and use, and the old log backward from its anchor; `coffre audit rebuild`. Adds, because nothing can be deleted until pages can read it. | E4 | no, `Reads.tla` with it | yes | 4 | +900 |
| P2 | Pages read the projection: `GET /audit`, the report, MCP. Deletes `log_reads`, the three-log merge, 18 + 11 + 10 indexes | P1 | no | yes | 3 | -2,300 |
| P3 | The page's check, flat: one `check` call a visit (6 statements, 4 round trips), the beat runs the same; the full walk in steps behind a Verify button and `coffre verify`; the page's walk of 0.14's chain deleted | P2 | no | no | 2 | -300 |
| T1 | Three `text[]` columns, `log_config` dropped | #564 | no | yes | 1 | -50 |
| A0 | Models for the head lock and the policy revision, each re-check stated against the lock it needs | now | it is the model | no | 2 | 0 |
| V1 | The vault's entries go to the chain only; `settings`, `log_keys`; the vault's upgrade step (one beat's tail, the anchor); `note` for events, and a refused read written by the call that refused it | P2 | `SealedObjects` with it | yes | 4 | -300 |
| A1 | The app's entries go to the chain; head lock, `audit_chain_head` and the policy revision deleted; `audit_log` frozen; sign-in in 5 round trips | P2, A0 | A0 | yes | 4 | -700 |
| V2b | `audit_log` reads out of the use and change functions; the cap from its row; old overloads dropped | V1, V2a | `HotPathOne`, small | yes | 1.5 | -300 |
| L1 | Per-object locks; the fence is the checkpointer's alone (D201). Its model is a draft PR stacked on A0, started in week one | V2b, A1 | yes | yes | 4 | +100 |
| U1 | `scripts/upgrade-check.sh`, its 0.15.0 pages compared without heartbeats and checkpoints | V1, A1 | no | no | 2 | +500 |
| S1 | The 5 s timeout from #552, with #559's sweep green at two sizes. Adds the sweep, which is the proof | all above | no | no | 2 | +1,600 |
| C1 | The collapse: one upgrade migration from 0.15.0, one baseline for new databases, 80 migration files deleted, functions as one file each, a parity test (0.15.0 plus the migration equals the baseline) | all above | no | it is the migration | 2 | -30,000 |
| C2 | `AGENTS.md`: 0.16.0 is a clean break like 0.4.0, expand-then-contract resumes with 0.16.1. Old design docs deleted | C1 | no | no | 0.5 | -5,300 |

**Order.** Day 0: E4 alone, since it edits `vault.ts`. Then three lanes at once. V: V0, V2a, then V1 once P2 is in,
V2b, L1. P: P1, P2, P3. A: T1, A0, then A1 once P2 is in, U1, S1. C1 and C2 close. No stack is deeper than two.
**Pairs that collide:** V1 and A1 both need `note` in the vault's contract (`packages/core/src/vault.ts`), so V1 lands
it and A1 uses it. P2 and P3 both edit `server/src/api/audit.ts` and run in sequence, as do E4 and V0 in `vault.ts`.
Every schema PR appends to `schema.ts` and the journal, one-line conflicts.

**Estimate.** About 40 agent-days. With three lanes the longest path is E4, P1, P2, V1, V2b, L1, S1, C1: 18 to 22
working days with L1 in (D201), if the two model-first PRs (A0 and L1) hold their size. They are where the risk is.
A0 retargets 29 protections in ten modules, and a counterexample there changes A1's shape. L1's model is the plan's
largest, so it is written in week one, on A0's, and its counterexamples come before V2b's and A1's code, not after.
On Node, the projector and the beat run on timers in the vault's process, where Workers use a Durable Object alarm.

## 8. Decided

No question is open. The five the first draft asked:

- **JSON that SQL never reads** (Erwin, D199): `log_changes.payload` and `audit_events.detail` stay JSON, and a test
  fails any SQL that parses them. The JSON columns SQL does read are typed in a task after 0.16.
- **The audit page's checks** (Erwin, D200): on every visit, at a cost that does not grow with the log; the full
  recheck only when asked (section 3). The first draft's scheduled row, `log_verified`, is not built.
- **The offboarding report and retention** (coordinator, on D161): the report covers what retention keeps and states
  the date it covers from. The summary stays a cache the projector rebuilds.
- **Per-object locks** (Erwin, D201): in 0.16, last before the timeout.
- **Old heartbeats and checkpoints** (coordinator): not listed. They stay in `audit_log`, verified, and a rebuild
  with another filter brings them back.

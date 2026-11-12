# State rows and the audit projection (0.16)

Draft, `[DESIGN, DO NOT MERGE]`: the build plan for finishing what 0.15 started. Settled before it: Workers on
Postgres; a clean break (0.16 upgrades offline from exactly 0.15.0, rollback is restoring the backup); at most 2
secondary indexes per table; derive, don't sync; typed columns; no planner steering; the 5 s statement timeout last.
Assumed, and Erwin's to overturn: Q2 and Q5 below; audit filtered by place stays for the CLI and API; a change still
answers only once sealed and witnessed. Numbers were measured on 2026-11-12 on main `021a8863`, on a Postgres 16.14 of
my own: `pg_stat_statements` under the dev stack, `EXPLAIN (ANALYZE, BUFFERS)` in a warm session, `pgbench` with one
client. Catalog facts come from a migrated database.

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

**What each operation runs.** Statements over the three database logins, with the sealing and projecting they cause.

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
  detail text,                          -- what the API returns as `metadata`; no query reads it (Q1)
  mac bytea CHECK (octet_length(mac) = 16),               -- the vault's; null for copied 0.14 entries
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
  through bigint NOT NULL, pair bigint NOT NULL, at bigint NOT NULL, mac bytea NOT NULL CHECK (octet_length(mac) = 16)
);
CREATE TABLE log_verified (             -- the last scheduled check, one row, read by the page
  only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
  through bigint NOT NULL, at bigint NOT NULL, problem text, mac bytea NOT NULL CHECK (octet_length(mac) = 16)
);
```

**Where this corrects the sketch.** `log_changes` gets no `kind` column: it was for the audit page's indexes, and the
page stops reading the chain. The projector classifies each entry once, in TypeScript, from the payload whose MAC it
has checked, and `change_input` takes the operation as a typed parameter instead of parsing the payload. There is no
table of object heads (section 4). And entries that change no object need a home, or `audit_log` cannot freeze: a page
read, a refusal, a sign-in, a finding. They go in `log_changes` as refusals already do, with the object `hash('event',
request id)` and no seal, written under the fence shared so they wait for no one. The vault signs them, as it signs
everything in the chain; the app hands them over in one call (`note`), outside any transaction.

**Each projection must beat its absence.**

| Table | The page's query | Why the chain cannot serve it flat |
|---|---|---|
| `audit_events` | newest 200, of everyone or of one member | A use row has no member and no project (`log_uses` holds a credential id and a key id, by design). The page merges three logs in application code today, with a cursor of three positions. |
| `audit_event_places` | newest 200 at a project, environment or key | One entry touches up to 7 places: its key, environment and project, a reference's source's three, a personal config's parent. A filter over several values needs rows. `log_reads` spends 8 indexes on it today. |
| `audit_member_keys` | every value a member read or wrote, newest time each | Measured at 440k entries: 18 pages against 18,421 reading the entries, and the scan grows with every read the member makes. A CI token reads on every deploy. |
| `audit_cursor` and the projector | | They exist today for `log_reads` (533 lines). The new projector covers changes and events too, and replaces the day tables and triggers. |

One job writes all three tables and the cursor in one transaction per batch, and reads only windows the checkpointer
has signed. Rebuilding is the same code: `coffre audit rebuild` empties the tables and sets the cursor to zero.
Retention deletes a dropped day's uses with one range delete on the primary key, which starts with `at`. Residual
filters (a member at a place, `decision`, a scoped reader's visibility) run over a bounded window of the best index,
and the page returns what it found with `next`. The API already allows a short page with `more`, so no combination of
filters needs an index of its own.

**JSON columns, by the typed-columns rule.**

| Column | Verdict |
|---|---|
| `audit_log.metadata`, 11 expression indexes | Frozen with its table. The indexes are dropped. Read once, by the upgrade. |
| `log_config.value` | Table dropped in 0.16. |
| `log_changes.payload` | Stays one signed value that only the vault reads whole. SQL stops looking inside: no `strpos`, no `->>` (Q1). |
| `audit_events.detail` | Display only, about 65 distinct keys over 60 actions (Q1). |
| `proxy_reserved.names`, `passkeys.transports`, `oauth_clients.redirect_uris` | Lists of scalars: `text[]` in 0.16, one small PR. |
| `service_bindings.claims` and `.jwks`, `mcp_approvals.arguments` | Stay JSON. The identity provider or the tool decides their shape. |
| `roles.definition`, `proxy_definitions.items`, the scopes (`credentials.scope`, `principals.scope`, `enrollment_codes.scope`, `service_bindings.scope` and `.policy`) | Second cut, after 0.16. Each is sealed and read inside SQL on the proxy's use path. Typing them is 6 to 8 more days and touches nothing this redesign needs. |

**The seal after.** A seal is the MAC of the object that one mapping (`packages/vault/src/objects.ts`) builds from the
row's typed columns. Once `log_config` is gone, no seal but a role's covers a stored JSON value. Splitting a JSON
column into typed ones later changes no seal while the object is the same, so it never needs the vault's keys.

## 3. What each operation reads after

| Operation | Rows by key | Seal seeks | Log inserts | `audit_log` |
|---|---|---|---|---|
| Use, isolate current | credential, member, grants, key, version, environment, policy, cap row, fence row | 0, plus the log's newest number | 1 use | 0 (today 1 to 2) |
| Use, after any change | the same, a reference's source and a fork's parents when there are any | up to 10 (today up to 10) | 1 use | 0 |
| Change, one secret written | key, version, environment, member, credential | 1 per row it changes or decides on | 1 change | 0 (today 1 append, 3 reads, the head lock) |
| Sign-in | identity, member, credential, `settings`, `log_keys` | 2 | 1 change, 1 event | 0 (today 13 mentions) |
| Audit page | `log_verified`, `audit_cursor`, 200 events by one index | 0 | 0 | 0 (today 33 mentions, 87 statements) |
| Offboarding report | member, `audit_member_keys` by key prefix, the keys by primary key | 0 | 0 | 0 |

**One use function.** `use_credential` is 1,157 lines because its statement exists four times: with or without the
seal seeks, with or without a reference and forks. 97 lines are identical in all four, and 648 lines are those copies.
The target is one statement. The seal seeks hang on `LEFT JOIN LATERAL … ON NOT cached`. The reference and fork rows
are left joins by primary key, and a null key descends no index. The access rule is already written once, in
`decide.ts`; SQL only gathers rows. Still one call per use. Budget: about 500 lines, held by `request-cost.alone.ts`
and `pnpm bench:workers` before and after.

**The policy revision disappears.** The app re-checks "the policy has not changed since I loaded the caller" on the
seq of the newest `policy.change`. After, it compares seals it already read, the roles' and those of the environments
the request touches, in the digest the two-trip key write already checks under its lock (`hold_inputs`).

**Locks after.** The head lock goes with the last append to `audit_log`. Flows that re-check a decision "under the
head" re-check under the fence, which they already take next. A last step, separable, makes the fence the
checkpointer's alone: uses and changes both take it shared, a change locks the objects it writes exclusive, and a use
locks the objects it reads shared, in key order. A write to one key then stalls only uses of that key. Ten shared
advisory locks cost a use 0.013 ms (0.052 ms against 0.039 ms for the one it takes today).

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
| What the pages list | the projections | a row's `mac` fails when the page shows it | the cursor's MAC covers how far it went; the scheduled check re-derives each signed window and compares | the vault on the page, the check every 5 minutes, `coffre verify log` |

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

**The seal seek stays on `log_changes`.** Nine seeks against nine primary-key reads of a heads table, prepared:

| Size | 9 seeks on `(object, number)` | 9 reads of a heads table |
|---|---|---|
| 100k changes, 10k objects | 0.143 ms | 0.132 ms |
| 5M changes, 200k objects | 0.196 ms | 0.134 ms |

A heads table would save 0.06 ms at fifty times Equisafe's size, as a second copy every writer keeps in step. Not built.

**Which changes need a model first.**

| Change | Model | When |
|---|---|---|
| The head lock leaves changes | `Coffre.tla` with its 11 scenarios, `Credentials`, `Issuing`, `Factor`, `Bulk`, `WorkloadEnrollment`, `AppKey`, `Writing`, `WriteLocks`, `Lifecycle`: 29 "recheck under the head" protections become "under the fence" | first |
| The policy revision becomes a digest of seals | `Lifecycle` (LifecyclePolicy), `Writing` (WritingProtect) | first |
| The cap read from the `policy` row, the 0.14 guard gone from uses | `HotPathOne` (CapSealed, HotPathOnePolicy) | first, small |
| Per-object locks | `HotPathOne` (UseLocks, ChangeLocks, LockToCommit), `WriteLocks` (NoWaitCycle), `Batching` | first, the largest |
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

**The three open PRs.**

- **#559** gives the growth sweep: `scripts/history-sweep.*`, `history.sweep.ts`, `growth.ts` and its doc, about 1,300
  lines. It runs every runtime statement at 2,000 and 20,000 entries and fails on a statement whose pages double. It
  is the timeout's proof. Also kept: the cap of 246 key rotations. Lost: its 4 `audit_log` indexes and `hiddenMore`.
  Its `log_uses (at, number)` would be a third index on that table; the checkpointer's `lowestAbove` gets rewritten or
  the index gets its measured reason.
- **#560** gives the rule that a version is still current when its `(iv, auth_tag)` equal the current version's, with
  its tests, and the `Reads.tla` scenario. Lost: the table, the triggers, the migration. `audit_member_keys`, written
  by the projector, replaces them.
- **#552** gives the pools derived from `max_connections` (`connections.ts`, land now) and the timeout's code
  (`holdRuntimeTimeouts`, 60 s for retention's two statements). Lost: the head waiters, which die with the head lock.

## 6. The upgrade from 0.15.0

1. **Stop.** Take the app off its route, then back up (`coffre backup`).
2. **`coffre migrate`**, as the owner, one migration. It refuses a database that is not a cut-over 0.15.0 (no cutover
   change in `log_changes`, or a schema past 0049 that is not 0.16's). In SQL it creates the tables; copies
   `audit_log` into `audit_events`, `audit_event_places` and `audit_member_keys`; fills `settings` and `log_keys` from
   the newest entries, unsealed; drops the indexes, triggers, functions and tables of section 5; revokes INSERT on
   `audit_log`. 0.15.0's code cannot run on the result: the functions it calls are gone or changed, and a row it
   writes directly has no seal, which the vault refuses.
3. **Deploy 0.16.**
4. **The vault's step**, on its first call, while the app answers 503 `upgrading` at its one door. It does what SQL
   cannot, for want of the vault's keys. It walks the whole 0.14 chain against its anchor one last time and writes the
   change that names its final seq and hash, which the old log is verified against from then on. It checks the
   settings' and keys' rows against the signed entries they came from and writes each one's first change and seal. It
   signs the cursor, projects the 0.15 chain's entries and writes `log_verified`. Last, it writes the change that
   marks the upgrade done, and the door opens.

**If the step dies halfway, it is rerun.** Each write is one change with a request id made from what it seals
(`upgrade-0.16:settings`), compared-and-set on a null seal, so the next call skips what is done and goes on. It only
adds changes and fills null seals. Restore is for a step that refuses: the 0.14 chain does not verify, or a row
disagrees with its entry. The door then says which, and the operator restores the backup, or accepts the loss with the
existing `coffre audit accept-loss`.

**How long.** The copy of 440,000 entries took 6 s on my Postgres: 3.2 s for the events, 2.3 s for 607,200 place rows,
0.4 s for the summary, indexes in place. The drops are instant. The vault's step reads the old chain once and writes a
handful of changes. I expect under a minute for the database part. The rehearsal on a copy of Equisafe's database
(T265) must measure the migration's duration, the vault step's duration, the size after (events and places came to 285
MB for 440k entries, beside 153 MB for `audit_log`), the first audit page, and the sweep at that size.

**How it is tested.** One script, `scripts/upgrade-check.sh`, built on `test:compat`'s installer: install 0.14.5 from
npm, run its own conformance to fill a database, update to 0.15.0 and let it cut over, save the audit API's pages and
one offboarding report, then run this checkout's migrate and start. It requires the same entries in the same order,
the same report, a green `coffre verify log`, a use, a change, and a second run of the vault's step killed between two
of its writes. `pnpm test:compat` is off for 0.16.0, as it was for 0.4.0, and returns with 0.16.1. A dev database on
main's unreleased migrations starts over.

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
| P1 | The projector and its four tables; every change, event and use; the copy of `audit_log`; `coffre audit rebuild`. Adds, because nothing can be deleted until pages can read it. | E4 | no, `Reads.tla` with it | yes | 4 | +900 |
| P2 | Pages read the projection: `GET /audit`, the report, MCP. Deletes `log_reads`, the three-log merge, 18 + 11 + 10 indexes | P1 | no | yes | 3 | -2,300 |
| P3 | Checks leave the page: the 5-minute beat writes `log_verified`, the page reads one row, a Verify button, `coffre verify` | P2 | no | yes | 2 | -100 |
| T1 | Three `text[]` columns, `log_config` dropped | #564 | no | yes | 1 | -50 |
| A0 | Models for the head lock and the policy revision | E4 | it is the model | no | 2 | 0 |
| V1 | The vault's entries go to the chain only; `settings`, `log_keys`; the vault's upgrade step; `note` for events | P2 | `SealedObjects` with it | yes | 4 | -300 |
| A1 | The app's entries go to the chain; head lock, `audit_chain_head` and the policy revision deleted; `audit_log` frozen | P2, A0 | A0 | yes | 4 | -700 |
| V2b | `audit_log` reads out of the use and change functions; the cap from its row; old overloads dropped | V1, V2a | `HotPathOne`, small | yes | 1.5 | -300 |
| L1 | Per-object locks; the fence is the checkpointer's alone | V2b, A1 | yes | yes | 4 | +100 |
| U1 | `scripts/upgrade-check.sh` | V1, A1 | no | no | 2 | +500 |
| S1 | The 5 s timeout from #552, with #559's sweep green at two sizes. Adds the sweep, which is the proof | all above | no | no | 2 | +1,600 |
| C1 | The collapse: one upgrade migration from 0.15.0, one baseline for new databases, 80 migration files deleted, functions as one file each, a parity test (0.15.0 plus the migration equals the baseline) | all above | no | it is the migration | 2 | -30,000 |
| C2 | `AGENTS.md`: 0.16.0 is a clean break like 0.4.0, expand-then-contract resumes with 0.16.1. Old design docs deleted | C1 | no | no | 0.5 | -5,300 |

**Order.** Day 0: E4 alone, since it edits `vault.ts`. Then three lanes at once. V: V0, V2a, then V1 once P2 is in,
V2b, L1. P: P1, P2, P3. A: T1, A0, then A1 once P2 is in, U1, S1. C1 and C2 close. No stack is deeper than two.
**Pairs that collide:** V1 and A1 both need `note` in the vault's contract (`packages/core/src/vault.ts`), so V1 lands
it and A1 uses it. P2 and P3 both edit `server/src/api/audit.ts` and run in sequence, as do E4 and V0 in `vault.ts`.
Every schema PR appends to `schema.ts` and the journal, one-line conflicts.

**Estimate.** About 40 agent-days. With three lanes the longest path is E4, P1, P2, V1, V2b, L1, S1, C1: 18 to 22
working days, or 16 to 18 without L1, if the two model-first PRs (A0 and L1) hold their size. They are where the risk
is. A0 retargets 29 protections in ten modules, and a counterexample there changes A1's shape. L1 is separable: 0.16
without it keeps 0.15's stall of uses behind a write and loses nothing else.

**Typed columns, two cuts.** In 0.16 as planned: what the redesign touches, plus T1, one day. All JSON columns in
0.16: 6 to 8 days more, for roles, proxy items and five scope columns. My pick is the first. On Node, the projector
and the scheduled check run on timers in the vault's process, where Workers use a Durable Object alarm; nothing else
differs.

## 8. Open questions for Erwin

**Q1. Two values stay JSON that SQL never reads. Is that within the typed-columns rule?** `log_changes.payload` is
what a change says, signed whole by the vault; its shape differs for each of about 30 operations, and after this
design no SQL looks inside it. `audit_events.detail` is the bag the audit API returns as `metadata`, about 65 distinct
keys over 60 actions, for display only. Options: (a) both stay opaque text, and a test fails any SQL that parses them;
(b) typed columns for both, about 65 nullable columns on `audit_events` and a table per kind of change, roughly 8 more
days; (c) the API stops returning `metadata`, which breaks CLI and MCP output. I recommend (a): everything a query
filters, joins or orders on is already a column.

**Q2. Should the audit page stop verifying the log on every visit?** Today a visit runs 87 statements, about two
thirds of them integrity checks, and again on every window focus. Proposed: a check every 5 minutes writes one row,
the page shows "verified through 14:05" with a Verify button, and `coffre verify log` still walks everything. The
cost: tampering shows up to 5 minutes later unless someone presses the button. Each row shown is still checked against
its MAC. I recommend yes.

**Q3. Should the offboarding report remember a read older than the uses' retention?** As far as I traced, today it
does not, and does not say so: once retention drops a day of uses, a value the member read that day is no longer
listed, even if it is still current. Options: (a) keep that, and have the report state the date it covers from, so the
summary stays a cache the projector can rebuild; (b) keep summary rows past retention, which makes the report stronger
and the summary a record no chain can rebuild. I recommend (a) for 0.16.

**Q4. Per-object locks (L1) in 0.16, or right after?** Without it a write still stalls every use for the few
milliseconds of its transaction, as in 0.15. With it a write stalls only uses of the object it changes. It needs the
plan's largest model change and four days. I recommend it last before the timeout, cut from 0.16 if A0 runs over.

**Q5. Should old technical entries appear in the new audit page?** The 0.14 chain writes a heartbeat and a checkpoint
every 5 minutes, 210,000 entries a year, so they are a large share of Equisafe's 440k (T265 counts them). 0.16 no
longer writes them. Copying them keeps `?detail=1` showing the same history; leaving them out shrinks the projection
by their share, and they stay in `audit_log` for verification either way. I recommend copying them, so the upgrade
check can demand identical pages.

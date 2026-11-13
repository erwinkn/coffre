# State rows and the audit projection (0.16)

Draft, `[DESIGN, DO NOT MERGE]`: the build plan for finishing what 0.15 started. Settled before it: Workers on
Postgres; a clean break (0.16 upgrades offline from exactly 0.15.0, rollback is restoring the backup); at most 2
secondary indexes per table; derive, don't sync; typed columns; no planner steering; the 5 s statement timeout last.
Decided since the first draft and folded in (section 8): the two JSON values SQL never reads stay JSON (D199); the
audit page checks the log on every visit, at a flat cost (D200); 0.16 keeps 0.15's one fence, and per-object locks are
not in it (D202, which supersedes D201); the offboarding report covers the reads retention keeps and every write; old
heartbeats and checkpoints are not listed. Assumed: audit filtered by place stays for the CLI and API; a change still
answers only once sealed. Numbers were measured on 2026-11-12 on main `021a8863`, on a Postgres 16.14 of my own:
`pg_stat_statements` under the dev stack, `EXPLAIN (ANALYZE, BUFFERS)` in a warm session, `pgbench` with one client,
and `change-cost.test.ts`'s harness for round trips. Catalog facts come from a migrated database.

## 1. Today in one page

Take one use: a signed-in person reads one key. The vault makes one call, `use_credential`. It reads the credential,
the member, the key, its environment and the policy by primary key. Each row carries a **seal**, a 16-byte MAC over
its columns, and the call seeks each row's newest entry in `log_changes` to check that the entry carries the same seal
(7 to 10 seeks, none when the isolate already knows the log's newest number). Then it reads the old log twice: the
newest `audit_log` entry about the member's access, and the newest `policy.change`. Those two reads, and their cousins
everywhere else, are what is left of 0.14.

| Table | From | Job today | Secondary indexes |
|---|---|---|---|
| `audit_log` | 0.14 | Hash-chained log. Also the store of a dozen facts of current state. Every change still appends to it, under a global lock. | 30 |
| `log_changes` | 0.15 | One signed entry per change to a sealed row. | 20, of which 18 serve the audit page |
| `log_uses` | 0.15 | One slim signed row per use, partitioned by day. | 2 |
| `log_reads` and 3 more | 0.15 | Uses as pages list them, with two day tables, two triggers and a cursor. | 10 |
| `principals`, `credentials`, `secrets`, `environments`, `service_bindings`, `mcp_connections`, `policy`, `roles` | 0.15 | State, one sealed row per object, read by primary key. | few |

**State still read from the old log.** Each line is a "newest entry of kind K" read, with a partial index of its own.

| Fact | Read by | After |
|---|---|---|
| Policy revision (newest `policy.change` seq) | every authenticated request, every use that carries an app token, token issue, bind, revoke: 11 reads in SQL, 5 in TypeScript | no row: the newest change's number of the roles object and of the policy object (section 3) |
| Policy content (protected environments, roles) | every vault decision, `GET /api/me` | the `policy` row's list (section 3) and `roles`: sealed rows |
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
change takes two global locks: the row `audit_chain_head` in its first statement, which no use takes, then in its last
statement an advisory lock exclusive (the **fence**) that every use takes shared. So a use waits for a change only
from the change's last statement to its commit, one round trip. 0.16 keeps that wait (D202).

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
-- audit_log: frozen. INSERT revoked from both logins; its 30 secondary indexes and 3 of its 5 triggers dropped.

-- STATE
CREATE TABLE settings (                 -- the instance's settings, one sealed row; read by key at sign-in and in /api/me
  name text PRIMARY KEY CHECK (name = 'instance'),
  -- who sets up service accounts themselves: two filters, each a kind ('all', 'only', 'except') and its list
  service_accounts_projects text NOT NULL,     service_accounts_project_ids uuid[] NOT NULL DEFAULT '{}',
  service_accounts_environments text NOT NULL, service_accounts_environment_slugs text[] NOT NULL DEFAULT '{}',
  seal bytea CHECK (octet_length(seal) = 16)   -- null only from the migration to the vault's upgrade step (section 6)
);
CREATE TABLE log_keys (                 -- every key the app or the vault has written under; read by key at sign-in, issue, bind
  holder text NOT NULL CHECK (holder IN ('app', 'vault')), key_id text NOT NULL,   -- key_id: '<holder>:<16 hex>'
  retired boolean NOT NULL DEFAULT false,                 -- one key per holder is in force
  seal bytea CHECK (octet_length(seal) = 16),             -- null as the settings'
  PRIMARY KEY (holder, key_id)
);
ALTER TABLE policy                      -- the protected set, whole, beside the cap (section 3): three aligned lists
  ADD COLUMN protected uuid[] NOT NULL DEFAULT '{}',            -- the environments' ids, with a row or not yet
  ADD COLUMN protected_projects uuid[] NOT NULL DEFAULT '{}',   -- each one's project
  ADD COLUMN protected_at bigint[] NOT NULL DEFAULT '{}',       -- when each was protected, ms
  ADD CHECK (cardinality(protected) = cardinality(protected_projects)
         AND cardinality(protected) = cardinality(protected_at));
ALTER TABLE principals DROP COLUMN access_seq, DROP COLUMN mac;   -- 0.14's pointer into audit_log and its row MAC
-- secret_references.created_seq loses its foreign key to audit_log and stays, as the number that orders a key's
-- references. The chain's sequence moves past the old log's last seq, so a new reference sorts after every old one,
-- and to a new name, which no 0.15.0 statement still running finds (section 6):
ALTER TABLE secret_references DROP CONSTRAINT secret_references_created_seq_fkey;
CREATE SEQUENCE log_next AS bigint CACHE 1;
SELECT setval('log_next', greatest(nextval('log_number'), (SELECT coalesce(max(seq), 0) + 1 FROM audit_log)));
DROP SEQUENCE log_number;
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
  reads_from bigint NOT NULL DEFAULT 0,  -- retention: no summary entry for a read timed below it; outside the MAC
  mac bytea NOT NULL CHECK (octet_length(mac) = 16)
);
```

**Where this corrects the sketch.** `log_changes` gets no `kind` column: it was for the audit page's indexes, and the
page stops reading the chain. The projector classifies each entry once, in TypeScript, from the payload whose MAC it
has checked (section 3, "A change carries its entry", says what it reads of a change). There is no table of object heads (section 4). And entries that change no object need a home, or
`audit_log` cannot freeze: a refusal, a refused sign-in, a finding. They go in `log_changes` as refused writes
already do, with an object of their own, `log_object('event', id)`, and no seal, signed by the vault as everything in
the chain is. The replay, and the full walk that replays the log, pass over an event as a change of no state (`op:
'event'`). The app hands them over in one call, `note`; section 3 says which requests gain that call.

**As pinned by the contract (K1, #581),** where it departs from the first drafts of this section:

- *The settings' scope is two filters.* Today's setting is a `Scope`: projects by id and environments by slug, each
  all, only or except. One `text` and one `uuid[]` held the first alone. `{ projects: 'all', environments: { except:
  ['prod'] } }` is the row `'all'`, `{}`, `'except'`, `{prod}`; a list is empty exactly when its kind is `all`.
- *Both new seals are nullable.* The migration fills the rows from the old log's entries, which it cannot seal; the
  vault's upgrade step seals each with its first change, compared-and-set on the null seal (`genesisCall`, which V0
  keeps for it). No reader accepts a row with no seal.
- *`note` takes an `audit_log` entry's fields by today's names:* action, allowed, code, actor, subject, the four
  places, credential, request id, detail, and `operationId` and `sourceIp`, which `audit_events` has columns for.
- *An event has an id of its own.* `NoteInput.id` is the row's `request_id` and the key of its object: a UUID its
  writer draws once and sends again unchanged on a retry, which then finds its row. The app's request id rides in the
  payload beside `operationId`, as a refusal's record has it today. So a request notes as many events as it has, the
  vault's own refusals inside it among them, and the projector fills `audit_events.request_id` from the payload for
  every kind of row. One id is derived: an event of no request that may be written twice (a finding of the beat) takes
  the one form pinned for it, `system:vault/finding:<checkpoint|none>:<behind|late|broken>` (`findingEventId`): a
  checkpointer stuck at 4410 is one `late` finding, `system:vault/finding:4410:late`, however many beats see it.
- *Who decided an event is in its payload.* `author`, `app` or `vault`, which the vault sets under its MAC and the
  projector reads. The actor cannot say it: a refusal the vault decides carries its caller as actor. The app never
  sends `author`, and `note` and `prepare` refuse the actor `system:vault`, the vault's alone, from the app.

**Each projection must beat its absence.**

| Table | The page's query | Why the chain cannot serve it flat |
|---|---|---|
| `audit_events` | newest 200, of everyone or of one member | A use row has no member and no project (`log_uses` holds a credential id and a key id, by design). The page merges three logs in application code today, with a cursor of three positions. |
| `audit_event_places` | newest 200 at a project, environment or key | One entry touches up to 7 places: its key, environment and project, a reference's source's three, a personal config's parent. A filter over several values needs rows. `log_reads` spends 8 indexes on it today. |
| `audit_member_keys` | every value a member read or wrote, newest time each | Measured at 440k entries: 18 pages against 18,421 reading the entries, and the scan grows with every read the member makes. A CI token reads on every deploy. |
| `audit_cursor` and the projector | | They exist today for `log_reads` (533 lines). The new projector covers changes and events too, and replaces the day tables and triggers. |

One job writes all three tables and the cursor in one transaction per batch. It has three sources: the two chains, of
which it reads only windows the checkpointer has signed, and the frozen `audit_log`, which it reads backward from its
anchor, leaving out heartbeats and checkpoints (section 6). Rebuilding is the same code: `coffre audit rebuild`
empties the tables and sets both of the cursor's positions back, so the old log's rows are rebuilt as the new are.
Retention deletes a dropped day's uses with one range delete on the primary key, which starts with `at`, and from the
summary the reads older than the day's end; it never deletes a `wrote` row (section 3). Residual filters (a member at
a place, `decision`, a scoped reader's visibility) run over a bounded window of the best index, and the page returns
what it found with `next`. The API already allows a short page with `more`, so no combination of filters needs an
index of its own.

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
| Use, one key by name | 1, 1, 1 | 1, 1, 1 | Its four statements become two, a lean one for the cached case and the full one, and neither reads `audit_log` (V2a, V2b). |
| Key write, one key | 7, 2, 2 (`writeKeys`, `waitSealed`) | 7, 2, 2 | The head lock's statement becomes the change lock's, which every change takes, the two-trip write among them (A0, `WriteTakesChangeLock`). The budget is 7. |
| Sign-in, browser | 11, 8, 3 measured (`access`, `prepare`, `waitSealed`) | 9, 5, 3 | The two reads of the head and the `audit_log` insert go. The transaction asks its reads together and leaves its writes to the commit, as a key write does (A1). |
| Audit page, one visit | 24, 26, 3 at a seeded log, more as the log grows | 6, 4, 2 | The flat check below (P2, P3). |
| Secrets list | 4, 4, 1 | 4, 4, 1 | The vault's statement reads rows by key; today it spends 3.1 ms planning its reads of `audit_log`. |
| `GET /api/me` | 2, 2, 0 | 2, 2, 0 | The credential's statement drops its read of the newest `policy.change`. |

Four of the six are already at their floor in statements and round trips. There the redesign buys planning time and
locks, and section 1's larger numbers are mostly the checkpointer and the projector at work beside the request. The
counts fall on the audit page, on sign-in and on refusals.

**What an event costs.** The chain has one signer, the vault, so an event the app decides reaches it through a vault
call, `note`: one statement under the fence shared, answered once written, as a use is, without waiting for its seal.
No page writes an event, and no allowed read but one: a use's row is its record, and a list writes nothing today
either.

| Event | Today, measured | After | Added to the request |
|---|---|---|---|
| A read allowed | The use's row, in the use's statement | The same | nothing |
| A proxy use the vault wrote no use row for (today, one whose values are all plain) | An `audit_log` entry, `credential.use` | `note`, after the credential is checked again and before the values go back; a `note` that fails fails the request | 1 vault call |
| A read the vault refuses (no grant, no such key) | The use, then the app's transaction under the head: 5 round trips | The vault writes the refusal in the call that decided it, before it answers: 2 round trips | no call; 3 round trips fewer |
| A key write or member add the vault refuses | `recordRefusal`, a second call: 2 round trips | The same call, named `note` | nothing |
| A refusal the app decides (a route the caller may not use, an unknown environment) | The app's transaction under the head: 4 of the request's 9 round trips | `note`: 1 of 6 | 1 vault call; 3 round trips fewer |
| A sign-in allowed, a token issued or exchanged | An `audit_log` entry beside the credential's change | The credential's change is the record | nothing |
| A sign-in refused | The app's transaction under the head: 4 of 6 round trips | `note`: 1 of 3 | 1 vault call; 3 round trips fewer |
| A finding | The beat's own transaction | An event the vault writes itself, in `beat` (below) | no request |

So no audited read gains a vault call but the plain proxy use, and that one goes if the use statement writes the use
row for a plain key too, which is open with V2a. The other requests that gain one are those the app refuses on its
own, and each trades four round trips under a global lock for one under none. Nothing cheaper is safe there: the entry
cannot ride the caller's check, which comes before the decision, and an entry the app signed with its own key would be
a second chain, which is what `audit_log` is.

**A change carries its entry.** A change's payload says what the object became, not what the page prints. A key's
change is `secret.write` or `secret.delete` with a version id and a nature. The 0.14 entry beside it said
`secret.loosen`, `secret.restore`, `secret.archive` or `secret.reset` and carried `was`, `kept`, `from` and `recipe`,
which the page's sentence is made of (`packages/ui/src/lib/audit-sentences.ts`). Once A1 stops writing those entries,
a sensitive value made readable would list as a plain write. Of the 37 sites whose entry has a change beside it, 22
lose the action or a detail that way, and all 37 lose what stands beside the detail: the trace (`credentialId`, `via`,
`confirmedBy`), the `operationId` that folds a 12-key write into one line, and who decided. So the entry rides whole
in the change that records the same act, under the vault's MAC:

- *The entry is an event's input without its id.* `ObjectChange` gains `entry`: a `NoteInput` less `id`, which the
  change's own identity serves, or `null`. That is the object the site hands `appendAudit` today, so converting a site
  moves what it already builds and drops no field by construction. The field is required, so each site says which. The
  vault refuses an entry whose actor is not the change's, or that is not allowed: a refused change is an event.
- *The field.* One key of the change's payload, `reported`, holding an event's payload less `op` and `ref`: `action`,
  `allowed`, `author`, `code`, `credential`, `detail`, `operationId`, `places`, `requestId`, `sourceIp`, `subject`.
  One encoder writes it and an event's payload, and the projector has one path from those fields to a row, with the
  row's own actor and time. The vault sets `author`: `app` for an entry `prepare` takes, `vault` for the one its own
  change carries (a settings change, a policy change, a member's). `places` are carried, not derived: a key's `ref`
  gives its id alone, the page files an entry under the project and environment as they were (a key moves later), and
  the member's summary needs the version id. A loosening:
  `{"digest":…,"op":"secret.write","ref":{…},"reported":{"action":"secret.loosen","author":"app","detail":{"from":"sensitive","kept":3,"key":"DB_URL","to":"secret","version":4},…},"version":"…"}`.
  No field is left out as unfit to sign: each is in `audit_log` or an event's payload today. A carrying change grows
  by its entry, 100 to 150 bytes of it the trace.
- *Why that name.* Keys sort, and until P2 deletes them 0.15's readers know a payload by how it starts (`RECORDS`,
  `packages/db/src/change-records.ts`: `{"caller":"`, `{"code":"`, `{"digest":`, `{"inputs":"`,
  `{"op":"credential.revoke",`). `reported` sorts after `op`, so no start moves. Each record is also known by text its
  payload holds (`"inputs":"`, `"signIn":{`), which a `detail` could hold by chance, so the writer refuses a `detail`
  whose encoding holds one of those texts, in `note`'s input check and in the carrier alike. The refusal lasts as long
  as one reader knows a payload by its text. P2 does not end that: `originsOf`, the read of admitted principals, one
  partial index and P1's `changeEvent` are left, and each needs an owner before section 2's "18 partial indexes
  dropped" is whole.
- *A fact the change's own record states is not repeated.* A token's kind and label are in the vault's `issue` record
  of the same payload, and a sign-in's run in `signIn`. The projector reads them there for the page's line, as
  `originsOf` reads a credential's origin there already, and the entry's detail leaves them out.
- *The vault holds the action to the op.* A fixed map beside `Op` (`packages/vault/src/inputs.ts`) lists the actions
  each op's change may carry: a `secret.delete` carries `secret.archive` or `secret.reset` and nothing else, a
  `secret.write` carries `secret.write`, `secret.loosen` or `secret.restore`, and A1's list of its sites fills the
  rest. An op the map does not name carries nothing, and `prepare` refuses the whole call for an action outside it. So
  the page cannot name an act the object did not undergo. The rest of the entry is the app's word, as an event's is,
  and `author` says so.
- *What an entry may name.* It is signed at `prepare`, before the transaction, so it names only what was read before
  it. Whatever of that the transaction reads again under the change lock, the site compares: a key's level before a
  write or a restore, the parent a reset shows through, the count of versions a deletion erases. A difference prepares
  again. What the transaction would choose is chosen before and written as chosen: a deletion's tombstone, which the
  slug's unique index refuses if it is taken.
- *No line is inferred from an op.* A change with no entry shows only where main's page shows it today, the eight
  records of the vault's own changes (a sign-in, an issue, a revoke, a sign-out, a two-trip write or add, either's
  refusal), by the same rules before the upgrade and after. Any other lists nothing. Otherwise the page gains lines no
  entry wrote: a sign-in's revokes of the credentials it replaces would each read as a sign-out. The chain still holds
  such a change, and the full recheck walks it.
- *One entry over several changes sits on one named change,* and the others carry `null`. They commit in one
  transaction, so the entry is there exactly when all of them are. Which one is the site's to name, by what the entry
  is about: a sign-in's on the issue its `targetCredentialId` names, the revokes of what it replaces silent; a
  step-up's on the new session's issue; an environment's deletion on that environment's own `environment.delete`, by
  id, its configs' and keys' deletions silent; a swept credential's revoke silent under the binding's change. Where
  the act has no object (a project archived or deleted is N environment changes), the first change of the call as the
  site hands them, which the commit numbers lowest: the choice is made at `prepare`, since the entry is under the MAC.
  A protect, of however many environments, is one change of the policy object, which carries its `policy.change`
  (below).
- *A binding's entry rides `changeBindings`.* `token.bind` and `token.unbind` cannot be read from the vault's own
  record of a bind or an unbind (no principal, no trace, no `operationId` in common), and they go through
  `changeBindings`, not `prepare`. Same rule, other call: `MadeBinding.entry` and `EndedBinding.entry` are a
  `NoteInput` less its id, or null, and the map gains `binding.make` to `token.bind` and `binding.revoke` to
  `token.unbind`. An end that writes no change (a sweep's, a row with no seal) refuses an entry; the site sends such
  an end's entry as an event, through `note`.
- *One change carries one entry.* `audit_events` has one row per row of the chain (its key holds the chain's number),
  so the field is not a list. The one case of two today is a key revived and written in one change (`secret.unarchive`
  beside `secret.write`): the write carries one entry, whose detail says `unarchived: true`, and the page's sentence
  adds the revival. Two more acts share a change the same way: a rename that also archives or restores an environment
  carries the archive's entry (`environment.archive`, `environment.restore`) with `from` in its detail, and a
  `secret.reference` on a revived key takes `unarchived: true`. An entry about something that has no change is an
  event in the same `prepare` call (`PrepareInput.events`), committed after the changes in the same transaction.
- *Once only.* A site hands its entry over in the commit that stops appending it to `audit_log`, never before: the
  interim projector lists `audit_log`'s entries and would list the act twice.
- *The member's summary.* A carried `secret.write` whose `detail` has no `kept` writes the `wrote` row of
  `audit_member_keys`, from the row's actor and the entry's `places`. A mark (a `secret.write` with `kept`: the value
  as it was, at another level), a `secret.loosen` and a `secret.restore` write none. None of them supplies a value,
  and the report ties a marked or restored version to its value by equal `(iv, auth_tag)` (D190). `from` and `kept`
  stay what the page prints; `relatedSeq` goes.
- *What it moves.* Nothing: no statement, round trip, lock or row is added. The entry rides a row the change writes
  already, and the site's `audit_log` insert goes. `app_change_strict` compares one key of the payload, `inputs`, to
  the read its transaction held (`p_payload::jsonb ->> 'inputs'`, migration 0062); `reported` is outside that
  comparison, and a change through `prepare` has no `inputs` in any case. No model changes: each takes a payload as
  one value under its MAC. It is built on the contract (K1's next PR), read by P1 and handed over by A1's sites.

**A finding about a member is an event, read by its id.** When the vault finds a member's row changed around it
(`mac`) or an older one put back (`stale`), it writes a `tamper` entry in `audit_log`. The members list, each member's
page, the report, an offboarding and `GET /references` mark the member while a finding names their newest change
(`tamperedMembers`, `packages/db/src/grants.ts`). That read groups every finding in the log: 92 pages, 917 at ten
times the findings (S0's sweep), over a partial index the freeze drops. After, the finding is an event the vault
writes itself in the call that found it, under a derived id as the beat's finding has:
`system:vault/tampered:<member>:<change>`, the change being the MAC of the member's newest change in hex
(`changeName`), `none` for a member the log holds no change of. Olga's row altered under change `9f2c…` is
`system:vault/tampered:user:olga@acme.example:9f2c…`, written once however many requests meet it. The page asks, for
each member it shows, whether that row exists: the member's newest change, which it reads already, then one lookup on
`log_changes`' unique `request_id`. That is two index probes a member shown, whatever the log holds, and no new index.
The rule is today's (`findingStands`, `formal/Findings.tla`: a finding stands while it names the member's newest
change, any finding and not the newest alone), and the id is that rule: a later change makes another id, which no
finding has. Like today's reader, the page takes the row on the database's word, with no key; the vault refuses the
member on its own check of the row, whatever the page shows.

It is not derived at read. `stale` could be, with no key (a row's seal against its newest change's); `mac` cannot, and
no call of these pages hands the vault the rows they list, so weighing them would add a vault call to each. The
upgrade carries no finding over: its precheck, on 0.15.0, lists the members a finding stands for and refuses while any
does. The runbook says how one is cleared on 0.15.0: an Owner changes what the member holds (a grant given or taken,
or the member removed), which is the change after the one the finding names. So 0.14's rule (a finding newer than the
member's newest access entry), `weighedBy` and `tamperedMembers` go, and old `tamper` entries stay listed like any old
entry. V1 writes the event, its id's form pinned beside `findingEventId`; P2 writes the reader (`api/members.ts`,
`db/queries.ts`).

**The audit page's check, flat (D200).** Today a visit asks the list, a walk of 0.14's chain from its last anchored
point, and 0.15's trees. The walk is what grows: in #559's sweep the checks took 42 statements at 2,000 entries and
241 at 20,000. After, the page asks the list on its own connection and one vault call, `check`, which reads in one
round trip:

1. The newest signed checkpoint: both trees' notes and their Ed25519 signatures, held to the pair the signer
   remembers outside the database (the checkpointer's Durable Object, written before the row). A database writer who
   serves an older checkpoint ends below that pair, and the check says `behind`. A witness, where one is configured,
   is a second copy for a signer that lost its memory. The signer remembers a pair before it writes its row, so for
   the length of one write the database is honestly one pair below it. So the check asks the signer first and reads
   after, and the signer answers with the pair the database must have reached: the one it remembers, or the one
   before while that row's write is pending.
2. The entries above it, each one's MAC. The checkpointer ticks every 500 ms, so they are a handful; the check reads
   at most 1,250 of them, with no setting of its own: `USES_IN_FLIGHT`, the keys one isolate has in flight at most
   (`packages/core/src/memory.ts`). That is more than two ticks at the database's measured ceiling of 1,040 uses a
   second (`docs/design/config.md`); no cap a second exists. Past that the page says the checkpointer is late, not
   "verified". It says `late` too when the checkpointer does not seal, by the signer's own word in the same answer
   as the pair: whether its last tick ended well in the last 5 s (`sealing`, T169), no answer within 2 s counting as
   no. A checkpointer dead for an hour with 10 unsealed uses under it is `late`, where the count alone said `ok`.
   The check does not compare the age of the oldest unsealed entry instead: that sets the vault's clock at the use
   against the database's, a dead checkpointer with nothing unsealed would pass until the next change answered
   503, and the signer's word is one a database writer cannot alter.
3. The frozen log's last row, against the change that anchored it at the upgrade (section 6).
4. Handed in with the call: the rows shown and the cursor. Each row's MAC, the cursor's, and how far the cursor is
   behind the checkpoint, which the page shows as "listed through 14:05:03".

That is 6 statements, 4 round trips and 2 vault calls (`access`, `check`) at 2,000, 20,000 and 1M entries: the page's
budget, with its pages held flat by the sweep (S1). Section 4 lists what it catches and what it leaves.

**The full recheck is asked for.** The Verify button and `coffre verify log` walk everything in bounded steps, a
request each, as `verifyWhole` and `verifyReads` do today: 10,000 entries of the old chain, or one checkpoint's range
of the new one, re-derived and held to its signed root and to the projection's rows. Each step is far inside the 5 s
timeout, so nothing has to run outside its reach. Its cost follows the log, and nothing runs it unasked.

The walk also holds the report's summary to the list: each listed read inside retention needs an entry of
`audit_member_keys` for its member, key and version, at its time or later, and each listed key write that supplied a
value needs its `wrote` row, whatever its age. Retention drops uses and never a change, so a `wrote` row lasts as long
as the table and a rebuild derives it again. It outlives its version too: a key deleted erases the version and leaves
the row, so the table follows the values ever written, as the log does, and not the values that exist. A reader that
lists values to rotate joins the live version, or it lists erased keys. It is one row for each write of a value (its
writer, key and version; a write is one change and makes one version), so the kept rows grow with writes, as the
versions do, and never with reads: a value someone set a year ago and that is still current is one to rotate, as
today's report says. For reads, the walk takes retention's floor from the sealed retention change, never from
`audit_cursor.reads_from`. That column has no MAC, and a writer who raises it makes the projector skip entries; a
verify that trusted it would excuse them all (`formal/Reads.tla`, `FloorSealed`, on P1). A read in the frozen log
timed before the newest dropped day keeps its row on the page, since retention drops only the uses' rows, and is on no
report: the report covers retention's window of reads and states the date it starts (D161).

**No `log_verified`, and the beat writes nothing.** With a check on every visit, the row the first draft had the page
read has no reader, so the table is not built. The 5-minute beat keeps one job: it runs the same `check` when nobody
is looking and raises a finding when it fails. A scheduled re-derivation of the projections does not earn its place:
it would vouch for rows as they were when it ran, and a row deleted later is the recheck's to find, as today.

### The watch after

Today's watch (`plugins/audit-watch.ts`, `watch.ts`, the store's three files: about 900 lines) serves the old chain.
Its beat appends `audit.heartbeat`, has the vault sign `audit_log` (`vault.checkpoint()`), walks the chain with the
app's key and keeps the outcome in a store of the app's, outside the database. After the freeze the app signs nothing
and nothing is appended, so little is left. Two names, kept apart from here on: **the watch's store** is that store of
the app's (`AnchorStore`: `durableAnchor(env.ANCHOR)` or `fileAnchor(path)`); **the anchor** is the change the upgrade
writes, naming the old chain's final entry (section 6).

**The beat is the app's scheduled run, and makes one vault call.** `runScheduled` (Workers' cron, Node's timer, every
5 minutes) reads the cursor's row and calls `beat`, a vault method P3 adds: the page's `check` with no rows, and,
when its state is not `ok`, the finding, an event the vault writes itself (author `vault`, id `findingEventId`). A
checkpointer stuck at 4410 is `system:vault/finding:4410:late`, written once however many beats see it, and each of
those runs fails, which the scheduler reports. The call replaces the run's `vault.checkpoint()`. The app runs it, not
the vault's own alarm: the cron exists anyway (spent tokens, removals), a checkpointer cannot report its own death,
and a finding that cannot be written must fail a run the platform reports.

- **No "finding cleared" event.** No outcome is stored, so no beat knows that one stood. A `late` is over when
  checkpoints exist above its number, each with its time. A `behind` or a `broken` ends with an operator's act (a
  restore, a forged row removed), and the next `ok` stands.
- **New: a projector that stopped.** The beat's statement also reads the first checkpoint above the cursor, and the
  beat fails its run, with no finding, when that checkpoint was signed more than two of the beat's periods ago, so
  what waits to be listed has waited that long, or when it does not open under the vault's keys (`projectorStopped`,
  #587). The period is the one interval the deployment already configures. Not the cursor's own `at`, which this
  section compared first and which fails honest runs: it is the time of the pair the cursor stands at, an hour old
  after a quiet hour, when the first checkpoint after it is a tick old and the projector a moment from listing it. A
  quiet instance never trips the rule: no checkpoint stands above its cursor, however old the one it stands at. Two
  periods and not one, because until the swap the projector reads the 5-minute checkpoints: just before a beat it is
  honestly one period behind, and a run that fires a few seconds late must not fail. After the swap it reads every
  tick and one period would do; two stays, so the rule does not change at the swap. The page already shows it ("listed
  through 14:05:03"); this is for when nobody looks. Nothing is wrong with the log, so readiness stays green.

**Readiness is the same check.** `/readyz`, past its doors (migrated, then upgraded, which a probe drives as it drove
the cutover), reads the cursor's row with the read it already makes and calls `check` with no rows: green on `ok`,
and the body is the state and its reason. No stored outcome and no heartbeat age. The cursor is handed in as the page
hands it, so a cursor forged or put back shows without a visitor. A probe costs one vault call, one round trip, one
ask of the signer and a handful of MACs, 1,250 at most; today's costs the store's read, a log read, the vault's
`about`, an Ed25519 verification and the `sealing` call, which `check` now includes. Two things change for an
operator: the body's `heartbeatAgeSeconds`, `checkpointed`, `broken` and `anchored` go (release notes), and a cron
that stopped no longer turns `/readyz` red. It stops findings and upkeep, not the check, and the platform reports it.

**"The log takes no writes" needs no probe write.** The heartbeat answered a queue that dropped entries while
operations went on. 0.16 has no queue: an entry is written by the statement or the transaction of what it records,
and nothing answers before it commits, a refusal included (a `note` that fails fails the request). A log that
takes no writes refuses the operation. On a quiet instance the checkpointer is the probe: every tick's barrier
raises the floor's row (`close_one`), entries or not, so `sealing` says the database took a write in the last 5 s,
where the heartbeat said 5 minutes.

**The watch's store keeps one reader in 0.16, and goes in 0.17.** After the upgrade it catches nothing the signer's
pair does not: it holds checkpoints of `audit_log` alone, the app's key vouches for no new entry, and the frozen
log's end is the anchor, a change under the pair. As a second copy for a signer that lost its memory it is what a
witness is. But 0.16 must read it once: the upgrade's step starts from the newest checkpoint it holds (section 6). So
in 0.16 the three files, the `ANCHOR` binding and its Durable Object class stay as they are, read by the upgrade's
door and written by nobody, and `auditWatch({ anchor })` keeps its option and loses its hooks (the beat, readiness,
`walkOn`, `verified`, `reseal`, `acceptLoss`). A deployment's config does not change at the upgrade. 0.17 deletes the
store, the binding and the class as a contraction; on Workers that needs a `deleted_classes` migration, which
`coffre update` writes.

**Loss acceptance goes.** `acceptLoss` moves the watch's store past entries of `audit_log` that a restore or a cut
lost. A frozen log has no tail to lose: every backup taken after the upgrade holds all of it. So `coffre audit
accept-loss`, `POST /audit/loss` and the two entry kinds are deleted, and old entries of those kinds stay listed. The
live chains' own case is unchanged: after a restore the signer's memory is ahead of the database, and resetting it is
the operator's step (`docs/restore.md`). The upgrade's door needs no acceptance either (section 6).

**Landing order.** One fact fixes it: the anchor is the last row of `audit_log` only once nothing appends to it. So
`check`'s third item, the page's and readiness's use of `check`, and the projector reading the old log from the
anchor alone become true in the PR that removes the last appender.

1. **P3, first PR: `check`'s vault half**, with `beat`, against K1's pinned types, called by nothing. Any time
   after K1.
2. **V1.** It leaves `vault.checkpoint()` and the old beat alone, so `/readyz` and the watch's tests stay green, and
   P1's interim projector keeps the 5-minute checkpoints it reads.
3. **A1's sites.** The app's entries become events. The old beat and its checkpoints are then the only appenders.
4. **P3, second PR: the swap.** `runScheduled` calls `beat`, `/readyz` and the page call `check`, the old beat, the
   heartbeat, `vault.checkpoint()`, loss acceptance and the projector's interim reading go, and conformance's
   readiness check is rewritten (a stopped checkpointer, a deleted checkpoint). It needs 2 and 3.
5. **A1's freeze**, directly on it: INSERT revoked, the head and `appendAudit` deleted.

The swap is not part of V1's PR. In production the old beat only has to run until the upgrade, and 0.15.0's own does.
No answer here moves a lock or a re-check: the finding is an event (the fence shared, no object lock, a transaction
of its own), `check` takes no lock, and the upgrade's step runs behind the door with no flow in flight. `Audit.tla`'s
scenarios go with the old beat (section 5).

**Two use statements, one rule.** `use_credential` is 1,157 lines because its statement exists four times: with or
without the seal seeks, with or without a reference and forks; 648 lines are those copies. The target is two
statements, about 700 to 750 lines. The full one is the definition: its seal seeks hang on `LEFT JOIN LATERAL … ON NOT
cached`, its reference and fork rows are left joins by primary key. The lean one serves the cached case and hands off
to the full one by answering `whole`, as today; a test holds it to the full one's answers. The access rule is written
once, an inlined SQL function both call (A645, option C). A use reads the credential, the member, the grants, the key,
its version, its environment, the policy, the cap row and the fence row by key, with no seal seek when the isolate
knows the log's newest number and up to 10 after a change, as today. Still one client statement, one round trip and
one vault call per use.

One statement for every case was the first target, and W386 measured it out on the 2-vCPU rig. Postgres initializes
every plan node and subplan each time a statement runs, whether the node runs or not, about 3 µs a node. With 82 nodes
against the lean statement's 59, a cached use costs 0.959 ms of Postgres CPU against 0.784 (+22%), a mixed load +11%,
probing the same, a reference 11% less. The whole difference is executor start-up, 358 µs against 227; the run time is
equal (107 µs against 100). A join that never runs is not free, so the cached case keeps a statement without them.

**The policy revision becomes two numbers.** The app re-checks "the policy has not changed since I loaded the caller"
on the seq of the newest `policy.change`. After, it compares two numbers read with the caller: the newest change of
the roles object and of the policy object in `log_changes`. Never the seal a row stores, which a database writer puts
back with the old row (#573, `TodayPolicyOnLog`). The re-read of the protected environments the caller was loaded with
(one renamed or deleted) stays as it is, and `issue_token`, `change_bindings` and `revoke_credential` take the two
numbers where they took `p_policy_seq`.

**The protected set is the policy's, one list on its row.** Main keeps protection twice. The policy's list (the ids in
the newest `policy.change` entry) is what the app's decisions and most of the vault's read (`protects`). Each
environment's `protected` flag, under the row's seal, is what 0.15's use and key write read (`readerOf`,
`write_inputs`). The vault's protect writes both. The first draft of this document made the flag the one truth, and
three things have no answer there. An id protected before its row exists has no row to hold it: a fork's is protected
one call before its row is written. A creation would decide its own protection, since `prepare` signs the flag as the
app sends it. And a protect would move neither of the two numbers above. So the set is one list, on the `policy` row
beside the cap: each protected id with its project and the time it was protected, as the entry holds them today, in
three aligned arrays (section 2). Every decision reads it there: the app's with the caller, the use and the key write
from the policy row they already read for the cap. It is derived where it is shown, never kept twice in step.

What follows from that. A protect or an unprotect is a real change of the policy's row, a new op, `policy.protect`,
carrying the whole policy as its value as `bulk.limit` does. So the policy's number moves by itself, in the one
decision that changes the set. Ada's caller is loaded while `prod` is unprotected, an Owner protects `prod`, and Ada's
key write to `prod` then finds the policy's number moved: 409 `policy_changed`, as today. A creation decides nothing
and touches nothing: an environment is protected when the list holds its id. `environment.protect` goes with the
flag's last reader (below). `'*'` (`EVERY_ENVIRONMENT`) is never stored: it is what the vault answers when it cannot
read its policy (`CLOSED_POLICY`), as today. The list holds ids and not slugs, as main's does: the policy's reader
joins each id's row for its slug and project (`livePolicy`), so the re-read of the loaded set and the issue lock a
rename of a protected environment takes stay exactly as they are. The model holds a narrower digest per write (the
roles, the policy row and the written environment's protection, `WritingDigest`); one number for every protection
compares more often than that, never less, and no route has a set of environments to remember.

An environment's `protected` column stays, frozen. Every seal since the cutover covers that field, and dropping it
from the object would seal every environment again and give the replay two mappings. But it is read today, so the
order matters. The commit that adds the list and the op keeps writing `environment.protect` beside the policy's
change, in key order: otherwise a protect stops protecting on main while 0.15's use, key write and `readerOf` still
decide from the flag. The commit that moves the last of those readers to the list (V2b) deletes that writer, and
renames the column in the schema and the queries, so that a leftover `e.protected` fails where it would have answered
`false`; the object's field keeps its name in the mapping, so no seal moves. From then on a new row has it `false`,
nothing reads it but to check the row's seal, and the pages derive what they show from the policy, as they do today
(`protectedFor`). No 0.16 is tagged while anything writes `environment.protect` or reads the flag. The column goes
when environments are next sealed again.

The list stays small by its own writer. A protect rewrites it whole, so each `policy.protect` drops the entries whose
environment is deleted and those with no row that are older than the time a fork has to write it
(`UNWRITTEN_FORK_MS`). That loses nothing: no op brings a deleted environment back under its id (`prepareChanges` has
`environment.delete` and nothing that reverses it), and the policy already reads past a fork never written. So the
list is bounded by the live protected environments, and the policy row a use reads does not grow with history.

The upgrade fills the list as it fills the settings. The migration takes it from the newest `policy.change` entry and
leaves out an id with no live row: behind 0.16's door no fork is in flight. The vault's step checks it against that
signed entry and against the flags of the live environments, which must agree with no exception (on 0.15.0 a personal
config's own flag is never set; the list holds its parent's id), and writes the policy's change, the one existing
object 0.16 seals again. One test per path: protect, unprotect, a protect of an id with no row, and a creation, which
must touch nothing. That change carries the `policy.change` entry (above), from the PR that deletes the vault's append
of it to `audit_log`, not before. It is built with the carrier, and A1's two numbers stack on it.

A protect is a policy change as the lock table has it (below): the issue lock exclusive, then the fence in its last
statement, where every use waits for it. What a use pays is the list in the policy row, 16 bytes an id, read when its
copy of the policy is not cached, and a lookup in it; V2a measures it. A protect's change holds the whole policy, so
its payload grows with the set, as the `policy.change` entry's does today.

**Locks after.** `audit_chain_head`, the reads under it, the 0.14 appends and the queued read head are deleted; one
advisory lock statement stays in multi-statement changes. The head did two jobs and only the first dies with the last
append to `audit_log`: ordering the chain. The second is serializing changes against each other from their first
statement, which 14 modelled protections rely on. The fence cannot take it over where it sits, in a change's last
statement: two Owners who each remove themselves both pass a count made before it, and no Owner is left (A0's
finding). So one lock stays, the **change lock**: `pg_advisory_xact_lock` on a key of its own, transaction-scoped,
taken where `lockLogHead` is today, in the first round trip, under the same wait bound (`boundLockWaits`,
`retryingLocks`). It has no table and no row, and nothing is read under it. Only changes take it: one of several
statements in its first round trip, one of a single statement inside that statement, where it took the head. Uses, the
checkpointer, the projector and `check` never do. The order is change lock, issue lock, fence; the checkpointer takes
the issue lock, then the fence. The two-trip key write keeps the lock (A0, `WriteTakesChangeLock`): without it, the
write holds the fence and waits for the key's row, while another change of that key holds the row and waits for the
fence. The member add takes it as every change does: one rule, no exemption. Each statement is the one the head's
was, so no budget gains one.

**The fence stays (Erwin, D202, which supersedes D201).** 0.16 keeps 0.15's one fence. A use takes it shared inside
its one statement, a change exclusive in its last statement, the checkpointer's barrier exclusive at each tick. So a
use waits for a change from the change's last statement to its commit, and for nothing else of it. 0.15 held 1,000
uses a second that way with no refusal. The rule for every lock is Erwin's: one only where it is necessary or
measurably better.

**Every lock 0.16 takes.** Read on main `95efd73ad`: the final definition of each of its 53 SQL functions, and the
TypeScript that locks. The head's row is counted as the change lock already. "Without it" names the model's removal
run, the protection taken out and the invariant that then breaks, or says that nothing models it.

| Lock | Who takes it, how, for how long | Without it | Who waits, at worst | Verdict |
|---|---|---|---|---|
| **Change lock** (advisory, one a database; the row `audit_chain_head` until A1) | every change, exclusive, from its first round trip to its commit | 14 protections, each with its run (the `…UnderChangeLock` of `Coffre.tla`'s scenarios: two Owners who each remove themselves, `OwnerStays`); `WriteLocks`: WriteTakesChangeLock, ChangeLockFirst > `NoWaitCycle` | every other change, for the holder's transaction: 2 to 5 round trips, tens of ms through Hyperdrive. No use. Each wait is bounded (`LOCK_WAIT_MS`) and tried again | necessary |
| **Issue lock** (advisory `(1668244070, 1)`) | shared: a sign-in, an issue, and a change's last statement, to the commit. Exclusive: the barrier and a rotation's number, before the fence; a policy change and a protected environment's rename, from that statement to the commit | `Lifecycle`: IssuePolicyHeld > `SensitiveOnlyFromOwners`. `HotPathOne`: BarrierWaitsIssues, IssueNumberUnderLock > `CheckpointsHold`; IssueOwnLock > `UsesNeverWaitOnIssues`. `ChangeLocks`: IssueBeforeFence, BarrierIssueFirst > `NoWaitCycle` | sign-ins and issues, behind a policy change's last round trips and behind each barrier. No use, which is its point | advantageous: before it, a fifth of the uses beside 30 sign-ins waited up to 50 ms (R58, `0.15-plan.md`). On merging it into the fence, see below |
| **Fence** (advisory `(1668244070, 0)`) | shared: every use, a refusal's entry, an event, a retention change, a write's request, for the statement. Exclusive: a change's last statement (except the change of a credential its own transaction made), a two-trip write's hold, a revoke, a bind that ends a binding or revokes; the barrier | `HotPathOne`: UseLocks, ChangeLocks, LockToCommit > `TotalOrder`, `NothingAllowedAfterAnswer`; CheckpointLocks > `CheckpointsHold`. `Lifecycle`: RevokeTakesFence > `RevokeOrdersUses`. `Writing`: HoldAfterFence > `WritesStandAtCommit` | every use, behind each change's last statement and its commit (a few ms; a removal's revokes in batches of 10 ms) and behind each barrier | necessary |
| **Principal's lock** (advisory `(1668244066, hash)`) | a use whose key enters its caller's cap set, exclusive; one that moves a key on to a new period, shared; a batch's second round, exclusive, before its first key. To the commit | `HotPathOne`: PrincipalLocks > `BulkCapHolds`, `BulkReplayAgrees`; RefreshLocks > `BulkReplayAgrees`; RefreshShared > `RefreshesNeverQueue`. `Batching`: StrongestFirst > `NoWaitCycle` | the same caller's other uses that take it, for one statement and its commit | necessary |
| **The cap's election lock** (`b_lock`: advisory, one a caller, key, period and round) | the uses moving one key on, under the principal's lock shared: one gets it without waiting and writes the cap's row; the others take it shared and read the row again; a winner that rolled back costs them a round more, on another lock. To the commit | nothing modelled, and no test names it. By the SQL's comment, each mover's UPDATE would queue on the row and keep it locked to its own commit: N uses committing one behind another at each period | the losers, for the winner's commit | advantageous under the shared lock, though never measured alone. Neither under the exclusive one: delete it there (below) |
| **Member's queue** (advisory `(1668245101, hash)`), with the member's row | a decision that names members: queue, then row, in principal order. Exclusive for a change, shared for the vault's reads under the head. A key rotation takes every member's | the row: `Members`, `Sharing`: StandingRecheckUnderChangeLock > `NothingReleasedAfterRevocation`; `Locks`: SortedMemberLocks > `NoWaitCycle`. The queue: nothing modelled. It is fairness: a stream of shared row locks never lets a removal in (`store.ts`) | changes that name the same member, for the holder's transaction | the row: necessary. The queue: neither, once nothing takes it shared (below) |
| **Factor lock** (advisory `(1717658484, hash)`) | an issue, for its issuer, and a change of that person's passkeys: exclusive, first, to the commit | `Factor`: IssueTakesFactor, ChangeTakesFactor > `ChangeEndsAll`, `LiveFromLive`; FactorFirst > `NoWaitCycle` | one person's issues and passkey changes, each behind the other | necessary |
| **Place in line** (advisory, tried: `reserveProxy`'s one place. The reads' 16 go with the reads under the head) | the one call that reserves a deploy's proxy names, to its commit; the others are refused at once and ask again | nothing modelled. Measured (#467): 3,080 no-op decisions queued 200 s behind the head at 1,000 uses a second, and every use behind them | nobody: it is tried, never waited for | advantageous |
| **Rows of members, credentials, bindings, connections** (`FOR SHARE`, `FOR KEY SHARE`, `FOR UPDATE`, in id order) | a sign-in, an issue, a bind, a revoke, inside their one statement, to the commit | `Lifecycle`: IssuerLocked > `SensitiveOnlyFromOwners`, `IssuedByLiveCredential`; BindingLocked, UnbindExclusive > `EndedBindingEndsCredentials`; TouchSkipsLocked > `SignInsRunTogether`. `Members`: MemberRecheckInSignin > `CredentialsAtCurrentGeneration` | an unbind behind the sign-ins through its binding, and they behind it, for one statement | necessary: an issue and a sign-in take no change lock |
| **A key's row** (`FOR UPDATE` at 7 sites of the app; `FOR SHARE` in `end_reference`) | a key's write, move, restore or delete, each in a change, to the commit | nothing modelled for the explicit lock: `WriteLocks` has the row as the UPDATE takes it | another change of that key, which the change lock already holds off | not judged: each site says which race it is for, and I did not read the seven |
| **A key rotation's signed rows** (`FOR UPDATE`, a page a step) | the app's rotation step, to its commit | nothing modelled that I found. By its comment: a session's renewal, which takes no change lock, would slip past the step | a renewal of a row on that page, for one step | necessary by its comment, not checked |
| **Sweeps** (`FOR UPDATE SKIP LOCKED`: the cap's old rows, spent tokens, old releases) | one sweeper at a time, for its statement | nothing modelled: two sweepers would do one's work twice | nobody: a locked row is skipped | harmless |
| **The projector's** (P1: the fence shared in `project_audit`; a rebuild's `TRUNCATE`) | a batch of the projector; a rebuild | `Reads`: CursorAfterRows > `LagShown` | the audit page, behind a rebuild's `TRUNCATE` | P1's to state |
| **The migrator's two** (advisory, session-long) | `coffre migrate`, and its index builds | nothing modelled: two migrators at once. On no request's path | a second migrator | necessary |

Not locks, and counted nowhere above: the UPDATEs' own row locks (a credential's last use, a binding's stamp, the
cap's row), which no statement asks for by name.

**What can go now.** Three, none of which needs a model:

- **The election under the exclusive lock.** A batch's second round holds its principal's lock exclusive, and each key
  still runs the election and wins it at once: up to 100 advisory locks a statement (`limits.batch`), each an entry in
  Postgres's lock table, electing among nobody. The smallest change: the cap's write is a plain UPDATE when its
  transaction holds the lock exclusive (`locked` in the function, `p_lock` from `use_batch` and `use_route`). V2a
  rewrites these statements anyway.
- **The batch that locks nothing first.** A second round whose rows name two principals for one credential, which only
  a credential's row written around the log produces, is sent with no lock ahead of its keys (`byIds`, `lock = null`):
  each key locks as its turn comes, and two such calls can wait on each other until Postgres ends one. The smallest
  change: `byIds` answers busy and sends nothing.
- **The members' queue, with its last shared caller.** Its 5 shared callers on main are the vault's reads under the
  head (`#decide` with `reads: true`), which the plan deletes. After that only changes take it, exclusive, in the
  statement that locks the same member's row, and it orders nothing the row does not. The smallest change:
  `lockMembers` and `change_input` drop their `pg_advisory_xact_lock`, in the PR that removes the last shared caller,
  with the check of the pair's order in `scripts/test-schema.sh`. If a shared caller stays, the queue stays.

**What does not go now: the issue lock into the fence.** They do different jobs today. The fence orders uses against
changes. The issue lock lets a transaction number a new credential, and compare the policy it was weighed on, without
standing on the fence. It could not be the fence taken shared, for one reason (`0.15-plan.md`, "Uses never wait on
sign-ins"): Postgres queues a shared request behind a waiting exclusive one, the barrier asks for the fence exclusive
at every tick, and a sign-in held its lock for its last two round trips, about 40 ms, so every use queued behind the
barrier that queued behind the sign-in. Freezing `audit_log` removes most of that reason: the 0.14 entry whose trigger
took the locks early is gone, and `sign_in`, `issue_token` and `change_bindings` are one statement each, their lock
taken last. If every issue takes it in its transaction's last statement, an issue holds the fence no longer than a use
does, and the fence shared could carry it. Three things stand between that and a deletion. A policy change takes the
issue lock exclusive from the middle of its transaction (`vault.ts:3262`), which on the fence would stop every use for
its remaining round trips, so it moves to the last statement first. I did not read A1's app sign-in to see that its
issue is in its last Sync. And `HotPathOneIssue`, `Lifecycle` and `ChangeLocks` are re-cut (about seven protections go
with the lock, one comes: an issue takes the fence last), with R58's bench run again. It would save one lock statement
in each change and in the barrier, and one rule of the order. Nothing measured asks for it, so it is a task for after
0.16.

**Not in 0.16: per-object locks (L1).** The design gave each object a decision reads a lock of its own, so that a
write to one key made only that key's uses wait, and left the fence to the checkpointer. Its models are written and
hold, each removal run breaking what it names (#585, parked). What they cost is in that pull request and in this
file's history (`bb16a17713`): a lock statement ahead of every use, an order of five kinds of lock, shared locks for a
hold, and a bound on Postgres's lock memory that pushed the keys into 32 stripes, where one use in six waits for an
unrelated change again. What would bring it back: a load test that shows uses waiting behind changes, and then the
smallest form that removes the wait measured, which may be less than this (one lock for the policy and the roles, say,
if those are the changes that hurt).

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
| Protected, roles, the cap | `policy`, `roles` | the same | the same | the vault, on every use and decision (already so) |
| Access revision | none | `principals.seal` | the same | already so; the read of `audit_log` only guarded against 0.14 writers, and none is left |
| Binding removed, reference ended, revoked | their rows | the flag is inside the sealed object (`objects.ts`: `revoked`, `ended`) | the same | the vault, on every use |
| What the pages list | the projections | a row's `mac` fails when the page shows it | the cursor's MAC covers how far it went; a row deleted behind it is the recheck's to find | the vault on every visit; the Verify button and `coffre verify log` |

**The three hard spots.**
1. *A projection can omit rows.* The offboarding report answers from `audit_member_keys` only when the cursor has
   passed the checkpoint that sealed the member's removal. Removal is a change, it answers only once sealed and
   witnessed, and every earlier read has a smaller number, so every read is inside. Before that the report says
   `behind`, as today. The summary row is written with the event, and its time only rises.
2. *Flags must be inside the seal.* They are: `revoked` for credentials, connections and bindings, `ended` for a
   reference under its holder's key, both archivals for an environment, and the protected set in the policy's
   object. This design adds no flag outside a sealed object.
3. *Objects made before the upgrade need a first change to seal against.* 0.15.0's cutover wrote one for every
   existing object. 0.16 adds two kinds, the settings and each key, and the vault writes their first change in its
   upgrade step (section 6). One existing object changes what its seal covers, the policy, which gains the
   protected set; the step writes its change. Nothing else is sealed again.

**What a visit's check catches.** For a database writer with no key:

| They | The visit | The recheck |
|---|---|---|
| alter or forge an entry above the newest checkpoint | caught: its MAC | |
| delete a checkpoint, or serve an older one | caught: the database ends below the pair held outside it | |
| alter a row the page shows | caught: the row's MAC | |
| stop the projector, or put an older cursor back | shown: "listed through" falls behind the checkpoint | |
| cut or extend the frozen log | caught: its last row is not the anchor | |
| delete the anchor and the whole frozen log with it | not seen until V1 answers "the upgrade ran" from outside the database (open, section 6): it reads as a database born on 0.16 | caught: the anchor is a change inside a signed range |
| alter or delete an entry inside a signed range, or an old entry of the frozen log | not seen: the page shows the projection's own signed rows | caught: the range's root, the chain's hashes |
| delete a projection row | not seen | caught: the range re-derived and compared |
| delete a use younger than one tick, before a checkpoint covers it | not seen by any check, today or after. A change answers only once sealed for this reason; a use does not wait. | |

**The seal seek stays on `log_changes`.** Nine seeks on `(object, number)` against nine primary-key reads of a heads
table, prepared: 0.143 ms against 0.132 ms at 100k changes, 0.196 ms against 0.134 ms at 5M. A heads table would save
0.06 ms at fifty times Equisafe's size, as a second copy every writer keeps in step. Not built.

**Which changes need a model first.**

| Change | Model | When |
|---|---|---|
| The head becomes the change lock | `Coffre.tla` with its 11 scenarios, `Credentials`, `Issuing`, `Factor`, `WorkloadEnrollment`, `Writing`, `WriteLocks`, `Lifecycle`: 14 "under the head" protections keep their place and take the lock's name, with their 18 runs; the order change lock, issue lock, fence gets a deadlock check; the key write and the member add are checked without the lock. `Bulk`, `Audit` and `AppKey` keep the head, 0.14's chain's, and go with the code that ends it | first (A0) |
| The policy revision becomes the newest change numbers of the roles and the policy objects | `Lifecycle` (LifecyclePolicy), `Writing` (WritingDigest, which holds the narrower per-write digest) | first (A0) |
| The cap read from the `policy` row, the 0.14 guard gone from uses | `HotPathOne` (CapSealed, HotPathOnePolicy) | first, small |
| Two new sealed objects | `SealedObjects`, after `Roles.tla`'s pattern | with the PR |
| The projector covers changes, the summary | `Reads.tla`, with #560's scenario | with the PR |
| The cutover deleted | `Migration015` goes; its issue-lock order moves to `WriteLocks` | with the PR |

## 5. What gets deleted

| What | Size |
|---|---|
| The vault's 0.14 mode (`log: '0.14'`), its CI job | 76 branch lines in `vault.ts`, 252 in 70 test files, `audit-writer.test.ts` (322) |
| The 0.14 write path | `packages/db/src/log.ts` append and head code (348), `appendAudit` (57), the vault's `#append`, `#record`, `#weigh` (62), 155 entry sites in the app rewritten as events |
| The cutover | 1,139 source lines, 7 SQL functions (164), 2 test files (1,294), `Migration015.tla` and 11 scenarios (1,531), 819 lines of docs |
| The head's row | 6 statements in 5 SQL functions, about 95 lines of `log.ts`, `audit_chain_head`, #552's head waiters; its 10 callers that are changes take the change lock in its place |
| `audit_log` reads on request paths | 26 reads in 10 SQL functions, 16 read sites in TypeScript: the snapshot statement's five, `answers.ts`, `policyNow`, `hasTombstone`, `referenceRows`, `tamperedMembers` with `findingStands` and `weighedBy` (section 3) |
| Freeze probes | about 200 source lines, 22 SQL, 230 test, `WorkloadFreezing.cfg` |
| Triggers | `audit_log_fence`, `audit_log_refuse_old`, `log_reads_placed_insert`, `log_reads_placed_update`, and `audit_log_releases` with `vault_releases` once V1 deletes the 0.14 read path that counts from them: 5 of 9 |
| Indexes | all 30 on `audit_log` (33 until #576); 18 on `log_changes` (`sign_in`, `issue_revoke`, `written`, `admitted`, `refused_write`, `refused_add`, each with its `_actor`, `_environment` and `_object` variants); 10 on `log_reads`; `secrets_lookup_idx`; 4 on `secret_references`; `credentials_enrollment_roots_idx` |
| `log_reads` and its family | 4 tables, 6 functions (182), 955 source lines, 430 test |
| The 0.14 chain's upkeep | heartbeats and checkpoints every 5 minutes, `Audit.tla` and 6 scenarios (910, the 7 to 11 minute `Tampering` run among them); `Audit.lean` stays for the verifier |
| The watch | `plugins/audit-watch.ts` (418) and most of `watch.ts` (200), their test (621), `vault.checkpoint()`, `coffre audit accept-loss` and its route; in 0.17 the store's three files (298), its test (138), the `ANCHOR` binding and its Durable Object class |
| `use_credential`'s copies, last release's overloads | 1,157 lines to about 700 to 750, two statements and not one (section 3); `sign_in/35`, `issue_token/28`, `change_bindings/53` (111) |
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
(`holdRuntimeTimeouts`, 60 s for retention's two statements). Lost: the head waiters, which die with the head's row and the 0.14 read path.

## 6. The upgrade from 0.15.0

1. **Before.** On 0.15.0, run `coffre verify log`: the full walk of the old chain, in steps, green. Run the upgrade's
   precheck, which only reads: it writes the mark of step 3 when asked (`--mark`), and only step 3 asks, so a check
   run against a serving 0.15.0, as often as wanted, locks none of its logs and leaves no table behind. It refuses
   before anything else is touched, each by id: a log with an `audit.loss_accepted` entry (the count and their seqs);
   a member a finding stands for; an OAuth client whose `redirect_uris` the type change of T278 cannot carry whole,
   which is anything but a JSON array of strings (the change would drop a non-string element, and all of a value that
   is no array); a newest `policy.change` that does not read, or one that disagrees with the environments' rows on
   what is protected, since the migration fills the policy's list from it; and a trust binding 0.14 ended, by its
   tombstone, that the log's rule would bring back. The finding's and the policy's refusals name the change on 0.15.0
   that settles them; for the binding none is known: stop and ask the maintainers. It prints, and does not refuse, a
   binding live on 0.15.0 that the log ends (its seal is not its newest change's, or the log revokes it): no supported
   operation of 0.15.0 leaves one.
2. **Deploy 0.16.** This starts the downtime, and it is what stops 0.15.0: no route is taken off, no cron removed, no
   beat waited for. The build's own `coffre migrate` skips this migration, loudly, and exits 0. Both Workers then run
   below their migrations, where 0.16 does nothing: the app answers 503 `migrating` to all but `/livez` and `/readyz`,
   an unreachable database included; the vault refuses every call; the checkpointer's and the projector's alarms
   re-arm and return, with no write and no day made; the watch's store's alarm the same; the scheduled run the same.
   0.15.0's cron goes with its deploy.
3. **Mark, then back up.** Run the precheck again, with `--mark`. Passing, it writes the **mark**: one row that holds
   the newest committed number of each of the three logs, `audit_log`'s seq and the numbers of `log_changes` and
   `log_uses`. Each is a `max` over the rows, never a sequence's value, which a rolled-back append moves, and it is
   read under `LOCK TABLE audit_log, log_changes, log_uses IN SHARE MODE`, taken first in the precheck's transaction:
   numbers do not commit in the order they are drawn, so without it the mark reads 101 while 100 is still open, 100
   commits after the dump, and step 4 still finds 101. The lock is the migration's own in its table order, with its
   wait (500 ms, 5 tries, the holders named). The row is in a table no migration creates (`coffre_upgrade_mark`), with
   SELECT for `coffre_backup` in the same transaction; a passing rerun overwrites it, a refusing one removes it, and a
   run not asked to mark leaves it. Then `coffre backup`, whose dump carries the mark. Nothing waits for 0.15.0 to
   drain and no value passes from one command to the next. A request or a scheduled run in flight at the deploy ends
   on 0.15.0's code, and nothing in 0.15.0 bounds how long (its app login has no statement timeout; 0.16's is S1):
   step 4 finds out whether one wrote.
4. **`coffre migrate`**, run by the operator as the owner, with the flag that says so: one migration, in one
   transaction. It refuses unless `/readyz` answers `migrating` at this release, and it refuses a database that is not
   a cut-over 0.15.0 (no cutover change in `log_changes`, or a schema past 0049 that is not 0.16's; `requireCutOver`,
   on main since V0): one of the checks before its first write. Its first statements lock `audit_chain_head`,
   `audit_log`, `log_changes` and `log_uses`, ACCESS EXCLUSIVE and held to the commit. Then it compares the three
   numbers to the mark and refuses if one moved, or with no mark ("run the precheck, then back up"), and drops the
   mark. Then it creates the tables; fills `settings` and `log_keys` from the newest entries, unsealed, and the
   policy's protected set (section 3); drops the indexes, triggers, functions and tables of section 5; revokes INSERT
   on `audit_log`; and, anywhere in the same transaction, replaces the sequence both newer logs number from
   (`log_number` dropped, `log_next` started where it stood; below). It copies nothing into the projections. A lock it
   cannot have within 500 ms ends the transaction (55P03): the migrator tries 5 times, a second apart, then fails
   naming the sessions that hold the tables, and has written nothing. Nothing in it depends on an index built after
   its commit.
5. **The vault's step**, on its first call, while the app answers 503 `upgrading` at its one door. It is the same size
   whatever the log holds. The vault cannot read the watch's store, so the app reads it at the door and hands the
   checkpoint it holds in on the call that runs the step; the vault verifies its own signature on it and requires the
   log to hold that entry at that hash. It checks the old chain from there to its last entry, as 0.15.0's own check
   does between beats: the app its entries' MACs, the vault its own, and the hashes that link them. That is one beat's
   entries at most, since no beat is waited for, 10,000 a call at most. It writes the change that names the chain's
   final seq and hash, the **anchor** the old log answers to from then on. It checks the settings' and keys' rows and
   the policy's protected set against the signed entries they came from and writes each one's change and seal. It
   signs the cursor at the anchor, writes the change that marks the upgrade done, and the door opens. It checks
   everything before its first write: the checkpoint handed in, the tail, the settings, the keys and the protected
   set. A step that refuses has then written nothing.

**What the mark covers.** The rule: every write of 0.15.0 whose loss would matter commits, in its own transaction, a
row in one of the three logs. So a backup is whole exactly when none of the three has moved since. A change the app
makes to its tables commits with its entry in `audit_log` (`audited`), and the vault's decisions append there too; a
sign-in, a token issue, a bind, a revoke and a session's renewal write `log_changes`; a use, so every read of a value,
writes `log_uses`. `log_reads` is not a fourth log: it is a projection of `log_uses` ("its use is the record",
migration 0049), built behind the checkpoints, and the migration drops it. What commits with no row in a log, and a
restore may lose: the last-used stamps of credentials and connections; a device login just started and an approval's
`reported_at`, which the user starts again; an OAuth client's registration, which the client repeats; the alert cap;
and what the checkpointer and the projector derive from the logs (the floor, tiles, checkpoints, day partitions,
`log_reads`), made again once the checkpointer's memory is reset. Three more are the second transaction of an act
whose first moved a log, with an empty entry list of their own (all 46 `audited` sites of 0.15.0 were walked): a
copied fork's keys filed in their folders (`fileSecrets`), the `revoked_at` stamp on a past membership's identities
(`endPriorMembership`, `removeMember`), and a device code marked consumed on a refused poll (`pollDevice`). A restore
that loses one leaves what a crash between the two transactions leaves, which 0.15.0 survives already: keys unfiled,
an identity not yet stamped, a code refused once more. None admits anyone: a credential stands only at its member's
current generation (`#liveCredential`), and the stamp is written for an older one. A write between the mark and the
dump's snapshot is in the backup and still refuses: the error is toward backing up again, never toward a lost write.

**After the commit, 0.15.0 cannot append.** The locks carry the comparison to the commit; what is left is a 0.15.0
statement that runs after it. One sent after the commit meets the new schema. One *already running inside a function*
does not: Postgres runs the body it entered to its end, whatever became of the function. Measured on 16.14: a call
held on the migration's table lock, its function dropped and replaced meanwhile, inserted its row when the migration
committed. So what refuses 0.15.0 has to be something its statement reaches after its last wait and no longer finds.
Each log's numbers come from one place, and the migration removes both:

- *`audit_log` numbers from the head's row.* Every append is one statement that inserts the entries and moves
  `audit_chain_head` (`appendEntries`, the only writer, the app's and the vault's): the table is gone, and INSERT is
  revoked from both logins. The app's changes run inside that statement (`app_change`), and a vault decision appends
  before it changes anything (`change_input` after it, in the same transaction), so neither writes `log_changes`
  alone.
- *`log_changes` and `log_uses` number from the sequence.* Every INSERT into either draws
  `nextval('public.log_number')`, in every function that appends (`sign_in`, `issue_token`, `change_bindings`,
  `revoke_credential`, `log_retention`, `use_credential` among them). With the sequence gone the held call of the
  measurement fails, `relation "public.log_number" does not exist`, its plan cached or not. It has to go under another
  name: dropped and created again as `log_number`, a body planned after the commit finds the new one and writes.
- *A call sent after the commit must not resolve.* One rule: no SQL function a runtime login calls has a defaulted
  argument, and none of the seven that append in a statement of their own, with no `audit_log` append beside them,
  keeps 0.15.0's argument list. On main all seven still take a 0.15.0 call. The judge is a test: 0.15.0 started once
  more on the migrated database, every write refused. Its real use is the operator who redeploys 0.15.0 without
  restoring, more than a straggler.

| Function, with 0.15.0's argument count | What changes its list in 0.16 | PR |
|---|---|---|
| `sign_in` (35) | The 35-argument overload goes; 0.16's takes 48 (passkeys, migration 0075) | V2b |
| `issue_token` (28) | The overload goes; 0.16's takes 29 (`p_passkey`, 0064), then two policy numbers for one | V2b, A1 |
| `change_bindings` (53) | The overload goes; 0.16's takes 54 (`p_sweep`, 0079), then the two numbers and the entries it carries | V2b, A1, the carrier |
| `revoke_credential` (16) | The policy revision becomes two numbers: 17 | A1 |
| `use_credential` (27) | Main's 31 lose their 23 defaults, which take a call of 27 today; rewritten as two statements | V2a |
| `use_batch` (19) | Its list stays: the two cap arguments are the isolate's cached cap, which the cached path decides on without reading the policy's row. So its name goes: `use_id_batch`, the by-ids twin of `use_named_batch`, made again in any case | V2a |
| `log_retention` (4) | Its list stays, so its name goes: `ALTER FUNCTION ... RENAME TO append_retention`, which keeps owner, grants and settings | the sequence's swap |

The last two keep 0.15.0's list. No argument is invented for them: a name is part of what a call resolves, so the
function takes another. There is no list of exceptions: the test refuses all seven. A function no runtime login may
execute is outside the rule, and safe outside it: `use_covered` keeps its one default, and no body of 0.15.0 names it
(migration 0057 made it).

A running 0.15.0 checkpointer can still raise the floor or write a checkpoint (`close_one`, `write_checkpoint`, whose
lists do not change), and a request can still stamp a last use. The vault's step reads neither the floor nor a
checkpoint of the newer logs. A checkpoint written so is one 0.16 takes as its own: the same key, the same row, over
log rows the migration did not touch; a floor raised only refuses an older `at`. The refusal test does not cover
these, and need not: none is a write the rule above counts.

**The projector lists the old log; the migration does not.** From the anchor it walks `audit_log` backward, 5,000
entries a batch. An entry's hash covers its content and the hash before it (`entryHash`), so each batch is
authenticated by the one above it, down from the anchored hash, with no key and no walk from the first entry. It lists
every entry but heartbeats and checkpoints, signs each row, and moves the cursor's old position (a seq, and the hash
the entry below must have) in the batch's transaction, so a batch that dies is done again from the cursor. The cursor
alone says where the walk is. Not started and done are the same bytes (`old_from` 0 and the zero hash, which is the
first entry's `prev_hash`), so the walk starts in the batch that lists the signed anchor change, which sets `old_from`
to the anchor's seq plus one and `old_hash` to its hash; it is still listing while `through` is below the anchor
change's number, or `old_from` is above 0. A batch is about 1.7 MB and a few milliseconds of hashing, well inside a
Worker's 128 MB and its CPU limit. Equisafe's 440,000 entries are 88 batches. `coffre audit rebuild` reads the frozen
log again the same way, so the old rows stay a cache that one job rebuilds, and the filter is one predicate: listing
heartbeats after all is a rebuild. The door does not wait for the walk. Until it reaches the first entry, the audit
page says how far back it lists and the offboarding report says `behind`.

One case is refused by the precheck, not handled: a log in which an Owner accepted a loss under 0.15.0
(`audit.loss_accepted`) has a break in its hashes at the accepted range, where the backward walk would stop with a
finding. The rehearsal on the copy of Equisafe's database answers for Equisafe. If a deployment has one, the walk
below an accepted range is designed then, from the log's own rows as 0.15.0's beat does it.

**With no checkpoint in the watch's store, the step starts from the log's own.** That is a deployment that never
added the watch (0.15.0 only warns), or a store that was lost. The step then starts from the
newest checkpoint entry `audit_log` itself holds, its signature verified, and the anchor's payload says which it was
(`held`: `outside` or `log`, a field to add to K1's `AnchorPayload`). Nothing outside the database bounds a cut then
but the 0.15 cutover's change, which names the old chain's position at the cutover: the exposure such a deployment
already has on 0.15.0. A record the app's key did not seal refuses the door, as it fails a beat today.

**What a database writer can do in the gap.** Before the anchor: cut entries off the end of the old chain, back to the
newest checkpoint held outside the database at most. Those are the last beat's entries, of the kinds 0.15.0 writes to
the old log alone (sign-ins, refusals, token issues), and 0.15.0 has the same window between two beats. The first
draft waited for a beat to empty it; with 0.16 deployed first there is no 0.15.0 beat to wait for, and the window is
the ordinary one. They cannot add or alter an entry without a key. After the anchor: an old entry altered before the
projector reaches it stops the walk there, with a finding; one altered after is the recheck's to find, and the rows
the page shows carry MACs of their own.

**Open, V1's to close: what says the upgrade ran (W395, on #587).** `check` holds the frozen log to its anchor only
once the upgrade has run, and no row can say so: a writer who deletes the anchor change, the done marker and every row
of `audit_log` leaves a database that reads as one born on 0.16, an empty log with nothing to anchor, and every visit
is `ok`. The deleted change is inside a signed range, so the full recheck finds it, and nothing sooner does. `check`
needs the answer from what a database writer cannot delete (`#upgraded()` in the vault, which #587 leaves answering
no). Two candidates: the signer's memory, outside the database and already asked once a visit (`reached`), told the
anchor's number when the step writes it; or the deployment's config, set at the upgrade. The coordinator leans to the
first: a flag is a new thing an operator can forget or set wrong (D170), and the signer is already the witness outside
the database. One question it must answer: what `check` says after the signer is reset. Going back (below) resets it
on the way to 0.15.0, which asks nothing, and the next upgrade's step tells it again. But the same reset follows any
restore of a 0.16 backup (`docs/restore.md`), and a memory that forgot the upgrade reads the restored database as one
born on 0.16. So either the reset keeps that one fact, or the first `check` after it takes the anchor from the
database the operator just vouched for and tells the signer. V1 picks one with its upgrade step. Until then a visit
does not catch that one act.

**If the step dies halfway, it is rerun.** Each write is one change with a request id made from what it seals
(`upgrade-0.16:settings`), compared-and-set on a null seal, so the next call skips what is done and goes on. It only
adds changes and fills null seals. A step that refuses (the old chain's tail does not verify, a row disagrees with its
entry, the watch's store is ahead of the log) has written nothing, and the door says which. Before step 4 commits,
going back is 0.15.0 redeployed: nothing was changed but the mark, which the next marking run overwrites. After it,
going back is step 3's backup restored and 0.15.0 redeployed, which brings its cron back by itself, and the
checkpointer's memory reset as after any restore (`docs/restore.md`, "On 0.15's log"): 0.16's checkpointer seals from
the migration on, so it remembers pairs the backup lacks. No command or argument accepts a loss: the door answers 503
to the route `coffre audit accept-loss` calls, and nothing writes the store it moved.

**How long.** The downtime runs from step 2's deploy to the door opening: the deploy, the backup, the migration and
the step. The migration creates and drops, and the vault's step reads one beat's entries and writes a handful of
changes: seconds, whatever the log holds. The walk runs behind the open door. Its SQL equivalent took 6 s for 440,000
entries on my Postgres (3.2 s the events, 2.3 s their 607,200 place rows, 0.4 s the summary), so I expect about a
minute through the projector. The rehearsal on a copy of Equisafe's database (T265) measures the migration, the step,
the walk, the size after (285 MB of events and places for 440k entries beside 153 MB of `audit_log`, before the
heartbeats and checkpoints are left out), the first audit page, and the sweep at that size.

**How it is tested.** One script, `scripts/upgrade-check.sh`, built on `test:compat`'s installer: install 0.14.5 from
npm, run its own conformance to fill a database, update to 0.15.0 and let it cut over, save the audit API's pages
(heartbeats and checkpoints filtered out) and one offboarding report, then start this checkout on that database,
require every door to answer `migrating` and no row to be written, mark, back up, run its migrate, and let the step
run. Around the migrate it requires: a refusal with no mark, and with a mark one append old; a 0.15.0 `sign_in` and a
0.15.0 `use_credential` sent while the migration holds its locks to fail at its commit; and 0.15.0 itself, started
once more on the migrated database, to have its sign-in, token issue, bind, revoke, use, batch use and one change of
each kind refused, the three numbers standing. Once the walk is done it requires the same entries in the same order,
the same report, a green `coffre verify log`, a use, a change, a second run of the vault's step killed between two of
its writes, a step made to refuse that leaves no change, no seal and the signer's pair as it was, and a walk killed
between two batches. `pnpm test:compat` is off for 0.16.0, as it was for 0.4.0, and returns with 0.16.1; until the tag
this script is the release's gate in its place, a step of Validate. A dev database on main's unreleased migrations
starts over. One rehearsal of the whole runbook on a throwaway Cloudflare account, before the release, answers for
what no test here can: invocations in flight at a real deploy.

## 7. The work graph

Three lanes by the files they own. **V** is the vault (`packages/vault/src`). **P** is the projection and the pages
(`vault/src/reads.ts`, `server/src/api/audit.ts`, `api/members.ts`, `packages/ui`). **A** is the app
(`server/src/api`, `server/src/db`, `packages/db/src/log.ts`). Each schema PR adds its own numbered migration until
the collapse. Days are working days for one agent under the fast gate. Net lines are rough.

| PR | What, main files | After | Model first | Migration | Days | Net lines |
|---|---|---|---|---|---|---|
| E1-E7 | The early list, handed out: snapshots, sessions, `ActionsLog`, the 0.14 mode, freeze probes, dead indexes | #564 for four of them | no | E6 | 3 | -330,000 |
| V0 | Cutover deleted; migrate refuses a database not cut over. `vault/cutover.ts`, `server/cutover.ts`, `store.ts`, `vault.ts`, `formal/Migration015*` | E4 | no, `WriteLocks` edit with it | no | 1.5 | -4,800 |
| V2a | Two use statements for four, the access rule one inlined SQL function, same reads. `use_credential`, `use_route`, `vault/use.ts` | E4 | no | yes | 3 | -400 to -450 |
| P1 | The projector and its four tables; every change, event and use, and the old log backward from its anchor; `coffre audit rebuild`. Adds, because nothing can be deleted until pages can read it. | E4 | no, `Reads.tla` with it | yes | 4 | +900 |
| P2 | Pages read the projection: `GET /audit`, the report, MCP. Deletes `log_reads`, the three-log merge, 18 + 11 + 10 indexes | P1 | no | yes | 3 | -2,300 |
| P3 | Two PRs (section 3, "The watch after"). First the page's check, flat: one `check` call a visit (6 statements, 4 round trips), and `beat`, the same with no rows plus the finding; the full walk in steps behind a Verify button and `coffre verify`, which also holds each listed read inside retention to the report's summary, the floor taken from the sealed retention change (`reads_from` has no MAC); the page's walk of 0.14's chain deleted. Then the swap, after V1 and A1's sites: the scheduled run and `/readyz` on it, the old beat, the heartbeat, `vault.checkpoint()` and loss acceptance deleted | P2; the swap V1, A1's sites | no | no | 3.5 | -1,400 |
| T1 | Three `text[]` columns, `log_config` dropped | #564 | no | yes | 1 | -50 |
| A0 | Models: the head becomes the change lock (section 3), the policy revision a digest of newest change numbers | now | it is the model | no | 2 | 0 |
| V1 | The vault's entries go to the chain only; `settings`, `log_keys`; the vault's upgrade step (one beat's tail, the anchor), and what tells `check` it ran, from outside the database (open, section 6); `note` for events, and a refused read written by the call that refused it | P2 | `SealedObjects` with it | yes | 4 | -300 |
| A1 | The app's entries go to the chain; `audit_chain_head`, the reads under it and the policy revision deleted, `lockLogHead` replaced by the change lock, no re-check moved; sign-in in 5 round trips; then `audit_log` frozen, directly on P3's swap | P2, A0; the freeze P3's swap | A0 | yes | 4 | -700 |
| V2b | `audit_log` reads out of the use and change functions; the cap from its row; old overloads dropped | V1, V2a | `HotPathOne`, small | yes | 1.5 | -300 |
| U1 | `scripts/upgrade-check.sh`, its 0.15.0 pages compared without heartbeats and checkpoints | V1, A1 | no | no | 2 | +500 |
| S1 | The 5 s timeout from #552, with #559's sweep green at two sizes. Adds the sweep, which is the proof | all above | no | no | 2 | +1,600 |
| C1 | The collapse: one upgrade migration from 0.15.0, one baseline for new databases, 80 migration files deleted, functions as one file each, a parity test (0.15.0 plus the migration equals the baseline) | all above | no | it is the migration | 2 | -30,000 |
| C2 | `AGENTS.md`: 0.16.0 is a clean break like 0.4.0, expand-then-contract resumes with 0.16.1. Old design docs deleted | C1 | no | no | 0.5 | -5,300 |

**Order.** Day 0: E4 alone, since it edits `vault.ts`. Then three lanes at once, built against a contract pinned first
(K1): `note` and the row it writes, `settings` and `log_keys`, the upgrade's changes, and `check` with the MAC inputs
of a projection row and of the cursor. V: V0, V2a, V1, V2b. P: P1, P2, P3. A: T1, A0, A1, U1, S1. C1 and C2 close. V1
and A1 are built beside P1 and P2 and land after P2: once entries go to the chain only, a page still reading
`audit_log` loses them. V2b lands after V1, whose rows it reads. The freeze waits for P3's swap, which removes the
last appender (the old beat) and is built beside A1's sites, so the path does not grow. **Pairs that collide:** V1 and
A1 both need `note` in the vault's contract (`packages/core/src/vault.ts`), which the contract PR lands first. P2 and
P3 both edit `server/src/api/audit.ts` and run in sequence, as do E4 and V0 in `vault.ts`. Every schema PR appends to
`schema.ts` and the journal, one-line conflicts.

**Estimate.** About 40 agent-days. With the contract pinned, the longest path is the contract, V1, V2b, S1, C1: 10.5
build days with L1's 4 gone (D202), which I have not laid out again against the landings (it was 15 to 17 working days
with L1). The two model-first PRs were where the risk is, and both are written. A0 found that the fence cannot stand
in for the head, so the 14 protections keep a lock of their own and A1 moves none of them. L1's is parked with its
pull request (#585). On Node, the projector runs on a timer in the vault's process, where Workers use a Durable Object
alarm. The beat is the app's scheduled run on both.

## 8. Decided

No question is open. The five the first draft asked:

- **JSON that SQL never reads** (Erwin, D199): `log_changes.payload` and `audit_events.detail` stay JSON, and a test
  fails any SQL that parses them. The JSON columns SQL does read are typed in a task after 0.16.
- **The audit page's checks** (Erwin, D200): on every visit, at a cost that does not grow with the log; the full
  recheck only when asked (section 3). The first draft's scheduled row, `log_verified`, is not built.
- **The offboarding report and retention** (coordinator, on D161): the report covers the reads retention keeps,
  stating the date they start from, and every write of a value, however old (W385: `drop_audit_day` and `reads_from`
  leave `wrote` rows alone). The summary stays a cache the projector rebuilds.
- **One fence** (Erwin, D202, superseding D201): 0.16 keeps 0.15's fence. Per-object locks are parked with their
  models (#585) until a load test asks for them (section 3).
- **Old heartbeats and checkpoints** (coordinator): not listed. They stay in `audit_log`, verified, and a rebuild
  with another filter brings them back.

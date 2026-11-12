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
| `audit_log` | 0.14 | Hash-chained log. Also the store of a dozen facts of current state. Every change still appends to it, under a global lock. | 30 |
| `log_changes` | 0.15 | One signed entry per change to a sealed row. | 20, of which 18 serve the audit page |
| `log_uses` | 0.15 | One slim signed row per use, partitioned by day. | 2 |
| `log_reads` and 3 more | 0.15 | Uses as pages list them, with two day tables, two triggers and a cursor. | 10 |
| `principals`, `credentials`, `secrets`, `environments`, `service_bindings`, `mcp_connections`, `policy`, `roles` | 0.15 | State, one sealed row per object, read by primary key. | few |

**State still read from the old log.** Each line is a "newest entry of kind K" read, with a partial index of its own.

| Fact | Read by | After |
|---|---|---|
| Policy revision (newest `policy.change` seq) | every authenticated request, every use that carries an app token, token issue, bind, revoke: 11 reads in SQL, 5 in TypeScript | no row: the newest change's number of the roles object and of the policy object (section 3) |
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
change takes two global locks: the row `audit_chain_head` in its first statement, which no use takes, then in its
last statement an advisory lock exclusive (the **fence**) that every use takes shared. So a use waits for a change
only from the change's last statement to its commit, one round trip; that wait is what L1 removes.

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
own, and each trades four round trips under a global lock for one under none. Nothing cheaper is safe there: the entry cannot ride
the caller's check, which comes before the decision, and an entry the app signed with its own key would be a second
chain, which is what `audit_log` is.

**A change carries its entry.** A change's payload says what the object became, not what the page prints. A key's
change is `secret.write` or `secret.delete` with a version id and a nature. The 0.14 entry beside it said
`secret.loosen`, `secret.restore`, `secret.archive` or `secret.reset` and carried `was`, `kept`, `from` and `recipe`,
which the page's sentence is made of (`packages/ui/src/lib/audit-sentences.ts`). Once A1 stops writing those entries,
a sensitive value made readable would list as a plain write. Of the 37 sites whose entry has a change beside it, 22
lose the action or a detail that way, and all 37 lose what stands beside the detail: the trace (`credentialId`, `via`,
`confirmedBy`), the `operationId` that folds a 12-key write into one line, who decided, and the kind and label of a
token that `originsOf` labels its later acts with. So the entry rides whole in the change that records the same act,
under the vault's MAC:

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
  payload holds (`"inputs":"`, `"signIn":{`), which a `detail` could hold by chance, so until P2 the carrier refuses a
  `detail` whose encoding holds one of those texts; that check is deleted with `RECORDS`.
- *The vault holds the action to the op.* A fixed map beside `Op` (`packages/vault/src/inputs.ts`) lists the actions
  each op's change may carry: a `secret.delete` carries `secret.archive` or `secret.reset` and nothing else, a
  `secret.write` carries `secret.write`, `secret.loosen` or `secret.restore`, and A1's list of its sites fills the
  rest. An op the map does not name carries nothing, and `prepare` refuses the whole call for an action outside it. So
  the page cannot name an act the object did not undergo. The rest of the entry is the app's word, as an event's is,
  and `author` says so.
- *No line is inferred from an op.* A change with no entry shows only where main's page shows it today, the seven
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
  A protect over N environments is one `policy.change`, on the policy object's change (below).
- *One change carries one entry.* `audit_events` has one row per row of the chain (its key holds the chain's number),
  so the field is not a list. The one case of two today is a key revived and written in one change (`secret.unarchive`
  beside `secret.write`): the write carries one entry, whose detail says `unarchived: true`, and the page's sentence
  adds the revival. An entry about something that has no change is an event in the same `prepare` call
  (`PrepareInput.events`), committed after the changes in the same transaction.
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
does (an Owner's change to the member settles one). So 0.14's rule (a finding newer than the member's newest access
entry), `weighedBy` and `tamperedMembers` go, and old `tamper` entries stay listed like any old entry. V1 writes the
event, its id's form pinned beside `findingEventId`; P2 writes the reader (`api/members.ts`, `db/queries.ts`).

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
`audit_member_keys` for its member, key and version, at its time or later. It takes retention's floor from the sealed
retention change, never from `audit_cursor.reads_from`. That column has no MAC, and a writer who raises it makes the
projector skip entries; a verify that trusted it would excuse them all (`formal/Reads.tla`, `FloorSealed`, on P1). A
read in the frozen log timed before the newest dropped day keeps its row on the page, since retention drops only the
uses' rows, and is on no report: the report covers retention's window and states the date it starts (D161).

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
- **New: a projector that stopped.** The beat fails its run, with no finding, when the cursor's `through` is below the
  number the checkpoint signs through and the cursor's `at` is older than two of the beat's periods, the one interval
  the deployment already configures. A quiet instance never trips it: its cursor is level with the checkpoint, however
  old. Two periods and not one, because until the swap the projector reads the 5-minute checkpoints: just before a
  beat it is honestly one period behind, and a run that fires a few seconds late must not fail. After the swap it
  reads every tick and one period would do; two stays, so the rule does not change at the swap. The page already shows
  it ("listed through 14:05:03"); this is for when nobody looks. Nothing is wrong with the log, so readiness stays
  green.

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

Today's one number covers a protection because every protect writes a `policy.change`. The same rule holds after,
stated on the set: **the protected set changes only in the vault's protect decision, and that decision changes the
policy object whenever the set changes, rows or no rows**, the condition under which it appends `policy.change` today.
Ada's caller is loaded while `prod` is unprotected, an Owner protects `prod`, and Ada's key write to `prod` then finds
the policy object's number moved: 409 `policy_changed`, as today. An environment created protected is no writer of the
set: it copies `protected` from the policy its caller was loaded with (`protectedFor`), under the same re-check, and
touches nothing. The model holds a narrower digest per write (the roles, the policy row and the written environment's
protection, `WritingDigest`); one number for every protection compares more often than that, never less, and no route
has a set of environments to remember.

The policy's change is a new op, `policy.protect`, carrying the whole policy as its value as `bulk.limit` does: the
use and the bulk prune read the cap from the policy's newest change whatever its op. It is not always the same value
written again. A fork's id is protected one call before its row is written (`access.ts`: an id with no row after a
short time is a fork abandoned, and read past), so the set holds ids with no row, which `environments.protected`
cannot. Those live in the policy's row, as they live in the `policy.change` entry today: three aligned arrays no SQL
reads (`ahead_environments`, `ahead_projects`, `ahead_at`), which the next protect decision prunes of ids that have a
row or are past their time. So a protect of an id with no row is a real change of that row, and a protect of
environments with rows writes their rows and the policy's value unchanged. One test per path: protect, unprotect, a
protect of an id with no row, and a creation as protected, which must touch nothing. The change carries the
`policy.change` entry (above), from the PR that deletes the vault's append of it to `audit_log`, not before. It is
built with the carrier, and A1's two numbers stack on it.

Under L1 a protect then locks the policy object and its environments exclusive in one statement, in key order after
the fence, as any change of several objects does; for an id with no row it locks the policy object alone, as a change
of the cap does. Every use holds the policy object shared for its cap, so a protect excludes uses for its last
statement, as a settings change does. Checked on the lock model: with the policy's change writing an environment's
object too, `ChangeLocks` holds (429,906 states) and breaks `NoWaitCycle` with the two taken out of key order.

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

**Object locks (L1, D201).** Last before the timeout, the fence becomes the checkpointer's alone: a use and a
change's last statement take it shared, so its barrier still waits for every number in flight. Each object a decision
reads gets an advisory lock keyed by the object. A use takes the lock of each object it reads, shared; a change's last
statement the lock of each object it writes, exclusive. A write to one key then makes only the uses of that key wait,
for that statement. L1 moves none of the 14 protections: they are change against change, the change lock's. A use
stays one statement, one round trip, one vault call. The models (T282, a draft stacked on #573) hold it; what they
fixed:

- **Which objects:** the ones whose newest change a use already seeks. Its credential (or connection, binding or
  Access account), its member, the roles, the policy, the key and the key's environment: 6. Another place, a personal
  config's parent, a reference's source and the source's environment make 10 at most by ids. By name, the fork chain
  adds up to 3 environments; a route, its definition a level and its editor's member.
- **One order:** the change lock, the issue lock, the fence, the objects' locks sorted by lock key, then a use's
  principal's lock. A transaction takes its objects' locks once, all of them, before its first read or write under
  them. Four ways to break that each close a wait cycle, a 1 s stall in Postgres: `revoke_credential`, which takes no
  issue lock, taking its object before the fence; a batch taking each key's lock as its turn comes; a statement of
  several `app_change` calls (a project's delete) taking each call's as it comes; and `use_batch` taking its
  principal's lock before its keys, as it does today. An event the app commits with its changes (`log_events`, which
  shares the fence) comes after them in that statement: before them, the transaction would hold the fence when its
  change asks for the issue lock, while the checkpointer holds the issue lock and waits for the fence.
- **A use reads ids before it locks.** The call names its credential, key and place; the member is on the
  credential's row, a reference's source on the reference's. The function reads those ids with no lock, takes the
  locks, then runs its statement. A key made a reference in between names an object the call did not lock: the
  statement writes nothing and answers `moved`, and the vault calls again. A use never locks after its first read.
  The locks are a statement of their own, ahead of the lean and the full read statement alike (taken inside a reading
  statement, they would come after its snapshot). A handoff from the lean one takes none, so a use still waits once.
- **A hold shares what it read.** The fence held exclusive did one more job: it made a two-trip write's hold stand to
  its COMMIT against a change that takes no change lock. So `hold_inputs` and `admit_hold` take the lock of each
  object the vault decided on, shared, with those they write; `write_request` reads as a use does, under the same
  locks. An entry that changes no object (`note`, a refusal) shares the fence and takes none.
- **Advisory locks, not `FOR SHARE`.** A statement takes its snapshot before it waits for a row's lock, so a use that
  waited for a change would decide on the other rows as they were before it. Row share locks also write the row
  (`xmax`, then a multixact for two holders, on the rows every use reads: 0.14.3's cost) and conflict with every
  update of it, a credential's last use too.

Cost, on the reference rig: 11 shared advisory locks taken in one statement cost 0.0024 ms more than 1 (0.0095 ms
against 0.0071 ms a round); the 0.013 ms measured first took each in a statement of its own. The bound that matters
is Postgres's shared lock table, where advisory locks live: `max_locks_per_transaction` (64) times `max_connections`,
6,400 objects at the defaults. Measured, one session holds 12,832 before `out of shared memory` at 100 connections,
and 5,248 at 25. What holds locks at once is the pool, 20 connections a Hyperdrive config at 100 and 6 at 25, not the
1,250 keys an isolate has in flight. Single uses never come near: 20 x 13 = 260. A batch statement of 100 keys holds
its caller's 4 and 1 to 6 a key: about 110 when its keys share an environment, 604 at the very worst (each key in a
place of its own and a reference into another). Twenty at once hold 2,200, or 12,080; six hold 660, or 3,624 against
1,600. Today's batch already takes up to 100 more a statement for the cap's rows (`b_lock`). A full table fails
whoever asks next, anywhere in the cluster, with an error. L1 must make that impossible, and its PR picks how:

1. **Stripes (recommended).** An object's lock key is its hash modulo 128. A statement then holds 128 object locks at
   most, whatever it reads: 20 x 128 = 2,560 of 6,400, and 6 x 128 = 768 of 1,600. The price is false sharing: a
   change makes a single use of other objects wait with probability 7 in 128, and a 100-key batch about half the time,
   for one statement, where today every change stalls every use. A batch's round 2, which holds its principal's lock
   exclusive, drops its `b_lock`s, which that lock makes redundant.
2. **Smaller batch statements**, sized at setup from the lock table as the pools are from `max_connections`: about 25
   keys a statement at the defaults, so a 100-key request is 4 statements in turn where it is 1.
3. **A larger table:** `coffre setup` refuses a database whose `max_locks_per_transaction` is below what its pools
   can ask for. A restart, and not every managed Postgres allows it.

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
| The head becomes the change lock | `Coffre.tla` with its 11 scenarios, `Credentials`, `Issuing`, `Factor`, `WorkloadEnrollment`, `Writing`, `WriteLocks`, `Lifecycle`: 14 "under the head" protections keep their place and take the lock's name, with their 18 runs; the order change lock, issue lock, fence gets a deadlock check; the key write and the member add are checked without the lock. `Bulk`, `Audit` and `AppKey` keep the head, 0.14's chain's, and go with the code that ends it | first (A0) |
| The policy revision becomes the newest change numbers of the roles and the policy objects | `Lifecycle` (LifecyclePolicy), `Writing` (WritingDigest, which holds the narrower per-write digest) | first (A0) |
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

1. **Stop.** Run `coffre verify log` on 0.15.0: the full walk of the old chain, in steps, green. Run the upgrade's
   precheck, which refuses before anything is touched: a log with an `audit.loss_accepted` entry (it prints the count
   and their seqs), a member a finding stands for. Take the app off its route and let one 5-minute beat pass, so that
   the chain ends in a checkpoint the watch's store holds; 0.15.0 has no command or route that runs the beat on
   demand. Then stop the beat and back up. On Workers the cron fires whatever the routes are, so stopping it is
   removing the cron trigger (the schedules API with an empty list, or the dashboard), read back to confirm; on Node
   it is stopping the process. Nothing then writes the log or the store between the backup and the migration. Step 3's
   deploy brings the trigger back, as redeploying 0.15.0 does on a rollback.
2. **`coffre migrate`**, as the owner, one migration. It refuses a database that is not a cut-over 0.15.0 (no cutover
   change in `log_changes`, or a schema past 0049 that is not 0.16's). In SQL it creates the tables; fills `settings`
   and `log_keys` from the newest entries, unsealed; drops the indexes, triggers, functions and tables of section 5;
   revokes INSERT on `audit_log`. It copies nothing into the projections. 0.15.0's code cannot run on the result: the
   functions it calls are gone or changed, and a row it writes directly has no seal, which the vault refuses.
3. **Deploy 0.16.**
4. **The vault's step**, on its first call, while the app answers 503 `upgrading` at its one door. It is the same
   size whatever the log holds. The vault cannot read the watch's store, so the app reads it at the door and hands
   the checkpoint it holds in on the call that runs the step; the vault verifies its own signature on it and
   requires the log to hold that entry at that hash. It checks the old chain from there to its last entry, as
   0.15.0's own check does between beats: the app its entries' MACs, the vault its own, and the hashes that link
   them. That is one beat's entries, 10,000 a call at most. It writes the change that names the chain's final seq
   and hash, the **anchor** the old log answers to from then on. It checks the settings' and keys' rows
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

**What a database writer can do in the gap.** Before the anchor: cut entries off the end of the old chain, back to
the newest checkpoint held outside the database at most. Those are the last beat's entries, of the kinds 0.15.0
writes to the old log alone (sign-ins, refusals, token issues), and 0.15.0 has the same window between two beats;
the beat that step 1 waits for leaves nothing in it. They cannot add or alter an entry without a key. After the
anchor: an old entry altered before the projector reaches it stops the walk there, with a finding; one altered after
is the recheck's to find, and the rows the page shows carry MACs of their own.

**If the step dies halfway, it is rerun.** Each write is one change with a request id made from what it seals
(`upgrade-0.16:settings`), compared-and-set on a null seal, so the next call skips what is done and goes on. It only
adds changes and fills null seals. Restore is for a step that refuses: the old chain's tail does not verify, or a row
disagrees with its entry. The door then says which, and the operator restores step 1's backup, which loses nothing:
the app was off its route. The store cannot be ahead of that backup, because the beat was stopped before it (step 1).
A store that is ahead all the same is the cut it looks like: the step refuses, and its message names step 1. No
command or argument accepts a loss: the door answers 503 to the route `coffre audit accept-loss` calls, and nothing
writes the store it moved.

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
| V2a | Two use statements for four, the access rule one inlined SQL function, same reads. `use_credential`, `use_route`, `vault/use.ts` | E4 | no | yes | 3 | -400 to -450 |
| P1 | The projector and its four tables; every change, event and use, and the old log backward from its anchor; `coffre audit rebuild`. Adds, because nothing can be deleted until pages can read it. | E4 | no, `Reads.tla` with it | yes | 4 | +900 |
| P2 | Pages read the projection: `GET /audit`, the report, MCP. Deletes `log_reads`, the three-log merge, 18 + 11 + 10 indexes | P1 | no | yes | 3 | -2,300 |
| P3 | Two PRs (section 3, "The watch after"). First the page's check, flat: one `check` call a visit (6 statements, 4 round trips), and `beat`, the same with no rows plus the finding; the full walk in steps behind a Verify button and `coffre verify`, which also holds each listed read inside retention to the report's summary, the floor taken from the sealed retention change (`reads_from` has no MAC); the page's walk of 0.14's chain deleted. Then the swap, after V1 and A1's sites: the scheduled run and `/readyz` on it, the old beat, the heartbeat, `vault.checkpoint()` and loss acceptance deleted | P2; the swap V1, A1's sites | no | no | 3.5 | -1,400 |
| T1 | Three `text[]` columns, `log_config` dropped | #564 | no | yes | 1 | -50 |
| A0 | Models: the head becomes the change lock (section 3), the policy revision a digest of newest change numbers | now | it is the model | no | 2 | 0 |
| V1 | The vault's entries go to the chain only; `settings`, `log_keys`; the vault's upgrade step (one beat's tail, the anchor); `note` for events, and a refused read written by the call that refused it | P2 | `SealedObjects` with it | yes | 4 | -300 |
| A1 | The app's entries go to the chain; `audit_chain_head`, the reads under it and the policy revision deleted, `lockLogHead` replaced by the change lock, no re-check moved; sign-in in 5 round trips; then `audit_log` frozen, directly on P3's swap | P2, A0; the freeze P3's swap | A0 | yes | 4 | -700 |
| V2b | `audit_log` reads out of the use and change functions; the cap from its row; old overloads dropped | V1, V2a | `HotPathOne`, small | yes | 1.5 | -300 |
| L1 | Per-object locks; the fence is the checkpointer's alone (D201). Its model is a draft PR stacked on A0, started in week one | V2b, A1 | yes | yes | 4 | +100 |
| U1 | `scripts/upgrade-check.sh`, its 0.15.0 pages compared without heartbeats and checkpoints | V1, A1 | no | no | 2 | +500 |
| S1 | The 5 s timeout from #552, with #559's sweep green at two sizes. Adds the sweep, which is the proof | all above | no | no | 2 | +1,600 |
| C1 | The collapse: one upgrade migration from 0.15.0, one baseline for new databases, 80 migration files deleted, functions as one file each, a parity test (0.15.0 plus the migration equals the baseline) | all above | no | it is the migration | 2 | -30,000 |
| C2 | `AGENTS.md`: 0.16.0 is a clean break like 0.4.0, expand-then-contract resumes with 0.16.1. Old design docs deleted | C1 | no | no | 0.5 | -5,300 |

**Order.** Day 0: E4 alone, since it edits `vault.ts`. Then three lanes at once, built against a contract pinned
first (K1): `note` and the row it writes, `settings` and `log_keys`, the upgrade's changes, and `check` with the MAC
inputs of a projection row and of the cursor. V: V0, V2a, V1, V2b, L1. P: P1, P2, P3. A: T1, A0, A1, U1, S1. C1 and
C2 close. V1 and A1 are built beside P1 and P2 and land after P2: once entries go to the chain only, a page still
reading `audit_log` loses them. V2b lands after V1, whose rows it reads; L1 after A1, which freezes `audit_log`,
whose insert trigger still takes the fence exclusive. The freeze waits for P3's swap, which removes the last
appender (the old beat) and is built beside A1's sites, so the path does not grow.
**Pairs that collide:** V1 and A1 both need `note` in the vault's contract (`packages/core/src/vault.ts`), which the
contract PR lands first. P2 and P3 both edit `server/src/api/audit.ts` and run in sequence, as do E4 and V0 in `vault.ts`.
Every schema PR appends to `schema.ts` and the journal, one-line conflicts.

**Estimate.** About 40 agent-days. With the contract pinned, the longest path is the contract, V1, V2b, L1, S1, C1:
14.5 build days, 15 to 17 working days with the landings in order (18 to 22 while V1 waited for P2). The two
model-first PRs were where the risk is, and both are written. A0 found that the fence cannot stand in for the head,
so the 14 protections keep a lock of their own and A1 moves none of them. L1's found the order above and the hold's
shared locks, before V2b's and A1's code.
On Node, the projector runs on a timer in the vault's process, where Workers use a Durable Object alarm. The beat
is the app's scheduled run on both.

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

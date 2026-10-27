# Release notes

## Unreleased

- **0.15's change path for the app's own writes, behind its switch:
  nothing calls it yet.** `0025_app_change` adds `app_change`, which only
  the app's login may run: with 0.15's log on, every write of the app's
  that makes or ends a credential logs its change, sealed by the vault
  before the transaction, beside its row in the same transaction. It also
  makes `change_input` seal a deleted environment with its slug before
  the tombstone. With the switch off, as every deployment has it, the
  app's writes are as in 0.14.5, but for two things. A member's removal
  now also revokes sessions whose sign-in account had already ended,
  which were dead anyway. And the checkpointer shares one tick among the
  changes waiting at once ([0.15-plan.md](docs/design/0.15-plan.md),
  "As built: PR 4b").

- **0.15's change path, behind its switch: nothing calls it yet.**
  `0023_change_path` replaces `change_input`, which nothing called, with
  one that takes every change the vault makes to members, grants, roles,
  the bulk cap and an environment's protection or slug. The vault logs
  them only with 0.15's log switched on, which no deployment can do yet
  ([0.15-plan.md](docs/design/0.15-plan.md), PR 4a). This release behaves
  as 0.14.5.

- **0.15's log, expanded: one migration, nothing calls it yet.**
  `0022_log_015` on Postgres (`0018_log_015` on SQLite) adds the tables,
  seals, functions and login 0.15's hot path will run on
  ([log-015.md](docs/design/log-015.md)). This release behaves as 0.14.5,
  which keeps serving on the new schema, so the order of the deploy and a
  rollback need no care.
  - **It makes a role**, `coffre_vault_hot`, the hot path's login, unable
    to log in until 0.15 gives it a password. So the login that runs
    `coffre migrate` needs `CREATEROLE` (or to be a superuser), as 0019
    did, unless the role exists already with its settings; without either
    the migration fails, saying what to run, and changes nothing. Check
    as the migrating login: `SELECT rolsuper OR rolcreaterole FROM
    pg_roles WHERE rolname = current_user`.
  - **Every 0.14 entry that changes access takes a new lock**, which
    nothing else takes before 0.15: an advisory lock, uncontended, in the
    append's own transaction. Reads and uses take none.
  - It adds nullable columns to five tables, and checks that scan nothing
    (`NOT VALID`), so it runs in a moment.

- **The CLI is an image.** Each release now publishes
  `ghcr.io/erwinkn/coffre-cli` for amd64 and arm64, tagged `<version>`,
  `<major>.<minor>` and `latest`, after npm: npm's own tarball of the
  version, checked against its integrity, on distroless Node 24, as uid
  65532, with `coffre` as its entrypoint, signed build provenance and an
  SBOM. A sidecar runs `coffre serve` from it, pinned by digest, with no
  image of its own ([workloads.md](docs/workloads.md#the-image), which
  also shows Compose). The release workflow's `workflow_dispatch`
  publishes the image alone for a version already on npm, and Validate
  builds both platforms from the revision's packed CLI and runs
  `coffre serve` in the image against a fake coffre (`pnpm test:image`).
- **A tunnel's late check no longer drops a newer session's cached URL.**
  A check of a `coffre run` tunnel's handle that answered after its last
  session had closed armed a watchdog for that gone group, which fired an
  interval and a deadline later and dropped the URL the cache held for the
  same handle, environment and tunnel: a session opened since then read
  the vault again on its next connection. Such a check now arms nothing; a
  refusal still drops the cache.

## 0.14.5 (2026-10-26)

- **Upgrading to 0.14.5, in short.** One migration, `0021_prune_vault_releases`
  (Postgres only; SQLite has none). It adds one function,
  `prune_vault_releases`, and grants `EXECUTE` on it to `coffre_vault`, the
  vault's runtime login: no table, no new role, nothing changes in your
  config, and it runs in a moment. Deploy in the usual order: `coffre
  migrate`, the vault Worker, then the app ([deploy.md](docs/deploy.md)):
  a vault older than 0.14.5 does not name a use back, and the app appends
  it as before. 0.14.4 runs on the new schema, which never calls the
  function, so rolling back needs no database step; the one caveat is a
  `bulkLimit.windowMinutes` over a day, which 0.14.4 accepted and 0.14.5
  refuses to start with, and which would count only a day after rows were
  pruned. The server fixes are the last two entries: a proxied use that
  takes the log's head once, and a read under load that answers within
  seconds.

- **Every "not signed in" error is two lines.** `coffre login` runs the
  device flow: it prints a link and waits for it to be approved, so an agent
  that ran it in the foreground hit its own timeout before the person saw
  the link. The error is now
  ``not signed in: run `coffre login https://coffre.acme.example` ``, and under
  it, `agents: run the command in the background and provide the link it
  prints to the user`. The URL lives in the command, so the first line no
  longer starts `not signed in to <url>` (a clone's `coffre.json` adds
  `(named by /path/coffre.json)` to it). One constant, `SIGN_IN_HINT` in
  `packages/cli/src/instance.ts`, is the second line of every such error: a
  command with no session, a session ended or unknown to the instance, a
  code that expired, `coffre use`, `coffre verify instance`. An instance
  behind Cloudflare Access, which signs in with cloudflared, gets no hint.
  `coffre login` also says how long it waits: "Waiting for you to approve
  it; the code expires in 10 minutes…".
- **`coffre update` updates an npm global whose prefix npm no longer has as
  its own.** After Node was reinstalled, npm's global prefix pointed
  elsewhere (`/opt/node-…`), `npm ls -g` listed nothing, and `coffre update`
  stopped with "can't tell how this CLI was installed", suggesting an
  `npm install -g` that would have put a second copy under the new prefix,
  shadowed on `PATH` by the old one. A CLI that runs from
  `<prefix>/lib/node_modules/@coffre/cli` (on Windows,
  `<prefix>\node_modules\@coffre\cli`), with npm's shim beside it
  (`<prefix>/bin/coffre`, on Windows `<prefix>\coffre.cmd`), is
  now npm's global at that prefix, and is updated with
  `npm install -g --prefix <prefix> @coffre/cli@<version>`. A project's
  dependency, pnpm's globals and npx's cache are told apart first; npm's
  own prefix runs the same command as before.
- **The bulk count's table keeps only a day of keys.** Since 0.14.4,
  `vault_releases` held a row for every key a principal was ever released,
  deleted keys included, and the count read them all. Each scheduled run's
  checkpoint now forgets those released over a day and an hour before, up
  to 10,000 a run, in one statement of its own, off every
  read's path. A failure leaves them to the next run and says so: the
  checkpoint's `warning`, which the audit watch reports. The day is the
  longest window `bulkLimit.windowMinutes` now takes (1,440; a vault given
  more refuses to start, saying so), and the hour a margin for the
  database's clock stepping back, which is seconds: a release any window
  counts never goes, and widening the window counts exactly. What is kept
  is the database's to say, not the caller's: migration
  `0021_prune_vault_releases` (Postgres only) adds the function the vault
  calls, `prune_vault_releases(at_most)`, which holds the day and an hour
  in its own SQL, so the vault's login, which still deletes no row itself,
  cannot forget a release a window counts. The release before never calls
  it.

- **A use through the credential proxy takes the log's head once.** The
  vault's read appended its `secret.read` under the head; then the app took
  the head again for its own `credential.use` entry, for six statements
  more (the head, the policy, the credential, the head's last entry, the
  append, the commit). Each `/use` held the head that every audited write
  waits for about seven round trips, which capped an instance near six
  uses a second at 20 ms. The app now hands its entry to the vault, which
  appends it beside its read, in the same decision; the app checks the
  credential again after the release with no lock, as an export always
  has. A cold proxied use runs 4 app statements, not 10, none in a
  transaction. Under 20 concurrent uses at 20 ms, 15.6 uses a second
  instead of 6.4, p50 1.2 s instead of 3.4 s. The log shows the same
  `credential.use`, its metadata unchanged; its author is the vault, and
  the audit page says the line was decided by the vault. Like the read
  beside it, it records the vault's release: when the app's check then
  finds the credential ended, a `credential_ended` refusal of the same
  operation follows it, and no value is handed back; when it finds the
  policy changed under a use that also holds plain values, the use
  answers 409 and hands back nothing, and the entry stands as the
  release's record alone. The vault vouches for the actor, the time, the
  release and its place, which must be the place the read was at (the
  fork it is read in, a reference's holder, or the value's own): another
  is refused as a bad claim, logged, with no use appended. Where the use
  went, its credential and host, are the app's word, as they were. A vault
  older than 0.14.5 does not name the use back, and the app appends it as
  before; so does a use of plain values
  only, which asks no vault, and one whose record is longer than the
  vault takes (16 KiB, a use naming hundreds of keys). Deploy the vault
  first, as ever. No migration ([formal.md](docs/formal.md), `Proxying`).

- **A read under load answers within seconds: read, or 503 at once.** A
  read's whole vault call, its retries, the entries of a refusal, the
  record of a vault key's check and a key service's intent included, is
  due five seconds after its key decision starts (with a key service, plus
  its own five-second budget, spent from the same deadline). Settling the
  vault's keys after a rotation, once, is not bound by it. Each transaction's
  waits are bounded by what is left, and past the deadline it fails as
  unavailable rather than start another; a refused read's entries take a
  place in line too, and no longer wait fifteen seconds for the log's
  head. At most sixteen reads wait for the head at once, each holding one
  of its places in line, an advisory lock that is tried and never waited
  for. The next answers 503 `unavailable` with `Retry-After` in one round
  trip, and holds no connection while it would have waited. The place is
  taken in the statement that already waited for the head, and only when
  another holds it: no statement more. On a burst of 50 reads of one
  principal, with 8 reads a second from three others, a 30 ms round trip,
  a 40-connection pool and a long read history: p99 2.1 s (4.4 s on
  0.14.4), no answer after 2.2 s (4.5 s), and every other principal read
  within 2.2 s. 35 of 290 reads were refused at once (20 failed after
  about 4.5 s on 0.14.4). The CLI and SDK ask again after `Retry-After`.
  No migration ([formal.md](docs/formal.md): a read that gives up its wait
  breaks no invariant).

## 0.14.4 (2026-10-26)

- **Upgrading to 0.14.4, in short.** One migration, `0020_vault_releases`
  (`0017` on SQLite). It adds a table, a trigger on `audit_log` and its
  function, owned by the login that runs `coffre migrate`, as the other
  tables are. It needs no new role or privilege, and nothing changes in
  your config. Audit appends wait while it fills the table from the log:
  2.1 s on a log of 119k entries, about 5.5 s at a million. Deploy the
  vault Worker before the app, as [deploy.md](docs/deploy.md) says. 0.14.2
  and 0.14.3 run on the new schema, and their reads keep the table too,
  so rolling back needs no step. The fix this release is for: the first
  entry below.

- **A read costs the database the same however much its reader has read
  before.** The bulk limit's count read every `secret.read` the reader had
  ever made, not only the window's. Its bound, `clock_timestamp()`, is
  volatile, so Postgres could not use it on the index and fetched each
  entry. On a copy of Equisafe's log (119k entries), the busiest reader's
  decision cost 17 ms and 18,882 pages of the database, and it grew every
  day. 0.14.3 let one principal's reads decide side by side, so a burst of
  50 ran it 50 times at once on a 2-vCPU database. Each then ran past the
  3 s a read's statement may take (57014), holding a Hyperdrive
  connection, and calls on every principal waited for one. The count now
  reads `vault_releases`: a row per principal and key, with when it was
  last released. A trigger on `audit_log` keeps it from the log, in each
  read's own transaction. No login writes it, and the vault and backups
  read it. The count reads one row per key the principal was ever
  released, deleted keys included, however often they read it: 0.5 ms
  and 22 pages on the same copy, and as many pages on a log of a million
  entries. Nothing prunes the table yet: its size follows the instance's
  keys, not the log. The limit counts exactly what it did.
  A test now holds every statement of the hot requests to the same pages
  on a log ten times longer.

  Migration `0020_vault_releases` (Postgres; `0017` on SQLite) makes the
  table and the trigger, then fills it from the log, in one transaction.
  Audit appends wait for it: 2.1 s on the 119k-entry copy, 7.7 s with the
  log grown to a million, the whole `coffre migrate` run on 2 vCPUs. A
  read waits at most 3 s, so on a log that large some reads answer 503
  `unavailable` meanwhile: migrate in a quiet minute. The release before
  keeps working on it, and its reads keep the table too.

- **A CI run's sign-in holds the audit log's head for fewer round trips.**
  `POST /api/auth/oidc` ran 14 app statements, 10 of them while its
  transaction held the head that every audited write on the instance
  waits for. It now runs 8, 6 under the head: the service's bindings,
  whether the token was spent and the newest policy change are one read;
  under the head, the member, the binding and its per-minute rate are
  one read, and on Postgres the token spent, the credential issued and
  the binding stamped are one statement, which issues nothing if the
  token was spent already. The checks and refusals are unchanged. Through
  a database 25 ms away, one sign-in went from 396 ms to 250 ms, three at
  once from 943 ms to 707 ms at p99, and ten at once from 2,473 ms to
  1,514 ms. No migration.
- **A refusal to checkpoint stands until the entry it found is whole
  again.** With three checkpoints at once, one could refuse for an entry
  edited after another had signed past it, and a third, starting after
  the refusal, resume from the second's checkpoint and sign, never reading
  the entry: the edit stayed unflagged until the rehash of the past found
  it again, within two laps. Now, while a refusal stands, a checkpoint
  whose walk began after the entry it names checks that entry again under
  the head, its hash, its links and the vault's MAC, and refuses while it
  is still broken (T104, found by `formal/Audit.tla`). A refusal that
  names no entry, or a lap of the rehash ending on a hash other than the
  one signed, is cleared by the next signature as before, and found again
  by the rehash.

- **A credential can put its key in one field of a small form or JSON
  body.** `form('refresh_token', '{GATHER_REFRESH_TOKEN}')` and
  `json('secret', '{TURNSTILE_SECRET_KEY}')`, from
  `@coffre/server/plugins/credential-proxy`, sit beside `header()` and
  `query()`. They cover Firebase's token refresh and Turnstile's siteverify.
  The app sends its usual body with its handle in that field (a workload
  puts anything there). coffre reads the body whole, 64 KiB and 256
  fields at most, replaces only that field's value and forwards every
  other byte as sent, with `Content-Length`, and any `Content-Digest`,
  computed again. It refuses, sending nothing:
  - a body of another type, charset or encoding;
  - a body that is too large or malformed;
  - a body without the field, or with it twice;
  - a handle anywhere else in the body, however it is encoded.

  SigV4 credentials take no body rule. Nothing to migrate, and no new
  query ([credential-proxy.md](docs/design/credential-proxy.md), section 5,
  "A field of the body").

## 0.14.3 (2026-10-26)

- **Upgrading to 0.14.3, in short.** One migration, `0019_backup_role`,
  Postgres only, which adds the group `coffre_backup` and its read grants:
  the release before never meets them. It makes a role, so the login that
  runs `coffre migrate` needs `CREATEROLE` (or to be a superuser), unless
  `coffre_backup` exists already and that login holds it `WITH ADMIN`
  (below); without either the migration fails, saying what to run, and
  changes nothing. Check before you deploy, as the migrating login: `SELECT
  rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user`.
  Nothing to change in your config.
  Deploy the vault Worker before the app, as [deploy.md](docs/deploy.md)
  says, and keep your Hyperdrive limits. The fix this release is for: one
  member's reads no longer queue behind each other on their own row, which
  failed a busy service's `/use` and reveals with 503 after 15 s. It also
  brings a credential proxy that opens a lapsing entry once, not once per
  request; a CLI and Action that ask again on 503; `verify` and `hmac()`
  for inbound webhooks; and backups as a login of their own, with `coffre
  backup`, `coffre restore` and `coffre verify backup`.

- **One member's reads no longer queue behind each other.** Every vault
  decision took its member's row `FOR NO KEY UPDATE`, which reads did too:
  a service reading values eight times a second as one principal, through
  `/use` or a reveal, waited on its own row, each read holding its
  database connection, until the lock timeout failed it after 15 s with
  503 `unavailable`, as on 2026-10-26. A read (`unwrap`, `wrap`, `rewrap`)
  changes no member and now takes the row `FOR SHARE`: one member's reads
  decide side by side, and a revocation, removal, grant change or key
  rotation still waits for a read already deciding and fences the next.
  Postgres lets a share lock join those held even while a change waits for
  them, so each row now comes with an advisory lock on its principal, in
  the same statement, which queues: a steady stream of reads cannot hold a
  removal off. Each statement of a read's decision now runs at most 3 s, a
  wait for the log's head included, then fails as 503 `unavailable`, which
  the CLI and the Action ask again; a change still waits up to 15 s for
  each lock, and so does the entry of a refused read.
  The bulk limit is counted under the log's head, exact as before. No
  query is added. The log's head is now the queue under heavy load from
  one member: with a key service and Hyperdrive far from the database,
  some reads of a long burst fail fast rather than all of them slowly.
  - **Upgrading:** no migration of its own. Deploy the vault before the
    app, as always; keep Hyperdrive's connection limit where it is. While
    instances of the release before still run, their changes to a member
    take no place in the queue, and a stream of that member's reads can
    hold one off until its 15 s bound: a few 503s during the rollout, gone
    once it completes. Afterwards too, a change to a member waits for their
    reads at the key service, 5 s at most; their reads that arrive
    meanwhile wait behind it, and fail as 503 after 3 s if the key service
    is that slow.

- **Backups need not hold the owner's password.** The new group
  `coffre_backup` reads every row and writes none: no insert, update,
  delete or truncate, no `CREATE` or `TEMPORARY`, no function that writes as
  its owner. The audit log's row-level security let only the app's and the
  vault's groups read it, so `pg_dump` as any other role, even one in
  `pg_read_all_data`, stopped at the log, or dumped none of its entries
  with `--enable-row-security`; a policy now shows `coffre_backup` every
  entry. `coffre migrate --backup-login <role>` grants the group to that
  role, which you make, as you make the runtime logins; pass it on every
  run, as a pipeline does, and it changes nothing once granted. A role that
  does not exist fails the run, named. Coffre never makes the role and
  never revokes the group: a run without the flag leaves the membership as
  it is. Back up with `pg_dump --enable-row-security` as that login
  ([restore.md](docs/restore.md#on-plain-postgres)). `coffre migrate`, in a
  deployment's folder, as a login that owns coffre's tables, now reasserts
  the database's privileges even when nothing is pending; before, it stopped at "up to date", and a restored
  database kept the privileges its dump left out until the next migration.
  `migrateDatabase` takes its `onPlan` callback in an options object now,
  beside `backupLogin`. A failure after the migrations committed no longer
  says that nothing was changed.
  - **Upgrading: one migration**, `0019_backup_role`, Postgres only, which
    only adds the group, read grants and the log's read policy for it:
    the release before never meets them. It grants only on coffre's own
    tables, by name: another table in `public` is left as it is, whichever
    login migrates, a superuser included. A `coffre_backup` made before
    keeps no other privilege on coffre's tables, and is refused if it is a
    member of another role or owns an object. Its members are yours, as
    `coffre_app`'s are: the groups are the server's, shared by every
    database on it. It makes a role, as no migration since the
    baseline did: the login that migrates needs `CREATEROLE`, which a
    member of the owner does not inherit, unless `coffre_backup` exists
    already, made by a login that has it, which then grants the migrating
    login `ADMIN` on it: `CREATE ROLE coffre_backup NOLOGIN; GRANT
    coffre_backup TO <login> WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`.
    `--backup-login` needs that `ADMIN`, and nothing on the role it names.
- **`coffre backup`, `coffre restore` and `coffre verify backup`.** Backup
  dumps the database with `pg_dump` as a backup login, a member of
  `coffre_backup`, in one snapshot, and writes a manifest beside the dump: each table's rows,
  counted and hashed, the newest migration, the audit log's head and the
  dump's SHA-256. It refuses a login whose row-level security would hide
  rows of any table from the dump, the trap a `pg_read_all_data` login
  falls into at the audit log. Restore brings a dump back into an empty database, in one
  transaction, then checks it against the manifest, the log's chain from
  its first entry to the head included, and lists what is left: passwords,
  both Hyperdrive configs, the redeploy, `coffre verify log`. `verify
  backup` restores a copy without grants or row policies, for a nightly
  check on a server with none of coffre's roles. With `--keys`, both also
  open every value with the vault key and authenticate every log entry its
  author signed under the keys given. Postgres only; they need PostgreSQL's
  `pg_dump` and `pg_restore` on `PATH` ([restore.md](docs/restore.md#on-plain-postgres)).
  The restore drill now runs them.
- **`coffre setup` makes the backup login.** Beside the runtime logins, it
  makes `coffre_backup_login`, with a fresh password, migrates with
  `--backup-login coffre_backup_login`, checks the login can read the log
  and write nothing, and shows its URL once, as `Backup database URL`
  (`backup.DATABASE_URL` with `--json`). With Cloudflare, no Worker gets
  it: the screen shows it beside the keys, for your backup job's secrets.
  `--reset-passwords` gives it a new password with the others; a run
  without leaves one that exists as it is, a login made by hand included,
  and grants it the group; one that cannot log in gets a password. With
  Cloudflare, the login takes its password only once you have saved it. A deployment set up before gets the login the
  next time it runs setup, the others kept.

- **A 503 `unavailable` says when to ask again.** When coffre could not
  reach its database or its vault in time (a lock or a connection it
  waited on gave up after 15 s), the API and the credential proxy now
  answer `Retry-After: 5`, as the app already did while it could not reach
  its database at all: a caller back sooner joins the queue it left. The
  CLI waits at least that long before it asks again (up to 10 s), each of
  its waits 15 s at most; told to come back later than that, it does not
  ask again. The workload SDK, `coffre serve` included, waits
  at least that long before it proves a session again. MCP's OAuth
  endpoints, a socket coffre took too long to admit, and vault-kv say it
  too. The exchange's own 503s say 5 s where nothing makes a longer wait
  useful: a limiter that could not count (`busy`, 60 s in 0.14.2) and STS
  not answering an AWS proof; an issuer's keys not fetched, which coffre
  does not ask for again within a minute, still say 60. The 503 of a
  deployment that runs no workload gate now carries the reason `no_gate`:
  it is configuration, and nothing asks it again. An app's own client behind the proxy, the sidecar's
  included, sees the header as coffre sent it.

- **A CI run asks again when the instance cannot answer it yet.** When
  the instance answered 503 `unavailable` (it could not reach its database
  or its vault, a busy one say, and says to try again in a moment), the
  CLI failed at once: on 2026-10-26, two jobs of one run failed their
  sign-in this way while a third, signing in the same second, went on.
  These are now asked again, about 2 s and then 5 s later, each wait
  varied by up to half so that a run's jobs do not ask again together,
  before the answer stands:
  - a run's sign-in (`--service`, `login --service`), each time with a
    fresh ID token from GitHub;
  - the check of who a new session is, after `login --service`,
    `login --token` (the Action's `token:` input) and
    `login --access-client-id`;
  - each read of values: `get`, `export`, `run` after `login --service`,
    and the Action's read;
  - the Action's `require-complete` check (`missing`).

  So are the exchange's own 503s, when it cannot count exchanges (`busy`)
  or reach the issuer's keys (`issuer_unavailable`), and an instance moving
  to its new app key (`rotating`). `--verbose`, which the Action passes,
  says each time it asks again. A 503 an operator or a deploy must clear
  (`wrong_kek`, `vault_outdated`, `app_key`, `migrating`) is not asked
  again, nor is anything that writes, nor yet `coffre --service <name>
  run` where the instance signs it in with a key-bound session.

- **Inbound webhooks verified without their secret: `verify` and
  `hmac()`.** The credential proxy takes `verifiers`, HMAC-SHA256 secrets
  that coffre checks a signature with and never signs with:
  `verifiers: { yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) }`.
  The app sends the body as it came and the header as it is,
  `coffre.credential('yousign').verify(req.rawBody, signature)`, through
  the SDK, `coffre serve`'s listener or a person's handle, and gets back
  `{ valid: true }` or `{ valid: false }`, compared in constant time and
  nothing more. An `hmac()` among `signers` also signs, as its scheme
  writes it, for an app's own tokens. Signatures are `hex`, `base64` or
  `base64url`, after an optional prefix. A message is 64 KiB at most
  unless the `hmac()` says `maxBytes` (up to 1 MiB). The secret is opened
  as a credential's key is, once a minute per session and name, so a warm
  verify by a workload is one statement and no vault call, and its use is
  logged then, not per webhook. Pass the raw body: a body parsed and
  written again (`JSON.stringify(req.body)`) is not what the provider
  signed. No migration. For every caller of `POST /use/<project>/<env>`, a
  request past its bound is now 413, not 400, and a private key signs a
  message of up to 64 KiB, where the whole request was 64 KiB before
  ([credential-proxy.md](docs/design/credential-proxy.md),
  section 5, "Verifying, and HMAC"; [workloads.md](docs/workloads.md)).

- **A busy caller of the credential proxy no longer turns a lapse into a
  vault call per request.** The proxy keeps a credential's opened values
  for `cacheSeconds` (60 by default), per session or handle, in each
  isolate. When an entry lapsed, every request that came before the vault
  answered asked the vault too: on 2026-10-26 at 04:00Z one backend job's
  8.5 requests a second, as one service, made thousands of vault calls in
  ten minutes, each waiting on that service's member row, and 3,787 of
  5,079 requests answered 503. In an entry's last quarter (15 seconds at
  most), one request at a time now opens the values again, holding the
  others off 5 seconds at most, while they are served the entry; if the
  vault does not answer, it is served the entry too, and another asks a
  second later. An entry serves `cacheSeconds` from when the vault was
  asked, never past it, so revocation and lost grants take effect as
  before; a refusal ends the entry. A steady caller now opens a key about
  every 45 seconds rather than every minute, so the audit log has about a
  third more `use` entries. The stable URL's lookup of a handle's environments
  (`/use/<credential>`) still lapses each minute.

## 0.14.2 (2026-10-26)

- **Upgrading to 0.14.2, in short.** No migration, and nothing to change in
  your config. Deploy the vault Worker before the app, as
  [deploy.md](docs/deploy.md) says. This release is 0.14.1 plus one change,
  the audit watch's beat walking the log outside a transaction, which adds
  no query. If you come from 0.14.0, it also brings 0.14.1's: a read of
  values makes one vault call, not two; a decision made from the policy is
  one statement, not two; and the vault's checkpoint walks the log without
  holding a connection. Keep both Hyperdrive limits at 20. Nothing here
  eases a rollback concern of 0.14.0's: after an `APP_KEY` rotation, don't
  go back to 0.13.x.

- **The audit watch's beat no longer holds the app's connection while it
  walks.** Each beat walks the log on from where the anchor says the app
  verified, up to 10,000 entries, checking every hash and the app's MACs.
  It did so in one read-only transaction, which on Workers held one of the
  app's Hyperdrive connections for the whole walk, as the vault's
  checkpoint did until 0.14.1. The walk now reads a batch a statement,
  outside any transaction, each linked to the hash it verified last, and
  ends at the hash the vault signed, as before; where the log moved on
  from a key it replaced is also read from the entries themselves, as a
  safeguard. With 6,000 entries
  to walk, what the beat reads inside the app's transactions went from
  12,010 rows to 2, and its longest transaction from about 115 ms to 3 ms.

## 0.14.1 (2026-10-25)

- **Upgrading to 0.14.1, in short.** No migration, and nothing to change in
  your config. Deploy the vault Worker before the app, as
  [deploy.md](docs/deploy.md) says; a new app beside an older vault asks
  the vault twice for a read, as 0.14.0 did, so either order is safe. This
  release makes the vault cheaper to use, without changing what it answers:
  a read of values makes one vault call, not two (a reveal of seven keys,
  two calls and three Workers connections before, is one call and two
  now); a decision made from the policy is one statement, not two; and the
  audit watch's checkpoint no longer holds a connection while it walks the
  log (its longest transaction, at 10,000 entries, from 148.6 to 6.8 ms).
  Nothing here eases a rollback concern of 0.14.0's: after an `APP_KEY`
  rotation, don't go back to 0.13.x.

- **A read of values makes one vault call, not two.** A reveal, an
  export, the Action's read and a proxied call whose cache lapsed asked
  the vault who the caller was (`access`), then had it open the values
  (`unwrap`): two calls, and on Workers two of the vault's Hyperdrive
  connections, for each. The app now keeps the vault's last answer about
  each caller, and a read decides on it, its unwrap naming it: the vault
  opens the values only while that is still its answer, under the
  reader's row and the head, and otherwise refuses, reading nothing and
  logging no read, and the read goes again, asking. What a read answers and logs
  is what it was. A read whose caller's access, or the policy, changed
  since their last request makes three calls, once. **Deploy the vault
  first, as always**: an app of 0.14.1 keeps only answers that a vault of
  0.14.1 names, so beside an older vault it asks as before; and an older
  app never names one, which a vault of 0.14.1 decides on as before.

- **A decision made from the policy is checked in one statement, not two.**
  Every write, and every proxied call whose cache has lapsed, checks under
  the audit log's head that the policy it decided from is still the
  newest: that no `policy.change` came since, and that no protected
  environment was renamed or deleted. That was two round trips, the
  protected environments' slugs, then the newest change, with every other
  append in the instance waiting on the head. It is now one, with the same
  answer. A proxied call whose cache lapsed runs 10 statements, not 11, of
  which 6 hold the head, not 7.

- **The vault's checkpoint no longer holds a connection while it walks.**
  The audit watch's beat, every five minutes, has the vault checkpoint the
  log: it rehashes every entry since the last checkpoint, up to 10,000,
  and checks the vault's own by their MACs. It did all of that in one
  read-only transaction, which on Workers held one of the vault's
  Hyperdrive connections for the whole walk, 6 to 30 s on Equisafe's
  instance, while requests waited for one. The transaction now covers only
  the members' rows and where the walk resumes; the walk itself reads a
  batch a statement, outside any transaction, and what it walked is held
  to the log again under the head before anything is signed over it, as
  before. With 10,000 entries to walk, what the vault reads inside
  transactions went from 20,222 rows to 219. On Node, over SQLite, the walk
  no longer holds up every other transaction on the file.

## 0.14.0 (2026-10-25)

- **Upgrading to 0.14.0, in short.** Run `coffre migrate`: one migration,
  `0018_rotate_app_key`, which only grants the app's login to update an
  enrollment code's MAC, so the previous release serves on it until the
  deploy. Upgrade the instance, its `coffre serve` sidecars and the apps on
  the SDK (and the Action, which pins the CLI of its own tag) together: the
  instance carries the 503 `unavailable`, the faster append and the key
  rotation, the sidecar the fresh-token wait, the CLI and Action `--verbose`.
  Then check each Hyperdrive config's `origin_connection_limit`: it should
  be 20, not 5 (Equisafe's two configs at 5 starved the pool: 15 s waits
  for a slot, then 503s). `coffre setup` now names a config below its
  share, and `wrangler hyperdrive update <id>
  --origin-connection-limit=20` raises it. An upgrade changes no key: the
  app key rotates only when you rotate it ([deploy.md](docs/deploy.md#rotating-the-app-key)),
  in a later deploy than the upgrade: list the old `APP_KEY` as a
  `previousAuditChainKeys` secret of its own, deploy, then set `APP_KEY` to
  the new key and wait on `/readyz`. **A rotation signs every browser and
  CLI session out**; service and personal tokens, bindings and workloads
  go on. **After a rotation, don't roll back to 0.13.x**: 0.13 knows one
  key, so under the new one it cannot verify the log's older entries, and
  under the old one every row the rotation signed again fails, tokens and
  bindings included; 0.14 itself answers 503 `app_key` to a start under a
  key it replaced, and to undo a rotation you rotate again to a new key.
  Before any rotation, going back to 0.13.x is as it was in 0.13: the
  migration only adds a grant. Keep every key replaced listed, and
  escrowed, to verify the log's history, and never list one that leaked.

- **The Action says where its time goes.** A step that read seven keys
  took 39 s on a busy instance and logged nothing in between. The CLI's
  new session flag `--verbose` writes a line to stderr for each request,
  with its method, path, status and duration (`coffre: POST /api/reveals:
  200 in 480 ms`), and for each time it asks again; never a header, a
  body, a query or a value. The Action passes it, so its log shows which
  call was slow.
- **A database that does not answer is 503, not 500.** When Hyperdrive had
  no free connection to the database for 15 s ("Timed out while waiting for
  an open slot in the pool"), or a statement gave up on a lock, a reveal or
  a proxied call answered 500 "something went wrong", as for a bug, and a
  CI run could not tell it from one. These now answer 503 `unavailable`,
  as do a dropped connection and a database out of connections: "coffre
  cannot reach what it depends on right now; try again in a moment". They
  are logged as `a dependency did not answer`, or, for a statement that
  gave up on a lock or its own bound, `a statement gave up waiting`: under
  a busy database an outage, and otherwise a transaction held too long,
  which a bug may be. On Node, the vault's own outage crosses its socket
  as one (503, with Postgres's code), where it was a 500 with the code
  dropped.
- **An append holds the log's head for two round trips fewer.** Every
  write, and every proxied call whose cache has lapsed, appends its entry
  under the audit log's head, the one lock every append in the instance
  waits for. Having locked the head, the app's append locked it again,
  then read the clock, then the last entry, before it wrote: three round
  trips through Hyperdrive, with every other append, the vault's
  included, queued behind them. It now reads all three in one statement.
  A token exchange runs 14 statements, not 16, and a proxied call whose
  cache lapsed 11, not 13, of which 7 hold the head, not 9.
- **Setup says when a Hyperdrive config is below what the database leaves
  it.** `coffre setup` keeps a connection limit set lower than its own
  share of `max_connections`, and said nothing about it. Equisafe's two
  configs sat at 5 on a database with room for 20 each: Hyperdrive's
  minimum, split into shards of one connection each, so one slow call
  stopped every other on its shard. The docs' commands now make configs
  at 20, the share for a `max_connections` of 100. Setup now prints each
  such config's limit beside the one it would give it, and the `wrangler
  hyperdrive update … --origin-connection-limit=<n>` that raises it
  ([deploy.md](docs/deploy.md)).
- **The Kubernetes proof waits for a fresh token instead of sending a spent
  one.** A long-running `coffre serve` sidecar re-proves at 90% of its
  session's life, and the kubelet's next projected token, written at 80%,
  sometimes lands after that. `kubernetes()` used to send the token it had
  exchanged already, get `replayed`, and only then wait, logging "was
  spent already, by an earlier start" at the renewals the kubelet was late
  for. Now it waits for the file to change before sending (up to 10
  minutes, the old session serving until its token expires), and logs
  `coffre: the token at <path> is already used; waiting for the next one`
  once per wait: a late kubelet still shows that line, but no failed
  exchange. A restarted process still waits the same way when the exchange
  says `replayed`.
- **The app key rotates.** `APP_KEY` (`auditChainKey`) signs the app's log
  entries and every row that signs someone in; changing it used to sign
  everyone out, break every service token and binding, leave the log's
  older entries unverifiable and the audit anchor red. Now the new key
  becomes `auditChainKey` and the old one moves to the new
  `previousAuditChainKeys`, as the vault's `previousKeks` do for the vault
  key ([deploy.md](docs/deploy.md#rotating-the-app-key)). The first start
  under the new key signs every signed row again under it, 100 rows a step,
  each step a `key.reseal` entry, and then writes `key.rotate`; it signs
  browser and CLI sessions out, and keeps service and personal tokens,
  handles, workloads' sessions (one awaiting approval included), trust
  bindings, enrollment codes, linked accounts and MCP connections; a CLI
  login approved but not yet taken is used up. Before `key.rotate`, it
  seals the audit anchor again under the new key. Until it is done, the
  app answers 503 `rotating`, each request taking it a step further, and a
  Node process steps it to the end as it starts: wait on `/readyz` after
  the deploy.
  - **From the first step, the old key writes nothing**: an append under a
    key the log moved on from is refused, so an instance still running the
    old key during the deploy has its writes refused. From `key.rotate`, it
    vouches for no row, and verifies only the log's entries from before the
    first step: an entry under it after is a finding. A key replaced cannot
    come back: a start under it answers 503 `app_key`, and so does an
    instance still writing under the old one. A start under a key the log
    does not know, a lost key, serves as before, everyone signed out. A key
    replaced by hand before this release is rotated from once listed,
    which brings back the tokens that swap ended: leave out one replaced
    because it leaked. Keep the old key configured, and
    escrowed: a walk of the whole log needs it.
  - **Rotations are crash-safe and race-free**: each step is one
    transaction under the log's head, and goes on from the step before,
    whichever process or isolate takes it.
  - `coffre verify keys` says when the app key pasted is one the app
    replaced (`GET /api/audit/keys` lists them, `app.previous`).
  - **Upgrading: one migration**, `0018_rotate_app_key`, which only grants
    the app's login to update an enrollment code's MAC. Upgrade first, and
    rotate in a later deploy: an instance of an earlier release would go on
    writing under the old key during the rotation.

## 0.13.0 (2026-10-24)

- **Upgrading to 0.13.0, in short.** No migration: the database, the
  settings and the API are as in 0.12.1, so `coffre migrate` has nothing to
  apply, and there is nothing to roll back beyond what 0.12 already was.
  Audit watching is now a plugin, `auditWatch`, and a deployment that
  upgrades without adding it keeps working, but `/readyz` answers
  `{ok, watched: false}` and tampering is only found when someone verifies
  the log. To add it: on Workers, an `ANCHOR` Durable Object binding, an
  `anchor` migration in `app/wrangler.jsonc` and the `CoffreAnchor` export;
  on Node, `fileAnchor` on a persistent volume. Expect one re-anchor alert
  on the first beat. Changing `APP_KEY` leaves `/readyz` red until the
  anchor's store is emptied (details below).

- **The audit watch: what the heartbeat verified is kept outside the
  database.** Whoever can write the database, without any key, could
  change the heartbeat rows that said how far the log was verified, and
  so where the next beat's walk began. Two gaps were left: a row of the
  app's relabelled as the vault's, with the tail chained again behind it,
  kept `/readyz` green for up to a beat; and a finding standing for more
  than 1,000 beats (about three and a half days) sent every walk back to
  the first entry, red for good. Each beat now walks the log from what it
  last verified to the prefix the vault just signed, and keeps that in an
  anchor outside the database, a Durable Object on Workers or a file on
  Node, written by compare-and-set and never moved back. `/readyz` reads
  the anchor and one entry of the log: a constant cost however long the
  log, and green on nothing the vault has not signed and the app walked.
  A finding stands in the anchor, and each beat rechecks only the entry it
  names until that entry verifies again; each finding and its clearing is
  logged (`audit.finding`, `audit.finding_cleared`). The heartbeat rows'
  resume cursor, its 1,000-beat lookback and its clearing rule are gone,
  and with them both gaps; old `audit.heartbeat` rows verify as any other
  entry.
  - **It is a plugin, `auditWatch`**, which `coffre init` writes into both
    kinds of deployment. Without it, `/readyz` says the database is
    migrated, with `watched: false`, the scheduled run still has the vault
    checkpoint the log and warns once that nothing watches it, and the log
    is verified when someone asks (`coffre verify log`, the audit page). A
    deployment that upgrades without adding the plugin is in that state.
  - **An empty store re-anchors by itself**: the first beat after the
    watch is added, or after its store was lost, walks the log whole,
    10,000 entries a beat and more between beats, with `/readyz` green
    meanwhile, then logs `audit.reanchor` and sends one alert on the
    workloads' alert channel (`signin({ workloads: { alert } })`). A cut
    made before the store emptied cannot be seen.
  - **Entries lost for good**, a tail cut with no backup, are accepted by
    an Owner of the whole instance, as a person: `coffre audit accept-loss
    <from> <to>` (`POST /api/audit/loss`), a range that holds the entry
    the finding names. The acceptance is logged with the finding, which
    stays in the log, and alerted.
  - **Upgrading: no database migration; each deployment adds the watch.**
    On Workers, in `app/wrangler.jsonc`, the binding `{ "name": "ANCHOR",
    "class_name": "CoffreAnchor" }` beside `GATES` and the migration `{
    "tag": "anchor", "new_sqlite_classes": ["CoffreAnchor"] }` after its
    own; in `app/src/server.ts`, `export const CoffreAnchor =
    coffre.Anchor;`; in `app/src/coffre.ts`, `ANCHOR: AnchorNamespace` in
    `Env` and `plugins: [auditWatch({ anchor: durableAnchor(env.ANCHOR)
    })]`. On Node, `plugins: [auditWatch({ anchor:
    fileAnchor(env('AUDIT_ANCHOR')) })]`, `AUDIT_ANCHOR` a path on a
    persistent volume only the server writes, one file per server process
    ([deploy.md](docs/deploy.md#the-audit-watch) says what several want).
    The first beat finds the store empty and re-anchors: expect its one
    alert.
  - **Changing `APP_KEY` makes the anchor unreadable**, as nothing re-seals
    it yet: `/readyz` is red and the beat leaves it alone until its store
    is emptied, which re-anchors. The record names the key it is sealed
    under, for the rotation that will.

## 0.12.1 (2026-10-24)

- **Upgrading to 0.12.1, in short.** No migration: the database, the
  settings and the API are as in 0.12.0, so `coffre migrate` has nothing to
  apply. To send a body past 16 MiB through the proxy, upgrade the instance
  and every `coffre serve` sidecar (and any app on the SDK) together, and
  size the sidecar's memory for the uploads in flight (below). Upgrade one
  side only and nothing breaks: bodies keep going, read whole, up to 16 MiB.

- **Workload uploads past 16 MiB stream: a 50 MB Yousign document goes
  through the proxy.** A request body that declares its SHA-256 in a
  `Content-Digest` (RFC 9530, `sha-256=:<base64>:`) and says its length now
  streams through coffre to the upstream, up to 95 MiB, instead of being
  read whole and refused past 16 MiB. coffre hashes it as it passes and
  holds back its last bytes until the digest matches: a body with other
  bytes, short of its length or past it, is cut off before the end, so the
  upstream never gets a complete request, and the app gets a 400 saying
  why. The proof signs the digest as the body's line and names the header
  in `hdr`. 95 MiB (99,614,720 bytes) sits under the 100 MB (decimal)
  Cloudflare takes in one request on Free and Pro zones, so a body near it
  gets coffre's 413, which names the way through, and not the zone's.
  - **`coffre serve` holds each body in memory while it hashes it**: the
    chunks it came in, one copy, never written to disk, up to 95 MiB per
    upload in flight. Size the sidecar's memory limit for the uploads you
    run at once: the process's own (about 120 MB at peak, idle) plus up to
    95 MiB for each. A 55 MB document raised its peak by 70 MB. Past 95
    MiB, the sidecar answers 413 before sending anything. An app's own
    `Content-Digest` of another algorithm keeps its member, with the
    sidecar's `sha-256` beside it.
  - **The SDK** (`@coffre/client/workload`) declares the digest of every
    body it reads whole, and streams a body that declares its own. A
    `Content-Digest` the app set stays as it is; one with no `sha-256`
    member declares nothing, and its body is read whole, up to 16 MiB.
  - **Old and new pair either way.** A 0.12.1 SDK or sidecar against a
    0.12.0 instance signs the same line (the digest of the bytes), so its
    requests still go, read whole up to 16 MiB, and the upstream gets the
    `Content-Digest` header too. A 0.12.0 sidecar against 0.12.1 sends no
    digest, and keeps the 16 MiB.
  - **What it leaves:** an upstream that acts on part of a request before
    it ends, a multipart part stored as soon as it is read, may act on a
    body whose digest then fails. That takes a request carrying other bytes
    than its proof signed.
  - **Fixed:** `coffre serve` dropped an S3 upload's `content-length`, so
    coffre read the upload whole, and refused one past 16 MiB. It sends it
    now, and the upload streams.
  - On Workers, a refused stream shows in the logs as an uncaught
    exception (workerd reports the subrequest body's error), beside the
    400 the app gets.

## 0.12.0 (2026-10-24)

- **Upgrading to 0.12, in short.** Run `coffre migrate` before you deploy,
  as always: it applies `0017_capped_alerts` (`0016_capped_alerts` on
  SQLite), which only adds a table, so the release before keeps serving on
  it until the deploy. Then:
  - **The GitHub Action needs `keys:`** (breaking, below). Add the keys the
    job's later steps use, by name or prefix, to every `erwinkn/coffre/action`
    step: `keys: DATABASE_URL STRIPE_*`. Without it, or with a bare `*`, the
    step fails before reading anything. To hand every key to one process,
    run it with `coffre run <environment> -- <cmd>` instead. Bump the
    Action's tag to `v0.12.0` together: it runs `@coffre/cli` at its own
    version, and `--format github` needs `--keys`.
  - **Old and new pair either way.** A workflow still on `action@v0.11.0`
    runs the 0.11 CLI, which sends no `keys` and exports the whole
    environment as before, against a 0.12 instance. The 0.12 Action against
    a 0.11 instance exports only the keys named, but the older instance
    opens, and its audit log records, every key of the environment.
  - Nothing else is breaking. The audit heartbeat and the unknown-key alert
    change no setting, API or config, and no data needs reissuing.

- **Breaking: the GitHub Action exports only the keys the workflow names.**
  Workflows must add `keys:`. What the Action writes to `GITHUB_ENV`, every
  later step of the job sees, so anyone who could only write `market/prod`
  could add `BASH_ENV`, `LD_PRELOAD` or a build tool's hook there and run
  their code with the job's access; the denylist of such names (0.10.2) can
  never be complete. Now the workflow, which its reviewers read, says what
  the job gets, as `env: FOO: ${{ secrets.FOO }}` does:
  `keys: DATABASE_URL STRIPE_*`, names or prefixes ending in `*`, separated
  by spaces or lines. A step without `keys`, or with a bare `*`, stops
  before anything is read, and points to `coffre run <environment> --
  <cmd>` to hand every key to one process. A name none of the environments
  holds, or a prefix that starts none of their keys, stops it too, before
  anything is read. The denylist stays, behind it: a key on it is refused
  before anything is read, named or found by a prefix. Several environments
  and `require-complete` work as before; an environment `keys` names none
  of is not read, and only named keys clash.
- **`coffre export --keys`, and `keys` on `POST /api/reveals`.** The Action
  runs `coffre export --format github --keys …`, which `--format github`
  now requires. `--keys` takes the same names and prefixes, in every format,
  but not with `--watch`, nor for a person's placeholders, which the
  credential proxy plans for whole environments: the CLI lists the environments first, which opens no
  value, then asks the instance for those keys only (`{"path":
  "market/prod", "keys": ["DATABASE_URL", "STRIPE_KEY"]}`). The other keys
  are never opened, logged or counted against the vault's bulk limit. An
  instance before this one reads the whole environment whatever it is
  asked: the CLI exports only the keys named, and says that the audit log
  has every one.

- **No heartbeat's finding is lost to two beats at once, or to someone
  who writes the database.** On several instances, each beating on its own
  timer, a beat whose walk began before another found the chain broken,
  and committed after it, said the chain verified: readiness went green,
  with the tamper found and still there, until the next beat. And whoever
  writes the database could hide the beat that found it, or change it
  only while the next beat read where to resume, and send every walk
  after it past the tamper. Now a beat reads where to resume in the
  snapshot it walks in, only from a beat its MAC vouches for, and no
  further than where the walk of any broken beat after that began, until
  a clean beat walked over the entry it found, after it found it, and
  found it whole (each beat records where its walk began and the newest
  entry its snapshot held); so
  every beat row past that point is one the walk reads, and one hidden or
  changed there is found. Readiness runs that same walk, to the head: it
  is red as soon as a finding stands, while the finder is hidden, and
  when the prefix the newest checkpoint signed is no longer there. Its
  cost is a beat's walk: the entries since the newest beat's began. One
  way round it stays open for a beat interval, until the vault's next
  checkpoint refuses: the finder made one of the vault's rows, which the
  app's walk checks by hash only
  ([formal.md](docs/formal.md#the-audit-chain-and-the-tunnel)). A beat
  whose database was out of reach no longer sends the next walk back to
  the first entry. No database migration. Found by `formal/Audit.tla`,
  which now gives the attacker any beat row to hide, forge or put back at
  any step.
- **Readiness reads the newest beat and the newest checkpoint in one
  snapshot.** Read apart, a beat that stopped short committing between
  them could answer green on rows that were never green together. Found
  by `formal/Audit.tla`.
- **`pnpm formal` checks the audit chain and the tunnel too**: heartbeats,
  checkpoints and readiness against someone who writes the database, and
  how long a revoked handle's tunnel session lives, which is the recheck
  interval and a check's deadline, 70 seconds by default, not the minute
  the docs said ([formal.md](docs/formal.md#the-audit-chain-and-the-tunnel)).

- **A rotated cluster key alerts.** A workload's sign-in whose token is
  signed by a key its binding's uploaded keys lack (`unknown_key`, most
  often a cluster that rotated its service-account key) now writes one
  `workload.alert { kind: 'unknown_key' }` and hands it to the
  deployment's `workloads.alert`, as limits already do. It names the
  service, the issuer and the token's `kid` (its first 64 characters, any
  character a kid does not use shown as `?`), and the commands that upload
  the keys again (`kubectl get --raw /openid/v1/jwks`, then `coffre trust
  <service> --issuer … --replace-keys --jwks-file … --apply`). Anyone may
  send such a token, so a service alerts once an hour at most, whatever
  the `kid`: one conditional write on the new `capped_alerts` table decides,
  across isolates and processes, and a refusal capped out costs one read,
  opens no transaction and never takes the audit log's head. Only a service with a
  binding on the token's issuer gets that far; any other refusal stays a
  line in the process log, which now names the issuer and `kid` of an
  unknown key too. `/api/auth/oidc` alerts the same for a bearer binding
  that carries its keys. Run `coffre migrate` before you deploy: it applies
  `0017_capped_alerts` (`0016_capped_alerts` on SQLite), which only adds a
  table.

## 0.11.0 (2026-10-24)

- **Upgrading to 0.11, in short.** Run `coffre migrate` before you deploy,
  as always: it applies `0015_workload_access` and `0016_spent_tokens`, both
  additive, so the release before keeps serving on them until the deploy.
  Then:
  - **Service accounts need an Owner to issue their sensitive reads (R32).**
    A token or trust binding reads a sensitive value only where an Owner
    covering the place issued it; any other is refused `not_owner_issued`
    (403) for those values. Tokens and bindings made before 0.11 are sealed
    on first use, by their issuer's standing then; `coffre migrate` lists
    them. Reissue any whose issuer is not an Owner of the project (or has
    left) and whose CI reads sensitive values.
  - **A tunnel with no `hosts` dials only an address** (breaking, below):
    add `hosts: ['db.acme.example']` to each `postgres(…)` tunnel that
    names its database by host.
  - **Do not roll back to 0.10.x once credentials are sealed.** The seal
    and the owner-issued rule are 0.11's; 0.10 does not read them, so the
    tokens and bindings 0.11 issued or sealed reach nothing there. Deploy
    0.11 once you mean to keep it.
  - A Workers deployment adds the `GATES` and `SOCKETS` Durable Objects by
    hand, as `coffre init` writes them (below); until it does, neither
    key-bound sessions nor the tunnel run, and nothing else changes.

- **The credential proxy takes a workload** ([workload-access.md](docs/design/workload-access.md),
  its PR 1d). A key-bound session uses credentials, signers and tunnels
  through `/use` as a handle does, with its proof in place of a
  placeholder. The proof signs the request whole. Only the headers it
  signs go upstream, and a query, header or body changed on the way is
  refused. A sigv4 upload is bound by the payload hash it declares, so it
  still streams; `UNSIGNED-PAYLOAD` with a body needs a binding that says
  `unsignedUploads`. The session is checked on every request before the
  value cache, so a revocation or a freeze stops the next request, warm
  or not, and an open tunnel within 15 seconds. A narrowed session is held
  to its constraints on the URL coffre sends. `POST /use` signs and
  presigns for a workload that reaches one environment. Credentials and
  signers take a `limit` (`{ perMinute, perDay }`, or a function of the
  service): past it, 429 with `Retry-After`, and one `workload.alert` per
  workload, credential and window, which also goes to the deployment's
  `workloads.alert`. A tunnel's group now stops once its last good check
  is a bound old, even if no check ran since. No database migration.
- **Workloads sign in with a key** ([workload-access.md](docs/design/workload-access.md),
  its PR 1a). `POST /api/auth/workload` takes a platform's ID token, with a
  DPoP proof of a key the workload made in memory, and answers a session
  bound to that key: `coffre_wl_…`, sent as `Authorization: DPoP` with a
  fresh proof on every request, worthless without the key. A token whose
  audience names the key (GitHub, Google, Fly) is never spent; a
  Kubernetes, GitLab or custom one is spent once, and its session ends at
  its own `exp`; an Entra managed identity's, which its platform repeats
  for hours, is never spent and may be hours old. Every request is checked
  in one statement, never from a cache: revocation, a freeze, the binding
  removed or the member removed end a session at its next request.
  `POST /api/auth/workload/renew` moves its expiry on, on the database's
  clock, and a late renewal revives nothing; `POST /api/auth/logout` ends
  it. A session reaches the routes a service token does, but issues no
  credential and changes no one's access, in every mode (403
  `workload_cannot_issue`). Trust bindings take a `policy`; every profile
  but today's five always carries one, and a binding's `reads` name keys
  by path and name (`{ "market/prod": ["STRIPE_WEBHOOK_SECRET"] }`),
  stored by ID, a sensitive one only if an Owner of its project makes it
  (R32). `workloads: { useOnly: true }` issues and takes no service token
  and answers 410 at `/api/auth/oidc`; `noReads: true` lets no binding list
  `reads`. `coffre init` does not write `useOnly` yet: it goes back once
  conformance and the Action sign services in with a key. A deployment
  needs a workload gate before any session is accepted; without one the
  routes answer 503. No database migration.
- **A Cloudflare binding's call opens values** (the workload-access design,
  section 9.2). A plugin's `use` for a caller from `bindingRoute` answered
  500: the vault takes only a credential's ID, and the call has none. Its
  vault entries now name no credential; its app entries name the binding,
  `binding:<id>`, and the two join on the request's ID. A binding unbound
  while its call was in flight releases nothing, as a revoked session's
  read does not.
- **Breaking: a tunnel with no `hosts` dials only an address.** Its URL is
  a secret's value, whose host anyone who writes the environment picks,
  and a name may resolve to a private address, which the lexical check
  never saw. `postgres('DATABASE_URL', { hosts: ['db.acme.example'] })`
  dials that name; without `hosts`, a URL that names its host by name is
  refused with 403, and one that names a public address still works. A
  tunnel through a network binding (`connect`) names its hosts already.
  `insecureUpstreams` lifts this, as it lifts the rest. Private addresses
  are now refused however they are written: `localhost.`, `LOCALHOST`,
  `127.0.0.1.`, `[::ffff:a00:1]`, `[::7f00:1]`, `[64:ff9b::a00:1]`; and
  so are site-local `fec0::/10`, `198.18.0.0/15`, and a 6to4 address
  (`2002::/16`) of a private IPv4.
- **`coffre export --format github` refuses keys a later step would take
  code from**: `PATH`, `BASH_ENV`, `LD_PRELOAD`, `DYLD_*`,
  `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `NODE_PATH`, npm's and pnpm's
  `NPM_CONFIG_SCRIPT_SHELL` and `PNPM_CONFIG_NODE_OPTIONS`, `PYTHONPATH`,
  `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `MAVEN_OPTS`, `MAVEN_ARGS`,
  `GOCACHEPROG`, `CC`, `CFLAGS`, `RUSTC_WRAPPER`, `CARGO_TARGET_*_RUNNER`
  and the rest of `RUNS_CODE` (`packages/cli/src/github-env.ts`), in any
  case, with an error that names the key and nothing written. Before,
  only `NODE_OPTIONS`. Credentials beside them (`NPM_CONFIG_OTP`,
  `CARGO_REGISTRIES_*_TOKEN`, LaunchDarkly's `LD_SDK_KEY`) and `ENV`, which
  only an interactive shell reads, still export. The list is a tripwire,
  not a boundary: it blocks the common tools' one-variable hijacks, not
  every one there is, and anyone who may write keys to an environment the
  Action exports is trusted with code execution in that job.
- **Spent ID tokens are forgotten two hours after.** `consumed_tokens`,
  which refuses a CI run's token sent twice, only grew. The scheduled
  beat now removes up to 5,000 records a beat of tokens spent over two
  hours ago: an exchange refuses a token issued over an hour ago, so
  those guard nothing. The runtime login still deletes no row itself: it
  calls `prune_consumed_tokens`, which migration 0016 adds and which
  deletes only those (Postgres; SQLite deletes them directly).
- **Fixes found by property tests** (docs/property-tests.md):
  - The credential proxy refuses a path with a dot segment hidden behind a
    `;` parameter, `/use/market/dev/api/..;/admin`, which Tomcat and Spring
    read as a step up past the credential's base path and its `paths`, and
    one encoded twice (`%252e%252e`), which a server behind another decodes
    twice.
  - A host spelled with a trailing dot, `localhost.`, is private, as
    `localhost` is: an upstream or a tunnel's database URL naming it needs
    `insecureUpstreams`, as any other loopback address does.
  - A restored version comes back no looser than it was, nor than its
    value was made since: the plain version of a value made a secret or
    sensitive in place comes back so, whatever was written after, and only
    whoever reads it as such may restore it. A Contributor, who reads no
    secret, could read one by restoring its plain version (R24). The vault
    holds the same rule, and refuses an app's request to bring back a value
    made sensitive as anything looser (R16).
  - A value holding a lone UTF-16 surrogate is refused with 400, rather than
    stored as U+FFFD, a value other than the one written.
  - A fork's key with neither a value nor a reference, written around the
    app, reads as no value rather than serve its parent's; a fork chain written
    around the app past three parents counts the same keys whichever
    environment is listed first.
  - `GET /api/me`, which every page asks, reads only the projects its caller
    reaches, rather than every environment and secret of the instance.
  - A redirect to an upstream `Location` that does not parse is a 502, not a 500;
    SASLprep judges right-to-left passwords as Postgres does; the listener
    no longer leaves a tunnel half-closed for 30 seconds when the app
    closes while the database still sends; a trust binding naming a
    `__proto__` claim is refused, rather than stored without it; an
    envelope claiming another version of its vault key, and a sealed
    sign-in value spelled another way, no longer open.
- **A workload uses what its binding does not list, and moves none of it**
  ([workload-access.md](docs/design/workload-access.md#61-the-rule), its
  PR 1c). Every vault call now says what kind of credential it came in on,
  a person's, a bearer's or a workload's key-bound session, and the vault
  refuses a workload's call that comes with no scope. A workload is handed
  back a secret or a sensitive value only where its scope's `reads` list
  the key, by ID, at the place where the value is held: a reference's
  source, a fork's parent, never the place the request names, so a rename
  onto a listed name reads nothing new. Anything else the vault refuses
  `use_only`, whatever the purpose but the proxy's use, a fork's copy
  included, and so does making a reference to it. The app answers the same
  first: a read of a whole environment leaves those keys out and names
  them in `useOnly`, a read of one is refused 403 `use_only`, a dry run
  never says whether a guess at one is right, and a fork or a reference
  that would copy or point at one is refused before anything is made.
  `scopeWithReads` puts a binding's `reads` on a session's scope, for the
  exchange to call. No session of this kind is issued yet, and bearer
  tokens and people are unchanged. The vault, deployed first, takes an
  older app's calls, which say no kind, as before. The Lean model holds
  the vault to it (`no_laundering`). No database migration.
- **A credential revoked while its read is under way gets nothing.** A
  read checked its token, handle or MCP connection, then asked the vault,
  which decides on the member and is only told the credential: a token
  revoked between the two, or a member removed and added again, still got
  the values. Now, once the vault has released them, the app reads the
  credential and the member's generation again before it answers, under
  the head when it commits entries of its own, and answers 401. A reveal
  runs one more statement. Found by `formal/Credentials.tla`.
- **An Owner demoted while issuing a service account a token gives it no
  sensitive value (R32).** A token, a trust binding, a binding's new keys
  and an older release's credential sealed at its first use are weighed
  on the vault's answer about their issuer, asked again when issuing
  starts, and committed only while it is still theirs; demoted meanwhile,
  the request answers 409 `access_changed`, and asked again it is weighed
  as they are now; removed and admitted again since the request came in,
  401. Before, a token was weighed on the answer the request's
  authentication got, which nothing fenced: a demotion is no change to
  the policy. Found by `formal/Issuing.tla`.
- **`pnpm formal` checks three more protocols**: a CI run's ID token
  exchanged for a credential and every way one ends, who may hand a
  service account sensitive values, and the vault's bulk limit, each
  failing as it must without each of the code's protections
  ([formal.md](docs/formal.md#credentials-issuing-and-the-bulk-limit)).
- **Each workload's gate**
  ([workload-access.md](docs/design/workload-access.md#52-the-gate-replay-nonces-live-counters),
  its PR 1b): what holds a key-bound session's proofs to one use and
  counts its limits. Its nonces are epochs of 2 minutes, a proof is taken
  under the current or the previous one and only once, and a gate that
  restarts starts a new epoch, so no proof it took passes again. Past
  1,000 requests a second it answers `overloaded`; past a limit, when to
  retry, and whether this is the window's first refusal. On Node the
  gates live in the server's process; on Workers, in a Durable Object per
  workload, whose counts over an hour or more outlive an eviction. `coffre init`
  writes the `GATES` binding and its migration, `gates: env.GATES` and
  `export const CoffreGates = coffre.Gates`; an older Workers deployment
  adds them by hand
  ([deploy.md](docs/deploy.md#key-bound-sessions-and-their-gate)). Nothing
  asks a gate yet: the sessions that do come with that design's PR 1a. No
  database migration.
- **Workload access's foundation**
  ([workload-access.md](docs/design/workload-access.md), its PR 0). A
  database migration, `0015_workload_access`, which only adds: a
  workload's key-bound sessions' columns on `credentials` and their kind,
  a `policy` on trust bindings, and an `enrollments` table, so the release
  before serves on it unchanged. `/api/auth/oidc` now takes only bindings
  of today's five profiles with no policy, as every binding of before is.
  Google's, Fly's, Vercel's and Entra's issuers now force their own
  profiles, as github.com's and gitlab.com's do: a new `custom` binding
  can no longer name them, and the binding they force signs in at
  `/api/auth/workload` once that is served. Bindings already made are
  unchanged.
  The design's routes and the `coffre enroll`, `approve`, `freeze`,
  `unfreeze` and `serve` commands are declared, and answer that they are
  not built yet until the changes that serve them land.
- **Workload access's platform proofs** (its PR 2). An `aws` proof, a
  `GetCallerIdentity` a role signs with the session's key and this
  instance under its signature, which coffre sends only to STS's
  commercial hosts, exactly as signed, and matches to a binding by the
  role's account and unique ID: a role made again under its name matches
  nothing, and an account's root, a federated user and an IAM user are
  refused. The `kubernetes`, `gcp`, `azure`, `fly` and `vercel` profiles
  check their bindings' IDs and issuers in their platforms' shapes. A
  Vercel function picks its token's audience, so `vercel` now names the
  session's key in it, as `gcp` and `fly` do, and its binding names no
  audience. `coffre trust` makes each of them: `--aws`, `--kubernetes` and
  `--gcp` (looking up IDs with the aws, kubectl and gcloud you are signed
  in to), `--azure`, `--fly`, `--vercel`, `--enrollment` and
  `--cloudflare`, `--workload` for a CI run's, and their policy's flags,
  `--reads`, `--source` (CIDRs; with `--gitlab`, push, web and schedule
  still name pipeline sources), `--session-hours`, `--unsigned-uploads`,
  `--replicas`, `--minted-by`, `--approve`, `--session-days`,
  `--overlap-minutes` and `--on-contention`. They sign in once
  `/api/auth/workload` is served. No database migration.
- **Workloads sign in key-bound, from any platform**
  ([workloads.md](docs/workloads.md), workload access's PR 5). In Node,
  Bun and Deno, `@coffre/client/workload` proves who the app is with its
  platform's own proof (`kubernetes()`, `aws()`, `gcp()`, `azure()`,
  `fly()`, `vercel()`, `github()`, `oidc()`, `enrollment()`), holds a
  session bound to a key that never leaves memory, and signs every request
  it sends through coffre: `coffre.fetch` for any SDK that takes one,
  `credential(name)`, `fromCoffre` for the AWS SDK, and
  `@coffre/client/workload/postgres` for node-postgres through the tunnel.
  Any other language runs `coffre serve`, a sidecar that forwards what the
  app sends its local listener, signed, or `coffre --service <name> run
  --proof <proof>`, which does the same for one command and falls back to
  the bearer exchange on an instance without key-bound sessions.
- **The database tunnel runs on Workers.** `coffre run market/dev -- psql
  "$DATABASE_URL"` now works against a Workers deployment as it does on
  Node: each run's connections to a database go to a Durable Object of
  their own, named by a digest of the path and the handle, which admits
  them as Node does (one `credential.use`, the handle checked again before
  login, a recheck a minute logged as a use, a revoked handle's sessions
  ended within it) and runs the same tunnel, cancel requests included.
  `coffre init` writes the object's wiring: the `SOCKETS` binding and its
  migration, `sockets: env.SOCKETS`, and `coffre.upgrade(request, env)` in
  the server entry, idle until the deployment adds the credential proxy
  with a tunnel. An older deployment adds them by hand
  ([deploy.md](docs/deploy.md#the-credential-proxys-database-tunnel)).
  No database migration.
- **The tunnel paces itself, and keeps an idle connection alive.** A
  Workers WebSocket has no back-pressure, so the CLI and the object count
  back what they took, and neither sends more than 1 MiB the other has
  not counted: a large `SELECT *` read by a slow client, or a large `COPY
  FROM STDIN`, waits in the database's socket, not in the object's
  memory, and a client that ignores the window is ended. One run holds 32
  connections to a database at most there; the CLI says why once when
  coffre refuses one. The CLI's listener sends a count every 30 seconds,
  so a psql left at its prompt outlives Cloudflare's 100-second idle
  timeout, and a ping, so a connection whose network went away ends
  within a minute rather than hang. A Workers coffre refuses an older CLI
  with 426: update it. Node is unchanged, and the 0.11 CLI still works
  against an older or Node one.
- **A tunnel through a private network**, for a database with no public
  address: `postgres('REPLICA_URL', { hosts: ['10.0.1.5'], connect:
  env.REPLICA_NET })`, a Workers VPC Network binding to a Cloudflare
  Tunnel in that network. With `connect`, and only then, `hosts` is
  required and may name private addresses, and the URL says
  `sslmode=disable`, since the binding carries plaintext TCP only; a URL
  that asks for TLS is refused. A binding the Worker lacks fails the
  configuration, never a direct dial. Without `connect`, nothing changes.
- **A cancel request reaches only a session of the same tunnel.** It
  already needed the same handle; now its key must also name a session of
  the tunnel it came on, so it is sent the way that tunnel dials.
- **The tunnel, tested on Cloudflare (#285).** A cancel request through a
  network binding reaches the database (it sent nothing), and an app that
  stops reading for a while keeps its connection (the listener ended it
  after 30 to 60 seconds). A pool's 32 connections opened at once are all
  let in: an object admits them in order, a few at a time, each with 45
  seconds from its turn, where a burst of 17 or more ran out of its 15
  together. A long result no longer fills the object: some 4.7 GB from the
  database outgrew its 128 MB. `coffre run` leaves a terminal's Ctrl-C to
  its command and keeps its tunnels for it, where it ended with them,
  passes a SIGTERM on, and revokes its handle when its command ends. A
  SIGINT sent to the run alone, with no terminal, is left to the command
  too: stop a run with SIGTERM.

- **Only an Owner hands a service account sensitive values** (R32).
  Anyone may set up a service account where the instance lets them, and
  give it what they hold; a service reads sensitive values. So a Developer
  of `backend/dev`, who does not read its sensitive `STRIPE_SECRET_KEY`,
  could give an account read there, issue it a token, and read the key
  with it; or issue one while nothing was sensitive, and read a key marked
  sensitive later. Now each place of a service token's or trust binding's
  scope says whether it reads the sensitive values there: only where whoever
  issued it is an Owner of the project, of the whole instance or by a
  grant or role scoped to it, on no credential's scope. The vault refuses
  anything else (`not_owner_issued`). The project is the value's own: a
  reference's source's, whose value it lends, so a token an Owner of
  `billing` issued reads no sensitive value of `backend` through a
  reference in `billing/dev`; a fork's inherited value, its parent's.
  A read of a whole environment that holds one is refused whole, naming
  the keys, rather than run without them; a dry run of a write does not
  compare them. Everything else reads as before.
  - Issuing a token or binding, or replacing a binding's keys, says which
    places of its scope hold a sensitive value it will not read: `withheld`
    in the API, a line in `coffre tokens issue` and `coffre trust`, a
    warning in the token, binding and key dialogs.
  - A binding that replaces another, inheriting its scope or with new keys,
    reads them only where both did.
  - **Tokens and bindings issued before this release** are sealed once,
    on the first credential this version checks, as 0.4's scopes were:
    each reads them where whoever issued it is an Owner of the project
    then, logged as `token.seal`: their standing when this version first
    checks a credential, project by project, not when they issued it. CI
    an Owner set up keeps working; one a Developer set up reads every other
    value, and an Owner issues it a new token or binding to read the
    sensitive ones; so does one whose issuer has left, or is no Owner of
    the project by then. `coffre migrate` lists them first, by account and
    issuer: check each issuer is an Owner of the projects their CI reads
    sensitive values in before you deploy.
  No database migration. Roll back across this release and the tokens and
  bindings it issued or sealed reach nothing until it is back: deploy it
  once you mean to keep it.

- **Protection shows where you are, and changes there.** A protected
  environment's tag is amber now, on its card and in its page's header,
  where it was grey, and changed only from the card's menu. For whoever
  may change it, the tag is the button that does, on both, behind the
  same confirmation as before: "Protect…" on an environment that is not,
  for those who manage the project's environments, and "Protected" on one
  that is, for an Owner of the project, who alone takes it off (below). Everyone else sees the tag
  alone, whose note says what it means and who changes it. The card's ⋯
  menu no longer offers Protect or Unprotect, which the tag does. Who may
  protect or unprotect is still decided by the server.
- **An Owner of a project makes a sensitive value a secret in place, and
  unprotects its environments** (R30). An Owner can already read any
  value of their project, through a service account they give read
  (break-glass), so typing a sensitive value again to loosen it, or
  asking an Owner of the whole instance to unprotect prod, protected
  nothing from them. Now an Owner of the project, by a grant on it or an
  instance role scoped to it, or of the whole instance, as a person on
  no credential's scope:
  - makes a sensitive value a secret with its value kept: `coffre mark
    market/prod/DATABASE_URL secret` (`coffre mark market/prod secret`
    for every one of its own), or the row's Who sees it › Secret, behind
    a confirmation. The vault opens the key and wraps it again without
    the sensitive binding, and refuses it to anyone else (`not_allowed`),
    so the value never reaches the app or its caller by it. It is a new
    version: the older ones stay sensitive, and a rollback to one brings
    it back sensitive. A reference to it reads it as a secret, live.
    Logged as its own entry, `secret.loosen`, saying both levels, as is a
    refusal of one (`not_owner`);
  - takes an environment's protection off (`coffre environments
    unprotect`, or the Protected tag), as far as their project protects
    it. Recovering a policy the vault cannot read is still the whole
    instance's Owner's.
  Everyone else types the value again, and leaves prod protected, as
  before. Secret to plain is unchanged: a reveal, then a write. The
  secrets listing says `loosenable` and `unprotectable`, the projects
  listing `unprotectable` per environment, as the server decides them:
  the UI reads those, not role names. An Owner of every `prod`, scoped to
  environments by slug, owns no project, and does neither. No migration.

## 0.10.2 (2026-10-20)

- **The bulk limit counts different keys, not reads.** It counted every
  key the vault released, repeats included, so a tool that exports the
  same 40 keys on every command tripped it on the 26th run within 15
  minutes, and locked out everyone signed in as that person. A key read
  again exposes nothing new: it now counts once in the window, whatever
  its version. The limit is still 1000 keys per principal in any 15
  minutes, counted exactly under the reader's row, in the statement that
  already read the decision: no statement more. On Postgres, a full
  window of 1000 different keys costs about 4 ms to count, as before; a
  read of 40 keys repeated adds about 0.1 ms to every later read in the
  window ([architecture.md](docs/architecture.md), "The bulk limit").
  No migration and no change to the configuration, the refusal or its
  entries.

- **A proxied credential can leave through the deployment's egress.** An
  upstream that lets in only the addresses it knows, as Schuman's API
  does, cannot allowlist a Worker's `fetch`, which leaves from
  Cloudflare's shared addresses. A credential now takes `egress`, anything
  with a `fetch(url, init)` method, which its requests go through instead:
  a Workers VPC Service binding to a Cloudflare Tunnel that exits from a
  fixed address, a service binding, or an object of the deployment's own,
  on Node too.

  ```ts
  schumann: { upstream: 'https://dev.api.europ.schuman.io', inject: header('x-api-key', '{SCHUMANN_API_KEY}'), egress: env.SCHUMAN_EGRESS },
  ```

  Every check before it is as it was, and so is everything done to the
  answer. The VPC Service must be made for the upstream's own host:
  coffre cannot read where a binding goes. A binding missing from
  `wrangler.jsonc`, `undefined` in `env`, fails the configuration, and
  the request never leaves through the global `fetch` in its place. The
  log's `credential.use` entry says `egress: true`. Redirects and streamed
  uploads through a real VPC Service are untested
  ([design](docs/design/credential-proxy.md), section 5, "Egress").

- **A reveal runs 11 statements, not 30.** Each is a round trip through
  Hyperdrive. A vault decision locks its member's row, then takes the
  log's head in the one statement that reads everything it decides on,
  and appends its entries and moves the head in one more. `access` is one
  statement. The app reads the newest
  policy change with the credential, and a fork's parents in one query.

  | Request, warm | App | Vault | Total |
  |---|---|---|---|
  | `POST /api/reveals` (one key, an environment, a service's export) | 5 → 3 | 25 → 8 | 30 → 11 |
  | `GET /api/me` | 3 → 2 | 7 → 2 | 10 → 4 |

  The locks and their order are unchanged. The head is taken `SKIP
  LOCKED`, so the statement never waits and reads as of the lock; when
  another holds it, the vault waits in a statement of its own and reads
  again ([single-database.md](docs/design/single-database.md), rule 4).
  `request-cost.test.ts` now holds each of these requests to its exact
  number of statements and vault calls.

## 0.10.1 (2026-10-19)

- **The audit log is verified from its last checkpoint, not its first
  entry.** Opening the audit page re-verified every entry, in the app and
  in the vault: on a Workers deployment with 7,000 entries that was 1.2
  seconds of CPU a visit, past the Free plan's limit, and it grew with
  the log. Each checkpoint now keeps, beside its signature, the tally of
  the prefix it signs: the vault's keys in order, the key batches under
  way, who is a member and what they hold. Each heartbeat says how far
  the app verified its own entries. The page's check, and each
  checkpoint, start from those and read what was written since: on
  Node, a log of 100,000 entries went from 6 seconds of CPU to some 10
  milliseconds. Nothing before is read again: its hash, which the newest
  checkpoint signed, pins it, and one count of the log's index finds an
  entry cut. An entry edited in place, its hash left as it was, is what
  that leaves, so each checkpoint also rehashes 100 entries of the past in
  turn, in laps, some 6 ms of a cold Worker's CPU: found within two laps
  at most, a lap about 6 hours for a log of 7,000 entries and 3½ days for
  100,000, where the hourly recomputation from the first entry found it
  within the hour but needed a second of CPU at 10,000 entries. `coffre
  verify log` finds it at once; run it on a schedule to narrow that.

  `coffre verify log`, and the page's new **Verify whole log**, still walk
  the log from its first entry, 10,000 entries a request, and check each
  checkpoint's tally against the log before it
  (`GET /api/audit/verification?from=start`, then each `next`).

  After the upgrade, the first checkpoints sign the log again from its
  first entry, 10,000 entries a beat, since those of 0.10.0 kept no
  tally: on a log longer than that, `/readyz` stays red for a beat or a
  few until they catch up, and the page says how many entries are left.
  A beat that walks 10,000 entries takes about a second of CPU: on the
  Workers Free plan it is cut off and the catch-up never ends. Even
  caught up, a beat and the audit page's check each take some 10 ms of
  CPU on Node, an estimated 25 on a Worker, more than the Free plan's 10,
  as 0.10.0's beat already did: run 0.10.1 on a paid plan, and move there
  before upgrading. No migration.

  `/readyz` now also turns red when the beat's own walk of the chain finds
  it broken, or cannot run: an entry in the app's name the app did not
  write, which the vault cannot tell, used to show only on the audit
  page.
- **Reveals cost less CPU.** On Workers' Free plan an invocation has 10 ms
  of CPU, and a reveal now runs 27 statements instead of 33, and reads
  the same rows however large the log grows: with a vault key in memory,
  the vault decides a read once, under the log's head, where it decided
  twice; it reads the newest policy and access entries alone, not 32 at
  a time; and a Worker no longer works out the database schema's
  configuration at every call. On local workerd a warm one-key reveal
  went from 33 to 25 ms of CPU, everything the runtime does for it
  included. `pnpm bench:workers` and `pnpm bench:node` measure each hot
  path, cold and warm.
- **Every request's hot queries are built once.** The caller check, the
  credential lookup, the vault's reads of a member, their grants and the
  newest entries, and the log's head are built once per process or
  isolate and run with new values each time (`prepared` in `@coffre/db`),
  rather than rebuilt by Drizzle at every call. A request on a session or
  a token no longer reads the newest policy change twice: only a token
  of 0.4 still waiting for its scope needs the second read. The vault's
  local key is imported once, not for every key it opens.
- **Closed dialogs cost the server nothing.** A dialog's root is drawn
  on the server only when it is open, and mounted once the page has
  hydrated; the HTML is the same.
- **Pages with times render with less CPU.** A relative time ("3 hours
  ago") made a new formatter each time it was shown; it reuses one. The
  audit page's render costs about a quarter less.
- **The audit page arrives with its verification.** The page rendered
  its table, then asked for the log's check from the browser and showed
  "Verifying…" until it came. The check from the last checkpoint now runs
  while the page renders, and the page is sent whole, badge included. A
  check that cannot run still leaves the page up, with the badge saying
  so and offering a retry. The page costs the check's CPU, on Node about
  11 ms warm at 7,000 entries; **Verify whole log** is unchanged, still
  asked for and walked in stretches.

## 0.10.0 (2026-10-19)

- **Protected environments, and roles an Owner edits.** Each role now
  holds permissions in two columns: in an environment that is not
  protected, and in one that is. A person in a protected environment
  holds the second; a service account holds the first everywhere, so CI
  reads what it read. As they ship, Viewer, Developer and Maintainer
  drop read in a protected environment and keep use; Developer and
  Maintainer keep write too:

  ```sh
  coffre environments protect market/prod   # whoever manages market's environments
  coffre roles developer                     # secret.read  yes  protected: no
  ```

  Ada, a Developer of `market`, reads `market/dev` as before; in
  `market/prod` her reveal is refused and `coffre run` gives her app
  placeholders. No environment is protected until someone says so, so
  nobody's access changes on upgrade. Only an Owner of the whole
  instance unprotects one (`coffre environments unprotect`), and a fork
  of a protected environment, a copy or one that inherits, is protected
  before its row exists. Forking one takes reading it there, as any fork
  takes reading its source: as they ship, an Owner forks a protected
  prod, and a Maintainer or a Developer does not. Settings › Roles, or
  `coffre roles set`, `reset` and `remove`, lets an Owner of the whole
  instance edit any role but Owner and the instance's Member, and make
  custom ones (`release-manager`), granted as any is and deleted once no
  grant names one; each change is previewed in words first ("Widens
  secret.read for 6 people on 4 protected environments") and logged as
  `policy.change`. The vault keeps roles and protection in its newest
  `policy.change` entry, under its MAC, and decides on them. A token, a
  service token or a trust binding keeps what its roles held when it was
  issued, and no more than its issuer held there, in either column, so
  neither a role nor its issuer, widened later, widens a credential, and
  a role narrowed narrows each at once. A personal token,
  service token or trust binding issued before 0.10 holds its roles as
  they ship, whatever an Owner makes of them. Deploy the vault Worker
  with the app, or first: a 0.9 vault refuses every request on a
  credential 0.10 issued (500), where a 0.9 app reads it as reaching
  nothing. A request whose roles or protected environments changed while
  it ran answers 409 `policy_changed`, "try again", as does a role's edit
  confirmed with an impact preview (`?revision=`) another change
  overtook. A reference takes its value and nature (plain, secret,
  sensitive) from its source, live, and its permissions from where it
  lives: whoever reads `market/dev` reads dev's reference into a protected
  `market/prod`, and a reference to a sensitive key is use-only there.
  Making or repointing one takes reading its source, and using it where
  it is sensitive; a reference to a plain value is plain, no longer
  secret. A value is made live only by whoever could have read it, or
  typed it: restoring an old version, or unarchiving a key, takes reading
  a secret there, using a sensitive one, writing alone for a plain one. A
  writer who cannot read prod no longer rolls a secret back there; they
  type a new value.
  The API: `GET /api/roles`, `PUT` and `DELETE /api/roles/<role>`
  and `/api/instance-roles/<role>` (`?dryRun=1` for the impact), and
  `PATCH /api/projects/<p>/<e>` with `{ "protected": true }`. Migration
  `0014_custom_roles` widens the grants' role check. See
  docs/design/roles.md.
- **Breaking: each key says who sees its value, and `people` and
  `expose` are gone.** One setting per key, three levels:
  - `plain`: anyone who lists the environment, as 0.9's plain values.
  - `secret`, the default: people whose role reads secrets.
  - `sensitive`: no person, Owners included. Their apps get a
    placeholder and use it through the credential proxy; service
    accounts (CI tokens, GitHub and Kubernetes OIDC) read the value.

  `coffre set market/prod/STRIPE_SECRET_KEY --sensitive` writes one;
  `coffre mark market/prod/DATABASE_URL sensitive` makes a key stricter,
  its value kept, and `coffre mark market/prod sensitive` every value of
  the environment's own. A reference reads its source's level, and a
  fork's inherited key its parent's: `mark` leaves them, naming each
  looser one and where to mark it. Making a key looser takes its value
  written again (`coffre set … --secret`), never a flip. A write that
  says nothing keeps a sensitive key sensitive. The vault decides it: a
  sensitive version's data key is wrapped as sensitive, so a person's
  reveal, `coffre get`, MCP or Vault KV read of it is refused
  (`sensitive`), whatever their role, and a person's read of a whole
  environment leaves its sensitive values out, naming them. The page has one control per key; the API
  takes `{ "value": "…", "sensitivity": "sensitive" }` and `{
  "sensitivity": "sensitive" }`. The vault's `people` option, the
  proxy's `expose` and a credential's `identifiers` are removed: a
  deployment that still sets one fails at startup, saying what to do.
  Migration `0012_sensitive_values` adds `secret_versions.sensitive`.

  **Moving a deployment that ran `people: 'stand-ins'`.** 0.10 has no
  switch for every key: from its deploy until the keys are marked, a
  person reads what their role reads, as 0.9 did without `people`. Make
  that window seconds, and check it:

  1. On 0.9, `coffre migrate` as usual (0012 only adds a column).
  2. Delete `people` from the vault's configuration and `expose` from
     `credentialProxy`, and deploy 0.10 from a pipeline whose next step,
     as a service account with write on the environments, marks
     sensitive what no person should read, leaving secret what they read
     (what `expose` listed):

     ```sh
     coffre mark backend/prod sensitive        # prod's own values, kept as they are
     coffre mark backend/staging sensitive
     coffre mark backend/local/LEMONWAY_API_KEY sensitive   # the real keys a local environment holds
     coffre mark backend/local/YOUSIGN_API_KEY sensitive
     ```

     `mark` names the references and inherited keys it leaves: mark
     each where it is held (the shared environment, the parent), or
     write the environment's own value over it.
  3. Check every key's level: `coffre list backend/prod` says
     `sensitive` on each no person should read, references and
     inherited keys included.
  4. Check that no person read a value in between: `coffre audit
     backend/prod --json` lists each `secret.read`, by whom and when; any
     the deploy window holds is a value to rotate.

  For no window at all, close coffre to people at its ingress for the
  deploy: an Owner the deployment names reads everything, and no grant
  narrows them. Let only the pipeline's service account through (its
  token, or its runner's address), deploy, mark, check, and open it
  again. See docs/design/credential-proxy.md, section 2.
- **`secret.use`, and the Contributor role.** Reading a value hands it
  back; using it does not: a person's app holds a placeholder, which the
  credential proxy fills in. Every role that reads now uses too, so
  nobody's access changed. A Contributor uses and writes, and reads
  nothing: they list the keys, set values and run their app on
  placeholders, and a reveal answers 403. `coffre grant market
  bob@acme.example --role contributor --env prod`. What a person gets is
  the narrower of their role and the key: a sensitive key is only ever
  used. Migration `0013_contributor_role` widens the grants' role check.
- **`<env>@me` is a partial overlay, its owner's to edit whatever their
  role, and its own values may be plain, secret or sensitive.** Each key
  its owner sets is theirs, over the environment's key or beside it, and
  every other key falls through to the environment's, live. A value of
  their own takes any level, `coffre set --plain|--secret|--sensitive` or
  the page's picker, as anywhere: they read their plain and secret ones,
  a plain one listed inline, and a sensitive one, theirs or not, is used
  and never read, its owner included. Nobody else sees any of them, plain
  ones included, Owners and the project's Maintainers included: they see
  key names, and may delete it. A write that says nothing takes the level
  of the value the key reads now: the environment's for an override, so
  `coffre set market/dev@me/DATABASE_URL` over a sensitive
  `DATABASE_URL` is sensitive (say `--secret` for a local database your
  app is given), then your own; `coffre set` says so, and each key of
  `PATCH /secrets/…`'s answer now names its `sensitivity` beside its
  `version`. A plain value there is in the clear in
  the database, as every plain value is: the vault binds a personal
  config's secrets and sensitive values to their owner, and the app's
  rule alone holds a plain one to them. `coffre run`'s values of a
  person's own under `generate` are written as the secrets the plan says;
  a CLI before 0.10 writes them sensitive, and its app goes without them.
  On 0.9 with `people: 'stand-ins'`, the page's Override and Edit opened
  nothing on a value its person could not read, an Owner's
  `backend/local@me` included: each edit read the value first, and gave
  up, unsaid, when the read was refused. An edit now opens empty, to
  replace the value, wherever it is not read: a sensitive value, a
  parent's its person does not read, or a read that failed, which the row
  says. A fork's removed key now reads `removed here: not inherited from
  dev`, or `dev dropped it too`, in `coffre list` and on the page.
- **Breaking: stand-ins are now called placeholders.** What a person's
  app holds in place of a key, the opaque handle or a shaped one, is a
  placeholder in the docs, the pages, `coffre run`'s output
  (`coffre: placeholders for market/dev: …`) and the log, whose
  `credential.use` entries now say `placeholder: { claims }`. A
  credential's `standIn` is now `placeholder`: `standIn: jwt({ claims })`
  becomes `placeholder: jwt({ claims })`. One that still has `standIn`
  fails at typecheck and at startup, saying to rename it.

## 0.9.0 (2026-10-18)

- **Breaking: the credential proxy's `baseUrl` is gone, for a stable
  URL.** `ANY /use/<credential>/<path>` (`https://secrets.acme.example/use/schumann`)
  is the same for every environment, fork and `@me`: its environment is
  the one the handle `coffre run` made is for. So the app's own
  configuration names it, and `coffre run` sets no `*_BASE_URL` any more.
  A deployment's `credentialProxy` that still has `baseUrl` fails at
  typecheck and at startup, naming the URL to use. To move, delete each
  `baseUrl` and point the app's local configuration at the stable URL:
  where the app had `SCHUMANN_BASE_URL` from `coffre run`, map `local` to
  `https://<instance>/use/schumann`. `/use/<project>/<env>/<credential>/…`
  still works, and is the URL for a run of several environments, which
  the stable URL refuses with a 409 naming each. Handles now keep the
  environments they were made for (migration `0010_handle_places`, a
  nullable column); one made by 0.8 works on its environments' URLs, and
  on the stable URL once `coffre run` makes a new one. See
  docs/design/credential-proxy.md, section 4.
- **Signing through the handle.** `credentialProxy({ signers: { 'dfns-key':
  privateKey('DFNS_PRIVATE_KEY') } })` keeps a private key in coffre, and
  the app asks for each signature with `credential('dfns-key').sign(message)`
  (`@coffre/client/credential`): what Node's `crypto.sign(undefined,
  message, key)` gives, base64url, for an Ed25519, P-256 or RSA key in
  PKCS#8. Each signature is one use in the log. `DFNS_PRIVATE_KEY` no
  longer needs `expose`: DFNS's `AsymmetricKeySigner` gives way to a
  15-line signer that calls coffre (docs/design/credential-proxy.md,
  section 5).
- **Shaped stand-ins.** A credential's `standIn` gives its client a
  stand-in in the shape it checks: `jwt({ claims })`, a JWT of the real
  token's named claims whose last part is the handle, or `prefix('sk_test_')`.
  DFNS's SDK reads its organization from its token's claims, so
  `DFNS_AUTH_TOKEN` no longer needs `expose`: `dfns: { upstream:
  'https://api.dfns.io', inject: header('authorization', 'Bearer
  {DFNS_AUTH_TOKEN}'), standIn: jwt({ claims: ['https://custom/app_metadata'] }) }`.
  For a header or query rule that carries one key (docs/design/credential-proxy.md,
  section 5).
- **Plain values.** A key can be marked not secret: an account's id, a
  region. `coffre set market/dev/TWILIO_SID AC0123… --plain` (a plain value
  may be an argument), `{ "value": "…", "plain": true }` in the API, or the
  page's Plain toggle. Whoever lists the environment sees it, the page
  inline; `coffre list` prints it. Reading it is no secret read: it is
  served from the clear copy its version keeps, with no vault call, so a
  person gets it under stand-ins, and `coffre run` and `export` pass it
  through as it is, the credential proxy unredacted. Any write that does
  not say `plain` is a secret, so writing over it without `--plain` makes
  it secret again. Making a stored secret plain is a reveal and a plain
  write, which stand-ins refuse a person: type the value again. A personal
  config holds none. Migration `0011_plain_values` adds
  `secret_versions.plaintext`.
- **Values of a person's own.** `credentialProxy({ generate: {
  'backend/local': 'all' } })`: a person's use of `backend/local` reads
  their personal config of it, and `coffre run` (and `export`) makes them
  their own value of each key their app would go without that a recipe
  made (`coffre set … --generate`), once, by that recipe, into
  `backend/local@me`: their app's local encryption, sealing and webhook
  keys, stable across runs. Two runs at once converge on one value. A
  personal config now exposes what the environment it configures exposes.
- **Deprecated: a credential's `identifiers`.** Mark the key plain instead:
  `coffre set <env>/TWILIO_SID <sid> --plain`. `identifiers` still works,
  and goes in a later release.

## 0.8.2 (2026-10-18)

- **`@coffre/client` runs on Node 20 and 22.** Its `engines` said Node 24,
  which only the workspace's sources need; the published client is plain
  JavaScript built for Node 20, with no dependency, so it now declares
  `>=20`. From CommonJS, `require('@coffre/client')` works where Node
  loads ES modules that way (20.19, 22.12 and later), `await import(…)`
  anywhere. The packed consumer test loads and calls it on Node 20, 22
  and 24, by `import` and by `require`.

## 0.8.1 (2026-10-18)

- **Postgres through the credential proxy, on Node.** `credentialProxy({
  tunnels: { db: postgres('DATABASE_URL') } })`: `coffre run` starts a
  local listener for the app, whose `DATABASE_URL` is that listener with
  the handle as its password. coffre logs in to the real database with the
  real password (SCRAM), then pipes bytes: queries, COPY, LISTEN/NOTIFY,
  cancel requests. A revoked handle or a lost grant ends open sessions
  within a minute. The deployment's HTTP server hands its upgrades to
  `coffre.upgrade(…)`. The database must take the role only from coffre's
  address (docs/design/credential-proxy.md, section 6).
- **S3 through the proxy, further.** Uploads the SDK signs with their hash
  and length stream through, up to 5 GiB, past the 16 MiB a proxied body
  was held to. `credential('s3').presign(path)` gets a presigned GET that
  coffre signs with the real key pair: the upstream's own URL, for at most
  an hour, each logged as a use.

## 0.8.0 (2026-10-18)

- **Stand-ins: people's apps use secrets without holding them.** A vault
  option, `people: 'stand-ins'`, makes every read a person asks for, on
  any credential of theirs (a session, a personal token, MCP), refused if
  it would hand values back. Service accounts read values as before, so CI
  and production are unchanged. A person's `coffre run` gets stand-ins
  instead, through an optional plugin, the credential proxy
  (`credentialProxy({ credentials, expose })` from
  `@coffre/server/plugins/credential-proxy`, and `routes/use.$.ts`):
  - Each credential is a bundle of an environment's keys, one upstream,
    and a rule for where its keys go: `header('x-api-key', '{KEY}')`,
    `query(…)` or `basic(…)`.
  - `coffre run` makes one handle (`coffre_use_…`) for the run, which the
    app holds where each key was. Its base URL points at the proxy, which
    puts the real key in the request and sends it to the credential's
    upstream, and only there.
  - An unchanged client works with no change. `credential('schumann').fetch(path)`
    (`@coffre/client/credential`) serves new code.
  - A handle reaches only the proxy, lasts 12 hours, and is revoked as a
    token is. Its keys are opened once per credential a minute, each
    opening logged as a read to `use`.
  - `expose` names the few values an exact environment's apps hold as
    they are, best an environment of local-only fakes.
  - S3 and other AWS-signed APIs through `sigv4(…)`: the SDK signs with
    the handle, at the proxy's endpoint (`AWS_ENDPOINT_URL_S3`,
    `forcePathStyle`), and coffre signs again with the real key pair.
    aws-chunked uploads and presigned URLs are refused, for now.
  - The design, its decisions and what comes next (the Postgres tunnel)
    are in docs/design/credential-proxy.md. Migration
    `0009_handles` widens a check, and nothing else.

## 0.7.0 (2026-10-17)

- **Read coffre from tools that speak Vault.** An optional plugin, added in
  the deployment's configuration (`plugins: [vaultKv()]` from
  `@coffre/server/plugins/vault-kv`) and one route file (`routes/v1.$.ts`),
  answers as a read-only HashiCorp Vault KV v2 store:
  - `secret/data/market/prod` is that environment's values, and
    `secret/data/market/prod/KEY` one of them.
  - External Secrets Operator, the `vault` CLI, vals and Terraform read
    with a coffre token as their Vault token.
  - Each read is the API's own reveal, as the token's holder, and is
    logged as one.
  - Writes, listing, versions and response wrapping are refused, and 404
    only ever means the place is not there, so that ESO never deletes a
    target over anything else.
  - Setup for each tool is in docs/vault.md.
- **ESO signs in to the Vault adapter with Kubernetes auth**, so a cluster
  stores no coffre token.
  - `PUT /v1/auth/kubernetes/login { role, jwt }` trades the service
    account's token through the coffre service account's trust bindings,
    keys uploaded included, as `coffre login --service` would, for a
    credential of five minutes.
  - `revoke-self` ends that credential.
  - `jwt` auth and vault-action's `method: jwt` work the same way.
  - Setup is in docs/vault.md.
- **Plugins.** `createCoffre({ plugins: […] })` takes optional
  integrations. A plugin answers paths of its own and reaches coffre only
  through the API, as whoever a request's token names, so it can do no
  more than that token's holder could with the CLI
  (docs/design/plugins.md).
- **`GET /api/me` says when its credential ends**, as `credentialExpiresAt`.
  That covers a session, a service or personal token, or one a trust
  binding issued, and is null behind Cloudflare Access.

- **Ask whether an environment changed without reading it.** `coffre version
  market/prod`, or `GET /api/projects/market/prod/version`, answers a
  version of what a read of it would open: a value written, a key added,
  archived or renamed, a reference's source rotated and, in a fork,
  anything it inherits change it; filing a key in a folder does not. It
  reads no value, so it is not logged, and it takes what a read takes:
  read on the environment, and on each parent a fork inherits from.
- **`coffre export --output-file` and `--watch`.** `--output-file .env`
  writes the export to a 0600 file, whole or not at all. `--watch` keeps it
  current: it asks the version every minute (`--interval`, from 5s to
  24h), reads only once it changed, rewrites the file only when its
  contents change, then runs `--on-change '<command>'`. A failed round
  keeps the file and waits twice as long each time, up to 15 minutes or
  the interval, whichever is longer.
- **A read of a whole environment answers its version.** `POST
  /api/reveals` of `market/prod` answers the `version` of exactly what it
  opened (null for one key's): a poller keeps that one, not the version it
  asked before reading, since a change undone in between brings that back.
- **`coffre run --keep-existing`.** `coffre run` still sets every key of the
  environments it names over a variable of the same name in your shell. With
  `--keep-existing`, a variable already set there keeps its value, an empty one
  included, and coffre's is dropped. One line on stderr names the keys kept,
  never a value. Every value is still read, and every read is audited.
- **Forks that inherit.** An environment can now be made as a fork of
  another in its project that keeps reading its parent's keys, live:
  `coffre fork market/prod prod-eu --inherit`, "Inheriting from prod" in
  Add environment, or MCP's `create_environment` with `inherits`. A key
  added to or rotated in prod reaches prod-eu on its next read. prod-eu
  overrides a key by writing it, adds keys of its own, and removes one it
  should not have (`coffre remove`, or Remove in the key's menu).
  `coffre reset`, or Reset to prod, goes back to the parent's value and
  keeps the override, which `--undo` serves again. Forks of forks are
  allowed, at most three parents up.
- **A fork lends nothing.** Reading what a fork inherits takes read on the
  parent, by your own grants: a reader of prod-eu alone gets a 403 that
  names the inherited keys. Each inherited value is logged as a read of
  prod's key, "in market/prod-eu", in both environments' logs; one read
  through prod's own reference stays in its source's log and prod's. To
  lend values across that line, use references, as before.
- **The environment page shows where each key comes from.** "from prod"
  for an inherited key, "overrides prod" for an override, flagged "prod
  changed since" when prod wrote a newer value, and removed keys struck
  through, with Restore. `coffre list` says the same, and
  `GET /secrets/...` gives each key a `parent` and the environment its
  `parents`.
- **Renames and missing keys follow.** Renaming a key in a parent renames
  the forks' overrides and removals of it. Missing keys compare what each
  environment resolves to: a fork misses nothing it inherits, and a parent
  misses no key that only its forks hold.
- **Guards.** An environment that live forks inherit from cannot be
  archived, and one any fork names cannot be deleted; a fork is restored
  only while its parent is live. A reference to a key a fork only
  inherits is refused, naming the parent's key to refer to instead.
- **Migration** `0004_environment_parents` adds `environments.parent_id`,
  nullable, with a same-project foreign key on Postgres. It only adds:
  the previous release runs on it. Rolled back to 0.6 after forks exist, a
  fork reads as holding only its own keys, so archive forks before rolling
  back.
- **Personal configs.** `market/dev@me` is your own fork of dev: its keys,
  live, with values of your own over them, which only you read, and only
  while you read dev. Nobody else reads them, an instance Owner included,
  and the vault binds each value to its owner, so a row changed in the
  database opens nothing. `coffre set market/dev@me/DATABASE_URL` makes
  yours, or "My own dev" on dev's page. A read of `market/dev@me` is dev's
  while you have none, so a committed `coffre run market/dev@me -- pnpm
  dev` serves everyone, CI included; a write never falls back. A Viewer of
  dev may keep one.
- **What others see of them.** Lists show you yours, as `dev@me`, and
  nobody else's, and missing keys compare none. Whoever manages a
  project's environments lists its personal configs (`coffre personal
  market`, or Personal configs on its Environments tab): whose, of what, and their
  key names, never a value; they and the owner may delete one, erasing its
  values. They are archived, restored and deleted with their parent, hold
  no reference, and take no grant.
- **Migration** `0007_personal_configs` adds `environments.owner`, with its
  check and a unique index. It only adds. A release before 0.7 cannot open
  a personal config's values: their data keys are bound to the owner.
- **Personal tokens: hand a script or an agent part of what you hold, for
  an afternoon.** `coffre tokens issue --label cursor-agent --scope
  market/dev=developer --expires-in 4h` makes a bearer token, `coffre_pat_…`,
  that acts as you on what its scope names: never more than you held when
  you made it, and at each request no more than you hold then. Losing a
  grant narrows it, gaining one widens nothing, and being removed ends it.
  It lasts a minute to a week, an hour unless told. Its scope names only
  roles that manage no access (viewer, developer, maintainer, auditor), and
  it reaches your secrets and places alone: it makes no token, session,
  connected app, grant, member, service account or trust binding, changes
  no setting, approves no sign-in, deletes nothing for good, and runs no
  instance, whatever your role. Every entry it writes, the vault's too,
  names it, and the audit log shows "ada via token 'cursor-agent'", in the
  pages and in `coffre audit`. `coffre tokens` lists yours and `coffre
  tokens revoke <id>` ends one; so does `coffre logout` signed in with it.
  Your account's Sessions tab lists them, with Revoke; a person's page lists
  theirs for whoever runs the instance, and their removal revokes them
  ([docs/design/personal-tokens.md](docs/design/personal-tokens.md)).
- **A credential with a scope holds nothing of the instance's.** A request
  on one runs no instance, reads no whole log, makes no project and sets up
  no service account under the instance's setting. Service accounts' tokens
  could not before either; an Owner's personal token cannot now.
- **API.** `GET`, `POST` and `DELETE /api/members/user:<email>/tokens` list,
  make and revoke personal tokens; a personal token's `POST` takes `label`,
  `expiresInMinutes` and `scope`, all three required. `GET /api/me` says
  which personal token a request came in on (`personalToken`), and each
  audit entry made with one carries it (`token`). The member report lists a
  person's (`personalTokens`), and `ServiceTokenRow` is now `TokenRow`.
- **Schema.** `0005_personal_tokens` widens `credentials`' kind check to
  `personal` and indexes the log's `token.create` entries by the credential
  they made. Nothing is removed or tightened, and 0.6 refuses a personal
  token during the deploy, as no token of its own.
- **Trust bindings for issuers coffre cannot reach.** A binding may carry its
  issuer's public keys, uploaded with it, instead of fetching them:
  `coffre trust <service> --issuer <iss> --jwks-file <path> --claim …`, or
  Keys under "Other issuer" in the Trust dialog. coffre then fetches nothing,
  so the issuer is any string its tokens name, matched exactly: a private
  Kubernetes cluster's, at a `.local` name or a private address, works.
  The keys are checked when uploaded (RS256 of 2048 bits or more, ES256 on
  P-256, public keys only), and are under the binding's MAC. Such a binding
  refuses a token that lives over an hour, `exp` minus `iat` (`too_long`),
  besides the age limit and single use every token keeps.
- **Replacing keys when the issuer rotates them.** `coffre trust <service>
  --issuer <iss> --replace-keys --jwks-file <path>`, or Replace keys under a
  binding's Claims, gives every binding of the service on the issuer the
  new keys. Each is replaced by one the same but for them, and the
  credentials the old one issued end. A set that holds the old key and the
  new takes tokens signed by either while the issuer moves over.
- **Nested claims.** A binding names a claim nested in the token by its
  path, as `kubernetes.io.serviceaccount.uid`, beside `sub` and the rest.
  It matches only when the path reads one way in the token.
- **Kubernetes.** [docs/kubernetes.md](docs/kubernetes.md) shows how a pod
  signs in with a projected service-account token for coffre's audience:
  the cluster's keys from `kubectl get --raw /openid/v1/jwks`, the account
  pinned by its UID, and a rotation.
- **Migration** `0006_uploaded_keys` adds `jwks` to `service_bindings`, a
  nullable column the app inserts and never updates. 0.6 keeps serving on
  it.
- **A read of many secrets is one audit entry.** `coffre run`, `coffre export`,
  reading an environment in the UI or through MCP, a fork and a reference's
  read used to write one `secret.read` per key: a machine polling an
  environment of a hundred keys every 15 minutes wrote a hundred entries a
  poll. The vault now writes one per place read, listing each secret and the
  version it released (`secrets`), committed before any value leaves as
  before; values read through references into another environment get an
  entry for that environment. The Audit page says "ran market/prod: 37
  secrets" and opens to each, and `coffre audit` adds "(37 secrets)". The
  bulk limit still counts keys, and the offboarding report still lists each
  value a member read. Entries written before stay as they are and verify as
  they did. No migration. A page of `GET /api/audit`, and each batch of a
  verification, holds at most 8 MiB of what its entries list, so a page of
  large reads can come back short of its `limit`: the response's new `more`
  says whether to page back with `before`.
- **Ask the log about one key.** `coffre audit market/prod/DATABASE_URL`, and
  `GET /api/audit?path=market/prod/DATABASE_URL`, list who read or changed
  it, reads of several that listed it included. The route took only a project
  or an environment, though the MCP tool `read_audit_log` offered a secret.
- **Generate a secret's value from the CLI, and regenerate it in one step.**
  `coffre set market/prod/SESSION_SECRET --generate bytes:32:hex` makes the
  value in the CLI and writes it; nobody sees it, the terminal included. A
  recipe is what the page's Generate dialog offers: `bytes:<1-256>`, as
  base62 unless `:hex`, `:base64` or `:base64url` follows; `aes:256` or
  `aes:128`; and key pairs, `ecdsa:` or `ecdh:` with `p-256`, `p-384` or
  `p-521`, whose public key is written beside the private key in the same
  write (`JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`, or `--public-key`).
- **A generated value keeps its recipe.** The write sends it with the value,
  and the server keeps it with the version, so `coffre regenerate
  market/prod/SESSION_SECRET`, or Regenerate in the row's menu, rotates the
  secret: a new value, made the same way, where you are, never shown. A key
  pair's either key regenerates both, and only if neither changed since it
  was listed (409 otherwise). In a fork, regenerating a key it inherits
  overrides it there; the parent keeps its value. A value typed or pasted over a generated
  one clears its recipe; a rollback brings it back with the value. The row
  marks a generated key; its version history, `coffre history` and `coffre
  list` name each recipe; and `coffre list` says `coffre regenerate` for a generated value due
  for rotation.
- **One recipe, in `@coffre/core/recipe`.** The page's generator, the CLI and
  the server's checks share it: the server makes no value, and refuses a
  recipe it cannot read, or a key pair not written whole (400).
- **Schema.** `0008_recipes` adds `recipe`, `pair_id` and `pair_half` to
  `secret_versions`, nullable, and extends the versions' erase-only trigger
  to them. 0.6 serves on it unchanged; its writes store no recipe.

## 0.6.2 (2026-10-17)

- **Copy a secret without revealing it.** A hidden value now has a Copy button
  beside Reveal, for whoever may reveal it. It reads the value the way Reveal
  does, with the same audit entry, and puts it on the clipboard exactly as
  stored, newlines included, without showing it: the mask stays. If the copy
  fails, the button turns red and the row says why.
- **A revealed value breaks only at its newlines.** A long token no longer wraps
  mid-word; it scrolls sideways inside the value, so the row and its buttons
  keep their place. A multi-line value, a PEM for one, shows one line per line.
- **Missing keys stay out of the way once handled.** The panel shows only
  while something is missing: with every difference dismissed it is gone,
  "Nothing missing" included. The Dismissed list and its Restore buttons are
  gone too; `coffre missing --dismissed` lists the dismissed keys, and
  `coffre missing restore` brings them back. Dismiss and Dismiss all now act
  at once: the keys leave the list before the server answers, a toast offers
  Undo, and a refusal puts the keys back with the reason beneath them.
- **Unsaved changes are saved at the foot of the table.** The floating bar at
  the bottom of the page is now part of the secrets table: under its last
  row, and stuck to the bottom of the window while the table runs past it.
  Cmd/Ctrl+Enter and Escape are as they were.
- **Add secret, and Add folder beside it.** New secret is now Add secret, a
  split button whose chevron opens a menu with Add folder: name a folder and
  pick the secrets to file in it. A folder exists while it holds a secret, so
  it is made with its first ones. A refused move, from here or from Move to
  folder…, now says why beneath its row; it only turned the row red.
- **Switching environments takes one round trip.** The page asked for an
  environment's secrets, then for its references and missing keys. It now asks
  all three at once wherever the project list already says you read the
  environment; elsewhere it still asks the secrets first, so a refused visit
  is logged once. The missing-keys read lost a query per sibling environment,
  and the secrets list a second query for folders.
- **A new service account's page opens without an error.** Its row in the
  list asked how it signs in before the server had made it, and its page
  then showed that "Not found" until a refresh. The row now waits for the
  account to be made, and making it reads again whatever was asked of it.
- **A user's or service account's tabs switch at once.** The page reads
  what every tab shows but the activity log when it opens, and each tab
  takes it from there, refreshing it behind the page, rather than waiting
  for the network. The activity log loads in place.
- **The audit page has one control for what it lists: Actions, Everything
  or Denials.** It replaces "All events / Denials only", whose two halves
  both showed as selected, and the "Show detail" switch. Everything adds
  sign-ins, tokens and the vault's key operations; Denials lists every
  refusal, those included, so a refused sign-in now shows there.
- **Shorter copy.** The Verified badge says "Audit log verified by the app
  and vault keys, last signature at …". A deployment-declared Owner's lock
  says "Owner defined by the deployment configuration." The service
  account page drops the explanations under its sign-in sections, its
  access and its activity, and an empty activity log, a person's too, says
  "Nothing yet".
- **The header's project and environment are each one button.** The project's
  tile, slug and chevron open the list of projects; the environment's slug and
  chevron open its siblings. The project's own page, all its environments, is
  the project ticked in its list, archived or not. Each entry in the two lists
  starts loading its page as it is pointed at or reached by keyboard.
- **Projects and environments go by their slug alone.** Pages, lists, the
  command palette and the CLI show the slug; New project, Add environment,
  Rename and a project's Settings no longer ask for a display name. Renaming
  is now giving a new slug, which changes the path: `coffre projects rename
  market --slug marketplace`. The API's `name` stays, for older CLIs:
  optional on `PUT /projects/:project` and `PUT /projects/:project/:environment`,
  where it defaults to the slug, still taken by `PATCH`, and still returned,
  though nothing shows it. The CLI still takes `--name` and says it ignores
  it; `rename` with `--name` alone changes nothing. The MCP tools
  `create_project` and `create_environment` ignore a `name`, so a call
  approved before the upgrade still matches its approval. The column goes in
  a later release.

## 0.6.1 (2026-10-16)

- **Shift+Enter types a line break in a secret's value.** A value could only
  become multi-line by pasting one. In the value field of a new or edited
  secret, Shift+Enter now inserts a line break at the caret, over any
  selection, and the field turns into the focused textarea, its caret after
  it. Enter alone, Cmd/Ctrl+Enter (save) and Escape are as they were.
- **A deployment-declared Owner shows a plain Owner tag.** People no
  longer adds "· set by deployment" after it. To another Owner, the tag
  is greyed, with the hint "Set by deployment" on hover or tap, or by keyboard;
  everyone else sees the normal tag. The Users table also keeps which
  Owners the deployment names, so their row shows the lock in place of the
  menu (it showed the menu, which the vault then refused).

## 0.6.0 (2026-10-16)

**Owners replace root admins.** Root admins were emails in the vault's
configuration that held everything, outside the member table and its
rules: nobody could change or remove them, and they showed in People only
because the vault said so. Now there is one kind of principal. The most
anyone holds is the Owner role with no scope, an Owner of the whole
instance: a member like any other, in People, changed by the same rules.

- **The instance always has an Owner.** The last Owner of the whole
  instance cannot be demoted, narrowed to a scope, or removed, by anyone,
  themselves included: "you're the last Owner of the whole instance: make
  someone else an Owner first" (409, `last_owner`). An Owner of one
  project doesn't count. Two changes at once, each about a different
  Owner, never leave none: the vault counts under the log's head, and
  `formal/Coffre.tla` checks it.
- **The deployment declares its Owners.** The vault's `owners` (`OWNERS`
  in a deployment `coffre init` writes) lists people who are Owners of the
  whole instance whatever the database says. The vault makes each one an
  Owner who is not one yet as it starts (every deploy, Worker isolate or
  Node restart) and when they sign in, logged as the vault's ("the
  deployment names them one"). While listed, nobody demotes, narrows or
  removes them, themselves included (403, "the deployment names
  omar@acme.example an Owner (owners, in the vault's configuration): take
  them off that list and deploy first"), and Users shows them "Owner · set
  by deployment". Taking an email off the list demotes nobody: they stay an
  Owner, one like any other. So setup and recovery are one step: on a new
  instance the first listed person to sign in becomes the Owner, and the
  rest follow at the vault's next call; when no Owner can sign in any more,
  or someone with the database demoted one, add an email you control,
  deploy, sign in. A row written around the vault adds nobody to the list,
  which lives in the deployment's code. Keep it to people you would trust
  as Owner. `bootstrapOwners` (`BOOTSTRAP_OWNERS`) and 0.5's `rootAdmins`
  (`ROOT_ADMINS`) are read until 0.7.
- **Only Owners make Owners.** Making someone an Owner, scoped or not,
  and changing or removing an Owner take an Owner of the whole instance:
  an Admin of all of it does neither (403, `not_allowed`), and People
  offers it no Owner to set or remove. An Owner of the whole instance may
  step down, the one role change anyone makes about themselves, unless
  they are the last, or the deployment names them. The vault decides it under both rows' locks, so an
  Owner demoted meanwhile makes nobody an Owner.
- **A wrong vault key is an outage.** A vault given the wrong key checks
  no member's row, the Owner's included, so every member's request answers
  503 and nobody signs in, with the reason in the app's log, where before root
  admins got through to a `wrong_kek` answer and everyone else was refused
  as tampered ([restore.md](docs/restore.md#if-the-vault-key-is-wrong)).
- The API's `isRootAdmin` and the `root-admin` instance role are gone, as
  is the vault's `root_admin` refusal. The vault's `about()` answers
  `rootAdmins: []` until 0.7, so a 0.5 app deployed after it keeps listing,
  adding and removing members meanwhile.
  Settings no longer lists root admins; Users does, as Owners.

**Upgrading from 0.5.** Nothing to migrate, and nothing to change first:

1. **`coffre update`**, then **`coffre migrate`**, which applies nothing.
2. **Deploy.** The vault's first call makes every email its configuration
   names (`rootAdmins`, `ROOT_ADMINS`) an Owner of the whole instance, as
   `system:vault`: a member row for one who never signed in too, so nobody
   loses what they held, and again at every start while you list them.
   Someone you took off the list before upgrading is not made an Owner, nor
   is anyone 0.5 let in as a root admin whom the list no longer names,
   rolled back to 0.5 and forward included. A root admin who still held
   grants on every project of 0.4 has them converted as anyone's first,
   then becomes an Owner: `coffre migrate` lists the grants. The vault
   reads 0.5's entries by its keys, so keep any vault key it replaced in
   `previousKeks`, as always.
3. **Check Users**, where your root admins are now Owners, set by
   deployment: take those who should not be off the list, deploy, and
   demote them; make Owners of anyone else who should run coffre.
4. **Optionally, rename the setting**: `rootAdmins` and `ROOT_ADMINS` are
   read until 0.7. In `vault/src/worker.ts`, `owners:
   env.OWNERS.split(',')`, and the var in `vault/wrangler.jsonc` (on Node,
   `src/vault.ts` and `vault.env`); `coffre setup` keeps whichever name
   your vault reads.

Rolling back to 0.5 leaves the new Owners Owners, and makes the listed
emails root admins again, as long as the vault's code still passes them as
`rootAdmins`: 0.5 refuses to start without it. Roll back the rename of
step 4 with it.

**How old each value is, and which are due for rotation.** An
environment's Last written column says when each value was last written
("ada · 7mo ago", the exact time on hover), and sorts the table by it, as
the Key column sorts by name; below 44rem the two sort controls stay, a row
above the stacked keys, and every row shows its age. A rename, a move into a
folder or a new reference never counts as a change: the age is the current
version's. A reference's value is its source's, so its age is the source's
current version's, and its source rotated is its value rotated; one that
reads nothing (broken, its source archived or empty) has none. The row
shows "source · 1y ago", and who made the reference on hover, where it
showed who made it and when.
A value unchanged for more than `rotateAfterDays` whole days gets a quiet
Rotate tag, its age in days on hover. `createCoffre({ …, rotateAfterDays })`
sets it for the deployment: 365 if left out, `null` for no flag, and
anything but a whole number of days from 1 fails the deployment's start.
There is no per-project setting: one threshold is the audit's, and
`--older-than` asks any other. `coffre list` prints each value's age, "214
days ago", and "(unchanged over 365 days: rotate it)" after those due;
`coffre list market/prod --stale` lists only those, and `--older-than 90d`
those older than any age, as text or `--json`, archived keys and keys
without a value never among them. `GET /api/secrets/market/prod` answers
`rotateAfterDays` beside the keys, and a reference's `updatedAt` is its
source's current version's, where it was `null`; `updatedBy` stays `null`
for one. `ageInDays` and `olderThan` in `@coffre/client` are the rule both
use.

**The CLI picks the instance by directory.** With several instances, a
company's and your own, `coffre login <url>` pins the directory it ran in
to that instance, for it and every directory below, as well as making it
the default. A command then uses `--url`, else the nearest pinned
directory's instance, else the default, so `~/Code/acme` talks to
secrets.acme.example and `~/Code/mine` to your own, without `--url` or
another login. `coffre whoami` says why: "on https://secrets.acme.example
(pinned at ~/Code/acme)", or "(the default)"; `coffre use` lists the
directories pinned to each instance and stars the one used here. A
directory pinned to an instance you are not signed in to says to sign in
there, and never uses the default's session instead, nor does a command
that cannot tell which pin applies (a pins file it cannot read, or reached
through a symbolic link, or a directory removed since): it stops, and
`--url` names the instance. `coffre login` with a session the instance
still knows keeps it and only pins (`coffre logout` first for a new one;
only the instance saying it does not know the session starts a new
login), and one in your home directory sets the default only. `coffre
logout` unpins the instance's directories. The pins live in
`~/.coffre/directories.json`, beside the sessions rather than in their
file, so a CLI before this one, which rewrites the sessions' file in the
shape it knows, keeps every session and never drops a pin; it ignores
them and uses the default everywhere.

**A repository names its instance in `coffre.json`.** Commit
`{ "url": "https://secrets.acme.example" }` as `coffre.json`, and every
clone uses that instance below it with no `--url` and no pin: a command
uses `--url`, else the nearest pin or `coffre.json` above the directory,
your own pin first in the same one, else the default. The file picks the
URL only. Commands still send that instance's own session, so a fresh
clone's first one says `not signed in to https://secrets.acme.example,
which /home/ada/Code/acme/coffre.json names`, and `coffre login`, with no URL,
signs in there after saying which file named it, pinning nothing.
`whoami` and `use` say `named by ~/Code/acme/coffre.json`. A CI run's
`--service` needs no `--url` there either: its ID token is asked for that
URL, which no other instance takes. A secret handed to `coffre login`
(`--token`, `--access-client-id`, `--id-token`) still goes only to a URL
you name. A `coffre.json` that is a link, holds anything but `"url"`, or
names something other than an origin stops the commands below it, with
its path. One in your home directory or above it is ignored.

**A deploy can stop on a key the other environments have.** Add
`STRIPE_WEBHOOK_SECRET` to `market/staging` but not `market/prod`, and
`coffre missing market/prod --check` lists it ("STRIPE_WEBHOOK_SECRET in
staging") and exits 1, so `coffre missing market/prod --check && coffre
run market/prod -- ./deploy` stops before anything is read. A key the team
dismissed never fails it, and with `--json` it fails the same way. The
Action takes `require-complete: true` (default `false`): it checks each
environment it reads, and stops the step before exporting, with an error
annotation per environment listing its missing keys
([ci.md](docs/ci.md#a-key-the-other-environments-have)).

**Key names are visible across a project.** Missing keys are now compared
with every other live environment of the project, not only those the
caller reads: the page's strip, `coffre missing`, `GET
/api/projects/market/prod/missing` and the gate above all show a reader of
`market/prod` that `market/staging` has `STRIPE_WEBHOOK_SECRET`. That is how
a CI token that reads only prod can check it is complete. Anyone who reads
one environment of a project can now learn the key names of its other
environments, and which of them the team dismissed, but never their
values. Values are unchanged, and other projects are never compared.

**An OIDC binding can require a GitHub environment.** Name one, such as
`production`, and only jobs that run in that environment sign in, after
its protection rules (required reviewers, the branches it deploys) let
them through. Set it under "GitHub environment" in the Trust dialog, with
`coffre trust … --github-environment production`, or as the `environment`
claim over the API and MCP. GitHub changes `sub` for such a job
(`repo:acme/api:environment:production`), but no GitHub binding reads
`sub`: `ref`, `workflow_ref` and `job_workflow_ref` are unchanged, so the
plain and the reusable-workflow profiles both work with it.
GitHub's environment names ignore case, so a binding for `production`
also takes a job in `Production`; they are one environment, with the same
rules. The name is checked as GitHub takes one: at most 255 characters, no
control character, no space at either end. The binding's summary, `coffre
trust`'s description of it and its audit entry ("…, in GitHub environment
production, reaching …") name it. Existing bindings are unchanged and take
jobs in any environment, or none, as before. `githubWorkflow` and
`githubReusable` in `@coffre/core/workloads` take an optional `environment`.

**The Trust dialog finds a repository's IDs itself.** Type `acme/api` and,
once you pause or leave the field, coffre asks GitHub for its IDs. It then
shows the repository and its owner as confirmation, spelled as GitHub
spells them: `Acme/API` becomes `acme/api`, as the runs' `workflow_ref`
names it. The ID fields appear only when GitHub shows nothing, behind
"Private repository? Enter IDs", with the `gh api` command that prints
them. For a reusable workflow called from any repository of the
organization, the field asks for the organization, `acme`, and finds its ID
the same way; `coffre trust --any-repository` looks it up too, instead of
requiring `--owner-id`. Each name is asked once per page. GitHub answers
60 lookups an hour to a server that does not sign in, which every user of a
Workers deployment shares; once they are spent the dialog says so and
offers the ID fields. `GET /api/workloads/lookup` takes an owner as well as
a repository, answers with GitHub's spelling, and answers 429 when GitHub's
limit is spent and 503 when GitHub does not answer, where it said 404 for
both. In `@coffre/client`, `WorkloadIds` gains that answer,
`{ github, ownerId }` with no `repositoryId`: code that read a GitHub
answer's `repositoryId` after checking only for `github` checks
`'repositoryId' in ids`.

**Events are chosen in a combobox.** The GitHub events and GitLab pipeline
sources a binding trusts were a row of checkboxes. Now you type to filter
and choose with the arrows and Enter, each chosen one a chip that Backspace
removes. `pull_request` and `workflow_run` are marked "unreviewed code" in
the list, and the warning under the field still says what each exposes.

**A project's Add service account makes a new one too.** The dialog
lists the service accounts you could grant, and as you type a name no
account has, offers it as a new one, last: "Create and grant access" makes
the account with that grant, in one vault decision. A grant refused (more
than you hold, a role only a project takes, an account someone else
removed) makes no account either, so none is left behind holding nothing,
and the row says why in the vault's words. Anyone who sets up service
accounts sees the list and the new option, not only admins: a project's
Owner picked from a list where before they typed a name.

- **API.** `PUT /api/members/token:<name>` takes `{ "access": { "market/prod":
  "viewer" } }`, the first grants as `PATCH /api/access` takes them, and
  answers their `changes` beside `created`. A person, or `access` with a
  `role`, is a 400. The vault's `setAccess` takes `admit`; a vault older
  than the app refuses it (`not_a_member`) and admits nobody, so a
  deployment whose Workers update one after the other never makes an
  account without its grant.
- **CLI.** `coffre admit api-deploy --service --grant market/prod=viewer`,
  repeated or a comma list.
- **MCP.** `admit_member` takes `access`; its approval page shows each grant.

**Pick a repository, private ones too, where a CI run is trusted.** A
trust binding names a repository by its IDs, and coffre looked up only a
public one's: a private one's were typed, from `gh api`. Now a deployment
may pass a GitHub App, installed on its organizations, as
`workloads.github`. In "Trust a workload", the Repository field then
offers every repository the app is installed on, private ones marked, as
the name is typed; picking one fills in its IDs at once, with no lookup.
For a reusable workflow called from any repository, the Organization
field offers the accounts it is installed on. A name the list lacks is
typed whole, and resolves through the app, or through GitHub's public API
outside it, as does a name given to `coffre trust`. Installed nowhere
yet, or reaching no repository, the dialog says so and links to the app's
installation page; GitHub down, it says so and the name can still be
typed. `GET /api/workloads/repositories` is the list, `{ "app": null }`
without an app, for whoever may set up a service account. The app needs
Metadata: read-only, which every GitHub App has, and no one's personal
token. [docs/github-app.md](docs/github-app.md) registers, installs and
passes it. The key stays in the app's configuration and memory, never in
the vault, the database, a log line or an answer.

**One GitHub App signs people in and lists repositories.**
`githubApp({ appId, privateKey, clientId, clientSecret })` makes the
deployment's app once, and the deployment passes the same value to each
side: `github({ app, organization: 'acme' })` signs in with its OAuth
client, `workloads: { github: app }` lists with its key. Neither side
picks up the other's credentials, and each works alone: `github({
clientId, clientSecret })` as before, or an app with no client for the
list only, with people signing in with Google, say. A deployment `coffre
init` writes signs in with `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
as before, and with `GITHUB_APP_ID`, a var, and `GITHUB_APP_PRIVATE_KEY`,
a secret of the app Worker, makes the app from all four for both. Its
permissions are Metadata, Email addresses and, with `organization`,
organization Members, each read-only; the organization check passes only
where the app is installed. When GitHub will not show the organization's
members (403), the sign-in is refused as before, and the server's log now
says why: the app lacks Members, or is not installed there. The sign-in
page's message for it names both remedies. GitHub Enterprise Server signs
in with an app, and `workloads.github` refuses its API, as the list's
IDs would be bound to github.com's issuer.

**The add-person dialog says what it asks.** Its field is "Email", not
"Cloudflare Access email", whichever way people sign in, and its description
of the role is gone: the role field under it already says what each role
holds. "Instance role" is "Role" in every label, and each role's hint
reads "Default permissions: …" ("None" for a Member), then "Project grants
add more."

**A row waiting on the server no longer spills over its neighbours.** In the
Users, Service accounts, grants and secrets tables, "Saving…" and
"Removing…" stood in for the row's menu in a column that fits only the
menu, and ran into the role column. Now the spinner stands there alone, the
words stay for screen readers and as its tooltip.

**Generate a secret's value in the browser.** A new secret's value field,
and an edited one's, has a Generate button. It opens a dialog that makes the
value with Web Crypto, in the page, and Use puts it in the field as if typed:
nothing is sent until the row is saved, through the same write as any other
value. It makes:

- **a random value**, 1 to 256 bytes of entropy (32 by default), as letters
  and digits (base62, each character drawn uniformly), hex, base64 or base64
  URL (unpadded). The dialog says how many characters that is and how many
  bits it holds: 32 bytes are 43 characters of base62, 256 bits.
- **an AES-GCM key**, 256 or 128 bits: the raw key, base64.
- **a key pair**, ECDSA or ECDH on P-521, P-384 or P-256: the private key
  (PKCS #8, base64) is the row's value, and the public key
  (SPKI, base64, as the private key is PKCS #8) is saved with it, under a name of its own that follows the
  first (`JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`). The public key is part
  of the row's edit, as the row says under its value: the row saves, or
  is cancelled, whole, in one write, so a new private key never lands
  beside the old public key. Typing over the value drops the public key.

**Pasting a multi-line value keeps its line breaks.** A new secret's value
field, and an edited single-line one's, is a text input, and a text input
drops the line breaks of what is pasted into it: a PEM private key pasted
there was saved on one line, and no longer parsed. Now a paste holding a line
break goes into the value whole, and the field becomes a textarea, focused,
its caret after the paste, and stays one until the row is saved or
cancelled. Line breaks are saved as `\n`: a `\r\n` from a Windows clipboard
becomes `\n`, as a textarea and PEM and `.env` tooling read them. Masking is
unchanged. Fields that already held a multi-line value were textareas, and
still are. Conformance pastes a key in Chrome (`pasted values`).

**`coffre get` no longer adds a newline when piped.** It printed the value
and a newline whatever stdout was, so `coffre get app/prod/KEY | wc -c`
counted one byte more than the value, and a secret copied that way into
another store (`… | scw secret version create … data=@-`) held a trailing
newline too. Now, with stdout a pipe or a file, it writes exactly the
value's bytes, newlines the value holds included, as `printf %s` would; in a
terminal it still ends the line. `$(coffre get …)` strips trailing
newlines itself, so it is unchanged. A script that removed the added
newline (`| head -c -1`) now cuts the value's last byte: drop that step.
One that relied on it (`coffre get … >> file`) adds it back with `echo`.

## 0.5.1 (2026-10-11)

**`coffre update` moves a deployment with the new release's pages.** The
deployment's own CLI, `pnpm exec coffre update`, belongs to the release
it moves from, and it used that release's list of pages. So 0.4's CLI,
moving a deployment to 0.5.0, left out the new `users.$user.apps.tsx`,
and running it again added nothing, since the deployment was at 0.5.0 by
then. Now a CLI of an earlier release asks the new release's own CLI,
`coffre update --plan <dir>`, which pages it adds and retires and which
versions its Start app and pnpm take. That runs the new release's code, so
it asks first: "Move this deployment from 0.5.1 to 0.5.2, with the pages
and pins its own CLI says, and install it?", then moves it as that CLI
says, without asking again. `--yes` answers for CI; without a terminal
and without `--yes`, nothing runs. npm installs that CLI in an empty
directory of its own, with the deployment's `.npmrc`, so it is the
registry's package the deployment's install fetches, never a copy of the
same version that a project or the global prefix has, as `npx` would run.
Its answer is checked whole before anything changes: page files only in
`app/src/routes/`, each as the deployment has it now; only the Start app's
packages, at exact versions; an exact pnpm. Fields this release doesn't
know are left out. When that CLI can't say, nothing changes and the update
exits 1. CLIs before 0.5.1 don't ask, so to move a deployment from 0.5.0 or
earlier, run the new release's CLI: `npx @coffre/cli@latest update`. A
deployment that 0.4's CLI moved to 0.5.0 still lacks the page: copy
`app/src/routes/_coffre/users.$user.apps.tsx` from
`node_modules/@coffre/cli/dist/templates/<workers or node>/`, then build,
which writes the route tree.

**`coffre migrate` names the role that owns the tables.** A login that
neither owns coffre's tables nor is a member of the role that does used
to get as far as Postgres's "permission denied for schema drizzle". Now
it stops before asking, with the owner and the fix: "coffre's tables are
owned by X, and this login, Y, is neither it nor a member of it: migrate
with X's connection string, or, as a role that administers it, run GRANT
"X" TO "Y" WITH INHERIT TRUE". A member of X that doesn't inherit its
privileges (NOINHERIT) is told so, since a plain GRANT would leave it
unable to migrate. Only the `drizzle` schema and the objects coffre's
migrations make count: another table in `public`, whoever owns it, is the
database's own. With nothing to apply, a login that can still read the
tables gets only a warning, so it can be fixed before the next migration
needs it. `coffre setup` and `coffre-server migrate` refuse the same way.

**CI runs `pnpm test:compat` again**, for both kinds: the newest release,
now 0.5.0, must stay conformant on each change's schema.

## 0.5.0 (2026-10-11)

**Upgrading from 0.4.** This release changes what people and service
accounts hold, so read what `coffre migrate` says before you deploy. The
steps are the usual ones ([Upgrading](docs/deploy.md#upgrading)):

1. **`coffre update`**, in the deployment's directory. It moves the pins
   and adds the new `users.$user.apps.tsx` page.
2. **`coffre migrate`** applies `0002_instance_roles` and
   `0003_credential_scopes`, and 0.4 keeps serving on both. Then it lists
   two things. First, each grant on every project, with what the vault
   will replace it by and anything it loses: "service:deploy: maintainer
   on every project → maintainer on market; not projects made later; loses
   access-manager on market (keeps maintainer)". Second, each service
   account's 0.4 tokens and trust bindings, which keep what the account
   holds when 0.5 first checks them. An account that holds nothing is
   flagged: "which will reach nothing: grant the account before you
   deploy". The pipeline runs it right before the deploy, so run it
   yourself first, from the deployment's directory, and read the lists.
   To choose otherwise, grant, revoke or regrant on 0.4, then run it again
   to check.
3. **Deploy in one step.** The first request converts every grant on every
   project, one member at a time, each logged as `system:vault`. A 0.4
   instance owner becomes an Admin, and the root admin stays root admin.
   Each 0.4 token and binding is sealed the first time it is checked
   (`token.seal`). A 0.4 instance still serving during a rollout answers
   401 to anything 0.5 has sealed.
4. **Check `/readyz`**, then the Audit page or `coffre verify log`.

Scripts that call `coffre grant '*'`, `coffre revoke '*'`, `coffre admit
--owner`, or `PUT /api/members/<member>` with `{ owner }` stop working.
Use roles and scopes instead (below). OIDC bindings need nothing: each
existing one keeps working as a binding on its one event. Rolling back to
0.4 is not an undo. It refuses every sealed token and binding, and every
member who is no longer a Member or an Admin, until they are replaced.

**Instance roles with scopes replace grants on every project.** Each
person has one instance role, Member, Auditor, Developer, Admin or Owner,
which applies in every project its scope takes in, the ones made later
too. A scope has two filters, Projects and Environments, each all, only
some, or all except some; environments match by name, so "Developer,
environments only dev" reads and writes every project's `dev`. Admin is
0.4's instance owner: it manages people, projects and access, and holds no
secret permission; Owner adds every secret. An Admin of the whole instance
can still reach any value, as a 0.4 owner could, by admitting a service
account, granting it a reading role and issuing its token, each step in the
log. A scoped Admin manages only inside its scope and sets no role, and
nobody changes their own role or grants themselves one, which 0.4 let an
owner or an access manager do: that stops a quiet read of one's own, not
an Admin set on reading. Grants are on a
project or an environment, and only add to the role. Service accounts hold
grants only. `*` and `*/<env>` are gone from the API, the CLI, the MCP
tools and the pages: the vault replaces the ones there are when this
version first runs, never giving more than they did, and logs each
(`docs/design/instance-roles.md` has the rule). It takes away nothing it
can keep in the projects there are now: viewer on `*` beside auditor on
billing becomes viewer on each of billing's environments, beside the
auditor grant. Where no grant can hold both, as maintainer on `*` beside
access-manager on billing for a service account, the one that reads stays.
`coffre migrate` says what it will make of each before you deploy, and
names what is lost: "loses access-manager on billing (keeps maintainer)".
A member the vault has reported tampered with is left as they are, until
their access next changes or they are started over. `coffre migrate`,
which holds no key to tell the vault's reports from forged ones, marks
such a member and still says what the conversion would be, so a forged
report never hides one the vault makes.
The first request after the upgrade converts every member holding one,
one after another, before it answers, so on an instance with many it may
be slow; one cut short leaves the rest to the next.

- **API.** `PUT /api/members/<member>` takes `{ role, scope }` instead of
  `{ owner }`; members list `instanceRole` (`member`, `auditor`,
  `developer`, `admin`, `owner` or `root-admin`) and `scope`, null but for
  those who run the instance, since a scope names projects, and a
  place's list says who reaches it by their role (`reachesByRole`).
  `GET /api/me` adds `scope` and `runsInstance`. `GET /api/members/<member>/access`
  answers a member's role, scope and the grants you manage in one query: a
  person's or service account's Access tab reads it once, not one list per
  project (`coffre access <member>`). Making a project or an
  environment no longer answers `inherited`, nor `GET /api/projects`
  `everyProject`. Refusals of what only an Admin or Owner of the whole
  instance may do log `requires_instance_admin`.
- **CLI.** `coffre admit <email> --role <role>`, with `--projects`,
  `--except-projects`, `--environments` and `--except-environments`,
  replaces `--owner` and `--no-owner`. `coffre grant '*'` and
  `coffre revoke '*'` are gone.
- **MCP.** `admit_member` takes `role` and `scope`; `set_access` takes
  projects and environments.
- **Schema.** `0002_instance_roles` adds `role` and `scope` to
  `vault_members`, and lets the vault's login update them. Rolling back to
  0.4 leaves Members and Admins everywhere as they were; anyone else is
  refused until removed.

**Anyone who holds access sets up service accounts for it.** Setting up
CI took an Admin of the whole instance; now a person who holds access adds
a service account, gives it grants, issues its tokens and trusts its
workflows by OIDC, with no Admin. They give it at most what they hold
themselves: a Developer of every `dev` gives `developer` on `market/dev`,
never `maintainer`, nor `market/prod`. They manage an account only while
they hold everything it holds, so a dev Developer issues no token for an
account that also reads prod; one that holds nothing yet is its maker's. A
new setting, **Who sets up service accounts**, keeps the rest to Admins:
environments all except prod, and prod's CI takes an Admin whose scope
takes in prod. Only those who run the instance change it, and each change
is logged with what it was. Service accounts is in the sidebar of anyone
who sets one up, listing only the accounts they manage. A person brings
back only an account they removed themselves. The setting names
environments by slug, so a Maintainer who renames `prod` takes it out of
`all except prod`, or, renaming `staging` away first, into `only dev,
staging`, for an environment they already hold: both lists follow the
current slug, and only keeping renames from them keeps prod to Admins.
Settings written into the log in the vault's name but not by it are
reported and passed over, and when the vault finds none of its own past
them, the setting is closed, never everywhere.

- **API.** `GET` and `PUT /api/settings`, `{ "serviceAccounts": <scope> }`.
  `GET /api/me` adds `setsUpServices` and `serviceSetup`; members and a
  member's access add `managed`. Removing a member answers its `report`
  only to those who run the instance (null otherwise). A refusal to
  someone who does not manage the account logs `not_service_manager`.
- **CLI.** `coffre settings`, and `coffre settings service-accounts` with
  the scope flags `coffre admit` takes. `coffre offboard` removes an account
  you manage.
- **MCP.** The service account tools are listed to anyone who holds access,
  and checked against the account; the setting is changed in the pages and
  the CLI only.

**Each service token and OIDC binding has its own scope.** A scope is
grants, as the account's are: `developer` on `market/dev`, `viewer` on
`market/prod`. It is set when the token or binding is made, at most what
the account holds and what you could give it, and all the account holds
unless you narrow it, by leaving places out or choosing a smaller role. A
request made with it reaches what both the scope and the account hold:
an Admin who later gives the account prod gives it to none of the tokens
and bindings made before, and narrowing the account narrows them all at
once. The server checks the scope for the pages, the CLI and MCP alike,
and the vault decides on it as well. It never changes: to change one,
make another and revoke the first. Someone who made one and then lost
access shrinks nothing, so CI keeps working; offboarding them lists the
tokens they issued, each with what it reaches. An account needs a grant
before it gets a token or binding, since nothing it is given later
reaches one made before. A binding that replaces others, by `--replace`
or because its issuer moved its keys, reaches what they reached unless
told otherwise; on the page, Trust a workload's picker then starts from
it. The tokens and bindings of 0.4 keep exactly what
they reached: the first time this version checks a credential, it gives
each one its account's grants then, after the conversion of grants on
every project, and logs it (`token.seal`); one a 0.4 instance makes while
both run gets its account's grants on its first use. `coffre migrate` lists them
before you deploy, and says which would reach nothing because their
account holds nothing. Rolling back to 0.4 refuses them, and so does any
0.4 instance still serving while 0.5 rolls out: it answers 401 to every
service token and CI run 0.5 has sealed until it is replaced, so deploy
in one step, or expect those to fail for the length of the rollout.

- **API.** `POST /api/members/<member>/tokens` and `/bindings` take
  `scope`, paths to roles as `PATCH /api/access` takes them; the tokens,
  bindings and offboarding's `issuedTokens` lists say each one's `scope`,
  and `token.create` and `token.bind` log it. A scope past the account or
  past you is refused, logged as `beyond_account`; one names at most 1000
  places. `POST …/tokens?dryRun=1` answers what the token would reach, and
  issues nothing, as `…/bindings?dryRun=1` does.
- **CLI.** `coffre tokens issue` and `coffre trust` take
  `--scope market/dev=viewer,…`; `coffre tokens`, `coffre trust
  <service>` and `coffre offboard` say what each reaches.
- **MCP.** `issue_service_token` and `trust_workload` take `scope`, and
  the approval page says what the token or binding will reach, as the
  server would make it: a scope past the account is refused before anyone
  is asked. If that changes before Approve, as when the account is given
  another grant, Approve is refused and the page shows it again; Approve
  makes the token or binding with the scope the page showed, so a grant
  landing just after reaches neither.
- **Schema.** `0003_credential_scopes` adds `scope` to `credentials` and
  `service_bindings`, and lets the app's login update it.

**An Auditor of the whole instance reads the whole log**, the instance's
own entries too: sign-ins, people, service accounts, settings. It verifies
the log, as `coffre verify log` and the Audit page do, and runs nothing it
reads about. A scoped Auditor still reads only the places in its scope.

**One OIDC binding per workflow, on several events, pull requests
included.** A GitHub binding now lists the events it trusts, so a workflow
that runs on push, by hand and on a schedule is one entry, not three. It
may also trust `pull_request`, matched by the branch the pull request
merges into, and `workflow_run`. Both can run code nobody reviewed: the
form, `coffre trust` and the MCP approval page say what each exposes when
it is chosen. Pull requests from forks get no ID token. `pull_request_target`
is still refused. Existing bindings keep working as they are, each a
one-event binding. GitLab bindings list pipeline sources the same way, and
`coffre trust --event a,b` now makes one binding, not one for each.
`@coffre/core/workloads`' `githubWorkflow`, `githubReusable` and
`gitlabProject` still take one `event` or `source`, as before, and now
also a list, `events` or `sources`; naming both, or neither, is refused.

**A person's connected apps are a tab of their page**, for owners, beside
Access and Activity. A deployment gains `users.$user.apps.tsx` through
`coffre update`.

**Shorter explainers.** "Sign in with OIDC" and "Bearer tokens" say what
each is, when to use it, and give one example.

**Hyperdrive's connection limits now fit the database.**
Left at Cloudflare's default, 60 per config on Paid, the app's and the
vault's configs together could outgrow a small database such as
PlanetScale's smallest, which then refused the connections a burst of
requests needed ("remaining connection slots are reserved", 53300). A
user's or service account's Access tab and the service accounts list each
send one request per project or account at once, and some of them failed
as "coffre is unavailable". `coffre setup` now reads the database's
`max_connections`, less what it reserves, and sets each config's connection
limit to half of what is left after 3 for the administrator (at most 20),
so that a burst waits in Hyperdrive instead. Cloudflare treats the limit as
a soft one, which a network failure can briefly exceed. It says how it chose, as in "max_connections
25, 3 reserved, 3 kept for the administrator and migrations: 9 each". A
run on an existing deployment lowers a higher limit, and keeps one set
lower. On a Workers deployment, setup refuses a database too small for
Hyperdrive's 5 per config right after asking for its URL: before it asks
about Cloudflare, so before any domain, custom hostname, login, password or
config changes. Without Cloudflare, its update commands set the limit too,
since setup can't see what each config allows now: it says to check each
with `wrangler hyperdrive get <id>` first, and to leave the flag out for one
set lower on purpose. To fix one now,
without setup: `wrangler hyperdrive update <id>
--origin-connection-limit=<n>` for each config.

**`coffre setup` refuses before it changes Cloudflare, as long as the
database holds still while it asks.** For
an address whose DNS is elsewhere, served through one of the account's
domains, setup made the fallback origin, its DNS record and the custom
hostname before three of its refusals: a Worker without its key over a
database that holds data, an administrator who can't create roles, and a
login that another deployment's Hyperdrive config uses on the same server,
whose message then said "Nothing was changed". Setup now checks the
administrator right after connecting, before it asks about Cloudflare, and
the other two once it has read the account, before its first change there,
adding a domain included, then again right before the logins change, in
case the database changed while setup asked its questions. That last
check comes after Cloudflare's changes, so a refusal it makes, for a
database that took data or a login another deployment uses meanwhile, can
still leave the domain, fallback origin, DNS record and custom hostname
behind; its message now says "Neither login was changed". A run after
reuses whatever a refused one left. Its Hyperdrive step also gives each config's own
connection limit when one set lower was kept ("connection limits of 5 and
7"), where it said "20 each".

**A project whose grants could not be read keeps its row** on a user's or
service account's Access tab, with the error and a Retry button. Before, a
notice sat above the table and the project's row was missing, as if the
member held nothing there.

## 0.4.6 (2026-10-07)

**MCP approvals are harder to misread or misuse**, after a security review.
`trust_workload`'s page names each ID it binds, as github.com's or
gitlab.com's API reads it back, or says to check an ID it can't name; any
other issuer is flagged, and its IDs are left for the person to check.
What the app wrote is shown as the app's ("The app calls it"). With Reveal values, the page no
longer promises the app never sees a value: it says the app can read it.
Approve refuses a page gone stale, when a version was set or a role, or
its end, changed since it was shown. Identical calls at once open one approval, and a burst
stays within five waiting. An approved change whose outcome was lost is
reported as unknown, never as "nothing changed", and the person is warned
before approving it again. The approval page's API takes only a browser
session: a CLI session, which an agent on the same machine may hold, can't
open or decide an approval. A change the person can't make is refused
before an approval opens, and a client's decline is logged.

## 0.4.5 (2026-10-06)

**`run_with_secrets` is gone from the MCP tools.** It only wrote out a
command, which the model can write itself. The server's instructions now
tell the model to run `coffre run <project>/<env> -- <command>` in the
person's terminal, with the CLI signed in, so values reach the process and
never the conversation.

**Shorter copy across the pages, the CLI and the MCP tools.** Sentences that
explained mechanics, hedged or repeated what the page already shows are cut;
warnings and the facts a person acts on stay. The consent page no longer
opens with a lede, says "30 days" for how long a connection lasts, and says
only that a new connection replaces the earlier one. `coffre update` ends
with how this deployment deploys: a push to main when it has
`.github/workflows/deploy.yml`, else `pnpm run deploy`, or a restart on
Node. `coffre whoami` puts MCP and CI sign-in on lines of their own.

## 0.4.4 (2026-10-06)

**An MCP client lists only the tools its person's roles reach.**
`tools/list`, in both protocol eras, leaves out the tools no role the
person holds reaches anywhere: a viewer's client no longer offers
`set_access`, `admit_member` or the audit log, and an access manager's no
longer offers values. A tool their roles allow but the connection's scopes
don't stays listed, so a client can still step up to it. The list is
computed per request from what the token check already read, and its
cache hints are now `cacheScope: "private"` and five minutes, not public
and an hour, so a role granted or taken shows within minutes. Calls are
checked as before: a hidden tool called by name is refused as it was.

**A Workers deployment deploys on every push.** `coffre init --workers`
writes `.github/workflows/deploy.yml`: on each push to `main`, it installs
the deployment as its lockfile says, migrates the database with
`printenv DATABASE_OWNER_URL | pnpm exec coffre migrate --yes`, then runs
`pnpm run deploy`, one run at a time. In a clone of a GitHub repository,
`coffre setup` wires it after deploying: it makes the Cloudflare API token
the workflow deploys with, scoped to the account's Workers Scripts, Account
Settings, Workers KV and Hyperdrive and the zone's Workers Routes, and sets
the repository's Actions secrets `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID` and `DATABASE_OWNER_URL` through GitHub's API, each
sealed to the repository's public key by libsodium's `crypto_box_seal`
(libsodium-wrappers 0.8.4, bundled in the CLI). wrangler's login may not
make API tokens, so setup usually prints the dashboard's token form, filled
in, and checks the token you paste before taking it. It signs in to GitHub with
gh's login, or a fine-grained token that lasts a day, and shows no value.
Run again, it keeps the token; `--rotate-deploy-token` makes a new one.
Without a GitHub remote, it says how to wire it later. Workers Builds stays
documented as the alternative (docs/deploy.md, "Deploys on every push").
A deployment made by an earlier `coffre init` gets the workflow from
setup, to commit.

## 0.4.3 (2026-10-06)

**`coffre update` writes the route tree with the route files it adds.** A
release that adds or removes a page file left the committed
`app/src/routeTree.gen.ts` stale until the next build rewrote it, so an
update's diff was incomplete: 0.4.2's account tabs were four new route
files and a tree that did not name them. Update now regenerates the tree
once it has installed the release, through the deployment's own Vite and
TanStack Router, as its build does, shows it among the changes, and lists
it with the files it changed.

**The MCP tool `read_secret_values` is `reveal_secret_values`**, to match its
scope, Reveal values. No alias is kept: a client that called the old name
gets an unknown-tool error, and finds the new one in `tools/list`.

## 0.4.2 (2026-10-06)

**The account page is in tabs, and shows how to connect Claude.** Profile
(who you are, and the accounts you sign in with), Sessions, Connected apps
and Appearance are routes under `/account`, as a project's tabs are, each
reading only what it shows. Connected apps opens with **Connect an app**:
this instance's MCP URL, `https://<your instance>/mcp`, to copy; Claude
Code's `claude mcp add --transport http coffre <url>`, then `/mcp`; and
claude.ai's steps. It shows only where the deployment turns MCP on.
`coffre init` writes the tabs' four route files,
`_coffre/account.{index,sessions,apps,appearance}.tsx`, and `coffre update`
adds them; `_coffre/account.tsx`, unchanged, is now their layout.

**`GET /me` says where MCP clients connect.** `features.mcp` is the MCP
endpoint's URL, built from the deployment's public URL as MCP's metadata
builds it (`https://secrets.acme.example/mcp`), where it was `true`, and
`null` where it was `false`. Connect an app shows it as the page is
rendered, not once it loads, and `coffre whoami` says it: `MCP clients are
on, at https://secrets.acme.example/mcp`. A page's tab bar now ends where
its cards do.

**`coffre run` and `coffre export` read several environments.** `coffre
run deploy/prod auth/prod -- ./deploy` gives the command both
environments' keys, where it took nesting one `coffre run` in another,
and the inner one's key won when both had it. Every environment is read,
one audited read each, or none is: the CLI first lists each one's keys,
which reads no value, and stops if it may not read one, if one holds a
reference that cannot be read, or if two define the same key, naming the
key and both environments, never a value. `coffre export` takes the same
list, in each format, and the Action's `environment` input takes several,
separated by spaces or lines ([docs/ci.md](docs/ci.md#several-environments)).
Both commands now refuse a secret's path, `market/prod/KEY`, where they
name an environment: `run` read the whole environment for it.

**MCP's scopes are Read, Write, Reveal values and Manage access.** Browse
is now Read, and Read values is Reveal values, on the consent page, the
account's Connected apps, the tools' answers and the docs. Their OAuth
scopes follow: `read`, `write`, `reveal` and `manage-access`, where
`browse` and `read-values` were. A connection made before holds Read
alone: disconnect it, and connect again to grant the others.

**You pick a connected app's scopes when you connect it.** Clients ask for
Read alone, and Claude Desktop did not ask for more, so a connection could
read and nothing else: every write tool, approval link and
`request_secret_value` was refused. coffre's consent page now lists all
four scopes, Read, Write, Reveal values and Manage access, with what the
client asked for ticked, and grants what you tick. The token answer's
`scope` says what was granted, and `mcp.connect` in the log records what
was asked for and what was granted. A tool call short of its scope still
answers `403 insufficient_scope` for clients that step up, as Claude Code
does, and its body is now the tool's result: which scope it needs, and how
to grant it, by connecting the app again and ticking it
([docs/mcp.md](docs/mcp.md#scopes)).

**A base64 secret pasted on its own line is not imported under its own
text.** Base64 that starts with a letter is a valid key name, and its
padding supplied the `=`: `c2stbGl2ZS0xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW4=`,
a 32-byte key, read as that key with an empty value, and
`c2stbGl2ZS0xMjM0NTY3OA==` as that key with the value `=`. `coffre import`
and the web app's import now refuse both, as lines they can't parse, named
by their number alone. **An empty value must be quoted:** `KEY=""` or
`KEY=''` imports as empty, and a bare `KEY=` is refused with `no value:
write KEY="" for an empty one`, since it can't be told from that padding.
An unquoted value of only `=` is refused too. **In an unquoted value, a `#`
after whitespace starts a comment**, as dotenv has it, found before the
value is trimmed: `KEY= # later` has no value, and is refused as a bare
`KEY=` is; it read as `# later`. `KEY=a #b` is `a`; `KEY=#fff` and
`KEY=a#b` keep their `#`. `coffre export` quotes any value that would read
differently unquoted, so its files import back as they were. A key is one
exactly when the API's `secretKey` says so.

**coffre's logo for the GitHub App setup makes.** Neither an app's
manifest nor GitHub's API sets a logo, so setup can't. Once it has made the
app, it prints where to upload one, the app's settings page, under Display
information, and the file: coffre's mark as a 512px PNG on its black tile,
which `@coffre/cli` now ships, at
`node_modules/@coffre/cli/assets/github-app-logo.png` in a deployment.

**The CLI says why it could not reach an instance.** It said only
`could not reach https://…: fetch failed`. It now gives Node's own reason,
with its code and address, such as `getaddrinfo ENOTFOUND
secrets.acme.example`, and what to try for the common ones: a name that
does not resolve here, IPv6 this network does not carry, and a
certificate that something in between presents. `@coffre/client` throws
`Unreachable`, saying the same, in place of `fetch`'s bare `TypeError`,
and `coffre verify instance` says it once, at its health check.

**`coffre import` no longer prints a line it can't parse.** It printed the
line's text, which can hold a value: a line with no `=`, or a key that is
not one, may be a secret pasted on its own. It now says the line's number,
why, and its key when it has a valid one; so does the web app's import.
`ParseProblem` in `@coffre/core/dotenv` has `key` in place of `text`.

**`coffre setup` survives a Hyperdrive config deleted while it runs.**
Setup lists the account's configs as it starts. A config deleted after
that, whose login was getting a new password, made the update answer 404
and stopped setup. It now makes the config again and says so. When the
login kept its password, which setup can't read, the run stops and says to
run setup again, which gives the login a new password and makes the config.

## 0.4.1 (2026-10-06)

**`/access` is gone.** It only sent links from before 0.4.0 on to
`/users`. `coffre update` deletes its route file,
`app/src/routes/_coffre/access.tsx`, from a 0.4.0 deployment, unless the
deployment changed it, and `@coffre/ui` no longer exports its `access`
route options.

**An owner sees a person's connected apps.** A person's page lists, to
owners, the MCP apps they connected, under **Connected apps**, and each can
be disconnected there. The member report (`GET /api/members/<member>`) has
`apps`, and `live.apps` counts them. Removing someone disconnects their
apps, not only through the generation: the removal dialog and `coffre
offboard` name them and count them first, and `revoked.apps` says how many
went. Re-admitting someone revokes the apps of their earlier membership
too, so none is listed again.

**Node: a vault in its own process no longer fails a call now and then.**
The server keeps its connections to the vault's socket open, and the
vault's HTTP server ended one idle for six seconds, Node's default. A call
the server sent on it at that moment failed with ECONNRESET, and its
request answered 503 "coffre cannot check who you are right now". The
vault now leaves idle connections open, for the server's next calls.

## 0.4.0 (2026-10-06)

**0.4.0 is a clean break.** There is no upgrade from 0.3 or earlier: deploy
0.4.0 afresh, on a new database, and bring over what you keep with
`coffre export` ([deploy.md](docs/deploy.md#from-a-release-before-040)).
The schema starts again from one baseline per engine, which only a new
database takes; `coffre migrate` refuses a database an earlier release
made, saying so. Folders are a `folder` column on projects and secrets, and
the last of 0.1's syncs is gone from the schema, the vault and the audit
page.

**Migrate, then deploy; never the other way.** Below the migrations its
release ships, the app answers everything but `/livez` and `/readyz` with
503 `migrating` (an HTML page for a browser), `/readyz` stays red, and the
scheduled job reports the same; it checks once per isolate or process,
until it holds. The per-feature checks that let a release run on the schema
before its migrations are gone, with the 503s they answered. With Workers
Builds, both Workers' builds now start with `printenv DATABASE_OWNER_URL |
pnpm exec coffre migrate --yes`, the app's too, each with the
`DATABASE_OWNER_URL` build variable ([Workers Builds](docs/deploy.md#workers-builds));
`coffre setup` says so. `coffre migrate` runs only in a deployment's
folder: its instance mode, the CLI's daily "migrations pending" line and
the pages' "Database migrations pending" banner are gone, as nothing
serves with migrations pending, and `GET /api/me` no longer reports the
instance's version and migrations. `pnpm test:compat` is off in CI for
0.4.0 and returns for 0.5.0, against 0.4.0.

**No code for releases before 0.4.0.** `coffre update` moves deployments
from 0.4.0 on, and leaves an older one as it was, saying to deploy afresh;
its 0.1-to-0.2 move to a Start app of its own is gone, with the 0.1 entry
points `coffre(env => …)` and `serve({ … })`, which threw to say so. The CLI
no longer refuses the `COFFRE_*` variables earlier CLIs read: it reads no
variable at all, as before, and says nothing of them.

**MCP and values.** `read_secret_values`, with the Read values scope only,
sends a secret's or an environment's values to the client, its answer
warning first that they are now part of the conversation; the vault logs
the reveal under the connection. `show_secret_value`, with Browse, shows the
person a value on coffre's approval page when they press Reveal, and never
sends it to the client. `generate_secret_value`, with Write, has coffre make
a random value on its own server when the person approves (base64url, hex
or alphanumeric, 16 to 128 characters; 32 bytes in base64url unless asked),
which nobody sees.

**MCP changes, each approved on coffre.** A client with the Write scope
can ask to set a secret to a value the person types (`request_secret_value`),
rename, archive, unarchive and restore secrets, and create projects and
environments; with Manage access, change a member's access, admit and
offboard members, issue and revoke service tokens, and trust and untrust
CI workloads. None changes anything when called: it opens an approval, and
the person decides it on coffre's page, `/approvals/<id>`, which shows the
app, the change and what it replaces; Approve makes the change there, once,
as the person through the connection, and its entries name the client and
the approval (`via.approvalId`), beside `mcp.approve` or `mcp.deny`. A
client on MCP 2026-07-28 that declares URL elicitation, Claude Code among
them, is asked to open the page and retries with a MACed `requestState`
bound to its connection and call; any other, claude.ai among them, gets the
link in the result and calls again with the same arguments, 2025-era
clients included: no client is read-only for its protocol version. Approvals
expire in five minutes, a connection holds five at once, and only their
person decides them, with the digest of the change the page showed. No tool takes a value; a token is shown on the
page only. A consent that grants all of an earlier connection of the same
client and more supersedes it once its code is redeemed (`mcp.disconnect`,
`superseded`), and a registration no connection names is revoked after a
week. Migration `0001_mcp_approvals` adds the approvals' table.

**Folder commands.** `coffre folders` lists the folders of projects and
what is in each, and `coffre folders market/prod` an environment's key
folders, both with `--json`. `coffre folders rename Clients Customers`
re-files every project in a folder (`… market/prod stripe payments`, every
key), and onto a folder in use merges the two; `coffre folders remove`
takes everything out of one, each item staying where it is, in no folder,
and previews when more than one would move. A folder is still a label,
there while something is filed in it: no schema change. The API's
`PATCH` and `DELETE /api/folders/<folder>` and
`/api/folders/<project>/<environment>/<folder>` do the same, in one
transaction under the log's head, one `project.move` or `secret.move` per
item; renaming a folder of projects takes `project.manage` on every
project in it. Folder headings in the projects list and in an
environment's keys have Rename and Remove folder in their menu. The
README's CLI section shows archive, unarchive and rename for keys,
environments and projects on lines of their own, and what `coffre roles`
prints.

**Settings read, not inferred.** `GET /api/me` reports what the
deployment's configuration turns on, `features: { mcp, workloads }`, and
the account page (Connected apps), a service account's page and the
directory (trust bindings), conformance and `coffre whoami` read it: a 404
from a feature's route is an ordinary error again. `coffre apps` says when
MCP is off on an instance. Every refusal the app logs now answers with its
reason too (`principal_not_registered`, `missing_secret_read`, …), which
the CLI's hints branch on, and the server's messages name a service account
`service:<name>` themselves. The consent page's describe call, asked with a
browser cookie, must come from coffre's own page, as a change must, so
another site cannot make coffre fetch an app's document, whatever the
path's spelling (`/api//oauth/authorizations/`); the page's own render
still reads it, when it is opened on its own rather than embedded in
another site. An MCP connection's client name, host and kind, and
a registration's name, are under their rows' MACs.

**MCP clients connect.** coffre is now an OAuth authorization server for
MCP clients such as Claude, which connect at `<PUBLIC_URL>/mcp` as the
people who approve them (docs/mcp.md). A client is known by its metadata
document, as Claude publishes one, or registers itself, and then shows as
Unverified; a registration's custom-scheme redirects are left out. The
consent page, `/oauth/authorize`, shows the client's website, where the
answer goes, and the scopes asked for, Browse always; nothing is granted
until the person approves, every time. Codes are PKCE-bound and last a
minute; access tokens last an hour and are good at `/mcp` only; refresh
tokens rotate, and one presented again, like a code redeemed twice, ends
the connection. The account page's Connected apps, and `coffre apps` and
`coffre apps revoke`, list and disconnect them; an owner may disconnect
anyone's. Each connection, token and disconnection is in the log under the
client's name, tokens as detail. `/mcp` speaks MCP 2026-07-28, stateless,
and answers a 2025-11-25 or 2025-06-18 client's `initialize` without a
session. Its tools browse: `whoami`, `list_projects`, `list_secrets`,
`secret_history`, `list_access`, `describe_member`, `read_audit_log`, and
`run_with_secrets`, which says how to give a command its secrets with
`coffre run` and puts no value in the conversation. Each tool is API calls
as its person, so it can do no more than they could; a call through MCP
reaches only the API routes its connection's scopes allow, and none of a
person's own sign-in. Every call is logged under the client (`mcp.read` for
a read that went through, as detail; `mcp.call` for a refusal), and the
API's own entries name the connection. `coffre init` turns it on with
`signin({ mcp })` and three limits: on Workers, the rate-limiting bindings
`MCP_PER_SOURCE`, `MCP_PER_CONNECTION` and `MCP_TOTAL`; on Node,
`processLimits()`, which now takes `perConnection` too. `coffre update`
adds the three route files to an older deployment, which turns MCP on
itself (docs/deploy.md, "MCP clients"). Migration `0010_mcp_connections`
adds the clients' and connections' tables; until it runs, connecting
answers 503.

**Missing keys.** An environment's page lists the keys its sibling
environments have and it lacks, compared only with those you can read: key
names are metadata. Each has Add, a new row with its name, and Dismiss,
plus Dismiss all; a dismissal is the team's, logged, and listed under
Dismissed with Restore. `coffre missing market/dev`, `coffre missing dismiss
market/dev/KEY` (or `--all`), `coffre missing restore`. Migration
`0009_dismissals` adds their table; until it runs, nothing is dismissed and
dismissing answers 503.

**References.** A secret can be a reference to another, in another
environment or project: `coffre set billing/prod/DATABASE_URL --ref
market/prod/DATABASE_URL`. Whoever reads `billing/prod` reads market's
current value through it, rotations included, without a grant in market:
a reference is a decision, taken by someone who reads the source and writes
where it is held. The vault makes each one, as a `reference.create` entry
under its MAC, and checks that entry at every read, so a reference row
written around the vault reads nothing. One hop: a reference never points
at a reference. Market's owners and access managers see every reference
into market, and who reads through it (`coffre references market`,
`coffre access market/prod`), and break one with `coffre references break`,
as can whoever writes where it is held.
A read through a reference is market's read, in market's log and its
offboarding report, and billing's too. A reference that cannot be read,
broken, or its source archived or deleted, stops the whole `run` or
`export`, saying why and who can fix it, rather than run without it.
Archiving what a live reference reads, the key, its environment or its
project, is refused (409) until the reference is broken, so archiving
never silently breaks another project's runs; the refusal names each
reference and who can break it, and the archive dialogs list them with
Break. A reference held inside what is archived does not block it, nor
does one held in a key, environment or project archived already (D58):
nobody reads through it, and if its holder is unarchived later, its key
shows "Source archived" and reads refuse saying how to fix it. A reference belongs to the environment that
holds it, like a value, not to whoever made it: removing them ends none,
and their offboarding report lists the references they made, read from the
log. A reference the vault sealed for a write that then stored nothing is
ended at once, `abandoned`, so no row written later can revive it. `coffre fork
--reference` makes each key a reference to its parent's. Migration
`0008_references` adds one app table and indexes on the log; until it runs,
making a reference answers 503 (docs/design/environments.md). It builds
four indexes on `audit_log` in the migration's transaction: on a large log,
appends wait while they build, so migrate a busy instance when it is quiet.

**Forks.** `coffre fork market/prod staging` makes `market/staging`, with
each of prod's live keys, its current value and its folder, and none of its
history. Copying is reading: it needs read on prod, and the vault logs one
`secret.read` per key with the purpose `copy`, then a write per key. The
UI's "Add environment" offers "Start from: a copy of prod". If a fork stops
half way, the environment stays, and forking into it again, as long as it
has no live secret, fills it. `PUT /api/projects/market/staging {"name":
"Staging", "from": "prod"}` (docs/design/environments.md).

**Folders.** Projects, and the secrets of an environment, can be filed in
folders, one level deep: `Clients / acme`, `database/`, `stripe/`. A folder
arranges a list and does nothing else: it grants, hides and renames
nothing, and `run` and `export` inject a key by its own name wherever it is
filed. `coffre move market/prod/STRIPE_KEY stripe`, `coffre move acme
Clients`, `--none` to take one out; `coffre list` and `coffre projects`
group by folder; `PATCH` takes `{"folder": …}`. Migration `0007_folders`
adds two tables, so this release runs on the schema before it, listing
everything in no folder and refusing to move until an owner runs
`coffre migrate` (docs/design/environments.md).

**An archived project, or environment, can be deleted for good.** Archiving
hides a place and keeps every value; deleting frees the space and hides it
for good. Instance owners only, and only once it is archived:

```sh
coffre projects delete market                 # what it would erase and revoke; nothing changes
coffre projects delete market --apply         # deleted
coffre environments delete market/old --apply # an environment alone
```

- Every version's ciphertext and wrapped data key is erased, in place, and
  the vault revokes every grant there, lapsed ones too. The preview counts
  the versions and names the grants, and the members left holding nothing,
  a CI service perhaps, with the `coffre offboard` that removes them.
- The vault refuses any key operation in a deleted place, as `deleted`,
  before it asks of any grant, so no grant of any kind reaches into one,
  and grants nothing there afterwards.
- The references into a deleted place, and out of it, are ended, broken,
  and the preview names them.
- An environment is deleted only once it is archived itself. A place
  restored, or granted, while its deletion runs makes the deletion stop
  with a 409, nothing erased; asked again, it revokes the new grant too.
- Two races with a deletion's commit, which a model of the locking
  protocol found, are closed. A rename, archive or restore whose request
  found the place just before it was deleted is refused with a 404,
  where it used to give the tombstone a live slug back. And a read the
  vault had checked just before the place was deleted is refused as
  `deleted`, where it used to release the key after the deletion.
  Adding an environment, or renaming, archiving or restoring a key, under
  a place deleted since the request found it is refused with a 404 too:
  nothing is written to a deleted place.
- What stays is a tombstone of names: the place, its keys and its versions'
  numbers, authors and times, which the audit log names. It is renamed
  `market~deleted-2026-10-05`, so `market` is free for a new project that
  the log never confuses with it, and it is gone from every list, archived
  ones included. `coffre audit` still reads its entries by that name, and
  `coffre verify log` passes after.
- The project's Settings, under Danger zone, and an archived environment's
  menu offer it in the browser, asking you to type the place's path first.
  Backups taken before the deletion still hold the encrypted values, which
  the dialog, the preview and [restore.md](docs/restore.md) say.
- `DELETE /api/projects/market` and `DELETE /api/projects/market/prod`,
  `?dryRun=1` to preview, logged as `project.delete` and
  `environment.delete`. A deletion cut off partway finishes when asked
  again.
- Migration `0006_deletions` widens the slug checks to admit a tombstone's,
  and lets the app empty a version's ciphertext and wrapped key, which a
  trigger makes the only change a version ever takes. It only adds: 0.3.0
  runs on it. Until it runs, deleting answers 503.
**A service account is an identity, not a token.** The CLI and the UI showed
a service as `token:deploy-slides`, so its OIDC trust bindings looked set
"on a token", though OIDC is the way to need no token at all. Now a service
account, a machine identity for CI and other machines, is
`service:<name>` wherever a person reads one: help, output, previews,
refusals, `coffre access`, `coffre audit`, the audit log's sentences and the
UI's pages. It signs in one of two ways, and they are named so: by OIDC (trust
bindings) or with bearer tokens.
- The UI's Tokens page is Service accounts, and a service account's page
  shows "Sign in with OIDC", its trust bindings, then "Bearer tokens".
- The CLI takes `service:<name>`, still takes `token:<name>`, and `--service`
  as before; `coffre admit service:deploy` needs no `--service`.
- The API, the vault and the audit log keep `token:<name>`: the log's signed
  entries hold it. Nothing is migrated, and nothing signed or verified
  changes; `@coffre/client` shows and takes the names at the edge
  (`shownMember`, `apiMember`).

**A sign-in error is said once, and a reload is a clean retry.** The page
coffre sends a refused sign-in back to, `/login?error=…`, renders the
error on the server, then takes it out of the address once its scripts
run, so a reload, or a link to the page, starts over. The same goes for
`/account?linked=…` and `/account?error=…`. Without scripts, a reload
still shows it.

**"Your email already signs in with a different account" names it.** It
now says "Your email already signs in with GitHub. Sign in with GitHub,
then link this account from your account page.", lists several when
there are, and says "another GitHub account" when the address signs in
with a different account at the same provider. Only the providers are
named, never another email or account name, and only to a visitor whose
provider has just verified that the address is theirs.

**Grants on every project.** A member or a service can hold a role on every
project, the ones created later too, or on one environment in every project:

```sh
coffre grant '*' ada@acme.example --role auditor            # every project
coffre grant '*' ci-deploy --role viewer --env dev --service  # dev in every project, never prod
coffre revoke '*' ci-deploy --env dev --service
coffre access '*'                                           # who holds them
```

- Only instance owners and root admins give or take them. They are grants
  like any other: roles (only those an environment can hold go on one
  environment's name), end dates, `access.grant` and `access.revoke` entries
  naming the place as `*` or `*/dev`, and offboarding, which revokes them
  with the rest and counts them in its preview.
- `*/dev` matches the environment's slug when it is used: a project that has
  no `dev` gains one when someone creates it, and renaming `staging` to `dev`
  brings it in. Making a project or an environment, or giving one a new slug,
  answers with who reaches it through them (`inherited`), and the CLI and
  the dialogs say so before you confirm.
- A person's or a service account's Access tab lists theirs, "All projects
  · Developer" or "dev in every project · Developer", and an owner grants
  and revokes them there: "Grant on every project" takes a role, an
  environment name or none, and an end date. A project's access list shows
  who reaches it through them. Each is shown to those who see the grants of
  a project it reaches, owners and that project's access managers, and no
  one else.
- One migration, `0005_instance_grants`: a column on `vault_grants`, and its
  checks loosened to allow these. 0.3.0 runs on the new schema, and this
  release on the old one, where it answers 503 to a grant on every project
  until `coffre migrate` has run.
- **Revoke grants on every project before rolling back past this release.**
  An older vault does not know them, and refuses everyone who holds one, as
  a member whose record was changed around it, until an owner removes them
  (deploy.md for 0.3.0, "Rolling back past grants on every project").

**`coffre trust` from first use.**
- A binding matches one event, and trusting a workflow that also runs by
  hand or on a schedule took one `coffre trust` for each. Now `--event` (and
  GitLab's `--source`) takes several, `--event
  push,workflow_dispatch,schedule`, a binding each, in one go. `push` is
  still the only default.
- The preview says which events the bindings accept, and names the flag
  that adds the others the ref allows: "Accepts runs started by push. Not
  by workflow_dispatch or schedule: add them with --event, as --event
  push,workflow_dispatch,schedule."
- For a private repository, whose IDs coffre cannot look up, it said only
  "not found". Now it says why in a line, then gives the command that gets
  the IDs and the flags to add:
  `gh api repos/OWNER/REPO --jq '"--repository-id \(.id) --owner-id \(.owner.id)"'`,
  and `glab api … | jq …` for a GitLab project.
- `coffre trust` alone prints its usage and exits 0, as `coffre help` says
  it does. A test now holds every command's `--help`, `-h` and `help
  <command>` to exit 0.

`coffre update` and `coffre migrate` without a terminal and without `--yes`
now say "Not a terminal, so nothing to confirm on: pass --yes to update
without asking."

**`coffre untrust` shows what it would end, and ends it with `--apply`**, as
every other command that ends something for good does. The preview names
the binding, its claims, and the CI runs that would lose sign-in, in a
sentence: "GitHub Actions runs of acme/api's workflow deploy.yml, on
branch main, by push would no longer sign in as token:api-deploy, and the
credentials they hold would end at once." A script that ran `coffre
untrust <service> <id>` adds `--apply`.

**wrangler 4.142, and `wrangler dev` stays up.** The Workers deployment's
wrangler moves from 4.118.0 to 4.142.0, with Cloudflare's Vite plugin
(1.50.0 to 1.61.0, which pins it) and the Workers types (5.20260926.1).
Under `wrangler dev` before 4.131, one request that met an idle internal
connection as it closed, about five seconds after the last, or a client
gone mid-upload, ended the whole dev server with an empty `✘ [ERROR]`
(cloudflare/workers-sdk#15203 and #14641, fixed by #15252): a local run, or
`pnpm conformance`, would stop partway. `coffre update` now moves wrangler
and the Workers types with the plugin.

## 0.3.0 (2026-10-05)

**Everything the API does, the CLI does.** The commands that were the
browser's alone:

```sh
coffre projects create market [--name …]       # rename, archive, unarchive
coffre environments create market/prod         # the same
coffre rename market/prod/DB_URL DATABASE_URL   # a secret's key, its versions with it
coffre archive market/prod/OLD_KEY              # unarchive brings it back
coffre admit ada@acme.example [--owner]         # a member; --no-owner ends ownership
coffre admit deploy-slides --service            # a service, for CI
coffre revoke market ada@acme.example --env prod
coffre tokens deploy-slides                     # a service's tokens
coffre tokens issue deploy-slides [--expires-in <days>] [--label …] [--output-file <path>]
coffre tokens revoke deploy-slides <id> [--apply]
coffre sessions                                 # sessions revoke <id> [--apply]
coffre identities                               # identities unlink <id> [--apply]
```

From nothing to a CI service: `coffre admit deploy-slides --service`, `coffre
grant deploy deploy-slides --role viewer --env prod --service`, then `coffre
trust deploy-slides --github … --apply`, or `coffre tokens issue
deploy-slides`. `grant` does not make a member: to one not yet admitted it
says `admit them first, coffre admit … --service`. `tokens issue` prints the
token once, on stdout, and on a terminal says that it will not be shown
again; `--output-file` writes it to a new file, 0600, never one already
there, and prints no token. What ends something for good, a token, a
session or a linked account, is shown first and done with `--apply`, as
`offboard` and `import` are. The lists take `--json`: `projects`, `list`,
`history`, `access` (which takes a place now, `access market/prod`),
`tokens`, `sessions`, `identities`, `audit` and `whoami`.

Approving a `coffre login` stays the browser's, which is what vouches for
the CLI. `packages/cli/src/commands.ts` maps every route of the API to its
commands, or to the browser with why; a route added with neither fails the
typecheck and the parity test, and the test runs every command's `--help`.

Also: `coffre --version` prints the version; `coffre <command> --help` and
`coffre help <command>` print its usage, for every command; a flag a command
does not take, or an argument too many, is refused in a line and its usage,
exit 2, never a stack trace.

**The CLI reads no environment variable, and takes no secret as a flag or an
argument.** `COFFRE_TOKEN`, `COFFRE_API_URL` and the rest used to override the
saved session where no one could see it, and a secret in a variable reaches
every process the shell starts. Now flags configure, and a command that
needs a secret asks for it: at a hidden prompt, with a label (`Database
owner URL`), or, when stdin is no terminal, from stdin, which is where a
pipeline pipes it and a file is redirected. A CI run signs in as a person
does, with `coffre login`, and the commands after it use the session it
saves:

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

The session flags, before the command, pick another instance than the
current one, `--url`, or sign one command in as a service by its ID token,
`--service`, which on GitHub Actions needs nothing else. A variable an
earlier CLI read, still set, stops the command that read it, in one line
saying what to do instead, rather than leaving the run to go elsewhere, or
as someone else, unseen:

```
coffre: COFFRE_TOKEN is no longer read: unset it; instead, run `coffre login <url> --token` and paste the token, or pipe it in
```

| Before | Now |
|---|---|
| `COFFRE_API_URL` | `--url <url>`, or `coffre login <url>` once |
| `COFFRE_TOKEN` | `coffre login <url> --token`, the token pasted or piped in |
| `COFFRE_ACCESS_CLIENT_ID`, `COFFRE_ACCESS_CLIENT_SECRET` | `coffre login <url> --access-client-id <id>`, the secret pasted or piped in |
| `COFFRE_SERVICE` | `--service <name>`; on GitHub Actions, still nothing else |
| `COFFRE_ID_TOKEN`, `COFFRE_ID_TOKEN_FILE` | `coffre login <url> --service <name> --id-token`, the ID token piped in |
| `COFFRE_AUTH_MODE` | `--auth-mode signin\|cloudflare` |
| `COFFRE_MIGRATE_DATABASE_URL` | `coffre migrate` asks, or the URL piped in: `printenv DATABASE_OWNER_URL \| coffre migrate --yes` |
| `COFFRE_SETUP_DATABASE_URL` | `coffre setup` asks, or the URL piped in |
| `COFFRE_VAULT_KEY`, `COFFRE_APP_KEY` | `coffre verify keys` asks, or both piped in, the vault key's line first |
| `COFFRE_VAULT_KEY_ID` | `coffre verify keys --vault-id <id>`, as before |
| `COFFRE_CONFORMANCE_CANARY` | `coffre verify instance --canary <path>` asks for the value, or it is piped in |
| `coffre set <path> <value>` | `coffre set <path>`, the value asked for or piped in |
| `coffre verify instance --canary <path>=<value>` | the same, the value asked for or piped in |
| `coffre migrate --url <url>` | `coffre --url <url> migrate` |

`coffre logout` forgets a service token's or an Access service token's
session there, and revokes nothing: the token is the service's. A machine
sign-in never replaces a person's session unseen: they sign out first, or
the run signs in from a home of its own. `coffre set` refuses an empty
value, which an unset variable piped in would be, and takes one as it is,
at the prompt or piped, less exactly one final line break. An empty
session flag, which is what an unset variable expands to, an instance named
both as an argument and as `--url`, a session flag after the command, and
one a command has no use for are refused. When the instance does not know
the session saved for it, as after it was reset at the same address, the
CLI says so and names `coffre login <url>`. The GitHub Action's inputs are
as they were; it pipes the token to `coffre login --token`, the CLI in a
home of the step's own, removed when the step ends. On Workers Builds, rename the vault's
build variable `COFFRE_MIGRATE_DATABASE_URL` to `DATABASE_OWNER_URL`, and
its build command to `printenv DATABASE_OWNER_URL | pnpm exec coffre migrate
--yes` ([Workers Builds](docs/deploy.md#workers-builds)). On GitLab, name the
ID token anything but `COFFRE_ID_TOKEN`, and pipe it to `coffre login
--service <name> --id-token` ([docs/ci.md](docs/ci.md#without-a-stored-token)).

**`coffre setup` on Workers takes an address whose DNS is elsewhere.** A
Worker answers only at an address Cloudflare serves, so setup makes it a
custom hostname of one of the account's domains, with Cloudflare for SaaS,
on the Free plan: it keeps or makes the domain's fallback origin, makes the
custom hostname, shows the CNAME and TXT records to add at the address's
DNS provider, and, after the deploy, waits for Cloudflare to see them. A
run stopped there picks up where it left off. With no domain on the
account, setup offers to add one, showing its nameservers, or the Worker's
workers.dev address for now. This needs Cloudflare for SaaS enabled on the
domain. When Cloudflare refuses wrangler's login a call this needs, setup
asks for an API token, hidden, saying which permissions it needs, and its
wranglers deploy under it ([deploy.md](docs/deploy.md#a-domain-whose-dns-is-elsewhere)).

## 0.2.0 (2026-10-04)

**A deployment's app is a TanStack Start app of its own** (0.2.0), a
conventional one, and coffre is a set of pieces it mounts, as an auth SDK's
are. Vite builds the app once, and nothing bundles it again: on Workers,
`wrangler deploy` uploads what Vite built, so no second pass rewrites what
the pages send the browser, as wrangler's `keep_names` did in 0.1.17. On
Node, srvx runs the same build, as TanStack Start documents, and the
vault stays a process of its own. The app's files, as `coffre init` writes
them:

- `app/src/coffre.ts`: the configuration, once, `export const coffre =
  createCoffre(…)`;
- `app/src/server.ts`: Start's handler, each request carrying coffre,
  `handler.fetch(request, { context: coffre.request(…) })`, and coffre's
  scheduled job;
- `app/src/start.ts`: `createStart(() => ({ requestMiddleware: [coffreMiddleware,
  createCsrfMiddleware(…)] }))`. coffre's middleware gives every response
  coffre's security headers and a fresh CSP nonce, and the pages the
  visitor's API client. A server route or page rendered without it fails,
  saying how to add it. Start's CSRF check for server functions, which Start
  drops once an app sets middleware of its own, stays for the app's;
- `app/src/routes/`: Start's file routes. The root, the app's own
  document, with coffre's stylesheet and icons and `<CoffreProvider>`; and a
  file for each of coffre's server routes, layouts and pages, each spreading
  coffre's route options: `createFileRoute('/_coffre/projects/')({ ...projects,
  component: ProjectsPage })`. Start splits each page into a chunk of its
  own, with its preload hints. Delete a page's file to leave it out; add
  files for the app's own pages, under coffre's nav or not. coffre's nav
  offers only the pages there. A page of the app's own may call the API as
  the signed-in visitor, `useCoffre()` in a component or `context.coffre` in
  a loader. An app that prefers routes in code mounts the same options with
  TanStack's `createRoute` ([Your own routes](docs/deploy.md#your-own-routes));
- `app/src/router.tsx`: `createRouter(routeTree)`, Start's generated tree;
- `app/vite.config.ts`: `cloudflare(…)` on Workers, `tanstackStart()`,
  `viteReact()`, and `coffre()` from `@coffre/ui/vite`, which puts the
  pages' files under `/_coffre/assets/` and checks the versions below.

The theme and the folded sidebar are cookies now, `coffre-theme` and
`coffre-sidebar`, which the server reads, so a page is drawn as the visitor
left it from the first byte, with no script of coffre's own before it: a
theme chosen before 0.2, kept in the browser's storage, is chosen once more.
coffre's look is scoped to the element `<CoffreProvider>` renders; the
app's document keeps its own.

React, TanStack Router, Start, Query and Vite are the deployment's own
dependencies now, pinned at exactly the versions `@coffre/ui` is built with;
`coffre update` moves them with coffre's packages, and adds the file of a
page a release adds. On Workers, `pnpm dev` is
now `vite dev app`, the vault beside the app. A refusal no longer waits for
the request's body: nothing in coffre reads what a caller is still sending
before answering.

To upgrade, in the deployment's directory, with the 0.2 CLI:

```sh
npx @coffre/cli@0.2.0 update
```

It moves a deployment whose files are as a release of 0.1 wrote them, its
configuration kept as that release had it, and shows each file it changes
before asking once. It changes nothing when a file is the deployment's own,
or one is already where 0.2 puts its own: it names each, and
Upgrading to 0.2 (deploy.md for 0.2.0) shows the move by hand.
A move cut short is finished by the next run. Then `pnpm typecheck`, and
deploy: on Workers Builds, the app's build command is now `pnpm exec vite
build app` and its deploy command `npx wrangler deploy -c
app/dist/server/wrangler.json`; `pnpm run deploy` does both. On Node,
`pnpm build`, then restart both processes.

## 0.1.18 (2026-10-04)

**Workers deployments: signed-in pages no longer go blank.** wrangler bundles
with esbuild's `keep_names` on, which wraps functions in an `__name` helper
that only the Worker has; seroval, which streams a page's data, writes its own
functions into the page as source, and with them the `__name` calls: in the
browser, `ReferenceError: __name is not defined`, then a blank page.
`app/wrangler.jsonc` now sets `"keep_names": false`, as `coffre init` writes
it, and `coffre update` offers to set it in an existing deployment, showing the
lines it adds. Deploy the app after. Node deployments were not affected.

Conformance loads the pages in a real browser: signed in, `/projects`, a
project and `/audit`, in headless Chrome, with no console error. Without a
Chrome on the machine, the check is skipped and says so; `--browser <path>`
names one.

`coffre setup` in a fresh clone of a deployment, with no `node_modules`,
installs it first, as its lockfile says, before Cloudflare's sign-in runs the
deployment's own wrangler: it no longer fails with `spawn …/wrangler ENOENT`.
An install that fails says why in a sentence. `coffre update` installs such
a clone as it was before moving it, so that the migrations it says the
release adds are counted from the deployment's own.

`coffre update` recognizes a CLI installed globally with pnpm 11, which
keeps it in its store's `links/` directory, and updates it with `pnpm add -g`
instead of calling it a dependency of that directory. It asks npm and pnpm
where their globals are (`ls -g`), with pnpm's `PNPM_HOME` when pnpm can't
answer; when neither claims the CLI, it says so and prints what each manager
would run. Run in a deployment, `pnpm coffre update` now knows its CLI as
one of the deployment's packages.

## 0.1.16 (2026-10-04)

`coffre update` moves a deployment from pnpm 10 to 11 without a terminal:
pnpm's question about removing `node_modules` no longer stops it. When a
lockfile another pnpm wrote holds a package too young for this one, it first
resolves again for versions old enough, and lists every version that moved;
only when no older version fits does it offer to wait or to let the package
through. An install that fails leaves `package.json`, `pnpm-workspace.yaml`
and `pnpm-lock.yaml` as they were, byte for byte, and says so.

## 0.1.15 (2026-10-03)

Deployments pin pnpm: `coffre init` writes `"packageManager": "pnpm@11.8.0"`,
and `coffre update` adds it to a deployment that lacks it, so every
install, Workers Builds' included, holds `minimumReleaseAge` alike. When
pnpm holds a package back, `coffre update` says when it is old enough, and
offers to wait or to let it through by name until then, never silently.

## 0.1.14 (2026-10-03)

`coffre update` and `coffre migrate` upgrade a deployment: update the CLI
and the deployment's coffre packages, deploy, then migrate the database
with the owner's URL, asked for at a hidden prompt. `coffre migrate` first
checks that the instance runs the CLI's own version, and shows what it will
apply. `/me` now tells owners and root admins the version an instance runs
and how many of its migrations the database has applied; owners see a
banner while some are pending, and the CLI says so once a day. `pnpm
migrate` stays, for automation. [Upgrading](docs/deploy.md#upgrading).

## 0.1.12 (2026-10-03)

Syncs are removed; use a service token with `coffre run` or `coffre export`,
or the GitHub Action.

Before upgrading, **check for syncs**, including archived destinations:

```sql
SELECT id, provider, created_by, archived_at FROM syncs;
SELECT sync_id, key FROM sync_keys;
```

The migration refuses to run if either table has any rows, rather than
silently discard a configured destination. Move each destination to your
CI/deploy pipeline, which already has its platform's write credentials.
Back up the database, then deploy the new vault and app before migrating;
they work with the old schema. Once old versions have stopped receiving
requests and scheduled events, have the database owner clear `sync_keys`
and then `syncs` after the destinations have been migrated, and run
`pnpm migrate` with the owner URL. An old app can create new syncs; do not
restart it. Workers upgrade steps (deploy.md for 0.1.12, "Upgrading to 0.1.12")
include the exact command and login.
Remove unneeded third-party tokens stored as ordinary coffre secrets and
revoke those tokens with their issuers. Removing a sync never revoked copies
of values already pushed to an external platform.

The new migration drops both sync tables and their references on Postgres
and SQLite. All old migration files remain immutable. Past `sync.*` audit
entries, checkpoints, sealed legacy members and grants remain unchanged:
the log still verifies and the audit page still renders its human sentences.
Legacy sync principals can no longer read values or acquire new grants.

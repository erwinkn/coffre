# Restoring from a backup

Everything coffre knows is in one Postgres database: values (encrypted),
wrapped data keys, members and grants, sessions and tokens, and the audit
log with its head. A backup of that database and two keys bring all of it
back, including a log that verifies. This page says what to keep, how to
back up and restore on PlanetScale Postgres or plain Postgres (`coffre
backup`, `coffre restore`), how to check a backup and the result, and what
the local drill (`scripts/restore-drill.sh`) shows.

## What to keep, and where

| What | Where | Without it |
|---|---|---|
| The database | PlanetScale's backups, or `pg_dump` files you keep off the server | nothing to restore |
| The vault key, `VAULT_KEY`, with its vault ID, `VAULT_KEY_ID`, and every earlier vault key in `previousKeks` | your password manager, never beside the backups | no value can be read, ever: the backup holds only wrapped data keys. The vault's signing key comes from the vault key too, so every member's row fails its MAC, and the vault's entries and checkpoints fail verification |
| The app key, `APP_KEY` | your password manager | the app's entries, sessions and tokens fail their MACs: verification fails, and every session and token is refused |
| The OAuth client secret and the deployment's settings | your password manager and the deployment's repository | nobody can sign in |

With AWS KMS, the vault key is the key in KMS, not a value to escrow: keep
the key, and its alias, from being deleted, and the vault's IAM credentials
in your password manager, with its `SIGNING_KEY`, which a KMS deployment has
instead of deriving one from the vault key. See [keys.md](keys.md).

Keep the keys apart from the backups. A backup alone opens nothing, and the
keys alone hold nothing; whoever has both has every value.

Check your escrow before you need it: `coffre verify keys`, as an Admin or
Owner of the whole instance, asks for the vault key and the app key you keep, and checks
each against the running instance on your machine, sending neither. A vault
key it replaced is named as such ([keys.md](keys.md#check-your-escrow)). Do
it once the keys are saved, and after every rotation.

## Before you restore

Restore the whole database to one moment. coffre's guarantees hold between
the tables of one database at one point in time: members and grants, the log
that records them, the versions it names. Never restore some tables, or two
databases to different moments.

A backup taken before a project or environment was [deleted for
good](architecture.md#deleting-for-good) still holds its encrypted values,
and restoring it brings them back, readable with the vault key. Deleting
frees the live database, not its copies: expire backups as your retention
policy says.

Stop traffic first. An instance left running against the old database keeps
writing to it, and one pointed at the restored database while still running
refuses to append behind the log head it remembers (`LogRewound`), which is
the intended response to a rollback, not a fault.

## On PlanetScale Postgres

PlanetScale's backups are physical: a base backup and its write-ahead log,
replayed to the moment you choose, every 12 hours by default and kept for 2
days. A restore always makes a new branch. It brings back the whole
database, the roles included, but **resets every role's password**, and a
role logs in to the new branch as `<role>.<new branch id>`.

1. Stop traffic: put the Workers behind a maintenance page, or delete their
   routes, so nothing writes to either branch.
2. Restore. In the database's **Backups** page, either choose a backup and
   **Restore to new branch**, or use **Point-in-time recovery** with the
   source branch and the moment. Name the branch, e.g. `restore-2026-10-01`.
3. Set the logins up again on the new branch, with the owner's connection
   string for it, as when the deployment was made, from the deployment's
   directory:

   ```sh
   pnpm exec coffre setup --reset-passwords
   ```

   It sets the four logins' passwords again, which the restore reset,
   and shows each login's new connection string, under the new branch id:
   the backup login's goes in your backup job's secrets, in place of the
   old one.
   It migrates: missing migrations are applied, and the database-level
   privileges reasserted, on every run, even when the schema is current; a
   database a newer release migrated is refused. It checks the boundary as
   each login. It makes no keys: the restored database has its own.
4. Point the three Hyperdrive configs at the new branch, with the
   `wrangler hyperdrive update` commands it shows, and check that caching
   stays disabled:

   ```sh
   pnpm exec wrangler hyperdrive get <app config id>   # caching: disabled
   ```

   Each update reads its database URL at a silent prompt, as in
   [deploy.md](deploy.md#2-three-hyperdrive-configs), so the password stays
   out of your shell's history; the Cloudflare dashboard's Hyperdrive page
   does the same.

   By hand, steps 3 and 4 are `\password` for the four logins as the
   owner, the three updates with `coffre_runtime.<branch id>`,
   `coffre_vault_runtime.<branch id>` and `coffre_vault_hot.<branch id>`,
   and `pnpm exec coffre migrate`, in
   the deployment's directory, with the owner's URL for the new branch.
5. Redeploy both Workers with `pnpm run deploy`, the same keys and settings:
   a fresh deployment remembers no log head.
6. Check the result, below, then reopen traffic. Promote the branch, or
   point production at it, as PlanetScale's branching docs describe.

## On plain Postgres

A dump is a logical copy of one database: its tables, rows, privileges and
row-level policies, but not the cluster's roles or their passwords, and
not the privileges on the database itself. Provision the roles before
restoring; `coffre migrate` reasserts the database privileges afterwards.
This is what the drill runs. Postgres only: a SQLite database, which only
tests and local development use, is one file, copied whole with
`sqlite3 coffre.db ".backup coffre-copy.db"`.

`coffre backup`, `coffre restore` and `coffre verify backup` run
PostgreSQL's own `pg_dump` and `pg_restore`, which must be on `PATH`:
`pg_dump` of the server's major version or newer, `pg_restore` of the
server's own (a newer one sends settings an older server lacks, and the
restore stops at once, restoring nothing). Each asks for its connection
string at a hidden prompt, or reads it from stdin, never an argument, and
hands it to the tool with the password in `PGPASSWORD`.

### Backing up

Back up as a login of its own, here `coffre_backup_login`, as often as you
can afford to lose. Its group, `coffre_backup`, which the migrations make,
reads every row, the audit log's included, and writes none, so the backup
job never holds the owner's password. `coffre setup` makes it, grants it
its group and shows its URL once, as `Backup database URL`; `coffre setup
--reset-passwords` gives it a new password, as it does the others. A login
is the server's: on a server another deployment set up first, setup keeps
the login that deployment made, password and all, unless it cannot log in. On a database set up by
hand, make it once, as the owner, the same way as the runtime logins:

```sql
CREATE ROLE coffre_backup_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password coffre_backup_login
```

then run `pnpm exec coffre migrate --backup-login coffre_backup_login` in
the deployment's directory, which grants the login its group. Passing it on
every run, as a pipeline does, is harmless. Migrate never makes the login
and never revokes its group: revoke it yourself when it should go. Postgres
keeps one membership per grantor, the role whose `ADMIN OPTION` granted it
(the owner, when a member of the owner migrated). A `REVOKE` naming no
grantor removes only the caller's own, and anyone else's, a superuser's
included, only warns while the login keeps reading.
List the grantors, then revoke each, as a superuser or that grantor:

```sql
SELECT grantor::regrole FROM pg_auth_members
 WHERE roleid = 'coffre_backup'::regrole AND member = 'coffre_backup_login'::regrole;
REVOKE coffre_backup FROM coffre_backup_login GRANTED BY <grantor>;
```

`$BACKUP_URL` is the owner's URL with that login's name and password:

```sh
printf '%s' "$BACKUP_URL" | coffre backup coffre-$(date -u +%Y%m%dT%H%MZ).dump
```

It opens one snapshot, reads in it what the dump must hold, and has
`pg_dump --snapshot --enable-row-security` dump exactly that snapshot. Beside
the dump, `coffre-….manifest.json` says what it holds: each table's rows,
counted and hashed in any order, the newest migration, the audit log's
head, and the dump's size and SHA-256. Neither file holds a key, but plain
values are in the clear: both are written for their owner alone. Keep the
manifest with the dump: `coffre restore` and `coffre verify backup` need it.

The audit log has row-level security: a login it applies to sees only
the entries a policy shows it, and `pg_dump --enable-row-security` dumps
only those, without a word (without the flag it stops at the log, "query
would be affected by row-level security policy"). `coffre backup` refuses,
before dumping anything, a login row-level security hides rows of any
table from: one no permissive policy shows a whole table, such as a login
in `pg_read_all_data` before the log, or one a restrictive policy hides
rows from. The log is the one table with row-level security today. A table in the database that coffre's migrations
did not make, `coffre_backup` cannot read, and the backup stops at it:
grant it `SELECT`, or move it to another database. While the snapshot is
open, a migration that wants an exclusive lock waits behind it, and the
app's writes behind the migration: the snapshot waits 30 seconds at most
for a lock, and so does `pg_dump`, and the server ends the session if it
sits idle for 10 minutes, which it never does while `pg_dump` runs: once
the backup's process is gone.

### Checking a backup

`coffre verify backup <dump>` restores it into an empty scratch database,
without owners, grants or row policies, so it needs none of coffre's roles,
and checks it as a restore does (below). Run it after every backup, on any
Postgres of the server's major version: a CI service container will do.
The copy stays in that database, for you to drop.

With `--keys`, it also asks for the vault keys and the app keys, and opens
every version of every value, a plain one compared with its text, and
authenticates every log entry the app and the vault signed under those
keys (below). That puts both keys and every value on the machine that
runs it: the job that backs up every night is no place for them. Run it in
a drill, on your own machine.

### Restoring

1. Stop both components (or both Workers).
2. Create the runtime logins if this server lacks them, and set their
   passwords, as in [deploy.md](deploy.md#appendix-the-database-by-hand):

   ```sql
   CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   CREATE ROLE coffre_vault_hot LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   \password coffre_runtime
   \password coffre_vault_runtime
   \password coffre_vault_hot
   ```

   The group roles, `coffre_app`, `coffre_vault` and `coffre_backup`, and
   the runtime logins' membership in them must exist too: run
   `pnpm exec coffre migrate` once against an empty database on this server
   if they do not. Make `coffre_backup_login` too, to back the restored
   database up: step 4 grants it its group.
3. Create an empty database, and restore into it as the owner:

   ```sh
   createdb --owner=coffre_owner coffre_restored
   printf '%s' "$OWNER_URL_OF_COFFRE_RESTORED" | coffre restore coffre-….dump
   ```

   It refuses a database that holds anything of coffre's already, and
   restores in one transaction, so a restore that fails leaves the database
   empty. Every object belongs to the login that restores, the one the
   deployment migrates as, whoever owned it before; the grants and row
   policies come back as they were. The database's default privileges name
   the role that owned it (`ALTER DEFAULT PRIVILEGES FOR ROLE coffre_owner`),
   so restore as that role, or as a member of it, on a server that has it. Then it checks the database against the
   manifest:
   - the dump is the one the manifest describes, byte for byte;
   - every table holds the rows it held, by count and by a hash of them;
   - the same migrations ran, the newest the same;
   - the audit log's head is the one backed up, and the chain runs from the
     first entry to it with no gap: every link and every hash. Without the
     keys, this says nothing about who wrote an entry: anyone who can write
     rows can link one.

   The walk also holds each author to its keys' order, as `coffre verify
   log` does, which needs no key: the app's key writes nothing from the
   first entry that moves on from it (`key.reseal`, `key.rotate`), and the
   vault never goes back to a key it left.

   With `--keys`, it asks at hidden prompts for the vault keys, then the
   app keys, separated by spaces (on stdin, the second and third lines
   after the connection string): first the one each signs with now, then
   any it replaced. Either line may be blank, not both. A vault whose
   config gives a `signingKey` of its own signs with it: give it first,
   then the vault keys. It then also opens every version of every value,
   each under the vault key its vault ID names, and counts those deleted
   for good, which hold no value any more; and it authenticates each log
   entry under its author's keys. Entries under a key not given pass by
   their place in the chain alone, and are counted; but each author's
   newest entries must be under the first key given, and once that key has
   written, no other may write after it, as the online verifiers require.
   Only local vault keys: one in a key service, AWS KMS, never leaves it,
   so values wrapped there are counted, not opened.

   It ends by listing what is left, the steps below.
4. In the deployment's directory, run `coffre migrate` with the owner's
   URL for the restored database, or `coffre setup --reset-passwords` if
   the runtime logins' passwords changed:

   ```sh
   printf '%s' "$OWNER_URL_OF_COFFRE_RESTORED" | pnpm exec coffre migrate --yes --backup-login coffre_backup_login
   ```

   Besides applying missing migrations, every run revokes `CREATE` and
   `TEMPORARY` on that database from `PUBLIC`, both runtime logins and the
   group roles. This repairs what a one-database dump leaves out, even when
   no schema migration is pending.
5. Check the app's login has exactly its privileges:

   ```sh
   COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="<coffre_runtime URL>" \
     pnpm --dir packages/db run db:verify:runtime
   ```

6. Point both components at the restored database, each with its own login:
   the three Hyperdrive configs on Workers, or `DATABASE_URL` in `.env` and
   `vault.env`, and `HOT_DATABASE_URL` in `vault.env`, on Node. Keep the same keys and settings.
7. Restart both processes, or redeploy both Workers.

A dump `pg_dump` made by hand, without a manifest, restores with
`pg_restore --no-owner --exit-on-error --single-transaction` into an empty
database, as the owner; nothing checks it then but the steps below.

## Checking the result

Before reopening traffic:

1. `coffre verify log`, as an Owner. It must say `audit log OK`,
   verified through the newest entry, with the last checkpoint the backup
   held. It walks the log from its first entry, a stretch a request: every
   link, both authors' MACs, every checkpoint against the prefix it signed
   and the tally it keeps, and replays the members and grants.
2. Reveal a canary: a secret kept for this, whose value you know.
3. Look at the Users page: members, owners, grants and the removed, as they
   were at the backup's moment. Someone removed before it stays removed, and
   their old sessions and tokens stay refused.
4. Write a value and read it back.
5. Wait for the next heartbeat, or trigger the Cron, then check `/readyz`:
   `ok`, with `checkpointed: true`. With the audit watch, a restore into a
   new deployment, whose anchor's store is empty, is walked whole and
   re-anchored by itself, with an alert ([deploy.md](deploy.md#the-audit-watch)).
   Restored over the same deployment, the anchor finds the log older than
   it: `/readyz` stays red on that finding until an Owner accepts the
   entries the backup lacks, `coffre audit accept-loss <from> <to>`, the
   range from the backup's first missing entry to the one the finding
   names.
6. `coffre verify keys` with the keys you deployed it with, from the
   escrow: both must be the instance's, the vault key the current one.
7. Optionally, `coffre verify instance` from outside: as no one, then as
   you, with a token of its own ([conformance.md](conformance.md#against-a-running-instance)).

Verification proves the restored history is the one coffre wrote, up to the
backup's moment. It cannot show what was written after it: a complete older
backup verifies as well as a recent one ([Limits](architecture.md#limits)).

## On 0.15's log

Since 0.15, an instance keeps two logs in the same database: 0.14's chain,
which the steps above check, and 0.15's, its changes and uses sealed into
checkpoints that its checkpointer signs. A backup holds both. Its
checkpointer keeps one thing outside the database: its memory of the newest
pair it signed (the vault's `CHECKPOINTER_MEMORY` file on Node, its Durable
Object's storage on Workers).

The restore takes one step more. The checkpointer's memory is newer than
the backup: it remembers pairs signed after it. It refuses the restored log
("the database lost entries the signer sealed"), exactly as it refuses a
database a writer rolled back, and seals nothing until its memory is reset.
That refusal is the point, so it is reset by hand, once, for a restore you
meant:

- **Node:** stop the vault, move its memory file aside (`<memory>` and
  `<memory>.alarms`), and start it again;
- **Workers:** clear the checkpointer's Durable Object storage, then start
  it.

A checkpointer with no memory takes the database's newest pair as its
start, and says so in an alarm ("the audit signer remembers no pair"). Then,
besides the checks above, `coffre verify instance` checks 0.15's trees:
the newest pair signed by the vault's key and every entry above it by its
MAC.

The wrong vault key fails here too: its checkpointer refuses the log's
checkpoints ("not a pair signed by this log"). The app cannot then ask
whether 0.15's log is cut over, so it answers every request but `/livez`
503, sign-in and every use of a value included, and `/readyz` is red; the
server's log says why (`cutover_refused`).

A backup from before a rotation of the vault key restores the same way,
under the configuration after it (the old key in `previousKeks`, or the old
`signingKey` in `previousSigningKeys`): the checkpointer, its memory reset,
takes the database's newest pair under the old key and moves the log on to
the new one again, with a rotation entry of its own
([audit-tree.md](design/audit-tree.md), "A rotation"). The same test drills
it.

`packages/server/test/restore-015.test.ts` drills it on Postgres, with
PostgreSQL 16's `pg_dump` and `pg_restore`: a cut-over instance backed up,
written to after, restored, refused by the old memory, taken by a new one,
its trees verified, a token's use serving the value it served at the
backup, a change sealed on top; the wrong vault key refused; and a backup
from before a rotation restored under the new key.

## If the vault key is wrong

The vault's configuration names the vault key `kek`, and the keys it
replaced `previousKeks`; the messages below name them in passing.

With a local vault key, the vault's own keys come from it
([keys.md](keys.md#a-local-key)). A vault key other than the one that
wrapped the data, whether a mistyped key under the right `VAULT_KEY_ID` or
the wrong escrowed key, holds none of the keys the vault's entries were written under, which
the vault sees at its first call. It then writes nothing at all, and
refuses every key operation and every change of access. It cannot check
anyone's member row either, since it sealed them under the same keys, the
Owner's included: it says of no member who they are, so nobody signs in,
and every request from a member's session or token answers

```
HTTP 503  {"error":"unavailable","message":"coffre cannot check who you are right now"}
```

while the app's log says why:

```
checking who called failed … the vault's entries are under vault:3f1c…, a key this vault does not hold: it was given the wrong vault key or signing key, or a vault key it replaced is missing from previousKeks in its config
```

The scheduled checkpoint is refused too, so `/readyz` turns red after the
next beat (`checkpointed: false`).

A vault key replaced and then dropped from `previousKeks` shows the other
way: the values under the new vault key read, and `coffre verify log` fails
at the first entry the vault wrote under the one dropped, saying why:

```
written under vault:3f1c…, a key this verifier does not hold: either it is forged,
or the vault wrote it under another vault key or signing key, which must stay configured:
a vault key that was replaced stays in the vault's config, in previousKeks
```

A vault key the vault's own keys do not come from, an earlier one in
`previousKeks` or a KMS key beside a `signingKey`, is checked before the
vault's first key operation instead. Each has a check value: a known value
wrapped under it the first time the vault used it, kept in a `key.check`
entry of the log. Opening it again opens no data. A key with no check value
yet is first tried on a few of the newest keys it wrapped, if any; a backup
from before check values existed is covered the same way. A vault key that
opens neither gets every key operation refused, each refused key logged with the code
`wrong_kek`, and the checkpoint with them:

```
HTTP 503  {"error":"unavailable","reason":"wrong_kek",
           "message":"the vault key arn:aws:kms:… (aws-kms), kek or previousKeks in the vault's config, is not the one that wrapped these values"}
```

Either message names keys by id, never key material. Restart the vault with
the escrowed vault key and its `VAULT_KEY_ID`: the vault decides once per
process, so a restart is what clears it.

A vault key the vault cannot reach (KMS down, or refusing the vault's
credentials) is not a verdict: the call fails as any key operation does
during an outage, the next one asks again, and checkpoints go on. A vault
key under a new id is a rotation: its check value is recorded on first use,
and values wrapped under an id the vault is no longer given fail with "no
vault key configured for …". Keep earlier vault keys in `previousKeks`.

## The local drill

`scripts/restore-drill.sh` runs the plain-Postgres restore end to end on
this machine, against the compose Postgres, after `pnpm build`, with
PostgreSQL 16's `pg_dump` and `pg_restore` on `PATH`, the compose server's
version:

1. It builds the Workers example (as `coffre init` writes it) and starts it
   under `wrangler dev`, over a new database, `coffre_drill`, with the dev IdP for
   sign-in and `.env.dev`'s keys. It seeds it, writes a canary, grants a
   member access, removes another whose browser session it keeps, issues a
   service token, and lets two heartbeats checkpoint the log.
2. It backs the database up with `coffre backup`, as `coffre_backup_login`,
   which migrate granted `coffre_backup` (`--backup-login`).
3. It restores into `coffre_drill_restored` with `coffre restore --keys`,
   whose checks must all pass, every value opened and every entry
   authenticated; provisions the logins, runs migrate to reassert database
   privileges, and checks the app login's privileges. Then it checks the
   backup again with `coffre verify backup --keys` and a random vault key,
   into `coffre_drill_scratch`, which must fail: no value opens, and no
   vault entry is under that key.
4. It starts the example over the restored database with the same keys, and
   checks:
   - verification passes through the newest entry, and the backup's last
     checkpoint still holds;
   - members, owners, grants and the removed are exactly as backed up;
   - the canary reveals;
   - the removed member's kept session is refused, and they cannot sign in;
   - a new value writes and reads back, and the next beat checkpoints;
   - `coffre verify instance` passes, as no one and with the restored
     token, which reads the canary.
5. It restarts the example with a random vault key under the same id, and checks
   that its Owner cannot sign in, that reading the canary and a new write,
   with the restored token, both answer 503, and that `/readyz` turns red.

It drops its databases and stops what it started, however it ends. It
does not drill a PlanetScale branch: there, the steps that differ are the
restore itself and the login names, and a physical restore brings back the
roles and database privileges. The local drill provisions the roles and
reasserts database privileges through migrate.

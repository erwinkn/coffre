# Restoring from a backup

Everything coffre knows is in one Postgres database: values (encrypted),
wrapped data keys, members and grants, sessions and tokens, and the log
with its signed head. A backup of that database and the keys bring all of
it back. The one thing outside it is the signer's own storage, a Durable
Object of the vault Worker's, which no backup holds and no restore needs:
a restore deploys the vault with a new signer, which goes on from the
restored log's head.

This page says what to keep, how to back up and restore on PlanetScale
Postgres or plain Postgres, how to check the result, how to go back after
the upgrade from 0.14, and what the local drill (`scripts/restore-drill.sh`)
shows. In 0.16.0, `coffre backup`, `coffre restore` and `coffre verify
backup` refuse: they read 0.14's log and envelopes, and come back in 0.16.x.
PostgreSQL's own `pg_dump` and `pg_restore` do the work meanwhile.

## What to keep, and where

| What | Where | Without it |
|---|---|---|
| The database | PlanetScale's backups, or `pg_dump` files you keep off the server | nothing to restore |
| The vault key, `VAULT_KEY`, with its vault ID, `VAULT_KEY_ID`, and every earlier vault key in `previousKeks` | your password manager, never beside the backups | no value can be read, ever: the backup holds only wrapped data keys. The vault's own keys come from the vault key too, so its new signer cannot take the restored log's head as the vault's, and the vault serves nothing |
| The app key, `APP_KEY` | your password manager | little: it seals only the cookies of sign-ins under way and, behind Cloudflare Access, the one that ties a browser to its session. Those sign in again; sessions, tokens and the log are untouched. |
| The OAuth client secret and the deployment's settings | your password manager and the deployment's repository | nobody can sign in |

With AWS KMS, the vault key is the key in KMS, not a value to escrow: keep
the key, and its alias, from being deleted, and the vault's IAM credentials
in your password manager, with its `SIGNING_KEY`, which a KMS deployment has
instead of deriving one from the vault key. See [keys.md](keys.md).

Keep the keys apart from the backups. A backup alone opens nothing, and the
keys alone hold nothing; whoever has both has every value.

Check your escrow before you need it: `coffre verify keys`, as an Admin or
Owner of the whole instance, asks for the vault key you keep, or with a key
service the `signingKey`, and checks it against the running instance on your
machine, sending nothing of it. A vault key it replaced is named as such ([keys.md](keys.md#check-your-escrow)). Do
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

Check the keys you will deploy while the instance still answers: `coffre
verify keys`, with the vault key from the escrow (or, with a key service,
the `signingKey`), must say it is the one the instance signs with now. A
restore deployed with other keys serves nothing until the right ones are
deployed ([below](#if-the-vault-key-is-wrong)).

Stop traffic first. An instance left running against the old database keeps
writing to it. And deploy the restored database with a new signer name
(below): the signer that ran before it remembers every entry and row since
the backup, and would report each one as tampered with, for good.

## The signer after a restore

The signer keeps, in its own storage, the head it signed last and what each
sealed row should be ([design](design/0.16.md#operations), "The signer"). A restored
database is behind it. So a restore names a new signer object, in the vault
Worker's configuration:

```ts
export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  owners: env.OWNERS.split(',').map((email) => email.trim()),
  // The object the signer runs in, `signer` until a restore: a new name after each.
  signerName: 'signer-2026-11-14',
}));
```

The object of the new name is blank. At the vault's first call it goes on
from the restored database's head: it checks the head's MAC under the
vault's keys, rebuilds both trees of the log from its entries and requires
them to reach the head's roots, takes the rows as they stand, and numbers
the next entry after the head's last. The vault's log says so once:

```
coffre: the signer's storage was empty: it took the database as it stands, a log begun that it did not sign, from its head (docs/design/0.16.md, "Losing the signer's storage")
```

If the head is not the vault's (the keys are not the ones the database was
written under) or the log does not reach it, every call is answered 503
`adopting`, and the vault's log says why: `the database's log is begun, and
its signer has signed none of it: its head is not the vault's`, or `its log
does not reach its head`. Nothing is written, and the signer stays blank:
its alarm signs nothing, and removes nothing that waits, until it has gone
on from the head. It tries again every 10 seconds, and the same name serves
once the right keys are deployed.

The object named before stops. Its alarm, the next time it fires, is not
set again, and it refuses every call, so it signs nothing of the new
signer's log. It writes nothing, to the database or its own storage, which
stays in the namespace as it was. Do not reuse a name: named again, that
object finds a database that moved on without it, and reports it.

*Example.* A bulk change goes wrong at 11:40. Ada restores the 06:00 backup,
deploys the vault with `signerName: 'signer-2026-11-14'`, and signs in. The
backup's log holds 1,202 entries; her first change is the 1,203rd, and the
signer's checks find nothing. Had she kept the old name, the signer would
report every member, grant and value changed between 06:00 and 11:40 as
`row`, and the head rewritten, for good, and number her change after the
1,250 entries it had signed, leaving a hole of 48 that its daily walk
reports `lost`.

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

   It sets the three logins' passwords again, which the restore reset,
   and shows each login's new connection string, under the new branch id:
   the backup login's goes in your backup job's secrets, in place of the
   old one.
   It migrates: missing migrations are applied, and the database-level
   privileges reasserted, on every run, even when the schema is current; a
   database a newer release migrated is refused. It checks the boundary as
   each login. It makes no keys: the restored database has its own.
4. Point both Hyperdrive configs at the new branch, with the
   `wrangler hyperdrive update` commands it shows, and check that caching
   stays disabled:

   ```sh
   pnpm exec wrangler hyperdrive get <app config id>   # caching: disabled
   ```

   Each update reads its database URL at a silent prompt, as in
   [deploy.md](deploy.md#2-two-hyperdrive-configs), so the password stays
   out of your shell's history; the Cloudflare dashboard's Hyperdrive page
   does the same.

   By hand, steps 3 and 4 are `\password` for the three logins as the
   owner, the two updates with `coffre_runtime.<branch id>` and
   `coffre_vault_runtime.<branch id>`, and `pnpm exec coffre migrate`, in
   the deployment's directory, with the owner's URL for the new branch.
5. Give the vault a new `signerName` ([above](#the-signer-after-a-restore)),
   and redeploy both Workers with `pnpm run deploy`, the same keys and
   settings.
6. Check the result, below, then reopen traffic. Promote the branch, or
   point production at it, as PlanetScale's branching docs describe.

## On plain Postgres

A dump is a logical copy of one database: its tables, rows, privileges and
row-level policies, but not the cluster's roles or their passwords, and
not the privileges on the database itself. Provision the roles before
restoring; `coffre migrate` reasserts the database privileges afterwards.
This is what the drill runs.

Use PostgreSQL's `pg_dump` of the server's major version or newer, and
`pg_restore` of the server's own: a newer one sends settings an older
server lacks, and the restore stops at once, restoring nothing.

### Backing up

Back up as a login of its own, here `coffre_backup_login`, as often as you
can afford to lose. Its group, `coffre_backup`, which the migrations make,
reads every row, the log's included, and writes none, so the backup
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

The backup itself, with the login's password in `PGPASSWORD`, never on the
command line:

```sh
pg_dump --format=custom --enable-row-security -h <host> -U coffre_backup_login -d coffre \
  -f coffre-$(date -u +%Y%m%dT%H%MZ).dump
```

`pg_dump` reads every table in one snapshot, so the dump is of one moment.
`--enable-row-security` dumps a table with row-level security as the
login's policies show it, which for `coffre_backup` is every row; without
the flag, a login that cannot bypass row-level security stops at such a
table. The dump holds no key, but plain values are in the clear: keep it
for its owner alone. A table in the database that coffre's migrations did
not make, `coffre_backup` cannot read, and the dump stops at it: grant it
`SELECT`, or move it to another database.

Check a backup by restoring it, as the drill does: into a scratch database
and a stack of its own, with the keys, on your own machine, never in the
job that backs up every night.

### Restoring

1. Stop both Workers.
2. Create the runtime logins if this server lacks them, and set their
   passwords, as in [deploy.md](deploy.md#appendix-the-database-by-hand):

   ```sql
   CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   \password coffre_runtime
   \password coffre_vault_runtime
   ```

   The group roles, `coffre_app`, `coffre_vault` and `coffre_backup`, and
   the runtime logins' membership in them must exist too: run
   `pnpm exec coffre migrate` once against an empty database on this server
   if they do not. Make `coffre_backup_login` too, to back the restored
   database up: step 4 grants it its group.
3. Create an empty database, and restore into it as the owner, in one
   transaction, so a restore that fails leaves it empty:

   ```sh
   createdb --owner=coffre_owner coffre_restored
   pg_restore --no-owner --exit-on-error --single-transaction -U coffre_owner -d coffre_restored coffre-….dump
   ```

   Every object belongs to the login that restores, the one the deployment
   migrates as, whoever owned it before; the grants and row policies come
   back as they were. The database's default privileges name the role that
   owned it (`ALTER DEFAULT PRIVILEGES FOR ROLE coffre_owner`), so restore
   as that role, or as a member of it, on a server that has it.
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

6. Point both Hyperdrive configs at the restored database, each with its
   own login. Keep the same keys and settings.
7. Give the vault a new `signerName` ([above](#the-signer-after-a-restore)),
   and redeploy both Workers.

## Checking the result

Before reopening traffic:

1. The vault's log says the signer went on from the head
   ([above](#the-signer-after-a-restore)), and a minute on, its first check
   sends no alert.
2. Reveal a canary: a secret kept for this, whose value you know.
3. Look at the Users page: members, owners, grants and the removed, as they
   were at the backup's moment. Someone removed before it stays removed, and
   their old sessions and tokens stay refused.
4. Write a value and read it back.
5. `coffre verify keys` with the keys you deployed it with, from the
   escrow: both must be the instance's, the vault key the current one.
6. Optionally, `coffre verify instance` from outside: as no one, then as
   you, with a token of its own ([conformance.md](conformance.md#against-a-running-instance)).

The signer holds the restored log to its head, and the head to the vault's
keys. It cannot show what was written after the backup: a complete older
database, put back, is taken as well as a recent one.

## If the vault key is wrong

With a local vault key, the vault's own keys come from it
([keys.md](keys.md#a-local-key)). Under another vault key, whether a
mistyped key under the right `VAULT_KEY_ID` or the wrong escrowed key, the
signer cannot take the restored head as the vault's, and every call is
answered 503 `adopting`, with the reason in the vault's log (above). Nobody
signs in, and nothing is read or written.

With a key service and a `signingKey`, the signing key is what the head is
held to. The right `signingKey` beside another KMS key serves, and each
value whose data key that KMS key did not wrap is refused, `unreadable`.

Either way, deploy the escrowed keys, `coffre verify keys` first if the old
instance still answers, under the same `signerName`: the signer that
refused the head kept nothing, and its alarm left the log as the backup
had it, the entries that waited included.

## If the signer's storage is lost

The signer's storage is the vault Worker's Durable Object (`CoffreSigner`).
What loses it:

- the object's class or its namespace deleted, or renamed without
  Wrangler's `renamed_classes` migration, which moves the storage;
- the vault Worker deployed under another name, or to another Cloudflare
  account: the namespace is the Worker's own.

A new signer over a database whose log was begun goes on from its head, as
after a restore, holding the head to the vault's keys and the log to the
head. What it cannot tell is a database a writer emptied or rolled back
behind it: an emptied log is adopted again, with whatever rows were planted
([design](design/0.16.md#still-to-design), "Losing the signer's storage").

How you know: the vault's log and the signer's `status` (`took`) say
`the signer's storage was empty: it took the database as it stands`, with
the time. A fresh install never says it, an upgrade from 0.14 says it
once, at its adoption, and a restore once, under its new name. At any
other time, the storage was lost.

What to do:

1. Stop traffic, as before any restore ([Before you restore](#before-you-restore)),
   and keep it stopped: the vault serves the database it took. When you
   know the loss is coming (a move to another account), stop it before.
2. Restore the last backup taken before the loss, as above, or compare the
   database with it, members, grants, roles and policy first, and put back
   by hand what differs.

Changes made after the backup are lost with a restore. Compare instead
when you must keep them.

## Going back after the upgrade from 0.14

The upgrade ([design](design/0.16.md#upgrade-from-014)) takes coffre offline
and backs up the 0.14 database before it migrates. That backup is the way
back, and 0.14.7's own CLI takes it, checks it and restores it: 0.16's
CLI cannot.

**At the upgrade, step 2**, once the two runtime logins are `NOLOGIN`:

```sh
printf '%s' "$BACKUP_URL" | npx coffre@0.14.7 backup coffre-0.14.7-$(date -u +%Y%m%dT%H%MZ).dump
printf '%s\n%s\n%s\n' "$SCRATCH_OWNER_URL" "$VAULT_KEY" "$APP_KEY" | npx coffre@0.14.7 verify backup coffre-0.14.7-….dump --keys
```

`verify backup --keys` restores the dump into an empty scratch database and
checks it against its manifest, walks the audit chain with every MAC, and
opens every value (0.14.7's `docs/restore.md`, "Checking a backup").
Run it on your own machine, never in a pipeline: it holds both keys. Upgrade
only once it passes.

**Going back**, once 0.16.0 has been deployed:

1. Take coffre offline: set the two runtime logins `NOLOGIN` and end their
   sessions. What 0.16 wrote since the upgrade is lost.
2. Restore into an empty database, as the owner, with 0.14.7's CLI:

   ```sh
   printf '%s\n%s\n%s\n' "$OWNER_URL_OF_COFFRE_RESTORED" "$VAULT_KEY" "$APP_KEY" | npx coffre@0.14.7 restore coffre-0.14.7-….dump --keys
   ```

   It checks what `verify backup` checks, and lists what is left to do.
3. Keep the signer's Durable Object class. 0.14.7's vault Worker exports no
   `CoffreSigner`, and its namespace stays bound
   (`vault/wrangler.jsonc`), so the deployment's own vault Worker exports
   one that does nothing, beside 0.14.7's code:

   ```ts
   // The signer's class, kept while 0.14.7 runs: 0.16 brings it back.
   import { DurableObject } from 'cloudflare:workers';
   export class CoffreSigner extends DurableObject {}
   ```

   Leave the binding and the migration in `vault/wrangler.jsonc` as 0.16
   wrote them. Cloudflare's documentation does not say what a deploy of a
   Worker that drops a class with a migration does under the `migrations`
   form coffre uses ([Durable Object migrations](https://developers.cloudflare.com/durable-objects/reference/durable-object-class-migrations-legacy/)),
   and its newer `exports` form refuses one
   (`orphaned_provisioned_namespace`, [Durable Object class exports](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/)).
   A `deleted_classes` migration would delete the class's every object and
   its storage, and the documentation does not say that a class deleted can
   be made again under its name: keeping the class needs neither.
4. Point both Hyperdrive configs at the restored database, and deploy
   0.14.7: the vault, then the app.
5. Set the two runtime logins `LOGIN`.
6. Check the result as 0.14.7's `docs/restore.md` says: `coffre@0.14.7 verify log`,
   a canary, `/readyz` checkpointed.

**Upgrading again** later is the upgrade from the start, with one change:
0.16's vault config names a new `signerName`. The old object signed 0.16's
first log, and refuses a database that shows none, so every call would be
answered 503 `adopting`; the new one is blank, and adopts it.

Rehearse the way back once, on a copy of the deployment on its own
Cloudflare account, before the upgrade.

## The local drill

`scripts/restore-drill.sh` runs the plain-Postgres restore end to end on
this machine, against the compose Postgres and its own `pg_dump` and
`pg_restore`, after `pnpm build`:

1. It builds the Workers example (as `coffre init` writes it) and starts it
   under `wrangler dev`, over a new database, `coffre_drill`, with the dev IdP for
   sign-in and `.env.dev`'s keys. It seeds it, writes a canary, grants a
   member access, removes another whose browser session it keeps, and issues
   a service token.
2. It backs the database up with `pg_dump`, as `coffre_backup_login`,
   which migrate granted `coffre_backup` (`--backup-login`).
3. It restores into `coffre_drill_restored` with `pg_restore`, runs migrate
   to reassert database privileges, and checks the app login's privileges.
4. It starts the example over the restored database with the same keys and
   a signer whose storage is new, as a new `signerName` gives, and checks:
   - members, owners, grants and the removed are exactly as backed up;
   - the canary reveals;
   - the removed member's kept session is refused, and they cannot sign in;
   - a new value writes and reads back;
   - the signer said it went on from the backup's head, its first check a
     minute on reports nothing, and the log has no hole: one entry per
     number, all of them counted by the head.
5. It restarts the example with a random vault key under the same id, and
   checks that its Owner cannot sign in, and that reading the canary and a
   new write, with the restored token, both answer 503.

It drops its databases and stops what it started, however it ends. It
does not drill a PlanetScale branch: there, the steps that differ are the
restore itself and the login names, and a physical restore brings back the
roles and database privileges. Nor does it drill the way back from the
upgrade, which is 0.14.7's own drill.

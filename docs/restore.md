# Restoring from a backup

Everything coffre knows is in one Postgres database: values (encrypted),
wrapped data keys, members and grants, sessions and tokens, and the audit
log with its head. A backup of that database and three keys bring all of it
back, including a log that verifies. This page says what to keep, how to
restore on PlanetScale Postgres or plain Postgres, how to check the result,
and what the local drill (`scripts/restore-drill.sh`) shows.

## What to keep, and where

| What | Where | Without it |
|---|---|---|
| The database | PlanetScale's backups, or `pg_dump` files you keep off the server | nothing to restore |
| The KEK, with its `KEK_ID`, and every earlier KEK still in `previousKeks` | your password manager, never beside the backups | no value can be read, ever: the backup holds only wrapped data keys |
| `SIGNING_KEY` (the vault) | your password manager | every member's row fails the vault's MAC, so the vault refuses everyone; its entries and checkpoints fail verification |
| `AUDIT_CHAIN_KEY` (the app) | your password manager | the app's entries, sessions and tokens fail their MACs: verification fails, and every session and token is refused |
| The OAuth client secret and the deployment's settings | your password manager and the deployment's repository | nobody can sign in |

With AWS KMS, the KEK is the key in KMS, not a value to escrow: keep the key
(and its alias) from being deleted, and the vault's IAM credentials in your
password manager. See [keys.md](keys.md).

Keep the keys apart from the backups. A backup alone opens nothing, and the
keys alone hold nothing; whoever has both has every value.

## Before you restore

Restore the whole database to one moment. coffre's guarantees hold between
the tables of one database at one point in time: members and grants, the log
that records them, the versions it names. Never restore some tables, or two
databases to different moments.

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
3. Set both runtime logins' passwords again, as the owner on the new branch,
   with new generated values from your password manager:

   ```sql
   \password coffre_runtime
   \password coffre_vault_runtime
   ```

4. Point both Hyperdrive configs at the new branch, each with its own login
   and the new branch id. Keep caching disabled:

   ```sh
   pnpm exec wrangler hyperdrive update <app config id> \
     --connection-string="postgres://coffre_runtime.<branch id>:…@<host>:5432/<database>"
   pnpm exec wrangler hyperdrive update <vault config id> \
     --connection-string="postgres://coffre_vault_runtime.<branch id>:…@<host>:5432/<database>"
   pnpm exec wrangler hyperdrive get <app config id>   # caching: disabled
   ```

5. Run `pnpm migrate` with the owner's URL for the new branch. It applies
   nothing to a backup of this release, the missing migrations to an older
   one, and refuses a database a newer release migrated.
6. Redeploy both Workers with `pnpm run deploy`, the same keys and settings:
   a fresh deployment remembers no log head.
7. Check the result, below, then reopen traffic. Promote the branch, or
   point production at it, as PlanetScale's branching docs describe.

## On plain Postgres

A `pg_dump` is a logical copy of one database: its tables, rows, privileges
and row-level policies, but not the cluster's roles or their passwords, and
not the privileges on the database itself. The restore puts those back by
hand. This is what the drill runs.

Back up, as the owner, as often as you can afford to lose:

```sh
pg_dump --format=custom --dbname="$OWNER_URL" --file=coffre-$(date -u +%Y%m%dT%H%MZ).dump
```

Restore:

1. Stop both components (or both Workers).
2. Create the runtime logins if this server lacks them, and set their
   passwords, as in [deploy.md](deploy.md#the-database-for-either-deployment):

   ```sql
   CREATE ROLE coffre_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   CREATE ROLE coffre_vault_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   \password coffre_runtime
   \password coffre_vault_runtime
   ```

   The group roles, `coffre_app` and `coffre_vault`, and the logins'
   membership in them must exist too: run `pnpm migrate` once against an
   empty database on this server if they do not.
3. Create an empty database owned by the owner, and restore into it:

   ```sh
   createdb --owner=coffre_owner coffre_restored
   pg_restore --exit-on-error --dbname="$OWNER_URL_OF_COFFRE_RESTORED" coffre-….dump
   ```

4. Take back what Postgres grants every new database, which the dump does
   not carry:

   ```sql
   REVOKE CREATE, TEMPORARY ON DATABASE coffre_restored
     FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime;
   ```

   Then check the app's login has exactly its privileges:

   ```sh
   COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="<coffre_runtime URL>" \
     pnpm --dir packages/db run db:verify:runtime
   ```

5. Run `pnpm migrate` with the owner's URL, as on PlanetScale.
6. Point both components at the restored database, each with its own login:
   both Hyperdrive configs on Workers, or `DATABASE_URL` in `server.env` and
   `vault.env` on Node. Keep the same keys and settings.
7. Restart both processes, or redeploy both Workers.

## Checking the result

Before reopening traffic:

1. `coffre verify`, as an owner or root admin. It must say `audit log OK`,
   verified through the newest entry, with the last checkpoint the backup
   held. It checks every link, both authors' MACs, every checkpoint against
   the prefix it signed, and replays the members and grants.
2. Reveal a canary: a secret kept for this, whose value you know.
3. Look at the Users page: members, owners, grants and the removed, as they
   were at the backup's moment. Someone removed before it stays removed, and
   their old sessions and tokens stay refused.
4. Write a value and read it back.
5. Wait for the next heartbeat, or trigger the Cron, then check `/readyz`:
   `ok`, with `checkpointed: true`. Right after a restore `/readyz` can be
   green on the backup's own last heartbeat, for up to eleven minutes; only
   a beat after the restore shows the restored instance writing and the
   vault signing.
6. Optionally, `coffre-conformance probe <url>` from outside, with a service
   token and the canary ([conformance.md](conformance.md)).

Verification proves the restored history is the one coffre wrote, up to the
backup's moment. It cannot show what was written after it: anything newer is
gone, and a complete older backup verifies as well as a recent one. See
[architecture.md](architecture.md#one-log-two-authors).

## If the KEK is wrong

With a KEK other than the one that wrapped the data keys, every value fails
closed: a reveal answers `403 vault_refused` with the reason `bad_claim`,
"the key does not belong to this secret", and the vault logs each refused
read. Nothing is opened, and nothing is changed. Verification and checkpoints
still pass: the log needs `SIGNING_KEY` and `AUDIT_CHAIN_KEY`, not the KEK.

`bad_claim` reads as though the wrapped key had been tampered with, so the
symptom to recognise is every value of every secret refused at once, while
verification passes. Stop, and restart the vault with the escrowed KEK and
its `KEK_ID`. Do not write values meanwhile: a write wraps its new data key
under whatever KEK the vault has.

## The local drill

`scripts/restore-drill.sh` runs the plain-Postgres restore end to end on
this machine, against the compose Postgres, after `pnpm build`:

1. It starts the Workers example (as `coffre init` writes it) under
   `wrangler dev`, over a new database, `coffre_drill`, with the dev IdP for
   sign-in and `.env.dev`'s keys. It seeds it, writes a canary, grants a
   member access, removes another whose browser session it keeps, issues a
   service token, and lets two heartbeats checkpoint the log.
2. It backs the database up with `pg_dump --format=custom`.
3. It restores into `coffre_drill_restored` as above, logins and database
   privileges included, and checks the app login's privileges.
4. It starts the example over the restored database with the same keys, and
   checks:
   - verification passes through the newest entry, and the backup's last
     checkpoint still holds;
   - members, owners, grants and the removed are exactly as backed up;
   - the canary reveals;
   - the removed member's kept session is refused, and they cannot sign in;
   - a new value writes and reads back, and the next beat checkpoints;
   - `coffre-conformance probe` passes, as no one and with the restored
     token, which reads the canary.
5. It restarts the example with a random KEK, and checks that the canary is
   refused while verification and checkpoints still pass.

It drops both databases and stops what it started, however it ends. It
does not drill a PlanetScale branch: there, the steps that differ are the
restore itself and the login names, and a physical restore brings back the
roles and database privileges this drill restores by hand.

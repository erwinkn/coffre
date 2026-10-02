# Restoring from a backup

Everything coffre knows is in one Postgres database: values (encrypted),
wrapped data keys, members and grants, sessions and tokens, and the audit
log with its head. A backup of that database and two keys bring all of it
back, including a log that verifies. This page says what to keep, how to
restore on PlanetScale Postgres or plain Postgres, how to check the result,
and what the local drill (`scripts/restore-drill.sh`) shows.

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
3. Set the logins up again on the new branch, with the owner's connection
   string for it, as when the deployment was made:

   ```sh
   npx @coffre/cli setup --reset-passwords
   ```

   It sets both runtime logins' passwords again, which the restore reset,
   and prints each login's new connection string, under the new branch id.
   It migrates: missing migrations are applied, and the database-level
   privileges reasserted, on every run, even when the schema is current; a
   database a newer release migrated is refused. It checks the boundary as
   each login. It makes no keys: the restored database has its own.
4. Point both Hyperdrive configs at the new branch, with the
   `wrangler hyperdrive update` commands it printed, and check that caching
   stays disabled:

   ```sh
   pnpm exec wrangler hyperdrive get <app config id>   # caching: disabled
   ```

   By hand, steps 3 and 4 are `\password` for both logins as the owner, the
   two updates with `coffre_runtime.<branch id>` and
   `coffre_vault_runtime.<branch id>`, and `pnpm migrate` with the owner's
   URL for the new branch.
5. Redeploy both Workers with `pnpm run deploy`, the same keys and settings:
   a fresh deployment remembers no log head.
6. Check the result, below, then reopen traffic. Promote the branch, or
   point production at it, as PlanetScale's branching docs describe.

## On plain Postgres

A `pg_dump` is a logical copy of one database: its tables, rows, privileges
and row-level policies, but not the cluster's roles or their passwords, and
not the privileges on the database itself. Provision the roles before
restoring; `pnpm migrate` reasserts the database privileges afterwards.
This is what the drill runs.

Back up, as the owner, as often as you can afford to lose:

```sh
pg_dump --format=custom --dbname="$OWNER_URL" --file=coffre-$(date -u +%Y%m%dT%H%MZ).dump
```

Restore:

1. Stop both components (or both Workers).
2. Create the runtime logins if this server lacks them, and set their
   passwords, as in [deploy.md](deploy.md#appendix-the-database-by-hand):

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

4. Run `pnpm migrate` with the owner's URL for the restored database:

   ```sh
   DATABASE_URL="$OWNER_URL_OF_COFFRE_RESTORED" pnpm migrate
   ```

   Besides applying missing migrations, every run revokes `CREATE` and
   `TEMPORARY` on that database from `PUBLIC`, both runtime logins and their
   group roles. This repairs the defaults a one-database dump leaves out,
   even when no schema migration is pending.
5. Check the app's login has exactly its privileges:

   ```sh
   COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="<coffre_runtime URL>" \
     pnpm --dir packages/db run db:verify:runtime
   ```

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
backup's moment. It cannot show what was written after it: a complete older
backup verifies as well as a recent one ([Limits](architecture.md#limits)).

## If the vault key is wrong

The messages below call the vault key by its technical name, the KEK
(key-encryption key), as its configuration does (`kek`, `previousKeks`).

With a local vault key, the vault's own keys come from it
([keys.md](keys.md#a-local-key)). A vault key other than the one that
wrapped the data, whether a mistyped key under the right `VAULT_KEY_ID` or
the wrong escrowed key, holds none of the keys the vault's entries were written under, which
the vault sees at its first call. It then writes nothing at all, and refuses
every key operation, reads and writes alike, and every change of access:

```
HTTP 503  {"error":"unavailable","reason":"wrong_kek",
           "message":"the vault's entries are under vault:3f1c…, a key this vault does not hold: it was given the wrong KEK or signing key, or a KEK it replaced is missing from previousKeks"}
```

The scheduled checkpoint is refused too, so `/readyz` turns red after the
next beat (`checkpointed: false`), and verification fails at the first
entry the vault wrote, which `coffre verify` explains:

```
written under vault:3f1c…, a key this verifier does not hold: either it is forged,
or the vault wrote it under another KEK or signing key, which must stay configured:
a KEK that was replaced stays in previousKeks
```

The same verdict, with the values under the new vault key readable, means a
vault key replaced and then dropped from `previousKeks`.

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
           "message":"this vault's aws-kms KEK arn:aws:kms:… does not open the data it holds: it is not the key that wrapped it"}
```

Either message names keys by id, never key material. Restart the vault with
the escrowed vault key and its `VAULT_KEY_ID`: the vault decides once per
process, so a restart is what clears it.

A vault key the vault cannot reach (KMS down, or refusing the vault's
credentials) is not a verdict: the call fails as any key operation does
during an outage, the next one asks again, and checkpoints go on. A vault
key under a new id is a rotation: its check value is recorded on first use,
and values wrapped under an id the vault is no longer given fail with "no
KEK configured for …". Keep earlier vault keys in `previousKeks`.

## The local drill

`scripts/restore-drill.sh` runs the plain-Postgres restore end to end on
this machine, against the compose Postgres, after `pnpm build`:

1. It starts the Workers example (as `coffre init` writes it) under
   `wrangler dev`, over a new database, `coffre_drill`, with the dev IdP for
   sign-in and `.env.dev`'s keys. It seeds it, writes a canary, grants a
   member access, removes another whose browser session it keeps, issues a
   service token, and lets two heartbeats checkpoint the log.
2. It backs the database up with `pg_dump --format=custom`.
3. It restores into `coffre_drill_restored`, provisions the logins, runs
   migrate to reassert database privileges, and checks the app login's
   privileges.
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
5. It restarts the example with a random vault key under the same id, and checks
   that the canary and a new write are both refused with `wrong_kek`, that
   verification fails at the vault's first entry and says why, and that
   `/readyz` turns red.

It drops both databases and stops what it started, however it ends. It
does not drill a PlanetScale branch: there, the steps that differ are the
restore itself and the login names, and a physical restore brings back the
roles and database privileges. The local drill provisions the roles and
reasserts database privileges through migrate.

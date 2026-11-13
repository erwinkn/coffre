import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { HOT_LOCK_TIMEOUT_MS, HOT_STATEMENT_TIMEOUT_MS, LOCK_WAIT_MS, RUNTIME_STATEMENT_TIMEOUT_MS } from '@coffre/core/vault';

import { checkDatabaseUrl } from './connect.ts';
import { lockNotAvailable } from './dialect.ts';
import { buildOnline, onlineIndex, onlineIndexes, unbuiltReason, valid, type OnlineIndex, type UnbuiltIndex } from './online-indexes.ts';
export { unbuiltNote, type UnbuiltIndex } from './online-indexes.ts';
import { postgresSession, quoteIdentifier, quoteLiteral, type PostgresClient } from './postgres.ts';

/**
 * Bring a database up to date with the migration tree, migrations/postgres.
 *
 * Applied history must be a prefix of the local journal, byte for byte,
 * before and after. Only one migrator runs at a time: it takes an
 * advisory lock. The restricted runtime roles are made in baseline/postgres.sql.
 *
 * coffre's objects have one owner: the role that owns the
 * `drizzle` schema, which the first migration made. The login applies the
 * migrations as itself, with its own attributes, which 0019's and 0022's
 * roles need (CREATEROLE), and with the privileges of the owners of
 * coffre's objects, which it must have; another is refused, NotOwner. What
 * it makes is its own, so in the migrations' transaction, before it
 * commits, each of coffre's objects whose owner's privileges the login has
 * is handed to the ledger's owner (`HANDED_OVER`): what this run made, and
 * what a member made before T193; a superuser has every role's. So a function the owner's functions call is the owner's too, and
 * needs no grant to them (0057's, 0058's, 0060's, 0064's and 0073's were
 * for a member that made its own, T187). Handing an object to a role asks a
 * login that may become it (SET ROLE): one that inherits the owner's
 * privileges but may not is refused too.
 */

const MIGRATION_LOCK_KEY = '7165058122361679213';

/**
 * The online builds' own lock (`online`), taken without waiting once the
 * migration lock is let go. A concurrent build waits for every transaction
 * older than it, a statement waiting for a lock included: built under the
 * migration lock, it would wait for another run's wait for that lock, which
 * waits for it, a deadlock (as two builds deploying at once, each Worker's,
 * would make). A run that finds another building leaves the builds to it, and says which are not built yet.
 */
export const ONLINE_LOCK_KEY = '7165058122361679214';

/**
 * How long each of a migration's statements waits for a lock, once the
 * migration lock is held: `LOCK_WAIT_MS` (`@coffre/core/vault`), half a
 * use's (`HOT_LOCK_TIMEOUT_MS`, the hot login's `lock_timeout`), as every
 * wait but a use's. Postgres
 * grants a table's locks in the order they were asked, so a DDL statement
 * waiting for a table that a long transaction holds queues every later
 * statement on that table behind it, a use's included. Leaving the queue
 * within half a use's own wait lets a use that queued behind it take its lock
 * with half its wait to spare, rather than be refused busy for the migration.
 * A statement that waits longer fails its transaction with 55P03, and the run
 * is tried again (`MIGRATION_LOCK_ATTEMPTS`). A migration's own changes to the
 * roles, which other databases' migrators may be changing too, wait as
 * briefly: they share the transaction that holds its tables.
 */
export const MIGRATION_LOCK_WAIT_MS = LOCK_WAIT_MS;

/**
 * Retry policy, not a constraint: how many times the migrations (all of them,
 * one transaction, as Drizzle runs them) are tried when a statement gave up
 * waiting for a lock, and the pause between tries, which holds no lock, so
 * uses run freely through it. Five tries a second apart outlast a holder of a
 * few seconds (a request's transaction, a vacuum of a small table) and give
 * up within about 7 s on one that will not end soon (a backup's `pg_dump`, a
 * session idle in a transaction), which whoever deploys must end or wait out.
 */
export const MIGRATION_LOCK_ATTEMPTS = 5;
export const MIGRATION_LOCK_PAUSE_MS = 1_000;

/**
 * How long a migrator waits for another migrator's run: this database's, for
 * the migration lock, or another database's of the same server, for the
 * roles' rows that reasserting the privileges changes, which the roles of
 * every database share. Neither wait holds a table, so no use queues behind
 * it. 5 minutes is history (277928a5, docs/design/limits.md D2), kept for the
 * waits that hold up no use.
 */
const OTHER_RUN_LOCK_TIMEOUT = '5min';

/**
 * The migrations gave up waiting for a lock `attempts` times: a session held
 * a table they change past `MIGRATION_LOCK_WAIT_MS` each time. The message
 * names the statement that waited, when the driver said which, and the
 * sessions holding coffre's tables when they gave up, as Postgres showed them
 * to this login (`holders`, null when they could not be read).
 */
export class LockWaitsExhausted extends Error {
  readonly attempts: number;
  readonly holders: LockHolder[] | null;

  constructor(attempts: number, holders: LockHolder[] | { unread: unknown }, cause: unknown) {
    const statement = failedStatement(cause);
    const held = Array.isArray(holders)
      ? holders.length > 0
        ? `Sessions holding coffre's tables: ${holders.map(holderInWords).join('; ')}. `
        : "No session held coffre's tables when they gave up. "
      : `Which sessions held coffre's tables could not be read: ${holders.unread instanceof Error ? holders.unread.message : String(holders.unread)}. `;
    super(
      `the migrations waited for a lock ${attempts} times, ${MIGRATION_LOCK_WAIT_MS} ms each, and gave up` +
        (statement === null ? '' : `, at ${statement}`) + '. ' + held +
        'Find the one holding the table (pg_locks, pg_stat_activity), wait for it to end or end it ' +
        "(SELECT pg_terminate_backend(<pid>), or ROLLBACK PREPARED '<name>' for a prepared transaction), then migrate again",
      { cause },
    );
    this.name = 'LockWaitsExhausted';
    this.attempts = attempts;
    this.holders = Array.isArray(holders) ? holders : null;
  }
}

/**
 * A session holding locks on coffre's tables, or a prepared transaction
 * (`pid` null, `prepared` its name), which holds its locks with no session.
 * `login` and `application` are null where Postgres hides them from this login.
 */
export type LockHolder = { pid: number | null; prepared: string | null; login: string | null; application: string | null; tables: string[] };

function holderInWords({ pid, prepared, login, application, tables }: LockHolder): string {
  const who = [login, application].filter((part) => part !== null && part !== '').join(', ');
  return `${pid === null ? `prepared transaction '${prepared}'` : `pid ${pid}`}${who === '' ? '' : ` (${who})`} on ${tables.join(', ')}`;
}

/**
 * The statement that failed, its first line of SQL, past the comments a
 * migration's statement may start with, when the driver or Drizzle said which.
 */
function failedStatement(error: unknown): string | null {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { query } = cause as { query?: unknown };
    const first = typeof query === 'string' ? query.split('\n').map((line) => line.trim()).find((line) => line !== '' && !line.startsWith('--')) : undefined;
    if (first !== undefined) return first.replace(/;$/, '');
  }
  return null;
}

/**
 * What holds locks on the tables of coffre's schemas in this database, but
 * this session, as pg_locks shows it: sessions, and prepared transactions,
 * whose locks have no pid, named by the transaction ID their virtual
 * transaction holds (PREPARE always assigns one). A day's partition is named
 * by its table (`log_uses`, not each `log_uses_<day>` a lock of the table
 * holds too).
 */
const LOCK_HOLDERS = `
  SELECT l.pid, p.gid AS prepared, coalesce(a.usename, p.owner)::text AS login, a.application_name AS application,
         array_agg(DISTINCT format('%I.%I', n.nspname, coalesce(t.relname, c.relname))) AS tables
    FROM pg_locks l
    JOIN pg_class c ON c.oid = l.relation
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_inherits i ON c.relispartition AND i.inhrelid = c.oid
    LEFT JOIN pg_class t ON t.oid = i.inhparent
    LEFT JOIN pg_stat_activity a ON a.pid = l.pid
    LEFT JOIN pg_prepared_xacts p ON l.pid IS NULL AND EXISTS (
      SELECT 1 FROM pg_locks x WHERE x.locktype = 'transactionid' AND x.pid IS NULL AND x.virtualtransaction = l.virtualtransaction AND x.transactionid = p.transaction)
   WHERE l.locktype = 'relation' AND l.granted AND l.pid IS DISTINCT FROM pg_backend_pid()
     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
     AND n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p')
   GROUP BY l.pid, p.gid, a.usename, p.owner, a.application_name, coalesce(a.xact_start, p.prepared)
   ORDER BY coalesce(a.xact_start, p.prepared) NULLS LAST, l.pid`;

/**
 * Reassert database privileges that pg_dump and CREATE DATABASE TEMPLATE do not carry and the hot path's login's
 * group and timeouts, clear the planner settings 0.15.0 gave the runtime logins, and give the app's and the vault's
 * logins their statement timeout where this login may: those it may not are `untimed` (`holdRuntimeTimeouts`).
 */
export async function restrictDatabase(client: Pick<PostgresClient, 'unsafe'>): Promise<{ untimed: string[] }> {
  await client.unsafe(`DO $$ BEGIN
    EXECUTE format(
      'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime, coffre_vault_hot, coffre_backup',
      current_database()
    );
  END $$`);
  await holdHotLogin(client);
  await clearPlannerSettings(client);
  return { untimed: await holdRuntimeTimeouts(client) };
}

/** The app's and the vault's logins' statement timeout as Postgres stores it: whole seconds, from `RUNTIME_STATEMENT_TIMEOUT_MS`. */
export const RUNTIME_SETTINGS = { statement_timeout: `${RUNTIME_STATEMENT_TIMEOUT_MS / 1000}s` } as const;

/**
 * Every value a release of coffre has given the runtime logins' `statement_timeout`: a role that holds one of them
 * holds coffre's, and a run moves it to today's (`RUNTIME_SETTINGS`); any other value is an administrator's, and stays.
 * So lowering `RUNTIME_STATEMENT_TIMEOUT_MS` moves every deployment's roles at its next migrate.
 */
const GIVEN_STATEMENT_TIMEOUTS: readonly string[] = ['60s'];

/**
 * Give the app's and the vault's logins (`logins` and `given`: the tests' own) their statement timeout, server-wide, as a
 * role's setting: to each that exists and has none of its own, or one coffre gave before (`GIVEN_STATEMENT_TIMEOUTS`),
 * where this login may alter the role (CREATEROLE and ADMIN on it, as `coffre setup`'s administrator has). Postgres
 * applies a role's setting at login, so the sessions of a login given it now are ended, those idle on this database,
 * and their pools reconnect with it; a query sent on one just as Postgres ends it fails once, as on a restart, and a
 * busy one takes it once its pool replaces it. Returns the logins this one may not give it, which the run says
 * (`untimedNote`). The roles are the server's, so a run on another database may be changing them too: Postgres fails
 * the second change, and it looks again once the first has committed.
 */
export async function holdRuntimeTimeouts(
  client: Pick<PostgresClient, 'unsafe'>,
  { logins, given: before }: { logins: readonly string[]; given: readonly string[] } = { logins: ['coffre_runtime', 'coffre_vault_runtime'], given: GIVEN_STATEMENT_TIMEOUTS },
): Promise<string[]> {
  const today = RUNTIME_SETTINGS.statement_timeout;
  const untimed: string[] = [];
  const given: string[] = [];
  for (const login of logins) {
    for (let attempt = 1; ; attempt += 1) {
      const [found] = await client.unsafe<{ exists: boolean; held: string | null }[]>(
        `SELECT to_regrole($1) IS NOT NULL AS exists,
                (SELECT substr(setting, length('statement_timeout=') + 1) FROM pg_db_role_setting s, unnest(s.setconfig) AS setting
                  WHERE s.setrole = to_regrole($1) AND s.setdatabase = 0 AND split_part(setting, '=', 1) = 'statement_timeout') AS held`,
        [login],
      );
      if (!found!.exists || found!.held === today || (found!.held !== null && !before.includes(found!.held))) break;
      try {
        await client.unsafe(`ALTER ROLE ${quoteIdentifier(login)} SET statement_timeout = '${today}'`);
        given.push(login);
        break;
      } catch (error) {
        const code = (error as { code?: string }).code;
        if (code === '42501') {
          untimed.push(login);
          break;
        }
        // Another database's run changing the same role: Postgres fails the second (XX000, or 23505 for a new row).
        if ((code !== 'XX000' && code !== '23505') || attempt === 5) throw error;
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }
  }
  if (given.length > 0) {
    await client.unsafe(`DO $$ DECLARE
      idle int;
    BEGIN
      FOR idle IN SELECT pid FROM pg_stat_activity
                   WHERE usename = ANY(ARRAY[${given.map(quoteLiteral).join(', ')}]::text[]) AND datname = current_database() AND state = 'idle' LOOP
        BEGIN
          PERFORM pg_terminate_backend(idle);
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
      END LOOP;
    END $$`);
  }
  return untimed;
}

/** What a run whose login may not give the runtime logins their statement timeout says, for whoever migrates; null when none is left. */
export function untimedNote(untimed: readonly string[]): string | null {
  if (untimed.length === 0) return null;
  const one = untimed.length === 1;
  const statements = untimed.map((login) => `ALTER ROLE ${login} SET statement_timeout = '${RUNTIME_SETTINGS.statement_timeout}';`).join(' ');
  return (
    `${untimed.join(' and ')} ${one ? 'lacks' : 'lack'} coffre's statement timeout, ${RUNTIME_SETTINGS.statement_timeout}, which this login may not give ${one ? 'it' : 'them'}. ` +
    `coffre works without it; to bound a stuck statement, have a login with CREATEROLE and ADMIN on ${one ? 'it' : 'them'} run, once per server: ${statements} (docs/deploy.md, "Statement timeouts")`
  );
}

/**
 * The hot path's login's timeouts as Postgres stores and reports them (`pg_db_role_setting`, `SHOW`): whole seconds,
 * from `HOT_LOCK_TIMEOUT_MS` and `HOT_STATEMENT_TIMEOUT_MS` (`@coffre/core/vault`), as 0022 wrote them.
 */
export const HOT_SETTINGS = { lock_timeout: `${HOT_LOCK_TIMEOUT_MS / 1000}s`, statement_timeout: `${HOT_STATEMENT_TIMEOUT_MS / 1000}s` } as const;

/**
 * What 0022 gives `coffre_vault_hot`, given again when it lacks it: its
 * membership in coffre_vault, inherited, and its lock and statement
 * timeouts. A role dropped and made again, as `coffre
 * setup` makes a missing one, has none of them, and 0022 never runs
 * twice. So whatever 0022 refuses, this refuses too: a role made again
 * may be anyone's. Unsafe attributes, objects it owns, a membership in
 * another role, one of any grantor that may set or grant coffre_vault
 * (which would let it hand the vault's rights to the app's login), and a
 * setting of its own for this database alone, which would outrank the
 * server-wide one at login. Then only what differs, and refused, saying
 * what to run, to a login that may not change the role or grant the group.
 */
export async function holdHotLogin(client: Pick<PostgresClient, 'unsafe'>): Promise<void> {
  await client.unsafe(`DO $$ DECLARE
    held text[];
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot') THEN
      RAISE EXCEPTION 'coffre_vault_hot does not exist, though 0022 made it: run coffre setup, which makes it a login, or have a login with CREATEROLE run CREATE ROLE coffre_vault_hot NOLOGIN, then migrate again';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot' AND (rolsuper OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'coffre_vault_hot has unsafe role attributes: SUPERUSER, REPLICATION and BYPASSRLS must be off';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass AND refobjid = 'coffre_vault_hot'::regrole AND deptype = 'o') THEN
      RAISE EXCEPTION 'coffre_vault_hot owns database objects';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid <> 'coffre_vault'::regrole) THEN
      RAISE EXCEPTION 'coffre_vault_hot is a member of a role other than coffre_vault: revoke its memberships';
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid = 'coffre_vault'::regrole AND (set_option OR admin_option)
    ) THEN
      RAISE EXCEPTION 'coffre_vault_hot may set or grant coffre_vault: have its grantor run REVOKE coffre_vault FROM coffre_vault_hot, then migrate again';
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS setting
       WHERE s.setrole = 'coffre_vault_hot'::regrole AND s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
         AND split_part(setting, '=', 1) IN ('lock_timeout', 'statement_timeout')
    ) THEN
      RAISE EXCEPTION 'coffre_vault_hot has its own lock_timeout or statement_timeout in this database, over the hot path''s: run ALTER ROLE coffre_vault_hot IN DATABASE % RESET ALL, then migrate again', quote_ident(current_database());
    END IF;
    -- The role is the server's, as clearPlannerSettings' logins are: a run on another database may be changing it too, and fails the second change.
    FOR attempt IN 1..5 LOOP
      BEGIN
        SELECT setconfig INTO held FROM pg_db_role_setting WHERE setrole = 'coffre_vault_hot'::regrole AND setdatabase = 0;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot' AND (NOT rolinherit OR rolcreatedb OR rolcreaterole)) THEN
          ALTER ROLE coffre_vault_hot INHERIT NOCREATEDB NOCREATEROLE;
        END IF;
        IF NOT coalesce(held @> ARRAY['lock_timeout=${HOT_SETTINGS.lock_timeout}'], false) THEN ALTER ROLE coffre_vault_hot SET lock_timeout = '${HOT_SETTINGS.lock_timeout}'; END IF;
        IF NOT coalesce(held @> ARRAY['statement_timeout=${HOT_SETTINGS.statement_timeout}'], false) THEN ALTER ROLE coffre_vault_hot SET statement_timeout = '${HOT_SETTINGS.statement_timeout}'; END IF;
        IF NOT EXISTS (
          SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid = 'coffre_vault'::regrole AND inherit_option
        ) THEN
          GRANT coffre_vault TO coffre_vault_hot WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
        END IF;
        EXIT;
      EXCEPTION
        WHEN insufficient_privilege THEN
          RAISE EXCEPTION '% may not make coffre_vault_hot what 0.15 needs (%): have a login with CREATEROLE and ADMIN on both roles run ALTER ROLE coffre_vault_hot INHERIT NOCREATEDB NOCREATEROLE; ALTER ROLE coffre_vault_hot SET lock_timeout = ''${HOT_SETTINGS.lock_timeout}''; ALTER ROLE coffre_vault_hot SET statement_timeout = ''${HOT_SETTINGS.statement_timeout}''; GRANT coffre_vault TO coffre_vault_hot WITH ADMIN FALSE, INHERIT TRUE, SET FALSE first', current_user, SQLERRM;
        WHEN internal_error OR unique_violation THEN
          IF attempt = 5 THEN RAISE; END IF;
          PERFORM pg_sleep(0.2);
      END;
    END LOOP;
  END $$`);
}

/**
 * Clear what 0.15.0 set on the runtime logins, server-wide: `jit = off` on
 * each, and `plan_cache_mode = force_generic_plan` on the hot login alone
 * (`logins` and `hot`: the tests' own roles). From 0.16.0 every statement plans
 * and runs at the server's settings (0068, docs/design/planner-defaults.md).
 *
 * Only those values on those logins, which coffre set (an administrator's
 * own setting of either stays, generic plans on another login included),
 * and only when this login may alter the role: CREATEROLE and
 * ADMIN on it, as `coffre setup`'s administrator has. A login that only
 * migrates leaves them, as 0.15.0 ran with them, and docs/deploy.md says
 * what to run. The rows are the server's, and the migration lock each
 * database's, so a run on another database may be changing them too:
 * Postgres fails the second change (a concurrent update, or a duplicate
 * key), and it looks again once the first has committed.
 */
export async function clearPlannerSettings(
  client: Pick<PostgresClient, 'unsafe'>,
  { logins, hot }: { logins: readonly string[]; hot: string } = { logins: ['coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot'], hot: 'coffre_vault_hot' },
): Promise<void> {
  const held = [...logins.map((login) => [login, 'jit']), [hot, 'plan_cache_mode']];
  await client.unsafe(
    `DO $$ DECLARE
      held record;
    BEGIN
      FOR held IN SELECT * FROM (VALUES ${held.map(([login, setting]) => `('${login}', '${setting}')`).join(', ')}) AS held(login, setting) LOOP
        CONTINUE WHEN to_regrole(held.login) IS NULL;
        FOR attempt IN 1..5 LOOP
          -- The cast is only of a jit row's: off however the boolean is spelled.
          EXIT WHEN NOT EXISTS (
            SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS entry
             WHERE s.setrole = held.login::regrole AND s.setdatabase = 0
               AND CASE WHEN held.setting = 'jit' AND split_part(entry, '=', 1) = 'jit' THEN substr(entry, 5)::boolean IS FALSE
                        WHEN held.setting = 'plan_cache_mode' THEN entry = 'plan_cache_mode=force_generic_plan'
                        ELSE false END);
          BEGIN
            EXECUTE format('ALTER ROLE %I RESET %I', held.login, held.setting);
            EXIT;
          EXCEPTION
            WHEN insufficient_privilege THEN EXIT;
            WHEN internal_error OR unique_violation THEN
              IF attempt = 5 THEN RAISE; END IF;
              PERFORM pg_sleep(0.2);
          END;
        END LOOP;
      END LOOP;
    END $$`,
  );
}

/** Why `login` cannot be the backup login, before anything runs, or null when it may. */
export function backupLoginProblem(login: string): string | null {
  if (login === '') return 'the backup login is empty: name the role to grant coffre_backup';
  if (['coffre_backup', 'coffre_app', 'coffre_vault', 'coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot'].includes(login)) {
    return `the backup login is ${login}, one of coffre's own roles: name the login that backs up`;
  }
  return null;
}

/**
 * The migrations are applied, by this run or an earlier one, and their
 * ledger checked, but what follows them failed: reasserting the privileges,
 * or building an index online (`online-indexes.ts`). Unlike a migration's
 * failure, this one may have changed the database.
 */
export class AfterMigrations extends Error {
  constructor(error: unknown, what = 'reasserting its privileges') {
    super(`the database is at the migrated schema, but ${what} failed: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    this.name = 'AfterMigrations';
  }
}

/**
 * Postgres refused to hand one of coffre's objects to the ledger's owner, in
 * the migrations' transaction, which it rolled back: `statement` says which
 * object, and to whom.
 */
export class HandOverFailed extends Error {
  readonly statement: string;

  constructor(statement: string, error: unknown) {
    super(`handing coffre's objects to the owner of its ledger failed, at ${statement}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    this.name = 'HandOverFailed';
    this.statement = statement;
  }
}

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

interface ExpectedMigration {
  createdAt: string;
  hash: string;
  tag: string;
  sql: string;
}

interface AppliedMigration {
  created_at: string;
  hash: string;
}

/** A connection that applies the tree. */
interface Migrator {
  /** The applied history, oldest first, or null before the first migration. */
  applied(): Promise<AppliedMigration[] | null>;
  lock(): Promise<void>;
  unlock(): Promise<void>;
  /** Apply `pending`, in one transaction, which hands `managed` to the ledger's owner before it commits. */
  migrate(pending: ExpectedMigration[], managed: Managed): Promise<void>;
  /** Reassert privileges a one-database backup does not carry, and grant `backupLogin` the backup group (0019_backup_role.sql). */
  restrict(backupLogin: string | undefined): Promise<{ untimed: string[] }>;
  /** Build each of `indexes` not built yet, without blocking writes (`online-indexes.ts`): those it left, and why. */
  online(indexes: readonly OnlineIndex[]): Promise<UnbuiltIndex[]>;
  /** Why this login cannot change the objects migrations change, `managed` among them, or hand them to their owner, or null when it can. */
  notOwner(managed: Managed): Promise<NotOwner | null>;
  /** Whether the database's log holds 0.15's cutover change (`requireCutOver`). */
  cutOver(): Promise<boolean>;
  close(): Promise<void>;
}

/**
 * An owner of coffre's objects whose privileges the login lacks: not a
 * member of it, or one that does not inherit them. `memberOfLogin`: it is
 * a member of the login, which granting it to the login would make a cycle.
 * `ownsLedger`: it owns the drizzle schema, so the hand-over gives it the
 * rest.
 */
export type ForeignOwner = { name: string; member: boolean; memberOfLogin?: boolean; ownsLedger?: boolean };

/**
 * The login cannot change coffre's objects, the ledger's schema, the tables
 * and the functions: their owners are roles whose privileges it does not
 * have, as neither one of them nor a member of one that inherits them.
 * Postgres would refuse the first migration that touches one, "permission
 * denied for schema drizzle"; this says whose login migrates, or what makes
 * this one able to: on Postgres 16 and later, a membership that inherits,
 * which each one's GRANT says; before, a membership, and a login that
 * inherits (`ALTER ROLE … INHERIT`).
 *
 * An owner that is a member of the login (a member that migrated before
 * T193, when the login is the ledger's owner) cannot be granted to it: its
 * own login, or a superuser's, migrating once hands its objects to the
 * ledger's owner. Unless it is the ledger's owner, as a member's first run
 * of a fresh database makes it: then it is coffre's owner, whose login
 * migrates. One that inherits the ledger's owner's privileges but may
 * not become it, a membership `WITH SET FALSE` (`settable`), could not hand
 * it what it makes, and is told the GRANT that lets it.
 */
export class NotOwner extends Error {
  readonly login: string;
  readonly owners: ForeignOwner[];

  constructor(
    login: string,
    owners: ForeignOwner[],
    { grantsInherit, inherits, settable = true }: { grantsInherit: boolean; inherits: boolean; settable?: boolean },
  ) {
    const one = owners.length === 1;
    const members = owners.every((owner) => owner.member);
    const grantable = owners.filter((owner) => !owner.memberOfLogin);
    const ungrantable = owners.filter((owner) => owner.memberOfLogin);
    const ledger = ungrantable.find((owner) => owner.ownsLedger);
    const whose = (some: ForeignOwner[]) => (some.length === 1 ? `${some[0]!.name}'s` : 'their');
    const fixes = settable
      ? [
          ...grantable.filter((owner) => grantsInherit || !owner.member).map((owner) => `GRANT ${identifier(owner.name)} TO ${identifier(login)}${grantsInherit ? ' WITH INHERIT TRUE' : ''}`),
          ...(grantsInherit || inherits ? [] : [`ALTER ROLE ${identifier(login)} INHERIT`]),
        ]
      : owners.map((owner) => `GRANT ${identifier(owner.name)} TO ${identifier(login)} WITH SET TRUE`);
    const handOver = `migrate once with ${whose(ungrantable)} connection string, or a superuser's, which hands ${ungrantable.length === 1 ? 'its' : 'their'} objects to the owner of coffre's ledger`;
    super(
      `coffre's tables are owned by ${owners.map((owner) => owner.name).join(' and ')}, and this login, ${login}, ` +
        (!settable
          ? `inherits ${one ? 'its' : 'their'} privileges but may not become ${one ? 'it' : 'them'} (SET ROLE), which handing ${one ? 'it' : 'them'} what the migrations make asks: `
          : members
            ? `is a member of ${one ? 'it' : 'them'} but does not inherit ${one ? 'its' : 'their'} privileges: `
            : `is neither ${one ? 'it nor a member of it' : 'one nor a member of one'}: `) +
        (ledger !== undefined
          ? `coffre's ledger, the drizzle schema, is ${ledger.name}'s, a member of this login, which makes ${ledger.name} the owner of coffre's objects: ` +
            (one
              ? `migrate with ${ledger.name}'s connection string`
              : `migrate once with a superuser's connection string, which hands ${owners
                  .filter((owner) => owner !== ledger)
                  .map((owner) => `${owner.name}'s`)
                  .join(' and ')} objects to ${ledger.name}, then with ${ledger.name}'s`)
          : grantable.length === 0
            ? handOver
            : `migrate with ${whose(grantable)} connection string, or, as a role that administers ${grantable.length === 1 ? 'it' : 'them'}, run ${fixes.join('; ')}` +
              (ungrantable.length === 0 ? '' : `; and, for ${ungrantable.map((owner) => owner.name).join(' and ')}, ${ungrantable.length === 1 ? 'a member' : 'members'} of this login, ${handOver}`)),
    );
    this.name = 'NotOwner';
    this.login = login;
    this.owners = owners;
  }
}

/** A role's name as SQL takes it: always quoted, as a keyword such as `user` must be. */
function identifier(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/** What coffre's migrations make and so change later: relations, functions and types, by name, in public. */
type Managed = { relations: string[]; functions: string[]; types: string[] };

/**
 * The names a migration's SQL makes: CREATE TABLE, VIEW, MATERIALIZED VIEW
 * and SEQUENCE, the new name of ALTER TABLE … RENAME TO, CREATE FUNCTION,
 * and CREATE TYPE, in public. Unquoted, a name is folded to lower case, as
 * Postgres folds it. A name followed by a dot is a schema's, never the
 * object's: `CREATE TABLE public.%I`, in the SQL a function runs (0022,
 * 0049), makes no table named public. A renamed table's old name stays
 * among them: 0076 keeps it, a view, one release (T178).
 */
export function managedObjects(sqlTexts: readonly string[]): Managed {
  const name = String.raw`(?:"?public"?\.)?(?:"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_$]*))(?![A-Za-z0-9_$"]|\s*\.)`;
  const relation = new RegExp(String.raw`\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:UNLOGGED\s+)?(?:TABLE|VIEW|MATERIALIZED\s+VIEW|SEQUENCE)\s+(?:IF\s+NOT\s+EXISTS\s+)?${name}`, 'gi');
  // The table renamed, by a name captured nowhere: the new one is what it makes.
  const any = String.raw`(?:"?public"?\.)?(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
  const renamed = new RegExp(String.raw`\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?${any}\s+RENAME\s+TO\s+${name}`, 'gi');
  const fn = new RegExp(String.raw`\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+${name}\s*\(`, 'gi');
  const type = new RegExp(String.raw`\bCREATE\s+TYPE\s+${name}`, 'gi');
  const names = (...patterns: RegExp[]) => [
    ...new Set(sqlTexts.flatMap((text) => patterns.flatMap((pattern) => [...text.matchAll(pattern)].map(([, quoted, bare]) => (quoted !== undefined ? quoted.replace(/""/g, '"') : bare!.toLowerCase()))))),
  ];
  return { relations: names(relation, renamed), functions: names(fn), types: names(type) };
}

/**
 * coffre's relations, as a recursive CTE, `relations`: the drizzle schema's,
 * and in public those coffre's migrations make ($1), and nothing else of
 * public, which may hold a database's other tables; each partition below
 * one, which a day's table is (0022, 0049); and retention's detached tables,
 * by the names its functions give and drop (0027's `drop_day` and
 * `drop_tiles`, which take a table of such a name without a parent for one
 * they detached), which no longer have a parent to be found by.
 */
const RELATIONS = String.raw`relations AS (
    SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
       AND (n.nspname = 'drizzle' OR (n.nspname = 'public' AND (c.relname = ANY($1::text[])
         OR (c.relkind = 'r' AND (c.relname ~ '^log_uses_\d{8}$' OR c.relname ~ '^log_tiles_uses_\d+$')))))
    UNION
    SELECT i.inhrelid FROM pg_inherits i JOIN relations r ON r.oid = i.inhparent
  )`;

/**
 * The owners of what migrations change, whose privileges the login lacks:
 * the drizzle schema, coffre's relations (`RELATIONS`) and the statistics
 * objects on them (0065, 0067), and in public the functions and types
 * coffre's migrations make ($2, $3). A superuser has every role's. Whether
 * each is a member of the login (`member_of_login`), whom it cannot then be
 * granted to, and whether it owns the ledger (`owns_ledger`).
 */
const FOREIGN_OWNERS = `
  WITH RECURSIVE ${RELATIONS}, owned AS (
    SELECT nspowner AS owner FROM pg_namespace WHERE nspname = 'drizzle'
    UNION ALL
    SELECT c.relowner FROM relations JOIN pg_class c USING (oid)
    UNION ALL
    SELECT s.stxowner FROM relations JOIN pg_statistic_ext s ON s.stxrelid = relations.oid
    UNION ALL
    SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = ANY($2::text[])
    UNION ALL
    SELECT t.typowner FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'public' AND t.typname = ANY($3::text[])
  )
  SELECT DISTINCT r.rolname AS owner, pg_has_role(owned.owner, 'MEMBER') AS member,
    pg_has_role(owned.owner, (SELECT oid FROM pg_roles WHERE rolname = current_user), 'MEMBER') AS member_of_login,
    owned.owner = (SELECT nspowner FROM pg_namespace WHERE nspname = 'drizzle') AS owns_ledger,
    current_user AS login, current_setting('server_version_num')::int >= 160000 AS grants_inherit,
    (SELECT rolinherit FROM pg_roles WHERE rolname = current_user) AS inherits
  FROM owned JOIN pg_roles r ON r.oid = owned.owner
  WHERE NOT pg_has_role(owned.owner, 'USAGE')
  ORDER BY r.rolname`;

/**
 * The ledger's owner, when it is another role whose privileges the login
 * has (null before the first migration, or when it is the login, or one
 * whose privileges `FOREIGN_OWNERS` says it lacks), and whether the login
 * may become it, as handing it an object asks (`SET` from Postgres 16, any
 * membership before; a superuser may become any role).
 */
const LEDGER_OWNER = `
  SELECT r.rolname AS owner, pg_has_role(r.oid, 'MEMBER') AS member,
    CASE WHEN current_setting('server_version_num')::int >= 160000 THEN pg_has_role(r.oid, 'SET') ELSE pg_has_role(r.oid, 'MEMBER') END AS settable,
    current_setting('server_version_num')::int >= 160000 AS grants_inherit,
    (SELECT rolinherit FROM pg_roles WHERE rolname = current_user) AS inherits
  FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
  WHERE n.nspname = 'drizzle' AND r.rolname <> current_user AND pg_has_role(r.oid, 'USAGE')`;

/**
 * What hands the ledger's owner each of coffre's objects that is another
 * role's, whose privileges the login has (its own, a role it is a member
 * of, or any, for a superuser), one statement each: coffre's relations
 * (`RELATIONS`, $1) but the sequences their columns own, the statistics
 * objects on them, and its functions and types ($2, $3). An ALTER of a
 * table moves its indexes and those sequences, but none of its partitions,
 * which are relations of their own here, nor its statistics objects
 * (`CREATE STATISTICS`, 0065, 0067), which are their maker's. The ACLs move with them, grants by the old owner becoming the new
 * one's, so a grant 0057 made the owner of a helper a member had made is
 * folded into the owner's own.
 */
const HANDED_OVER = `
  WITH RECURSIVE ${RELATIONS}, ledger AS (
    SELECT n.nspowner AS oid, r.rolname AS name FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'drizzle'
  )
  SELECT format('ALTER %s %s OWNER TO %I',
      CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE' WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END,
      c.oid::regclass, ledger.name) AS statement
    FROM relations JOIN pg_class c USING (oid), ledger
    WHERE c.relowner <> ledger.oid AND pg_has_role(c.relowner, 'USAGE')
      AND NOT (c.relkind = 'S' AND EXISTS (
        SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')))
  UNION ALL
  SELECT format('ALTER STATISTICS %I.%I OWNER TO %I', n.nspname, s.stxname, ledger.name)
    FROM relations JOIN pg_statistic_ext s ON s.stxrelid = relations.oid JOIN pg_namespace n ON n.oid = s.stxnamespace, ledger
    WHERE s.stxowner <> ledger.oid AND pg_has_role(s.stxowner, 'USAGE')
  UNION ALL
  SELECT format('ALTER ROUTINE %s OWNER TO %I', p.oid::regprocedure, ledger.name) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, ledger
    WHERE n.nspname = 'public' AND p.proname = ANY($2::text[]) AND p.proowner <> ledger.oid AND pg_has_role(p.proowner, 'USAGE')
  UNION ALL
  SELECT format('ALTER TYPE %s OWNER TO %I', t.oid::regtype, ledger.name) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace, ledger
    WHERE n.nspname = 'public' AND t.typname = ANY($3::text[]) AND t.typowner <> ledger.oid AND pg_has_role(t.typowner, 'USAGE')`;

/**
 * Beside this module: src/migrations in the workspace, and dist/migrations
 * in the built package, where the build copies them.
 */
export function migrationsFolder(): string {
  return fileURLToPath(new URL('./migrations/postgres', import.meta.url));
}

async function expectedMigrations(): Promise<ExpectedMigration[]> {
  const folder = migrationsFolder();
  const journal = JSON.parse(await readFile(`${folder}/meta/_journal.json`, 'utf8')) as { entries?: JournalEntry[] };
  if (!Array.isArray(journal.entries)) {
    throw new Error('invalid Drizzle migration journal');
  }

  const expected = await Promise.all(
    journal.entries.map(async (entry, position) => {
      if (
        entry.idx !== position
        || !Number.isSafeInteger(entry.when)
        || typeof entry.tag !== 'string'
        || !/^[a-zA-Z0-9_-]+$/.test(entry.tag)
      ) {
        throw new Error(`invalid Drizzle migration journal entry at index ${position}`);
      }
      const sqlText = await readFile(`${folder}/${entry.tag}.sql`, 'utf8');
      return {
        createdAt: String(entry.when),
        hash: createHash('sha256').update(sqlText).digest('hex'),
        tag: entry.tag,
        sql: sqlText,
      };
    }),
  );

  for (let index = 1; index < expected.length; index += 1) {
    if (BigInt(expected[index - 1].createdAt) >= BigInt(expected[index].createdAt)) {
      throw new Error('Drizzle migration journal timestamps must be strictly increasing');
    }
  }
  return expected;
}

/**
 * A database a newer coffre migrated: it has applied every migration this
 * version knows, and more. The ledger keeps no names, so each one it does not
 * know is named by when it was made and its hash.
 */
export class DatabaseAhead extends Error {
  readonly known: string[];
  readonly unknown: { createdAt: string; hash: string }[];

  constructor(known: string[], unknown: { createdAt: string; hash: string }[]) {
    const made = unknown.map(({ createdAt, hash }) => `one made ${new Date(Number(createdAt)).toISOString().slice(0, 16).replace('T', ' ')} UTC (${hash.slice(0, 12)})`);
    super(
      `the database has applied ${unknown.length === 1 ? 'a migration' : `${unknown.length} migrations`} this version does not know, ` +
        `after ${known.at(-1) ?? 'none'}: ${made.join(', ')}. A newer coffre migrated it`,
    );
    this.name = 'DatabaseAhead';
    this.known = known;
    this.unknown = unknown;
  }
}

/** The release whose baseline every database since was made from. */
const CLEAN_BREAK = '0.4.0';

/**
 * Migrations rewritten after a release, by tag: the hashes of their earlier
 * texts, which a database that applied one keeps in its ledger. A rewrite
 * changes only what a database yet to apply it would do. 0022 gave the hot
 * login generic plans until 0.16.0; once a run had cleared them, a login
 * without ADMIN on the role could no longer migrate another database of the
 * server through it (T207, docs/design/planner-defaults.md).
 */
const REWRITTEN: Readonly<Record<string, readonly string[]>> = {
  '0022_log_015': ['738dd033a0339eac8218494a5cc43568c1b06ad363cd2aa3c0dfc9c82570a2da'],
};

function verifyHistory(
  expected: ExpectedMigration[],
  applied: AppliedMigration[] | null,
  requireComplete: boolean,
): void {
  const rows = applied ?? [];
  rows.slice(0, expected.length).forEach((row, index) => {
    const local = expected[index]!;
    if (row.created_at !== local.createdAt || (row.hash !== local.hash && !REWRITTEN[local.tag]?.includes(row.hash))) {
      // 0.4.0 began again from one baseline: a database from before it is not upgraded, but made afresh.
      if (index === 0) throw new Error(`the database was made by a coffre before ${CLEAN_BREAK}, which is a clean break: deploy afresh, on a new database (docs/deploy.md)`);
      throw new Error(
        `migration history diverged at ${local.tag}; applied migrations must never be edited`,
      );
    }
  });
  if (rows.length > expected.length) {
    throw new DatabaseAhead(expected.map((entry) => entry.tag), rows.slice(expected.length).map((row) => ({ createdAt: row.created_at, hash: row.hash })));
  }
  if (requireComplete && rows.length !== expected.length) {
    throw new Error(`migration history is incomplete: expected ${expected.length}, found ${rows.length}`);
  }
}

/** The last migration of 0.15.0, the one release 0.16 upgrades from (D197). */
const UPGRADES_FROM = '0049_reads';

/**
 * Refuse a database this version cannot upgrade: it has no code that cuts a
 * log over from 0.14, which 0.15.0's vault does at its first start. So a
 * database a release before 0.15.0 made steps through 0.15.0 first, and
 * 0.15.0's own is migrated only once its log holds the cutover's change. A
 * new database has nothing to cut over, and one past 0.15.0's migrations was
 * migrated by this version or a later one (the migrations of a run commit
 * together).
 */
async function requireCutOver(expected: readonly ExpectedMigration[], done: number, migrator: Migrator): Promise<void> {
  const at = expected.findIndex((entry) => entry.tag === UPGRADES_FROM);
  // A journal without 0.15.0's last migration would wave every database through: refused instead.
  if (at < 0) throw new Error(`the migrations have no ${UPGRADES_FROM}, 0.15.0's last: this version cannot tell which databases it upgrades`);
  const release = at + 1;
  if (done === 0 || done > release) return;
  if (done < release) {
    throw new Error(
      'the database was made by a coffre before 0.15.0, which this version does not upgrade from: ' +
        "upgrade it to 0.15.0 and start it once, so that its vault moves the audit log to 0.15's, then to this version (docs/deploy.md)",
    );
  }
  if (!(await migrator.cutOver())) {
    throw new Error(
      "the database's audit log is not moved to 0.15's yet, which 0.15.0's vault does at its first start: " +
        'start 0.15.0 once, then migrate to this version (docs/deploy.md)',
    );
  }
}

async function postgresMigrator(url: string): Promise<Migrator> {
  // One session: the advisory lock and lock_timeout are the session's, and a statement after it is lost fails.
  const client = postgresSession(url, { application_name: 'coffre-migrations' });
  const buildAll = async (indexes: readonly OnlineIndex[]): Promise<UnbuiltIndex[]> => {
    const unbuilt: UnbuiltIndex[] = [];
    const session = {
      client,
      briefly: <T>(run: () => Promise<T>) => waitingBriefly(client, run),
      waitShort: async () => void (await client.unsafe(`SET lock_timeout = '${MIGRATION_LOCK_WAIT_MS}ms'`)),
      // A concurrent build waits for every transaction older than it, an open backup's included, and queues no
      // write behind it meanwhile: it waits as long as for another run.
      waitLong: async () => void (await client.unsafe(`SET lock_timeout = '${OTHER_RUN_LOCK_TIMEOUT}'`)),
    };
    for (const index of indexes) {
      try {
        await buildOnline(session, index);
      } catch (error) {
        const reason = unbuiltReason(error);
        if (reason === null) throw error;
        unbuilt.push({ name: index.name, table: index.table, reason });
      }
    }
    return unbuilt;
  };
  return {
    async applied() {
      const [found] = await client.unsafe<{ relation: string | null }[]>(
        "SELECT to_regclass('drizzle.__drizzle_migrations')::text AS relation",
      );
      if (!found?.relation) return null;
      return [...await client.unsafe<AppliedMigration[]>(
        'SELECT hash, created_at::text FROM drizzle.__drizzle_migrations ORDER BY created_at, id',
      )];
    },
    async lock() {
      await client.unsafe(`SET lock_timeout = '${OTHER_RUN_LOCK_TIMEOUT}'`);
      await client.unsafe('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_KEY]);
      // The statements after it, the migrations', wait for a lock no longer than a use could stand to wait behind them.
      await client.unsafe(`SET lock_timeout = '${MIGRATION_LOCK_WAIT_MS}ms'`);
    },
    async unlock() {
      await client.unsafe('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_KEY]);
    },
    // As drizzle-orm's migrator applies a tree, to the same ledger: each migration's statements, split where drizzle-kit
    // breaks them, then its row; but all in one transaction with the ledger's own, and the hand-over before it commits,
    // so that no session sees an object of coffre's that is not the owner's, and a failure changes nothing. A statement
    // that gave up waiting aborts it: the whole run is tried again.
    migrate: (pending, { relations, functions, types }) =>
      waitingBriefly(client, () =>
        client.begin(async (tx) => {
          await tx.unsafe('CREATE SCHEMA IF NOT EXISTS drizzle');
          await tx.unsafe('CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
          for (const migration of pending) {
            // A CONCURRENTLY build runs after the transaction commits (`online`).
            for (const statement of migration.sql.split('--> statement-breakpoint')) if (onlineIndex(statement) === null) await tx.unsafe(statement);
            await tx.unsafe('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2::bigint)', [migration.hash, migration.createdAt]);
          }
          for (const { statement } of await tx.unsafe<{ statement: string }[]>(HANDED_OVER, [relations, functions, types])) {
            await tx.unsafe(statement).catch((error: unknown) => {
              // A lock wait's is tried again with the run, as a migration's.
              throw lockNotAvailable(error) ? error : new HandOverFailed(statement, error);
            });
          }
        }),
      ),
    async restrict(backupLogin) {
      // It changes no table, only rows of the roles and of the database, which no use locks: it may wait for another
      // database's migrator changing the same roles, as for the migration lock. The last of the run's statements.
      await client.unsafe(`SET lock_timeout = '${OTHER_RUN_LOCK_TIMEOUT}'`);
      const restricted = await restrictDatabase(client);
      if (backupLogin !== undefined) {
        // Compared as text: as a name, Postgres would cut it to 63 bytes, and grant whichever role bears the cut.
        const found = await client.unsafe('SELECT 1 FROM pg_roles WHERE rolname::text = $1', [backupLogin]);
        if (found.length === 0) throw new Error(`role ${quoteIdentifier(backupLogin)} does not exist: make it, coffre never does`);
        await client.unsafe(`GRANT coffre_backup TO ${quoteIdentifier(backupLogin)} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`);
      }
      return restricted;
    },
    async online(indexes) {
      const [{ got }] = await client.unsafe<[{ got: boolean }]>('SELECT pg_try_advisory_lock($1::bigint) AS got', [ONLINE_LOCK_KEY]);
      if (!got) {
        // Another run builds them: say which are not built yet, as that run will.
        const unbuilt: UnbuiltIndex[] = [];
        for (const index of indexes) {
          if (!(await valid(client, index.name))) unbuilt.push({ name: index.name, table: index.table, reason: 'another migration run is building it' });
        }
        return unbuilt;
      }
      try {
        return await buildAll(indexes);
      } finally {
        await client.unsafe('SELECT pg_advisory_unlock($1::bigint)', [ONLINE_LOCK_KEY]);
      }
    },
    async notOwner({ relations, functions, types }) {
      type Foreign = { owner: string; member: boolean; member_of_login: boolean; owns_ledger: boolean; login: string; grants_inherit: boolean; inherits: boolean };
      const rows = await client.unsafe<Foreign[]>(FOREIGN_OWNERS, [relations, functions, types]);
      if (rows.length > 0) {
        const [{ login, grants_inherit: grantsInherit, inherits }] = rows as unknown as [Foreign];
        return new NotOwner(login, rows.map(({ owner, member, member_of_login: memberOfLogin, owns_ledger: ownsLedger }) => ({ name: owner, member, memberOfLogin, ownsLedger })), { grantsInherit, inherits });
      }
      const [ledger] = await client.unsafe<{ owner: string; member: boolean; settable: boolean; grants_inherit: boolean; inherits: boolean }[]>(LEDGER_OWNER);
      if (ledger === undefined || ledger.settable) return null;
      // It has the ledger's owner's privileges but may not become it (Postgres 16's `WITH SET FALSE`), so may not hand
      // it what it makes: that would be its own, beside the owner's, which one owner rules out.
      const [{ login }] = await client.unsafe<[{ login: string }]>('SELECT current_user AS login');
      return new NotOwner(login, [{ name: ledger.owner, member: ledger.member }], { grantsInherit: ledger.grants_inherit, inherits: ledger.inherits, settable: false });
    },
    async cutOver() {
      const [{ cut }] = await client.unsafe<[{ cut: boolean }]>("SELECT EXISTS (SELECT 1 FROM log_changes WHERE object = log_object('log', 'cutover')) AS cut");
      return cut;
    },
    async close() {
      await client.end();
    },
  };
}

/**
 * `run`, tried again after a pause when one of its statements gave up waiting
 * for a lock (55P03), up to `MIGRATION_LOCK_ATTEMPTS` times; any other failure
 * fails at once. Then `LockWaitsExhausted`, naming what held coffre's tables.
 */
async function waitingBriefly<T>(client: Pick<PostgresClient, 'unsafe'>, run: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await run();
    } catch (error) {
      if (!lockNotAvailable(error)) throw error;
      if (attempt === MIGRATION_LOCK_ATTEMPTS) {
        // The failure is the wait's, whether or not Postgres still says who held the tables.
        const holders = await client.unsafe<LockHolder[]>(LOCK_HOLDERS).then((rows) => [...rows], (unread: unknown) => ({ unread }));
        throw new LockWaitsExhausted(attempt, holders, error);
      }
      await new Promise((resolve) => setTimeout(resolve, MIGRATION_LOCK_PAUSE_MS));
    }
  }
}

/**
 * A migration run's plan: `applied` of the `total` migrations there before
 * it, and the tags of the rest, which it applies.
 */
export type MigrationPlan = { applied: number; total: number; pending: string[] };

/**
 * Which of this version's migrations a database has applied, and which it
 * has not, without changing it or waiting on a migration under way; and
 * whether this login could apply them (`notOwner`), as `migrateDatabase`
 * requires: thrown, when it cannot read which. A history that is not a
 * prefix of this version's is refused, as `migrateDatabase` refuses it.
 */
export async function migrationStatus(url: string): Promise<{ applied: string[]; pending: string[]; notOwner: NotOwner | null }> {
  checkDatabaseUrl(url);
  const expected = await expectedMigrations();
  const migrator = await postgresMigrator(url);
  try {
    const notOwner = await migrator.notOwner(managedObjects(expected.map((entry) => entry.sql)));
    // A login that may not even read the ledger is told why.
    const history = await migrator.applied().catch((error: unknown) => {
      throw notOwner ?? error;
    });
    verifyHistory(expected, history, false);
    const applied = history?.length ?? 0;
    await requireCutOver(expected, applied, migrator);
    return {
      applied: expected.slice(0, applied).map((entry) => entry.tag),
      pending: expected.slice(applied).map((entry) => entry.tag),
      notOwner,
    };
  } finally {
    await migrator.close();
  }
}

/** What a run leaves for whoever migrates to hear: `unbuiltNote` and `untimedNote` say it. */
export type MigrateRun = { unbuilt: UnbuiltIndex[]; untimed: string[] };

/**
 * Apply missing migrations, check their history, and reassert database
 * privileges, on every run, even with nothing to apply, as a login that can
 * change coffre's objects and hand them to their owner (see above): another
 * is refused, NotOwner, before anything changes. `onPlan` hears what there
 * is to apply before it is, under the migration lock, and may stop the run
 * by throwing: all of it then goes in one transaction, with no word of each,
 * and with it the hand-over, which a run with nothing to apply makes too.
 * `backupLogin` names an existing role to
 * grant the backup group, `coffre_backup`; it is never made, and
 * never revoked when a later run names none. `unbuilt`: the indexes left to
 * the next run (`unbuiltNote`); `untimed`: the runtime logins this login may
 * not give their statement timeout (`untimedNote`).
 */
export async function migrateDatabase(
  url: string,
  { onPlan, backupLogin }: { onPlan?: (plan: MigrationPlan) => void | Promise<void>; backupLogin?: string } = {},
): Promise<MigrateRun> {
  checkDatabaseUrl(url);
  const problem = backupLogin === undefined ? null : backupLoginProblem(backupLogin);
  if (problem !== null) throw new Error(problem);
  const expected = await expectedMigrations();
  const migrator = await postgresMigrator(url);
  let locked = false;

  try {
    await migrator.lock();
    locked = true;

    const managed = managedObjects(expected.map((entry) => entry.sql));
    const notOwner = await migrator.notOwner(managed);
    if (notOwner !== null) throw notOwner;
    const applied = await migrator.applied();
    verifyHistory(expected, applied, false);
    const done = applied?.length ?? 0;
    await requireCutOver(expected, done, migrator);
    await onPlan?.({ applied: done, total: expected.length, pending: expected.slice(done).map((entry) => entry.tag) });
    await migrator.migrate(expected.slice(done), managed);
    verifyHistory(expected, await migrator.applied(), true);
    let untimed: string[];
    try {
      ({ untimed } = await migrator.restrict(backupLogin));
    } catch (error) {
      throw new AfterMigrations(error);
    }
    // Last, for they may take minutes on a large log, holding up no write: the indexes built without blocking
    // writes, every run until each is built, once the migration lock is let go (`ONLINE_LOCK_KEY`). One that
    // waited too long is said, and left to the next run.
    await migrator.unlock();
    locked = false;
    try {
      return { unbuilt: await migrator.online(onlineIndexes(expected.map((entry) => entry.sql))), untimed };
    } catch (error) {
      throw new AfterMigrations(error, 'building its indexes online');
    }
  } finally {
    try {
      if (locked) await migrator.unlock();
    } finally {
      await migrator.close();
    }
  }
}

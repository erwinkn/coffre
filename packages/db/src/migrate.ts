import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';

import { engineOfUrl } from './connect.ts';
import type { Engine } from './dialect.ts';
import { postgresConnection } from './postgres.ts';

/**
 * Bring a database up to date with its engine's migration tree:
 * migrations/postgres or migrations/sqlite. Both trees
 * describe one schema; see schema-parity.test.ts.
 *
 * Applied history must be a prefix of the local journal, byte for byte,
 * before and after. Only one migrator runs at a time: Postgres takes an
 * advisory lock, and SQLite's own write lock covers the
 * whole run. Restricted runtime roles are Postgres-only (baseline/postgres.sql).
 */

const MIGRATION_LOCK_KEY = '7165058122361679213';

/** Reassert database privileges that pg_dump and CREATE DATABASE TEMPLATE do not carry. */
export async function restrictDatabase(client: Pick<PoolClient, 'query'>): Promise<void> {
  await client.query(`DO $$ BEGIN
    EXECUTE format(
      'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime, coffre_backup',
      current_database()
    );
  END $$`);
}

/**
 * The migrations are applied, and their ledger checked, but reasserting the
 * privileges after them failed: unlike a migration's failure, this one
 * changed the database.
 */
export class AfterMigrations extends Error {
  constructor(error: unknown) {
    super(`the migrations are applied, but reasserting the database's privileges after them failed: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    this.name = 'AfterMigrations';
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

/** A connection that applies one engine's tree. */
interface Migrator {
  /** The applied history, oldest first, or null before the first migration. */
  applied(): Promise<AppliedMigration[] | null>;
  lock(): Promise<void>;
  unlock(): Promise<void>;
  migrate(migrationsFolder: string): Promise<void>;
  /** Reassert privileges a one-database backup does not carry, and grant `backupLogin` the backup group (0019_backup_role.sql). */
  restrict(backupLogin: string | undefined): Promise<void>;
  /** Why this login cannot change the objects migrations change, `managed` among them, or null when it can. */
  notOwner(managed: Managed): Promise<NotOwner | null>;
  close(): Promise<void>;
}

/** An owner of coffre's objects whose privileges the login lacks: not a member of it, or one that does not inherit them. */
export type ForeignOwner = { name: string; member: boolean };

/**
 * The login cannot change coffre's objects, the ledger's schema, the tables
 * and the functions: their owners are roles whose privileges it does not
 * have, as neither one of them nor a member of one that inherits them.
 * Postgres would refuse the first migration that touches one, "permission
 * denied for schema drizzle"; this says whose login migrates, or what makes
 * this one able to: on Postgres 16 and later, a membership that inherits,
 * which each one's GRANT says; before, a membership, and a login that
 * inherits (`ALTER ROLE … INHERIT`).
 */
export class NotOwner extends Error {
  readonly login: string;
  readonly owners: ForeignOwner[];

  constructor(login: string, owners: ForeignOwner[], { grantsInherit, inherits }: { grantsInherit: boolean; inherits: boolean }) {
    const one = owners.length === 1;
    const members = owners.every((owner) => owner.member);
    const fixes = [
      ...owners.filter((owner) => grantsInherit || !owner.member).map((owner) => `GRANT ${identifier(owner.name)} TO ${identifier(login)}${grantsInherit ? ' WITH INHERIT TRUE' : ''}`),
      ...(grantsInherit || inherits ? [] : [`ALTER ROLE ${identifier(login)} INHERIT`]),
    ];
    super(
      `coffre's tables are owned by ${owners.map((owner) => owner.name).join(' and ')}, and this login, ${login}, ` +
        (members
          ? `is a member of ${one ? 'it' : 'them'} but does not inherit ${one ? 'its' : 'their'} privileges: `
          : `is neither ${one ? 'it nor a member of it' : 'one nor a member of one'}: `) +
        `migrate with ${one ? `${owners[0]!.name}'s` : 'their'} connection string, or, as a role that administers ${one ? 'it' : 'them'}, run ${fixes.join('; ')}`,
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

/** What coffre's migrations make and so change later: relations and functions, by name, in public. */
type Managed = { relations: string[]; functions: string[] };

/**
 * The names a migration's SQL makes: CREATE TABLE, VIEW, MATERIALIZED VIEW
 * and SEQUENCE, and CREATE FUNCTION, in public. Unquoted, a name is folded
 * to lower case, as Postgres folds it.
 */
export function managedObjects(sqlTexts: readonly string[]): Managed {
  const name = String.raw`(?:"?public"?\.)?(?:"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_$]*))`;
  const relation = new RegExp(String.raw`\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:UNLOGGED\s+)?(?:TABLE|VIEW|MATERIALIZED\s+VIEW|SEQUENCE)\s+(?:IF\s+NOT\s+EXISTS\s+)?${name}`, 'gi');
  const fn = new RegExp(String.raw`\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+${name}\s*\(`, 'gi');
  const names = (pattern: RegExp) => [
    ...new Set(sqlTexts.flatMap((text) => [...text.matchAll(pattern)].map(([, quoted, bare]) => (quoted !== undefined ? quoted.replace(/""/g, '"') : bare!.toLowerCase())))),
  ];
  return { relations: names(relation), functions: names(fn) };
}

/**
 * The owners of what migrations change, whose privileges the login lacks:
 * the drizzle schema and everything in it, and in public the relations and
 * functions coffre's migrations make ($1, $2), and nothing else of public,
 * which may hold a database's other tables. A superuser has every role's.
 */
const FOREIGN_OWNERS = `
  WITH owned AS (
    SELECT nspowner AS owner FROM pg_namespace WHERE nspname = 'drizzle'
    UNION ALL
    SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
        AND (n.nspname = 'drizzle' OR (n.nspname = 'public' AND c.relname = ANY($1::text[])))
    UNION ALL
    SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = ANY($2::text[])
  )
  SELECT DISTINCT r.rolname AS owner, pg_has_role(owned.owner, 'MEMBER') AS member, current_user AS login,
    current_setting('server_version_num')::int >= 160000 AS grants_inherit,
    (SELECT rolinherit FROM pg_roles WHERE rolname = current_user) AS inherits
  FROM owned JOIN pg_roles r ON r.oid = owned.owner
  WHERE NOT pg_has_role(owned.owner, 'USAGE')
  ORDER BY r.rolname`;

/**
 * Beside this module: src/migrations in the workspace, and dist/migrations
 * in the built package, where the build copies them.
 */
export function migrationsFolder(engine: Engine): string {
  return fileURLToPath(new URL(`./migrations/${engine}`, import.meta.url));
}

async function expectedMigrations(engine: Engine): Promise<ExpectedMigration[]> {
  const folder = migrationsFolder(engine);
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

function verifyHistory(
  expected: ExpectedMigration[],
  applied: AppliedMigration[] | null,
  requireComplete: boolean,
): void {
  const rows = applied ?? [];
  rows.slice(0, expected.length).forEach((row, index) => {
    const local = expected[index]!;
    if (row.created_at !== local.createdAt || row.hash !== local.hash) {
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

async function postgresMigrator(url: string): Promise<Migrator> {
  const [{ default: pg }, { drizzle }, { migrate }] = await Promise.all([
    import('pg'),
    import('drizzle-orm/node-postgres'),
    import('drizzle-orm/node-postgres/migrator'),
  ]);
  const pool = new pg.Pool({ ...postgresConnection(url), application_name: 'coffre-migrations', max: 1 });
  const client = await pool.connect();
  return {
    async applied() {
      const relation = await client.query<{ relation: string | null }>(
        "SELECT to_regclass('drizzle.__drizzle_migrations')::text AS relation",
      );
      if (!relation.rows[0]?.relation) return null;
      const result = await client.query<AppliedMigration>(
        'SELECT hash, created_at::text FROM drizzle.__drizzle_migrations ORDER BY created_at, id',
      );
      return result.rows;
    },
    async lock() {
      await client.query("SET lock_timeout = '5min'");
      await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_KEY]);
    },
    async unlock() {
      await client.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_KEY]);
    },
    migrate: (migrationsFolder) => migrate(drizzle(client), { migrationsFolder }),
    async restrict(backupLogin) {
      await restrictDatabase(client);
      if (backupLogin !== undefined) {
        await client.query(`GRANT coffre_backup TO ${client.escapeIdentifier(backupLogin)} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`);
      }
    },
    async notOwner({ relations, functions }) {
      const { rows } = await client.query<{ owner: string; member: boolean; login: string; grants_inherit: boolean; inherits: boolean }>(FOREIGN_OWNERS, [relations, functions]);
      if (rows.length === 0) return null;
      const [{ login, grants_inherit: grantsInherit, inherits }] = rows as [(typeof rows)[number]];
      return new NotOwner(login, rows.map(({ owner, member }) => ({ name: owner, member })), { grantsInherit, inherits });
    },
    async close() {
      client.release();
      await pool.end();
    },
  };
}

async function sqliteMigrator(url: string): Promise<Migrator> {
  const [{ openDatabase }, { migrate }] = await Promise.all([
    import('./connect.ts'),
    import('drizzle-orm/libsql/migrator'),
  ]);
  const { db, close } = await openDatabase(url);
  const sqlite = db as unknown as Parameters<typeof migrate>[0];
  return {
    async applied() {
      const tables = await sqlite.all(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '__drizzle_migrations'",
      );
      if (tables.length === 0) return null;
      return sqlite.all<AppliedMigration>(
        'SELECT hash, CAST(created_at AS TEXT) AS created_at FROM __drizzle_migrations ORDER BY created_at, id',
      );
    },
    // The migration runs as one transaction, in the database's write queue.
    async lock() {},
    async unlock() {},
    migrate: (migrationsFolder) => migrate(sqlite, { migrationsFolder }),
    async restrict() {},
    // One file, which whoever opens it may change.
    notOwner: async () => null,
    close,
  };
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
  const engine = engineOfUrl(url);
  const expected = await expectedMigrations(engine);
  const migrator = await { postgres: postgresMigrator, sqlite: sqliteMigrator }[engine](url);
  try {
    const notOwner = await migrator.notOwner(managedObjects(expected.map((entry) => entry.sql)));
    // A login that may not even read the ledger is told why.
    const history = await migrator.applied().catch((error: unknown) => {
      throw notOwner ?? error;
    });
    verifyHistory(expected, history, false);
    const applied = history?.length ?? 0;
    return {
      applied: expected.slice(0, applied).map((entry) => entry.tag),
      pending: expected.slice(applied).map((entry) => entry.tag),
      notOwner,
    };
  } finally {
    await migrator.close();
  }
}

/**
 * Apply missing migrations, check their history, and reassert database
 * privileges, on every run, even with nothing to apply, as a login that can
 * change coffre's objects: another is refused, NotOwner, before anything
 * changes. `onPlan` hears what there is to apply before it is, under
 * the migration lock, and may stop the run by throwing: all of it then goes
 * in one call, with no word of each. `backupLogin` names an existing role to
 * grant the backup group, `coffre_backup`, on Postgres; it is never made, and
 * never revoked when a later run names none.
 */
export async function migrateDatabase(
  url: string,
  { onPlan, backupLogin }: { onPlan?: (plan: MigrationPlan) => void | Promise<void>; backupLogin?: string } = {},
): Promise<void> {
  const engine = engineOfUrl(url);
  if (engine === 'sqlite' && backupLogin !== undefined) throw new Error('SQLite has no roles, so no backup login');
  const expected = await expectedMigrations(engine);
  const migrator = await { postgres: postgresMigrator, sqlite: sqliteMigrator }[engine](url);
  let locked = false;

  try {
    await migrator.lock();
    locked = true;

    const notOwner = await migrator.notOwner(managedObjects(expected.map((entry) => entry.sql)));
    if (notOwner !== null) throw notOwner;
    const applied = await migrator.applied();
    verifyHistory(expected, applied, false);
    const done = applied?.length ?? 0;
    await onPlan?.({ applied: done, total: expected.length, pending: expected.slice(done).map((entry) => entry.tag) });
    await migrator.migrate(migrationsFolder(engine));
    verifyHistory(expected, await migrator.applied(), true);
    try {
      await migrator.restrict(backupLogin);
    } catch (error) {
      throw new AfterMigrations(error);
    }
  } finally {
    try {
      if (locked) await migrator.unlock();
    } finally {
      await migrator.close();
    }
  }
}

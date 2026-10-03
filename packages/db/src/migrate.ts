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
      'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime',
      current_database()
    );
  END $$`);
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
  /** Reassert privileges a one-database backup does not carry. */
  restrict(): Promise<void>;
  close(): Promise<void>;
}

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

function verifyHistory(
  expected: ExpectedMigration[],
  applied: AppliedMigration[] | null,
  requireComplete: boolean,
): void {
  const rows = applied ?? [];
  if (rows.length > expected.length) {
    throw new Error('database contains migrations that are absent from this image');
  }
  if (requireComplete && rows.length !== expected.length) {
    throw new Error(`migration history is incomplete: expected ${expected.length}, found ${rows.length}`);
  }

  rows.forEach((row, index) => {
    const local = expected[index];
    if (row.created_at !== local.createdAt || row.hash !== local.hash) {
      throw new Error(
        `migration history diverged at ${local.tag}; applied migrations must never be edited`,
      );
    }
  });
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
    restrict: () => restrictDatabase(client),
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
    close,
  };
}

/** A migration run's plan: `applied` of the `total` migrations there before it, the rest applied by it. */
export type MigrationPlan = { applied: number; total: number };

/**
 * Apply missing migrations, check their history and reassert database
 * privileges. `onPlan` hears how many there are to apply before they are:
 * all of them go in one call, with no word of each.
 */
export async function migrateDatabase(url: string, onPlan?: (plan: MigrationPlan) => void): Promise<void> {
  const engine = engineOfUrl(url);
  const expected = await expectedMigrations(engine);
  const migrator = await { postgres: postgresMigrator, sqlite: sqliteMigrator }[engine](url);
  let locked = false;

  try {
    await migrator.lock();
    locked = true;

    const applied = await migrator.applied();
    verifyHistory(expected, applied, false);
    onPlan?.({ applied: applied?.length ?? 0, total: expected.length });
    await migrator.migrate(migrationsFolder(engine));
    verifyHistory(expected, await migrator.applied(), true);
    await migrator.restrict();
  } finally {
    try {
      if (locked) await migrator.unlock();
    } finally {
      await migrator.close();
    }
  }
}

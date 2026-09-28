import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { engineOfUrl } from './connect.ts';
import type { Engine } from './dialect.ts';

/**
 * Bring a database up to date with its engine's migration tree:
 * migrations/postgres, migrations/mysql or migrations/sqlite. The three trees
 * describe one schema; see schema-parity.test.ts.
 *
 * Applied history must be a prefix of the local journal, byte for byte,
 * before and after. Only one migrator runs at a time: Postgres takes an
 * advisory lock, MySQL a named lock, and SQLite's own write lock covers the
 * whole run. The restricted runtime role is Postgres-only (0001_bootstrap).
 */

const MIGRATION_LOCK_KEY = '7165058122361679213';

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
  close(): Promise<void>;
}

export function migrationsFolder(engine: Engine): string {
  return fileURLToPath(new URL(`../migrations/${engine}`, import.meta.url));
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
  const pool = new pg.Pool({ application_name: 'coffre-migrations', connectionString: url, max: 1 });
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
    async close() {
      client.release();
      await pool.end();
    },
  };
}

async function mysqlMigrator(url: string): Promise<Migrator> {
  const [{ createConnection }, { drizzle }, { migrate }] = await Promise.all([
    import('mysql2/promise'),
    import('drizzle-orm/mysql2'),
    import('drizzle-orm/mysql2/migrator'),
  ]);
  const connection = await createConnection({ uri: url, supportBigNumbers: true, bigNumberStrings: true, timezone: 'Z' });
  return {
    async applied() {
      const [tables] = await connection.query(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '__drizzle_migrations'",
      );
      if ((tables as unknown[]).length === 0) return null;
      const [rows] = await connection.query(
        'SELECT hash, CAST(created_at AS CHAR) AS created_at FROM __drizzle_migrations ORDER BY created_at, id',
      );
      return rows as AppliedMigration[];
    },
    async lock() {
      const [[{ locked }]] = (await connection.query("SELECT GET_LOCK('coffre-migrations', 300) AS locked")) as unknown as [[{ locked: string | null }]];
      if (Number(locked) !== 1) throw new Error('another migrator held the lock for five minutes');
    },
    async unlock() {
      await connection.query("SELECT RELEASE_LOCK('coffre-migrations')");
    },
    migrate: (migrationsFolder) => migrate(drizzle({ client: connection }), { migrationsFolder }),
    close: () => connection.end(),
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
    close,
  };
}

/** Apply every migration the database lacks, checking the history on both sides. */
export async function migrateDatabase(url: string): Promise<void> {
  const engine = engineOfUrl(url);
  const expected = await expectedMigrations(engine);
  const migrator = await { postgres: postgresMigrator, mysql: mysqlMigrator, sqlite: sqliteMigrator }[engine](url);
  let locked = false;

  try {
    await migrator.lock();
    locked = true;

    verifyHistory(expected, await migrator.applied(), false);
    await migrator.migrate(migrationsFolder(engine));
    verifyHistory(expected, await migrator.applied(), true);
  } finally {
    try {
      if (locked) await migrator.unlock();
    } finally {
      await migrator.close();
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const url = process.env.DATABASE_URL?.trim();
  if (!url) throw new Error('DATABASE_URL is required');
  await migrateDatabase(url);
  console.log('database schema is up to date');
}

import { count, sql, type SQL } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { engineOf, migrationLedger, type Engine } from './dialect.ts';
import postgresJournal from './migrations/postgres/meta/_journal.json' with { type: 'json' };
import sqliteJournal from './migrations/sqlite/meta/_journal.json' with { type: 'json' };

/**
 * Every migration this version ships, oldest first, per engine: read from
 * the journals at build time, so a Worker, which has no files, knows them
 * too.
 */
export const KNOWN_MIGRATIONS: Record<Engine, readonly string[]> = {
  postgres: postgresJournal.entries.map((entry) => entry.tag),
  sqlite: sqliteJournal.entries.map((entry) => entry.tag),
};

/**
 * Whether the database has applied every migration this version ships:
 * below that, the app serves nothing but its readiness, which says so
 * (`coffre migrate` runs before each deploy). A database never loses a
 * migration, so once true it stays true.
 */
export async function migrated(db: Queryable): Promise<boolean> {
  // A database never migrated has no ledger at all, which is no migration, not an error. On Postgres the count alone,
  // one round trip at a cold isolate's door, not two (T206): a ledger missing is its relation's error, 42P01.
  if (engineOf(db) === 'sqlite' && !(await hasSqliteLedger(db))) return false;
  const counted = await db.select({ n: count() }).from(migrationLedger(db)).then(
    ([ledger]) => ledger?.n ?? 0,
    (error: unknown) => {
      if (engineOf(db) === 'postgres' && codeIn(error) === UNDEFINED_TABLE) return 0;
      throw error;
    },
  );
  return counted >= KNOWN_MIGRATIONS[engineOf(db)].length;
}

/** Postgres's undefined_table: `drizzle.__drizzle_migrations` missing, its schema too, as before the first `coffre migrate`. */
const UNDEFINED_TABLE = '42P01';

/** The SQLSTATE an error or one of its causes carries (Drizzle wraps the driver's). */
function codeIn(error: unknown): string | undefined {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code } = cause as { code?: unknown };
    if (typeof code === 'string') return code;
  }
  return undefined;
}

async function hasSqliteLedger(db: Queryable): Promise<boolean> {
  const rows = await (db as unknown as { all<R>(query: SQL): Promise<R[]> }).all<{ present: number }>(
    sql`SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = '__drizzle_migrations'`,
  );
  return rows.length > 0;
}

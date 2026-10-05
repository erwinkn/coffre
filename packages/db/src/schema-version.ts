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
  // A database never migrated has no ledger at all, which is no migration, not an error.
  if (!(await hasLedger(db))) return false;
  const [ledger] = await db.select({ n: count() }).from(migrationLedger(db));
  return (ledger?.n ?? 0) >= KNOWN_MIGRATIONS[engineOf(db)].length;
}

async function hasLedger(db: Queryable): Promise<boolean> {
  if (engineOf(db) === 'postgres') {
    const { rows } = await db.execute<{ present: boolean }>(sql`SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS present`);
    return rows[0]?.present === true;
  }
  const rows = await (db as unknown as { all<R>(query: SQL): Promise<R[]> }).all<{ present: number }>(
    sql`SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = '__drizzle_migrations'`,
  );
  return rows.length > 0;
}

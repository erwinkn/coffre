import { count } from 'drizzle-orm';

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
  const [ledger] = await db.select({ n: count() }).from(migrationLedger(db));
  return (ledger?.n ?? 0) >= KNOWN_MIGRATIONS[engineOf(db)].length;
}

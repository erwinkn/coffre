import { count } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { engineOf, migrationLedger, type Engine } from './dialect.ts';
import postgresJournal from './migrations/postgres/meta/_journal.json' with { type: 'json' };
import sqliteJournal from './migrations/sqlite/meta/_journal.json' with { type: 'json' };

/**
 * Minimum migration prefix required by this application image, per engine:
 * Advance this only when the runtime needs the new schema. The sync-removal
 * migration only drops unused tables: new code works with either prefix,
 * so Workers Builds can deploy before an owner runs the migration.
 * Applied migrations remain immutable (see baseline.ts).
 */
export const REQUIRED_MIGRATIONS: Record<Engine, number> = { postgres: 1, sqlite: 1 };

export function requiredMigrations(db: Queryable): number {
  return REQUIRED_MIGRATIONS[engineOf(db)];
}

/**
 * Every migration this version ships, oldest first, per engine: read from
 * the journals at build time, so a Worker, which has no files, knows them
 * too. A database that has applied fewer is behind this code, whatever
 * `REQUIRED_MIGRATIONS` lets it run on.
 */
export const KNOWN_MIGRATIONS: Record<Engine, readonly string[]> = {
  postgres: postgresJournal.entries.map((entry) => entry.tag),
  sqlite: sqliteJournal.entries.map((entry) => entry.tag),
};

export function knownMigrations(db: Queryable): readonly string[] {
  return KNOWN_MIGRATIONS[engineOf(db)];
}

/**
 * Whether the database has applied the migration `tag`, one this version
 * ships: what code asks before it uses what that migration adds, which a
 * database it runs on before `coffre migrate` does not have yet.
 */
export async function applied(db: Queryable, tag: string): Promise<boolean> {
  const needed = knownMigrations(db).indexOf(tag) + 1;
  if (needed === 0) throw new Error(`no migration ${tag} in this version`);
  const [ledger] = await db.select({ n: count() }).from(migrationLedger(db));
  return (ledger?.n ?? 0) >= needed;
}

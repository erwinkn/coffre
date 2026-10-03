import type { Queryable } from './database.ts';
import { engineOf, type Engine } from './dialect.ts';

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

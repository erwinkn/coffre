import type { Queryable } from './database.ts';
import { engineOf, type Engine } from './dialect.ts';

/**
 * Minimum migration prefix required by this application image, per engine:
 * each tree has its own history, all ending at the same schema.
 */
export const REQUIRED_MIGRATIONS: Record<Engine, number> = { postgres: 6, mysql: 1, sqlite: 1 };

export function requiredMigrations(db: Queryable): number {
  return REQUIRED_MIGRATIONS[engineOf(db)];
}

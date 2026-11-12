import { count } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { migrationLedger } from './dialect.ts';
import journal from './migrations/postgres/meta/_journal.json' with { type: 'json' };

/**
 * Every migration this version ships, oldest first: read from the journal
 * at build time, so a Worker, which has no files, knows them too.
 */
export const KNOWN_MIGRATIONS: readonly string[] = journal.entries.map((entry) => entry.tag);

/**
 * Whether the database has applied every migration this version ships:
 * below that, the app serves nothing but its readiness, which says so
 * (`coffre migrate` runs before each deploy). A database never loses a
 * migration, so once true it stays true.
 */
export async function migrated(db: Queryable): Promise<boolean> {
  // A database never migrated has no ledger at all, which is no migration, not an error. The count alone, one round
  // trip at a cold isolate's door, not two (T206): a ledger missing is its relation's error, 42P01.
  const counted = await db.select({ n: count() }).from(migrationLedger()).then(
    ([ledger]) => ledger?.n ?? 0,
    (error: unknown) => {
      if (codeIn(error) === UNDEFINED_TABLE) return 0;
      throw error;
    },
  );
  return counted >= KNOWN_MIGRATIONS.length;
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

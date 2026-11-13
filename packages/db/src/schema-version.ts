import { count, sql } from 'drizzle-orm';

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
  // A database never migrated has no ledger at all, which is no migration, not an error.
  if (!(await hasLedger(db))) return false;
  const [ledger] = await db.select({ n: count() }).from(migrationLedger(db));
  return (ledger?.n ?? 0) >= KNOWN_MIGRATIONS.length;
}

async function hasLedger(db: Queryable): Promise<boolean> {
  const { rows } = await db.execute<{ present: boolean }>(sql`SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS present`);
  return rows[0]?.present === true;
}

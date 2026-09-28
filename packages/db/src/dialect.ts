import { getTableColumns, sql } from 'drizzle-orm';
import { bigint, integer, pgSchema, text, type PgTable } from 'drizzle-orm/pg-core';

/**
 * Everything that is written differently on Postgres, MySQL and SQLite, and
 * nothing else. The queries themselves are builder code in queries.ts that
 * reads the same on all three, so moving to another database means another
 * copy of this file, not an audit of the server.
 *
 *                     Postgres                MySQL                  SQLite
 *   lock a row        SELECT … FOR UPDATE     SELECT … FOR UPDATE    one writer at a time
 *   insert if absent  ON CONFLICT DO NOTHING  INSERT IGNORE          ON CONFLICT DO NOTHING
 *   upsert            ON CONFLICT DO UPDATE   ON DUPLICATE KEY       ON CONFLICT DO UPDATE
 *   rows changed      rowCount                affectedRows           changes
 *   duplicate key     SQLSTATE 23505          errno 1062             SQLITE_CONSTRAINT_UNIQUE
 */

export type Table = PgTable;

/** Lock the rows a select reads until the transaction ends. */
export function forUpdate<Query extends { for: (strength: 'update') => unknown }>(
  query: Query,
): ReturnType<Query['for']> {
  return query.for('update') as ReturnType<Query['for']>;
}

/** Skip the rows of an insert that would repeat a unique key. */
export function ignoreConflicts<Query extends { onConflictDoNothing: () => unknown }>(
  query: Query,
): ReturnType<Query['onConflictDoNothing']> {
  return query.onConflictDoNothing() as ReturnType<Query['onConflictDoNothing']>;
}

/**
 * Where an insert repeats the unique key `target`, overwrite `columns` of the
 * existing row with the values it was about to insert.
 */
export function onConflictUpdate<
  T extends Table,
  Query extends { onConflictDoUpdate: (config: { target: never; set: never }) => unknown },
>(query: Query, table: T, target: (keyof T['$inferSelect'])[], columns: (keyof T['$inferSelect'])[]) {
  const all = getTableColumns(table) as Record<string, ReturnType<typeof getTableColumns>[string]>;
  return query.onConflictDoUpdate({
    target: target.map((name) => all[name as string]) as never,
    set: Object.fromEntries(
      columns.map((name) => [name, sql`excluded.${sql.identifier(all[name as string].name)}`]),
    ) as never,
  });
}

/** How many rows an insert, update or delete touched. */
export function changedRows(result: unknown): number {
  return (result as { rowCount?: number | null }).rowCount ?? 0;
}

/** Whether an insert or update failed on a unique constraint. */
export function isUniqueViolation(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; ) {
    if ((cause as { code?: unknown }).code === '23505') return true;
    cause = (cause as { cause?: unknown }).cause;
  }
  return false;
}

/** A consistent read of several statements that cannot write, such as verifying the chain. */
export const SNAPSHOT = { isolationLevel: 'repeatable read', accessMode: 'read only' } as const;

const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/;

/**
 * The one rendering of a timestamp read as text: UTC, microseconds, `Z`.
 *
 * The audit chain covers occurred_at as text, so reading a row back has to
 * reproduce it byte for byte. Databases hand timestamps back in their own
 * shapes (`2026-09-27 12:34:56.1+02` from Postgres), and a Date would drop
 * the microseconds, so every value goes through here on the way in and out:
 *
 *   2026-09-27 12:34:56.1+02  ->  2026-09-27T10:34:56.100000Z
 */
export function canonicalTimestamp(raw: string): string {
  const match = TIMESTAMP.exec(raw);
  if (match === null) throw new Error(`unexpected timestamp from the database: ${raw}`);
  const [, year, month, day, hour, minute, second, fraction = '', zone] = match;
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone.startsWith('-') ? -1 : 1;
    const digits = zone.slice(1).replace(':', '');
    offsetMinutes = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2) || '0'));
  }
  const utc = new Date(
    Date.UTC(+year, +month - 1, +day, +hour, +minute, +second) - offsetMinutes * 60_000,
  );
  return `${utc.toISOString().slice(0, 19)}.${fraction.padEnd(6, '0')}Z`;
}

/**
 * The migrator's own ledger, read by readiness to tell a database that is
 * up but not yet migrated from one that is ready. Drizzle keeps it in a
 * `drizzle` schema on Postgres, and in a plain table elsewhere.
 */
export const migrations = pgSchema('drizzle').table('__drizzle_migrations', {
  id: integer().primaryKey(),
  hash: text().notNull(),
  createdAt: bigint('created_at', { mode: 'number' }),
});

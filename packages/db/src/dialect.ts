import { entityKind, getTableColumns, sql, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';

import type { Queryable } from './database.ts';

/**
 * Differences between Postgres and the SQLite used for tests and local dev.
 * Queries stay in the server's queries.ts; it never asks which database it has.
 *
 *                     Postgres                SQLite
 *   isolation         READ COMMITTED          one writer at a time
 *   lock a row        SELECT … FOR UPDATE     one writer at a time
 *   rows changed      rowCount                rowsAffected
 *   duplicate key     SQLSTATE 23505          SQLITE_CONSTRAINT_UNIQUE
 *   clock             CURRENT_TIMESTAMP       strftime(…, 'now')
 *   clock, in ms      clock_timestamp()       unixepoch('subsec')
 *   a condition read  true / false            1 / 0
 *
 * Nothing here imports SQLite code, so the Worker bundles none.
 */

export type Table = PgTable;

export type Engine = 'postgres' | 'sqlite';

/** Which database this is, from the Drizzle dialect it was opened with. */
export function engineOf(db: Queryable): Engine {
  const kind = (db as unknown as { dialect: { constructor: { [entityKind]: string } } }).dialect.constructor[entityKind];
  if (kind.startsWith('Pg')) return 'postgres';
  if (kind.startsWith('SQLite')) return 'sqlite';
  throw new Error(`unsupported database: ${kind}`);
}

/**
 * Lock the rows a select reads until the transaction ends. SQLite has no row
 * locks and needs none: connect.ts runs one transaction at a time, and each
 * holds the database's write lock from its first statement.
 */
export function forUpdate<Query extends { for: (strength: 'update') => unknown }>(
  db: Queryable,
  query: Query,
): ReturnType<Query['for']> {
  if (engineOf(db) === 'sqlite') return query as ReturnType<Query['for']>;
  return query.for('update') as ReturnType<Query['for']>;
}

/** Insert the rows whose unique keys are free; returns how many that was. */
export async function insertIfAbsent(db: Queryable, table: Table, rows: object[]): Promise<number> {
  return changedRows(await db.insert(table).values(rows as never).onConflictDoNothing());
}

/**
 * Insert the rows, or where one repeats the unique key `target`, overwrite
 * `columns` of the existing row with the values it was about to insert.
 */
export async function upsert<T extends Table>(
  db: Queryable,
  table: T,
  rows: object[],
  target: (keyof T['$inferSelect'])[],
  columns: (keyof T['$inferSelect'])[],
): Promise<void> {
  const all = getTableColumns(table) as Record<string, ReturnType<typeof getTableColumns>[string]>;
  const incoming = (name: string) => sql`excluded.${sql.identifier(all[name].name)}`;
  const set = Object.fromEntries(columns.map((name) => [name, incoming(name as string)]));
  const query = db.insert(table).values(rows as never);
  await query.onConflictDoUpdate({
    target: target.map((name) => all[name as string]) as never,
    set: set as never,
  });
}

/** A condition read as a boolean: Postgres returns true or false, SQLite 1 or 0. */
export function truth(condition: SQL): SQL<boolean> {
  return condition.mapWith((value) => Number(value) === 1);
}

/** How many rows an insert, update or delete touched. */
export function changedRows(result: unknown): number {
  const header = result as { rowCount?: number | null; rowsAffected?: number };
  return header.rowCount ?? header.rowsAffected ?? 0;
}

const DUPLICATE_KEY = new Set(['23505', 'SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_CONSTRAINT_PRIMARYKEY']);

/** Whether an insert or update failed on a unique constraint. */
export function isUniqueViolation(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; ) {
    const { code, extendedCode } = cause as { code?: unknown; extendedCode?: unknown };
    if (DUPLICATE_KEY.has(code as string) || DUPLICATE_KEY.has(extendedCode as string)) return true;
    cause = (cause as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * A consistent read of several statements that cannot write, such as
 * verifying the chain. SQLite ignores it: its transactions already see one
 * snapshot, and connect.ts runs them one at a time.
 */
export const SNAPSHOT = { isolationLevel: 'repeatable read', accessMode: 'read only' } as const;

/**
 * The database clock as text, for canonicalTimestamp. Entries from several
 * servers order by it, so it is never an application server's.
 */
export function clock(db: Queryable): SQL<string> {
  switch (engineOf(db)) {
    case 'postgres':
      return sql<string>`CURRENT_TIMESTAMP`;
    case 'sqlite':
      return sql<string>`strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;
  }
}

/**
 * The database clock as milliseconds since the epoch, as the statement runs:
 * Postgres's `clock_timestamp()`, not `CURRENT_TIMESTAMP`, which is the
 * transaction's start and would date an entry that waited for the log's lock
 * before one written while it waited. Read it in a statement after the lock.
 */
export function clockMillis(db: Queryable): SQL<number> {
  switch (engineOf(db)) {
    case 'postgres':
      return sql`(extract(epoch from clock_timestamp()) * 1000)::bigint`.mapWith(Number);
    case 'sqlite':
      return sql`CAST(unixepoch('subsec') * 1000 AS INTEGER)`.mapWith(Number);
  }
}

/**
 * The migrator's own ledger, read by readiness to tell a database that is
 * up but not yet migrated from one that is ready. Drizzle keeps it in a
 * `drizzle` schema on Postgres, and in a plain table elsewhere.
 */
export function migrationLedger(db: Queryable): SQL {
  const table = sql.identifier('__drizzle_migrations');
  return engineOf(db) === 'postgres' ? sql`${sql.identifier('drizzle')}.${table}` : sql`${table}`;
}

const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)?$/;

/**
 * The one rendering of a timestamp read as text: UTC, microseconds, `Z`.
 *
 * The audit chain covers occurred_at as text, so reading a row back has to
 * reproduce it byte for byte. Databases hand timestamps back in their own
 * shapes (`2026-09-27 12:34:56.1+02` from Postgres, ISO text from SQLite),
 * and a Date would drop the microseconds, so every value goes through here
 * on the way in and out:
 *
 *   2026-09-27 12:34:56.1+02  ->  2026-09-27T10:34:56.100000Z
 *   2026-09-27T10:34:56.1Z   ->  2026-09-27T10:34:56.100000Z
 */
export function canonicalTimestamp(raw: string): string {
  const match = TIMESTAMP.exec(raw);
  if (match === null) throw new Error(`unexpected timestamp from the database: ${raw}`);
  const [, year, month, day, hour, minute, second, fraction = '', zone = 'Z'] = match;
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

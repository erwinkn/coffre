import { entityKind, getTableColumns, sql, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';

import type { Queryable } from './database.ts';

/**
 * Everything that is written differently on Postgres, MySQL and SQLite, and
 * nothing else. The queries themselves are builder code in queries.ts that
 * reads the same on all three; the server never asks which database it has.
 *
 *                     Postgres                MySQL                    SQLite
 *   lock a row        SELECT … FOR UPDATE     SELECT … FOR UPDATE      one writer at a time
 *   insert if absent  ON CONFLICT DO NOTHING  skip duplicate-key rows  ON CONFLICT DO NOTHING
 *   upsert            ON CONFLICT DO UPDATE   ON DUPLICATE KEY UPDATE  ON CONFLICT DO UPDATE
 *   rows changed      rowCount                affectedRows             rowsAffected
 *   duplicate key     SQLSTATE 23505          ER_DUP_ENTRY             SQLITE_CONSTRAINT_UNIQUE
 *   clock             CURRENT_TIMESTAMP       UTC_TIMESTAMP(6)         strftime(…, 'now')
 *
 * Nothing here imports MySQL or SQLite code, so the Worker bundles none.
 */

export type Table = PgTable;

export type Engine = 'postgres' | 'mysql' | 'sqlite';

/** Which database this is, from the Drizzle dialect it was opened with. */
export function engineOf(db: Queryable): Engine {
  const kind = (db as unknown as { dialect: { constructor: { [entityKind]: string } } }).dialect.constructor[entityKind];
  if (kind.startsWith('Pg')) return 'postgres';
  if (kind.startsWith('MySql')) return 'mysql';
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

/**
 * Insert the rows whose unique keys are free; returns how many that was.
 *
 * MySQL's INSERT IGNORE would also let through a failed check or a bad
 * value, as a warning. So on MySQL a duplicate key fails the statement, which
 * MySQL undoes on its own without ending the transaction, and the rows are
 * then tried one by one.
 */
export async function insertIfAbsent(db: Queryable, table: Table, rows: object[]): Promise<number> {
  if (engineOf(db) !== 'mysql') {
    return changedRows(await db.insert(table).values(rows as never).onConflictDoNothing());
  }
  try {
    return changedRows(await db.insert(table).values(rows as never));
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
  }
  if (rows.length === 1) return 0;
  let inserted = 0;
  for (const row of rows) inserted += await insertIfAbsent(db, table, [row]);
  return inserted;
}

/**
 * Insert the rows, or where one repeats the unique key `target`, overwrite
 * `columns` of the existing row with the values it was about to insert.
 * MySQL takes the conflict on whichever unique key it hits, so `target` is
 * only honoured there if it is the table's one unique key.
 */
export async function upsert<T extends Table>(
  db: Queryable,
  table: T,
  rows: object[],
  target: (keyof T['$inferSelect'])[],
  columns: (keyof T['$inferSelect'])[],
): Promise<void> {
  const all = getTableColumns(table) as Record<string, ReturnType<typeof getTableColumns>[string]>;
  const incoming = (name: string) =>
    engineOf(db) === 'mysql'
      ? sql`values(${sql.identifier(all[name].name)})`
      : sql`excluded.${sql.identifier(all[name].name)}`;
  const set = Object.fromEntries(columns.map((name) => [name, incoming(name as string)]));
  const query = db.insert(table).values(rows as never);
  if (engineOf(db) === 'mysql') {
    await (query as unknown as { onDuplicateKeyUpdate: (config: { set: object }) => Promise<unknown> })
      .onDuplicateKeyUpdate({ set });
    return;
  }
  await query.onConflictDoUpdate({
    target: target.map((name) => all[name as string]) as never,
    set: set as never,
  });
}

/** How many rows an insert, update or delete touched. */
export function changedRows(result: unknown): number {
  // mysql2 answers with a [header, fields] pair.
  const header = (Array.isArray(result) ? result[0] : result) as {
    rowCount?: number | null;
    affectedRows?: number;
    rowsAffected?: number;
  };
  return header.rowCount ?? header.affectedRows ?? header.rowsAffected ?? 0;
}

const DUPLICATE_KEY = new Set(['23505', 'ER_DUP_ENTRY', 'SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_CONSTRAINT_PRIMARYKEY']);

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
    case 'mysql':
      return sql<string>`UTC_TIMESTAMP(6)`;
    case 'sqlite':
      return sql<string>`strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;
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
 * shapes (`2026-09-27 12:34:56.1+02` from Postgres, a MySQL `datetime` with
 * no zone at all, which is UTC here), and a Date would drop the
 * microseconds, so every value goes through here on the way in and out:
 *
 *   2026-09-27 12:34:56.1+02  ->  2026-09-27T10:34:56.100000Z
 *   2026-09-27 10:34:56.1     ->  2026-09-27T10:34:56.100000Z
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

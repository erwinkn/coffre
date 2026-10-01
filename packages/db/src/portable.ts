import type { LibSQLDatabase } from 'drizzle-orm/libsql';

import { trackCommits } from './commits.ts';
import type { Database } from './database.ts';
import type * as postgres from './schema.ts';
import type * as sqlite from './schema.sqlite.ts';

/**
 * The one place a SQLite database becomes a Postgres one.
 *
 * Drizzle has no type that spans dialects, so the queries are written once,
 * against the Postgres schema, and a SQLite database is handed to
 * them under the Postgres type. That holds because both schemas have the
 * same tables with the same row types (checked below, at compile time, and
 * in schema-parity.test.ts, at run time), and because every query runs on
 * the database's own tables: queries.ts reads them from the database it is
 * given (`tablesOf`), never from an import. A Postgres column on a SQLite
 * database would encode its values the Postgres way.
 */

export type PostgresSchema = typeof postgres;

/** Some of a schema's tables, read as their Postgres twins. */
export function asPostgres<Tables extends Partial<Record<keyof PostgresSchema, unknown>>>(
  tables: Tables,
): Pick<PostgresSchema, keyof Tables & keyof PostgresSchema> {
  return tables as never;
}

/** A SQLite database, read as a Postgres one. */
export function asPostgresDatabase(
  db: LibSQLDatabase<typeof sqlite>,
): Database {
  return trackCommits(db as unknown as Database);
}

// --- the row types match ---------------------------------------------------------

type TableName = {
  [K in keyof PostgresSchema]: PostgresSchema[K] extends { $inferSelect: object } ? K : never;
}[keyof PostgresSchema];

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

/** The tables whose rows differ from their Postgres twin's; never if none. */
type Mismatched<Schema extends Record<TableName, { $inferSelect: object }>> = {
  [K in TableName]: Equal<Schema[K]['$inferSelect'], PostgresSchema[K]['$inferSelect']> extends true ? never : K;
}[TableName];

type None<T extends never> = T;

// A column that differs in type, nullability or name breaks the typecheck
// here, naming its table.
export type SqliteRowsMatch = None<Mismatched<typeof sqlite>>;

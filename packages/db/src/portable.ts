import type { LibSQLDatabase } from 'drizzle-orm/libsql';
import type { MySql2Database } from 'drizzle-orm/mysql2';

import type { Database } from './database.ts';
import type * as postgres from './schema.ts';
import type * as mysql from './schema.mysql.ts';
import type * as sqlite from './schema.sqlite.ts';

/**
 * The one place a MySQL or SQLite database becomes a Postgres one.
 *
 * Drizzle has no type that spans dialects, so the queries are written once,
 * against the Postgres schema, and a MySQL or SQLite database is handed to
 * them under the Postgres type. That holds because the three schemas have the
 * same tables with the same row types (checked below, at compile time, and
 * in schema-parity.test.ts, at run time), and because every query runs on
 * the database's own tables: queries.ts reads them from the database it is
 * given (`tablesOf`), never from an import. A Postgres column on a MySQL
 * database would encode its values the Postgres way.
 */

export type PostgresSchema = typeof postgres;

/** Some of a schema's tables, read as their Postgres twins. */
export function asPostgres<Tables extends Partial<Record<keyof PostgresSchema, unknown>>>(
  tables: Tables,
): Pick<PostgresSchema, keyof Tables & keyof PostgresSchema> {
  return tables as never;
}

/** A MySQL or SQLite database, read as a Postgres one. */
export function asPostgresDatabase(
  db: MySql2Database<typeof mysql> | LibSQLDatabase<typeof sqlite>,
): Database {
  return db as unknown as Database;
}

// --- the row types match ---------------------------------------------------------

type TableName = {
  [K in keyof PostgresSchema]: PostgresSchema[K] extends { $inferSelect: object } ? K : never;
}[keyof PostgresSchema];

type Rows<Schema extends Record<TableName, { $inferSelect: object }>> = {
  [K in TableName]: Schema[K]['$inferSelect'];
};

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

// A column that differs in type, nullability or name breaks the build here.
true satisfies Equal<Rows<typeof mysql>, Rows<PostgresSchema>>;
true satisfies Equal<Rows<typeof sqlite>, Rows<PostgresSchema>>;

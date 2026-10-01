import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import * as postgresSchema from './schema.postgres.ts';

export type LogicalSchema = typeof postgresSchema;
export type LogicalDatabase = NodePgDatabase<LogicalSchema>;
export type LogicalTransaction = Parameters<Parameters<LogicalDatabase['transaction']>[0]>[0];

/**
 * Drizzle has no public database or table type shared by the three dialects.
 * These are the spike's only unsound casts. Runtime table objects and the
 * runtime database always come from the same dialect module.
 */
export function asLogicalDatabase(database: unknown): LogicalDatabase {
  return database as LogicalDatabase;
}

export function asLogicalTransaction(transaction: unknown): LogicalTransaction {
  return transaction as LogicalTransaction;
}

export function asLogicalSchema(schema: unknown): LogicalSchema {
  return schema as LogicalSchema;
}

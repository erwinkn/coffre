import { drizzle, type DrizzleSqliteDODatabase } from 'drizzle-orm/durable-sqlite';
import { migrate } from 'drizzle-orm/durable-sqlite/migrator';

import migrations from './migrations.ts';
import * as schema from './schema.ts';

/**
 * What the vault needs of its storage: a Durable Object's `ctx.storage`, as
 * far as Drizzle's Durable Object driver uses it. On Workers it is the real
 * thing; in a Node process, `libsqlStorage` provides the same two calls over
 * a libSQL file. Either way the vault runs the same driver and the same SQL.
 */
export type SqlStorage = {
  sql: { exec(query: string, ...bindings: unknown[]): SqlCursor };
  transactionSync<T>(closure: () => T): T;
};

export type SqlCursor = {
  toArray(): Record<string, unknown>[];
  raw(): { toArray(): unknown[][] };
  next(): IteratorResult<Record<string, unknown>>;
};

export type Store = DrizzleSqliteDODatabase<typeof schema>;

/** The vault's store on `storage`, migrated. */
export async function openStore(storage: SqlStorage): Promise<Store> {
  const db = drizzle(storage as never, { schema });
  await migrate(db, migrations);
  return db;
}

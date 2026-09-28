import { getTableName, is, Table } from 'drizzle-orm';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import type pg from 'pg';

import * as schema from './schema.ts';

export { schema };

/**
 * A database, typed as Postgres whichever it is; see portable.ts for why
 * that holds. connect.ts opens one of each from a URL.
 */
export type Database = NodePgDatabase<typeof schema>;
export type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];
/** Anything a read can run on: the database, or an open transaction. */
export type Queryable = Database | Transaction;

/**
 * What Drizzle needs from a connection pool. A `pg.Pool` fits, and so does the
 * per-invocation Hyperdrive pool, whose class name ends in `Pool` for the
 * same reason: that is how Drizzle knows to check out a client for a
 * transaction rather than run BEGIN on a shared connection.
 */
export type PoolLike = pg.Pool | {
  query: pg.Pool['query'];
  connect: () => Promise<Pick<pg.PoolClient, 'query'> & { release: () => void }>;
};

export function createDatabase(pool: PoolLike): Database {
  return drizzle(pool as pg.Pool, { schema });
}

/**
 * The tables of the database's own dialect: the Postgres ones on Postgres,
 * the MySQL ones on MySQL. Every query builds on these.
 */
export function tablesOf(db: Queryable): typeof schema {
  return db._.fullSchema;
}

const byName = new WeakMap<object, Map<string, Table>>();

/**
 * The database's own twin of `table`, which may be another dialect's: the
 * server names tables by importing schema.ts, and the database decides
 * which one that means.
 */
export function own<T extends Table>(db: Queryable, table: T): T {
  const tables = tablesOf(db);
  let named = byName.get(tables);
  if (named === undefined) {
    named = new Map(
      Object.values(tables)
        .filter((value) => is(value, Table))
        .map((value) => [getTableName(value), value]),
    );
    byName.set(tables, named);
  }
  const found = named.get(getTableName(table));
  if (found === undefined) throw new Error(`no table ${getTableName(table)} in this database`);
  return found as T;
}

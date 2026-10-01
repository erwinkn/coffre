import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import type pg from 'pg';

import * as schema from './schema.ts';

export { schema };

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

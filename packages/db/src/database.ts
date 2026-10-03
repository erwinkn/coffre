import { AsyncLocalStorage } from 'node:async_hooks';

import { getTableName, is, Table } from 'drizzle-orm';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import type pg from 'pg';

import { trackCommits } from './commits.ts';
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

/**
 * A query made on the database from inside one of its own transactions,
 * rather than through the transaction. With one connection per call, as on
 * Workers, it would wait for the transaction, which waits for it: a call
 * Cloudflare cancels as hung, and nothing says why. So it is refused at
 * once, with this, wherever the database runs.
 */
export class QueryOutsideTransaction extends Error {
  constructor() {
    super('query outside its transaction: use tx. A query on the database inside one of its own transactions waits for that transaction, which waits for it');
    this.name = 'QueryOutsideTransaction';
  }
}

/** The transaction a flow of work runs inside, with the pool it holds, while it is open. */
const inside = new AsyncLocalStorage<{ pool: PoolLike; open: boolean }>();

/**
 * `pool`, refusing a query or a transaction asked from inside a transaction
 * it is already running. Work from any other flow, a concurrent request's,
 * or what the transaction left running after it ended, goes on as before.
 */
function guarded(pool: PoolLike): PoolLike {
  return new Proxy(pool, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      if (key !== 'query' && key !== 'connect') return value.bind(target);
      return (...args: unknown[]) => {
        const open = inside.getStore();
        if (open?.open === true && open.pool === target) throw new QueryOutsideTransaction();
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

/** The refusal `error` is, or was caused by. */
function brokenRule(error: unknown): QueryOutsideTransaction | undefined {
  for (let cause = error; cause instanceof Error; cause = cause.cause) {
    if (cause instanceof QueryOutsideTransaction) return cause;
  }
  return undefined;
}

export function createDatabase(pool: PoolLike): Database {
  const db = drizzle(guarded(pool) as pg.Pool, { schema });
  // Each transaction's work runs knowing which one it is in, until the transaction ends.
  const run = db.transaction.bind(db);
  db.transaction = (async (work, config) => {
    const open = { pool, open: true };
    try {
      return await run((tx) => inside.run(open, () => work(tx)), config);
    } catch (error) {
      // Drizzle wraps what a query throws: the rule broken is what to say.
      throw brokenRule(error) ?? error;
    } finally {
      open.open = false;
    }
  }) as Database['transaction'];
  return trackCommits(db);
}

/**
 * The tables of the database's own dialect: the Postgres ones on Postgres,
 * the SQLite ones on SQLite. Every query builds on these.
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

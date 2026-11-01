import { AsyncLocalStorage } from 'node:async_hooks';

import { getTableName, is, Table, type Assume, type RelationalSchemaConfig } from 'drizzle-orm';
import { PgDatabase, PgDialect, type PgQueryResultHKT, type PgTransactionConfig } from 'drizzle-orm/pg-core';
import { PostgresJsSession, PostgresJsTransaction } from 'drizzle-orm/postgres-js/session';

import { trackCommits } from './commits.ts';
import type { Row, RowList } from './postgres-js/index.ts';
import { textTypes, type PostgresClient } from './postgres.ts';
import * as schema from './schema.ts';

export { schema };
export type { PostgresClient } from './postgres.ts';

/** What a hand-written statement answers on Postgres: its rows, with `count` and `command`. */
export interface QueryResult extends PgQueryResultHKT {
  type: RowList<Assume<this['row'], Row>[]>;
}

/**
 * A database, typed as Postgres whichever it is; see portable.ts for why
 * that holds. connect.ts opens one of each from a URL.
 */
export type Database = PgDatabase<QueryResult, typeof schema, NoRelations>;
export type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];
/** Anything a read can run on: the database, or an open transaction. */
export type Queryable = Database | Transaction;

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

/** The transaction a flow of work runs inside, with the client it holds, while it is open. */
const inside = new AsyncLocalStorage<{ client: Client; open: boolean }>();

/** What Drizzle asks of the client: a statement, or a transaction, which postgres.js runs on a connection it holds. */
const ASKS = new Set<PropertyKey>(['unsafe', 'begin', 'reserve']);

/**
 * `client`, refusing a query or a transaction asked from inside a transaction
 * it is already running. Work from any other flow, a concurrent request's,
 * or what the transaction left running once its work was done, goes on as before.
 */
function guarded(client: Client): Client {
  const refuse = (target: Client) => {
    const open = inside.getStore();
    if (open?.open === true && open.client === target) throw new QueryOutsideTransaction();
  };
  return new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function' || !ASKS.has(key)) return value;
      return (...args: unknown[]) => {
        refuse(target);
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

/**
 * Coffre runs no relational query (`db.query.*`), and Drizzle's work out of
 * them, `extractTablesRelationalConfig` and a query builder per table for
 * every database, was 4 to 11 ms of a cold isolate's CPU and 0.1 ms of each
 * later call on Workers, where a database is made per call. So the database
 * has none: `db.query` is empty, in type and at run time, and a `db.query.x`
 * fails the typecheck. Only the tables stay, for `tablesOf`.
 */
type NoRelations = Record<never, never>;
type Relational = RelationalSchemaConfig<NoRelations>;
const relational: Relational = { fullSchema: schema, schema: {}, tableNamesMap: {} };

/**
 * Drizzle's session for postgres.js, but for a transaction's options, which
 * go in its BEGIN, as node-postgres's session sends them, rather than in a
 * SET TRANSACTION of their own: a round trip less for a snapshot read.
 */
class Session extends PostgresJsSession<PostgresClient, typeof schema, NoRelations> {
  override transaction<T>(work: (tx: PostgresJsTransaction<typeof schema, NoRelations>) => Promise<T>, config?: PgTransactionConfig): Promise<T> {
    const { dialect, schema: tables, options } = this as unknown as { dialect: PgDialect; schema: Relational; options: object };
    return this.client.begin(config === undefined ? '' : transactionOptions(config), (client) =>
      work(new PostgresJsTransaction(dialect, new PostgresJsSession(client, dialect, tables, options), tables))) as Promise<T>;
  }
}

/** What follows BEGIN for `config`, as Drizzle writes it for SET TRANSACTION. */
function transactionOptions(config: PgTransactionConfig): string {
  return [
    config.isolationLevel === undefined ? null : `isolation level ${config.isolationLevel}`,
    config.accessMode ?? null,
    config.deferrable === undefined ? null : config.deferrable ? 'deferrable' : 'not deferrable',
  ].filter((option) => option !== null).join(' ');
}

/**
 * What a database runs on: a postgres.js client (`postgresClient`), or
 * Workers' `HyperdrivePool`, which makes them. Drizzle asks it for
 * statements (`unsafe`) and transactions (`begin`).
 */
export type Client = Pick<PostgresClient, 'unsafe' | 'begin'>;

export function createDatabase(client: Client): Database {
  // What `drizzle(client, { schema })` sets up, but with no relational queries.
  if ('options' in client) textTypes(client as PostgresClient);
  const dialect = new PgDialect();
  const db = new PgDatabase(dialect, new Session(guarded(client) as PostgresClient, dialect, relational), relational) as Database;
  // Each transaction's work runs knowing which one it is in, until that work is done. Not until
  // the COMMIT comes back: the transaction waits on nothing then, so what the work left running
  // may ask for a query, which waits for the transaction to end rather than for itself.
  const run = db.transaction.bind(db);
  db.transaction = (async (work, config) => {
    const open = { client, open: true };
    try {
      return await run(
        (tx) =>
          inside.run(open, async () => {
            try {
              return await work(tx);
            } finally {
              open.open = false;
            }
          }),
        config,
      );
    } catch (error) {
      // Drizzle wraps what a query throws: the rule broken is what to say.
      throw brokenRule(error) ?? error;
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

export { prepared } from './prepared.ts';
export { later } from './later.ts';

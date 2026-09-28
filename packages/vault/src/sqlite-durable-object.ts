import type { Sqlite, SqlValue } from './sqlite.ts';

/**
 * A Durable Object's SQLite. `sql.exec` runs its statement at once and
 * streams the rows; `transactionSync` is the only way to a transaction there,
 * since the object refuses `BEGIN` itself. It would nest, with savepoints;
 * the Node side does not, so neither does this.
 */
export function durableObjectSqlite(storage: DurableObjectStorage): Sqlite {
  const exec = (sql: string, params: SqlValue[]) => storage.sql.exec(sql, ...params);
  let open = false;
  return {
    run(sql, ...params) {
      exec(sql, params);
    },
    get<T>(sql: string, ...params: SqlValue[]) {
      return exec(sql, params).next().value as T | undefined;
    },
    all<T>(sql: string, ...params: SqlValue[]) {
      return exec(sql, params).toArray() as T[];
    },
    iterate<T>(sql: string, ...params: SqlValue[]) {
      return exec(sql, params) as Iterable<T>;
    },
    transaction(fn) {
      if (open) throw new Error('vault transactions do not nest');
      open = true;
      try {
        return storage.transactionSync(fn);
      } finally {
        open = false;
      }
    },
  };
}

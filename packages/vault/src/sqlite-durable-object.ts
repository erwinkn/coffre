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
      // Every row, though there is one at most: a cursor stopped at its first
      // is not finished (see `finished`).
      return exec(sql, params).toArray()[0] as T | undefined;
    },
    all<T>(sql: string, ...params: SqlValue[]) {
      return exec(sql, params).toArray() as T[];
    },
    iterate<T>(sql: string, ...params: SqlValue[]) {
      return finished(exec(sql, params)) as Iterable<T>;
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

/**
 * A cursor's rows, read to the end even when the loop over them stops early.
 * A cursor cannot be closed, and until its last row, or until it is
 * collected, its statement holds a read open: on the database as it was when
 * the read began, so a change made outside the object stays unseen, and the
 * WAL cannot be checkpointed past it.
 */
function* finished(cursor: SqlStorageCursor<Record<string, SqlStorageValue>>) {
  try {
    yield* cursor;
  } finally {
    for (const _ of cursor);
  }
}

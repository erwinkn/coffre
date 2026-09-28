import Database from 'libsql';

import type { SqlCursor, SqlStorage } from './store.ts';

/**
 * A Durable Object's storage over a libSQL file, for the vault in a Node
 * process: `sql.exec` runs one statement, `transactionSync` nests with
 * savepoints, as a Durable Object's does. Synchronous, like the original, so
 * one call's reads and writes run with nothing in between.
 */
export function libsqlStorage(path: string): SqlStorage & { close(): void } {
  const db = new Database(path);
  let depth = 0;
  return {
    sql: {
      exec(query, ...bindings) {
        const statement = db.prepare(query);
        if (!statement.reader) {
          statement.run(...bindings);
          return cursor([], []);
        }
        const names = statement.columns().map((column) => column.name);
        return cursor(names, statement.raw(true).all(...bindings) as unknown[][]);
      },
    },
    transactionSync(closure) {
      const savepoint = `vault_${depth}`;
      db.exec(`SAVEPOINT ${savepoint}`);
      depth += 1;
      try {
        const result = closure();
        depth -= 1;
        db.exec(`RELEASE ${savepoint}`);
        return result;
      } catch (error) {
        depth -= 1;
        db.exec(`ROLLBACK TO ${savepoint}`);
        db.exec(`RELEASE ${savepoint}`);
        throw error;
      }
    },
    close() {
      db.close();
    },
  };
}

function cursor(names: string[], rows: unknown[][]): SqlCursor {
  const object = (row: unknown[]) => Object.fromEntries(names.map((name, i) => [name, row[i]]));
  return {
    toArray: () => rows.map(object),
    raw: () => rows.values(),
    next: () => (rows.length === 0 ? { done: true, value: undefined } : { done: false, value: object(rows[0]) }),
  };
}

import { chmodSync, closeSync, openSync, statSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

import type { Sqlite, SqlValue } from './sqlite.ts';

export type NodeSqlite = Sqlite & { close(): void };

/**
 * A file of the vault's own, through Node's built-in SQLite. WAL, so a reader
 * of the file (a backup) never holds up a decision; `synchronous = FULL`, so
 * a decision that returned, and the log entry recording it, survives a power
 * cut; a busy timeout, so a moment's lock from another process waits rather
 * than fails.
 *
 * A transaction is `BEGIN IMMEDIATE`: it takes the write lock before its
 * first read, so what a decision read cannot change before it writes. The
 * vault never nests one, and a nested `BEGIN` would fail, so it is refused
 * up front, by name.
 */
export function nodeSqlite(path: string): NodeSqlite {
  claim(path);
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = FULL');
  db.exec('PRAGMA busy_timeout = 5000');
  return {
    run(sql, ...params) {
      db.prepare(sql).run(...params);
    },
    get<T>(sql: string, ...params: SqlValue[]) {
      return db.prepare(sql).get(...params) as T | undefined;
    },
    all<T>(sql: string, ...params: SqlValue[]) {
      return db.prepare(sql).all(...params) as T[];
    },
    iterate<T>(sql: string, ...params: SqlValue[]) {
      return db.prepare(sql).iterate(...params) as Iterable<T>;
    },
    transaction(fn) {
      if (db.isTransaction) throw new Error('vault transactions do not nest');
      db.exec('BEGIN IMMEDIATE');
      try {
        const result = fn();
        db.exec('COMMIT');
        return result;
      } catch (error) {
        if (db.isTransaction) db.exec('ROLLBACK');
        throw error;
      }
    },
    close() {
      db.close();
    },
  };
}

/**
 * Make `path` the vault's alone before SQLite opens it: the log says who
 * read which secret, and whoever can write the grants can give themselves
 * any key. A new file is created 0600, and SQLite gives the `-wal` and
 * `-shm` it makes beside it the same mode. A file others may write is
 * refused, since nothing in it can be trusted any more; one they may only
 * read is closed to them, with a warning, since they may have read it.
 */
function claim(path: string): void {
  try {
    closeSync(openSync(path, 'wx', 0o600));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  for (const file of [path, `${path}-wal`, `${path}-shm`]) {
    const stat = statSync(file, { throwIfNoEntry: false });
    if (stat === undefined) continue;
    const mode = (stat.mode & 0o777).toString(8);
    if (stat.mode & 0o022) {
      throw new Error(`${file} is writable by other users (mode ${mode}): the vault will not trust it`);
    }
    if (stat.mode & 0o044) {
      chmodSync(file, 0o600);
      console.warn(`${file} was readable by other users (mode ${mode}); it is now 600`);
    }
  }
}

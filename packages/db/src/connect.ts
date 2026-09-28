import { resolve } from 'node:path';

import type { Client, Transaction as LibsqlTransaction, TransactionMode } from '@libsql/client';
import pg from 'pg';

import { createDatabase, type Database } from './database.ts';
import type { Engine } from './dialect.ts';
import { asPostgresDatabase } from './portable.ts';

/**
 * Open a database from its URL, on a Node server:
 *
 *   postgres://… or postgresql://…   node-postgres
 *   mysql://…                         mysql2
 *   file:… or libsql:…                @libsql/client (SQLite)
 *
 * The MySQL and SQLite drivers load only when asked for. The Worker does not
 * come through here; it builds its Postgres database from the Hyperdrive
 * pool with createDatabase.
 */
export async function openDatabase(url: string): Promise<OpenDatabase> {
  switch (engineOfUrl(url)) {
    case 'postgres': {
      const pool = new pg.Pool({ connectionString: url });
      return { engine: 'postgres', db: createDatabase(pool), close: () => pool.end() };
    }
    case 'mysql': {
      const [{ createPool }, { drizzle }, schema] = await Promise.all([
        import('mysql2/promise'),
        import('drizzle-orm/mysql2'),
        import('./schema.mysql.ts'),
      ]);
      const pool = createPool({
        uri: url,
        // Every bigint is read exactly, as a string that Drizzle turns into one.
        supportBigNumbers: true,
        bigNumberStrings: true,
        timezone: 'Z',
      });
      const db = drizzle({ client: pool, schema, mode: 'default' });
      return { engine: 'mysql', db: asPostgresDatabase(db), close: () => pool.end() };
    }
    case 'sqlite': {
      const [{ createClient }, { drizzle }, schema] = await Promise.all([
        import('@libsql/client'),
        import('drizzle-orm/libsql'),
        import('./schema.sqlite.ts'),
      ]);
      // A lone statement that finds the database locked waits this long.
      const client = createClient({ url, timeout: 5_000 });
      if (url.startsWith('file:')) await client.execute('PRAGMA journal_mode = WAL');
      const db = drizzle({ client: oneTransactionAtATime(client, writeQueueFor(url)), schema });
      return { engine: 'sqlite', db: asPostgresDatabase(db), close: async () => client.close() };
    }
  }
}

export type OpenDatabase = { engine: Engine; db: Database; close: () => Promise<void> };

export function engineOfUrl(url: string): Engine {
  const scheme = url.slice(0, url.indexOf(':'));
  if (scheme === 'postgres' || scheme === 'postgresql') return 'postgres';
  if (scheme === 'mysql') return 'mysql';
  if (scheme === 'file' || scheme === 'libsql') return 'sqlite';
  throw new Error(`unsupported database URL scheme: ${scheme}:`);
}

// --- SQLite: one writer at a time ---------------------------------------------------

/**
 * SQLite lets one connection write at a time and fails the others at once
 * with SQLITE_BUSY rather than queueing them; 24 concurrent audit appends were
 * enough to see it. So transactions queue here instead, in the order they
 * asked, one open at a time per database file, however many clients or
 * connections reach it. Each begins IMMEDIATE (libsql's default), taking the
 * write lock with its first statement, which is what makes a read inside it
 * as good as a locked one (see forUpdate).
 */
class WriteQueue {
  #tail: Promise<void> = Promise.resolve();

  /** Wait for our turn; the returned function ends it. */
  acquire(): Promise<() => void> {
    let release!: () => void;
    const turn = new Promise<void>((done) => (release = done));
    const ready = this.#tail.then(() => release);
    this.#tail = this.#tail.then(() => turn);
    return ready;
  }
}

const queues = new Map<string, WriteQueue>();

function writeQueueFor(url: string): WriteQueue {
  // file:/a.db, file:///a.db and a relative file:a.db from / are one file.
  const key = url.startsWith('file:') ? resolve(url.replace(/^file:(\/\/)?/, '').split('?')[0]) : url;
  let queue = queues.get(key);
  if (queue === undefined) queues.set(key, (queue = new WriteQueue()));
  return queue;
}

function oneTransactionAtATime(client: Client, queue: WriteQueue): Client {
  return new Proxy(client, {
    get(target, key) {
      if (key === 'transaction') {
        return async (mode?: TransactionMode) => {
          const release = await queue.acquire();
          try {
            return settling(await target.transaction(mode), release);
          } catch (error) {
            release();
            throw error;
          }
        };
      }
      if (key === 'batch' || key === 'migrate' || key === 'executeMultiple') {
        return async (...args: unknown[]) => {
          const release = await queue.acquire();
          try {
            return await (target[key] as (...args: unknown[]) => Promise<unknown>)(...args);
          } finally {
            release();
          }
        };
      }
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

/** Ends the transaction's turn when it commits, rolls back or closes. */
function settling(tx: LibsqlTransaction, release: () => void): LibsqlTransaction {
  let settled = false;
  const settle = () => {
    if (settled) return;
    settled = true;
    release();
  };
  const { commit, rollback, close } = tx;
  tx.commit = async () => {
    try {
      return await commit.call(tx);
    } finally {
      settle();
    }
  };
  tx.rollback = async () => {
    try {
      return await rollback.call(tx);
    } finally {
      settle();
    }
  };
  tx.close = () => {
    try {
      close.call(tx);
    } finally {
      settle();
    }
  };
  return tx;
}

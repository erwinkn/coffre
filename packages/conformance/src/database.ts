// SQL on a deployment's shared database, as whoever holds its
// password or its file: what the checks use to go around coffre, to see
// what it wrote, and to break what it must notice.
import { DatabaseSync } from 'node:sqlite';

import { postgresSession } from '@coffre/db/connect';

export type Sql = {
  readonly engine: 'postgres' | 'sqlite';
  /** One statement, with `$1`-style parameters on Postgres and `?` on SQLite. */
  query<Row = Record<string, unknown>>(statement: string, params?: unknown[]): Promise<Row[]>;
  /** Any number of statements, no parameters. */
  exec(statements: string): Promise<void>;
  close(): Promise<void>;
};

export async function postgres(url: string): Promise<Sql> {
  // One session, as a check's transaction needs: lost, its statements fail rather than run on a new connection, unheld.
  const client = postgresSession(url);
  // Connected now, as the harness expects a database it can reach.
  await client.unsafe('SELECT 1');
  return {
    engine: 'postgres',
    query: async <Row>(statement: string, params: unknown[] = []) => [...await client.unsafe(statement, params as never[])] as Row[],
    exec: async (statements) => void (await client.unsafe(statements)),
    close: () => client.end(),
  };
}

/** A SQLite file, perhaps open in another process: it waits out their locks. */
export function sqlite(file: string): Sql {
  const db = new DatabaseSync(file, { timeout: 5000 });
  return {
    engine: 'sqlite',
    query: async <Row>(statement: string, params: unknown[] = []) =>
      db.prepare(statement).all(...(params as never[])) as Row[],
    exec: async (statements) => db.exec(statements),
    close: async () => db.close(),
  };
}

export async function using<T>(open: Sql | Promise<Sql>, use: (sql: Sql) => Promise<T>): Promise<T> {
  const sql = await open;
  try {
    return await use(sql);
  } finally {
    await sql.close();
  }
}

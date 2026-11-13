// SQL on a deployment's shared database, as whoever holds its
// password: what the checks use to go around coffre, to see what it
// wrote, and to break what it must notice.
import pg from 'pg';
import { postgresConnection } from '@coffre/db/connect';

export type Sql = {
  /** The schema coffre's tables are in: `public` in a deployment. */
  readonly schema: string;
  /** One statement, with `$1`-style parameters. */
  query<Row = Record<string, unknown>>(statement: string, params?: unknown[]): Promise<Row[]>;
  /** Any number of statements, no parameters. */
  exec(statements: string): Promise<void>;
  close(): Promise<void>;
};

export async function postgres(url: string, schema = 'public'): Promise<Sql> {
  const client = new pg.Client(postgresConnection(url));
  await client.connect();
  return {
    schema,
    query: async <Row>(statement: string, params: unknown[] = []) => (await client.query(statement, params)).rows as Row[],
    exec: async (statements) => void (await client.query(statements)),
    close: () => client.end(),
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
